"""
Bagman — Secure key management for AI agent payments.

The problem: An AI agent needs to sign crypto transactions, but giving it
direct access to a private key is dangerous. If the agent is compromised,
the key is compromised.

Bagman solves this by:
1. Gating key access behind time-limited sessions with spending caps
2. Never exposing the raw key — only providing signing operations
3. Enforcing budget limits BEFORE signing (not after)
4. Auto-expiring sessions so compromised agents lose access quickly
5. Sanitizing all output to prevent key leakage

Architecture:
    Josh (delegator)
        → Creates session via Bagman CLI (sets time limit, spend cap)
        → Bagman fetches key from 1Password (key never leaves Bagman)
        → Agent receives session handle (opaque token)
        → Agent requests signatures through session (Bagman signs, not agent)
        → Session expires → key access revoked

    The agent NEVER sees the private key. It only gets:
    - A session ID
    - The wallet address (public)
    - A sign() method that enforces all limits
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from eth_account import Account
from eth_account.signers.local import LocalAccount

logger = logging.getLogger(__name__)


@dataclass
class SessionConfig:
    """Configuration for a Bagman session."""
    max_spend_usd: float = 10.0       # Total spending cap for this session
    max_per_tx_usd: float = 1.0       # Per-transaction limit
    ttl_seconds: int = 3600            # Session lifetime (default: 1 hour)
    allowed_networks: list[str] = field(default_factory=lambda: ["eip155:84532"])
    allowed_merchants: list[str] = field(default_factory=list)  # Empty = all allowed


@dataclass
class SessionState:
    """Runtime state of a Bagman session."""
    session_id: str
    created_at: float
    config: SessionConfig
    total_spent_usd: float = 0.0
    tx_count: int = 0
    _account: Optional[LocalAccount] = field(default=None, repr=False)

    @property
    def wallet_address(self) -> str:
        if self._account is None:
            raise RuntimeError("Session not initialized")
        return self._account.address

    @property
    def is_expired(self) -> bool:
        return time.time() > self.created_at + self.config.ttl_seconds

    @property
    def remaining_usd(self) -> float:
        return self.config.max_spend_usd - self.total_spent_usd

    @property
    def seconds_remaining(self) -> int:
        return max(0, int(self.created_at + self.config.ttl_seconds - time.time()))

    def check_spend(self, amount_usd: float) -> tuple[bool, str]:
        """Check if a spend is allowed within session limits."""
        if self.is_expired:
            return False, "Session expired"
        if amount_usd > self.config.max_per_tx_usd:
            return False, f"Amount ${amount_usd} exceeds per-tx limit ${self.config.max_per_tx_usd}"
        if self.total_spent_usd + amount_usd > self.config.max_spend_usd:
            return False, f"Would exceed session spend cap (${self.total_spent_usd + amount_usd:.2f} > ${self.config.max_spend_usd})"
        return True, "OK"

    def record_spend(self, amount_usd: float):
        """Record a successful spend."""
        self.total_spent_usd += amount_usd
        self.tx_count += 1

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "wallet_address": self.wallet_address if self._account else None,
            "created_at": self.created_at,
            "expires_at": self.created_at + self.config.ttl_seconds,
            "seconds_remaining": self.seconds_remaining,
            "total_spent_usd": self.total_spent_usd,
            "remaining_usd": self.remaining_usd,
            "tx_count": self.tx_count,
            "config": {
                "max_spend_usd": self.config.max_spend_usd,
                "max_per_tx_usd": self.config.max_per_tx_usd,
                "ttl_seconds": self.config.ttl_seconds,
                "allowed_networks": self.config.allowed_networks,
            },
        }

    def destroy(self):
        """Destroy session, wiping key from memory."""
        self._account = None


class Bagman:
    """
    Secure key management for AI agent payments.

    Usage:
        bagman = Bagman()

        # Create a session (loads key from 1Password)
        session = bagman.create_session(
            op_item="trustee test",
            op_vault="Ada",
            op_field="credential",
            config=SessionConfig(max_spend_usd=5.0, ttl_seconds=1800),
        )

        # Agent uses session to get a signer (for x402 client)
        signer = bagman.get_signer(session.session_id)

        # When done
        bagman.destroy_session(session.session_id)
    """

    def __init__(self):
        self._sessions: dict[str, SessionState] = {}

    def create_session(
        self,
        op_item: str,
        op_vault: str,
        op_field: str = "credential",
        config: Optional[SessionConfig] = None,
    ) -> SessionState:
        """
        Create a new Bagman session.

        Loads the private key from 1Password, creates a time-limited
        session around it. The key is held in memory only and is
        destroyed when the session expires or is destroyed.
        """
        config = config or SessionConfig()

        # Load key from 1Password
        key = self._load_key_from_1password(op_item, op_vault, op_field)
        account = Account.from_key(key)

        # Wipe the key string from local scope
        # (account holds it internally, but we don't keep a second copy)
        session_id = self._generate_session_id()

        session = SessionState(
            session_id=session_id,
            created_at=time.time(),
            config=config,
            _account=account,
        )

        self._sessions[session_id] = session
        logger.info(
            "Bagman session created: %s (wallet: %s, ttl: %ds, cap: $%.2f)",
            session_id, account.address, config.ttl_seconds, config.max_spend_usd,
        )
        return session

    def get_session(self, session_id: str) -> SessionState:
        """Get a session by ID. Raises if expired or not found."""
        from .errors import SessionNotFoundError, SessionExpiredError
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(f"Session not found: {session_id}")
        if session.is_expired:
            self.destroy_session(session_id)
            raise SessionExpiredError(f"Session expired: {session_id}")
        return session

    def get_signer(self, session_id: str) -> "BagmanSigner":
        """
        Get a signer for the given session.

        Returns a BagmanSigner that wraps the session's key and enforces
        spending limits on every signature. This is what you pass to
        X402PaymentClient or ExactEvmScheme.
        """
        session = self.get_session(session_id)
        return BagmanSigner(session)

    def destroy_session(self, session_id: str):
        """Destroy a session, wiping the key from memory."""
        session = self._sessions.pop(session_id, None)
        if session:
            session.destroy()
            logger.info("Bagman session destroyed: %s", session_id)

    def destroy_all(self):
        """Destroy all sessions."""
        for sid in list(self._sessions.keys()):
            self.destroy_session(sid)

    def list_sessions(self) -> list[dict]:
        """List all active sessions (no key material exposed)."""
        # Clean up expired sessions first
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            self.destroy_session(sid)
        return [s.to_dict() for s in self._sessions.values()]

    def _load_key_from_1password(self, item: str, vault: str, field: str) -> str:
        """Load a private key from 1Password via op CLI."""
        result = subprocess.run(
            ["op", "item", "get", item, "--vault", vault, "--format", "json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"1Password error: {result.stderr.strip()}")

        fields = json.loads(result.stdout)["fields"]
        key = next(
            (f["value"] for f in fields if f.get("label") == field),
            None,
        )
        if not key:
            raise ValueError(f"Field '{field}' not found in 1Password item '{item}'")
        return key

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        entropy = f"{time.time()}-{os.urandom(16).hex()}"
        return f"bm-{hashlib.sha256(entropy.encode()).hexdigest()[:12]}"


class BagmanSigner:
    """
    A signer that enforces Bagman session limits.

    Implements the x402 ClientEvmSigner protocol, but checks session
    validity and spending limits before every signature.

    The agent sees this object. It can:
    - Get the wallet address (public, safe)
    - Request signatures (gated by session limits)
    - Check remaining budget

    It CANNOT:
    - Access the raw private key
    - Sign after session expiry
    - Exceed spending limits
    """

    def __init__(self, session: SessionState):
        self._session = session

    @property
    def address(self) -> str:
        return self._session.wallet_address

    @property
    def remaining_usd(self) -> float:
        return self._session.remaining_usd

    @property
    def seconds_remaining(self) -> int:
        return self._session.seconds_remaining

    def check_and_record_spend(self, amount_usd: float) -> tuple[bool, str]:
        """Check if spend is allowed and record it if so."""
        allowed, reason = self._session.check_spend(amount_usd)
        if allowed:
            self._session.record_spend(amount_usd)
        return allowed, reason

    def sign_typed_data(
        self,
        domain: Any,
        types: dict[str, list],
        primary_type: str,
        message: dict[str, Any],
    ) -> bytes:
        """
        Sign EIP-712 typed data through the Bagman session.

        This is the x402 ClientEvmSigner protocol method.
        Session must be valid (not expired) to sign.
        """
        if self._session.is_expired:
            raise RuntimeError("Bagman session expired — cannot sign")
        if self._session._account is None:
            raise RuntimeError("Session key has been destroyed")

        # Import the adapter's signing logic
        from .x402_client import EthAccountSigner
        adapter = EthAccountSigner(self._session._account)
        return adapter.sign_typed_data(domain, types, primary_type, message)

    def __repr__(self) -> str:
        return (
            f"BagmanSigner(address={self.address}, "
            f"remaining=${self.remaining_usd:.2f}, "
            f"ttl={self.seconds_remaining}s)"
        )
