"""
Mandate creation, signing, and verification.

A Mandate is a cryptographically signed authorization that defines
what an agent is allowed to spend. The human (delegator) creates
and signs mandates; the agent (delegate) verifies and operates
within their bounds.

Signing uses Ethereum's EIP-712 typed data signatures, which:
- Are human-readable (wallet shows structured data, not raw bytes)
- Are domain-separated (can't replay across different contexts)
- Are widely supported (MetaMask, eth_account, hardware wallets)
"""

from __future__ import annotations

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from eth_account import Account
from eth_account.messages import encode_typed_data


# ── Domain separator for EIP-712 ──────────────────────────────────

TRUSTEE_DOMAIN = {
    "name": "Trustee",
    "version": "1",
    "chainId": 8453,  # Base mainnet
}

# ── Mandate types ─────────────────────────────────────────────────


class MandateStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EXHAUSTED = "exhausted"  # budget fully spent


@dataclass
class SpendingLimit:
    """Defines spending constraints within a mandate."""
    max_total_usd: float          # Maximum total spend in USD
    max_per_tx_usd: float         # Maximum per-transaction spend
    daily_limit_usd: Optional[float] = None  # Optional daily cap
    allowed_merchants: list[str] = field(default_factory=list)  # Empty = any merchant
    allowed_categories: list[str] = field(default_factory=list)  # Empty = any category


@dataclass
class Mandate:
    """
    A signed authorization from delegator to delegate.
    
    The delegator (Josh) creates this, signs it with their Ethereum key,
    and the delegate (Ada) verifies the signature before spending.
    """
    # Identity
    mandate_id: str                # Unique identifier (hash of contents)
    delegator_address: str         # Ethereum address of the human
    delegate_address: str          # Ethereum address of the agent
    
    # Authorization
    spending_limit: SpendingLimit
    description: str               # Human-readable purpose
    
    # Temporal bounds
    created_at: int                # Unix timestamp
    expires_at: int                # Unix timestamp
    
    # Signature (filled after signing)
    signature: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at
    
    def to_eip712_message(self) -> dict:
        """Convert mandate to EIP-712 typed data for signing."""
        return {
            "types": {
                "Mandate": [
                    {"name": "mandateId", "type": "string"},
                    {"name": "delegator", "type": "address"},
                    {"name": "delegate", "type": "address"},
                    {"name": "maxTotalUsd", "type": "uint256"},
                    {"name": "maxPerTxUsd", "type": "uint256"},
                    {"name": "dailyLimitUsd", "type": "uint256"},
                    {"name": "description", "type": "string"},
                    {"name": "createdAt", "type": "uint256"},
                    {"name": "expiresAt", "type": "uint256"},
                ],
            },
            "primaryType": "Mandate",
            "domain": TRUSTEE_DOMAIN,
            "message": {
                "mandateId": self.mandate_id,
                "delegator": self.delegator_address,
                "delegate": self.delegate_address,
                "maxTotalUsd": _usd_to_micros(self.spending_limit.max_total_usd),
                "maxPerTxUsd": _usd_to_micros(self.spending_limit.max_per_tx_usd),
                "dailyLimitUsd": _usd_to_micros(self.spending_limit.daily_limit_usd or 0),
                "description": self.description,
                "createdAt": self.created_at,
                "expiresAt": self.expires_at,
            },
        }
    
    def to_dict(self) -> dict:
        """Serialize mandate for storage/transmission."""
        d = asdict(self)
        d["spending_limit"] = asdict(self.spending_limit)
        return d
    
    @classmethod
    def from_dict(cls, d: dict) -> Mandate:
        """Deserialize mandate from storage."""
        sl = SpendingLimit(**d.pop("spending_limit"))
        return cls(spending_limit=sl, **d)


# ── Signing & verification ────────────────────────────────────────


def create_mandate(
    delegator_key: str,
    delegate_address: str,
    max_total_usd: float,
    max_per_tx_usd: float,
    duration_hours: float = 24.0,
    daily_limit_usd: Optional[float] = None,
    description: str = "General spending authorization",
    allowed_merchants: Optional[list[str]] = None,
    allowed_categories: Optional[list[str]] = None,
) -> Mandate:
    """
    Create and sign a new mandate.
    
    Args:
        delegator_key: Ethereum private key of the delegator (human).
                       In production, this comes from bagman session key,
                       NEVER stored in code or config files.
        delegate_address: Ethereum address of the delegate (agent).
        max_total_usd: Maximum total USD the agent can spend.
        max_per_tx_usd: Maximum per-transaction USD.
        duration_hours: How long the mandate is valid.
        daily_limit_usd: Optional daily spending cap.
        description: Human-readable description of the mandate's purpose.
    
    Returns:
        Signed Mandate object.
    """
    account = Account.from_key(delegator_key)
    now = int(time.time())
    
    spending_limit = SpendingLimit(
        max_total_usd=max_total_usd,
        max_per_tx_usd=max_per_tx_usd,
        daily_limit_usd=daily_limit_usd,
        allowed_merchants=allowed_merchants or [],
        allowed_categories=allowed_categories or [],
    )
    
    # Generate deterministic mandate ID from contents
    content_hash = hashlib.sha256(
        json.dumps({
            "delegator": account.address,
            "delegate": delegate_address,
            "max_total": max_total_usd,
            "max_per_tx": max_per_tx_usd,
            "created": now,
        }, sort_keys=True).encode()
    ).hexdigest()[:16]
    
    mandate = Mandate(
        mandate_id=f"mandate-{content_hash}",
        delegator_address=account.address,
        delegate_address=delegate_address,
        spending_limit=spending_limit,
        description=description,
        created_at=now,
        expires_at=now + int(duration_hours * 3600),
    )
    
    # Sign with EIP-712
    typed_data = mandate.to_eip712_message()
    signed = Account.sign_typed_data(
        account.key,
        typed_data["domain"],
        typed_data["types"],
        typed_data["message"],
    )
    mandate.signature = signed.signature.hex()
    
    return mandate


def verify_mandate(mandate: Mandate) -> tuple[bool, str]:
    """
    Verify a mandate's signature and validity.
    
    Returns:
        (is_valid, reason) tuple.
    """
    if mandate.signature is None:
        return False, "Mandate is unsigned"
    
    if mandate.is_expired:
        return False, f"Mandate expired at {mandate.expires_at}"
    
    # Recover signer from EIP-712 signature
    typed_data = mandate.to_eip712_message()
    
    try:
        signable = encode_typed_data(
            typed_data["domain"],
            typed_data["types"],
            typed_data["message"],
        )
        recovered = Account.recover_message(
            signable,
            signature=bytes.fromhex(mandate.signature),
        )
    except Exception as e:
        return False, f"Signature verification failed: {e}"
    
    if recovered.lower() != mandate.delegator_address.lower():
        return False, (
            f"Signer mismatch: expected {mandate.delegator_address}, "
            f"got {recovered}"
        )
    
    return True, "Valid mandate"


# ── Helpers ───────────────────────────────────────────────────────

def _usd_to_micros(usd: float) -> int:
    """Convert USD to micro-dollars for uint256 representation."""
    return int(usd * 1_000_000)
