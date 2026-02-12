"""
Mandate creation, signing, and verification.

A Mandate is a cryptographically signed authorization that defines
what an agent is allowed to spend.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

from eth_account import Account
from eth_account.messages import encode_typed_data

from .money import limit_usd_to_micros


DEFAULT_NETWORK = "eip155:84532"


class MandateStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EXHAUSTED = "exhausted"


@dataclass
class SpendingLimit:
    """Defines spending constraints within a mandate."""

    max_total_usd: float
    max_per_tx_usd: float
    daily_limit_usd: Optional[float] = None
    allowed_merchants: list[str] = field(default_factory=list)
    allowed_categories: list[str] = field(default_factory=list)


@dataclass
class Mandate:
    """A signed authorization from delegator to delegate."""

    mandate_id: str
    delegator_address: str
    delegate_address: str
    spending_limit: SpendingLimit
    description: str
    created_at: int
    expires_at: int
    network: str = DEFAULT_NETWORK
    signature: Optional[str] = None

    @property
    def chain_id(self) -> int:
        return _network_to_chain_id(self.network)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def _domain(self) -> dict:
        return {
            "name": "Trustee",
            "version": "2",
            "chainId": self.chain_id,
        }

    def to_eip712_message(self) -> dict:
        """Convert mandate to EIP-712 typed data for signing."""
        return {
            "types": {
                "Mandate": [
                    {"name": "mandateId", "type": "string"},
                    {"name": "delegator", "type": "address"},
                    {"name": "delegate", "type": "address"},
                    {"name": "network", "type": "string"},
                    {"name": "maxTotalUsd", "type": "uint256"},
                    {"name": "maxPerTxUsd", "type": "uint256"},
                    {"name": "dailyLimitUsd", "type": "uint256"},
                    {"name": "allowedMerchantsHash", "type": "bytes32"},
                    {"name": "allowedCategoriesHash", "type": "bytes32"},
                    {"name": "description", "type": "string"},
                    {"name": "createdAt", "type": "uint256"},
                    {"name": "expiresAt", "type": "uint256"},
                ],
            },
            "primaryType": "Mandate",
            "domain": self._domain(),
            "message": {
                "mandateId": self.mandate_id,
                "delegator": self.delegator_address,
                "delegate": self.delegate_address,
                "network": self.network,
                "maxTotalUsd": _usd_to_micros(self.spending_limit.max_total_usd),
                "maxPerTxUsd": _usd_to_micros(self.spending_limit.max_per_tx_usd),
                "dailyLimitUsd": _usd_to_micros(self.spending_limit.daily_limit_usd or 0),
                "allowedMerchantsHash": _allowlist_hash(self.spending_limit.allowed_merchants),
                "allowedCategoriesHash": _allowlist_hash(self.spending_limit.allowed_categories),
                "description": self.description,
                "createdAt": self.created_at,
                "expiresAt": self.expires_at,
            },
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["spending_limit"] = asdict(self.spending_limit)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Mandate:
        sl = SpendingLimit(**d.pop("spending_limit"))
        if "network" not in d:
            d["network"] = DEFAULT_NETWORK
        return cls(spending_limit=sl, **d)


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
    network: str = DEFAULT_NETWORK,
) -> Mandate:
    """Create and sign a new mandate."""
    account = Account.from_key(delegator_key)
    now = int(time.time())

    spending_limit = SpendingLimit(
        max_total_usd=max_total_usd,
        max_per_tx_usd=max_per_tx_usd,
        daily_limit_usd=daily_limit_usd,
        allowed_merchants=allowed_merchants or [],
        allowed_categories=allowed_categories or [],
    )

    content_hash = hashlib.sha256(
        json.dumps(
            {
                "delegator": account.address,
                "delegate": delegate_address,
                "network": network,
                "max_total_micros": _usd_to_micros(max_total_usd),
                "max_per_tx_micros": _usd_to_micros(max_per_tx_usd),
                "daily_limit_micros": _usd_to_micros(daily_limit_usd or 0),
                "allowed_merchants": sorted([m.lower() for m in spending_limit.allowed_merchants]),
                "allowed_categories": sorted([c.lower() for c in spending_limit.allowed_categories]),
                "created": now,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()[:16]

    mandate = Mandate(
        mandate_id=f"mandate-{content_hash}",
        delegator_address=account.address,
        delegate_address=delegate_address,
        spending_limit=spending_limit,
        description=description,
        created_at=now,
        expires_at=now + int(duration_hours * 3600),
        network=network,
    )

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
    """Verify a mandate's signature and validity."""
    if mandate.signature is None:
        return False, "Mandate is unsigned"
    if mandate.is_expired:
        return False, f"Mandate expired at {mandate.expires_at}"
    try:
        typed_data = mandate.to_eip712_message()
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
        return (
            False,
            f"Signer mismatch: expected {mandate.delegator_address}, got {recovered}",
        )
    return True, "Valid mandate"


def _network_to_chain_id(network: str) -> int:
    if not network.startswith("eip155:"):
        raise ValueError(f"Unsupported network format: {network}")
    try:
        return int(network.split(":", 1)[1])
    except ValueError as e:
        raise ValueError(f"Invalid network chain id: {network}") from e


def _allowlist_hash(values: list[str]) -> str:
    canonical = "\n".join(sorted(v.strip().lower() for v in values if v.strip()))
    return "0x" + hashlib.sha256(canonical.encode()).hexdigest()


def _usd_to_micros(usd: float) -> int:
    return limit_usd_to_micros(usd)
