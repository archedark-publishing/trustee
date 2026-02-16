"""
Mandate creation, signing, and verification.

A Mandate is a cryptographically signed authorization that defines
what an agent is allowed to spend.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from .money import limit_usd_to_micros


DEFAULT_NETWORK = "eip155:8453"

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_CAIP_NETWORK_RE = re.compile(r"^eip155:(\d+)$")
_CAIP_ERC20_ASSET_RE = re.compile(r"^eip155:(\d+)/erc20:(0x[a-fA-F0-9]{40})$")


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


# ---------------------------------------------------------------------------
# AP2 mandate helpers (Phase 1)
# ---------------------------------------------------------------------------


AP2_SCHEMA_VERSION = "1"
AP2_DOMAIN_NAME = "Trustee AP2"
AP2_DOMAIN_VERSION = "1"


class AP2MandateStatus(str, Enum):
    DRAFT = "draft"
    PENDING_ON_CHAIN = "pending_on_chain"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    FAILED = "failed"


@dataclass
class AP2Mandate:
    """Canonical AP2 mandate payload stored locally and referenced on-chain."""

    mandate_hash: str
    payload_hash: str
    metadata_uri: str
    issuer: str
    agent: str
    network: str
    asset_id: str
    max_amount_per_tx: int
    max_amount_per_day: int
    allowed_recipients: list[str]
    expires_at: int
    nonce: int
    eip712_data: dict[str, Any]
    issuer_signature: str
    issued_at: int
    status: str = AP2MandateStatus.DRAFT.value
    schema_version: str = AP2_SCHEMA_VERSION
    chain_tx_hash: Optional[str] = None
    chain_block_number: Optional[int] = None
    failure_reason: Optional[str] = None

    @property
    def chain_id(self) -> int:
        return _network_to_chain_id(self.network)

    @property
    def is_expired(self) -> bool:
        return self.expires_at != 0 and int(time.time()) >= self.expires_at

    def core_payload(self) -> dict[str, Any]:
        return ap2_core_payload(
            schema_version=self.schema_version,
            metadata_uri=self.metadata_uri,
            issuer=self.issuer,
            agent=self.agent,
            network=self.network,
            asset_id=self.asset_id,
            max_amount_per_tx=self.max_amount_per_tx,
            max_amount_per_day=self.max_amount_per_day,
            allowed_recipients=self.allowed_recipients,
            expires_at=self.expires_at,
            nonce=self.nonce,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mandate_hash": self.mandate_hash,
            "payload_hash": self.payload_hash,
            "metadata_uri": self.metadata_uri,
            "issuer": self.issuer,
            "agent": self.agent,
            "network": self.network,
            "asset_id": self.asset_id,
            "max_amount_per_tx": str(self.max_amount_per_tx),
            "max_amount_per_day": str(self.max_amount_per_day),
            "allowed_recipients": list(self.allowed_recipients),
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "eip712_data": self.eip712_data,
            "issuer_signature": self.issuer_signature,
            "issued_at": self.issued_at,
            "status": self.status,
            "chain_tx_hash": self.chain_tx_hash,
            "chain_block_number": self.chain_block_number,
            "failure_reason": self.failure_reason,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AP2Mandate":
        data = dict(payload)
        return cls(
            schema_version=str(data.get("schema_version", AP2_SCHEMA_VERSION)),
            mandate_hash=_normalize_hex32(data["mandate_hash"], "mandate_hash"),
            payload_hash=_normalize_hex32(data["payload_hash"], "payload_hash"),
            metadata_uri=str(data.get("metadata_uri", "")),
            issuer=normalize_address(str(data["issuer"])),
            agent=normalize_address(str(data["agent"])),
            network=normalize_caip2_network(str(data["network"])),
            asset_id=validate_caip19_asset_id(str(data["asset_id"])),
            max_amount_per_tx=_parse_base_units(data["max_amount_per_tx"], "max_amount_per_tx"),
            max_amount_per_day=_parse_base_units(data["max_amount_per_day"], "max_amount_per_day"),
            allowed_recipients=normalize_recipient_allowlist(data.get("allowed_recipients", [])),
            expires_at=int(data["expires_at"]),
            nonce=int(data["nonce"]),
            eip712_data=dict(data["eip712_data"]),
            issuer_signature=_normalize_hex(data["issuer_signature"], "issuer_signature"),
            issued_at=int(data["issued_at"]),
            status=str(data.get("status", AP2MandateStatus.DRAFT.value)),
            chain_tx_hash=data.get("chain_tx_hash"),
            chain_block_number=(
                int(data["chain_block_number"]) if data.get("chain_block_number") is not None else None
            ),
            failure_reason=data.get("failure_reason"),
        )


def normalize_address(address: str) -> str:
    """Normalize Ethereum addresses to lower-case hex."""
    candidate = address.strip()
    if candidate.startswith(("0X", "0x")):
        candidate = "0x" + candidate[2:]
    if not _ADDRESS_RE.match(candidate):
        raise ValueError(f"Invalid Ethereum address: {address}")
    return "0x" + candidate[2:].lower()


def normalize_caip2_network(network: str) -> str:
    """Validate and normalize CAIP-2 network identifiers."""
    match = _CAIP_NETWORK_RE.match(network.strip())
    if match is None:
        raise ValueError(f"Invalid CAIP-2 network identifier: {network}")
    return f"eip155:{int(match.group(1))}"


def validate_caip19_asset_id(asset_id: str) -> str:
    """Validate and normalize CAIP-19 ERC-20 asset IDs."""
    match = _CAIP_ERC20_ASSET_RE.match(asset_id.strip())
    if match is None:
        raise ValueError(f"Invalid CAIP-19 ERC-20 asset identifier: {asset_id}")
    chain_id = int(match.group(1))
    token_address = normalize_address(match.group(2))
    return f"eip155:{chain_id}/erc20:{token_address}"


def normalize_recipient_allowlist(recipients: list[str]) -> list[str]:
    """Normalize recipient allowlist and enforce deterministic ordering."""
    normalized = [normalize_address(str(item)) for item in recipients]
    return sorted(set(normalized))


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON using deterministic ordering and no insignificant whitespace."""
    normalized = _normalize_for_canonical_json(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_json_hash(value: Any) -> str:
    """Return keccak256 hash of canonical JSON bytes."""
    return "0x" + keccak(canonical_json_bytes(value)).hex()


def ap2_core_payload(
    *,
    schema_version: str,
    metadata_uri: str,
    issuer: str,
    agent: str,
    network: str,
    asset_id: str,
    max_amount_per_tx: int,
    max_amount_per_day: int,
    allowed_recipients: list[str],
    expires_at: int,
    nonce: int,
) -> dict[str, Any]:
    if expires_at < 0:
        raise ValueError("expires_at must be >= 0")
    if nonce < 0:
        raise ValueError("nonce must be >= 0")

    return {
        "schema_version": str(schema_version),
        "metadata_uri": str(metadata_uri),
        "issuer": normalize_address(issuer),
        "agent": normalize_address(agent),
        "network": normalize_caip2_network(network),
        "asset_id": validate_caip19_asset_id(asset_id),
        "max_amount_per_tx": str(_parse_base_units(max_amount_per_tx, "max_amount_per_tx")),
        "max_amount_per_day": str(_parse_base_units(max_amount_per_day, "max_amount_per_day")),
        "allowed_recipients": normalize_recipient_allowlist(allowed_recipients),
        "expires_at": int(expires_at),
        "nonce": int(nonce),
    }


def compute_ap2_payload_hash(payload: Mapping[str, Any]) -> str:
    """Compute canonical payload hash for AP2 core payload."""
    canonical = ap2_core_payload(
        schema_version=str(payload["schema_version"]),
        metadata_uri=str(payload.get("metadata_uri", "")),
        issuer=str(payload["issuer"]),
        agent=str(payload["agent"]),
        network=str(payload["network"]),
        asset_id=str(payload["asset_id"]),
        max_amount_per_tx=_parse_base_units(payload["max_amount_per_tx"], "max_amount_per_tx"),
        max_amount_per_day=_parse_base_units(payload["max_amount_per_day"], "max_amount_per_day"),
        allowed_recipients=list(payload.get("allowed_recipients", [])),
        expires_at=int(payload["expires_at"]),
        nonce=int(payload["nonce"]),
    )
    return canonical_json_hash(canonical)


def canonicalize_ap2_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize AP2 payload fields into canonical form."""
    return ap2_core_payload(
        schema_version=str(payload["schema_version"]),
        metadata_uri=str(payload.get("metadata_uri", "")),
        issuer=str(payload["issuer"]),
        agent=str(payload["agent"]),
        network=str(payload["network"]),
        asset_id=str(payload["asset_id"]),
        max_amount_per_tx=_parse_base_units(payload["max_amount_per_tx"], "max_amount_per_tx"),
        max_amount_per_day=_parse_base_units(payload["max_amount_per_day"], "max_amount_per_day"),
        allowed_recipients=list(payload.get("allowed_recipients", [])),
        expires_at=int(payload["expires_at"]),
        nonce=int(payload["nonce"]),
    )


def build_ap2_eip712_data(
    *,
    agent: str,
    payload_hash: str,
    expires_at: int,
    nonce: int,
    chain_id: int,
    verifying_contract: str,
    domain_name: str = AP2_DOMAIN_NAME,
    domain_version: str = AP2_DOMAIN_VERSION,
) -> dict[str, Any]:
    normalized_agent = normalize_address(agent)
    normalized_hash = _normalize_hex32(payload_hash, "payload_hash")
    normalized_contract = normalize_address(verifying_contract)
    if expires_at < 0:
        raise ValueError("expires_at must be >= 0")
    if nonce < 0:
        raise ValueError("nonce must be >= 0")

    return {
        "domain": {
            "name": domain_name,
            "version": domain_version,
            "chainId": int(chain_id),
            "verifyingContract": normalized_contract,
        },
        "types": {
            "Mandate": [
                {"name": "agent", "type": "address"},
                {"name": "payloadHash", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
            ],
        },
        "primaryType": "Mandate",
        "message": {
            "agent": normalized_agent,
            "payloadHash": normalized_hash,
            "expiresAt": int(expires_at),
            "nonce": int(nonce),
        },
    }


def ap2_mandate_hash(eip712_data: Mapping[str, Any]) -> str:
    """Compute EIP-712 digest used as mandate hash."""
    signable = encode_typed_data(
        eip712_data["domain"],
        eip712_data["types"],
        eip712_data["message"],
    )
    digest = keccak(b"\x19" + signable.version + signable.header + signable.body)
    return "0x" + digest.hex()


def create_ap2_mandate(
    *,
    issuer_key: str,
    agent: str,
    asset_id: str,
    max_amount_per_tx: int,
    max_amount_per_day: int,
    allowed_recipients: Optional[list[str]] = None,
    expires_at: int = 0,
    nonce: int = 0,
    metadata_uri: str = "",
    network: str = DEFAULT_NETWORK,
    verifying_contract: str = "0x0000000000000000000000000000000000000000",
    issued_at: Optional[int] = None,
) -> AP2Mandate:
    """Create and sign a canonical AP2 mandate."""
    now = int(time.time()) if issued_at is None else int(issued_at)
    account = Account.from_key(issuer_key)
    normalized_network = normalize_caip2_network(network)
    normalized_issuer = normalize_address(account.address)
    normalized_agent = normalize_address(agent)

    core = ap2_core_payload(
        schema_version=AP2_SCHEMA_VERSION,
        metadata_uri=metadata_uri,
        issuer=normalized_issuer,
        agent=normalized_agent,
        network=normalized_network,
        asset_id=asset_id,
        max_amount_per_tx=max_amount_per_tx,
        max_amount_per_day=max_amount_per_day,
        allowed_recipients=allowed_recipients or [],
        expires_at=int(expires_at),
        nonce=int(nonce),
    )
    payload_hash = canonical_json_hash(core)
    eip712_data = build_ap2_eip712_data(
        agent=normalized_agent,
        payload_hash=payload_hash,
        expires_at=int(expires_at),
        nonce=int(nonce),
        chain_id=_network_to_chain_id(normalized_network),
        verifying_contract=verifying_contract,
    )
    signed = Account.sign_typed_data(
        account.key,
        eip712_data["domain"],
        eip712_data["types"],
        eip712_data["message"],
    )
    signature = "0x" + signed.signature.hex()
    mandate_hash = ap2_mandate_hash(eip712_data)

    return AP2Mandate(
        mandate_hash=mandate_hash,
        payload_hash=payload_hash,
        metadata_uri=str(metadata_uri),
        issuer=normalized_issuer,
        agent=normalized_agent,
        network=normalized_network,
        asset_id=core["asset_id"],
        max_amount_per_tx=int(core["max_amount_per_tx"]),
        max_amount_per_day=int(core["max_amount_per_day"]),
        allowed_recipients=list(core["allowed_recipients"]),
        expires_at=int(core["expires_at"]),
        nonce=int(core["nonce"]),
        eip712_data=eip712_data,
        issuer_signature=signature,
        issued_at=now,
        status=AP2MandateStatus.DRAFT.value,
        schema_version=AP2_SCHEMA_VERSION,
    )


def verify_ap2_mandate(
    mandate: AP2Mandate,
    *,
    trusted_issuers: Optional[set[str]] = None,
    now: Optional[int] = None,
) -> tuple[bool, str]:
    """Verify AP2 payload integrity, EIP-712 signature, and trusted issuer policy."""
    try:
        canonical = mandate.core_payload()
        expected_payload_hash = canonical_json_hash(canonical)
        if _normalize_hex32(mandate.payload_hash, "payload_hash") != expected_payload_hash:
            return False, "Payload hash mismatch"

        if mandate.expires_at < 0:
            return False, "Invalid expires_at"
        if mandate.expires_at != 0 and int(now or time.time()) >= mandate.expires_at:
            return False, f"Mandate expired at {mandate.expires_at}"

        message = mandate.eip712_data.get("message", {})
        if normalize_address(str(message.get("agent", ""))) != mandate.agent:
            return False, "EIP-712 message agent mismatch"
        if _normalize_hex32(str(message.get("payloadHash", "")), "payloadHash") != mandate.payload_hash:
            return False, "EIP-712 message payload hash mismatch"
        if int(message.get("expiresAt", -1)) != mandate.expires_at:
            return False, "EIP-712 message expiresAt mismatch"
        if int(message.get("nonce", -1)) != mandate.nonce:
            return False, "EIP-712 message nonce mismatch"

        signable = encode_typed_data(
            mandate.eip712_data["domain"],
            mandate.eip712_data["types"],
            mandate.eip712_data["message"],
        )
        recovered = Account.recover_message(
            signable,
            signature=bytes.fromhex(_strip_0x(mandate.issuer_signature)),
        )
        if normalize_address(recovered) != mandate.issuer:
            return False, "Issuer signature mismatch"

        expected_mandate_hash = ap2_mandate_hash(mandate.eip712_data)
        if _normalize_hex32(mandate.mandate_hash, "mandate_hash") != expected_mandate_hash:
            return False, "Mandate hash mismatch"

        if trusted_issuers is not None:
            normalized_trusted = {normalize_address(addr) for addr in trusted_issuers}
            if mandate.issuer not in normalized_trusted:
                return False, "Issuer is not trusted for this agent"
    except Exception as exc:
        return False, f"AP2 verification failed: {exc}"

    return True, "Valid AP2 mandate"


def _parse_base_units(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer base-unit value")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip() and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        raise ValueError(f"{field_name} must be an integer base-unit value")
    if parsed <= 0:
        raise ValueError(f"{field_name} must be > 0")
    return parsed


def _normalize_for_canonical_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _normalize_for_canonical_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_for_canonical_json(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_for_canonical_json(item) for item in value]
    if isinstance(value, float):
        raise ValueError("Floats are not allowed in canonical AP2 payloads")
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise ValueError(f"Unsupported JSON canonicalization value type: {type(value).__name__}")


def _normalize_hex(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a hex string")
    candidate = value.strip().lower()
    if candidate.startswith("0x"):
        hex_part = candidate[2:]
    else:
        hex_part = candidate
    if not hex_part or any(ch not in "0123456789abcdef" for ch in hex_part):
        raise ValueError(f"{field_name} must be a hex string")
    return "0x" + hex_part


def _normalize_hex32(value: Any, field_name: str) -> str:
    normalized = _normalize_hex(value, field_name)
    if len(normalized) != 66:
        raise ValueError(f"{field_name} must be 32 bytes (0x + 64 hex chars)")
    return normalized


def _strip_0x(value: str) -> str:
    return value[2:] if value.lower().startswith("0x") else value
