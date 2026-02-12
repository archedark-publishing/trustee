"""
Audit trail for all Trustee operations.

Events are append-only JSONL entries with an HMAC hash chain so
tampering is detected during reads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .storage import ensure_private_dir, ensure_private_file


DEFAULT_AUDIT_PATH = Path.home() / ".trustee" / "audit.jsonl"
DEFAULT_AUDIT_KEY_PATH = Path.home() / ".trustee-secrets" / "audit_hmac.key"


class EventType(str, Enum):
    MANDATE_CREATED = "mandate_created"
    MANDATE_VERIFIED = "mandate_verified"
    MANDATE_EXPIRED = "mandate_expired"
    MANDATE_REVOKED = "mandate_revoked"
    SPENDING_CHECK = "spending_check"
    SPENDING_DENIED = "spending_denied"
    PAYMENT_INITIATED = "payment_initiated"
    PAYMENT_COMPLETED = "payment_completed"
    PAYMENT_FAILED = "payment_failed"
    BUDGET_UPDATED = "budget_updated"
    KEY_REQUESTED = "key_requested"
    KEY_DENIED = "key_denied"


@dataclass
class AuditEvent:
    """A single audit trail entry."""

    event_type: str
    timestamp: float
    mandate_id: Optional[str] = None
    delegator: Optional[str] = None
    delegate: Optional[str] = None
    amount_usd: Optional[float] = None
    merchant: Optional[str] = None
    success: bool = True
    reason: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    prev_hash: Optional[str] = None
    event_hash: Optional[str] = None

    def to_json(self) -> str:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(d, separators=(",", ":"))


class AuditTrail:
    """Tamper-evident append-only audit log."""

    def __init__(
        self,
        path: Optional[Path] = None,
        key_path: Optional[Path] = None,
    ):
        self.path = path or DEFAULT_AUDIT_PATH
        self.key_path = key_path or DEFAULT_AUDIT_KEY_PATH

        ensure_private_dir(self.path.parent)
        ensure_private_dir(self.key_path.parent)
        ensure_private_file(self.path)
        ensure_private_file(self.key_path)

        self._hmac_key = self._load_or_create_key()
        self._last_hash = self._scan_last_hash()

    def _load_or_create_key(self) -> bytes:
        env_key = os.getenv("TRUSTEE_AUDIT_HMAC_KEY")
        if env_key:
            return env_key.encode()
        if self.key_path.exists() and self.key_path.stat().st_size > 0:
            return self.key_path.read_bytes().strip()
        key = secrets.token_hex(32).encode()
        self.key_path.write_bytes(key)
        ensure_private_file(self.key_path)
        return key

    def _scan_last_hash(self) -> str:
        if not self.path.exists():
            return ""
        last = ""
        with open(self.path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                event = json.loads(line)
                last = event.get("event_hash", "")
        return last

    def _event_hash(self, event_payload: dict, prev_hash: str) -> str:
        canonical = json.dumps(event_payload, sort_keys=True, separators=(",", ":"))
        digest = hmac.new(self._hmac_key, f"{prev_hash}|{canonical}".encode(), hashlib.sha256)
        return digest.hexdigest()

    def log(
        self,
        event_type: EventType,
        mandate_id: Optional[str] = None,
        delegator: Optional[str] = None,
        delegate: Optional[str] = None,
        amount_usd: Optional[float] = None,
        merchant: Optional[str] = None,
        success: bool = True,
        reason: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditEvent:
        base_payload = {
            "event_type": event_type.value,
            "timestamp": time.time(),
            "mandate_id": mandate_id,
            "delegator": delegator,
            "delegate": delegate,
            "amount_usd": amount_usd,
            "merchant": merchant,
            "success": success,
            "reason": reason,
            "details": details,
        }
        payload = {k: v for k, v in base_payload.items() if v is not None}
        prev_hash = self._last_hash
        current_hash = self._event_hash(payload, prev_hash)

        event = AuditEvent(
            **payload,
            prev_hash=prev_hash or None,
            event_hash=current_hash,
        )

        with open(self.path, "a") as f:
            f.write(event.to_json() + "\n")
            f.flush()
            os.fsync(f.fileno())
        ensure_private_file(self.path)

        self._last_hash = current_hash
        return event

    def read_events(
        self,
        mandate_id: Optional[str] = None,
        event_type: Optional[EventType] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        if not self.path.exists():
            return []

        events: list[AuditEvent] = []
        expected_prev = ""
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)

                payload = {
                    k: v
                    for k, v in raw.items()
                    if k not in {"prev_hash", "event_hash"}
                }
                prev_hash = raw.get("prev_hash", "") or ""
                event_hash = raw.get("event_hash", "") or ""
                if prev_hash != expected_prev:
                    raise RuntimeError("Audit chain broken: previous hash mismatch")
                expected_hash = self._event_hash(payload, prev_hash)
                if not hmac.compare_digest(expected_hash, event_hash):
                    raise RuntimeError("Audit chain broken: event hash mismatch")
                expected_prev = event_hash

                if mandate_id and raw.get("mandate_id") != mandate_id:
                    continue
                if event_type and raw.get("event_type") != event_type.value:
                    continue

                events.append(
                    AuditEvent(
                        **{
                            k: v
                            for k, v in raw.items()
                            if k in AuditEvent.__dataclass_fields__
                        }
                    )
                )

        self._last_hash = expected_prev
        return events[-limit:]

    def summary(self, mandate_id: Optional[str] = None) -> dict:
        events = self.read_events(mandate_id=mandate_id, limit=10000)
        by_type: dict[str, int] = {}
        for e in events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        failures = [e for e in events if not e.success]
        return {
            "total_events": len(events),
            "by_type": by_type,
            "failures": len(failures),
            "last_event": events[-1].to_json() if events else None,
        }
