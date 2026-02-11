"""
Audit trail for all Trustee operations.

Every mandate creation, verification, spending check, and payment
gets logged to an append-only JSONL file. This is the accountability
layer — if something goes wrong, the audit trail tells the story.

Design principles:
- Append-only (never modify existing entries)
- Human-readable (JSONL, one event per line)
- Complete (every operation logged, including failures)
- Timestamped (UTC for consistency)
"""

from __future__ import annotations

import json
import time
import os
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Optional, Any


DEFAULT_AUDIT_PATH = Path.home() / ".trustee" / "audit.jsonl"


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
    timestamp: float  # Unix timestamp (UTC)
    mandate_id: Optional[str] = None
    delegator: Optional[str] = None
    delegate: Optional[str] = None
    amount_usd: Optional[float] = None
    merchant: Optional[str] = None
    success: bool = True
    reason: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    
    def to_json(self) -> str:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(d, separators=(",", ":"))


class AuditTrail:
    """
    Append-only audit log for all Trustee operations.
    
    Usage:
        audit = AuditTrail()
        audit.log(EventType.MANDATE_CREATED, mandate_id="abc", ...)
    """
    
    def __init__(self, path: Optional[Path] = None):
        self.path = path or DEFAULT_AUDIT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
    
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
        """Log an event to the audit trail."""
        event = AuditEvent(
            event_type=event_type.value,
            timestamp=time.time(),
            mandate_id=mandate_id,
            delegator=delegator,
            delegate=delegate,
            amount_usd=amount_usd,
            merchant=merchant,
            success=success,
            reason=reason,
            details=details,
        )
        
        with open(self.path, "a") as f:
            f.write(event.to_json() + "\n")
            f.flush()
            os.fsync(f.fileno())
        
        return event
    
    def read_events(
        self,
        mandate_id: Optional[str] = None,
        event_type: Optional[EventType] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Read events from the audit trail with optional filters."""
        if not self.path.exists():
            return []
        
        events = []
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                
                if mandate_id and d.get("mandate_id") != mandate_id:
                    continue
                if event_type and d.get("event_type") != event_type.value:
                    continue
                
                events.append(AuditEvent(**{
                    k: v for k, v in d.items() 
                    if k in AuditEvent.__dataclass_fields__
                }))
        
        return events[-limit:]  # Return most recent
    
    def summary(self, mandate_id: Optional[str] = None) -> dict:
        """Get a summary of audit events."""
        events = self.read_events(mandate_id=mandate_id, limit=10000)
        
        by_type = {}
        for e in events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        
        failures = [e for e in events if not e.success]
        
        return {
            "total_events": len(events),
            "by_type": by_type,
            "failures": len(failures),
            "last_event": events[-1].to_json() if events else None,
        }
