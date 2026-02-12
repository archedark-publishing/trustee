"""Tests for tamper-evident audit trail behavior."""

import json

import pytest

from trustee.audit import AuditTrail, EventType


def test_audit_hash_chain_detects_tampering(tmp_path):
    trail = AuditTrail(
        path=tmp_path / "audit.jsonl",
        key_path=tmp_path / "secret" / "audit_hmac.key",
    )
    trail.log(EventType.MANDATE_CREATED, mandate_id="m-1", success=True)
    trail.log(EventType.PAYMENT_COMPLETED, mandate_id="m-1", success=True, amount_usd=0.5)

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    first["amount_usd"] = 9999
    lines[0] = json.dumps(first, separators=(",", ":"))
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")

    with pytest.raises(RuntimeError, match="Audit chain broken"):
        trail.read_events()
