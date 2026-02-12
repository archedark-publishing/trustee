"""Tests for mandate creation, signing, and verification."""

import time
import pytest
from eth_account import Account

from trustee.mandate import (
    Mandate, SpendingLimit, create_mandate, verify_mandate,
)


@pytest.fixture
def delegator():
    return Account.create()


@pytest.fixture
def delegate():
    return Account.create()


@pytest.fixture
def mandate(delegator, delegate):
    return create_mandate(
        delegator_key=delegator.key.hex(),
        delegate_address=delegate.address,
        max_total_usd=10.0,
        max_per_tx_usd=2.0,
        daily_limit_usd=5.0,
        duration_hours=24.0,
        description="Test mandate",
        network="eip155:84532",
    )


class TestMandateCreation:
    def test_creates_signed_mandate(self, mandate, delegator, delegate):
        assert mandate.mandate_id.startswith("mandate-")
        assert mandate.delegator_address == delegator.address
        assert mandate.delegate_address == delegate.address
        assert mandate.signature is not None
        assert mandate.spending_limit.max_total_usd == 10.0
        assert mandate.spending_limit.max_per_tx_usd == 2.0
    
    def test_mandate_not_expired(self, mandate):
        assert not mandate.is_expired
    
    def test_mandate_expiry(self, delegator, delegate):
        m = create_mandate(
            delegator_key=delegator.key.hex(),
            delegate_address=delegate.address,
            max_total_usd=1.0,
            max_per_tx_usd=1.0,
            duration_hours=0.0,  # Expires immediately
        )
        assert m.is_expired


class TestMandateVerification:
    def test_valid_mandate(self, mandate):
        valid, reason = verify_mandate(mandate)
        assert valid, f"Expected valid but got: {reason}"
    
    def test_unsigned_mandate(self, delegator, delegate):
        m = Mandate(
            mandate_id="test",
            delegator_address=delegator.address,
            delegate_address=delegate.address,
            spending_limit=SpendingLimit(max_total_usd=1.0, max_per_tx_usd=1.0),
            description="unsigned",
            created_at=int(time.time()),
            expires_at=int(time.time()) + 3600,
        )
        valid, reason = verify_mandate(m)
        assert not valid
        assert "unsigned" in reason.lower()
    
    def test_tampered_mandate(self, mandate):
        # Tamper with the amount after signing
        mandate.spending_limit.max_total_usd = 999999.0
        valid, reason = verify_mandate(mandate)
        assert not valid
        assert "mismatch" in reason.lower() or "failed" in reason.lower()

    def test_tampered_allowlist_fails(self, mandate):
        mandate.spending_limit.allowed_merchants = ["evil.example.com"]
        valid, reason = verify_mandate(mandate)
        assert not valid
        assert "mismatch" in reason.lower() or "failed" in reason.lower()

    def test_tampered_network_fails(self, mandate):
        mandate.network = "eip155:8453"
        valid, reason = verify_mandate(mandate)
        assert not valid
        assert "mismatch" in reason.lower() or "failed" in reason.lower()
    
    def test_expired_mandate(self, delegator, delegate):
        m = create_mandate(
            delegator_key=delegator.key.hex(),
            delegate_address=delegate.address,
            max_total_usd=1.0,
            max_per_tx_usd=1.0,
            duration_hours=0.0,
        )
        valid, reason = verify_mandate(m)
        assert not valid
        assert "expired" in reason.lower()


class TestMandateSerialization:
    def test_roundtrip(self, mandate):
        d = mandate.to_dict()
        restored = Mandate.from_dict(d)
        assert restored.mandate_id == mandate.mandate_id
        assert restored.signature == mandate.signature
        assert restored.spending_limit.max_total_usd == mandate.spending_limit.max_total_usd
    
    def test_verify_after_roundtrip(self, mandate):
        d = mandate.to_dict()
        restored = Mandate.from_dict(d)
        valid, reason = verify_mandate(restored)
        assert valid, f"Expected valid after roundtrip but got: {reason}"
