"""Tests for the payment execution flow."""

import pytest
from pathlib import Path
from eth_account import Account

from trustee.mandate import create_mandate
from trustee.budget import BudgetTracker
from trustee.audit import AuditTrail
from trustee.payment import PaymentExecutor, PaymentRequest


@pytest.fixture
def accounts():
    return Account.create(), Account.create()


@pytest.fixture
def mandate(accounts):
    delegator, delegate = accounts
    return create_mandate(
        delegator_key=delegator.key.hex(),
        delegate_address=delegate.address,
        max_total_usd=5.00,
        max_per_tx_usd=1.00,
        daily_limit_usd=3.00,
        duration_hours=24.0,
        description="Test spending",
        network="eip155:84532",
    )


@pytest.fixture
def executor(tmp_path):
    return PaymentExecutor(
        budget=BudgetTracker(budget_dir=tmp_path / "budgets"),
        audit=AuditTrail(path=tmp_path / "audit.jsonl"),
        dry_run=True,
    )


class TestPaymentFlow:
    def test_successful_payment(self, mandate, executor):
        result = executor.execute(mandate, PaymentRequest(
            mandate_id=mandate.mandate_id,
            amount_usd=0.50,
            merchant="OpenAI",
            description="API call",
        ))
        assert result.success
        assert result.tx_id is not None
        assert result.amount_usd == 0.50
    
    def test_over_per_tx_limit(self, mandate, executor):
        result = executor.execute(mandate, PaymentRequest(
            mandate_id=mandate.mandate_id,
            amount_usd=1.50,  # Over $1 limit
            merchant="Expensive",
            description="Too much",
        ))
        assert not result.success
        assert "per-transaction" in result.reason
    
    def test_budget_exhaustion(self, mandate, executor):
        # Daily limit is $3, so 3 payments of $0.90 = $2.70, then $0.90 more exceeds daily
        for i in range(3):
            result = executor.execute(mandate, PaymentRequest(
                mandate_id=mandate.mandate_id,
                amount_usd=0.90,
                merchant=f"Merchant{i}",
                description=f"Payment {i}",
            ))
            assert result.success, f"Payment {i} should succeed"
        
        # This should fail (would bring daily to $3.60 > $3.00)
        result = executor.execute(mandate, PaymentRequest(
            mandate_id=mandate.mandate_id,
            amount_usd=0.90,
            merchant="TooMuch",
            description="Should fail",
        ))
        assert not result.success
        assert "daily" in result.reason.lower()
    
    def test_audit_trail_recorded(self, mandate, executor, tmp_path):
        executor.execute(mandate, PaymentRequest(
            mandate_id=mandate.mandate_id,
            amount_usd=0.25,
            merchant="TestMerchant",
            description="Audit test",
        ))
        
        audit = AuditTrail(path=tmp_path / "audit.jsonl")
        events = audit.read_events(mandate_id=mandate.mandate_id)
        assert len(events) > 0
        event_types = [e.event_type for e in events]
        assert "mandate_verified" in event_types
        assert "payment_completed" in event_types

    def test_disallowed_merchant_denied(self, accounts, executor):
        delegator, delegate = accounts
        restricted = create_mandate(
            delegator_key=delegator.key.hex(),
            delegate_address=delegate.address,
            max_total_usd=5.0,
            max_per_tx_usd=1.0,
            duration_hours=24.0,
            allowed_merchants=["approved.example.com"],
        )
        result = executor.execute(
            restricted,
            PaymentRequest(
                mandate_id=restricted.mandate_id,
                amount_usd=0.25,
                merchant="RandomMerchant",
                merchant_endpoint="https://not-approved.example.com/pay",
                description="Should fail",
            ),
        )
        assert not result.success
        assert "Merchant" in (result.reason or "")

    def test_disallowed_category_denied(self, accounts, executor):
        delegator, delegate = accounts
        restricted = create_mandate(
            delegator_key=delegator.key.hex(),
            delegate_address=delegate.address,
            max_total_usd=5.0,
            max_per_tx_usd=1.0,
            duration_hours=24.0,
            allowed_categories=["infra"],
        )
        result = executor.execute(
            restricted,
            PaymentRequest(
                mandate_id=restricted.mandate_id,
                amount_usd=0.25,
                merchant="Approved",
                description="Should fail",
                category="marketing",
            ),
        )
        assert not result.success
        assert "Category" in (result.reason or "")

    def test_network_mismatch_denied(self, mandate, executor):
        result = executor.execute(
            mandate,
            PaymentRequest(
                mandate_id=mandate.mandate_id,
                amount_usd=0.25,
                merchant="OpenAI",
                description="network mismatch",
                network="eip155:8453",
            ),
        )
        assert not result.success
        assert "network" in (result.reason or "").lower()

    def test_idempotent_duplicate_returns_single_settlement(self, mandate, executor):
        req = PaymentRequest(
            mandate_id=mandate.mandate_id,
            amount_usd=0.25,
            merchant="OpenAI",
            description="idempotent",
            idempotency_key="intent-fixed",
        )
        first = executor.execute(mandate, req)
        second = executor.execute(mandate, req)
        assert first.success
        assert second.success
        assert first.tx_id == second.tx_id
