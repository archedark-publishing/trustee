"""Tests for budget tracking."""

import pytest
from pathlib import Path
from eth_account import Account

from trustee.mandate import create_mandate
from trustee.budget import BudgetTracker


DELEGATOR = Account.create()
DELEGATE = Account.create()


def make_mandate(**kwargs):
    defaults = dict(
        delegator_key=DELEGATOR.key.hex(),
        delegate_address=DELEGATE.address,
        max_total_usd=100.0,
        max_per_tx_usd=10.0,
        duration_hours=24.0,
    )
    defaults.update(kwargs)
    return create_mandate(**defaults)


class TestBudgetTracker:
    def test_check_within_limits(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        mandate = make_mandate()
        
        ok, reason = tracker.check_spending(
            mandate.mandate_id, 5.0,
            mandate.spending_limit.max_total_usd,
            mandate.spending_limit.max_per_tx_usd,
        )
        assert ok
    
    def test_deny_over_per_tx_limit(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        mandate = make_mandate(max_per_tx_usd=10.0)
        
        ok, reason = tracker.check_spending(
            mandate.mandate_id, 15.0,
            mandate.spending_limit.max_total_usd,
            mandate.spending_limit.max_per_tx_usd,
        )
        assert not ok
        assert "per-transaction" in reason
    
    def test_deny_over_total_limit(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        mandate = make_mandate(max_total_usd=20.0, max_per_tx_usd=15.0)
        
        # Record first transaction
        tracker.record_transaction(
            mandate.mandate_id, "tx-1", 12.0, "merchant", "test"
        )
        
        # Check second - should fail
        ok, reason = tracker.check_spending(
            mandate.mandate_id, 12.0,
            mandate.spending_limit.max_total_usd,
            mandate.spending_limit.max_per_tx_usd,
        )
        assert not ok
        assert "remaining budget" in reason
    
    def test_deny_over_daily_limit(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        mandate = make_mandate(
            max_total_usd=100.0,
            max_per_tx_usd=10.0,
            daily_limit_usd=15.0,
        )
        
        # Record first transaction
        tracker.record_transaction(
            mandate.mandate_id, "tx-1", 10.0, "merchant", "test"
        )
        
        # Check second - should fail against daily limit
        ok, reason = tracker.check_spending(
            mandate.mandate_id, 10.0,
            mandate.spending_limit.max_total_usd,
            mandate.spending_limit.max_per_tx_usd,
            daily_limit_usd=mandate.spending_limit.daily_limit_usd,
        )
        assert not ok
        assert "daily" in reason
    
    def test_record_transaction(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        mandate = make_mandate()
        
        tx = tracker.record_transaction(
            mandate.mandate_id, "tx-1", 5.0, "openai", "API call"
        )
        assert tx.amount_usd == 5.0
        assert tx.merchant == "openai"
        
        state = tracker.get_state(mandate.mandate_id)
        assert state.total_spent_usd == 5.0
        assert state.transaction_count == 1
    
    def test_budget_summary(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        mandate = make_mandate(max_total_usd=100.0)
        
        tracker.record_transaction(
            mandate.mandate_id, "tx-1", 25.0, "merchant", "API calls"
        )
        tracker.record_transaction(
            mandate.mandate_id, "tx-2", 10.0, "merchant", "Data"
        )
        
        summary = tracker.get_summary(mandate.mandate_id, 100.0)
        assert summary["total_spent"] == "$35.00"
        assert summary["remaining"] == "$65.00"
        assert summary["transactions"] == 2
    
    def test_multiple_mandates_independent(self, tmp_path):
        tracker = BudgetTracker(tmp_path)
        # Use different amounts to ensure different mandate IDs
        mandate1 = make_mandate(max_total_usd=50.0, max_per_tx_usd=50.0)
        mandate2 = make_mandate(max_total_usd=30.0, max_per_tx_usd=30.0)
        
        tracker.record_transaction(
            mandate1.mandate_id, "tx-1", 40.0, "merchant", "big spend"
        )
        
        # Mandate 2 should be unaffected
        ok, _ = tracker.check_spending(
            mandate2.mandate_id, 25.0,
            mandate2.spending_limit.max_total_usd,
            mandate2.spending_limit.max_per_tx_usd,
        )
        assert ok
