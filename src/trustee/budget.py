"""
Budget tracking for mandate spending.

Mandates define *authorization* (what you're allowed to spend).
The budget tracker handles *state* (what you've actually spent).
These are deliberately separate concerns.

Storage: JSON file on disk. Simple, auditable, human-readable.
For production, this could be backed by a database, but for MVP
a JSON file with atomic writes is sufficient.
"""

from __future__ import annotations

import json
import time
import os
import fcntl
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


DEFAULT_BUDGET_DIR = Path.home() / ".trustee" / "budgets"


@dataclass
class Transaction:
    """A single spending event."""
    tx_id: str
    mandate_id: str
    amount_usd: float
    merchant: str
    description: str
    timestamp: int  # Unix timestamp
    status: str = "completed"  # completed, failed, refunded
    x402_payment_id: Optional[str] = None  # x402 payment reference
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: dict) -> Transaction:
        return cls(**d)


@dataclass
class BudgetState:
    """
    Tracks spending against a mandate's limits.
    
    Invariant: total_spent_usd <= mandate.spending_limit.max_total_usd
    """
    mandate_id: str
    total_spent_usd: float = 0.0
    daily_spent_usd: float = 0.0
    daily_reset_date: str = ""  # YYYY-MM-DD of last daily reset
    transaction_count: int = 0
    transactions: list[Transaction] = field(default_factory=list)
    last_updated: int = 0
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d["transactions"] = [t.to_dict() if isinstance(t, Transaction) else t 
                             for t in self.transactions]
        return d
    
    @classmethod
    def from_dict(cls, d: dict) -> BudgetState:
        txns = [Transaction.from_dict(t) for t in d.pop("transactions", [])]
        return cls(transactions=txns, **d)


class BudgetTracker:
    """
    Manages budget state for mandates.
    
    Uses file-level locking for concurrent access safety.
    Each mandate gets its own JSON file in the budget directory.
    """
    
    def __init__(self, budget_dir: Optional[Path] = None):
        self.budget_dir = budget_dir or DEFAULT_BUDGET_DIR
        self.budget_dir.mkdir(parents=True, exist_ok=True)
    
    def _state_path(self, mandate_id: str) -> Path:
        """Path to the budget state file for a mandate."""
        safe_id = mandate_id.replace("/", "_").replace("..", "_")
        return self.budget_dir / f"{safe_id}.json"
    
    def get_state(self, mandate_id: str) -> BudgetState:
        """Load current budget state for a mandate."""
        path = self._state_path(mandate_id)
        if not path.exists():
            return BudgetState(mandate_id=mandate_id)
        
        with open(path, "r") as f:
            return BudgetState.from_dict(json.load(f))
    
    def _save_state(self, state: BudgetState) -> None:
        """Atomically save budget state with file locking."""
        path = self._state_path(state.mandate_id)
        tmp_path = path.with_suffix(".tmp")
        
        state.last_updated = int(time.time())
        
        with open(tmp_path, "w") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(state.to_dict(), f, indent=2)
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        
        os.replace(tmp_path, path)  # Atomic rename
    
    def check_spending(
        self,
        mandate_id: str,
        amount_usd: float,
        max_total_usd: float,
        max_per_tx_usd: float,
        daily_limit_usd: Optional[float] = None,
    ) -> tuple[bool, str]:
        """
        Check if a proposed spend is within mandate limits.
        
        Returns:
            (allowed, reason) tuple.
        """
        if amount_usd <= 0:
            return False, "Amount must be positive"
        
        if amount_usd > max_per_tx_usd:
            return False, (
                f"Amount ${amount_usd:.2f} exceeds per-transaction "
                f"limit ${max_per_tx_usd:.2f}"
            )
        
        state = self.get_state(mandate_id)
        _maybe_reset_daily(state)
        
        remaining_total = max_total_usd - state.total_spent_usd
        if amount_usd > remaining_total:
            return False, (
                f"Amount ${amount_usd:.2f} exceeds remaining budget "
                f"${remaining_total:.2f} (spent ${state.total_spent_usd:.2f} "
                f"of ${max_total_usd:.2f})"
            )
        
        if daily_limit_usd is not None:
            remaining_daily = daily_limit_usd - state.daily_spent_usd
            if amount_usd > remaining_daily:
                return False, (
                    f"Amount ${amount_usd:.2f} exceeds remaining daily budget "
                    f"${remaining_daily:.2f} (spent ${state.daily_spent_usd:.2f} "
                    f"of ${daily_limit_usd:.2f} today)"
                )
        
        return True, "Within limits"
    
    def record_transaction(
        self,
        mandate_id: str,
        tx_id: str,
        amount_usd: float,
        merchant: str,
        description: str,
        x402_payment_id: Optional[str] = None,
    ) -> Transaction:
        """
        Record a completed transaction against a mandate's budget.
        
        This should only be called AFTER payment succeeds.
        """
        state = self.get_state(mandate_id)
        _maybe_reset_daily(state)
        
        tx = Transaction(
            tx_id=tx_id,
            mandate_id=mandate_id,
            amount_usd=amount_usd,
            merchant=merchant,
            description=description,
            timestamp=int(time.time()),
            x402_payment_id=x402_payment_id,
        )
        
        state.total_spent_usd += amount_usd
        state.daily_spent_usd += amount_usd
        state.transaction_count += 1
        state.transactions.append(tx)
        
        self._save_state(state)
        return tx
    
    def get_summary(self, mandate_id: str, max_total_usd: float) -> dict:
        """Get a human-readable budget summary."""
        state = self.get_state(mandate_id)
        _maybe_reset_daily(state)
        
        return {
            "mandate_id": mandate_id,
            "total_spent": f"${state.total_spent_usd:.2f}",
            "total_budget": f"${max_total_usd:.2f}",
            "remaining": f"${max_total_usd - state.total_spent_usd:.2f}",
            "utilization": f"{(state.total_spent_usd / max_total_usd * 100):.1f}%" if max_total_usd > 0 else "N/A",
            "transactions": state.transaction_count,
            "daily_spent": f"${state.daily_spent_usd:.2f}",
        }


def _maybe_reset_daily(state: BudgetState) -> None:
    """Reset daily spending if the date has changed."""
    today = time.strftime("%Y-%m-%d")
    if state.daily_reset_date != today:
        state.daily_spent_usd = 0.0
        state.daily_reset_date = today
