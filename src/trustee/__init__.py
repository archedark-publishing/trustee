"""
Trustee — Delegated payment infrastructure for AI agents.

Cryptographically enforced spending delegation:
Human sets bounds → Agent operates within them → Full audit trail.
"""

__version__ = "0.1.0"

from .mandate import Mandate, SpendingLimit, create_mandate, verify_mandate
from .budget import BudgetTracker, BudgetState, Transaction
from .payment import PaymentExecutor, PaymentRequest, PaymentResult
from .audit import AuditTrail, EventType

__all__ = [
    "Mandate", "SpendingLimit", "create_mandate", "verify_mandate",
    "BudgetTracker", "BudgetState", "Transaction",
    "PaymentExecutor", "PaymentRequest", "PaymentResult",
    "AuditTrail", "EventType",
]
