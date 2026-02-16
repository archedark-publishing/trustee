"""
Trustee — Delegated payment infrastructure for AI agents.

Cryptographically enforced spending delegation:
Human sets bounds → Agent operates within them → Full audit trail.
"""

__version__ = "0.1.0"

from .mandate import (
    AP2Mandate,
    AP2MandateStatus,
    Mandate,
    SpendingLimit,
    canonicalize_ap2_payload,
    compute_ap2_payload_hash,
    create_ap2_mandate,
    create_mandate,
    verify_ap2_mandate,
    verify_mandate,
)
from .mandate_store import MandateStore
from .mandate_registry import LocalMandateRegistry, MandateRegistryStatus
from .mandate_validator import MandateValidator, TransactionIntent
from .budget import BudgetTracker, BudgetState, Transaction
from .payment import PaymentExecutor, PaymentRequest, PaymentResult
from .audit import AuditTrail, EventType

__all__ = [
    "Mandate", "SpendingLimit", "create_mandate", "verify_mandate",
    "AP2Mandate", "AP2MandateStatus", "create_ap2_mandate", "verify_ap2_mandate",
    "canonicalize_ap2_payload", "compute_ap2_payload_hash", "MandateStore",
    "LocalMandateRegistry", "MandateRegistryStatus", "MandateValidator", "TransactionIntent",
    "BudgetTracker", "BudgetState", "Transaction",
    "PaymentExecutor", "PaymentRequest", "PaymentResult",
    "AuditTrail", "EventType",
]
