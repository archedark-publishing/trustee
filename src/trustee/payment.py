"""
Payment execution via x402 protocol.

Flow:
1. Verify mandate signature/expiry/network
2. Enforce merchant/category policy
3. Atomically authorize+reserve budget
4. Execute payment
5. Finalize budget reservation and audit
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from .audit import AuditTrail, EventType
from .budget import BudgetTracker
from .mandate import Mandate, verify_mandate

try:
    from .x402_client import X402PaymentClient
except ImportError:
    X402PaymentClient = None  # type: ignore


@dataclass
class PaymentRequest:
    """A request to make a payment."""

    mandate_id: str
    amount_usd: float
    merchant: str
    description: str
    merchant_endpoint: Optional[str] = None
    category: Optional[str] = None
    network: Optional[str] = None
    idempotency_key: Optional[str] = None


@dataclass
class PaymentResult:
    """Result of a payment attempt."""

    success: bool
    tx_id: Optional[str] = None
    x402_payment_id: Optional[str] = None
    reason: Optional[str] = None
    amount_usd: float = 0.0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "tx_id": self.tx_id,
            "x402_payment_id": self.x402_payment_id,
            "reason": self.reason,
            "amount_usd": self.amount_usd,
        }


class PaymentExecutor:
    """Orchestrates the full payment flow."""

    def __init__(
        self,
        budget: BudgetTracker,
        audit: AuditTrail,
        dry_run: bool = False,
        x402_client: Optional[X402PaymentClient] = None,
    ):
        self.budget = budget
        self.audit = audit
        self.dry_run = dry_run
        self.x402_client = x402_client

    def execute(self, mandate: Mandate, request: PaymentRequest) -> PaymentResult:
        valid, reason = verify_mandate(mandate)
        self.audit.log(
            EventType.MANDATE_VERIFIED,
            mandate_id=mandate.mandate_id,
            delegator=mandate.delegator_address,
            delegate=mandate.delegate_address,
            success=valid,
            reason=reason,
        )
        if not valid:
            return PaymentResult(success=False, reason=f"Invalid mandate: {reason}")
        if request.mandate_id != mandate.mandate_id:
            return PaymentResult(success=False, reason="Mandate ID mismatch", amount_usd=request.amount_usd)

        active_network = request.network or _infer_network(self.x402_client) or mandate.network
        if active_network != mandate.network:
            return PaymentResult(
                success=False,
                reason=f"Mandate network {mandate.network} does not match active network {active_network}",
                amount_usd=request.amount_usd,
            )

        merchant_ok, merchant_reason = _enforce_merchant_category_policy(mandate, request)
        if not merchant_ok:
            self.audit.log(
                EventType.SPENDING_DENIED,
                mandate_id=mandate.mandate_id,
                amount_usd=request.amount_usd,
                merchant=request.merchant,
                success=False,
                reason=merchant_reason,
            )
            return PaymentResult(success=False, reason=merchant_reason, amount_usd=request.amount_usd)

        intent_id = request.idempotency_key or _payment_intent_key(mandate.mandate_id, request)
        tx_id = _tx_id_from_intent(intent_id)

        self.audit.log(
            EventType.PAYMENT_INITIATED,
            mandate_id=mandate.mandate_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            details={
                "tx_id": tx_id,
                "dry_run": self.dry_run,
                "idempotency_key": intent_id,
                "network": active_network,
            },
        )

        reservation = self.budget.authorize_and_reserve(
            mandate_id=mandate.mandate_id,
            tx_id=tx_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            description=request.description,
            max_total_usd=mandate.spending_limit.max_total_usd,
            max_per_tx_usd=mandate.spending_limit.max_per_tx_usd,
            daily_limit_usd=mandate.spending_limit.daily_limit_usd,
            idempotency_key=intent_id,
            category=request.category,
            merchant_endpoint=request.merchant_endpoint,
        )
        if not reservation.allowed or reservation.tx is None:
            self.audit.log(
                EventType.SPENDING_DENIED,
                mandate_id=mandate.mandate_id,
                amount_usd=request.amount_usd,
                merchant=request.merchant,
                success=False,
                reason=reservation.reason,
            )
            return PaymentResult(
                success=False,
                reason=f"Budget check failed: {reservation.reason}",
                amount_usd=request.amount_usd,
            )
        if reservation.duplicate and reservation.tx.status == "completed":
            self.audit.log(
                EventType.PAYMENT_COMPLETED,
                mandate_id=mandate.mandate_id,
                amount_usd=request.amount_usd,
                merchant=request.merchant,
                details={"tx_id": reservation.tx.tx_id, "idempotency_key": intent_id, "duplicate": True},
            )
            return PaymentResult(
                success=True,
                tx_id=reservation.tx.tx_id,
                x402_payment_id=reservation.tx.x402_payment_id,
                amount_usd=reservation.tx.amount_usd,
            )
        if reservation.duplicate and reservation.tx.status == "pending":
            return PaymentResult(
                success=False,
                tx_id=reservation.tx.tx_id,
                reason="Payment with this idempotency key is already in progress",
                amount_usd=reservation.tx.amount_usd,
            )

        self.audit.log(
            EventType.SPENDING_CHECK,
            mandate_id=mandate.mandate_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            success=True,
            details={"reserved_tx_id": tx_id, "idempotency_key": intent_id},
        )

        x402_id: Optional[str] = None
        payment_error: Optional[str] = None
        try:
            if self.dry_run:
                x402_id = f"dry-run-{tx_id}"
            elif self.x402_client and request.merchant_endpoint:
                payee_allowlist = [
                    m for m in mandate.spending_limit.allowed_merchants if m.lower().startswith("0x")
                ]
                x402_result = self.x402_client.pay(
                    url=request.merchant_endpoint,
                    method="GET",
                    expected_amount_usd=request.amount_usd,
                    allowed_networks=[mandate.network],
                    allowed_payees=payee_allowlist or None,
                    idempotency_key=intent_id,
                )
                if not x402_result.success:
                    payment_error = f"x402 payment failed: {x402_result.error}"
                else:
                    x402_id = x402_result.payment_id or f"x402-{tx_id}"
            else:
                x402_id = _mock_x402_payment(request, tx_id=tx_id)
        except Exception as e:
            payment_error = f"Payment execution error: {type(e).__name__}: {e}"

        if payment_error is not None:
            self.budget.finalize_transaction(tx_id=tx_id, success=False)
            self.audit.log(
                EventType.PAYMENT_FAILED,
                mandate_id=mandate.mandate_id,
                amount_usd=request.amount_usd,
                merchant=request.merchant,
                success=False,
                reason=payment_error,
                details={"tx_id": tx_id, "idempotency_key": intent_id},
            )
            return PaymentResult(
                success=False,
                tx_id=tx_id,
                reason=payment_error,
                amount_usd=request.amount_usd,
            )

        finalized = self.budget.finalize_transaction(
            tx_id=tx_id,
            success=True,
            x402_payment_id=x402_id,
        )
        self.audit.log(
            EventType.PAYMENT_COMPLETED,
            mandate_id=mandate.mandate_id,
            amount_usd=finalized.amount_usd,
            merchant=request.merchant,
            details={
                "tx_id": finalized.tx_id,
                "x402_payment_id": finalized.x402_payment_id,
                "dry_run": self.dry_run,
                "idempotency_key": intent_id,
            },
        )
        return PaymentResult(
            success=True,
            tx_id=finalized.tx_id,
            x402_payment_id=finalized.x402_payment_id,
            amount_usd=finalized.amount_usd,
        )


def _infer_network(client: Optional[X402PaymentClient]) -> Optional[str]:
    if client is None:
        return None
    cfg = getattr(client, "config", None)
    if cfg is None:
        return None
    network = getattr(cfg, "network", None)
    return network.value if hasattr(network, "value") else network


def _enforce_merchant_category_policy(mandate: Mandate, request: PaymentRequest) -> tuple[bool, str]:
    allowed_merchants = [m.lower() for m in mandate.spending_limit.allowed_merchants]
    if allowed_merchants:
        merchant_candidates = {request.merchant.lower()}
        if request.merchant_endpoint:
            endpoint_host = urlparse(request.merchant_endpoint).netloc.lower()
            if endpoint_host:
                merchant_candidates.add(endpoint_host)
        if not merchant_candidates.intersection(set(allowed_merchants)):
            return False, "Merchant is not in mandate allowlist"

    allowed_categories = [c.lower() for c in mandate.spending_limit.allowed_categories]
    if allowed_categories:
        if not request.category:
            return False, "Payment category required by mandate allowlist"
        if request.category.lower() not in set(allowed_categories):
            return False, "Category is not in mandate allowlist"
    return True, "OK"


def _payment_intent_key(mandate_id: str, request: PaymentRequest) -> str:
    payload = json.dumps(
        {
            "mandate_id": mandate_id,
            "amount_usd": round(request.amount_usd, 6),
            "merchant": request.merchant.lower(),
            "merchant_endpoint": (request.merchant_endpoint or "").lower(),
            "description": request.description,
            "category": (request.category or "").lower(),
            "network": request.network or "",
        },
        sort_keys=True,
    )
    digest = hashlib.sha256(payload.encode()).hexdigest()[:24]
    return f"intent-{digest}"


def _tx_id_from_intent(intent_id: str) -> str:
    return f"tx-{hashlib.sha256(intent_id.encode()).hexdigest()[:16]}"


def _mock_x402_payment(request: PaymentRequest, tx_id: str) -> str:
    return f"mock-x402-{hashlib.sha256(f'{tx_id}:{time.time()}'.encode()).hexdigest()[:8]}"
