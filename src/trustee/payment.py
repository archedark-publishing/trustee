"""
Payment execution via x402 protocol.

This module handles the actual money movement:
1. Verify mandate is valid
2. Check budget allows the spend
3. Execute x402 payment
4. Record transaction and audit

For MVP, the x402 payment layer is mocked. In production,
this calls Stripe's x402 endpoint to move USDC on Base.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional

from .mandate import Mandate, verify_mandate
from .budget import BudgetTracker
from .audit import AuditTrail, EventType

try:
    from .x402_client import X402PaymentClient, X402PaymentResult, X402Config, Network
except ImportError:
    X402PaymentClient = None  # type: ignore


@dataclass
class PaymentRequest:
    """A request to make a payment."""
    mandate_id: str
    amount_usd: float
    merchant: str
    description: str
    merchant_endpoint: Optional[str] = None  # x402 endpoint URL


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
    """
    Orchestrates the full payment flow.
    
    Mandate verification → Budget check → Payment → Record → Audit
    
    Usage:
        executor = PaymentExecutor(budget_tracker, audit_trail)
        mandate = load_mandate(...)  # From storage
        result = executor.execute(mandate, PaymentRequest(...))
    """
    
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
    
    def execute(
        self,
        mandate: Mandate,
        request: PaymentRequest,
    ) -> PaymentResult:
        """
        Execute a payment against a mandate.
        
        Steps:
        1. Verify mandate signature and expiry
        2. Check budget allows the spend
        3. Execute x402 payment (or mock)
        4. Record transaction in budget tracker
        5. Log everything to audit trail
        """
        # Step 1: Verify mandate
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
        
        # Step 2: Check budget
        allowed, budget_reason = self.budget.check_spending(
            mandate_id=mandate.mandate_id,
            amount_usd=request.amount_usd,
            max_total_usd=mandate.spending_limit.max_total_usd,
            max_per_tx_usd=mandate.spending_limit.max_per_tx_usd,
            daily_limit_usd=mandate.spending_limit.daily_limit_usd,
        )
        
        if not allowed:
            self.audit.log(
                EventType.SPENDING_DENIED,
                mandate_id=mandate.mandate_id,
                amount_usd=request.amount_usd,
                merchant=request.merchant,
                success=False,
                reason=budget_reason,
            )
            return PaymentResult(
                success=False,
                reason=f"Budget check failed: {budget_reason}",
                amount_usd=request.amount_usd,
            )
        
        self.audit.log(
            EventType.SPENDING_CHECK,
            mandate_id=mandate.mandate_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            success=True,
        )
        
        # Step 3: Execute payment
        tx_id = _generate_tx_id(mandate.mandate_id, request)
        
        self.audit.log(
            EventType.PAYMENT_INITIATED,
            mandate_id=mandate.mandate_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            details={"tx_id": tx_id, "dry_run": self.dry_run},
        )
        
        if self.dry_run:
            x402_id = f"dry-run-{tx_id}"
        elif self.x402_client and request.merchant_endpoint:
            # Real x402 payment via official SDK
            x402_result = self.x402_client.pay(
                url=request.merchant_endpoint,
                method="GET",
            )
            if not x402_result.success:
                self.audit.log(
                    EventType.PAYMENT_COMPLETED,
                    mandate_id=mandate.mandate_id,
                    amount_usd=request.amount_usd,
                    merchant=request.merchant,
                    success=False,
                    reason=f"x402 payment failed: {x402_result.error}",
                )
                return PaymentResult(
                    success=False,
                    tx_id=tx_id,
                    reason=f"x402 payment failed: {x402_result.error}",
                    amount_usd=request.amount_usd,
                )
            x402_id = x402_result.payment_id or f"x402-{tx_id}"
        else:
            x402_id = _mock_x402_payment(request)
        
        # Step 4: Record transaction
        tx = self.budget.record_transaction(
            mandate_id=mandate.mandate_id,
            tx_id=tx_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            description=request.description,
            x402_payment_id=x402_id,
        )
        
        # Step 5: Audit completion
        self.audit.log(
            EventType.PAYMENT_COMPLETED,
            mandate_id=mandate.mandate_id,
            amount_usd=request.amount_usd,
            merchant=request.merchant,
            details={
                "tx_id": tx_id,
                "x402_payment_id": x402_id,
                "dry_run": self.dry_run,
            },
        )
        
        return PaymentResult(
            success=True,
            tx_id=tx_id,
            x402_payment_id=x402_id,
            amount_usd=request.amount_usd,
        )


def _generate_tx_id(mandate_id: str, request: PaymentRequest) -> str:
    """Generate a unique transaction ID."""
    content = json.dumps({
        "mandate": mandate_id,
        "amount": request.amount_usd,
        "merchant": request.merchant,
        "time": time.time(),
    }, sort_keys=True)
    return f"tx-{hashlib.sha256(content.encode()).hexdigest()[:12]}"


def _mock_x402_payment(request: PaymentRequest) -> str:
    """
    Mock x402 payment for testing.
    
    In production, this would:
    1. Create Stripe PaymentIntent with crypto method
    2. Get deposit address
    3. Sign EIP-712 payment authorization with agent's key
    4. Submit to facilitator
    5. Return payment ID
    """
    return f"mock-x402-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"


# Future: Real x402 payment implementation
# def _execute_x402_payment(
#     request: PaymentRequest,
#     mandate: Mandate,
#     agent_key: str,  # From bagman session key
# ) -> str:
#     """Execute real x402 payment via Stripe."""
#     from eth_account import Account
#     account = Account.from_key(agent_key)
#     
#     # 1. Hit merchant endpoint, get 402 response with payment requirements
#     # 2. Create Stripe PaymentIntent
#     # 3. Sign payment authorization (EIP-712)
#     # 4. Retry request with payment header
#     # 5. Return payment ID
#     pass
