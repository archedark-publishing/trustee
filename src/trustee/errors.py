"""
Trustee error types.

Specific exceptions for different failure modes, enabling callers
to handle each case appropriately (retry, abort, alert, etc.).
"""


class TrusteeError(Exception):
    """Base error for all Trustee operations."""
    pass


# Payment errors
class PaymentError(TrusteeError):
    """Base error for payment failures."""
    pass


class InsufficientFundsError(PaymentError):
    """Wallet doesn't have enough USDC for the payment."""
    pass


class PaymentRejectedError(PaymentError):
    """Facilitator or server rejected the payment."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"Payment rejected ({status_code}): {message}")


class PaymentTimeoutError(PaymentError):
    """Payment request timed out."""
    pass


class FacilitatorError(PaymentError):
    """Facilitator returned an error during verification/settlement."""
    pass


class SignatureError(PaymentError):
    """EIP-712 signature creation or verification failed."""
    pass


# Budget errors
class BudgetError(TrusteeError):
    """Base error for budget limit violations."""
    pass


class PerTransactionLimitError(BudgetError):
    """Amount exceeds per-transaction limit."""
    def __init__(self, amount: float, limit: float):
        self.amount = amount
        self.limit = limit
        super().__init__(f"${amount} exceeds per-tx limit ${limit}")


class SessionCapError(BudgetError):
    """Amount would exceed session spending cap."""
    def __init__(self, amount: float, remaining: float):
        self.amount = amount
        self.remaining = remaining
        super().__init__(f"${amount} exceeds remaining session budget ${remaining:.2f}")


class DailyLimitError(BudgetError):
    """Amount would exceed daily spending limit."""
    pass


# Session errors
class SessionError(TrusteeError):
    """Base error for Steward session issues."""
    pass


class SessionExpiredError(SessionError):
    """Steward session has expired."""
    pass


class SessionNotFoundError(SessionError):
    """Steward session ID not found."""
    pass


class KeyAccessError(SessionError):
    """Cannot access signing key (session destroyed or invalid)."""
    pass


# Mandate errors
class MandateError(TrusteeError):
    """Base error for mandate issues."""
    pass


class MandateExpiredError(MandateError):
    """Mandate has expired."""
    pass


class MandateSignatureError(MandateError):
    """Mandate signature verification failed."""
    pass


# Network errors
class NetworkError(TrusteeError):
    """Network-level failures (DNS, connection refused, etc.)."""
    pass


class RetryableError(TrusteeError):
    """Error that may succeed if retried."""
    def __init__(self, message: str, retry_after: float = 1.0):
        self.retry_after = retry_after
        super().__init__(message)
