"""
Real x402 payment client integration.

Wraps the official x402 Python SDK to execute USDC payments
on Base mainnet or Base Sepolia.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

import httpx
from eth_account import Account
from eth_account.signers.local import LocalAccount
from x402 import x402ClientSync
from x402.http.x402_http_client import x402HTTPClientSync
from x402.mechanisms.evm.exact import ExactEvmScheme
from x402.mechanisms.evm.utils import get_asset_info

logger = logging.getLogger(__name__)


class EthAccountSigner:
    """Adapter that wraps eth-account LocalAccount for x402 signer protocol."""

    def __init__(self, account: LocalAccount):
        self._account = account

    @property
    def address(self) -> str:
        return self._account.address

    def sign_typed_data(
        self,
        domain: Any,
        types: dict[str, list],
        primary_type: str,
        message: dict[str, Any],
    ) -> bytes:
        plain_types = {}
        for type_name, fields in types.items():
            plain_types[type_name] = [
                {
                    "name": f["name"] if isinstance(f, dict) else getattr(f, "name"),
                    "type": f["type"] if isinstance(f, dict) else getattr(f, "type"),
                }
                for f in fields
            ]

        domain_dict: dict[str, Any] = {}
        if isinstance(domain, dict):
            domain_dict = domain
        else:
            if getattr(domain, "name", None) is not None:
                domain_dict["name"] = domain.name
            if getattr(domain, "version", None) is not None:
                domain_dict["version"] = domain.version
            chain_id = getattr(domain, "chain_id", None) or getattr(domain, "chainId", None)
            if chain_id is not None:
                domain_dict["chainId"] = chain_id
            verifying = getattr(domain, "verifying_contract", None) or getattr(
                domain, "verifyingContract", None
            )
            if verifying is not None:
                domain_dict["verifyingContract"] = verifying
            salt = getattr(domain, "salt", None)
            if salt is not None:
                domain_dict["salt"] = salt

        msg = dict(message)
        if "nonce" in msg and isinstance(msg["nonce"], bytes):
            msg["nonce"] = "0x" + msg["nonce"].hex()

        full_message = {
            "types": {**plain_types, "EIP712Domain": _build_domain_type(domain_dict)},
            "primaryType": primary_type,
            "domain": domain_dict,
            "message": msg,
        }

        signed = self._account.sign_typed_data(full_message=full_message)
        return bytes(signed.signature)


def _build_domain_type(domain: dict) -> list[dict]:
    fields = []
    if "name" in domain:
        fields.append({"name": "name", "type": "string"})
    if "version" in domain:
        fields.append({"name": "version", "type": "string"})
    if "chainId" in domain:
        fields.append({"name": "chainId", "type": "uint256"})
    if "verifyingContract" in domain:
        fields.append({"name": "verifyingContract", "type": "address"})
    if "salt" in domain:
        fields.append({"name": "salt", "type": "bytes32"})
    return fields


class Network(str, Enum):
    BASE_MAINNET = "eip155:8453"
    BASE_SEPOLIA = "eip155:84532"


@dataclass
class X402Config:
    network: Network = Network.BASE_SEPOLIA
    timeout_seconds: float = 30.0
    max_amount_usd: float = 10.0


@dataclass
class X402PaymentResult:
    success: bool
    payment_id: Optional[str] = None
    tx_hash: Optional[str] = None
    network: Optional[str] = None
    amount_usdc: Optional[float] = None
    error: Optional[str] = None
    raw_response: Optional[dict] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "payment_id": self.payment_id,
            "tx_hash": self.tx_hash,
            "network": self.network,
            "amount_usdc": self.amount_usdc,
            "error": self.error,
        }


@dataclass
class _ValidatedRequirement:
    network: str
    pay_to: str
    amount_base_units: int
    amount_usd: float
    requirement: Any


class X402PaymentClient:
    """Executes x402 payments using the official SDK."""

    def __init__(
        self,
        account: Optional[LocalAccount] = None,
        config: Optional[X402Config] = None,
        signer: Any = None,
    ):
        self.config = config or X402Config()

        if signer is not None:
            self._signer = signer
        elif account is not None:
            self._signer = EthAccountSigner(account)
        else:
            raise ValueError("Provide either account or signer")

        self._x402_client = x402ClientSync()
        self._x402_client.register(self.config.network.value, ExactEvmScheme(signer=self._signer))
        self._http_handler = x402HTTPClientSync(client=self._x402_client)
        self._http = httpx.Client(timeout=self.config.timeout_seconds)

    @classmethod
    def from_private_key(
        cls,
        private_key: str,
        config: Optional[X402Config] = None,
    ) -> "X402PaymentClient":
        account = Account.from_key(private_key)
        return cls(account=account, config=config)

    @classmethod
    def from_bagman_session(
        cls,
        bagman: Any,
        session_id: str,
        config: Optional[X402Config] = None,
    ) -> "X402PaymentClient":
        signer = bagman.get_signer(session_id)
        return cls(signer=signer, config=config)

    @property
    def address(self) -> str:
        return self._signer.address

    def pay(
        self,
        url: str,
        method: str = "GET",
        max_retries: int = 2,
        retry_delay: float = 1.0,
        expected_amount_usd: Optional[float] = None,
        allowed_networks: Optional[list[str]] = None,
        allowed_payees: Optional[list[str]] = None,
        idempotency_key: Optional[str] = None,
        **kwargs,
    ) -> X402PaymentResult:
        """Pay for access to an x402-protected resource."""
        import time as _time

        idem_key = idempotency_key or self._derive_idempotency_key(url=url, method=method, kwargs=kwargs)
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                result = self._pay_once(
                    url=url,
                    method=method,
                    expected_amount_usd=expected_amount_usd,
                    allowed_networks=allowed_networks,
                    allowed_payees=allowed_payees,
                    idempotency_key=idem_key,
                    **kwargs,
                )

                if not result.success and attempt < max_retries:
                    error = (result.error or "").lower()
                    if any(
                        t in error
                        for t in ("timeout", "connection", "503", "502", "429", "temporarily", "retry")
                    ):
                        logger.info(
                            "Retryable error (attempt %d/%d): %s",
                            attempt + 1,
                            max_retries + 1,
                            result.error,
                        )
                        _time.sleep(retry_delay * (attempt + 1))
                        continue

                return result

            except httpx.TimeoutException as e:
                last_error = f"Request timeout: {e}"
                if attempt < max_retries:
                    _time.sleep(retry_delay * (attempt + 1))
                    continue
            except httpx.ConnectError as e:
                last_error = f"Connection failed: {e}"
                if attempt < max_retries:
                    _time.sleep(retry_delay * (attempt + 1))
                    continue
            except Exception as e:
                logger.exception("x402 payment failed (non-retryable)")
                return X402PaymentResult(success=False, error=f"{type(e).__name__}: {e}")

        return X402PaymentResult(
            success=False,
            error=f"Failed after {max_retries + 1} attempts: {last_error}",
        )

    def _pay_once(
        self,
        url: str,
        method: str,
        expected_amount_usd: Optional[float],
        allowed_networks: Optional[list[str]],
        allowed_payees: Optional[list[str]],
        idempotency_key: str,
        **kwargs,
    ) -> X402PaymentResult:
        req_headers = dict(kwargs.pop("headers", {}))
        req_headers["Idempotency-Key"] = idempotency_key

        response = self._http.request(method, url, headers=req_headers, **kwargs)

        if response.status_code != 402:
            if response.status_code == 200:
                return X402PaymentResult(
                    success=True,
                    payment_id="free-access",
                    network=self.config.network.value,
                )
            if response.status_code in (502, 503):
                return X402PaymentResult(
                    success=False,
                    error=f"Server unavailable ({response.status_code}) — temporarily down",
                )
            if response.status_code == 429:
                return X402PaymentResult(
                    success=False,
                    error="Rate limited (429) — retry after delay",
                )
            return X402PaymentResult(
                success=False,
                error=f"Unexpected status {response.status_code}: {response.text[:200]}",
            )

        raw_headers = dict(response.headers)
        body = response.content

        try:
            payment_required = self._http_handler.get_payment_required_response(
                lambda h: _header_lookup(raw_headers, h),
                body,
            )
        except Exception as e:
            return X402PaymentResult(
                success=False,
                error=f"Failed to parse 402 requirements: {type(e).__name__}: {e}",
            )

        validated = self._validate_payment_required(
            payment_required=payment_required,
            expected_amount_usd=expected_amount_usd,
            allowed_networks=allowed_networks,
            allowed_payees=allowed_payees,
        )
        if isinstance(validated, str):
            return X402PaymentResult(success=False, error=validated)

        if hasattr(payment_required, "model_copy"):
            filtered_required = payment_required.model_copy(update={"accepts": [validated.requirement]})
        else:
            return X402PaymentResult(success=False, error="Unsupported x402 payment version")

        if hasattr(self._signer, "prepare_payment"):
            self._signer.prepare_payment(
                network=validated.network,
                pay_to=validated.pay_to,
                amount_base_units=validated.amount_base_units,
            )

        try:
            payload = self._http_handler.create_payment_payload(filtered_required)
            payment_headers = self._http_handler.encode_payment_signature_header(payload)
        except Exception as e:
            return X402PaymentResult(
                success=False,
                error=f"Failed to create payment: {type(e).__name__}: {e}",
            )

        req_headers = {**req_headers, **payment_headers}
        paid_response = self._http.request(method, url, headers=req_headers, **kwargs)

        if paid_response.status_code == 200:
            try:
                settle = self._http_handler.get_payment_settle_response(
                    lambda h: paid_response.headers.get(h),
                )
                tx_hash = getattr(settle, "tx_hash", None) or getattr(
                    settle, "transaction_hash", None
                ) or getattr(settle, "transaction", None)
                payment_id = getattr(settle, "payment_id", None)
            except Exception:
                tx_hash = None
                payment_id = payment_headers.get("PAYMENT-SIGNATURE", "")[:16]

            return X402PaymentResult(
                success=True,
                payment_id=payment_id,
                tx_hash=tx_hash,
                network=validated.network,
                amount_usdc=validated.amount_usd,
            )

        error_detail = paid_response.text[:200]
        return X402PaymentResult(
            success=False,
            error=f"Payment rejected ({paid_response.status_code}): {error_detail}",
        )

    def _validate_payment_required(
        self,
        payment_required: Any,
        expected_amount_usd: Optional[float],
        allowed_networks: Optional[list[str]],
        allowed_payees: Optional[list[str]],
    ) -> _ValidatedRequirement | str:
        accepts = getattr(payment_required, "accepts", None)
        if not accepts:
            return "No payment requirements in 402 response"

        configured_allowed_networks = set(allowed_networks or [self.config.network.value])
        required_max = Decimal(str(expected_amount_usd)) if expected_amount_usd is not None else None
        client_max = Decimal(str(self.config.max_amount_usd))
        max_allowed = min(client_max, required_max) if required_max is not None else client_max
        allow_payees = {p.lower() for p in (allowed_payees or [])}

        first_error: Optional[str] = None
        for req in accepts:
            network = str(getattr(req, "network", ""))
            pay_to = str(getattr(req, "pay_to", ""))
            amount_raw = int(getattr(req, "amount", "0"))
            asset = str(getattr(req, "asset", ""))

            if network not in configured_allowed_networks:
                first_error = first_error or f"402 requirement network {network} not allowed"
                continue

            if allow_payees and pay_to.lower() not in allow_payees:
                first_error = first_error or f"402 payee {pay_to} not allowed"
                continue

            amount_usd = _base_units_to_usd(
                amount=amount_raw,
                network=network,
                asset=asset,
            )
            if amount_usd > max_allowed:
                first_error = first_error or (
                    f"402 amount ${amount_usd:.6f} exceeds approved max ${float(max_allowed):.6f}"
                )
                continue

            return _ValidatedRequirement(
                network=network,
                pay_to=pay_to,
                amount_base_units=amount_raw,
                amount_usd=float(amount_usd),
                requirement=req,
            )

        return first_error or "No acceptable 402 requirement matched policy"

    def _derive_idempotency_key(self, url: str, method: str, kwargs: dict[str, Any]) -> str:
        body = kwargs.get("content") or kwargs.get("json") or kwargs.get("data")
        h = hashlib.sha256()
        h.update(method.upper().encode())
        h.update(b"|")
        h.update(url.encode())
        h.update(b"|")
        h.update(str(body).encode())
        return f"x402-{h.hexdigest()[:32]}"

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _base_units_to_usd(amount: int, network: str, asset: str) -> Decimal:
    decimals = 6
    try:
        asset_info = get_asset_info(network, asset)
        decimals = int(asset_info.get("decimals", 6))
    except Exception:
        pass
    return Decimal(amount) / (Decimal(10) ** decimals)


def _header_lookup(headers: dict[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None
