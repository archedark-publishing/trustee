"""
Real x402 payment client integration.

Wraps the official x402 Python SDK to execute actual USDC payments
on Base (mainnet) or Base Sepolia (testnet).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from typing import Any

import httpx
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_account.messages import encode_typed_data

from x402 import x402ClientSync
from x402.http.x402_http_client import x402HTTPClientSync
from x402.mechanisms.evm.exact import ExactEvmScheme


class EthAccountSigner:
    """
    Adapter that wraps eth-account's LocalAccount to match
    x402's ClientEvmSigner protocol.
    """

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
        # Convert TypedDataField objects to plain dicts for eth-account
        plain_types = {}
        for type_name, fields in types.items():
            plain_types[type_name] = [
                {"name": f["name"] if isinstance(f, dict) else getattr(f, "name"),
                 "type": f["type"] if isinstance(f, dict) else getattr(f, "type")}
                for f in fields
            ]

        # Convert domain object to dict (x402 uses snake_case: chain_id, verifying_contract)
        domain_dict = {}
        if isinstance(domain, dict):
            domain_dict = domain
        else:
            # TypedDataDomain dataclass with snake_case fields
            if getattr(domain, "name", None) is not None:
                domain_dict["name"] = domain.name
            if getattr(domain, "version", None) is not None:
                domain_dict["version"] = domain.version
            # Map snake_case to camelCase for EIP-712
            chain_id = getattr(domain, "chain_id", None) or getattr(domain, "chainId", None)
            if chain_id is not None:
                domain_dict["chainId"] = chain_id
            verifying = getattr(domain, "verifying_contract", None) or getattr(domain, "verifyingContract", None)
            if verifying is not None:
                domain_dict["verifyingContract"] = verifying
            salt = getattr(domain, "salt", None)
            if salt is not None:
                domain_dict["salt"] = salt

        # Convert bytes32 nonce to hex string for eth-account
        msg = dict(message)
        if "nonce" in msg and isinstance(msg["nonce"], bytes):
            msg["nonce"] = "0x" + msg["nonce"].hex()

        # Build full EIP-712 message
        full_message = {
            "types": {**plain_types, "EIP712Domain": _build_domain_type(domain_dict)},
            "primaryType": primary_type,
            "domain": domain_dict,
            "message": msg,
        }

        signed = self._account.sign_typed_data(full_message=full_message)
        return bytes(signed.signature)


def _build_domain_type(domain: dict) -> list[dict]:
    """Build EIP712Domain type definition from domain dict."""
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

logger = logging.getLogger(__name__)


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


class X402PaymentClient:
    """
    Executes real x402 payments using the official SDK.

    Usage:
        client = X402PaymentClient.from_private_key("0x...", config=X402Config())
        result = client.pay(url="https://api.example.com/data")
    """

    def __init__(self, account: LocalAccount, config: X402Config):
        self.account = account
        self.config = config
        self._signer = EthAccountSigner(account)
        self._x402_client = x402ClientSync()
        self._x402_client.register(
            config.network.value,
            ExactEvmScheme(signer=self._signer),
        )
        self._http_handler = x402HTTPClientSync(client=self._x402_client)
        self._http = httpx.Client(timeout=config.timeout_seconds)

    @classmethod
    def from_private_key(
        cls, private_key: str, config: Optional[X402Config] = None,
    ) -> "X402PaymentClient":
        account = Account.from_key(private_key)
        return cls(account=account, config=config or X402Config())

    @property
    def address(self) -> str:
        return self.account.address

    def pay(self, url: str, method: str = "GET", **kwargs) -> X402PaymentResult:
        """
        Pay for access to an x402-protected resource.

        Makes initial request, handles 402 via SDK, retries with payment.
        """
        try:
            # Step 1: Hit resource, expect 402
            response = self._http.request(method, url, **kwargs)

            if response.status_code != 402:
                if response.status_code == 200:
                    return X402PaymentResult(
                        success=True, payment_id="free-access",
                        network=self.config.network.value,
                    )
                return X402PaymentResult(
                    success=False,
                    error=f"Unexpected status {response.status_code}",
                )

            # Step 2: Use SDK to parse 402 and create payment headers
            raw_headers = dict(response.headers)
            body = response.content

            payment_headers, payload = self._http_handler.handle_402_response(
                raw_headers, body,
            )

            # Step 3: Retry with payment headers
            req_headers = {**kwargs.pop("headers", {}), **payment_headers}
            paid_response = self._http.request(
                method, url, headers=req_headers, **kwargs,
            )

            if paid_response.status_code == 200:
                # Try to extract settle response
                try:
                    settle = self._http_handler.get_payment_settle_response(
                        lambda h: paid_response.headers.get(h),
                    )
                    tx_hash = getattr(settle, "tx_hash", None) or getattr(settle, "transaction_hash", None)
                    payment_id = getattr(settle, "payment_id", None)
                except Exception:
                    tx_hash = None
                    payment_id = payment_headers.get("PAYMENT-SIGNATURE", "")[:16]

                return X402PaymentResult(
                    success=True,
                    payment_id=payment_id,
                    tx_hash=tx_hash,
                    network=self.config.network.value,
                )
            else:
                return X402PaymentResult(
                    success=False,
                    error=f"Payment rejected: {paid_response.status_code} {paid_response.text[:200]}",
                )

        except Exception as e:
            logger.exception("x402 payment failed")
            return X402PaymentResult(
                success=False,
                error=f"{type(e).__name__}: {str(e)}",
            )

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
