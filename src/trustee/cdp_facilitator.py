"""
CDP facilitator configuration and authentication helpers.

Provides:
1. CDP API key loading from environment variables or 1Password
2. JWT-based facilitator auth headers for verify/settle/supported endpoints
3. Convenience builder for x402 FacilitatorConfig
"""

from __future__ import annotations

import base64
import json
import os
import random
import subprocess
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from x402.http import AuthHeaders, AuthProvider, FacilitatorConfig

from .__init__ import __version__

CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
CDP_API_AUDIENCE = ["cdp_service"]

CDP_API_KEY_ID_ENV = "CDP_API_KEY_ID"
CDP_API_KEY_SECRET_ENV = "CDP_API_KEY_SECRET"

TRUSTEE_CDP_OP_ITEM_ENV = "TRUSTEE_CDP_OP_ITEM"
TRUSTEE_CDP_OP_VAULT_ENV = "TRUSTEE_CDP_OP_VAULT"
TRUSTEE_CDP_OP_KEY_ID_FIELD_ENV = "TRUSTEE_CDP_OP_KEY_ID_FIELD"
TRUSTEE_CDP_OP_KEY_SECRET_FIELD_ENV = "TRUSTEE_CDP_OP_KEY_SECRET_FIELD"

DEFAULT_OP_KEY_ID_FIELD = "CDP_API_KEY_ID"
DEFAULT_OP_KEY_SECRET_FIELD = "CDP_API_KEY_SECRET"


@dataclass(frozen=True)
class CDPApiCredentials:
    api_key_id: str
    api_key_secret: str


class CDPFacilitatorAuthProvider(AuthProvider):
    """AuthProvider for CDP facilitator endpoints."""

    def __init__(
        self,
        api_key_id: str,
        api_key_secret: str,
        facilitator_url: str = CDP_FACILITATOR_URL,
        expires_in_seconds: int = 120,
    ):
        if not api_key_id:
            raise ValueError("CDP API key ID is required")
        if not api_key_secret:
            raise ValueError("CDP API key secret is required")

        parsed = urlparse(facilitator_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid facilitator URL: {facilitator_url}")

        base_path = parsed.path.rstrip("/")
        if not base_path:
            raise ValueError(f"Facilitator URL path cannot be empty: {facilitator_url}")

        private_key, algorithm = _parse_private_key(api_key_secret)

        self._api_key_id = api_key_id
        self._private_key = private_key
        self._algorithm = algorithm
        self._host = parsed.netloc
        self._base_path = base_path
        self._expires_in_seconds = expires_in_seconds

    def get_auth_headers(self) -> AuthHeaders:
        correlation = _correlation_context()
        verify_path = f"{self._base_path}/verify"
        settle_path = f"{self._base_path}/settle"
        supported_path = f"{self._base_path}/supported"
        return AuthHeaders(
            verify={
                "Correlation-Context": correlation,
                "Authorization": self._authorization_header("POST", verify_path),
            },
            settle={
                "Correlation-Context": correlation,
                "Authorization": self._authorization_header("POST", settle_path),
            },
            supported={
                "Correlation-Context": correlation,
                "Authorization": self._authorization_header("GET", supported_path),
            },
        )

    def _authorization_header(self, method: str, path: str) -> str:
        now = int(time.time())
        claims = {
            "sub": self._api_key_id,
            "iss": "cdp",
            "aud": CDP_API_AUDIENCE,
            "nbf": now,
            "exp": now + self._expires_in_seconds,
            "uris": [f"{method} {self._host}{path}"],
        }
        token = jwt.encode(
            claims,
            self._private_key,
            algorithm=self._algorithm,
            headers={
                "alg": self._algorithm,
                "kid": self._api_key_id,
                "typ": "JWT",
                "nonce": _nonce(),
            },
        )
        return f"Bearer {token}"


def load_cdp_api_credentials(
    *,
    api_key_id: str | None = None,
    api_key_secret: str | None = None,
    op_item: str | None = None,
    op_vault: str | None = None,
    op_key_id_field: str = DEFAULT_OP_KEY_ID_FIELD,
    op_key_secret_field: str = DEFAULT_OP_KEY_SECRET_FIELD,
    timeout_seconds: float = 10.0,
) -> CDPApiCredentials:
    """Load CDP API key ID/secret from env or 1Password."""

    resolved_api_key_id = api_key_id or os.getenv(CDP_API_KEY_ID_ENV)
    resolved_api_key_secret = api_key_secret or os.getenv(CDP_API_KEY_SECRET_ENV)

    if resolved_api_key_id and resolved_api_key_secret:
        return CDPApiCredentials(
            api_key_id=resolved_api_key_id,
            api_key_secret=resolved_api_key_secret,
        )

    resolved_op_item = op_item or os.getenv(TRUSTEE_CDP_OP_ITEM_ENV)
    resolved_op_vault = op_vault or os.getenv(TRUSTEE_CDP_OP_VAULT_ENV)
    resolved_id_field = os.getenv(TRUSTEE_CDP_OP_KEY_ID_FIELD_ENV, op_key_id_field)
    resolved_secret_field = os.getenv(TRUSTEE_CDP_OP_KEY_SECRET_FIELD_ENV, op_key_secret_field)

    if resolved_op_item and resolved_op_vault:
        fields = _load_1password_fields(
            item=resolved_op_item,
            vault=resolved_op_vault,
            timeout_seconds=timeout_seconds,
        )
        if not resolved_api_key_id:
            resolved_api_key_id = _get_case_insensitive(fields, resolved_id_field)
        if not resolved_api_key_secret:
            resolved_api_key_secret = _get_case_insensitive(fields, resolved_secret_field)

    if not resolved_api_key_id or not resolved_api_key_secret:
        raise ValueError(
            "CDP API credentials not found. Set CDP_API_KEY_ID/CDP_API_KEY_SECRET or configure "
            "TRUSTEE_CDP_OP_ITEM + TRUSTEE_CDP_OP_VAULT (and optional field names)."
        )

    return CDPApiCredentials(
        api_key_id=resolved_api_key_id,
        api_key_secret=resolved_api_key_secret,
    )


def create_cdp_facilitator_config(
    *,
    api_key_id: str | None = None,
    api_key_secret: str | None = None,
    op_item: str | None = None,
    op_vault: str | None = None,
    op_key_id_field: str = DEFAULT_OP_KEY_ID_FIELD,
    op_key_secret_field: str = DEFAULT_OP_KEY_SECRET_FIELD,
    facilitator_url: str = CDP_FACILITATOR_URL,
) -> FacilitatorConfig:
    credentials = load_cdp_api_credentials(
        api_key_id=api_key_id,
        api_key_secret=api_key_secret,
        op_item=op_item,
        op_vault=op_vault,
        op_key_id_field=op_key_id_field,
        op_key_secret_field=op_key_secret_field,
    )
    return FacilitatorConfig(
        url=facilitator_url,
        auth_provider=CDPFacilitatorAuthProvider(
            api_key_id=credentials.api_key_id,
            api_key_secret=credentials.api_key_secret,
            facilitator_url=facilitator_url,
        ),
    )


def _load_1password_fields(item: str, vault: str, timeout_seconds: float) -> dict[str, str]:
    result = subprocess.run(
        ["op", "item", "get", item, "--vault", vault, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    if result.returncode != 0:
        raise RuntimeError(f"1Password error: {result.stderr.strip()}")

    payload = json.loads(result.stdout)
    fields = payload.get("fields", [])
    values: dict[str, str] = {}
    for entry in fields:
        label = str(entry.get("label") or "")
        value = str(entry.get("value") or "")
        if label:
            values[label] = value
    return values


def _get_case_insensitive(values: dict[str, str], key: str) -> str | None:
    direct = values.get(key)
    if direct:
        return direct
    lowered_key = key.lower()
    for k, v in values.items():
        if k.lower() == lowered_key and v:
            return v
    return None


def _parse_private_key(
    key_data: str,
) -> tuple[ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey, str]:
    # Handle literal '\n' sequences often present in unquoted env vars.
    if "\\n" in key_data:
        key_data = key_data.replace("\\n", "\n")

    try:
        key = serialization.load_pem_private_key(key_data.encode("utf-8"), password=None)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return key, "ES256"
    except Exception:
        pass

    try:
        decoded = base64.b64decode(key_data)
        if len(decoded) == 64:
            seed = decoded[:32]
            return ed25519.Ed25519PrivateKey.from_private_bytes(seed), "EdDSA"
    except Exception:
        pass

    raise ValueError("CDP API key secret must be either PEM EC key or base64 Ed25519 key")


def _correlation_context() -> str:
    data = {
        "sdk_version": __version__,
        "sdk_language": "python",
        "source": "trustee",
        "source_version": __version__,
    }
    return ",".join(f"{k}={quote(str(v), safe='')}" for k, v in data.items())


def _nonce() -> str:
    return "".join(random.choices("0123456789", k=16))
