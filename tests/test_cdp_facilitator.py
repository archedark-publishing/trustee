"""Tests for CDP facilitator auth and credential loading."""

import json
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import trustee.cdp_facilitator as cdp_facilitator


def _make_ec_private_key_pem() -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return pem, key


def test_load_cdp_credentials_prefers_env(monkeypatch):
    monkeypatch.setenv(cdp_facilitator.CDP_API_KEY_ID_ENV, "env-key-id")
    monkeypatch.setenv(cdp_facilitator.CDP_API_KEY_SECRET_ENV, "env-key-secret")

    creds = cdp_facilitator.load_cdp_api_credentials()
    assert creds.api_key_id == "env-key-id"
    assert creds.api_key_secret == "env-key-secret"


def test_load_cdp_credentials_from_1password(monkeypatch):
    monkeypatch.delenv(cdp_facilitator.CDP_API_KEY_ID_ENV, raising=False)
    monkeypatch.delenv(cdp_facilitator.CDP_API_KEY_SECRET_ENV, raising=False)
    monkeypatch.setenv(cdp_facilitator.TRUSTEE_CDP_OP_ITEM_ENV, "cdp creds")
    monkeypatch.setenv(cdp_facilitator.TRUSTEE_CDP_OP_VAULT_ENV, "Ada")

    payload = {
        "fields": [
            {"label": "CDP_API_KEY_ID", "value": "op-key-id"},
            {"label": "CDP_API_KEY_SECRET", "value": "op-key-secret"},
        ]
    }

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(cdp_facilitator.subprocess, "run", fake_run)

    creds = cdp_facilitator.load_cdp_api_credentials()
    assert creds.api_key_id == "op-key-id"
    assert creds.api_key_secret == "op-key-secret"


def test_auth_provider_builds_endpoint_specific_signed_headers():
    api_key_id = "organizations/org-123/apiKeys/key-456"
    private_pem, private_key = _make_ec_private_key_pem()
    provider = cdp_facilitator.CDPFacilitatorAuthProvider(
        api_key_id=api_key_id,
        api_key_secret=private_pem,
    )

    headers = provider.get_auth_headers()
    correlation = headers.verify.get("Correlation-Context", "")
    assert "source=trustee" in correlation

    endpoint_matrix = [
        ("verify", headers.verify, "POST", "/platform/v2/x402/verify"),
        ("settle", headers.settle, "POST", "/platform/v2/x402/settle"),
        ("supported", headers.supported, "GET", "/platform/v2/x402/supported"),
    ]
    for name, endpoint_headers, method, path in endpoint_matrix:
        assert "Authorization" in endpoint_headers, f"{name} missing Authorization"
        token = endpoint_headers["Authorization"].split(" ", 1)[1]
        claims = jwt.decode(
            token,
            key=private_key.public_key(),
            algorithms=["ES256"],
            audience=cdp_facilitator.CDP_API_AUDIENCE,
            options={"verify_exp": False, "verify_nbf": False},
        )
        assert claims["iss"] == "cdp"
        assert claims["sub"] == api_key_id
        assert claims["uris"] == [f"{method} api.cdp.coinbase.com{path}"]


def test_create_cdp_facilitator_config_uses_cdp_url_and_provider():
    private_pem, _ = _make_ec_private_key_pem()
    config = cdp_facilitator.create_cdp_facilitator_config(
        api_key_id="orgs/test/apiKeys/test",
        api_key_secret=private_pem,
    )
    assert config.url == cdp_facilitator.CDP_FACILITATOR_URL
    assert isinstance(config.auth_provider, cdp_facilitator.CDPFacilitatorAuthProvider)


def test_load_cdp_credentials_raises_when_missing(monkeypatch):
    monkeypatch.delenv(cdp_facilitator.CDP_API_KEY_ID_ENV, raising=False)
    monkeypatch.delenv(cdp_facilitator.CDP_API_KEY_SECRET_ENV, raising=False)
    monkeypatch.delenv(cdp_facilitator.TRUSTEE_CDP_OP_ITEM_ENV, raising=False)
    monkeypatch.delenv(cdp_facilitator.TRUSTEE_CDP_OP_VAULT_ENV, raising=False)

    with pytest.raises(ValueError, match="CDP API credentials not found"):
        cdp_facilitator.load_cdp_api_credentials()
