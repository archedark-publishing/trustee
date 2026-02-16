"""Tests for AP2 canonical payload helpers and signatures."""

import pytest
from eth_account import Account

from trustee.mandate import (
    AP2MandateStatus,
    canonicalize_ap2_payload,
    compute_ap2_payload_hash,
    create_ap2_mandate,
    validate_caip19_asset_id,
    verify_ap2_mandate,
)


USDC_BASE_MAINNET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
REGISTRY_PLACEHOLDER = "0x0000000000000000000000000000000000000001"


def _base_payload(issuer: str, agent: str) -> dict:
    return {
        "schema_version": "1",
        "metadata_uri": "ipfs://mandate-1",
        "issuer": issuer,
        "agent": agent,
        "network": "eip155:8453",
        "asset_id": USDC_BASE_MAINNET,
        "max_amount_per_tx": "1000000",
        "max_amount_per_day": "5000000",
        "allowed_recipients": [
            "0x1234567890123456789012345678901234567890",
            "0xabcdef1234567890abcdef1234567890abcdef12",
        ],
        "expires_at": 1_900_000_000,
        "nonce": 42,
    }


class TestCanonicalization:
    def test_hash_determinism_for_equivalent_payloads(self):
        issuer = Account.create().address
        agent = Account.create().address
        payload_a = _base_payload(issuer, agent)
        payload_b = {
            **payload_a,
            "issuer": issuer.upper(),
            "agent": agent.upper(),
            "asset_id": payload_a["asset_id"].lower(),
            "allowed_recipients": [
                payload_a["allowed_recipients"][1].upper(),
                payload_a["allowed_recipients"][0].upper(),
                payload_a["allowed_recipients"][0],
            ],
            "max_amount_per_tx": 1_000_000,
            "max_amount_per_day": "5000000",
        }

        canonical_a = canonicalize_ap2_payload(payload_a)
        canonical_b = canonicalize_ap2_payload(payload_b)

        assert canonical_a == canonical_b
        assert compute_ap2_payload_hash(canonical_a) == compute_ap2_payload_hash(canonical_b)

    def test_rejects_invalid_asset_id(self):
        with pytest.raises(ValueError):
            validate_caip19_asset_id("USDC")


class TestAP2MandateCreationAndVerification:
    def test_create_and_verify_ap2_mandate(self):
        issuer = Account.create()
        agent = Account.create()

        mandate = create_ap2_mandate(
            issuer_key=issuer.key.hex(),
            agent=agent.address,
            asset_id=USDC_BASE_MAINNET,
            max_amount_per_tx=1_000_000,
            max_amount_per_day=5_000_000,
            allowed_recipients=[
                "0xabcdef1234567890abcdef1234567890abcdef12",
                "0x1234567890123456789012345678901234567890",
            ],
            expires_at=1_900_000_000,
            nonce=7,
            metadata_uri="ipfs://mandate-1",
            network="eip155:8453",
            verifying_contract=REGISTRY_PLACEHOLDER,
        )

        assert mandate.status == AP2MandateStatus.DRAFT.value
        assert mandate.allowed_recipients == sorted(mandate.allowed_recipients)

        valid, reason = verify_ap2_mandate(mandate)
        assert valid, reason

    def test_rejects_non_integer_base_units(self):
        issuer = Account.create()
        agent = Account.create()

        with pytest.raises(ValueError):
            create_ap2_mandate(
                issuer_key=issuer.key.hex(),
                agent=agent.address,
                asset_id=USDC_BASE_MAINNET,
                max_amount_per_tx="100.25",  # type: ignore[arg-type]
                max_amount_per_day=5_000_000,
                expires_at=1_900_000_000,
                verifying_contract=REGISTRY_PLACEHOLDER,
            )

    def test_detects_payload_tampering(self):
        issuer = Account.create()
        agent = Account.create()

        mandate = create_ap2_mandate(
            issuer_key=issuer.key.hex(),
            agent=agent.address,
            asset_id=USDC_BASE_MAINNET,
            max_amount_per_tx=1_000_000,
            max_amount_per_day=5_000_000,
            allowed_recipients=["0x1234567890123456789012345678901234567890"],
            expires_at=1_900_000_000,
            nonce=1,
            verifying_contract=REGISTRY_PLACEHOLDER,
        )

        mandate.max_amount_per_day += 1
        valid, reason = verify_ap2_mandate(mandate)
        assert not valid
        assert "payload hash mismatch" in reason.lower()

    def test_enforces_trusted_issuer_if_supplied(self):
        issuer = Account.create()
        agent = Account.create()

        mandate = create_ap2_mandate(
            issuer_key=issuer.key.hex(),
            agent=agent.address,
            asset_id=USDC_BASE_MAINNET,
            max_amount_per_tx=1_000_000,
            max_amount_per_day=5_000_000,
            expires_at=1_900_000_000,
            verifying_contract=REGISTRY_PLACEHOLDER,
        )

        valid, reason = verify_ap2_mandate(
            mandate,
            trusted_issuers={Account.create().address},
        )
        assert not valid
        assert "not trusted" in reason.lower()
