"""Tests for AP2 mandate validator and payment-path integration."""

from __future__ import annotations

import json

from eth_account import Account

from trustee.audit import AuditTrail
from trustee.budget import BudgetTracker
from trustee.mandate import AP2MandateStatus, create_ap2_mandate, create_mandate
from trustee.mandate_registry import LocalMandateRegistry
from trustee.mandate_store import MandateStore
from trustee.mandate_validator import MandateValidator, TransactionIntent
from trustee.payment import PaymentExecutor, PaymentRequest


USDC_BASE_MAINNET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
REGISTRY_PLACEHOLDER = "0x0000000000000000000000000000000000000001"
RECIPIENT = "0x1234567890123456789012345678901234567890"


def _issue_active_mandate(
    *,
    store: MandateStore,
    registry: LocalMandateRegistry,
    issuer,
    agent,
    nonce: int,
    recipient: str = RECIPIENT,
    max_per_tx: int = 1_000_000,
) -> object:
    mandate = create_ap2_mandate(
        issuer_key=issuer.key.hex(),
        agent=agent.address,
        asset_id=USDC_BASE_MAINNET,
        max_amount_per_tx=max_per_tx,
        max_amount_per_day=5_000_000,
        allowed_recipients=[recipient],
        expires_at=1_900_000_000,
        nonce=nonce,
        metadata_uri=f"ipfs://mandate/{nonce}",
        network="eip155:8453",
        verifying_contract=REGISTRY_PLACEHOLDER,
    )
    mandate.status = AP2MandateStatus.PENDING_ON_CHAIN.value
    store.save_mandate(mandate)

    registry.set_trusted_issuer(agent.address, issuer.address, True)
    registry.issue_mandate(
        mandate_hash=mandate.mandate_hash,
        payload_hash=mandate.payload_hash,
        issuer=issuer.address,
        agent=agent.address,
        expires_at=mandate.expires_at,
        metadata_uri=mandate.metadata_uri,
    )
    store.record_chain_confirmation(mandate.mandate_hash, tx_hash=f"0xtx{nonce}", block_number=nonce)
    return mandate


def test_validator_rejects_ambiguous_auto_selection(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()

    m1 = _issue_active_mandate(store=store, registry=registry, issuer=issuer, agent=agent, nonce=1)
    _issue_active_mandate(store=store, registry=registry, issuer=issuer, agent=agent, nonce=2)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
        ),
        agent.address,
    )
    assert not ok
    assert "multiple active mandates" in (err or "").lower()

    ok, err, selected = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=m1.mandate_hash,
        ),
        agent.address,
    )
    assert ok, err
    assert selected is not None
    assert selected.mandate_hash == m1.mandate_hash


def test_revocation_is_enforced_even_after_initial_success(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store=store, registry=registry, issuer=issuer, agent=agent, nonce=1)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert ok, err

    registry.revoke_mandate(mandate.mandate_hash, issuer.address)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "not active" in (err or "").lower() or "revoked" in (err or "").lower()


def test_paused_agent_is_rejected(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store=store, registry=registry, issuer=issuer, agent=agent, nonce=1)

    registry.set_agent_paused(agent.address, True)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "paused" in (err or "").lower()


def test_payload_hash_mismatch_is_rejected(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store=store, registry=registry, issuer=issuer, agent=agent, nonce=1)

    mandate_file = next((tmp_path / "mandates").glob("*.json"))
    with open(mandate_file, encoding="utf-8") as f:
        raw = json.load(f)
    raw["max_amount_per_tx"] = "7777777"
    with open(mandate_file, "w", encoding="utf-8") as f:
        json.dump(raw, f)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "validation error" in (err or "").lower() or "hash" in (err or "").lower()


def test_registry_outage_fails_closed(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")

    class FailingStatusRegistry(LocalMandateRegistry):
        def get_mandate_status(self, mandate_hash: str):  # type: ignore[override]
            raise RuntimeError("rpc unavailable")

    failing_registry = FailingStatusRegistry(tmp_path / "failing-registry.json")
    validator = MandateValidator(failing_registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = create_ap2_mandate(
        issuer_key=issuer.key.hex(),
        agent=agent.address,
        asset_id=USDC_BASE_MAINNET,
        max_amount_per_tx=1_000_000,
        max_amount_per_day=5_000_000,
        allowed_recipients=[RECIPIENT],
        expires_at=1_900_000_000,
        nonce=3,
        verifying_contract=REGISTRY_PLACEHOLDER,
        network="eip155:8453",
    )
    mandate.status = AP2MandateStatus.ACTIVE.value
    store.save_mandate(mandate)
    failing_registry.set_trusted_issuer(agent.address, issuer.address, True)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "validation error" in (err or "").lower()


def test_payment_executor_integration_success_path(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    ap2_mandate = _issue_active_mandate(store=store, registry=registry, issuer=issuer, agent=agent, nonce=1)

    legacy_mandate = create_mandate(
        delegator_key=issuer.key.hex(),
        delegate_address=agent.address,
        max_total_usd=5.0,
        max_per_tx_usd=1.0,
        daily_limit_usd=3.0,
        duration_hours=24,
        network="eip155:8453",
    )

    executor = PaymentExecutor(
        budget=BudgetTracker(budget_dir=tmp_path / "budgets"),
        audit=AuditTrail(path=tmp_path / "audit.jsonl"),
        dry_run=True,
        mandate_validator=validator,
    )

    result = executor.execute(
        legacy_mandate,
        PaymentRequest(
            mandate_id=legacy_mandate.mandate_id,
            amount_usd=0.50,
            merchant="Vendor",
            description="AP2-validated payment",
            network="eip155:8453",
            mandate_hash=ap2_mandate.mandate_hash,
            to_address=RECIPIENT,
            asset_id=USDC_BASE_MAINNET,
            amount_base_units=500_000,
        ),
    )

    assert result.success
    assert result.tx_id is not None
