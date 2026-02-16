"""Tests for AP2 mandate store durability and integrity behavior."""

from concurrent.futures import ThreadPoolExecutor
import json

import pytest
from eth_account import Account

from trustee.mandate import AP2MandateStatus, create_ap2_mandate
from trustee.mandate_store import MandateStore


USDC_BASE_MAINNET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
REGISTRY_PLACEHOLDER = "0x0000000000000000000000000000000000000001"


def _make_mandate(
    *,
    nonce: int = 1,
    expires_at: int = 1_900_000_000,
    issuer=None,
    agent=None,
):
    issuer = issuer or Account.create()
    agent = agent or Account.create()
    mandate = create_ap2_mandate(
        issuer_key=issuer.key.hex(),
        agent=agent.address,
        asset_id=USDC_BASE_MAINNET,
        max_amount_per_tx=1_000_000,
        max_amount_per_day=5_000_000,
        allowed_recipients=["0x1234567890123456789012345678901234567890"],
        expires_at=expires_at,
        nonce=nonce,
        metadata_uri="ipfs://mandate",
        network="eip155:8453",
        verifying_contract=REGISTRY_PLACEHOLDER,
    )
    mandate.status = AP2MandateStatus.PENDING_ON_CHAIN.value
    return mandate


class TestMandateStore:
    def test_save_get_and_status_updates(self, tmp_path):
        store = MandateStore(tmp_path)
        mandate = _make_mandate()

        store.save_mandate(mandate)
        loaded = store.get_mandate(mandate.mandate_hash)

        assert loaded is not None
        assert loaded.mandate_hash == mandate.mandate_hash
        assert loaded.status == AP2MandateStatus.PENDING_ON_CHAIN.value

        store.record_chain_confirmation(mandate.mandate_hash, tx_hash="0xtx", block_number=123)
        confirmed = store.get_mandate(mandate.mandate_hash)

        assert confirmed is not None
        assert confirmed.status == AP2MandateStatus.ACTIVE.value
        assert confirmed.chain_tx_hash == "0xtx"
        assert confirmed.chain_block_number == 123

        store.mark_revoked(mandate.mandate_hash)
        revoked = store.get_mandate(mandate.mandate_hash)

        assert revoked is not None
        assert revoked.status == AP2MandateStatus.REVOKED.value

    def test_cleanup_expired_marks_expired(self, tmp_path):
        store = MandateStore(tmp_path)
        mandate = _make_mandate(expires_at=1)
        mandate.status = AP2MandateStatus.ACTIVE.value
        store.save_mandate(mandate)

        updated = store.cleanup_expired()
        assert updated == 1

        loaded = store.get_mandate(mandate.mandate_hash)
        assert loaded is not None
        assert loaded.status == AP2MandateStatus.EXPIRED.value

    def test_list_filters_active_by_default(self, tmp_path):
        store = MandateStore(tmp_path)
        issuer = Account.create()
        agent = Account.create()
        active = _make_mandate(nonce=1, issuer=issuer, agent=agent)
        revoked = _make_mandate(nonce=2, issuer=issuer, agent=agent)

        active.status = AP2MandateStatus.ACTIVE.value
        revoked.status = AP2MandateStatus.REVOKED.value

        store.save_mandate(active)
        store.save_mandate(revoked)

        active_only = store.list_mandates(active.agent)
        all_items = store.list_mandates(active.agent, include_inactive=True)

        assert [m.mandate_hash for m in active_only] == [active.mandate_hash]
        assert {m.mandate_hash for m in all_items} == {active.mandate_hash, revoked.mandate_hash}

    def test_integrity_mismatch_raises(self, tmp_path):
        store = MandateStore(tmp_path)
        mandate = _make_mandate()
        store.save_mandate(mandate)

        path = next(tmp_path.glob("*.json"))
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        raw["max_amount_per_tx"] = "9999999"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2)

        with pytest.raises(ValueError, match="payload hash mismatch"):
            store.get_mandate(mandate.mandate_hash)

    def test_concurrent_writes_are_safe(self, tmp_path):
        store = MandateStore(tmp_path)
        issuer = Account.create()
        agent = Account.create()
        mandates = [
            _make_mandate(nonce=i + 1, issuer=issuer, agent=agent)
            for i in range(32)
        ]

        def write_one(index: int):
            store.save_mandate(mandates[index])
            return mandates[index].mandate_hash

        with ThreadPoolExecutor(max_workers=8) as ex:
            saved_hashes = set(ex.map(write_one, range(len(mandates))))

        stored_hashes = {m.mandate_hash for m in store.list_mandates(agent.address, include_inactive=True)}
        expected_for_agent = {m.mandate_hash for m in mandates}

        assert saved_hashes
        assert stored_hashes == expected_for_agent
