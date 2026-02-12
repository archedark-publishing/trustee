"""Tests for Bagman secure signing controls."""

import time

import pytest
from eth_account import Account

from trustee.bagman import Bagman, SessionConfig
from trustee.errors import SessionExpiredError, SessionNotFoundError


def _make_session(bagman: Bagman, **config_kwargs):
    acct = Account.create()
    session = bagman.create_session_from_private_key(
        acct.key.hex(),
        config=SessionConfig(**config_kwargs),
    )
    return session.session_id, acct


def _typed_data(amount_base_units: int, *, to: str, from_addr: str, chain_id: int = 84532):
    domain = {"name": "USDC", "version": "2", "chainId": chain_id, "verifyingContract": to}
    types = {
        "TransferWithAuthorization": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
        ]
    }
    message = {
        "from": from_addr,
        "to": to,
        "value": amount_base_units,
        "validAfter": int(time.time()) - 30,
        "validBefore": int(time.time()) + 3600,
        "nonce": b"\x01" * 32,
    }
    return domain, types, "TransferWithAuthorization", message


class TestBagmanCore:
    def test_signer_does_not_expose_session_account_path(self):
        bagman = Bagman()
        sid, _ = _make_session(bagman)
        signer = bagman.get_signer(sid)
        assert not hasattr(signer, "_session")
        with pytest.raises(AttributeError):
            _ = signer._session  # type: ignore[attr-defined]

    def test_session_lifecycle(self):
        bagman = Bagman()
        sid, acct = _make_session(bagman, max_spend_usd=10.0)
        assert bagman.get_session(sid).wallet_address == acct.address
        signer = bagman.get_signer(sid)
        assert signer.address == acct.address
        bagman.destroy_session(sid)
        with pytest.raises(SessionNotFoundError):
            bagman.get_session(sid)

    def test_expired_session_raises(self):
        bagman = Bagman()
        sid, acct = _make_session(bagman)
        bagman._sessions[sid].created_at = time.time() - 7200
        with pytest.raises(SessionExpiredError):
            bagman.get_session(sid)

    def test_destroy_all(self):
        bagman = Bagman()
        for _ in range(3):
            _make_session(bagman)
        assert len(bagman.list_sessions()) == 3
        bagman.destroy_all()
        assert len(bagman.list_sessions()) == 0


class TestSigningPolicyEnforcement:
    def test_sign_requires_prepared_intent(self):
        bagman = Bagman()
        sid, acct = _make_session(bagman, max_spend_usd=1.0, max_per_tx_usd=1.0)
        signer = bagman.get_signer(sid)
        recipient = Account.create().address
        domain, types, primary_type, message = _typed_data(
            500,
            to=recipient,
            from_addr=acct.address,
        )
        with pytest.raises(RuntimeError, match="intent not prepared"):
            signer.sign_typed_data(domain, types, primary_type, message)

    def test_sign_path_enforces_spend_caps_without_precheck(self):
        bagman = Bagman()
        sid, acct = _make_session(bagman, max_spend_usd=0.002, max_per_tx_usd=0.001)
        signer = bagman.get_signer(sid)
        recipient = Account.create().address
        signer.prepare_payment(network="eip155:84532", pay_to=recipient, amount_base_units=2_000)
        domain, types, primary_type, message = _typed_data(
            2_000,  # 0.002 USDC
            to=recipient,
            from_addr=acct.address,
        )
        with pytest.raises(RuntimeError):
            signer.sign_typed_data(domain, types, primary_type, message)

    def test_sign_path_enforces_allowed_networks(self):
        bagman = Bagman()
        sid, acct = _make_session(bagman, allowed_networks=["eip155:84532"])
        signer = bagman.get_signer(sid)
        recipient = Account.create().address
        signer.prepare_payment(network="eip155:84532", pay_to=recipient, amount_base_units=500)
        domain, types, primary_type, message = _typed_data(
            500,
            to=recipient,
            from_addr=acct.address,
            chain_id=8453,
        )
        with pytest.raises(RuntimeError, match="Network"):
            signer.sign_typed_data(domain, types, primary_type, message)

    def test_sign_path_enforces_allowed_payees(self):
        bagman = Bagman()
        approved = Account.create().address
        sid, acct = _make_session(
            bagman,
            allowed_networks=["eip155:84532"],
            allowed_payees=[approved],
        )
        signer = bagman.get_signer(sid)
        recipient = Account.create().address
        signer.prepare_payment(network="eip155:84532", pay_to=recipient, amount_base_units=500)
        domain, types, primary_type, message = _typed_data(
            500,
            to=recipient,
            from_addr=acct.address,
        )
        with pytest.raises(RuntimeError, match="Payee"):
            signer.sign_typed_data(domain, types, primary_type, message)

    def test_prepared_payment_mismatch_is_rejected(self):
        bagman = Bagman()
        approved = Account.create().address
        sid, acct = _make_session(
            bagman,
            allowed_networks=["eip155:84532"],
        )
        signer = bagman.get_signer(sid)
        signer.prepare_payment(network="eip155:84532", pay_to=approved, amount_base_units=100)
        domain, types, primary_type, message = _typed_data(
            100,
            to=Account.create().address,
            from_addr=acct.address,
        )
        with pytest.raises(RuntimeError, match="recipient mismatch"):
            signer.sign_typed_data(domain, types, primary_type, message)

    def test_check_and_record_spend_updates_remaining(self):
        bagman = Bagman()
        sid, _ = _make_session(bagman, max_spend_usd=1.0)
        signer = bagman.get_signer(sid)
        ok, _ = signer.check_and_record_spend(0.25)
        assert ok
        assert signer.remaining_usd < 1.0
