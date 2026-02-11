"""Tests for Bagman secure key management."""

import time
import pytest
from eth_account import Account

from trustee.bagman import Bagman, BagmanSigner, SessionConfig, SessionState
from trustee.errors import SessionExpiredError, SessionNotFoundError


class TestSessionConfig:
    def test_defaults(self):
        config = SessionConfig()
        assert config.max_spend_usd == 10.0
        assert config.max_per_tx_usd == 1.0
        assert config.ttl_seconds == 3600

    def test_custom(self):
        config = SessionConfig(max_spend_usd=50, ttl_seconds=300)
        assert config.max_spend_usd == 50
        assert config.ttl_seconds == 300


class TestSessionState:
    @pytest.fixture
    def session(self):
        acct = Account.create()
        return SessionState(
            session_id="bm-test123",
            created_at=time.time(),
            config=SessionConfig(max_spend_usd=5.0, max_per_tx_usd=2.0, ttl_seconds=3600),
            _account=acct,
        )

    def test_wallet_address(self, session):
        assert session.wallet_address.startswith("0x")

    def test_not_expired(self, session):
        assert not session.is_expired

    def test_expired(self):
        acct = Account.create()
        session = SessionState(
            session_id="bm-expired",
            created_at=time.time() - 7200,
            config=SessionConfig(ttl_seconds=3600),
            _account=acct,
        )
        assert session.is_expired

    def test_check_spend_ok(self, session):
        ok, reason = session.check_spend(1.0)
        assert ok

    def test_check_spend_over_per_tx(self, session):
        ok, reason = session.check_spend(3.0)
        assert not ok
        assert "per-tx" in reason

    def test_check_spend_over_total(self, session):
        session.record_spend(4.0)
        ok, reason = session.check_spend(2.0)
        assert not ok
        assert "cap" in reason

    def test_check_spend_expired(self):
        acct = Account.create()
        session = SessionState(
            session_id="bm-expired",
            created_at=time.time() - 7200,
            config=SessionConfig(ttl_seconds=3600),
            _account=acct,
        )
        ok, reason = session.check_spend(0.01)
        assert not ok
        assert "expired" in reason.lower()

    def test_record_spend(self, session):
        session.record_spend(1.5)
        assert session.total_spent_usd == 1.5
        assert session.tx_count == 1
        assert session.remaining_usd == 3.5

    def test_destroy(self, session):
        session.destroy()
        assert session._account is None

    def test_to_dict(self, session):
        d = session.to_dict()
        assert d["session_id"] == "bm-test123"
        assert d["wallet_address"].startswith("0x")
        assert d["remaining_usd"] == 5.0


class TestBagmanSigner:
    @pytest.fixture
    def signer(self):
        acct = Account.create()
        session = SessionState(
            session_id="bm-signer-test",
            created_at=time.time(),
            config=SessionConfig(max_spend_usd=5.0, max_per_tx_usd=2.0, ttl_seconds=3600),
            _account=acct,
        )
        return BagmanSigner(session)

    def test_address(self, signer):
        assert signer.address.startswith("0x")

    def test_remaining(self, signer):
        assert signer.remaining_usd == 5.0

    def test_check_and_record(self, signer):
        ok, _ = signer.check_and_record_spend(1.0)
        assert ok
        assert signer.remaining_usd == 4.0

    def test_repr(self, signer):
        r = repr(signer)
        assert "BagmanSigner" in r
        assert "$5.00" in r


class TestBagman:
    def test_create_destroy(self):
        """Test session lifecycle without 1Password (manual key injection)."""
        bagman = Bagman()
        # Manually create a session (bypassing 1Password for testing)
        acct = Account.create()
        session = SessionState(
            session_id=bagman._generate_session_id(),
            created_at=time.time(),
            config=SessionConfig(max_spend_usd=10.0),
            _account=acct,
        )
        bagman._sessions[session.session_id] = session

        # Get it back
        retrieved = bagman.get_session(session.session_id)
        assert retrieved.wallet_address == acct.address

        # Get signer
        signer = bagman.get_signer(session.session_id)
        assert signer.address == acct.address

        # List
        sessions = bagman.list_sessions()
        assert len(sessions) == 1

        # Destroy
        bagman.destroy_session(session.session_id)
        assert len(bagman.list_sessions()) == 0

    def test_expired_session_raises(self):
        bagman = Bagman()
        acct = Account.create()
        session = SessionState(
            session_id="bm-old",
            created_at=time.time() - 7200,
            config=SessionConfig(ttl_seconds=3600),
            _account=acct,
        )
        bagman._sessions[session.session_id] = session

        with pytest.raises(SessionExpiredError):
            bagman.get_session(session.session_id)

    def test_missing_session_raises(self):
        bagman = Bagman()
        with pytest.raises(SessionNotFoundError):
            bagman.get_session("bm-nonexistent")

    def test_destroy_all(self):
        bagman = Bagman()
        for _ in range(3):
            acct = Account.create()
            sid = bagman._generate_session_id()
            bagman._sessions[sid] = SessionState(
                session_id=sid, created_at=time.time(),
                config=SessionConfig(), _account=acct,
            )
        assert len(bagman.list_sessions()) == 3
        bagman.destroy_all()
        assert len(bagman.list_sessions()) == 0
