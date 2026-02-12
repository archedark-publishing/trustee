"""Tests for x402 payment client integration."""

import pytest
from types import SimpleNamespace
from eth_account import Account

from trustee.x402_client import X402PaymentClient, X402Config, Network, X402PaymentResult


class TestX402Config:
    def test_defaults(self):
        config = X402Config()
        assert config.network == Network.BASE_SEPOLIA
        assert config.max_amount_usd == 10.0

    def test_mainnet(self):
        config = X402Config(network=Network.BASE_MAINNET)
        assert config.network == Network.BASE_MAINNET

    def test_custom_timeout(self):
        config = X402Config(timeout_seconds=60.0)
        assert config.timeout_seconds == 60.0


class TestX402PaymentClient:
    @pytest.fixture
    def agent_key(self):
        return Account.create()

    @pytest.fixture
    def client(self, agent_key):
        config = X402Config(network=Network.BASE_SEPOLIA)
        c = X402PaymentClient(account=agent_key, config=config)
        yield c
        c.close()

    def test_from_private_key(self):
        acct = Account.create()
        client = X402PaymentClient.from_private_key(acct.key.hex())
        assert client.address == acct.address
        client.close()

    def test_address(self, client, agent_key):
        assert client.address == agent_key.address
        assert client.address.startswith("0x")

    def test_context_manager(self):
        acct = Account.create()
        with X402PaymentClient.from_private_key(acct.key.hex()) as client:
            assert client.address == acct.address

    def test_validate_402_requirement_over_amount_denied(self, client):
        req = SimpleNamespace(
            network="eip155:84532",
            pay_to="0x1111111111111111111111111111111111111111",
            amount="2000000",  # 2.0 USDC
            asset="0x0000000000000000000000000000000000000000",
        )
        payment_required = SimpleNamespace(accepts=[req])
        result = client._validate_payment_required(
            payment_required=payment_required,
            expected_amount_usd=1.0,
            allowed_networks=["eip155:84532"],
            allowed_payees=None,
        )
        assert isinstance(result, str)
        assert "exceeds approved max" in result

    def test_validate_402_requirement_payee_denied(self, client):
        req = SimpleNamespace(
            network="eip155:84532",
            pay_to="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            amount="100000",
            asset="0x0000000000000000000000000000000000000000",
        )
        payment_required = SimpleNamespace(accepts=[req])
        result = client._validate_payment_required(
            payment_required=payment_required,
            expected_amount_usd=1.0,
            allowed_networks=["eip155:84532"],
            allowed_payees=["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        )
        assert isinstance(result, str)
        assert "payee" in result.lower()

    def test_validate_402_requirement_network_denied(self, client):
        req = SimpleNamespace(
            network="eip155:8453",
            pay_to="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            amount="100000",
            asset="0x0000000000000000000000000000000000000000",
        )
        payment_required = SimpleNamespace(accepts=[req])
        result = client._validate_payment_required(
            payment_required=payment_required,
            expected_amount_usd=1.0,
            allowed_networks=["eip155:84532"],
            allowed_payees=None,
        )
        assert isinstance(result, str)
        assert "network" in result.lower()


class TestX402PaymentResult:
    def test_success_result(self):
        result = X402PaymentResult(
            success=True,
            payment_id="pay-123",
            tx_hash="0xabc",
            network="eip155:84532",
            amount_usdc=0.01,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["payment_id"] == "pay-123"
        assert d["tx_hash"] == "0xabc"

    def test_failure_result(self):
        result = X402PaymentResult(
            success=False,
            error="Insufficient funds",
        )
        assert result.to_dict()["success"] is False
        assert "Insufficient" in result.to_dict()["error"]
