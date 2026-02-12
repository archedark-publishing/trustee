"""CLI security hardening tests."""

from click.testing import CliRunner
from eth_account import Account

from trustee.cli import main


def test_create_rejects_raw_key_on_argv():
    runner = CliRunner()
    delegator = Account.create()
    delegate = Account.create()

    result = runner.invoke(
        main,
        [
            "create",
            "--delegator-key",
            delegator.key.hex(),
            "--delegate-address",
            delegate.address,
            "--max-total",
            "1",
            "--max-per-tx",
            "1",
            "--duration",
            "1",
            "--description",
            "test",
        ],
    )

    assert result.exit_code != 0
    assert "Refusing --delegator-key from argv" in result.output
