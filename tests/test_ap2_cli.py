"""AP2 mandate CLI command tests."""

from pathlib import Path

from click.testing import CliRunner
from eth_account import Account

from trustee.cli import main


USDC_BASE_MAINNET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
RECIPIENT = "0x1234567890123456789012345678901234567890"


def _base_env(tmp_path: Path) -> dict[str, str]:
    return {
        "HOME": str(tmp_path),
        "TRUSTEE_AP2_REGISTRY_STATE_PATH": str(tmp_path / "registry-state.json"),
        "MANDATE_REGISTRY_ADDRESS": "0x0000000000000000000000000000000000000001",
    }


def test_mandate_issue_rejects_raw_key_on_argv_without_unsafe(tmp_path):
    runner = CliRunner()
    issuer = Account.create()
    agent = Account.create()

    env = _base_env(tmp_path)

    trust_result = runner.invoke(
        main,
        [
            "mandate",
            "trust-issuer",
            "--agent",
            agent.address,
            "--issuer",
            issuer.address,
            "--allow",
        ],
        env=env,
    )
    assert trust_result.exit_code == 0

    result = runner.invoke(
        main,
        [
            "mandate",
            "issue",
            "--agent",
            agent.address,
            "--asset-id",
            USDC_BASE_MAINNET,
            "--max-per-tx",
            "1000000",
            "--max-per-day",
            "5000000",
            "--recipients",
            RECIPIENT,
            "--expires-in",
            "30d",
            "--issuer-key",
            issuer.key.hex(),
        ],
        env=env,
    )

    assert result.exit_code != 0
    assert "Refusing --issuer-key from argv" in result.output


def test_mandate_cli_issue_status_revoke_flow(tmp_path):
    runner = CliRunner()
    issuer = Account.create()
    agent = Account.create()

    env = _base_env(tmp_path)

    trust_result = runner.invoke(
        main,
        [
            "mandate",
            "trust-issuer",
            "--agent",
            agent.address,
            "--issuer",
            issuer.address,
            "--allow",
        ],
        env=env,
    )
    assert trust_result.exit_code == 0

    issue_result = runner.invoke(
        main,
        [
            "mandate",
            "issue",
            "--agent",
            agent.address,
            "--asset-id",
            USDC_BASE_MAINNET,
            "--template",
            "micro",
            "--recipients",
            RECIPIENT,
            "--expires-in",
            "30d",
            "--issuer-key",
            issuer.key.hex(),
            "--unsafe-allow-key-arg",
        ],
        env=env,
    )
    assert issue_result.exit_code == 0, issue_result.output
    assert "Mandate issued" in issue_result.output

    mandate_hash = ""
    for line in issue_result.output.splitlines():
        if "Mandate issued:" in line:
            mandate_hash = line.split(":", 1)[1].strip()
            break
    assert mandate_hash.startswith("0x")

    list_result = runner.invoke(
        main,
        [
            "mandate",
            "list",
            "--agent",
            agent.address,
            "--include-inactive",
        ],
        env=env,
    )
    assert list_result.exit_code == 0
    assert mandate_hash in list_result.output
    assert "Status: active" in list_result.output

    status_result = runner.invoke(
        main,
        [
            "mandate",
            "status",
            "--mandate-hash",
            mandate_hash,
        ],
        env=env,
    )
    assert status_result.exit_code == 0
    assert "Registry active: True" in status_result.output

    revoke_result = runner.invoke(
        main,
        [
            "mandate",
            "revoke",
            "--mandate-hash",
            mandate_hash,
            "--issuer-key",
            issuer.key.hex(),
            "--unsafe-allow-key-arg",
        ],
        env=env,
    )
    assert revoke_result.exit_code == 0

    status_after_revoke = runner.invoke(
        main,
        [
            "mandate",
            "status",
            "--mandate-hash",
            mandate_hash,
        ],
        env=env,
    )
    assert status_after_revoke.exit_code == 0
    assert "Registry revoked: True" in status_after_revoke.output


def test_mandate_check_expiry_threshold(tmp_path):
    runner = CliRunner()
    issuer = Account.create()
    agent = Account.create()

    env = _base_env(tmp_path)

    trust_result = runner.invoke(
        main,
        [
            "mandate",
            "trust-issuer",
            "--agent",
            agent.address,
            "--issuer",
            issuer.address,
            "--allow",
        ],
        env=env,
    )
    assert trust_result.exit_code == 0

    soon_issue = runner.invoke(
        main,
        [
            "mandate",
            "issue",
            "--agent",
            agent.address,
            "--asset-id",
            USDC_BASE_MAINNET,
            "--max-per-tx",
            "1000000",
            "--max-per-day",
            "5000000",
            "--recipients",
            RECIPIENT,
            "--expires-in",
            "1h",
            "--issuer-key",
            issuer.key.hex(),
            "--unsafe-allow-key-arg",
        ],
        env=env,
    )
    assert soon_issue.exit_code == 0

    later_issue = runner.invoke(
        main,
        [
            "mandate",
            "issue",
            "--agent",
            agent.address,
            "--asset-id",
            USDC_BASE_MAINNET,
            "--max-per-tx",
            "1000000",
            "--max-per-day",
            "5000000",
            "--recipients",
            RECIPIENT,
            "--expires-in",
            "10d",
            "--issuer-key",
            issuer.key.hex(),
            "--unsafe-allow-key-arg",
            "--nonce",
            "99",
        ],
        env=env,
    )
    assert later_issue.exit_code == 0

    check_result = runner.invoke(
        main,
        [
            "mandate",
            "check-expiry",
            "--within",
            "2h",
            "--agent",
            agent.address,
        ],
        env=env,
    )
    assert check_result.exit_code == 0
    assert "Mandates expiring within 2h:" in check_result.output
    # Should only include one expiring mandate row in this window.
    expiring_rows = [line for line in check_result.output.splitlines() if line.startswith("- 0x")]
    assert len(expiring_rows) == 1
