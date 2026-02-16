"""
Trustee CLI — Delegated payment management for AI agents.

Commands:
    trustee create    Create a new spending mandate
    trustee verify    Verify a mandate's signature
    trustee pay       Execute a payment against a mandate
    trustee budget    Check budget status for a mandate
    trustee audit     View audit trail
    trustee demo      Run a full demo flow
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import click
from click.core import ParameterSource
from eth_account import Account

from .mandate import (
    AP2MandateStatus,
    DEFAULT_NETWORK,
    Mandate,
    create_ap2_mandate,
    create_mandate,
    verify_mandate,
)
from .mandate_registry import LocalMandateRegistry
from .mandate_store import MandateStore
from .budget import BudgetTracker
from .payment import PaymentExecutor, PaymentRequest, PaymentResult
from .audit import AuditTrail, EventType
from .storage import ensure_private_dir, ensure_private_file, safe_child_path


# ── Storage ───────────────────────────────────────────────────────

TRUSTEE_DIR = Path.home() / ".trustee"
MANDATES_DIR = TRUSTEE_DIR / "mandates"
AP2_MANDATES_DIR = TRUSTEE_DIR / "ap2_mandates"
DEFAULT_AP2_REGISTRY_PATH = TRUSTEE_DIR / "ap2_registry_state.json"

AP2_TEMPLATES = {
    "micro": {"max_per_tx": 100_000, "max_per_day": 500_000},
    "daily_ops": {"max_per_tx": 1_000_000, "max_per_day": 10_000_000},
    "vendor_locked": {"max_per_tx": 1_000_000, "max_per_day": 5_000_000},
}


def _ensure_dirs():
    ensure_private_dir(TRUSTEE_DIR)
    ensure_private_dir(MANDATES_DIR)


def _save_mandate(mandate: Mandate) -> Path:
    _ensure_dirs()
    path = safe_child_path(MANDATES_DIR, mandate.mandate_id, ".json")
    with open(path, "w") as f:
        json.dump(mandate.to_dict(), f, indent=2)
    ensure_private_file(path)
    return path


def _load_mandate(mandate_id: str) -> Optional[Mandate]:
    _ensure_dirs()
    path = safe_child_path(MANDATES_DIR, mandate_id, ".json")
    if not path.exists():
        # Try searching by prefix
        matches = list(MANDATES_DIR.glob(f"*{mandate_id}*.json"))
        if len(matches) == 1:
            path = matches[0]
        elif len(matches) > 1:
            click.echo(f"Multiple mandates match '{mandate_id}':")
            for m in matches:
                click.echo(f"  {m.stem}")
            return None
        else:
            return None
    
    with open(path) as f:
        return Mandate.from_dict(json.load(f))


def _ap2_store() -> MandateStore:
    _ensure_dirs()
    ensure_private_dir(AP2_MANDATES_DIR)
    return MandateStore(AP2_MANDATES_DIR)


def _ap2_registry() -> LocalMandateRegistry:
    _ensure_dirs()
    override_path = os.getenv("TRUSTEE_AP2_REGISTRY_STATE_PATH")
    path = Path(override_path) if override_path else DEFAULT_AP2_REGISTRY_PATH
    return LocalMandateRegistry(path)


def _parse_duration_to_seconds(value: str) -> int:
    raw = value.strip().lower()
    if raw in {"never", "none", "0"}:
        return 0
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(raw) < 2 or raw[-1] not in units or not raw[:-1].isdigit():
        raise ValueError(f"Invalid duration: {value} (expected formats like 72h, 30d, never)")
    return int(raw[:-1]) * units[raw[-1]]


def _resolve_private_key(key_input: str) -> str:
    candidate = key_input.strip()
    if candidate.startswith("op://"):
        result = subprocess.run(
            ["op", "read", candidate],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to read key from 1Password reference: {result.stderr.strip()}")
        candidate = result.stdout.strip()

    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if len(candidate) != 64:
        raise ValueError("Private key must be a 32-byte hex string or valid op:// reference")
    int(candidate, 16)
    return "0x" + candidate


def _parse_recipients(recipients_raw: str) -> list[str]:
    if not recipients_raw.strip():
        return []
    return [item.strip() for item in recipients_raw.split(",") if item.strip()]


def _load_ap2_by_hash(store: MandateStore, registry: LocalMandateRegistry, mandate_hash: str):
    mandate = store.get_mandate(mandate_hash)
    status = registry.get_mandate_status(mandate_hash)

    if mandate is not None and status.exists:
        if status.revoked and mandate.status != AP2MandateStatus.REVOKED.value:
            store.update_status(mandate_hash, AP2MandateStatus.REVOKED.value)
            mandate = store.get_mandate(mandate_hash)
        elif status.active and mandate.status != AP2MandateStatus.ACTIVE.value:
            store.update_status(mandate_hash, AP2MandateStatus.ACTIVE.value)
            mandate = store.get_mandate(mandate_hash)
    return mandate, status


# ── CLI ───────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="0.1.0")
def main():
    """Trustee — Delegated payment infrastructure for AI agents."""
    pass


@main.command()
@click.option("--delegator-key", prompt=True, hide_input=True,
              help="Delegator's Ethereum private key (hex)")
@click.option(
    "--unsafe-allow-key-arg",
    is_flag=True,
    default=False,
    help="Allow passing --delegator-key via argv (unsafe; can leak in shell/process history).",
)
@click.option("--delegate-address", prompt=True,
              help="Delegate's Ethereum address")
@click.option("--max-total", type=float, prompt=True,
              help="Maximum total spending (USD)")
@click.option("--max-per-tx", type=float, prompt=True,
              help="Maximum per-transaction (USD)")
@click.option("--daily-limit", type=float, default=None,
              help="Optional daily spending cap (USD)")
@click.option("--duration", type=float, default=24.0,
              help="Mandate duration in hours (default: 24)")
@click.option("--network", type=str, default=DEFAULT_NETWORK,
              help="Mandate network in CAIP-2 format (default: eip155:8453)")
@click.option("--description", default="General spending authorization",
              help="Human-readable description")
def create(
    delegator_key: str,
    unsafe_allow_key_arg: bool,
    delegate_address: str,
    max_total: float,
    max_per_tx: float,
    daily_limit: Optional[float],
    duration: float,
    network: str,
    description: str,
):
    """Create and sign a new spending mandate."""
    audit = AuditTrail()

    ctx = click.get_current_context(silent=True)
    key_from_argv = (
        ctx is not None
        and ctx.get_parameter_source("delegator_key") == ParameterSource.COMMANDLINE
    )
    if key_from_argv and not unsafe_allow_key_arg:
        click.echo(
            "❌ Refusing --delegator-key from argv. Re-run with prompt input or pass "
            "--unsafe-allow-key-arg to acknowledge the risk.",
            err=True,
        )
        sys.exit(1)
    
    try:
        mandate = create_mandate(
            delegator_key=delegator_key,
            delegate_address=delegate_address,
            max_total_usd=max_total,
            max_per_tx_usd=max_per_tx,
            duration_hours=duration,
            daily_limit_usd=daily_limit,
            network=network,
            description=description,
        )
    except Exception as e:
        click.echo(f"❌ Failed to create mandate: {e}", err=True)
        sys.exit(1)
    
    path = _save_mandate(mandate)
    
    audit.log(
        EventType.MANDATE_CREATED,
        mandate_id=mandate.mandate_id,
        delegator=mandate.delegator_address,
        delegate=mandate.delegate_address,
        details={
            "max_total_usd": max_total,
            "max_per_tx_usd": max_per_tx,
            "duration_hours": duration,
            "network": network,
        },
    )
    
    click.echo(f"✅ Mandate created: {mandate.mandate_id}")
    click.echo(f"   Delegator: {mandate.delegator_address}")
    click.echo(f"   Delegate:  {mandate.delegate_address}")
    click.echo(f"   Budget:    ${max_total:.2f} total, ${max_per_tx:.2f}/tx")
    if daily_limit:
        click.echo(f"   Daily cap: ${daily_limit:.2f}")
    click.echo(f"   Expires:   {time.strftime('%Y-%m-%d %H:%M', time.localtime(mandate.expires_at))}")
    click.echo(f"   Saved to:  {path}")


@main.command()
@click.argument("mandate_id")
def verify(mandate_id: str):
    """Verify a mandate's signature and validity."""
    mandate = _load_mandate(mandate_id)
    if not mandate:
        click.echo(f"❌ Mandate not found: {mandate_id}", err=True)
        sys.exit(1)
    
    valid, reason = verify_mandate(mandate)
    
    if valid:
        click.echo(f"✅ Mandate is valid: {reason}")
        click.echo(f"   ID:        {mandate.mandate_id}")
        click.echo(f"   Delegator: {mandate.delegator_address}")
        click.echo(f"   Budget:    ${mandate.spending_limit.max_total_usd:.2f}")
        click.echo(f"   Expires:   {time.strftime('%Y-%m-%d %H:%M', time.localtime(mandate.expires_at))}")
    else:
        click.echo(f"❌ Mandate is invalid: {reason}")
        sys.exit(1)


@main.group("mandate")
def mandate_group():
    """AP2 mandate lifecycle operations."""
    pass


@mandate_group.command("issue")
@click.option("--agent", required=True, help="Agent wallet address")
@click.option(
    "--asset-id",
    required=True,
    help="Asset identifier (CAIP-19), e.g. eip155:8453/erc20:0x...",
)
@click.option("--max-per-tx", type=int, default=None, help="Max amount per transaction (base units)")
@click.option("--max-per-day", type=int, default=None, help="Max amount per day (base units)")
@click.option("--recipients", default="", help="Comma-separated allowlist of recipient addresses")
@click.option("--expires-in", default="30d", help="Duration until expiry (e.g., 72h, 30d, never)")
@click.option("--issuer-key", prompt=True, hide_input=True, help="Issuer private key hex or op:// reference")
@click.option(
    "--unsafe-allow-key-arg",
    is_flag=True,
    default=False,
    help="Allow passing --issuer-key via argv (unsafe; can leak in shell/process history).",
)
@click.option("--metadata-uri", default="", help="Metadata URI (ipfs://... or https://...)")
@click.option("--network", default=DEFAULT_NETWORK, help="CAIP-2 network, default eip155:8453")
@click.option(
    "--verifying-contract",
    default=lambda: os.getenv("MANDATE_REGISTRY_ADDRESS", "0x0000000000000000000000000000000000000001"),
    show_default="env MANDATE_REGISTRY_ADDRESS or zero-address placeholder",
    help="Verifying contract address for EIP-712 domain",
)
@click.option("--nonce", type=int, default=None, help="Nonce override (default: current timestamp)")
@click.option(
    "--template",
    type=click.Choice(sorted(AP2_TEMPLATES.keys()), case_sensitive=False),
    default=None,
    help="Apply a predefined template for max-per-tx/max-per-day",
)
def mandate_issue(
    agent: str,
    asset_id: str,
    max_per_tx: Optional[int],
    max_per_day: Optional[int],
    recipients: str,
    expires_in: str,
    issuer_key: str,
    unsafe_allow_key_arg: bool,
    metadata_uri: str,
    network: str,
    verifying_contract: str,
    nonce: Optional[int],
    template: Optional[str],
):
    """Issue an AP2 mandate and register it in the local registry adapter."""
    ctx = click.get_current_context(silent=True)
    key_from_argv = (
        ctx is not None
        and ctx.get_parameter_source("issuer_key") == ParameterSource.COMMANDLINE
    )
    if key_from_argv and not unsafe_allow_key_arg:
        click.echo(
            "❌ Refusing --issuer-key from argv. Re-run with prompt input or pass "
            "--unsafe-allow-key-arg to acknowledge the risk.",
            err=True,
        )
        sys.exit(1)

    selected_template = template.lower() if template else None
    if selected_template:
        template_values = AP2_TEMPLATES[selected_template]
        if max_per_tx is None:
            max_per_tx = int(template_values["max_per_tx"])
        if max_per_day is None:
            max_per_day = int(template_values["max_per_day"])

    if max_per_tx is None or max_per_day is None:
        click.echo("❌ --max-per-tx and --max-per-day are required (or supply --template).", err=True)
        sys.exit(1)

    try:
        expires_delta = _parse_duration_to_seconds(expires_in)
        expires_at = int(time.time()) + expires_delta if expires_delta > 0 else 0
        private_key = _resolve_private_key(issuer_key)
        issuer_address = Account.from_key(private_key).address
        mandate = create_ap2_mandate(
            issuer_key=private_key,
            agent=agent,
            asset_id=asset_id,
            max_amount_per_tx=max_per_tx,
            max_amount_per_day=max_per_day,
            allowed_recipients=_parse_recipients(recipients),
            expires_at=expires_at,
            nonce=nonce if nonce is not None else int(time.time()),
            metadata_uri=metadata_uri,
            network=network,
            verifying_contract=verifying_contract,
        )
    except Exception as exc:
        click.echo(f"❌ Failed to build mandate: {exc}", err=True)
        sys.exit(1)

    store = _ap2_store()
    registry = _ap2_registry()

    try:
        mandate.status = AP2MandateStatus.PENDING_ON_CHAIN.value
        store.save_mandate(mandate)
        tx_hash = registry.issue_mandate(
            mandate_hash=mandate.mandate_hash,
            payload_hash=mandate.payload_hash,
            issuer=issuer_address,
            agent=mandate.agent,
            expires_at=mandate.expires_at,
            metadata_uri=mandate.metadata_uri,
        )
        # Local registry adapter has no real block numbers; use 0 sentinel.
        store.record_chain_confirmation(mandate.mandate_hash, tx_hash=tx_hash, block_number=0)
    except Exception as exc:
        try:
            store.update_status(mandate.mandate_hash, AP2MandateStatus.FAILED.value, reason=str(exc))
        except Exception:
            pass
        click.echo(f"❌ Failed to issue mandate: {exc}", err=True)
        sys.exit(1)

    click.echo(f"✓ Mandate issued: {mandate.mandate_hash}")
    click.echo(f"  Status: active")
    click.echo(f"  Transaction: {tx_hash}")
    click.echo(f"  Expires: {mandate.expires_at if mandate.expires_at else 'Never'}")


@mandate_group.command("revoke")
@click.option("--mandate-hash", required=True, help="Mandate hash")
@click.option("--issuer-key", prompt=True, hide_input=True, help="Issuer private key hex or op:// reference")
@click.option(
    "--unsafe-allow-key-arg",
    is_flag=True,
    default=False,
    help="Allow passing --issuer-key via argv (unsafe; can leak in shell/process history).",
)
def mandate_revoke(mandate_hash: str, issuer_key: str, unsafe_allow_key_arg: bool):
    """Revoke an AP2 mandate."""
    ctx = click.get_current_context(silent=True)
    key_from_argv = (
        ctx is not None
        and ctx.get_parameter_source("issuer_key") == ParameterSource.COMMANDLINE
    )
    if key_from_argv and not unsafe_allow_key_arg:
        click.echo(
            "❌ Refusing --issuer-key from argv. Re-run with prompt input or pass "
            "--unsafe-allow-key-arg to acknowledge the risk.",
            err=True,
        )
        sys.exit(1)

    try:
        private_key = _resolve_private_key(issuer_key)
        issuer_address = Account.from_key(private_key).address
    except Exception as exc:
        click.echo(f"❌ Failed to load issuer key: {exc}", err=True)
        sys.exit(1)

    store = _ap2_store()
    registry = _ap2_registry()

    try:
        tx_hash = registry.revoke_mandate(mandate_hash, issuer_address)
        if store.get_mandate(mandate_hash) is not None:
            store.mark_revoked(mandate_hash)
    except Exception as exc:
        click.echo(f"❌ Failed to revoke mandate: {exc}", err=True)
        sys.exit(1)

    click.echo(f"✓ Mandate revoked: {mandate_hash}")
    click.echo(f"  Transaction: {tx_hash}")


@mandate_group.command("list")
@click.option("--agent", required=True, help="Agent wallet address")
@click.option("--include-inactive", is_flag=True, help="Include revoked/expired/failed mandates")
def mandate_list(agent: str, include_inactive: bool):
    """List AP2 mandates for an agent."""
    store = _ap2_store()
    registry = _ap2_registry()

    try:
        mandates = store.list_mandates(agent, include_inactive=True)
    except Exception as exc:
        click.echo(f"❌ Failed to list mandates: {exc}", err=True)
        sys.exit(1)

    if not mandates:
        click.echo("No mandates found")
        return

    rows = []
    for mandate in mandates:
        local, status = _load_ap2_by_hash(store, registry, mandate.mandate_hash)
        if local is None:
            continue
        if not include_inactive and local.status != AP2MandateStatus.ACTIVE.value:
            continue
        rows.append((local, status))

    if not rows:
        click.echo("No mandates found")
        return

    for mandate, status in rows:
        click.echo(f"\\n{mandate.mandate_hash}")
        click.echo(f"  Status: {mandate.status}")
        click.echo(f"  On-chain active: {status.active}")
        click.echo(f"  Issued: {mandate.issued_at}")
        click.echo(f"  Expires: {mandate.expires_at or 'Never'}")
        click.echo(f"  Max/tx: {mandate.max_amount_per_tx}")
        click.echo(f"  Max/day: {mandate.max_amount_per_day}")
        if mandate.allowed_recipients:
            click.echo(f"  Recipients: {', '.join(mandate.allowed_recipients)}")


@mandate_group.command("status")
@click.option("--mandate-hash", required=True, help="Mandate hash")
def mandate_status(mandate_hash: str):
    """Show local and registry status for one AP2 mandate."""
    store = _ap2_store()
    registry = _ap2_registry()

    mandate, status = _load_ap2_by_hash(store, registry, mandate_hash)
    if mandate is None and not status.exists:
        click.echo(f"❌ Mandate not found: {mandate_hash}", err=True)
        sys.exit(1)

    click.echo(f"Mandate: {mandate_hash}")
    click.echo(f"Registry exists: {status.exists}")
    click.echo(f"Registry active: {status.active}")
    click.echo(f"Registry revoked: {status.revoked}")
    click.echo(f"Registry expiresAt: {status.expires_at}")
    click.echo(f"Registry issuer: {status.issuer or 'N/A'}")
    click.echo(f"Registry agent: {status.agent or 'N/A'}")
    if mandate is not None:
        click.echo(f"Local status: {mandate.status}")
        click.echo(f"Local payload hash: {mandate.payload_hash}")
        click.echo(f"Local issued_at: {mandate.issued_at}")
        if mandate.failure_reason:
            click.echo(f"Local failure_reason: {mandate.failure_reason}")


@mandate_group.command("trust-issuer")
@click.option("--agent", required=True, help="Agent wallet address")
@click.option("--issuer", required=True, help="Issuer wallet address")
@click.option("--allow/--deny", default=True, help="Allow or remove issuer trust")
def mandate_trust_issuer(agent: str, issuer: str, allow: bool):
    """Manage trusted issuer list for an agent."""
    registry = _ap2_registry()
    try:
        registry.set_trusted_issuer(agent, issuer, allow)
    except Exception as exc:
        click.echo(f"❌ Failed to update trusted issuer: {exc}", err=True)
        sys.exit(1)

    click.echo(f"✓ Trusted issuer updated: agent={agent} issuer={issuer} allowed={allow}")


@mandate_group.command("pause-agent")
@click.option("--agent", required=True, help="Agent wallet address")
@click.option("--pause", type=bool, required=True, help="true to pause, false to unpause")
def mandate_pause_agent(agent: str, pause: bool):
    """Pause or unpause an agent."""
    registry = _ap2_registry()
    try:
        registry.set_agent_paused(agent, pause)
    except Exception as exc:
        click.echo(f"❌ Failed to update pause state: {exc}", err=True)
        sys.exit(1)

    click.echo(f"✓ Agent pause updated: agent={agent} paused={pause}")


@mandate_group.command("check-expiry")
@click.option("--within", required=True, help="Lookahead window (e.g. 72h, 7d)")
@click.option("--agent", default=None, help="Optional agent filter")
@click.option("--webhook-url", default=None, help="Optional webhook URL for expiry notifications")
def mandate_check_expiry(within: str, agent: Optional[str], webhook_url: Optional[str]):
    """Report mandates expiring within a window and optionally POST to webhook."""
    try:
        horizon_seconds = _parse_duration_to_seconds(within)
    except Exception as exc:
        click.echo(f"❌ Invalid --within value: {exc}", err=True)
        sys.exit(1)
    if horizon_seconds <= 0:
        click.echo("❌ --within must be a positive duration", err=True)
        sys.exit(1)

    store = _ap2_store()
    now = int(time.time())
    expires_before = now + horizon_seconds

    mandates = []
    if agent:
        mandates = store.list_mandates(agent, include_inactive=True)
    else:
        for path in sorted(AP2_MANDATES_DIR.glob("*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    payload = json.load(f)
                mandates.append(store.get_mandate(payload["mandate_hash"]))
            except Exception:
                continue
        mandates = [m for m in mandates if m is not None]

    expiring = [
        m
        for m in mandates
        if m.status == AP2MandateStatus.ACTIVE.value
        and m.expires_at != 0
        and now <= m.expires_at <= expires_before
    ]

    if not expiring:
        click.echo("No active mandates expiring in the selected window.")
        return

    click.echo(f"Mandates expiring within {within}:")
    for mandate in expiring:
        remaining = mandate.expires_at - now
        click.echo(f"- {mandate.mandate_hash} (agent={mandate.agent}, expires_at={mandate.expires_at}, in={remaining}s)")

    if webhook_url:
        try:
            import httpx

            body = {
                "event": "mandate_expiry_warning",
                "within": within,
                "count": len(expiring),
                "mandates": [
                    {
                        "mandate_hash": m.mandate_hash,
                        "agent": m.agent,
                        "expires_at": m.expires_at,
                    }
                    for m in expiring
                ],
            }
            response = httpx.post(webhook_url, json=body, timeout=5.0)
            response.raise_for_status()
            click.echo(f"Webhook delivered: {webhook_url}")
        except Exception as exc:
            click.echo(f"❌ Failed to deliver webhook: {exc}", err=True)
            sys.exit(1)


@main.command()
@click.argument("mandate_id")
@click.option("--amount", type=float, prompt=True, help="Amount in USD")
@click.option("--merchant", prompt=True, help="Merchant name")
@click.option("--description", default="Payment", help="Payment description")
@click.option("--merchant-endpoint", default=None, help="x402-protected endpoint URL")
@click.option("--category", default=None, help="Payment category label")
@click.option("--network", default=None, help="Active payment network (CAIP-2)")
@click.option("--dry-run", is_flag=True, help="Simulate without executing")
def pay(
    mandate_id: str,
    amount: float,
    merchant: str,
    description: str,
    merchant_endpoint: Optional[str],
    category: Optional[str],
    network: Optional[str],
    dry_run: bool,
):
    """Execute a payment against a mandate."""
    mandate = _load_mandate(mandate_id)
    if not mandate:
        click.echo(f"❌ Mandate not found: {mandate_id}", err=True)
        sys.exit(1)
    
    budget = BudgetTracker()
    audit = AuditTrail()
    executor = PaymentExecutor(budget, audit, dry_run=dry_run)
    
    request = PaymentRequest(
        mandate_id=mandate.mandate_id,
        amount_usd=amount,
        merchant=merchant,
        description=description,
        merchant_endpoint=merchant_endpoint,
        category=category,
        network=network,
    )
    
    if dry_run:
        click.echo("🔍 DRY RUN — no actual payment will be made")
    
    result = executor.execute(mandate, request)
    
    if result.success:
        click.echo(f"✅ Payment {'simulated' if dry_run else 'completed'}!")
        click.echo(f"   Amount:    ${result.amount_usd:.2f}")
        click.echo(f"   Tx ID:     {result.tx_id}")
        click.echo(f"   x402 ID:   {result.x402_payment_id}")
        
        # Show remaining budget
        summary = budget.get_summary(
            mandate.mandate_id,
            mandate.spending_limit.max_total_usd,
        )
        click.echo(f"   Remaining: {summary['remaining']} of {summary['total_budget']}")
    else:
        click.echo(f"❌ Payment failed: {result.reason}")
        sys.exit(1)


@main.command()
@click.argument("mandate_id")
def budget(mandate_id: str):
    """Check budget status for a mandate."""
    mandate = _load_mandate(mandate_id)
    if not mandate:
        click.echo(f"❌ Mandate not found: {mandate_id}", err=True)
        sys.exit(1)
    
    tracker = BudgetTracker()
    summary = tracker.get_summary(
        mandate.mandate_id,
        mandate.spending_limit.max_total_usd,
    )
    
    click.echo(f"📊 Budget for {mandate.mandate_id}")
    click.echo(f"   Spent:        {summary['total_spent']} of {summary['total_budget']}")
    click.echo(f"   Remaining:    {summary['remaining']}")
    click.echo(f"   Utilization:  {summary['utilization']}")
    click.echo(f"   Transactions: {summary['transactions']}")
    click.echo(f"   Today:        {summary['daily_spent']}")


@main.command()
@click.option("--mandate-id", default=None, help="Filter by mandate ID")
@click.option("--limit", type=int, default=20, help="Number of events")
def audit(mandate_id: Optional[str], limit: int):
    """View the audit trail."""
    trail = AuditTrail()
    events = trail.read_events(mandate_id=mandate_id, limit=limit)
    
    if not events:
        click.echo("No audit events found.")
        return
    
    for event in events:
        ts = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
        status = "✅" if event.success else "❌"
        amount = f" ${event.amount_usd:.2f}" if event.amount_usd else ""
        merchant = f" → {event.merchant}" if event.merchant else ""
        reason = f" ({event.reason})" if event.reason and not event.success else ""
        click.echo(f"  {ts} {status} {event.event_type}{amount}{merchant}{reason}")


@main.command()
def demo():
    """Run a full demo of the Trustee delegation flow."""
    from eth_account import Account
    
    click.echo("🎬 Trustee Demo — Delegated Payment Flow")
    click.echo("=" * 50)
    
    # Generate test keys
    click.echo("\n1️⃣  Generating test accounts...")
    delegator = Account.create()
    delegate = Account.create()
    click.echo(f"   Delegator (Josh): {delegator.address}")
    click.echo(f"   Delegate  (Ada):  {delegate.address}")
    
    # Create mandate
    click.echo("\n2️⃣  Creating mandate (Josh authorizes Ada)...")
    mandate = create_mandate(
        delegator_key=delegator.key.hex(),
        delegate_address=delegate.address,
        max_total_usd=5.00,
        max_per_tx_usd=1.00,
        daily_limit_usd=3.00,
        duration_hours=24.0,
        description="Demo: Ada can spend up to $5, max $1/tx, $3/day",
    )
    _save_mandate(mandate)
    click.echo(f"   ✅ Mandate: {mandate.mandate_id}")
    click.echo(f"   Budget: $5.00 total | $1.00/tx | $3.00/day")
    
    # Verify
    click.echo("\n3️⃣  Verifying mandate signature (Ada checks)...")
    valid, reason = verify_mandate(mandate)
    click.echo(f"   {'✅' if valid else '❌'} {reason}")
    
    # Set up executor
    budget_tracker = BudgetTracker()
    audit_trail = AuditTrail()
    executor = PaymentExecutor(budget_tracker, audit_trail, dry_run=True)
    
    # Make payments
    click.echo("\n4️⃣  Making payments...")
    
    payments = [
        ("API call", 0.50, "OpenAI"),
        ("Data lookup", 0.25, "Brave Search"),
        ("Tool access", 0.75, "GitHub Copilot"),
        ("Over per-tx limit", 1.50, "Expensive Service"),  # Should fail
    ]
    
    for desc, amount, merchant in payments:
        result = executor.execute(mandate, PaymentRequest(
            mandate_id=mandate.mandate_id,
            amount_usd=amount,
            merchant=merchant,
            description=desc,
        ))
        status = "✅" if result.success else "❌"
        if result.success:
            click.echo(f"   {status} ${amount:.2f} → {merchant} ({desc})")
        else:
            click.echo(f"   {status} ${amount:.2f} → {merchant}: {result.reason}")
    
    # Budget summary
    click.echo("\n5️⃣  Budget summary...")
    summary = budget_tracker.get_summary(
        mandate.mandate_id,
        mandate.spending_limit.max_total_usd,
    )
    click.echo(f"   Spent:     {summary['total_spent']} of {summary['total_budget']}")
    click.echo(f"   Remaining: {summary['remaining']}")
    click.echo(f"   Today:     {summary['daily_spent']}")
    click.echo(f"   Txns:      {summary['transactions']}")
    
    # Audit trail
    click.echo("\n6️⃣  Audit trail (last 10 events)...")
    events = audit_trail.read_events(mandate_id=mandate.mandate_id, limit=10)
    for event in events:
        ts = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
        status = "✅" if event.success else "❌"
        amount = f" ${event.amount_usd:.2f}" if event.amount_usd else ""
        click.echo(f"   {ts} {status} {event.event_type}{amount}")
    
    click.echo("\n" + "=" * 50)
    click.echo("🎉 Demo complete! Mandate → Verify → Pay → Track → Audit")
    click.echo("   All delegation was cryptographically enforced.")
    click.echo("   The agent never had access to the delegator's private key.")


if __name__ == "__main__":
    main()
