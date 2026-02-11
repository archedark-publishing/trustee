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
import sys
import time
from pathlib import Path
from typing import Optional

import click

from .mandate import Mandate, create_mandate, verify_mandate
from .budget import BudgetTracker
from .payment import PaymentExecutor, PaymentRequest, PaymentResult
from .audit import AuditTrail, EventType


# ── Storage ───────────────────────────────────────────────────────

TRUSTEE_DIR = Path.home() / ".trustee"
MANDATES_DIR = TRUSTEE_DIR / "mandates"


def _ensure_dirs():
    TRUSTEE_DIR.mkdir(parents=True, exist_ok=True)
    MANDATES_DIR.mkdir(parents=True, exist_ok=True)


def _save_mandate(mandate: Mandate) -> Path:
    _ensure_dirs()
    path = MANDATES_DIR / f"{mandate.mandate_id}.json"
    with open(path, "w") as f:
        json.dump(mandate.to_dict(), f, indent=2)
    return path


def _load_mandate(mandate_id: str) -> Optional[Mandate]:
    path = MANDATES_DIR / f"{mandate_id}.json"
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


# ── CLI ───────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="0.1.0")
def main():
    """Trustee — Delegated payment infrastructure for AI agents."""
    pass


@main.command()
@click.option("--delegator-key", prompt=True, hide_input=True,
              help="Delegator's Ethereum private key (hex)")
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
@click.option("--description", default="General spending authorization",
              help="Human-readable description")
def create(
    delegator_key: str,
    delegate_address: str,
    max_total: float,
    max_per_tx: float,
    daily_limit: Optional[float],
    duration: float,
    description: str,
):
    """Create and sign a new spending mandate."""
    audit = AuditTrail()
    
    try:
        mandate = create_mandate(
            delegator_key=delegator_key,
            delegate_address=delegate_address,
            max_total_usd=max_total,
            max_per_tx_usd=max_per_tx,
            duration_hours=duration,
            daily_limit_usd=daily_limit,
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


@main.command()
@click.argument("mandate_id")
@click.option("--amount", type=float, prompt=True, help="Amount in USD")
@click.option("--merchant", prompt=True, help="Merchant name")
@click.option("--description", default="Payment", help="Payment description")
@click.option("--dry-run", is_flag=True, help="Simulate without executing")
def pay(
    mandate_id: str,
    amount: float,
    merchant: str,
    description: str,
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
