# Trustee 🔐

**Delegated payment infrastructure for AI agents.**

Cryptographically enforced spending delegation: Human sets bounds → Agent operates within them → Full audit trail. Real crypto payments on Base via x402 protocol.

> Built by [@archedark_ada](https://github.com/archedark-ada) (autonomous AI agent), supervised by [@archedark](https://github.com/archedark)

## Status

| Component | Status | Description |
|-----------|--------|-------------|
| **Mandate System** | ✅ Complete | EIP-712 signed spending authorizations |
| **Budget Tracking** | ✅ Complete | Per-tx/daily/total limits with transactional reserve+commit |
| **x402 Payments** | ✅ Complete | Real USDC payments on Base via Coinbase facilitator |
| **Steward Security** | ✅ Complete | Session-based key management with auto-expiry |
| **Audit Trail** | ✅ Complete | Append-only JSONL event logging |
| **52 tests** | ✅ Passing | Full coverage across all modules |

**First testnet payment:** Feb 10, 2026 — $0.001 USDC on Base Sepolia ([view on Basescan](https://sepolia.basescan.org/token/0x036cbd53842c5426634e7929541ec2318f3dcf7e?a=0x273326453960864fba4d2f6cf09d65fa13e45297))

## The Problem

Current AI agent payment approaches are broken:

1. **"Give the agent a hot wallet"** → Security disaster. Keys leak through prompt injection, memory extraction, or output exposure.
2. **"Human approves every transaction"** → No real autonomy. Defeats the purpose of autonomous agents.

## The Solution

**Trustee** is the middle path: **delegated autonomy with cryptographic enforcement**.

```
Josh creates mandate → Steward creates session → Ada pays within bounds → Full audit trail
```

Even if the agent is compromised, the attacker gets:
- A session that expires in **minutes** (not permanent key access)
- Per-transaction spending caps (e.g., **$0.01 max per payment**)
- Total session budget (e.g., **$1 max total**)
- The root private key is **never exposed** to the agent

## Quick Start

```bash
# Install
git clone https://github.com/archedark-publishing/trustee.git
cd trustee
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the demo (mock payments, no wallet needed)
trustee demo
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                      Trustee                         │
├──────────┬──────────┬─────────────┬─────────────────┤
│ Mandate  │ Steward   │ x402 Client │ Audit           │
│ Module   │ Security │             │ Trail           │
│          │          │             │                 │
│ EIP-712  │ Session  │ Real USDC   │ Append-only     │
│ signing  │ keys     │ on Base     │ JSONL           │
│ & verify │ 1Pass    │ via SDK     │                 │
├──────────┼──────────┼─────────────┤                 │
│          │  Budget Tracker        │                 │
│          │  Per-tx / Daily / Total│                 │
└──────────┴───────────────────────┴─────────────────┘
```

### The Payment Flow

```
1. Human creates mandate (spending authorization, EIP-712 signed)
2. Steward worker process loads wallet key from 1Password into time-limited session
3. Agent receives StewardSigner (can sign, but never sees the key)
4. Agent hits x402-protected endpoint → gets 402 Payment Required
5. x402 SDK signs EIP-3009 TransferWithAuthorization
6. Coinbase facilitator verifies and settles USDC on Base
7. Budget tracker records spend, audit trail logs everything
8. Session expires → key wiped from memory
```

### Modules

| Module | Purpose |
|--------|---------|
| `mandate.py` | EIP-712 signed spending authorizations |
| `steward.py` | Session-based key management (1Password → time-limited sessions) |
| `x402_client.py` | Real x402 payments via official Coinbase SDK |
| `budget.py` | Transactional spending state with idempotency and tamper checks |
| `payment.py` | Payment orchestration (verify → check → pay → record) |
| `audit.py` | Append-only event log for accountability |
| `cli.py` | Command-line interface for all operations |

## Steward: Secure Key Management

The agent **never** sees the private key. Instead:

```python
from trustee.steward import Steward, SessionConfig
from trustee.x402_client import X402PaymentClient, X402Config, Network

# Create a time-limited session (worker loads key from 1Password)
steward = Steward()
session = steward.create_session(
    op_item="trustee-wallet",
    op_vault="MyVault",
    config=SessionConfig(
        max_spend_usd=5.0,      # Total session cap
        max_per_tx_usd=0.10,    # Per-transaction limit
        ttl_seconds=1800,        # 30 minute session
    ),
)

# Agent gets a signer (never sees the key!)
client = X402PaymentClient.from_steward_session(
    steward=steward,
    session_id=session.session_id,
    config=X402Config(network=Network.BASE_SEPOLIA),
)

# Make a real payment
result = client.pay(url="https://api.example.com/data")

# When done, destroy session (key wiped from memory)
steward.destroy_session(session.session_id)
```

## x402: Real Crypto Payments

Trustee uses the [x402 protocol](https://x402.org) for HTTP-native payments:

```python
from trustee.x402_client import X402PaymentClient, X402Config, Network

# Direct key access (for testing)
client = X402PaymentClient.from_private_key(
    private_key="0x...",
    config=X402Config(network=Network.BASE_SEPOLIA),
)

# Hit any x402-protected endpoint
result = client.pay(url="https://api.example.com/data")
# result.success → True
# result.tx_hash → "0x..." (on-chain proof)
# result.network → "eip155:84532"
```

Supports:
- **Base Sepolia** (testnet): `eip155:84532`
- **Base Mainnet** (production): `eip155:8453`
- **USDC** stablecoin via EIP-3009 TransferWithAuthorization
- Coinbase public facilitator at `x402.org/facilitator`

## Security Model

**Protects against:**
- ✅ **Compromised agent** — Session keys with minutes-long expiry, not root wallet
- ✅ **Prompt injection** — Can't exceed mandate/session limits even if manipulated
- ✅ **Credential leaks** — Keys never stored in files; 1Password → memory → wiped
- ✅ **Overspending** — Per-tx + daily + total limits, cryptographically + budget enforced
- ✅ **Local tampering** — Budget/audit integrity checks fail closed on modification
- ✅ **Mandate tampering** — EIP-712 signature verification catches any modification
- ✅ **Rounding drift** — Conservative rounding: amounts up, limits down

**Trust assumptions:**
- 1Password service account token is secure
- Delegator's private key remains secure
- Host OS/process isolation and endpoint integrity

## CLI

```bash
trustee create     # Create a signed spending mandate
trustee verify     # Verify mandate signature & validity
trustee pay        # Execute payment against a mandate
trustee budget     # Check spending status
trustee audit      # View audit trail
trustee demo       # Run full demo flow
```

Key handling order of preference:
1. Best: Steward session flow (`Steward.create_session(...)`) with 1Password reference.
2. Good: Hidden CLI prompt entry for key material.
3. Unsafe fallback: `--unsafe-allow-key-arg` (explicit opt-in; can leak via shell/process args).

## Demo Output

```
🎬 Trustee Demo — Delegated Payment Flow
==================================================

1️⃣  Generating test accounts...
   Delegator (Josh): 0xF73c...58Cb
   Delegate  (Ada):  0xAe6B...BC2E

2️⃣  Creating mandate (Josh authorizes Ada)...
   ✅ Mandate: mandate-6e75dc20
   Budget: $5.00 total | $1.00/tx | $3.00/day

3️⃣  Verifying mandate signature (Ada checks)...
   ✅ Valid mandate

4️⃣  Making payments...
   ✅ $0.50 → OpenAI (API call)
   ✅ $0.25 → Brave Search (Data lookup)
   ✅ $0.75 → GitHub Copilot (Tool access)
   ❌ $1.50 → Expensive Service: exceeds per-transaction limit

5️⃣  Budget summary...
   Spent: $1.50 of $5.00 | Remaining: $3.50 | Txns: 3

6️⃣  Audit trail...
   ✅ mandate_verified → spending_check → payment_completed (×3)
   ❌ spending_denied $1.50 (per-tx limit)

🎉 Demo complete! The agent never had access to the delegator's private key.
```

## Roadmap

- [x] **Phase 0**: Core mandate + budget + audit trail
- [x] **Phase 1**: Real x402 payments via Coinbase facilitator (Base Sepolia)
- [x] **Phase 2**: Steward secure key management (1Password + session keys)
- [ ] **Phase 3**: Mainnet deployment (Stripe crypto approved, ready to switch)
- [ ] **Phase 4**: AP2 mandate protocol integration
- [ ] **Phase 5**: On-chain budget verification

## Tech Stack

- **Python 3.11+** with type hints
- **eth-account** for EIP-712 signing
- **x402 SDK v2.0.0** (Coinbase) for payment protocol
- **1Password CLI** (`op`) for secure key storage
- **Click** for CLI
- **Pydantic** for data validation
- **pytest** — 52 tests passing

## Why "Trustee"?

A trustee is someone entrusted with responsibility on behalf of another. That's exactly what this enables: the human delegates spending authority, the agent operates as a trustee within those bounds. The name captures both delegation and responsibility.

## License

MIT

---

*Part of the [Archedark Publishing](https://github.com/archedark-publishing) ecosystem.*
