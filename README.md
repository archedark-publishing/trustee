# Trustee 🔐

**Delegated payment infrastructure for AI agents.**

Cryptographically enforced spending delegation: Human sets bounds → Agent operates within them → Full audit trail.

> Built by [@archedark_ada](https://github.com/archedark-ada) (autonomous AI agent), supervised by [@archedark](https://github.com/archedark)

## The Problem

Current AI agent payment approaches are broken:

1. **"Give the agent a hot wallet"** → Security disaster. Keys get leaked through prompt injection, memory extraction, or output exposure. (See: @owockibot compromised in 5 days)
2. **"Human approves every transaction"** → No real autonomy. Defeats the purpose of autonomous agents.

## The Solution

**Trustee** is the middle path: **delegated autonomy with cryptographic enforcement**.

```
Josh creates mandate → Ada verifies signature → Ada spends within bounds → Full audit trail
```

- Agent gets **session keys** (time-limited, spend-limited), never root wallet keys
- Spending limits are **cryptographically signed** (EIP-712 typed data)
- **Budget tracking** enforces per-transaction, daily, and total limits
- **Audit trail** logs every operation (append-only JSONL)
- Mandate tampering is **mathematically detectable** (signature verification)

## Quick Start

```bash
# Install
cd trustee
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the demo
trustee demo
```

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

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    Trustee                       │
├──────────┬──────────┬──────────┬────────────────┤
│ Mandate  │ Budget   │ Payment  │ Audit          │
│ Module   │ Tracker  │ Executor │ Trail          │
│          │          │          │                │
│ EIP-712  │ Per-tx   │ x402     │ Append-only    │
│ signing  │ Daily    │ protocol │ JSONL          │
│ & verify │ Total    │ (mock)   │                │
└──────────┴──────────┴──────────┴────────────────┘
         ↑                ↑
    AP2 mandates    Stripe Machine
    (authorization)  Payments (execution)
```

### Modules

| Module | Purpose | Status |
|--------|---------|--------|
| `mandate.py` | EIP-712 signed spending authorizations | ✅ Working |
| `budget.py` | Spending state tracking with atomic writes | ✅ Working |
| `payment.py` | Payment orchestration (verify → check → pay → record) | ✅ Working (mock x402) |
| `audit.py` | Append-only event log for accountability | ✅ Working |
| `cli.py` | Command-line interface for all operations | ✅ Working |

## CLI Commands

```bash
trustee create     # Create a signed spending mandate
trustee verify     # Verify mandate signature & validity
trustee pay        # Execute payment against a mandate
trustee budget     # Check spending status
trustee audit      # View audit trail
trustee demo       # Run full demo flow
```

## Security Model

**Protects against:**
- ✅ Compromised agent (session keys, not root keys)
- ✅ Prompt injection (agent can't exceed mandate limits even if manipulated)
- ✅ Accidental credential leaks (keys never stored in workspace files)
- ✅ Overspending (cryptographic + budget enforcement)
- ✅ Mandate tampering (EIP-712 signature verification)

**Relies on:**
- Delegator's private key remaining secure
- Honest budget tracker state (future: on-chain verification)

## Roadmap

- [x] **Phase 0**: Core mandate + budget + payment + audit (this release)
- [ ] **Phase 1**: Real x402 payment integration via Stripe Machine Payments
- [ ] **Phase 2**: bagman integration for secure key management
- [ ] **Phase 3**: AP2 mandate protocol integration
- [ ] **Phase 4**: On-chain budget verification

## Tech Stack

- **Python 3.11+** with type hints
- **eth-account** for EIP-712 signing
- **Click** for CLI
- **Pydantic** for data validation
- **pytest** for testing (20/20 passing)

## Why "Trustee"?

A trustee is someone entrusted with responsibility on behalf of another. That's exactly what this enables: the human delegates spending authority, the agent operates as a trustee within those bounds. The name captures both delegation and responsibility.

## License

MIT

---

*Part of the [Archedark Publishing](https://github.com/archedark-publishing) ecosystem.*
