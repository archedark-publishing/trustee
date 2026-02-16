# Trustee Architecture

**Version:** 0.1 (Architecture Phase)  
**Last Updated:** 2026-02-10  
**Status:** Research & Design

---

## Problem Statement

Current AI agent payment models require either:
1. **Full trust** - Agent has access to root wallet, can spend anything
2. **Full dependency** - Human manually approves every transaction
3. **No autonomy** - Agent can't transact at all

**Trustee solves this** with cryptographically enforced delegation: human sets bounds, agent operates within them, full audit trail, instant revocation.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Human (Josh)                        │
│  - Creates AP2 Intent Mandate (budget + rules)              │
│  - Manages mandate lifecycle (update/revoke)                │
│  - Monitors spending via audit trail                        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ AP2 Mandate
                     │ (cryptographically signed)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                        steward Layer                         │
│  - Verifies mandate is valid                                │
│  - Provisions session key (NOT root wallet key)             │
│  - Enforces spend limits                                    │
│  - Output sanitization (catches keys before leak)           │
│  - Prompt injection defense                                 │
│  - Stores secrets via 1Password                             │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ Session Key
                     │ (time-limited, spend-limited)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Agent (Ada)                            │
│  - Requests session key for payment                         │
│  - Makes x402 payment within authorized bounds              │
│  - Logs transaction for own records                         │
│  - NEVER sees root wallet private key                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ x402 Payment Request
                     │ (HTTP + X-PAYMENT header)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  Payment Processor                          │
│  - Stripe Machine Payments                                  │
│  - Verifies x402 payment signature                          │
│  - Broadcasts USDC transaction on Base                      │
│  - Returns confirmation                                     │
└─────────────────────────────────────────────────────────────┘
                     │
                     │ Blockchain Settlement
                     ▼
                  ✅ Payment Complete
                  📋 Audit Trail Updated
```

---

## Core Components

### 1. AP2 Mandate Layer
**What it does:** Cryptographic proof of authorization

**Intent Mandate Structure (conceptual):**
```json
{
  "mandateId": "uuid-here",
  "issuer": "josh@example.com",
  "agent": "ada@example.com",
  "rules": {
    "monthlyBudget": 100.00,
    "maxPerTransaction": 10.00,
    "allowedCategories": ["infrastructure", "tools", "research"],
    "validFrom": "2026-02-01T00:00:00Z",
    "validUntil": "2026-03-01T00:00:00Z"
  },
  "signature": "cryptographic-signature-here"
}
```

**Cart Mandate Structure (conceptual):**
```json
{
  "mandateId": "uuid-here",
  "intentMandateRef": "parent-uuid",
  "items": [
    {
      "description": "API call to service X",
      "amount": 0.50,
      "currency": "USD"
    }
  ],
  "total": 0.50,
  "timestamp": "2026-02-10T18:30:00Z",
  "signature": "cryptographic-signature-here"
}
```

**Unknowns:**
- [ ] Exact mandate format (JSON? Custom structure?)
- [ ] Signing mechanism (what crypto primitives? ECDSA? EdDSA?)
- [ ] Verification process (who verifies? steward? payment processor?)
- [ ] Revocation mechanism (on-chain? off-chain registry? CRL?)
- [ ] Reference implementations available?

---

### 2. steward Security Layer
**What it does:** Session key provisioning + secret isolation + output sanitization

**Session Key Lifecycle (conceptual):**
1. Agent requests session key for payment
2. steward verifies Intent Mandate is valid
3. steward checks spend limits haven't been exceeded
4. steward provisions ephemeral session key (NOT root wallet key)
5. Session key has time limit (e.g., 1 hour) and spend limit (e.g., $10)
6. Agent uses session key for x402 payment
7. Session key expires automatically

**Security Features:**
- Secrets stored in 1Password (never in files/code)
- Output sanitization catches private keys before they leak to chat
- Prompt injection defense prevents adversarial extraction
- Session keys auto-expire (time + spend limits)

**Unknowns:**
- [ ] steward API for requesting session key
- [ ] How are spend limits enforced? (client checks? server validation? blockchain?)
- [ ] Session key format (standard? custom?)
- [ ] Key rotation mechanism
- [ ] Error handling when limits exceeded
- [ ] Integration with 1Password (storage format?)
- [ ] Output sanitization implementation (regex? AST parsing?)

---

### 3. x402 Payment Execution
**What it does:** HTTP-native payment protocol

**Flow:**
1. Agent makes HTTP request: `GET /api/service`
2. Server responds: `402 Payment Required` with payment details
3. Agent parses payment info (amount, token, recipient)
4. Agent requests session key from steward
5. steward returns session key (if authorized)
6. Agent signs payment with session key
7. Agent re-sends request with `X-PAYMENT` header
8. Server verifies payment, broadcasts on-chain
9. Server responds: `200 OK` with resource + `X-PAYMENT-RESPONSE` confirmation

**Unknowns:**
- [ ] How to attach AP2 mandate to x402 payment? (custom header? payload extension?)
- [ ] Does Stripe Machine Payments support mandate verification natively?
- [ ] Integration between steward session keys and x402 signature format
- [ ] Error handling for failed payments

---

### 4. Stripe Machine Payments Integration
**What it does:** Payment processing layer

**Known:**
- PaymentIntents API for agent payments
- USDC stablecoins on Base blockchain
- x402 protocol support
- Sales tax, refunds, reporting

**Unknowns:**
- [ ] Does Stripe support AP2 mandates natively?
- [ ] Or do we verify mandates ourselves before calling Stripe?
- [ ] Can session keys work with Stripe's API?
- [ ] What's the webhook flow for payment confirmation?
- [ ] How to map crypto wallet to Stripe account?

---

## User Flows

### Flow 1: Josh Creates Budget Mandate

1. Josh opens mandate management interface (CLI? Web UI?)
2. Josh creates Intent Mandate:
   - Monthly budget: $100
   - Max per transaction: $10
   - Allowed categories: infrastructure, tools
   - Valid for: Feb 2026
3. Josh signs mandate with his key
4. Mandate is stored (where? steward? blockchain? both?)
5. Ada receives notification: "You now have $100 budget for February"

**Unknowns:**
- [ ] Interface for Josh (existing tooling? custom build?)
- [ ] Where are mandates stored? (centralized DB? decentralized ledger?)
- [ ] Notification mechanism to agent

---

### Flow 2: Ada Makes Autonomous Payment

1. Ada needs to pay $0.50 for API call
2. Ada checks: Is this within my budget? (Intent Mandate rules)
3. Ada creates Cart Mandate (specific items + amount)
4. Ada requests session key from steward:
   ```
   steward.requestKey({
     mandate: intentMandateId,
     cart: cartMandate,
     amount: 0.50
   })
   ```
5. steward verifies:
   - Intent Mandate is valid
   - Amount within limits
   - Categories allowed
   - Not over budget
6. steward returns session key (or rejects if over limit)
7. Ada makes x402 payment using session key
8. Payment settles on-chain
9. Ada logs transaction locally
10. Budget decremented ($99.50 remaining)

**Unknowns:**
- [ ] steward API syntax (actual function signatures?)
- [ ] Where is budget state tracked? (steward? blockchain? both?)
- [ ] Real-time vs. eventual consistency for budget checks
- [ ] Concurrent transaction handling

---

### Flow 3: Josh Monitors Spending

1. Josh opens audit dashboard
2. Dashboard shows:
   - Current budget: $99.50 / $100
   - Transactions this month: 1
   - Last transaction: $0.50 to service X at [timestamp]
   - Categories: infrastructure (1)
3. Josh can:
   - View full transaction history
   - Export for accounting
   - Adjust budget mid-month
   - Revoke mandate

**Unknowns:**
- [ ] Dashboard implementation (existing? custom?)
- [ ] Where is transaction data pulled from? (blockchain? steward logs? both?)
- [ ] Real-time updates or polling?

---

### Flow 4: Josh Revokes Mandate

1. Josh decides to revoke budget (emergency or just changing plans)
2. Josh clicks "Revoke" in dashboard
3. Revocation is cryptographically signed
4. Revocation propagated to:
   - steward (stops issuing session keys)
   - Blockchain (optional: on-chain revocation record)
5. Ada receives notification: "Your budget has been revoked"
6. Any in-flight session keys expire immediately (or finish current transaction?)
7. Ada can no longer spend from this mandate

**Unknowns:**
- [ ] Revocation mechanism (instant? grace period?)
- [ ] What happens to in-flight transactions?
- [ ] On-chain vs. off-chain revocation
- [ ] Notification delivery

---

## Security Model

### Threat Model

**What we're protecting against:**
1. **Compromised agent** - Even if Ada's entire system is compromised, attacker only gets session keys (limited time/spend)
2. **Prompt injection** - Adversarial inputs trying to extract wallet keys (steward output sanitization catches this)
3. **Accidental leaks** - Agent accidentally logs/shares private key (steward prevents key from ever reaching agent)
4. **Overspending** - Agent tries to spend beyond authorized bounds (cryptographically enforced limits)
5. **Unauthorized transactions** - Someone impersonating agent (mandate signatures required)

**What we're NOT protecting against (out of scope):**
- Compromised human (if Josh's signing key is stolen, attacker can create malicious mandates)
- Compromised steward (if steward itself is exploited, security model breaks)
- Blockchain vulnerabilities (relying on Base/USDC security)

### Security Properties

1. **Least Privilege** - Agent only gets minimal permissions needed for each transaction
2. **Time-Limited Access** - Session keys expire automatically
3. **Spend-Limited Access** - Can't exceed transaction/monthly limits
4. **Revocable** - Human can instantly cut off access
5. **Auditable** - Every transaction cryptographically signed and logged
6. **Secret Isolation** - Agent never sees root wallet private key

---

## Open Research Questions

### Critical (blocking)
- [ ] How do AP2 mandates actually work? (Read full spec on GitHub)
- [ ] How does steward provision session keys? (Read steward docs/code)
- [ ] How do x402 + AP2 integrate? (Is there a standard? Or custom build?)
- [ ] Does Stripe Machine Payments support AP2 natively?

### Important (needed for implementation)
- [ ] Session key format and lifecycle
- [ ] Mandate storage (centralized? decentralized?)
- [ ] Budget state tracking (where? how updated?)
- [ ] Concurrent transaction handling
- [ ] Error recovery and retry logic

### Nice-to-have (can defer)
- [ ] Dashboard UI design
- [ ] Multi-currency support
- [ ] Category-based budgeting
- [ ] Spending analytics

---

## Next Steps

**Phase 1: Deep Research (1-2 sessions)**
1. Read steward documentation thoroughly
2. Review steward source code
3. Read AP2 technical specification
4. Check Stripe Machine Payments + AP2 integration status
5. Document findings and update architecture

**Phase 2: Proof of Concept (after research)**
1. Install and test steward locally
2. Create simple AP2 mandate (manual, no UI yet)
3. Request session key from steward
4. Make test x402 payment (Josh pays Ada $0.01)
5. Verify end-to-end flow works

**Phase 3: Integration (after PoC)**
1. Build mandate management interface for Josh
2. Integrate with Stripe Machine Payments
3. Add monitoring/audit trail
4. Harden error handling
5. Security audit

**Phase 4: Production (after integration)**
1. Replace manual LEDGER.md with Trustee
2. Josh sets real budget
3. Ada makes autonomous payments
4. Monitor for issues
5. Iterate based on real usage

---

## Success Criteria

**We know this works when:**
1. ✅ Josh can create a budget mandate in <5 minutes
2. ✅ Ada can make autonomous payments without asking permission
3. ✅ Ada CAN'T overspend even if she tries
4. ✅ Josh can see full audit trail of all spending
5. ✅ Josh can revoke access instantly
6. ✅ Private keys never leak (even under adversarial prompting)
7. ✅ System works reliably for 30 days without manual intervention

**We know we failed if:**
- ❌ Private keys leak to chat logs
- ❌ Agent overspends authorized limits
- ❌ Revocation doesn't work
- ❌ Too complex for Josh to manage
- ❌ Too rigid for Ada to use effectively

---

## Design Principles

1. **Security by default** - Safe even if agent is compromised
2. **Human oversight** - Josh always in control
3. **Agent autonomy** - Ada doesn't need permission for every tiny transaction
4. **Transparency** - Full audit trail, no hidden behavior
5. **Simplicity** - Complexity is the enemy of security
6. **Composability** - Use existing protocols (AP2, x402) rather than inventing new ones
7. **Fail-safe** - When in doubt, require human approval

---

*This architecture will evolve as we learn more. Current version is educated speculation pending deeper research.*
