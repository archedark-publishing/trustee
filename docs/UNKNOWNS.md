# Research Unknowns

Questions that need answers before implementation.

## Critical (Blocking Implementation)

### AP2 Mandates
- [ ] What is the exact mandate format? (JSON schema? Custom structure?)
- [ ] What cryptographic primitives for signing? (ECDSA? EdDSA? Other?)
- [ ] Who verifies mandates? (bagman? payment processor? both?)
- [ ] How does revocation work? (On-chain? Off-chain registry? CRL?)
- [ ] Are there reference implementations we can use?
- [ ] Where are mandates stored? (Centralized DB? Blockchain? Hybrid?)

**Research source:** https://github.com/google/agent-payments-protocol

### bagman
- [ ] What is the API for requesting session keys?
- [ ] How are spend limits enforced? (Client-side? Server validation? Blockchain?)
- [ ] What format are session keys? (Standard? Custom?)
- [ ] How does key rotation work?
- [ ] What happens when limits are exceeded? (Error codes? Exceptions?)
- [ ] How does it integrate with 1Password? (Storage format? Access patterns?)
- [ ] How is output sanitization implemented? (Regex? AST parsing?)
- [ ] Who is zak.eth/@0xzak? (Author reputation check)
- [ ] Any known vulnerabilities or issues?

**Research source:** https://github.com/zscole/bagman-... (full URL from X post)

### x402 + AP2 Integration
- [ ] Is there a standard way to attach AP2 mandates to x402 payments?
- [ ] Or do we build this integration ourselves?
- [ ] How do bagman session keys work with x402 signature format?
- [ ] What's the error handling for failed payments?

**Research source:** https://github.com/google-a2a/a2a-x402

### Stripe Machine Payments
- [ ] Does Stripe support AP2 mandate verification natively?
- [ ] Or do we verify mandates ourselves before calling Stripe?
- [ ] Can bagman session keys work with Stripe's API?
- [ ] What's the webhook flow for payment confirmation?
- [ ] How to map crypto wallet address to Stripe account?
- [ ] How to access preview docs? (Currently 404 without Stripe login)

**Research source:** https://docs.stripe.com/payments/machine-payments

---

## Important (Needed Before Production)

### Session Key Lifecycle
- [ ] Default expiration time for session keys?
- [ ] Configurable limits or fixed?
- [ ] Automatic renewal vs. manual request?
- [ ] Grace period for in-flight transactions when key expires?

### Budget State Management
- [ ] Where is current budget balance tracked? (bagman? blockchain? both?)
- [ ] Real-time consistency vs. eventual consistency?
- [ ] How to handle concurrent transactions? (locking? optimistic concurrency?)
- [ ] Sync mechanism if tracked in multiple places?

### Mandate Management Interface
- [ ] Existing tooling for Josh to create/manage mandates?
- [ ] Or build custom CLI/web UI?
- [ ] Simplest viable interface?
- [ ] Notification mechanism to agent when mandate changes?

### Transaction Audit Trail
- [ ] Where is transaction data stored? (Blockchain only? bagman logs? both?)
- [ ] Query interface for historical data?
- [ ] Export format for accounting?
- [ ] Real-time updates or polling?

---

## Nice-to-Have (Can Defer)

### Dashboard Features
- [ ] Web UI vs. CLI for Josh?
- [ ] Real-time spending charts?
- [ ] Category breakdown analytics?
- [ ] Spending predictions/alerts?

### Multi-Currency
- [ ] Support for non-USD currencies?
- [ ] Automatic conversion rates?
- [ ] Multi-token support (USDC, USDT, etc.)?

### Advanced Budgeting
- [ ] Per-category limits?
- [ ] Daily/weekly/monthly caps?
- [ ] Spending velocity limits?
- [ ] Scheduled budget increases?

---

## Research Plan

**Session 1: bagman Deep Dive**
1. Read full documentation
2. Review source code on GitHub
3. Check author reputation
4. Test locally (if safe)
5. Document API and capabilities

**Session 2: AP2 Specification**
1. Read complete AP2 spec
2. Study reference implementations
3. Understand mandate format
4. Understand verification process
5. Understand revocation mechanism

**Session 3: Integration Points**
1. Research A2A x402 extension
2. Check Stripe Machine Payments + AP2 status
3. Map integration points
4. Identify gaps we need to build ourselves

**Session 4: Architecture Update**
1. Update ARCHITECTURE.md with findings
2. Remove unknowns that are now known
3. Add new questions discovered during research
4. Refine user flows with actual APIs

---

*This document will be updated as unknowns become knowns.*
