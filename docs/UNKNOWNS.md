# Research Unknowns

Questions that need answers before implementation.

**Last Updated:** 2026-02-10 20:26 EST

---

## ✅ Resolved (Research Complete)

### Stripe Machine Payments + AP2 (2026-02-10 20:26 EST)
- ✅ **Stripe AP2 support:** NO - Stripe x402 is payment execution only, no built-in AP2 mandate verification
- ✅ **Our responsibility:** We implement AP2 authorization layer ourselves, call Stripe for payment execution
- ✅ **x402 payment flow:** Clear from docs - Server returns 402 → Client pays → Client retries with auth → Server confirms
- ✅ **Architecture implication:** AP2 (our code) → bagman (our code) → Stripe x402 (their API)
- ✅ **Documentation:** https://docs.stripe.com/payments/machine/x402 (Stripe preview enabled, pending review)

### x402 Signing Implementation (2026-02-10 19:42 EST)
- ✅ **Library:** `eth_account.Account` (Ethereum key management)
- ✅ **Signing method:** EIP-712 typed data signing (NOT JWT)
- ✅ **Key type:** Ethereum private key (secp256k1)
- ✅ **API:** `x402.clients.base.x402Client.process_payment(requirements, account)` returns `PaymentPayload`
- ✅ **Storage:** Private key in 1Password via bagman
- ✅ **Reference:** https://github.com/google-agentic-commerce/a2a-x402/tree/main/python/samples

### AP2 Mandates (Basic Structure)
- ✅ **Mandate format:** Pydantic BaseModels (JSON-serializable), documented in `src/ap2/types/mandate.py`
- ✅ **Cryptographic primitives:** JWT (RS256/ES256K) for merchant signatures, sd-jwt-vc for user authorization
- ✅ **Reference implementations:** Available at https://github.com/google-agentic-commerce/AP2 (Python samples)

### bagman (Architecture)
- ✅ **API patterns:** Documented in `examples/secret_manager.py` and `examples/session_keys.py`
- ✅ **1Password integration:** Native backend support via `op` CLI
- ✅ **Output sanitization:** Regex-based pattern matching in `examples/sanitizer.py`
- ✅ **Author reputation:** zak.eth (@0xzak) - legitimate developer, 211 GitHub followers, active in AI agent + crypto space
- ✅ **Security model:** Defense-in-depth layers documented

---

## Critical (Blocking Implementation)

### AP2 Signing Implementation (JWT for Cart Mandates)
**Note:** x402 payment signing is RESOLVED (uses eth_account + EIP-712). Still need Cart/Payment mandate signing.

- [ ] **JWT signing library:** What Python library for merchant JWT signatures? (PyJWT? python-jose? jwcrypto?)
- [ ] **Key format for JWT:** RS256 (RSA)? ES256K (secp256k1)? Which to use?
- [ ] **sd-jwt-vc implementation:** What library for user verifiable credentials? (Reference implementation available?)
- [ ] **Key generation:** How to generate signing key pairs for JWT? (openssl? library-specific?)
- [ ] **Key storage:** Store in 1Password via bagman, but what format? (PEM? JWK?)

**Next step:** Fetch raw Python files from AP2 samples directory to see JWT/sd-jwt-vc signing implementation

### AP2 Mandate Verification
- [ ] **Who verifies mandates?** Agent-side before payment? Merchant-side? Payment processor? All three?
- [ ] **Verification process:** Just signature check? Or also expiry, spending limits, etc.?
- [ ] **Failed verification:** What happens? Error codes? Exceptions? Retry logic?

**Next step:** Read AP2 docs on verification flow

### AP2 Mandate Revocation
- [ ] **Revocation mechanism:** CRL (Certificate Revocation List)? On-chain registry? Off-chain database?
- [ ] **Propagation time:** Instant? Eventually consistent?
- [ ] **In-flight transactions:** What happens to transactions already initiated when mandate revoked?
- [ ] **Revocation format:** Another signed credential? API call? Smart contract transaction?

**Research source:** https://github.com/google-agentic-commerce/AP2 (check docs/)

### AP2 Mandate Storage
- [ ] **Storage location:** Where do signed mandates live? (On-chain? Off-chain database? IPFS? Hybrid?)
- [ ] **Retention policy:** How long to keep mandates? (Until expiry? Forever for audit? Configurable?)
- [ ] **Access control:** Who can read mandates? (User? Agent? Merchant? Payment processor? Public?)
- [ ] **Query interface:** How to retrieve mandates by ID? By user? By date range?
- [ ] **Privacy considerations:** Payment Mandate contains sensitive data - how to protect while maintaining verifiability?
- [ ] **Backup/recovery:** If storage fails, are mandates recoverable? Where are backups?

**Research source:** AP2 samples may show storage patterns

### bagman + AP2 Integration
- [ ] **Session key to mandate connection:** How do bagman session keys connect to AP2 mandate signing?
- [ ] **Spend limit enforcement:** bagman provides session keys with limits, but who/what enforces? (Client checks? Smart contract? Payment processor?)
- [ ] **Session key format:** ERC-4337 keys? Standard Ethereum keys? What's the actual format?
- [ ] **Key rotation with active mandates:** What happens to signed mandates when session key rotates?
- [ ] **Error handling:** When bagman denies session key (over limit), what does agent do? Retry? Wait? Ask for approval?

**Research source:** https://github.com/zscole/bagman-skill + AP2 integration docs

### x402 + AP2 Integration
- [ ] Is there a standard way to attach AP2 mandates to x402 payments?
- [ ] Or do we build this integration ourselves?
- [ ] How do bagman session keys (Ethereum format) work with x402 signature format (also Ethereum)?
- [ ] What's the error handling for failed payments?

**Research source:** https://github.com/google-agentic-commerce/a2a-x402

---

## Important (Needed Before Production)

### Session Key Lifecycle
- [ ] Default expiration time for session keys?
- [ ] Configurable limits or fixed?
- [ ] Automatic renewal vs. manual request?
- [ ] Grace period for in-flight transactions when key expires?

### Budget State Management
**Key insight from research:** AP2 mandates are **stateless** - they define authorization rules but don't track spending. Need separate system for "spent $X of $Y budget".

- [ ] **Storage location:** Where to track current balance? (Database? Redis? Blockchain state?)
- [ ] **Update mechanism:** How to decrement balance atomically when payment succeeds?
- [ ] **Consistency model:** Real-time (strong consistency)? Eventual consistency? Trade-offs?
- [ ] **Concurrent transactions:** Two payments at same time - how to prevent race conditions? (Pessimistic locking? Optimistic with retry?)
- [ ] **Failure recovery:** Payment fails after decrementing balance - how to rollback?
- [ ] **Audit sync:** How to ensure budget state matches actual on-chain transactions?

**Architecture decision needed:** Separate budget tracker service? Or extend bagman? Or use smart contract state?

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

### ✅ Completed (2026-02-10)

**Session 1: Payment Infrastructure Overview**
- ✅ Researched ACP, AP2, x402, Stripe Machine Payments
- ✅ Identified three complementary protocols
- ✅ Documented in `docs/ARCHITECTURE.md`

**Session 2: bagman Security Layer**
- ✅ Read full documentation
- ✅ Checked author reputation
- ✅ Documented API patterns and security model
- ✅ Findings in `docs/BAGMAN_RESEARCH.md`

**Session 3: AP2 Mandate Structures**
- ✅ Read AP2 protocol documentation
- ✅ Found reference implementations
- ✅ Documented three mandate types (Intent, Cart, Payment)
- ✅ Findings in `docs/AP2_RESEARCH.md`

**Session 4: x402 Signing + Stripe Integration (2026-02-10 evening)**
- ✅ Found x402 payment signing implementation (eth_account + EIP-712)
- ✅ Josh enabled Stripe crypto payments (pending review)
- ✅ Read Stripe x402 docs - clarified Stripe does NOT handle AP2
- ✅ Architecture decision: AP2/bagman layers are our code, Stripe is payment execution only
- ✅ Updated `docs/UNKNOWNS.md` with findings

---

### 🔄 Next Sessions

**Session 5: AP2 JWT/sd-jwt-vc Signing (next)**
1. Fetch raw Python files from AP2 `samples/python/scenarios/a2a/human-present/`
2. Find JWT signing implementation for Cart Mandates (library, key format)
3. Find sd-jwt-vc signing implementation for Payment Mandates
4. Document exact code patterns
5. Update UNKNOWNS.md with findings

**Session 6: Budget Tracking Architecture**
1. Design separate state management system
2. Choose storage (Redis? PostgreSQL? Smart contract?)
3. Design atomic update patterns
4. Design concurrent transaction handling
5. Document in `docs/BUDGET_TRACKING.md`

**Session 7: Proof of Concept**
1. Install AP2 types: `uv pip install git+https://github.com/google-agentic-commerce/AP2.git@main`
2. Install bagman: `clawhub install bagman`
3. Create test Intent Mandate
4. Sign with test keys
5. Make $0.01 test payment (Josh → Ada)

---

*This document will be updated as unknowns become knowns.*
