# Research Unknowns

Questions that need answers before implementation.

**Last Updated:** 2026-02-10 21:55 EST

---

## ✅ Resolved

### Core Payment System (2026-02-10)
- ✅ **x402 payments:** Working end-to-end on Base Sepolia. Official x402 SDK v2.0.0, EIP-712/EIP-3009 signing via EthAccountSigner adapter
- ✅ **Signing implementation:** `eth_account.Account` + custom `EthAccountSigner` adapter for x402 `ClientEvmSigner` protocol
- ✅ **Key management:** Steward session-based access. Key in 1Password, loaded into time-limited sessions, agent only gets `StewardSigner`
- ✅ **Budget tracking:** File-based with atomic writes and file locking. Per-tx, daily, total limits.
- ✅ **Audit trail:** Append-only JSONL. Every operation logged.
- ✅ **Mandate system:** EIP-712 signed spending authorizations with verification.
- ✅ **Stripe crypto:** Approved and enabled. Ready for mainnet switch.
- ✅ **Architecture:** AP2 (our code) → Steward (our code) → x402 SDK → Coinbase facilitator → Base blockchain

### Technical Details Resolved
- ✅ **eth-account compatibility:** v0.13.x uses `full_message=` kwarg for `sign_typed_data`, not positional args. x402 SDK expects `ClientEvmSigner` protocol. Bridge: `EthAccountSigner` adapter.
- ✅ **Domain field naming:** x402 `TypedDataDomain` uses snake_case (`chain_id`, `verifying_contract`). EIP-712 needs camelCase (`chainId`, `verifyingContract`). Adapter handles conversion.
- ✅ **Nonce format:** x402 provides `bytes32` nonce, eth-account expects hex string. Adapter converts.
- ✅ **Facilitator URL:** `https://x402.org/facilitator` for both testnet and mainnet.
- ✅ **Network IDs:** Base Sepolia = `eip155:84532`, Base Mainnet = `eip155:8453`
- ✅ **USDC contracts:** Base Sepolia = `0x036CbD53842c5426634e7929541eC2318f3dCF7e`
- ✅ **Steward session model:** In-memory sessions with configurable TTL, spend caps, auto-expiry. Key wiped on destroy.

---

## Open (Future Work)

### AP2 Mandate Protocol Integration
- [ ] JWT signing for Cart Mandates (PyJWT? python-jose? jwcrypto?)
- [ ] sd-jwt-vc for user verifiable credentials
- [ ] Mandate verification flow (agent-side? merchant-side? both?)
- [ ] Mandate revocation mechanism
- [ ] Mandate storage and retrieval
- [ ] Connect AP2 mandates to existing EIP-712 mandate system

### Production Hardening
- [ ] **Mainnet deployment:** Switch `BASE_SEPOLIA` → `BASE_MAINNET` (code ready, needs funding)
- [ ] **Session key persistence:** Currently in-memory only. Need session recovery across restarts?
- [ ] **Budget state backup:** File-based state vulnerable to corruption. Consider database?
- [ ] **Concurrent transaction safety:** File locking works but may not scale. Evaluate.
- [ ] **On-chain budget verification:** Compare budget tracker state to actual blockchain transactions
- [ ] **Error recovery:** Payment fails after budget decrement — rollback mechanism needed

### UX / Management
- [ ] CLI for Josh to create/manage mandates easily
- [ ] Dashboard or reporting for spending oversight
- [ ] Notifications when budget thresholds hit
- [ ] Mandate templates for common use cases

### Nice-to-Have
- [ ] Multi-currency / multi-token support
- [ ] Smart contract wallet (ERC-4337) for on-chain spending limits
- [ ] Per-category spending breakdown
- [ ] Spending velocity alerts

---

## Research Plan

### ✅ Completed
1. Payment infrastructure survey (ACP, AP2, x402, Stripe)
2. Steward security architecture
3. AP2 mandate structures
4. x402 signing + Stripe integration
5. **MVP implementation** (mandate + budget + audit + x402 + steward)
6. **E2E testnet payment** (real USDC on Base Sepolia)

### Next
1. AP2 JWT/sd-jwt-vc signing (fetch Python samples, find implementation patterns)
2. Mainnet readiness checklist
3. Production error handling and recovery
