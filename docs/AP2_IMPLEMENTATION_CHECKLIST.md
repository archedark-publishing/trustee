# AP2 Integration Implementation Checklist

**Source Spec:** `docs/AP2_INTEGRATION_SPEC.md` (v1.1, 2026-02-16)  
**Purpose:** Execution tracker for implementation and readiness sign-off.

---

## How To Use This Checklist

- Keep boxes unchecked until code is merged and validated.
- Attach evidence (test output, tx hash, screenshot, PR link) to each completed item.
- Do not start a new phase until the prior phase exit criteria are met.

---

## Phase 0: Contract and Trust Model

### 0.1 Scaffold and Contract Design
- [x] Create `contracts/` workspace (Foundry or existing Solidity tooling) and document commands in `README`.
- [x] Implement `contracts/MandateRegistry.sol` with:
- [x] `trustedIssuerForAgent` mapping
- [x] `agentPaused` mapping
- [x] `MandateRecord` storage (`mandateHash`, `payloadHash`, `issuer`, `agent`, `issuedAt`, `expiresAt`, `revokedAt`, `metadataURI`)
- [x] `setTrustedIssuer` access control
- [x] `setAgentPaused` access control
- [x] `issueMandateOnChain` authorization + duplicate protection
- [x] `revokeMandate` issuer-only authorization
- [x] `getMandateStatus` status view
- [x] `getMandatesByAgentPaged` pagination
- [x] Emit all required events (`TrustedIssuerUpdated`, `AgentPauseUpdated`, `MandateIssued`, `MandateRevoked`).

### 0.2 Contract Tests
- [x] Add tests for trusted issuer gating.
- [x] Add tests for paused agent behavior.
- [x] Add tests for revoke authorization.
- [x] Add tests for expiry semantics.
- [x] Add tests for duplicate issuance rejection.
- [x] Add tests for pagination behavior.

### 0.3 Deployment
- [ ] Deploy to Base Sepolia first.
- [ ] Run smoke tests on deployed Sepolia contract.
- [ ] Deploy to Base mainnet (`eip155:8453`).
- [ ] Verify contract on Basescan.
- [ ] Record addresses and ABI config in repo config docs.

### Phase 0 Exit Criteria
- [x] All contract tests passing.
- [ ] Sepolia + mainnet addresses documented.
- [ ] Basescan verification links recorded.

---

## Phase 1: Canonical Payload and Local Store

### 1.1 Canonical Payload Utilities
- [x] Extend `src/trustee/mandate.py` with canonical serialization/hashing helpers.
- [x] Implement deterministic canonical JSON function.
- [x] Normalize addresses (lowercase + `0x`).
- [x] Normalize and sort unique recipient allowlist.
- [x] Enforce integer base units for amounts.
- [x] Enforce CAIP-style asset identifier support.

### 1.2 Mandate Store
- [x] Add `src/trustee/mandate_store.py` with required APIs:
- [x] `save_mandate`
- [x] `get_mandate`
- [x] `list_mandates`
- [x] `update_status`
- [x] `record_chain_confirmation`
- [x] `cleanup_expired`
- [x] Implement lifecycle statuses: `draft`, `pending_on_chain`, `active`, `revoked`, `expired`, `failed`.
- [x] Enforce `pending_on_chain -> active` only after confirmed chain tx.
- [x] Add atomic write strategy (temp-file + rename or sqlite).
- [x] Add concurrent access protection.
- [x] Add payload hash integrity check on load.

### 1.3 Tests
- [x] Add unit tests for canonical hash determinism.
- [x] Add unit tests for lifecycle transitions.
- [x] Add concurrent read/write tests.
- [x] Add tests for integrity mismatch failure behavior.

### Phase 1 Exit Criteria
- [x] Deterministic payload hash tests passing.
- [x] Concurrency tests passing.
- [x] Lifecycle transition constraints enforced.

---

## Phase 2: Steward Enforcement Integration

### 2.1 Validator Implementation
- [x] Add `src/trustee/mandate_validator.py`.
- [x] Implement validation pipeline in required order from spec.
- [x] Add deterministic mandate selection rules:
- [x] explicit `mandate_hash` path
- [x] single-candidate auto-select
- [x] multi-candidate ambiguity rejection
- [x] Verify EIP-712 signer and trusted issuer binding.
- [x] Validate payload hash against canonical payload bytes.

### 2.2 Signing Path Integration
- [x] Integrate validator into signing boundary in `src/trustee/steward.py` and/or payment orchestration.
- [x] Require live `getMandateStatus` check immediately before signing.
- [x] Enforce fail-closed on RPC/store/validation errors.
- [x] Reject when agent is paused.

### 2.3 Budget Race Safety
- [x] Reuse atomic reserve/commit/rollback path from `src/trustee/budget.py`.
- [x] Remove or block non-atomic read-then-write spending checks.
- [x] Ensure rollback on downstream signing/submission failures.

### 2.4 Tests
- [x] Unit tests for mandate matching and ambiguity rejection.
- [x] Integration test: issue -> validate -> sign success path.
- [x] Integration test: revoke -> immediate rejection path.
- [x] Integration test: paused agent rejection path.
- [x] Integration test: metadata hash mismatch rejection.
- [x] Integration test: RPC outage fail-closed behavior.
- [x] Concurrency test: daily boundary double-spend race (only one success).

### Phase 2 Exit Criteria
- [x] All validator/integration tests passing.
- [x] Demonstrated immediate revocation enforcement at signing boundary.
- [x] Concurrency tests prove no daily cap overspend.

---

## Phase 3: CLI and Ops Controls

### 3.1 CLI Commands
- [x] Extend `src/trustee/cli.py` with `trustee mandate` group.
- [x] Implement `mandate issue`.
- [x] Implement `mandate revoke`.
- [x] Implement `mandate list`.
- [x] Implement `mandate status`.
- [x] Implement `mandate trust-issuer`.
- [x] Implement `mandate pause-agent`.
- [x] Implement `mandate check-expiry`.

### 3.2 CLI Behavior Quality
- [x] `issue` reports pending + confirmed chain status.
- [x] `issue` does not claim success before confirmation.
- [x] `list` and `status` reconcile with on-chain state.
- [x] Add clear operator-facing error messages for fail-closed cases.

### 3.3 Template Presets
- [x] Add local templates (`micro`, `daily_ops`, `vendor_locked`).
- [x] Compile templates into explicit mandate fields before signing.
- [x] Document template behavior and boundaries.

### 3.4 Notification Hook
- [x] Add expiry warning command (`--within` duration parsing).
- [x] Add optional webhook output mode.
- [x] Add tests for threshold calculations and output behavior.

### 3.5 Ops Runbooks
- [x] Document key rotation runbook.
- [x] Document emergency kill switch runbook.
- [x] Document outage/fail-closed runbook.
- [x] Document any manual break-glass procedure with audit requirements.

### Phase 3 Exit Criteria
- [x] End-to-end CLI flow works: trust issuer -> issue -> sign pay -> revoke -> reject.
- [x] Runbooks complete and reviewed.

---

## Phase 4: Hardening and Production Readiness

### 4.1 Security Tests
- [x] Forged signature test.
- [x] Untrusted issuer test.
- [x] Cross-chain replay rejection test.
- [x] Expired mandate boundary tests.
- [x] Cache poisoning attempt tests.

### 4.2 Logging and Audit
- [x] Emit structured decision logs for every validation result.
- [x] Ensure logs include `mandate_hash`, `issuer`, `agent`, reason code, and tx context.
- [x] Ensure pause/kill-switch actions are logged.

### 4.3 Staging Validation
- [x] Staging outage simulation: RPC down -> fail closed.
- [x] Staging metadata retrieval failure -> fail closed.
- [x] Staging budget store failure -> fail closed.

### 4.4 Mainnet Verification
- [ ] Execute one full mainnet happy-path transaction under mandate.
- [ ] Revoke mandate and verify subsequent rejection.
- [ ] Archive tx hashes and logs in docs.

### Phase 4 Exit Criteria
- [ ] No open critical/high severity defects.
- [ ] Coverage target met for AP2 modules (90%+).
- [ ] Operator documentation complete.

---

## Cross-Cutting Decisions (v1 Locked)

- [x] Multi-signature mandates deferred to v2.
- [x] Mandate inheritance/delegation deferred to v2.
- [x] Analytics product features deferred; structured logs enabled now.
- [x] Supported scope locked to Base mainnet USDC x402 path only.

---

## Final Go-Live Checklist

- [ ] Contract addresses and env config validated in production.
- [ ] Trusted issuer list reviewed and minimal.
- [ ] Kill switch tested in live-like environment.
- [ ] Key rotation rehearsal completed.
- [ ] Alerting/notification path validated.
- [ ] Incident response contacts and runbooks confirmed.
