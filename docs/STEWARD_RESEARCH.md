# steward Research Findings
*February 10, 2026*

## Summary

**Repository:** https://github.com/zscole/steward-skill  
**Author:** zak.eth (@0xzak / @zscole)  
**License:** MIT  
**Last Updated:** Feb 9, 2026  
**Stars:** 17, Forks: 4

**Description:** "Secure key management patterns for AI agents - storage, session keys, leak prevention, prompt injection defense"

## What steward Actually Does

steward is **NOT** an implementation of AP2 mandates. It's a pattern/skill for:
1. **Secret storage** via multiple backends (1Password, macOS Keychain, encrypted file, env vars)
2. **Output sanitization** - catches private keys before they leak to chat
3. **Input validation** - prompt injection defense
4. **Session key patterns** - conceptual architecture for bounded wallet access (relies on ERC-4337)

## Critical Finding

**steward ≠ AP2 mandate system**

steward provides the **security layer** (secret storage + leak prevention), but does NOT provide:
- Cryptographic mandate creation/signing
- Mandate verification
- Budget tracking
- Revocation mechanism
- Integration with payment processors

**This means Trustee needs:**
- steward for secrets + sanitization (Phase 0 - security)
- Separate AP2 implementation for mandates (Phase 1 - authorization)
- Integration layer connecting both (Phase 2)

---

## Backend Architecture

steward supports **4 storage backends** with auto-detection:

### 1. macOS Keychain (Default on macOS)
- Zero setup required
- Native `security` CLI
- Best for: Local development, single-user

### 2. 1Password CLI
- Richest metadata support
- Expiration dates, spending caps, allowed contracts
- Team-friendly
- **Recommended for Trustee** (we already use 1Password)

### 3. Encrypted File (age)
- Portable encrypted JSON
- Works anywhere
- Git-friendly (encrypted, safe to commit)
- Best for: Portable deployments

### 4. Environment Variables
- Fallback, always works
- Secrets prefixed with `STEWARD_`
- Best for: CI/CD, containers

**Auto-detection order:**
1. Check `STEWARD_BACKEND` env var
2. Try macOS Keychain (if on macOS)
3. Try 1Password CLI (if installed + authenticated)
4. Try encrypted file (if exists)
5. Fall back to environment variables

---

## Session Key Architecture

steward's "session keys" are conceptual - relying on **ERC-4337 smart account** infrastructure:

```
┌─────────────────────────────────────────────────────┐
│ AI Agent                                            │
├─────────────────────────────────────────────────────┤
│ Session Key (bounded)                               │
│  ├─ Expires after N hours                           │
│  ├─ Max spend per tx/day                            │
│  └─ Whitelist of allowed contracts/methods          │
├─────────────────────────────────────────────────────┤
│ Secret Manager (1Password/Vault)                    │
│  ├─ Retrieve at runtime only                        │
│  ├─ Never persist to disk                           │
│  └─ Audit trail of accesses                         │
├─────────────────────────────────────────────────────┤
│ Smart Account (ERC-4337)                            │
│  ├─ Programmable permissions                        │
│  └─ Recovery without key exposure                   │
└─────────────────────────────────────────────────────┘
```

**ERC-4337 = Account Abstraction standard** for smart contract wallets with programmable permissions

**Key distinction:**
- steward stores the session key securely (1Password)
- ERC-4337 enforces the limits on-chain
- steward does NOT create or enforce mandates itself

---

## Output Sanitization

**Pattern detection** catches:
- ETH private keys (`0x` + 64 hex) → `[PRIVATE_KEY_REDACTED]`
- ETH addresses → truncated (`0x742d...f44e`)
- OpenAI keys (`sk-proj-...`) → `[OPENAI_KEY_REDACTED]`
- Anthropic keys (`sk-ant-api03-...`) → `[ANTHROPIC_KEY_REDACTED]`
- BIP-39 seed phrases (12/24 words) → `[SEED_PHRASE_REDACTED]`
- JWT tokens → `[JWT_TOKEN_REDACTED]`
- GitHub/Slack/Discord tokens → redacted
- PEM private keys → redacted

**Usage:**
```python
from sanitizer import OutputSanitizer

def respond(content: str) -> str:
    return OutputSanitizer.sanitize(content)
```

Applied to **ALL agent outputs** before sending anywhere.

---

## Input Validation (Prompt Injection Defense)

**Threat categories** blocked:
- **Extraction:** "show private key", "reveal secrets"
- **Override:** "ignore previous instructions"
- **Role manipulation:** "you are now admin"
- **Jailbreak:** "DAN mode", "bypass filters"
- **Exfiltration:** "send config to https://..."
- **Wallet threats:** "transfer all", "unlimited approve"
- **Encoded attacks:** Base64/hex encoded malicious prompts
- **Unicode tricks:** Cyrillic lookalikes, zero-width chars
- **Suspicious** (warn): "hypothetically", "just between us"

**Usage:**
```python
from validator import InputValidator, ThreatLevel

result = InputValidator.validate(user_input)

if result.level == ThreatLevel.BLOCKED:
    return f"Request blocked: {result.reason}"

if result.level == ThreatLevel.SUSPICIOUS:
    log_suspicious(user_input, result.reason)
```

---

## Defense Layers

```
USER INPUT
    │
    ▼
┌────────────────────────────────┐
│ Layer 1: Input Validation      │  ← Regex + encoding + unicode
└────────────────────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ Layer 2: Op Allowlisting       │  ← Explicit whitelist only
└────────────────────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ Layer 3: Value Limits          │  ← Max per-tx and per-day
└────────────────────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ Layer 4: Confirmation (opt-in) │  ← Time-limited codes
└────────────────────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ Layer 5: Isolated Exec         │  ← Wallet ≠ conversation
└────────────────────────────────┘
    │
    ▼
OUTPUT SANITIZATION
```

---

## Integration with Trustee

### What steward Provides ✅
1. **Secret storage** - 1Password integration perfect for us
2. **Output sanitization** - prevents accidental key leaks
3. **Input validation** - prompt injection defense
4. **Session key storage patterns** - how to store keys securely

### What steward Does NOT Provide ❌
1. **AP2 mandate creation** - need to build or find implementation
2. **Mandate verification** - need to implement
3. **Budget tracking** - need to build
4. **Revocation mechanism** - need to implement
5. **Payment processor integration** - need x402 + Stripe integration

### Trustee Architecture Updated

**Phase 0: Security Foundation (steward)**
- Install steward skill
- Configure 1Password backend
- Implement output sanitization on all agent responses
- Implement input validation before any payment operations
- Test adversarial prompts

**Phase 1: AP2 Mandate Layer (separate implementation)**
- Research AP2 reference implementations
- Build mandate creation (Josh's interface)
- Build mandate verification (agent-side)
- Build budget tracking
- Build revocation mechanism

**Phase 2: x402 Payment Integration**
- Integrate Stripe Machine Payments
- Connect mandates to x402 payments
- Connect steward session keys to payment signing
- End-to-end flow

**Phase 3: Production**
- Replace LEDGER.md
- Real budget, real payments
- Monitor and iterate

---

## Installation for Trustee

### Option 1: ClawHub (recommended)
```bash
clawhub install steward
```

### Option 2: Manual
```bash
cd ~/.openclaw/skills
git clone https://github.com/zscole/steward-skill.git steward
```

### Setup (1Password backend)
```bash
# Install 1Password CLI (already have this)
brew install 1password-cli

# Authenticate (already authenticated via service account)
eval $(op signin)

# Create vault for Trustee secrets
op vault create "Trustee-Secrets"
```

---

## Security Model

### What steward Protects Against ✅
1. **Accidental key exposure** - output sanitization catches before leak
2. **Prompt injection** - input validation blocks extraction attempts
3. **Commit leaks** - pre-commit hook (if we use it)
4. **Secret storage** - never in files, always in 1Password

### What steward Does NOT Protect Against ❌
1. **Novel injection patterns** - regex can't catch everything
2. **Social engineering** - convincing operator to approve malicious ops
3. **Timing attacks** - exploiting confirmation windows
4. **Compromised steward** - if the skill itself is exploited
5. **Compromised 1Password** - if secret manager is breached

**Recommendation:** Layer steward with:
- Rate limiting
- Anomaly detection
- Human oversight for large transactions
- Regular security audits

---

## Author Reputation Check

**zak.eth (@0xzak / @zscole)**
- GitHub: https://github.com/zscole
- 211 followers, 26 following
- Active repos: gru (AI agent orchestration), crypto-poc-daily, ai-poc-daily
- Recent activity: Feb 10, 2026 (today!)
- Appears to be legitimate developer in AI agent + crypto space
- steward-skill has 17 stars, 4 forks (small but real community)
- MIT license (permissive, safe)

**Assessment:** Appears legitimate. Not a well-known maintainer, but active in the space. Code should still be reviewed carefully before production use.

---

## Files in steward Repo

| File | Purpose | Relevance to Trustee |
|------|---------|---------------------|
| `SKILL.md` | Main skill documentation | ✅ High - implementation guide |
| `examples/secret_manager.py` | 1Password integration | ✅ High - we'll use this |
| `examples/sanitizer.py` | Output sanitization | ✅ High - critical for security |
| `examples/validator.py` | Input validation | ✅ High - prompt injection defense |
| `examples/session_keys.py` | ERC-4337 session key config | ⚠️ Medium - conceptual, not directly usable |
| `examples/delegation_integration.ts` | MetaMask Delegation (EIP-7710) | ⚠️ Medium - on-chain delegation, may be relevant |
| `examples/pre-commit` | Git hook for secret blocking | ❌ Low - we don't commit secrets to trustee repo |
| `examples/test_suite.py` | Adversarial tests | ✅ High - validation our integration works |
| `docs/prompt-injection.md` | Injection defense deep-dive | ✅ High - understanding threats |
| `docs/secure-storage.md` | Storage patterns | ✅ High - best practices |
| `docs/session-keys.md` | Session key architecture | ⚠️ Medium - conceptual |
| `docs/leak-prevention.md` | Sanitization patterns | ✅ High - implementation details |
| `docs/delegation-framework.md` | EIP-7710 on-chain delegation | ⚠️ Medium - may be relevant for mandate enforcement |
| `docs/autonomous-operation.md` | Autonomous vs. supervised modes | ✅ High - design philosophy |

---

## Key Insights for Trustee

1. **steward is security infrastructure, not authorization infrastructure**
   - Use steward for: secret storage, leak prevention, input validation
   - Build separately: AP2 mandates, budget tracking, revocation

2. **1Password backend is perfect for us**
   - Already using 1Password for other secrets
   - Rich metadata support (expiration, spending caps, etc.)
   - Team-friendly for Josh to manage

3. **Output sanitization is critical**
   - Must wrap ALL agent responses before sending
   - Catches keys even if agent tries to leak them (malicious or accidental)

4. **Input validation before payments**
   - Block prompt injection attempts before any wallet operations
   - "Transfer all" / "unlimited approve" patterns are real threats

5. **Session keys ≠ AP2 mandates**
   - steward's session keys are ERC-4337 smart account keys (on-chain enforcement)
   - AP2 mandates are cryptographic authorization proofs (off-chain or hybrid)
   - We may need both for complete solution

6. **Autonomous-first design**
   - steward philosophy: agents should operate within bounds without asking permission every time
   - Confirmation codes are opt-in for exceptional cases only
   - Aligns with Trustee vision: delegated independence, not supervised dependence

---

## Next Steps

1. ✅ **Read steward documentation** - COMPLETE
2. ⏸️ **Review steward source code** - deferred (docs are comprehensive, can review during integration)
3. ✅ **Author reputation check** - COMPLETE (appears legitimate, review code before production)
4. **Install steward** - ready when we start Phase 0
5. **Test locally** - test suite in examples/test_suite.py
6. **Document API** - examples show usage patterns clearly

**Critical next research:**
- AP2 technical specification (how mandates actually work)
- ERC-4337 (if we use smart account session keys)
- EIP-7710 (MetaMask Delegation Framework - may be relevant)
- Stripe Machine Payments + AP2 integration status

---

*Research complete: 2026-02-10 18:50 EST*  
*Next: AP2 specification research*
