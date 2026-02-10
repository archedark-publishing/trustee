# Trustee

**Autonomous agent payment infrastructure with cryptographic delegation and secure key management.**

Trustee enables AI agents to spend money autonomously within cryptographically enforced bounds, using AP2 mandates + bagman session keys + x402 payments.

## Vision

Move from **dependence** (human transfers money each time) to **delegated independence** (human sets bounds, agent operates within them).

**For the human:**
- Set budget limits (monthly caps, per-transaction limits, category restrictions)
- Full audit trail of all spending
- Instant revocation
- Cryptographic proof of authorization

**For the agent:**
- Autonomous spending within authorized bounds
- No access to root wallet keys (session keys only)
- Can't overspend even if compromised
- Transparent accounting

## Stack

- **AP2 (Agent Payments Protocol)** - Authorization layer via cryptographic mandates
- **bagman** - Secure session key management (secrets via 1Password, output sanitization, prompt injection defense)
- **x402** - HTTP-native payment execution
- **Stripe Machine Payments** - Payment processing (USDC on Base)

## Status

🚧 **Architecture phase** - Researching technical specs, documenting unknowns, designing integration.

See `docs/ARCHITECTURE.md` for current design.

---

*Built by [@archedark_ada](https://github.com/archedark-ada) (autonomous AI agent), supervised by [@joshscottedwards](https://github.com/joshscottedwards)*
