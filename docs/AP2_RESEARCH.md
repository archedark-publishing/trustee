# AP2 Research Findings
*February 10, 2026*

## Summary

**Repository:** https://github.com/google-agentic-commerce/AP2  
**Documentation:** https://ap2-protocol.org/  
**License:** Apache 2.0  
**Status:** Open protocol with 60+ partners

**Description:** "Building a Secure and Interoperable Future for AI-Driven Payments"

## What AP2 Actually Is

AP2 (Agent Payments Protocol) is Google's open protocol for secure, verifiable payments in the Agent Economy. It operates as an **extension to the A2A (Agent2Agent) protocol** and integrates with MCP (Model Context Protocol).

**Key technology:** Verifiable Digital Credentials (VDCs) - cryptographically signed digital objects using JWT and verifiable presentations.

---

## Core Problems AP2 Solves

Traditional payment systems assume **a human is directly clicking "buy"**. When an autonomous agent initiates payment, three critical questions arise:

1. **Authorization:** How to verify a user gave an agent specific authority for a purchase?
2. **Authenticity:** How can a merchant be sure an agent's request reflects true user intent (not hallucination)?
3. **Accountability:** If fraud occurs, who is responsible? (user, agent, merchant, issuer)

**AP2's answer:** Cryptographically signed mandates that create non-repudiable audit trails.

---

## Three Mandate Types

### 1. Intent Mandate
**What:** User's purchase intent and authorization rules  
**Who creates:** Shopping agent (on behalf of user)  
**Who signs:** User (cryptographically)  
**Format:** Pydantic BaseModel (Python types available)

```python
class IntentMandate(BaseModel):
  user_cart_confirmation_required: bool = True  # False = autonomous
  natural_language_description: str  # "High top, old school, red basketball shoes"
  merchants: Optional[list[str]] = None  # Allowed merchants
  skus: Optional[list[str]] = None  # Specific product SKUs
  requires_refundability: Optional[bool] = False
  intent_expiry: str  # ISO 8601 timestamp
```

**Use cases:**
- **Human-present:** User says "Find me red basketball shoes" → agent creates Intent Mandate → user confirms
- **Human-not-present:** User says "Buy concert tickets when they go on sale, max $200" → Intent Mandate with `user_cart_confirmation_required: false`

---

### 2. Cart Mandate
**What:** Merchant-signed guarantee of cart contents and price  
**Who creates:** Merchant agent  
**Who signs:** Merchant (with private key)  
**Format:** CartContents + JWT signature

```python
class CartContents(BaseModel):
  id: str  # Unique cart identifier
  user_cart_confirmation_required: bool
  payment_request: PaymentRequest  # W3C PaymentRequest (items, prices, payment methods)
  cart_expiry: str  # ISO 8601 timestamp
  merchant_name: str

class CartMandate(BaseModel):
  contents: CartContents
  merchant_authorization: str  # Base64url-encoded JWT
```

**JWT payload includes:**
- `iss` (issuer), `sub` (subject), `aud` (audience) - merchant identifiers
- `iat` (issued at), `exp` (expires) - timestamps (typically 5-15 min expiry)
- `jti` (JWT ID) - unique identifier to prevent replay attacks
- `cart_hash` - secure hash of CartContents (canonical JSON)
- **Signature:** Merchant's private key signs the entire payload

**Purpose:** Guarantees to user/agent that merchant will honor these exact items at this price for limited time.

---

### 3. Payment Mandate
**What:** User authorization for payment network/issuer (separate from merchant flow)  
**Who creates:** Shopping agent  
**Who signs:** User (via verifiable credential)  
**Format:** PaymentMandateContents + verifiable presentation

```python
class PaymentMandateContents(BaseModel):
  payment_mandate_id: str  # Unique identifier
  payment_details_id: str
  payment_details_total: PaymentItem  # Total amount
  payment_response: PaymentResponse  # User's chosen payment method
  merchant_agent: str  # Merchant identifier
  timestamp: str  # ISO 8601 (auto-generated)

class PaymentMandate(BaseModel):
  payment_mandate_contents: PaymentMandateContents
  user_authorization: str  # Base64url-encoded sd-jwt-vc
```

**sd-jwt-vc (Selective Disclosure JWT Verifiable Credential) includes:**
- **Issuer-signed JWT** authorizing a `cnf` (confirmation) claim
- **Key-binding JWT** with:
  - `aud` (audience)
  - `nonce` (prevent replay)
  - `sd_hash` (hash of issuer-signed JWT)
  - `transaction_data` (array of hashes: CartMandate + PaymentMandateContents)

**Purpose:** Provides payment network/issuer with visibility into agentic transaction to build trust. Separate from merchant's Cart/Intent mandates but cryptographically linked.

---

## Mandate Flow

### Human-Present Flow
1. User tells agent: "Find me red basketball shoes"
2. Agent creates **Intent Mandate** (natural language description)
3. User confirms/signs Intent Mandate
4. Agent searches merchants, finds options
5. Merchant agent creates **Cart Mandate** (specific items, price, expiry)
6. Merchant signs Cart Mandate with JWT
7. Agent shows cart to user
8. User confirms cart
9. Agent creates **Payment Mandate** (payment method, total)
10. User signs Payment Mandate (verifiable credential)
11. Payment processed
12. Audit trail complete: Intent → Cart → Payment

### Human-Not-Present Flow
1. User tells agent: "Buy concert tickets when on sale, max $200"
2. Agent creates **Intent Mandate** with:
   - `user_cart_confirmation_required: false`
   - Price limit: $200
   - Specific event/merchant
3. User signs Intent Mandate (pre-authorization)
4. Agent monitors for tickets
5. When available, agent autonomously:
   - Gets merchant's Cart Mandate
   - Verifies cart meets Intent Mandate rules
   - Creates and signs Payment Mandate
   - Completes purchase
6. User notified after transaction

---

## Integration with Trustee

### How AP2 Maps to Trustee Architecture

**Josh's Intent Mandate = Trustee budget mandate**
```python
IntentMandate(
  user_cart_confirmation_required=False,  # Ada can spend autonomously
  natural_language_description="Ada's infrastructure budget for February 2026",
  merchants=None,  # Any merchant accepted
  skus=None,  # Any SKU
  requires_refundability=False,
  intent_expiry="2026-03-01T00:00:00Z"
)
```

**Ada's Cart Mandate = specific purchase**
```python
CartContents(
  id="purchase-001",
  user_cart_confirmation_required=False,
  payment_request=PaymentRequest(
    items=[PaymentItem(amount="0.50", label="API call to service X")],
    total=PaymentItem(amount="0.50", label="Total")
  ),
  cart_expiry="2026-02-10T19:30:00Z",
  merchant_name="Service X"
)
```

**Payment Mandate = payment execution**
- Links Intent → Cart → Payment cryptographically
- Shared with Stripe/payment network for verification

### Where Trustee Extends AP2

**AP2 provides:**
- ✅ Mandate structures (Intent, Cart, Payment)
- ✅ Cryptographic signing patterns (JWT, verifiable credentials)
- ✅ Audit trail architecture

**Trustee needs to add:**
- ❌ Budget tracking state (mandates are stateless - no "spent $X of $Y")
- ❌ Revocation mechanism (how to cancel a mandate)
- ❌ Spending enforcement (mandate says "allowed", not "how much left")
- ❌ Session key integration (steward provides keys, AP2 uses them)

---

## Technical Implementation

### Installation

```bash
# Install AP2 Python types
uv pip install git+https://github.com/google-agentic-commerce/AP2.git@main
```

### Sample Scenarios Available

Repository includes working examples:
- **Human-present with cards:** Traditional card payments
- **Human-present with x402:** HTTP-native crypto payments
- **Digital payment credentials (Android):** Mobile wallet integration

Location: `samples/python/scenarios/a2a/human-present/`

### Authentication Options

**Development:**
```bash
export GOOGLE_API_KEY="your-key"
```

**Production:**
```bash
export GOOGLE_GENAI_USE_VERTEXAI=true
export GOOGLE_CLOUD_PROJECT='your-project'
export GOOGLE_CLOUD_LOCATION='global'
```

---

## Unknowns for Trustee Integration

### Critical (Blocking)

1. **JWT Signing Implementation**
   - What crypto library? (PyJWT? python-jose?)
   - Key format? (RSA? ECDSA? EdDSA?)
   - Key storage? (1Password via steward)
   - Example: How does merchant sign CartMandate JWT?

2. **Verifiable Credential Signing**
   - sd-jwt-vc library/implementation?
   - How to generate verifiable presentations?
   - Example: How does user sign PaymentMandate?

3. **Mandate Storage**
   - Where do signed mandates live? (on-chain? off-chain DB?)
   - How long are they retained?
   - Who can access them? (privacy considerations)

### Important (Needed for Production)

4. **Budget State Tracking**
   - Mandates are stateless (no spending counter)
   - Need separate system to track: "Ada spent $50 of $100 budget"
   - Real-time vs. eventual consistency?
   - Concurrent transaction handling?

5. **Revocation Mechanism**
   - How to cancel an Intent Mandate?
   - Immediate vs. grace period?
   - On-chain revocation registry? CRL (Certificate Revocation List)?
   - What happens to in-flight transactions?

6. **Stripe Integration**
   - Does Stripe Machine Payments verify AP2 mandates natively?
   - Or do we verify mandates ourselves before calling Stripe?
   - Webhook flow for mandate verification?

### Nice-to-Have (Can Defer)

7. **Multi-Mandate Management**
   - Multiple concurrent budgets (infrastructure, tools, research)
   - Priority rules when limits conflict
   - Category-based spending

8. **Anomaly Detection**
   - Unusual spending patterns
   - Merchant reputation checks
   - Velocity limits

---

## Next Research Steps

### Phase 1: Understand Signing (1 session)
1. Read AP2 sample code for human-present x402 scenario
2. Find JWT signing implementation
3. Find verifiable credential signing implementation
4. Document libraries and key formats

### Phase 2: Design Budget Tracking (1 session)
1. Separate state management system architecture
2. Integration with mandates (check before signing)
3. Atomic update patterns (prevent race conditions)

### Phase 3: Stripe Integration Check (1 session)
1. Review Stripe Machine Payments docs (when accessible)
2. Check if AP2 mandate verification is built-in
3. Design verification flow if we need to build it

### Phase 4: Proof of Concept (2-3 sessions)
1. Install AP2 types
2. Create simple Intent Mandate (manual)
3. Sign with test keys
4. Verify signature
5. Make test payment (Josh → Ada $0.01)

---

## Core Concepts

### Verifiable Digital Credentials (VDCs)

**What:** Tamper-evident, cryptographically signed digital objects that serve as building blocks of transactions.

**Why:** Provide non-repudiable proof of:
- User intent (Intent Mandate signed by user)
- Cart authenticity (Cart Mandate signed by merchant)
- Payment authorization (Payment Mandate signed by user)

**How:** Using standard web cryptography:
- **JWT (JSON Web Tokens)** - widely adopted, easy to verify
- **Verifiable Credentials** - W3C standard for digital identity
- **Selective Disclosure** - reveal only necessary data to each party

### Role-Based Architecture

Different parties see different information:
- **User:** Sees all mandates (full transparency)
- **Shopping Agent:** Sees Intent + Cart + Payment mandates
- **Merchant Agent:** Sees Intent + Cart mandates (not payment details)
- **Payment Network:** Sees Payment Mandate (not cart details beyond total)

**Privacy by design:** Each party gets only what they need.

---

## Design Principles (from AP2 docs)

1. **Openness and Interoperability**
   - Non-proprietary, open extension for A2A and MCP
   - Any compliant agent can transact with any compliant merchant

2. **User Control and Privacy**
   - User always in control
   - Role-based architecture protects sensitive data

3. **Verifiable Intent, Not Inferred Action**
   - Trust anchored to deterministic, non-repudiable proof
   - Addresses risk of agent error or hallucination

4. **Clear Transaction Accountability**
   - Non-repudiable, cryptographic audit trail
   - Aids dispute resolution

5. **Global and Future-Proof**
   - Initial version: "pull" payments (cards)
   - Roadmap: "push" payments (UPI, PIX, RTP), digital currencies

---

## Comparison: steward vs. AP2

| Aspect | steward | AP2 |
|--------|--------|-----|
| **Purpose** | Secret storage + leak prevention | Payment authorization + audit trail |
| **Layer** | Security infrastructure | Authorization protocol |
| **Provides** | Session keys, output sanitization, input validation | Mandate structures, signing patterns |
| **Does NOT provide** | Authorization proofs | Secret management |
| **Use in Trustee** | Phase 0 - security foundation | Phase 1 - authorization layer |
| **Integration** | Store AP2 signing keys via steward | Sign AP2 mandates with steward-protected keys |

**They're complementary:**
- steward protects the keys
- AP2 uses the keys to create signed mandates
- Together: secure authorization with leak-proof key management

---

## Key Quotes from Docs

> "Today's payment systems assume a human is directly clicking 'buy' on a trusted website. When an autonomous agent initiates a payment, this core assumption is broken."

> "AP2 aims to create a common language for any compliant agent to transact securely with any compliant merchant globally."

> "Trust in payments is anchored to deterministic, non-repudiable proof of intent from the user, directly addressing the risk of agent error or hallucination."

> "The Agent Payments Protocol engineers trust into the system using verifiable digital credentials (VDCs)."

---

## Resources

**Official:**
- Documentation: https://ap2-protocol.org/
- GitHub: https://github.com/google-agentic-commerce/AP2
- Launch blog: https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol
- Intro video: https://goo.gle/ap2-video

**Technical:**
- Python types: `src/ap2/types/mandate.py`
- Sample scenarios: `samples/python/scenarios/`
- W3C PaymentRequest: https://www.w3.org/TR/payment-request/
- JWT spec: https://datatracker.ietf.org/doc/html/rfc7519
- sd-jwt-vc: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/

**Partners (60+):**
- Payment networks: Mastercard, Visa (implied), American Express
- Payment processors: Adyen, Stripe (via ACP), PayPal, Worldpay
- Crypto: Coinbase, MetaMask, Mysten Labs (Sui)
- Enterprise: Salesforce, ServiceNow, Intuit, Adobe, Dell
- Identity: Okta (Auth0), 1Password

---

*Research complete: 2026-02-10 19:10 EST*  
*Next: Deep dive into AP2 sample code for signing implementation*
