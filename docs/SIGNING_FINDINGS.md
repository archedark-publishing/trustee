# Signing Implementation Findings
*February 10, 2026 - 7:45 PM EST*

## Summary

Research into a2a-x402 Python implementation revealed the actual signing architecture for agent payments.

---

## Payment Authorization Signing (Agent → Merchant)

**What we found:** Payment signatures use **EIP-712 typed data signing**, NOT JWT.

### Implementation Details

**Library Stack:**
```python
from x402.clients.base import x402Client
from eth_account import Account
from x402.types import PaymentRequirements, PaymentPayload
```

**Signing Flow:**
```python
# 1. Create Ethereum account (or load from key)
account = Account.from_key("0x_private_key_here")

# 2. Initialize x402 client with spending limits
client = x402Client(account=account, max_value=1000)  # max $10 in atomic units

# 3. Receive payment requirements from merchant
payment_required = x402PaymentRequiredResponse(
    x402_version=1,
    accepts=[payment_requirements]
)

# 4. Client selects payment option
selected = client.select_payment_requirements(payment_required.accepts)

# 5. Sign payment (creates EIP-712 signature)
payment_payload = await process_payment(selected, account)

# PaymentPayload structure:
# - scheme: "exact"
# - network: "base"  
# - payload: ExactPaymentPayload with EIP712 signature
```

**Key Components:**

**EIP-712 Domain:**
```python
EIP712Domain(
    name="x402",
    version="1", 
    chainId=8453,  # Base mainnet
    verifyingContract="0x..."  # Token contract
)
```

**ExactPaymentPayload:**
```python
ExactPaymentPayload(
    authorization: EIP3009Authorization(  # EIP-3009 transfer authorization
        from_address="0x...",  # Payer
        to_address="0x...",    # Recipient  
        value="1000000",       # Amount in atomic units
        validAfter=timestamp,
        validBefore=timestamp + 600,
        nonce=unique_nonce
    ),
    signature="0x...",  # EIP-712 signature of authorization
    signer="0x..."      # Signer address
)
```

**Security Properties:**
- **Bound to specific contract:** EIP-712 domain includes token contract address
- **Time-limited:** validAfter/validBefore timestamps
- **Non-replayable:** Unique nonce per payment
- **Amount-limited:** Explicitly specified value
- **Network-specific:** ChainId in domain

---

## Cart Mandate Signing (Merchant → Agent)

**Status:** Implementation not yet found in samples

**Expected Pattern (from AP2 types):**
```python
CartMandate(
    contents: CartContents(...),
    merchant_authorization: str  # Base64url-encoded JWT
)
```

**JWT Payload (from AP2_RESEARCH.md):**
```json
{
  "iss": "merchant-id",
  "sub": "cart-contents",
  "aud": "payment-processor",
  "iat": 1707607200,
  "exp": 1707607800,
  "jti": "unique-jwt-id",
  "cart_hash": "sha256-of-cart-contents"
}
```

**Likely Libraries:**
- `PyJWT` (most popular Python JWT library)
- `python-jose` (includes JWT + JWS/JWE)
- `jwcrypto` (comprehensive crypto library)

**Key Type:** RS256 (RSA) or ES256K (secp256k1 ECDSA)

**Next Step:** Search AP2 samples for JWT signing code

---

## Payment Mandate User Authorization

**Status:** Implementation not yet found

**Expected Pattern (from AP2 types):**
```python
PaymentMandate(
    payment_mandate_contents: PaymentMandateContents(...),
    user_authorization: str  # Base64url-encoded sd-jwt-vc
)
```

**sd-jwt-vc Structure:**
- **Issuer-signed JWT:** Authorizes a `cnf` (confirmation) claim
- **Key-binding JWT:** Contains transaction_data hashes
- **Selective Disclosure:** Reveals only necessary fields

**Likely Libraries:**
- Reference implementation from IETF spec
- Google/Coinbase may have custom implementation

**Next Step:** Check if AP2 samples include sd-jwt-vc or use simplified approach

---

## Integration Plan for Trustee

### Phase 0: Payment Signing (x402)

**Install Dependencies:**
```bash
uv pip install git+https://github.com/google-agentic-commerce/a2a-x402.git#subdirectory=python/x402_a2a
uv pip install eth_account
```

**Generate Ethereum Key:**
```python
from eth_account import Account
account = Account.create()
# Store private_key in 1Password via steward
```

**Sign Test Payment:**
```python
from x402_a2a import process_payment
from x402.types import PaymentRequirements

requirements = PaymentRequirements(
    scheme="exact",
    network="base",
    asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC on Base
    pay_to="0xjosh_address",
    max_amount_required="10000",  # $0.01 (6 decimals)
    resource="/test-payment"
)

payload = await process_payment(requirements, account)
```

### Phase 1: Cart Mandate Signing (JWT)

**Research Needed:**
1. Find JWT signing in AP2 samples
2. Determine key format (RSA vs ECDSA)
3. Generate/store signing key via steward
4. Implement cart hash function

### Phase 2: Payment Mandate (Optional for MVP)

**sd-jwt-vc may not be required for proof-of-concept** - depends on whether Stripe verifies these or if they're just for payment network visibility.

**Possible simplification:** Use simpler signature format initially, add full VDC compliance later.

---

## Security Considerations

### Key Storage via steward

**Payment Signing Key (Ethereum):**
```bash
# Store in 1Password
op item create \
  --vault "Trustee-Secrets" \
  --category "API Credential" \
  --title "trustee-payment-key" \
  --field "private_key=0x..."
```

**Cart Signing Key (JWT):**
```bash
# Store RSA private key
op item create \
  --vault "Trustee-Secrets" \
  --category "API Credential" \
  --title "trustee-cart-signing-key" \
  --field "private_key=-----BEGIN PRIVATE KEY-----..."
```

**Access via steward:**
```python
from steward import get_secret

# Retrieve at runtime (never persisted)
payment_key = get_secret("trustee-payment-key", "private_key")
account = Account.from_key(payment_key)
```

### Output Sanitization

**Critical:** All private keys must be sanitized before ANY output:

```python
from steward.sanitizer import OutputSanitizer

def respond(content: str) -> str:
    return OutputSanitizer.sanitize(content)
```

Catches:
- Ethereum private keys (0x + 64 hex)
- PEM private keys (RSA/ECDSA)
- JWT tokens
- Seed phrases

---

## Remaining Unknowns

### Critical
- [ ] JWT signing library used by AP2 samples
- [ ] JWT key generation (RSA vs ECDSA? Key size?)
- [ ] Cart hash function (SHA-256 of canonical JSON?)
- [ ] sd-jwt-vc requirement (mandatory for Stripe? or optional?)

### Important
- [ ] Key rotation strategy (how to update keys without breaking active mandates?)
- [ ] Multi-signature support (does Trustee need multiple signing keys?)
- [ ] Facilitator endpoint (x402.org/facilitator vs custom?)

### Nice-to-Have
- [ ] Hardware wallet integration (Ledger/Trezor support?)
- [ ] Multi-party computation (MPC) for key management
- [ ] Biometric confirmation for high-value transactions

---

## Next Research Steps

1. **Search AP2 samples for JWT signing:**
   ```bash
   # Clone AP2 repo
   git clone https://github.com/google-agentic-commerce/AP2.git
   # Search for JWT/jose/jwcrypto imports
   grep -r "import jwt\|from jose\|import jwcrypto" AP2/samples/python/
   ```

2. **Test x402 payment signing locally:**
   - Install x402-a2a package
   - Create test account
   - Sign test payment
   - Verify signature

3. **Check Stripe Machine Payments docs:**
   - Does Stripe verify AP2 mandates?
   - Or just x402 payment signatures?
   - What's required for MVP?

---

*Research session complete: 2026-02-10 7:45 PM EST*  
*Major breakthrough: Payment signing fully understood via eth_account + EIP-712*
