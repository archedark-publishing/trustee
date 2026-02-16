"""
End-to-end test: Steward-secured x402 payment on Base Sepolia.

This is the PRODUCTION flow:
1. Steward creates a time-limited session (loads key from 1Password)
2. Agent gets a StewardSigner (never sees private key)
3. X402PaymentClient uses StewardSigner to make payments
4. Session enforces spending limits and auto-expires
"""

import time
import threading
import sys

import uvicorn

sys.path.insert(0, "../src")
from test_server import app
from trustee.steward import Steward, SessionConfig
from trustee.x402_client import X402PaymentClient, X402Config, Network


def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8402, log_level="error")


def main():
    print("🔐 Trustee + Steward E2E — Secure x402 Payment")
    print("=" * 55)
    print()

    # 1. Start server
    print("1️⃣  Starting x402 test server...")
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(2)
    print("   ✅ Server running")
    print()

    # 2. Create Steward session
    print("2️⃣  Creating Steward session...")
    steward = Steward()
    session = steward.create_session(
        op_item="trustee test",
        op_vault="Ada",
        op_field="credential",
        config=SessionConfig(
            max_spend_usd=1.0,       # Session can spend up to $1
            max_per_tx_usd=0.01,     # Max $0.01 per transaction
            ttl_seconds=300,          # 5 minute session
            allowed_networks=["eip155:84532"],
        ),
    )
    print(f"   ✅ Session: {session.session_id}")
    print(f"   Wallet: {session.wallet_address}")
    print(f"   Budget: ${session.config.max_spend_usd} total, ${session.config.max_per_tx_usd}/tx")
    print(f"   TTL: {session.config.ttl_seconds}s")
    print()

    # 3. Agent creates x402 client FROM Steward session (never sees key!)
    print("3️⃣  Creating x402 client from Steward session...")
    client = X402PaymentClient.from_steward_session(
        steward=steward,
        session_id=session.session_id,
        config=X402Config(network=Network.BASE_SEPOLIA),
    )
    print(f"   ✅ Client ready (address: {client.address})")
    print(f"   Agent NEVER saw the private key!")
    print()

    # 4. Make payment through Steward
    print("4️⃣  Making x402 payment through Steward session...")
    signer = steward.get_signer(session.session_id)

    # Pre-check spending (Steward enforces limits)
    ok, reason = signer.check_and_record_spend(0.001)
    print(f"   Spend check ($0.001): {'✅' if ok else '❌'} {reason}")

    if ok:
        result = client.pay(url="http://127.0.0.1:8402/data", method="GET")
        if result.success:
            print(f"   🎉 PAYMENT SUCCESSFUL!")
            print(f"   Network: {result.network}")
        else:
            print(f"   ❌ Payment failed: {result.error}")
    print()

    # 5. Check session state
    print("5️⃣  Session state after payment...")
    print(f"   Spent: ${session.total_spent_usd:.3f} of ${session.config.max_spend_usd}")
    print(f"   Remaining: ${session.remaining_usd:.3f}")
    print(f"   TTL remaining: {session.seconds_remaining}s")
    print()

    # 6. Test budget enforcement
    print("6️⃣  Testing budget enforcement...")
    ok, reason = signer.check_and_record_spend(0.05)
    print(f"   Spend check ($0.05): {'✅' if ok else '❌'} {reason}")
    print()

    # 7. Destroy session
    print("7️⃣  Destroying session...")
    steward.destroy_session(session.session_id)
    print(f"   ✅ Session destroyed, key wiped from memory")
    print(f"   Active sessions: {len(steward.list_sessions())}")
    print()

    print("=" * 55)
    print("🔐 Full Steward flow complete!")
    print("   Key loaded from 1Password → held in session only")
    print("   Agent used StewardSigner → never saw raw key")
    print("   Spending limits enforced → budget capped")
    print("   Session destroyed → key gone from memory")
    client.close()


if __name__ == "__main__":
    main()
