"""
End-to-end test: real x402 payment on Base mainnet.
"""

import json
import subprocess
import time
import threading
import sys

import httpx
import uvicorn
from eth_account import Account

sys.path.insert(0, "../src")
from test_server import app
from trustee.x402_client import X402PaymentClient, X402Config, Network


def load_key_from_1password() -> str:
    result = subprocess.run(
        ["op", "item", "get", "trustee test", "--vault", "Ada", "--format", "json"],
        capture_output=True, text=True,
    )
    fields = json.loads(result.stdout)["fields"]
    return next(f["value"] for f in fields if f["label"] == "credential")


def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8402, log_level="error")


def main():
    print("🚀 Trustee E2E Test — Real x402 Payment on Base Mainnet")
    print("=" * 55)
    print()

    # 1. Start server
    print("1️⃣  Starting x402 test server...")
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(2)
    print("   ✅ Server running on http://127.0.0.1:8402")
    print()

    # 2. Load key
    print("2️⃣  Loading agent key from 1Password...")
    key = load_key_from_1password()
    acct = Account.from_key(key)
    print(f"   ✅ Agent wallet: {acct.address}")
    print()

    # 3. Debug: check what 402 looks like
    print("3️⃣  Checking 402 response...")
    http = httpx.Client(timeout=30)
    resp = http.get("http://127.0.0.1:8402/data")
    print(f"   Status: {resp.status_code}")
    # Show relevant headers
    for h in ("payment-required", "x-payment", "payment-signature"):
        val = resp.headers.get(h)
        if val:
            print(f"   {h}: {val[:100]}...")
    print(f"   Body: {resp.text[:200]}")
    print()

    # 4. Create client and pay
    print("4️⃣  Making real x402 payment...")
    config = X402Config(network=Network.BASE_MAINNET, max_amount_usd=1.0)
    client = X402PaymentClient(account=acct, config=config)

    result = client.pay(url="http://127.0.0.1:8402/data", method="GET")
    print()

    if result.success:
        print(f"   🎉 PAYMENT SUCCESSFUL!")
        print(f"   Payment ID: {result.payment_id}")
        print(f"   TX Hash: {result.tx_hash}")
        print(f"   Network: {result.network}")
        print(f"   Amount: ${result.amount_usdc} USDC")
    else:
        print(f"   ❌ Payment failed: {result.error}")

    print()
    print("=" * 55)
    client.close()
    http.close()


if __name__ == "__main__":
    main()
