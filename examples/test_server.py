"""
Minimal x402-protected test server on Base Sepolia.
"""

import uvicorn
from fastapi import FastAPI, Request, Response

from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.server import x402ResourceServer

app = FastAPI()

PAY_TO = "0x273326453960864FbA4D2F6Cf09D65fA13E45297"

facilitator = HTTPFacilitatorClient(
    FacilitatorConfig(url="https://x402.org/facilitator")
)

server = x402ResourceServer(facilitator)
server.register("eip155:84532", ExactEvmServerScheme())

routes = {
    "GET /data": RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                pay_to=PAY_TO,
                price="$0.001",
                network="eip155:84532",
            ),
        ],
        mime_type="application/json",
        description="Test endpoint",
    ),
}

app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/data")
async def data():
    return {"message": "Payment successful!", "cost": "$0.001 USDC"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8402)
