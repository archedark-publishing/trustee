# AP2 Deployment Record

Use this file to record canonical contract addresses and verification links.

## Mandate Registry

| Network | Chain ID | Contract | Tx Hash | Basescan Link | Verified |
|---|---:|---|---|---|---|
| Base Sepolia | 84532 | TODO | TODO | TODO | TODO |
| Base Mainnet | 8453 | TODO | TODO | TODO | TODO |

## Configuration Updates

- [ ] `MANDATE_REGISTRY_ADDRESS` updated in runtime config/env
- [ ] EIP-712 `verifyingContract` updated to mainnet address
- [ ] Deployment commit/tag recorded
- [ ] Smoke test hashes recorded

## Deployment Commands

```bash
cd contracts
cp .env.example .env
# fill env vars
source .env
make test
make deploy-sepolia
make smoke-sepolia
make deploy-mainnet
make smoke-mainnet
```

## Local Readiness Evidence

- Foundry installed: `forge 1.5.1-stable`
- `forge test -vv` in `contracts/`: pass (20/20)
- Deployment smoke script added: `contracts/script/SmokeMandateRegistry.s.sol`
- Local anvil simulation: deploy + smoke flow succeeded (`Smoke test succeeded for registry ...`)

## Smoke Test Evidence

- [ ] Trusted issuer set
- [ ] Mandate issued
- [ ] Mandate revoked
- [ ] Status query verified
