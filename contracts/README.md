# Contracts Workspace (Phase 0)

This directory contains the AP2 on-chain mandate registry and Foundry-based tests/deployment scripts.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Base RPC URLs and Basescan API key

## Quick Start

```bash
cd contracts
forge install --no-git foundry-rs/forge-std
forge build
forge test -vv
```

Or with make targets:

```bash
cd contracts
make install
make test
```

## Environment Variables

- `BASE_SEPOLIA_RPC_URL`
- `BASE_RPC_URL`
- `BASESCAN_API_KEY`
- `DEPLOYER_PRIVATE_KEY`
- `MANDATE_GUARDIAN` (optional, defaults to deployer)

## Deploy

### Base Sepolia

```bash
cd contracts
make deploy-sepolia
```

### Base Mainnet

```bash
cd contracts
make deploy-mainnet
```

## Post-Deploy Smoke Test

Set:
- `MANDATE_REGISTRY_ADDRESS`
- `SMOKE_AGENT_ADDRESS`
- `DEPLOYER_PRIVATE_KEY`
- Optional `SMOKE_ISSUER_PRIVATE_KEY` (defaults to deployer key)

Then run:

```bash
cd contracts
make smoke-sepolia
# or
make smoke-mainnet
```

Smoke script validates:
1. trusted issuer update
2. mandate issuance
3. mandate revocation
4. registry status consistency

## Test Focus (Phase 0)

- Trusted issuer authorization
- Pause controls
- Issuance/revocation authorization
- Expiry semantics
- Pagination over active + inactive mandates
