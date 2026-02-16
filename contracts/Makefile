.PHONY: install build test deploy-sepolia deploy-mainnet smoke-sepolia smoke-mainnet

install:
	forge install --no-git foundry-rs/forge-std

build:
	forge build

test:
	forge test -vv

deploy-sepolia:
	forge script script/DeployMandateRegistry.s.sol:DeployMandateRegistry \
		--rpc-url base_sepolia \
		--broadcast \
		--verify \
		-vvvv

deploy-mainnet:
	forge script script/DeployMandateRegistry.s.sol:DeployMandateRegistry \
		--rpc-url base \
		--broadcast \
		--verify \
		-vvvv

smoke-sepolia:
	forge script script/SmokeMandateRegistry.s.sol:SmokeMandateRegistry \
		--rpc-url base_sepolia \
		--broadcast \
		-vvvv

smoke-mainnet:
	forge script script/SmokeMandateRegistry.s.sol:SmokeMandateRegistry \
		--rpc-url base \
		--broadcast \
		-vvvv
