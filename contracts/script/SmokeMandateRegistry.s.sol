// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {MandateRegistry} from "src/MandateRegistry.sol";

/// @notice Post-deploy smoke test for registry trust -> issue -> revoke flow.
contract SmokeMandateRegistry is Script {
    function run() external {
        uint256 guardianPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        uint256 issuerPrivateKey = vm.envOr("SMOKE_ISSUER_PRIVATE_KEY", guardianPrivateKey);

        address registryAddress = vm.envAddress("MANDATE_REGISTRY_ADDRESS");
        address agent = vm.envAddress("SMOKE_AGENT_ADDRESS");
        address issuer = vm.addr(issuerPrivateKey);

        MandateRegistry registry = MandateRegistry(registryAddress);

        bytes32 mandateHash = keccak256(
            abi.encodePacked(
                "smoke",
                block.chainid,
                registryAddress,
                agent,
                issuer,
                block.timestamp
            )
        );
        bytes32 payloadHash = keccak256(abi.encodePacked("payload", mandateHash));
        uint64 expiresAt = uint64(block.timestamp + 1 days);

        vm.startBroadcast(guardianPrivateKey);
        registry.setTrustedIssuer(agent, issuer, true);
        vm.stopBroadcast();

        vm.startBroadcast(issuerPrivateKey);
        registry.issueMandateOnChain(mandateHash, payloadHash, agent, expiresAt, "ipfs://smoke");
        registry.revokeMandate(mandateHash);
        vm.stopBroadcast();

        _assertRegistryState(
            registry,
            mandateHash,
            expiresAt,
            issuer,
            agent,
            payloadHash
        );

        console2.log("Smoke test succeeded for registry", registryAddress);
        console2.log("Mandate hash", vm.toString(mandateHash));
    }

    function _assertRegistryState(
        MandateRegistry registry,
        bytes32 mandateHash,
        uint64 expiresAt,
        address issuer,
        address agent,
        bytes32 payloadHash
    ) internal view {
        (
            bool exists,
            bool active,
            bool revoked,
            uint64 returnedExpiresAt,
            address returnedIssuer,
            address returnedAgent,
            bytes32 returnedPayloadHash,
            string memory returnedMetadataURI
        ) = registry.getMandateStatus(mandateHash);

        require(exists, "smoke: mandate missing");
        require(!active, "smoke: expected inactive after revoke");
        require(revoked, "smoke: expected revoked");
        require(returnedExpiresAt == expiresAt, "smoke: expiry mismatch");
        require(returnedIssuer == issuer, "smoke: issuer mismatch");
        require(returnedAgent == agent, "smoke: agent mismatch");
        require(returnedPayloadHash == payloadHash, "smoke: payload hash mismatch");
        require(
            keccak256(bytes(returnedMetadataURI)) == keccak256(bytes("ipfs://smoke")),
            "smoke: metadata mismatch"
        );
    }
}
