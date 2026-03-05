// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {DevicePassRegistry} from "../src/DevicePassRegistry.sol";

/// @notice Claim a device on a local Anvil testnet.
/// Usage:
///   DEVICE_KEY=0x... REGISTRY=0x... forge script script/Claim.s.sol \
///     --rpc-url http://localhost:8545 --private-key <GUARDIAN_KEY> --broadcast
contract ClaimScript is Script {
    function run() public {
        // Device key from environment
        uint256 deviceKey = vm.envUint("DEVICE_KEY");
        address device = vm.addr(deviceKey);
        address registry = vm.envAddress("REGISTRY");

        uint256 nonce = block.timestamp;

        // Open claim (guardian = address(0))
        address guardianInBlob = address(0);

        // Reconstruct the message the device signs (matches devicepass-cli onboard)
        bytes32 innerHash = keccak256(
            abi.encodePacked(device, guardianInBlob, nonce, block.chainid)
        );
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", innerHash)
        );

        // Sign with device key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, messageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        console.log("Device:", device);
        console.log("Guardian:", msg.sender);
        console.log("Nonce:", nonce);

        // Submit claim as guardian (msg.sender = the --private-key account)
        vm.startBroadcast();
        DevicePassRegistry(registry).claimDevice(device, guardianInBlob, nonce, sig);
        vm.stopBroadcast();

        // Verify
        (, address guardian, , bool active) = DevicePassRegistry(registry).passports(device);
        console.log("Claimed! Guardian:", guardian);
        console.log("Active:", active);
    }
}
