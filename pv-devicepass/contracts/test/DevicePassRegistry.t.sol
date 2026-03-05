// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {DevicePassRegistry} from "../src/DevicePassRegistry.sol";

contract DevicePassRegistryTest is Test {
    DevicePassRegistry public registry;

    // Test accounts
    uint256 constant DEVICE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address deviceAddr;

    address guardian = address(0x7A3F);
    address guardian2 = address(0x8B2A);

    function setUp() public {
        registry = new DevicePassRegistry();
        deviceAddr = vm.addr(DEVICE_KEY);
    }

    /// @dev Build a device signature matching devicepass-cli onboard format
    function _makeClaimSig(uint256 deviceKey, uint256 nonce) internal view returns (bytes memory) {
        address device = vm.addr(deviceKey);

        // Match devicepass-cli: keccak256(abi.encodePacked(device, nonce, chainId))
        bytes32 innerHash = keccak256(
            abi.encodePacked(device, nonce, block.chainid)
        );
        // Ethereum signed message prefix
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", innerHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_claimDevice() public {
        uint256 nonce = 1739612345;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        (address dev, address grd, uint256 created, bool active) = registry.passports(deviceAddr);
        assertEq(dev, deviceAddr);
        assertEq(grd, guardian);
        assertGt(created, 0);
        assertTrue(active);

        assertEq(registry.guardianDeviceCount(guardian), 1);
        assertEq(registry.guardianDeviceAt(guardian, 0), deviceAddr);
    }

    function test_claimDevice_emitsEvent() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.expectEmit(true, true, false, false);
        emit DevicePassRegistry.PassportCreated(deviceAddr, guardian);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);
    }

    function test_claimDevice_revert_alreadyClaimed() public {
        uint256 nonce1 = 100;
        bytes memory sig1 = _makeClaimSig(DEVICE_KEY, nonce1);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce1, sig1);

        // Second claim with different nonce should fail
        uint256 nonce2 = 200;
        bytes memory sig2 = _makeClaimSig(DEVICE_KEY, nonce2);

        vm.prank(guardian2);
        vm.expectRevert(DevicePassRegistry.AlreadyClaimed.selector);
        registry.claimDevice(deviceAddr, nonce2, sig2);
    }

    function test_claimDevice_revert_nonceReplay() public {
        // First: claim and revoke so the device can be reclaimed
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.prank(guardian);
        registry.revokeDevice(deviceAddr);

        // Try to re-claim with same nonce — should fail even after revoke
        vm.prank(guardian2);
        vm.expectRevert(DevicePassRegistry.NonceAlreadyUsed.selector);
        registry.claimDevice(deviceAddr, nonce, sig);
    }

    function test_claimDevice_revert_wrongSigner() public {
        // Sign with a different key than the device address
        uint256 wrongKey = 0xdead;
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(wrongKey, nonce);

        vm.prank(guardian);
        vm.expectRevert(DevicePassRegistry.InvalidSignature.selector);
        registry.claimDevice(deviceAddr, nonce, sig);
    }

    function test_claimDevice_revert_badSignatureLength() public {
        vm.prank(guardian);
        vm.expectRevert(DevicePassRegistry.InvalidSignature.selector);
        registry.claimDevice(deviceAddr, 100, hex"deadbeef");
    }

    function test_transferDevice() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.expectEmit(true, true, true, false);
        emit DevicePassRegistry.PassportTransferred(deviceAddr, guardian, guardian2);

        vm.prank(guardian);
        registry.transferDevice(deviceAddr, guardian2);

        (, address grd, , bool active) = registry.passports(deviceAddr);
        assertEq(grd, guardian2);
        assertTrue(active);

        // Old guardian has 0 devices, new guardian has 1
        assertEq(registry.guardianDeviceCount(guardian), 0);
        assertEq(registry.guardianDeviceCount(guardian2), 1);
    }

    function test_transferDevice_revert_notGuardian() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.prank(guardian2);
        vm.expectRevert(DevicePassRegistry.NotGuardian.selector);
        registry.transferDevice(deviceAddr, guardian2);
    }

    function test_transferDevice_revert_toSelf() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.prank(guardian);
        vm.expectRevert(DevicePassRegistry.TransferToSelf.selector);
        registry.transferDevice(deviceAddr, guardian);
    }

    function test_revokeDevice() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.expectEmit(true, true, false, false);
        emit DevicePassRegistry.PassportRevoked(deviceAddr, guardian);

        vm.prank(guardian);
        registry.revokeDevice(deviceAddr);

        (, , , bool active) = registry.passports(deviceAddr);
        assertFalse(active);
    }

    function test_revokeDevice_revert_notGuardian() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.prank(guardian2);
        vm.expectRevert(DevicePassRegistry.NotGuardian.selector);
        registry.revokeDevice(deviceAddr);
    }

    function test_revokeDevice_revert_alreadyRevoked() public {
        uint256 nonce = 100;
        bytes memory sig = _makeClaimSig(DEVICE_KEY, nonce);

        vm.prank(guardian);
        registry.claimDevice(deviceAddr, nonce, sig);

        vm.prank(guardian);
        registry.revokeDevice(deviceAddr);

        vm.prank(guardian);
        vm.expectRevert(DevicePassRegistry.NotActive.selector);
        registry.revokeDevice(deviceAddr);
    }

    function test_multipleDevicesPerGuardian() public {
        // Claim two devices with same guardian
        uint256 key2 = 0xbeef;
        address device2 = vm.addr(key2);

        bytes memory sig1 = _makeClaimSig(DEVICE_KEY, 100);
        bytes memory sig2 = _makeClaimSig(key2, 200);

        vm.startPrank(guardian);
        registry.claimDevice(deviceAddr, 100, sig1);
        registry.claimDevice(device2, 200, sig2);
        vm.stopPrank();

        assertEq(registry.guardianDeviceCount(guardian), 2);
    }
}
