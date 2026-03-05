// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title DevicePassRegistry
/// @notice On-chain registry for DevicePass device identity and guardian ownership.
/// @dev Devices generate secp256k1 keypairs offline. Guardians claim devices by
///      submitting a device-signed blob. The contract verifies the signature and
///      records the guardian as the device's owner.
contract DevicePassRegistry {
    struct Passport {
        address device;
        address guardian;
        uint256 createdAt;
        bool active;
    }

    /// @notice device address => Passport
    mapping(address => Passport) public passports;

    /// @notice guardian address => list of owned device addresses
    mapping(address => address[]) public guardianDevices;

    /// @notice Tracks used nonces per device to prevent replay
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    event PassportCreated(address indexed device, address indexed guardian);
    event PassportTransferred(address indexed device, address indexed oldGuardian, address indexed newGuardian);
    event PassportRevoked(address indexed device, address indexed guardian);

    error AlreadyClaimed();
    error InvalidSignature();
    error NonceAlreadyUsed();
    error NotGuardian();
    error NotActive();
    error TransferToSelf();

    /// @notice Claim a device by submitting its signed onboard blob.
    /// @param device The device's Ethereum address
    /// @param nonce The nonce from the claim blob (typically a timestamp)
    /// @param deviceSignature 65-byte Ethereum signature (r, s, v) from the device
    /// @dev The device signs: keccak256("\x19Ethereum Signed Message:\n32" + keccak256(abi.encodePacked(device, nonce, chainId)))
    function claimDevice(
        address device,
        uint256 nonce,
        bytes calldata deviceSignature
    ) external {
        if (passports[device].active) revert AlreadyClaimed();
        if (usedNonces[device][nonce]) revert NonceAlreadyUsed();

        // Reconstruct the message the device signed
        bytes32 innerHash = keccak256(
            abi.encodePacked(device, nonce, block.chainid)
        );
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", innerHash)
        );

        // Recover signer from signature
        address signer = _recover(messageHash, deviceSignature);
        if (signer != device) revert InvalidSignature();

        // Mark nonce as used
        usedNonces[device][nonce] = true;

        // Create passport
        passports[device] = Passport({
            device: device,
            guardian: msg.sender,
            createdAt: block.timestamp,
            active: true
        });

        guardianDevices[msg.sender].push(device);

        emit PassportCreated(device, msg.sender);
    }

    /// @notice Transfer device ownership to a new guardian.
    /// @param device The device address
    /// @param newGuardian The new guardian address
    function transferDevice(address device, address newGuardian) external {
        Passport storage p = passports[device];
        if (p.guardian != msg.sender) revert NotGuardian();
        if (!p.active) revert NotActive();
        if (newGuardian == msg.sender) revert TransferToSelf();

        address oldGuardian = p.guardian;
        p.guardian = newGuardian;

        // Remove from old guardian's list
        _removeDevice(oldGuardian, device);
        // Add to new guardian's list
        guardianDevices[newGuardian].push(device);

        emit PassportTransferred(device, oldGuardian, newGuardian);
    }

    /// @notice Revoke (deactivate) a device passport.
    /// @param device The device address
    function revokeDevice(address device) external {
        Passport storage p = passports[device];
        if (p.guardian != msg.sender) revert NotGuardian();
        if (!p.active) revert NotActive();

        p.active = false;

        emit PassportRevoked(device, msg.sender);
    }

    /// @notice Get the number of devices owned by a guardian.
    function guardianDeviceCount(address guardian) external view returns (uint256) {
        return guardianDevices[guardian].length;
    }

    /// @notice Get a device address from a guardian's device list by index.
    function guardianDeviceAt(address guardian, uint256 index) external view returns (address) {
        return guardianDevices[guardian][index];
    }

    /// @dev Recover signer address from a signed message hash.
    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        // Support both {27,28} and {0,1} for v
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();

        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();

        return signer;
    }

    /// @dev Remove a device from a guardian's list (swap-and-pop).
    function _removeDevice(address guardian, address device) internal {
        address[] storage devices = guardianDevices[guardian];
        for (uint256 i = 0; i < devices.length; i++) {
            if (devices[i] == device) {
                devices[i] = devices[devices.length - 1];
                devices.pop();
                return;
            }
        }
    }
}
