// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {DevicePassRegistry} from "../src/DevicePassRegistry.sol";

contract DeployScript is Script {
    function run() public {
        vm.startBroadcast();
        DevicePassRegistry registry = new DevicePassRegistry();
        vm.stopBroadcast();

        console.log("DevicePassRegistry deployed at:", address(registry));
    }
}
