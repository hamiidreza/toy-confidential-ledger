// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";
import {Script} from "forge-std/Script.sol";

contract DeployLedger is Script {
    function run() external {
        // start broadcasting transactions
        vm.startBroadcast();

        // deploy the contract with the first Anvil account as trusted verifier
        new ConfidentialLedger(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);

        vm.stopBroadcast();
    }
}
