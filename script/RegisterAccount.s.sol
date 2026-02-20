// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";
import {console} from "forge-std/console.sol";

contract RegisterAccountScript is Script {
    function run() external {
        // Address of deployed contract
        address ledgerAddress = vm.envAddress("LEDGER_ADDRESS");
        ConfidentialLedger ledger = ConfidentialLedger(ledgerAddress);

        ConfidentialLedger.G1Point memory commitment = ConfidentialLedger.G1Point({x: 1111, y: 2222});

        // Start broadcast
        vm.startBroadcast();

        ledger.registerAccount(commitment);

        vm.stopBroadcast();

        console.log("Account registered");
    }
}
