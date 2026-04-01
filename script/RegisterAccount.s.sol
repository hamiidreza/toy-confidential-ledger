// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";
import {console} from "forge-std/console.sol";

contract RegisterAccount is Script {
    function run() external {
        address ledgerAddress = vm.envAddress("LEDGER_ADDRESS");
        ConfidentialLedger ledger = ConfidentialLedger(ledgerAddress);

        uint256 value = 10;
        uint256 blinding = 123;
        ConfidentialLedger.G1Point memory cm = ledger.buildCommitment(value, blinding);

        // Start broadcast
        vm.startBroadcast();

        ledger.registerAccount(cm);

        vm.stopBroadcast();

        console.log("Account registered");
    }
}
