// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";
import {Script} from "forge-std/Script.sol";

contract ApproveTransfer is Script {
    function run() external {
        address ledgerAddress = vm.envAddress("LEDGER_ADDRESS");
        ConfidentialLedger ledger = ConfidentialLedger(ledgerAddress);

        vm.startBroadcast();
        ledger.approveAndExecuteTransfer(0);
        vm.stopBroadcast();
    }
}
