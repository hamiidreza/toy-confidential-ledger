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

        // toy commitment values
        uint256 commitmentX = 1111;
        uint256 commitmentY = 2222;

        // Start broadcast
        vm.startBroadcast();

        ledger.registerAccount(commitmentX, commitmentY);

        vm.stopBroadcast();

        console.log("Account registered with commitmentX:", commitmentX, "commitmentY:", commitmentY);
    }
}
