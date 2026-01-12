// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

contract SubmitTransfer is Script {
    function run() external {
        // Address of deployed contract
        address ledgerAddress = vm.envAddress("LEDGER_ADDRESS");

        // Parameters for transfer
        address to = vm.addr(1);
        uint256 valueCommitmentX = 1111;
        uint256 valueCommitmentY = 2222;
        bytes memory proof = hex"1234";

        // Broadcast transaction
        vm.startBroadcast();

        // Submit transfer
        uint256 transferId = ConfidentialLedger(ledgerAddress).submitTransfer(to, valueCommitmentX, valueCommitmentY, proof);
        vm.stopBroadcast();

        // Log result
        console.log("Transfer submitted with ID:", transferId);
    }
}
