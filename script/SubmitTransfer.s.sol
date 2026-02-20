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
        address to = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
        ConfidentialLedger.G1Point memory valueCommitment = ConfidentialLedger.G1Point({x: 1111, y: 2222});
        bytes memory proof = hex"1234";

        // Broadcast transaction
        vm.startBroadcast();

        // Submit transfer
        uint256 transferId = ConfidentialLedger(ledgerAddress).submitTransfer(to, valueCommitment, proof);
        vm.stopBroadcast();

        // Log result
        console.log("Transfer submitted with ID:", transferId);
    }
}
