// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";

contract ConfidentialLedgerTest is Test {
    ConfidentialLedger ledger;

    address verifier;
    address alice;
    address bob;

    function setUp() public {
        // Assign addresses
        verifier = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266); // Address 0
        alice = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8); // Address 1
        bob = address(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC); // Address 2

        // Deploy ledger with verifier
        ledger = new ConfidentialLedger(verifier);
    }

    function testTransfer() public {
        // Register accounts
        vm.startPrank(alice);
        uint256 aliceV = 100; // value
        uint256 aliceR = 42; // blinding factor
        ConfidentialLedger.Commitment memory aliceCommit = pedersenCommitOffchain(aliceV, aliceR);
        ledger.registerAccount(aliceCommit.x, aliceCommit.y);
        vm.stopPrank();

        vm.startPrank(bob);
        uint256 bobV = 50;
        uint256 bobR = 99;
        ConfidentialLedger.Commitment memory bobCommit = pedersenCommitOffchain(bobV, bobR);
        ledger.registerAccount(bobCommit.x, bobCommit.y);
        vm.stopPrank();

        // Submit transfer: Alice sends 20 to Bob
        vm.startPrank(alice);
        uint256 transferValue = 20;
        uint256 transferR = 7; // blinding
        ConfidentialLedger.Commitment memory valueCommit = pedersenCommitOffchain(transferValue, transferR);

        uint256 transferId = ledger.submitTransfer(
            bob,
            valueCommit.x,
            valueCommit.y,
            hex"1234" // dummy proof; this will be replaced by a Bulletproof range proof later.
        );
        vm.stopPrank();

        // Approve transfer (by trusted verifier)
        vm.prank(verifier);
        ledger.approveTransfer(transferId);

        // Execute transfer
        ledger.executeTransfer(transferId);

        // Check balances
        (uint256 aliceX, uint256 aliceY) = ledger.commitments(alice);
        ConfidentialLedger.Commitment memory aliceFinal = ConfidentialLedger.Commitment(aliceX, aliceY);

        (uint256 bobX, uint256 bobY) = ledger.commitments(bob);
        ConfidentialLedger.Commitment memory bobFinal = ConfidentialLedger.Commitment(bobX, bobY);

        // sanity check (commitments are on curve)
        require(EllipticCurve.isOnCurve(aliceFinal.x, aliceFinal.y, AA, BB, PP), "Alice final not on curve");
        require(EllipticCurve.isOnCurve(bobFinal.x, bobFinal.y, AA, BB, PP), "Bob final not on curve");

        // Compute expected final commitments for Alice
        uint256 expectedAliceV = 80; // 100 - 20
        uint256 expectedAliceR = 35; // 42 - 7
        ConfidentialLedger.Commitment memory expectedAlice = pedersenCommitOffchain(expectedAliceV, expectedAliceR);

        // Compute expected final commitments for Bob
        uint256 expectedBobV = 70; // 50 + 20
        uint256 expectedBobR = 106; // 99 + 7
        ConfidentialLedger.Commitment memory expectedBob = pedersenCommitOffchain(expectedBobV, expectedBobR);

        assertEq(aliceFinal.x, expectedAlice.x, "Alice commitment X mismatch");
        assertEq(aliceFinal.y, expectedAlice.y, "Alice commitment Y mismatch");
        assertEq(bobFinal.x, expectedBob.x, "Bob commitment X mismatch");
        assertEq(bobFinal.y, expectedBob.y, "Bob commitment Y mismatch");
    }
}
