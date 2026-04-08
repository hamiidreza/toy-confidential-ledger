// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ConfidentialLedger} from "../ConfidentialLedger.sol";

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

    function testCommitment() public view {
        uint256 value = 10;
        uint256 blinding = 123;
        ConfidentialLedger.G1Point memory cm = ledger.buildCommitment(value, blinding);

        console.log("Solidity commitment:");
        console.log("x:", cm.x);
        console.log("y:", cm.y);
    }

    function testTransfer() public {
        // Dummy proof
        ConfidentialLedger.RegistrationProof memory dummyProof =
            ConfidentialLedger.RegistrationProof({A: ConfidentialLedger.G1Point(123, 456), z: 123});
        // Register accounts
        vm.startPrank(alice);
        uint256 aliceV = 100; // value
        uint256 aliceR = 42; // blinding factor
        ConfidentialLedger.G1Point memory aliceCommit = ledger.buildCommitment(aliceV, aliceR);
        ledger.registerAccount(aliceCommit, dummyProof);
        vm.stopPrank();

        vm.startPrank(bob);
        uint256 bobV = 50;
        uint256 bobR = 99;
        ConfidentialLedger.G1Point memory bobCommit = ledger.buildCommitment(bobV, bobR);
        ledger.registerAccount(bobCommit, dummyProof);
        vm.stopPrank();

        // Submit transfer: Alice sends 20 to Bob
        vm.startPrank(alice);
        uint256 transferValue = 20;
        uint256 transferR = 7; // blinding
        ConfidentialLedger.G1Point memory valueCommit = ledger.buildCommitment(transferValue, transferR);

        uint256 transferId = ledger.submitTransfer(
            bob,
            valueCommit,
            hex"1234" // dummy proof; this will be replaced by a Bulletproof range proof later.
        );
        vm.stopPrank();

        // Approve and execute transfer (by trusted verifier)
        vm.prank(verifier);
        ledger.approveAndExecuteTransfer(transferId);

        // Check balances
        (uint256 aliceX, uint256 aliceY) = ledger.commitments(alice);
        ConfidentialLedger.G1Point memory aliceFinal = ConfidentialLedger.G1Point(aliceX, aliceY);

        (uint256 bobX, uint256 bobY) = ledger.commitments(bob);
        ConfidentialLedger.G1Point memory bobFinal = ConfidentialLedger.G1Point(bobX, bobY);

        // sanity check (commitments are on curve)

        ledger.requireValidPoint(aliceFinal);
        ledger.requireValidPoint(bobFinal);

        // Compute expected final commitments for Alice
        uint256 expectedAliceV = 80; // 100 - 20
        uint256 expectedAliceR = 35; // 42 - 7
        ConfidentialLedger.G1Point memory expectedAlice = ledger.buildCommitment(expectedAliceV, expectedAliceR);

        // Compute expected final commitments for Bob
        uint256 expectedBobV = 70; // 50 + 20
        uint256 expectedBobR = 106; // 99 + 7
        ConfidentialLedger.G1Point memory expectedBob = ledger.buildCommitment(expectedBobV, expectedBobR);

        assertEq(aliceFinal.x, expectedAlice.x, "Alice commitment X mismatch");
        assertEq(aliceFinal.y, expectedAlice.y, "Alice commitment Y mismatch");
        assertEq(bobFinal.x, expectedBob.x, "Bob commitment X mismatch");
        assertEq(bobFinal.y, expectedBob.y, "Bob commitment Y mismatch");
    }

    function testComputeChallenge() public view {
        address sender = address(0x2222222222222222222222222222222222222222);
        uint256 value = 42;

        ConfidentialLedger.G1Point memory C = ledger.generatorG();
        ConfidentialLedger.G1Point memory A = ledger.generatorH();

        uint256 c = ledger.computeChallenge(sender, value, C, A);

        console.log("challenge:", c);
    }
}
