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

    function testRegisterAccountValid() public {
        vm.deal(alice, 10 ether);
        vm.startPrank(alice);

        uint256 v = 10;

        // The commitment and proof are test vectors computed by the rust backend
        ConfidentialLedger.G1Point memory C = ConfidentialLedger.G1Point({
            x: 2728948068662588906053375844853277504133613820970435701842157998734568672810,
            y: 853849046403142810594520388990037673382175221343473553991405080325106189102
        });

        ConfidentialLedger.RegistrationProof memory proof = ConfidentialLedger.RegistrationProof({
            A: ConfidentialLedger.G1Point({
                x: 1580254641683112776236868289133220474143398396497069723358872286826089243728,
                y: 20252714120964733343018400241965905222243836476699619031872049389087716721440
            }),
            z: 8808648237554383923209689863624107147014760259119199861981385717219860194777
        });

        ledger.registerAccount{value: v}(C, proof);

        assertTrue(ledger.registered(alice));

        (uint256 x, uint256 y) = ledger.commitments(alice);
        assertEq(x, C.x);
        assertEq(y, C.y);

        vm.stopPrank();
    }

    function testTransfer() public {
        // Register accounts
        vm.deal(alice, 10 ether);
        vm.startPrank(alice);
        uint256 aliceV = 10; // value
        uint256 aliceR = 123; // blinding factor
        ConfidentialLedger.G1Point memory aliceCommit = ledger.buildCommitment(aliceV, aliceR);
        ConfidentialLedger.RegistrationProof memory aliceProof = ConfidentialLedger.RegistrationProof({
            A: ConfidentialLedger.G1Point({
                x: 5136569057728998864821096742374154201164091431178401175976611314497886384996,
                y: 2428854302252424305312248532193723208356413145561465756402318950353065516707
            }),
            z: 5740415415077101799673591281475485139428209021836784676637295105521256500527
        });
        ledger.registerAccount{value: aliceV}(aliceCommit, aliceProof);
        vm.stopPrank();

        vm.deal(bob, 10 ether);
        vm.startPrank(bob);
        uint256 bobV = 5;
        uint256 bobR = 456;
        ConfidentialLedger.G1Point memory bobCommit = ledger.buildCommitment(bobV, bobR);
        ConfidentialLedger.RegistrationProof memory bobProof = ConfidentialLedger.RegistrationProof({
            A: ConfidentialLedger.G1Point({
                x: 10748493291561824590430443926313305471328232386979114914642935691411658258018,
                y: 7299166563974178625266321178994838975949053246356435486097075263660445100230
            }),
            z: 3592587229999400369810703726385929904982100614603883068905409518128218158904
        });
        ledger.registerAccount{value: bobV}(bobCommit, bobProof);
        vm.stopPrank();

        // Submit transfer: Alice sends 2 to Bob
        vm.startPrank(alice);
        uint256 transferValue = 2;
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
        uint256 expectedAliceV = 8; // 10 - 2
        uint256 expectedAliceR = 116; // 123 - 7
        ConfidentialLedger.G1Point memory expectedAlice = ledger.buildCommitment(expectedAliceV, expectedAliceR);

        // Compute expected final commitments for Bob
        uint256 expectedBobV = 7; // 5 + 2
        uint256 expectedBobR = 463; // 456 + 7
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

        console.log("Solidity Challenge:");
        console.log(c);
    }
}
