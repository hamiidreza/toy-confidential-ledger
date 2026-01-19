// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialLedger} from "../src/ConfidentialLedger.sol";
import {EllipticCurve} from "elliptic-curve-solidity/contracts/EllipticCurve.sol";

contract ConfidentialLedgerTest is Test {
    ConfidentialLedger ledger;

    // Toy secp256k1 parameters (should match the contract)
    uint256 constant AA = 0;
    uint256 constant BB = 7;
    uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    uint256 constant GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint256 constant GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424;

    uint256 constant HX = 89565891926547004231252920425935692360644145829622209833684329913297188986597;
    uint256 constant HY = 12158399299693830322967808612713398636155367887041628176798871954788371653930;

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

    function pedersenCommitOffchain(uint256 _value, uint256 _rand)
        internal
        pure
        returns (ConfidentialLedger.Commitment memory)
    {
        (uint256 _valueX, uint256 _valueY) = EllipticCurve.ecMul(_value, GX, GY, AA, PP);
        (uint256 _randX, uint256 _randY) = EllipticCurve.ecMul(_rand, HX, HY, AA, PP);
        (uint256 _commitmentX, uint256 _commitmentY) = EllipticCurve.ecAdd(_valueX, _valueY, _randX, _randY, AA, PP);
        return ConfidentialLedger.Commitment({x: _commitmentX, y: _commitmentY});
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
    }
}
