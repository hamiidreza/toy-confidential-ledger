// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialLedger} from "../ConfidentialLedger.sol";

contract CurveArithmeticTest is Test {
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

    function test_ecSub_inverse() public view {
        ConfidentialLedger.G1Point memory a = ledger.generatorMul(5);
        ConfidentialLedger.G1Point memory b = ledger.generatorMul(3);

        ConfidentialLedger.G1Point memory result = ledger.ecAdd(ledger.ecSub(a, b), b);

        assertEq(result.x, a.x);
        assertEq(result.y, a.y);
    }

    function test_ecAdd_identity() public view {
        ConfidentialLedger.G1Point memory a = ledger.generatorMul(7);
        ConfidentialLedger.G1Point memory zero = ConfidentialLedger.G1Point(0, 0);

        ConfidentialLedger.G1Point memory result = ledger.ecAdd(a, zero);

        assertEq(result.x, a.x);
        assertEq(result.y, a.y);
    }

    function test_ecSub_self() public view {
        ConfidentialLedger.G1Point memory a = ledger.generatorMul(9);

        ConfidentialLedger.G1Point memory result = ledger.ecSub(a, a);

        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }
}
