// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EllipticCurve} from "lib/elliptic-curve-solidity/contracts/EllipticCurve.sol";

contract EcTest {
    // secp256k1 parameters
    uint256 constant AA = 0;
    uint256 constant PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Generator G
    uint256 constant GX =
        55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint256 constant GY =
        32670510020758816978083085130507043184471273380659243275938904335757337482424;

    function mulG(uint256 k) external pure returns (uint256 x, uint256 y) {
        return EllipticCurve.ecMul(k, GX, GY, AA, PP);
    }

    function addG(
        uint256 k1,
        uint256 k2
    ) external pure returns (uint256 x, uint256 y) {
        (uint256 x1, uint256 y1) = EllipticCurve.ecMul(k1, GX, GY, AA, PP);
        (uint256 x2, uint256 y2) = EllipticCurve.ecMul(k2, GX, GY, AA, PP);
        return EllipticCurve.ecAdd(x1, y1, x2, y2, AA, PP);
    }
}
