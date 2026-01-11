// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Toy Confidential Ledger
/// @notice Stores homomorphic balance commitments and a trusted verifier address
/// @dev This is a learning project. Do NOT use in production.
contract ConfidentialLedger {
    /// @notice Address of the trusted off-chain proof verifier
    address public trustedVerifier;

    /// @param _trustedVerifier Address allowed to approve transfers
    constructor(address _trustedVerifier) {
        require(_trustedVerifier != address(0), "verifier is zero address");
        trustedVerifier = _trustedVerifier;
    }

/// @notice Represents a balance commitment
struct Commitment {
    uint256 x;  // Pedersen commitment X coordinate
    uint256 y;  // Pedersen commitment Y coordinate
}

/// @notice Maps user addresses to their commitments
mapping(address => Commitment) public commitments;

/// @notice Register a new account with an initial commitment
/// @param _x X coordinate of the commitment
/// @param _y Y coordinate of the commitment
function registerAccount(uint256 _x, uint256 _y) external {
    require(commitments[msg.sender].x == 0 && commitments[msg.sender].y == 0, "Account already registered");

    commitments[msg.sender] = Commitment({
        x: _x,
        y: _y
    });
}

}