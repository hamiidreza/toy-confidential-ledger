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
}
