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

    modifier onlyTrustedVerifier() {
        require(msg.sender == trustedVerifier, "Only trusted verifier can call this function");
        _;
    }

    function approveTransfer(uint256 _transferId) public onlyTrustedVerifier {
        Transfer storage t = pendingTransfers[_transferId];
        require(!t.approved, "Transfer already approved");
        t.approved = true;
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

/// @notice Represents a confidential transfer request
struct Transfer {
    address from;
    address to;
    uint256 valueCommitmentX;
    uint256 valueCommitmentY;
    bytes proof;        // placeholder for ZK proof
    bool approved;      // set by trusted verifier
}

/// @notice Incremental transfer ID
uint256 public nextTransferId;

/// @notice Pending transfers awaiting verification
mapping(uint256 => Transfer) public pendingTransfers;

/// @notice Submit a confidential transfer for off-chain verification
function submitTransfer(address _to, uint256 _valueCommitmentX, uint256 _valueCommitmentY, bytes calldata _proof) external returns (uint256 transferId) {
    transferId = nextTransferId++;

    pendingTransfers[transferId] = Transfer({
        from: msg.sender,
        to: _to,
        valueCommitmentX: _valueCommitmentX,
        valueCommitmentY: _valueCommitmentY,
        proof: _proof,
        approved: false
    });
}
}