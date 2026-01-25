// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Toy Confidential Ledger
/// @notice Stores opaque balance commitments; all cryptography is verified off-chain
/// @dev This is a learning project. Do NOT use in production.
contract ConfidentialLedger {
    /// @notice Address of the trusted off-chain proof verifier
    address public trustedVerifier;

    /// @param _trustedVerifier Address allowed to approve transfers
    constructor(address _trustedVerifier) {
        require(_trustedVerifier != address(0), "verifier is zero address");
        trustedVerifier = _trustedVerifier;
    }

    /// @notice Maps user addresses to their commitments
    mapping(address => bytes32) public commitments;

    /// @notice Register a new account with an initial commitment
    /// @param _compressed The commitment
    function registerAccount(bytes32 _compressed) external {
        require(commitments[msg.sender] == 0, "Account already registered");
        require(_compressed != bytes32(0), "Invalid commitment");

        commitments[msg.sender] = _compressed;
    }

    /// @notice Represents a confidential transfer request
    struct Transfer {
        address from;
        address to;
        bytes32 valueCommitment;
        bytes proofBlob; // placeholder for ZK proof
    }

    /// @notice Incremental transfer ID
    uint256 public nextTransferId;

    /// @notice Pending transfers awaiting verification
    mapping(uint256 => Transfer) public pendingTransfers;

    /// @notice Submit a confidential transfer for off-chain verification
    function submitTransfer(address _to, bytes32 _valueCommitment, bytes calldata _proof)
        external
        returns (uint256 transferId)
    {
        require(_to != address(0), "Invalid recipient");
        require(commitments[msg.sender] != 0, "Sender not registered");

        transferId = nextTransferId++;

        pendingTransfers[transferId] =
            Transfer({from: msg.sender, to: _to, valueCommitment: _valueCommitment, proofBlob: _proof});
    }

    modifier onlyTrustedVerifier() {
        _onlyTrustedVerifier();
        _;
    }

    function _onlyTrustedVerifier() internal view {
        require(msg.sender == trustedVerifier, "Only trusted verifier can call this function");
    }

    /// @notice Approve and execute a confidential transfer atomically
    /// @dev All cryptographic verification happens off-chain by the trusted verifier
    function approveAndExecuteTransfer(uint256 _transferId, bytes32 newSenderCommitment, bytes32 newReceiverCommitment)
        external
        onlyTrustedVerifier
    {
        Transfer storage t = pendingTransfers[_transferId];
        require(t.from != address(0), "Invalid sender");
        require(t.to != address(0), "Invalid receiver");

        // Ensure accounts exist
        require(commitments[t.from] != bytes32(0), "Sender not registered");
        require(commitments[t.to] != bytes32(0), "Receiver not registered");

        // Apply commitment updates
        commitments[t.from] = newSenderCommitment;
        commitments[t.to] = newReceiverCommitment;

        emit TransferExecuted(_transferId, t.from, t.to);

        // Cleanup
        delete pendingTransfers[_transferId];
    }

    /// @notice Emitted when a transfer is executed
    event TransferExecuted(uint256 indexed transferId, address indexed from, address indexed to);
}
