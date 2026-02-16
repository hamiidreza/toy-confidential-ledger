// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Toy Confidential Ledger  (BN254 + off-chain Bulletproof range proofs)
/// @notice Ledger enforces commitment algebra; ZK proofs verified off-chain
/// @dev Learning project — NOT production safe
contract ConfidentialLedger {
    /// @notice BN254 G1 point
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// @notice Represents a confidential transfer request
    struct Transfer {
        address from;
        address to;
        G1Point valueCommitment; // C_v
        bytes proofBlob; // Bulletproof proof (opaque to contract)
    }

    /// @notice Address of the trusted off-chain proof verifier
    address public trustedVerifier;

    /// @param _trustedVerifier Address allowed to approve transfers
    constructor(address _trustedVerifier) {
        require(_trustedVerifier != address(0), "verifier is zero address");
        trustedVerifier = _trustedVerifier;
    }

    modifier onlyTrustedVerifier() {
        _onlyTrustedVerifier();
        _;
    }

    function _onlyTrustedVerifier() internal view {
        require(msg.sender == trustedVerifier, "Only trusted verifier can call this function");
    }

    /// @notice Maps user addresses to their balance commitments
    mapping(address => G1Point) public commitments;

    /// @notice Incremental transfer ID
    uint256 public nextTransferId;

    /// @notice Pending transfers awaiting verification
    mapping(uint256 => Transfer) public pendingTransfers;

    //------------------------EC OPERATIONS for BN254----------------------------

    uint256 constant FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev G1 addition via precompile 0x06
    function ecAdd(G1Point memory a, G1Point memory b) internal view returns (G1Point memory r) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        bool success;

        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }

        require(success, "ecAdd failed");
    }

    /// @dev G1 subtraction: a - b = a + (-b)
    function ecSub(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {
        // Negate y-coordinate mod p
        uint256 negY = (b.y == 0) ? 0 : FIELD_MODULUS - (b.y % FIELD_MODULUS);

        return ecAdd(a, G1Point(b.x, negY));
    }

    /// @dev Basic curve membership check
    function requireValidPoint(G1Point calldata p) internal pure {
        require(p.x != 0 || p.y != 0, "infinity point");
    }

    //------------------------ACCOUNT REGISTRATION----------------------------

    /// @notice Register a new account with an initial balance commitment
    /// @dev The commitment is assumed to encode a deposit value chosen by the user.
    ///      Correctness of the commitment (e.g., that it commits to the intended
    ///      deposit amount) is verified offchain by an
    ///      external component and is out of scope for this contract.
    /// @param _commitment The commitment
    function registerAccount(G1Point calldata _commitment) external {
        require(commitments[msg.sender].x == 0, "Account already registered");
        requireValidPoint(_commitment);

        commitments[msg.sender] = _commitment;
    }

    //------------------------TRANSFER SUBMISSION----------------------------

    /// @notice Submit a confidential transfer for off-chain verification
    function submitTransfer(address _to, G1Point calldata _valueCommitment, bytes calldata _proof)
        external
        returns (uint256 transferId)
    {
        require(_to != address(0), "Invalid recipient");
        require(commitments[msg.sender].x != 0, "Sender not registered");
        requireValidPoint(_valueCommitment);

        transferId = nextTransferId++;

        pendingTransfers[transferId] =
            Transfer({from: msg.sender, to: _to, valueCommitment: _valueCommitment, proofBlob: _proof});
    }

    //------------------------VERIFIER-APPROVED EXECUTION----------------------------

    /// @notice Approve and execute a confidential transfer
    /// @dev All proof verification is performed off-chain by the trusted verifier.
    ///      A call to this function implies that the verifier has already validated
    ///      the corresponding proofs.
    function approveAndExecuteTransfer(uint256 _transferId) external onlyTrustedVerifier {
        Transfer storage t = pendingTransfers[_transferId];
        require(t.from != address(0), "Invalid sender");
        require(t.to != address(0), "Invalid receiver");

        // Ensure accounts exist
        require(commitments[t.from].x != 0, "Sender not registered");
        require(commitments[t.to].x != 0, "Receiver not registered");

        G1Point memory C_from = commitments[t.from];
        G1Point memory C_to = commitments[t.to];

        commitments[t.from] = ecSub(C_from, t.valueCommitment); // C_from' = C_from - C_v
        commitments[t.to] = ecAdd(C_to, t.valueCommitment); // C_to' = C_to + C_v

        emit TransferApproved(_transferId, t.from, t.to);

        // Cleanup
        delete pendingTransfers[_transferId];
    }

    /// @notice Emitted when a transfer is approved
    event TransferApproved(uint256 indexed transferId, address indexed from, address indexed to);
}
