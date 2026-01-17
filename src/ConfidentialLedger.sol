// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EllipticCurve} from "lib/elliptic-curve-solidity/contracts/EllipticCurve.sol";

uint256 constant AA = 0;
uint256 constant BB = 7;
uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

// Generator G
uint256 constant GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
uint256 constant GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424;

// Generator H = [s] · G (This is insecure as s should be unknown; but for learning purposes this is okay)
uint256 constant HX = 89565891926547004231252920425935692360644145829622209833684329913297188986597;
uint256 constant HY = 12158399299693830322967808612713398636155367887041628176798871954788371653930;

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
        uint256 x; // Pedersen commitment X coordinate
        uint256 y; // Pedersen commitment Y coordinate
    }

    function pedersenCommitment(uint256 _value, uint256 _rand) internal pure returns (Commitment memory) {
        (uint256 _valueX, uint256 _valueY) = EllipticCurve.ecMul(_value, GX, GY, AA, PP);
        (uint256 _randX, uint256 _randY) = EllipticCurve.ecMul(_rand, HX, HY, AA, PP);
        (uint256 _commitmentX, uint256 _commitmentY) = EllipticCurve.ecAdd(_valueX, _valueY, _randX, _randY, AA, PP);
        return Commitment({x: _commitmentX, y: _commitmentY});
    }

    function addCommitments(Commitment memory _c1, Commitment memory _c2) internal pure returns (Commitment memory) {
        (uint256 cX, uint256 cY) = EllipticCurve.ecAdd(_c1.x, _c1.y, _c2.x, _c2.y, AA, PP);
        return Commitment({x: cX, y: cY});
    }

    function subCommitments(Commitment memory _c1, Commitment memory _c2) internal pure returns (Commitment memory) {
        (uint256 cX, uint256 cY) = EllipticCurve.ecSub(_c1.x, _c1.y, _c2.x, _c2.y, AA, PP);
        return Commitment({x: cX, y: cY});
    }

    /// @notice Maps user addresses to their commitments
    mapping(address => Commitment) public commitments;

    /// @notice Register a new account with an initial commitment
    /// @param _x X coordinate of the commitment
    /// @param _y Y coordinate of the commitment
    function registerAccount(uint256 _x, uint256 _y) external {
        require(commitments[msg.sender].x == 0 && commitments[msg.sender].y == 0, "Account already registered");

        commitments[msg.sender] = Commitment({x: _x, y: _y});
    }

    /// @notice Represents a confidential transfer request
    struct Transfer {
        address from;
        address to;
        uint256 valueCommitmentX;
        uint256 valueCommitmentY;
        bytes proof; // placeholder for ZK proof
        bool approved; // set by trusted verifier
    }

    /// @notice Incremental transfer ID
    uint256 public nextTransferId;

    /// @notice Pending transfers awaiting verification
    mapping(uint256 => Transfer) public pendingTransfers;

    /// @notice Submit a confidential transfer for off-chain verification
    function submitTransfer(address _to, uint256 _valueCommitmentX, uint256 _valueCommitmentY, bytes calldata _proof)
        external
        returns (uint256 transferId)
    {
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

    modifier onlyTrustedVerifier() {
        _onlyTrustedVerifier();
        _;
    }

    function _onlyTrustedVerifier() internal view {
        require(msg.sender == trustedVerifier, "Only trusted verifier can call this function");
    }

    function approveTransfer(uint256 _transferId) public onlyTrustedVerifier {
        Transfer storage t = pendingTransfers[_transferId];
        require(!t.approved, "Transfer already approved");
        t.approved = true;
    }

    /// @notice Execute a verified transfer by updating commitments
    /// @param transferId The ID of the approved transfer
    function executeTransfer(uint256 transferId) external {
        Transfer storage t = pendingTransfers[transferId];
        require(t.approved, "Transfer not approved yet");
        require(t.from != address(0), "Invalid sender address");
        require(t.to != address(0), "Invalid receiver address");

        Commitment storage senderCommitment = commitments[t.from];
        Commitment storage receiverCommitment = commitments[t.to];

        require(senderCommitment.x != 0 && senderCommitment.y != 0, "Sender not registered");
        require(receiverCommitment.x != 0 && receiverCommitment.y != 0, "Receiver not registered");

        require(
            EllipticCurve.isOnCurve(senderCommitment.x, senderCommitment.y, AA, BB, PP),
            "Sender commitment not on curve!"
        );

        require(
            EllipticCurve.isOnCurve(receiverCommitment.x, receiverCommitment.y, AA, BB, PP),
            "Receiver commitment not on curve!"
        );

        // Build the transfer value commitment
        Commitment memory valueCommitment = Commitment({x: t.valueCommitmentX, y: t.valueCommitmentY});
        require(
            EllipticCurve.isOnCurve(valueCommitment.x, valueCommitment.y, AA, BB, PP), "value commitment not on curve!"
        );

        // Homomorphic updates
        (senderCommitment.x, senderCommitment.y) =
            EllipticCurve.ecSub(senderCommitment.x, senderCommitment.y, valueCommitment.x, valueCommitment.y, AA, PP);
        (receiverCommitment.x, receiverCommitment.y) = EllipticCurve.ecAdd(
            receiverCommitment.x, receiverCommitment.y, valueCommitment.x, valueCommitment.y, AA, PP
        );

        delete pendingTransfers[transferId];
        emit TransferExecuted(transferId, t.from, t.to);
    }

    /// @notice Emitted when a transfer is executed
    event TransferExecuted(uint256 indexed transferId, address indexed from, address indexed to);
}
