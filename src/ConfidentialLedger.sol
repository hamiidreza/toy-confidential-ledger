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

    /// @notice Maps user addresses to their registration status
    mapping(address => bool) public registered;

    //-----------------------------STORAGE GETTERS-------------------------------

    function getCommitments(address user) external view returns (uint256, uint256) {
        G1Point memory commitment = commitments[user];
        return (commitment.x, commitment.y);
    }

    function getPendingTransfer(uint256 transferId)
        external
        view
        returns (address, address, uint256, uint256, bytes memory)
    {
        Transfer memory transfer = pendingTransfers[transferId];
        return (transfer.from, transfer.to, transfer.valueCommitment.x, transfer.valueCommitment.y, transfer.proofBlob);
    }

    //---------------------------- GENERATORS FOR BN254 --------------------------

    function generatorG() public pure returns (G1Point memory) {
        return G1Point({x: 1, y: 2});
    }

    function generatorH() public pure returns (G1Point memory) {
        return G1Point({
            x: 15874583062915680608726096264639934847252182205744433427769184792172832649573,
            y: 18094243890165305569146610927749331108413006235138910969355226634001094084669
        });
    }

    //------------------------EC OPERATIONS for BN254----------------------------

    uint256 internal constant BASE_FIELD_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 internal constant SCALAR_FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev G1 addition via precompile 0x06
    function ecAdd(G1Point memory a, G1Point memory b) public view returns (G1Point memory r) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        bool success;

        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }

        require(success, "ecAdd failed");
    }

    /// @dev G1 subtraction: a - b = a + (-b)
    function ecSub(G1Point memory a, G1Point memory b) public view returns (G1Point memory) {
        // Negate y-coordinate mod p
        uint256 negY = (b.y == 0) ? 0 : BASE_FIELD_MODULUS - (b.y % BASE_FIELD_MODULUS);

        return ecAdd(a, G1Point({x: b.x, y: negY}));
    }

    function ecMul(G1Point memory p, uint256 scalar) public view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = scalar;

        bool success;

        assembly {
            success := staticcall(
                gas(),
                7, // ECMUL precompile
                input,
                0x60, // 3 * 32 bytes
                r,
                0x40 // 2 * 32 bytes
            )
        }

        require(success, "ECMUL failed");
    }

    // Multiplies the curve generator G by a scalar s (i.e., computes s*G)
    function generatorMul(uint256 s) public view returns (G1Point memory) {
        return ecMul(generatorG(), s);
    }

    /// @dev Basic curve membership check
    function requireValidPoint(G1Point memory p) public pure {
        require(p.x < BASE_FIELD_MODULUS, "x out of field");
        require(p.y < BASE_FIELD_MODULUS, "y out of field");
        require(!(p.x == 0 && p.y == 0), "point at infinity");

        // y^2 mod p
        uint256 lhs = mulmod(p.y, p.y, BASE_FIELD_MODULUS);

        // x^3 + 3 mod p
        uint256 x2 = mulmod(p.x, p.x, BASE_FIELD_MODULUS);
        uint256 x3 = mulmod(x2, p.x, BASE_FIELD_MODULUS);
        uint256 rhs = addmod(x3, 3, BASE_FIELD_MODULUS);

        require(lhs == rhs, "point not on curve");
    }

    function computeChallenge(address _sender, uint256 _value, G1Point memory _commitment, G1Point memory _A)
        public
        view
        returns (uint256)
    {
        G1Point memory g = generatorG();
        G1Point memory h = generatorH();

        bytes memory data = bytes.concat(
            bytes("ConfidentialLedger:Register"),
            bytes20(address(this)),
            bytes20(_sender),
            bytes32(g.x),
            bytes32(g.y),
            bytes32(h.x),
            bytes32(h.y),
            bytes32(_value),
            bytes32(_commitment.x),
            bytes32(_commitment.y),
            bytes32(_A.x),
            bytes32(_A.y)
        );
        uint256 challenge = uint256(keccak256(data));
        return challenge % BASE_FIELD_MODULUS;
    }

    function buildCommitment(uint256 value, uint256 blinding) public view returns (ConfidentialLedger.G1Point memory) {
        G1Point memory vG = generatorMul(value);
        G1Point memory rH = ecMul(generatorH(), blinding);

        return ecAdd(vG, rH);
    }

    //------------------------ACCOUNT REGISTRATION----------------------------

    /// @notice Register a new account with an initial balance commitment
    /// @dev The commitment is assumed to encode a deposit value chosen by the user.
    ///      Correctness of the commitment (e.g., that it commits to the intended
    ///      deposit amount) is verified offchain by an
    ///      external component and is out of scope for this contract.
    /// @param _commitment The commitment
    function registerAccount(G1Point calldata _commitment) external {
        require(!registered[msg.sender], "Account already registered");
        requireValidPoint(_commitment);

        commitments[msg.sender] = _commitment;
        registered[msg.sender] = true;
    }

    //------------------------TRANSFER SUBMISSION----------------------------

    /// @notice Submit a confidential transfer for off-chain verification
    function submitTransfer(address _to, G1Point calldata _valueCommitment, bytes calldata _proof)
        external
        returns (uint256 transferId)
    {
        require(_to != address(0), "Invalid recipient");
        require(registered[msg.sender], "Sender not registered");
        require(registered[_to], "Receiver not registered");
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

        G1Point memory cmFrom = commitments[t.from];
        G1Point memory cmTo = commitments[t.to];

        commitments[t.from] = ecSub(cmFrom, t.valueCommitment); // cmFrom' = cmFrom - C_v
        commitments[t.to] = ecAdd(cmTo, t.valueCommitment); // cmTo' = cmTo + C_v

        emit TransferApproved(_transferId, t.from, t.to);

        // Cleanup
        delete pendingTransfers[_transferId];
    }

    /// @notice Emitted when a transfer is approved
    event TransferApproved(uint256 indexed transferId, address indexed from, address indexed to);
}
