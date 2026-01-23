use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Clone)]
pub struct CommitmentEqualityProof {
    pub A_r: RistrettoPoint,
    pub A_s: PublicKey,
    pub z_v: Scalar,
    pub z_r: Scalar,
}

// Generate a Sigma proof for equality of `value-blinding` in two different commitmetns, one over Ristretto255 curve and one over Secp256k1 curve.
pub fn prove_com_equality(value: u64, blinding: Scalar) -> CommitmentEqualityProof {
    todo!()
}

/// Sigma protocol verifier
pub fn verifier_com_equality(proof: CommitmentEqualityProof) -> bool {
    todo!()
}
