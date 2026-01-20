use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// Generate a Bulletproof range proof for `value \in [0, 2^bits)`
pub fn prove_range(
    value: u64,
    blinding: Scalar,
    bits: usize,
) -> (RangeProof, curve25519_dalek::ristretto::CompressedRistretto) {
    // Generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bits, 1);

    // Transcript
    let mut transcript = Transcript::new(b"ToyConfidentialLedgerRangeProof");

    // Prove
    let (proof, commitment) =
        RangeProof::prove_single(&bp_gens, &pc_gens, &mut transcript, value, &blinding, bits)
            .expect("range proof generation failed");

    (proof, commitment)
}

/// Verify a Bulletproof range proof for a given commitment
pub fn verify_range(proof_bytes: &[u8], commitment: CompressedRistretto, bits: usize) -> bool {
    // Recreate generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bits, 1);

    // Transcript must use the SAME label as the prover
    let mut transcript = Transcript::new(b"ToyConfidentialLedgerRangeProof");

    // Deserialize proof
    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify
    proof
        .verify_single(&bp_gens, &pc_gens, &mut transcript, &commitment, bits)
        .is_ok()
}
