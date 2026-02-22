use crate::helper::*;
use crate::pedersen::*;
use crate::range_proof::{RangeProof, prove_less_than_or_equal};
use ark_bn254::{Fr, G1Projective as C};
use ethers::types::Address;
use merlin::Transcript;
use rand::thread_rng;

pub fn create_transfer_proof(
    from: Address,
    to: Address,
    v_transfer: u64,
    r_transfer: Fr,
    v_balance: u64,
    r_balance: Fr,
    gens: &Vec<(C, C)>,
    key: &CommitmentKey,
    n: u8,
) -> (C, RangeProof) {
    assert!(v_transfer <= v_balance, "Transfer exceeds balance");

    // Construct C_v
    let cm_v = C::from(key.g) * Fr::from(v_transfer) + C::from(key.h) * r_transfer;

    let mut transcript = Transcript::new(b"ConfidentialLedger");
    transcript_append_u8(&mut transcript, b"from", from.as_bytes());
    transcript_append_u8(&mut transcript, b"to", to.as_bytes());
    transcript_append_point(&mut transcript, b"value_commitment", &cm_v);

    // Generate proof
    let mut rng = thread_rng();
    let proof = prove_less_than_or_equal(
        &mut transcript,
        &mut rng,
        n,
        v_transfer,
        v_balance,
        gens,
        key,
        &r_transfer,
        &r_balance,
    )
    .expect("Failed to generate the range proof");

    (cm_v, proof)
}
