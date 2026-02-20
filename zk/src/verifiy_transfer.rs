use crate::helper::*;
use crate::pedersen::*;
use crate::range_proof::{RangeProof, verify_less_than_or_equal};
use ark_bn254::G1Projective as C;
use merlin::Transcript;

fn verify_transfer(
    transfer_id: u64, // TODO: do we need this?
    gens: &Vec<(C, C)>,
    key: &CommitmentKey,
    n: u8,
    cm_v: C,
    cm_from: C,
    proof: RangeProof,
) -> bool {
    let mut transcript = Transcript::new(b"ConfidentialLedger");
    transcript_append_point(&mut transcript, b"value_commitment", &cm_v);

    if !verify_less_than_or_equal(&mut transcript, n, &cm_v, &cm_from, &proof, &gens, &key) {
        return false;
    }

    true
}
