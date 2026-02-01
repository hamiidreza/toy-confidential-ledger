use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};

use halo2curves::bn256::{Fr, G1Affine};
use rand_core::OsRng;

use crate::circuit_transfer::TransferCircuit;
use crate::types::ProofBundle;

pub fn prove_transfer(b: u64, v: u64) -> ProofBundle {
    // Decompose v into bits
    let mut v_bits = [Value::unknown(); 64];
    for i in 0..64 {
        let bit = (v >> i) & 1;
        v_bits[i] = Value::known(Fr::from(bit));
    }

    // Create circuit
    let circuit = TransferCircuit {
        b: Value::known(Fr::from(b)),
        v: Value::known(Fr::from(v)),
        v_bits,
    };

    // Params (deterministic, no trusted setup)
    let k = 7;
    let params: Params<_> = Params::<G1Affine>::new(k);

    // Keys
    let vk = keygen_vk(&params, &circuit).expect("vk");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk");

    // Transcript
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    // Create proof
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[]], // no public inputs
        OsRng,
        &mut transcript,
    )
    .expect("proof generation");

    let proof = transcript.finalize();

    ProofBundle {
        proof,
        public_inputs: vec![],
    }
}
