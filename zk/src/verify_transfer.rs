use halo2_proofs::{
    plonk::{SingleVerifier, keygen_vk, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};

use halo2curves::bn256::{G1Affine, Fr};

use crate::circuit_transfer::TransferCircuit;
use crate::types::ProofBundle;

pub fn verify_transfer(bundle: ProofBundle) -> bool {
    let k = 7;
    let params: Params<_> = Params::<G1Affine>::new(k);

    // Empty circuit (no witnesses)
    let circuit = TransferCircuit::default();

    let vk = keygen_vk(&params, &circuit).expect("vk");


    let mut transcript =
        Blake2bRead::<_, _, Challenge255<_>>::init(&bundle.proof[..]);

    let public_inputs: &[&[&[Fr]]] = &[&[&bundle.public_inputs[..]]];
    

    let strategy = SingleVerifier::new(&params);

    verify_proof(
        &params,
        &vk,
        strategy,
        &public_inputs,
        &mut transcript
    )
    .is_ok()
}
