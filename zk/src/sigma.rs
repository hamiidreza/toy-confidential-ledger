use std::ops::Mul;

use ark_bn254::{Fr, G1Projective as C};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use rand::thread_rng;

use crate::{
    helper::{Address, compute_sigma_challenge},
    pedersen::CommitmentKey,
};

/// Sigma protocol for registration of a new account
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct RegistrationProof {
    pub A: C,
    pub z: Fr,
}

pub fn prove_registration(
    r: Fr,
    v: u128,
    commitment: C,
    ck: &CommitmentKey,
    contract_address: Address,
    sender: Address,
) -> RegistrationProof {
    let mut rng = thread_rng();

    // Compute vG
    let v_fr = Fr::from(v);
    let vG = ck.g.mul(v_fr);

    // Compute C' = C - vG
    let Cprime = commitment - vG;

    // Sample `a` for the first message
    let a = Fr::rand(&mut rng);

    // Compute A = aH
    let A = ck.h.mul(a);

    let e: Fr = compute_sigma_challenge(
        ck,
        contract_address,
        sender,
        v,
        commitment.into_affine(),
        A.into_affine(),
    );

    // Response
    let z = a + e * r;
    RegistrationProof { A, z }
}
