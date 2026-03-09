///
use ark_bn254::{Fq, Fr, G1Affine, G1Projective as C};
use ark_ec::AffineRepr;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::MontFp;
use ark_ff::UniformRand;
use rand::prelude::ThreadRng;

/// Sigma protocol for registration of a new account
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct RegistrationProof {
    pub A: C,
    pub t: Fr,
}
