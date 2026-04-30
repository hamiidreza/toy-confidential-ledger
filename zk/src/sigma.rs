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

#[allow(non_snake_case)]
pub fn prove_registration(
    r: Fr,
    v: Fr,
    commitment: C,
    ck: &CommitmentKey,
    contract_address: Address,
    sender: Address,
) -> RegistrationProof {
    let mut rng = thread_rng();

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

    // Response z
    let z = a + e * r;

    RegistrationProof { A, z }
}

#[cfg(test)]
mod tests {
    use crate::helper::{Address, compute_sigma_challenge};
    use crate::pedersen::CommitmentKey;
    use ark_bn254::Fr;
    use ark_ec::CurveGroup;

    use crate::sigma::prove_registration;
    use std::ops::Mul;

    #[allow(non_snake_case)]
    #[test]
    fn test_prove_registration() {
        let ck = CommitmentKey::fixed();

        let v = Fr::from(10u64);
        let r = Fr::from(123u64);

        let commitment = ck.hide(&v, &r);

        let dummy_contract_address = Address([0x11; 20]);
        let dummy_sender_address = Address([0x22; 20]);

        let sigma_proof = prove_registration(
            r,
            v,
            commitment,
            &ck,
            dummy_contract_address,
            dummy_sender_address,
        );

        let A = sigma_proof.A;
        let z = sigma_proof.z;

        // Compute vG
        let vG = ck.g.mul(v);

        // Compute C' = C - vG
        let Cprime = commitment - vG;

        let e: Fr = compute_sigma_challenge(
            &ck,
            dummy_contract_address,
            dummy_sender_address,
            v,
            commitment.into_affine(),
            A.into_affine(),
        );

        let lhs = ck.h.mul(z);
        let rhs = A + Cprime.mul(e);
        assert_eq!(lhs, rhs, "Internal proof verification failed");
    }
}
