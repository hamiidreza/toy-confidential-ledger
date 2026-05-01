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
    fn test_prove_registration_internal() {
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

    #[allow(non_snake_case)]
    #[test]
    fn test_prove_registration_solidity() {
        let ck = CommitmentKey::fixed();

        // The deployed ledger address
        let contract = Address([
            0x56, 0x15, 0xde, 0xb7, 0x98, 0xbb, 0x3e, 0x4d, 0xfa, 0x01, 0x39, 0xdf, 0xa1, 0xb3,
            0xd4, 0x33, 0xcc, 0x23, 0xb7, 0x2f,
        ]);

        // Alice's exact address from Foundry setUp()
        let sender = Address([
            0x70, 0x99, 0x79, 0x70, 0xC5, 0x18, 0x12, 0xdc, 0x3A, 0x01, 0x0C, 0x7d, 0x01, 0xb5,
            0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xC8,
        ]);

        let v = Fr::from(10u64);
        let r = Fr::from(123u64);

        let cm = ck.hide(&v, &r);
        let sigma_proof = prove_registration(r, v, cm, &ck, contract, sender);

        let cm_affine = cm.into_affine();
        let A_affine = sigma_proof.A.into_affine();

        println!("// Copy this directly into testRegisterAccountValid():");
        println!("uint256 v = {};", v);
        println!("ConfidentialLedger.G1Point memory cm = ConfidentialLedger.G1Point({{");
        println!("    x: {},", cm_affine.x);
        println!("    y: {}", cm_affine.y);
        println!("}});");
        println!(
            "ConfidentialLedger.RegistrationProof memory sigma_proof = ConfidentialLedger.RegistrationProof({{"
        );
        println!("    A: ConfidentialLedger.G1Point({{");
        println!("        x: {},", A_affine.x);
        println!("        y: {}", A_affine.y);
        println!("    }}),");
        println!("    z: {}", sigma_proof.z);
        println!("}});");
    }
}
