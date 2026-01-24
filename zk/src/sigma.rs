use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use hex_literal::hex;
use merlin::Transcript;
use rand::random;
use rand::rngs::OsRng;
use secp256k1::Scalar as SecpScalar;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub struct Generators {
    pub G_r: RistrettoPoint,
    pub H_r: RistrettoPoint,
    pub G_s: PublicKey,
    pub H_s: PublicKey,
}

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct CommitmentEqualityProof {
    // Only the Ristretto commitment is included; the other commitment should be
    // fetched from the contract.
    pub C_r: RistrettoPoint,

    // Ephemeral commitments
    pub A_r: RistrettoPoint,
    pub A_s: PublicKey,

    // Sigma-proof responses (i.e., last message elements)
    pub z_v: u64,
    pub z_r: u64,
    pub z_r_fresh: u64,
}

fn pubkey_from_xy(x: [u8; 32], y: [u8; 32]) -> PublicKey {
    let mut data = [0u8; 65];
    data[0] = 0x04; // uncompressed
    data[1..33].copy_from_slice(&x);
    data[33..65].copy_from_slice(&y);
    PublicKey::from_slice(&data).expect("invalid secp256k1 point")
}

fn hash_to_scalar(label: &[u8]) -> DalekScalar {
    let hash = Sha256::digest(label);
    DalekScalar::from_bytes_mod_order(hash.into())
}

#[allow(non_snake_case)]
pub fn generators() -> Generators {
    let G_r = RistrettoPoint::default();
    let H_r = hash_to_scalar(b"H_r") * G_r;

    let Gx = hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let Gy = hex!("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    let Hx = hex!("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
    let Hy = hex!("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A");

    let G_s = pubkey_from_xy(Gx, Gy);
    let H_s = pubkey_from_xy(Hx, Hy);

    Generators { G_r, H_r, G_s, H_s }
}

/// Convert a u64 into a secp256k1 scalar (mod curve order)
pub fn u64_to_secp_scalar(x: u64) -> SecpScalar {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&x.to_be_bytes());
    SecpScalar::from_be_bytes(bytes).expect("u64 < curve order")
}

/// Generate a Sigma proof for equality of a value `v` in two different
/// commitmetns, one over Ristretto255 curve and one over Secp256k1 curve.
#[allow(non_snake_case)]
pub fn prove_com_equality(v: u64 , r: u64 , gens: &Generators) -> CommitmentEqualityProof {
    let mut transcript = Transcript::new(b"Pedersen-equality");

    // Compute Ristretto commitment
    let r_fresh: u64 = random();
    let C_r = DalekScalar::from(v) * gens.G_r + DalekScalar::from(r_fresh) * gens.H_r;
    transcript.append_message(b"C_r", C_r.compress().as_bytes());

    // Compute Secp256k1 commitment
    let secp = Secp256k1::new();
    let C_s_1 = gens.G_s.mul_tweak(&secp, &u64_to_secp_scalar(v)).expect("scalar mul");
    let C_s_2 = gens.H_s.mul_tweak(&secp, &u64_to_secp_scalar(r)).expect("scalar mul");
    let C_s = C_s_1.combine(&C_s_2).expect("valid point addition");
    transcript.append_message(b"C_s", &C_s.serialize());

    // Generate random integers for masking; insecure, but ok for toy example! 
    let k_v: u64 = random();
    let k_r: u64 = random();
    let k_r_fresh: u64 = random();

    // Compute ephemeral commitments
    let A_r = DalekScalar::from(k_v) * gens.G_r + DalekScalar::from(k_r_fresh) * gens.H_r;
    transcript.append_message(b"A_r", A_r.compress().as_bytes());

    let A_s_1 = gens.G_s.mul_tweak(&secp, &u64_to_secp_scalar(k_v)).expect("scalar mul");
    let A_s_2 = gens.H_s.mul_tweak(&secp, &u64_to_secp_scalar(k_r)).expect("scalar mul");
    let A_s = A_s_1.combine(&A_s_2).expect("valid point addition");
    transcript.append_message(b"A_s", &A_s.serialize());

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"e", &mut buf);
    let e = DalekScalar::from_bytes_mod_order_wide(&buf);
    let e_u64 = u64::from_le_bytes(e.to_bytes()[0..8].try_into().unwrap());

    // The last message elements are revealed as integers. This is insecure; they must be
    // revealed as curve scalars.
    let z_v = k_v + e_u64 * v;
    let z_r = k_r + e_u64 * r;
    let z_r_fresh = k_r + e_u64 * r;

    CommitmentEqualityProof {
        C_r,
        A_r,
        A_s,
        z_v,
        z_r,
        z_r_fresh,
    }
}

/// Sigma protocol verifier
#[allow(non_snake_case)]
pub fn verifier_com_equality(
    proof: &CommitmentEqualityProof,
    C_s: PublicKey,
    gens: &Generators,
) -> bool {
    let secp = Secp256k1::new();

    // Recompute Fiat–Shamir challenge
    let mut transcript = Transcript::new(b"Pedersen-equality");
    transcript.append_message(b"C_r", proof.C_r.compress().as_bytes());
    transcript.append_message(b"C_s", &C_s.serialize());
    transcript.append_message(b"A_r", proof.A_r.compress().as_bytes());
    transcript.append_message(b"A_s", &proof.A_s.serialize());

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"e", &mut buf);
    let e = DalekScalar::from_bytes_mod_order_wide(&buf);
    let e_u64 = u64::from_le_bytes(e.to_bytes()[0..8].try_into().unwrap());

    todo!()
}
