use crate::pedersen::*;
use ark_bn254::G1Projective as C;
use ark_bn254::{Fr, G1Affine};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;
use sha3::{Digest, Keccak256};
use std::ops::MulAssign;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

pub fn transcript_append_point(transcript: &mut Transcript, label: &'static [u8], p: &C) {
    let mut buf = Vec::new();
    p.into_affine().serialize_compressed(&mut buf).unwrap();
    transcript.append_message(label, &buf);
}

pub fn transcript_append_element(transcript: &mut Transcript, label: &'static [u8], e: &Fr) {
    let mut buf = Vec::new();
    e.serialize_compressed(&mut buf).unwrap();
    transcript.append_message(label, &buf);
}

pub fn transcript_append_points(transcript: &mut Transcript, label: &'static [u8], points: &[C]) {
    for (_, p) in points.iter().enumerate() {
        transcript_append_point(transcript, &label, p);
    }
}

pub fn transcript_append_u8(transcript: &mut Transcript, label: &'static [u8], e: &[u8]) {
    transcript.append_message(label, e);
}

/// This function is copied from Concordium Rust library (https://github.com/concordium);
/// This function takes one argument n and returns the
/// vector (z^j, z^{j+1}, ..., z^{j+n-1}) in F^n for any field F
/// The arguments are
/// - z - the field element z
/// - first_power - the first power j
/// - n - the integer n.
pub fn z_vec(z: Fr, first_power: u64, n: usize) -> Vec<Fr> {
    let mut z_n = Vec::with_capacity(n);
    let exp: [u64; 1] = [first_power];
    let mut z_i = z.pow(exp);
    for _ in 0..n {
        z_n.push(z_i);
        z_i.mul_assign(&z);
    }
    z_n
}

/// Encodes a `u128` value as a 32-byte big-endian integer.
///
/// Solidity represents integers as 256-bit values (`uint256`), so
/// even small integers must be padded to 32 bytes when constructing
/// the Fiat–Shamir transcript.
pub fn u128_to_bytes32(x: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&x.to_be_bytes());
    out
}

/// Converts a field element into a fixed-width 32-byte big-endian encoding.
///
/// Arkworks' `to_bytes_be()` returns a variable-length representation.
/// However, the Solidity verifier expects integers to be encoded as
/// 32-byte values (equivalent to `uint256`).
///
/// This function left-pads the field element to 32 bytes so that the
/// encoding matches Solidity's representation exactly.
pub fn field_to_bytes32<F: PrimeField>(x: &F) -> [u8; 32] {
    let mut out = [0u8; 32];

    let bytes = x.into_bigint().to_bytes_be();

    // left-pad to 32 bytes
    out[32 - bytes.len()..].copy_from_slice(&bytes);

    out
}

/// Manual Keccak-based Fiat–Shamir implementation:
/// - Used for proofs that are verified by a Solidity smart contract.
/// - Solidity must recompute the challenge deterministically.
/// Therefore the transcript must be explicitly defined and encoded in a way that
/// both Rust and Solidity can reproduce exactly.
///
/// Transcript structure:
///
/// ```text
/// domain ||
/// contract_address ||
/// sender_address ||
/// Gx || Gy ||
/// Hx || Hy ||
/// value ||
/// Cx || Cy ||
/// Ax || Ay
/// ```
///
/// where all field elements and integers are encoded as 32-byte big-endian
/// values and addresses are encoded as 20 bytes.
///
/// The resulting hash is reduced modulo the BN254 scalar field `Fr`.
///
/// This explicit Fiat–Shamir implementation is used only for proofs that
/// are verified on-chain. Off-chain proofs in this project use
/// `merlin::Transcript` instead.
#[allow(non_snake_case)]
pub fn compute_sigma_challenge(
    ck: &CommitmentKey,
    contract: Address,
    sender: Address,
    value: Fr,
    C: G1Affine,
    A: G1Affine,
) -> Fr {
    let g = ck.g.into_affine();
    let h = ck.h.into_affine();

    let mut hasher = Keccak256::new();

    hasher.update(b"ConfidentialLedger:Register");
    hasher.update(contract.as_bytes());
    hasher.update(sender.as_bytes());

    hasher.update(field_to_bytes32(&g.x));
    hasher.update(field_to_bytes32(&g.y));
    hasher.update(field_to_bytes32(&h.x));
    hasher.update(field_to_bytes32(&h.y));

    hasher.update(field_to_bytes32(&value));

    hasher.update(field_to_bytes32(&C.x));
    hasher.update(field_to_bytes32(&C.y));
    hasher.update(field_to_bytes32(&A.x));
    hasher.update(field_to_bytes32(&A.y));

    let digest = hasher.finalize();

    Fr::from_be_bytes_mod_order(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(non_snake_case)]
    #[test]
    fn test_compute_sigma_challenge() {
        let ck = CommitmentKey::fixed();

        let contract = Address([0x11; 20]);
        let sender = Address([0x22; 20]);

        let value = Fr::from(42u64);

        let C = ck.g.into_affine();
        let A = ck.h.into_affine();

        let challenge = compute_sigma_challenge(&ck, contract, sender, value, C, A);

        let challenge_bytes = challenge.into_bigint().to_bytes_be();
        let mut padded = [0u8; 32];
        padded[32 - challenge_bytes.len()..].copy_from_slice(&challenge_bytes);

        print!("Rust Challenge: 0x");
        for b in padded.iter() {
            print!("{:02x}", b);
        }
        println!();
    }
}
