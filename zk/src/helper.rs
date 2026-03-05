use ark_bn254::Fr;
use ark_bn254::G1Projective as C;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;
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
