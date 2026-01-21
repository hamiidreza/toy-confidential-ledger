use crate::bulletproof::verify_range;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use merlin::Transcript;

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub struct Commitment {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

pub struct TransferInput {
    //pub transfer_id: u64,
    pub proof_bytes: Vec<u8>,
    pub sender_commitment: Commitment,
    pub transfer_commitment: Commitment,
}

pub struct ParsedProof {
    pub range_bits: usize,
    pub proof_v: Vec<u8>,
    pub proof_u: Vec<u8>,
    pub commitment_v: CompressedRistretto,
}

pub fn parse_proof_bytes(bytes: &[u8]) -> Option<(usize, Vec<u8>, Vec<u8>)> {
    let mut read = Cursor::new(bytes);

    let range_bits = read.read_u64::<LittleEndian>().ok()? as usize;

    let len_v = read.read_u32::<LittleEndian>().ok()? as uszie;
    let mut proof_v = vec![0u8; len_v];
    read.read_exact(&mut proof_v).ok()?;

    let len_u = read.read_u32::<LittleEndian>().ok()? as uszie;
    let mut proof_u = vec![0u8; len_u];
    read.read_exact(&mut proof_u).ok()?;

    Some((range_bits, proof_v, proof_u))
}

pub fn subtract_commitments(
    c_b: CompressedRistretto,
    c_v: CompressedRistretto,
) -> Option<CompressedRistretto> {
    let pb = c_b.decompress()?;
    let pv = c_v.decompress()?;
    let pu = pb - pv;
    Some(pu.compress())
}

pub fn verify_transfer(input: TransferInput) -> bool {
    let (proof_bytes, sender_com, transfer_com) = (
        input.proof_bytes,
        input.sender_commitment,
        input.transfer_commitment,
    );
    let (range_bits, proof_v, proof_u) = match parse_proof_bytes(&input.proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    // TODO
    true
}
