use crate::bulletproof::verify_range;
use curve25519_dalek::ristretto::CompressedRistretto;

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub fn parse_proof_bytes(bytes: &[u8]) -> Option<(usize, Vec<u8>, Vec<u8>)> {
    let mut read = Cursor::new(bytes);

    let range_bits = read.read_u64::<LittleEndian>().ok()? as usize;

    let len_v = read.read_u32::<LittleEndian>().ok()? as usize;
    let mut proof_v = vec![0u8; len_v];
    read.read_exact(&mut proof_v).ok()?;

    let len_u = read.read_u32::<LittleEndian>().ok()? as usize;
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

pub fn verify_transfer(
    proof_bytes: &[u8],
    sender_com: CompressedRistretto,
    transfer_com: CompressedRistretto,
) -> bool {
    let (range_bits, proof_v, proof_u) = match parse_proof_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };

    // 3. Verify range proof for transfer value
    if !verify_range(&proof_v, transfer_com, range_bits) {
        return false;
    }

    // 4. Compute C_u = C_b − C_v
    let remaining_commitment = match subtract_commitments(sender_com, transfer_com) {
        Some(c) => c,
        None => return false,
    };

    // 5. Verify range proof for remaining balance
    if !verify_range(&proof_u, remaining_commitment, range_bits) {
        return false;
    }

    true
}
