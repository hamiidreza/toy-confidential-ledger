mod bulletproof;
mod verifier;

use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

fn main() {
    let bits = 64;

    // Fake sender balance
    let sender_value = 100u64;
    let transfer_value = 40u64;

    let r_b = Scalar::random(&mut thread_rng());
    let r_v = Scalar::random(&mut thread_rng());

    let (_, c_b) = bulletproof::prove_range(sender_value, r_b, bits);
    let (proof_v, c_v) = bulletproof::prove_range(transfer_value, r_v, bits);

    // remaining balance
    let u = sender_value - transfer_value;
    let r_u = r_b - r_v;
    let (proof_u, _) = bulletproof::prove_range(u, r_u, bits);

    // build proof_bytes
    let mut proof_bytes = vec![];
    proof_bytes.extend_from_slice(&(bits as u64).to_le_bytes());
    proof_bytes.extend_from_slice(&(proof_v.to_bytes().len() as u32).to_le_bytes());
    proof_bytes.extend_from_slice(&proof_v.to_bytes());
    proof_bytes.extend_from_slice(&(proof_u.to_bytes().len() as u32).to_le_bytes());
    proof_bytes.extend_from_slice(&proof_u.to_bytes());

    let ok = verifier::verify_transfer(&proof_bytes, c_b, c_v);

    println!("Transfer valid: {}", ok);
}
