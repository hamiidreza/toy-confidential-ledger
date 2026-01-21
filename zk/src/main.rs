mod bulletproof;
mod verifier;

use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

fn main() {
    let value: u64 = 123;
    let blinding = Scalar::random(&mut thread_rng());
    let bits = 64;

    let (proof, commitment) = bulletproof::prove_range(value, blinding, bits);

    let ok = bulletproof::verify_range(&proof.to_bytes(), commitment, bits);

    println!("Range proof valid: {}", ok);
}
