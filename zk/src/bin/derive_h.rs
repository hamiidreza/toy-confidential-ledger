use ark_bn254::{Fq, G1Affine};
use ark_ff::{Field, PrimeField};
use sha3::{Digest, Keccak256};

fn main() {
    let domain = b"ConfidentialLedger Pedersen H";

    let mut counter: u64 = 0;

    loop {
        let mut hasher = Keccak256::new();
        hasher.update(domain);
        hasher.update(counter.to_le_bytes());

        let hash = hasher.finalize();

        let x = Fq::from_le_bytes_mod_order(&hash);

        let rhs = x * x * x + Fq::from(3u64);

        if let Some(y) = rhs.sqrt() {
            let point = G1Affine::new(x, y);

            println!("Hx = {}", point.x);
            println!("Hy = {}", point.y);

            break;
        }

        counter += 1;
    }
}
