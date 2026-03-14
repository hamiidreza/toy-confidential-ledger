use ark_ec::CurveGroup;
use zk::helper::*;
use zk::pedersen::CommitmentKey;


#[allow(non_snake_case)]
fn main() {
    let ck = CommitmentKey::fixed();

    let contract = Address([1u8; 20]);
    let sender   = Address([2u8; 20]);

    let value = 42u64;

    let C = ck.g.into_affine();
    let A = ck.h.into_affine();

    let challenge = compute_sigma_challenge(
        &ck,
        contract,
        sender,
        value,
        C,
        A,
    );

    println!("challenge = {}", challenge);
}
