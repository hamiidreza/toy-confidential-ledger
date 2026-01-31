use halo2curves::bn256::Fr;

pub fn verify_transfer(
    proof: &[u8],
    public_inputs: &[Fr],
) -> bool {
    todo!()
    // verify Plonk proof for transfer
}