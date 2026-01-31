use halo2curves::bn256::Fr;

pub struct TransferWitness {
    pub sender_balance: Fr,
    pub transfer_value: Fr,
}

pub struct ProofBundle {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Fr>,
}