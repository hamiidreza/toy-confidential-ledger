use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
};

use halo2curves::bn256::Fr;

use crate::circuit_transfer::TransferCircuit;

pub fn prove_transfer(b: u64, v: u64) -> bool {
    // Decompose v into bits
    let mut v_bits = [Value::unknown(); 64];
    for i in 0..64 {
        let bit = (v >> i) & 1;
        v_bits[i] = Value::known(Fr::from(bit));
    }

    let circuit = TransferCircuit {
        b: Value::known(Fr::from(b)),
        v: Value::known(Fr::from(v)),
        v_bits,
    };

    let k = 7;
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.verify().is_ok()
}
