use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
};

use halo2curves::bn256::Fr;

use crate::circuit_transfer::TransferCircuit;

pub fn prove_transfer(b: u64, v: u64) -> bool {
    let circuit = TransferCircuit {
        b: Value::known(Fr::from(b)),
        v: Value::known(Fr::from(v)),
    };

    let k = 4; // circuit size
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.verify().is_ok()
}
