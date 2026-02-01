use halo2_proofs::{circuit::Value, dev::MockProver};
use halo2curves::bn256::Fr;
use zk::circuit_transfer::TransferCircuit;

const K: u32 = 10;

#[test]
fn test_transfer_circuit_small_values() {
    // Example values: sender balance = 100, transfer = 42
    let b_val: u64 = 100;
    let v_val: u64 = 42;

    let circuit = TransferCircuit {
        b: Value::known(Fr::from(b_val)),
        v: Value::known(Fr::from(v_val)),
        v_bits: {
            let mut bits = [Value::unknown(); 64];
            for i in 0..64 {
                bits[i] = Value::known(Fr::from((v_val >> i) & 1));
            }
            bits
        },
    };

    // Run MockProver
    let prover = MockProver::run(K, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_transfer_circuit_zero_transfer() {
    // sender balance = 50, transfer = 0
    let b_val: u64 = 50;
    let v_val: u64 = 0;

    let circuit = TransferCircuit {
        b: Value::known(Fr::from(b_val)),
        v: Value::known(Fr::from(v_val)),
        v_bits: {
            let mut bits = [Value::unknown(); 64];
            for i in 0..64 {
                bits[i] = Value::known(Fr::from((v_val >> i) & 1));
            }
            bits
        },
    };

    let prover = MockProver::run(K, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
#[should_panic]
fn test_transfer_circuit_invalid() {
    // sender balance = 10, transfer = 20 → invalid because v > b
    let b_val: u64 = 10;
    let v_val: u64 = 20;

    let circuit = TransferCircuit {
        b: Value::known(Fr::from(b_val)),
        v: Value::known(Fr::from(v_val)),
        v_bits: {
            let mut bits = [Value::unknown(); 64];
            for i in 0..64 {
                bits[i] = Value::known(Fr::from((v_val >> i) & 1));
            }
            bits
        },
    };

    let prover = MockProver::run(K, &circuit, vec![]).unwrap();

    // This should fail verification
    assert!(prover.verify().is_err());
}
