use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
    halo2curves::bn256::Fr,
};

#[derive(Default)]
pub struct TransferCircuit {
    // private witnesses
    pub b: Value<Fr>, // sender balance
    pub v: Value<Fr>, // transfer value
}

#[derive(Clone)]
struct Config {
    b: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    v: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    b_prime: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
}

impl Circuit<Fr> for TransferCircuit {
    type Config: Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            b: Value::unknown(),
            v: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Config {
        let b = meta.advice_column();
        let v = meta.advice_column();
        let b_prime = meta.advice_column();

        meta.create_gate("b' = b - v", |meta| {
            let b = meta.query_advice(b, halo2_proofs::plonk::Rotation::cur());
            let v = meta.query_advice(v, halo2_proofs::plonk::Rotation::cur());
            let bp = meta.query_advice(b_prime, halo2_proofs::plonk::Rotation::cur());

            vec![b - v - bp]
        });

        Config { b, v, b_prime }
    }

    
}