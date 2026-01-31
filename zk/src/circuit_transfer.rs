use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

#[derive(Clone)]
pub struct TransferConfig {
    b: Column<Advice>,
    v: Column<Advice>,
    b_prime: Column<Advice>,
}

#[derive(Default)]
pub struct TransferCircuit {
    pub b: Value<Fr>, // sender balance
    pub v: Value<Fr>, // transfer value
}

impl Circuit<Fr> for TransferCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            b: Value::unknown(),
            v: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> TransferConfig {
        let b = meta.advice_column();
        let v = meta.advice_column();
        let b_prime = meta.advice_column();

        meta.create_gate("b' = b - v", |meta| {
            let b = meta.query_advice(b, Rotation::cur());
            let v = meta.query_advice(v, Rotation::cur());
            let bp = meta.query_advice(b_prime, Rotation::cur());
            vec![b - v - bp]
        });

        TransferConfig { b, v, b_prime }
    }

    fn synthesize(
        &self,
        config: TransferConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "transfer",
            |mut region| {
                region.assign_advice(|| "b", config.b, 0, || self.b)?;
                region.assign_advice(|| "v", config.v, 0, || self.v)?;

                let b_prime =
                    self.b.zip(self.v).map(|(b, v)| b - v);

                region.assign_advice(|| "b'", config.b_prime, 0, || b_prime)?;
                Ok(())
            },
        )
    }
}
