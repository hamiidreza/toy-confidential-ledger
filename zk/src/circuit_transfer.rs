use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

#[derive(Clone)]
pub struct TransferConfig {
    b: Column<Advice>,
    v: Column<Advice>,
    b_prime: Column<Advice>,
    v_bits: [Column<Advice>; 64],
}

pub struct TransferCircuit {
    pub b: Value<Fr>, // sender balance
    pub v: Value<Fr>, // transfer value
    pub v_bits: [Value<Fr>; 64],
}

impl Circuit<Fr> for TransferCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            b: Value::unknown(),
            v: Value::unknown(),
            v_bits: std::array::from_fn(|_| Value::unknown()),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> TransferConfig {
        let b = meta.advice_column();
        let v = meta.advice_column();
        let b_prime = meta.advice_column();

        let v_bits: [Column<Advice>; 64] = std::array::from_fn(|_| meta.advice_column());

        meta.create_gate("b' = b - v", |meta| {
            let b = meta.query_advice(b, Rotation::cur());
            let v = meta.query_advice(v, Rotation::cur());
            let bp = meta.query_advice(b_prime, Rotation::cur());
            vec![b - v - bp]
        });

        for bit_col in &v_bits {
            meta.create_gate("bit booleanity", |meta| {
                let bit = meta.query_advice(*bit_col, Rotation::cur());
                vec![bit.clone() * (bit - Expression::Constant(Fr::one()))]
            });
        }

        meta.create_gate("v reconstruction", |meta| {
            let v_val = meta.query_advice(v, Rotation::cur());
            let mut sum = Expression::Constant(Fr::zero());
            for (i, bit_col) in v_bits.iter().enumerate() {
                let bit = meta.query_advice(*bit_col, Rotation::cur());
                sum = sum + bit * Expression::Constant(Fr::from(1u64 << i));
            }
            vec![v_val - sum]
        });

        TransferConfig {
            b,
            v,
            b_prime,
            v_bits,
        }
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

                let b_prime = self.b.zip(self.v).map(|(b, v)| b - v);
                region.assign_advice(|| "b'", config.b_prime, 0, || b_prime)?;

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "v bits",
            |mut region| {
                for i in 0..64 {
                    region.assign_advice(
                        || format!("v_bit_{}", i),
                        config.v_bits[i],
                        i,
                        || self.v_bits[i],
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl Default for TransferCircuit {
    fn default() -> Self {
        Self {
            b: Value::unknown(),
            v: Value::unknown(),
            v_bits: std::array::from_fn(|_| Value::unknown()),
        }
    }
}
