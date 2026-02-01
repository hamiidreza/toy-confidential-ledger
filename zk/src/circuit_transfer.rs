use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

#[derive(Clone)]
pub struct TransferConfig {
    q: Selector,
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

impl TransferCircuit {
    pub fn new(b: u64, v: u64) -> Self {
        Self {
            b: Value::known(Fr::from(b)),
            v: Value::known(Fr::from(v)),
            v_bits: std::array::from_fn(|i| Value::known(Fr::from((v >> i) & 1))),
        }
    }
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
        let q = meta.selector();
        let b = meta.advice_column();
        let v = meta.advice_column();
        let b_prime = meta.advice_column();

        let v_bits: [Column<Advice>; 64] = std::array::from_fn(|_| meta.advice_column());

        meta.enable_equality(b);
        meta.enable_equality(v);
        meta.enable_equality(b_prime);
        for col in &v_bits {
            meta.enable_equality(*col);
        }

        meta.create_gate("b' = b - v", |meta| {
            let q = meta.query_selector(q);
            let b = meta.query_advice(b, Rotation::cur());
            let v = meta.query_advice(v, Rotation::cur());
            let bp = meta.query_advice(b_prime, Rotation::cur());
            vec![q * (b - v - bp)]
        });

        for bit_col in &v_bits {
            meta.create_gate("bit booleanity", |meta| {
                let q = meta.query_selector(q);
                let bit = meta.query_advice(*bit_col, Rotation::cur());
                vec![q * bit.clone() * (bit - Expression::Constant(Fr::one()))]
            });
        }

        meta.create_gate("v reconstruction", |meta| {
            let q = meta.query_selector(q);
            let v_val = meta.query_advice(v, Rotation::cur());
            let mut sum = Expression::Constant(Fr::zero());
            for (i, bit_col) in v_bits.iter().enumerate() {
                let bit = meta.query_advice(*bit_col, Rotation::cur());
                sum = sum + bit * Expression::Constant(Fr::from(1u64 << i));
            }
            vec![q * (v_val - sum)]
        });

        TransferConfig {
            q,
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
                let offset = 0;

                //let b = Fr::from(self.b);
                //let v = Fr::from(self.v);

                config.q.enable(&mut region, offset)?;

                region.assign_advice(|| "b", config.b, offset, || self.b)?;

                region.assign_advice(|| "v", config.v, offset, || self.v)?;

                for i in 0..64 {
                    region.assign_advice(
                        || format!("v_bit_{}", i),
                        config.v_bits[i],
                        0,
                        || self.v_bits[i],
                    )?;
                }

                let b_prime = self.b.zip(self.v).map(|(b, v)| b - v);
                region.assign_advice(|| "b'", config.b_prime, offset, || b_prime)?;

                Ok(())
            },
        )
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
