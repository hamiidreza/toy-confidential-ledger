/// Bulletproof implemnetation adapted from Concordium Rust library (https://github.com/concordium);
/// Modified to use Merlin transcript and Arkworks BN254 curves

use ark_bn254::Fr;
use ark_bn254::{G1Affine, G1Projective as C};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use rand::prelude::ThreadRng;

/// A commitment key is a pair of group elements that are used as a base to
/// raise the value and randomness, respectively.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CommitmentKey {
    /// Base to raise the value to when committing.
    pub g: C,
    /// Base to raise the randomness to when committing.
    pub h: C,
}

/// A vector commitment key is a list of group elements that are used as bases
/// to raise the values and randomness, respectively.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VecCommitmentKey {
    /// Bases to raise the values to when committing.
    /// It is assumed that this is non-empty.
    pub gs: Vec<C>,
    /// Base to raise the randomness to when committing.
    pub h: C,
}

impl CommitmentKey {
    pub fn new(g: C, h: C) -> Self {
        CommitmentKey { g, h }
    }

    /// Commit to the given value using a freshly generated randomness, and
    /// return the randomness that was generated.
    pub fn commit(&self, s: &Fr, csprng: &mut ThreadRng) -> (C, Fr) {
        let r = Fr::rand(csprng);
        (self.hide(s, &r), r)
    }

    /// The low-level worker function that actually does the commitment.
    /// The interface is not very type-safe, hence the availability of other
    /// functions.
    pub fn hide_worker(&self, value: &Fr, randomness: &Fr) -> C {
        let h = self.h;
        let g = self.g;
        let cmm = <C as VariableBaseMSM>::msm(
            &[g.into_affine(), h.into_affine()],
            &[*value, *randomness],
        )
        .unwrap();
        cmm
    }

    #[inline(always)]
    /// Hide the value inside a commitment using the given randomness.
    pub fn hide(&self, s: &Fr, r: &Fr) -> C {
        self.hide_worker(&s, &r)
    }

    /// Prove that the commitment `self` contains the given value and
    /// randomness.
    pub fn open(&self, s: &Fr, r: &Fr, c: &C) -> bool {
        self.hide(s, r) == *c
    }

    pub fn generate(csprng: &mut ThreadRng) -> CommitmentKey {
        let h = C::rand(csprng);
        let g = C::rand(csprng);
        CommitmentKey { g, h }
    }
}

impl VecCommitmentKey {
    pub fn new(gs: Vec<C>, h: C) -> Self {
        VecCommitmentKey { gs, h }
    }

    /// Commit to the given values using a freshly generated randomness, and
    /// return the randomness that was generated.
    pub fn commit(&self, s: &[Fr], csprng: &mut ThreadRng) -> Option<(C, Fr)> {
        let r = Fr::rand(csprng);
        Some((self.hide(s, &r)?, r))
    }

    /// The low-level worker function that actually does the commitment.
    pub fn hide_worker(&self, values: &[Fr], randomness: &Fr) -> Option<C> {
        if values.len() > self.gs.len() {
            return None;
        }
        let mut bases = self
            .gs
            .iter()
            .take(values.len())
            .copied()
            .collect::<Vec<_>>();
        bases.push(self.h);
        let mut scalars = values.to_vec();
        scalars.push(*randomness);
        let bases_affine: Vec<G1Affine> = bases.iter().map(|p| p.into_affine()).collect();
        let cmm = <C as VariableBaseMSM>::msm(&bases_affine, &scalars).unwrap();
        Some(cmm)
    }

    #[inline(always)]
    /// Hide the values inside a commitment using the given randomness.
    pub fn hide(&self, s: &[Fr], r: &Fr) -> Option<C> {
        self.hide_worker(s, &r)
    }

    /// Prove that the commitment `self` contains the given values and
    /// randomness.
    pub fn open(&self, s: &[Fr], r: &Fr, c: &C) -> bool {
        if let Some(comm) = self.hide(s, r) {
            comm == *c
        } else {
            false
        }
    }

    /// Generate a vector commitment key.
    /// NB: `n` should be non-zero in order to generate a meaningful commitment
    /// key.
    pub fn generate(csprng: &mut ThreadRng, n: usize) -> VecCommitmentKey {
        let h = C::rand(csprng);
        let mut gs = Vec::with_capacity(n);
        for _ in 0..n {
            gs.push(C::rand(csprng));
        }
        VecCommitmentKey { gs, h }
    }
}

pub struct Generators {
    pub G_H: Vec<(C, C)>,
}

impl Generators {
    /// **Warning** do not use in production!
    /// This generates a list of generators of a given size for
    /// testing purposes. For production, generators must be created such that
    /// discrete logarithms between different generators are not known, which is
    /// not guaranteed by this function.
    #[cfg(test)]
    pub(crate) fn generate(n: usize, csprng: &mut ThreadRng) -> Self {
        let mut gh = Vec::with_capacity(n);
        for _ in 0..n {
            let x = C::rand(csprng);
            let y = C::rand(csprng);
            gh.push((x, y));
        }
        Self { G_H: gh }
    }

    /// Returns the prefix of length nm of a given generator.
    /// This function panics if nm > length of the generator.
    pub fn take(&self, nm: usize) -> Self {
        Self {
            G_H: self.G_H[0..nm].to_vec(),
        }
    }
}
