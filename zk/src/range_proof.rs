/// Bulletproof implementation adapted from Concordium Rust library (https://github.com/concordium);
/// Modified to use Merlin transcript and Arkworks BN254 curves
use crate::helper::*;
use crate::inner_product::*;
use crate::pedersen::*;
use ark_bn254::Fr;
use ark_bn254::{G1Affine, G1Projective as C};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use merlin::Transcript;
use rand::prelude::ThreadRng;
use std::io::Cursor;
use std::iter::once;
use std::ops::{AddAssign, MulAssign, SubAssign};

/// Bulletproof style range proof
#[allow(non_snake_case)]
pub struct RangeProof {
    /// Commitments to the bits `a_i` of the value, and `a_i - 1`
    A: C,
    /// Commitment to the blinding factors in `s_L` and `s_R`
    S: C,
    /// Commitment to the `t_1` coefficient of polynomial `t(x)`
    T_1: C,
    /// Commitment to the `t_2` coefficient of polynomial `t(x)`
    T_2: C,
    /// Evaluation of `t(x)` at the challenge point `x`
    tx: Fr,
    /// Blinding factor for the commitment to tx
    tx_tilde: Fr,
    /// Blinding factor for the commitment to the inner-product arguments
    e_tilde: Fr,
    /// Inner product proof
    ip_proof: InnerProductProof,
}

impl RangeProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Curve points
        self.A.serialize_compressed(&mut buf).unwrap();
        self.S.serialize_compressed(&mut buf).unwrap();
        self.T_1.serialize_compressed(&mut buf).unwrap();
        self.T_2.serialize_compressed(&mut buf).unwrap();

        // Scalars
        self.tx.serialize_compressed(&mut buf).unwrap();
        self.tx_tilde.serialize_compressed(&mut buf).unwrap();
        self.e_tilde.serialize_compressed(&mut buf).unwrap();

        // Inner product proof
        buf.extend(self.ip_proof.to_bytes());

        buf
    }

    #[allow(non_snake_case)]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Cursor::new(bytes);
        // Curve points
        let A = C::deserialize_compressed(&mut reader).ok()?;
        let S = C::deserialize_compressed(&mut reader).ok()?;
        let T_1 = C::deserialize_compressed(&mut reader).ok()?;
        let T_2 = C::deserialize_compressed(&mut reader).ok()?;

        // Scalars
        let tx = Fr::deserialize_compressed(&mut reader).ok()?;
        let tx_tilde = Fr::deserialize_compressed(&mut reader).ok()?;
        let e_tilde = Fr::deserialize_compressed(&mut reader).ok()?;

        // Inner product proof
        let remaining = &bytes[reader.position() as usize..];
        let ip_proof = InnerProductProof::from_bytes(remaining)?;

        Some(Self {
            A,
            S,
            T_1,
            T_2,
            tx,
            tx_tilde,
            e_tilde,
            ip_proof,
        })
    }
}

/// Determine whether the `i`-th bit (counting from least significant) is set in
/// the given u64 value.
fn ith_bit_bool(v: u64, i: u8) -> bool {
    v & (1 << i) != 0
}

/// This function computes the n-bit binary representation `a_L` of input value
/// `v` The vector `a_R` is the bit-wise negation of `a_L`
#[allow(non_snake_case)]
fn a_L_a_R(v: u64, n: u8) -> (Vec<Fr>, Vec<Fr>) {
    let mut a_L = Vec::with_capacity(usize::from(n));
    let mut a_R = Vec::with_capacity(usize::from(n));
    for i in 0..n {
        let mut bit = Fr::zero();
        if ith_bit_bool(v, i) {
            bit = Fr::one();
        }
        a_L.push(bit);
        bit.sub_assign(&Fr::one());
        a_R.push(bit);
    }
    (a_L, a_R)
}

/// This function takes one argument n and returns the
/// vector (1, 2, ..., 2^{n-1}) in F^n for any field F
///
/// This could use the next `z_vec` function, but for efficiency it implements
/// the special-case logic for doubling directly.
#[allow(non_snake_case)]
fn two_n_vec(n: u8) -> Vec<Fr> {
    let mut two_n = Vec::with_capacity(usize::from(n));
    let mut two_i = Fr::one();
    for _ in 0..n {
        two_n.push(two_i);
        two_i.double_in_place();
    }
    two_n
}

/// This function produces a range proof given scalars in a prime field
/// instead of integers. It invokes prove(), documented below.
///
/// See the documentation of `prove` below for the meaning of arguments.
#[allow(clippy::too_many_arguments)]
pub fn prove_given_scalars(
    transcript: &mut Transcript,
    csprng: &mut ThreadRng,
    n: u8,
    m: u8,
    v_vec: &[Fr],
    gens: &Vec<(C, C)>,
    v_keys: &CommitmentKey,
    randomness: &[Fr],
) -> Option<RangeProof> {
    let mut v_integers = Vec::with_capacity(v_vec.len());
    for &v in v_vec {
        let rep = v.into_bigint();
        let r = rep.0[0];
        v_integers.push(r);
    }

    prove(
        transcript,
        csprng,
        n,
        m,
        &v_integers,
        gens,
        v_keys,
        randomness,
    )
}

/// This function produces a range proof, i.e. a proof of knowledge
/// of value `v_1, v_2, ..., v_m` that are all in `[0, 2^n)` that are consistent
/// with commitments V_i to v_i. The arguments are
/// - `n` - the number n such that `v_i` is in `[0,2^n)` for all `i`
/// - `m` - the number of values that is proved to be in `[0,2^n)`
/// - `v_vec` - the vector having `v_1, ..., v_m` as entrances
/// - `gens` - generators containing vectors `G` and `H` both of length at least
///   `nm`
/// - `v_keys` - commitment keys `B` and `B_tilde`
/// - `randomness` - the randomness used to commit to each `v_i` using `v_keys`
#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub fn prove(
    transcript: &mut Transcript,
    csprng: &mut ThreadRng,
    n: u8,
    m: u8,
    v_vec: &[u64],
    gens: &Vec<(C, C)>,
    v_keys: &CommitmentKey,
    randomness: &[Fr],
) -> Option<RangeProof> {
    // Part 1: Setup and generation of vector commitments
    // V (for the values),
    // A (their binary representation),
    // S (the blinding factors)
    let nm = usize::from(n) * usize::from(m);

    if v_vec.len() != randomness.len() {
        return None;
    }

    if gens.len() < nm {
        return None;
    }
    // Select generators for vector commitments
    let (G, H): (Vec<_>, Vec<_>) = gens.iter().take(nm).cloned().unzip();
    // Generator for single commitments
    let B = v_keys.g;
    // Generator for the blinding of commitments
    let B_tilde = v_keys.h;
    // Setup blinding factors for a_L and a_R
    let mut s_L = Vec::with_capacity(usize::from(n));
    let mut s_R = Vec::with_capacity(usize::from(n));
    for _ in 0..nm {
        s_L.push(Fr::rand(csprng));
        s_R.push(Fr::rand(csprng));
    }
    // Vectors for binary representation of values in v_vec
    let mut a_L: Vec<Fr> = Vec::with_capacity(usize::from(n));
    let mut a_R: Vec<Fr> = Vec::with_capacity(usize::from(n));
    // Vectors for value commitments V_j
    let mut V_vec: Vec<C> = Vec::with_capacity(usize::from(m));
    // Blinding factors for V_j,A_j,S_j commitments
    let mut v_tilde_vec: Vec<Fr> = Vec::with_capacity(usize::from(m));
    let mut a_tilde_vec: Vec<Fr> = Vec::with_capacity(usize::from(m));
    let mut s_tilde_vec: Vec<Fr> = Vec::with_capacity(usize::from(m));
    // Explicitly generators and commitment keys to the transcript
    transcript_append_points(transcript, b"G", &G);
    transcript_append_points(transcript, b"H", &H);
    transcript_append_point(transcript, b"v_keys_g", &v_keys.g);
    transcript_append_point(transcript, b"v_keys_h", &v_keys.h);
    for j in 0..v_vec.len() {
        // get binary representation of value j
        let (a_L_j, a_R_j) = a_L_a_R(v_vec[j], n);
        a_L.extend(&a_L_j);
        a_R.extend(&a_R_j);
        // generate blinding factors
        let v_j_tilde = &randomness[j];
        let a_j_tilde = Fr::rand(csprng);
        let s_j_tilde = Fr::rand(csprng);
        v_tilde_vec.push(*v_j_tilde);
        a_tilde_vec.push(a_j_tilde);
        s_tilde_vec.push(s_j_tilde);
        // convert value to scalar in base field of C
        let v_value = Fr::from(v_vec[j]);
        // generate commitment V_j to value v_j
        let V_j = v_keys.hide(&v_value, v_j_tilde);
        // append commitment V_j to transcript!
        transcript_append_point(transcript, b"Vj", &V_j);
        V_vec.push(V_j);
    }

    // compute blinding factor of A and S
    let mut a_tilde_sum = Fr::zero();
    let mut s_tilde_sum = Fr::zero();
    for i in 0..a_tilde_vec.len() {
        a_tilde_sum.add_assign(&a_tilde_vec[i]);
        s_tilde_sum.add_assign(&s_tilde_vec[i]);
    }
    // get scalars for A commitment, that is (a_L,a_r,a_tilde_sum)
    let A_scalars: Vec<Fr> = a_L
        .iter()
        .chain(a_R.iter())
        .copied()
        .chain(once(a_tilde_sum))
        .collect();
    // get scalars for S commitment, that is (s_L,s_r,s_tilde_sum)
    let S_scalars: Vec<Fr> = s_L
        .iter()
        .chain(s_R.iter())
        .copied()
        .chain(once(s_tilde_sum))
        .collect();
    // get generator vector for blinded vector commitments, i.e. (G,H,B_tilde)
    let GH_B_tilde: Vec<C> = G
        .iter()
        .chain(H.iter())
        .copied()
        .chain(once(B_tilde))
        .collect();
    // compute A and S commitments using multi exponentiation
    let GH_B_tilde_affine: Vec<G1Affine> = GH_B_tilde.iter().map(|p| p.into_affine()).collect();
    let A = <C as VariableBaseMSM>::msm(&GH_B_tilde_affine, &A_scalars).unwrap();
    let S = <C as VariableBaseMSM>::msm(&GH_B_tilde_affine, &S_scalars).unwrap();

    // append commitments A and S to transcript
    transcript_append_point(transcript, b"A", &A);
    transcript_append_point(transcript, b"S", &S);

    // Part 2: Computation of vector polynomials l(x),r(x)
    // get challenges y,z from transcript
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"y", &mut challenge_bytes);
    let y: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);
    transcript.challenge_bytes(b"z", &mut challenge_bytes);
    let z: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);

    // y_nm = (1,y,..,y^(nm-1))
    let y_nm = z_vec(y, 0, nm);
    // two_n = (1, 2, ..., 2^{n-1})
    let two_n: Vec<Fr> = two_n_vec(n);
    // z_m = (1,z,..,z^(m-1))
    let z_m = z_vec(z, 0, usize::from(m));
    // z squared
    let z_sq = if z_m.len() > 2 {
        z_m[2]
    } else {
        let mut z_sq = z;
        z_sq.mul_assign(&z);
        z_sq
    };

    // coefficients of l(x) and r(x)
    let mut l_0 = Vec::with_capacity(nm);
    let mut l_1 = Vec::with_capacity(nm);
    let mut r_0 = Vec::with_capacity(nm);
    let mut r_1 = Vec::with_capacity(nm);
    // compute l_0 and l_1
    for i in 0..a_L.len() {
        // l_0[i] <- a_L[i] - z
        let mut l_0_i = a_L[i];
        l_0_i.sub_assign(&z);
        l_0.push(l_0_i);
        // l_1[i] <- s_L[i]
        l_1.push(s_L[i]);
    }
    // compute r_0 and r_1
    for i in 0..a_R.len() {
        // r_0[i] <- y_nm[i] * (a_R[i] + z) + z^2*z_m[i//n]*two_n[i%n]
        let mut r_0_i = a_R[i];
        r_0_i.add_assign(&z);
        r_0_i.mul_assign(&y_nm[i]);
        let j = i / (usize::from(n));
        let mut z_jz_2_2_n = z_m[j];
        let two_i = two_n[i % (usize::from(n))];
        z_jz_2_2_n.mul_assign(&z_sq);
        z_jz_2_2_n.mul_assign(&two_i);
        r_0_i.add_assign(&z_jz_2_2_n);
        r_0.push(r_0_i);

        // r_1[i] <- y_nm[i] * s_R[i]
        let mut r_1_i = y_nm[i];
        r_1_i.mul_assign(&s_R[i]);
        r_1.push(r_1_i);
    }

    // Part 3: Computation of polynomial t(x) = <l(x),r(x)>
    // coefficients of polynomials t_j(x)
    let mut t_0 = Vec::with_capacity(usize::from(m));
    let mut t_1 = Vec::with_capacity(usize::from(m));
    let mut t_2 = Vec::with_capacity(usize::from(m));
    // blinding factors for upper coefficients of t_j(x)
    let mut t_1_tilde = Vec::with_capacity(usize::from(m));
    let mut t_2_tilde = Vec::with_capacity(usize::from(m));

    // for each t_j(x)
    for j in 0..usize::from(m) {
        let n = usize::from(n);
        // compute coefficients of t_j(x)
        // t_0,j <- <l_{0,j},r_{0,j}>
        let t_0_j = inner_product(&l_0[j * n..(j + 1) * n], &r_0[j * n..(j + 1) * n]);
        // t_2,j <- <l_{1,j},r_{1,j}>
        let t_2_j = inner_product(&l_1[j * n..(j + 1) * n], &r_1[j * n..(j + 1) * n]);
        // t_1,j <- <l_{0,j}+l_{1,j},r_{0,j}+r_{1,j}> - t_0,j - t_2,j
        let mut t_1_j: Fr = Fr::zero();
        for i in 0..n {
            let mut l_0_j_l_1_j = l_0[j * n + i];
            l_0_j_l_1_j.add_assign(&l_1[j * n + i]);
            let mut r_0_j_r_1_j = r_0[j * n + i];
            r_0_j_r_1_j.add_assign(&r_1[j * n + i]);
            let mut prod = l_0_j_l_1_j;
            prod.mul_assign(&r_0_j_r_1_j);
            t_1_j.add_assign(&prod);
        }
        t_1_j.sub_assign(&t_0_j);
        t_1_j.sub_assign(&t_2_j);

        t_0.push(t_0_j);
        t_1.push(t_1_j);
        t_2.push(t_2_j);

        // compute blinding factors
        let t_1_j_tilde = Fr::rand(csprng);
        let t_2_j_tilde = Fr::rand(csprng);
        t_1_tilde.push(t_1_j_tilde);
        t_2_tilde.push(t_2_j_tilde);
    }

    // compute commitments T_1 and T_2 for upper coefficients
    let mut t_1_sum = Fr::zero();
    let mut t_1_tilde_sum = Fr::zero();
    let mut t_2_sum = Fr::zero();
    let mut t_2_tilde_sum = Fr::zero();
    for i in 0..t_1.len() {
        t_1_sum.add_assign(&t_1[i]);
        t_1_tilde_sum.add_assign(&t_1_tilde[i]);
        t_2_sum.add_assign(&t_2[i]);
        t_2_tilde_sum.add_assign(&t_2_tilde[i]);
    }
    let T_1 = B * (&t_1_sum) + B_tilde * (&t_1_tilde_sum);
    let T_2 = B * (&t_2_sum) + B_tilde * (&t_2_tilde_sum);
    // append T1, T2 commitments to transcript
    transcript_append_point(transcript, b"T1", &T_1);
    transcript_append_point(transcript, b"T2", &T_2);

    // Part 4: Evaluate l(x), r(x), and t(x) at challenge point x
    // get challenge x from transcript
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"x", &mut challenge_bytes);
    let x: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);
    // println!("prover's x = {:?}", x);
    let mut x2 = x;
    x2.mul_assign(&x);
    let mut l: Vec<Fr> = Vec::with_capacity(nm);
    let mut r: Vec<Fr> = Vec::with_capacity(nm);

    // evaluate l(x) and r(x)
    for i in 0..nm {
        // l[i] <- l_0[i] + x* l_1[i]
        let mut l_i = l_1[i];
        l_i.mul_assign(&x);
        l_i.add_assign(&l_0[i]);
        // r[i] = r_0[i] + x* r_1[i]
        let mut r_i = r_1[i];
        r_i.mul_assign(&x);
        r_i.add_assign(&r_0[i]);
        l.push(l_i);
        r.push(r_i);
    }

    // evaluate t(x) at challenge point x,
    // compute blinding factor tx_tilde for t(x) evaluation commitments,
    // and compute blinding factor e_tilde for the inner product commitments
    let mut tx: Fr = Fr::zero();
    let mut tx_tilde: Fr = Fr::zero();
    let mut e_tilde: Fr = Fr::zero();
    for j in 0..usize::from(m) {
        // Around 1 ms
        // tx_j <- t_0[j] + t_1[j]*x + t_2[j]*x^2
        let mut t1jx = t_1[j];
        t1jx *= &x;
        let mut t2jx2 = t_2[j];
        t2jx2 *= &x2; //TODO: check if mul_assign or add_assign or correct 
        let mut tjx = t_0[j];
        tjx += &t1jx;
        tjx += &t2jx2;
        tx += &tjx;

        // tx_j_tilde <- z^2*z_j*v_j_tilde + t_1_j_tilde*x + t_2_j_tilde*x^2
        let mut z2vj_tilde = z_sq;
        z2vj_tilde.mul_assign(&z_m[j]); // This line is MISSING in the Bulletproof documentation (https://doc-internal.dalek.rs/bulletproofs/range_proof/index.html), but shows in https://doc-internal.dalek.rs/bulletproofs/notes/range_proof/index.html
        z2vj_tilde.mul_assign(&v_tilde_vec[j]);
        let mut xt1j_tilde = x;
        xt1j_tilde.mul_assign(&t_1_tilde[j]);
        let mut x2t2j_tilde = x2;
        x2t2j_tilde.mul_assign(&t_2_tilde[j]);
        let mut txj_tilde = z2vj_tilde;
        txj_tilde.add_assign(&xt1j_tilde);
        txj_tilde.add_assign(&x2t2j_tilde);
        tx_tilde.add_assign(&txj_tilde);

        // e_tilde_j <- a_tilde_j + s_tilde_j * x
        let mut ej_tilde = x;
        ej_tilde.mul_assign(&s_tilde_vec[j]);
        ej_tilde.add_assign(&a_tilde_vec[j]);
        e_tilde.add_assign(&ej_tilde);
    }
    // append tx, tx_tilde, e_tilde to transcript
    transcript_append_element(transcript, b"tx", &tx);
    transcript_append_element(transcript, b"tx_tilde", &tx_tilde);
    transcript_append_element(transcript, b"e_tilde", &e_tilde);

    // Part 5: Inner product proof for t(x) = <l(x),r(x)>
    // get challenge w from transcript
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"w", &mut challenge_bytes);
    let w: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);
    // get generator q
    let Q = B * (&w);

    // let mut H_prime : Vec<C> = Vec::with_capacity(nm);
    // compute scalars such that c*H = H', that is H_prime_scalars = (1, y^-1,
    // \dots, y^-(nm-1))
    let mut H_prime_scalars: Vec<Fr> = Vec::with_capacity(nm);
    let y_inv = y.inverse()?;
    let mut y_inv_i = Fr::one();
    for _i in 0..nm {
        // H_prime.push(H[i].mul_by_scalar(&y_inv_i));
        H_prime_scalars.push(y_inv_i);
        y_inv_i.mul_assign(&y_inv);
    }
    // compute inner product proof
    let proof = prove_inner_product_with_scalars(transcript, &G, &H, &H_prime_scalars, &Q, &l, &r);

    // return range proof
    if let Some(ip_proof) = proof {
        return Some(RangeProof {
            A,
            S,
            T_1,
            T_2,
            tx,
            tx_tilde,
            e_tilde,
            ip_proof,
        });
    }
    None
}

/// The verifier does two checks. In case verification fails, it can be useful
/// to know which of the checks led to failure.
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// Choice of randomness led to verification failure.
    DivisionError,
    /// The first check failed (see function below for what this means)
    First,
    /// The second check failed.
    Second,
    /// The length of G_H was less than nm, which is too small
    NotEnoughGenerators,
}

/// This function verifies an aggregated range proof, i.e., a proof of knowledge
/// of values `v_1, v_2, ..., v_m` in `[0, 2^n)` that are consistent
/// with commitments `V_i` to `v_i`. The arguments are
/// - `n` - the number `n` such that each `v_i` is claimed to be in `[0, 2^n)`
///   by the prover
/// - `commitments` - commitments `V_i` to each `v_i`
/// - `proof` - the range proof
/// - `gens` - generators containing vectors `G` and `H` both of length at least
///   `nm` (bold **g**,**h** in bluepaper)
/// - `v_keys` - commitment keys `B` and `B_tilde` (`g,h` in bluepaper)
///
/// Note: The bulletproof paper also describes an optimized verification method
/// that integrates the exponentiations from the inner-product verification into
/// the range proof verification using the Schwartz–Zippel lemma. We had
/// implemented this and compared the performance, but since the performance
/// gains were negligible and modularity much worse, we do not use this here.
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::many_single_char_names)]
pub fn verify_efficient(
    transcript: &mut Transcript,
    n: u8,
    commitments: &[C],
    proof: &RangeProof,
    gens: &Vec<(C, C)>,
    v_keys: &CommitmentKey,
) -> Result<(), VerificationError> {
    // Part 1: Setup
    let m = commitments.len();
    let nm = usize::from(n) * m;
    // Check that we have enough generators for vector commitments
    if gens.len() < nm {
        return Err(VerificationError::NotEnoughGenerators);
    }
    // Select generators G, H, B, B_tilde
    let (G, H): (Vec<_>, Vec<_>) = gens.iter().take(nm).cloned().unzip();
    let B = v_keys.g;
    let B_tilde = v_keys.h;
    // Explicitly add generators and commitment keys to the transcript
    transcript_append_points(transcript, b"G", &G);
    transcript_append_points(transcript, b"H", &H);
    transcript_append_point(transcript, b"v_keys_g", &v_keys.g);
    transcript_append_point(transcript, b"v_keys_h", &v_keys.h);
    // append commitment V_j to transcript!
    for V in commitments {
        transcript_append_point(transcript, b"Vj", &V);
    }
    // define the commitments A,S,T_1,T_2
    let A = proof.A;
    let S = proof.S;
    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    // define polynomial evaluation value
    let tx = proof.tx;
    // define blinding factors for tx and i.p. proof
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    // append commitments A and S to transcript
    transcript_append_point(transcript, b"A", &A);
    transcript_append_point(transcript, b"S", &S);
    // get challenges y,z from transcript
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"y", &mut challenge_bytes);
    let y: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);
    transcript.challenge_bytes(b"z", &mut challenge_bytes);
    let z: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);
    let mut z2 = z;
    z2.mul_assign(&z);
    let mut z3 = z2;
    z3.mul_assign(&z);
    // append T1, T2 commitments to transcript
    transcript_append_point(transcript, b"T1", &T_1);
    transcript_append_point(transcript, b"T2", &T_2);
    // get challenge x (evaluation point) from transcript
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"x", &mut challenge_bytes);
    let x: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);
    let mut x2 = x;
    x2.mul_assign(&x);
    // println!("verifier's x = {:?}", x);
    // append tx, tx_tilde, e_tilde to transcript
    transcript_append_element(transcript, b"tx", &tx);
    transcript_append_element(transcript, b"tx_tilde", &tx_tilde);
    transcript_append_element(transcript, b"e_tilde", &e_tilde);
    // get challenge w from transcript
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"w", &mut challenge_bytes);
    let w: Fr = Fr::from_le_bytes_mod_order(&challenge_bytes);

    // Part 2: Check verification equation 1
    // Calculate delta(x,y) <- (z-z^2)*<1,y_nm> - <1,2_nm> * sum_j=0^m-1 z^(j+3)
    // ip_1_y_nm <- <1,y_nm>
    let mut ip_1_y_nm = Fr::zero();
    let mut yi = Fr::one();
    for _ in 0..G.len() {
        ip_1_y_nm.add_assign(&yi);
        yi.mul_assign(&y);
    }
    // ip_1_2_n <- <1,2_nm>
    let mut ip_1_2_n = Fr::zero();
    let mut two_i = Fr::one();
    for _ in 0..usize::from(n) {
        ip_1_2_n.add_assign(&two_i);
        two_i.double_in_place();
    }
    let mut sum = Fr::zero();
    let mut zj3 = z3;
    for _ in 0..m {
        sum.add_assign(&zj3);
        zj3.mul_assign(&z);
    }
    sum.mul_assign(&ip_1_2_n);
    let mut delta_yz = z;
    delta_yz.sub_assign(&z2);
    delta_yz.mul_assign(&ip_1_y_nm);
    delta_yz.sub_assign(&sum);

    // eq1 LHS  <- t_x*B + t_tilde(x)*B_tilde
    let LHS = B * (&tx) + B_tilde * (&tx_tilde);

    // eq2 RHS <- sum_j=0^m-1 z^(j+2)*V_j + delta(x,y)*B + x*T_1 + x^2*T_2
    let mut zj2 = z2;
    let mut powers = Vec::with_capacity(m);
    for _ in 0..m {
        powers.push(zj2);
        zj2.mul_assign(&z);
    }
    // sum_j=0^m-1 z^(j+2)*V_j
    //multiexp::<C, Commitment<C>>(commitments, &powers);

    let commitments_affine: Vec<G1Affine> = commitments.iter().map(|p| p.into_affine()).collect();
    let mut RHS = <C as VariableBaseMSM>::msm(&commitments_affine, &powers).unwrap();

    let bases_affine: Vec<G1Affine> = [B, T_1, T_2].iter().map(|p| p.into_affine()).collect();
    let result: C = <C as VariableBaseMSM>::msm(&bases_affine, &[delta_yz, x, x2]).unwrap();
    RHS = RHS + result;

    // LHS - RHS ?= 0
    let first = (LHS - &RHS).is_zero();
    if !first {
        // Terminate early to avoid wasted effort.
        return Err(VerificationError::First);
    }

    // Part 2: Verify inner-product proof
    // First compute helper variables g_hat, h_prime, and P_prime
    // g_hat = g^w (= B^w)
    let g_hat = B * (&w);
    // h_prime = multiexp(h, y^-n); compute exponents and calculate in
    // verify_inner_product_with_scalars
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(VerificationError::DivisionError),
    };
    let y_inv_nm = z_vec(y_inv, 0, H.len());

    // P' = multiexp(G, -z1) multiexp(H, PH_scalars) g_hat^t_x * h^-e_tilde * A S^x,
    // where H_scalars[j] = z + y^-j * z^(2+j//n) * 2^(j%n)
    let mut P_prime_exps = Vec::with_capacity(2 * nm + 4);
    //let mut minus_z = z;
    //minus_z.negate();
    let mut minus_z_vec = vec![-z; G.len()];
    P_prime_exps.append(&mut minus_z_vec);

    // compute PH_scalars and add to P_prime_exps
    let two_n: Vec<Fr> = two_n_vec(n); // 1, 2, 4, 8, ...
    let z_2_m = z_vec(z, 2, m); // z^2, z^3, ...
    for j in 0..H.len() {
        let mut H_scalar = y_inv_nm[j];
        H_scalar.mul_assign(&z_2_m[j / usize::from(n)]);
        H_scalar.mul_assign(&two_n[j % usize::from(n)]);
        H_scalar.add_assign(&z);
        P_prime_exps.push(H_scalar);
    }

    // add remaining exponents
    P_prime_exps.push(tx); // exponent for g_hat
    //let mut minus_e_tilde = e_tilde;
    //minus_e_tilde.negate();
    P_prime_exps.push(-e_tilde); // exponent for h = B_tilde
    P_prime_exps.push(Fr::one()); // exponent for A
    P_prime_exps.push(x); // exponent for S

    // P_prime_bases starts with G, H, and Q = g_hat
    let mut P_prime_bases = Vec::with_capacity(2 * nm + 4);
    P_prime_bases.extend(G);
    P_prime_bases.extend(H);
    P_prime_bases.push(g_hat);

    // add remaining bases
    P_prime_bases.push(B_tilde);
    P_prime_bases.push(A);
    P_prime_bases.push(S);

    // Finally verify inner product
    let second = verify_inner_product_with_scalars(
        transcript,
        &y_inv_nm,
        &P_prime_bases,
        &P_prime_exps,
        &proof.ip_proof,
    );

    if !second {
        return Err(VerificationError::Second);
    }

    Ok(())
}

/// For proving that a <= b for integers a,b
/// It is assumed that a,b \in [0, 2^n)
#[allow(clippy::too_many_arguments)]
pub fn prove_less_than_or_equal(
    transcript: &mut Transcript,
    csprng: &mut ThreadRng,
    n: u8,
    a: u64,
    b: u64,
    gens: &Vec<(C, C)>,
    key: &CommitmentKey,
    randomness_a: &Fr,
    randomness_b: &Fr,
) -> Option<RangeProof> {
    let mut randomness = *randomness_b;
    randomness.sub_assign(randomness_a);
    prove(
        transcript,
        csprng,
        n,
        2,
        &[b - a, a],
        gens,
        key,
        &[randomness, *randomness_a],
    )
}

/// Given commitments to a and b, verify that a <= b.
/// It is assumed that b \in [0, 2^n),
/// but it should follow that a \in [0, 2^n) if the
/// proof verifies.
pub fn verify_less_than_or_equal(
    transcript: &mut Transcript,
    n: u8,
    commitment_a: &C,
    commitment_b: &C,
    proof: &RangeProof,
    gens: &Vec<(C, C)>,
    key: &CommitmentKey,
) -> bool {
    let commitment = commitment_b - commitment_a;
    verify_efficient(
        transcript,
        n,
        &[commitment, *commitment_a],
        proof,
        gens,
        key,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[allow(non_snake_case)]
    #[test]
    fn test_less_than_or_equal_to() {
        // Test for nm = 512
        let rng = &mut thread_rng();
        let n = 16;
        let m = 10u8;
        let nm = (usize::from(n)) * (usize::from(m));
        let mut G = Vec::with_capacity(nm);
        let mut H = Vec::with_capacity(nm);
        let mut G_H = Vec::with_capacity(nm);

        for _i in 0..(nm) {
            let g = C::rand(rng);
            let h = C::rand(rng);
            G.push(g);
            H.push(h);
            G_H.push((g, h));
        }

        let gens: Vec<(C, C)> = G_H;
        let B = C::rand(rng);
        let B_tilde = C::rand(rng);
        let key = CommitmentKey { g: B, h: B_tilde };

        let a = 499;
        let b = 500;

        let r_a = Fr::rand(rng);
        let r_b = Fr::rand(rng);
        let a_scalar = Fr::from(a);
        let b_scalar = Fr::from(b);
        let com_a = key.hide_worker(&a_scalar, &r_a);
        let com_b = key.hide_worker(&b_scalar, &r_b);
        let mut transcript: Transcript = Transcript::new(b"Range proof test");
        let proof =
            prove_less_than_or_equal(&mut transcript, rng, n, a, b, &gens, &key, &r_a, &r_b)
                .unwrap();
        let mut transcript: Transcript = Transcript::new(b"Range proof test");
        assert!(verify_less_than_or_equal(
            &mut transcript,
            n,
            &com_a,
            &com_b,
            &proof,
            &gens,
            &key
        ));
    }
}
