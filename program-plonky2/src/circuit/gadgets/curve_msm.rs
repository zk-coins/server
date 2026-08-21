//! Two-bit-window in-circuit multi-scalar multiplication.

use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::keccak::KeccakHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericHashOut, Hasher};

use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::{Curve, CurveScalar};
use crate::circuit::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
use crate::circuit::gadgets::nonnative::NonNativeTarget;
use crate::circuit::gadgets::split_nonnative::CircuitBuilderSplit;

/// Compute `n*p + m*q` with a joint 2-bit window. Requires `p != q`.
pub fn curve_msm_circuit<C: Curve, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p: &AffinePointTarget<C>,
    q: &AffinePointTarget<C>,
    n: &NonNativeTarget<C::ScalarField>,
    m: &NonNativeTarget<C::ScalarField>,
) -> AffinePointTarget<C> {
    let limbs_n = builder.split_nonnative_to_2_bit_limbs(n);
    let limbs_m = builder.split_nonnative_to_2_bit_limbs(m);
    assert_eq!(limbs_n.len(), limbs_m.len());
    let num_limbs = limbs_n.len();

    let hash = KeccakHash::<32>::hash_no_pad(&[F::ZERO]);
    let scalar = C::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_le(
        &GenericHashOut::<F>::to_bytes(&hash),
    ));
    let blind = (CurveScalar(scalar) * C::GENERATOR_PROJECTIVE).to_affine();
    let blind_t = builder.constant_affine_point(blind);
    let neg_blind_t = builder.constant_affine_point(-blind);

    // table[i + 4*j] = i*p + j*q, with a nonzero blind in slot zero.
    let mut table = vec![p.clone(); 16];
    let mut cur_p = blind_t.clone();
    let mut cur_q = blind_t.clone();
    for i in 0..4 {
        table[i] = cur_p.clone();
        table[4 * i] = cur_q.clone();
        cur_p = builder.curve_add(&cur_p, p);
        cur_q = builder.curve_add(&cur_q, q);
    }
    for i in 1..4 {
        table[i] = builder.curve_add(&table[i], &neg_blind_t);
        table[4 * i] = builder.curve_add(&table[4 * i], &neg_blind_t);
    }
    for i in 1..4 {
        for j in 1..4 {
            table[i + 4 * j] = builder.curve_add(&table[i], &table[4 * j]);
        }
    }

    let four = builder.constant(F::from_canonical_usize(4));
    let zero = builder.zero();
    let mut result = blind_t;
    for (limb_n, limb_m) in limbs_n.into_iter().zip(limbs_m).rev() {
        result = builder.curve_repeated_double(&result, 2);
        let index = builder.mul_add(four, limb_m, limb_n);
        let selected = builder.random_access_curve_points(index, table.clone());
        let is_zero = builder.is_equal(index, zero);
        let should_add = builder.not(is_zero);
        result = builder.curve_conditional_add(&result, &selected, should_add);
    }
    let multiplied_blind = (0..2 * num_limbs).fold(blind, |acc, _| acc.double());
    let correction = builder.constant_affine_point(-multiplied_blind);
    builder.curve_add(&result, &correction)
}
