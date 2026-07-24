//! Four-bit windowed fixed-base scalar multiplication.

use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::keccak::KeccakHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericHashOut, Hasher};

use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::{AffinePoint, Curve, CurveScalar};
use crate::circuit::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
use crate::circuit::gadgets::nonnative::NonNativeTarget;
use crate::circuit::gadgets::split_nonnative::CircuitBuilderSplit;

pub fn fixed_base_curve_mul_circuit<C: Curve, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    base: AffinePoint<C>,
    scalar: &NonNativeTarget<C::ScalarField>,
) -> AffinePointTarget<C> {
    let scaled_base = (0..scalar.value.limbs.len() * 8).scan(base, |acc, _| {
        let current = *acc;
        for _ in 0..4 {
            *acc = acc.double();
        }
        Some(current)
    });
    let limbs = builder.split_nonnative_to_4_bit_limbs(scalar);
    let hash = KeccakHash::<32>::hash_no_pad(&[F::ZERO]);
    let blind_scalar = C::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_le(
        &GenericHashOut::<F>::to_bytes(&hash),
    ));
    let blind = (CurveScalar(blind_scalar) * C::GENERATOR_PROJECTIVE).to_affine();
    let zero = builder.zero();
    let mut result = builder.constant_affine_point(blind);

    for (limb, point) in limbs.into_iter().zip(scaled_base) {
        let mut multiples = (0..16)
            .scan(AffinePoint::ZERO, |acc, _| {
                let current = *acc;
                *acc = (point + *acc).to_affine();
                Some(current)
            })
            .skip(1)
            .map(|p| builder.constant_affine_point(p))
            .collect::<Vec<_>>();
        multiples.insert(0, multiples[0].clone());
        let selected = builder.random_access_curve_points(limb, multiples);
        let is_zero = builder.is_equal(limb, zero);
        let should_add = builder.not(is_zero);
        result = builder.curve_conditional_add(&result, &selected, should_add);
    }
    let correction = builder.constant_affine_point(-blind);
    builder.curve_add(&result, &correction)
}
