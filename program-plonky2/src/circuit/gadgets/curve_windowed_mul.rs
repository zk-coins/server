//! Four-bit windowed in-circuit scalar multiplication helpers.

use std::marker::PhantomData;

use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::keccak::KeccakHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericHashOut, Hasher};

use crate::circuit::gadgets::biguint::BigUintTarget;
use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::{Curve, CurveScalar};
use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::circuit::gadgets::split_nonnative::CircuitBuilderSplit;
use crate::u32_lib::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

const WINDOW_SIZE: usize = 4;

pub trait CircuitBuilderWindowedMul<F: RichField + Extendable<D>, const D: usize> {
    fn precompute_window<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
    ) -> Vec<AffinePointTarget<C>>;
    fn random_access_curve_points<C: Curve>(
        &mut self,
        access_index: Target,
        points: Vec<AffinePointTarget<C>>,
    ) -> AffinePointTarget<C>;
    fn if_affine_point<C: Curve>(
        &mut self,
        b: BoolTarget,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C>;
    fn curve_scalar_mul_windowed<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderWindowedMul<F, D>
    for CircuitBuilder<F, D>
{
    fn precompute_window<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
    ) -> Vec<AffinePointTarget<C>> {
        let blind = (CurveScalar(C::ScalarField::from_canonical_u64(0xc0ffee))
            * C::GENERATOR_PROJECTIVE)
            .to_affine();
        let neg_blind = self.constant_affine_point(-blind);
        let mut multiples = vec![self.constant_affine_point(blind)];
        for i in 1..1 << WINDOW_SIZE {
            multiples.push(self.curve_add(p, &multiples[i - 1]));
        }
        for item in multiples.iter_mut().skip(1) {
            *item = self.curve_add(&neg_blind, item);
        }
        multiples
    }

    fn random_access_curve_points<C: Curve>(
        &mut self,
        access_index: Target,
        points: Vec<AffinePointTarget<C>>,
    ) -> AffinePointTarget<C> {
        let num_limbs = C::BaseField::BITS.div_ceil(32);
        let zero = self.zero_u32();
        let select = |builder: &mut Self, x_coordinate: bool| {
            (0..num_limbs)
                .map(|i| {
                    let values = points
                        .iter()
                        .map(|p| {
                            let coordinate = if x_coordinate { &p.x } else { &p.y };
                            coordinate.value.limbs.get(i).copied().unwrap_or(zero).0
                        })
                        .collect();
                    U32Target(builder.random_access(access_index, values))
                })
                .collect()
        };
        let x = NonNativeTarget {
            value: BigUintTarget {
                limbs: select(self, true),
            },
            _phantom: PhantomData,
        };
        let y = NonNativeTarget {
            value: BigUintTarget {
                limbs: select(self, false),
            },
            _phantom: PhantomData,
        };
        AffinePointTarget { x, y }
    }

    fn if_affine_point<C: Curve>(
        &mut self,
        b: BoolTarget,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C> {
        AffinePointTarget {
            x: self.if_nonnative(b, &p1.x, &p2.x),
            y: self.if_nonnative(b, &p1.y, &p2.y),
        }
    }

    fn curve_scalar_mul_windowed<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C> {
        let hash = KeccakHash::<25>::hash_no_pad(&[F::ZERO]);
        let scalar = C::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_le(
            &GenericHashOut::<F>::to_bytes(&hash),
        ));
        let starting = CurveScalar(scalar) * C::GENERATOR_PROJECTIVE;
        let mut ending_blind = starting;
        for _ in 0..C::ScalarField::BITS {
            ending_blind = ending_blind.double();
        }

        let mut result = self.constant_affine_point(starting.to_affine());
        let table = self.precompute_window(p);
        let zero = self.zero();
        for window in self.split_nonnative_to_4_bit_limbs(n).into_iter().rev() {
            result = self.curve_repeated_double(&result, WINDOW_SIZE);
            let selected = self.random_access_curve_points(window, table.clone());
            let is_zero = self.is_equal(window, zero);
            let should_add = self.not(is_zero);
            result = self.curve_conditional_add(&result, &selected, should_add);
        }
        let correction = self.constant_affine_point(-ending_blind.to_affine());
        self.curve_add(&result, &correction)
    }
}
