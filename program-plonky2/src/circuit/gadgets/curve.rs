//! In-circuit affine short-Weierstrass arithmetic over nonnative fields.

use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::gadgets::curve_types::{AffinePoint, Curve, CurveScalar};
use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

/// An affine nonzero point target. Arithmetic is intentionally incomplete at infinity.
#[derive(Clone, Debug)]
pub struct AffinePointTarget<C: Curve> {
    pub x: NonNativeTarget<C::BaseField>,
    pub y: NonNativeTarget<C::BaseField>,
}

impl<C: Curve> AffinePointTarget<C> {
    pub fn to_vec(&self) -> Vec<NonNativeTarget<C::BaseField>> {
        vec![self.x.clone(), self.y.clone()]
    }
}

pub trait CircuitBuilderCurve<F: RichField + Extendable<D>, const D: usize> {
    fn constant_affine_point<C: Curve>(&mut self, point: AffinePoint<C>) -> AffinePointTarget<C>;
    fn connect_affine_point<C: Curve>(
        &mut self,
        lhs: &AffinePointTarget<C>,
        rhs: &AffinePointTarget<C>,
    );
    fn add_virtual_affine_point_target<C: Curve>(&mut self) -> AffinePointTarget<C>;
    fn curve_assert_valid<C: Curve>(&mut self, p: &AffinePointTarget<C>);
    fn curve_neg<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C>;
    fn curve_conditional_neg<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C>;
    fn curve_double<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C>;
    fn curve_repeated_double<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: usize,
    ) -> AffinePointTarget<C>;
    /// Add points which are assumed distinct and not inverses.
    fn curve_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C>;
    fn curve_conditional_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C>;
    fn curve_scalar_mul<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCurve<F, D>
    for CircuitBuilder<F, D>
{
    fn constant_affine_point<C: Curve>(&mut self, point: AffinePoint<C>) -> AffinePointTarget<C> {
        assert!(
            !point.zero,
            "circuit affine targets cannot represent infinity"
        );
        AffinePointTarget {
            x: self.constant_nonnative(point.x),
            y: self.constant_nonnative(point.y),
        }
    }

    fn connect_affine_point<C: Curve>(
        &mut self,
        lhs: &AffinePointTarget<C>,
        rhs: &AffinePointTarget<C>,
    ) {
        self.connect_nonnative(&lhs.x, &rhs.x);
        self.connect_nonnative(&lhs.y, &rhs.y);
    }

    fn add_virtual_affine_point_target<C: Curve>(&mut self) -> AffinePointTarget<C> {
        AffinePointTarget {
            x: self.add_virtual_nonnative_target(),
            y: self.add_virtual_nonnative_target(),
        }
    }

    fn curve_assert_valid<C: Curve>(&mut self, p: &AffinePointTarget<C>) {
        let a = self.constant_nonnative(C::A);
        let b = self.constant_nonnative(C::B);
        let y2 = self.mul_nonnative(&p.y, &p.y);
        let x2 = self.mul_nonnative(&p.x, &p.x);
        let x3 = self.mul_nonnative(&x2, &p.x);
        let ax = self.mul_nonnative(&a, &p.x);
        let ax_b = self.add_nonnative(&ax, &b);
        let rhs = self.add_nonnative(&x3, &ax_b);
        self.connect_nonnative(&y2, &rhs);
    }

    fn curve_neg<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C> {
        AffinePointTarget {
            x: p.x.clone(),
            y: self.neg_nonnative(&p.y),
        }
    }

    fn curve_conditional_neg<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C> {
        AffinePointTarget {
            x: p.x.clone(),
            y: self.nonnative_conditional_neg(&p.y, b),
        }
    }

    fn curve_double<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C> {
        let two_y = self.add_nonnative(&p.y, &p.y);
        let inv_two_y = self.inv_nonnative(&two_y);
        let x2 = self.mul_nonnative(&p.x, &p.x);
        let two_x2 = self.add_nonnative(&x2, &x2);
        let three_x2 = self.add_nonnative(&two_x2, &x2);
        let a = self.constant_nonnative(C::A);
        let numerator = self.add_nonnative(&three_x2, &a);
        let lambda = self.mul_nonnative(&numerator, &inv_two_y);
        let lambda2 = self.mul_nonnative(&lambda, &lambda);
        let two_x = self.add_nonnative(&p.x, &p.x);
        let x3 = self.sub_nonnative(&lambda2, &two_x);
        let x_diff = self.sub_nonnative(&p.x, &x3);
        let lambda_x_diff = self.mul_nonnative(&lambda, &x_diff);
        let y3 = self.sub_nonnative(&lambda_x_diff, &p.y);
        AffinePointTarget { x: x3, y: y3 }
    }

    fn curve_repeated_double<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: usize,
    ) -> AffinePointTarget<C> {
        let mut result = p.clone();
        for _ in 0..n {
            result = self.curve_double(&result);
        }
        result
    }

    fn curve_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C> {
        let u = self.sub_nonnative(&p2.y, &p1.y);
        let v = self.sub_nonnative(&p2.x, &p1.x);
        let v_inv = self.inv_nonnative(&v);
        let slope = self.mul_nonnative(&u, &v_inv);
        let slope2 = self.mul_nonnative(&slope, &slope);
        let x_sum = self.add_nonnative(&p2.x, &p1.x);
        let x3 = self.sub_nonnative(&slope2, &x_sum);
        let x_diff = self.sub_nonnative(&p1.x, &x3);
        let product = self.mul_nonnative(&slope, &x_diff);
        let y3 = self.sub_nonnative(&product, &p1.y);
        AffinePointTarget { x: x3, y: y3 }
    }

    fn curve_conditional_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C> {
        let sum = self.curve_add(p1, p2);
        AffinePointTarget {
            x: self.if_nonnative(b, &sum.x, &p1.x),
            y: self.if_nonnative(b, &sum.y, &p1.y),
        }
    }

    fn curve_scalar_mul<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C> {
        let bits = self.split_nonnative_to_bits(n);
        let blind = (CurveScalar(C::ScalarField::from_canonical_u64(0x5a17))
            * C::GENERATOR_PROJECTIVE)
            .to_affine();
        let blind_t = self.constant_affine_point(blind);
        let mut result = blind_t.clone();
        let mut doubled = p.clone();
        for bit in bits {
            let sum = self.curve_add(&result, &doubled);
            result = AffinePointTarget {
                x: self.if_nonnative(bit, &sum.x, &result.x),
                y: self.if_nonnative(bit, &sum.y, &result.y),
            };
            doubled = self.curve_double(&doubled);
        }
        let neg_blind = self.curve_neg(&blind_t);
        self.curve_add(&result, &neg_blind)
    }
}
