//! Host-side short-Weierstrass curve types and secp256k1 parameters.

use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::{Add, Mul, Neg};

use num::{BigUint, One, Zero};
use plonky2::field::ops::Square;
use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};

/// Wrapper used to avoid overlapping scalar multiplication implementations.
pub struct CurveScalar<C: Curve>(pub C::ScalarField);

/// A short-Weierstrass curve.
pub trait Curve: 'static + Sync + Sized + Copy + Debug {
    type BaseField: PrimeField;
    type ScalarField: PrimeField;

    const A: Self::BaseField;
    const B: Self::BaseField;
    const GENERATOR_AFFINE: AffinePoint<Self>;
    const GENERATOR_PROJECTIVE: ProjectivePoint<Self> = ProjectivePoint {
        x: Self::GENERATOR_AFFINE.x,
        y: Self::GENERATOR_AFFINE.y,
        z: Self::BaseField::ONE,
    };

    fn convert(x: Self::ScalarField) -> CurveScalar<Self> {
        CurveScalar(x)
    }

    fn is_safe_curve() -> bool {
        (Self::A.cube().double().double() + Self::B.square().triple().triple().triple())
            .is_nonzero()
    }
}

/// An affine point. `zero` denotes the point at infinity.
#[derive(Copy, Clone, Debug)]
pub struct AffinePoint<C: Curve> {
    pub x: C::BaseField,
    pub y: C::BaseField,
    pub zero: bool,
}

impl<C: Curve> AffinePoint<C> {
    pub const ZERO: Self = Self {
        x: C::BaseField::ZERO,
        y: C::BaseField::ZERO,
        zero: true,
    };

    pub fn nonzero(x: C::BaseField, y: C::BaseField) -> Self {
        let point = Self { x, y, zero: false };
        debug_assert!(point.is_valid());
        point
    }

    pub fn is_valid(&self) -> bool {
        self.zero || self.y.square() == self.x.cube() + C::A * self.x + C::B
    }

    pub fn to_projective(&self) -> ProjectivePoint<C> {
        ProjectivePoint {
            x: self.x,
            y: self.y,
            z: if self.zero {
                C::BaseField::ZERO
            } else {
                C::BaseField::ONE
            },
        }
    }

    pub fn batch_to_projective(points: &[Self]) -> Vec<ProjectivePoint<C>> {
        points.iter().map(Self::to_projective).collect()
    }

    #[must_use]
    pub fn double(&self) -> Self {
        if self.zero {
            return Self::ZERO;
        }
        let lambda = (self.x.square().triple() + C::A) * self.y.double().inverse();
        let x = lambda.square() - self.x.double();
        let y = lambda * (self.x - x) - self.y;
        Self { x, y, zero: false }
    }
}

impl<C: Curve> PartialEq for AffinePoint<C> {
    fn eq(&self, other: &Self) -> bool {
        if self.zero || other.zero {
            self.zero == other.zero
        } else {
            self.x == other.x && self.y == other.y
        }
    }
}

impl<C: Curve> Eq for AffinePoint<C> {}

impl<C: Curve> Hash for AffinePoint<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.zero {
            self.zero.hash(state);
        } else {
            self.x.hash(state);
            self.y.hash(state);
        }
    }
}

impl<C: Curve> Neg for AffinePoint<C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: self.x,
            y: -self.y,
            zero: self.zero,
        }
    }
}

/// A homogeneous projective point representing `(x/z, y/z)`.
#[derive(Copy, Clone, Debug)]
pub struct ProjectivePoint<C: Curve> {
    pub x: C::BaseField,
    pub y: C::BaseField,
    pub z: C::BaseField,
}

impl<C: Curve> ProjectivePoint<C> {
    pub const ZERO: Self = Self {
        x: C::BaseField::ZERO,
        y: C::BaseField::ONE,
        z: C::BaseField::ZERO,
    };

    pub fn nonzero(x: C::BaseField, y: C::BaseField, z: C::BaseField) -> Self {
        let point = Self { x, y, z };
        debug_assert!(point.is_valid());
        point
    }

    pub fn is_valid(&self) -> bool {
        self.z.is_zero()
            || self.y.square() * self.z
                == self.x.cube() + C::A * self.x * self.z.square() + C::B * self.z.cube()
    }

    pub fn to_affine(&self) -> AffinePoint<C> {
        if self.z.is_zero() {
            AffinePoint::ZERO
        } else {
            let z_inv = self.z.inverse();
            AffinePoint::nonzero(self.x * z_inv, self.y * z_inv)
        }
    }

    pub fn batch_to_affine(points: &[Self]) -> Vec<AffinePoint<C>> {
        let zs: Vec<_> = points.iter().map(|p| p.z).collect();
        let z_inverses = C::BaseField::batch_multiplicative_inverse(&zs);
        points
            .iter()
            .zip(z_inverses)
            .map(|(p, z_inv)| {
                if p.z.is_zero() {
                    AffinePoint::ZERO
                } else {
                    AffinePoint::nonzero(p.x * z_inv, p.y * z_inv)
                }
            })
            .collect()
    }

    /// EFD `dbl-2007-bl` homogeneous projective doubling formula.
    #[must_use]
    pub fn double(&self) -> Self {
        if self.z.is_zero() {
            return Self::ZERO;
        }
        let xx = self.x.square();
        let zz = self.z.square();
        let mut w = xx.triple();
        if C::A.is_nonzero() {
            w += C::A * zz;
        }
        let s = self.y.double() * self.z;
        let r = self.y * s;
        let rr = r.square();
        let b = (self.x + r).square() - (xx + rr);
        let h = w.square() - b.double();
        Self {
            x: h * s,
            y: w * (b - h) - rr.double(),
            z: s.cube(),
        }
    }

    pub fn add_slices(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b).map(|(&x, &y)| x + y).collect()
    }

    pub fn mul_precompute(&self) -> MultiplicationPrecomputation<C> {
        let mut powers = Vec::with_capacity(digits_per_scalar::<C>());
        powers.push(*self);
        for i in 1..digits_per_scalar::<C>() {
            let mut p = powers[i - 1];
            for _ in 0..HOST_WINDOW_BITS {
                p = p.double();
            }
            powers.push(p);
        }
        MultiplicationPrecomputation { powers }
    }

    #[must_use]
    pub fn mul_with_precomputation(
        &self,
        scalar: C::ScalarField,
        precomputation: MultiplicationPrecomputation<C>,
    ) -> Self {
        let digits = scalar_digits::<C>(&scalar);
        let mut y = Self::ZERO;
        let mut u = Self::ZERO;
        for j in (1..HOST_WINDOW_BASE).rev() {
            let sum = digits
                .iter()
                .enumerate()
                .filter(|(_, digit)| **digit == j as u64)
                .fold(Self::ZERO, |acc, (i, _)| acc + precomputation.powers[i]);
            u = u + sum;
            y = y + u;
        }
        y
    }
}

impl<C: Curve> PartialEq for ProjectivePoint<C> {
    fn eq(&self, other: &Self) -> bool {
        if self.z.is_zero() || other.z.is_zero() {
            self.z.is_zero() == other.z.is_zero()
        } else {
            self.x * other.z == other.x * self.z && self.y * other.z == other.y * self.z
        }
    }
}

impl<C: Curve> Eq for ProjectivePoint<C> {}

impl<C: Curve> Neg for ProjectivePoint<C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

/// EFD `add-1998-cmo-2` homogeneous projective addition formula.
impl<C: Curve> Add<ProjectivePoint<C>> for ProjectivePoint<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self.z.is_zero() {
            return rhs;
        }
        if rhs.z.is_zero() {
            return self;
        }
        let x1z2 = self.x * rhs.z;
        let y1z2 = self.y * rhs.z;
        let x2z1 = rhs.x * self.z;
        let y2z1 = rhs.y * self.z;
        if x1z2 == x2z1 {
            if y1z2 == y2z1 {
                return self.double();
            }
            if y1z2 == -y2z1 {
                return Self::ZERO;
            }
        }
        let z1z2 = self.z * rhs.z;
        let u = y2z1 - y1z2;
        let uu = u.square();
        let v = x2z1 - x1z2;
        let vv = v.square();
        let vvv = v * vv;
        let r = vv * x1z2;
        let a = uu * z1z2 - vvv - r.double();
        Self::nonzero(v * a, u * (r - a) - vvv * y1z2, vvv * z1z2)
    }
}

/// EFD `madd-1998-cmo` mixed projective/affine addition formula.
impl<C: Curve> Add<AffinePoint<C>> for ProjectivePoint<C> {
    type Output = Self;

    fn add(self, rhs: AffinePoint<C>) -> Self::Output {
        if self.z.is_zero() {
            return rhs.to_projective();
        }
        if rhs.zero {
            return self;
        }
        let x2z1 = rhs.x * self.z;
        let y2z1 = rhs.y * self.z;
        if self.x == x2z1 {
            if self.y == y2z1 {
                return self.double();
            }
            if self.y == -y2z1 {
                return Self::ZERO;
            }
        }
        let u = y2z1 - self.y;
        let uu = u.square();
        let v = x2z1 - self.x;
        let vv = v.square();
        let vvv = v * vv;
        let r = vv * self.x;
        let a = uu * self.z - vvv - r.double();
        Self::nonzero(v * a, u * (r - a) - vvv * self.y, vvv * self.z)
    }
}

/// EFD `mmadd-1998-cmo` affine/affine to projective addition formula.
impl<C: Curve> Add<AffinePoint<C>> for AffinePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.zero {
            return rhs.to_projective();
        }
        if rhs.zero {
            return self.to_projective();
        }
        if self.x == rhs.x {
            if self.y == rhs.y {
                return self.to_projective().double();
            }
            if self.y == -rhs.y {
                return ProjectivePoint::ZERO;
            }
        }
        let u = rhs.y - self.y;
        let uu = u.square();
        let v = rhs.x - self.x;
        let vv = v.square();
        let vvv = v * vv;
        let r = vv * self.x;
        let a = uu - vvv - r.double();
        ProjectivePoint::nonzero(v * a, u * (r - a) - vvv * self.y, vvv)
    }
}

const HOST_WINDOW_BITS: usize = 4;
const HOST_WINDOW_BASE: usize = 1 << HOST_WINDOW_BITS;

fn digits_per_scalar<C: Curve>() -> usize {
    C::ScalarField::BITS.div_ceil(HOST_WINDOW_BITS)
}

#[derive(Clone)]
pub struct MultiplicationPrecomputation<C: Curve> {
    powers: Vec<ProjectivePoint<C>>,
}

impl<C: Curve> Mul<ProjectivePoint<C>> for CurveScalar<C> {
    type Output = ProjectivePoint<C>;

    fn mul(self, rhs: ProjectivePoint<C>) -> Self::Output {
        rhs.mul_with_precomputation(self.0, rhs.mul_precompute())
    }
}

fn scalar_digits<C: Curve>(x: &C::ScalarField) -> Vec<u64> {
    let mut digits = Vec::with_capacity(digits_per_scalar::<C>());
    for limb in x.to_canonical_biguint().to_u64_digits() {
        for j in 0..(64 / HOST_WINDOW_BITS) {
            digits.push((limb >> (j * HOST_WINDOW_BITS)) % HOST_WINDOW_BASE as u64);
        }
    }
    digits.resize(digits_per_scalar::<C>(), 0);
    digits
}

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub struct Secp256K1;

impl Curve for Secp256K1 {
    type BaseField = Secp256K1Base;
    type ScalarField = Secp256K1Scalar;

    const A: Secp256K1Base = Secp256K1Base::ZERO;
    const B: Secp256K1Base = Secp256K1Base([7, 0, 0, 0]);
    const GENERATOR_AFFINE: AffinePoint<Self> = AffinePoint {
        x: Secp256K1Base([
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        ]),
        y: Secp256K1Base([
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ]),
        zero: false,
    };
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct LiftXError;

impl Display for LiftXError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("x does not lift to a secp256k1 point")
    }
}

impl std::error::Error for LiftXError {}

/// BIP-340 `lift_x`: return the secp256k1 point with this x and even canonical y.
pub fn lift_x_even_y(x: Secp256K1Base) -> Result<AffinePoint<Secp256K1>, LiftXError> {
    let rhs = x.cube() + Secp256K1::A * x + Secp256K1::B;
    let candidate = rhs.sqrt().ok_or(LiftXError)?;
    let odd = !(&candidate.to_canonical_biguint() & BigUint::one()).is_zero();
    let y = if odd { -candidate } else { candidate };
    Ok(AffinePoint::nonzero(x, y))
}

pub fn base_to_scalar<C: Curve>(x: C::BaseField) -> C::ScalarField {
    C::ScalarField::from_noncanonical_biguint(x.to_canonical_biguint())
}

pub fn scalar_to_base<C: Curve>(x: C::ScalarField) -> C::BaseField {
    C::BaseField::from_noncanonical_biguint(x.to_canonical_biguint())
}

pub const GLV_BETA: Secp256K1Base = Secp256K1Base([
    13923278643952681454,
    11308619431505398165,
    7954561588662645993,
    8856726876819556112,
]);

pub const GLV_S: Secp256K1Scalar = Secp256K1Scalar([
    16069571880186789234,
    1310022930574435960,
    11900229862571533402,
    6008836872998760672,
]);

const A1: Secp256K1Scalar = Secp256K1Scalar([16747920425669159701, 3496713202691238861, 0, 0]);
const MINUS_B1: Secp256K1Scalar =
    Secp256K1Scalar([8022177200260244675, 16448129721693014056, 0, 0]);
const A2: Secp256K1Scalar = Secp256K1Scalar([6323353552219852760, 1498098850674701302, 1, 0]);
const B2: Secp256K1Scalar = Secp256K1Scalar([16747920425669159701, 3496713202691238861, 0, 0]);

/// Decompose `k` as signed, at-most-128-bit `k1 + GLV_S * k2`.
pub fn decompose_secp256k1_scalar(
    k: Secp256K1Scalar,
) -> (Secp256K1Scalar, Secp256K1Scalar, bool, bool) {
    use num::rational::Ratio;

    let order = Secp256K1Scalar::order();
    let c1 = Secp256K1Scalar::from_noncanonical_biguint(
        Ratio::new(
            B2.to_canonical_biguint() * k.to_canonical_biguint(),
            order.clone(),
        )
        .round()
        .to_integer(),
    );
    let c2 = Secp256K1Scalar::from_noncanonical_biguint(
        Ratio::new(
            MINUS_B1.to_canonical_biguint() * k.to_canonical_biguint(),
            order.clone(),
        )
        .round()
        .to_integer(),
    );
    let k1_raw = k - c1 * A1 - c2 * A2;
    let k2_raw = c1 * MINUS_B1 - c2 * B2;
    debug_assert_eq!(k1_raw + GLV_S * k2_raw, k);

    let half = &order >> 1;
    let k1_neg = k1_raw.to_canonical_biguint() > half;
    let k2_neg = k2_raw.to_canonical_biguint() > half;
    let k1 = if k1_neg {
        Secp256K1Scalar::from_noncanonical_biguint(order.clone() - k1_raw.to_canonical_biguint())
    } else {
        k1_raw
    };
    let k2 = if k2_neg {
        Secp256K1Scalar::from_noncanonical_biguint(order - k2_raw.to_canonical_biguint())
    } else {
        k2_raw
    };
    (k1, k2, k1_neg, k2_neg)
}

/// Host GLV multiplication, implemented from the ported projective add and scalar mul.
pub fn host_glv_mul(
    p: ProjectivePoint<Secp256K1>,
    k: Secp256K1Scalar,
) -> ProjectivePoint<Secp256K1> {
    let (k1, k2, k1_neg, k2_neg) = decompose_secp256k1_scalar(k);
    let p_affine = p.to_affine();
    let psi = AffinePoint::<Secp256K1> {
        x: p_affine.x * GLV_BETA,
        y: p_affine.y,
        zero: p_affine.zero,
    }
    .to_projective();
    CurveScalar(k1) * if k1_neg { -p } else { p }
        + CurveScalar(k2) * if k2_neg { -psi } else { psi }
}
