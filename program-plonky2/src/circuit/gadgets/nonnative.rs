//! Canonical non-native arithmetic for the secp256k1 base and scalar fields.
//!
//! Values use eight little-endian, range-checked `u32` limbs. Every public
//! constructor and arithmetic result also enforces strict reduction modulo the
//! selected secp256k1 modulus. Multiplication proves the integer identity
//! `a * b = q * modulus + r` over exact 512-bit limb arrays; generators only
//! supply the quotient, remainder, and inverse witnesses.

use std::any::type_name;
use std::fmt::Debug;
use std::marker::PhantomData;

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

const LIMBS: usize = 8;
const WIDE_LIMBS: usize = 9;
const PRODUCT_LIMBS: usize = 16;
const LIMB_BITS: usize = 32;
const LIMB_BASE: u64 = 1u64 << LIMB_BITS;

/// Selects the foreign-field modulus used by a [`NonNativeTarget`].
pub trait NonNativeModulus: Clone + Copy + Debug + 'static {
    /// The modulus as eight little-endian 32-bit limbs.
    const MODULUS_LIMBS: [u32; LIMBS];
}

/// The secp256k1 base field `Fp`.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1Base;

impl NonNativeModulus for Secp256k1Base {
    const MODULUS_LIMBS: [u32; LIMBS] = [
        0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff,
    ];
}

/// The secp256k1 scalar field `Fn`.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1Scalar;

impl NonNativeModulus for Secp256k1Scalar {
    const MODULUS_LIMBS: [u32; LIMBS] = [
        0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe, 0xffffffff, 0xffffffff,
        0xffffffff,
    ];
}

/// A canonical foreign-field element represented by eight little-endian limbs.
///
/// Values returned by this module have every limb constrained to 32 bits and
/// the full 256-bit integer constrained to be strictly less than `M`'s modulus.
#[derive(Clone, Copy, Debug)]
pub struct NonNativeTarget<M: NonNativeModulus> {
    /// Limb 0 contains bits 0..31 and limb 7 contains bits 224..255.
    pub limbs: [Target; LIMBS],
    _marker: PhantomData<M>,
}

impl<M: NonNativeModulus> NonNativeTarget<M> {
    fn from_raw_limbs(limbs: [Target; LIMBS]) -> Self {
        Self {
            limbs,
            _marker: PhantomData,
        }
    }

    /// Registers a fresh canonical foreign-field witness.
    pub fn new_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let limbs = builder.add_virtual_target_arr();
        from_limbs_checked(builder, limbs)
    }

    /// Registers a compile-time constant in the canonical limb representation.
    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        limbs: [u32; LIMBS],
    ) -> Self {
        constant(builder, limbs)
    }
}

/// Registers a fresh canonical foreign-field witness.
pub fn new_virtual<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
) -> NonNativeTarget<M> {
    NonNativeTarget::new_virtual(builder)
}

/// Applies the canonical range constraint to existing little-endian limbs.
pub fn from_limbs_checked<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    limbs: [Target; LIMBS],
) -> NonNativeTarget<M> {
    // `split_le(limb, 32)` is both the exact u32 range check and the bit
    // decomposition consumed by the MSB-first strict comparison.
    let canonical = less_than_constant_limbs(builder, &limbs, &M::MODULUS_LIMBS);
    builder.assert_one(canonical.target);
    NonNativeTarget::from_raw_limbs(limbs)
}

/// Registers a compile-time canonical foreign-field constant.
pub fn constant<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    limbs: [u32; LIMBS],
) -> NonNativeTarget<M> {
    assert!(
        cmp_limbs(&limbs, &M::MODULUS_LIMBS).is_lt(),
        "non-native constant must be strictly smaller than its modulus"
    );
    let targets = limbs.map(|limb| builder.constant(F::from_canonical_u32(limb)));
    from_limbs_checked(builder, targets)
}

/// Exact strict comparison of little-endian u32 limbs against a constant.
///
/// The scan is lexicographic from the most-significant bit, matching the
/// comparison pattern used by `u128_arith::geq`.
fn less_than_constant_limbs<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &[Target; N],
    rhs: &[u32; N],
) -> BoolTarget {
    let mut lhs_bits = Vec::with_capacity(N * LIMB_BITS);
    for &limb in lhs {
        lhs_bits.extend(builder.split_le(limb, LIMB_BITS));
    }

    let mut equal_so_far = builder.constant_bool(true);
    let mut lhs_less = builder.constant_bool(false);
    for bit_index in (0..N * LIMB_BITS).rev() {
        let rhs_bit = builder
            .constant_bool(((rhs[bit_index / LIMB_BITS] >> (bit_index % LIMB_BITS)) & 1) == 1);
        let not_lhs = builder.not(lhs_bits[bit_index]);
        let less_at_bit = builder.and(not_lhs, rhs_bit);
        let first_difference_is_less = builder.and(equal_so_far, less_at_bit);
        lhs_less = builder.or(lhs_less, first_difference_is_less);

        let bits_equal = builder.is_equal(lhs_bits[bit_index].target, rhs_bit.target);
        equal_so_far = builder.and(equal_so_far, bits_equal);
    }
    lhs_less
}

/// Adds two 256-bit integers into an exact nine-limb representation.
fn add_256_wide<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &[Target; LIMBS],
    rhs: &[Target; LIMBS],
) -> [Target; WIDE_LIMBS] {
    let mut output = [builder.zero(); WIDE_LIMBS];
    let mut carry = builder.zero();
    for i in 0..LIMBS {
        builder.range_check(lhs[i], LIMB_BITS);
        builder.range_check(rhs[i], LIMB_BITS);
        let total = builder.add_many([lhs[i], rhs[i], carry]);

        // Two u32 limbs plus a carry bit are at most
        // 2 * (2^32 - 1) + 1 = 2^33 - 1, exactly 33 bits and far below
        // the Goldilocks modulus.
        let bits = builder.split_le(total, 33);
        output[i] = builder.le_sum(bits[..LIMB_BITS].iter());
        builder.range_check(output[i], LIMB_BITS);
        carry = bits[LIMB_BITS].target;
    }
    output[LIMBS] = carry;
    output
}

/// Subtracts equal-width limb arrays and returns `(difference, borrow_out)`.
fn sub_limbs<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &[Target; N],
    rhs: &[Target; N],
) -> ([Target; N], BoolTarget) {
    let mut output = [builder.zero(); N];
    let mut borrow = builder.constant_bool(false);
    let base = F::from_canonical_u64(LIMB_BASE);

    for i in 0..N {
        builder.range_check(lhs[i], LIMB_BITS);
        builder.range_check(rhs[i], LIMB_BITS);
        let with_base = builder.add_const(lhs[i], base);
        let minus_rhs = builder.sub(with_base, rhs[i]);
        let total = builder.sub(minus_rhs, borrow.target);

        // 2^32 + lhs - rhs - borrow is always in 0..=2^33-1. It is
        // nonnegative before entering the native field, so the 33-bit split
        // is an exact integer equation rather than a wrapped subtraction.
        let bits = builder.split_le(total, 33);
        output[i] = builder.le_sum(bits[..LIMB_BITS].iter());
        builder.range_check(output[i], LIMB_BITS);
        // The high bit is one exactly when this limb did not borrow.
        borrow = builder.not(bits[LIMB_BITS]);
    }
    (output, borrow)
}

/// Reduces a value known to be below twice the modulus by one conditional
/// subtraction.
fn reduce_once<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    wide: &[Target; WIDE_LIMBS],
) -> NonNativeTarget<M> {
    let modulus_wide = [
        M::MODULUS_LIMBS[0],
        M::MODULUS_LIMBS[1],
        M::MODULUS_LIMBS[2],
        M::MODULUS_LIMBS[3],
        M::MODULUS_LIMBS[4],
        M::MODULUS_LIMBS[5],
        M::MODULUS_LIMBS[6],
        M::MODULUS_LIMBS[7],
        0,
    ];
    let below_modulus = less_than_constant_limbs(builder, wide, &modulus_wide);
    let subtract_modulus = builder.not(below_modulus);
    let selected_modulus = std::array::from_fn(|i| {
        builder.mul_const(
            F::from_canonical_u32(modulus_wide[i]),
            subtract_modulus.target,
        )
    });
    let (reduced_wide, borrow) = sub_limbs(builder, wide, &selected_modulus);
    builder.assert_zero(borrow.target);
    builder.assert_zero(reduced_wide[LIMBS]);

    let reduced = std::array::from_fn(|i| reduced_wide[i]);
    from_limbs_checked(builder, reduced)
}

/// Computes `(a + b) mod M`.
pub fn add_mod<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
    b: &NonNativeTarget<M>,
) -> NonNativeTarget<M> {
    let sum = add_256_wide(builder, &a.limbs, &b.limbs);
    reduce_once(builder, &sum)
}

/// Computes `(a - b) mod M`.
pub fn sub_mod<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
    b: &NonNativeTarget<M>,
) -> NonNativeTarget<M> {
    let modulus_targets =
        M::MODULUS_LIMBS.map(|limb| builder.constant(F::from_canonical_u32(limb)));
    let a_plus_modulus = add_256_wide(builder, &a.limbs, &modulus_targets);
    let b_wide = [
        b.limbs[0],
        b.limbs[1],
        b.limbs[2],
        b.limbs[3],
        b.limbs[4],
        b.limbs[5],
        b.limbs[6],
        b.limbs[7],
        builder.zero(),
    ];
    let (unreduced, borrow) = sub_limbs(builder, &a_plus_modulus, &b_wide);
    // Canonical b is strictly below the modulus, so a + modulus - b >= 1.
    builder.assert_zero(borrow.target);
    reduce_once(builder, &unreduced)
}

/// Splits one exact u32 product into its low and high u32 halves.
fn mul_u32_exact<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
) -> (Target, Target) {
    builder.range_check(x, LIMB_BITS);
    builder.range_check(y, LIMB_BITS);
    let product = builder.mul(x, y);

    // (2^32 - 1)^2 = 2^64 - 2^33 + 1, which is strictly below the
    // Goldilocks prime 2^64 - 2^32 + 1. Thus the native multiplication
    // itself cannot wrap. A 64-bit split over Goldilocks could otherwise
    // represent a small value plus the native modulus, so we additionally
    // constrain its bit pattern to the canonical interval below that prime.
    let bits = builder.split_le(product, 64);
    let goldilocks_limbs = [1u32, 0xffff_ffff];
    let product_limbs = [
        builder.le_sum(bits[..LIMB_BITS].iter()),
        builder.le_sum(bits[LIMB_BITS..].iter()),
    ];
    let canonical_product = less_than_constant_limbs(builder, &product_limbs, &goldilocks_limbs);
    builder.assert_one(canonical_product.target);
    builder.range_check(product_limbs[0], LIMB_BITS);
    builder.range_check(product_limbs[1], LIMB_BITS);
    (product_limbs[0], product_limbs[1])
}

/// Computes an exact 512-bit schoolbook product.
fn product_256<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &[Target; LIMBS],
    rhs: &[Target; LIMBS],
) -> [Target; PRODUCT_LIMBS] {
    let mut columns: [Vec<Target>; PRODUCT_LIMBS] = std::array::from_fn(|_| Vec::new());
    for i in 0..LIMBS {
        for j in 0..LIMBS {
            let (low, high) = mul_u32_exact(builder, lhs[i], rhs[j]);
            columns[i + j].push(low);
            columns[i + j + 1].push(high);
        }
    }

    let mut output = [builder.zero(); PRODUCT_LIMBS];
    let mut carry = builder.zero();
    for column in 0..PRODUCT_LIMBS {
        let mut summands = columns[column].clone();
        summands.push(carry);
        let total = builder.add_many(summands);

        // A schoolbook column has at most 15 u32 half-products. Inductively,
        // its incoming carry is at most 14, so the total is at most
        // 15 * (2^32 - 1) + 14 = 15 * 2^32 - 1 < 2^36. The 36-bit split is
        // therefore exact and comfortably below the Goldilocks modulus.
        let bits = builder.split_le(total, 36);
        output[column] = builder.le_sum(bits[..LIMB_BITS].iter());
        builder.range_check(output[column], LIMB_BITS);
        carry = builder.le_sum(bits[LIMB_BITS..].iter());
        builder.range_check(carry, 4);
    }
    // Both inputs are below 2^256, so their product is below 2^512.
    builder.assert_zero(carry);
    output
}

/// Adds a 256-bit value to a 512-bit value without discarding overflow.
fn add_256_to_512<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    wide: &[Target; PRODUCT_LIMBS],
    addend: &[Target; LIMBS],
) -> [Target; PRODUCT_LIMBS] {
    let mut output = [builder.zero(); PRODUCT_LIMBS];
    let mut carry = builder.zero();
    for i in 0..PRODUCT_LIMBS {
        builder.range_check(wide[i], LIMB_BITS);
        let rhs = if i < LIMBS {
            builder.range_check(addend[i], LIMB_BITS);
            addend[i]
        } else {
            builder.zero()
        };
        let total = builder.add_many([wide[i], rhs, carry]);

        // Two u32 limbs and one carry bit fit exactly in 33 bits:
        // 2 * (2^32 - 1) + 1 = 2^33 - 1.
        let bits = builder.split_le(total, 33);
        output[i] = builder.le_sum(bits[..LIMB_BITS].iter());
        builder.range_check(output[i], LIMB_BITS);
        carry = bits[LIMB_BITS].target;
    }
    // q < modulus and r < modulus imply q * modulus + r < modulus^2 < 2^512.
    builder.assert_zero(carry);
    output
}

/// Constrains `a * b = q * modulus + r` as an exact 512-bit integer identity.
pub(crate) fn assert_product_reduction<
    F: RichField + Extendable<D>,
    const D: usize,
    M: NonNativeModulus,
>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
    b: &NonNativeTarget<M>,
    q: &NonNativeTarget<M>,
    r: &NonNativeTarget<M>,
) {
    let actual = product_256(builder, &a.limbs, &b.limbs);
    let modulus = M::MODULUS_LIMBS.map(|limb| builder.constant(F::from_canonical_u32(limb)));
    let q_times_modulus = product_256(builder, &q.limbs, &modulus);
    let claimed = add_256_to_512(builder, &q_times_modulus, &r.limbs);
    for i in 0..PRODUCT_LIMBS {
        builder.connect(actual[i], claimed[i]);
    }
}

/// Computes `(a * b) mod M`, witnessing and then constraining quotient and remainder.
pub fn mul_mod<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
    b: &NonNativeTarget<M>,
) -> NonNativeTarget<M> {
    let q = NonNativeTarget::<M>::new_virtual(builder);
    let r = NonNativeTarget::<M>::new_virtual(builder);
    builder.add_simple_generator(MulReductionGenerator::<M> {
        a: a.limbs,
        b: b.limbs,
        q: q.limbs,
        r: r.limbs,
        _marker: PhantomData,
    });
    assert_product_reduction(builder, a, b, &q, &r);
    r
}

/// Computes the multiplicative inverse modulo `M`.
///
/// The inverse is witnessed by Fermat exponentiation and verified by a fully
/// constrained modular multiplication. A zero input makes witness generation
/// panic rather than producing a meaningless value.
pub fn inverse_mod<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
) -> NonNativeTarget<M> {
    let inverse = NonNativeTarget::<M>::new_virtual(builder);
    builder.add_simple_generator(InverseGenerator::<M> {
        a: a.limbs,
        inverse: inverse.limbs,
        _marker: PhantomData,
    });

    let product = mul_mod(builder, a, &inverse);
    let one = constant::<F, D, M>(builder, [1, 0, 0, 0, 0, 0, 0, 0]);
    for i in 0..LIMBS {
        builder.connect(product.limbs[i], one.limbs[i]);
    }
    inverse
}

/// Returns one exactly when all canonical limbs of `a` are zero.
pub fn is_zero<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
) -> BoolTarget {
    let zero = builder.zero();
    let mut result = builder.constant_bool(true);
    for &limb in &a.limbs {
        let limb_is_zero = builder.is_equal(limb, zero);
        result = builder.and(result, limb_is_zero);
    }
    result
}

/// Returns one exactly when two canonical foreign-field values are equal.
pub fn equal<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<M>,
    b: &NonNativeTarget<M>,
) -> BoolTarget {
    let mut result = builder.constant_bool(true);
    for i in 0..LIMBS {
        let limbs_equal = builder.is_equal(a.limbs[i], b.limbs[i]);
        result = builder.and(result, limbs_equal);
    }
    result
}

#[derive(Debug)]
struct MulReductionGenerator<M: NonNativeModulus> {
    a: [Target; LIMBS],
    b: [Target; LIMBS],
    q: [Target; LIMBS],
    r: [Target; LIMBS],
    _marker: PhantomData<fn() -> M>,
}

impl<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus> SimpleGenerator<F, D>
    for MulReductionGenerator<M>
{
    fn id(&self) -> String {
        format!("MulReductionGenerator<{}>", type_name::<M>())
    }

    fn dependencies(&self) -> Vec<Target> {
        self.a.into_iter().chain(self.b).collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let a = read_u32_limbs(witness, &self.a, "mul_mod left input");
        let b = read_u32_limbs(witness, &self.b, "mul_mod right input");
        assert!(
            cmp_limbs(&a, &M::MODULUS_LIMBS).is_lt(),
            "mul_mod generator received a non-canonical left input"
        );
        assert!(
            cmp_limbs(&b, &M::MODULUS_LIMBS).is_lt(),
            "mul_mod generator received a non-canonical right input"
        );
        let product = mul_256_host(&a, &b);
        let (q, r) = div_rem_512_by_256(&product, &M::MODULUS_LIMBS);
        assert!(
            cmp_limbs(&q, &M::MODULUS_LIMBS).is_lt(),
            "mul_mod quotient unexpectedly exceeded the modulus"
        );
        write_u32_limbs(out_buffer, &self.q, &q)?;
        write_u32_limbs(out_buffer, &self.r, &r)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target_array(&self.a)?;
        dst.write_target_array(&self.b)?;
        dst.write_target_array(&self.q)?;
        dst.write_target_array(&self.r)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            a: src.read_target_array()?,
            b: src.read_target_array()?,
            q: src.read_target_array()?,
            r: src.read_target_array()?,
            _marker: PhantomData,
        })
    }
}

#[derive(Debug)]
struct InverseGenerator<M: NonNativeModulus> {
    a: [Target; LIMBS],
    inverse: [Target; LIMBS],
    _marker: PhantomData<fn() -> M>,
}

impl<F: RichField + Extendable<D>, const D: usize, M: NonNativeModulus> SimpleGenerator<F, D>
    for InverseGenerator<M>
{
    fn id(&self) -> String {
        format!("InverseGenerator<{}>", type_name::<M>())
    }

    fn dependencies(&self) -> Vec<Target> {
        self.a.to_vec()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let a = read_u32_limbs(witness, &self.a, "inverse_mod input");
        assert!(
            cmp_limbs(&a, &M::MODULUS_LIMBS).is_lt(),
            "inverse_mod generator received a non-canonical input"
        );
        assert!(
            a.iter().any(|&limb| limb != 0),
            "inverse_mod has no inverse for zero"
        );

        let exponent = sub_small(M::MODULUS_LIMBS, 2);
        let inverse = pow_mod_host(a, exponent, M::MODULUS_LIMBS);
        let check = mul_mod_host(&a, &inverse, &M::MODULUS_LIMBS);
        assert_eq!(
            check,
            [1, 0, 0, 0, 0, 0, 0, 0],
            "inverse_mod generator produced an invalid inverse"
        );
        write_u32_limbs(out_buffer, &self.inverse, &inverse)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target_array(&self.a)?;
        dst.write_target_array(&self.inverse)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            a: src.read_target_array()?,
            inverse: src.read_target_array()?,
            _marker: PhantomData,
        })
    }
}

fn read_u32_limbs<F: PrimeField64>(
    witness: &impl Witness<F>,
    targets: &[Target; LIMBS],
    context: &str,
) -> [u32; LIMBS] {
    std::array::from_fn(|i| {
        let value = witness.get_target(targets[i]).to_canonical_u64();
        assert!(
            value <= u32::MAX as u64,
            "{context} limb {i} is not a u32: {value}"
        );
        value as u32
    })
}

fn write_u32_limbs<F: Field>(
    out_buffer: &mut GeneratedValues<F>,
    targets: &[Target; LIMBS],
    limbs: &[u32; LIMBS],
) -> Result<()> {
    for i in 0..LIMBS {
        out_buffer.set_target(targets[i], F::from_canonical_u32(limbs[i]))?;
    }
    Ok(())
}

fn cmp_limbs<const N: usize>(lhs: &[u32; N], rhs: &[u32; N]) -> std::cmp::Ordering {
    for i in (0..N).rev() {
        match lhs[i].cmp(&rhs[i]) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

/// Dependency-free exact 256-by-256-bit schoolbook multiplication.
fn mul_256_host(lhs: &[u32; LIMBS], rhs: &[u32; LIMBS]) -> [u32; PRODUCT_LIMBS] {
    let mut output = [0u32; PRODUCT_LIMBS];
    for i in 0..LIMBS {
        let mut carry = 0u64;
        for j in 0..LIMBS {
            let k = i + j;
            let total = output[k] as u128 + lhs[i] as u128 * rhs[j] as u128 + carry as u128;
            output[k] = total as u32;
            carry = (total >> LIMB_BITS) as u64;
        }
        assert_eq!(
            output[i + LIMBS],
            0,
            "host schoolbook multiplication carry slot was already occupied"
        );
        output[i + LIMBS] = carry as u32;
    }
    output
}

fn geq_9(lhs: &[u32; WIDE_LIMBS], modulus: &[u32; LIMBS]) -> bool {
    if lhs[LIMBS] != 0 {
        return true;
    }
    cmp_limbs(&std::array::from_fn::<_, LIMBS, _>(|i| lhs[i]), modulus).is_ge()
}

fn sub_modulus_9(value: &mut [u32; WIDE_LIMBS], modulus: &[u32; LIMBS]) {
    let mut borrow = 0u64;
    for i in 0..WIDE_LIMBS {
        let rhs = if i < LIMBS { modulus[i] as u64 } else { 0 };
        let subtrahend = rhs + borrow;
        let lhs = value[i] as u64;
        if lhs >= subtrahend {
            value[i] = (lhs - subtrahend) as u32;
            borrow = 0;
        } else {
            value[i] = (LIMB_BASE + lhs - subtrahend) as u32;
            borrow = 1;
        }
    }
    assert_eq!(borrow, 0, "host long division subtraction underflowed");
}

/// Bit-serial 512-by-256 division. The running remainder has a ninth limb so
/// shifting a value below the modulus never loses its possible 257th bit.
fn div_rem_512_by_256(
    numerator: &[u32; PRODUCT_LIMBS],
    modulus: &[u32; LIMBS],
) -> ([u32; LIMBS], [u32; LIMBS]) {
    assert!(
        modulus[LIMBS - 1] >> 31 == 1,
        "host long division expects a full-width 256-bit modulus"
    );
    let mut quotient = [0u32; LIMBS];
    let mut remainder = [0u32; WIDE_LIMBS];

    for bit_index in (0..PRODUCT_LIMBS * LIMB_BITS).rev() {
        let mut incoming =
            ((numerator[bit_index / LIMB_BITS] >> (bit_index % LIMB_BITS)) & 1) as u64;
        for limb in &mut remainder {
            let shifted = (*limb as u64) * 2 + incoming;
            *limb = shifted as u32;
            incoming = shifted >> LIMB_BITS;
        }
        assert_eq!(
            incoming, 0,
            "host long division remainder exceeded 288 bits"
        );

        if geq_9(&remainder, modulus) {
            sub_modulus_9(&mut remainder, modulus);
            assert!(
                bit_index < LIMBS * LIMB_BITS,
                "host long division quotient exceeded 256 bits"
            );
            quotient[bit_index / LIMB_BITS] |= 1u32 << (bit_index % LIMB_BITS);
        }
    }

    assert_eq!(
        remainder[LIMBS], 0,
        "host long division retained a 257th remainder bit"
    );
    let remainder_256 = std::array::from_fn(|i| remainder[i]);
    assert!(
        cmp_limbs(&remainder_256, modulus).is_lt(),
        "host long division produced a non-canonical remainder"
    );

    let recomposed_product = mul_256_host(&quotient, modulus);
    let recomposed_product = add_host_256_to_512(recomposed_product, &remainder_256);
    assert_eq!(
        &recomposed_product, numerator,
        "host long division failed quotient/remainder recomposition"
    );
    (quotient, remainder_256)
}

fn add_host_256_to_512(
    mut wide: [u32; PRODUCT_LIMBS],
    addend: &[u32; LIMBS],
) -> [u32; PRODUCT_LIMBS] {
    let mut carry = 0u64;
    for i in 0..PRODUCT_LIMBS {
        let rhs = if i < LIMBS { addend[i] as u64 } else { 0 };
        let total = wide[i] as u64 + rhs + carry;
        wide[i] = total as u32;
        carry = total >> LIMB_BITS;
    }
    assert_eq!(carry, 0, "host 512-bit addition overflowed");
    wide
}

fn mul_mod_host(lhs: &[u32; LIMBS], rhs: &[u32; LIMBS], modulus: &[u32; LIMBS]) -> [u32; LIMBS] {
    let product = mul_256_host(lhs, rhs);
    div_rem_512_by_256(&product, modulus).1
}

fn sub_small(mut value: [u32; LIMBS], amount: u32) -> [u32; LIMBS] {
    let (low, mut borrow) = value[0].overflowing_sub(amount);
    value[0] = low;
    for limb in value.iter_mut().skip(1) {
        if !borrow {
            break;
        }
        let (next, next_borrow) = limb.overflowing_sub(1);
        *limb = next;
        borrow = next_borrow;
    }
    assert!(!borrow, "host small subtraction underflowed");
    value
}

fn pow_mod_host(base: [u32; LIMBS], exponent: [u32; LIMBS], modulus: [u32; LIMBS]) -> [u32; LIMBS] {
    let mut result = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut power = base;
    for bit_index in 0..LIMBS * LIMB_BITS {
        if ((exponent[bit_index / LIMB_BITS] >> (bit_index % LIMB_BITS)) & 1) == 1 {
            result = mul_mod_host(&result, &power, &modulus);
        }
        if bit_index + 1 != LIMBS * LIMB_BITS {
            power = mul_mod_host(&power, &power, &modulus);
        }
    }
    result
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{C, D, F};
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    fn biguint_from_limbs(limbs: &[u32; LIMBS]) -> BigUint {
        let mut bytes = Vec::with_capacity(32);
        for limb in limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    fn limbs_from_biguint(value: &BigUint) -> [u32; LIMBS] {
        let digits = value.to_u32_digits();
        assert!(digits.len() <= LIMBS);
        std::array::from_fn(|i| digits.get(i).copied().unwrap_or(0))
    }

    fn set_target<M: NonNativeModulus>(
        witness: &mut PartialWitness<F>,
        target: NonNativeTarget<M>,
        value: &BigUint,
    ) {
        let limbs = limbs_from_biguint(value);
        for i in 0..LIMBS {
            witness
                .set_target(target.limbs[i], F::from_canonical_u32(limbs[i]))
                .unwrap();
        }
    }

    fn outputs_as_biguint(public_inputs: &[F]) -> Vec<BigUint> {
        public_inputs
            .chunks_exact(LIMBS)
            .map(|chunk| {
                let limbs: [u32; LIMBS] =
                    std::array::from_fn(|i| u32::try_from(chunk[i].to_canonical_u64()).unwrap());
                biguint_from_limbs(&limbs)
            })
            .collect()
    }

    fn arithmetic_cases<M: NonNativeModulus>() {
        let modulus = biguint_from_limbs(&M::MODULUS_LIMBS);
        let one = BigUint::one();
        let m1 = &modulus - &one;
        let m2 = &modulus - BigUint::from(2u32);
        let mid_a = BigUint::from_bytes_be(&[
            0x42, 0x11, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ]);
        let mid_b = BigUint::from_bytes_be(&[
            0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab,
        ]);
        let cases = vec![
            (BigUint::zero(), BigUint::zero()),
            (one.clone(), m1.clone()),
            (m1.clone(), m2.clone()),
            (m2, one),
            (mid_a, mid_b),
        ];

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut witness = PartialWitness::new();
        let mut expected = Vec::new();
        for (a_value, b_value) in cases {
            let a = NonNativeTarget::<M>::new_virtual(&mut builder);
            let b = NonNativeTarget::<M>::new_virtual(&mut builder);
            set_target(&mut witness, a, &a_value);
            set_target(&mut witness, b, &b_value);

            let sum = add_mod(&mut builder, &a, &b);
            let difference = sub_mod(&mut builder, &a, &b);
            let product = mul_mod(&mut builder, &a, &b);
            builder.register_public_inputs(&sum.limbs);
            builder.register_public_inputs(&difference.limbs);
            builder.register_public_inputs(&product.limbs);

            expected.push((&a_value + &b_value) % &modulus);
            expected.push((&a_value + &modulus - &b_value) % &modulus);
            expected.push((&a_value * &b_value) % &modulus);
        }

        let data = builder.build::<C>();
        let proof = data
            .prove(witness)
            .expect("valid non-native arithmetic witness must prove");
        assert_eq!(outputs_as_biguint(&proof.public_inputs), expected);
        data.verify(proof)
            .expect("valid non-native arithmetic proof must verify");
    }

    #[test]
    fn fp_arithmetic_matches_num_bigint() {
        arithmetic_cases::<Secp256k1Base>();
    }

    #[test]
    fn fn_arithmetic_matches_num_bigint() {
        arithmetic_cases::<Secp256k1Scalar>();
    }

    fn inverse_cases<M: NonNativeModulus>() {
        let modulus = biguint_from_limbs(&M::MODULUS_LIMBS);
        let one = BigUint::one();
        let values = [
            one.clone(),
            &modulus - &one,
            BigUint::from_bytes_be(&[
                0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                0x80, 0x90,
            ]),
        ];
        let exponent = &modulus - BigUint::from(2u32);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut witness = PartialWitness::new();
        let mut expected = Vec::new();
        for value in values {
            let a = NonNativeTarget::<M>::new_virtual(&mut builder);
            set_target(&mut witness, a, &value);
            // `inverse_mod` internally constrains this exact product to one.
            let inverse = inverse_mod(&mut builder, &a);
            builder.register_public_inputs(&inverse.limbs);
            expected.push(value.modpow(&exponent, &modulus));
        }

        let data = builder.build::<C>();
        let proof = data
            .prove(witness)
            .expect("valid non-native inverse witness must prove");
        assert_eq!(outputs_as_biguint(&proof.public_inputs), expected);
        data.verify(proof)
            .expect("valid non-native inverse proof must verify");
    }

    #[test]
    fn fp_inverse_matches_num_bigint() {
        inverse_cases::<Secp256k1Base>();
    }

    #[test]
    fn fn_inverse_matches_num_bigint() {
        inverse_cases::<Secp256k1Scalar>();
    }

    fn rejects_noncanonical<M: NonNativeModulus>() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let value = NonNativeTarget::<M>::new_virtual(&mut builder);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for i in 0..LIMBS {
            witness
                .set_target(value.limbs[i], F::from_canonical_u32(M::MODULUS_LIMBS[i]))
                .unwrap();
        }
        assert!(
            data.prove(witness).is_err(),
            "the modulus itself must not be accepted as canonical"
        );
    }

    #[test]
    fn fp_rejects_noncanonical_witness() {
        rejects_noncanonical::<Secp256k1Base>();
    }

    #[test]
    fn fn_rejects_noncanonical_witness() {
        rejects_noncanonical::<Secp256k1Scalar>();
    }

    fn rejects_wrong_reduction<M: NonNativeModulus>() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a = constant::<F, D, M>(&mut builder, [7, 0, 0, 0, 0, 0, 0, 0]);
        let b = constant::<F, D, M>(&mut builder, [9, 0, 0, 0, 0, 0, 0, 0]);
        let q = NonNativeTarget::<M>::new_virtual(&mut builder);
        let r = NonNativeTarget::<M>::new_virtual(&mut builder);
        assert_product_reduction(&mut builder, &a, &b, &q, &r);
        let data = builder.build::<C>();

        let mut witness = PartialWitness::new();
        set_target(&mut witness, q, &BigUint::zero());
        set_target(&mut witness, r, &BigUint::from(62u32));
        assert!(
            data.prove(witness).is_err(),
            "a canonical but incorrect quotient/remainder pair must fail"
        );
    }

    #[test]
    fn fp_rejects_wrong_product_reduction() {
        rejects_wrong_reduction::<Secp256k1Base>();
    }

    #[test]
    fn fn_rejects_wrong_product_reduction() {
        rejects_wrong_reduction::<Secp256k1Scalar>();
    }
}
