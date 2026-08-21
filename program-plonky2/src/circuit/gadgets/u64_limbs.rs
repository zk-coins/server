//! Protocol-wide `u64` values as two range-checked little-endian `u32` limbs.
//!
//! Goldilocks has `p = 2^64 − 2^32 + 1 < 2^64`. A protocol size or position in
//! `0 … 2^64 − 1` therefore cannot live in a single field element without either
//! (a) an alias (`1` and `p + 1` share a residue) or (b) a narrowing canonicity
//! check that rejects every value in `p … 2^64 − 1`.
//!
//! The limbs **are** the representation: every comparison, subtraction, split-
//! point derivation, and byte encoding for hashing operates on the pair
//! `(lo, hi)` with `value = lo + hi · 2^32`. No intermediate packing into one
//! `Target` is performed for protocol arithmetic.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::u32_lib::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::u32_lib::gadgets::multiple_comparison::list_le_u32_circuit;

/// Little-endian two-limb encoding of a protocol `u64`.
///
/// `value = lo + hi · 2^32` with both limbs range-checked to 32 bits. That
/// packing is bijective onto `0 … 2^64 − 1`: collision-free and fully
/// representable.
#[derive(Clone, Copy, Debug)]
pub struct U64LimbsTarget {
    pub lo: Target,
    pub hi: Target,
}

impl U64LimbsTarget {
    /// Allocates a free protocol `u64` and range-checks both limbs.
    pub fn new_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let lo = builder.add_virtual_target();
        let hi = builder.add_virtual_target();
        builder.range_check(lo, 32);
        builder.range_check(hi, 32);
        Self { lo, hi }
    }

    /// Constant protocol `u64` (both limbs are circuit constants).
    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: u64,
    ) -> Self {
        Self {
            lo: builder.constant(F::from_canonical_u32(value as u32)),
            hi: builder.constant(F::from_canonical_u32((value >> 32) as u32)),
        }
    }

    pub fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, 0)
    }

    pub fn one<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, 1)
    }

    /// Little-endian bit decomposition. Each limb is already `< 2^32`, so
    /// `split_le(_, 32)` is injective — no field-order canonicity check.
    pub fn bits_le<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BoolTarget> {
        let lo_bits = builder.split_le(self.lo, 32);
        let hi_bits = builder.split_le(self.hi, 32);
        let mut bits = Vec::with_capacity(64);
        bits.extend(lo_bits);
        bits.extend(hi_bits);
        bits
    }

    /// Spec §1.7.6 / §2.5: `n` as an 8-byte big-endian byte string, derived
    /// from the limbs (MSB = high limb).
    pub fn to_be_bytes<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> [Target; 8] {
        let lo_bits = builder.split_le(self.lo, 32);
        let hi_bits = builder.split_le(self.hi, 32);
        std::array::from_fn(|i| {
            let (bits, byte_index) = if i < 4 {
                // High limb supplies the four most-significant bytes.
                (&hi_bits[..], 3 - i)
            } else {
                (&lo_bits[..], 3 - (i - 4))
            };
            let offset = byte_index * 8;
            builder.le_sum(bits[offset..offset + 8].iter())
        })
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) {
        builder.connect(self.lo, other.lo);
        builder.connect(self.hi, other.hi);
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) -> BoolTarget {
        let lo_eq = builder.is_equal(self.lo, other.lo);
        let hi_eq = builder.is_equal(self.hi, other.hi);
        builder.and(lo_eq, hi_eq)
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        cond: BoolTarget,
        x: Self,
        y: Self,
    ) -> Self {
        Self {
            lo: builder.select(cond, x.lo, y.lo),
            hi: builder.select(cond, x.hi, y.hi),
        }
    }

    /// Strict comparison `self < other` over the full `u64` domain.
    ///
    /// Uses little-endian limb order with the existing multi-limb ≤ gadget,
    /// then excludes equality.
    pub fn less_than<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) -> BoolTarget {
        let le = list_le_u32_circuit(
            builder,
            vec![U32Target(self.lo), U32Target(self.hi)],
            vec![U32Target(other.lo), U32Target(other.hi)],
        );
        let eq = self.is_equal(builder, other);
        let not_eq = builder.not(eq);
        builder.and(le, not_eq)
    }

    /// Limb subtraction `self − other` with free underflow (wrapping result).
    ///
    /// Inactive RFC-6962 levels may evaluate discarded right-branch
    /// differences that under the honest path would not arise; the borrow is
    /// therefore **not** asserted zero. Callers that need a non-wrapping sub
    /// must enforce `other ≤ self` separately (as inclusion/consistency do).
    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) -> Self {
        let zero_borrow = builder.zero_u32();
        let (diff_lo, borrow) =
            builder.sub_u32(U32Target(self.lo), U32Target(other.lo), zero_borrow);
        let (diff_hi, _borrow_hi) =
            builder.sub_u32(U32Target(self.hi), U32Target(other.hi), borrow);
        Self {
            lo: diff_lo.0,
            hi: diff_hi.0,
        }
    }

    /// `self + 1` with an explicit carry; rejects wrap past `u64::MAX`.
    pub fn add_one<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let one = builder.one_u32();
        let (sum_lo, carry) = builder.add_u32(U32Target(self.lo), one);
        let (sum_hi, carry_out) = builder.add_u32(U32Target(self.hi), carry);
        builder.assert_zero(carry_out.0);
        Self {
            lo: sum_lo.0,
            hi: sum_hi.0,
        }
    }

    /// Highest set bit of `self`, as its power-of-two value, still as limbs.
    ///
    /// Returns `0` when `self == 0`. Used for RFC-6962 `split_point(n) =
    /// 2^{floor(log2(n−1))}`.
    pub fn highest_set_bit_pow2<F: RichField + Extendable<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let bits = self.bits_le(builder);
        let mut any_higher = builder.constant_bool(false);
        let mut lo = builder.zero();
        let mut hi = builder.zero();
        for j in (0..64).rev() {
            let not_higher = builder.not(any_higher);
            let is_msb_j = builder.and(bits[j], not_higher);
            if j < 32 {
                lo = builder.mul_const_add(F::from_canonical_u64(1u64 << j), is_msb_j.target, lo);
            } else {
                hi = builder.mul_const_add(
                    F::from_canonical_u64(1u64 << (j - 32)),
                    is_msb_j.target,
                    hi,
                );
            }
            any_higher = builder.or(any_higher, bits[j]);
        }
        Self { lo, hi }
    }
}

/// Assign a host `u64` to a limb pair. Always uses `from_canonical_u32` so
/// values in `p … 2^64 − 1` are representable (unlike `from_canonical_u64`).
pub fn set_u64_limbs<F: RichField>(
    witness: &mut PartialWitness<F>,
    target: U64LimbsTarget,
    value: u64,
) -> anyhow::Result<()> {
    witness.set_target(target.lo, F::from_canonical_u32(value as u32))?;
    witness.set_target(target.hi, F::from_canonical_u32((value >> 32) as u32))?;
    Ok(())
}

/// Fallible-free variant for tests that already use `.expect`.
pub fn set_u64_limbs_unwrap<F: RichField>(
    witness: &mut PartialWitness<F>,
    target: U64LimbsTarget,
    value: u64,
) {
    witness
        .set_target(target.lo, F::from_canonical_u32(value as u32))
        .expect("u64 lo limb assignment");
    witness
        .set_target(target.hi, F::from_canonical_u32((value >> 32) as u32))
        .expect("u64 hi limb assignment");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{C, D, F};
    use plonky2::field::types::{Field, Field64};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;

    #[test]
    fn limbs_roundtrip_full_u64_domain_edges() {
        let edges = [
            0u64,
            1,
            (1u64 << 32) - 1,
            1u64 << 32,
            F::ORDER - 1,
            F::ORDER,
            F::ORDER + 1,
            u64::MAX,
        ];
        for &value in &edges {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let x = U64LimbsTarget::new_virtual(&mut builder);
            let c = U64LimbsTarget::constant(&mut builder, value);
            x.connect(&mut builder, c);
            builder.register_public_input(x.lo);
            builder.register_public_input(x.hi);
            let data = builder.build::<C>();
            let mut pw = PartialWitness::new();
            set_u64_limbs_unwrap(&mut pw, x, value);
            let proof = data.prove(pw).unwrap_or_else(|_| {
                panic!("limb assignment for {value:#x} must prove");
            });
            data.verify(proof).expect("verify");
        }
    }

    #[test]
    fn sub_and_less_than_across_p() {
        let p = F::ORDER;
        let cases = [
            (p - 1, p, true),
            (p, p - 1, false),
            (p + 1, p, false),
            (p, p + 1, true),
            (u64::MAX, p, false),
            (p, u64::MAX, true),
            (0, 1, true),
            (1, 0, false),
        ];
        for (a_val, b_val, a_lt_b) in cases {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let a = U64LimbsTarget::new_virtual(&mut builder);
            let b = U64LimbsTarget::new_virtual(&mut builder);
            let lt = a.less_than(&mut builder, b);
            if a_lt_b {
                builder.assert_one(lt.target);
            } else {
                builder.assert_zero(lt.target);
            }
            if a_val >= b_val {
                let diff = a.sub(&mut builder, b);
                let expected = U64LimbsTarget::constant(&mut builder, a_val - b_val);
                diff.connect(&mut builder, expected);
            }
            let data = builder.build::<C>();
            let mut pw = PartialWitness::new();
            set_u64_limbs_unwrap(&mut pw, a, a_val);
            set_u64_limbs_unwrap(&mut pw, b, b_val);
            let proof = data
                .prove(pw)
                .unwrap_or_else(|_| panic!("a={a_val:#x} b={b_val:#x} must prove"));
            data.verify(proof).expect("verify");
        }
    }

    #[test]
    fn add_one_rejects_u64_max() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let x = U64LimbsTarget::new_virtual(&mut builder);
        let _y = x.add_one(&mut builder);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        set_u64_limbs_unwrap(&mut pw, x, u64::MAX);
        assert!(
            data.prove(pw).is_err(),
            "send_counter wrap past u64::MAX must fail"
        );
    }

    #[test]
    fn be_bytes_match_host_to_be_bytes() {
        let values = [
            0u64,
            1,
            0x0102_0304_0506_0708,
            F::ORDER,
            F::ORDER + 1,
            u64::MAX,
        ];
        for &value in &values {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let x = U64LimbsTarget::new_virtual(&mut builder);
            let bytes = x.to_be_bytes(&mut builder);
            for b in bytes {
                builder.register_public_input(b);
            }
            let data = builder.build::<C>();
            let mut pw = PartialWitness::new();
            set_u64_limbs_unwrap(&mut pw, x, value);
            let proof = data.prove(pw).expect("prove");
            data.verify(proof.clone()).expect("verify");
            let host = value.to_be_bytes();
            for i in 0..8 {
                assert_eq!(
                    proof.public_inputs[i],
                    F::from_canonical_u8(host[i]),
                    "byte {i} of {value:#x}"
                );
            }
        }
    }
}
