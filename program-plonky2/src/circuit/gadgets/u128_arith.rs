//! Exact wide arithmetic for protocol `u128` amounts.
//!
//! Public amount limbs follow the specification's little-endian limb order.
//! Wide sums use five 32-bit limbs (160 bits), comfortably exceeding the
//! normative 132-bit minimum. All addition constraints operate on values of
//! at most 35 bits, well below the Goldilocks modulus, so field wraparound
//! cannot mimic an integer carry.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Number of 32-bit limbs in the wide accumulator.
pub const WIDE_LIMBS: usize = 5;

/// A `u128` represented by four little-endian, range-checked `u32` limbs.
#[derive(Clone, Copy, Debug)]
pub struct U128Target {
    /// Limb 0 contains bits 0..31 and limb 3 contains bits 96..127.
    pub limbs: [Target; 4],
}

impl U128Target {
    /// Registers a fresh `u128` witness and constrains every limb to `< 2^32`.
    pub fn new_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let limbs = builder.add_virtual_target_arr();
        for limb in limbs {
            builder.range_check(limb, 32);
        }
        Self { limbs }
    }
}

/// A 160-bit non-negative integer as five little-endian `u32` limbs.
///
/// The representation has 28 more bits than the specification's required
/// 132-bit balance width. Values returned by [`accumulate`] are exact sums of
/// at most eight `u128` terms and therefore use at most 131 of these bits.
#[derive(Clone, Copy, Debug)]
pub struct WideSum {
    /// Five little-endian, range-checked 32-bit limbs.
    pub limbs: [Target; WIDE_LIMBS],
}

impl WideSum {
    /// Promotes a `u128` into the 160-bit representation without changing it.
    pub fn from_u128<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &U128Target,
    ) -> Self {
        for limb in value.limbs {
            builder.range_check(limb, 32);
        }
        let zero = builder.zero();
        Self {
            limbs: [
                value.limbs[0],
                value.limbs[1],
                value.limbs[2],
                value.limbs[3],
                zero,
            ],
        }
    }
}

/// Sums at most eight `u128` terms exactly into a 160-bit accumulator.
///
/// Carries are propagated across all four source limbs into the fifth limb.
/// No reduction modulo `2^128` occurs.
pub fn accumulate<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    terms: &[U128Target],
) -> WideSum {
    assert!(
        terms.len() <= 8,
        "wide u128 accumulation supports at most eight terms"
    );

    // Re-check at the consumption boundary so even a manually constructed
    // public U128Target cannot introduce an unconstrained limb.
    for term in terms {
        for limb in term.limbs {
            builder.range_check(limb, 32);
        }
    }

    let mut output = [builder.zero(); WIDE_LIMBS];
    let mut carry = builder.zero();
    for limb_index in 0..4 {
        let mut summands = Vec::with_capacity(terms.len() + 1);
        summands.push(carry);
        summands.extend(terms.iter().map(|term| term.limbs[limb_index]));
        let total = builder.add_many(summands);

        // Eight u32 limbs plus a carry in 0..=7 fit exactly in 35 bits:
        // 8 * (2^32 - 1) + 7 = 2^35 - 1.
        let bits = builder.split_le(total, 35);
        let limb = builder.le_sum(bits[..32].iter());
        builder.range_check(limb, 32);
        output[limb_index] = limb;

        carry = builder.le_sum(bits[32..].iter());
        builder.range_check(carry, 3);
    }
    // The terminal carry is retained, rather than discarded at 128 bits.
    builder.range_check(carry, 32);
    output[4] = carry;

    WideSum { limbs: output }
}

/// Adds two 160-bit values exactly, making `In + Mint` composition convenient.
///
/// A carry beyond bit 159 is constrained to zero, so this function never
/// silently wraps at the chosen wide width. Protocol balance sums are at most
/// 132 bits and therefore cannot approach this bound.
pub fn add_wide<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &WideSum,
    rhs: &WideSum,
) -> WideSum {
    let mut output = [builder.zero(); WIDE_LIMBS];
    let mut carry = builder.zero();

    for i in 0..WIDE_LIMBS {
        builder.range_check(lhs.limbs[i], 32);
        builder.range_check(rhs.limbs[i], 32);
        let total = builder.add_many([lhs.limbs[i], rhs.limbs[i], carry]);
        let bits = builder.split_le(total, 33);
        let limb = builder.le_sum(bits[..32].iter());
        builder.range_check(limb, 32);
        output[i] = limb;
        carry = bits[32].target;
    }
    builder.assert_zero(carry);

    WideSum { limbs: output }
}

/// Exact `lhs >= rhs` over the full 160-bit wide representation.
///
/// Both operands are range-checked limb-by-limb before a most-significant-bit
/// lexicographic comparison. The result is a constrained Boolean target.
pub fn geq<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &WideSum,
    rhs: &WideSum,
) -> BoolTarget {
    let mut lhs_bits = Vec::with_capacity(WIDE_LIMBS * 32);
    let mut rhs_bits = Vec::with_capacity(WIDE_LIMBS * 32);
    for i in 0..WIDE_LIMBS {
        lhs_bits.extend(builder.split_le(lhs.limbs[i], 32));
        rhs_bits.extend(builder.split_le(rhs.limbs[i], 32));
    }

    let mut equal = builder.constant_bool(true);
    let mut greater = builder.constant_bool(false);
    for i in (0..WIDE_LIMBS * 32).rev() {
        let not_rhs = builder.not(rhs_bits[i]);
        let lhs_greater_at_bit = builder.and(lhs_bits[i], not_rhs);
        let first_difference_is_greater = builder.and(equal, lhs_greater_at_bit);
        greater = builder.or(greater, first_difference_is_greater);

        let bits_equal = builder.is_equal(lhs_bits[i].target, rhs_bits[i].target);
        equal = builder.and(equal, bits_equal);
    }
    builder.or(greater, equal)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{C, D, F};
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    fn set_u128(witness: &mut PartialWitness<F>, target: U128Target, value: u128) {
        for i in 0..4 {
            let limb = ((value >> (i * 32)) & 0xffff_ffff) as u32;
            witness
                .set_target(target.limbs[i], F::from_canonical_u32(limb))
                .unwrap();
        }
    }

    #[test]
    fn wide_conservation_holds() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let inputs = [
            U128Target::new_virtual(&mut builder),
            U128Target::new_virtual(&mut builder),
            U128Target::new_virtual(&mut builder),
        ];
        let mint = [U128Target::new_virtual(&mut builder)];
        let outputs = [
            U128Target::new_virtual(&mut builder),
            U128Target::new_virtual(&mut builder),
        ];

        let input_sum = accumulate(&mut builder, &inputs);
        let mint_sum = accumulate(&mut builder, &mint);
        let available = add_wide(&mut builder, &input_sum, &mint_sum);
        let output_sum = accumulate(&mut builder, &outputs);
        let conservation_holds = geq(&mut builder, &available, &output_sum);
        builder.assert_one(conservation_holds.target);

        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for (target, value) in inputs.into_iter().zip([100_u128, 250, 900]) {
            set_u128(&mut witness, target, value);
        }
        set_u128(&mut witness, mint[0], 50);
        for (target, value) in outputs.into_iter().zip([500_u128, 700]) {
            set_u128(&mut witness, target, value);
        }

        let proof = data
            .prove(witness)
            .expect("valid wide conservation relation must prove");
        data.verify(proof)
            .expect("valid wide conservation proof must verify");
    }

    fn build_wraparound_case(assert_relation: bool) -> bool {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let available_term = U128Target::new_virtual(&mut builder);
        let output_terms = [
            U128Target::new_virtual(&mut builder),
            U128Target::new_virtual(&mut builder),
        ];
        let available = accumulate(&mut builder, &[available_term]);
        let outputs = accumulate(&mut builder, &output_terms);
        let conservation_holds = geq(&mut builder, &available, &outputs);
        if assert_relation {
            builder.assert_one(conservation_holds.target);
        } else {
            builder.assert_zero(conservation_holds.target);
        }

        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        // True values: available = 2, outputs = 2^128 + 1.
        // A wrapping u128 implementation sees outputs = 1 and would accept
        // the false claim 2 >= 1.
        set_u128(&mut witness, available_term, 2);
        set_u128(&mut witness, output_terms[0], u128::MAX);
        set_u128(&mut witness, output_terms[1], 2);

        match data.prove(witness) {
            Ok(proof) => data.verify(proof).is_ok(),
            Err(_) => false,
        }
    }

    #[test]
    fn wide_sum_prevents_u128_wraparound_conservation() {
        assert!(
            build_wraparound_case(false),
            "the exact comparison must prove that the wrapped claim is false"
        );
        assert!(
            !build_wraparound_case(true),
            "asserting the false wrapped conservation claim must fail"
        );
    }
}
