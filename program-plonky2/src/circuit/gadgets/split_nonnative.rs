//! Small-limb decomposition helpers used by windowed nonnative arithmetic.

use std::marker::PhantomData;

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::gadgets::biguint::BigUintTarget;
use crate::circuit::gadgets::nonnative::NonNativeTarget;
use crate::u32_lib::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

pub trait CircuitBuilderSplit<F: RichField + Extendable<D>, const D: usize> {
    fn split_u32_to_4_bit_limbs(&mut self, value: U32Target) -> Vec<Target>;
    fn split_nonnative_to_4_bit_limbs<FF: Field>(
        &mut self,
        value: &NonNativeTarget<FF>,
    ) -> Vec<Target>;
    fn split_nonnative_to_2_bit_limbs<FF: Field>(
        &mut self,
        value: &NonNativeTarget<FF>,
    ) -> Vec<Target>;
    /// Recombines limbs that are assumed to be four-bit values.
    ///
    /// As in the reference gadget, this function does not range-check the input limbs.
    fn recombine_nonnative_4_bit_limbs<FF: Field>(
        &mut self,
        limbs: Vec<Target>,
    ) -> NonNativeTarget<FF>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSplit<F, D>
    for CircuitBuilder<F, D>
{
    fn split_u32_to_4_bit_limbs(&mut self, value: U32Target) -> Vec<Target> {
        let two_bit_limbs = self.split_le_base::<4>(value.0, 16);
        let four = self.constant(F::from_canonical_usize(4));
        two_bit_limbs
            .iter()
            .tuples()
            .map(|(&low, &high)| self.mul_add(high, four, low))
            .collect()
    }

    fn split_nonnative_to_4_bit_limbs<FF: Field>(
        &mut self,
        value: &NonNativeTarget<FF>,
    ) -> Vec<Target> {
        value
            .value
            .limbs
            .iter()
            .flat_map(|limb| self.split_u32_to_4_bit_limbs(*limb))
            .collect()
    }

    fn split_nonnative_to_2_bit_limbs<FF: Field>(
        &mut self,
        value: &NonNativeTarget<FF>,
    ) -> Vec<Target> {
        value
            .value
            .limbs
            .iter()
            .flat_map(|limb| self.split_le_base::<4>(limb.0, 16))
            .collect()
    }

    fn recombine_nonnative_4_bit_limbs<FF: Field>(
        &mut self,
        limbs: Vec<Target>,
    ) -> NonNativeTarget<FF> {
        assert!(
            limbs.len() % 8 == 0,
            "four-bit limb count must be a multiple of eight"
        );
        let base = self.constant_u32(1 << 4);
        let u32_limbs = limbs
            .chunks_exact(8)
            .map(|chunk| {
                let mut combined = self.zero_u32();
                for limb in chunk.iter().rev() {
                    combined = self.mul_add_u32(combined, base, U32Target(*limb)).0;
                }
                combined
            })
            .collect();
        NonNativeTarget {
            value: BigUintTarget { limbs: u32_limbs },
            _phantom: PhantomData,
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;

    use super::*;
    use crate::circuit::gadgets::nonnative::CircuitBuilderNonNative;
    use crate::{C, D, F};

    #[test]
    fn split_nonnative_round_trip() -> Result<()> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let value = Secp256K1Scalar::from_noncanonical_u64(0x1234_5678_9abc_def0);
        let target = builder.constant_nonnative(value);
        let limbs = builder.split_nonnative_to_4_bit_limbs(&target);
        let recombined: NonNativeTarget<Secp256K1Scalar> =
            builder.recombine_nonnative_4_bit_limbs(limbs);
        builder.connect_nonnative(&target, &recombined);

        let data = builder.build::<C>();
        let proof = data.prove(PartialWitness::new())?;
        data.verify(proof)
    }
}
