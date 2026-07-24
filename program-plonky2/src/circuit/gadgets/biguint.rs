//! Variable-width unsigned integer gadgets backed by the custom u32 gates.

use std::any::type_name;
use std::marker::PhantomData;

use anyhow::Result;
use num::{BigUint, Integer, Zero};
use plonky2::field::extension::Extendable;
use plonky2::field::types::{PrimeField, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::u32_lib::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::u32_lib::gadgets::multiple_comparison::list_le_u32_circuit;
use crate::u32_lib::gadgets::range_check::range_check_u32_circuit;
use crate::u32_lib::witness::{GeneratedValuesU32, WitnessU32};

#[derive(Clone, Debug)]
pub struct BigUintTarget {
    pub limbs: Vec<U32Target>,
}

impl BigUintTarget {
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    pub fn get_limb(&self, i: usize) -> U32Target {
        self.limbs[i]
    }
}

pub trait CircuitBuilderBiguint<F: RichField + Extendable<D>, const D: usize> {
    fn constant_biguint(&mut self, value: &BigUint) -> BigUintTarget;
    fn zero_biguint(&mut self) -> BigUintTarget;
    fn connect_biguint(&mut self, lhs: &BigUintTarget, rhs: &BigUintTarget);
    fn pad_biguints(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget);
    fn cmp_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget;
    fn add_virtual_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget;
    fn add_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;
    fn sub_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;
    fn mul_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;
    fn mul_biguint_by_bool(&mut self, a: &BigUintTarget, b: BoolTarget) -> BigUintTarget;
    fn mul_add_biguint(
        &mut self,
        x: &BigUintTarget,
        y: &BigUintTarget,
        z: &BigUintTarget,
    ) -> BigUintTarget;
    fn div_rem_biguint(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget);
    fn div_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;
    fn rem_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderBiguint<F, D>
    for CircuitBuilder<F, D>
{
    fn constant_biguint(&mut self, value: &BigUint) -> BigUintTarget {
        BigUintTarget {
            limbs: value
                .to_u32_digits()
                .into_iter()
                .map(|limb| self.constant_u32(limb))
                .collect(),
        }
    }

    fn zero_biguint(&mut self) -> BigUintTarget {
        self.constant_biguint(&BigUint::zero())
    }

    fn connect_biguint(&mut self, lhs: &BigUintTarget, rhs: &BigUintTarget) {
        let common_limbs = lhs.num_limbs().min(rhs.num_limbs());
        for i in 0..common_limbs {
            self.connect_u32(lhs.get_limb(i), rhs.get_limb(i));
        }
        for i in common_limbs..lhs.num_limbs() {
            self.assert_zero_u32(lhs.get_limb(i));
        }
        for i in common_limbs..rhs.num_limbs() {
            self.assert_zero_u32(rhs.get_limb(i));
        }
    }

    fn pad_biguints(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget) {
        let num_limbs = a.num_limbs().max(b.num_limbs());
        let mut a = a.clone();
        let mut b = b.clone();
        a.limbs.resize_with(num_limbs, || self.zero_u32());
        b.limbs.resize_with(num_limbs, || self.zero_u32());
        (a, b)
    }

    fn cmp_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BoolTarget {
        let (a, b) = self.pad_biguints(a, b);
        list_le_u32_circuit(self, a.limbs, b.limbs)
    }

    fn add_virtual_biguint_target(&mut self, num_limbs: usize) -> BigUintTarget {
        BigUintTarget {
            limbs: self.add_virtual_u32_targets(num_limbs),
        }
    }

    fn add_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let num_limbs = a.num_limbs().max(b.num_limbs());
        let mut limbs = Vec::with_capacity(num_limbs + 1);
        let mut carry = self.zero_u32();
        for i in 0..num_limbs {
            let a_limb = a.limbs.get(i).copied().unwrap_or_else(|| self.zero_u32());
            let b_limb = b.limbs.get(i).copied().unwrap_or_else(|| self.zero_u32());
            let (limb, next_carry) = self.add_many_u32(&[carry, a_limb, b_limb]);
            limbs.push(limb);
            carry = next_carry;
        }
        limbs.push(carry);
        BigUintTarget { limbs }
    }

    fn sub_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        let (a, b) = self.pad_biguints(a, b);
        let mut limbs = Vec::with_capacity(a.num_limbs());
        let mut borrow = self.zero_u32();
        for i in 0..a.num_limbs() {
            let (limb, next_borrow) = self.sub_u32(a.limbs[i], b.limbs[i], borrow);
            limbs.push(limb);
            borrow = next_borrow;
        }
        // The reference assumes a >= b. Make that assumption a constraint.
        self.assert_zero_u32(borrow);
        BigUintTarget { limbs }
    }

    fn mul_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        if a.limbs.is_empty() || b.limbs.is_empty() {
            return self.zero_biguint();
        }
        let total_limbs = a.num_limbs() + b.num_limbs();
        let mut columns = vec![Vec::new(); total_limbs];
        for i in 0..a.num_limbs() {
            for j in 0..b.num_limbs() {
                let (low, high) = self.mul_u32(a.limbs[i], b.limbs[j]);
                columns[i + j].push(low);
                columns[i + j + 1].push(high);
            }
        }

        let mut limbs = Vec::with_capacity(total_limbs + 1);
        let mut carry = self.zero_u32();
        for column in &columns {
            let (limb, next_carry) = self.add_u32s_with_carry(column, carry);
            limbs.push(limb);
            carry = next_carry;
        }
        limbs.push(carry);
        BigUintTarget { limbs }
    }

    fn mul_biguint_by_bool(&mut self, a: &BigUintTarget, b: BoolTarget) -> BigUintTarget {
        BigUintTarget {
            limbs: a
                .limbs
                .iter()
                .map(|limb| U32Target(self.mul(limb.0, b.target)))
                .collect(),
        }
    }

    fn mul_add_biguint(
        &mut self,
        x: &BigUintTarget,
        y: &BigUintTarget,
        z: &BigUintTarget,
    ) -> BigUintTarget {
        let product = self.mul_biguint(x, y);
        self.add_biguint(&product, z)
    }

    fn div_rem_biguint(
        &mut self,
        a: &BigUintTarget,
        b: &BigUintTarget,
    ) -> (BigUintTarget, BigUintTarget) {
        assert!(
            b.num_limbs() > 0,
            "div_rem_biguint requires a non-empty divisor target"
        );
        let div_num_limbs = if b.num_limbs() > a.num_limbs() {
            0
        } else {
            a.num_limbs() - b.num_limbs() + 1
        };
        let div = self.add_virtual_biguint_target(div_num_limbs);
        range_check_u32_circuit(self, div.limbs.clone());
        let rem = self.add_virtual_biguint_target(b.num_limbs());

        self.add_simple_generator(BigUintDivRemGenerator::<F, D> {
            a: a.clone(),
            b: b.clone(),
            div: div.clone(),
            rem: rem.clone(),
            _phantom: PhantomData,
        });

        let reconstructed = self.mul_add_biguint(&div, b, &rem);
        self.connect_biguint(a, &reconstructed);
        let rem_le_b = self.cmp_biguint(&rem, b);
        let (padded_rem, padded_b) = self.pad_biguints(&rem, b);
        let mut rem_eq_b = self.constant_bool(true);
        for (rem_limb, b_limb) in padded_rem.limbs.iter().zip(&padded_b.limbs) {
            let limbs_equal = self.is_equal(rem_limb.0, b_limb.0);
            rem_eq_b = self.and(rem_eq_b, limbs_equal);
        }
        let rem_ne_b = self.not(rem_eq_b);
        let rem_lt_b = self.and(rem_le_b, rem_ne_b);
        self.assert_one(rem_lt_b.target);
        (div, rem)
    }

    fn div_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        self.div_rem_biguint(a, b).0
    }

    fn rem_biguint(&mut self, a: &BigUintTarget, b: &BigUintTarget) -> BigUintTarget {
        self.div_rem_biguint(a, b).1
    }
}

pub trait WitnessBigUint<F: PrimeField64>: Witness<F> {
    fn get_biguint_target(&self, target: BigUintTarget) -> BigUint;
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()>;
}

impl<T: Witness<F>, F: PrimeField64> WitnessBigUint<F> for T {
    fn get_biguint_target(&self, target: BigUintTarget) -> BigUint {
        target
            .limbs
            .into_iter()
            .rev()
            .fold(BigUint::zero(), |acc, limb| {
                (acc << 32) + self.get_target(limb.0).to_canonical_biguint()
            })
    }

    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()> {
        let mut limbs = value.to_u32_digits();
        assert!(
            target.num_limbs() >= limbs.len(),
            "value does not fit in BigUintTarget"
        );
        limbs.resize(target.num_limbs(), 0);
        for (target_limb, value_limb) in target.limbs.iter().zip(limbs) {
            self.set_u32_target(*target_limb, value_limb)?;
        }
        Ok(())
    }
}

pub trait GeneratedValuesBigUint<F: PrimeField> {
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()>;
}

impl<F: PrimeField> GeneratedValuesBigUint<F> for GeneratedValues<F> {
    fn set_biguint_target(&mut self, target: &BigUintTarget, value: &BigUint) -> Result<()> {
        let mut limbs = value.to_u32_digits();
        assert!(
            target.num_limbs() >= limbs.len(),
            "generated value does not fit in BigUintTarget"
        );
        limbs.resize(target.num_limbs(), 0);
        for (target_limb, value_limb) in target.limbs.iter().zip(limbs) {
            self.set_u32_target(*target_limb, value_limb)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct BigUintDivRemGenerator<F: RichField + Extendable<D>, const D: usize> {
    a: BigUintTarget,
    b: BigUintTarget,
    div: BigUintTarget,
    rem: BigUintTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for BigUintDivRemGenerator<F, D>
{
    fn id(&self) -> String {
        format!("{}<{}, {D}>", type_name::<Self>(), type_name::<F>())
    }

    fn dependencies(&self) -> Vec<Target> {
        self.a
            .limbs
            .iter()
            .chain(&self.b.limbs)
            .map(|limb| limb.0)
            .collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let a = witness.get_biguint_target(self.a.clone());
        let b = witness.get_biguint_target(self.b.clone());
        assert!(!b.is_zero(), "BigUint division by zero");
        let (div, rem) = a.div_rem(&b);
        out_buffer.set_biguint_target(&self.div, &div)?;
        out_buffer.set_biguint_target(&self.rem, &rem)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_biguint_target(dst, &self.a)?;
        write_biguint_target(dst, &self.b)?;
        write_biguint_target(dst, &self.div)?;
        write_biguint_target(dst, &self.rem)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            a: read_biguint_target(src)?,
            b: read_biguint_target(src)?,
            div: read_biguint_target(src)?,
            rem: read_biguint_target(src)?,
            _phantom: PhantomData,
        })
    }
}

fn write_biguint_target(dst: &mut Vec<u8>, value: &BigUintTarget) -> IoResult<()> {
    let targets: Vec<_> = value.limbs.iter().map(|limb| limb.0).collect();
    dst.write_target_vec(&targets)
}

fn read_biguint_target(src: &mut Buffer) -> IoResult<BigUintTarget> {
    Ok(BigUintTarget {
        limbs: src.read_target_vec()?.into_iter().map(U32Target).collect(),
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use anyhow::Result;
    use num::{BigUint, Integer, One, Zero};
    use plonky2::field::types::Field;
    use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGeneratorRef};
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, PartitionWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};

    use super::*;
    use crate::{C, D, F};

    #[derive(Debug)]
    struct NonCanonicalDivGenerator {
        a: BigUintTarget,
        b: BigUintTarget,
        div: BigUintTarget,
        rem: BigUintTarget,
    }

    impl SimpleGenerator<F, D> for NonCanonicalDivGenerator {
        fn id(&self) -> String {
            "NonCanonicalDivGenerator".to_owned()
        }

        fn dependencies(&self) -> Vec<Target> {
            self.a
                .limbs
                .iter()
                .chain(&self.b.limbs)
                .map(|limb| limb.0)
                .collect()
        }

        fn run_once(
            &self,
            witness: &PartitionWitness<F>,
            out_buffer: &mut GeneratedValues<F>,
        ) -> Result<()> {
            assert_eq!(
                witness.get_biguint_target(self.a.clone()),
                BigUint::one() << 40,
                "the malicious division fixture requires a = 2^40"
            );
            assert_eq!(
                witness.get_biguint_target(self.b.clone()),
                BigUint::one(),
                "the malicious division fixture requires b = 1"
            );
            assert_eq!(self.div.num_limbs(), 1);
            out_buffer.set_target(self.div.limbs[0].0, F::from_canonical_u64(1u64 << 40))?;
            out_buffer.set_biguint_target(&self.rem, &BigUint::zero())
        }

        fn serialize(
            &self,
            dst: &mut Vec<u8>,
            _common_data: &CommonCircuitData<F, D>,
        ) -> IoResult<()> {
            write_biguint_target(dst, &self.a)?;
            write_biguint_target(dst, &self.b)?;
            write_biguint_target(dst, &self.div)?;
            write_biguint_target(dst, &self.rem)
        }

        fn deserialize(
            src: &mut Buffer,
            _common_data: &CommonCircuitData<F, D>,
        ) -> IoResult<Self> {
            Ok(Self {
                a: read_biguint_target(src)?,
                b: read_biguint_target(src)?,
                div: read_biguint_target(src)?,
                rem: read_biguint_target(src)?,
            })
        }
    }

    fn limb_len(value: &BigUint) -> usize {
        value.to_u32_digits().len().max(1)
    }

    fn seeded_biguint(seed: &mut u64, limbs: usize) -> BigUint {
        let digits: Vec<u32> = (0..limbs)
            .map(|_| {
                *seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (*seed >> 32) as u32
            })
            .collect();
        BigUint::from_slice(&digits)
    }

    #[test]
    fn biguint_arithmetic_matches_host_edge_and_mismatched_cases() -> Result<()> {
        let max = BigUint::from(u32::MAX);
        let mut seed = 0x5eed_cafe_f00d_beefu64;
        let mut cases = vec![
            (BigUint::zero(), BigUint::one()),
            (max.clone(), BigUint::one()),
            (
                (&BigUint::one() << 160) + BigUint::from(0x1234_5678u32),
                (&BigUint::one() << 32) + BigUint::from(7u32),
            ),
            (
                BigUint::parse_bytes(b"123456789abcdef0123456789abcdef", 16).unwrap(),
                BigUint::parse_bytes(b"fedcba9876543211", 16).unwrap(),
            ),
        ];
        for (a_limbs, b_limbs) in [(4, 4), (7, 2), (3, 6)] {
            let a = seeded_biguint(&mut seed, a_limbs);
            let mut b = seeded_biguint(&mut seed, b_limbs);
            if b.is_zero() {
                b = BigUint::one();
            }
            cases.push((a, b));
        }

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut witness = PartialWitness::new();
        for (case_index, (a_value, b_value)) in cases.into_iter().enumerate() {
            let a_extra = usize::from(case_index == 2);
            let b_extra = usize::from(case_index == 3);
            let a = builder.add_virtual_biguint_target(limb_len(&a_value) + a_extra);
            let b = builder.add_virtual_biguint_target(limb_len(&b_value) + b_extra);
            witness.set_biguint_target(&a, &a_value)?;
            witness.set_biguint_target(&b, &b_value)?;

            let sum = builder.add_biguint(&a, &b);
            let product = builder.mul_biguint(&a, &b);
            let difference = if a_value >= b_value {
                builder.sub_biguint(&a, &b)
            } else {
                builder.sub_biguint(&b, &a)
            };
            let (div, rem) = builder.div_rem_biguint(&a, &b);
            let cmp = builder.cmp_biguint(&a, &b);

            let expected_sum = builder.constant_biguint(&(&a_value + &b_value));
            let expected_product = builder.constant_biguint(&(&a_value * &b_value));
            builder.connect_biguint(&sum, &expected_sum);
            builder.connect_biguint(&product, &expected_product);
            let expected_difference = if a_value >= b_value {
                &a_value - &b_value
            } else {
                &b_value - &a_value
            };
            let expected_difference = builder.constant_biguint(&expected_difference);
            builder.connect_biguint(&difference, &expected_difference);
            let (expected_div, expected_rem) = a_value.div_rem(&b_value);
            let expected_div = builder.constant_biguint(&expected_div);
            let expected_rem = builder.constant_biguint(&expected_rem);
            builder.connect_biguint(&div, &expected_div);
            builder.connect_biguint(&rem, &expected_rem);
            let expected_cmp = builder.constant_bool(a_value <= b_value);
            builder.connect(cmp.target, expected_cmp.target);
        }

        let data = builder.build::<C>();
        let proof = data.prove(witness)?;
        data.verify(proof)
    }

    /// A raw quotient limb of 2^40 can satisfy `div * 1 + 0 = 2^40`
    /// across two canonical input limbs, but it is not a canonical u32 limb.
    #[test]
    fn div_rem_biguint_rejects_noncanonical_quotient_limb() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a = builder.add_virtual_biguint_target(2);
        let b = builder.add_virtual_biguint_target(2);
        let (div, rem) = builder.div_rem_biguint(&a, &b);
        assert_eq!(div.num_limbs(), 1);
        let mut data = builder.build::<C>();

        let generator_index = data
            .prover_only
            .generators
            .iter()
            .position(|generator| generator.0.id().contains("BigUintDivRemGenerator"))
            .expect("BigUint division generator must be present");
        data.prover_only.generators[generator_index] =
            WitnessGeneratorRef::new(NonCanonicalDivGenerator {
                a: a.clone(),
                b: b.clone(),
                div,
                rem,
            }
            .adapter());

        let mut witness = PartialWitness::new();
        witness
            .set_biguint_target(&a, &(BigUint::one() << 40))
            .expect("a fits in two canonical limbs");
        witness
            .set_biguint_target(&b, &BigUint::one())
            .expect("b fits in two canonical limbs");
        match catch_unwind(AssertUnwindSafe(|| data.prove(witness))) {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(
                    data.verify(proof).is_err(),
                    "a noncanonical quotient limb unexpectedly satisfied the circuit"
                );
            }
        }
    }
}
