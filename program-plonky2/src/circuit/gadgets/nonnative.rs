//! Non-native field arithmetic backed by variable-width custom-gated u32 integers.

use std::any::type_name;
use std::marker::PhantomData;

use anyhow::Result;
use num::{BigUint, Integer, One, Zero};
use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::circuit::gadgets::biguint::{
    BigUintTarget, CircuitBuilderBiguint, GeneratedValuesBigUint, WitnessBigUint,
};
use crate::u32_lib::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::u32_lib::gadgets::range_check::range_check_u32_circuit;
use crate::u32_lib::witness::GeneratedValuesU32;

#[derive(Clone, Debug)]
pub struct NonNativeTarget<FF: Field> {
    pub(crate) value: BigUintTarget,
    pub(crate) _phantom: PhantomData<FF>,
}

impl<FF: Field> NonNativeTarget<FF> {
    /// Underlying canonical big-integer target, exposed for host-side witness
    /// assignment. This does not add or alter circuit constraints.
    pub fn value(&self) -> &BigUintTarget {
        &self.value
    }
}

pub trait CircuitBuilderNonNative<F: RichField + Extendable<D>, const D: usize> {
    fn num_nonnative_limbs<FF: Field>() -> usize {
        FF::BITS.div_ceil(32)
    }

    fn biguint_to_nonnative<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF>;
    fn nonnative_to_canonical_biguint<FF: Field>(
        &mut self,
        x: &NonNativeTarget<FF>,
    ) -> BigUintTarget;
    fn constant_nonnative<FF: PrimeField>(&mut self, x: FF) -> NonNativeTarget<FF>;
    fn zero_nonnative<FF: PrimeField>(&mut self) -> NonNativeTarget<FF>;
    fn connect_nonnative<FF: Field>(
        &mut self,
        lhs: &NonNativeTarget<FF>,
        rhs: &NonNativeTarget<FF>,
    );
    fn add_virtual_nonnative_target<FF: Field>(&mut self) -> NonNativeTarget<FF>;
    fn add_virtual_nonnative_target_sized<FF: Field>(
        &mut self,
        num_limbs: usize,
    ) -> NonNativeTarget<FF>;
    fn add_nonnative<FF: PrimeField>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF>;
    fn mul_nonnative_by_bool<FF: Field>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: BoolTarget,
    ) -> NonNativeTarget<FF>;
    fn if_nonnative<FF: PrimeField>(
        &mut self,
        b: BoolTarget,
        x: &NonNativeTarget<FF>,
        y: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF>;
    fn add_many_nonnative<FF: PrimeField>(
        &mut self,
        to_add: &[NonNativeTarget<FF>],
    ) -> NonNativeTarget<FF>;
    fn sub_nonnative<FF: PrimeField>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF>;
    fn mul_nonnative<FF: PrimeField>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF>;
    fn mul_many_nonnative<FF: PrimeField>(
        &mut self,
        to_mul: &[NonNativeTarget<FF>],
    ) -> NonNativeTarget<FF>;
    fn neg_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;
    fn inv_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;
    fn reduce<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF>;
    fn reduce_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;
    fn bool_to_nonnative<FF: Field>(&mut self, b: &BoolTarget) -> NonNativeTarget<FF>;
    fn split_nonnative_to_bits<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> Vec<BoolTarget>;
    fn nonnative_conditional_neg<FF: PrimeField>(
        &mut self,
        x: &NonNativeTarget<FF>,
        b: BoolTarget,
    ) -> NonNativeTarget<FF>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderNonNative<F, D>
    for CircuitBuilder<F, D>
{
    fn biguint_to_nonnative<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF> {
        assert_canonical_biguint::<F, D, FF>(self, x);
        NonNativeTarget {
            value: x.clone(),
            _phantom: PhantomData,
        }
    }

    fn nonnative_to_canonical_biguint<FF: Field>(
        &mut self,
        x: &NonNativeTarget<FF>,
    ) -> BigUintTarget {
        x.value.clone()
    }

    fn constant_nonnative<FF: PrimeField>(&mut self, x: FF) -> NonNativeTarget<FF> {
        let value = self.constant_biguint(&x.to_canonical_biguint());
        self.biguint_to_nonnative(&value)
    }

    fn zero_nonnative<FF: PrimeField>(&mut self) -> NonNativeTarget<FF> {
        self.constant_nonnative(FF::ZERO)
    }

    fn connect_nonnative<FF: Field>(
        &mut self,
        lhs: &NonNativeTarget<FF>,
        rhs: &NonNativeTarget<FF>,
    ) {
        self.connect_biguint(&lhs.value, &rhs.value);
    }

    fn add_virtual_nonnative_target<FF: Field>(&mut self) -> NonNativeTarget<FF> {
        self.add_virtual_nonnative_target_sized(Self::num_nonnative_limbs::<FF>())
    }

    fn add_virtual_nonnative_target_sized<FF: Field>(
        &mut self,
        num_limbs: usize,
    ) -> NonNativeTarget<FF> {
        let value = self.add_virtual_biguint_target(num_limbs);
        self.biguint_to_nonnative(&value)
    }

    fn add_nonnative<FF: PrimeField>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF> {
        let sum = self.add_virtual_nonnative_target::<FF>();
        let overflow = self.add_virtual_bool_target_safe();
        self.add_simple_generator(NonNativeAdditionGenerator::<F, D, FF> {
            a: a.clone(),
            b: b.clone(),
            sum: sum.clone(),
            overflow,
            _phantom: PhantomData,
        });

        let expected = self.add_biguint(&a.value, &b.value);
        let modulus = self.constant_biguint(&FF::order());
        let modulus_if_overflow = self.mul_biguint_by_bool(&modulus, overflow);
        let actual = self.add_biguint(&sum.value, &modulus_if_overflow);
        self.connect_biguint(&expected, &actual);
        sum
    }

    fn mul_nonnative_by_bool<FF: Field>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: BoolTarget,
    ) -> NonNativeTarget<FF> {
        NonNativeTarget {
            value: self.mul_biguint_by_bool(&a.value, b),
            _phantom: PhantomData,
        }
    }

    fn if_nonnative<FF: PrimeField>(
        &mut self,
        b: BoolTarget,
        x: &NonNativeTarget<FF>,
        y: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF> {
        let not_b = self.not(b);
        let maybe_x = self.mul_nonnative_by_bool(x, b);
        let maybe_y = self.mul_nonnative_by_bool(y, not_b);
        self.add_nonnative(&maybe_x, &maybe_y)
    }

    fn add_many_nonnative<FF: PrimeField>(
        &mut self,
        to_add: &[NonNativeTarget<FF>],
    ) -> NonNativeTarget<FF> {
        match to_add.len() {
            0 => return self.zero_nonnative(),
            1 => return to_add[0].clone(),
            _ => {}
        }

        let sum = self.add_virtual_nonnative_target::<FF>();
        let overflow = self.add_virtual_u32_target();
        let summands = to_add.to_vec();
        self.add_simple_generator(NonNativeMultipleAddsGenerator::<F, D, FF> {
            summands: summands.clone(),
            sum: sum.clone(),
            overflow,
            _phantom: PhantomData,
        });

        range_check_u32_circuit(self, vec![overflow]);
        let expected = summands.iter().fold(self.zero_biguint(), |acc, value| {
            self.add_biguint(&acc, &value.value)
        });
        let modulus = self.constant_biguint(&FF::order());
        let overflow_biguint = BigUintTarget {
            limbs: vec![overflow],
        };
        let modulus_multiple = self.mul_biguint(&modulus, &overflow_biguint);
        let actual = self.add_biguint(&sum.value, &modulus_multiple);
        self.connect_biguint(&expected, &actual);
        sum
    }

    fn sub_nonnative<FF: PrimeField>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF> {
        let difference = self.add_virtual_nonnative_target::<FF>();
        let overflow = self.add_virtual_bool_target_safe();
        self.add_simple_generator(NonNativeSubtractionGenerator::<F, D, FF> {
            a: a.clone(),
            b: b.clone(),
            difference: difference.clone(),
            overflow,
            _phantom: PhantomData,
        });

        let difference_plus_b = self.add_biguint(&difference.value, &b.value);
        let modulus = self.constant_biguint(&FF::order());
        let modulus_if_overflow = self.mul_biguint_by_bool(&modulus, overflow);
        let reduced = self.sub_biguint(&difference_plus_b, &modulus_if_overflow);
        self.connect_biguint(&a.value, &reduced);
        difference
    }

    fn mul_nonnative<FF: PrimeField>(
        &mut self,
        a: &NonNativeTarget<FF>,
        b: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF> {
        let product = self.add_virtual_nonnative_target::<FF>();
        let modulus = self.constant_biguint(&FF::order());
        // For canonical field inputs the quotient is always smaller than the modulus.
        // A fixed modulus-width target also handles short constants (including zero).
        let overflow = self.add_virtual_biguint_target(modulus.num_limbs());
        self.add_simple_generator(NonNativeMultiplicationGenerator::<F, D, FF> {
            a: a.clone(),
            b: b.clone(),
            product: product.clone(),
            overflow: overflow.clone(),
            _phantom: PhantomData,
        });

        range_check_u32_circuit(self, overflow.limbs.clone());
        constrain_product_reduction(self, a, b, &overflow, &product);
        product
    }

    fn mul_many_nonnative<FF: PrimeField>(
        &mut self,
        to_mul: &[NonNativeTarget<FF>],
    ) -> NonNativeTarget<FF> {
        assert!(
            !to_mul.is_empty(),
            "mul_many_nonnative requires at least one factor"
        );
        if to_mul.len() == 1 {
            return to_mul[0].clone();
        }
        let mut product = self.mul_nonnative(&to_mul[0], &to_mul[1]);
        for factor in &to_mul[2..] {
            product = self.mul_nonnative(&product, factor);
        }
        product
    }

    fn neg_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let zero = self.zero_nonnative();
        self.sub_nonnative(&zero, x)
    }

    fn inv_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let inverse = self.add_virtual_nonnative_target::<FF>();
        let quotient = self.add_virtual_biguint_target(x.value.num_limbs());
        self.add_simple_generator(NonNativeInverseGenerator::<F, D, FF> {
            x: x.clone(),
            inverse: inverse.clone(),
            quotient: quotient.clone(),
            _phantom: PhantomData,
        });

        range_check_u32_circuit(self, quotient.limbs.clone());
        let product = self.mul_biguint(&x.value, &inverse.value);
        let modulus = self.constant_biguint(&FF::order());
        let modulus_multiple = self.mul_biguint(&modulus, &quotient);
        let one = self.constant_biguint(&BigUint::one());
        let expected = self.add_biguint(&modulus_multiple, &one);
        self.connect_biguint(&product, &expected);
        inverse
    }

    fn reduce<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF> {
        let modulus = self.constant_biguint(&FF::order());
        let remainder = self.rem_biguint(x, &modulus);
        self.biguint_to_nonnative(&remainder)
    }

    fn reduce_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        self.reduce(&x.value)
    }

    fn bool_to_nonnative<FF: Field>(&mut self, b: &BoolTarget) -> NonNativeTarget<FF> {
        NonNativeTarget {
            value: BigUintTarget {
                limbs: vec![U32Target(b.target)],
            },
            _phantom: PhantomData,
        }
    }

    fn split_nonnative_to_bits<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> Vec<BoolTarget> {
        x.value
            .limbs
            .iter()
            .flat_map(|limb| {
                self.split_le_base::<2>(limb.0, 32)
                    .into_iter()
                    .map(BoolTarget::new_unsafe)
            })
            .collect()
    }

    fn nonnative_conditional_neg<FF: PrimeField>(
        &mut self,
        x: &NonNativeTarget<FF>,
        b: BoolTarget,
    ) -> NonNativeTarget<FF> {
        let not_b = self.not(b);
        let negative = self.neg_nonnative(x);
        let maybe_negative = self.mul_nonnative_by_bool(&negative, b);
        let maybe_positive = self.mul_nonnative_by_bool(x, not_b);
        self.add_nonnative(&maybe_negative, &maybe_positive)
    }
}

fn assert_canonical_biguint<F: RichField + Extendable<D>, const D: usize, FF: Field>(
    builder: &mut CircuitBuilder<F, D>,
    value: &BigUintTarget,
) {
    if !value.limbs.is_empty() {
        range_check_u32_circuit(builder, value.limbs.clone());
    }
    let maximum = FF::order() - BigUint::one();
    let maximum = builder.constant_biguint(&maximum);
    let is_canonical = builder.cmp_biguint(value, &maximum);
    builder.assert_one(is_canonical.target);
}

fn constrain_product_reduction<F: RichField + Extendable<D>, const D: usize, FF: PrimeField>(
    builder: &mut CircuitBuilder<F, D>,
    a: &NonNativeTarget<FF>,
    b: &NonNativeTarget<FF>,
    quotient: &BigUintTarget,
    remainder: &NonNativeTarget<FF>,
) {
    let expected = builder.mul_biguint(&a.value, &b.value);
    let modulus = builder.constant_biguint(&FF::order());
    let modulus_multiple = builder.mul_biguint(&modulus, quotient);
    let actual = builder.add_biguint(&remainder.value, &modulus_multiple);
    builder.connect_biguint(&expected, &actual);
}

fn read_canonical<FF: Field, F: RichField>(
    witness: &PartitionWitness<F>,
    target: &NonNativeTarget<FF>,
    context: &str,
) -> BigUint {
    let value = witness.get_biguint_target(target.value.clone());
    assert!(
        value < FF::order(),
        "{context} received a non-canonical input"
    );
    value
}

#[derive(Debug)]
struct NonNativeAdditionGenerator<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> {
    a: NonNativeTarget<FF>,
    b: NonNativeTarget<FF>,
    sum: NonNativeTarget<FF>,
    overflow: BoolTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D>
    for NonNativeAdditionGenerator<F, D, FF>
{
    fn id(&self) -> String {
        format!("{}<{}>", type_name::<Self>(), type_name::<FF>())
    }

    fn dependencies(&self) -> Vec<Target> {
        binary_dependencies(&self.a, &self.b)
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let sum = read_canonical(witness, &self.a, "nonnative addition left input")
            + read_canonical(witness, &self.b, "nonnative addition right input");
        let modulus = FF::order();
        let (overflow, reduced) = if sum >= modulus {
            (true, sum - modulus)
        } else {
            (false, sum)
        };
        out_buffer.set_biguint_target(&self.sum.value, &reduced)?;
        out_buffer.set_bool_target(self.overflow, overflow)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_nonnative(dst, &self.a)?;
        write_nonnative(dst, &self.b)?;
        write_nonnative(dst, &self.sum)?;
        dst.write_target_bool(self.overflow)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            a: read_nonnative(src)?,
            b: read_nonnative(src)?,
            sum: read_nonnative(src)?,
            overflow: src.read_target_bool()?,
            _phantom: PhantomData,
        })
    }
}

#[derive(Debug)]
struct NonNativeMultipleAddsGenerator<F: RichField + Extendable<D>, const D: usize, FF: PrimeField>
{
    summands: Vec<NonNativeTarget<FF>>,
    sum: NonNativeTarget<FF>,
    overflow: U32Target,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D>
    for NonNativeMultipleAddsGenerator<F, D, FF>
{
    fn id(&self) -> String {
        format!("{}<{}>", type_name::<Self>(), type_name::<FF>())
    }

    fn dependencies(&self) -> Vec<Target> {
        self.summands
            .iter()
            .flat_map(|summand| summand.value.limbs.iter().map(|limb| limb.0))
            .collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let sum = self.summands.iter().fold(BigUint::zero(), |acc, summand| {
            acc + read_canonical(witness, summand, "nonnative multiple-add input")
        });
        let (overflow, reduced) = sum.div_rem(&FF::order());
        let overflow_digits = overflow.to_u32_digits();
        assert!(
            overflow_digits.len() <= 1,
            "nonnative multiple-add quotient does not fit in u32"
        );
        out_buffer.set_biguint_target(&self.sum.value, &reduced)?;
        out_buffer.set_u32_target(self.overflow, overflow_digits.first().copied().unwrap_or(0))
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.summands.len())?;
        for summand in &self.summands {
            write_nonnative(dst, summand)?;
        }
        write_nonnative(dst, &self.sum)?;
        dst.write_target(self.overflow.0)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let len = src.read_usize()?;
        let mut summands = Vec::with_capacity(len);
        for _ in 0..len {
            summands.push(read_nonnative(src)?);
        }
        Ok(Self {
            summands,
            sum: read_nonnative(src)?,
            overflow: U32Target(src.read_target()?),
            _phantom: PhantomData,
        })
    }
}

#[derive(Debug)]
struct NonNativeSubtractionGenerator<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> {
    a: NonNativeTarget<FF>,
    b: NonNativeTarget<FF>,
    difference: NonNativeTarget<FF>,
    overflow: BoolTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D>
    for NonNativeSubtractionGenerator<F, D, FF>
{
    fn id(&self) -> String {
        format!("{}<{}>", type_name::<Self>(), type_name::<FF>())
    }

    fn dependencies(&self) -> Vec<Target> {
        binary_dependencies(&self.a, &self.b)
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let a = read_canonical(witness, &self.a, "nonnative subtraction left input");
        let b = read_canonical(witness, &self.b, "nonnative subtraction right input");
        let (difference, overflow) = if a >= b {
            (a - b, false)
        } else {
            (FF::order() + a - b, true)
        };
        out_buffer.set_biguint_target(&self.difference.value, &difference)?;
        out_buffer.set_bool_target(self.overflow, overflow)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_nonnative(dst, &self.a)?;
        write_nonnative(dst, &self.b)?;
        write_nonnative(dst, &self.difference)?;
        dst.write_target_bool(self.overflow)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            a: read_nonnative(src)?,
            b: read_nonnative(src)?,
            difference: read_nonnative(src)?,
            overflow: src.read_target_bool()?,
            _phantom: PhantomData,
        })
    }
}

#[derive(Debug)]
struct NonNativeMultiplicationGenerator<
    F: RichField + Extendable<D>,
    const D: usize,
    FF: PrimeField,
> {
    a: NonNativeTarget<FF>,
    b: NonNativeTarget<FF>,
    product: NonNativeTarget<FF>,
    overflow: BigUintTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D>
    for NonNativeMultiplicationGenerator<F, D, FF>
{
    fn id(&self) -> String {
        format!("{}<{}>", type_name::<Self>(), type_name::<FF>())
    }

    fn dependencies(&self) -> Vec<Target> {
        binary_dependencies(&self.a, &self.b)
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let a = read_canonical(witness, &self.a, "nonnative multiplication left input");
        let b = read_canonical(witness, &self.b, "nonnative multiplication right input");
        let (overflow, product) = (a * b).div_rem(&FF::order());
        out_buffer.set_biguint_target(&self.product.value, &product)?;
        out_buffer.set_biguint_target(&self.overflow, &overflow)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_nonnative(dst, &self.a)?;
        write_nonnative(dst, &self.b)?;
        write_nonnative(dst, &self.product)?;
        write_biguint(dst, &self.overflow)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            a: read_nonnative(src)?,
            b: read_nonnative(src)?,
            product: read_nonnative(src)?,
            overflow: read_biguint(src)?,
            _phantom: PhantomData,
        })
    }
}

#[derive(Debug)]
struct NonNativeInverseGenerator<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> {
    x: NonNativeTarget<FF>,
    inverse: NonNativeTarget<FF>,
    quotient: BigUintTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D>
    for NonNativeInverseGenerator<F, D, FF>
{
    fn id(&self) -> String {
        format!("{}<{}>", type_name::<Self>(), type_name::<FF>())
    }

    fn dependencies(&self) -> Vec<Target> {
        self.x.value.limbs.iter().map(|limb| limb.0).collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let x_biguint = read_canonical(witness, &self.x, "nonnative inverse input");
        assert!(!x_biguint.is_zero(), "nonnative inverse of zero");
        let x = FF::from_noncanonical_biguint(x_biguint.clone());
        let inverse = x.inverse().to_canonical_biguint();
        let (quotient, remainder) = (x_biguint * &inverse).div_rem(&FF::order());
        assert_eq!(
            remainder,
            BigUint::one(),
            "field inverse did not satisfy x * inverse = 1 mod modulus"
        );
        out_buffer.set_biguint_target(&self.inverse.value, &inverse)?;
        out_buffer.set_biguint_target(&self.quotient, &quotient)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_nonnative(dst, &self.x)?;
        write_nonnative(dst, &self.inverse)?;
        write_biguint(dst, &self.quotient)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            x: read_nonnative(src)?,
            inverse: read_nonnative(src)?,
            quotient: read_biguint(src)?,
            _phantom: PhantomData,
        })
    }
}

fn binary_dependencies<FF: Field>(a: &NonNativeTarget<FF>, b: &NonNativeTarget<FF>) -> Vec<Target> {
    a.value
        .limbs
        .iter()
        .chain(&b.value.limbs)
        .map(|limb| limb.0)
        .collect()
}

fn write_biguint(dst: &mut Vec<u8>, value: &BigUintTarget) -> IoResult<()> {
    let targets: Vec<_> = value.limbs.iter().map(|limb| limb.0).collect();
    dst.write_target_vec(&targets)
}

fn read_biguint(src: &mut Buffer) -> IoResult<BigUintTarget> {
    Ok(BigUintTarget {
        limbs: src.read_target_vec()?.into_iter().map(U32Target).collect(),
    })
}

fn write_nonnative<FF: Field>(dst: &mut Vec<u8>, value: &NonNativeTarget<FF>) -> IoResult<()> {
    write_biguint(dst, &value.value)
}

fn read_nonnative<FF: Field>(src: &mut Buffer) -> IoResult<NonNativeTarget<FF>> {
    Ok(NonNativeTarget {
        value: read_biguint(src)?,
        _phantom: PhantomData,
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use plonky2::field::secp256k1_base::Secp256K1Base;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2::field::types::{Field, PrimeField};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;

    use super::*;
    use crate::{C, D, F};

    fn register_nonnative<FF: Field>(
        builder: &mut CircuitBuilder<F, D>,
        value: &NonNativeTarget<FF>,
    ) {
        for limb in &value.value.limbs {
            builder.register_public_input(limb.0);
        }
    }

    fn outputs_as_biguint(public_inputs: &[F]) -> Vec<BigUint> {
        public_inputs
            .chunks_exact(8)
            .map(|chunk| {
                chunk.iter().rev().fold(BigUint::zero(), |acc, limb| {
                    (acc << 32) + limb.to_canonical_biguint()
                })
            })
            .collect()
    }

    fn arithmetic_cases<FF: PrimeField>() {
        let modulus = FF::order();
        let one = BigUint::one();
        let values = [
            (BigUint::zero(), BigUint::zero()),
            (one.clone(), &modulus - &one),
            (&modulus - &one, &modulus - BigUint::from(2u32)),
            (
                BigUint::parse_bytes(b"421199887766554433221100fedcba9876543210", 16).unwrap(),
                BigUint::parse_bytes(b"1337cafebabedeadbeef0123456789ab", 16).unwrap(),
            ),
        ];

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut witness = PartialWitness::new();
        let mut expected = Vec::new();
        for (a_value, b_value) in values {
            let a = builder.add_virtual_nonnative_target::<FF>();
            let b = builder.add_virtual_nonnative_target::<FF>();
            witness
                .set_biguint_target(&a.value, &a_value)
                .expect("a must fit");
            witness
                .set_biguint_target(&b.value, &b_value)
                .expect("b must fit");

            let sum = builder.add_nonnative(&a, &b);
            let difference = builder.sub_nonnative(&a, &b);
            let product = builder.mul_nonnative(&a, &b);
            register_nonnative(&mut builder, &sum);
            register_nonnative(&mut builder, &difference);
            register_nonnative(&mut builder, &product);

            expected.push((&a_value + &b_value) % &modulus);
            expected.push((&a_value + &modulus - &b_value) % &modulus);
            expected.push((&a_value * &b_value) % &modulus);
        }

        let zero = builder.zero_nonnative::<FF>();
        let seven = builder.constant_nonnative::<FF>(FF::from_canonical_u64(7));
        let zero_product = builder.mul_nonnative(&zero, &seven);
        register_nonnative(&mut builder, &zero_product);
        expected.push(BigUint::zero());

        let data = builder.build::<C>();
        let proof = data
            .prove(witness)
            .expect("valid nonnative arithmetic witness must prove");
        assert_eq!(outputs_as_biguint(&proof.public_inputs), expected);
        data.verify(proof)
            .expect("valid nonnative arithmetic proof must verify");
    }

    #[test]
    fn fp_nonnative_arithmetic_matches_biguint() {
        arithmetic_cases::<Secp256K1Base>();
    }

    #[test]
    fn fn_nonnative_arithmetic_matches_biguint() {
        arithmetic_cases::<Secp256K1Scalar>();
    }

    fn inverse_cases<FF: PrimeField>() {
        let modulus = FF::order();
        let values = [
            BigUint::one(),
            &modulus - BigUint::one(),
            BigUint::parse_bytes(b"23456789abcdef102030405060708090", 16).unwrap(),
        ];
        let exponent = &modulus - BigUint::from(2u32);
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut witness = PartialWitness::new();
        let mut expected = Vec::new();
        for value in values {
            let target = builder.add_virtual_nonnative_target::<FF>();
            witness
                .set_biguint_target(&target.value, &value)
                .expect("input must fit");
            let inverse = builder.inv_nonnative(&target);
            register_nonnative(&mut builder, &inverse);
            expected.push(value.modpow(&exponent, &modulus));
        }

        let data = builder.build::<C>();
        let proof = data
            .prove(witness)
            .expect("valid nonnative inverse witness must prove");
        assert_eq!(outputs_as_biguint(&proof.public_inputs), expected);
        data.verify(proof)
            .expect("valid nonnative inverse proof must verify");
    }

    #[test]
    fn fp_nonnative_inverse_matches_biguint() {
        inverse_cases::<Secp256K1Base>();
    }

    #[test]
    fn fn_nonnative_inverse_matches_biguint() {
        inverse_cases::<Secp256K1Scalar>();
    }

    fn rejects_noncanonical<FF: PrimeField>() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let value = builder.add_virtual_nonnative_target::<FF>();
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness
            .set_biguint_target(&value.value, &FF::order())
            .expect("modulus fits the limb array");
        assert!(
            data.prove(witness).is_err(),
            "the modulus itself must not be accepted as canonical"
        );
    }

    #[test]
    fn fp_nonnative_rejects_noncanonical_witness() {
        rejects_noncanonical::<Secp256K1Base>();
    }

    #[test]
    fn fn_nonnative_rejects_noncanonical_witness() {
        rejects_noncanonical::<Secp256K1Scalar>();
    }

    fn rejects_wrong_reduction<FF: PrimeField>() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let a = builder.constant_nonnative::<FF>(FF::from_canonical_u64(7));
        let b = builder.constant_nonnative::<FF>(FF::from_canonical_u64(9));
        let quotient = builder.add_virtual_biguint_target(8);
        range_check_u32_circuit(&mut builder, quotient.limbs.clone());
        let remainder = builder.add_virtual_nonnative_target::<FF>();
        constrain_product_reduction(&mut builder, &a, &b, &quotient, &remainder);
        let data = builder.build::<C>();

        let mut witness = PartialWitness::new();
        witness
            .set_biguint_target(&quotient, &BigUint::zero())
            .expect("zero quotient fits");
        witness
            .set_biguint_target(&remainder.value, &BigUint::from(62u32))
            .expect("wrong remainder fits");
        assert!(
            data.prove(witness).is_err(),
            "a canonical but incorrect quotient/remainder pair must fail"
        );
    }

    #[test]
    fn fp_nonnative_rejects_wrong_product_reduction() {
        rejects_wrong_reduction::<Secp256K1Base>();
    }

    #[test]
    fn fn_nonnative_rejects_wrong_product_reduction() {
        rejects_wrong_reduction::<Secp256K1Scalar>();
    }

    #[test]
    fn one_nonnative_mul_mod_gate_count() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let a = builder.add_virtual_nonnative_target::<Secp256K1Base>();
        let b = builder.add_virtual_nonnative_target::<Secp256K1Base>();
        let _product = builder.mul_nonnative(&a, &b);
        let gate_count = builder.num_gates();
        println!("one nonnative mul mod gate count: {gate_count}");
        assert!(
            gate_count <= 1_000,
            "one nonnative multiplication used {gate_count} gates"
        );
    }
}
