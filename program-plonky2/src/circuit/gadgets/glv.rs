//! secp256k1 GLV decomposition and efficient in-circuit scalar multiplication.

use std::any::type_name;
use std::marker::PhantomData;

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::circuit::gadgets::biguint::{GeneratedValuesBigUint, WitnessBigUint};
use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_msm::curve_msm_circuit;
use crate::circuit::gadgets::curve_types::{
    decompose_secp256k1_scalar as host_decompose, Secp256K1, GLV_BETA, GLV_S,
};
use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

pub trait CircuitBuilderGlv<F: RichField + Extendable<D>, const D: usize> {
    fn secp256k1_glv_beta(&mut self) -> NonNativeTarget<Secp256K1Base>;
    fn decompose_secp256k1_scalar(
        &mut self,
        k: &NonNativeTarget<Secp256K1Scalar>,
    ) -> (
        NonNativeTarget<Secp256K1Scalar>,
        NonNativeTarget<Secp256K1Scalar>,
        BoolTarget,
        BoolTarget,
    );
    fn glv_mul(
        &mut self,
        p: &AffinePointTarget<Secp256K1>,
        k: &NonNativeTarget<Secp256K1Scalar>,
    ) -> AffinePointTarget<Secp256K1>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderGlv<F, D>
    for CircuitBuilder<F, D>
{
    fn secp256k1_glv_beta(&mut self) -> NonNativeTarget<Secp256K1Base> {
        self.constant_nonnative(GLV_BETA)
    }

    fn decompose_secp256k1_scalar(
        &mut self,
        k: &NonNativeTarget<Secp256K1Scalar>,
    ) -> (
        NonNativeTarget<Secp256K1Scalar>,
        NonNativeTarget<Secp256K1Scalar>,
        BoolTarget,
        BoolTarget,
    ) {
        let k1 = self.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k2 = self.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k1_neg = self.add_virtual_bool_target_safe();
        let k2_neg = self.add_virtual_bool_target_safe();
        self.add_simple_generator(GlvDecompositionGenerator::<F, D> {
            k: k.clone(),
            k1: k1.clone(),
            k2: k2.clone(),
            k1_neg,
            k2_neg,
            _phantom: PhantomData,
        });

        let k1_raw = self.nonnative_conditional_neg(&k1, k1_neg);
        let k2_raw = self.nonnative_conditional_neg(&k2, k2_neg);
        let s = self.constant_nonnative(GLV_S);
        let s_k2 = self.mul_nonnative(&s, &k2_raw);
        let reconstructed = self.add_nonnative(&s_k2, &k1_raw);
        self.connect_nonnative(&reconstructed, k);
        (k1, k2, k1_neg, k2_neg)
    }

    fn glv_mul(
        &mut self,
        p: &AffinePointTarget<Secp256K1>,
        k: &NonNativeTarget<Secp256K1Scalar>,
    ) -> AffinePointTarget<Secp256K1> {
        let (k1, k2, k1_neg, k2_neg) = self.decompose_secp256k1_scalar(k);
        let beta = self.secp256k1_glv_beta();
        let beta_x = self.mul_nonnative(&beta, &p.x);
        let psi_p = AffinePointTarget {
            x: beta_x,
            y: p.y.clone(),
        };
        let signed_p = self.curve_conditional_neg(p, k1_neg);
        let signed_psi_p = self.curve_conditional_neg(&psi_p, k2_neg);
        curve_msm_circuit(self, &signed_p, &signed_psi_p, &k1, &k2)
    }
}

#[derive(Debug)]
struct GlvDecompositionGenerator<F: RichField + Extendable<D>, const D: usize> {
    k: NonNativeTarget<Secp256K1Scalar>,
    k1: NonNativeTarget<Secp256K1Scalar>,
    k2: NonNativeTarget<Secp256K1Scalar>,
    k1_neg: BoolTarget,
    k2_neg: BoolTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for GlvDecompositionGenerator<F, D>
{
    fn id(&self) -> String {
        type_name::<Self>().to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.k.value.limbs.iter().map(|limb| limb.0).collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let k = Secp256K1Scalar::from_noncanonical_biguint(
            witness.get_biguint_target(self.k.value.clone()),
        );
        let (k1, k2, k1_neg, k2_neg) = host_decompose(k);
        out_buffer.set_biguint_target(&self.k1.value, &k1.to_canonical_biguint())?;
        out_buffer.set_biguint_target(&self.k2.value, &k2.to_canonical_biguint())?;
        out_buffer.set_bool_target(self.k1_neg, k1_neg)?;
        out_buffer.set_bool_target(self.k2_neg, k2_neg)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_nonnative(dst, &self.k)?;
        write_nonnative(dst, &self.k1)?;
        write_nonnative(dst, &self.k2)?;
        dst.write_target_bool(self.k1_neg)?;
        dst.write_target_bool(self.k2_neg)
    }

    fn deserialize(src: &mut Buffer, _common: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            k: read_nonnative(src)?,
            k1: read_nonnative(src)?,
            k2: read_nonnative(src)?,
            k1_neg: src.read_target_bool()?,
            k2_neg: src.read_target_bool()?,
            _phantom: PhantomData,
        })
    }
}

fn write_nonnative<FF: Field>(dst: &mut Vec<u8>, value: &NonNativeTarget<FF>) -> IoResult<()> {
    dst.write_usize(value.value.limbs.len())?;
    for limb in &value.value.limbs {
        dst.write_target(limb.0)?;
    }
    Ok(())
}

fn read_nonnative<FF: Field>(src: &mut Buffer) -> IoResult<NonNativeTarget<FF>> {
    let len = src.read_usize()?;
    let mut limbs = Vec::with_capacity(len);
    for _ in 0..len {
        limbs.push(crate::u32_lib::gadgets::arithmetic_u32::U32Target(
            src.read_target()?,
        ));
    }
    Ok(NonNativeTarget {
        value: crate::circuit::gadgets::biguint::BigUintTarget { limbs },
        _phantom: PhantomData,
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod curve_tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::time::Instant;

    use num::BigUint;
    use plonky2::field::secp256k1_base::Secp256K1Base;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2::field::types::{Field, PrimeField};
    use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGeneratorRef};
    use plonky2::iop::target::{BoolTarget, Target};
    use plonky2::iop::witness::{PartialWitness, PartitionWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
    use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
    use secp256k1::{Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::{read_nonnative, write_nonnative, CircuitBuilderGlv};
    use crate::circuit::gadgets::biguint::{GeneratedValuesBigUint, WitnessBigUint};
    use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
    use crate::circuit::gadgets::curve_types::{
        lift_x_even_y, AffinePoint, Curve, CurveScalar, Secp256K1,
    };
    use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
    use crate::{C, D, F};

    #[derive(Debug)]
    struct NonBooleanGlvDecompositionGenerator {
        k: NonNativeTarget<Secp256K1Scalar>,
        k1: NonNativeTarget<Secp256K1Scalar>,
        k2: NonNativeTarget<Secp256K1Scalar>,
        k1_neg: BoolTarget,
        k2_neg: BoolTarget,
    }

    impl SimpleGenerator<F, D> for NonBooleanGlvDecompositionGenerator {
        fn id(&self) -> String {
            "NonBooleanGlvDecompositionGenerator".to_owned()
        }

        fn dependencies(&self) -> Vec<Target> {
            self.k.value.limbs.iter().map(|limb| limb.0).collect()
        }

        fn run_once(
            &self,
            witness: &PartitionWitness<F>,
            out_buffer: &mut GeneratedValues<F>,
        ) -> anyhow::Result<()> {
            assert_eq!(
                witness.get_biguint_target(self.k.value.clone()),
                BigUint::from(0u8),
                "the malicious GLV fixture requires k = 0"
            );
            out_buffer.set_biguint_target(&self.k1.value, &BigUint::from(0u8))?;
            out_buffer.set_biguint_target(&self.k2.value, &BigUint::from(0u8))?;
            out_buffer.set_target(self.k1_neg.target, F::from_canonical_u64(2))?;
            out_buffer.set_bool_target(self.k2_neg, false)
        }

        fn serialize(
            &self,
            dst: &mut Vec<u8>,
            _common: &CommonCircuitData<F, D>,
        ) -> IoResult<()> {
            write_nonnative(dst, &self.k)?;
            write_nonnative(dst, &self.k1)?;
            write_nonnative(dst, &self.k2)?;
            dst.write_target_bool(self.k1_neg)?;
            dst.write_target_bool(self.k2_neg)
        }

        fn deserialize(src: &mut Buffer, _common: &CommonCircuitData<F, D>) -> IoResult<Self> {
            Ok(Self {
                k: read_nonnative(src)?,
                k1: read_nonnative(src)?,
                k2: read_nonnative(src)?,
                k1_neg: src.read_target_bool()?,
                k2_neg: src.read_target_bool()?,
            })
        }
    }

    fn scalar_from_bytes(bytes: [u8; 32]) -> Secp256K1Scalar {
        Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&bytes))
    }

    fn field_bytes<FF: PrimeField>(value: FF) -> [u8; 32] {
        let bytes = value.to_canonical_biguint().to_bytes_be();
        assert!(bytes.len() <= 32);
        let mut result = [0u8; 32];
        result[32 - bytes.len()..].copy_from_slice(&bytes);
        result
    }

    fn oracle_mul(bytes: [u8; 32]) -> AffinePoint<Secp256K1> {
        let secret = SecretKey::from_slice(&bytes).expect("test scalar must be a valid secret key");
        let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        oracle_point(public)
    }

    fn oracle_point(public: PublicKey) -> AffinePoint<Secp256K1> {
        let serialized = public.serialize_uncompressed();
        AffinePoint::nonzero(
            Secp256K1Base::from_noncanonical_biguint(BigUint::from_bytes_be(&serialized[1..33])),
            Secp256K1Base::from_noncanonical_biguint(BigUint::from_bytes_be(&serialized[33..65])),
        )
    }

    fn set_nonnative<FF: PrimeField>(
        witness: &mut PartialWitness<F>,
        target: &NonNativeTarget<FF>,
        value: FF,
    ) {
        witness
            .set_biguint_target(&target.value, &value.to_canonical_biguint())
            .expect("set nonnative witness");
    }

    fn set_point(
        witness: &mut PartialWitness<F>,
        target: &AffinePointTarget<Secp256K1>,
        point: AffinePoint<Secp256K1>,
    ) {
        set_nonnative(witness, &target.x, point.x);
        set_nonnative(witness, &target.y, point.y);
    }

    fn proof_failure(result: std::thread::Result<anyhow::Result<impl Sized>>) -> bool {
        result.is_err() || result.expect("checked panic").is_err()
    }

    #[test]
    fn curve_host_arithmetic_and_lift_x_match_secp256k1_oracle() {
        let one_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        };
        let wide_bytes = [0x42; 32];
        for bytes in [one_bytes, wide_bytes] {
            let scalar = scalar_from_bytes(bytes);
            let ours = (CurveScalar(scalar) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
            assert_eq!(ours, oracle_mul(bytes));
        }

        let generator_x = field_bytes(Secp256K1::GENERATOR_AFFINE.x);
        let x_only = XOnlyPublicKey::from_slice(&generator_x).expect("generator x must lift");
        let oracle_even = oracle_point(PublicKey::from_x_only_public_key(x_only, Parity::Even));
        let lifted = lift_x_even_y(Secp256K1::GENERATOR_AFFINE.x).expect("generator x must lift");
        assert_eq!(lifted, oracle_even);
        assert_eq!(
            lifted.y.to_canonical_biguint() & BigUint::from(1u8),
            BigUint::from(0u8)
        );

        let mut saw_non_residue = false;
        for x_u64 in 0..64 {
            let x = Secp256K1Base::from_canonical_u64(x_u64);
            let bytes = field_bytes(x);
            let oracle = XOnlyPublicKey::from_slice(&bytes);
            let ours = lift_x_even_y(x);
            assert_eq!(
                ours.is_ok(),
                oracle.is_ok(),
                "lift_x disagreement for x={x_u64}"
            );
            if oracle.is_err() {
                saw_non_residue = true;
                assert!(ours.is_err(), "non-residue must fail loudly");
            } else {
                let point = ours.expect("status checked");
                let expected = oracle_point(PublicKey::from_x_only_public_key(
                    oracle.expect("status checked"),
                    Parity::Even,
                ));
                assert_eq!(point, expected);
            }
        }
        assert!(saw_non_residue, "test range must contain a non-residue");
    }

    #[test]
    fn curve_assert_valid_rejects_off_curve_point() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let generator = Secp256K1::GENERATOR_AFFINE;
        let tampered = AffinePoint::<Secp256K1> {
            x: generator.x,
            y: generator.y + Secp256K1Base::ONE,
            zero: false,
        };
        let target = builder.constant_affine_point(tampered);
        builder.curve_assert_valid(&target);
        let data = builder.build::<C>();
        let failed = catch_unwind(AssertUnwindSafe(|| data.prove(PartialWitness::new())));
        assert!(
            proof_failure(failed),
            "an off-curve constant unexpectedly satisfied the circuit"
        );
    }

    /// A malicious GLV generator setting a sign flag to 2 must fail proving.
    ///
    /// With `k = k1 = k2 = 0`, the non-Boolean flag does not disturb any of
    /// the pre-existing scalar-reconstruction equations, so this regression
    /// fails before the production sign allocation is made Boolean-safe.
    #[test]
    fn glv_decomposition_rejects_non_boolean_sign_flag() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let k = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let (k1, k2, k1_neg, k2_neg) = builder.decompose_secp256k1_scalar(&k);
        let mut data = builder.build::<C>();

        let generator_index = data
            .prover_only
            .generators
            .iter()
            .position(|generator| generator.0.id().contains("GlvDecompositionGenerator"))
            .expect("GLV decomposition generator must be present");
        data.prover_only.generators[generator_index] = WitnessGeneratorRef::new(
            NonBooleanGlvDecompositionGenerator {
                k: k.clone(),
                k1,
                k2,
                k1_neg,
                k2_neg,
            }
            .adapter(),
        );

        let mut witness = PartialWitness::new();
        set_nonnative(&mut witness, &k, Secp256K1Scalar::ZERO);
        let failed = catch_unwind(AssertUnwindSafe(|| data.prove(witness)));
        assert!(
            proof_failure(failed),
            "a non-Boolean GLV sign flag unexpectedly satisfied the circuit"
        );
    }

    #[test]
    fn curve_glv_scalar_mul_release_measurement() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let scalar_target = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let expected_target = builder.add_virtual_affine_point_target::<Secp256K1>();
        let generator_target = builder.constant_affine_point(Secp256K1::GENERATOR_AFFINE);
        let actual = builder.glv_mul(&generator_target, &scalar_target);
        builder.connect_affine_point(&actual, &expected_target);
        builder.curve_assert_valid(&actual);

        // Exercise affine circuit doubling/addition against independent libsecp256k1 points.
        let doubled = builder.curve_double(&generator_target);
        let two_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 2;
            bytes
        };
        let doubled_oracle = builder.constant_affine_point(oracle_mul(two_bytes));
        builder.connect_affine_point(&doubled, &doubled_oracle);
        let tripled = builder.curve_add(&generator_target, &doubled);
        let three_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 3;
            bytes
        };
        let tripled_oracle = builder.constant_affine_point(oracle_mul(three_bytes));
        builder.connect_affine_point(&tripled, &tripled_oracle);

        let num_gates = builder.num_gates();
        println!("scalar_mul num_gates(): {num_gates}");
        assert!(
            num_gates <= 5_000_000,
            "scalar_mul circuit exceeds the 5M-gate stop threshold"
        );
        let build_started = Instant::now();
        let data = builder.build::<C>();
        let build_elapsed = build_started.elapsed();
        println!("scalar_mul degree_bits(): {}", data.common.degree_bits());
        println!("scalar_mul build() wall-clock: {build_elapsed:?}");

        let wide_bytes = [0x42; 32];
        let wide_scalar = scalar_from_bytes(wide_bytes);
        let wide_expected = oracle_mul(wide_bytes);
        let mut wide_witness = PartialWitness::new();
        set_nonnative(&mut wide_witness, &scalar_target, wide_scalar);
        set_point(&mut wide_witness, &expected_target, wide_expected);
        let prove_started = Instant::now();
        let proof = data.prove(wide_witness).expect("wide scalar proof failed");
        let prove_elapsed = prove_started.elapsed();
        println!("scalar_mul prove() wall-clock: {prove_elapsed:?}");
        data.verify(proof)
            .expect("wide scalar proof verification failed");

        let one_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        };
        let mut one_witness = PartialWitness::new();
        set_nonnative(&mut one_witness, &scalar_target, Secp256K1Scalar::ONE);
        set_point(&mut one_witness, &expected_target, oracle_mul(one_bytes));
        let one_proof = data.prove(one_witness).expect("k=1 proof failed");
        data.verify(one_proof)
            .expect("k=1 proof verification failed");

        let mut wrong_witness = PartialWitness::new();
        set_nonnative(&mut wrong_witness, &scalar_target, wide_scalar);
        let wrong = AffinePoint::<Secp256K1> {
            x: wide_expected.x,
            y: wide_expected.y + Secp256K1Base::ONE,
            zero: false,
        };
        set_point(&mut wrong_witness, &expected_target, wrong);
        let failed = catch_unwind(AssertUnwindSafe(|| data.prove(wrong_witness)));
        assert!(
            proof_failure(failed),
            "a mutated scalar-multiplication result unexpectedly satisfied the circuit"
        );
    }

    #[test]
    fn curve_glv_scalar_mul_fits_standard_recursion_zk_config() {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let scalar_target = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let expected_target = builder.add_virtual_affine_point_target::<Secp256K1>();
        let generator_target = builder.constant_affine_point(Secp256K1::GENERATOR_AFFINE);
        let actual = builder.glv_mul(&generator_target, &scalar_target);
        builder.connect_affine_point(&actual, &expected_target);
        builder.curve_assert_valid(&actual);

        println!(
            "pinned recursion-zk scalar_mul num_gates(): {}",
            builder.num_gates()
        );
        let data = builder.build::<C>();
        println!(
            "pinned recursion-zk scalar_mul degree_bits(): {}",
            data.common.degree_bits()
        );

        let scalar_bytes = [0x42; 32];
        let mut witness = PartialWitness::new();
        set_nonnative(
            &mut witness,
            &scalar_target,
            scalar_from_bytes(scalar_bytes),
        );
        set_point(&mut witness, &expected_target, oracle_mul(scalar_bytes));
        let proof = data
            .prove(witness)
            .expect("pinned recursion-zk scalar_mul proof failed");
        data.verify(proof)
            .expect("pinned recursion-zk scalar_mul proof verification failed");
    }
}
