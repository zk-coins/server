//! In-circuit BIP-340 verification and sign-to-contract opening for secp256k1.

use std::any::type_name;
use std::marker::PhantomData;

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartitionWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::circuit::gadgets::biguint::{BigUintTarget, GeneratedValuesBigUint, WitnessBigUint};
use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::{lift_x_even_y, Curve, Secp256K1};
use crate::circuit::gadgets::glv::CircuitBuilderGlv;
use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::circuit::gadgets::sha256::{sha256, tagged_sha256};
use crate::u32_lib::gadgets::arithmetic_u32::U32Target;

/// The complete verifier-side result of opening a sign-to-contract nonce.
#[derive(Clone, Debug)]
pub struct S2cOpening {
    /// The committed nonce point `R = R' + tG`.
    pub r: AffinePointTarget<Secp256K1>,
    /// The BIP-340 x-only nonce encoding as a canonical base-field target.
    pub rx: NonNativeTarget<Secp256K1Base>,
    /// The same x-only nonce encoding as 32 big-endian byte targets.
    pub rx_bytes: [Target; 32],
}

/// Decompose a canonical 256-bit nonnative value into 32 big-endian bytes.
///
/// The source limbs are little-endian u32 values. Each returned byte is
/// reconstructed from Boolean bits and explicitly range-checked.
pub fn nonnative_to_be_bytes32<FF: Field, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &NonNativeTarget<FF>,
) -> [Target; 32] {
    assert_eq!(FF::BITS, 256, "byte encoding requires a 256-bit field");
    let value = builder.nonnative_to_canonical_biguint(x);
    assert!(
        value.limbs.len() <= 8,
        "a 256-bit nonnative value must have at most eight u32 limbs"
    );

    let mut bytes = Vec::with_capacity(32);
    for limb_index in (0..8).rev() {
        let limb = value
            .limbs
            .get(limb_index)
            .map(|limb| limb.0)
            .unwrap_or_else(|| builder.zero());
        let bits = builder.split_le(limb, 32);
        for byte_index in (0..4).rev() {
            let offset = byte_index * 8;
            let byte = builder.le_sum(bits[offset..offset + 8].iter());
            builder.range_check(byte, 8);
            bytes.push(byte);
        }
    }
    bytes
        .try_into()
        .expect("eight u32 limbs always encode as 32 bytes")
}

/// Reduce 32 big-endian bytes into a canonical nonnative field element.
///
/// The input bytes are expected to have already been range-checked by their
/// producer. Splitting them here also constrains their eight-bit
/// decompositions before regrouping them into little-endian u32 limbs.
pub fn be_bytes32_to_nonnative<FF: Field, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bytes: &[Target; 32],
) -> NonNativeTarget<FF> {
    assert_eq!(FF::BITS, 256, "byte decoding requires a 256-bit field");

    let mut limbs = Vec::with_capacity(8);
    for chunk in bytes.rchunks_exact(4) {
        let mut limb_bits = Vec::with_capacity(32);
        for &byte in chunk.iter().rev() {
            limb_bits.extend(builder.split_le(byte, 8));
        }
        let limb = builder.le_sum(limb_bits.iter());
        builder.range_check(limb, 32);
        limbs.push(U32Target(limb));
    }
    builder.reduce::<FF>(&BigUintTarget { limbs })
}

fn assert_even<FF: Field, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: &NonNativeTarget<FF>,
) {
    let canonical = builder.nonnative_to_canonical_biguint(value);
    let low_limb = canonical
        .limbs
        .first()
        .expect("a secp256k1 field target always has a low limb");
    let low_bits = builder.split_le(low_limb.0, 32);
    builder.assert_zero(low_bits[0].target);
}

/// BIP-340 `lift_x`: witness and constrain the unique even-y point for `x`.
pub fn lift_x_even_y_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &NonNativeTarget<Secp256K1Base>,
) -> AffinePointTarget<Secp256K1> {
    let y = builder.add_virtual_nonnative_target::<Secp256K1Base>();
    builder.add_simple_generator(LiftXEvenYGenerator::<F, D> {
        x: x.clone(),
        y: y.clone(),
        _phantom: PhantomData,
    });
    let point = AffinePointTarget { x: x.clone(), y };
    builder.curve_assert_valid(&point);
    assert_even(builder, &point.y);
    point
}

/// Verify a BIP-340 signature `(rx, s)` by the x-only key `pk_x`.
///
/// `m_state` is compile-time circuit structure and is baked into the tagged
/// challenge as constant ASCII bytes. Canonical-range constraints on `pk_x`,
/// `rx`, and `s` are supplied by their `NonNativeTarget` allocators.
///
/// The final affine addition cannot represent the point at infinity. No
/// separate infinity flag is added: if `sG` and `e(-P)` are mutual inverses
/// (or hit the doubling exceptional case), `curve_add` must invert a zero
/// denominator, whose existing nonnative inverse constraints are
/// unsatisfiable. Thus the existing incomplete-affine representation already
/// rejects the BIP-340 `R = infinity` case.
pub fn bip340_verify<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pk_x: &NonNativeTarget<Secp256K1Base>,
    rx: &NonNativeTarget<Secp256K1Base>,
    s: &NonNativeTarget<Secp256K1Scalar>,
    m_state: &[u8],
) {
    let rx_bytes = nonnative_to_be_bytes32(builder, rx);
    bip340_verify_with_rx_bytes(builder, pk_x, rx, &rx_bytes, s, m_state);
}

fn bip340_verify_with_rx_bytes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pk_x: &NonNativeTarget<Secp256K1Base>,
    rx: &NonNativeTarget<Secp256K1Base>,
    rx_bytes: &[Target; 32],
    s: &NonNativeTarget<Secp256K1Scalar>,
    m_state: &[u8],
) {
    assert!(
        m_state.is_ascii(),
        "the fixed BIP-340 state message must be ASCII"
    );
    let canonical_s = builder.nonnative_to_canonical_biguint(s);
    let zero = builder.zero();
    let mut s_is_zero = builder.constant_bool(true);
    for limb in canonical_s.limbs {
        let limb_is_zero = builder.is_equal(limb.0, zero);
        s_is_zero = builder.and(s_is_zero, limb_is_zero);
    }
    let s_is_nonzero = builder.not(s_is_zero);
    builder.assert_one(s_is_nonzero.target);

    let p = lift_x_even_y_target(builder, pk_x);
    let pk_bytes = nonnative_to_be_bytes32(builder, pk_x);
    let mut challenge_preimage = Vec::with_capacity(64 + m_state.len());
    challenge_preimage.extend_from_slice(rx_bytes);
    challenge_preimage.extend_from_slice(&pk_bytes);
    challenge_preimage.extend(
        m_state
            .iter()
            .map(|&byte| builder.constant(F::from_canonical_u8(byte))),
    );
    let e_bytes = tagged_sha256(builder, b"BIP0340/challenge", &challenge_preimage);
    let e = be_bytes32_to_nonnative::<Secp256K1Scalar, F, D>(builder, &e_bytes);

    let generator = builder.constant_affine_point(Secp256K1::GENERATOR_AFFINE);
    let s_g = builder.glv_mul(&generator, s);
    let neg_p = builder.curve_neg(&p);
    let e_neg_p = builder.glv_mul(&neg_p, &e);
    let candidate = builder.curve_add(&s_g, &e_neg_p);
    builder.connect_nonnative(&candidate.x, rx);
    assert_even(builder, &candidate.y);
}

fn s2c_open_full<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    r_prime: &AffinePointTarget<Secp256K1>,
    h_proof_data: &[Target; 32],
) -> S2cOpening {
    builder.curve_assert_valid(r_prime);
    let r_prime_bytes = nonnative_to_be_bytes32(builder, &r_prime.x);
    let mut tweak_preimage = Vec::with_capacity(64);
    tweak_preimage.extend_from_slice(&r_prime_bytes);
    tweak_preimage.extend_from_slice(h_proof_data);
    let t_bytes = sha256(builder, &tweak_preimage);
    let t = be_bytes32_to_nonnative::<Secp256K1Scalar, F, D>(builder, &t_bytes);

    let generator = builder.constant_affine_point(Secp256K1::GENERATOR_AFFINE);
    let t_g = builder.glv_mul(&generator, &t);
    let r = builder.curve_add(r_prime, &t_g);
    let rx = r.x.clone();
    let rx_bytes = nonnative_to_be_bytes32(builder, &rx);
    S2cOpening { r, rx, rx_bytes }
}

/// Open a sign-to-contract nonce and return its BIP-340 x-only value.
pub fn s2c_open<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    r_prime: &AffinePointTarget<Secp256K1>,
    h_proof_data: &[Target; 32],
) -> NonNativeTarget<Secp256K1Base> {
    s2c_open_full(builder, r_prime, h_proof_data).rx
}

/// Open a sign-to-contract nonce and expose its point and x-only byte forms.
pub fn s2c_open_with_point<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    r_prime: &AffinePointTarget<Secp256K1>,
    h_proof_data: &[Target; 32],
) -> S2cOpening {
    s2c_open_full(builder, r_prime, h_proof_data)
}

/// Verify the full clause-2 chain: the signature and its S2C opening.
///
/// `signature_rx` is the canonical x-only nonce carried by the signature. It
/// is copy-constrained to the opening result, and that computed result is fed
/// directly to [`bip340_verify`]'s internal verification path.
pub fn bip340_verify_with_s2c<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pk_x: &NonNativeTarget<Secp256K1Base>,
    signature_rx: &NonNativeTarget<Secp256K1Base>,
    s: &NonNativeTarget<Secp256K1Scalar>,
    m_state: &[u8],
    r_prime: &AffinePointTarget<Secp256K1>,
    h_proof_data: &[Target; 32],
) -> S2cOpening {
    let opening = s2c_open_full(builder, r_prime, h_proof_data);
    builder.connect_nonnative(&opening.rx, signature_rx);
    bip340_verify_with_rx_bytes(builder, pk_x, &opening.rx, &opening.rx_bytes, s, m_state);
    opening
}

#[derive(Debug)]
struct LiftXEvenYGenerator<F: RichField + Extendable<D>, const D: usize> {
    x: NonNativeTarget<Secp256K1Base>,
    y: NonNativeTarget<Secp256K1Base>,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for LiftXEvenYGenerator<F, D>
{
    fn id(&self) -> String {
        type_name::<Self>().to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.x.value.limbs.iter().map(|limb| limb.0).collect()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let x = Secp256K1Base::from_noncanonical_biguint(
            witness.get_biguint_target(self.x.value.clone()),
        );
        let point = lift_x_even_y(x)?;
        out_buffer.set_biguint_target(&self.y.value, &point.y.to_canonical_biguint())
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common: &CommonCircuitData<F, D>) -> IoResult<()> {
        write_nonnative(dst, &self.x)?;
        write_nonnative(dst, &self.y)
    }

    fn deserialize(src: &mut Buffer, _common: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            x: read_nonnative(src)?,
            y: read_nonnative(src)?,
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
        limbs.push(U32Target(src.read_target()?));
    }
    Ok(NonNativeTarget {
        value: BigUintTarget { limbs },
        _phantom: PhantomData,
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::time::Instant;

    use num::BigUint;
    use plonky2::field::types::PrimeField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::circuit::gadgets::curve_types::{AffinePoint, CurveScalar};
    use crate::{C, D, F};

    const M_STATE: &[u8] = b"zkCoins/v1/StateUpdate/testnet";
    const PK_1: &str = "e7f2a98e7b45e9424e3e0cb1d937a1698ebd339c6d8344906db979642cf20474";
    const R_PRIME_1: &str = "5657f2e91dc3a2d248501a37dbe674d2cf8ed1a13c89b7710ca89aad3b9fe050";
    const T_1: &str = "423984fa39ce7b1a4d8eb164ab2a300d56b9de4f4ed3134339db5ead7ccc17c2";
    const R_1: &str = "c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4";
    const E_1: &str = "88aa41dbac65bb97f235c7fe064ebd5b8882d2bc04f8792aebec2c8c4df7fd4f";
    const S_1: &str = "748ae8e2fded9df9830cbaa8893484e753fdfd141cccc8b35a27ab5a870a83d2";
    const M_SC: &str = "bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2";

    #[derive(Clone)]
    struct FixtureTargets {
        pk_x: NonNativeTarget<Secp256K1Base>,
        rx: NonNativeTarget<Secp256K1Base>,
        s: NonNativeTarget<Secp256K1Scalar>,
        r_prime: AffinePointTarget<Secp256K1>,
        h_proof_data: [Target; 32],
        expected_rx: NonNativeTarget<Secp256K1Base>,
    }

    fn hex_bytes(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut result = [0u8; 32];
        for (index, byte) in result.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16).expect("fixture hex");
        }
        result
    }

    fn field_from_hex<FF: PrimeField>(value: &str) -> FF {
        let integer = BigUint::from_bytes_be(&hex_bytes(value));
        assert!(integer < FF::order(), "fixture value must be canonical");
        FF::from_noncanonical_biguint(integer)
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

    fn fixture_witness(
        targets: &FixtureTargets,
        pk: &str,
        rx: &str,
        s: &str,
        h_proof_data: &str,
    ) -> PartialWitness<F> {
        let mut witness = PartialWitness::new();
        set_nonnative(
            &mut witness,
            &targets.pk_x,
            field_from_hex::<Secp256K1Base>(pk),
        );
        set_nonnative(
            &mut witness,
            &targets.rx,
            field_from_hex::<Secp256K1Base>(rx),
        );
        set_nonnative(
            &mut witness,
            &targets.s,
            field_from_hex::<Secp256K1Scalar>(s),
        );
        let r_prime =
            lift_x_even_y(field_from_hex::<Secp256K1Base>(R_PRIME_1)).expect("pinned R' must lift");
        set_point(&mut witness, &targets.r_prime, r_prime);
        for (&target, byte) in targets.h_proof_data.iter().zip(hex_bytes(h_proof_data)) {
            witness
                .set_target(target, F::from_canonical_u8(byte))
                .expect("set H(ProofData) byte");
        }
        set_nonnative(
            &mut witness,
            &targets.expected_rx,
            field_from_hex::<Secp256K1Base>(R_1),
        );
        witness
    }

    fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
        let tag_hash = Sha256::digest(tag);
        let mut preimage = Vec::with_capacity(64 + message.len());
        preimage.extend_from_slice(&tag_hash);
        preimage.extend_from_slice(&tag_hash);
        preimage.extend_from_slice(message);
        Sha256::digest(preimage).into()
    }

    fn host_fixture_sanity() {
        let r_prime_x = field_from_hex::<Secp256K1Base>(R_PRIME_1);
        let r_prime = lift_x_even_y(r_prime_x).expect("R' must lift");
        let mut tweak_preimage = Vec::with_capacity(64);
        tweak_preimage.extend_from_slice(&hex_bytes(R_PRIME_1));
        tweak_preimage.extend_from_slice(&hex_bytes(M_SC));
        let t_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
        assert_eq!(t_bytes, hex_bytes(T_1), "pinned tweak mismatch");
        let t = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&t_bytes));
        let r =
            (r_prime + (CurveScalar(t) * Secp256K1::GENERATOR_PROJECTIVE).to_affine()).to_affine();
        assert!(!r.zero, "S2C point must not be infinity");
        assert_eq!(r.x, field_from_hex::<Secp256K1Base>(R_1));
        assert!(
            !(&r.y.to_canonical_biguint() & BigUint::from(1u8)).eq(&BigUint::from(1u8)),
            "S2C nonce y must be even"
        );

        let mut challenge_preimage = Vec::with_capacity(64 + M_STATE.len());
        challenge_preimage.extend_from_slice(&hex_bytes(R_1));
        challenge_preimage.extend_from_slice(&hex_bytes(PK_1));
        challenge_preimage.extend_from_slice(M_STATE);
        let e_bytes = tagged_hash(b"BIP0340/challenge", &challenge_preimage);
        assert_eq!(e_bytes, hex_bytes(E_1), "pinned challenge mismatch");
        let e = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&e_bytes));
        let s = field_from_hex::<Secp256K1Scalar>(S_1);
        let p = lift_x_even_y(field_from_hex::<Secp256K1Base>(PK_1))
            .expect("pinned public key must lift");
        let candidate = ((CurveScalar(s) * Secp256K1::GENERATOR_PROJECTIVE)
            + (CurveScalar(e) * (-p).to_projective()))
        .to_affine();
        assert!(!candidate.zero, "BIP-340 candidate must not be infinity");
        assert_eq!(candidate.x, field_from_hex::<Secp256K1Base>(R_1));
        assert!(
            !(&candidate.y.to_canonical_biguint() & BigUint::from(1u8)).eq(&BigUint::from(1u8)),
            "BIP-340 candidate y must be even"
        );
    }

    #[test]
    fn bip340_v8_composed_release_measurement_and_negative_cases() {
        host_fixture_sanity();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let targets = FixtureTargets {
            pk_x: builder.add_virtual_nonnative_target(),
            rx: builder.add_virtual_nonnative_target(),
            s: builder.add_virtual_nonnative_target(),
            r_prime: builder.add_virtual_affine_point_target(),
            h_proof_data: builder
                .add_virtual_targets(32)
                .try_into()
                .expect("32 H(ProofData) targets"),
            expected_rx: builder.add_virtual_nonnative_target(),
        };
        for &byte in &targets.h_proof_data {
            builder.range_check(byte, 8);
        }
        let opening = bip340_verify_with_s2c(
            &mut builder,
            &targets.pk_x,
            &targets.rx,
            &targets.s,
            M_STATE,
            &targets.r_prime,
            &targets.h_proof_data,
        );
        builder.connect_nonnative(&opening.rx, &targets.expected_rx);

        let num_gates = builder.num_gates();
        println!("bip340+s2c num_gates(): {num_gates}");
        let build_started = Instant::now();
        let data = builder.build::<C>();
        let build_elapsed = build_started.elapsed();
        println!("bip340+s2c degree_bits(): {}", data.common.degree_bits());
        println!("bip340+s2c build() wall-clock: {build_elapsed:?}");

        let valid_witness = fixture_witness(&targets, PK_1, R_1, S_1, M_SC);
        let prove_started = Instant::now();
        let proof = data
            .prove(valid_witness)
            .expect("V.8 composed proof failed");
        let prove_elapsed = prove_started.elapsed();
        println!("bip340+s2c prove() wall-clock: {prove_elapsed:?}");
        data.verify(proof)
            .expect("V.8 composed proof verification failed");
        println!("V.8 valid-verify: PASS");
        println!("S2C valid-opening matches R_1: PASS");
        println!("end-to-end composed clause-2 check: PASS");

        let assert_rejected = |label: &str, witness: PartialWitness<F>| {
            let result = catch_unwind(AssertUnwindSafe(|| data.prove(witness)));
            match result {
                Err(_) | Ok(Err(_)) => {}
                Ok(Ok(proof)) => {
                    assert!(
                        data.verify(proof).is_err(),
                        "{label}: tampered witness unexpectedly proved and verified"
                    );
                }
            }
            println!("{label}: PASS (rejected)");
        };

        let mut tampered_s = S_1.to_owned();
        tampered_s.replace_range(63..64, "3");
        assert_rejected(
            "tampered-s",
            fixture_witness(&targets, PK_1, R_1, &tampered_s, M_SC),
        );
        assert_rejected(
            "zero-s",
            fixture_witness(
                &targets,
                PK_1,
                R_1,
                "0000000000000000000000000000000000000000000000000000000000000000",
                M_SC,
            ),
        );

        let mut tampered_pk = PK_1.to_owned();
        tampered_pk.replace_range(63..64, "5");
        assert_rejected(
            "tampered-Pk",
            fixture_witness(&targets, &tampered_pk, R_1, S_1, M_SC),
        );

        let mut tampered_rx = R_1.to_owned();
        tampered_rx.replace_range(63..64, "5");
        assert_rejected(
            "tampered-rx",
            fixture_witness(&targets, PK_1, &tampered_rx, S_1, M_SC),
        );

        let mut tampered_h = M_SC.to_owned();
        tampered_h.replace_range(63..64, "3");
        assert_rejected(
            "S2C wrong-H(ProofData)",
            fixture_witness(&targets, PK_1, R_1, S_1, &tampered_h),
        );
    }
}
