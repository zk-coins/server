use plonky2::field::types::{Field, Field64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::gadgets::sha256::sha256;
use crate::circuit::gadgets::u128_arith::U128Target;
use crate::{D, F};

pub(crate) fn encode_ascii_tag_elements(tag: &str) -> Vec<u64> {
    let bytes = tag.as_bytes();
    let mut out = Vec::with_capacity(1 + bytes.len().div_ceil(7));
    out.push(bytes.len() as u64);
    for chunk in bytes.chunks(7) {
        let mut seven = [0u8; 7];
        seven[..chunk.len()].copy_from_slice(chunk);
        out.push(u64::from_be_bytes([
            0, seven[0], seven[1], seven[2], seven[3], seven[4], seven[5], seven[6],
        ]));
    }
    out
}

pub(crate) fn tag_targets(builder: &mut CircuitBuilder<F, D>, tag: &str) -> Vec<Target> {
    encode_ascii_tag_elements(tag)
        .into_iter()
        .map(|value| builder.constant(F::from_canonical_u64(value)))
        .collect()
}

pub(crate) fn encode_byte_string_target(
    builder: &mut CircuitBuilder<F, D>,
    bytes: &[Target],
) -> Vec<Target> {
    let mut out = Vec::with_capacity(1 + bytes.len().div_ceil(7));
    out.push(builder.constant(F::from_canonical_usize(bytes.len())));
    for chunk in bytes.chunks(7) {
        let mut encoded = builder.zero();
        for (i, &byte) in chunk.iter().enumerate() {
            builder.split_le(byte, 8);
            let weight = F::from_canonical_u64(1u64 << (8 * (6 - i)));
            encoded = builder.mul_const_add(weight, byte, encoded);
        }
        out.push(encoded);
    }
    out
}

fn less_than_constant_bits(
    builder: &mut CircuitBuilder<F, D>,
    bits_le: &[BoolTarget],
    bound: u64,
) -> BoolTarget {
    let mut equal = builder.constant_bool(true);
    let mut less = builder.constant_bool(false);
    for i in (0..bits_le.len()).rev() {
        let bound_bit = ((bound >> i) & 1) != 0;
        if bound_bit {
            let not_bit = builder.not(bits_le[i]);
            let first_less = builder.and(equal, not_bit);
            less = builder.or(less, first_less);
            equal = builder.and(equal, bits_le[i]);
        } else {
            let not_bit = builder.not(bits_le[i]);
            equal = builder.and(equal, not_bit);
        }
    }
    less
}

/// Canonically decomposes a Goldilocks element.
///
/// `split_le(_, 64)` alone admits a second 64-bit representative for some
/// field values. The explicit `< ORDER` check makes the emitted bytes match
/// host `to_canonical_u64()` byte-for-byte for every proof.
fn canonical_u64_bits(builder: &mut CircuitBuilder<F, D>, value: Target) -> Vec<BoolTarget> {
    let bits = builder.split_le(value, 64);
    let canonical = less_than_constant_bits(builder, &bits, F::ORDER);
    builder.assert_one(canonical.target);
    bits
}

pub(crate) fn digest_to_be_bytes_target(
    builder: &mut CircuitBuilder<F, D>,
    digest: HashOutTarget,
) -> [Target; 32] {
    let mut bytes = Vec::with_capacity(32);
    for element in digest.elements {
        let bits = canonical_u64_bits(builder, element);
        for byte_index in (0..8).rev() {
            let offset = byte_index * 8;
            let byte = builder.le_sum(bits[offset..offset + 8].iter());
            builder.range_check(byte, 8);
            bytes.push(byte);
        }
    }
    bytes
        .try_into()
        .expect("four Goldilocks limbs always encode as 32 bytes")
}

pub(crate) fn u64_to_be_bytes_target(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) -> [Target; 8] {
    let bits = canonical_u64_bits(builder, value);
    std::array::from_fn(|i| {
        let hi = 63 - i * 8;
        let lo = hi - 7;
        builder.le_sum(bits[lo..=hi].iter())
    })
}

pub(crate) fn u128_to_be_bytes_target(
    builder: &mut CircuitBuilder<F, D>,
    value: U128Target,
) -> [Target; 16] {
    let mut bytes = Vec::with_capacity(16);
    for limb in value.limbs.into_iter().rev() {
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
        .expect("four u32 limbs always encode as 16 bytes")
}

/// Converts a big-endian 32-byte integer into eight little-endian u32 limbs.
pub(crate) fn be_bytes32_to_u32_limbs(
    builder: &mut CircuitBuilder<F, D>,
    bytes: &[Target; 32],
) -> [Target; 8] {
    std::array::from_fn(|limb_index| {
        let start = 28 - 4 * limb_index;
        let mut limb = builder.zero();
        for &byte in &bytes[start..start + 4] {
            builder.split_le(byte, 8);
            limb = builder.mul_const_add(F::from_canonical_u64(256), limb, byte);
        }
        builder.range_check(limb, 32);
        limb
    })
}

/// Converts eight little-endian u32 limbs into one big-endian 32-byte integer.
pub(crate) fn u32_limbs_to_be_bytes32(
    builder: &mut CircuitBuilder<F, D>,
    limbs: &[Target; 8],
) -> [Target; 32] {
    let mut bytes = Vec::with_capacity(32);
    for &limb in limbs.iter().rev() {
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

pub(crate) fn strict_be_bytes_less_than(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &[Target; 32],
    rhs: &[Target; 32],
) -> BoolTarget {
    let mut equal = builder.constant_bool(true);
    let mut less = builder.constant_bool(false);
    for (&lhs_byte, &rhs_byte) in lhs.iter().zip(rhs) {
        let lhs_bits = builder.split_le(lhs_byte, 8);
        let rhs_bits = builder.split_le(rhs_byte, 8);
        for bit in (0..8).rev() {
            let not_lhs = builder.not(lhs_bits[bit]);
            let less_here = builder.and(not_lhs, rhs_bits[bit]);
            let first_less = builder.and(equal, less_here);
            less = builder.or(less, first_less);
            let same = builder.is_equal(lhs_bits[bit].target, rhs_bits[bit].target);
            equal = builder.and(equal, same);
        }
    }
    less
}

/// `SHA256(Pk0 || digest_to_bytes(nk_commit))`.
pub fn address_from_pk0_and_nk_commit(
    builder: &mut CircuitBuilder<F, D>,
    pk0: &[Target; 32],
    nk_commit: HashOutTarget,
) -> [Target; 32] {
    let nk_commit_bytes = digest_to_be_bytes_target(builder, nk_commit);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(pk0);
    preimage.extend_from_slice(&nk_commit_bytes);
    sha256(builder, &preimage)
}
