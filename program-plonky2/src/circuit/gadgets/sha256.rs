//! SHA-256 built directly from Plonky2 Boolean and arithmetic primitives.
//!
//! Words are represented internally by 32 little-endian bits. SHA-256's
//! external byte and word encoding remains big-endian, as required by
//! FIPS 180-4.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

type Word = [BoolTarget; 32];
type Byte = [BoolTarget; 8];

const INITIAL_HASH: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn constant_byte<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: u8,
) -> Byte {
    std::array::from_fn(|i| builder.constant_bool(((value >> i) & 1) != 0))
}

fn constant_word<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: u32,
) -> Word {
    std::array::from_fn(|i| builder.constant_bool(((value >> i) & 1) != 0))
}

fn xor_bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lhs: BoolTarget,
    rhs: BoolTarget,
) -> BoolTarget {
    // lhs XOR rhs = lhs + rhs - 2 * lhs * rhs. Since both inputs are
    // constrained booleans, this expression is itself necessarily Boolean.
    let sum = builder.add(lhs.target, rhs.target);
    let target = builder.arithmetic(-F::TWO, F::ONE, lhs.target, rhs.target, sum);
    BoolTarget::new_unsafe(target)
}

fn xor_words<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    words: &[Word],
) -> Word {
    assert!(!words.is_empty(), "xor_words requires at least one word");
    let mut result = words[0];
    for word in &words[1..] {
        result = std::array::from_fn(|i| xor_bit(builder, result[i], word[i]));
    }
    result
}

fn rotate_right(word: &Word, amount: usize) -> Word {
    assert!(amount < 32, "SHA-256 rotation must be less than 32");
    std::array::from_fn(|i| word[(i + amount) % 32])
}

fn shift_right<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    word: &Word,
    amount: usize,
) -> Word {
    assert!(amount < 32, "SHA-256 shift must be less than 32");
    std::array::from_fn(|i| {
        if i + amount < 32 {
            word[i + amount]
        } else {
            builder.constant_bool(false)
        }
    })
}

fn choose<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &Word,
    y: &Word,
    z: &Word,
) -> Word {
    std::array::from_fn(|i| {
        let xy = builder.and(x[i], y[i]);
        let not_x = builder.not(x[i]);
        let not_xz = builder.and(not_x, z[i]);
        // The two terms are disjoint, so OR is identical to XOR here.
        builder.or(xy, not_xz)
    })
}

fn majority<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &Word,
    y: &Word,
    z: &Word,
) -> Word {
    std::array::from_fn(|i| {
        let xy = builder.and(x[i], y[i]);
        let x_or_y = builder.or(x[i], y[i]);
        let z_and_either = builder.and(z[i], x_or_y);
        builder.or(xy, z_and_either)
    })
}

fn add_words<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    words: &[Word],
) -> Word {
    assert!(
        !words.is_empty() && words.len() <= 5,
        "SHA-256 word addition requires between one and five operands"
    );

    let word_targets: Vec<Target> = words
        .iter()
        .map(|word| builder.le_sum(word.iter()))
        .collect();
    let sum = builder.add_many(word_targets);

    // At most five 32-bit operands are added. Splitting all 35 possible
    // sum bits constrains the carries exactly; retaining the low 32 bits
    // implements addition modulo 2^32.
    let sum_bits = builder.split_le(sum, 35);
    sum_bits[..32]
        .try_into()
        .expect("SHA-256 low word always has 32 bits")
}

fn small_sigma_0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &Word,
) -> Word {
    let r7 = rotate_right(x, 7);
    let r18 = rotate_right(x, 18);
    let s3 = shift_right(builder, x, 3);
    xor_words(builder, &[r7, r18, s3])
}

fn small_sigma_1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &Word,
) -> Word {
    let r17 = rotate_right(x, 17);
    let r19 = rotate_right(x, 19);
    let s10 = shift_right(builder, x, 10);
    xor_words(builder, &[r17, r19, s10])
}

fn big_sigma_0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &Word,
) -> Word {
    xor_words(
        builder,
        &[rotate_right(x, 2), rotate_right(x, 13), rotate_right(x, 22)],
    )
}

fn big_sigma_1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: &Word,
) -> Word {
    xor_words(
        builder,
        &[rotate_right(x, 6), rotate_right(x, 11), rotate_right(x, 25)],
    )
}

fn compress_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &mut [Word; 8],
    block: &[Byte],
) {
    assert_eq!(
        block.len(),
        64,
        "SHA-256 compression block must be 64 bytes"
    );

    let mut schedule = Vec::with_capacity(64);
    for bytes in block.chunks_exact(4) {
        // The block is big-endian, while each internal word is little-endian.
        let word = std::array::from_fn(|i| bytes[3 - (i / 8)][i % 8]);
        schedule.push(word);
    }
    for t in 16..64 {
        let sigma0 = small_sigma_0(builder, &schedule[t - 15]);
        let sigma1 = small_sigma_1(builder, &schedule[t - 2]);
        schedule.push(add_words(
            builder,
            &[schedule[t - 16], sigma0, schedule[t - 7], sigma1],
        ));
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for round in 0..64 {
        let sigma1 = big_sigma_1(builder, &e);
        let ch = choose(builder, &e, &f, &g);
        let k = constant_word(builder, ROUND_CONSTANTS[round]);
        let temp1 = add_words(builder, &[h, sigma1, ch, k, schedule[round]]);
        let sigma0 = big_sigma_0(builder, &a);
        let maj = majority(builder, &a, &b, &c);
        let temp2 = add_words(builder, &[sigma0, maj]);

        h = g;
        g = f;
        f = e;
        e = add_words(builder, &[d, temp1]);
        d = c;
        c = b;
        b = a;
        a = add_words(builder, &[temp1, temp2]);
    }

    let working = [a, b, c, d, e, f, g, h];
    for i in 0..8 {
        state[i] = add_words(builder, &[state[i], working[i]]);
    }
}

/// SHA-256 of a byte string given as in-circuit targets.
///
/// Every input is constrained to `0..=255`. The returned digest uses the
/// standard 32-byte big-endian SHA-256 encoding, and every returned target is
/// likewise constrained to `0..=255`.
pub fn sha256<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_bytes: &[Target],
) -> [Target; 32] {
    let message_len = u64::try_from(msg_bytes.len())
        .expect("SHA-256 message length must fit in a 64-bit length field");
    let bit_len = message_len
        .checked_mul(8)
        .expect("SHA-256 message bit length must fit in u64");

    let mut padded: Vec<Byte> = msg_bytes
        .iter()
        .map(|&byte| {
            builder
                .split_le(byte, 8)
                .try_into()
                .expect("a byte decomposition always has eight bits")
        })
        .collect();
    padded.push(constant_byte(builder, 0x80));
    while padded.len() % 64 != 56 {
        padded.push(constant_byte(builder, 0));
    }
    for byte in bit_len.to_be_bytes() {
        padded.push(constant_byte(builder, byte));
    }
    assert_eq!(
        padded.len() % 64,
        0,
        "SHA-256 padding must produce whole blocks"
    );

    let mut state = INITIAL_HASH.map(|word| constant_word(builder, word));
    for block in padded.chunks_exact(64) {
        compress_block(builder, &mut state, block);
    }

    let mut digest = Vec::with_capacity(32);
    for word in state {
        for byte_index in 0..4 {
            let offset = (3 - byte_index) * 8;
            let byte = builder.le_sum(word[offset..offset + 8].iter());
            // This is implied by the Boolean recomposition, but keeping the
            // explicit range check makes the byte-level API invariant local.
            builder.range_check(byte, 8);
            digest.push(byte);
        }
    }
    digest
        .try_into()
        .expect("SHA-256 always emits exactly 32 bytes")
}

/// BIP-340 tagged SHA-256:
/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
///
/// `tag` is compile-time-known circuit structure and is baked in as byte
/// constants. `msg` remains a range-checked in-circuit byte string.
pub fn tagged_sha256<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tag: &[u8],
    msg: &[Target],
) -> [Target; 32] {
    assert!(
        tag.is_ascii(),
        "BIP-340 tagged SHA-256 tag must be an ASCII byte string"
    );
    let tag_targets: Vec<Target> = tag
        .iter()
        .map(|&byte| builder.constant(F::from_canonical_u8(byte)))
        .collect();
    let tag_hash = sha256(builder, &tag_targets);

    let mut tagged_preimage = Vec::with_capacity(64 + msg.len());
    tagged_preimage.extend_from_slice(&tag_hash);
    tagged_preimage.extend_from_slice(&tag_hash);
    tagged_preimage.extend_from_slice(msg);
    sha256(builder, &tagged_preimage)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{C, D, F};
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use sha2::{Digest, Sha256};

    fn prove_sha256(message: &[u8]) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let message_targets = builder.add_virtual_targets(message.len());
        let digest_targets = sha256(&mut builder, &message_targets);
        let expected = Sha256::digest(message);
        for (&actual, &expected_byte) in digest_targets.iter().zip(expected.iter()) {
            let expected_target = builder.constant(F::from_canonical_u8(expected_byte));
            builder.connect(actual, expected_target);
        }

        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for (&target, &byte) in message_targets.iter().zip(message) {
            witness
                .set_target(target, F::from_canonical_u8(byte))
                .unwrap();
        }

        let proof = data.prove(witness).expect("SHA-256 circuit must prove");
        data.verify(proof).expect("SHA-256 proof must verify");
    }

    #[test]
    fn sha256_empty_matches_host() {
        prove_sha256(b"");
    }

    #[test]
    fn sha256_abc_matches_host() {
        prove_sha256(b"abc");
    }

    #[test]
    fn sha256_192_bytes_matches_host() {
        let message: Vec<u8> = (0..192).map(|i| i as u8).collect();
        prove_sha256(&message);
    }

    #[test]
    fn sha256_wrong_preimage_fails_proving() {
        let expected_message = b"abc";
        let witnessed_message = b"abd";

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let message_targets = builder.add_virtual_targets(expected_message.len());
        let digest_targets = sha256(&mut builder, &message_targets);
        let expected = Sha256::digest(expected_message);
        for (&actual, &expected_byte) in digest_targets.iter().zip(expected.iter()) {
            let expected_target = builder.constant(F::from_canonical_u8(expected_byte));
            builder.connect(actual, expected_target);
        }

        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for (&target, &byte) in message_targets.iter().zip(witnessed_message) {
            witness
                .set_target(target, F::from_canonical_u8(byte))
                .unwrap();
        }

        assert!(
            data.prove(witness).is_err(),
            "a preimage inconsistent with the asserted digest must not prove"
        );
    }

    #[test]
    fn tagged_sha256_matches_host() {
        let tag = b"BIP0340/challenge";
        let message = b"zkCoins tagged hash test";

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let message_targets = builder.add_virtual_targets(message.len());
        let digest_targets = tagged_sha256(&mut builder, tag, &message_targets);

        let tag_hash = Sha256::digest(tag);
        let mut preimage = Vec::with_capacity(64 + message.len());
        preimage.extend_from_slice(&tag_hash);
        preimage.extend_from_slice(&tag_hash);
        preimage.extend_from_slice(message);
        let expected = Sha256::digest(preimage);
        for (&actual, &expected_byte) in digest_targets.iter().zip(expected.iter()) {
            let expected_target = builder.constant(F::from_canonical_u8(expected_byte));
            builder.connect(actual, expected_target);
        }

        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for (&target, &byte) in message_targets.iter().zip(message) {
            witness
                .set_target(target, F::from_canonical_u8(byte))
                .unwrap();
        }

        let proof = data
            .prove(witness)
            .expect("tagged SHA-256 circuit must prove");
        data.verify(proof)
            .expect("tagged SHA-256 proof must verify");
    }
}
