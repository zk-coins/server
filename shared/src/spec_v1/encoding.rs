//! Field encoding `E(·)` and the `Hc` primitive (spec §§1.7.1–1.7.3).
//!
//! `Hc(tag, x1, …, xn) := PoseidonHash::hash_no_pad(E(tag) ‖ E(x1) ‖ … ‖ E(xn))`.
//!
//! **Critical:** this is intentionally different from the old-model
//! `zkcoins_program::hash::hash_bytes`, which packs little-endian 7-byte
//! chunks with no length prefix. Spec §1.7.2 requires a length element and
//! **big-endian** 7-byte chunks.

use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use super::error::SpecError;
use zkcoins_program::hash::HashDigest;
use zkcoins_program::F;

/// Maximum byte-string length representable as a single length element (`L < 2^56`).
pub const MAX_BYTE_STRING_LEN: u64 = 1u64 << 56;

/// Maximum value for a small-numeric `Hc` input (`v < 2^56`).
pub const MAX_SMALL_NUMERIC: u64 = 1u64 << 56;

/// Typed `Hc` input, classified per §1.7.3.
#[derive(Clone, Debug)]
pub enum HcInput<'a> {
    /// Length-prefixed, 7-byte big-endian chunks.
    ByteString(&'a [u8]),
    /// Four field elements, no length prefix (prior `Hc` output only).
    Digest(HashDigest),
    /// Single field element; valid only for `v < 2^56`.
    SmallNumeric(u64),
}

/// Encode a byte-string input per §1.7.2:
/// one length element `L`, then `ceil(L/7)` big-endian 7-byte chunks
/// (final chunk right-padded with zero bytes).
pub fn encode_byte_string(bytes: &[u8]) -> Result<Vec<F>, SpecError> {
    let len = bytes.len() as u64;
    if len >= MAX_BYTE_STRING_LEN {
        return Err(SpecError::ByteStringTooLong { len: bytes.len() });
    }
    let n_chunks = bytes.len().div_ceil(7);
    let mut out = Vec::with_capacity(1 + n_chunks);
    out.push(F::from_canonical_u64(len));
    for chunk in bytes.chunks(7) {
        // Right-pad the final chunk to 7 bytes with zeros, then interpret
        // as the low 7 bytes of an 8-byte big-endian u64 (implicit leading 0).
        let mut seven = [0u8; 7];
        seven[..chunk.len()].copy_from_slice(chunk);
        let mut be8 = [0u8; 8];
        be8[1..8].copy_from_slice(&seven);
        out.push(F::from_canonical_u64(u64::from_be_bytes(be8)));
    }
    Ok(out)
}

/// Encode a digest input: the four limbs, no length prefix.
pub fn encode_digest(d: HashDigest) -> [F; 4] {
    d.elements
}

/// Encode a small-numeric input as one field element. Fails if `v ≥ 2^56`.
pub fn encode_small_numeric(v: u64) -> Result<F, SpecError> {
    if v >= MAX_SMALL_NUMERIC {
        return Err(SpecError::SmallNumericOutOfRange { value: v });
    }
    Ok(F::from_canonical_u64(v))
}

/// `Hc(tag, inputs…)`: single `hash_no_pad` over the concatenated encodings.
///
/// `tag` is absorbed as a byte-string (UTF-8/ASCII of the full
/// `"zkCoins/v1/<Context>"` prefix).
pub fn hc(tag: &str, inputs: &[HcInput<'_>]) -> Result<HashDigest, SpecError> {
    let mut elements = encode_byte_string(tag.as_bytes())?;
    for input in inputs {
        match input {
            HcInput::ByteString(b) => {
                elements.extend(encode_byte_string(b)?);
            }
            HcInput::Digest(d) => {
                elements.extend_from_slice(&d.elements);
            }
            HcInput::SmallNumeric(v) => {
                elements.push(encode_small_numeric(*v)?);
            }
        }
    }
    Ok(PoseidonHash::hash_no_pad(&elements))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_v1::tags::{TAG_COINS_ROOT_LEAF, TAG_NFLOG_EMPTY};
    use plonky2::field::types::Field;
    use zkcoins_program::hash::ZERO_HASH;

    #[test]
    fn encode_byte_string_empty() {
        let e = encode_byte_string(b"").unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0], F::from_canonical_u64(0));
    }

    #[test]
    fn encode_byte_string_abcdefg_hand_check() {
        // E(b"ABCDEFG"): length 7 + one 7-byte BE chunk "ABCDEFG"
        // u64 = 0x0041424344454647
        let e = encode_byte_string(b"ABCDEFG").unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0], F::from_canonical_u64(7));
        let expected_chunk = u64::from_be_bytes([0x00, b'A', b'B', b'C', b'D', b'E', b'F', b'G']);
        assert_eq!(e[1], F::from_canonical_u64(expected_chunk));
        assert_eq!(expected_chunk, 0x0041_4243_4445_4647);
    }

    #[test]
    fn encode_byte_string_partial_final_chunk_right_padded() {
        // "AB" → length 2, chunk = AB + 5 zero pads
        let e = encode_byte_string(b"AB").unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0], F::from_canonical_u64(2));
        let expected = u64::from_be_bytes([0x00, b'A', b'B', 0, 0, 0, 0, 0]);
        assert_eq!(e[1], F::from_canonical_u64(expected));
    }

    #[test]
    fn encode_byte_string_32_bytes_is_1_plus_5() {
        let e = encode_byte_string(&[0u8; 32]).unwrap();
        assert_eq!(e.len(), 1 + 5);
    }

    #[test]
    fn encode_byte_string_16_bytes_is_1_plus_3() {
        // amount u128 → 4 elements total
        let e = encode_byte_string(&[0u8; 16]).unwrap();
        assert_eq!(e.len(), 4);
    }

    #[test]
    fn encode_byte_string_8_bytes_is_1_plus_2() {
        // wide u64 → 3 elements
        let e = encode_byte_string(&[0u8; 8]).unwrap();
        assert_eq!(e.len(), 3);
    }

    #[test]
    fn small_numeric_rejects_2_pow_56() {
        assert!(matches!(
            encode_small_numeric(1u64 << 56),
            Err(SpecError::SmallNumericOutOfRange { .. })
        ));
        assert!(encode_small_numeric((1u64 << 56) - 1).is_ok());
    }

    #[test]
    fn hc_is_deterministic() {
        let a = hc(
            "zkCoins/v1/NkCommit",
            &[HcInput::ByteString(&[1u8; 32])],
        )
        .unwrap();
        let b = hc(
            "zkCoins/v1/NkCommit",
            &[HcInput::ByteString(&[1u8; 32])],
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hc_sensitive_to_tag_byte_digest_numeric_and_order() {
        let base_tag = "zkCoins/v1/NkCommit";
        let bytes = [7u8; 32];
        let d = ZERO_HASH;
        let n = 3u64;

        let base = hc(
            base_tag,
            &[
                HcInput::ByteString(&bytes),
                HcInput::Digest(d),
                HcInput::SmallNumeric(n),
            ],
        )
        .unwrap();

        // tag change
        let mut tag2 = base_tag.as_bytes().to_vec();
        tag2[0] ^= 1;
        let tag2_str = String::from_utf8(tag2).unwrap();
        assert_ne!(
            base,
            hc(
                &tag2_str,
                &[
                    HcInput::ByteString(&bytes),
                    HcInput::Digest(d),
                    HcInput::SmallNumeric(n),
                ],
            )
            .unwrap()
        );

        // one byte of byte-string
        let mut bytes2 = bytes;
        bytes2[0] ^= 1;
        assert_ne!(
            base,
            hc(
                base_tag,
                &[
                    HcInput::ByteString(&bytes2),
                    HcInput::Digest(d),
                    HcInput::SmallNumeric(n),
                ],
            )
            .unwrap()
        );

        // digest limb
        let mut d2 = d;
        d2.elements[0] = F::from_canonical_u64(1);
        assert_ne!(
            base,
            hc(
                base_tag,
                &[
                    HcInput::ByteString(&bytes),
                    HcInput::Digest(d2),
                    HcInput::SmallNumeric(n),
                ],
            )
            .unwrap()
        );

        // small-numeric
        assert_ne!(
            base,
            hc(
                base_tag,
                &[
                    HcInput::ByteString(&bytes),
                    HcInput::Digest(d),
                    HcInput::SmallNumeric(n + 1),
                ],
            )
            .unwrap()
        );

        // argument order
        assert_ne!(
            base,
            hc(
                base_tag,
                &[
                    HcInput::Digest(d),
                    HcInput::ByteString(&bytes),
                    HcInput::SmallNumeric(n),
                ],
            )
            .unwrap()
        );
    }

    #[test]
    fn nflog_empty_vs_coinsroot_empty_leaf_shapes_differ() {
        // NfLog/Empty: tag + small-numeric 0 → tag_elems + 1
        // CoinsRoot/Leaf with ZERO_HASH: tag + 4 digest limbs → tag_elems + 4
        let tag_elems = encode_byte_string(TAG_NFLOG_EMPTY.as_bytes()).unwrap().len();
        let empty_log = hc(TAG_NFLOG_EMPTY, &[HcInput::SmallNumeric(0)]).unwrap();
        let empty_leaf = hc(TAG_COINS_ROOT_LEAF, &[HcInput::Digest(ZERO_HASH)]).unwrap();
        assert_ne!(empty_log, empty_leaf);

        // Explicit element-count shapes
        let nflog_elems = tag_elems + 1;
        let coins_tag_elems = encode_byte_string(TAG_COINS_ROOT_LEAF.as_bytes())
            .unwrap()
            .len();
        let coins_elems = coins_tag_elems + 4;
        assert_ne!(nflog_elems, coins_elems);
        assert_eq!(nflog_elems, tag_elems + 1);
        assert_eq!(coins_elems, coins_tag_elems + 4);
    }
}
