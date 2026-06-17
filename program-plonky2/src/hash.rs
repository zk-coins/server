//! Protocol hash function `H` and `HashDigest` type for the Plonky2 backend.
//!
//! `H` is Poseidon over Goldilocks (4-element output). All Merkle structures
//! and `AccountState::hash` use this function; SHA256 lives only at the
//! Bitcoin-signing boundary (`SHA256(serialize(asth) || serialize(ocr))`).
//!
//! See `SPEC.md` §2.1 (hash function abstraction) and `MIGRATION_RESEARCH.md`
//! §5.3 (decision) / §5.4 (Schnorr boundary).

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use sha2::{Digest, Sha256};

use crate::F;

/// Protocol hash digest: 4 Goldilocks field elements (≡ 256 bits).
pub type HashDigest = HashOut<F>;

/// Zero digest: 4 field-zero elements. Used as the MMR pad and SMT sentinel.
pub const ZERO_HASH: HashDigest = HashOut {
    elements: [F::ZERO; 4],
};

/// `H(left || right)` — the canonical two-input Merkle node hash. Single
/// Poseidon absorption of 8 field elements (rate = 8 for Poseidon-Goldilocks).
pub fn hash_concat(left: &HashDigest, right: &HashDigest) -> HashDigest {
    PoseidonHash::two_to_one(*left, *right)
}

/// Hash arbitrary bytes into a `HashDigest`. Bytes are packed 7-per-field-elt
/// (little-endian) so the canonical Goldilocks representation is never
/// ambiguous (`p < 2^64` would otherwise leave 8-byte chunks at risk of
/// non-canonical wraparound).
pub fn hash_bytes(bytes: &[u8]) -> HashDigest {
    let mut elements = Vec::with_capacity(bytes.len().div_ceil(7));
    for chunk in bytes.chunks(7) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        elements.push(F::from_canonical_u64(u64::from_le_bytes(buf)));
    }
    PoseidonHash::hash_no_pad(&elements)
}

/// Serialize a digest to exactly 32 bytes, big-endian per field element. This
/// is the on-the-wire representation used at the Poseidon ↔ Bitcoin boundary
/// (Schnorr message bytes, on-disk SMT storage).
pub fn digest_to_bytes(d: &HashDigest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, e) in d.elements.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&e.0.to_be_bytes());
    }
    out
}

/// Parse 32 bytes back into a digest. Each 8-byte chunk is interpreted as a
/// big-endian Goldilocks element. Bytes that exceed the field modulus are
/// reduced (`from_noncanonical_u64`) — the reduction is deterministic and
/// inverse of `digest_to_bytes` for any digest this crate emits.
pub fn digest_from_bytes(bytes: &[u8; 32]) -> HashDigest {
    let mut elements = [F::ZERO; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        // `from_noncanonical_u64` (not `from_canonical_u64`): an 8-byte
        // chunk of an externally-supplied 32-byte value (e.g. a SHA-256
        // address) can exceed the Goldilocks modulus; canonical conversion
        // would debug-panic / yield a non-canonical element. Noncanonical
        // reduction is deterministic and consistent across all consumers.
        elements[i] = F::from_noncanonical_u64(u64::from_be_bytes(buf));
    }
    HashOut { elements }
}

/// Account address / owner: `H(pubkey) = SHA-256(pubkey)`, per the protocol
/// spec (`address = H(Pk₀)`, where `H` is SHA-256 for addresses / off-circuit
/// ids). The 32-byte SHA-256 image is carried as a [`HashDigest`] via
/// [`digest_from_bytes`] (big-endian, 4 field elements). This is the
/// off-circuit identity hash and is distinct from the in-circuit Poseidon `H`
/// used for Merkle/state hashing.
pub fn sha256_to_digest(bytes: &[u8]) -> HashDigest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest_from_bytes(&digest)
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_concat_is_deterministic() {
        let a = HashOut {
            elements: [F::from_canonical_u64(1); 4],
        };
        let b = HashOut {
            elements: [F::from_canonical_u64(2); 4],
        };
        assert_eq!(hash_concat(&a, &b), hash_concat(&a, &b));
        assert_ne!(hash_concat(&a, &b), hash_concat(&b, &a));
    }

    #[test]
    fn hash_bytes_distinguishes_inputs() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        let h3 = hash_bytes(b"hello");
        assert_ne!(h1, h2);
        assert_eq!(h1, h3);
    }

    #[test]
    fn digest_byte_round_trip() {
        let original = HashOut {
            elements: [
                F::from_canonical_u64(0x0102030405060708),
                F::from_canonical_u64(0x1112131415161718),
                F::from_canonical_u64(0x2122232425262728),
                F::from_canonical_u64(0x3132333435363738),
            ],
        };
        let bytes = digest_to_bytes(&original);
        let recovered = digest_from_bytes(&bytes);
        assert_eq!(original, recovered);

        // Witness the exact byte layout we promise downstream consumers
        // (Bitcoin wallet signs SHA256 over this exact byte sequence).
        assert_eq!(&bytes[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &bytes[24..32],
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        );
    }

    #[test]
    fn zero_hash_is_all_zero_elements() {
        assert_eq!(ZERO_HASH.elements, [F::ZERO; 4]);
        assert_eq!(digest_to_bytes(&ZERO_HASH), [0u8; 32]);
    }

    #[test]
    fn hash_bytes_chunks_are_safe_canonical() {
        // 7 bytes per field-element packing means each u64 holds at most
        // 7*8 = 56 bits of input, well below the 64-bit Goldilocks modulus.
        // No non-canonical reduction can ever occur. Smoke test: hashing
        // 0xFF..FF (max bytes) and a one-byte difference must still differ.
        let max = vec![0xFFu8; 28];
        let mut almost = max.clone();
        almost[14] ^= 1;
        assert_ne!(hash_bytes(&max), hash_bytes(&almost));
    }
}
