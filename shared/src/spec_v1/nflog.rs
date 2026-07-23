//! Nullifier accumulator log — hashing + `mth` only (§1.7.6).
//!
//! Full inclusion/consistency-proof machinery (RFC 6962 PATH/PROOF) is out of
//! scope for P1-A.

use serde::{Deserialize, Serialize};

use super::encoding::{hc, HcInput};
use super::tags::{TAG_NFLOG_EMPTY, TAG_NFLOG_LEAF, TAG_NFLOG_NODE, TAG_NFLOG_ROOT};
use zkcoins_program::hash::HashDigest;

/// An on-chain `(Pk_i, R_i)` nullifier entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfLogEntry {
    pub pk: [u8; 32],
    pub r: [u8; 32],
}

/// Leaf hash binding absolute position `p`:
/// `Hc("NfLog/Leaf", ByteString(p_be8), ByteString(pk), ByteString(r))`.
pub fn nflog_leaf_hash(position: u64, entry: &NfLogEntry) -> HashDigest {
    let p_be = position.to_be_bytes();
    hc(
        TAG_NFLOG_LEAF,
        &[
            HcInput::ByteString(&p_be),
            HcInput::ByteString(&entry.pk),
            HcInput::ByteString(&entry.r),
        ],
    )
    .expect("fixed-size inputs")
}

/// Interior node: `Hc("NfLog/Node", Digest(left), Digest(right))`.
pub fn nflog_node_hash(left: HashDigest, right: HashDigest) -> HashDigest {
    hc(
        TAG_NFLOG_NODE,
        &[HcInput::Digest(left), HcInput::Digest(right)],
    )
    .expect("digest inputs")
}

/// Empty log constant: `Hc("NfLog/Empty", SmallNumeric(0))`.
///
/// The `0` is a **small-numeric** input, not the all-zero digest.
pub fn nflog_empty() -> HashDigest {
    hc(TAG_NFLOG_EMPTY, &[HcInput::SmallNumeric(0)]).expect("literal 0 is in range")
}

/// Committed accumulator form: `nav_root = Hc("NfLog/Root", ByteString(size_be8), Digest(mth))`.
pub fn nflog_root(size: u64, mth: HashDigest) -> HashDigest {
    let size_be = size.to_be_bytes();
    hc(
        TAG_NFLOG_ROOT,
        &[HcInput::ByteString(&size_be), HcInput::Digest(mth)],
    )
    .expect("fixed-size inputs")
}

/// Accumulator value `(size, mth)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nav {
    pub size: u64,
    pub mth: HashDigest,
}

impl Nav {
    pub fn root(&self) -> HashDigest {
        nflog_root(self.size, self.mth)
    }
}

/// RFC 6962 MTH over a fully materialised leaf sequence (small logs).
///
/// - `n = 0` → `nflog_empty()`
/// - `n = 1` → `nflog_leaf_hash(start_pos, &entries[0])`
/// - `n > 1` → split at `k = largest power of two strictly less than n`,
///   recurse with absolute positions, combine via `nflog_node_hash`.
pub fn nflog_mth(entries: &[NfLogEntry]) -> HashDigest {
    mth_range(entries, 0)
}

fn mth_range(entries: &[NfLogEntry], start_pos: u64) -> HashDigest {
    let n = entries.len();
    if n == 0 {
        return nflog_empty();
    }
    if n == 1 {
        return nflog_leaf_hash(start_pos, &entries[0]);
    }
    // k = largest power of two strictly less than n
    // k = 1 << (bit_length(n - 1) - 1)
    let bit_length = 64 - (n as u64 - 1).leading_zeros();
    let k = 1usize << (bit_length - 1);
    let left = mth_range(&entries[..k], start_pos);
    let right = mth_range(&entries[k..], start_pos + k as u64);
    nflog_node_hash(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Synthetic deterministic leaves for V.11 smoke set.
    ///
    /// **Note:** the full-spec V.11 reuses V.8 BIP-340 fixtures for positions
    /// 0 and 1. This chunk uses the same `p`-parameterised SHA-256 rule for
    /// *every* position (including 0 and 1) as a deliberate, documented
    /// simplification — signing fixtures are out of scope for P1-A.
    fn synthetic_entries(n: usize) -> Vec<NfLogEntry> {
        (0..n)
            .map(|p| {
                let mut pk_pre = b"zkCoins/v1/test-vector/nflog/pk".to_vec();
                pk_pre.push(p as u8);
                let mut r_pre = b"zkCoins/v1/test-vector/nflog/r".to_vec();
                r_pre.push(p as u8);
                NfLogEntry {
                    pk: Sha256::digest(&pk_pre).into(),
                    r: Sha256::digest(&r_pre).into(),
                }
            })
            .collect()
    }

    #[test]
    fn nflog_empty_stable() {
        assert_eq!(nflog_empty(), nflog_empty());
    }

    #[test]
    fn mth_base_cases_and_split() {
        let entries = synthetic_entries(9);
        // n=1 base case
        assert_eq!(
            nflog_mth(&entries[..1]),
            nflog_leaf_hash(0, &entries[0])
        );
        // n=2 = node(leaf0, leaf1)
        assert_eq!(
            nflog_mth(&entries[..2]),
            nflog_node_hash(
                nflog_leaf_hash(0, &entries[0]),
                nflog_leaf_hash(1, &entries[1]),
            )
        );
        // determinism for several n
        for n in [1, 2, 3, 4, 5, 7, 8, 9] {
            let a = nflog_mth(&entries[..n]);
            let b = nflog_mth(&entries[..n]);
            assert_eq!(a, b, "mth@{n} not deterministic");
        }
    }

    #[test]
    fn nav_root_deterministic_and_sensitive() {
        let entries = synthetic_entries(3);
        let mth = nflog_mth(&entries);
        let r1 = nflog_root(3, mth);
        let r2 = nflog_root(3, mth);
        assert_eq!(r1, r2);
        assert_ne!(nflog_root(2, mth), r1);
        assert_ne!(nflog_root(3, nflog_empty()), r1);
        let nav = Nav { size: 3, mth };
        assert_eq!(nav.root(), r1);
    }
}
