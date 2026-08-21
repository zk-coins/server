//! Nullifier accumulator log — hashing, MTH, and RFC 6962 PATH/PROOF (§1.7.6 / §3.7).

use serde::{Deserialize, Serialize};

use super::encoding::{hc, HcInput};
use super::error::SpecError;
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

/// Largest power of two strictly less than `n`. Requires `n >= 2`.
///
/// Protocol sizes are `u64` (log capacity up to `2^H_MAX − 1`, `H_MAX = 64`).
/// Keeping the split arithmetic in `u64` avoids silent truncation of those
/// sizes when the host `usize` is narrower (e.g. `wasm32`).
fn split_point(n: u64) -> u64 {
    debug_assert!(n >= 2);
    let bit_length = 64 - (n - 1).leading_zeros();
    1u64 << (bit_length - 1)
}

/// RFC 6962 MTH over a fully materialised leaf sequence (small logs).
///
/// - `n = 0` → `nflog_empty()`
/// - `n = 1` → `nflog_leaf_hash(start_pos, &entries[0])`
/// - `n > 1` → split at `k = largest power of two strictly less than n`,
///   recurse with absolute positions, combine via `nflog_node_hash`.
///
/// This is the **normative reference** implementation. Callers that append
/// many entries SHOULD use [`NflogIncrementalMth`] instead; that type is
/// required to stay byte-identical to this function for every prefix length.
pub fn nflog_mth(entries: &[NfLogEntry]) -> HashDigest {
    mth_range(entries, 0)
}

/// Incremental RFC-6962 Merkle Tree Hash state (perfect-subtree peaks).
///
/// Maintains the left-to-right list of complete-subtree roots implied by the
/// binary representation of the leaf count. Each [`Self::append`] costs
/// `O(log n)` node hashes; [`Self::mth`] bags the `O(log n)` peaks into the
/// same root that [`nflog_mth`] would compute over the full sequence.
///
/// **Equivalence (normative):** for any sequence `entries`, after appending
/// each entry in order, `incremental.mth() == nflog_mth(&entries)`. This is
/// the contract that keeps every inclusion and consistency proof valid against
/// an incrementally maintained tip.
#[derive(Clone, Debug, Default)]
pub struct NflogIncrementalMth {
    /// Perfect-subtree roots, left-to-right (oldest / largest first).
    /// After `size` appends, this list is exactly the peaks for the set bits
    /// of `size` (largest power first).
    peaks: Vec<HashDigest>,
    /// Number of leaves represented by `peaks`.
    size: u64,
}

impl NflogIncrementalMth {
    /// Empty log: no peaks, size 0, MTH = [`nflog_empty`].
    pub fn new() -> Self {
        Self {
            peaks: Vec::new(),
            size: 0,
        }
    }

    /// Number of leaves folded so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Append one entry at the next absolute position (`self.size`).
    ///
    /// Leaf hash binds that position; equal-height peaks on the right are
    /// merged bottom-up exactly as the recursive MTH split would combine
    /// perfect power-of-two runs. Cost: `O(log n)` Poseidon hashes.
    pub fn append(&mut self, entry: &NfLogEntry) {
        let position = self.size;
        let mut node = nflog_leaf_hash(position, entry);
        // Index of the leaf just placed. While it is the right child of its
        // parent (odd index at this height), merge with the matching left
        // peak already on the stack and climb one level.
        let mut i = position;
        while i & 1 == 1 {
            let left = self
                .peaks
                .pop()
                .expect("peak-stack invariant: a right-child leaf always has a left sibling peak");
            node = nflog_node_hash(left, node);
            i >>= 1;
        }
        self.peaks.push(node);
        self.size = self
            .size
            .checked_add(1)
            .expect("nullifier log size cannot overflow u64");
    }

    /// Current MTH — byte-identical to [`nflog_mth`] over the same sequence.
    ///
    /// Bags peaks right-to-left: for peaks `[P_large, …, P_small]`,
    /// `Node(P_large, Node(…, P_small))`, matching the RFC-6962 recursion
    /// that always takes the largest power-of-two split on the left.
    pub fn mth(&self) -> HashDigest {
        if self.peaks.is_empty() {
            return nflog_empty();
        }
        let mut acc = self.peaks[self.peaks.len() - 1];
        for &peak in self.peaks[..self.peaks.len() - 1].iter().rev() {
            acc = nflog_node_hash(peak, acc);
        }
        acc
    }

    /// Reset to the empty-log state (used by truncate-and-refold reorg).
    pub fn clear(&mut self) {
        self.peaks.clear();
        self.size = 0;
    }
}

fn mth_range(entries: &[NfLogEntry], start_pos: u64) -> HashDigest {
    let n = entries.len();
    if n == 0 {
        return nflog_empty();
    }
    if n == 1 {
        return nflog_leaf_hash(start_pos, &entries[0]);
    }
    // `k < n = entries.len()`, so the split always fits in `usize`.
    let k = split_point(n as u64) as usize;
    let left = mth_range(&entries[..k], start_pos);
    let right = mth_range(&entries[k..], start_pos + k as u64);
    nflog_node_hash(left, right)
}

/// RFC 6962 audit path `PATH(position, D[0:entries.len()])`.
///
/// Requires `position < entries.len()`; returns
/// [`SpecError::PositionOutOfRange`] otherwise.
pub fn inclusion_path(position: u64, entries: &[NfLogEntry]) -> Result<Vec<HashDigest>, SpecError> {
    let n = entries.len() as u64;
    if position >= n {
        return Err(SpecError::PositionOutOfRange { position, size: n });
    }
    Ok(path_range(position as usize, entries, 0))
}

/// `entries` is the CURRENT absolute sub-range; `start_pos` is its absolute
/// offset in the full log (needed because leaf hashes bind absolute
/// position). `rel_pos` is the target position relative to `entries`.
fn path_range(rel_pos: usize, entries: &[NfLogEntry], start_pos: u64) -> Vec<HashDigest> {
    let n = entries.len();
    if n == 1 {
        return vec![];
    }
    // `k < n = entries.len()`, so the split always fits in `usize`.
    let k = split_point(n as u64) as usize;
    if rel_pos < k {
        let mut path = path_range(rel_pos, &entries[..k], start_pos);
        path.push(mth_range(&entries[k..], start_pos + k as u64));
        path
    } else {
        let mut path = path_range(rel_pos - k, &entries[k..], start_pos + k as u64);
        path.push(mth_range(&entries[..k], start_pos));
        path
    }
}

/// `leaf` is the position-bound leaf hash `nflog_leaf_hash(position, entry)`.
/// Pure predicate: no panics on malformed `path`.
///
/// `position` and `size` stay `u64` end-to-end (protocol type). They are never
/// narrowed to `usize`, so a 32-bit host cannot silently truncate a large size
/// into a small one and false-accept.
pub fn verify_inclusion(
    leaf: HashDigest,
    position: u64,
    path: &[HashDigest],
    size: u64,
    mth: HashDigest,
) -> bool {
    if size == 0 || position >= size {
        return false;
    }
    match verify_path_range(position, size, leaf, path) {
        Some(recomputed) => recomputed == mth,
        None => false,
    }
}

/// Mirrors `path_range`'s recursion, consuming `path` from its END inward.
/// Returns `None` for any malformed/wrong-length path instead of panicking.
///
/// `rel_pos` / `n` are protocol sizes (`u64`), not host pointer widths.
fn verify_path_range(
    rel_pos: u64,
    n: u64,
    leaf: HashDigest,
    path: &[HashDigest],
) -> Option<HashDigest> {
    if n == 1 {
        return if path.is_empty() { Some(leaf) } else { None };
    }
    if path.is_empty() {
        return None;
    }
    let k = split_point(n);
    let (inner, last_slice) = path.split_at(path.len() - 1);
    let sibling = last_slice[0];
    if rel_pos < k {
        let sub = verify_path_range(rel_pos, k, leaf, inner)?;
        Some(nflog_node_hash(sub, sibling))
    } else {
        let sub = verify_path_range(rel_pos - k, n - k, leaf, inner)?;
        Some(nflog_node_hash(sibling, sub))
    }
}

/// `PROOF(m, D[0:n]) = SUBPROOF(m, D[0:n], true)`, `n = entries.len()`.
/// Requires `m <= n`; returns [`SpecError::ConsistencyRangeInvalid`] otherwise.
pub fn consistency_proof(m: u64, entries: &[NfLogEntry]) -> Result<Vec<HashDigest>, SpecError> {
    let n = entries.len() as u64;
    if m > n {
        return Err(SpecError::ConsistencyRangeInvalid { m, n });
    }
    if m == 0 || m == n {
        return Ok(vec![]);
    }
    Ok(subproof_range(m as usize, entries, 0, true))
}

/// `entries`/`start_pos`: current absolute sub-range and its offset.
/// Precondition: `0 < m < entries.len()` (so `entries.len() >= 2`).
fn subproof_range(m: usize, entries: &[NfLogEntry], start_pos: u64, b: bool) -> Vec<HashDigest> {
    let n = entries.len();
    if m == n {
        return if b {
            vec![]
        } else {
            vec![mth_range(entries, start_pos)]
        };
    }
    // `k < n = entries.len()`, so the split always fits in `usize`.
    let k = split_point(n as u64) as usize;
    if m <= k {
        let mut proof = subproof_range(m, &entries[..k], start_pos, b);
        proof.push(mth_range(&entries[k..], start_pos + k as u64));
        proof
    } else {
        let mut proof = subproof_range(m - k, &entries[k..], start_pos + k as u64, false);
        proof.push(mth_range(&entries[..k], start_pos));
        proof
    }
}

/// `prefix(a, b)` for `a = (m, mth_a)`, `b = (n, mth_b)`.
///
/// `m` and `n` stay `u64` end-to-end (protocol type). They are never narrowed
/// to `usize`, so a 32-bit host cannot silently truncate both sizes to the
/// same small value and false-accept a non-prefix consistency claim.
pub fn verify_consistency(
    m: u64,
    mth_a: HashDigest,
    n: u64,
    mth_b: HashDigest,
    proof: &[HashDigest],
) -> bool {
    if m > n {
        return false;
    }
    if m == 0 {
        // Trivial witness: no proof elements; mth_a must be exactly the
        // empty-log constant. mth_b is NOT constrained by this check.
        return proof.is_empty() && mth_a == nflog_empty();
    }
    if m == n {
        return proof.is_empty() && mth_a == mth_b;
    }
    match verify_subproof(m, n, true, mth_a, proof) {
        Some((chunks, n_side)) => {
            if n_side != mth_b {
                return false;
            }
            fold_chunks(&chunks) == mth_a
        }
        None => false,
    }
}

/// Reconstruct `mth_a` from the closing chunks produced by `verify_subproof`.
///
/// `verify_subproof` yields chunks outermost-first / deepest-last (mirroring
/// the recursion). Seed with the last (deepest) chunk, then walk reverse order
/// combining each remaining chunk on the LEFT: `Node(chunk, acc)`.
fn fold_chunks(chunks: &[HashDigest]) -> HashDigest {
    assert!(
        !chunks.is_empty(),
        "verify_subproof always yields >= 1 chunk"
    );
    let mut acc = chunks[chunks.len() - 1];
    for &c in chunks[..chunks.len() - 1].iter().rev() {
        acc = nflog_node_hash(c, acc);
    }
    acc
}

/// Mirrors `subproof_range`'s recursion structurally.
///
/// Returns `(chunks, local_value)`:
///  - `local_value` = recomputed MTH of this call's sub-range
///  - `chunks` = ordered list of prefix-closing contributions to `mth_a`
///
/// `m` / `n` are protocol sizes (`u64`), not host pointer widths.
fn verify_subproof(
    m: u64,
    n: u64,
    b: bool,
    mth_a_hint: HashDigest,
    proof: &[HashDigest],
) -> Option<(Vec<HashDigest>, HashDigest)> {
    if m == n {
        if b {
            // Residual proof must be empty — otherwise an attacker can prepend
            // garbage digests to a genuine consistency proof for power-of-two
            // prefixes and still pass verification.
            if !proof.is_empty() {
                return None;
            }
            return Some((vec![mth_a_hint], mth_a_hint));
        }
        if proof.len() != 1 {
            return None;
        }
        return Some((vec![proof[0]], proof[0]));
    }
    if proof.is_empty() {
        return None;
    }
    let k = split_point(n);
    let (inner, last_slice) = proof.split_at(proof.len() - 1);
    let sibling = last_slice[0];
    if m <= k {
        let (chunks, inner_local) = verify_subproof(m, k, b, mth_a_hint, inner)?;
        let local_value = nflog_node_hash(inner_local, sibling);
        Some((chunks, local_value))
    } else {
        let (chunks, inner_local) = verify_subproof(m - k, n - k, false, mth_a_hint, inner)?;
        let mut all_chunks = vec![sibling];
        all_chunks.extend(chunks);
        let local_value = nflog_node_hash(sibling, inner_local);
        Some((all_chunks, local_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Synthetic deterministic leaves for V.11 smoke set / boundary suite.
    ///
    /// Position is encoded as a 4-byte big-endian suffix so leaves stay unique
    /// past `n = 256` (single-byte suffix would wrap).
    fn synthetic_entries(n: usize) -> Vec<NfLogEntry> {
        (0..n)
            .map(|p| {
                let mut pk_pre = b"zkCoins/v1/test-vector/nflog/pk".to_vec();
                pk_pre.extend_from_slice(&(p as u32).to_be_bytes());
                let mut r_pre = b"zkCoins/v1/test-vector/nflog/r".to_vec();
                r_pre.extend_from_slice(&(p as u32).to_be_bytes());
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
        assert_eq!(nflog_mth(&entries[..1]), nflog_leaf_hash(0, &entries[0]));
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

    #[test]
    fn inclusion_path_verifies_at_correct_position() {
        let pairs: &[(u64, usize)] = &[
            (0, 3),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (3, 4),
            (0, 5),
            (2, 5),
            (4, 5),
            (0, 8),
            (3, 8),
            (7, 8),
        ];
        let entries = synthetic_entries(8);
        for &(p, n) in pairs {
            let slice = &entries[..n];
            let path = inclusion_path(p, slice).expect("in range");
            let leaf = nflog_leaf_hash(p, &slice[p as usize]);
            let mth = nflog_mth(slice);
            assert!(
                verify_inclusion(leaf, p, &path, n as u64, mth),
                "inclusion failed at p={p} n={n}"
            );
        }
    }

    #[test]
    fn inclusion_fails_at_wrong_position() {
        let entries = synthetic_entries(5);
        let p = 2u64;
        let path = inclusion_path(p, &entries).expect("in range");
        let leaf = nflog_leaf_hash(p, &entries[p as usize]);
        let mth = nflog_mth(&entries);
        // Same size, different position — position is bound into the leaf.
        assert!(!verify_inclusion(leaf, 1, &path, 5, mth));
        assert!(!verify_inclusion(leaf, 3, &path, 5, mth));
        assert!(!verify_inclusion(leaf, 0, &path, 5, mth));
    }

    #[test]
    fn inclusion_fails_at_or_beyond_size() {
        let entries = synthetic_entries(4);
        let leaf = nflog_leaf_hash(0, &entries[0]);
        let mth = nflog_mth(&entries);
        let path = inclusion_path(0, &entries).expect("in range");
        assert!(!verify_inclusion(leaf, 4, &path, 4, mth));
        assert!(!verify_inclusion(leaf, 5, &path, 4, mth));
        assert!(!verify_inclusion(leaf, 0, &path, 0, mth));
        assert!(matches!(
            inclusion_path(4, &entries),
            Err(SpecError::PositionOutOfRange {
                position: 4,
                size: 4
            })
        ));
    }

    /// Counterexample for silent `size as usize` truncation on 32-bit hosts.
    ///
    /// On a 32-bit `usize`, `2^32 + 1` narrows to `1`. The outer guards
    /// (`size == 0`, `position >= size`) still see the full `u64`, so they
    /// pass; the base case `n == 1` then accepts an empty path and returns
    /// `leaf`, matching `mth == leaf` — a false accept.
    ///
    /// With protocol sizes carried as `u64` end-to-end, `n` stays `2^32 + 1`,
    /// the empty path is rejected for `n > 1`, and verification fails on both
    /// 32-bit and 64-bit hosts. Meaningful on a 64-bit host: it exercises the
    /// large-size path, not a platform-gated try-from branch.
    #[test]
    fn verify_inclusion_rejects_size_beyond_u32_max_with_empty_path() {
        let leaf = nflog_empty();
        let size = (u32::MAX as u64) + 1; // 2^32 + 1
        assert!(
            !verify_inclusion(leaf, 0, &[], size, leaf),
            "size=2^32+1 with empty path must never verify (would false-accept under usize truncation)"
        );
        // Same class: any size that exceeds u32::MAX must not be silently
        // narrowed; empty path still fails for every n > 1.
        let size2 = (u32::MAX as u64) + 2;
        assert!(!verify_inclusion(leaf, 0, &[], size2, leaf));
    }

    #[test]
    fn consistency_prefix_holds_for_m_less_than_n() {
        let entries = synthetic_entries(8);
        for &(m, n) in &[(1u64, 3), (2, 5), (3, 5), (4, 8), (7, 8)] {
            let mth_a = nflog_mth(&entries[..m as usize]);
            let mth_b = nflog_mth(&entries[..n as usize]);
            let proof = consistency_proof(m, &entries[..n as usize]).expect("m <= n");
            assert!(
                verify_consistency(m, mth_a, n, mth_b, &proof),
                "consistency failed m={m} n={n}"
            );
        }
    }

    #[test]
    fn consistency_prefix_holds_for_m_equals_zero() {
        let entries = synthetic_entries(5);
        let mth_a = nflog_empty();
        let mth_b = nflog_mth(&entries);
        let proof = consistency_proof(0, &entries).expect("m <= n");
        assert!(proof.is_empty());
        assert!(verify_consistency(0, mth_a, 5, mth_b, &proof));
        // mth_b is unconstrained for m=0 — even a garbage mth_b is fine
        assert!(verify_consistency(0, mth_a, 5, nflog_empty(), &proof));
    }

    #[test]
    fn consistency_prefix_holds_for_m_equals_n() {
        let entries = synthetic_entries(6);
        let mth = nflog_mth(&entries);
        let proof = consistency_proof(6, &entries).expect("m == n");
        assert!(proof.is_empty());
        assert!(verify_consistency(6, mth, 6, mth, &proof));
    }

    #[test]
    fn consistency_rejects_non_prefix() {
        let entries = synthetic_entries(5);
        let mth_a = nflog_mth(&entries[..3]);
        let mth_b = nflog_mth(&entries);
        let proof = consistency_proof(3, &entries).expect("m <= n");
        assert!(verify_consistency(3, mth_a, 5, mth_b, &proof));

        // Unrelated mth_a from a different leaf sequence
        let other = synthetic_entries(3);
        // Force different content: flip first pk byte after re-deriving
        let mut other_entries = other;
        other_entries[0].pk[0] ^= 0xff;
        let wrong_mth_a = nflog_mth(&other_entries);
        assert!(!verify_consistency(3, wrong_mth_a, 5, mth_b, &proof));

        // Wrong mth_b
        assert!(!verify_consistency(3, mth_a, 5, mth_a, &proof));

        // m > n
        assert!(!verify_consistency(6, mth_a, 5, mth_b, &proof));
        assert!(matches!(
            consistency_proof(6, &entries),
            Err(SpecError::ConsistencyRangeInvalid { m: 6, n: 5 })
        ));
    }

    /// Counterexample for silent `m as usize` / `n as usize` truncation on
    /// 32-bit hosts.
    ///
    /// On a 32-bit `usize`, `n = 2^32 + 1` narrows to `1`. With `m = 1` the
    /// outer `m == n` check still sees the full `u64` values and does not
    /// short-circuit; after narrowing both become `1`, the subproof base case
    /// `m == n && b` accepts an empty proof — a false accept of a non-prefix.
    ///
    /// With protocol sizes carried as `u64` end-to-end, `m != n` remains true,
    /// the empty proof is rejected, and verification fails on both 32-bit and
    /// 64-bit hosts. Meaningful on a 64-bit host: it exercises the large-size
    /// path, not a platform-gated try-from branch.
    #[test]
    fn verify_consistency_rejects_sizes_beyond_u32_max_with_empty_proof() {
        let mth = nflog_empty();
        let n = (u32::MAX as u64) + 1; // 2^32 + 1
        assert!(
            !verify_consistency(1, mth, n, mth, &[]),
            "m=1, n=2^32+1 with empty proof must never verify (would false-accept under usize truncation)"
        );
        // Same class with a non-matching digest pair (still must reject).
        let other = nflog_root(0, mth);
        assert!(!verify_consistency(1, mth, n, other, &[]));
    }

    #[test]
    fn consistency_dual_accumulator_hand_traced_m3_n5() {
        let entries = synthetic_entries(9);
        let m = 3usize;
        let n = 5usize;
        let slice = &entries[..n];

        // Independent recomputation of expected structures
        let mth_0_2 = nflog_node_hash(
            nflog_leaf_hash(0, &entries[0]),
            nflog_leaf_hash(1, &entries[1]),
        );
        assert_eq!(mth_0_2, nflog_mth(&entries[..2]));

        let mth_a = nflog_node_hash(mth_0_2, nflog_leaf_hash(2, &entries[2]));
        assert_eq!(mth_a, nflog_mth(&entries[..m]));

        let mth_b = nflog_mth(slice);

        let proof = consistency_proof(m as u64, slice).expect("m <= n");
        // Hand-traced: [leaf(2), leaf(3), MTH(D[0:2]), leaf(4)]
        assert_eq!(proof.len(), 4);
        assert_eq!(proof[0], nflog_leaf_hash(2, &entries[2]));
        assert_eq!(proof[1], nflog_leaf_hash(3, &entries[3]));
        assert_eq!(proof[2], mth_0_2);
        assert_eq!(proof[3], nflog_leaf_hash(4, &entries[4]));

        assert!(verify_consistency(m as u64, mth_a, n as u64, mth_b, &proof));
    }

    /// Explicit m=0 consistency path (degenerate pair branch + continue).
    #[test]
    fn consistency_m_eq_0_against_n_eq_1() {
        let entries = synthetic_entries(1);
        let proof = consistency_proof(0, &entries).expect("ok");
        assert!(verify_consistency(
            0,
            nflog_empty(),
            1,
            nflog_mth(&entries),
            &proof
        ));
    }

    #[test]
    fn boundary_suite_inclusion_and_consistency() {
        for k in 0..=12u32 {
            let pow = 1usize << k;
            let candidates = [pow.saturating_sub(1), pow, pow.saturating_add(1)];
            // Dedup while preserving order for the three candidates
            let mut sizes: Vec<usize> = Vec::new();
            for n in candidates {
                if n > 0 && !sizes.contains(&n) {
                    sizes.push(n);
                }
            }

            for &n in &sizes {
                let entries = synthetic_entries(n);
                let mth = nflog_mth(&entries);

                // Inclusion at 0, n-1, and power-of-two boundary p = 2^floor(log2(n-1))
                let mut positions = vec![0usize, n - 1];
                if n >= 2 {
                    let p_boundary = 1usize << (n - 1).ilog2();
                    if p_boundary < n && !positions.contains(&p_boundary) {
                        positions.push(p_boundary);
                    }
                }
                for &p in &positions {
                    let path = inclusion_path(p as u64, &entries).expect("in range");
                    let leaf = nflog_leaf_hash(p as u64, &entries[p]);
                    assert!(
                        verify_inclusion(leaf, p as u64, &path, n as u64, mth),
                        "boundary inclusion k={k} n={n} p={p}"
                    );
                }
            }

            // Consistency for adjacent pairs (2^k - 1, 2^k) and (2^k, 2^k + 1)
            let mut pairs: Vec<(usize, usize)> =
                vec![(pow.saturating_sub(1), pow), (pow, pow.saturating_add(1))];
            if k == 0 {
                // Degenerierter Fall m==0 && n==0: deckt den bisher nie genommenen
                // false-Zweig von `if m == 0 && n > 0` ab. n==0 ist mit
                // pow = 1<<k >= 1 durch die reguläre Paar-Konstruktion nie erreichbar.
                pairs.push((0usize, 0usize));
            }
            for (m, n) in pairs {
                if m == 0 || n == 0 || m >= n {
                    // m==0 covered elsewhere; skip degenerate when pow==1 etc.
                    // Explicit m=0 path (also hit at k=0 → (0,1)).
                    if m == 0 && n > 0 {
                        let entries = synthetic_entries(n);
                        let proof = consistency_proof(0, &entries).expect("ok");
                        assert!(verify_consistency(
                            0,
                            nflog_empty(),
                            n as u64,
                            nflog_mth(&entries),
                            &proof
                        ));
                    }
                    continue;
                }
                let entries = synthetic_entries(n);
                let mth_a = nflog_mth(&entries[..m]);
                let mth_b = nflog_mth(&entries);
                let proof = consistency_proof(m as u64, &entries).expect("m <= n");
                assert!(
                    verify_consistency(m as u64, mth_a, n as u64, mth_b, &proof),
                    "boundary consistency m={m} n={n} k={k}"
                );
            }
        }
    }

    /// A genuine consistency proof for power-of-two `m` must reject a proof
    /// that has garbage digests prepended (proof canonicity: residual at the
    /// `m == n && b == true` base case must be empty).
    #[test]
    fn consistency_rejects_prepended_garbage_for_power_of_two_m() {
        // m=4 (power of two), n=8: subproof recursion eventually hits
        // m==n && b==true with an empty residual for a genuine proof.
        // Prepending garbage leaves a non-empty residual at that base case.
        let entries = synthetic_entries(8);
        let m = 4u64;
        let n = 8u64;
        let mth_a = nflog_mth(&entries[..m as usize]);
        let mth_b = nflog_mth(&entries[..n as usize]);
        let proof = consistency_proof(m, &entries[..n as usize]).expect("m <= n");
        assert!(
            verify_consistency(m, mth_a, n, mth_b, &proof),
            "genuine proof must verify"
        );

        let garbage = nflog_leaf_hash(99, &entries[0]);
        let mut padded = vec![garbage];
        padded.extend_from_slice(&proof);
        assert!(
            !verify_consistency(m, mth_a, n, mth_b, &padded),
            "prepended garbage must be rejected for power-of-two m={m}"
        );

        // Also cover m=2, n=4 for the same class of bug.
        let m2 = 2u64;
        let n2 = 4u64;
        let mth_a2 = nflog_mth(&entries[..m2 as usize]);
        let mth_b2 = nflog_mth(&entries[..n2 as usize]);
        let proof2 = consistency_proof(m2, &entries[..n2 as usize]).expect("m <= n");
        assert!(verify_consistency(m2, mth_a2, n2, mth_b2, &proof2));
        let mut padded2 = vec![garbage];
        padded2.extend_from_slice(&proof2);
        assert!(
            !verify_consistency(m2, mth_a2, n2, mth_b2, &padded2),
            "prepended garbage must be rejected for power-of-two m={m2}"
        );
    }

    /// Incremental peak-stack MTH must match the recursive reference for every
    /// prefix length (including empty and power-of-two boundaries).
    #[test]
    fn incremental_mth_matches_reference_for_every_prefix() {
        const MAX_N: usize = 256;
        let entries = synthetic_entries(MAX_N);
        let mut inc = NflogIncrementalMth::new();
        assert_eq!(inc.mth(), nflog_empty());
        assert_eq!(inc.size(), 0);

        for n in 1..=MAX_N {
            inc.append(&entries[n - 1]);
            assert_eq!(inc.size(), n as u64);
            assert_eq!(
                inc.mth(),
                nflog_mth(&entries[..n]),
                "incremental != reference at n={n}"
            );
        }

        // clear returns to empty
        inc.clear();
        assert_eq!(inc.size(), 0);
        assert_eq!(inc.mth(), nflog_empty());
        assert_eq!(inc.mth(), nflog_mth(&[]));
    }

    #[test]
    fn incremental_mth_power_of_two_boundaries() {
        let entries = synthetic_entries(257);
        let mut inc = NflogIncrementalMth::new();
        for n in 1..=257 {
            inc.append(&entries[n - 1]);
            let is_boundary = n.is_power_of_two()
                || (n + 1).is_power_of_two()
                || (n > 1 && (n - 1).is_power_of_two());
            if is_boundary {
                assert_eq!(
                    inc.mth(),
                    nflog_mth(&entries[..n]),
                    "boundary mismatch at n={n}"
                );
            }
        }
    }

    /// Round-trip consistency proofs for prefixes whose binary representation
    /// has 3+ set bits — these produce multiple closing chunks and exercise
    /// the non-associative reconstruction order in `fold_chunks`.
    #[test]
    fn consistency_proof_multi_set_bit_prefixes() {
        // m with 3 or 4 set bits; n = next power of two strictly greater than m.
        let cases: &[(usize, usize)] = &[
            (7, 8),   // 0b0111
            (11, 16), // 0b1011
            (13, 16), // 0b1101
            (14, 16), // 0b1110
            (15, 16), // 0b1111
            (23, 32), // 0b10111
            (29, 32), // 0b11101
            (31, 32), // 0b11111
        ];
        for &(m, n) in cases {
            assert!(m < n, "need positive growth: m={m} n={n}");
            let ones = m.count_ones();
            assert!(ones >= 3, "m={m} should have 3+ set bits (got {ones})");

            let entries = synthetic_entries(n);
            let mth_a = nflog_mth(&entries[..m]);
            let mth_b = nflog_mth(&entries[..n]);
            let proof = consistency_proof(m as u64, &entries[..n]).expect("m <= n");
            assert!(
                verify_consistency(m as u64, mth_a, n as u64, mth_b, &proof),
                "genuine consistency rejected m={m} n={n}"
            );

            // Tamper: mutate first field element of first proof digest.
            assert!(
                !proof.is_empty(),
                "expected non-empty proof for m={m} n={n}"
            );
            let mut tampered = proof.clone();
            {
                use plonky2::field::types::Field;
                tampered[0].elements[0] += zkcoins_program::F::ONE;
            }
            assert_ne!(tampered[0], proof[0], "tamper must change proof element");
            assert!(
                !verify_consistency(m as u64, mth_a, n as u64, mth_b, &tampered),
                "tampered proof accepted m={m} n={n}"
            );
        }
    }
}
