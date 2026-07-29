//! V.11 generated log-boundary fixtures and independent RFC-6962 reference.
//!
//! **Test-only** — compiled only with the `test-fixtures` feature. Not part of
//! the production library surface (a normal `cargo build -p shared` does not
//! compile this module).
//!
//! Shared by:
//! - `shared` integration tests (host verifiers + independent reference)
//! - `program-plonky2` gadget suite (same fixtures into the in-circuit
//!   inclusion/consistency arithmetization)
//!
//! Path / proof *construction* and the independent verifier live here so the
//! three consumers cannot drift onto lookalike generators. Production
//! `verify_inclusion` / `verify_consistency` / `nflog_node_hash` are the only
//! normative primitives this module calls; split / bagging / PATH / SUBPROOF
//! are re-derived independently.

use super::encoding::{hc, HcInput};
use super::nflog::{nflog_empty, nflog_node_hash};
use super::HashDigest;

// ---------------------------------------------------------------------------
// Independent RFC-6962 primitives
// ---------------------------------------------------------------------------

/// Largest power of two strictly less than `n`. Requires `n >= 2`.
/// Pure `u64` arithmetic — no `usize` cast.
pub fn ref_split_point(n: u64) -> u64 {
    assert!(n >= 2, "ref_split_point requires n >= 2, got {n}");
    let bits = 64 - (n - 1).leading_zeros();
    assert!(
        (1..=64).contains(&bits),
        "ref_split_point: impossible bit length {bits} for n={n}"
    );
    1u64 << (bits - 1)
}

/// Deterministic fixture digest standing in for the MTH of range
/// `[start, start+len)`. O(1) — never walks the range.
pub fn fixture_range(case_id: u64, start: u64, len: u64) -> HashDigest {
    assert!(len > 0, "fixture_range: len must be > 0");
    let mut preimage = [0u8; 24];
    preimage[0..8].copy_from_slice(&case_id.to_be_bytes());
    preimage[8..16].copy_from_slice(&start.to_be_bytes());
    preimage[16..24].copy_from_slice(&len.to_be_bytes());
    match hc(
        "zkCoins/v1/test-vector/nflog/boundary-range",
        &[HcInput::ByteString(&preimage)],
    ) {
        Ok(d) => d,
        Err(e) => panic!("fixture_range hc failed: {e:?}"),
    }
}

/// Independent peak bagging: peaks ordered largest-first (left → right).
/// Folds right-to-left: `Node(P_large, Node(…, P_small))` (§1.7.6 / RFC 6962).
pub fn ref_bag_peaks(peaks: &[HashDigest]) -> HashDigest {
    assert!(
        !peaks.is_empty(),
        "ref_bag_peaks: empty peak list — use nflog_empty for size 0"
    );
    let mut acc = peaks[peaks.len() - 1];
    for &peak in peaks[..peaks.len() - 1].iter().rev() {
        acc = nflog_node_hash(peak, acc);
    }
    acc
}

/// Swapped bagging order (fault injection): same fold direction as the
/// normative right-to-left bag, but with left/right operands of `Node`
/// reversed — `Node(acc, peak)` instead of `Node(peak, acc)`.
pub fn bag_peaks_swapped(peaks: &[HashDigest]) -> HashDigest {
    assert!(!peaks.is_empty(), "bag_peaks_swapped: empty peak list");
    let mut acc = peaks[peaks.len() - 1];
    for &peak in peaks[..peaks.len() - 1].iter().rev() {
        acc = nflog_node_hash(acc, peak);
    }
    acc
}

/// Power-of-two peak sizes for `n`, largest first (matches binary representation).
pub fn peak_sizes(n: u64) -> Vec<u64> {
    let mut sizes = Vec::new();
    let mut rem = n;
    for bit in (0..64u32).rev() {
        let sz = 1u64 << bit;
        if rem >= sz {
            sizes.push(sz);
            rem -= sz;
            if rem == 0 {
                break;
            }
        }
    }
    sizes
}

/// Ordered peak fixtures for a log of `size` (largest peak first).
pub fn fixture_peaks(case_id: u64, size: u64) -> Vec<HashDigest> {
    assert!(size > 0, "fixture_peaks: size must be > 0");
    let mut peaks = Vec::new();
    let mut start = 0u64;
    for sz in peak_sizes(size) {
        peaks.push(fixture_range(case_id, start, sz));
        start = match start.checked_add(sz) {
            Some(v) => v,
            None => panic!("peak start overflow at size={size}"),
        };
    }
    assert_eq!(start, size, "peak coverage must equal size");
    peaks
}

/// MTH of range `[start, start+len)` via peak bagging of atomic fixtures.
/// O(popcount(len)) — never Θ(len).
pub fn ref_mth_run(case_id: u64, start: u64, len: u64) -> HashDigest {
    assert!(len > 0, "ref_mth_run: len must be > 0");
    if len == 1 {
        return fixture_range(case_id, start, 1);
    }
    let mut peaks = Vec::new();
    let mut pos = start;
    let mut rem = len;
    for bit in (0..64u32).rev() {
        let sz = 1u64 << bit;
        if rem >= sz {
            peaks.push(fixture_range(case_id, pos, sz));
            pos = match pos.checked_add(sz) {
                Some(v) => v,
                None => panic!("ref_mth_run pos overflow"),
            };
            rem -= sz;
            if rem == 0 {
                break;
            }
        }
    }
    ref_bag_peaks(&peaks)
}

// ---------------------------------------------------------------------------
// Inclusion PATH builder + independent verifier
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct InclusionWitness {
    pub leaf: HashDigest,
    pub path: Vec<HashDigest>,
    pub mth: HashDigest,
}

/// Honest PATH + MTH from symbolic fixtures. O(log n) node hashes.
pub fn ref_build_inclusion(case_id: u64, position: u64, size: u64) -> InclusionWitness {
    assert!(size > 0, "inclusion requires size > 0");
    assert!(
        position < size,
        "position {position} out of range for size {size}"
    );

    fn rec(
        case_id: u64,
        rel_pos: u64,
        n: u64,
        abs_start: u64,
    ) -> (HashDigest, Vec<HashDigest>, HashDigest) {
        if n == 1 {
            let leaf = fixture_range(case_id, abs_start, 1);
            return (leaf, vec![], leaf);
        }
        let k = ref_split_point(n);
        assert!(k >= 1 && k < n, "split k={k} invalid for n={n}");
        if rel_pos < k {
            let (leaf, mut path, left_mth) = rec(case_id, rel_pos, k, abs_start);
            let right_mth = ref_mth_run(case_id, abs_start + k, n - k);
            path.push(right_mth);
            (leaf, path, nflog_node_hash(left_mth, right_mth))
        } else {
            let (leaf, mut path, right_mth) = rec(case_id, rel_pos - k, n - k, abs_start + k);
            let left_mth = ref_mth_run(case_id, abs_start, k);
            path.push(left_mth);
            (leaf, path, nflog_node_hash(left_mth, right_mth))
        }
    }

    let (leaf, path, mth) = rec(case_id, position, size, 0);
    InclusionWitness { leaf, path, mth }
}

/// Inclusion path length under a custom top-level pivot; interior levels use
/// the honest `ref_split_point`.
fn inclusion_path_len_with_top_pivot(rel_pos: u64, n: u64, top_k: u64) -> usize {
    fn honest_len(rel_pos: u64, n: u64) -> usize {
        if n == 1 {
            return 0;
        }
        let k = ref_split_point(n);
        if rel_pos < k {
            1 + honest_len(rel_pos, k)
        } else {
            1 + honest_len(rel_pos - k, n - k)
        }
    }
    if n == 1 {
        return 0;
    }
    assert!(top_k >= 1 && top_k < n);
    if rel_pos < top_k {
        1 + honest_len(rel_pos, top_k)
    } else {
        1 + honest_len(rel_pos - top_k, n - top_k)
    }
}

/// Build inclusion with a wrong **top-level** pivot only; interior splits are
/// honest. Uses the **same** `case_id` fixtures as the honest witness.
fn ref_build_inclusion_with_top_pivot(
    case_id: u64,
    position: u64,
    size: u64,
    top_k: u64,
) -> InclusionWitness {
    assert!(size >= 2);
    assert!(top_k >= 1 && top_k < size);
    assert!(position < size);

    fn rec_honest(
        case_id: u64,
        rel_pos: u64,
        n: u64,
        abs_start: u64,
    ) -> (HashDigest, Vec<HashDigest>, HashDigest) {
        if n == 1 {
            let leaf = fixture_range(case_id, abs_start, 1);
            return (leaf, vec![], leaf);
        }
        let k = ref_split_point(n);
        if rel_pos < k {
            let (leaf, mut path, left_mth) = rec_honest(case_id, rel_pos, k, abs_start);
            let right_mth = ref_mth_run(case_id, abs_start + k, n - k);
            path.push(right_mth);
            (leaf, path, nflog_node_hash(left_mth, right_mth))
        } else {
            let (leaf, mut path, right_mth) =
                rec_honest(case_id, rel_pos - k, n - k, abs_start + k);
            let left_mth = ref_mth_run(case_id, abs_start, k);
            path.push(left_mth);
            (leaf, path, nflog_node_hash(left_mth, right_mth))
        }
    }

    if position < top_k {
        let (leaf, mut path, left_mth) = rec_honest(case_id, position, top_k, 0);
        let right_mth = ref_mth_run(case_id, top_k, size - top_k);
        path.push(right_mth);
        InclusionWitness {
            leaf,
            path,
            mth: nflog_node_hash(left_mth, right_mth),
        }
    } else {
        let (leaf, mut path, right_mth) =
            rec_honest(case_id, position - top_k, size - top_k, top_k);
        let left_mth = ref_mth_run(case_id, 0, top_k);
        path.push(left_mth);
        InclusionWitness {
            leaf,
            path,
            mth: nflog_node_hash(left_mth, right_mth),
        }
    }
}

/// Result of attempting a pure single-property wrong-pivot mutation.
#[derive(Clone, Debug)]
pub enum PivotMutation {
    /// Same fixture roots, same path length, only top pivot wrong.
    Ok {
        wrong_pivot: u64,
        witness: InclusionWitness,
    },
    /// Cannot construct a pure pivot mutation at this (n, p) without also
    /// changing the path length (or no alternate power-of-two pivot exists).
    Unreachable { reason: String },
}

/// Try to build a wrong-pivot inclusion witness that keeps path length fixed.
///
/// Searches power-of-two pivots `k' ≠ honest` in `[1, n)` for one that yields
/// the same path length as the honest decomposition. Uses the **same**
/// `case_id` (same fixture roots).
pub fn try_inclusion_wrong_pivot(case_id: u64, position: u64, size: u64) -> PivotMutation {
    if size < 3 {
        return PivotMutation::Unreachable {
            reason: format!("size={size} < 3: no alternate power-of-two pivot in [1, n)"),
        };
    }
    let honest = ref_split_point(size);
    let honest_len = inclusion_path_len_with_top_pivot(position, size, honest);
    let mut candidate: Option<u64> = None;
    for bit in 0..64u32 {
        let k = 1u64 << bit;
        if k < 1 || k >= size || k == honest {
            continue;
        }
        let bad_len = inclusion_path_len_with_top_pivot(position, size, k);
        if bad_len == honest_len {
            candidate = Some(k);
            break;
        }
    }
    match candidate {
        None => PivotMutation::Unreachable {
            reason: format!(
                "no power-of-two k'≠{honest} in [1,{size}) preserves inclusion path length \
                 {honest_len} at p={position}"
            ),
        },
        Some(wrong_pivot) => {
            let witness = ref_build_inclusion_with_top_pivot(case_id, position, size, wrong_pivot);
            assert_eq!(
                witness.path.len(),
                honest_len,
                "internal: length-preserving pivot search mismatched"
            );
            // Same leaf fixture (absolute position unchanged).
            let honest_w = ref_build_inclusion(case_id, position, size);
            assert_eq!(
                witness.leaf, honest_w.leaf,
                "wrong-pivot must keep the same leaf fixture"
            );
            PivotMutation::Ok {
                wrong_pivot,
                witness,
            }
        }
    }
}

/// Swap left/right bagging at the **top hop only**: same path siblings and
/// leaf (same fixtures, same length), only the claimed root combines
/// `Node(right, left)` instead of `Node(left, right)`.
///
/// The audit-path *slots* are unchanged; only the public `mth` differs. This
/// is the pure bagging-order mutation for inclusion (the verifier chooses L/R
/// from position bits — a swapped claimed root must not accept).
pub fn ref_build_inclusion_swapped_top_mth(
    case_id: u64,
    position: u64,
    size: u64,
) -> Option<InclusionWitness> {
    if size < 2 {
        return None;
    }
    let honest = ref_build_inclusion(case_id, position, size);
    // Recompute top combination with swapped operands from the same path.
    let k = ref_split_point(size);
    let top_sibling = *honest.path.last().expect("n>=2 ⇒ path non-empty");
    let inner_mth = if honest.path.len() == 1 {
        honest.leaf
    } else {
        // Recompute the sub-root with honest bagging on the prefix path.
        match ref_verify_path(
            if position < k { position } else { position - k },
            if position < k { k } else { size - k },
            honest.leaf,
            &honest.path[..honest.path.len() - 1],
        ) {
            Some(v) => v,
            None => panic!("honest prefix path must verify"),
        }
    };
    let swapped_mth = if position < k {
        // Honest: Node(inner, sibling); swapped: Node(sibling, inner).
        nflog_node_hash(top_sibling, inner_mth)
    } else {
        // Honest: Node(sibling, inner); swapped: Node(inner, sibling).
        nflog_node_hash(inner_mth, top_sibling)
    };
    if swapped_mth == honest.mth {
        return None;
    }
    Some(InclusionWitness {
        leaf: honest.leaf,
        path: honest.path,
        mth: swapped_mth,
    })
}

/// Independent inclusion verifier (RFC 6962 §2.1.1), `u64` throughout.
pub fn ref_verify_inclusion(
    leaf: HashDigest,
    position: u64,
    path: &[HashDigest],
    size: u64,
    mth: HashDigest,
) -> bool {
    if size == 0 || position >= size {
        return false;
    }
    match ref_verify_path(position, size, leaf, path) {
        Some(recomputed) => recomputed == mth,
        None => false,
    }
}

fn ref_verify_path(
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
    let k = ref_split_point(n);
    let (inner, last) = path.split_at(path.len() - 1);
    let sibling = last[0];
    if rel_pos < k {
        let sub = ref_verify_path(rel_pos, k, leaf, inner)?;
        Some(nflog_node_hash(sub, sibling))
    } else {
        let sub = ref_verify_path(rel_pos - k, n - k, leaf, inner)?;
        Some(nflog_node_hash(sibling, sub))
    }
}

// ---------------------------------------------------------------------------
// Consistency SUBPROOF builder + independent verifier
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ConsistencyWitness {
    pub mth_a: HashDigest,
    pub mth_b: HashDigest,
    pub proof: Vec<HashDigest>,
    /// Prefix-closing chunks that bag into `mth_a` (outermost-first).
    pub chunks: Vec<HashDigest>,
}

/// Honest consistency witness. O(log n).
pub fn ref_build_consistency(case_id: u64, m: u64, n: u64) -> ConsistencyWitness {
    assert!(
        m > 0 && m < n,
        "ref_build_consistency: need 0 < m < n (got m={m} n={n})"
    );

    fn subproof(
        case_id: u64,
        m: u64,
        n: u64,
        start: u64,
        b: bool,
    ) -> (Vec<HashDigest>, HashDigest, Vec<HashDigest>) {
        if m == n {
            let mth = ref_mth_run(case_id, start, n);
            if b {
                return (vec![], mth, vec![mth]);
            }
            return (vec![mth], mth, vec![mth]);
        }
        let k = ref_split_point(n);
        if m <= k {
            let (mut proof, left_mth, chunks) = subproof(case_id, m, k, start, b);
            let right_mth = ref_mth_run(case_id, start + k, n - k);
            proof.push(right_mth);
            let local = nflog_node_hash(left_mth, right_mth);
            (proof, local, chunks)
        } else {
            let (mut proof, right_mth, chunks) = subproof(case_id, m - k, n - k, start + k, false);
            let left_mth = ref_mth_run(case_id, start, k);
            proof.push(left_mth);
            let mut all_chunks = vec![left_mth];
            all_chunks.extend(chunks);
            let local = nflog_node_hash(left_mth, right_mth);
            (proof, local, all_chunks)
        }
    }

    let (proof, mth_b, chunks) = subproof(case_id, m, n, 0, true);
    let mth_a = ref_fold_chunks(&chunks);
    ConsistencyWitness {
        mth_a,
        mth_b,
        proof,
        chunks,
    }
}

pub fn ref_fold_chunks(chunks: &[HashDigest]) -> HashDigest {
    assert!(
        !chunks.is_empty(),
        "ref_fold_chunks: subproof always yields ≥ 1 chunk"
    );
    let mut acc = chunks[chunks.len() - 1];
    for &c in chunks[..chunks.len() - 1].iter().rev() {
        acc = nflog_node_hash(c, acc);
    }
    acc
}

/// Fold with swapped Node operands (fault injection for peak bagging order).
pub fn ref_fold_chunks_swapped(chunks: &[HashDigest]) -> HashDigest {
    assert!(!chunks.is_empty(), "ref_fold_chunks_swapped: empty chunks");
    let mut acc = chunks[chunks.len() - 1];
    for &c in chunks[..chunks.len() - 1].iter().rev() {
        acc = nflog_node_hash(acc, c);
    }
    acc
}

/// NL-B2 mutation for a **singleton** peak/chunk list: claim `Node(P, P)`
/// instead of the honest identity bag `P`.
///
/// Swap is a no-op when there is only one peak/chunk; duplication changes
/// only the bagging summary and is the pure single-property fault for that
/// shape (proof, sizes, ordering, and `mth_b` stay honest).
pub fn mth_a_duplicated_singleton(singleton: HashDigest) -> HashDigest {
    nflog_node_hash(singleton, singleton)
}

/// NL-B2 mutation: claim the empty-log summary instead of the honest bag of
/// prefix chunks/peaks. Pure bagging fault — proof and sizes unchanged.
pub fn mth_a_dropped_to_empty() -> HashDigest {
    nflog_empty()
}

fn consistency_proof_len_with_top_pivot(m: u64, n: u64, top_k: u64) -> usize {
    fn honest_len(m: u64, n: u64, b: bool) -> usize {
        if m == n {
            return if b { 0 } else { 1 };
        }
        let k = ref_split_point(n);
        if m <= k {
            honest_len(m, k, b) + 1
        } else {
            honest_len(m - k, n - k, false) + 1
        }
    }
    assert!(m > 0 && m < n);
    assert!(top_k >= 1 && top_k < n);
    if m <= top_k {
        // Need m < top_k or handle m == top_k.
        if m == top_k {
            // subproof terminates early on left with b=true →
            // empty subproof (0) + sibling (1) = 1
            1
        } else {
            honest_len(m, top_k, true) + 1
        }
    } else {
        honest_len(m - top_k, n - top_k, false) + 1
    }
}

fn ref_build_consistency_with_top_pivot(
    case_id: u64,
    m: u64,
    n: u64,
    top_k: u64,
) -> ConsistencyWitness {
    assert!(m > 0 && m < n);
    assert!(top_k >= 1 && top_k < n);

    fn subproof_honest(
        case_id: u64,
        m: u64,
        n: u64,
        start: u64,
        b: bool,
    ) -> (Vec<HashDigest>, HashDigest, Vec<HashDigest>) {
        if m == n {
            let mth = ref_mth_run(case_id, start, n);
            if b {
                return (vec![], mth, vec![mth]);
            }
            return (vec![mth], mth, vec![mth]);
        }
        let k = ref_split_point(n);
        if m <= k {
            let (mut proof, left_mth, chunks) = subproof_honest(case_id, m, k, start, b);
            let right_mth = ref_mth_run(case_id, start + k, n - k);
            proof.push(right_mth);
            (proof, nflog_node_hash(left_mth, right_mth), chunks)
        } else {
            let (mut proof, right_mth, chunks) =
                subproof_honest(case_id, m - k, n - k, start + k, false);
            let left_mth = ref_mth_run(case_id, start, k);
            proof.push(left_mth);
            let mut all_chunks = vec![left_mth];
            all_chunks.extend(chunks);
            (proof, nflog_node_hash(left_mth, right_mth), all_chunks)
        }
    }

    let (proof, mth_b, chunks) = if m <= top_k {
        if m == top_k {
            let left_mth = ref_mth_run(case_id, 0, top_k);
            let right_mth = ref_mth_run(case_id, top_k, n - top_k);
            (
                vec![right_mth],
                nflog_node_hash(left_mth, right_mth),
                vec![left_mth],
            )
        } else {
            let (mut proof, left_mth, chunks) = subproof_honest(case_id, m, top_k, 0, true);
            let right_mth = ref_mth_run(case_id, top_k, n - top_k);
            proof.push(right_mth);
            (proof, nflog_node_hash(left_mth, right_mth), chunks)
        }
    } else {
        let (mut proof, right_mth, chunks) =
            subproof_honest(case_id, m - top_k, n - top_k, top_k, false);
        let left_mth = ref_mth_run(case_id, 0, top_k);
        proof.push(left_mth);
        let mut all_chunks = vec![left_mth];
        all_chunks.extend(chunks);
        (proof, nflog_node_hash(left_mth, right_mth), all_chunks)
    };
    let mth_a = ref_fold_chunks(&chunks);
    ConsistencyWitness {
        mth_a,
        mth_b,
        proof,
        chunks,
    }
}

/// Result of attempting a pure wrong-pivot consistency mutation.
#[derive(Clone, Debug)]
pub enum ConsistencyPivotMutation {
    Ok {
        wrong_pivot: u64,
        witness: ConsistencyWitness,
    },
    Unreachable {
        reason: String,
    },
}

/// Try wrong top-level pivot for consistency, same fixtures, same proof length.
pub fn try_consistency_wrong_pivot(case_id: u64, m: u64, n: u64) -> ConsistencyPivotMutation {
    if n < 3 {
        return ConsistencyPivotMutation::Unreachable {
            reason: format!("n={n} < 3: no alternate power-of-two pivot"),
        };
    }
    if m == 0 || m >= n {
        return ConsistencyPivotMutation::Unreachable {
            reason: format!("need 0 < m < n (got m={m} n={n})"),
        };
    }
    let honest = ref_split_point(n);
    let honest_len = {
        let w = ref_build_consistency(case_id, m, n);
        w.proof.len()
    };
    let mut candidate: Option<u64> = None;
    for bit in 0..64u32 {
        let k = 1u64 << bit;
        if k < 1 || k >= n || k == honest {
            continue;
        }
        // Skip pivots that would make the left run empty of the prefix logic.
        if consistency_proof_len_with_top_pivot(m, n, k) == honest_len {
            candidate = Some(k);
            break;
        }
    }
    match candidate {
        None => ConsistencyPivotMutation::Unreachable {
            reason: format!(
                "no power-of-two k'≠{honest} in [1,{n}) preserves consistency proof length \
                 {honest_len} at m={m}"
            ),
        },
        Some(wrong_pivot) => {
            let witness = ref_build_consistency_with_top_pivot(case_id, m, n, wrong_pivot);
            assert_eq!(
                witness.proof.len(),
                honest_len,
                "internal: consistency length-preserving pivot search mismatched"
            );
            ConsistencyPivotMutation::Ok {
                wrong_pivot,
                witness,
            }
        }
    }
}

/// Independent consistency verifier (RFC 6962 §2.1.2), `u64` throughout.
pub fn ref_verify_consistency(
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
        return proof.is_empty() && mth_a == nflog_empty();
    }
    if m == n {
        return proof.is_empty() && mth_a == mth_b;
    }
    match ref_verify_subproof(m, n, true, mth_a, proof) {
        Some((chunks, n_side)) => {
            if n_side != mth_b {
                return false;
            }
            ref_fold_chunks(&chunks) == mth_a
        }
        None => false,
    }
}

fn ref_verify_subproof(
    m: u64,
    n: u64,
    b: bool,
    mth_a_hint: HashDigest,
    proof: &[HashDigest],
) -> Option<(Vec<HashDigest>, HashDigest)> {
    if m == n {
        if b {
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
    let k = ref_split_point(n);
    let (inner, last) = proof.split_at(proof.len() - 1);
    let sibling = last[0];
    if m <= k {
        let (chunks, inner_local) = ref_verify_subproof(m, k, b, mth_a_hint, inner)?;
        let local_value = nflog_node_hash(inner_local, sibling);
        Some((chunks, local_value))
    } else {
        let (chunks, inner_local) = ref_verify_subproof(m - k, n - k, false, mth_a_hint, inner)?;
        let mut all_chunks = vec![sibling];
        all_chunks.extend(chunks);
        let local_value = nflog_node_hash(sibling, inner_local);
        Some((all_chunks, local_value))
    }
}

// ---------------------------------------------------------------------------
// Capacity / size helpers
// ---------------------------------------------------------------------------

/// In-scope boundary sizes for bit `k`: `{2^k−1, 2^k, 2^k+1}` ∩ `[0, 2^64−1]`.
pub fn boundary_sizes(k: u32) -> Vec<u64> {
    assert!(k <= 63, "k must be in 0…63");
    let pow = 1u64 << k;
    let mut candidates = Vec::with_capacity(3);
    let n_lo = pow.saturating_sub(1);
    let n_mid = pow;
    let n_hi = match pow.checked_add(1) {
        Some(v) => v,
        None => panic!("2^{k}+1 overflowed u64"),
    };
    for n in [n_lo, n_mid, n_hi] {
        if !candidates.contains(&n) {
            candidates.push(n);
        }
    }
    candidates
}

/// Representative inclusion positions for size `n` (Accept set).
pub fn inclusion_positions(n: u64) -> Vec<u64> {
    assert!(n >= 1);
    let mut positions = vec![0u64, n - 1];
    if n >= 2 {
        let log = (n - 1).ilog2();
        let p_boundary = 1u64 << log;
        if p_boundary < n && !positions.contains(&p_boundary) {
            positions.push(p_boundary);
        }
    }
    let mut out = Vec::new();
    for p in positions {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Positions to probe when searching for a pure (same-length) wrong-pivot
/// inclusion mutation. Accept positions alone often force a length change;
/// interior samples (still O(1) many, never Θ(n)) cover the reachable class.
pub fn wrong_pivot_search_positions(n: u64) -> Vec<u64> {
    assert!(n >= 1);
    let mut out = inclusion_positions(n);
    let push = |out: &mut Vec<u64>, p: u64| {
        if p < n && !out.contains(&p) {
            out.push(p);
        }
    };
    for extra in [1u64, 2, 3, 5, 6, 7] {
        push(&mut out, extra);
    }
    if n >= 4 {
        for d in [1u64, 2, 3] {
            if n - 1 > d {
                push(&mut out, n - 1 - d);
            }
        }
    }
    if n >= 8 {
        let mid = n / 2;
        for d in [0u64, 1, 2, 3] {
            if mid >= d {
                push(&mut out, mid - d);
            }
            push(&mut out, mid.saturating_add(d));
        }
    }
    out
}

/// Find one pure wrong-pivot inclusion mutation for `size`, if any exists among
/// [`wrong_pivot_search_positions`]. Returns `(position, wrong_pivot, witness)`.
pub fn find_inclusion_wrong_pivot(case_id: u64, size: u64) -> Option<(u64, u64, InclusionWitness)> {
    for p in wrong_pivot_search_positions(size) {
        match try_inclusion_wrong_pivot(case_id, p, size) {
            PivotMutation::Ok {
                wrong_pivot,
                witness,
            } => return Some((p, wrong_pivot, witness)),
            PivotMutation::Unreachable { .. } => continue,
        }
    }
    None
}

/// Adjacent consistency pairs for bit `k`: `(2^k−1, 2^k)` and `(2^k, 2^k+1)`.
pub fn adjacent_consistency_pairs(k: u32) -> [(u64, u64); 2] {
    let pow = 1u64 << k;
    [
        (pow.saturating_sub(1), pow),
        (
            pow,
            match pow.checked_add(1) {
                Some(v) => v,
                None => panic!("2^{k}+1 overflowed"),
            },
        ),
    ]
}

/// Stable case_id for a boundary cell (keeps fixture roots reproducible).
pub fn case_id_inclusion(k: u32, n: u64, p: u64) -> u64 {
    (u64::from(k) << 16) | 0xB000 | p.wrapping_mul(3) | n.wrapping_mul(7)
}

pub fn case_id_consistency(k: u32, m: u64, n: u64) -> u64 {
    (u64::from(k) << 16) | 0xC000 | m.wrapping_mul(5) | n.wrapping_mul(11)
}

pub fn case_id_peaks(k: u32) -> u64 {
    (u64::from(k) << 16) | 0xA000
}
