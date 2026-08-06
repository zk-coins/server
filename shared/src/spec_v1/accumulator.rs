//! Stateful in-memory Path-A nullifier accumulator (§3.6 / §3.7 / §3.9).

use std::collections::HashMap;

use super::error::SpecError;
use super::nflog::{
    inclusion_path, nflog_empty, nflog_mth, nflog_root, Nav, NfLogEntry, NflogIncrementalMth,
};
use zkcoins_program::hash::HashDigest;

/// Protocol-pinned finality depth (§3.9): six confirmations.
///
/// Local constant — not threaded from `NetworkParams` — because
/// `NfLogAccumulator` has no handle to network params today and the
/// protocol pins this as a fixed constant rather than a free parameter.
const FINALITY_CONFIRMATIONS: u64 = 6;

/// Canonical total order key (section 3.6 step 4): block height, then reveal-tx
/// index, then reveal-input index, then in-payload member index. Field
/// declaration order MUST stay exactly this (height, tx_index, vin_index,
/// member_index) — `#[derive(PartialOrd, Ord)]` compares fields in
/// declaration order, which is what makes this the correct canonical sort.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainPosition {
    pub height: u64,
    pub tx_index: u32,
    pub vin_index: u32,
    pub member_index: u32,
}

/// One surviving (signature-verified, structurally valid) on-chain
/// nullifier, before first-occurrence folding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedNullifier {
    pub chain_pos: ChainPosition,
    pub pk: [u8; 32],
    pub r: [u8; 32],
}

/// Outcome of folding one published nullifier (section 3.6 step 5 / activation
/// height scan-origin).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldOutcome {
    /// Newly admitted at this position (first occurrence of `pk`).
    Appended(u64),
    /// `pk` was already present (a fork/double-spend loser, or an exact
    /// republish) — NOT appended; the earlier position/R wins.
    DuplicateIgnored,
    /// `chain_pos.height < activation_height` — not part of the
    /// accumulator at all (section 3.6 "Scan origin").
    BelowActivationHeight,
}

/// Outcome of a truncate-and-refold reorg (§3.9).
///
/// Callers that observe `finality_broken == true` MUST surface the condition
/// (e.g. `/health/ready` → 503 deep_reorg) and MUST NOT continue crediting
/// against the broken state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgOutcome {
    /// True iff any position that was final before the reorg
    /// (`p < size_final(old_tip_height)`) is gone or maps to a different
    /// `(pk, r)` after replay.
    pub finality_broken: bool,
    /// Count of final positions that were displaced (gone or pk/r mismatch).
    pub displaced_final_count: u64,
}

/// A Path-A membership answer for one `Pk` (section 3.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupResult {
    Present {
        pos: u64,
        r: [u8; 32],
        inclusion_proof: Vec<HashDigest>,
    },
    /// Unauthenticated local-index absence answer. v1 defines NO
    /// authenticated non-membership proof over this log (section 3.7 Path-B
    /// `present: false`) — a caller MUST NOT treat this as cryptographic
    /// proof of absence, only as "not yet in this node's local index".
    Absent,
}

/// section 3.7 "Double-spend check (per-transition, Pk_i-keyed)" classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendClassification {
    /// `pk` present with the matching `r` — first, valid, anchored spend.
    ValidFirstSpend,
    /// `pk` present with a DIFFERENT `r` — a competing transition was
    /// anchored first; this one is the rejected double-spend.
    RejectedDoubleSpend,
    /// `pk` absent — not yet anchored (section 3.10 `pending`).
    Pending,
}

/// The stateful, in-memory nullifier accumulator (Path-A, section 3.7).
pub struct NfLogAccumulator {
    activation_height: u64,
    log: Vec<NfLogEntry>,
    /// Parallel to `log`; `heights[i]` = inclusion-block height of `log[i]`.
    heights: Vec<u64>,
    /// `pk -> (position, r)`
    index: HashMap<[u8; 32], (u64, [u8; 32])>,
    mth: HashDigest,
    /// Perfect-subtree peaks for O(log n) tip-MTH updates on each append.
    /// Always in lockstep with `log`: after every successful append,
    /// `mth_state.mth() == nflog_mth(&log)` and `mth_state.size() == log.len()`.
    mth_state: NflogIncrementalMth,
    /// Last chain position that reached the duplicate/append decision
    /// (i.e. passed the activation-height filter). Used to enforce
    /// strictly-increasing canonical order (§3.6 step 4).
    last_position: Option<ChainPosition>,
}

impl NfLogAccumulator {
    pub fn new(activation_height: u64) -> Self {
        Self {
            activation_height,
            log: Vec::new(),
            heights: Vec::new(),
            index: HashMap::new(),
            mth: nflog_empty(),
            mth_state: NflogIncrementalMth::new(),
            last_position: None,
        }
    }

    /// Fold one published nullifier by first-occurrence (section 3.6 step 5).
    ///
    /// Enforces strictly-increasing `ChainPosition` order for every call that
    /// is not filtered by activation height. On a successful first-occurrence
    /// append, updates the tip MTH in `O(log n)` Poseidon hashes via the
    /// perfect-subtree peak stack ([`NflogIncrementalMth`]) — byte-identical
    /// to recomputing [`nflog_mth`] over the full log. Suitable for bulk
    /// chain-scan folds; total cost to admit `N` distinct nullifiers is
    /// `O(N log N)` hashes, not `O(N²)`.
    pub fn fold(
        &mut self,
        chain_pos: ChainPosition,
        pk: [u8; 32],
        r: [u8; 32],
    ) -> Result<FoldOutcome, SpecError> {
        if chain_pos.height < self.activation_height {
            return Ok(FoldOutcome::BelowActivationHeight);
        }
        if let Some(prev) = self.last_position {
            if chain_pos <= prev {
                return Err(SpecError::OutOfOrderFold {
                    previous: prev,
                    attempted: chain_pos,
                });
            }
        }
        // Ordering accepted for this call — record before duplicate/append
        // so a DuplicateIgnored call still advances the order cursor.
        self.last_position = Some(chain_pos);

        if self.index.contains_key(&pk) {
            return Ok(FoldOutcome::DuplicateIgnored);
        }
        let pos = self.log.len() as u64;
        let entry = NfLogEntry { pk, r };
        self.log.push(entry);
        self.heights.push(chain_pos.height);
        self.index.insert(pk, (pos, r));
        self.mth_state.append(&entry);
        self.mth = self.mth_state.mth();
        Ok(FoldOutcome::Appended(pos))
    }

    pub fn nav(&self) -> Nav {
        Nav {
            size: self.log.len() as u64,
            mth: self.mth,
        }
    }

    /// Canonical iff `mth == MTH(D[0:size])` over THIS accumulator's own
    /// rebuilt log (section 3.7 "Canonical value").
    pub fn is_canonical(&self, size: u64, mth: HashDigest) -> bool {
        let n = self.log.len() as u64;
        if size > n {
            return false;
        }
        if size == n {
            return mth == self.mth;
        }
        nflog_mth(&self.log[..size as usize]) == mth
    }

    /// The committed §3.7 accumulator ROOT (`nflog_root(size, mth)`) this accumulator would report
    /// for prefix length `size`, or `None` if `size` exceeds how many entries this accumulator has
    /// actually folded. Same size-branching as `is_canonical` (reuse the cached tip `mth` at
    /// `size == log.len()`, `nflog_empty()` at `size == 0`, else recompute `nflog_mth` over the
    /// prefix) but returns the committed root digest instead of a bool, because callers that only
    /// have a disclosed ROOT (not a raw `mth`) need something to compare against directly.
    pub fn root_at(&self, size: u64) -> Option<HashDigest> {
        let n = self.log.len() as u64;
        if size > n {
            return None;
        }
        let mth = if size == n {
            self.mth
        } else if size == 0 {
            nflog_empty()
        } else {
            nflog_mth(&self.log[..size as usize])
        };
        Some(nflog_root(size, mth))
    }

    pub fn lookup(&self, pk: [u8; 32]) -> LookupResult {
        match self.index.get(&pk) {
            Some(&(pos, r)) => {
                let inclusion_proof = inclusion_path(pos, &self.log)
                    .expect("index invariant: pos is always < log.len()");
                LookupResult::Present {
                    pos,
                    r,
                    inclusion_proof,
                }
            }
            None => LookupResult::Absent,
        }
    }

    pub fn classify(&self, pk: [u8; 32], r: [u8; 32]) -> SpendClassification {
        match self.index.get(&pk) {
            Some(&(_, winner_r)) if winner_r == r => SpendClassification::ValidFirstSpend,
            Some(_) => SpendClassification::RejectedDoubleSpend,
            None => SpendClassification::Pending,
        }
    }

    /// Truncate-and-refold reorg (section 3.6/3.9): snapshots final positions
    /// under `old_tip_height`, clears all state, re-folds `canonical_stream`
    /// (sorted by `ChainPosition`) from scratch, and reports whether any
    /// previously-final position was displaced.
    pub fn reorg_replay(
        &mut self,
        old_tip_height: u64,
        mut canonical_stream: Vec<PublishedNullifier>,
    ) -> Result<ReorgOutcome, SpecError> {
        let old_final = self.size_final(old_tip_height) as usize;
        let final_snapshot: Vec<NfLogEntry> = self.log[..old_final].to_vec();

        canonical_stream.sort_by_key(|e| e.chain_pos);
        self.log.clear();
        self.heights.clear();
        self.index.clear();
        self.mth_state.clear();
        self.mth = nflog_empty();
        self.last_position = None;

        for entry in canonical_stream {
            // Propagate fold errors (should not arise from a well-formed,
            // already-sorted stream, but fail-loud rather than swallow).
            self.fold(entry.chain_pos, entry.pk, entry.r)?;
        }

        let mut displaced_final_count = 0u64;
        for (p, old) in final_snapshot.iter().enumerate() {
            let displaced = match self.log.get(p) {
                Some(new) => new.pk != old.pk || new.r != old.r,
                None => true,
            };
            if displaced {
                displaced_final_count = displaced_final_count
                    .checked_add(1)
                    .expect("displaced count cannot overflow u64");
            }
        }

        Ok(ReorgOutcome {
            finality_broken: displaced_final_count > 0,
            displaced_final_count,
        })
    }

    /// `size_final` (section 3.9): the accumulator size at the highest block
    /// height `<= tip_height - (FINALITY_CONFIRMATIONS - 1)`. Returns 0 if
    /// `tip_height < 5` (i.e. fewer than 6 confirmations are possible).
    ///
    /// Finality depth is the protocol-pinned constant 6 — not a free
    /// parameter — matching §3.9.
    pub fn size_final(&self, tip_height: u64) -> u64 {
        // FINALITY_CONFIRMATIONS - 1 = 5; compile-time safe (6 is a literal).
        const OFFSET: u64 = FINALITY_CONFIRMATIONS - 1;
        let Some(max_final_height) = tip_height.checked_sub(OFFSET) else {
            return 0;
        };
        self.heights.partition_point(|&h| h <= max_final_height) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_v1::nflog::{nflog_leaf_hash, verify_inclusion};

    fn pk(byte: u8) -> [u8; 32] {
        let mut p = [0u8; 32];
        p[0] = byte;
        p
    }

    fn r(byte: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[31] = byte;
        v
    }

    fn pos(height: u64) -> ChainPosition {
        ChainPosition {
            height,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        }
    }

    fn pos_full(height: u64, tx_index: u32, vin_index: u32, member_index: u32) -> ChainPosition {
        ChainPosition {
            height,
            tx_index,
            vin_index,
            member_index,
        }
    }

    fn published(height: u64, pk_b: u8, r_b: u8) -> PublishedNullifier {
        PublishedNullifier {
            chain_pos: pos(height),
            pk: pk(pk_b),
            r: r(r_b),
        }
    }

    #[test]
    fn first_occurrence_duplicate_pk_does_not_move_position() {
        let mut acc = NfLogAccumulator::new(0);
        assert_eq!(
            acc.fold(pos(100), pk(1), r(1)).expect("fold"),
            FoldOutcome::Appended(0)
        );
        assert_eq!(
            acc.fold(pos(101), pk(1), r(1)).expect("fold"),
            FoldOutcome::DuplicateIgnored
        );
        match acc.lookup(pk(1)) {
            LookupResult::Present { pos, r: got_r, .. } => {
                assert_eq!(pos, 0);
                assert_eq!(got_r, r(1));
            }
            LookupResult::Absent => panic!("expected present"),
        }
        assert_eq!(acc.nav().size, 1);
    }

    #[test]
    fn first_occurrence_fork_loser_has_no_canonical_position() {
        let mut acc = NfLogAccumulator::new(0);
        assert_eq!(
            acc.fold(pos(100), pk(1), r(10)).expect("fold"),
            FoldOutcome::Appended(0)
        );
        assert_eq!(
            acc.fold(pos(101), pk(1), r(20)).expect("fold"),
            FoldOutcome::DuplicateIgnored
        );
        match acc.lookup(pk(1)) {
            LookupResult::Present { pos, r: got_r, .. } => {
                assert_eq!(pos, 0);
                assert_eq!(got_r, r(10));
            }
            LookupResult::Absent => panic!("expected present"),
        }
        assert_eq!(
            acc.classify(pk(1), r(20)),
            SpendClassification::RejectedDoubleSpend
        );
        assert_eq!(
            acc.classify(pk(1), r(10)),
            SpendClassification::ValidFirstSpend
        );
    }

    #[test]
    fn path_a_equals_path_b() {
        let mut acc = NfLogAccumulator::new(0);
        let pairs = [(pk(1), r(1)), (pk(2), r(2)), (pk(3), r(3)), (pk(4), r(4))];
        for (i, &(p, rr)) in pairs.iter().enumerate() {
            assert_eq!(
                acc.fold(pos(100 + i as u64), p, rr).expect("fold"),
                FoldOutcome::Appended(i as u64)
            );
        }

        // Independent Path-B rebuild
        let independent: Vec<NfLogEntry> = pairs
            .iter()
            .map(|&(p, rr)| NfLogEntry { pk: p, r: rr })
            .collect();
        let independent_mth = nflog_mth(&independent);
        let size = independent.len() as u64;

        let target_pk = pk(3);
        match acc.lookup(target_pk) {
            LookupResult::Present {
                pos,
                r: got_r,
                inclusion_proof,
            } => {
                assert_eq!(pos, 2);
                assert_eq!(got_r, r(3));
                let entry = NfLogEntry {
                    pk: target_pk,
                    r: got_r,
                };
                let leaf = nflog_leaf_hash(pos, &entry);
                assert!(verify_inclusion(
                    leaf,
                    pos,
                    &inclusion_proof,
                    size,
                    independent_mth
                ));
            }
            LookupResult::Absent => panic!("expected present"),
        }
    }

    #[test]
    fn reorg_replay_reassigns_positions_canonically() {
        let mut acc = NfLogAccumulator::new(0);
        let a = published(100, 1, 1);
        let b = published(101, 2, 2);
        let c = published(102, 3, 3);
        let d = published(103, 4, 4);
        for e in [a, b, c, d] {
            acc.fold(e.chain_pos, e.pk, e.r).expect("fold");
        }
        assert_eq!(acc.nav().size, 4);

        let e = published(102, 5, 5);
        let f = published(103, 6, 6);
        // old_tip_height=103 → max_final=98 → no entries final yet, so this
        // reorg (position reassignment of non-final positions) is benign.
        let outcome = acc
            .reorg_replay(103, vec![a, b, e, f])
            .expect("reorg_replay");
        assert!(!outcome.finality_broken);

        assert_eq!(acc.nav().size, 4);
        let independent = vec![
            NfLogEntry { pk: a.pk, r: a.r },
            NfLogEntry { pk: b.pk, r: b.r },
            NfLogEntry { pk: e.pk, r: e.r },
            NfLogEntry { pk: f.pk, r: f.r },
        ];
        assert_eq!(acc.nav().mth, nflog_mth(&independent));

        match acc.lookup(e.pk) {
            LookupResult::Present { pos, .. } => assert_eq!(pos, 2),
            LookupResult::Absent => panic!("E should be present"),
        }
        match acc.lookup(f.pk) {
            LookupResult::Present { pos, .. } => assert_eq!(pos, 3),
            LookupResult::Absent => panic!("F should be present"),
        }
        assert_eq!(acc.lookup(c.pk), LookupResult::Absent);
        assert_eq!(acc.lookup(d.pk), LookupResult::Absent);
    }

    #[test]
    fn activation_height_rejects_below_origin() {
        let mut acc = NfLogAccumulator::new(50);
        assert_eq!(
            acc.fold(pos(10), pk(1), r(1)).expect("fold"),
            FoldOutcome::BelowActivationHeight
        );
        assert_eq!(acc.nav().size, 0);
        assert_eq!(
            acc.fold(pos(50), pk(1), r(1)).expect("fold"),
            FoldOutcome::Appended(0)
        );
        assert_eq!(acc.nav().size, 1);
    }

    #[test]
    fn size_final_confirmation_boundary() {
        let mut acc = NfLogAccumulator::new(0);
        // heights 10, 11, 12, 20
        assert_eq!(
            acc.fold(pos(10), pk(1), r(1)).expect("fold"),
            FoldOutcome::Appended(0)
        );
        assert_eq!(
            acc.fold(pos(11), pk(2), r(2)).expect("fold"),
            FoldOutcome::Appended(1)
        );
        assert_eq!(
            acc.fold(pos(12), pk(3), r(3)).expect("fold"),
            FoldOutcome::Appended(2)
        );
        assert_eq!(
            acc.fold(pos(20), pk(4), r(4)).expect("fold"),
            FoldOutcome::Appended(3)
        );

        // tip_height < FINALITY_CONFIRMATIONS - 1 (= 5) → 0
        assert_eq!(acc.size_final(0), 0);
        assert_eq!(acc.size_final(4), 0);

        // tip=15 → max_final = 15 - 5 = 10 → only height 10 confirmed → size 1
        assert_eq!(acc.size_final(15), 1);
        // tip=16 → max_final = 11 → heights 10,11 → size 2
        assert_eq!(acc.size_final(16), 2);
        // tip=17 → max_final = 12 → heights 10,11,12 → size 3
        assert_eq!(acc.size_final(17), 3);
        // tip=25 → max_final = 20 → all four
        assert_eq!(acc.size_final(25), 4);
    }

    #[test]
    fn is_canonical_matches_prefix_mth() {
        let mut acc = NfLogAccumulator::new(0);
        for i in 0..4u8 {
            acc.fold(pos(100 + i as u64), pk(i + 1), r(i + 1))
                .expect("fold");
        }
        let full = acc.nav();
        assert!(acc.is_canonical(full.size, full.mth));
        let prefix_mth = nflog_mth(&[
            NfLogEntry { pk: pk(1), r: r(1) },
            NfLogEntry { pk: pk(2), r: r(2) },
        ]);
        assert!(acc.is_canonical(2, prefix_mth));
        assert!(!acc.is_canonical(2, full.mth));
        assert!(!acc.is_canonical(5, full.mth));
    }

    // --- MAJOR 1: fold ordering ---

    #[test]
    fn fold_strictly_increasing_chain_positions_succeeds() {
        let mut acc = NfLogAccumulator::new(0);
        // Vary height, then tx_index, then vin_index, then member_index.
        let sequence = [
            pos_full(100, 0, 0, 0),
            pos_full(100, 0, 0, 1),
            pos_full(100, 0, 1, 0),
            pos_full(100, 1, 0, 0),
            pos_full(101, 0, 0, 0),
        ];
        for (i, p) in sequence.iter().enumerate() {
            assert_eq!(
                acc.fold(*p, pk(i as u8 + 1), r(i as u8 + 1))
                    .expect("in-order fold"),
                FoldOutcome::Appended(i as u64)
            );
        }
        assert_eq!(acc.nav().size, 5);
    }

    #[test]
    fn fold_rejects_equal_chain_position() {
        let mut acc = NfLogAccumulator::new(0);
        let p = pos_full(100, 1, 2, 3);
        acc.fold(p, pk(1), r(1)).expect("first fold");
        let err = acc.fold(p, pk(2), r(2)).expect_err("equal pos");
        assert_eq!(
            err,
            SpecError::OutOfOrderFold {
                previous: p,
                attempted: p,
            }
        );
    }

    #[test]
    fn fold_rejects_out_of_order_tx_vin_member() {
        let mut acc = NfLogAccumulator::new(0);
        let first = pos_full(100, 5, 5, 5);
        acc.fold(first, pk(1), r(1)).expect("first fold");

        // Same height, lower tx_index
        let lower_tx = pos_full(100, 4, 0, 0);
        let err = acc.fold(lower_tx, pk(2), r(2)).expect_err("lower tx");
        assert_eq!(
            err,
            SpecError::OutOfOrderFold {
                previous: first,
                attempted: lower_tx,
            }
        );

        // Same height/tx, lower vin_index
        let lower_vin = pos_full(100, 5, 4, 0);
        let err = acc.fold(lower_vin, pk(3), r(3)).expect_err("lower vin");
        assert_eq!(
            err,
            SpecError::OutOfOrderFold {
                previous: first,
                attempted: lower_vin,
            }
        );

        // Same height/tx/vin, lower member_index
        let lower_member = pos_full(100, 5, 5, 4);
        let err = acc
            .fold(lower_member, pk(4), r(4))
            .expect_err("lower member");
        assert_eq!(
            err,
            SpecError::OutOfOrderFold {
                previous: first,
                attempted: lower_member,
            }
        );

        // Same height/tx/vin, equal member_index (already covered by equal test,
        // but assert again in this multi-axis suite)
        let equal_member = pos_full(100, 5, 5, 5);
        let err = acc
            .fold(equal_member, pk(5), r(5))
            .expect_err("equal member");
        assert_eq!(
            err,
            SpecError::OutOfOrderFold {
                previous: first,
                attempted: equal_member,
            }
        );

        // Strictly greater still works after rejected attempts
        assert_eq!(
            acc.fold(pos_full(100, 5, 5, 6), pk(6), r(6))
                .expect("greater member"),
            FoldOutcome::Appended(1)
        );
    }

    #[test]
    fn fold_below_activation_does_not_corrupt_ordering() {
        let mut acc = NfLogAccumulator::new(50);
        // Below-activation probe — must not set last_position.
        assert_eq!(
            acc.fold(pos(10), pk(1), r(1)).expect("below"),
            FoldOutcome::BelowActivationHeight
        );
        // First real fold at activation succeeds (no ordering conflict).
        assert_eq!(
            acc.fold(pos(50), pk(2), r(2)).expect("at activation"),
            FoldOutcome::Appended(0)
        );
        // Another below-activation probe after a real fold still ignored.
        assert_eq!(
            acc.fold(pos(40), pk(3), r(3)).expect("below again"),
            FoldOutcome::BelowActivationHeight
        );
        // Subsequent in-order fold still works.
        assert_eq!(
            acc.fold(pos(51), pk(4), r(4)).expect("after probe"),
            FoldOutcome::Appended(1)
        );
    }

    // --- MAJOR 2: reorg finality signal ---

    #[test]
    fn reorg_replay_benign_non_final_displacement() {
        let mut acc = NfLogAccumulator::new(0);
        // Heights 100-103; with old_tip=103, max_final=98 → size_final=0.
        let a = published(100, 1, 1);
        let b = published(101, 2, 2);
        let c = published(102, 3, 3);
        for e in [a, b, c] {
            acc.fold(e.chain_pos, e.pk, e.r).expect("fold");
        }
        assert_eq!(acc.size_final(103), 0);

        let e = published(102, 5, 5);
        let outcome = acc.reorg_replay(103, vec![a, b, e]).expect("reorg_replay");
        assert!(!outcome.finality_broken);
        assert_eq!(outcome.displaced_final_count, 0);
        assert_eq!(acc.lookup(c.pk), LookupResult::Absent);
        match acc.lookup(e.pk) {
            LookupResult::Present { pos, .. } => assert_eq!(pos, 2),
            LookupResult::Absent => panic!("E should be present"),
        }
    }

    #[test]
    fn reorg_replay_detects_finality_breaking_displacement() {
        let mut acc = NfLogAccumulator::new(0);
        // Fold entries deep enough that at tip=20, height-10 is final
        // (max_final = 20 - 5 = 15).
        let a = published(10, 1, 1);
        let b = published(11, 2, 2);
        let c = published(20, 3, 3);
        for e in [a, b, c] {
            acc.fold(e.chain_pos, e.pk, e.r).expect("fold");
        }
        let old_tip = 20u64;
        assert_eq!(acc.size_final(old_tip), 2); // heights 10, 11 final

        // Displace the final position 0: replace A with a different pk/r
        // while keeping a height-10 entry so the log length doesn't hide it.
        let a_prime = published(10, 9, 9);
        let b2 = published(11, 2, 2);
        let c2 = published(20, 3, 3);
        let outcome = acc
            .reorg_replay(old_tip, vec![a_prime, b2, c2])
            .expect("reorg_replay");
        assert!(outcome.finality_broken);
        assert!(outcome.displaced_final_count >= 1);
    }

    // --- MAJOR 3: size_final low-tip edge ---

    #[test]
    fn size_final_low_tip_no_panic_returns_zero() {
        let mut acc = NfLogAccumulator::new(0);
        // Entries at very low heights — still size_final==0 for tip < 5.
        acc.fold(pos(0), pk(1), r(1)).expect("fold");
        acc.fold(pos(1), pk(2), r(2)).expect("fold");
        acc.fold(pos(3), pk(3), r(3)).expect("fold");

        // Exercises checked_sub path: tip 0,1,4 all yield 0 without panic/wrap.
        assert_eq!(acc.size_final(0), 0);
        assert_eq!(acc.size_final(1), 0);
        assert_eq!(acc.size_final(4), 0);
        // tip=5 → max_final=0 → height 0 is final → size 1
        assert_eq!(acc.size_final(5), 1);
    }

    // --- MINOR 6: adversarial reorg edges ---

    #[test]
    fn reorg_promotes_surviving_duplicate_pk_after_orphan() {
        // (a) Winning Pk occurrence orphaned; same Pk survives in a later block.
        let mut acc = NfLogAccumulator::new(0);
        let win = published(100, 1, 10); // winner pre-reorg
        let other = published(101, 2, 2);
        let later_same_pk = published(102, 1, 20); // same pk, different r — ignored pre-reorg
        for e in [win, other, later_same_pk] {
            acc.fold(e.chain_pos, e.pk, e.r).expect("fold");
        }
        match acc.lookup(pk(1)) {
            LookupResult::Present { pos, r: got_r, .. } => {
                assert_eq!(pos, 0);
                assert_eq!(got_r, r(10));
            }
            LookupResult::Absent => panic!("expected present"),
        }

        // Orphan block 100; keep 101 and the later same-Pk occurrence.
        let outcome = acc
            .reorg_replay(102, vec![other, later_same_pk])
            .expect("reorg_replay");
        // tip=102 → max_final=97 → nothing was final.
        assert!(!outcome.finality_broken);

        match acc.lookup(pk(1)) {
            LookupResult::Present { pos, r: got_r, .. } => {
                assert_eq!(pos, 1); // after `other` at pos 0
                assert_eq!(got_r, r(20));
            }
            LookupResult::Absent => panic!("surviving Pk should be promoted"),
        }
        assert_eq!(
            acc.classify(pk(1), r(20)),
            SpendClassification::ValidFirstSpend
        );
        assert_eq!(
            acc.classify(pk(1), r(10)),
            SpendClassification::RejectedDoubleSpend
        );
    }

    #[test]
    fn reorg_promotes_previous_loser_as_new_winner() {
        // (b) Different occurrence of same Pk becomes first under new order.
        let mut acc = NfLogAccumulator::new(0);
        let first = published(100, 1, 10); // winner with r=10
        let loser = published(101, 1, 20); // same pk, r=20 — ignored
        let unrelated = published(102, 2, 2);
        for e in [first, loser, unrelated] {
            acc.fold(e.chain_pos, e.pk, e.r).expect("fold");
        }
        assert_eq!(
            acc.classify(pk(1), r(10)),
            SpendClassification::ValidFirstSpend
        );
        assert_eq!(
            acc.classify(pk(1), r(20)),
            SpendClassification::RejectedDoubleSpend
        );

        // Orphan the original winner's block; the previous loser becomes first.
        // Also include a new earlier occurrence with different r to make the
        // new winner identity explicit: after reorg only loser+unrelated remain,
        // so r=20 at height 101 is the new winner at position 0.
        let outcome = acc
            .reorg_replay(102, vec![loser, unrelated])
            .expect("reorg_replay");
        assert!(!outcome.finality_broken);

        match acc.lookup(pk(1)) {
            LookupResult::Present { pos, r: got_r, .. } => {
                assert_eq!(pos, 0);
                assert_eq!(got_r, r(20));
            }
            LookupResult::Absent => panic!("new winner must be present"),
        }
        assert_eq!(
            acc.classify(pk(1), r(20)),
            SpendClassification::ValidFirstSpend
        );
        assert_eq!(
            acc.classify(pk(1), r(10)),
            SpendClassification::RejectedDoubleSpend
        );

        let expected = vec![
            NfLogEntry {
                pk: pk(1),
                r: r(20),
            },
            NfLogEntry { pk: pk(2), r: r(2) },
        ];
        assert_eq!(acc.nav().mth, nflog_mth(&expected));
        assert_eq!(acc.nav().size, 2);
    }

    // --- Incremental MTH equivalence (the point of the O(log n) change) ---

    /// Distinct deterministic `pk` for bulk folds (duplicates are ignored by
    /// first-occurrence, so all-identical keys would only exercise size 1).
    fn pk_u64(i: u64) -> [u8; 32] {
        let mut p = [0u8; 32];
        p[..8].copy_from_slice(&i.to_be_bytes());
        p
    }

    fn r_u64(i: u64) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[24..].copy_from_slice(&i.to_be_bytes());
        v
    }

    fn entry_at(i: u64) -> NfLogEntry {
        NfLogEntry {
            pk: pk_u64(i),
            r: r_u64(i.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        }
    }

    /// For every size `n` in `0..=max_n`, fold `n` distinct entries and assert
    /// the accumulator tip MTH equals the normative `nflog_mth` oracle.
    #[test]
    fn incremental_mth_matches_nflog_mth_for_every_size_0_to_300() {
        const MAX_N: usize = 300;
        let mut acc = NfLogAccumulator::new(0);
        let mut entries: Vec<NfLogEntry> = Vec::with_capacity(MAX_N);

        // n = 0
        assert_eq!(acc.nav().mth, nflog_empty());
        assert_eq!(acc.nav().mth, nflog_mth(&[]));
        assert_eq!(acc.nav().size, 0);

        for n in 1..=MAX_N {
            let i = (n - 1) as u64;
            let e = entry_at(i);
            acc.fold(pos(100 + i), e.pk, e.r).expect("fold");
            entries.push(e);
            let expected = nflog_mth(&entries);
            let nav = acc.nav();
            assert_eq!(nav.size, n as u64, "size mismatch at n={n}");
            assert_eq!(nav.mth, expected, "incremental mth != nflog_mth at n={n}");
            assert!(acc.is_canonical(nav.size, nav.mth));
        }
        eprintln!("equivalence sweep: n=0..={MAX_N} all matched nflog_mth byte-for-byte");
    }

    /// Power-of-two boundaries are where split-point / peak-bagging behaviour
    /// changes — assert equality at `2^k − 1`, `2^k`, `2^k + 1`.
    #[test]
    fn incremental_mth_matches_at_power_of_two_boundaries() {
        // Largest boundary size we materialise: 2^9 + 1 = 513 (well under
        // the 0..=300 sweep's intent but covers extra power-of-two edges).
        const MAX_K: u32 = 9;
        let max_n = (1usize << MAX_K) + 1;
        let mut acc = NfLogAccumulator::new(0);
        let mut entries: Vec<NfLogEntry> = Vec::with_capacity(max_n);

        let mut targets: Vec<usize> = Vec::new();
        for k in 0..=MAX_K {
            let pow = 1usize << k;
            for n in [pow.saturating_sub(1), pow, pow.saturating_add(1)] {
                if n > 0 && !targets.contains(&n) {
                    targets.push(n);
                }
            }
        }
        targets.sort_unstable();

        let mut next_target = 0usize;
        for n in 1..=max_n {
            let i = (n - 1) as u64;
            let e = entry_at(i.wrapping_add(0x1000));
            acc.fold(pos(1000 + i), e.pk, e.r).expect("fold");
            entries.push(e);
            if next_target < targets.len() && n == targets[next_target] {
                let expected = nflog_mth(&entries);
                assert_eq!(
                    acc.nav().mth,
                    expected,
                    "boundary mismatch at n={n} (2^k±1 suite)"
                );
                next_target += 1;
            }
        }
        assert_eq!(next_target, targets.len(), "missed boundary sizes");
        eprintln!("power-of-two boundaries: checked {targets:?} — all matched");
    }

    /// After `reorg_replay`, state equals a fresh sequential fold of the same
    /// canonical stream (nav + mth vs `nflog_mth`).
    #[test]
    fn reorg_replay_incremental_state_matches_fresh_fold() {
        let mut acc = NfLogAccumulator::new(0);
        // Seed with a longer log so reorg actually rebuilds non-trivial peaks.
        for i in 0..40u64 {
            let e = entry_at(i);
            acc.fold(pos(100 + i), e.pk, e.r).expect("fold");
        }

        // Canonical stream after reorg: drop some early winners, insert new
        // ones, keep order by ChainPosition via reorg_replay's sort.
        let mut stream: Vec<PublishedNullifier> = Vec::new();
        for i in 0..35u64 {
            // Shift heights and pks so the peak forest is rebuilt, not merely
            // truncated-and-extended identically.
            let e = entry_at(i.wrapping_add(500));
            stream.push(PublishedNullifier {
                chain_pos: pos(200 + i),
                pk: e.pk,
                r: e.r,
            });
        }
        // tip=234 → max_final=229; heights start at 200 so some may be final,
        // but we only care about state equality here.
        acc.reorg_replay(234, stream.clone()).expect("reorg");

        let mut fresh = NfLogAccumulator::new(0);
        let mut entries: Vec<NfLogEntry> = Vec::new();
        let mut sorted = stream;
        sorted.sort_by_key(|e| e.chain_pos);
        for e in &sorted {
            fresh.fold(e.chain_pos, e.pk, e.r).expect("fresh fold");
            entries.push(NfLogEntry { pk: e.pk, r: e.r });
        }

        assert_eq!(acc.nav(), fresh.nav(), "nav after reorg != fresh fold");
        assert_eq!(acc.nav().mth, nflog_mth(&entries));
        assert_eq!(acc.nav().size, entries.len() as u64);
    }

    /// Inclusion and consistency proofs over the accumulator log still verify
    /// against the incrementally maintained tip MTH.
    #[test]
    fn inclusion_and_consistency_verify_against_incremental_mth() {
        use crate::spec_v1::nflog::{consistency_proof, verify_consistency};

        let mut acc = NfLogAccumulator::new(0);
        let mut entries: Vec<NfLogEntry> = Vec::new();
        const N: usize = 64;
        for i in 0..N as u64 {
            let e = entry_at(i.wrapping_add(0xabc));
            acc.fold(pos(50 + i), e.pk, e.r).expect("fold");
            entries.push(e);
        }
        let tip = acc.nav();
        assert_eq!(tip.mth, nflog_mth(&entries));

        // Inclusion at several positions, including power-of-two edges.
        for &p in &[0u64, 1, 7, 8, 15, 16, 31, 32, 63] {
            match acc.lookup(entries[p as usize].pk) {
                LookupResult::Present {
                    pos,
                    r: got_r,
                    inclusion_proof,
                } => {
                    assert_eq!(pos, p);
                    assert_eq!(got_r, entries[p as usize].r);
                    let leaf = nflog_leaf_hash(
                        pos,
                        &NfLogEntry {
                            pk: entries[p as usize].pk,
                            r: got_r,
                        },
                    );
                    assert!(
                        verify_inclusion(leaf, pos, &inclusion_proof, tip.size, tip.mth),
                        "inclusion failed at p={p}"
                    );
                }
                LookupResult::Absent => panic!("expected present at p={p}"),
            }
        }

        // Consistency for several prefixes against the incremental tip.
        for &m in &[1u64, 2, 3, 4, 7, 8, 15, 16, 32, 48, 63, 64] {
            let mth_a = nflog_mth(&entries[..m as usize]);
            let proof = consistency_proof(m, &entries).expect("m <= n");
            assert!(
                verify_consistency(m, mth_a, tip.size, tip.mth, &proof),
                "consistency failed m={m} n={}",
                tip.size
            );
            // Prefix is also canonical under the accumulator.
            assert!(acc.is_canonical(m, mth_a));
        }
    }

    /// Performance evidence: fold 20_000 distinct entries and report wall time.
    /// Old behaviour was O(N²) full `nflog_mth` recompute (~2·10⁸ leaf-range
    /// hashes at N=20k); new is O(N log N) peak updates.
    #[test]
    fn fold_20000_entries_reports_non_quadratic_wall_time() {
        use std::time::Instant;

        const N: u64 = 20_000;
        let mut acc = NfLogAccumulator::new(0);
        let t0 = Instant::now();
        for i in 0..N {
            let e = entry_at(i);
            acc.fold(pos(i + 1), e.pk, e.r).expect("fold");
        }
        let elapsed = t0.elapsed();
        let nav = acc.nav();
        assert_eq!(nav.size, N);

        // Spot-check equivalence at the tip (full oracle over 20k is fine once).
        let entries: Vec<NfLogEntry> = (0..N).map(entry_at).collect();
        let t_oracle = Instant::now();
        let expected = nflog_mth(&entries);
        let oracle_elapsed = t_oracle.elapsed();
        assert_eq!(nav.mth, expected, "tip mth diverged at N={N}");

        // Rough projection of old O(N²) cost: each append recomputed MTH over
        // the whole log. A single full MTH at size N took `oracle_elapsed`;
        // summing sizes 1..N is ~N/2 times that work → project N/2 * oracle.
        let projected_old_ms = oracle_elapsed.as_secs_f64() * 1000.0 * (N as f64 / 2.0);
        eprintln!(
            "perf N={N}: incremental fold wall={elapsed:?}; \
             one-shot nflog_mth wall={oracle_elapsed:?}; \
             projected old O(N²) full-recompute ≈ {projected_old_ms:.0} ms \
             (≈ N/2 × one-shot MTH)"
        );
        // Sanity: incremental fold of N entries should finish well under a
        // minute on any reasonable host (guards against accidental O(N²)).
        assert!(
            elapsed.as_secs() < 60,
            "fold of {N} took {elapsed:?} — still looks quadratic?"
        );
    }

    // --- §3.9 reorg finality depth suite (depths 1..=7 + edge cases) ---

    /// Build a dense chain: one nullifier per height `0..=old_tip` with
    /// `pk(h)/r(h)`. Position index equals height under this construction.
    fn fold_dense_chain_0_to(acc: &mut NfLogAccumulator, old_tip: u64) {
        for h in 0..=old_tip {
            acc.fold(pos(h), pk(h as u8), r(h as u8))
                .expect("fold dense chain");
        }
    }

    /// Canonical stream for a content-changing reorg of depth `d` at tip
    /// `old_tip`: heights `0..=old_tip-d` keep original `pk(h)/r(h)`; heights
    /// `old_tip-d+1..=old_tip` get offset-100 replacements.
    fn canonical_stream_reorg_depth(old_tip: u64, d: u64) -> Vec<PublishedNullifier> {
        assert!(d >= 1 && d <= old_tip);
        let mut stream = Vec::with_capacity((old_tip + 1) as usize);
        for h in 0..=(old_tip - d) {
            stream.push(published(h, h as u8, h as u8));
        }
        for h in (old_tip - d + 1)..=old_tip {
            stream.push(published(h, 100 + h as u8, 100 + h as u8));
        }
        stream
    }

    /// Shared body for the seven depth-finality tests.
    fn assert_reorg_depth_finality(d: u64, expect_broken: bool, expect_displaced: u64) {
        const OLD_TIP: u64 = 20;
        let mut acc = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc, OLD_TIP);

        let old_final = acc.size_final(OLD_TIP);
        assert_eq!(
            old_final, 16,
            "depth {d}: size_final({OLD_TIP}) must be 16 (heights 0..=15 final)"
        );

        let stream = canonical_stream_reorg_depth(OLD_TIP, d);
        let outcome = acc
            .reorg_replay(OLD_TIP, stream)
            .unwrap_or_else(|e| panic!("depth {d}: reorg_replay must succeed: {e:?}"));

        assert_eq!(
            outcome.finality_broken, expect_broken,
            "depth {d}: finality_broken expected {expect_broken}, got {}",
            outcome.finality_broken
        );
        assert_eq!(
            outcome.displaced_final_count, expect_displaced,
            "depth {d}: expected displaced_final_count={expect_displaced}, got {}",
            outcome.displaced_final_count
        );

        // Position 0 is never in the replaced range for d <= 7.
        assert_eq!(
            acc.log[0].pk,
            pk(0),
            "depth {d}: final position 0 pk must remain pk(0)"
        );
        assert_eq!(
            acc.log[0].r,
            r(0),
            "depth {d}: final position 0 r must remain r(0)"
        );

        // Position 15 (height 15) stays untouched only when the reorg starts
        // at height > 15, i.e. d <= 5 (first replaced = OLD_TIP-d+1 >= 16).
        if d <= 5 {
            assert_eq!(
                acc.log[15].pk,
                pk(15),
                "depth {d}: final position 15 pk must remain pk(15) (not replaced)"
            );
            assert_eq!(
                acc.log[15].r,
                r(15),
                "depth {d}: final position 15 r must remain r(15) (not replaced)"
            );
        }
    }

    #[test]
    fn reorg_depth_1_finality() {
        // Replaced heights 20..=20 — all > 15 → no final displacement.
        assert_reorg_depth_finality(1, false, 0);
    }

    #[test]
    fn reorg_depth_2_finality() {
        // Replaced heights 19..=20 — all > 15 → no final displacement.
        assert_reorg_depth_finality(2, false, 0);
    }

    #[test]
    fn reorg_depth_3_finality() {
        // Replaced heights 18..=20 — all > 15 → no final displacement.
        assert_reorg_depth_finality(3, false, 0);
    }

    #[test]
    fn reorg_depth_4_finality() {
        // Replaced heights 17..=20 — all > 15 → no final displacement.
        assert_reorg_depth_finality(4, false, 0);
    }

    #[test]
    fn reorg_depth_5_finality() {
        // Replaced heights 16..=20 — all > 15 → no final displacement.
        assert_reorg_depth_finality(5, false, 0);
    }

    #[test]
    fn reorg_depth_6_finality() {
        // Replaced heights 15..=20 → final position 15 displaced → count 1.
        assert_reorg_depth_finality(6, true, 1);
    }

    #[test]
    fn reorg_depth_7_finality() {
        // Replaced heights 14..=20 → final positions 14 and 15 displaced → count 2.
        assert_reorg_depth_finality(7, true, 2);
    }

    #[test]
    fn reorg_depth_6_content_preserving_not_broken() {
        // Same depth-6 height range (15..=20) but identical (pk,r) content —
        // displacement is content-based, not depth-based.
        const OLD_TIP: u64 = 20;
        let mut acc = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc, OLD_TIP);
        assert_eq!(acc.size_final(OLD_TIP), 16);

        // "New" stream is byte-identical to the original chain.
        let stream: Vec<PublishedNullifier> = (0..=OLD_TIP)
            .map(|h| published(h, h as u8, h as u8))
            .collect();
        let outcome = acc
            .reorg_replay(OLD_TIP, stream)
            .expect("content-preserving depth-6 reorg_replay");

        assert!(
            !outcome.finality_broken,
            "depth 6 content-preserving: finality_broken must be false"
        );
        assert_eq!(
            outcome.displaced_final_count, 0,
            "depth 6 content-preserving: displaced_final_count must be 0, got {}",
            outcome.displaced_final_count
        );
        assert_eq!(acc.log[0].pk, pk(0));
        assert_eq!(acc.log[15].pk, pk(15));
        assert_eq!(acc.log[15].r, r(15));
    }

    #[test]
    fn reorg_depth_7_shrinks_final_position_missing() {
        // Depth-7 style shrink: drop heights 14..=20 entirely so former final
        // positions 14 and 15 no longer exist after replay (None, not mismatch).
        const OLD_TIP: u64 = 20;
        let mut acc = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc, OLD_TIP);
        let old_final = acc.size_final(OLD_TIP);
        assert_eq!(old_final, 16, "precondition: 16 final positions");

        // Keep only heights 0..=13 (OLD_TIP - 7); omit the depth-7 range.
        let stream: Vec<PublishedNullifier> = (0..=(OLD_TIP - 7))
            .map(|h| published(h, h as u8, h as u8))
            .collect();
        let outcome = acc
            .reorg_replay(OLD_TIP, stream)
            .expect("shrinking depth-7 reorg_replay");

        assert!(
            outcome.finality_broken,
            "depth 7 shrink: finality_broken must be true when final positions vanish"
        );
        assert!(
            outcome.displaced_final_count >= 1,
            "depth 7 shrink: displaced_final_count >= 1, got {}",
            outcome.displaced_final_count
        );
        assert_eq!(
            outcome.displaced_final_count, 2,
            "depth 7 shrink: positions 14 and 15 missing → displaced=2, got {}",
            outcome.displaced_final_count
        );
        // Explicit "missing" evidence (not pk/r mismatch at an existing slot).
        assert!(
            acc.log.len() < 16,
            "depth 7 shrink: log must be shorter than old_final=16, len={}",
            acc.log.len()
        );
        assert!(
            acc.log.get(15).is_none(),
            "depth 7 shrink: log.get(15) must be None (position missing)"
        );
        assert!(
            acc.log.get(14).is_none(),
            "depth 7 shrink: log.get(14) must be None (position missing)"
        );
        // Surviving finals still match the snapshot.
        assert_eq!(acc.log[0].pk, pk(0));
        assert_eq!(acc.log[13].pk, pk(13));
    }

    #[test]
    fn size_final_boundaries() {
        // --- empty log: every tip yields 0 ---
        let empty = NfLogAccumulator::new(0);
        assert_eq!(empty.size_final(0), 0, "empty: tip=0 → 0");
        assert_eq!(empty.size_final(1), 0, "empty: tip=1 → 0");
        assert_eq!(empty.size_final(4), 0, "empty: tip=4 → 0");
        assert_eq!(empty.size_final(5), 0, "empty: tip=5 → 0 (no entries)");
        assert_eq!(empty.size_final(100), 0, "empty: tip=100 → 0");

        // --- dense low heights ---
        let mut low = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut low, 3); // heights 0,1,2,3
        assert_eq!(low.size_final(0), 0, "dense low: tip=0 → 0 (checked_sub)");
        assert_eq!(low.size_final(1), 0, "dense low: tip=1 → 0");
        assert_eq!(low.size_final(4), 0, "dense low: tip=4 → 0");
        // tip=5 → max_final=0 → only height 0
        assert_eq!(low.size_final(5), 1, "dense low: tip=5 → 1 (height 0 only)");
        // tip=8 → max_final=3 → all four entries final
        assert_eq!(low.size_final(8), 4, "dense low: tip=8 → all 4 final");

        // --- gapped heights (not every height has an entry) ---
        // Fold heights 0, 1, 10, 11, 12, 20 — distinct from the existing
        // size_final_confirmation_boundary suite (which uses 10,11,12,20 only).
        let mut gapped = NfLogAccumulator::new(0);
        for (h, b) in [(0u64, 1u8), (1, 2), (10, 3), (11, 4), (12, 5), (20, 6)] {
            gapped
                .fold(pos(h), pk(b), r(b))
                .expect("fold gapped chain");
        }
        assert_eq!(gapped.nav().size, 6);

        assert_eq!(gapped.size_final(0), 0, "gapped: tip=0 → 0");
        assert_eq!(gapped.size_final(4), 0, "gapped: tip=4 → 0");
        // tip=5 → max_final=0 → height 0 → 1
        assert_eq!(gapped.size_final(5), 1, "gapped: tip=5 → 1 (height 0)");
        // tip=6 → max_final=1 → heights 0,1 → 2
        assert_eq!(gapped.size_final(6), 2, "gapped: tip=6 → 2 (heights 0,1)");
        // tip=14 → max_final=9 → still only 0,1 (next is 10) → 2
        assert_eq!(
            gapped.size_final(14),
            2,
            "gapped: tip=14 → 2 (gap before height 10; max_final=9)"
        );
        // tip=15 → max_final=10 → heights 0,1,10 → 3
        assert_eq!(gapped.size_final(15), 3, "gapped: tip=15 → 3");
        // tip=16 → max_final=11 → +height 11 → 4
        assert_eq!(gapped.size_final(16), 4, "gapped: tip=16 → 4");
        // tip=17 → max_final=12 → +height 12 → 5
        assert_eq!(gapped.size_final(17), 5, "gapped: tip=17 → 5");
        // tip=24 → max_final=19 → still 5 (height 20 not yet final)
        assert_eq!(
            gapped.size_final(24),
            5,
            "gapped: tip=24 → 5 (height 20 not final; max_final=19)"
        );
        // tip=25 → max_final=20 → all six
        assert_eq!(gapped.size_final(25), 6, "gapped: tip=25 → all 6 final");
    }

    #[test]
    fn reorg_replay_empty_stream() {
        const OLD_TIP: u64 = 20;
        let mut acc = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc, OLD_TIP);
        let old_final = acc.size_final(OLD_TIP);
        // old_final = 16 (heights 0..=15); empty replay displaces every one.
        assert_eq!(old_final, 16, "empty-stream: pre-reorg old_final must be 16");

        let outcome = acc
            .reorg_replay(OLD_TIP, vec![])
            .expect("empty-stream reorg_replay");

        assert!(
            outcome.finality_broken,
            "empty-stream: finality_broken must be true"
        );
        assert_eq!(
            outcome.displaced_final_count, old_final,
            "empty-stream: displaced_final_count must equal old_final={old_final}, got {}",
            outcome.displaced_final_count
        );
        assert_eq!(acc.nav().size, 0, "empty-stream: log must be fully cleared");
        assert!(acc.log.get(0).is_none());
    }

    #[test]
    fn reorg_replay_identical_stream_no_break() {
        const OLD_TIP: u64 = 20;
        let mut acc = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc, OLD_TIP);
        assert_eq!(acc.size_final(OLD_TIP), 16);

        let stream: Vec<PublishedNullifier> = (0..=OLD_TIP)
            .map(|h| published(h, h as u8, h as u8))
            .collect();
        let outcome = acc
            .reorg_replay(OLD_TIP, stream)
            .expect("identical-stream reorg_replay");

        assert!(
            !outcome.finality_broken,
            "identical-stream: finality_broken must be false"
        );
        assert_eq!(
            outcome.displaced_final_count, 0,
            "identical-stream: displaced_final_count must be 0, got {}",
            outcome.displaced_final_count
        );
        assert_eq!(acc.nav().size, 21, "identical-stream: full chain restored");
        assert_eq!(acc.log[0].pk, pk(0));
        assert_eq!(acc.log[15].pk, pk(15));
        assert_eq!(acc.log[20].pk, pk(20));
    }

    #[test]
    fn reorg_replay_reorders_only_nonfinal() {
        // Content-swap only non-final heights (16..=20); finals 0..=15 intact.
        const OLD_TIP: u64 = 20;
        let mut acc = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc, OLD_TIP);
        let old_final = acc.size_final(OLD_TIP);
        assert_eq!(old_final, 16);

        let mut stream: Vec<PublishedNullifier> = Vec::new();
        for h in 0..=15u64 {
            stream.push(published(h, h as u8, h as u8));
        }
        for h in 16..=OLD_TIP {
            // Distinct replacement content at non-final heights only.
            stream.push(published(h, 100 + h as u8, 100 + h as u8));
        }

        let outcome = acc
            .reorg_replay(OLD_TIP, stream)
            .expect("nonfinal-only reorg_replay");

        assert!(
            !outcome.finality_broken,
            "nonfinal-only: finality_broken must be false"
        );
        assert_eq!(
            outcome.displaced_final_count, 0,
            "nonfinal-only: displaced_final_count must be 0, got {}",
            outcome.displaced_final_count
        );
        // Finals unchanged; non-finals carry the new bytes.
        assert_eq!(acc.log[0].pk, pk(0));
        assert_eq!(acc.log[15].pk, pk(15));
        assert_eq!(acc.log[15].r, r(15));
        assert_eq!(
            acc.log[16].pk,
            pk(116),
            "nonfinal-only: height 16 must carry replacement pk"
        );
        assert_eq!(acc.log[20].pk, pk(120));
    }

    #[test]
    fn reorg_replay_out_of_order_stream_still_sorts() {
        // Depth-1 reorg stream delivered sorted vs. a fixed permutation — both
        // must yield identical ReorgOutcome and final log (internal sort).
        const OLD_TIP: u64 = 20;
        let d = 1u64;

        let mut acc_sorted = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc_sorted, OLD_TIP);
        let mut acc_shuffled = NfLogAccumulator::new(0);
        fold_dense_chain_0_to(&mut acc_shuffled, OLD_TIP);

        let sorted_stream = canonical_stream_reorg_depth(OLD_TIP, d);
        // Deterministic permutation: reverse, then swap a few fixed indices.
        let mut shuffled_stream = sorted_stream.clone();
        shuffled_stream.reverse();
        if shuffled_stream.len() >= 4 {
            let n = shuffled_stream.len();
            shuffled_stream.swap(0, 3);
            shuffled_stream.swap(1, n - 1);
            shuffled_stream.swap(2, 5.min(n - 1));
        }
        // Sanity: permutation is not already sorted by chain_pos.
        let mut probe = shuffled_stream.clone();
        probe.sort_by_key(|e| e.chain_pos);
        assert_ne!(
            shuffled_stream
                .iter()
                .map(|e| e.chain_pos)
                .collect::<Vec<_>>(),
            probe.iter().map(|e| e.chain_pos).collect::<Vec<_>>(),
            "out-of-order test: shuffled stream must differ from sorted order"
        );

        let outcome_sorted = acc_sorted
            .reorg_replay(OLD_TIP, sorted_stream)
            .expect("sorted reorg_replay");
        let outcome_shuffled = acc_shuffled
            .reorg_replay(OLD_TIP, shuffled_stream)
            .expect("shuffled reorg_replay");

        assert_eq!(
            outcome_sorted, outcome_shuffled,
            "out-of-order: ReorgOutcome must match sorted vs shuffled stream"
        );
        assert_eq!(
            acc_sorted.log, acc_shuffled.log,
            "out-of-order: final log must match sorted vs shuffled stream"
        );
        assert_eq!(
            acc_sorted.heights, acc_shuffled.heights,
            "out-of-order: heights must match sorted vs shuffled stream"
        );
        assert_eq!(
            acc_sorted.nav(),
            acc_shuffled.nav(),
            "out-of-order: nav must match sorted vs shuffled stream"
        );
        // Depth-1: no final displacement.
        assert!(!outcome_sorted.finality_broken);
        assert_eq!(outcome_sorted.displaced_final_count, 0);
    }

    #[test]
    fn reorg_replay_propagates_fold_error() {
        // Non-empty pre-state so the clear+refold path is exercised; then a
        // stream with two identical chain_pos values triggers OutOfOrderFold.
        let mut acc = NfLogAccumulator::new(0);
        for h in 0..=5u64 {
            acc.fold(pos(h), pk(h as u8), r(h as u8))
                .expect("pre-state fold");
        }
        assert!(acc.nav().size > 0);

        let dup_pos = pos(50);
        let stream = vec![
            published(10, 10, 10),
            PublishedNullifier {
                chain_pos: dup_pos,
                pk: pk(50),
                r: r(50),
            },
            PublishedNullifier {
                chain_pos: dup_pos, // identical chain_pos → fold rejects second
                pk: pk(51),
                r: r(51),
            },
            published(60, 60, 60),
        ];

        let err = acc
            .reorg_replay(5, stream)
            .expect_err("duplicate chain_pos must propagate fold error");

        assert_eq!(
            err,
            SpecError::OutOfOrderFold {
                previous: dup_pos,
                attempted: dup_pos,
            },
            "propagates_fold_error: expected OutOfOrderFold at pos(50), got {err:?}"
        );
    }
}

