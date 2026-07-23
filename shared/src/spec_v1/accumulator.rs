//! Stateful in-memory Path-A nullifier accumulator (§3.6 / §3.7 / §3.9).

use std::collections::HashMap;

use super::error::SpecError;
use super::nflog::{inclusion_path, nflog_empty, nflog_mth, Nav, NfLogEntry};
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
            last_position: None,
        }
    }

    /// Fold one published nullifier by first-occurrence (section 3.6 step 5).
    ///
    /// Enforces strictly-increasing `ChainPosition` order for every call that
    /// is not filtered by activation height. Recomputes `mth` from scratch on
    /// every successful append — O(size) per call. Acceptable for this
    /// in-memory chunk's scope; bulk fixtures should use the pure `nflog_mth`
    /// / `inclusion_path` / `consistency_proof` functions on a materialised
    /// `Vec<NfLogEntry>` instead.
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
        self.log.push(NfLogEntry { pk, r });
        self.heights.push(chain_pos.height);
        self.index.insert(pk, (pos, r));
        self.mth = nflog_mth(&self.log);
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

    fn published_at(chain_pos: ChainPosition, pk_b: u8, r_b: u8) -> PublishedNullifier {
        PublishedNullifier {
            chain_pos,
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
            NfLogEntry {
                pk: pk(1),
                r: r(1),
            },
            NfLogEntry {
                pk: pk(2),
                r: r(2),
            },
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
        let outcome = acc
            .reorg_replay(103, vec![a, b, e])
            .expect("reorg_replay");
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
            NfLogEntry {
                pk: pk(2),
                r: r(2),
            },
        ];
        assert_eq!(acc.nav().mth, nflog_mth(&expected));
        assert_eq!(acc.nav().size, 2);
    }
}
