//! Stateful in-memory Path-A nullifier accumulator (§3.6 / §3.7 / §3.9).

use std::collections::HashMap;

use super::nflog::{inclusion_path, nflog_empty, nflog_mth, Nav, NfLogEntry};
use zkcoins_program::hash::HashDigest;

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
}

impl NfLogAccumulator {
    pub fn new(activation_height: u64) -> Self {
        Self {
            activation_height,
            log: Vec::new(),
            heights: Vec::new(),
            index: HashMap::new(),
            mth: nflog_empty(),
        }
    }

    /// Fold one published nullifier by first-occurrence (section 3.6 step 5).
    ///
    /// Recomputes `mth` from scratch on every successful append — O(size)
    /// per call. Acceptable for this in-memory chunk's scope; bulk fixtures
    /// should use the pure `nflog_mth` / `inclusion_path` / `consistency_proof`
    /// functions on a materialised `Vec<NfLogEntry>` instead.
    pub fn fold(&mut self, height: u64, pk: [u8; 32], r: [u8; 32]) -> FoldOutcome {
        if height < self.activation_height {
            return FoldOutcome::BelowActivationHeight;
        }
        if self.index.contains_key(&pk) {
            return FoldOutcome::DuplicateIgnored;
        }
        let pos = self.log.len() as u64;
        self.log.push(NfLogEntry { pk, r });
        self.heights.push(height);
        self.index.insert(pk, (pos, r));
        self.mth = nflog_mth(&self.log);
        FoldOutcome::Appended(pos)
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

    /// Truncate-and-refold reorg (section 3.6/3.9): clears all state and re-folds
    /// `canonical_stream` (sorted by `ChainPosition`) from scratch.
    pub fn reorg_replay(&mut self, mut canonical_stream: Vec<PublishedNullifier>) {
        canonical_stream.sort_by_key(|e| e.chain_pos);
        self.log.clear();
        self.heights.clear();
        self.index.clear();
        self.mth = nflog_empty();
        for entry in canonical_stream {
            self.fold(entry.chain_pos.height, entry.pk, entry.r);
        }
    }

    /// `size_final` (section 3.9): the accumulator size at the highest block
    /// height `<= tip_height - (finality_confirmations - 1)`. Returns 0 if
    /// `tip_height < finality_confirmations - 1`.
    pub fn size_final(&self, tip_height: u64, finality_confirmations: u64) -> u64 {
        let Some(max_final_height) = tip_height.checked_sub(finality_confirmations - 1) else {
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

    fn published(height: u64, pk_b: u8, r_b: u8) -> PublishedNullifier {
        PublishedNullifier {
            chain_pos: ChainPosition {
                height,
                tx_index: 0,
                vin_index: 0,
                member_index: 0,
            },
            pk: pk(pk_b),
            r: r(r_b),
        }
    }

    #[test]
    fn first_occurrence_duplicate_pk_does_not_move_position() {
        let mut acc = NfLogAccumulator::new(0);
        assert_eq!(acc.fold(100, pk(1), r(1)), FoldOutcome::Appended(0));
        assert_eq!(acc.fold(101, pk(1), r(1)), FoldOutcome::DuplicateIgnored);
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
        assert_eq!(acc.fold(100, pk(1), r(10)), FoldOutcome::Appended(0));
        assert_eq!(acc.fold(101, pk(1), r(20)), FoldOutcome::DuplicateIgnored);
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
            assert_eq!(acc.fold(100 + i as u64, p, rr), FoldOutcome::Appended(i as u64));
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
            acc.fold(e.chain_pos.height, e.pk, e.r);
        }
        assert_eq!(acc.nav().size, 4);

        let e = published(102, 5, 5);
        let f = published(103, 6, 6);
        // New stream after reorg of blocks 102/103: C,D gone; E,F take place
        acc.reorg_replay(vec![a, b, e, f]);

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
            acc.fold(10, pk(1), r(1)),
            FoldOutcome::BelowActivationHeight
        );
        assert_eq!(acc.nav().size, 0);
        assert_eq!(acc.fold(50, pk(1), r(1)), FoldOutcome::Appended(0));
        assert_eq!(acc.nav().size, 1);
    }

    #[test]
    fn size_final_confirmation_boundary() {
        let mut acc = NfLogAccumulator::new(0);
        // heights 10, 11, 12, 20
        assert_eq!(acc.fold(10, pk(1), r(1)), FoldOutcome::Appended(0));
        assert_eq!(acc.fold(11, pk(2), r(2)), FoldOutcome::Appended(1));
        assert_eq!(acc.fold(12, pk(3), r(3)), FoldOutcome::Appended(2));
        assert_eq!(acc.fold(20, pk(4), r(4)), FoldOutcome::Appended(3));

        // tip_height < finality_confirmations - 1 (= 5) → 0
        assert_eq!(acc.size_final(0, 6), 0);
        assert_eq!(acc.size_final(4, 6), 0);

        // tip=15 → max_final = 15 - 5 = 10 → only height 10 confirmed → size 1
        assert_eq!(acc.size_final(15, 6), 1);
        // tip=16 → max_final = 11 → heights 10,11 → size 2
        assert_eq!(acc.size_final(16, 6), 2);
        // tip=17 → max_final = 12 → heights 10,11,12 → size 3
        assert_eq!(acc.size_final(17, 6), 3);
        // tip=25 → max_final = 20 → all four
        assert_eq!(acc.size_final(25, 6), 4);
    }

    #[test]
    fn is_canonical_matches_prefix_mth() {
        let mut acc = NfLogAccumulator::new(0);
        for i in 0..4u8 {
            acc.fold(100 + i as u64, pk(i + 1), r(i + 1));
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
}
