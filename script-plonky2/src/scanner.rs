//! Chain scanner (§3.6): rebuild the nullifier accumulator from Bitcoin alone.
//!
//! Reads confirmed Bitcoin blocks from a real bitcoind, discovers zkCoins
//! inscriptions under the §3.5 envelope grammar, validates them (structure,
//! `block_anchor` bound, signatures), and folds surviving nullifiers into
//! [`NfLogAccumulator`] in the canonical
//! `(height, tx_index, vin_index, member_index)` order.
//!
//! This module is fail-closed and fail-loud: every rejection carries a reason
//! and appears in the scan result; ambiguous or unverifiable inputs contribute
//! **zero** nullifiers. The same confirmed chain always yields the same
//! accumulator — no randomness, wall-clock, or RPC-result-order dependence.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, TxIn, TxOut};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use shared::spec_v1::accumulator::ReorgOutcome;
use shared::spec_v1::{ChainPosition, FoldOutcome, NfLogAccumulator, PublishedNullifier};
use zkcoins_program_plonky2::circuit::compliance::Network;

use crate::half_agg::{
    aggregate_verify, verify_single, AggregateStateNullifierV3, BlockAnchor, FORMAT_HALF_AGG,
    FORMAT_RAW,
};
use crate::inscription::extract_payload_from_input;
use crate::publisher::ensure_chain_matches_config;

/// §3.5 `block_anchor` bound: the anchor must be a **strict** ancestor of the
/// inclusion block and the height gap must not exceed this constant.
pub const MAX_ANCHOR_GAP: u64 = 100;

/// OP_FALSE (`0x00`) followed by OP_IF (`0x63`) — the §3.5 envelope opener.
const ENVELOPE_OPENER: [u8; 2] = [0x00, 0x63];

/// Scanner configuration. Every field is mandatory — no silent defaults.
///
/// `activation_height` is a pinned consensus parameter (§3.6 "Scan origin");
/// the caller supplies the network-correct value (regtest pins `0`).
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// Base RPC URL, e.g. `http://127.0.0.1:18443` (no wallet path required).
    pub rpc_url: String,
    /// Path to bitcoind's `.cookie` file. Cookie-file auth only.
    pub cookie_path: PathBuf,
    /// Selects the per-network fixed `m_state` used for signature verification
    /// (§3.6 step 3). Must match the connected chain.
    pub network: Network,
    /// First Bitcoin height at which zkCoins nullifiers are recognised
    /// (§3.6 Scan origin). Consensus-critical.
    pub activation_height: u64,
}

/// One inscription (or candidate input) rejected during a block scan.
///
/// Fail-closed: the input contributes zero nullifiers. The reason is always
/// recorded — nothing is dropped quietly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedInscription {
    /// Inclusion block height.
    pub height: u64,
    /// Transaction index within the block.
    pub tx_index: u32,
    /// Input index within the transaction.
    pub vin_index: u32,
    /// Human-readable rejection reason (parse / bound / signature / extract).
    pub reason: String,
}

/// Result of scanning a single confirmed block.
#[derive(Clone, Debug)]
pub struct BlockScanResult {
    pub height: u64,
    pub block_hash: BlockHash,
    /// Envelopes found before validation (successful `extract_payload_from_input`
    /// yielding `Some(_)`, plus extract `Err`s that looked like marker inputs).
    pub inscriptions_seen: usize,
    /// Every rejection with its reason — never silently dropped.
    pub rejected: Vec<RejectedInscription>,
    /// Admitted (first-occurrence) nullifiers: `(chain position, log position)`.
    pub admitted: Vec<(ChainPosition, u64)>,
    /// Count of first-occurrence losers (`FoldOutcome::DuplicateIgnored`).
    pub duplicates: usize,
}

/// Aggregate report for one [`Scanner::scan_to_tip`] call.
#[derive(Clone, Debug)]
pub struct ScanReport {
    /// First height scanned in this call, if any block was processed.
    pub from_height: Option<u64>,
    /// Last height scanned in this call, if any block was processed.
    pub to_height: Option<u64>,
    /// Chain tip after the scan.
    pub tip_height: u64,
    pub tip_hash: BlockHash,
    /// Per-block results in ascending height order.
    pub blocks: Vec<BlockScanResult>,
    /// Present when a reorg was detected and replayed before scanning forward.
    /// Callers MUST inspect `finality_broken` and stop crediting when set.
    pub reorg: Option<ReorgOutcome>,
    /// Sum of `inscriptions_seen` across blocks.
    pub inscriptions_seen: usize,
    /// Total first-occurrence admissions this call.
    pub admitted_count: usize,
    /// Total rejections this call.
    pub rejected_count: usize,
    /// Total duplicate-ignored folds this call.
    pub duplicates: usize,
}

/// Path-A chain scanner: bitcoind RPC + in-memory nullifier accumulator.
pub struct Scanner {
    rpc: Client,
    config: ScannerConfig,
    accumulator: NfLogAccumulator,
    /// All signature-verified, bound-checked nullifiers in canonical order
    /// (including first-occurrence losers). Input for [`NfLogAccumulator::reorg_replay`].
    survivors: Vec<PublishedNullifier>,
    /// Highest fully-scanned height and its block hash at scan time.
    scanned_through: Option<(u64, BlockHash)>,
    /// Every height → hash observed while scanning (for reorg common-ancestor).
    scanned_blocks: BTreeMap<u64, BlockHash>,
}

impl Scanner {
    /// Connect to bitcoind with cookie auth and verify the chain matches
    /// [`ScannerConfig::network`].
    pub fn connect(config: ScannerConfig) -> Result<Self> {
        ensure!(
            !config.rpc_url.is_empty(),
            "ScannerConfig.rpc_url must not be empty"
        );
        ensure!(
            !config.cookie_path.as_os_str().is_empty(),
            "ScannerConfig.cookie_path must not be empty"
        );

        let base = config.rpc_url.trim_end_matches('/');
        let rpc = Client::new(base, Auth::CookieFile(config.cookie_path.clone())).with_context(
            || {
                format!(
                    "failed to open bitcoind RPC client at {base} using cookie {:?}",
                    config.cookie_path
                )
            },
        )?;

        let chain_info = rpc
            .get_blockchain_info()
            .with_context(|| format!("bitcoind unreachable or RPC auth failed at {base}"))?;
        ensure_chain_matches_config(chain_info.chain, config.network)?;

        let accumulator = NfLogAccumulator::new(config.activation_height);
        Ok(Self {
            rpc,
            config,
            accumulator,
            survivors: Vec::new(),
            scanned_through: None,
            scanned_blocks: BTreeMap::new(),
        })
    }

    /// Scan forward from the last scanned block to the current chain tip.
    ///
    /// Before scanning forward, verifies the previously scanned tip is still
    /// canonical. On reorg: finds the highest common ancestor, drops survivors
    /// above it, re-collects nullifiers on the new canonical fork, and calls
    /// [`NfLogAccumulator::reorg_replay`]. `ReorgOutcome::finality_broken` is
    /// surfaced in the report — never swallowed.
    pub fn scan_to_tip(&mut self) -> Result<ScanReport> {
        let reorg = self.detect_and_handle_reorg()?;

        let tip_height = self
            .rpc
            .get_block_count()
            .context("getblockcount failed")?;
        let tip_hash = self
            .rpc
            .get_block_hash(tip_height)
            .with_context(|| format!("getblockhash({tip_height}) failed"))?;

        let start = match self.scanned_through {
            Some((h, _)) => h
                .checked_add(1)
                .context("scanned height + 1 overflowed u64")?,
            None => self.config.activation_height,
        };

        let mut blocks = Vec::new();
        let mut inscriptions_seen = 0usize;
        let mut admitted_count = 0usize;
        let mut rejected_count = 0usize;
        let mut duplicates = 0usize;
        let mut from_height = None;
        let mut to_height = None;

        if start <= tip_height {
            for height in start..=tip_height {
                let result = self.scan_block(height)?;
                inscriptions_seen = inscriptions_seen
                    .checked_add(result.inscriptions_seen)
                    .context("inscriptions_seen overflow")?;
                admitted_count = admitted_count
                    .checked_add(result.admitted.len())
                    .context("admitted_count overflow")?;
                rejected_count = rejected_count
                    .checked_add(result.rejected.len())
                    .context("rejected_count overflow")?;
                duplicates = duplicates
                    .checked_add(result.duplicates)
                    .context("duplicates overflow")?;
                if from_height.is_none() {
                    from_height = Some(height);
                }
                to_height = Some(height);
                blocks.push(result);
            }
        }

        Ok(ScanReport {
            from_height,
            to_height,
            tip_height,
            tip_hash,
            blocks,
            reorg,
            inscriptions_seen,
            admitted_count,
            rejected_count,
            duplicates,
        })
    }

    /// Borrow the in-memory Path-A accumulator rebuilt from the chain.
    pub fn accumulator(&self) -> &NfLogAccumulator {
        &self.accumulator
    }

    /// Highest fully-scanned block, if any scan has completed.
    pub fn scanned_through(&self) -> Option<(u64, BlockHash)> {
        self.scanned_through
    }

    /// All signature-verified, bound-checked nullifiers in canonical order
    /// (including first-occurrence losers). Suitable as the reorg-replay stream.
    pub fn survivors(&self) -> &[PublishedNullifier] {
        &self.survivors
    }

    /// Scanner configuration (network, activation height, …).
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }
}

// ── §3.6 pure helpers (unit-testable without bitcoind) ───────────────────

/// Cheap discover pre-filter: is this input a script-path spend whose executed
/// Tapscript **may** contain a zkCoins envelope?
///
/// ## Why this filter is safe (cannot discard a valid envelope)
///
/// A conforming §3.5 zkCoins envelope is the opcode sequence
/// `OP_FALSE OP_IF` … `OP_ENDIF` inside the **executed** Tapscript leaf. Those
/// two opener opcodes encode as the consecutive bytes `0x00 0x63`. Every leaf
/// produced by [`crate::inscription::build_envelope_script`] contains that
/// pair, and [`crate::inscription::extract_payload_from_input`] only extracts
/// envelopes that parse as that construct.
///
/// This filter:
/// 1. Strips a BIP-341 annex (last witness element beginning with `0x50`);
/// 2. Requires a script-path-shaped witness (≥2 elements after annex strip);
/// 3. Checks that the tapscript element (second-to-last) **contains** the byte
///    pair `0x00 0x63` at any offset.
///
/// A false positive only costs a prevout fetch + full extract. A false
/// negative would require a valid envelope **without** `OP_FALSE OP_IF`, which
/// is not a zkCoins envelope under §3.5. Key-path spends (single-element
/// witness) are correctly excluded — scanners evaluate only script-path leaves.
pub fn may_contain_zkcoins_envelope(input: &TxIn) -> bool {
    let witness = input.witness.to_vec();
    let mut end = witness.len();
    if witness
        .last()
        .is_some_and(|element| element.first() == Some(&0x50))
    {
        end = end.saturating_sub(1);
    }
    if end < 2 {
        return false;
    }
    let script = &witness[end - 2];
    script
        .windows(ENVELOPE_OPENER.len())
        .any(|window| window == ENVELOPE_OPENER)
}

/// Pure §3.5 `block_anchor` bound predicate (all three parts).
///
/// `canonical_hash_at_anchor` must be `getblockhash(anchor.height)` under the
/// normative byte order ([`BlockHash::to_byte_array`]).
///
/// Rejects when:
/// 1. `anchor.height >= inclusion_height` (not a strict ancestor by height);
/// 2. `inclusion_height - anchor.height > MAX_ANCHOR_GAP`;
/// 3. `anchor.block_hash != canonical_hash_at_anchor` (not this chain).
pub fn evaluate_anchor_bound(
    anchor: &BlockAnchor,
    inclusion_height: u64,
    canonical_hash_at_anchor: [u8; 32],
) -> Result<(), String> {
    let anchor_height = u64::from(anchor.height);
    if anchor_height >= inclusion_height {
        return Err(format!(
            "block_anchor height {anchor_height} is not a strict ancestor of \
             inclusion height {inclusion_height} (equal or forward anchor rejected)"
        ));
    }
    let gap = inclusion_height - anchor_height;
    if gap > MAX_ANCHOR_GAP {
        return Err(format!(
            "block_anchor gap {gap} exceeds MAX_ANCHOR_GAP ({MAX_ANCHOR_GAP}): \
             inclusion {inclusion_height}, anchor {anchor_height}"
        ));
    }
    if anchor.block_hash != canonical_hash_at_anchor {
        return Err(format!(
            "block_anchor.block_hash is not the canonical block at height {anchor_height} \
             (anchor names a hash that is not on this chain)"
        ));
    }
    Ok(())
}

// ── internal scanning ───────────────────────────────────────────────────

impl Scanner {
    fn detect_and_handle_reorg(&mut self) -> Result<Option<ReorgOutcome>> {
        let Some((scanned_h, scanned_hash)) = self.scanned_through else {
            return Ok(None);
        };

        let tip = self
            .rpc
            .get_block_count()
            .context("getblockcount during reorg check failed")?;

        let still_canonical = if scanned_h > tip {
            false
        } else {
            match self.rpc.get_block_hash(scanned_h) {
                Ok(live) => live == scanned_hash,
                Err(_) => false,
            }
        };
        if still_canonical {
            return Ok(None);
        }

        // Highest common ancestor: walk down stored hashes.
        let mut fork_height: Option<u64> = None;
        for (&height, old_hash) in self.scanned_blocks.iter().rev() {
            if height > tip {
                continue;
            }
            match self.rpc.get_block_hash(height) {
                Ok(live) if live == *old_hash => {
                    fork_height = Some(height);
                    break;
                }
                _ => continue,
            }
        }

        // If no common block remains, replay from empty (everything above
        // activation is re-collected). `fork_height = None` means retained = [].
        let old_tip_height = scanned_h;
        let retained: Vec<PublishedNullifier> = match fork_height {
            Some(fork) => self
                .survivors
                .iter()
                .filter(|n| n.chain_pos.height <= fork)
                .cloned()
                .collect(),
            None => Vec::new(),
        };

        // Drop scan state above the fork.
        let rescan_from = match fork_height {
            Some(fork) => fork
                .checked_add(1)
                .context("fork height + 1 overflowed")?,
            None => self.config.activation_height,
        };
        self.scanned_blocks.retain(|&h, _| {
            fork_height.map(|fork| h <= fork).unwrap_or(false)
        });
        self.survivors = retained.clone();

        // Re-collect verified nullifiers on the new canonical blocks through
        // min(old tip, current tip). Do not fold yet — reorg_replay does that.
        let recollect_through = tip.min(old_tip_height);
        let mut stream = retained;
        if rescan_from <= recollect_through {
            for height in rescan_from..=recollect_through {
                let (block_hash, verified, _rejected, _seen) =
                    self.collect_block_nullifiers(height)?;
                stream.extend(verified);
                self.scanned_blocks.insert(height, block_hash);
            }
            let hash = self
                .rpc
                .get_block_hash(recollect_through)
                .with_context(|| format!("getblockhash({recollect_through}) after reorg"))?;
            self.scanned_through = Some((recollect_through, hash));
        } else {
            // Chain tip is at or below fork; nothing to recollect.
            self.scanned_through = match fork_height {
                Some(fork) => {
                    let hash = *self.scanned_blocks.get(&fork).ok_or_else(|| {
                        anyhow!("internal: missing scanned hash at fork {fork}")
                    })?;
                    Some((fork, hash))
                }
                None => None,
            };
        }

        let outcome = self
            .accumulator
            .reorg_replay(old_tip_height, stream.clone())
            .map_err(|e| anyhow!("accumulator reorg_replay failed: {e}"))?;
        self.survivors = stream;

        if outcome.finality_broken {
            // Loud surface: finality assumption broken — caller must stop crediting.
            eprintln!(
                "zkCoins scanner: FINALITY BROKEN after reorg — \
                 displaced_final_count={}, old_tip_height={old_tip_height}, \
                 fork={fork_height:?}. Callers MUST stop crediting against the \
                 broken state (§3.9).",
                outcome.displaced_final_count
            );
        }

        Ok(Some(outcome))
    }

    fn scan_block(&mut self, height: u64) -> Result<BlockScanResult> {
        let (block_hash, verified, rejected, inscriptions_seen) =
            self.collect_block_nullifiers(height)?;

        let mut admitted = Vec::new();
        let mut duplicates = 0usize;

        // §3.6 steps 4–5: fold in strictly ascending ChainPosition order.
        // collect_block_nullifiers already emits members in canonical order
        // within the block; heights are scanned ascending.
        for nf in &verified {
            let outcome = self
                .accumulator
                .fold(nf.chain_pos, nf.pk, nf.r)
                .map_err(|e| {
                    anyhow!(
                        "accumulator.fold out-of-order or failed at {:?}: {e}",
                        nf.chain_pos
                    )
                })?;
            match outcome {
                FoldOutcome::Appended(pos) => {
                    admitted.push((nf.chain_pos, pos));
                }
                FoldOutcome::DuplicateIgnored => {
                    duplicates = duplicates
                        .checked_add(1)
                        .context("duplicates counter overflow")?;
                }
                FoldOutcome::BelowActivationHeight => {
                    // Should not arise: we only scan height >= activation_height.
                    bail!(
                        "fold returned BelowActivationHeight at height {} \
                         (activation_height={}); scanner must not scan below activation",
                        nf.chain_pos.height,
                        self.config.activation_height
                    );
                }
            }
            self.survivors.push(*nf);
        }

        self.scanned_blocks.insert(height, block_hash);
        self.scanned_through = Some((height, block_hash));

        Ok(BlockScanResult {
            height,
            block_hash,
            inscriptions_seen,
            rejected,
            admitted,
            duplicates,
        })
    }

    /// Discover → parse/bound-check → verify for one block. Returns verified
    /// nullifiers in canonical order (does **not** fold into the accumulator).
    fn collect_block_nullifiers(
        &self,
        height: u64,
    ) -> Result<(
        BlockHash,
        Vec<PublishedNullifier>,
        Vec<RejectedInscription>,
        usize,
    )> {
        ensure!(
            height >= self.config.activation_height,
            "collect_block_nullifiers called below activation_height \
             ({height} < {})",
            self.config.activation_height
        );

        let block_hash = self
            .rpc
            .get_block_hash(height)
            .with_context(|| format!("getblockhash({height}) failed"))?;
        let block: Block = self
            .rpc
            .get_block(&block_hash)
            .with_context(|| format!("getblock({block_hash}) failed"))?;

        let mut verified = Vec::new();
        let mut rejected = Vec::new();
        let mut inscriptions_seen = 0usize;

        for (tx_index_usize, tx) in block.txdata.iter().enumerate() {
            let tx_index = u32::try_from(tx_index_usize)
                .with_context(|| format!("tx_index {tx_index_usize} does not fit in u32"))?;

            for (vin_index_usize, input) in tx.input.iter().enumerate() {
                let vin_index = u32::try_from(vin_index_usize)
                    .with_context(|| format!("vin_index {vin_index_usize} does not fit in u32"))?;

                // §3.6 step 1 — Discover (cheap pre-filter, then full extract).
                if !may_contain_zkcoins_envelope(input) {
                    continue;
                }

                let prevout = match self.fetch_prevout(input) {
                    Ok(p) => p,
                    Err(err) => {
                        // Fail-closed: cannot verify without prevout.
                        rejected.push(RejectedInscription {
                            height,
                            tx_index,
                            vin_index,
                            reason: format!("prevout fetch failed: {err:#}"),
                        });
                        continue;
                    }
                };

                let payload = match extract_payload_from_input(input, &prevout) {
                    Ok(None) => continue, // not a marker envelope after full check
                    Ok(Some(bytes)) => {
                        inscriptions_seen = inscriptions_seen
                            .checked_add(1)
                            .context("inscriptions_seen overflow")?;
                        bytes
                    }
                    Err(err) => {
                        // Malformed marker input → zero nullifiers, record reason.
                        inscriptions_seen = inscriptions_seen
                            .checked_add(1)
                            .context("inscriptions_seen overflow")?;
                        rejected.push(RejectedInscription {
                            height,
                            tx_index,
                            vin_index,
                            reason: format!("extract_payload_from_input: {err:#}"),
                        });
                        continue;
                    }
                };

                // §3.6 step 2 — Parse and bound-check.
                let agg = match AggregateStateNullifierV3::deserialize(&payload) {
                    Ok(a) => a,
                    Err(err) => {
                        rejected.push(RejectedInscription {
                            height,
                            tx_index,
                            vin_index,
                            reason: format!("deserialize AggregateStateNullifierV3: {err:#}"),
                        });
                        continue;
                    }
                };

                if let Err(reason) = self.check_anchor_on_chain(&agg.block_anchor, height) {
                    rejected.push(RejectedInscription {
                        height,
                        tx_index,
                        vin_index,
                        reason,
                    });
                    continue;
                }

                // §3.6 step 3 — Verify signatures (whole aggregate or nothing).
                let m_state = self.config.network.m_state_bytes();
                if let Err(reason) = verify_payload_signatures(&agg, m_state) {
                    rejected.push(RejectedInscription {
                        height,
                        tx_index,
                        vin_index,
                        reason,
                    });
                    continue;
                }

                // §3.6 step 4 — Order: build ChainPosition per member.
                for (member_index_usize, (pk, r)) in agg.members.iter().enumerate() {
                    let member_index = u32::try_from(member_index_usize).with_context(|| {
                        format!("member_index {member_index_usize} does not fit in u32")
                    })?;
                    verified.push(PublishedNullifier {
                        chain_pos: ChainPosition {
                            height,
                            tx_index,
                            vin_index,
                            member_index,
                        },
                        pk: *pk,
                        r: *r,
                    });
                }
            }
        }

        // Canonical order within the block is already (tx_index, vin_index,
        // member_index) from the nested loops. Do not re-sort defensively —
        // an ordering bug must surface as OutOfOrderFold, not be hidden.
        Ok((block_hash, verified, rejected, inscriptions_seen))
    }

    fn check_anchor_on_chain(&self, anchor: &BlockAnchor, inclusion_height: u64) -> Result<(), String> {
        let anchor_height = u64::from(anchor.height);
        // Height/gap first so unit-testable messages stay stable; then chain identity.
        if anchor_height >= inclusion_height {
            return Err(format!(
                "block_anchor height {anchor_height} is not a strict ancestor of \
                 inclusion height {inclusion_height} (equal or forward anchor rejected)"
            ));
        }
        let gap = inclusion_height - anchor_height;
        if gap > MAX_ANCHOR_GAP {
            return Err(format!(
                "block_anchor gap {gap} exceeds MAX_ANCHOR_GAP ({MAX_ANCHOR_GAP}): \
                 inclusion {inclusion_height}, anchor {anchor_height}"
            ));
        }

        let canonical = self
            .rpc
            .get_block_hash(anchor_height)
            .map_err(|e| {
                format!(
                    "getblockhash({}) for anchor identity check failed: {e}",
                    anchor.height
                )
            })?;
        let canonical_bytes = canonical.to_byte_array();
        evaluate_anchor_bound(anchor, inclusion_height, canonical_bytes)
    }

    fn fetch_prevout(&self, input: &TxIn) -> Result<TxOut> {
        let parent_txid = input.previous_output.txid;
        let parent = self
            .rpc
            .get_raw_transaction(&parent_txid, None)
            .with_context(|| {
                format!(
                    "getrawtransaction(parent {parent_txid}) failed; is txindex=1 enabled?"
                )
            })?;
        let vout = input.previous_output.vout as usize;
        parent.output.get(vout).cloned().with_context(|| {
            format!("parent {parent_txid} has no vout {vout}")
        })
    }
}

/// §3.6 step 3: verify signatures. On failure the **whole** payload is discarded.
fn verify_payload_signatures(agg: &AggregateStateNullifierV3, m_state: &[u8]) -> Result<(), String> {
    match agg.format {
        FORMAT_RAW => {
            let (pk, r) = agg.members.first().ok_or_else(|| {
                "raw AggregateStateNullifierV3 has no members".to_string()
            })?;
            let s = agg.raw_s.as_ref().ok_or_else(|| {
                "raw AggregateStateNullifierV3 missing raw_s".to_string()
            })?;
            verify_single(pk, r, s, m_state).map_err(|e| {
                format!("verify_single failed (whole payload discarded): {e:#}")
            })
        }
        FORMAT_HALF_AGG => aggregate_verify(agg, m_state).map_err(|e| {
            format!("aggregate_verify failed (whole aggregate discarded): {e:#}")
        }),
        other => Err(format!(
            "unsupported AggregateStateNullifierV3 format {other:#04x} (whole payload discarded)"
        )),
    }
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use bitcoincore_rpc::json::AddressType;
    use shared::spec_v1::{ProofData, SpendClassification, ZERO_HASH};
    use sha2::{Digest, Sha256};

    use crate::half_agg::{
        aggregate_sig_with_anchor, AggregateStateNullifierV3, BlockAnchor, NullifierSig,
    };
    use crate::inscription::{build_envelope_script, build_inscription, InscriptionRequest};
    use crate::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };
    use crate::publisher::{
        nums_internal_key, BatchMember, Publisher, PublisherConfig,
        BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
    };

    // ── unit tests (no bitcoind) ────────────────────────────────────────

    #[test]
    fn anchor_bound_equal_height_rejected() {
        let hash = [0x11; 32];
        let anchor = BlockAnchor {
            block_hash: hash,
            height: 50,
        };
        let err = evaluate_anchor_bound(&anchor, 50, hash).expect_err("equal height");
        assert!(
            err.contains("strict ancestor") || err.contains("equal"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn anchor_bound_gap_100_accepted() {
        let hash = [0x22; 32];
        let anchor = BlockAnchor {
            block_hash: hash,
            height: 10,
        };
        evaluate_anchor_bound(&anchor, 110, hash).expect("gap 100 must pass");
    }

    #[test]
    fn anchor_bound_gap_101_rejected() {
        let hash = [0x33; 32];
        let anchor = BlockAnchor {
            block_hash: hash,
            height: 10,
        };
        let err = evaluate_anchor_bound(&anchor, 111, hash).expect_err("gap 101");
        assert!(
            err.contains("MAX_ANCHOR_GAP") || err.contains("101"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn anchor_bound_wrong_hash_rejected() {
        let anchor = BlockAnchor {
            block_hash: [0x44; 32],
            height: 10,
        };
        let err = evaluate_anchor_bound(&anchor, 20, [0x55; 32]).expect_err("wrong hash");
        assert!(
            err.contains("canonical") || err.contains("not on this chain") || err.contains("hash"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn discover_prefilter_keeps_valid_envelope_leaf() {
        // build_envelope_script produces OP_FALSE OP_IF … OP_ENDIF.
        let mut payload = vec![0x42, 0x42, 0x03, 0x01];
        payload.extend_from_slice(&[0u8; 64]); // pad so it is non-trivial
        let script = build_envelope_script(&payload).expect("envelope script");
        // Script-path witness: <truthy> <tapscript> <control block>
        let mut input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        input.witness.push([0x01]); // truthy stack element
        input.witness.push(script.as_bytes());
        // Minimal fake control block (filter does not validate it).
        input.witness.push([0xc0; 33]);
        assert!(
            may_contain_zkcoins_envelope(&input),
            "valid envelope leaf must never be pre-filtered out"
        );
    }

    #[test]
    fn discover_prefilter_rejects_keypath_and_empty() {
        let mut keypath = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        keypath.witness.push([0u8; 64]); // single sig element
        assert!(!may_contain_zkcoins_envelope(&keypath));

        let empty = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        assert!(!may_contain_zkcoins_envelope(&empty));
    }

    #[test]
    fn discover_prefilter_keeps_envelope_not_at_script_start() {
        // Prefix opcodes then the envelope — filter must still match 0x00 0x63.
        let mut payload = vec![0x42, 0x42];
        payload.extend_from_slice(&[0xab; 8]);
        let envelope = build_envelope_script(&payload).expect("envelope");
        let mut script_bytes = vec![0x51]; // OP_PUSHNUM_1 prefix
        script_bytes.extend_from_slice(envelope.as_bytes());

        let mut input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        input.witness.push([0x01]);
        input.witness.push(script_bytes);
        input.witness.push([0xc0; 33]);
        assert!(
            may_contain_zkcoins_envelope(&input),
            "envelope not at byte 0 of the leaf must still pass the pre-filter"
        );
    }

    // ── live regtest helpers ────────────────────────────────────────────

    fn require_env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "live regtest test requires env var {name} to be set \
                 (do not silently skip — missing coverage would be a lie)"
            )
        })
    }

    fn live_publisher() -> Publisher {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        let wallet = require_env("ZKCOINS_REGTEST_WALLET");
        Publisher::connect(PublisherConfig {
            rpc_url: url,
            cookie_path: PathBuf::from(cookie),
            wallet_name: wallet,
            fee_rate_sat_per_vb: 2,
            reveal_output_value: Amount::from_sat(1_000),
            network: Network::Regtest,
            inclusion_delay_margin: BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
        })
        .expect("Publisher::connect to live regtest must succeed")
    }

    fn live_scanner() -> Scanner {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        Scanner::connect(ScannerConfig {
            rpc_url: url,
            cookie_path: PathBuf::from(cookie),
            network: Network::Regtest,
            activation_height: 0, // §3.6 regtest pin — passed explicitly
        })
        .expect("Scanner::connect to live regtest must succeed")
    }

    fn wallet_rpc() -> Client {
        let url = require_env("ZKCOINS_REGTEST_URL");
        let cookie = require_env("ZKCOINS_REGTEST_COOKIE");
        let wallet = require_env("ZKCOINS_REGTEST_WALLET");
        let base = url.trim_end_matches('/');
        let wallet_url = format!("{base}/wallet/{wallet}");
        Client::new(&wallet_url, Auth::CookieFile(PathBuf::from(cookie)))
            .expect("wallet RPC client")
    }

    /// Unique-per-call tag so repeated regtest runs never collide on the same
    /// deterministic `Pk` already present in the chain/accumulator.
    fn unique_tag(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        format!("{prefix}-{nanos}")
    }

    fn signed_members(count: usize, seed_tag: &str) -> Vec<NullifierSig> {
        let mut members = Vec::with_capacity(count);
        for index in 0..count {
            let label = format!("zkCoins/v1/scanner/{seed_tag}/secret-{index}");
            let (secret, public, _) = normalized_key(deterministic_secret(label.as_bytes()));
            let proof_data = ProofData {
                new_account_state_hash: ZERO_HASH,
                output_coins_root: ZERO_HASH,
                input_nullifiers_root: ZERO_HASH,
                coin_history_root: ZERO_HASH,
                nav_commitment: ZERO_HASH,
                npk_commit: Sha256::digest(format!("{seed_tag}-next-{index}")).into(),
            };
            let signed = sign_transition(secret, public, &proof_data, Network::Regtest);
            let transition = signed.transition;
            members.push(NullifierSig {
                pk: transition.pk_i,
                r: transition.signature_r(),
                s: transition.signature_s(),
            });
        }
        members
    }

    /// Two signatures with the **same** `Pk` and different `R` (double-spend pair).
    fn double_spend_pair(seed_tag: &str) -> (NullifierSig, NullifierSig) {
        let label = format!("zkCoins/v1/scanner/{seed_tag}/dup-pk");
        let (secret, public, _) = normalized_key(deterministic_secret(label.as_bytes()));
        let mk = |suffix: &str| {
            let proof_data = ProofData {
                new_account_state_hash: ZERO_HASH,
                output_coins_root: ZERO_HASH,
                input_nullifiers_root: ZERO_HASH,
                coin_history_root: ZERO_HASH,
                nav_commitment: ZERO_HASH,
                npk_commit: Sha256::digest(format!("{seed_tag}-{suffix}")).into(),
            };
            let signed = sign_transition(secret, public, &proof_data, Network::Regtest);
            let t = signed.transition;
            NullifierSig {
                pk: t.pk_i,
                r: t.signature_r(),
                s: t.signature_s(),
            }
        };
        let a = mk("first");
        let b = mk("second");
        assert_eq!(a.pk, b.pk, "same secret must yield same pk");
        assert_ne!(a.r, b.r, "different proof_data must yield different R");
        (a, b)
    }

    fn batch_at_tip(publisher: &Publisher, sigs: &[NullifierSig]) -> Vec<BatchMember> {
        let tip = publisher.current_anchor().expect("current_anchor");
        sigs.iter()
            .map(|sig| BatchMember {
                sig: *sig,
                build_tip: tip,
            })
            .collect()
    }

    fn mine_one(publisher: &Publisher) {
        let rpc = wallet_rpc();
        let network = rpc.get_blockchain_info().expect("chain").chain;
        let addr = rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("getnewaddress")
            .require_network(network)
            .expect("address network");
        rpc.generate_to_address(1, &addr).expect("generatetoaddress");
        let _ = publisher; // keep call sites symmetric
    }

    /// Advance the scanner from its current tip through the full chain.
    /// Used so each live test only cares about blocks it itself produced
    /// after catching up once.
    fn catch_up(scanner: &mut Scanner) -> ScanReport {
        scanner.scan_to_tip().expect("catch_up scan_to_tip")
    }

    /// Broadcast an arbitrary payload as a commit/reveal inscription using the
    /// wallet (for tests that must bypass Publisher::publish validation).
    fn broadcast_raw_payload(payload: &[u8]) -> (Txid, Txid) {
        let rpc = wallet_rpc();
        let network = rpc.get_blockchain_info().expect("chain").chain;
        let nums = nums_internal_key().expect("NUMS");
        let reveal_addr = rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("reveal addr")
            .require_network(network)
            .expect("net");
        let change_addr = rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("change addr")
            .require_network(network)
            .expect("net");
        let reveal_script = reveal_addr.script_pubkey();
        let change_script = change_addr.script_pubkey();
        let reveal_value = Amount::from_sat(1_000);
        let commit_fee = Amount::from_sat(500);
        let reveal_fee = Amount::from_sat(2_000);

        let utxos = rpc
            .list_unspent(Some(1), None, None, Some(false), None)
            .expect("listunspent");
        let funding = utxos
            .into_iter()
            .find(|u| {
                u.amount >= reveal_value + commit_fee + reveal_fee + Amount::from_sat(500)
                    && (u.script_pub_key.is_p2wpkh() || u.script_pub_key.is_p2tr())
            })
            .expect("funding UTXO for raw payload broadcast");

        let inscription = build_inscription(
            payload,
            InscriptionRequest {
                funding_outpoint: OutPoint {
                    txid: funding.txid,
                    vout: funding.vout,
                },
                funding_value: funding.amount,
                internal_key: nums,
                reveal_output: TxOut {
                    value: reveal_value,
                    script_pubkey: reveal_script,
                },
                change_script_pubkey: Some(change_script),
                commit_fee,
                reveal_fee,
            },
        )
        .expect("build_inscription");

        let signed = rpc
            .sign_raw_transaction_with_wallet(&inscription.commit_tx, None, None)
            .expect("sign commit");
        assert!(signed.complete, "commit signing incomplete");
        let commit_tx: Transaction =
            bitcoin::consensus::deserialize(&signed.hex).expect("deserialize signed commit");
        let commit_txid = rpc
            .send_raw_transaction(&commit_tx)
            .expect("send commit");
        let reveal_txid = rpc
            .send_raw_transaction(&inscription.reveal_tx)
            .expect("send reveal");
        (commit_txid, reveal_txid)
    }

    // ── live regtest tests ──────────────────────────────────────────────

    /// 1. Round trip: publish 3-member batch → mine → scan → all admitted.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_roundtrip_three_members() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let size_before = scanner.accumulator().nav().size;

        let sigs = signed_members(3, &unique_tag("roundtrip"));
        let members = batch_at_tip(&publisher, &sigs);
        let batch = publisher.publish(&members).expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm reveal");

        let report = scanner.scan_to_tip().expect("scan_to_tip");
        assert!(
            report.admitted_count >= 3,
            "expected ≥3 admissions, got {} (report: admitted={}, rejected={}, dups={})",
            report.admitted_count,
            report.admitted_count,
            report.rejected_count,
            report.duplicates
        );

        // Locate the three members of this batch in survivors.
        let mut found_positions = Vec::new();
        for (j, (pk, r)) in batch.aggregate.members.iter().enumerate() {
            let hit = scanner.survivors().iter().find(|n| n.pk == *pk && n.r == *r);
            let n = hit.unwrap_or_else(|| {
                panic!("member {j} pk/r not found in survivors after scan")
            });
            assert_eq!(n.chain_pos.member_index, j as u32);
            found_positions.push(n.chain_pos);
        }
        assert!(
            found_positions[0] < found_positions[1] && found_positions[1] < found_positions[2],
            "member order must follow payload order: {found_positions:?}"
        );

        // Log positions must be consecutive starting at size_before.
        let acc = scanner.accumulator();
        assert_eq!(acc.nav().size, size_before + 3);
        for (j, (pk, _)) in batch.aggregate.members.iter().enumerate() {
            match acc.lookup(*pk) {
                shared::spec_v1::LookupResult::Present { pos, r, .. } => {
                    assert_eq!(pos, size_before + j as u64);
                    assert_eq!(r, batch.aggregate.members[j].1);
                }
                shared::spec_v1::LookupResult::Absent => {
                    panic!("member {j} absent from accumulator")
                }
            }
        }
    }

    /// 2. First-occurrence / double-spend: second Pk with different R is ignored.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_first_occurrence_double_spend() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);

        let (first, second) = double_spend_pair(&unique_tag("doublespend"));
        assert_eq!(first.pk, second.pk);
        assert_ne!(first.r, second.r);

        let batch1 = publisher
            .publish(&batch_at_tip(&publisher, &[first]))
            .expect("publish first");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch1.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm first");
        let report1 = scanner.scan_to_tip().expect("scan first");
        assert!(report1.admitted_count >= 1);
        assert_eq!(
            scanner.accumulator().classify(first.pk, first.r),
            SpendClassification::ValidFirstSpend
        );

        let batch2 = publisher
            .publish(&batch_at_tip(&publisher, &[second]))
            .expect("publish second (same pk)");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch2.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm second");
        let report2 = scanner.scan_to_tip().expect("scan second");
        assert!(
            report2.duplicates >= 1,
            "second occurrence must be DuplicateIgnored, got duplicates={}",
            report2.duplicates
        );

        // Accumulator still holds the FIRST R.
        match scanner.accumulator().lookup(first.pk) {
            shared::spec_v1::LookupResult::Present { r, .. } => {
                assert_eq!(r, first.r, "first R must win");
            }
            shared::spec_v1::LookupResult::Absent => panic!("pk must be present"),
        }
        assert_eq!(
            scanner.accumulator().classify(second.pk, second.r),
            SpendClassification::RejectedDoubleSpend
        );
        assert_eq!(
            scanner.accumulator().classify(first.pk, first.r),
            SpendClassification::ValidFirstSpend
        );
    }

    /// 3. Anchor bound: equal-height / wrong-hash style violations are rejected.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_rejects_anchor_bound_violation() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);

        let sigs = signed_members(1, &unique_tag("anchor-bound"));
        // Build a valid aggregate, then set anchor height to tip+1 so that when
        // the reveal is mined into tip+1 the heights are equal → reject.
        let tip = publisher.current_anchor().expect("tip");
        let inclusion_height_target = tip.height.checked_add(1).expect("height+1");
        let mut agg = aggregate_sig_with_anchor(&sigs, tip).expect("aggregate");
        agg.block_anchor = BlockAnchor {
            block_hash: tip.block_hash, // deliberately wrong height identity
            height: inclusion_height_target,
        };
        let payload = agg.serialize();
        let bad_pk = sigs[0].pk;

        let (_commit, reveal) = broadcast_raw_payload(&payload);
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&reveal, 1, Duration::from_secs(30))
            .expect("confirm bad-anchor reveal");

        let report = scanner.scan_to_tip().expect("scan");
        assert!(
            report.rejected_count >= 1,
            "anchor-bound violation must be rejected, rejected_count={}",
            report.rejected_count
        );
        let reasons: Vec<&str> = report
            .blocks
            .iter()
            .flat_map(|b| b.rejected.iter().map(|r| r.reason.as_str()))
            .collect();
        assert!(
            reasons.iter().any(|r| {
                r.contains("strict ancestor")
                    || r.contains("equal")
                    || r.contains("MAX_ANCHOR_GAP")
                    || r.contains("canonical")
                    || r.contains("block_anchor")
            }),
            "expected anchor-bound rejection reason, got: {reasons:?}"
        );
        // This payload's members must not enter the log. (Global size may still
        // grow if leftover mempool inscriptions from earlier tests are mined
        // into the same block — only *this* payload is under assertion.)
        assert!(
            matches!(
                scanner.accumulator().lookup(bad_pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "bad-anchor payload pk must not be admitted"
        );
        assert!(
            !scanner.survivors().iter().any(|n| n.pk == bad_pk),
            "bad-anchor pk must not appear in survivors"
        );
    }

    /// 4. Bad signature: corrupted s_agg discards the whole aggregate.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_rejects_bad_signature() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let size_before = scanner.accumulator().nav().size;

        let sigs = signed_members(2, &unique_tag("badsig"));
        let tip = publisher.current_anchor().expect("tip");
        let mut agg = aggregate_sig_with_anchor(&sigs, tip).expect("aggregate");
        // Corrupt s_agg so aggregate_verify fails.
        if let Some(ref mut s) = agg.s_agg {
            s[0] ^= 0xff;
            s[15] ^= 0xaa;
        }
        // Ensure the payload still deserializes (canonical scalar may reject —
        // flip low bits that keep it a 32-byte field element on the wire).
        let payload = match agg.serialize() {
            p => p,
        };
        // serialize() validates canonical scalar; if corruption broke that,
        // rebuild with a still-canonical but wrong scalar.
        let payload = if AggregateStateNullifierV3::deserialize(&payload).is_err() {
            // Use a different valid scalar that fails the multi-scalar check.
            let mut s = [0u8; 32];
            s[31] = 1;
            agg.s_agg = Some(s);
            agg.serialize()
        } else {
            payload
        };

        let pks: Vec<_> = agg.members.iter().map(|(pk, _)| *pk).collect();
        let (_commit, reveal) = broadcast_raw_payload(&payload);
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&reveal, 1, Duration::from_secs(30))
            .expect("confirm bad-sig reveal");

        let report = scanner.scan_to_tip().expect("scan");
        assert!(
            report.rejected_count >= 1,
            "bad signature must reject, got rejected_count={}",
            report.rejected_count
        );
        let reasons: Vec<&str> = report
            .blocks
            .iter()
            .flat_map(|b| b.rejected.iter().map(|r| r.reason.as_str()))
            .collect();
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("aggregate_verify") || r.contains("verify") || r.contains("discarded")),
            "expected signature rejection, got: {reasons:?}"
        );
        assert_eq!(scanner.accumulator().nav().size, size_before);
        for pk in pks {
            assert!(
                matches!(
                    scanner.accumulator().lookup(pk),
                    shared::spec_v1::LookupResult::Absent
                ),
                "corrupted aggregate must contribute zero nullifiers"
            );
        }
    }

    /// Mine one **empty** block (coinbase only) via `generateblock`, so mempool
    /// txs (including previously-orphaned inscriptions) are **not** re-included.
    /// This is what makes a real reorg actually drop a nullifier rather than
    /// immediately re-admit it from the mempool.
    fn mine_empty_block(rpc: &Client) -> BlockHash {
        let network = rpc.get_blockchain_info().expect("chain").chain;
        let addr = rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("addr")
            .require_network(network)
            .expect("net");
        // generateblock "address" [] — empty tx list ⇒ coinbase only.
        let result: bitcoincore_rpc::jsonrpc::serde_json::Value = rpc
            .call(
                "generateblock",
                &[
                    bitcoincore_rpc::jsonrpc::serde_json::Value::String(addr.to_string()),
                    bitcoincore_rpc::jsonrpc::serde_json::Value::Array(vec![]),
                ],
            )
            .expect("generateblock empty");
        let hash_hex = result
            .get("hash")
            .and_then(|v| v.as_str())
            .expect("generateblock returns hash");
        hash_hex.parse().expect("parse block hash")
    }

    /// 5. Real reorg via invalidateblock + empty replacement blocks.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_real_reorg() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let size_before = scanner.accumulator().nav().size;
        let rpc = wallet_rpc();

        // Publish + mine a batch so it lands in the tip block.
        let sigs = signed_members(1, &unique_tag("reorg"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");
        let report1 = scanner.scan_to_tip().expect("scan after publish");
        assert!(
            report1.admitted_count >= 1,
            "fresh nullifier must be admitted; admitted={} rejected={} dups={} reasons={:?}",
            report1.admitted_count,
            report1.rejected_count,
            report1.duplicates,
            report1
                .blocks
                .iter()
                .flat_map(|b| b.rejected.iter().map(|r| r.reason.clone()))
                .collect::<Vec<_>>()
        );
        let pk = sigs[0].pk;
        let r_first = sigs[0].r;
        assert_eq!(
            scanner.accumulator().classify(pk, r_first),
            SpendClassification::ValidFirstSpend
        );
        let tip_after_scan = scanner.scanned_through().expect("scanned");
        let orphaned_hash = tip_after_scan.1;
        let orphaned_height = tip_after_scan.0;

        // Invalidate the tip (orphans the inscription block). The commit/reveal
        // return to the mempool — mine an **empty** replacement so they stay
        // off-chain (a normal generatetoaddress would re-include them and the
        // nullifier would not actually leave the canonical set).
        rpc.invalidate_block(&orphaned_hash)
            .expect("invalidateblock");
        let new_hash = mine_empty_block(&rpc);
        let live = rpc
            .get_block_hash(orphaned_height)
            .expect("getblockhash after reorg");
        assert_eq!(live, new_hash, "empty block must be the new tip at height");
        assert_ne!(live, orphaned_hash, "reorg must replace the block hash");

        let report2 = scanner.scan_to_tip().expect("scan after reorg");
        let reorg = report2
            .reorg
            .as_ref()
            .expect("reorg must be detected and reported");
        // The inscription was only one confirmation deep — not final (needs 6).
        // finality_broken should be false for a shallow reorg.
        assert!(
            !reorg.finality_broken,
            "shallow 1-conf reorg must not break finality; outcome={reorg:?}"
        );

        // After reorg the orphaned nullifier must be gone from the accumulator.
        assert!(
            matches!(
                scanner.accumulator().lookup(pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "orphaned nullifier must not remain in the accumulator"
        );
        assert_eq!(
            scanner.accumulator().nav().size,
            size_before,
            "accumulator must rewind to pre-inscription size"
        );

        // Stabilize the active chain for subsequent tests: mine one more empty
        // block so the orphaned fork is strictly shorter. Abandon the orphaned
        // commit/reveal in the wallet mempool so later tests' `generatetoaddress`
        // does not re-include them (which would re-admit the nullifier).
        let _ = mine_empty_block(&rpc);
        let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
            "abandontransaction",
            &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(
                batch.commit_txid.to_string(),
            )],
        );
        let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
            "abandontransaction",
            &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(
                batch.reveal_txid.to_string(),
            )],
        );
        let _ = scanner.scan_to_tip();
    }

    /// 6. Ordering: two batches in one block → log positions follow
    ///    (height, tx_index, vin_index, member_index).
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_ordering_two_batches_one_block() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let size_before = scanner.accumulator().nav().size;

        let sigs_a = signed_members(2, &unique_tag("order-a"));
        let sigs_b = signed_members(2, &unique_tag("order-b"));
        let batch_a = publisher
            .publish(&batch_at_tip(&publisher, &sigs_a))
            .expect("publish A");
        let batch_b = publisher
            .publish(&batch_at_tip(&publisher, &sigs_b))
            .expect("publish B");
        // Single mine so both land in the same block.
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_a.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm A");
        publisher
            .wait_for_confirmation(&batch_b.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm B");

        let report = scanner.scan_to_tip().expect("scan");
        assert!(
            report.admitted_count >= 4,
            "expected 4 admissions, got {}",
            report.admitted_count
        );

        // Resolve chain positions for all four members.
        let mut entries: Vec<(ChainPosition, [u8; 32])> = Vec::new();
        for (pk, r) in batch_a
            .aggregate
            .members
            .iter()
            .chain(batch_b.aggregate.members.iter())
        {
            let n = scanner
                .survivors()
                .iter()
                .find(|s| s.pk == *pk && s.r == *r)
                .unwrap_or_else(|| panic!("missing survivor for pk"));
            entries.push((n.chain_pos, *pk));
        }
        // Sort by chain position and verify it matches log order.
        entries.sort_by_key(|(pos, _)| *pos);
        for i in 0..entries.len().saturating_sub(1) {
            assert!(
                entries[i].0 < entries[i + 1].0,
                "positions must be strictly increasing: {:?} vs {:?}",
                entries[i].0,
                entries[i + 1].0
            );
        }
        // Same height for both batches.
        assert_eq!(entries[0].0.height, entries[3].0.height);
        // tx_index of the earlier-in-block reveal is smaller.
        // Members of the same payload share tx_index/vin_index and differ by member_index.
        let a0 = scanner
            .survivors()
            .iter()
            .find(|s| s.pk == sigs_a[0].pk)
            .expect("a0");
        let a1 = scanner
            .survivors()
            .iter()
            .find(|s| s.pk == sigs_a[1].pk)
            .expect("a1");
        assert_eq!(a0.chain_pos.tx_index, a1.chain_pos.tx_index);
        assert_eq!(a0.chain_pos.vin_index, a1.chain_pos.vin_index);
        assert_eq!(a0.chain_pos.member_index, 0);
        assert_eq!(a1.chain_pos.member_index, 1);
        assert!(a0.chain_pos < a1.chain_pos);

        // Accumulator log positions follow the same total order.
        let mut log_pairs = Vec::new();
        for (pos, pk) in &entries {
            match scanner.accumulator().lookup(*pk) {
                shared::spec_v1::LookupResult::Present {
                    pos: log_pos, ..
                } => log_pairs.push((*pos, log_pos)),
                shared::spec_v1::LookupResult::Absent => panic!("pk absent"),
            }
        }
        for i in 0..log_pairs.len().saturating_sub(1) {
            assert!(
                log_pairs[i].1 < log_pairs[i + 1].1,
                "log positions must increase with chain order"
            );
        }
        assert_eq!(scanner.accumulator().nav().size, size_before + 4);
    }
}
