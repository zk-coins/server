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
//!
//! # Governing principle
//!
//! The accumulator is a **pure function of the confirmed chain** given the pinned
//! network parameters. Two honest nodes at the same tip must produce
//! byte-identical logs. Therefore a failure that is not derivable from chain
//! data must **never** influence the accumulator:
//!
//! - **Data failures** (malformed envelope, invalid payload, anchor-bound
//!   violation, signature failure, missing vout on a resolved parent) are
//!   deterministic rejections: zero nullifiers, recorded reason, scan continues.
//! - **Infrastructure failures** (RPC error, timeout, lagging/missing `txindex`)
//!   abort the scan loudly at the failing block. Earlier blocks already
//!   committed in the same call remain durable (per-block atomicity); the
//!   failing block is not checkpointed, so retry resumes there.
//!
//! These are distinct types ([`DataFailure`] vs [`InfrastructureError`]); only
//! data failures can become a [`RejectedInscription`].
//!
//! # Chain-connectivity invariant
//!
//! The accumulator only ever reflects **one connected chain**. While scanning
//! forward, every block's `prev_blockhash` is checked against the previous
//! block's hash (or the recorded checkpoint). A mismatch stops the forward
//! advance and runs the reorg path. Any split of a scan into different call
//! granularities therefore yields the same accumulator on the same final chain.
//!
//! # Reorg atomicity invariant
//!
//! **Collection** of the entire replacement range into local state completes
//! before any mutation of `scanned_blocks`, `survivors`, `scanned_through`, or
//! the accumulator. Any failure during collection leaves the scanner exactly
//! as it was, so a retry starts from the same consistent point and cannot
//! permanently skip a replacement block's nullifiers.
//!
//! **Apply** after a successful collection: truncate + `reorg_replay` of the
//! retained prefix, then fold each replacement block via the same per-block
//! path as forward scanning. A failure mid-apply leaves the fork prefix and
//! any fully folded replacement blocks committed (per-block atomicity); retry
//! resumes from that checkpoint without re-mixing forks.
//!
//! # Per-block atomicity (forward scan)
//!
//! A single [`Scanner::scan_to_tip`] call is **not** all-or-nothing across
//! blocks. Each forward block is committed (folded + checkpointed) only after
//! it has been fully processed. An infrastructure failure aborts at the
//! failing block; earlier blocks committed in the same call remain durable.
//! Retry resumes at the failed block. When a call aborts after partial
//! progress, [`InfrastructureError::partial_report`] carries the committed
//! work so callers can observe what landed.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Transaction, TxIn, TxOut, Txid};
use bitcoincore_rpc::json::GetIndexInfoResult;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use shared::spec_v1::accumulator::ReorgOutcome;
use shared::spec_v1::network_params::NetworkParams;
use shared::spec_v1::tags::NETWORK_TAG_REGTEST;
#[cfg(test)]
use shared::spec_v1::tags::{NETWORK_TAG_MAINNET, NETWORK_TAG_TESTNET};
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

/// Number of verified block hashes retained for ancestry lookups
/// (`MAX_ANCHOR_GAP` ancestors plus the inclusion block itself).
const VERIFIED_CHAIN_CAPACITY: usize = (MAX_ANCHOR_GAP as usize) + 1;

/// OP_FALSE (`0x00`) followed by OP_IF (`0x63`) — the §3.5 envelope opener.
const ENVELOPE_OPENER: [u8; 2] = [0x00, 0x63];

/// Scanner configuration. Every field is mandatory — no silent defaults.
///
/// `activation_height` is a pinned consensus parameter (§3.6 "Scan origin").
/// It must equal [`NetworkParams::activation_height`] of the supplied
/// [`Self::network_params`]. [`Scanner::connect`] **rejects** disagreement;
/// it never silently substitutes the pinned value for a wrong configuration.
///
/// For **mainnet** and **testnet** the pin is deployment-observed and must be
/// supplied via `network_params` (there is no compile-time constant). For
/// **regtest** §3.6 pins `0` and connect enforces that.
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
    /// (§3.6 Scan origin). Consensus-critical; must equal
    /// `network_params.activation_height()`.
    pub activation_height: u64,
    /// Pinned network-parameter set (§3.6). Required for every network —
    /// never optional, never defaulted. Its `activation_height` is the
    /// consensus pin that [`Self::activation_height`] must match.
    pub network_params: NetworkParams,
}

/// Deterministic inscription rejection (a pure function of chain content).
///
/// Only this failure class may become a [`RejectedInscription`]. Infrastructure
/// failures use [`InfrastructureError`] and never flow through this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataFailure {
    /// Human-readable reason (parse / bound / signature / extract / missing vout).
    pub reason: String,
}

impl DataFailure {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Node-local infrastructure / environment failure.
///
/// Propagates out of [`Scanner::scan_to_tip`] as `Err`. Must never be recorded
/// as a rejection and must never be followed by checkpointing the **failing**
/// block. Earlier blocks already committed in the same call remain durable
/// (per-block atomicity); see [`InfrastructureError::partial_report`].
#[derive(Debug)]
pub struct InfrastructureError {
    message: String,
    /// Committed progress from the same `scan_to_tip` call before the abort,
    /// when any block was fully processed. `None` when nothing was committed.
    partial_report: Option<Box<ScanReport>>,
}

impl InfrastructureError {
    /// Infrastructure failure with no committed partial progress.
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            partial_report: None,
        }
    }

    /// Infrastructure failure after one or more blocks were committed this call.
    fn with_partial(message: impl Into<String>, report: ScanReport) -> Self {
        Self {
            message: message.into(),
            partial_report: Some(Box::new(report)),
        }
    }

    /// Committed [`ScanReport`] fragment from the aborted call, if any.
    pub fn partial_report(&self) -> Option<&ScanReport> {
        self.partial_report.as_deref()
    }
}

impl std::fmt::Display for InfrastructureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "scanner infrastructure failure: {}", self.message)
    }
}

impl std::error::Error for InfrastructureError {}

/// Internal operator error: data (per-input rejection) vs infrastructure (abort).
enum ScanOpError {
    Data(DataFailure),
    Infrastructure(InfrastructureError),
}

impl From<InfrastructureError> for ScanOpError {
    fn from(e: InfrastructureError) -> Self {
        ScanOpError::Infrastructure(e)
    }
}

impl From<DataFailure> for ScanOpError {
    fn from(e: DataFailure) -> Self {
        ScanOpError::Data(e)
    }
}

/// One inscription (or candidate input) rejected during a block scan.
///
/// Fail-closed: the input contributes zero nullifiers. The reason is always
/// recorded — nothing is dropped quietly. Constructed only from [`DataFailure`].
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

impl RejectedInscription {
    fn from_data(height: u64, tx_index: u32, vin_index: u32, failure: DataFailure) -> Self {
        Self {
            height,
            tx_index,
            vin_index,
            reason: failure.reason,
        }
    }
}

/// A first-occurrence loser: same `Pk` as an earlier admitted nullifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateNullifier {
    /// Chain position of the ignored (loser) nullifier.
    pub position: ChainPosition,
    /// Chain position of the first-occurrence winner this loser lost to.
    pub winner_position: ChainPosition,
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
    /// Every duplicate with its position and the winner it lost to.
    pub duplicate_details: Vec<DuplicateNullifier>,
}

/// Aggregate report for one [`Scanner::scan_to_tip`] call.
#[derive(Clone, Debug)]
pub struct ScanReport {
    /// First height scanned in this call, if any block was processed.
    pub from_height: Option<u64>,
    /// Last height scanned in this call, if any block was processed.
    pub to_height: Option<u64>,
    /// Tip height reflected by the scanner accumulator / checkpoint.
    ///
    /// When the scanner has scanned at least one block, this is
    /// [`Scanner::scanned_through`]'s height — never a live RPC tip the
    /// accumulator does not yet reflect. Only when nothing has ever been
    /// scanned (`scanned_through == None`) is the live RPC tip reported.
    pub tip_height: u64,
    /// Block hash paired with [`Self::tip_height`] under the same rule.
    pub tip_hash: BlockHash,
    /// Per-block results in ascending height order (forward scan **and**
    /// reorg-replacement blocks — nothing is dropped quietly).
    pub blocks: Vec<BlockScanResult>,
    /// Present when one or more reorgs were handled in this call.
    /// Outcomes are merged (sticky `finality_broken`, summed
    /// `displaced_final_count`) — a later shallow reorg never erases an
    /// earlier finality break. Callers MUST inspect `finality_broken`.
    pub reorg: Option<ReorgOutcome>,
    /// Sum of `inscriptions_seen` across blocks.
    pub inscriptions_seen: usize,
    /// Total first-occurrence admissions this call.
    pub admitted_count: usize,
    /// Total rejections this call.
    pub rejected_count: usize,
    /// Total duplicate-ignored folds this call.
    pub duplicates: usize,
    /// Every duplicate detail this call (positions + winner positions).
    pub duplicate_details: Vec<DuplicateNullifier>,
}

/// Path-A chain scanner: bitcoind RPC + in-memory nullifier accumulator.
pub struct Scanner {
    rpc: Client,
    config: ScannerConfig,
    accumulator: NfLogAccumulator,
    /// All signature-verified, bound-checked nullifiers in canonical order
    /// (including first-occurrence losers). Input for [`NfLogAccumulator::reorg_replay`].
    survivors: Vec<PublishedNullifier>,
    /// First-occurrence winner position per `Pk` among `survivors`.
    ///
    /// Maintained alongside `survivors` so duplicate handling is **O(1)** per
    /// repeated member rather than a linear scan of prior survivors
    /// (`Θ(D·S)` → `Θ(D + S)` over a stream of `S` survivors and `D` duplicates).
    /// Duplicates remain in `survivors` (a reorg can promote one to winner);
    /// this index only stores the current winner. Rebuilt from retained
    /// survivors on reorg apply.
    winner_by_pk: HashMap<[u8; 32], ChainPosition>,
    /// Highest fully-scanned height and its block hash at scan time.
    scanned_through: Option<(u64, BlockHash)>,
    /// Every height → hash observed while scanning (for reorg common-ancestor).
    scanned_blocks: BTreeMap<u64, BlockHash>,
    /// Per-scan-run cache of parent transactions for prevout resolution.
    ///
    /// Bound: at most one `getrawtransaction` per distinct parent `txid` per
    /// [`Scanner::scan_to_tip`] call (cleared at the start of each call). A
    /// transaction with many inputs spending the same parent therefore costs
    /// one RPC, not one per input.
    parent_tx_cache: HashMap<Txid, Transaction>,
    /// Hashes of the last [`VERIFIED_CHAIN_CAPACITY`] blocks this scanner has
    /// actually validated (via `prev_blockhash` linkage). Used for
    /// `block_anchor` ancestry checks relative to the inclusion block —
    /// **never** against the live tip. Front = oldest, back = newest.
    verified_chain: VecDeque<(u64, BlockHash)>,
    /// Ancestor walks keyed by the **descendant** (inclusion) block hash they
    /// were derived from. Maps `inclusion_hash → (height → hash)` for ancestors
    /// resolved by walking `prev_blockhash` from that inclusion block. An entry
    /// can never be reused under a different fork because the key is the
    /// inclusion block's own hash.
    ancestor_walk_cache: HashMap<BlockHash, BTreeMap<u64, BlockHash>>,
    /// Test seam: next prevout fetch fails as infrastructure (then clears).
    #[cfg(test)]
    inject_prevout_infra_failure: bool,
    /// Test seam: `fetch_block_linked` at this height fails as infrastructure.
    #[cfg(test)]
    inject_infra_fail_at_height: Option<u64>,
    /// Test seam: force `ChainBroken` during linked fetch at this height (one-shot).
    #[cfg(test)]
    inject_broken_link_at_height: Option<u64>,
    /// Test seam: after committing the forward block at this height, invalidate
    /// it and mine an empty replacement via RPC (one-shot).
    #[cfg(test)]
    inject_reorg_after_commit_height: Option<u64>,
    /// Test seam: after at least one block is committed this call, the next
    /// post-commit tip query (`getblockcount` / `getblockhash`) fails (one-shot).
    #[cfg(test)]
    inject_post_commit_rpc_failure: bool,
    /// Test counter: how many `getrawtransaction` RPCs this scan run issued.
    #[cfg(test)]
    prevout_rpc_count: usize,
    /// Test counter: how many O(1) winner-index lookups this scan run issued.
    #[cfg(test)]
    winner_index_lookups: usize,
    /// Test counter: how many `getblock` RPCs ancestry walks issued this run.
    #[cfg(test)]
    ancestor_walk_rpc_count: usize,
}

impl Scanner {
    /// Connect to bitcoind with cookie auth and verify the chain matches
    /// [`ScannerConfig::network`].
    ///
    /// Also enforces:
    /// - `activation_height` equals `network_params.activation_height()`
    ///   (§3.6 Scan origin — load the published pin and compare);
    /// - regtest pin is `0` (§3.6);
    /// - `txindex` is enabled **and** fully synchronized (`getindexinfo`).
    pub fn connect(config: ScannerConfig) -> Result<Self> {
        ensure!(
            !config.rpc_url.is_empty(),
            "ScannerConfig.rpc_url must not be empty"
        );
        ensure!(
            !config.cookie_path.as_os_str().is_empty(),
            "ScannerConfig.cookie_path must not be empty"
        );

        let pinned = config.network_params.activation_height();
        // §3.6: regtest activation_height is pinned at 0.
        if config.network == Network::Regtest {
            ensure!(
                pinned == 0,
                "ScannerConfig.network_params.activation_height {pinned} is not the \
                 §3.6 regtest pin (0) — refuse to start rather than fold a divergent log"
            );
        }
        ensure!(
            config.activation_height == pinned,
            "ScannerConfig.activation_height {} does not match network_params.activation_height {} \
             for {:?} (§3.6 Scan origin — refuse to start rather than fold a divergent log)",
            config.activation_height,
            pinned,
            config.network
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

        let index_info = rpc
            .get_index_info()
            .context("getindexinfo failed — cannot verify txindex readiness")?;
        ensure_txindex_ready(&index_info)?;

        let accumulator = NfLogAccumulator::new(config.activation_height);
        Ok(Self {
            rpc,
            config,
            accumulator,
            survivors: Vec::new(),
            winner_by_pk: HashMap::new(),
            scanned_through: None,
            scanned_blocks: BTreeMap::new(),
            parent_tx_cache: HashMap::new(),
            verified_chain: VecDeque::new(),
            ancestor_walk_cache: HashMap::new(),
            #[cfg(test)]
            inject_prevout_infra_failure: false,
            #[cfg(test)]
            inject_infra_fail_at_height: None,
            #[cfg(test)]
            inject_broken_link_at_height: None,
            #[cfg(test)]
            inject_reorg_after_commit_height: None,
            #[cfg(test)]
            inject_post_commit_rpc_failure: false,
            #[cfg(test)]
            prevout_rpc_count: 0,
            #[cfg(test)]
            winner_index_lookups: 0,
            #[cfg(test)]
            ancestor_walk_rpc_count: 0,
        })
    }

    /// Scan forward from the last scanned block to the current chain tip.
    ///
    /// Before scanning forward, verifies the previously scanned tip is still
    /// canonical. On reorg: finds the highest common ancestor, drops survivors
    /// above it, re-collects nullifiers on the new canonical fork, and calls
    /// [`NfLogAccumulator::reorg_replay`] then folds replacement blocks.
    /// `ReorgOutcome::finality_broken` is surfaced in the report — never
    /// swallowed. Multiple reorgs in one call are merged (sticky finality).
    ///
    /// While scanning forward, verifies each block links to the previous one
    /// (`prev_blockhash`). On mismatch the reorg path runs instead of mixing
    /// forks into the accumulator.
    ///
    /// # Per-block atomicity
    ///
    /// Each forward block is fully processed and checkpointed, or not at all.
    /// An infrastructure failure aborts at the failing block; earlier commits
    /// from this call remain. Retry resumes at the failed block. On abort after
    /// partial progress, the error is [`InfrastructureError`] with
    /// [`InfrastructureError::partial_report`] set.
    ///
    /// # Tip reporting
    ///
    /// `tip_height` / `tip_hash` always reflect the accumulator checkpoint
    /// (`scanned_through`) when any block has been scanned — never a live RPC
    /// tip the accumulator does not reflect.
    pub fn scan_to_tip(&mut self) -> Result<ScanReport> {
        // Fresh per-run parent cache. Verified-chain history and ancestor-walk
        // cache are fork-keyed / linkage-verified and survive across calls;
        // reorg handling truncates / clears them explicitly.
        self.parent_tx_cache.clear();
        #[cfg(test)]
        {
            self.prevout_rpc_count = 0;
            self.winner_index_lookups = 0;
            self.ancestor_walk_rpc_count = 0;
        }

        // Single accumulator for committed work this call. Every error exit
        // after the first committed block attaches a partial report from this
        // state — newly added RPC call sites cannot forget it.
        let mut acc = ScanCallAccumulator::new();

        // May need more than one pass: a mid-scan chain break re-runs reorg then
        // continues forward from the repaired checkpoint.
        loop {
            let reorg_result = self.detect_and_handle_reorg();
            let (reorg_outcome, reorg_blocks) = match reorg_result {
                Ok(v) => v,
                Err(e) => return Err(acc.fail_err(e, self.scanned_through)),
            };
            if let Some(outcome) = reorg_outcome {
                merge_reorg_outcome(&mut acc.reorg, outcome);
            }
            for result in reorg_blocks {
                acc.push_block(result)?;
            }

            let tip_height = match self.rpc_get_block_count_post_commit(&acc, "getblockcount") {
                Ok(h) => h,
                Err(e) => return Err(e),
            };

            let start = match self.scanned_through {
                Some((h, _)) => h
                    .checked_add(1)
                    .context("scanned height + 1 overflowed u64")
                    .map_err(|e| acc.fail_err(e, self.scanned_through))?,
                None => self.config.activation_height,
            };

            // Expected prev hash: recorded checkpoint, or none at the absolute start.
            let mut expected_prev: Option<BlockHash> = self.scanned_through.map(|(_, h)| h);

            let mut chain_broke_at: Option<u64> = None;
            if start <= tip_height {
                for height in start..=tip_height {
                    let scan_result = self.scan_block_linked(height, expected_prev);
                    match scan_result {
                        Ok(ScanBlockOutcome::Scanned(result)) => {
                            expected_prev = Some(result.block_hash);
                            acc.push_block(result)?;
                        }
                        Ok(ScanBlockOutcome::ChainBroken) => {
                            // Stop advancing; re-enter so the reorg path can
                            // repair state, then continue on the new fork.
                            chain_broke_at = Some(height);
                            break;
                        }
                        Err(e) => return Err(acc.fail_err(e, self.scanned_through)),
                    }
                }
            }

            if let Some(broke_height) = chain_broke_at {
                // Ensure the next loop iteration actually changes something.
                // If our checkpoint is still the live hash at that height, the
                // link break is an inconsistent tip view — fail loud rather
                // than spin forever.
                if let Some((scanned_h, scanned_hash)) = self.scanned_through {
                    let live = match self.rpc_get_block_hash_post_commit(
                        &acc,
                        scanned_h,
                        &format!(
                            "getblockhash({scanned_h}) after chain break at {broke_height}"
                        ),
                    ) {
                        Ok(h) => h,
                        Err(e) => return Err(e),
                    };
                    if live == scanned_hash {
                        return Err(acc.fail_msg(
                            format!(
                                "chain link broken at height {broke_height}: block prev_blockhash \
                                 does not match checkpoint {scanned_hash} at height {scanned_h}, \
                                 yet that checkpoint is still the live canonical hash — refuse to \
                                 mix forks or spin"
                            ),
                            self.scanned_through,
                        ));
                    }
                }
                continue;
            }

            // Tip must match the accumulator: never report a live tip the
            // scanner has not fully reflected.
            let live_tip = match self.rpc_get_block_count_post_commit(
                &acc,
                "getblockcount (post-scan tip re-read)",
            ) {
                Ok(h) => h,
                Err(e) => return Err(e),
            };
            if let Some((scanned_h, _)) = self.scanned_through {
                if scanned_h < live_tip {
                    // New blocks appeared after the forward pass — continue.
                    continue;
                }
                let live_hash = match self.rpc_get_block_hash_post_commit(
                    &acc,
                    scanned_h,
                    &format!("getblockhash({scanned_h}) post-scan tip check"),
                ) {
                    Ok(h) => h,
                    Err(e) => return Err(e),
                };
                let scanned_hash = self.scanned_through.map(|(_, h)| h).ok_or_else(|| {
                    anyhow!(
                        "internal: scanned_through became None during post-scan tip check \
                         at height {scanned_h}"
                    )
                })?;
                if live_hash != scanned_hash {
                    // Reorg under us after the forward pass — repair next loop.
                    continue;
                }
            }

            let (report_tip_height, report_tip_hash) = match self.scanned_through {
                Some((h, hash)) => (h, hash),
                None => {
                    let tip_hash = match self.rpc_get_block_hash_post_commit(
                        &acc,
                        live_tip,
                        &format!("getblockhash({live_tip})"),
                    ) {
                        Ok(h) => h,
                        Err(e) => return Err(e),
                    };
                    (live_tip, tip_hash)
                }
            };

            return Ok(acc.into_report(report_tip_height, report_tip_hash));
        }
    }

    /// `getblockcount` that attaches a partial report when this call already
    /// committed work (structural post-commit error path).
    fn rpc_get_block_count_post_commit(
        &mut self,
        acc: &ScanCallAccumulator,
        context: &str,
    ) -> Result<u64> {
        #[cfg(test)]
        if self.inject_post_commit_rpc_failure && acc.has_committed() {
            self.inject_post_commit_rpc_failure = false;
            return Err(acc.fail_msg(
                format!("injected post-commit RPC failure: {context}"),
                self.scanned_through,
            ));
        }
        self.rpc.get_block_count().map_err(|e| {
            acc.fail_msg(
                format!("{context} failed: {e}"),
                self.scanned_through,
            )
        })
    }

    /// `getblockhash` that attaches a partial report when this call already
    /// committed work (structural post-commit error path).
    fn rpc_get_block_hash_post_commit(
        &mut self,
        acc: &ScanCallAccumulator,
        height: u64,
        context: &str,
    ) -> Result<BlockHash> {
        #[cfg(test)]
        if self.inject_post_commit_rpc_failure && acc.has_committed() {
            self.inject_post_commit_rpc_failure = false;
            return Err(acc.fail_msg(
                format!("injected post-commit RPC failure: {context}"),
                self.scanned_through,
            ));
        }
        self.rpc.get_block_hash(height).map_err(|e| {
            acc.fail_msg(
                format!("{context}: {e}"),
                self.scanned_through,
            )
        })
    }

    /// Test seam: after committing ≥1 block this call, the next post-commit
    /// tip RPC fails with a partial report (one-shot).
    #[cfg(test)]
    pub fn inject_post_commit_rpc_failure(&mut self) {
        self.inject_post_commit_rpc_failure = true;
    }

    /// Test observation: O(1) winner-index lookups this scan run.
    #[cfg(test)]
    pub fn winner_index_lookups(&self) -> usize {
        self.winner_index_lookups
    }

    /// Test observation: ancestry-walk `getblock` RPCs this scan run.
    #[cfg(test)]
    pub fn ancestor_walk_rpc_count(&self) -> usize {
        self.ancestor_walk_rpc_count
    }

    /// Test observation: verified-chain history length.
    #[cfg(test)]
    pub fn verified_chain_len(&self) -> usize {
        self.verified_chain.len()
    }

    /// Test observation: winner index size.
    #[cfg(test)]
    pub fn winner_index_len(&self) -> usize {
        self.winner_by_pk.len()
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

    /// Test seam: next prevout fetch aborts as infrastructure failure.
    #[cfg(test)]
    pub fn inject_next_prevout_infra_failure(&mut self) {
        self.inject_prevout_infra_failure = true;
    }

    /// Test seam: fetching/collecting the block at `height` aborts as infrastructure.
    #[cfg(test)]
    pub fn inject_infra_fail_at_height(&mut self, height: u64) {
        self.inject_infra_fail_at_height = Some(height);
    }

    /// Test seam: force a chain-link break at `height` (one-shot) during linked fetch.
    #[cfg(test)]
    pub fn inject_broken_link_at_height(&mut self, height: u64) {
        self.inject_broken_link_at_height = Some(height);
    }

    /// Test seam: after committing the forward block at `height`, invalidate it
    /// and mine an empty replacement (one-shot).
    #[cfg(test)]
    pub fn inject_reorg_after_commit_height(&mut self, height: u64) {
        self.inject_reorg_after_commit_height = Some(height);
    }

    /// Test observation: `getrawtransaction` RPC count for the current/last scan run.
    #[cfg(test)]
    pub fn prevout_rpc_count(&self) -> usize {
        self.prevout_rpc_count
    }
}

/// Per-`scan_to_tip` accumulator of committed block reports.
///
/// Centralises partial-report construction so every error path after the first
/// committed block attaches the same report — newly added RPC call sites cannot
/// forget it. Rule: work already committed to the accumulator is always reported.
struct ScanCallAccumulator {
    blocks: Vec<BlockScanResult>,
    inscriptions_seen: usize,
    admitted_count: usize,
    rejected_count: usize,
    duplicates: usize,
    duplicate_details: Vec<DuplicateNullifier>,
    from_height: Option<u64>,
    to_height: Option<u64>,
    reorg: Option<ReorgOutcome>,
}

impl ScanCallAccumulator {
    fn new() -> Self {
        Self {
            blocks: Vec::new(),
            inscriptions_seen: 0,
            admitted_count: 0,
            rejected_count: 0,
            duplicates: 0,
            duplicate_details: Vec::new(),
            from_height: None,
            to_height: None,
            reorg: None,
        }
    }

    fn has_committed(&self) -> bool {
        !self.blocks.is_empty()
    }

    fn push_block(&mut self, result: BlockScanResult) -> Result<()> {
        self.inscriptions_seen = self
            .inscriptions_seen
            .checked_add(result.inscriptions_seen)
            .context("inscriptions_seen overflow")?;
        self.admitted_count = self
            .admitted_count
            .checked_add(result.admitted.len())
            .context("admitted_count overflow")?;
        self.rejected_count = self
            .rejected_count
            .checked_add(result.rejected.len())
            .context("rejected_count overflow")?;
        self.duplicates = self
            .duplicates
            .checked_add(result.duplicates)
            .context("duplicates overflow")?;
        self.duplicate_details
            .extend(result.duplicate_details.iter().cloned());
        if self.from_height.is_none() {
            self.from_height = Some(result.height);
        }
        self.to_height = Some(result.height);
        self.blocks.push(result);
        Ok(())
    }

    fn to_report(&self, tip_height: u64, tip_hash: BlockHash) -> ScanReport {
        ScanReport {
            from_height: self.from_height,
            to_height: self.to_height,
            tip_height,
            tip_hash,
            blocks: self.blocks.clone(),
            reorg: self.reorg.clone(),
            inscriptions_seen: self.inscriptions_seen,
            admitted_count: self.admitted_count,
            rejected_count: self.rejected_count,
            duplicates: self.duplicates,
            duplicate_details: self.duplicate_details.clone(),
        }
    }

    fn into_report(self, tip_height: u64, tip_hash: BlockHash) -> ScanReport {
        ScanReport {
            from_height: self.from_height,
            to_height: self.to_height,
            tip_height,
            tip_hash,
            blocks: self.blocks,
            reorg: self.reorg,
            inscriptions_seen: self.inscriptions_seen,
            admitted_count: self.admitted_count,
            rejected_count: self.rejected_count,
            duplicates: self.duplicates,
            duplicate_details: self.duplicate_details,
        }
    }

    /// Attach a partial report when any block was committed; otherwise pass through.
    fn fail_err(
        &self,
        err: impl Into<anyhow::Error>,
        scanned_through: Option<(u64, BlockHash)>,
    ) -> anyhow::Error {
        let err = err.into();
        if !self.has_committed() {
            return err;
        }
        let (tip_h, tip_hash) = match scanned_through {
            Some(v) => v,
            None => {
                return anyhow!(
                    "internal: blocks committed this call but scanned_through is None \
                     while attaching partial report: {err:#}"
                );
            }
        };
        InfrastructureError::with_partial(format!("{err:#}"), self.to_report(tip_h, tip_hash))
            .into()
    }

    /// Infrastructure failure, with partial report when committed work exists.
    fn fail_msg(
        &self,
        message: impl Into<String>,
        scanned_through: Option<(u64, BlockHash)>,
    ) -> anyhow::Error {
        let message = message.into();
        if !self.has_committed() {
            return InfrastructureError::new(message).into();
        }
        let (tip_h, tip_hash) = match scanned_through {
            Some(v) => v,
            None => {
                return anyhow!(
                    "internal: blocks committed this call but scanned_through is None \
                     while attaching partial report: {message}"
                );
            }
        };
        InfrastructureError::with_partial(message, self.to_report(tip_h, tip_hash)).into()
    }
}

/// Merge a reorg outcome into an accumulator of outcomes for one scan call.
///
/// Sticky finality: once `finality_broken` is true it stays true.
/// `displaced_final_count` is summed with checked arithmetic (fail-loud on overflow).
///
/// Returns `Some(ReorgOutcome{...})` in `acc` after the first merge; subsequent
/// calls update that value in place.
pub fn merge_reorg_outcome(acc: &mut Option<ReorgOutcome>, next: ReorgOutcome) {
    match acc {
        None => *acc = Some(next),
        Some(existing) => {
            existing.finality_broken |= next.finality_broken;
            existing.displaced_final_count = existing
                .displaced_final_count
                .checked_add(next.displaced_final_count)
                .expect(
                    "displaced_final_count overflow while merging reorg outcomes — refuse to wrap",
                );
        }
    }
}

/// Maximum times the reorg path may abandon a replacement collection and
/// restart from the current chain tip after a mid-collection linkage break.
const MAX_REORG_COLLECTION_RESTARTS: u32 = 16;

// ── §3.6 pure helpers (unit-testable without bitcoind) ───────────────────

/// §3.6-pinned [`NetworkParams`] for regtest (`activation_height = 0`).
///
/// Circuit digests and bootstrap pubkey are zero placeholders — only the
/// activation-height pin is consensus-critical for the scanner gate. Mainnet
/// and testnet must be constructed by the deployer from the published
/// `network-params.json`; they are never invented here.
pub fn regtest_network_params() -> Result<NetworkParams> {
    let tag = std::str::from_utf8(NETWORK_TAG_REGTEST)
        .context("NETWORK_TAG_REGTEST is not valid UTF-8")?
        .to_string();
    NetworkParams::new(
        tag,
        [0u8; 32],
        [0u8; 32],
        0, // §3.6: regtest activation_height = 0
        6,
        [0u8; 32],
    )
    .map_err(|e| anyhow!("internal: regtest NetworkParams construction failed: {e}"))
}

/// Activation height from supplied [`NetworkParams`], with the §3.6 regtest pin
/// check. Mainnet/testnet use the parameter set as-is — no compile-time constant.
pub fn pinned_activation_height(network: Network, params: &NetworkParams) -> Result<u64> {
    let h = params.activation_height();
    match network {
        Network::Regtest => {
            ensure!(
                h == 0,
                "regtest NetworkParams.activation_height must be 0 per §3.6, got {h}"
            );
            Ok(0)
        }
        Network::Mainnet | Network::Testnet => Ok(h),
    }
}

/// Require `txindex` enabled and fully synchronized (`getindexinfo`).
///
/// A scanner that cannot resolve prevouts cannot produce a correct accumulator,
/// so it must refuse to start rather than produce a wrong one.
pub fn ensure_txindex_ready(index_info: &GetIndexInfoResult) -> Result<()> {
    match &index_info.txindex {
        None => bail!(
            "txindex is not enabled (getindexinfo.txindex is absent); \
             scanner requires txindex=1 and a fully synchronized index"
        ),
        Some(status) if !status.synced => bail!(
            "txindex is enabled but not fully synchronized \
             (synced=false, best_block_height={}); refuse to start",
            status.best_block_height
        ),
        Some(_) => Ok(()),
    }
}

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
/// `ancestor_hash_at_anchor` is the hash of the block at `anchor.height` on
/// the **inclusion block's own ancestor chain** (not the live tip), under the
/// normative byte order ([`BlockHash::to_byte_array`]).
///
/// Rejects when:
/// 1. `anchor.height >= inclusion_height` (not a strict ancestor by height);
/// 2. `inclusion_height - anchor.height > MAX_ANCHOR_GAP`;
/// 3. `anchor.block_hash != ancestor_hash_at_anchor` (not an ancestor of the
///    inclusion block).
pub fn evaluate_anchor_bound(
    anchor: &BlockAnchor,
    inclusion_height: u64,
    ancestor_hash_at_anchor: [u8; 32],
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
    if anchor.block_hash != ancestor_hash_at_anchor {
        return Err(format!(
            "block_anchor.block_hash is not an ancestor of the inclusion block at \
             height {anchor_height} (anchor names a hash that is not on the \
             inclusion block's chain)"
        ));
    }
    Ok(())
}

// ── internal scanning ───────────────────────────────────────────────────

/// Outcome of attempting to scan one forward block under chain-link checks.
enum ScanBlockOutcome {
    Scanned(BlockScanResult),
    /// `prev_blockhash` did not match the expected parent — stop and reorg.
    ChainBroken,
}

/// A block fetched via RPC and verified against the expected parent hash.
struct LinkedFetch {
    height: u64,
    block_hash: BlockHash,
    block: Block,
}

/// Result of [`Scanner::fetch_block_linked`]: linked block or chain break.
enum LinkedFetchOutcome {
    Linked(LinkedFetch),
    /// `prev_blockhash` mismatch (or test-injected break) — do not fold.
    ChainBroken,
}

/// Collected replacement-block data before the reorg path mutates scanner state.
struct CollectedBlock {
    height: u64,
    block_hash: BlockHash,
    verified: Vec<PublishedNullifier>,
    rejected: Vec<RejectedInscription>,
    inscriptions_seen: usize,
}

impl Scanner {
    /// Detect a reorg against the recorded tip and, if needed, atomically
    /// collect + apply the replacement range.
    ///
    /// # Atomicity invariant
    ///
    /// **Collection** of every replacement block into local state completes
    /// **before** any mutation of `scanned_blocks`, `survivors`,
    /// `scanned_through`, or the accumulator. Failure during collection leaves
    /// the scanner exactly as it was so a retry starts from the same point
    /// and cannot permanently skip a replacement block's nullifiers.
    ///
    /// **Apply** truncates to the fork, replays the retained stream, then folds
    /// each collected block with the shared forward fold helper (real
    /// admissions/duplicates). Mid-apply failure leaves already-folded
    /// replacement blocks committed; retry continues from that checkpoint.
    ///
    /// # Anchor ancestry on reorg
    ///
    /// Anchor admissibility is a pure function of the inclusion block and its
    /// ancestors (never the live tip). On reorg detection the ancestor-walk
    /// cache is cleared (keys are inclusion hashes of the orphaned view) and
    /// `verified_chain` is truncated to the fork before APPLY. Replacement
    /// blocks resolve anchors by walking `prev_blockhash` from the inclusion
    /// block itself.
    ///
    /// # Replacement linkage
    ///
    /// Each collected replacement block is chain-linked via
    /// [`Self::fetch_block_linked`]. A mid-collection linkage break abandons
    /// the entire collection (no APPLY) and restarts from the current chain
    /// state, bounded by [`MAX_REORG_COLLECTION_RESTARTS`].
    fn detect_and_handle_reorg(
        &mut self,
    ) -> Result<(Option<ReorgOutcome>, Vec<BlockScanResult>)> {
        let mut restarts = 0u32;
        loop {
            let Some((scanned_h, scanned_hash)) = self.scanned_through else {
                return Ok((None, Vec::new()));
            };

            let tip = self.rpc.get_block_count().map_err(|e| {
                InfrastructureError::new(format!("getblockcount during reorg check: {e}"))
            })?;

            let still_canonical = if scanned_h > tip {
                false
            } else {
                match self.rpc.get_block_hash(scanned_h) {
                    Ok(live) => live == scanned_hash,
                    // Cannot tell whether the tip is canonical — abort, do not
                    // treat an RPC failure as "reorg happened".
                    Err(e) => {
                        return Err(InfrastructureError::new(format!(
                            "getblockhash({scanned_h}) during reorg check: {e}"
                        ))
                        .into());
                    }
                }
            };
            if still_canonical {
                return Ok((None, Vec::new()));
            }

            // Finding 1: clear inclusion-keyed ancestor walks the moment reorg
            // is detected — BEFORE any replacement-block validation. Verified
            // chain history is truncated at APPLY (after fork is known).
            self.ancestor_walk_cache.clear();

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
                    Ok(_) => continue,
                    Err(e) => {
                        return Err(InfrastructureError::new(format!(
                            "getblockhash({height}) while finding common ancestor: {e}"
                        ))
                        .into());
                    }
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

            let rescan_from = match fork_height {
                Some(fork) => fork
                    .checked_add(1)
                    .context("fork height + 1 overflowed")?,
                None => self.config.activation_height,
            };
            let recollect_through = tip.min(old_tip_height);

            // ── COLLECT (no scanner-state mutation yet) ──────────────────
            // First block links to the fork point; subsequent blocks chain.
            let mut expected_prev: Option<BlockHash> = match fork_height {
                Some(fork) => Some(
                    *self.scanned_blocks.get(&fork).ok_or_else(|| {
                        anyhow!("internal: missing scanned hash at fork {fork}")
                    })?,
                ),
                // From activation: no parent link required for the first block.
                None => None,
            };

            let mut collected: Vec<CollectedBlock> = Vec::new();
            let mut collection_restart = false;
            if rescan_from <= recollect_through {
                for height in rescan_from..=recollect_through {
                    match self.fetch_block_linked(height, expected_prev)? {
                        LinkedFetchOutcome::ChainBroken => {
                            // Abandon entire collection (no APPLY); restart from
                            // current chain state. Scanner state untouched.
                            collection_restart = true;
                            break;
                        }
                        LinkedFetchOutcome::Linked(fetch) => {
                            let (verified, rejected, inscriptions_seen) = self
                                .collect_block_nullifiers_from(height, &fetch.block)?;
                            expected_prev = Some(fetch.block_hash);
                            collected.push(CollectedBlock {
                                height: fetch.height,
                                block_hash: fetch.block_hash,
                                verified,
                                rejected,
                                inscriptions_seen,
                            });
                        }
                    }
                }
            }

            if collection_restart {
                restarts = restarts.checked_add(1).context("reorg restart counter overflow")?;
                if restarts > MAX_REORG_COLLECTION_RESTARTS {
                    return Err(InfrastructureError::new(format!(
                        "reorg replacement collection exceeded MAX_REORG_COLLECTION_RESTARTS \
                         ({MAX_REORG_COLLECTION_RESTARTS}) after mid-collection chain breaks"
                    ))
                    .into());
                }
                // Re-read chain state from the top of the loop.
                continue;
            }

            // ── APPLY (single atomic step after full collection succeeded) ─
            // Ancestor-walk cache already cleared at reorg detection (Finding 1).

            // 1–3: retain survivors, replay retained stream, rebuild winner index.
            let outcome = self
                .accumulator
                .reorg_replay(old_tip_height, retained.clone())
                .map_err(|e| anyhow!("accumulator reorg_replay failed: {e}"))?;
            self.survivors = retained;
            self.rebuild_winner_index();

            // 4: truncate checkpoints and verified-chain history to fork.
            self.scanned_blocks
                .retain(|&h, _| fork_height.map(|fork| h <= fork).unwrap_or(false));
            self.verified_chain
                .retain(|(h, _)| fork_height.map(|fork| *h <= fork).unwrap_or(false));
            self.scanned_through = match fork_height {
                Some(fork) => {
                    let hash = *self.scanned_blocks.get(&fork).ok_or_else(|| {
                        anyhow!("internal: missing scanned hash at fork {fork}")
                    })?;
                    Some((fork, hash))
                }
                None => None,
            };

            // 5: fold each collected block (real admissions / duplicates).
            let mut block_reports = Vec::new();
            for block in collected {
                let (admitted, duplicates, duplicate_details) =
                    self.fold_verified_nullifiers(&block.verified)?;
                self.scanned_blocks.insert(block.height, block.block_hash);
                self.scanned_through = Some((block.height, block.block_hash));
                self.record_verified_block(block.height, block.block_hash);
                block_reports.push(BlockScanResult {
                    height: block.height,
                    block_hash: block.block_hash,
                    inscriptions_seen: block.inscriptions_seen,
                    rejected: block.rejected,
                    admitted,
                    duplicates,
                    duplicate_details,
                });
            }

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

            return Ok((Some(outcome), block_reports));
        }
    }

    /// Fetch a block at `height` and verify its `prev_blockhash` link.
    ///
    /// Returns [`LinkedFetchOutcome::ChainBroken`] on parent mismatch (do not
    /// fold). Infrastructure failures (RPC, injected) return `Err`.
    ///
    /// Honours `inject_infra_fail_at_height` and `inject_broken_link_at_height`
    /// on entry (test seams).
    fn fetch_block_linked(
        &mut self,
        height: u64,
        expected_prev: Option<BlockHash>,
    ) -> Result<LinkedFetchOutcome> {
        #[cfg(test)]
        if self.inject_infra_fail_at_height == Some(height) {
            self.inject_infra_fail_at_height = None;
            return Err(InfrastructureError::new(format!(
                "injected infrastructure failure at height {height}"
            ))
            .into());
        }

        #[cfg(test)]
        if self.inject_broken_link_at_height == Some(height) {
            self.inject_broken_link_at_height = None;
            return Ok(LinkedFetchOutcome::ChainBroken);
        }

        let block_hash = self.rpc.get_block_hash(height).map_err(|e| {
            InfrastructureError::new(format!("getblockhash({height}): {e}"))
        })?;
        let block: Block = self.rpc.get_block(&block_hash).map_err(|e| {
            InfrastructureError::new(format!("getblock({block_hash}): {e}"))
        })?;

        if let Some(expected) = expected_prev {
            if block.header.prev_blockhash != expected {
                // Distinct from infrastructure: connected-chain mismatch.
                return Ok(LinkedFetchOutcome::ChainBroken);
            }
        }

        Ok(LinkedFetchOutcome::Linked(LinkedFetch {
            height,
            block_hash,
            block,
        }))
    }

    /// Scan one block after verifying its `prev_blockhash` link.
    fn scan_block_linked(
        &mut self,
        height: u64,
        expected_prev: Option<BlockHash>,
    ) -> Result<ScanBlockOutcome> {
        match self.fetch_block_linked(height, expected_prev)? {
            LinkedFetchOutcome::ChainBroken => Ok(ScanBlockOutcome::ChainBroken),
            LinkedFetchOutcome::Linked(fetch) => {
                let result =
                    self.scan_block_contents(fetch.height, fetch.block_hash, &fetch.block)?;
                Ok(ScanBlockOutcome::Scanned(result))
            }
        }
    }

    /// Fold verified nullifiers into the accumulator and append them to
    /// `survivors`. Shared by the forward path and reorg APPLY after truncate.
    ///
    /// Duplicate winner lookup is **O(1)** via `winner_by_pk` (not a linear
    /// scan of prior survivors). Complexity over a stream of `S` survivors
    /// and `D` duplicates: `Θ(S + D)` total, not `Θ(D·S)`.
    ///
    /// Returns `(admitted, duplicates, duplicate_details)`.
    fn fold_verified_nullifiers(
        &mut self,
        verified: &[PublishedNullifier],
    ) -> Result<(
        Vec<(ChainPosition, u64)>,
        usize,
        Vec<DuplicateNullifier>,
    )> {
        let mut admitted = Vec::new();
        let mut duplicates = 0usize;
        let mut duplicate_details = Vec::new();

        // §3.6 steps 4–5: fold in strictly ascending ChainPosition order.
        for nf in verified {
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
                    // First occurrence: record winner position for O(1) duplicate lookup.
                    if self.winner_by_pk.insert(nf.pk, nf.chain_pos).is_some() {
                        bail!(
                            "Appended nullifier but pk already present in winner_by_pk \
                             (internal invariant broken) at {:?}",
                            nf.chain_pos
                        );
                    }
                    admitted.push((nf.chain_pos, pos));
                }
                FoldOutcome::DuplicateIgnored => {
                    duplicates = duplicates
                        .checked_add(1)
                        .context("duplicates counter overflow")?;
                    #[cfg(test)]
                    {
                        self.winner_index_lookups =
                            self.winner_index_lookups.saturating_add(1);
                    }
                    let winner_position =
                        self.winner_by_pk.get(&nf.pk).copied().ok_or_else(|| {
                            anyhow!(
                                "DuplicateIgnored for pk but no winner in winner_by_pk \
                                 (internal invariant broken) at {:?}",
                                nf.chain_pos
                            )
                        })?;
                    duplicate_details.push(DuplicateNullifier {
                        position: nf.chain_pos,
                        winner_position,
                    });
                }
                FoldOutcome::BelowActivationHeight => {
                    bail!(
                        "fold returned BelowActivationHeight at height {} \
                         (activation_height={}); scanner must not scan below activation",
                        nf.chain_pos.height,
                        self.config.activation_height
                    );
                }
            }
            // Keep duplicates in survivors — a reorg can promote one to winner.
            self.survivors.push(*nf);
        }

        Ok((admitted, duplicates, duplicate_details))
    }

    /// Rebuild `winner_by_pk` from `survivors` in canonical order (first occurrence wins).
    fn rebuild_winner_index(&mut self) {
        self.winner_by_pk.clear();
        for nf in &self.survivors {
            self.winner_by_pk.entry(nf.pk).or_insert(nf.chain_pos);
        }
    }

    /// Record a validated block in the verified-chain ancestry window.
    fn record_verified_block(&mut self, height: u64, hash: BlockHash) {
        self.verified_chain.push_back((height, hash));
        while self.verified_chain.len() > VERIFIED_CHAIN_CAPACITY {
            self.verified_chain.pop_front();
        }
    }

    /// Fold verified nullifiers from an already-fetched, chain-linked block.
    ///
    /// Collect + fold + checkpoint. On success the block is fully committed
    /// (per-block atomicity).
    fn scan_block_contents(
        &mut self,
        height: u64,
        block_hash: BlockHash,
        block: &Block,
    ) -> Result<BlockScanResult> {
        let (verified, rejected, inscriptions_seen) =
            self.collect_block_nullifiers_from(height, block)?;

        let (admitted, duplicates, duplicate_details) =
            self.fold_verified_nullifiers(&verified)?;

        self.scanned_blocks.insert(height, block_hash);
        self.scanned_through = Some((height, block_hash));
        self.record_verified_block(height, block_hash);

        #[cfg(test)]
        if self.inject_reorg_after_commit_height == Some(height) {
            self.inject_reorg_after_commit_height = None;
            self.rpc.invalidate_block(&block_hash).map_err(|e| {
                InfrastructureError::new(format!(
                    "inject_reorg_after_commit invalidateblock({block_hash}): {e}"
                ))
            })?;
            Self::mine_empty_block_via_rpc(&self.rpc).map_err(|e| {
                InfrastructureError::new(format!(
                    "inject_reorg_after_commit mine empty replacement: {e}"
                ))
            })?;
        }

        Ok(BlockScanResult {
            height,
            block_hash,
            inscriptions_seen,
            rejected,
            admitted,
            duplicates,
            duplicate_details,
        })
    }

    /// Mine one empty (coinbase-only) block via `generateblock` on the base RPC.
    #[cfg(test)]
    fn mine_empty_block_via_rpc(rpc: &Client) -> Result<BlockHash> {
        use bitcoin::{Address, Network as BtcNetwork, ScriptBuf, WPubkeyHash};
        // Deterministic unspendable-ish p2wpkh for the coinbase; only needs to
        // be a valid regtest address for generateblock.
        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x42; 20]));
        let addr = Address::from_script(&script, BtcNetwork::Regtest)
            .context("p2wpkh script must form a regtest address")?;
        let result: bitcoincore_rpc::jsonrpc::serde_json::Value = rpc
            .call(
                "generateblock",
                &[
                    bitcoincore_rpc::jsonrpc::serde_json::Value::String(addr.to_string()),
                    bitcoincore_rpc::jsonrpc::serde_json::Value::Array(vec![]),
                ],
            )
            .context("generateblock empty for inject_reorg")?;
        let hash_hex = result
            .get("hash")
            .and_then(|v| v.as_str())
            .context("generateblock response missing hash")?;
        hash_hex
            .parse()
            .context("parse generateblock hash")
    }

    /// Discover → parse/bound-check → verify against an already-loaded block.
    fn collect_block_nullifiers_from(
        &mut self,
        height: u64,
        block: &Block,
    ) -> Result<(
        Vec<PublishedNullifier>,
        Vec<RejectedInscription>,
        usize,
    )> {
        ensure!(
            height >= self.config.activation_height,
            "collect_block_nullifiers_from called below activation_height \
             ({height} < {})",
            self.config.activation_height
        );

        // Inclusion block hash is a pure function of the block contents — used
        // as the key for ancestry walks (never the live tip).
        let inclusion_hash = block.block_hash();

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
                    Err(ScanOpError::Infrastructure(e)) => return Err(e.into()),
                    Err(ScanOpError::Data(failure)) => {
                        rejected.push(RejectedInscription::from_data(
                            height, tx_index, vin_index, failure,
                        ));
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
                        rejected.push(RejectedInscription::from_data(
                            height,
                            tx_index,
                            vin_index,
                            DataFailure::new(format!("extract_payload_from_input: {err:#}")),
                        ));
                        continue;
                    }
                };

                // §3.6 step 2 — Parse and bound-check.
                let agg = match AggregateStateNullifierV3::deserialize(&payload) {
                    Ok(a) => a,
                    Err(err) => {
                        rejected.push(RejectedInscription::from_data(
                            height,
                            tx_index,
                            vin_index,
                            DataFailure::new(format!(
                                "deserialize AggregateStateNullifierV3: {err:#}"
                            )),
                        ));
                        continue;
                    }
                };

                match self.check_anchor_for_inclusion(
                    &agg.block_anchor,
                    height,
                    inclusion_hash,
                    block,
                ) {
                    Ok(()) => {}
                    Err(ScanOpError::Infrastructure(e)) => return Err(e.into()),
                    Err(ScanOpError::Data(failure)) => {
                        rejected.push(RejectedInscription::from_data(
                            height, tx_index, vin_index, failure,
                        ));
                        continue;
                    }
                }

                // §3.6 step 3 — Verify signatures (whole aggregate or nothing).
                let m_state = self.config.network.m_state_bytes();
                if let Err(reason) = verify_payload_signatures(&agg, m_state) {
                    rejected.push(RejectedInscription::from_data(
                        height,
                        tx_index,
                        vin_index,
                        DataFailure::new(reason),
                    ));
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
        Ok((verified, rejected, inscriptions_seen))
    }

    /// §3.5 `block_anchor` bound against the **inclusion block's own ancestry**.
    ///
    /// # Invariant
    ///
    /// **Anchor admissibility is a pure function of the inclusion block and its
    /// ancestors, and is never influenced by the current tip.** Two nodes that
    /// agree on the inclusion block therefore agree on whether its payload's
    /// anchor is admissible — even if one of them observed a transient fork of
    /// the live tip during the scan (A → B → A). Resolving
    /// `getblockhash(anchor_height)` against the live chain would couple the
    /// decision to the tip and permanently diverge checkpoints; this path never
    /// does that.
    ///
    /// Resolution order:
    /// 1. Look up `anchor_height` in [`Self::verified_chain`] when that history
    ///    is the parent chain of the inclusion block (already linkage-verified).
    /// 2. Otherwise walk `prev_blockhash` from the inclusion block (at most
    ///    [`MAX_ANCHOR_GAP`] steps) and cache the walk under the inclusion
    ///    block hash so it cannot be reused on a different fork.
    fn check_anchor_for_inclusion(
        &mut self,
        anchor: &BlockAnchor,
        inclusion_height: u64,
        inclusion_hash: BlockHash,
        inclusion_block: &Block,
    ) -> Result<(), ScanOpError> {
        let anchor_height = u64::from(anchor.height);
        // Height/gap first so unit-testable messages stay stable; then ancestry.
        if anchor_height >= inclusion_height {
            return Err(DataFailure::new(format!(
                "block_anchor height {anchor_height} is not a strict ancestor of \
                 inclusion height {inclusion_height} (equal or forward anchor rejected)"
            ))
            .into());
        }
        let gap = inclusion_height - anchor_height;
        if gap > MAX_ANCHOR_GAP {
            return Err(DataFailure::new(format!(
                "block_anchor gap {gap} exceeds MAX_ANCHOR_GAP ({MAX_ANCHOR_GAP}): \
                 inclusion {inclusion_height}, anchor {anchor_height}"
            ))
            .into());
        }

        let ancestor_hash = self.resolve_ancestor_hash(
            inclusion_height,
            inclusion_hash,
            inclusion_block,
            anchor_height,
        )?;
        evaluate_anchor_bound(anchor, inclusion_height, ancestor_hash.to_byte_array())
            .map_err(|reason| ScanOpError::Data(DataFailure::new(reason)))
    }

    /// Hash of the block at `target_height` on the inclusion block's ancestor
    /// chain. Never uses `getblockhash(height)` against the live tip.
    fn resolve_ancestor_hash(
        &mut self,
        inclusion_height: u64,
        inclusion_hash: BlockHash,
        inclusion_block: &Block,
        target_height: u64,
    ) -> Result<BlockHash, ScanOpError> {
        debug_assert!(target_height < inclusion_height);

        // Fast path: parent of inclusion is exactly the target.
        if target_height
            .checked_add(1)
            .expect("target_height + 1")
            == inclusion_height
        {
            return Ok(inclusion_block.header.prev_blockhash);
        }

        // Prefer verified-chain history when it is the parent chain of inclusion.
        if let Some(&(tip_h, tip_hash)) = self.verified_chain.back() {
            let history_is_parent = tip_h
                .checked_add(1)
                .is_some_and(|h| h == inclusion_height)
                && inclusion_block.header.prev_blockhash == tip_hash;
            if history_is_parent {
                if let Some((_, h)) = self
                    .verified_chain
                    .iter()
                    .find(|(h, _)| *h == target_height)
                {
                    return Ok(*h);
                }
            }
            // Inclusion itself already recorded (e.g. re-check) — look below it.
            if let Some(idx) = self
                .verified_chain
                .iter()
                .position(|(h, hash)| *h == inclusion_height && *hash == inclusion_hash)
            {
                if let Some((_, h)) = self.verified_chain.iter().take(idx).find(|(h, _)| {
                    *h == target_height
                }) {
                    return Ok(*h);
                }
            }
        }

        // Walk-cache keyed by inclusion hash (fork-safe).
        if let Some(map) = self.ancestor_walk_cache.get(&inclusion_hash) {
            if let Some(h) = map.get(&target_height) {
                return Ok(*h);
            }
        }

        // Walk prev_blockhash from the inclusion block — deterministic function
        // of the inclusion block, not of the live chain tip.
        let mut walk: BTreeMap<u64, BlockHash> = self
            .ancestor_walk_cache
            .remove(&inclusion_hash)
            .unwrap_or_default();
        walk.insert(inclusion_height, inclusion_hash);

        let mut cur_height = inclusion_height;
        let mut cur_prev = inclusion_block.header.prev_blockhash;
        let mut steps = 0u64;

        while cur_height > target_height {
            steps = match steps.checked_add(1) {
                Some(s) => s,
                None => {
                    return Err(InfrastructureError::new(
                        "ancestor walk step counter overflowed u64",
                    )
                    .into());
                }
            };
            if steps > MAX_ANCHOR_GAP {
                self.ancestor_walk_cache.insert(inclusion_hash, walk);
                return Err(DataFailure::new(format!(
                    "ancestor walk from inclusion {inclusion_height} exceeded \
                     MAX_ANCHOR_GAP ({MAX_ANCHOR_GAP}) before reaching anchor \
                     height {target_height}"
                ))
                .into());
            }

            let parent_height = match cur_height.checked_sub(1) {
                Some(h) => h,
                None => {
                    return Err(InfrastructureError::new(
                        "ancestor walk height underflowed u64",
                    )
                    .into());
                }
            };

            // Short-circuit via verified_chain if we reconnect to known history.
            if let Some((_, known)) = self
                .verified_chain
                .iter()
                .find(|(h, hash)| *h == parent_height && *hash == cur_prev)
            {
                walk.insert(parent_height, *known);
                if parent_height == target_height {
                    self.ancestor_walk_cache.insert(inclusion_hash, walk);
                    return Ok(*known);
                }
                // Remaining ancestors in the same verified window.
                if let Some((_, deeper)) = self
                    .verified_chain
                    .iter()
                    .find(|(h, _)| *h == target_height)
                {
                    walk.insert(target_height, *deeper);
                    self.ancestor_walk_cache.insert(inclusion_hash, walk);
                    return Ok(*deeper);
                }
                // History does not reach target; continue walking from known parent.
                let parent_block: Block = self.rpc.get_block(known).map_err(|e| {
                    InfrastructureError::new(format!(
                        "getblock({known}) during inclusion-ancestry walk for \
                         anchor height {target_height}: {e}"
                    ))
                })?;
                #[cfg(test)]
                {
                    self.ancestor_walk_rpc_count =
                        self.ancestor_walk_rpc_count.saturating_add(1);
                }
                cur_height = parent_height;
                cur_prev = parent_block.header.prev_blockhash;
                continue;
            }

            let parent_hash = cur_prev;
            let parent_block: Block = self.rpc.get_block(&parent_hash).map_err(|e| {
                InfrastructureError::new(format!(
                    "getblock({parent_hash}) during inclusion-ancestry walk for \
                     anchor height {target_height}: {e}"
                ))
            })?;
            #[cfg(test)]
            {
                self.ancestor_walk_rpc_count = self.ancestor_walk_rpc_count.saturating_add(1);
            }
            walk.insert(parent_height, parent_hash);
            if parent_height == target_height {
                self.ancestor_walk_cache.insert(inclusion_hash, walk);
                return Ok(parent_hash);
            }
            cur_height = parent_height;
            cur_prev = parent_block.header.prev_blockhash;
        }

        self.ancestor_walk_cache.insert(inclusion_hash, walk);
        Err(DataFailure::new(format!(
            "ancestor walk from inclusion {inclusion_height} failed to reach \
             anchor height {target_height}"
        ))
        .into())
    }

    /// Resolve the prevout for a reveal input.
    ///
    /// Parent transactions are cached per scan run (one RPC per distinct
    /// `txid`). RPC/`txindex` failures are infrastructure; a parent that exists
    /// but lacks the requested vout is a data failure.
    fn fetch_prevout(&mut self, input: &TxIn) -> Result<TxOut, ScanOpError> {
        #[cfg(test)]
        if self.inject_prevout_infra_failure {
            self.inject_prevout_infra_failure = false;
            return Err(InfrastructureError::new(
                "injected infrastructure failure: getrawtransaction unavailable",
            )
            .into());
        }

        let parent_txid = input.previous_output.txid;
        let parent = if let Some(tx) = self.parent_tx_cache.get(&parent_txid) {
            tx.clone()
        } else {
            let tx = self
                .rpc
                .get_raw_transaction(&parent_txid, None)
                .map_err(|e| {
                    InfrastructureError::new(format!(
                        "getrawtransaction(parent {parent_txid}) failed: {e}"
                    ))
                })?;
            #[cfg(test)]
            {
                self.prevout_rpc_count = self.prevout_rpc_count.saturating_add(1);
            }
            self.parent_tx_cache.insert(parent_txid, tx.clone());
            tx
        };
        let vout = input.previous_output.vout as usize;
        parent.output.get(vout).cloned().ok_or_else(|| {
            ScanOpError::Data(DataFailure::new(format!(
                "parent {parent_txid} has no vout {vout}"
            )))
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

    // ── F2 / F3 unit tests (no bitcoind) ─────────────────────────────────

    #[test]
    fn ensure_txindex_ready_refuses_missing_index() {
        let info = GetIndexInfoResult {
            txindex: None,
            coinstatsindex: None,
            basic_block_filter_index: None,
        };
        let err = ensure_txindex_ready(&info).expect_err("missing txindex must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("txindex") && (msg.contains("absent") || msg.contains("not enabled")),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn ensure_txindex_ready_refuses_lagging_index() {
        use bitcoincore_rpc::json::IndexStatus;
        let info = GetIndexInfoResult {
            txindex: Some(IndexStatus {
                synced: false,
                best_block_height: 12,
            }),
            coinstatsindex: None,
            basic_block_filter_index: None,
        };
        let err = ensure_txindex_ready(&info).expect_err("lagging txindex must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not fully synchronized") || msg.contains("synced=false"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn ensure_txindex_ready_accepts_synced_index() {
        use bitcoincore_rpc::json::IndexStatus;
        let info = GetIndexInfoResult {
            txindex: Some(IndexStatus {
                synced: true,
                best_block_height: 100,
            }),
            coinstatsindex: None,
            basic_block_filter_index: None,
        };
        ensure_txindex_ready(&info).expect("synced txindex must pass");
    }

    #[test]
    fn pinned_activation_height_regtest_is_zero() {
        let params = regtest_network_params().expect("regtest params");
        let h = pinned_activation_height(Network::Regtest, &params).expect("regtest pin");
        assert_eq!(h, 0, "§3.6 regtest activation_height = 0");
    }

    /// F2: mainnet/testnet accept a supplied NetworkParams pin (no compile-time invent).
    #[test]
    fn connect_accepts_mainnet_and_testnet_when_params_match() {
        for (network, tag_bytes, height) in [
            (Network::Mainnet, NETWORK_TAG_MAINNET, 840_000u64),
            (Network::Testnet, NETWORK_TAG_TESTNET, 2_500_000u64),
        ] {
            let tag = std::str::from_utf8(tag_bytes)
                .expect("tag utf8")
                .to_string();
            let params = NetworkParams::new(tag, [1u8; 32], [2u8; 32], height, 6, [3u8; 32])
                .expect("params");
            // Pin agreement runs before RPC — dummy URL/cookie still exercises the gate.
            let result = Scanner::connect(ScannerConfig {
                rpc_url: "http://127.0.0.1:1".into(),
                cookie_path: PathBuf::from("/nonexistent-cookie-for-network-params-test"),
                network,
                activation_height: height,
                network_params: params,
            });
            let err = match result {
                Ok(_) => panic!("{network:?}: RPC must fail after pin check passes"),
                Err(e) => e,
            };
            let msg = format!("{err:#}");
            assert!(
                !msg.contains("does not match network_params")
                    && !msg.contains("does not match pinned")
                    && !msg.contains("deployment-observed"),
                "{network:?}: pin agreement must pass; got: {msg}"
            );
            // Must not invent a refusal for mainnet/testnet when params are supplied.
            assert!(
                msg.contains("cookie")
                    || msg.contains("RPC")
                    || msg.contains("failed")
                    || msg.contains("Connection")
                    || msg.contains("os error")
                    || msg.contains("No such file"),
                "{network:?}: expected RPC/cookie failure after pin gate; got: {msg}"
            );
        }
    }

    /// F2: configured height that disagrees with NetworkParams is refused loudly.
    #[test]
    fn connect_rejects_mainnet_params_height_mismatch() {
        let params = NetworkParams::new(
            std::str::from_utf8(NETWORK_TAG_MAINNET)
                .expect("utf8")
                .to_string(),
            [0u8; 32],
            [0u8; 32],
            840_000,
            6,
            [0u8; 32],
        )
        .expect("params");
        let result = Scanner::connect(ScannerConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            cookie_path: PathBuf::from("/nonexistent-cookie-for-mainnet-mismatch"),
            network: Network::Mainnet,
            activation_height: 840_001,
            network_params: params,
        });
        let err = match result {
            Ok(_) => panic!("mismatched mainnet activation_height must be refused"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("840001") && msg.contains("840000"),
            "error must name both values; got: {msg}"
        );
        assert!(
            msg.contains("activation_height") || msg.contains("network_params"),
            "unexpected: {msg}"
        );
    }

    /// F2: regtest NetworkParams with non-zero activation_height is refused.
    #[test]
    fn connect_rejects_regtest_nonzero_network_params() {
        let tag = std::str::from_utf8(NETWORK_TAG_REGTEST)
            .expect("utf8")
            .to_string();
        let params = NetworkParams::new(tag, [0u8; 32], [0u8; 32], 7, 6, [0u8; 32]).expect("ok");
        let result = Scanner::connect(ScannerConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            cookie_path: PathBuf::from("/nonexistent-cookie-for-regtest-nonzero"),
            network: Network::Regtest,
            activation_height: 7,
            network_params: params,
        });
        let err = match result {
            Ok(_) => panic!("nonzero regtest pin must be refused"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("regtest") && (msg.contains('0') || msg.contains("pin")),
            "unexpected: {msg}"
        );
    }

    /// F2 unit: chain/network rejection is independent of the activation pin.
    #[test]
    fn ensure_chain_matches_config_rejects_cross_network() {
        // Bitcoin ↔ Mainnet; Regtest config must refuse a Bitcoin chain.
        let err = ensure_chain_matches_config(bitcoin::Network::Bitcoin, Network::Regtest)
            .expect_err("mainnet chain vs regtest config");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not match") || msg.contains("chain"),
            "unexpected: {msg}"
        );
    }

    /// F3: duplicate winner lookup is index-based (O(1) per duplicate).
    #[test]
    fn winner_lookup_is_index_based_not_linear() {
        // Build a scanner without a live chain. UserPass auth avoids cookie I/O
        // at Client construction; fold_verified_nullifiers never touches RPC.
        let params = regtest_network_params().expect("params");
        let rpc = Client::new(
            "http://127.0.0.1:1",
            Auth::UserPass("unit".into(), "test".into()),
        )
        .expect("client with userpass auth");
        let mut scanner = Scanner {
            rpc,
            config: ScannerConfig {
                rpc_url: "http://127.0.0.1:1".into(),
                cookie_path: PathBuf::from("/nonexistent-for-winner-index-unit"),
                network: Network::Regtest,
                activation_height: 0,
                network_params: params,
            },
            accumulator: NfLogAccumulator::new(0),
            survivors: Vec::new(),
            winner_by_pk: HashMap::new(),
            scanned_through: None,
            scanned_blocks: BTreeMap::new(),
            parent_tx_cache: HashMap::new(),
            verified_chain: VecDeque::new(),
            ancestor_walk_cache: HashMap::new(),
            inject_prevout_infra_failure: false,
            inject_infra_fail_at_height: None,
            inject_broken_link_at_height: None,
            inject_reorg_after_commit_height: None,
            inject_post_commit_rpc_failure: false,
            prevout_rpc_count: 0,
            winner_index_lookups: 0,
            ancestor_walk_rpc_count: 0,
        };

        let pk = [0xABu8; 32];
        let n_dups = 200usize;
        let mut stream = Vec::with_capacity(1 + n_dups);
        // Winner at position 0.
        stream.push(PublishedNullifier {
            chain_pos: ChainPosition {
                height: 1,
                tx_index: 0,
                vin_index: 0,
                member_index: 0,
            },
            pk,
            r: [0x01; 32],
        });
        // Many duplicates of the same pk with distinct R — stay in survivors.
        for i in 0..n_dups {
            stream.push(PublishedNullifier {
                chain_pos: ChainPosition {
                    height: 1,
                    tx_index: 0,
                    vin_index: 0,
                    member_index: u32::try_from(i + 1).expect("fits"),
                },
                pk,
                r: {
                    let mut r = [0u8; 32];
                    r[0] = 0x02;
                    r[1] = (i % 256) as u8;
                    r[2] = (i / 256) as u8;
                    r
                },
            });
        }

        let (admitted, duplicates, details) = scanner
            .fold_verified_nullifiers(&stream)
            .expect("fold stream");
        assert_eq!(admitted.len(), 1, "one winner");
        assert_eq!(duplicates, n_dups);
        assert_eq!(details.len(), n_dups);
        assert_eq!(
            scanner.winner_index_lookups(),
            n_dups,
            "each duplicate must use exactly one O(1) index lookup"
        );
        assert_eq!(scanner.winner_index_len(), 1);
        assert_eq!(
            scanner.survivors().len(),
            1 + n_dups,
            "duplicates remain in survivors for reorg promotion"
        );
        // Structural: winner index holds the first occurrence, not a late loser.
        assert_eq!(
            details[0].winner_position,
            stream[0].chain_pos,
            "winner position must be the first occurrence"
        );
        for d in &details {
            assert_eq!(d.winner_position, stream[0].chain_pos);
        }
    }

    /// F4 unit: sticky finality across merged reorg outcomes.
    #[test]
    fn merge_reorg_outcome_sticky_finality() {
        // Deep then shallow → finality stays broken; displaced counts sum.
        let mut acc: Option<ReorgOutcome> = None;
        merge_reorg_outcome(
            &mut acc,
            ReorgOutcome {
                finality_broken: true,
                displaced_final_count: 2,
            },
        );
        merge_reorg_outcome(
            &mut acc,
            ReorgOutcome {
                finality_broken: false,
                displaced_final_count: 0,
            },
        );
        let deep_then_shallow = acc.expect("merged");
        assert!(
            deep_then_shallow.finality_broken,
            "deep then shallow must keep finality_broken"
        );
        assert_eq!(deep_then_shallow.displaced_final_count, 2);

        // Shallow then deep → same sticky result with summed displaced.
        let mut acc2: Option<ReorgOutcome> = None;
        merge_reorg_outcome(
            &mut acc2,
            ReorgOutcome {
                finality_broken: false,
                displaced_final_count: 0,
            },
        );
        merge_reorg_outcome(
            &mut acc2,
            ReorgOutcome {
                finality_broken: true,
                displaced_final_count: 2,
            },
        );
        let shallow_then_deep = acc2.expect("merged");
        assert!(
            shallow_then_deep.finality_broken,
            "shallow then deep must set finality_broken"
        );
        assert_eq!(
            shallow_then_deep.displaced_final_count, 2,
            "displaced counts must sum"
        );
    }

    #[test]
    fn connect_rejects_activation_height_mismatch() {
        // Pin check runs before RPC — dummy URL/cookie still exercises the gate.
        // Configured height disagrees with network_params (and with regtest pin 0).
        let params = regtest_network_params().expect("params");
        let pinned = params.activation_height();
        let wrong = pinned.saturating_add(7);
        // Use non-zero wrong height: regtest gate rejects params pin first when
        // params say 0 and config says 7. Construct params with height 0 and
        // mismatched config field.
        let result = Scanner::connect(ScannerConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            cookie_path: PathBuf::from("/nonexistent-cookie-for-activation-height-test"),
            network: Network::Regtest,
            activation_height: wrong,
            network_params: params,
        });
        let err = match result {
            Ok(_) => panic!("mismatched activation_height must be refused at connect"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&wrong.to_string()) && msg.contains(&pinned.to_string()),
            "error must name both configured and pinned values; got: {msg}"
        );
        assert!(
            msg.contains("activation_height")
                || msg.contains("network_params")
                || msg.contains("pinned"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn connect_accepts_pinned_activation_height_reaches_rpc() {
        // Correct pin must not trip the height gate — failure must come from RPC/cookie.
        let result = Scanner::connect(ScannerConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            cookie_path: PathBuf::from("/nonexistent-cookie-for-activation-height-test"),
            network: Network::Regtest,
            activation_height: 0,
            network_params: regtest_network_params().expect("params"),
        });
        let err = match result {
            Ok(_) => panic!("RPC/cookie must fail after pin check passes"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("does not match network_params") && !msg.contains("does not match pinned"),
            "pinned height must be accepted; got: {msg}"
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
            network_params: regtest_network_params().expect("regtest NetworkParams"),
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

    /// Abandon every tx currently in the mempool that the wallet knows about.
    ///
    /// Reorg tests orphan inscriptions back into the mempool; a later
    /// `generatetoaddress` would re-include them and inflate size-based
    /// assertions in unrelated tests. `abandontransaction` is best-effort —
    /// non-wallet mempool entries (if any) are left alone.
    fn abandon_mempool_wallet_txs() {
        let rpc = wallet_rpc();
        let mempool: Vec<String> = rpc
            .call("getrawmempool", &[])
            .unwrap_or_else(|_| Vec::new());
        for txid in mempool {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid)],
            );
        }
    }

    /// Advance the scanner from its current tip through the full chain.
    /// Used so each live test only cares about blocks it itself produced
    /// after catching up once.
    fn catch_up(scanner: &mut Scanner) -> ScanReport {
        abandon_mempool_wallet_txs();
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

        // Log positions for this batch must be consecutive. Global size may be
        // larger than size_before+3 if leftover mempool inscriptions from prior
        // reorg tests were re-included in the same block (non-wallet reveals
        // cannot always be abandoned).
        let acc = scanner.accumulator();
        assert!(
            acc.nav().size >= size_before + 3,
            "expected ≥3 new admissions, size {} → {}",
            size_before,
            acc.nav().size
        );
        let mut log_positions = Vec::new();
        for (j, (pk, _)) in batch.aggregate.members.iter().enumerate() {
            match acc.lookup(*pk) {
                shared::spec_v1::LookupResult::Present { pos, r, .. } => {
                    assert_eq!(r, batch.aggregate.members[j].1);
                    log_positions.push(pos);
                }
                shared::spec_v1::LookupResult::Absent => {
                    panic!("member {j} absent from accumulator")
                }
            }
        }
        assert_eq!(log_positions[1], log_positions[0] + 1);
        assert_eq!(log_positions[2], log_positions[1] + 1);
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
        mine_block_with_txids(rpc, &[])
    }

    /// Mine one block via `generateblock` that includes **exactly** the given
    /// mempool txids (in order) plus coinbase. Unlike `generatetoaddress`, this
    /// does not pull other mempool txs — critical after `invalidateblock` when
    /// orphaned inscriptions would otherwise re-enter the replacement block.
    fn mine_block_with_txids(rpc: &Client, txids: &[Txid]) -> BlockHash {
        let network = rpc.get_blockchain_info().expect("chain").chain;
        let addr = rpc
            .get_new_address(None, Some(AddressType::Bech32m))
            .expect("addr")
            .require_network(network)
            .expect("net");
        let tx_list: Vec<bitcoincore_rpc::jsonrpc::serde_json::Value> = txids
            .iter()
            .map(|t| bitcoincore_rpc::jsonrpc::serde_json::Value::String(t.to_string()))
            .collect();
        let result: bitcoincore_rpc::jsonrpc::serde_json::Value = rpc
            .call(
                "generateblock",
                &[
                    bitcoincore_rpc::jsonrpc::serde_json::Value::String(addr.to_string()),
                    bitcoincore_rpc::jsonrpc::serde_json::Value::Array(tx_list),
                ],
            )
            .expect("generateblock with txids");
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
        // ≥4: leftover mempool reveals from prior reorg tests may share the block.
        assert!(
            scanner.accumulator().nav().size >= size_before + 4,
            "expected ≥4 new admissions, size {} → {}",
            size_before,
            scanner.accumulator().nav().size
        );
    }

    /// F1: mid-scan reorg must not produce a mixed-fork accumulator.
    ///
    /// Scan step 1 admits a nullifier on fork A; reorg to empty B; scan step 2
    /// continues. The running scanner must match a fresh scanner on the final
    /// chain. Also: one-shot scan equals multi-step scan on a stable range.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_mid_scan_reorg_matches_fresh() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        let sigs = signed_members(1, &unique_tag("f1-mid-reorg"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");

        // Step 1: scan the inscription block.
        let report1 = scanner.scan_to_tip().expect("scan step 1");
        assert!(
            report1.admitted_count >= 1,
            "step 1 must admit; admitted={}",
            report1.admitted_count
        );
        let pk = sigs[0].pk;
        assert!(matches!(
            scanner.accumulator().lookup(pk),
            shared::spec_v1::LookupResult::Present { .. }
        ));
        let (orphaned_h, orphaned_hash) = scanner.scanned_through().expect("scanned");

        // Reorg between scan steps: invalidate the inscription block, mine empty.
        rpc.invalidate_block(&orphaned_hash)
            .expect("invalidateblock");
        let _ = mine_empty_block(&rpc);
        let live = rpc.get_block_hash(orphaned_h).expect("live hash");
        assert_ne!(live, orphaned_hash, "chain must have reorged");

        // Step 2: continuing scanner must detect the break / reorg and repair.
        let report2 = scanner.scan_to_tip().expect("scan step 2 after reorg");
        assert!(
            report2.reorg.is_some(),
            "reorg between steps must be reported"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "orphaned nullifier must not remain after mid-scan reorg repair"
        );

        // Definitive check: fresh scanner on final chain matches.
        let mut fresh = live_scanner();
        let _ = catch_up(&mut fresh);
        assert_eq!(
            scanner.accumulator().nav().mth,
            fresh.accumulator().nav().mth,
            "running scanner after mid-scan reorg must equal fresh scan of final chain"
        );
        assert_eq!(
            scanner.accumulator().nav().size,
            fresh.accumulator().nav().size
        );

        // Stabilize for later tests.
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

    /// F1: scanning a range in one call equals several smaller calls.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_call_granularity_invariant() {
        let publisher = live_publisher();
        let mut one_shot = live_scanner();
        let _ = catch_up(&mut one_shot);
        let size_before = one_shot.accumulator().nav().size;

        // Publish three batches, mine each separately so multi-step has work.
        let mut pks = Vec::new();
        for i in 0..3 {
            let sigs = signed_members(1, &unique_tag(&format!("f1-granularity-{i}")));
            pks.push(sigs[0].pk);
            let batch = publisher
                .publish(&batch_at_tip(&publisher, &sigs))
                .expect("publish");
            mine_one(&publisher);
            publisher
                .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
                .expect("confirm");
        }

        // Multi-step: scan after each mine was already done above — rebuild with
        // a scanner that scans one tip at a time by connecting fresh mid-way is
        // hard; instead run one-shot from activation vs step-by-step from a
        // second scanner that we advance with three scan_to_tip calls after all
        // three blocks exist. That tests call granularity on the same final chain.
        let mut stepped = live_scanner();
        // Catch up to pre-test tip by scanning once to size_before equivalent:
        // both start from genesis; we compare final mth only.
        let _ = stepped.scan_to_tip().expect("stepped full scan");

        let _ = one_shot.scan_to_tip().expect("one-shot full scan");

        assert_eq!(
            one_shot.accumulator().nav().mth,
            stepped.accumulator().nav().mth,
            "one call vs equivalent full scan must agree"
        );

        // Explicit multi-call equality: restart stepped from scratch and scan
        // three times after each new block on a third publisher sequence.
        let mut multi = live_scanner();
        let _ = catch_up(&mut multi);
        let multi_before = multi.accumulator().nav().mth;
        let mut single = live_scanner();
        let _ = catch_up(&mut single);
        assert_eq!(multi.accumulator().nav().mth, single.accumulator().nav().mth);

        let mut multi_pks = Vec::new();
        for i in 0..2 {
            let sigs = signed_members(1, &unique_tag(&format!("f1-gran-split-{i}")));
            multi_pks.push(sigs[0].pk);
            let batch = publisher
                .publish(&batch_at_tip(&publisher, &sigs))
                .expect("publish");
            mine_one(&publisher);
            publisher
                .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
                .expect("confirm");
            // Multi-step advances one block at a time.
            let _ = multi.scan_to_tip().expect("multi step");
        }
        // Single-shot catches both blocks in one call.
        let _ = single.scan_to_tip().expect("single step");

        assert_eq!(
            multi.accumulator().nav().mth,
            single.accumulator().nav().mth,
            "scanning a range in several calls must equal one call"
        );
        assert_ne!(
            multi.accumulator().nav().mth,
            multi_before,
            "test must have advanced the log"
        );
        for pk in multi_pks {
            assert!(matches!(
                multi.accumulator().lookup(pk),
                shared::spec_v1::LookupResult::Present { .. }
            ));
            assert!(matches!(
                single.accumulator().lookup(pk),
                shared::spec_v1::LookupResult::Present { .. }
            ));
        }
        let _ = size_before; // silence if unused under some paths
        let _ = pks;
        let _ = one_shot;
    }

    /// F2: RPC/infrastructure prevout failure aborts the scan; checkpoint
    /// unchanged; retry recovers the nullifier.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_infra_prevout_failure_aborts_not_rejects() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let checkpoint_before = scanner.scanned_through();
        let size_before = scanner.accumulator().nav().size;

        let sigs = signed_members(1, &unique_tag("f2-infra-prevout"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");

        // Inject infrastructure failure for the next prevout fetch.
        scanner.inject_next_prevout_infra_failure();
        let err = scanner
            .scan_to_tip()
            .expect_err("infra failure must abort scan");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("infrastructure") || msg.contains("injected"),
            "expected infrastructure error, got: {msg}"
        );

        // Checkpoint unchanged — block not recorded as scanned.
        assert_eq!(
            scanner.scanned_through(),
            checkpoint_before,
            "checkpoint must not advance on infrastructure failure"
        );
        assert_eq!(scanner.accumulator().nav().size, size_before);
        // Must NOT have recorded a rejection for this (no permanent data reject).
        // (scan aborted before returning a report.)

        // Retry without injection recovers the nullifier.
        let report = scanner.scan_to_tip().expect("retry must succeed");
        assert!(
            report.admitted_count >= 1,
            "retry must admit the nullifier; admitted={}",
            report.admitted_count
        );
        assert!(matches!(
            scanner.accumulator().lookup(sigs[0].pk),
            shared::spec_v1::LookupResult::Present { .. }
        ));
    }

    /// F2 live: connect against the real node accepts a synced txindex.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_connect_requires_synced_txindex() {
        // Live node has synced txindex (verified by live_scanner succeeding).
        let scanner = live_scanner();
        assert_eq!(scanner.config().activation_height, 0);
        // Unit tests cover missing/lagging refusal; here we prove connect with
        // a healthy index succeeds (would have bailed in ensure_txindex_ready).
    }

    /// F4: reorg collection failure mid-way leaves scanner unchanged; retry
    /// recovers the full replacement range including B[F+1].
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_reorg_collection_atomic() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        // Build two blocks with nullifiers so reorg replacement has ≥2 heights.
        let sigs_a = signed_members(1, &unique_tag("f4-reorg-a"));
        let batch_a = publisher
            .publish(&batch_at_tip(&publisher, &sigs_a))
            .expect("publish a");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_a.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm a");
        let _ = scanner.scan_to_tip().expect("scan a");
        let pk_a = sigs_a[0].pk;
        let height_a = scanner.scanned_through().expect("tip a").0;

        let sigs_b = signed_members(1, &unique_tag("f4-reorg-b"));
        let batch_b = publisher
            .publish(&batch_at_tip(&publisher, &sigs_b))
            .expect("publish b");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_b.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm b");
        let _ = scanner.scan_to_tip().expect("scan b");
        let pk_b = sigs_b[0].pk;
        let (tip_h, tip_hash) = scanner.scanned_through().expect("tip b");

        // Snapshot state before reorg attempt.
        let survivors_before: Vec<_> = scanner.survivors().to_vec();
        let mth_before = scanner.accumulator().nav().mth;
        let size_before = scanner.accumulator().nav().size;
        let scanned_before = scanner.scanned_through();
        // Hash of the first inscription block, from the live chain before reorg.
        let hash_a = rpc
            .get_block_hash(height_a)
            .expect("getblockhash height_a");

        // Invalidate both tip blocks so the reorg must recollect a range.
        // Invalidate tip first, then the parent inscription block.
        rpc.invalidate_block(&tip_hash).expect("invalidate tip");
        rpc.invalidate_block(&hash_a).expect("invalidate a");

        // Mine two empty replacement blocks so the range has F+1 and F+2.
        let _ = mine_empty_block(&rpc);
        let _ = mine_empty_block(&rpc);

        // Inject failure when collecting the second replacement height (F+2).
        // rescan starts at height_a (fork is height_a-1 or earlier). After
        // invalidating both, common ancestor is below height_a; recollect
        // through min(old_tip, tip). Fail at height_a + 1 (second block).
        let fail_at = height_a
            .checked_add(1)
            .expect("height+1")
            .min(tip_h);
        scanner.inject_infra_fail_at_height(fail_at);

        let err = scanner
            .scan_to_tip()
            .expect_err("mid-reorg collection failure must abort");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("infrastructure") || msg.contains("injected"),
            "expected injected infra failure, got: {msg}"
        );

        // Atomicity: state unchanged.
        assert_eq!(scanner.scanned_through(), scanned_before);
        assert_eq!(scanner.accumulator().nav().mth, mth_before);
        assert_eq!(scanner.accumulator().nav().size, size_before);
        assert_eq!(scanner.survivors(), survivors_before.as_slice());
        assert!(
            matches!(
                scanner.accumulator().lookup(pk_a),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "pre-reorg nullifier A must still be present after aborted reorg"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(pk_b),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "pre-reorg nullifier B must still be present after aborted reorg"
        );

        // Retry: reorg completes; empty replacements mean both nullifiers gone.
        let report = scanner.scan_to_tip().expect("retry reorg");
        assert!(report.reorg.is_some(), "retry must complete the reorg");
        assert!(
            matches!(
                scanner.accumulator().lookup(pk_a),
                shared::spec_v1::LookupResult::Absent
            ),
            "after successful reorg, A (orphaned) must be absent"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(pk_b),
                shared::spec_v1::LookupResult::Absent
            ),
            "after successful reorg, B (orphaned) must be absent"
        );

        // Stabilize.
        let _ = mine_empty_block(&rpc);
        for txid in [batch_a.commit_txid, batch_a.reveal_txid, batch_b.commit_txid, batch_b.reveal_txid]
        {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F5: duplicates carry positions + winner; replacement rejections reported.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_duplicate_details_and_reorg_rejections() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        let (first, second) = double_spend_pair(&unique_tag("f5-dup-details"));
        let batch1 = publisher
            .publish(&batch_at_tip(&publisher, &[first]))
            .expect("publish first");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch1.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm first");
        let report1 = scanner.scan_to_tip().expect("scan first");
        assert!(report1.admitted_count >= 1);
        let winner_pos = scanner
            .survivors()
            .iter()
            .find(|n| n.pk == first.pk && n.r == first.r)
            .expect("winner survivor")
            .chain_pos;

        let batch2 = publisher
            .publish(&batch_at_tip(&publisher, &[second]))
            .expect("publish second");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch2.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm second");
        let report2 = scanner.scan_to_tip().expect("scan second");
        assert!(
            report2.duplicates >= 1,
            "expected duplicate count, got {}",
            report2.duplicates
        );
        assert!(
            !report2.duplicate_details.is_empty(),
            "duplicate_details must not be empty"
        );
        let detail = report2
            .duplicate_details
            .iter()
            .find(|d| d.winner_position == winner_pos)
            .expect("detail must reference the winner position");
        assert_eq!(detail.winner_position, winner_pos);
        assert_ne!(
            detail.position, detail.winner_position,
            "loser position must differ from winner"
        );
        assert_eq!(detail.position.height, scanner.scanned_through().unwrap().0);

        // Replacement-block rejections: reorg the tip onto an empty block, but
        // first put a bad-signature payload that will be re-collected if it were
        // on the new fork — instead, reorg the double-spend block away and ensure
        // reorg report surfaces block results (inscriptions_seen / rejected from
        // replacement). Mine a bad payload on a new tip then reorg it.
        let sigs_bad = signed_members(1, &unique_tag("f5-reorg-reject"));
        let tip = publisher.current_anchor().expect("tip");
        let mut agg = aggregate_sig_with_anchor(&sigs_bad, tip).expect("agg");
        if let Some(ref mut s) = agg.s_agg {
            s[0] ^= 0xff;
        }
        let mut s = [0u8; 32];
        s[31] = 1;
        agg.s_agg = Some(s);
        let payload = agg.serialize();
        let (_c, reveal) = broadcast_raw_payload(&payload);
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&reveal, 1, Duration::from_secs(30))
            .expect("confirm bad");
        let report_bad = scanner.scan_to_tip().expect("scan bad");
        assert!(
            report_bad.rejected_count >= 1,
            "bad sig must reject; rejected={}",
            report_bad.rejected_count
        );
        let bad_height = scanner.scanned_through().expect("tip").0;
        let bad_hash = scanner.scanned_through().expect("tip").1;

        // Reorg that block away with an empty replacement; reorg report must
        // include the replacement block entry (even if empty of inscriptions).
        rpc.invalidate_block(&bad_hash).expect("invalidate");
        let _ = mine_empty_block(&rpc);
        let report_reorg = scanner.scan_to_tip().expect("reorg scan");
        assert!(report_reorg.reorg.is_some());
        assert!(
            report_reorg
                .blocks
                .iter()
                .any(|b| b.height == bad_height),
            "replacement block at {bad_height} must appear in report blocks; got heights {:?}",
            report_reorg
                .blocks
                .iter()
                .map(|b| b.height)
                .collect::<Vec<_>>()
        );

        let _ = mine_empty_block(&rpc);
        let _ = scanner.scan_to_tip();
    }

    /// F6: repeated parent fetched once per scan run; verified-chain history
    /// tracks scanned blocks; ancestry walks are keyed by inclusion hash.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_prevout_and_anchor_caches() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        // One batch → one parent commit tx → one prevout RPC for the reveal input.
        let sigs = signed_members(1, &unique_tag("f6-cache"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");

        let report = scanner.scan_to_tip().expect("scan");
        assert!(report.admitted_count >= 1);
        let prevout_rpcs = scanner.prevout_rpc_count();
        assert!(
            prevout_rpcs >= 1,
            "at least one prevout RPC expected, got {prevout_rpcs}"
        );
        assert!(
            scanner.verified_chain_len() >= 1,
            "verified-chain history must record scanned blocks"
        );
        // Gap-1 anchors resolve from inclusion.prev_blockhash — zero walk RPCs.
        assert_eq!(
            scanner.ancestor_walk_rpc_count(),
            0,
            "gap-1 anchor must not need ancestry walk RPCs"
        );

        // Second inscription: per-run parent cache resets each scan_to_tip.
        let sigs2 = signed_members(1, &unique_tag("f6-cache-2"));
        let batch2 = publisher
            .publish(&batch_at_tip(&publisher, &sigs2))
            .expect("publish2");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch2.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm2");
        let _ = scanner.scan_to_tip().expect("scan2");
        assert_eq!(
            scanner.prevout_rpc_count(),
            1,
            "one parent txid must be fetched once per scan run (got {})",
            scanner.prevout_rpc_count()
        );

        // Reorg onto empty replacement: verified history truncates to fork;
        // no new inscriptions → no new walk RPCs this run.
        let (_tip_h, tip_hash) = scanner.scanned_through().expect("tip");
        rpc.invalidate_block(&tip_hash).expect("invalidate");
        let _ = mine_empty_block(&rpc);
        let _ = scanner.scan_to_tip().expect("reorg scan");
        assert_eq!(
            scanner.ancestor_walk_rpc_count(),
            0,
            "empty replacement must not issue ancestry walk RPCs"
        );

        let _ = mine_empty_block(&rpc);
        for txid in [
            batch.commit_txid,
            batch.reveal_txid,
            batch2.commit_txid,
            batch2.reveal_txid,
        ] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// Extract [`InfrastructureError`] from an anyhow error chain.
    fn infra_from_err(err: &anyhow::Error) -> Option<&InfrastructureError> {
        for cause in err.chain() {
            if let Some(infra) = cause.downcast_ref::<InfrastructureError>() {
                return Some(infra);
            }
        }
        None
    }

    /// F1: after reorg, ancestry check must not accept an orphaned-fork hash.
    ///
    /// Catch up, publish+mine nullifier on A_H, scan. Invalidate A_H; mine empty
    /// B_H. Broadcast good (anchor B_H) and bad (anchor orphaned A_H) for
    /// inclusion in B_{H+1}. Mine. scan_to_tip admits good, rejects bad.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_replacement_anchor_cache() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        let sigs = signed_members(1, &unique_tag("f1-anchor-cache"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");
        let report0 = scanner.scan_to_tip().expect("scan A_H");
        assert!(report0.admitted_count >= 1);
        assert!(
            scanner.verified_chain_len() >= 1,
            "scan must populate verified-chain history"
        );
        let (orphaned_h, orphaned_hash) = scanner.scanned_through().expect("tip A_H");
        let orphaned_bytes = orphaned_hash.to_byte_array();

        // Reorg A_H → empty B_H.
        rpc.invalidate_block(&orphaned_hash).expect("invalidate");
        let new_at_h = mine_empty_block(&rpc);
        assert_ne!(new_at_h, orphaned_hash);
        let live_h = rpc.get_block_hash(orphaned_h).expect("live at H");
        assert_eq!(live_h, new_at_h);

        // Good payload: anchors to new B_H. Bad: anchors to orphaned A_H hash.
        let good_sigs = signed_members(1, &unique_tag("f1-anchor-good"));
        let good_pk = good_sigs[0].pk;
        let good_anchor = BlockAnchor {
            block_hash: new_at_h.to_byte_array(),
            height: u32::try_from(orphaned_h).expect("height fits u32"),
        };
        let good_agg =
            aggregate_sig_with_anchor(&good_sigs, good_anchor).expect("good aggregate");
        let (_gc, good_reveal) = broadcast_raw_payload(&good_agg.serialize());

        let bad_sigs = signed_members(1, &unique_tag("f1-anchor-bad"));
        let bad_pk = bad_sigs[0].pk;
        let bad_anchor = BlockAnchor {
            block_hash: orphaned_bytes,
            height: u32::try_from(orphaned_h).expect("height fits u32"),
        };
        let bad_agg = aggregate_sig_with_anchor(&bad_sigs, bad_anchor).expect("bad aggregate");
        let (_bc, bad_reveal) = broadcast_raw_payload(&bad_agg.serialize());

        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&good_reveal, 1, Duration::from_secs(30))
            .expect("confirm good");
        publisher
            .wait_for_confirmation(&bad_reveal, 1, Duration::from_secs(30))
            .expect("confirm bad");

        let report = scanner.scan_to_tip().expect("scan after reorg + B_H+1");
        assert!(
            report.reorg.is_some(),
            "reorg of A_H must be reported"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(good_pk),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "good payload (anchor B_H) must be admitted"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(bad_pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "bad payload (anchor orphaned A_H) must not be admitted"
        );
        let reasons: Vec<&str> = report
            .blocks
            .iter()
            .flat_map(|b| b.rejected.iter().map(|r| r.reason.as_str()))
            .collect();
        assert!(
            reasons.iter().any(|r| {
                r.contains("ancestor")
                    || r.contains("chain")
                    || r.contains("hash")
                    || r.contains("block_anchor")
            }),
            "bad-anchor rejection must mention ancestry/chain/hash; got: {reasons:?}"
        );

        let mut fresh = live_scanner();
        let _ = catch_up(&mut fresh);
        assert_eq!(
            scanner.accumulator().nav().mth,
            fresh.accumulator().nav().mth,
            "running scanner must match fresh scan after ancestry reorg"
        );

        let _ = mine_empty_block(&rpc);
        for txid in [
            batch.commit_txid,
            batch.reveal_txid,
            good_reveal,
            bad_reveal,
        ] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F1 (critical design): A→B→A around a block with an A-ancestor anchor.
    ///
    /// Anchor admissibility is a pure function of the inclusion block and its
    /// ancestors — independent of the live tip. A transient A→B→A reorg must
    /// not change the admission decision relative to a fresh scanner on final A.
    /// Converse: a payload naming orphaned B_(h-1) inside a block of chain A is
    /// rejected by both.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_anchor_aba_fork_matches_fresh() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        // ── Build orphaned B_parent at height H_parent ────────────────────
        let a_parent_hash = rpc
            .get_block_hash(rpc.get_block_count().expect("tip"))
            .expect("a_parent");
        let parent_height = rpc.get_block_count().expect("tip");
        rpc.invalidate_block(&a_parent_hash)
            .expect("invalidate a_parent");
        let b_parent_hash = mine_empty_block(&rpc);
        assert_ne!(b_parent_hash, a_parent_hash);
        // Return to A: invalidate B, reconsider A.
        rpc.invalidate_block(&b_parent_hash)
            .expect("invalidate b_parent");
        let _: bitcoincore_rpc::jsonrpc::serde_json::Value = rpc
            .call(
                "reconsiderblock",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(
                    a_parent_hash.to_string(),
                )],
            )
            .expect("reconsider a_parent");
        let live_parent = rpc.get_block_hash(parent_height).expect("live parent");
        assert_eq!(live_parent, a_parent_hash, "must be back on A at parent");
        // Catch up after the tip oscillated (scanner may still be at old tip).
        let _ = scanner.scan_to_tip().expect("catch up after parent fork");

        // ── Good payload (anchor A_parent) + bad payload (anchor B_parent) ─
        let good_sigs = signed_members(1, &unique_tag("f1-aba-good"));
        let good_pk = good_sigs[0].pk;
        let good_anchor = BlockAnchor {
            block_hash: a_parent_hash.to_byte_array(),
            height: u32::try_from(parent_height).expect("fits"),
        };
        let good_agg =
            aggregate_sig_with_anchor(&good_sigs, good_anchor).expect("good agg");
        let (_gc, good_reveal) = broadcast_raw_payload(&good_agg.serialize());

        let bad_sigs = signed_members(1, &unique_tag("f1-aba-bad"));
        let bad_pk = bad_sigs[0].pk;
        let bad_anchor = BlockAnchor {
            block_hash: b_parent_hash.to_byte_array(),
            height: u32::try_from(parent_height).expect("fits"),
        };
        let bad_agg = aggregate_sig_with_anchor(&bad_sigs, bad_anchor).expect("bad agg");
        let (_bc, bad_reveal) = broadcast_raw_payload(&bad_agg.serialize());

        // Mine both into A_h via generatetoaddress (pulls mempool).
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&good_reveal, 1, Duration::from_secs(30))
            .expect("confirm good");
        publisher
            .wait_for_confirmation(&bad_reveal, 1, Duration::from_secs(30))
            .expect("confirm bad");
        let inclusion_height = rpc.get_block_count().expect("tip after mine");
        let a_inclusion = rpc
            .get_block_hash(inclusion_height)
            .expect("a inclusion hash");

        // ── A → B → A at the inclusion height ─────────────────────────────
        // Invalidate A_h, mine two empty B blocks (B longer), then invalidate B
        // and reconsider A_h so the active tip is again A.
        rpc.invalidate_block(&a_inclusion)
            .expect("invalidate a_inclusion");
        let b_inclusion = mine_empty_block(&rpc);
        let b_extra = mine_empty_block(&rpc);
        assert_ne!(b_inclusion, a_inclusion);
        // Peel B from the tip down to inclusion height, then reconsider A.
        rpc.invalidate_block(&b_extra).expect("invalidate b_extra");
        rpc.invalidate_block(&b_inclusion)
            .expect("invalidate b_inclusion");
        let _: bitcoincore_rpc::jsonrpc::serde_json::Value = rpc
            .call(
                "reconsiderblock",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(
                    a_inclusion.to_string(),
                )],
            )
            .expect("reconsider a_inclusion");
        let live_inc = rpc
            .get_block_hash(inclusion_height)
            .expect("live inclusion");
        assert_eq!(
            live_inc, a_inclusion,
            "must be back on A at inclusion height after A→B→A"
        );

        // ── Scan: long-lived + fresh must agree ───────────────────────────
        let report = scanner.scan_to_tip().expect("scan after A→B→A");
        assert!(
            matches!(
                scanner.accumulator().lookup(good_pk),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "good A-anchor payload must be admitted after A→B→A; report={report:?}"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(bad_pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "bad B-anchor payload must be rejected on chain A"
        );
        let reasons: Vec<&str> = report
            .blocks
            .iter()
            .flat_map(|b| b.rejected.iter().map(|r| r.reason.as_str()))
            .collect();
        assert!(
            reasons.iter().any(|r| {
                r.contains("ancestor")
                    || r.contains("chain")
                    || r.contains("hash")
                    || r.contains("block_anchor")
            }),
            "bad-anchor reason expected; got: {reasons:?}"
        );

        let mut fresh = live_scanner();
        let _ = catch_up(&mut fresh);
        assert_eq!(
            scanner.accumulator().nav().mth,
            fresh.accumulator().nav().mth,
            "scanner that lived through A→B→A must match fresh scan of final A"
        );
        assert_eq!(
            scanner.accumulator().nav().size,
            fresh.accumulator().nav().size
        );
        assert!(
            matches!(
                fresh.accumulator().lookup(good_pk),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "fresh scanner must also admit good"
        );
        assert!(
            matches!(
                fresh.accumulator().lookup(bad_pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "fresh scanner must also reject bad B-anchor"
        );

        let _ = mine_empty_block(&rpc);
        for txid in [good_reveal, bad_reveal] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F4: post-commit getblockcount/getblockhash failure carries partial report.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_post_commit_rpc_failure_partial_report() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let size_before = scanner.accumulator().nav().size;

        let sigs = signed_members(1, &unique_tag("f4-post-commit-rpc"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");

        // After the block is folded+checkpointed, tip re-read fails.
        scanner.inject_post_commit_rpc_failure();
        let err = scanner
            .scan_to_tip()
            .expect_err("post-commit RPC failure must abort");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("infrastructure")
                || msg.contains("injected")
                || msg.contains("post-commit"),
            "expected post-commit infra error, got: {msg}"
        );
        let infra = infra_from_err(&err).expect("must be InfrastructureError");
        let partial = infra
            .partial_report()
            .expect("partial_report must be Some after block committed");
        assert!(
            partial.admitted_count >= 1,
            "partial must report the committed admissions; admitted={}",
            partial.admitted_count
        );
        assert!(
            !partial.blocks.is_empty(),
            "partial must include the committed block report"
        );
        // Work is durable: checkpoint advanced, nullifier folded.
        assert!(
            matches!(
                scanner.accumulator().lookup(sigs[0].pk),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "committed nullifier must remain after post-commit abort"
        );
        assert!(
            scanner.accumulator().nav().size >= size_before + 1,
            "accumulator must retain the committed admission"
        );

        // Retry does not re-process the already-checkpointed block; the caller
        // already observed its admissions/duplicates/rejections in partial_report.
        let committed_height = partial.blocks[0].height;
        let report = scanner.scan_to_tip().expect("retry must succeed");
        assert!(
            !report.blocks.iter().any(|b| b.height == committed_height),
            "retry must not re-report the already-checkpointed height {committed_height}; \
             got heights {:?}",
            report.blocks.iter().map(|b| b.height).collect::<Vec<_>>()
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(sigs[0].pk),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "pk still present after retry"
        );
        let mut fresh = live_scanner();
        let _ = catch_up(&mut fresh);
        assert_eq!(
            scanner.accumulator().nav().mth,
            fresh.accumulator().nav().mth
        );

        let rpc = wallet_rpc();
        let _ = mine_empty_block(&rpc);
        for txid in [batch.commit_txid, batch.reveal_txid] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F2: mid-replacement-collection chain break restarts; final state matches fresh.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_mid_replacement_collection_chain_break() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        let sigs_a = signed_members(1, &unique_tag("f2-link-a"));
        let batch_a = publisher
            .publish(&batch_at_tip(&publisher, &sigs_a))
            .expect("publish a");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_a.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm a");
        let _ = scanner.scan_to_tip().expect("scan a");
        let height_a = scanner.scanned_through().expect("tip a").0;

        let sigs_b = signed_members(1, &unique_tag("f2-link-b"));
        let batch_b = publisher
            .publish(&batch_at_tip(&publisher, &sigs_b))
            .expect("publish b");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_b.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm b");
        let _ = scanner.scan_to_tip().expect("scan b");
        let (tip_h, tip_hash) = scanner.scanned_through().expect("tip b");
        let hash_a = rpc.get_block_hash(height_a).expect("hash a");

        rpc.invalidate_block(&tip_hash).expect("invalidate tip");
        rpc.invalidate_block(&hash_a).expect("invalidate a");
        let _ = mine_empty_block(&rpc);
        let _ = mine_empty_block(&rpc);

        // Break linkage on the second replacement height (one-shot).
        let break_at = height_a
            .checked_add(1)
            .expect("height+1")
            .min(tip_h);
        scanner.inject_broken_link_at_height(break_at);

        let report = scanner
            .scan_to_tip()
            .expect("chain-break restart must still succeed");
        assert!(
            report.reorg.is_some(),
            "reorg must complete after collection restart"
        );

        let mut fresh = live_scanner();
        let _ = catch_up(&mut fresh);
        assert_eq!(
            scanner.accumulator().nav().mth,
            fresh.accumulator().nav().mth,
            "after mid-collection chain break, mth must equal fresh scanner"
        );

        // Checkpoint hashes must match live chain.
        if let Some((h, hash)) = scanner.scanned_through() {
            let live = rpc.get_block_hash(h).expect("live hash at checkpoint");
            assert_eq!(hash, live, "checkpoint hash must match live at {h}");
        }

        let _ = mine_empty_block(&rpc);
        for txid in [
            batch_a.commit_txid,
            batch_a.reveal_txid,
            batch_b.commit_txid,
            batch_b.reveal_txid,
        ] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F3: tip_hash after scan equals accumulator checkpoint, never a wrong-fork tip.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_tip_equals_accumulator_after_post_commit_reorg() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        let sigs = signed_members(1, &unique_tag("f3-tip-match"));
        let batch = publisher
            .publish(&batch_at_tip(&publisher, &sigs))
            .expect("publish");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm");

        // Nullifier is in the current tip block; reorg that height after commit.
        let nullifier_height = rpc.get_block_count().expect("tip");
        scanner.inject_reorg_after_commit_height(nullifier_height);

        let report = scanner
            .scan_to_tip()
            .expect("scan_to_tip Ok despite post-commit reorg");
        let (scanned_h, scanned_hash) = scanner.scanned_through().expect("must have checkpoint");
        assert_eq!(
            report.tip_height, scanned_h,
            "report tip_height must equal scanned_through height"
        );
        assert_eq!(
            report.tip_hash, scanned_hash,
            "report tip_hash must equal scanned_through hash"
        );
        // After inject reorg + outer-loop repair, checkpoint is on the live chain.
        let live_at_scanned = rpc
            .get_block_hash(scanned_h)
            .expect("getblockhash scanned");
        assert_eq!(
            scanned_hash, live_at_scanned,
            "scanned_through must be on the live chain after repair"
        );

        let _ = mine_empty_block(&rpc);
        for txid in [batch.commit_txid, batch.reveal_txid] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F5: replacement BlockScanResult reports real admissions and duplicates.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_replacement_admissions_and_duplicates() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let rpc = wallet_rpc();

        // Winner at H-1 stays across reorg of H.
        let winner = signed_members(1, &unique_tag("f5-winner"));
        let batch_w = publisher
            .publish(&batch_at_tip(&publisher, &winner))
            .expect("publish winner");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_w.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm winner");
        let _ = scanner.scan_to_tip().expect("scan winner");
        let winner_pk = winner[0].pk;
        let winner_r = winner[0].r;

        // Garbage (unique nullifier) at H — will be reorged away.
        let garbage = signed_members(1, &unique_tag("f5-garbage"));
        let batch_g = publisher
            .publish(&batch_at_tip(&publisher, &garbage))
            .expect("publish garbage");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_g.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm garbage");
        let _ = scanner.scan_to_tip().expect("scan garbage");
        let (h, hash_h) = scanner.scanned_through().expect("tip H");

        // Invalidate H. Orphaned garbage returns to the mempool — a normal
        // `generatetoaddress` would re-include it (same pitfall as
        // `regtest_scanner_real_reorg`). Abandon garbage, broadcast new
        // first-occurrence + same-pk duplicate, then mine H' with an **explicit**
        // txid list so garbage cannot re-enter the replacement.
        rpc.invalidate_block(&hash_h).expect("invalidate H");
        for txid in [batch_g.commit_txid, batch_g.reveal_txid] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }

        let (first_r, second_r) = double_spend_pair(&unique_tag("f5-repl-dup"));
        let batch_new = publisher
            .publish(&batch_at_tip(&publisher, &[first_r]))
            .expect("publish new first");
        let batch_dup = publisher
            .publish(&batch_at_tip(&publisher, &[second_r]))
            .expect("publish dup");
        // Commit before reveal for each inscription; only new+dup — not garbage.
        let repl_hash = mine_block_with_txids(
            &rpc,
            &[
                batch_new.commit_txid,
                batch_new.reveal_txid,
                batch_dup.commit_txid,
                batch_dup.reveal_txid,
            ],
        );
        let live = rpc
            .get_block_hash(h)
            .expect("getblockhash after reorg");
        assert_eq!(live, repl_hash, "explicit-txid block must be the new tip at H");
        assert_ne!(live, hash_h, "reorg must replace the block hash at H");
        publisher
            .wait_for_confirmation(&batch_new.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm new");
        publisher
            .wait_for_confirmation(&batch_dup.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm dup");

        let report = scanner.scan_to_tip().expect("reorg scan");
        assert!(report.reorg.is_some(), "reorg must be reported");
        // Replacement block at H must have real admissions and duplicates.
        let repl = report
            .blocks
            .iter()
            .find(|b| b.height == h)
            .expect("replacement block at H must appear in report");
        assert!(
            repl.admitted.len() >= 1,
            "replacement must report admitted>=1; got {}",
            repl.admitted.len()
        );
        assert!(
            repl.duplicates >= 1,
            "replacement must report duplicates>=1; got {}",
            repl.duplicates
        );
        assert!(
            !repl.duplicate_details.is_empty(),
            "replacement must include duplicate_details"
        );
        assert!(
            report.admitted_count >= 1,
            "report admitted_count must reflect replacement"
        );
        assert!(
            report.duplicates >= 1,
            "report duplicates must reflect replacement"
        );
        // Original winner at H-1 still present.
        assert!(
            matches!(
                scanner.accumulator().lookup(winner_pk),
                shared::spec_v1::LookupResult::Present { r, .. } if r == winner_r
            ),
            "winner at H-1 must remain after reorg of H"
        );
        // Garbage from old H gone.
        assert!(
            matches!(
                scanner.accumulator().lookup(garbage[0].pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "garbage at old H must be absent after reorg"
        );

        let _ = mine_empty_block(&rpc);
        for txid in [
            batch_w.commit_txid,
            batch_w.reveal_txid,
            batch_g.commit_txid,
            batch_g.reveal_txid,
            batch_new.commit_txid,
            batch_new.reveal_txid,
            batch_dup.commit_txid,
            batch_dup.reveal_txid,
        ] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }

    /// F6: per-block atomicity — infra fail on second block keeps first commit
    /// and attaches a partial report; retry completes.
    #[test]
    #[ignore = "requires live bitcoind; set ZKCOINS_REGTEST_{URL,COOKIE,WALLET}"]
    fn regtest_scanner_per_block_atomicity_partial_report() {
        let publisher = live_publisher();
        let mut scanner = live_scanner();
        let _ = catch_up(&mut scanner);
        let size_before = scanner.accumulator().nav().size;
        let checkpoint_before = scanner.scanned_through();

        let sigs_1 = signed_members(1, &unique_tag("f6-atomic-1"));
        let batch_1 = publisher
            .publish(&batch_at_tip(&publisher, &sigs_1))
            .expect("publish 1");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_1.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm 1");

        let sigs_2 = signed_members(1, &unique_tag("f6-atomic-2"));
        let batch_2 = publisher
            .publish(&batch_at_tip(&publisher, &sigs_2))
            .expect("publish 2");
        mine_one(&publisher);
        publisher
            .wait_for_confirmation(&batch_2.reveal_txid, 1, Duration::from_secs(30))
            .expect("confirm 2");

        // Both blocks unscanned. Fail on the second (current tip) height.
        let _ = checkpoint_before;
        let rpc = wallet_rpc();
        let tip = rpc.get_block_count().expect("tip");
        let fail_at = tip; // second (last) unscanned block
        let first_height = tip.checked_sub(1).expect("tip-1");
        scanner.inject_infra_fail_at_height(fail_at);

        let err = scanner
            .scan_to_tip()
            .expect_err("infra on second block must abort");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("infrastructure") || msg.contains("injected"),
            "expected infrastructure error, got: {msg}"
        );
        let infra = infra_from_err(&err).expect("error must be InfrastructureError");
        let partial = infra
            .partial_report()
            .expect("partial_report must be Some after first block committed");
        assert!(
            partial.admitted_count >= 1,
            "partial must include first-block admissions; admitted={}",
            partial.admitted_count
        );
        assert!(
            partial.blocks.iter().any(|b| b.height == first_height),
            "partial blocks must include first height {first_height}; got {:?}",
            partial.blocks.iter().map(|b| b.height).collect::<Vec<_>>()
        );

        let (scanned_h, _) = scanner.scanned_through().expect("first block committed");
        assert_eq!(
            scanned_h, first_height,
            "scanned_through must be first block only"
        );
        assert!(
            scanner.accumulator().nav().size >= size_before + 1,
            "first nullifier must be committed"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(sigs_1[0].pk),
                shared::spec_v1::LookupResult::Present { .. }
            ),
            "first pk must be present after partial commit"
        );
        assert!(
            matches!(
                scanner.accumulator().lookup(sigs_2[0].pk),
                shared::spec_v1::LookupResult::Absent
            ),
            "second pk must not be present yet"
        );

        // Retry succeeds; final mth equals fresh scanner.
        let report = scanner.scan_to_tip().expect("retry must succeed");
        assert!(
            report.admitted_count >= 1,
            "retry must admit the second nullifier"
        );
        assert!(matches!(
            scanner.accumulator().lookup(sigs_2[0].pk),
            shared::spec_v1::LookupResult::Present { .. }
        ));

        let mut fresh = live_scanner();
        let _ = catch_up(&mut fresh);
        assert_eq!(
            scanner.accumulator().nav().mth,
            fresh.accumulator().nav().mth,
            "after retry, mth must equal fresh scanner"
        );

        let _ = mine_empty_block(&rpc);
        for txid in [
            batch_1.commit_txid,
            batch_1.reveal_txid,
            batch_2.commit_txid,
            batch_2.reveal_txid,
        ] {
            let _ = rpc.call::<bitcoincore_rpc::jsonrpc::serde_json::Value>(
                "abandontransaction",
                &[bitcoincore_rpc::jsonrpc::serde_json::Value::String(txid.to_string())],
            );
        }
        let _ = scanner.scan_to_tip();
    }
}
