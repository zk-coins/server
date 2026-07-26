//! v1.1 scan-fold path: §3.6 first-occurrence into the EngineAdapter NfLog.
//!
//! The full chain-connectivity loop (bitcoind RPC, envelope parse, anchor
//! bound, signature verify) lives in `zkcoins_prover::scanner::Scanner`.
//! This module owns the **node-side apply** of already-validated survivors
//! into the Stage-1 persistence adapter, pure helpers for ordering and
//! first-occurrence, and **boot tip reconciliation** so a restart across
//! a reorg cannot fold a new canonical stream into a stale NfLog.
//!
//! ## Reorg behaviour (v1.1 path)
//!
//! On reorg the script-plonky2 `Scanner` collects the replacement range
//! **before** mutating its survivors list, then truncate-and-refolds the
//! retained prefix and folds each replacement block. The node mirrors
//! that outcome by replacing the engine NfLog from the scanner's
//! post-reorg survivor stream ([`apply_canonical_survivors`]) and
//! persisting atomically. Account/CoinHist rows are left intact — only
//! the nullifier log is a pure function of the confirmed chain.
//!
//! ## Restart across a reorg
//!
//! Every boot creates a fresh scanner with an empty checkpoint. If Bitcoin
//! reorganised while the node was down, that scanner cannot report a reorg
//! (no previous tip). The node therefore reconciles the **persisted** tip
//! against the **immutable ancestry of the captured scan-tip hash** — never
//! against mutable `getblockhash(height)` observations of the live tip
//! (same design as §3.5 `block_anchor` ancestry in the script-plonky2
//! scanner: A→B→A leaves no detectable reorg if you only sample the live
//! tip twice):
//!
//! 1. Run `scan_to_tip` to obtain `(tip_height, tip_hash, survivors)`.
//! 2. **Behind-node gate first**: if the connected node's tip height is
//!    still below the persisted height, return
//!    [`TipReconcileOutcome::RetryableIncompleteView`] **before** resolving
//!    the persisted hash. A restored bitcoind that does not know later
//!    blocks must retry, not fail-stop.
//! 3. Resolve the persisted tip hash (by hash). Unknown / pruned is fatal
//!    **only** once the live node is already at or beyond that height.
//! 4. Classify against the **scan tip's immutable ancestry** (walk
//!    `previousblockhash` from the fixed scan-tip hash — never
//!    `getblockhash(height)` on the live tip):
//!    - hash at `persisted_height` on that ancestry equals `tip_hash` →
//!      StillCanonical;
//!    - otherwise walk the old chain to the last common ancestor with the
//!      scan-tip ancestry; reorg depth = `persisted_height − ancestor_height`.
//! 5. **Taxonomy of outcomes**:
//!    - **Ready** ([`PersistedTipReconciliation`]): Fresh / StillCanonical
//!      / ShallowReorg — apply from **this** scan's survivors.
//!    - **Retryable incomplete view**: RPC behind / observation incomplete.
//!      Stay unready, leave `finality_ok` untouched, back off, full
//!      re-verify. Never assume canonical, never assume reorg, never
//!      conflate lag with deep_reorg.
//!    - **Fatal** (`Err`): unresolvable tip (with live already at height),
//!      no common ancestor, depth beyond §3.9, RPC infrastructure failure,
//!      ambiguous cursor. Fail-stop; deep reorg trips readiness `deep_reorg`.
//! 6. Only a **shallow** (depth ≤ 5), non-final reorg may full-replace
//!    NfLog from the rescan survivor stream. A one-block reorg of the
//!    **activation block** has common ancestor `activation_height − 1`
//!    (below activation); that is still safely replayable from
//!    activation (NfLog is empty below the pin) and must not refuse.
//! 7. Tip still canonical → seed folded keys; forward-append only.
//!
//! Property: after any crash or *tolerated* reorg, a restarted node
//! reaches the same accumulator a continuously running node would hold.
//! A finality-breaking offline reorg fails the process; it does **not**
//! silently rebuild.
//!
//! A mid-apply crash leaves the previous snapshot (persist is
//! all-or-nothing via [`crate::v11::db_v11::persist_engine_snapshot`]);
//! apply paths restore the in-memory engine from a pre-mutation snapshot
//! when persist fails so the live adapter never advances past durable
//! state.

use anyhow::{bail, Context, Result};
use shared::spec_v1::{ChainPosition, FoldOutcome, PublishedNullifier};
use zkcoins_prover::state_engine::StateEngine;

use super::adapter::EngineAdapter;
use super::separation::{ensure_v11_publisher_allowed, require_v11_process_for_nflog_write};

/// Outcome counters for one fold pass (forward scan or reorg apply).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FoldStats {
    pub appended: u64,
    pub duplicate_ignored: u64,
    pub below_activation: u64,
}

/// Sort key = declaration order of [`ChainPosition`]:
/// `(height, tx_index, vin_index, member_index)`.
pub fn sort_canonical(survivors: &mut [PublishedNullifier]) {
    survivors.sort_by_key(|n| n.chain_pos);
}

/// Fold already-validated survivors into `engine` under §3.6 rules.
///
/// * Callers must supply survivors in any order; this sorts canonically.
/// * First occurrence of each `Pk` is appended; later same-`Pk` entries
///   are counted as `duplicate_ignored` and do **not** move the winner.
/// * Pre-activation heights are skipped (counted, not fatal).
/// * Out-of-order after sort is impossible; a fold error is fatal.
///
/// This is the pure core used by tests and by [`EngineAdapter`] apply.
pub fn fold_survivors_into_engine(
    engine: &mut StateEngine,
    survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    let mut ordered: Vec<PublishedNullifier> = survivors.to_vec();
    sort_canonical(&mut ordered);

    let mut stats = FoldStats::default();
    // Track first occurrence within this stream; engine.lookup covers prior.
    let mut seen_in_stream: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for nf in ordered {
        // Already a winner in the engine → first-occurrence ignore.
        if !matches!(
            engine.nflog().lookup(nf.pk),
            shared::spec_v1::LookupResult::Absent
        ) {
            stats.duplicate_ignored = stats
                .duplicate_ignored
                .checked_add(1)
                .context("duplicate_ignored counter overflow")?;
            continue;
        }
        if !seen_in_stream.insert(nf.pk) {
            stats.duplicate_ignored = stats
                .duplicate_ignored
                .checked_add(1)
                .context("duplicate_ignored counter overflow")?;
            continue;
        }

        match engine.append_nullifier(nf.chain_pos, nf.pk, nf.r) {
            Ok(_) => {
                stats.appended = stats
                    .appended
                    .checked_add(1)
                    .context("appended counter overflow")?;
            }
            Err(err) => {
                let msg = format!("{err:#}");
                // append_nullifier fails loud on duplicates and pre-activation;
                // map those back to stats only when we raced the pre-checks.
                if msg.contains("already present") || msg.contains("first-occurrence") {
                    stats.duplicate_ignored = stats
                        .duplicate_ignored
                        .checked_add(1)
                        .context("duplicate_ignored counter overflow")?;
                    continue;
                }
                if msg.contains("below activation_height") {
                    stats.below_activation = stats
                        .below_activation
                        .checked_add(1)
                        .context("below_activation counter overflow")?;
                    // Drop from seen so a later in-window same-pk could still
                    // win — but §3.6 orders by chain position, so a later
                    // higher height cannot be below activation if this one was.
                    seen_in_stream.remove(&nf.pk);
                    continue;
                }
                return Err(err).context("fold_survivors_into_engine: fatal fold error");
            }
        }
    }
    Ok(stats)
}

/// Build the first-occurrence NfLog pair list from a survivor stream.
///
/// Used by the reorg path so the engine can be reconstructed via
/// [`super::db_v11::EngineSnapshot`] (accounts stay byte-identical).
pub fn first_occurrence_nflog_pairs(
    activation_height: u64,
    survivors: &[PublishedNullifier],
) -> Result<(Vec<(ChainPosition, shared::spec_v1::NfLogEntry)>, FoldStats)> {
    let mut ordered: Vec<PublishedNullifier> = survivors.to_vec();
    sort_canonical(&mut ordered);

    let mut nflog_pairs: Vec<(ChainPosition, shared::spec_v1::NfLogEntry)> = Vec::new();
    let mut first_r: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
        std::collections::BTreeMap::new();
    let mut stats = FoldStats::default();

    for nf in &ordered {
        if nf.chain_pos.height < activation_height {
            stats.below_activation = stats
                .below_activation
                .checked_add(1)
                .context("below_activation counter overflow")?;
            continue;
        }
        match first_r.entry(nf.pk) {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(nf.r);
                nflog_pairs.push((
                    nf.chain_pos,
                    shared::spec_v1::NfLogEntry {
                        pk: nf.pk,
                        r: nf.r,
                    },
                ));
                stats.appended = stats
                    .appended
                    .checked_add(1)
                    .context("appended counter overflow")?;
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                stats.duplicate_ignored = stats
                    .duplicate_ignored
                    .checked_add(1)
                    .context("duplicate_ignored counter overflow")?;
            }
        }
    }
    Ok((nflog_pairs, stats))
}

/// Apply a full canonical survivor stream as the **sole** NfLog contents
/// (reorg path): rebuild the engine NfLog from scratch while keeping
/// accounts / CoinHist via an intermediate [`EngineSnapshot`].
///
/// Used after the script-plonky2 scanner reports a reorg outcome so the
/// persisted NfLog matches the new canonical chain exactly.
pub fn replace_engine_nflog_from_survivors(
    engine: &mut StateEngine,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    use super::db_v11::EngineSnapshot;

    let activation_height = engine.activation_height();
    let (nflog_pairs, stats) = first_occurrence_nflog_pairs(activation_height, survivors)?;

    // Snapshot accounts (and current meta) without needing AccountRecord: Clone.
    let mut snap = EngineSnapshot::from_engine_with_tip_hash(engine, tip_hash);
    snap.tip_height = tip_height;
    snap.tip_hash = tip_hash;
    snap.nflog = nflog_pairs;

    let rebuilt = snap
        .into_engine()
        .context("replace_engine_nflog_from_survivors: into_engine")?;
    *engine = rebuilt;
    Ok(stats)
}

/// Forward-scan apply on the live adapter: fold new survivors, set tip, persist.
///
/// Mutates memory only after a successful durable write would be wrong —
/// this path snapshots the live engine, mutates, persists, and **restores**
/// the snapshot if persist fails so the adapter never advances past Postgres.
///
/// Holds [`EngineAdapter::lock_writes`] for the full snapshot→mutate→persist
/// →restore window so a concurrent receive cannot have its committed work
/// rolled back by this path's restore (and vice versa).
pub async fn apply_forward_scan(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    new_survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    require_v11_process_for_nflog_write()?;
    let _write_gate = adapter.lock_writes().await;
    let backup = adapter.snapshot_live();

    let stats = match adapter.with_engine_mut(|engine| -> Result<FoldStats> {
        if tip_height < engine.tip_height() {
            bail!(
                "apply_forward_scan: tip_height {tip_height} is behind engine tip {}; \
                 use replace_engine_nflog_from_survivors for reorg",
                engine.tip_height()
            );
        }
        // set_tip_height zeroes fold_seq — only advance when moving forward.
        if tip_height > engine.tip_height() {
            engine.set_tip_height(tip_height);
        }
        fold_survivors_into_engine(engine, new_survivors)
    }) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) | Err(e) => {
            adapter
                .restore_live(backup)
                .context("apply_forward_scan: restore after mutate error")?;
            return Err(e);
        }
    };
    adapter
        .set_tip_hash(tip_hash)
        .context("apply_forward_scan: set_tip_hash")?;
    if let Err(e) = adapter
        .persist()
        .await
        .context("apply_forward_scan: persist")
    {
        adapter
            .restore_live(backup)
            .context("apply_forward_scan: restore after persist failure")?;
        return Err(e);
    }
    Ok(stats)
}

/// Reorg / full-rebuild apply: replace NfLog from the full post-reorg
/// (or post-rescan) survivor stream.
///
/// Same memory-before-persist safety as [`apply_forward_scan`]: restore
/// the pre-mutation snapshot if durable write fails. Same write-gate
/// serialisation against receive.
pub async fn apply_canonical_survivors(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    require_v11_process_for_nflog_write()?;
    let _write_gate = adapter.lock_writes().await;
    let backup = adapter.snapshot_live();

    let stats = match adapter.with_engine_mut(|engine| {
        replace_engine_nflog_from_survivors(engine, tip_height, tip_hash, survivors)
    }) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) | Err(e) => {
            adapter
                .restore_live(backup)
                .context("apply_canonical_survivors: restore after mutate error")?;
            return Err(e);
        }
    };
    adapter
        .set_tip_hash(tip_hash)
        .context("apply_canonical_survivors: set_tip_hash")?;
    if let Err(e) = adapter
        .persist()
        .await
        .context("apply_canonical_survivors: persist")
    {
        adapter
            .restore_live(backup)
            .context("apply_canonical_survivors: restore after persist failure")?;
        return Err(e);
    }
    Ok(stats)
}

/// §3.9: reorgs of **up to 5 blocks** are tolerated (non-final only).
/// Depth ≥ 6 is outside v1's recovery guarantee (finality = 6 confirmations).
pub const MAX_RECOVERABLE_REORG_DEPTH: u64 = 5;

/// A block resolved by hash from bitcoind (or a test double).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedBlock {
    pub height: u64,
    /// Previous-block hash; all-zero for the genesis block.
    pub prev_hash: [u8; 32],
}

/// Outcome of reconciling a persisted tip against the live Bitcoin chain
/// when the live view is complete enough to classify.
///
/// Decides whether a restarted node may forward-append, may rebuild from
/// a shallow offline reorg, or must **fail-stop** (returned as `Err` from
/// [`reconcile_persisted_tip`]). Incomplete live views are **not** this
/// type — see [`TipReconcileOutcome::RetryableIncompleteView`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistedTipReconciliation {
    /// Engine has no tip yet (height 0, all-zero hash). Scan forward from
    /// activation; first persist will establish the cursor.
    Fresh,
    /// Persisted tip is still the live hash at that height. Seed folded
    /// keys from the engine and forward-append only new survivors.
    StillCanonical {
        tip_height: u64,
        tip_hash: [u8; 32],
    },
    /// Offline reorg within the ≤5-block recoverable window. First apply
    /// after the rescan **must** full-replace the NfLog from the survivor
    /// stream (equivalent to truncate-and-extend from the ancestor) —
    /// never forward-fold into the stale accumulator.
    ShallowReorg {
        ancestor_height: u64,
        ancestor_hash: [u8; 32],
        /// `persisted_height − ancestor_height` (1..=[`MAX_RECOVERABLE_REORG_DEPTH`]).
        reorg_depth: u64,
        persisted_height: u64,
        persisted_hash: [u8; 32],
    },
}

/// Full result of tip reconciliation: ready, retryable lag, or fatal (`Err`).
///
/// Distinguishes **transient** incomplete RPC views from **corruption /
/// real divergence** so a syncing bitcoind never crash-loops the node and
/// a deep reorg never looks like lag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TipReconcileOutcome {
    /// Live view was complete; proceed with the inner classification.
    Ready(PersistedTipReconciliation),
    /// RPC tip behind a queried height / height not yet known.
    ///
    /// Caller must: leave `v11_scan` unready, leave `finality_ok` /
    /// `deep_reorg` untouched, back off, and re-run the full verification.
    /// Never assume canonical, never assume reorg.
    RetryableIncompleteView {
        queried_height: u64,
        detail: String,
    },
}

/// Whether a scan tip is still the live main-chain hash at that height.
///
/// Secondary pin after ancestry-based recon: if the live tip at the scan
/// height has moved away from the captured `scan_tip_hash`, the whole
/// observation (scan + recon) is stale and the caller must re-observe.
///
/// **Not** the defence against A→B→A: equality of a mutable live-tip
/// sample observed twice proves nothing. Classification is a pure
/// function of the fixed scan-tip ancestry (see [`reconcile_persisted_tip`]).
pub fn observation_tip_still_live(
    scan_tip_hash: [u8; 32],
    live_at_scan_height: Option<[u8; 32]>,
) -> bool {
    matches!(live_at_scan_height, Some(h) if h == scan_tip_hash)
}

/// Whether the first boot apply for a ready recon must full-replace
/// NfLog from the bound scan's survivors (vs forward-append with seeded keys).
pub fn first_boot_requires_full_replace(recon: &PersistedTipReconciliation) -> bool {
    matches!(recon, PersistedTipReconciliation::ShallowReorg { .. })
}

/// Hash of the block at `target_height` on the **immutable ancestry** of a
/// fixed tip `(tip_height, tip_hash)`.
///
/// Walks `prev_hash` from the tip via `resolve_hash` — never
/// `getblockhash(height)` against the mutable live tip. Same principle as
/// script-plonky2 scanner anchor resolution from the inclusion block.
///
/// Returns `Ok(None)` when `target_height > tip_height` (target is not on
/// this tip's ancestry). Returns `Err` on resolve failure / inconsistency.
fn hash_at_height_on_ancestry(
    tip_height: u64,
    tip_hash: [u8; 32],
    target_height: u64,
    resolve_hash: &mut impl FnMut([u8; 32]) -> Result<Option<ResolvedBlock>>,
) -> Result<Option<[u8; 32]>> {
    if target_height > tip_height {
        return Ok(None);
    }
    if target_height == tip_height {
        return Ok(Some(tip_hash));
    }

    let mut walk_height = tip_height;
    let mut walk_hash = tip_hash;
    while walk_height > target_height {
        let block = resolve_hash(walk_hash).with_context(|| {
            format!(
                "v1.1 boot tip reconciliation: resolve during observation-ancestry \
                 walk for height {target_height} (from tip height={tip_height} \
                 hash={}) failed",
                hex::encode(tip_hash)
            )
        })?;
        let Some(block) = block else {
            bail!(
                "v1.1 boot tip reconciliation: observation-ancestry block {} at \
                 height {walk_height} became unresolvable while walking to height \
                 {target_height} — refusing to fold",
                hex::encode(walk_hash)
            );
        };
        if block.height != walk_height {
            bail!(
                "v1.1 boot tip reconciliation: resolved height {} != walk height {} \
                 for hash {} during observation-ancestry walk; refusing",
                block.height,
                walk_height,
                hex::encode(walk_hash)
            );
        }
        walk_hash = block.prev_hash;
        walk_height = walk_height
            .checked_sub(1)
            .context("v1.1 boot tip reconciliation: height underflow on observation ancestry")?;
    }
    Ok(Some(walk_hash))
}

/// Reconcile `(tip_height, tip_hash)` from the persisted engine against the
/// **immutable ancestry of a fixed observation tip** (the captured scan tip)
/// under §3.9 finality rules.
///
/// # Why the observation tip, not the live tip
///
/// Sampling `getblockhash(height)` on the live chain is mutable: an
/// A→B→A sequence can make recon see chain B (StillCanonical for a B
/// persisted tip) while the scan survivors and the post-recon pin both
/// belong to A — permanently mixing accumulators. Equality of a mutable
/// value observed twice proves nothing. Classification is therefore a
/// pure function of the **fixed** `(observation_tip_height,
/// observation_tip_hash)` ancestry (walk `prev_hash` via `resolve_hash`),
/// mirroring how the scanner decides anchor admissibility from the
/// inclusion block's ancestry rather than the live tip.
///
/// # Arguments
///
/// * `live_node_height` — highest height the connected node currently
///   reports (`getblockcount`). Checked **before** resolving the
///   persisted hash: a restored/syncing node that has not reached the
///   persisted height returns [`TipReconcileOutcome::RetryableIncompleteView`]
///   instead of treating an unknown hash as fatal.
/// * `observation_tip_height` / `observation_tip_hash` — the scan tip this
///   recon is bound to (same observation as the survivors to apply).
/// * `resolve_hash(hash)` returns:
///   - `Ok(Some(ResolvedBlock))` when bitcoind knows the block (main or orphan)
///   - `Ok(None)` when the hash is unknown / pruned
///   - `Err(_)` on RPC failure — refused, never treated as a shallow reorg
///
/// # Failures (`Err` — fatal only, no silent recovery)
///
/// - `tip_height > 0` with all-zero `tip_hash` (ambiguous cursor)
/// - persisted tip hash unknown / pruned **while** `live_node_height >= tip_height`
/// - no common ancestor with the observation tip's ancestry (walked to genesis)
/// - reorg depth > [`MAX_RECOVERABLE_REORG_DEPTH`] (§3.9 ≥6-block fail-stop)
/// - resolve RPC **infrastructure** failure
/// - observation tip unresolvable / height mismatch
///
/// Incomplete views (live node behind persisted height, or observation tip
/// below persisted height) are **not** failures; they return
/// [`TipReconcileOutcome::RetryableIncompleteView`].
///
/// # Activation boundary
///
/// A one-block reorg of the activation block has common ancestor
/// `activation_height − 1`. That height is below the scan origin, but
/// NfLog is empty below activation (§3.6), so the reorg is non-final and
/// safely full-replaceable from activation when depth ≤ 5. Do **not**
/// refuse solely because the ancestor is below `activation_height`.
pub fn reconcile_persisted_tip(
    tip_height: u64,
    tip_hash: [u8; 32],
    activation_height: u64,
    observation_tip_height: u64,
    observation_tip_hash: [u8; 32],
    live_node_height: u64,
    mut resolve_hash: impl FnMut([u8; 32]) -> Result<Option<ResolvedBlock>>,
) -> Result<TipReconcileOutcome> {
    let zero = [0u8; 32];
    if tip_height == 0 && tip_hash == zero {
        return Ok(TipReconcileOutcome::Ready(
            PersistedTipReconciliation::Fresh,
        ));
    }
    if tip_hash == zero {
        bail!(
            "v1.1 boot tip reconciliation: tip_height={tip_height} but tip_hash \
             is all-zero — ambiguous cursor; refusing to fold (restore a \
             snapshot with a real tip_hash or wipe v1.1 tables)"
        );
    }

    // 1. Behind-node gate FIRST (Defect 3). A restored bitcoind that has not
    //    reached the persisted height does not know the tip hash yet;
    //    resolving before this check misclassifies lag as fatal unknown.
    if live_node_height < tip_height {
        return Ok(TipReconcileOutcome::RetryableIncompleteView {
            queried_height: tip_height,
            detail: format!(
                "connected bitcoind tip height {live_node_height} is behind \
                 persisted tip height {tip_height} (hash={}). Incomplete view \
                 — not a confirmed reorg and not an unresolvable tip. Staying \
                 unready and retrying (no silent assume-canonical, no silent \
                 assume-reorg).",
                hex::encode(tip_hash)
            ),
        });
    }

    // 2. Observation must cover the persisted height (bound scan window).
    if observation_tip_height < tip_height {
        return Ok(TipReconcileOutcome::RetryableIncompleteView {
            queried_height: tip_height,
            detail: format!(
                "observation (scan) tip height {observation_tip_height} is below \
                 persisted tip height {tip_height} (hash={}). Incomplete \
                 observation relative to the engine cursor — staying unready \
                 and retrying (no silent assume-canonical).",
                hex::encode(tip_hash)
            ),
        });
    }

    // 3. Resolve the persisted tip hash **itself** (not merely height→hash).
    //    Live node is already at/beyond tip_height, so unknown/pruned is fatal.
    let tip_block = resolve_hash(tip_hash).context(
        "v1.1 boot tip reconciliation: resolve of persisted tip hash failed; \
         refusing to fold onto an unverified persisted tip",
    )?;
    let Some(tip_block) = tip_block else {
        bail!(
            "v1.1 boot tip reconciliation: persisted tip hash {} at height {} \
             is unknown or pruned on the connected bitcoind (live tip height \
             {live_node_height} ≥ persisted height) — reorg depth and common \
             ancestor cannot be determined. Refusing to fold (fail-stop; no \
             silent recovery of an unresolvable tip). Manual recovery required.",
            hex::encode(tip_hash),
            tip_height
        );
    };
    if tip_block.height != tip_height {
        bail!(
            "v1.1 boot tip reconciliation: persisted tip_height={tip_height} but \
             resolved hash {} is at height {} — cursor inconsistency; refusing \
             to fold",
            hex::encode(tip_hash),
            tip_block.height
        );
    }

    // 4. Resolve the fixed observation tip (scan tip) — ancestry root.
    let obs_block = resolve_hash(observation_tip_hash).context(
        "v1.1 boot tip reconciliation: resolve of observation (scan) tip hash failed; \
         refusing to fold onto an unverified observation",
    )?;
    let Some(obs_block) = obs_block else {
        bail!(
            "v1.1 boot tip reconciliation: observation tip hash {} at height {} \
             is unknown or pruned — cannot build immutable ancestry; refusing \
             to fold",
            hex::encode(observation_tip_hash),
            observation_tip_height
        );
    };
    if obs_block.height != observation_tip_height {
        bail!(
            "v1.1 boot tip reconciliation: observation_tip_height={observation_tip_height} \
             but resolved hash {} is at height {} — observation inconsistency; \
             refusing to fold",
            hex::encode(observation_tip_hash),
            obs_block.height
        );
    }

    // 5. Hash at persisted height on the **observation tip's immutable ancestry**.
    //    Never getblockhash(height) on the live tip.
    let hash_on_obs = hash_at_height_on_ancestry(
        observation_tip_height,
        observation_tip_hash,
        tip_height,
        &mut resolve_hash,
    )?
    .context(
        "v1.1 boot tip reconciliation: internal — observation tip height covers \
         persisted height but ancestry walk returned None",
    )?;

    if hash_on_obs == tip_hash {
        return Ok(TipReconcileOutcome::Ready(
            PersistedTipReconciliation::StillCanonical {
                tip_height,
                tip_hash,
            },
        ));
    }

    // 6. Diverged: walk the old (persisted) chain via previousblockhash to
    //    the last common ancestor with the observation ancestry.
    let mut walk_hash = tip_hash;
    let mut walk_height = tip_height;
    let mut cached: Option<ResolvedBlock> = Some(tip_block);

    loop {
        if walk_height == 0 {
            bail!(
                "v1.1 boot tip reconciliation: no common ancestor between \
                 persisted tip (height={tip_height}, hash={}) and the observation \
                 tip ancestry (height={observation_tip_height}, hash={}) — walked \
                 to genesis. Refusing to fold (fail-stop; §3.9 provides no \
                 recovery for an unrooted offline reorg).",
                hex::encode(tip_hash),
                hex::encode(observation_tip_hash)
            );
        }

        let block = match cached.take() {
            Some(b) => b,
            None => {
                let resolved = resolve_hash(walk_hash).context(
                    "v1.1 boot tip reconciliation: resolve during ancestor walk failed; \
                     refusing to fold",
                )?;
                match resolved {
                    Some(b) => b,
                    None => bail!(
                        "v1.1 boot tip reconciliation: block hash {} at height {} \
                         became unresolvable during ancestor walk — refusing to \
                         fold (no silent assumption of a shallow reorg)",
                        hex::encode(walk_hash),
                        walk_height
                    ),
                }
            }
        };
        if block.height != walk_height {
            bail!(
                "v1.1 boot tip reconciliation: resolved height {} != walk height {} \
                 for hash {}; refusing",
                block.height,
                walk_height,
                hex::encode(walk_hash)
            );
        }

        let parent_hash = block.prev_hash;
        let parent_height = walk_height
            .checked_sub(1)
            .context("v1.1 boot tip reconciliation: height underflow during ancestor walk")?;
        let reorg_depth = tip_height
            .checked_sub(parent_height)
            .context("v1.1 boot tip reconciliation: reorg_depth underflow")?;

        // Fail-stop as soon as depth exceeds the recoverable window — do not
        // keep walking and silently recover a ≥6-block offline reorg.
        if reorg_depth > MAX_RECOVERABLE_REORG_DEPTH {
            bail!(
                "v1.1 boot tip reconciliation: offline reorg depth {reorg_depth} \
                 exceeds recoverable limit {MAX_RECOVERABLE_REORG_DEPTH} \
                 (persisted tip height={tip_height} hash={}). §3.9: reorgs of \
                 ≥6 blocks MAY displace final nullifier positions and v1 \
                 provides no recovery path — refusing to fold; readiness must \
                 not report ready (deep_reorg). Manual recovery required.",
                hex::encode(tip_hash)
            );
        }

        // Membership of parent on observation ancestry — immutable walk,
        // not live getblockhash(parent_height).
        let parent_on_obs = hash_at_height_on_ancestry(
            observation_tip_height,
            observation_tip_hash,
            parent_height,
            &mut resolve_hash,
        )?;
        match parent_on_obs {
            Some(h) if h == parent_hash => {
                // Found last common ancestor on the observation ancestry.
                //
                // Ancestor may sit below `activation_height` (e.g. one-block
                // reorg of the activation block → parent = activation − 1).
                // NfLog has no entries below activation (§3.6), so a full
                // replace from the rescan stream is exactly "replay from
                // activation". Depth is already gated above — do not refuse
                // solely because `parent_height < activation_height`.
                let _: bool = parent_height < activation_height;
                return Ok(TipReconcileOutcome::Ready(
                    PersistedTipReconciliation::ShallowReorg {
                        ancestor_height: parent_height,
                        ancestor_hash: parent_hash,
                        reorg_depth,
                        persisted_height: tip_height,
                        persisted_hash: tip_hash,
                    },
                ));
            }
            Some(_) => {
                // Parent still diverged from the observation ancestry — keep walking.
                walk_hash = parent_hash;
                walk_height = parent_height;
            }
            None => {
                // parent_height > observation_tip_height is impossible here
                // (we gated observation_tip_height >= tip_height >= walk).
                // Treat as incomplete rather than silent reorg.
                return Ok(TipReconcileOutcome::RetryableIncompleteView {
                    queried_height: parent_height,
                    detail: format!(
                        "observation ancestry has no block at height {parent_height} \
                         during ancestor walk (persisted tip height={tip_height}). \
                         Incomplete view — staying unready and retrying (no silent \
                         reorg classification)."
                    ),
                });
            }
        }
    }
}

/// Fold-key type used by the v1.1 scan loop to skip already-applied
/// survivors after a still-canonical restart.
pub type FoldedSurvivorKey = (u64, u32, u32, u32, [u8; 32]);

/// Seed the in-process folded-key set from a persisted NfLog mirror so a
/// still-canonical restart does not re-append first-occurrence winners.
pub fn folded_keys_from_nflog_mirror(
    mirror: &[(ChainPosition, shared::spec_v1::NfLogEntry)],
) -> std::collections::HashSet<FoldedSurvivorKey> {
    mirror
        .iter()
        .map(|(pos, entry)| {
            (
                pos.height,
                pos.tx_index,
                pos.vin_index,
                pos.member_index,
                entry.pk,
            )
        })
        .collect()
}

/// Build [`PublishedNullifier`] rows for one multi-member inscription at a
/// fixed chain position (member_index = 0..n-1). Test and synthetic helper.
pub fn members_to_published(
    height: u64,
    tx_index: u32,
    vin_index: u32,
    members: &[([u8; 32], [u8; 32])],
) -> Result<Vec<PublishedNullifier>> {
    let mut out = Vec::with_capacity(members.len());
    for (i, (pk, r)) in members.iter().enumerate() {
        let member_index = u32::try_from(i).context("member_index does not fit in u32")?;
        out.push(PublishedNullifier {
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
    Ok(out)
}

/// Drain one `scan_to_tip` report into the adapter (forward-only helper).
///
/// Full reorg detection is owned by `zkcoins_prover::scanner::Scanner`;
/// when its report carries a reorg outcome the caller must invoke
/// [`apply_canonical_survivors`] with the complete post-reorg survivor
/// list instead of this forward-only path.
pub fn fold_outcome_label(outcome: FoldOutcome) -> &'static str {
    match outcome {
        FoldOutcome::Appended(_) => "appended",
        FoldOutcome::DuplicateIgnored => "duplicate_ignored",
        FoldOutcome::BelowActivationHeight => "below_activation",
    }
}

/// Env keys required to connect the script-plonky2 bitcoind scanner.
/// Missing any of them fails loud under v1.1 mode — never fall back to
/// the Esplora commitment scanner.
pub const V11_SCANNER_RPC_URL_ENV: &str = "ZKCOINS_V11_BITCOIND_RPC_URL";
pub const V11_SCANNER_COOKIE_ENV: &str = "ZKCOINS_V11_BITCOIND_COOKIE_PATH";

/// Resolve bitcoind scanner config from env (no silent defaults).
pub fn v11_bitcoind_rpc_from_env() -> Result<(String, std::path::PathBuf)> {
    // v1.1 exclusive claim required — never open bitcoind for NfLog under legacy.
    ensure_v11_publisher_allowed()?;

    let rpc_url = std::env::var(V11_SCANNER_RPC_URL_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_SCANNER_RPC_URL_ENV} for the \
             AggregateStateNullifierV3 scanner (bitcoind RPC). Refusing to \
             fall back to the legacy Esplora commitment scanner — that would \
             corrupt the NfLog claim with SMT first-write semantics"
        )
    })?;
    if rpc_url.trim().is_empty() {
        bail!(
            "{V11_SCANNER_RPC_URL_ENV} is empty; refusing to start the v1.1 scanner \
             (no silent default)"
        );
    }
    let cookie = std::env::var(V11_SCANNER_COOKIE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_SCANNER_COOKIE_ENV} (bitcoind \
             cookie file). Refusing to fall back to the legacy scanner"
        )
    })?;
    if cookie.trim().is_empty() {
        bail!(
            "{V11_SCANNER_COOKIE_ENV} is empty; refusing to start the v1.1 scanner \
             (no silent default)"
        );
    }
    Ok((rpc_url, std::path::PathBuf::from(cookie)))
}
