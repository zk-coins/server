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
//! hash against the live chain **before** any fold:
//!
//! - tip still canonical → seed folded keys; forward-append only
//! - tip diverged / missing → full NfLog replace from the rescan survivor
//!   stream (equivalent to replaying from activation; NfLog is a pure
//!   function of the confirmed chain's first-occurrence winners)
//! - tip height > 0 with all-zero hash → refuse (ambiguous cursor)
//! - live-chain query failure → refuse (never fold onto an unverified tip)
//!
//! Property: after any crash or reorg, a restarted node reaches the same
//! accumulator a continuously running node would hold.
//!
//! A mid-apply crash leaves the previous snapshot (persist is
//! all-or-nothing via [`crate::v11::db_v11::persist_engine_snapshot`]);
//! retry reloads and re-applies from the scanner checkpoint.

use anyhow::{bail, Context, Result};
use shared::spec_v1::{ChainPosition, FoldOutcome, PublishedNullifier};
use zkcoins_prover::state_engine::StateEngine;

use super::adapter::EngineAdapter;
use super::separation::{ensure_v11_publisher_allowed, process_stack_mode, ScanStackMode};

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

/// Require an exclusive v1.1 process claim before mutating NfLog state.
///
/// Unset process mode is **not** permitted: an unset mode previously
/// allowed writes that later left v1.1 data under a legacy marker.
fn require_v11_process_for_nflog_write() -> Result<()> {
    match process_stack_mode() {
        Some(ScanStackMode::V11) => Ok(()),
        Some(ScanStackMode::Legacy) => bail!(
            "stack separation: refusing to fold NfLog while process \
             is claimed as legacy (no silent cross-stack write)"
        ),
        None => bail!(
            "stack separation: refusing to fold NfLog without a process \
             claim of ScanStackMode::V11 (no silent write under unset mode)"
        ),
    }
}

/// Forward-scan apply on the live adapter: fold new survivors, set tip, persist.
pub async fn apply_forward_scan(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    new_survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    require_v11_process_for_nflog_write()?;

    let stats = adapter.with_engine_mut(|engine| {
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
    })?;
    adapter.set_tip_hash(tip_hash);
    adapter
        .persist()
        .await
        .context("apply_forward_scan: persist")?;
    Ok(stats)
}

/// Reorg / full-rebuild apply: replace NfLog from the full post-reorg
/// (or post-rescan) survivor stream.
pub async fn apply_canonical_survivors(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    require_v11_process_for_nflog_write()?;
    let stats = adapter.with_engine_mut(|engine| {
        replace_engine_nflog_from_survivors(engine, tip_height, tip_hash, survivors)
    })?;
    adapter.set_tip_hash(tip_hash);
    adapter
        .persist()
        .await
        .context("apply_canonical_survivors: persist")?;
    Ok(stats)
}

/// Outcome of reconciling a persisted tip against the live Bitcoin chain.
///
/// Decides whether a restarted node may forward-append or must rebuild
/// the NfLog from the full canonical survivor stream.
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
    /// Persisted tip is no longer on the canonical chain (hash mismatch,
    /// height above live tip, or height missing). First apply after the
    /// rescan **must** full-replace the NfLog — never forward-fold into
    /// the stale accumulator.
    MustFullReplace {
        persisted_height: u64,
        persisted_hash: [u8; 32],
    },
}

/// Reconcile `(tip_height, tip_hash)` from the persisted engine against
/// the live chain.
///
/// `live_hash_at(height)` returns:
/// - `Ok(Some(hash))` when the height is on the live chain
/// - `Ok(None)` when the height is above the live tip (or otherwise absent)
/// - `Err(_)` on RPC / infrastructure failure — this function propagates
///   the error and **refuses** to classify the tip (never fold blind)
///
/// # Failures
///
/// - `tip_height > 0` with all-zero `tip_hash` (ambiguous cursor)
/// - live-chain query failure
pub fn reconcile_persisted_tip(
    tip_height: u64,
    tip_hash: [u8; 32],
    live_hash_at: impl FnOnce(u64) -> Result<Option<[u8; 32]>>,
) -> Result<PersistedTipReconciliation> {
    let zero = [0u8; 32];
    if tip_height == 0 && tip_hash == zero {
        return Ok(PersistedTipReconciliation::Fresh);
    }
    if tip_hash == zero {
        bail!(
            "v1.1 boot tip reconciliation: tip_height={tip_height} but tip_hash \
             is all-zero — ambiguous cursor; refusing to fold (restore a \
             snapshot with a real tip_hash or wipe v1.1 tables)"
        );
    }

    let live = live_hash_at(tip_height).context(
        "v1.1 boot tip reconciliation: live-chain query failed; \
         refusing to fold onto an unverified persisted tip",
    )?;

    match live {
        Some(hash) if hash == tip_hash => Ok(PersistedTipReconciliation::StillCanonical {
            tip_height,
            tip_hash,
        }),
        Some(_) | None => Ok(PersistedTipReconciliation::MustFullReplace {
            persisted_height: tip_height,
            persisted_hash: tip_hash,
        }),
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
