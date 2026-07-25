//! v1.1 scan-fold path: §3.6 first-occurrence into the EngineAdapter NfLog.
//!
//! The full chain-connectivity loop (bitcoind RPC, envelope parse, anchor
//! bound, signature verify) lives in `zkcoins_prover::scanner::Scanner`.
//! This module owns the **node-side apply** of already-validated survivors
//! into the Stage-1 persistence adapter, plus pure helpers for ordering
//! and first-occurrence so unit tests can prove §3.6 without a bitcoind.
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
//! A mid-apply crash leaves the previous snapshot (persist is
//! all-or-nothing via [`crate::v11::db_v11::persist_engine_snapshot`]);
//! retry reloads and re-applies from the scanner checkpoint.

use anyhow::{bail, Context, Result};
use shared::spec_v1::{ChainPosition, FoldOutcome, PublishedNullifier};
use zkcoins_prover::state_engine::StateEngine;

use super::adapter::EngineAdapter;
use super::separation::{ensure_v11_publisher_allowed, ScanStackMode};

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
pub async fn apply_forward_scan(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    new_survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    // Structural: only the v1.1 process may write the NfLog.
    // (Publisher allow-check is the same claim; reuse its error wording.)
    if super::separation::process_stack_mode() != Some(ScanStackMode::V11) {
        // Tests may call apply without process claim when they pass adapter
        // directly; require either process claim OR that caller uses the
        // adapter only after enforce. Fail if process explicitly claimed legacy.
        if let Some(ScanStackMode::Legacy) = super::separation::process_stack_mode() {
            bail!(
                "stack separation: refusing to fold NfLog while process \
                 is claimed as legacy (no silent cross-stack write)"
            );
        }
    }

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

/// Reorg apply: replace NfLog from the full post-reorg survivor stream.
pub async fn apply_canonical_survivors(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    if let Some(ScanStackMode::Legacy) = super::separation::process_stack_mode() {
        bail!(
            "stack separation: refusing reorg NfLog replace while process \
             is claimed as legacy"
        );
    }
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
