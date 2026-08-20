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
//! all-or-nothing via [`crate::v1::db_v1::persist_engine_snapshot`]);
//! apply paths restore the in-memory engine from a pre-mutation snapshot
//! when persist fails so the live adapter never advances past durable
//! state.

use anyhow::{bail, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use shared::spec_v1::{ChainPosition, PublishedNullifier};
use std::path::Path;
use zkcoins_prover::state_engine::StateEngine;

use super::adapter::EngineAdapter;
use super::separation::{ensure_v1_publisher_allowed, require_v1_process_for_nflog_write};

/// Outcome counters for one fold pass (forward scan or reorg apply).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FoldStats {
    pub appended: u64,
    pub duplicate_ignored: u64,
    pub below_activation: u64,
}

/// Sort key = declaration order of [`ChainPosition`]:
/// `(height, tx_index, vin_index, member_index)`.
pub(crate) fn sort_canonical(survivors: &mut [PublishedNullifier]) {
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
/// Pure core used by crate-internal tests and by the sealed adapter apply
/// path. **Crate-private scan-apply sink** — downstream must use
/// [`apply_forward_scan`] / [`apply_canonical_survivors`].
pub(crate) fn fold_survivors_into_engine(
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

        match engine
            .append_nullifier(zkcoins_prover::state_engine::ScannedNullifier::from_survivor(&nf))
        {
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
/// [`super::db_v1::EngineSnapshot`] (accounts stay byte-identical).
pub(crate) fn first_occurrence_nflog_pairs(
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
                    shared::spec_v1::NfLogEntry { pk: nf.pk, r: nf.r },
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
///
/// **Crate-private scan-apply sink.** Downstream reorg apply goes through
/// [`apply_canonical_survivors`] only.
pub(crate) fn replace_engine_nflog_from_survivors(
    engine: &mut StateEngine,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
) -> Result<FoldStats> {
    use super::db_v1::EngineSnapshot;

    let activation_height = engine.activation_height();
    let (nflog_pairs, stats) = first_occurrence_nflog_pairs(activation_height, survivors)?;

    // Snapshot accounts (and current meta) without needing AccountRecord: Clone.
    let mut snap = EngineSnapshot::from_engine_with_tip_hash(engine, tip_hash, Vec::new());
    snap.tip_height = tip_height;
    snap.tip_hash = tip_hash;
    snap.nflog = nflog_pairs;

    let rebuilt = snap
        .into_engine()
        .context("replace_engine_nflog_from_survivors: into_engine")?;
    *engine = rebuilt;
    Ok(stats)
}

/// Durably record the block hash of every block the scanner observed this poll.
///
/// Writes one `block_log` row per entry in `blocks` via
/// [`crate::db::insert_block_log`], refreshing the observation time and
/// backfilling a missing header timestamp when the block hash already exists.
/// The live v1.1 scan loop calls this **unconditionally** after each
/// successful `scan_to_tip` so below-tip §5.7 anchor locators can resolve
/// inclusion hashes through [`crate::db::load_block_hash_at_height`].
/// `block_time` is the header nTime carried from the scanner's already-fetched
/// block; this function performs no independent RPC lookup.
///
/// Does not touch the in-memory engine or the durable inscription catalog —
/// only the block-observation audit log.
pub async fn record_scanned_block_hashes(
    pool: &sqlx::PgPool,
    blocks: &[zkcoins_prover::scanner::BlockScanResult],
) -> Result<()> {
    for block in blocks {
        let block_height = i64::try_from(block.height).with_context(|| {
            format!(
                "record_scanned_block_hashes: block height {} does not fit i64",
                block.height
            )
        })?;
        let inscription_count = i32::try_from(block.inscriptions_seen).with_context(|| {
            format!(
                "record_scanned_block_hashes: inscriptions_seen {} at height {} does not fit i32",
                block.inscriptions_seen, block.height
            )
        })?;
        let entry = crate::db::BlockLogEntry {
            block_time: Some(i64::from(block.block_time)),
            block_hash: block.block_hash.to_byte_array().to_vec(),
            block_height: Some(block_height),
            inscription_count,
            processing_duration_us: None,
        };
        crate::db::insert_block_log(pool, &entry)
            .await
            .with_context(|| {
                format!(
                    "record_scanned_block_hashes: insert block_log failed \
                     at height {} hash={}",
                    block.height,
                    hex::encode(block.block_hash.to_byte_array())
                )
            })?;
    }
    Ok(())
}

/// One BIP-113 prelude header: height in `[activation-10, activation)`,
/// canonical hash, header nTime (Bitcoin `time`, not `mediantime`).
///
/// Persisted so check (v) can re-derive MTP for inclusion heights in
/// `[activation, activation+9]` without folding NfLog below activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip113PreludeHeader {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub n_time: u32,
}

/// True only for Bitcoin Core's missing-height / unknown-hash replies.
/// Substring matches on `"-5"`, `"-8"`, or bare `"not found"` are too
/// broad (they would swallow "Method not found" and neighbouring RPC
/// codes); those must stay fail-closed.
fn is_skippable_bitcoind_lookup_error(err: &bitcoincore_rpc::Error) -> bool {
    let msg = err.to_string();
    msg.contains("Block height out of range")
        || msg.contains("Block not found")
        || msg.contains("Block header not found")
}

/// Persist prelude headers into `block_log` via [`crate::db::insert_block_log`].
///
/// `inscription_count = 0`, `processing_duration_us = None`. Idempotent
/// (ON CONFLICT COALESCE). An empty slice is `Ok` (activation height 0).
/// Does not fold NfLog.
pub async fn record_bip113_prelude_headers(
    pool: &sqlx::PgPool,
    headers: &[Bip113PreludeHeader],
) -> Result<()> {
    for header in headers {
        let block_height = i64::try_from(header.height).with_context(|| {
            format!(
                "record_bip113_prelude_headers: block height {} does not fit i64",
                header.height
            )
        })?;
        let entry = crate::db::BlockLogEntry {
            block_time: Some(i64::from(header.n_time)),
            block_hash: header.block_hash.to_vec(),
            block_height: Some(block_height),
            inscription_count: 0,
            processing_duration_us: None,
        };
        crate::db::insert_block_log(pool, &entry)
            .await
            .with_context(|| {
                format!(
                    "record_bip113_prelude_headers: insert block_log failed \
                     at height {} hash={}",
                    header.height,
                    hex::encode(header.block_hash)
                )
            })?;
    }
    Ok(())
}

/// Fetch prelude headers from bitcoind for `[activation.saturating_sub(10), activation)`.
///
/// Returns header nTime (`time`), never `mediantime`. Does not collect or fold
/// nullifiers. An empty range (activation 0) returns `Ok(vec![])` without
/// opening an RPC client. Heights the connected node does not yet know are
/// skipped; other RPC errors fail closed.
pub fn fetch_bip113_prelude_headers(
    rpc_url: &str,
    cookie_path: &Path,
    activation_height: u64,
) -> Result<Vec<Bip113PreludeHeader>> {
    use bitcoincore_rpc::RpcApi;

    let first_height = activation_height.saturating_sub(10);
    if first_height >= activation_height {
        return Ok(Vec::new());
    }

    let client = bitcoincore_rpc::Client::new(
        rpc_url.trim_end_matches('/'),
        bitcoincore_rpc::Auth::CookieFile(cookie_path.to_path_buf()),
    )
    .context("bitcoind RPC client for BIP-113 prelude headers")?;

    let mut headers = Vec::new();
    for height in first_height..activation_height {
        let hash = match client.get_block_hash(height) {
            Ok(hash) => hash,
            Err(err) if is_skippable_bitcoind_lookup_error(&err) => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("getblockhash for BIP-113 prelude header at height {height}")
                });
            }
        };
        let info = match client.get_block_header_info(&hash) {
            Ok(info) => info,
            Err(err) if is_skippable_bitcoind_lookup_error(&err) => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("getblockheader for BIP-113 prelude header at height {height}")
                });
            }
        };
        let reported_height = u64::try_from(info.height).with_context(|| {
            format!(
                "getblockheader height {} at requested height {height} does not fit u64",
                info.height
            )
        })?;
        if reported_height != height {
            bail!("getblockheader height {reported_height} != requested prelude height {height}");
        }
        let n_time = u32::try_from(info.time).with_context(|| {
            format!(
                "header time {} at height {height} does not fit u32",
                info.time
            )
        })?;
        headers.push(Bip113PreludeHeader {
            height,
            block_hash: hash.to_byte_array(),
            n_time,
        });
    }
    Ok(headers)
}

struct NullBlockTimeRow {
    hash: [u8; 32],
    hash_bytes: Vec<u8>,
}

/// Blocking bitcoind nTime lookup for NULL `block_time` rows.
///
/// Opens the RPC client and walks headers on the calling thread. Callers
/// must wrap this in `spawn_blocking` so the async scan loop does not
/// run `Client::new` or `get_block_header_info` on a Tokio worker.
fn lookup_n_times_for_null_rows(
    rpc_url: &str,
    cookie_path: &Path,
    rows: Vec<NullBlockTimeRow>,
) -> Result<Vec<(NullBlockTimeRow, u32)>> {
    use bitcoincore_rpc::RpcApi;

    let client = bitcoincore_rpc::Client::new(
        rpc_url.trim_end_matches('/'),
        bitcoincore_rpc::Auth::CookieFile(cookie_path.to_path_buf()),
    )
    .context("bitcoind RPC client for NULL block_time backfill")?;

    let mut found = Vec::new();
    for row in rows {
        let hash = BlockHash::from_byte_array(row.hash);
        match client.get_block_header_info(&hash) {
            Ok(info) => {
                let n_time = u32::try_from(info.time).with_context(|| {
                    format!(
                        "header time {} for hash {} does not fit u32",
                        info.time,
                        hex::encode(row.hash)
                    )
                })?;
                found.push((row, n_time));
            }
            Err(err) if is_skippable_bitcoind_lookup_error(&err) => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "getblockheader for NULL block_time backfill hash={}",
                        hex::encode(row.hash)
                    )
                });
            }
        }
    }
    Ok(found)
}

/// Backfill `block_log.block_time` where it is still SQL NULL, by hash.
///
/// Looks up header nTime (`time`, never `mediantime`) and writes it through
/// [`crate::db::fill_null_block_time`] so a NULL timestamp is filled without
/// bumping `processed_at` (height lookups order by that column; an orphan
/// must not steal the height). Unknown hashes are skipped; other RPC errors
/// fail closed. Bitcoind RPC runs on `spawn_blocking`; only the Postgres
/// read/write stays on the async task.
pub async fn backfill_null_block_times(
    pool: &sqlx::PgPool,
    rpc_url: &str,
    cookie_path: &Path,
) -> Result<()> {
    let raw_rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT block_hash FROM block_log WHERE block_time IS NULL")
            .fetch_all(pool)
            .await
            .context("backfill_null_block_times: load NULL block_time rows")?;
    if raw_rows.is_empty() {
        return Ok(());
    }

    let mut rows = Vec::with_capacity(raw_rows.len());
    for (hash_bytes,) in raw_rows {
        let hash: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "backfill_null_block_times: block_hash length {} is not 32 bytes",
                hash_bytes.len()
            )
        })?;
        rows.push(NullBlockTimeRow { hash, hash_bytes });
    }

    let rpc_url = rpc_url.to_string();
    let cookie_path = cookie_path.to_path_buf();
    let looked_up = tokio::task::spawn_blocking(move || {
        lookup_n_times_for_null_rows(&rpc_url, &cookie_path, rows)
    })
    .await
    .context("backfill_null_block_times: bitcoind lookup join")?
    .context("backfill_null_block_times: bitcoind lookup")?;

    for (row, n_time) in looked_up {
        crate::db::fill_null_block_time(pool, &row.hash_bytes, i64::from(n_time))
            .await
            .with_context(|| {
                format!(
                    "backfill_null_block_times: fill NULL block_time failed hash={}",
                    hex::encode(row.hash)
                )
            })?;
    }
    Ok(())
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
///
/// `survivors` is the scanner's full survivor stream (for coupling check);
/// `accepted_inscriptions` is the scanner's full accepted stream. Expansion
/// from inscriptions is the **sole** fold source; `already_folded` filters
/// the forward delta. Catalog append is the subset not already durable.
/// New catalog heads must have every member present in that delta — see
/// [`ensure_new_catalog_delta_coupled`].
///
/// Full-stream coupling ([`ensure_accepted_survivor_coupling`]) runs here,
/// immediately before mutate, so a forward-only caller cannot skip it.
pub async fn apply_forward_scan(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
    accepted_inscriptions: &[zkcoins_prover::scanner::ScannedInscription],
    already_folded: &std::collections::HashSet<(u64, u32, u32, u32, [u8; 32])>,
) -> Result<FoldStats> {
    require_v1_process_for_nflog_write()?;
    ensure_accepted_survivor_coupling(survivors, accepted_inscriptions).with_context(|| {
        format!(
            "apply_forward_scan: stream coupling refused \
             (survivor_count={} inscription_count={})",
            survivors.len(),
            accepted_inscriptions.len()
        )
    })?;
    // Expansion is the sole fold source; filter against already-folded keys
    // for the forward delta (first-occurrence losers stay out of NfLog but
    // must not re-enter the fold after a still-canonical restart).
    let expanded = survivors_from_accepted_inscriptions(accepted_inscriptions)?;
    let new_survivors: Vec<PublishedNullifier> = expanded
        .iter()
        .copied()
        .filter(|nf| {
            !already_folded.contains(&(
                nf.chain_pos.height,
                nf.chain_pos.tx_index,
                nf.chain_pos.vin_index,
                nf.chain_pos.member_index,
                nf.pk,
            ))
        })
        .collect();

    let _write_gate = adapter.lock_writes().await;
    // Catalog delta under the write gate (heads not yet durable). Refuse new
    // catalog rows whose members are missing from `new_survivors` before any
    // mutate so a decoupled feed cannot fold NfLog then leave catalog orphaned
    // (or the reverse).
    let existing_keys: std::collections::HashSet<(u64, u32, u32)> = adapter
        .catalog_snapshot()
        .iter()
        .map(|i| (i.height, i.tx_index, i.vin_index))
        .collect();
    let catalog_rows: Vec<crate::v1::db_v1::CatalogInscription> = accepted_inscriptions
        .iter()
        .filter(|ins| !existing_keys.contains(&(ins.height, ins.tx_index, ins.vin_index)))
        .map(crate::v1::db_v1::CatalogInscription::from_scanned)
        .collect();
    ensure_new_catalog_delta_coupled(&catalog_rows, &new_survivors)?;

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
        fold_survivors_into_engine(engine, &new_survivors)
    }) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) | Err(e) => {
            adapter
                .restore_live(backup)
                .context("apply_forward_scan: restore after mutate error")?;
            return Err(e);
        }
    };
    // Catalog append in the same mutate window as the fold; persist writes
    // both in one transaction (see EngineAdapter::persist / db_v1::clear_all).
    //
    // Delta was computed above (crate-private `catalog_snapshot`) so the
    // binary does not re-derive catalog keys.
    if let Err(e) = adapter.append_catalog(&catalog_rows) {
        adapter
            .restore_live(backup)
            .context("apply_forward_scan: restore after catalog append error")?;
        return Err(e);
    }
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
///
/// `survivors` is the scanner's full survivor stream (for coupling check);
/// `inscriptions` is the scanner's full accepted stream. Expansion from
/// inscriptions is the **sole** fold/replace source. Full streams must
/// couple: every accepted inscription expands to the survivors that share
/// its head key, and every survivor belongs to an accepted inscription
/// ([`ensure_accepted_survivor_coupling`]) — checked immediately before
/// mutate so a second caller cannot skip it.
pub async fn apply_canonical_survivors(
    adapter: &EngineAdapter,
    tip_height: u64,
    tip_hash: [u8; 32],
    survivors: &[PublishedNullifier],
    inscriptions: &[zkcoins_prover::scanner::ScannedInscription],
) -> Result<FoldStats> {
    require_v1_process_for_nflog_write()?;
    ensure_accepted_survivor_coupling(survivors, inscriptions).with_context(|| {
        format!(
            "apply_canonical_survivors: stream coupling refused \
             (survivor_count={} inscription_count={})",
            survivors.len(),
            inscriptions.len()
        )
    })?;
    // Expansion is the sole NfLog replace source (equals `survivors` after
    // the coupling check above).
    let expanded = survivors_from_accepted_inscriptions(inscriptions)?;
    let _write_gate = adapter.lock_writes().await;
    let backup = adapter.snapshot_live();

    let stats = match adapter.with_engine_mut(|engine| {
        replace_engine_nflog_from_survivors(engine, tip_height, tip_hash, &expanded)
    }) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) | Err(e) => {
            adapter
                .restore_live(backup)
                .context("apply_canonical_survivors: restore after mutate error")?;
            return Err(e);
        }
    };
    // Full-replace the catalog from the post-reorg accepted stream in the
    // same window as NfLog replace; durable write is one TX.
    let catalog_rows: Vec<crate::v1::db_v1::CatalogInscription> = inscriptions
        .iter()
        .map(crate::v1::db_v1::CatalogInscription::from_scanned)
        .collect();
    if let Err(e) = adapter.replace_catalog(catalog_rows) {
        adapter
            .restore_live(backup)
            .context("apply_canonical_survivors: restore after catalog replace error")?;
        return Err(e);
    }
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
pub(crate) const MAX_RECOVERABLE_REORG_DEPTH: u64 = 5;

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
    StillCanonical { tip_height: u64, tip_hash: [u8; 32] },
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
    /// Caller must: leave `v1_scan` unready, leave `finality_ok` /
    /// `deep_reorg` untouched, back off, and re-run the full verification.
    /// Never assume canonical, never assume reorg.
    RetryableIncompleteView { queried_height: u64, detail: String },
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
pub(crate) type FoldedSurvivorKey = (u64, u32, u32, u32, [u8; 32]);

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

/// Expand accepted inscriptions to the survivor stream they imply.
///
/// Same construction the script-plonky2 scanner uses after steps 1–3: one
/// [`PublishedNullifier`] per member, in inscription then member order.
/// Production apply paths treat this expansion as the **sole** survivor
/// source so catalog and NfLog cannot be fed independent streams.
///
/// Crate-private: called from [`apply_forward_scan`] /
/// [`apply_canonical_survivors`] (and unit tests). Not part of the public
/// surface — the binary passes scanner streams only.
pub(crate) fn survivors_from_accepted_inscriptions(
    inscriptions: &[zkcoins_prover::scanner::ScannedInscription],
) -> Result<Vec<PublishedNullifier>> {
    let mut out = Vec::new();
    for ins in inscriptions {
        if ins.members.is_empty() {
            bail!(
                "accepted inscription at ({},{},{}) has zero members",
                ins.height,
                ins.tx_index,
                ins.vin_index
            );
        }
        for (i, (pk, r)) in ins.members.iter().enumerate() {
            let member_index = u32::try_from(i).with_context(|| {
                format!(
                    "member_index {i} at ({},{},{}) does not fit in u32",
                    ins.height, ins.tx_index, ins.vin_index
                )
            })?;
            out.push(PublishedNullifier {
                chain_pos: ChainPosition {
                    height: ins.height,
                    tx_index: ins.tx_index,
                    vin_index: ins.vin_index,
                    member_index,
                },
                pk: *pk,
                r: *r,
            });
        }
    }
    Ok(out)
}

/// Fail loud when the survivor list is not exactly the member expansion of
/// `inscriptions` (order and content).
///
/// Counts in the error message: `survivor_count` vs `inscription_member_count`
/// (and `inscription_count` for context). Either direction of drift refuses.
///
/// Crate-private: invoked by the apply paths immediately before mutate (and
/// by unit tests). Not part of the public surface.
pub(crate) fn ensure_accepted_survivor_coupling(
    survivors: &[PublishedNullifier],
    inscriptions: &[zkcoins_prover::scanner::ScannedInscription],
) -> Result<()> {
    let expected = survivors_from_accepted_inscriptions(inscriptions)?;
    if survivors.len() != expected.len() {
        bail!(
            "accepted-inscription / survivor stream coupling broken: \
             survivor_count={} inscription_member_count={} inscription_count={}",
            survivors.len(),
            expected.len(),
            inscriptions.len()
        );
    }
    for (i, (got, want)) in survivors.iter().zip(expected.iter()).enumerate() {
        if got != want {
            bail!(
                "accepted-inscription / survivor stream coupling broken at index {i}: \
                 survivor_count={} inscription_member_count={} inscription_count={}; \
                 got chain_pos=({},{},{},{}) pk={} want chain_pos=({},{},{},{}) pk={}",
                survivors.len(),
                expected.len(),
                inscriptions.len(),
                got.chain_pos.height,
                got.chain_pos.tx_index,
                got.chain_pos.vin_index,
                got.chain_pos.member_index,
                hex::encode(got.pk),
                want.chain_pos.height,
                want.chain_pos.tx_index,
                want.chain_pos.vin_index,
                want.chain_pos.member_index,
                hex::encode(want.pk),
            );
        }
    }
    Ok(())
}

/// Forward-path delta check: every newly appended catalog head must have all
/// of its members present in `new_survivors`.
///
/// The reverse (new survivors without new catalog heads) is allowed — after a
/// still-canonical restart, first-occurrence losers reappear as fold delta
/// while their catalog head is already durable.
fn ensure_new_catalog_delta_coupled(
    catalog_rows: &[crate::v1::db_v1::CatalogInscription],
    new_survivors: &[PublishedNullifier],
) -> Result<()> {
    if catalog_rows.is_empty() {
        return Ok(());
    }
    let mut expected: Vec<PublishedNullifier> = Vec::new();
    for ins in catalog_rows {
        for (member_index, pk, r) in &ins.members {
            expected.push(PublishedNullifier {
                chain_pos: ChainPosition {
                    height: ins.height,
                    tx_index: ins.tx_index,
                    vin_index: ins.vin_index,
                    member_index: *member_index,
                },
                pk: *pk,
                r: *r,
            });
        }
    }
    let head_keys: std::collections::HashSet<(u64, u32, u32)> = catalog_rows
        .iter()
        .map(|i| (i.height, i.tx_index, i.vin_index))
        .collect();
    let relevant: Vec<&PublishedNullifier> = new_survivors
        .iter()
        .filter(|s| {
            head_keys.contains(&(
                s.chain_pos.height,
                s.chain_pos.tx_index,
                s.chain_pos.vin_index,
            ))
        })
        .collect();
    let mut missing = 0u64;
    for e in &expected {
        if !new_survivors.iter().any(|s| s == e) {
            missing += 1;
        }
    }
    if missing > 0 || relevant.len() != expected.len() {
        bail!(
            "forward catalog/survivor delta coupling broken: \
             new_catalog_inscriptions={} new_catalog_members={} \
             new_survivors_total={} new_survivors_for_new_catalog_heads={} \
             missing_member_rows={}",
            catalog_rows.len(),
            expected.len(),
            new_survivors.len(),
            relevant.len(),
            missing
        );
    }
    Ok(())
}

/// Build [`PublishedNullifier`] rows for one multi-member inscription at a
/// fixed chain position (member_index = 0..n-1). Test and synthetic helper.
#[cfg(test)]
pub(crate) fn members_to_published(
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

/// Env keys required to connect the script-plonky2 bitcoind scanner.
/// Missing any of them fails loud under v1.1 mode — never fall back to
/// the Esplora commitment scanner.
pub(crate) const V1_SCANNER_RPC_URL_ENV: &str = "ZKCOINS_V1_BITCOIND_RPC_URL";
pub(crate) const V1_SCANNER_COOKIE_ENV: &str = "ZKCOINS_V1_BITCOIND_COOKIE_PATH";

/// Resolve bitcoind scanner config from env (no silent defaults).
pub fn v1_bitcoind_rpc_from_env() -> Result<(String, std::path::PathBuf)> {
    // v1.1 exclusive claim required — never open bitcoind for NfLog under legacy.
    ensure_v1_publisher_allowed()?;

    let rpc_url = std::env::var(V1_SCANNER_RPC_URL_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_SCANNER_RPC_URL_ENV} for the \
             AggregateStateNullifierV3 scanner (bitcoind RPC). Refusing to \
             fall back to the legacy Esplora commitment scanner — that would \
             corrupt the NfLog claim with SMT first-write semantics"
        )
    })?;
    if rpc_url.trim().is_empty() {
        bail!(
            "{V1_SCANNER_RPC_URL_ENV} is empty; refusing to start the v1.1 scanner \
             (no silent default)"
        );
    }
    let cookie = std::env::var(V1_SCANNER_COOKIE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_SCANNER_COOKIE_ENV} (bitcoind \
             cookie file). Refusing to fall back to the legacy scanner"
        )
    })?;
    if cookie.trim().is_empty() {
        bail!(
            "{V1_SCANNER_COOKIE_ENV} is empty; refusing to start the v1.1 scanner \
             (no silent default)"
        );
    }
    Ok((rpc_url, std::path::PathBuf::from(cookie)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        insert_block_log, load_block_time_at_height, load_median_time_past, BlockLogEntry,
    };

    fn prelude_header(height: u64, n_time: u32) -> Bip113PreludeHeader {
        let mut block_hash = [0u8; 32];
        block_hash[0] = u8::try_from(height).expect("test prelude height fits u8");
        Bip113PreludeHeader {
            height,
            block_hash,
            n_time,
        }
    }

    #[tokio::test]
    async fn record_bip113_prelude_headers_persists_n_time_idempotently() {
        let scope = crate::test_db::setup_pool().await;
        let headers: Vec<Bip113PreludeHeader> = (90_u64..100)
            .map(|height| prelude_header(height, u32::try_from(height).unwrap()))
            .collect();

        record_bip113_prelude_headers(&scope.pool, &headers)
            .await
            .expect("first prelude persist");
        assert_eq!(
            load_block_time_at_height(&scope.pool, 90).await.unwrap(),
            Some(90)
        );
        assert_eq!(
            load_block_time_at_height(&scope.pool, 99).await.unwrap(),
            Some(99)
        );

        record_bip113_prelude_headers(&scope.pool, &headers)
            .await
            .expect("idempotent prelude persist");
        assert_eq!(
            load_block_time_at_height(&scope.pool, 90).await.unwrap(),
            Some(90)
        );
        assert_eq!(
            load_block_time_at_height(&scope.pool, 99).await.unwrap(),
            Some(99)
        );
    }

    #[tokio::test]
    async fn record_bip113_prelude_headers_completes_mtp_window_at_activation() {
        let scope = crate::test_db::setup_pool().await;
        let headers: Vec<Bip113PreludeHeader> = (90_u64..100)
            .map(|height| prelude_header(height, u32::try_from(height).unwrap()))
            .collect();
        record_bip113_prelude_headers(&scope.pool, &headers)
            .await
            .expect("prelude persist");

        insert_block_log(
            &scope.pool,
            &BlockLogEntry {
                block_time: Some(100),
                block_hash: {
                    let mut hash = [0u8; 32];
                    hash[0] = 100;
                    hash.to_vec()
                },
                block_height: Some(100),
                inscription_count: 0,
                processing_duration_us: None,
            },
        )
        .await
        .expect("inclusion height 100");

        assert!(
            load_median_time_past(&scope.pool, 100)
                .await
                .unwrap()
                .is_some(),
            "prelude 90-99 plus scanned 100 must complete the BIP-113 window"
        );
    }

    #[tokio::test]
    async fn record_bip113_prelude_headers_empty_slice_is_ok() {
        let scope = crate::test_db::setup_pool().await;
        record_bip113_prelude_headers(&scope.pool, &[])
            .await
            .expect("empty prelude slice is Ok");
    }

    #[test]
    fn fetch_bip113_prelude_headers_skips_rpc_when_activation_is_zero() {
        let headers =
            fetch_bip113_prelude_headers("http://127.0.0.1:1", Path::new("/nonexistent"), 0)
                .expect("empty prelude range must not open RPC");
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn backfill_null_block_times_is_ok_when_no_null_rows() {
        let scope = crate::test_db::setup_pool().await;
        backfill_null_block_times(&scope.pool, "http://127.0.0.1:1", Path::new("/nonexistent"))
            .await
            .expect("no NULL block_time rows must skip RPC");
    }
}
