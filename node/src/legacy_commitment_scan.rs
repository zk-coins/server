//! Stage 3 seal for the legacy Commitment → SMT/MMR scan loop.
//!
//! The production binary claims the exclusive v1 NfLog stack and never
//! obtains a [`LegacyCommitmentScanCap`]. Possession of that type is the
//! only proof a caller may fold a bincode [`shared::commitment::Commitment`]
//! into the SMT/MMR — and the type is unobtainable outside this crate's
//! own `#[cfg(test)]`. A feature flag cannot reopen it.
//!
//! Stage 4 deletes this module. Stage 3 makes the path unreachable.

use std::sync::{Arc, Mutex};

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use shared::commitment::Commitment;
use tokio::sync::mpsc;

use crate::db;
use crate::esplora_bound::EsploraReadClient;
use crate::persist_state_from_sync_context;
use crate::publisher::EsploraConfig;
use crate::scanner_runtime::scan_for_inscriptions;
use crate::scanner_ws::{run_scanner_ws, ScannerWsConfig};
use crate::state::State;
use crate::NETWORK_CONFIG;

/// Capability token required to run the legacy Commitment scan fold.
///
/// Private field; the only mint is [`LegacyCommitmentScanCap::mint_for_test`]
/// under `#[cfg(test)]` of this crate. Dependency builds never see that
/// constructor (no Cargo feature).
pub struct LegacyCommitmentScanCap {
    _private: (),
}

#[cfg(test)]
impl LegacyCommitmentScanCap {
    /// Residual unit-test mint. Absent from every dependency edge.
    pub fn mint_for_test() -> Self {
        Self { _private: () }
    }
}

/// Legacy Commitment → SMT/MMR Esplora scan loop.
///
/// **Stage 3:** possession of [`LegacyCommitmentScanCap`] is the only way
/// to reach this sink. The cap has no production constructor — only
/// `#[cfg(test)]` of this crate can mint one — so no production binary,
/// release build, downstream test target, or feature edge can invoke the
/// fold. Stage 4 deletes the body.
pub async fn run_legacy_commitment_scan_loop(
    _cap: LegacyCommitmentScanCap,
    pool: Arc<sqlx::PgPool>,
    state: Arc<Mutex<State>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try to load the latest block hash from Postgres or fall back to
    // Esplora's current tip. The Postgres row is written atomically
    // alongside the SMT/MMR snapshot in the scanner callback, which is
    // the structural fix for issue #11.
    let network_config: &EsploraConfig = &NETWORK_CONFIG;
    let start_block_hash = match db::load_latest_block(&pool).await? {
        Some(hash_bytes) => {
            let hash = BlockHash::from_byte_array(hash_bytes);
            println!("Resuming from previously saved block: {}", hash);
            hash
        }
        None => {
            println!("No saved block hash found, fetching latest from Esplora...");
            let client = EsploraReadClient::connect(&network_config.url)
                .map_err(|e| format!("EsploraReadClient::connect: {e}"))?;
            let tip_hash = client
                .get_tip_hash()
                .await
                .map_err(|e| format!("get_tip_hash: {e}"))?;
            println!("Fetched latest tip hash from Esplora: {}", tip_hash);
            tip_hash
        }
    };

    // Clones for the scanner callback closure.
    let pool_for_callback = Arc::clone(&pool);
    let pool_for_scanner = (*pool).clone();
    let state_for_callback = Arc::clone(&state);

    // Event-driven chain ingestion (issue #84). The previous
    // implementation polled `get_tip_hash` every 30 s, gating
    // visibility on `/api/mint` and `/api/send` by up to a full
    // block-time + poll-interval. `scanner_ws::run_scanner_ws`
    // subscribes to the Esplora WebSocket stream and publishes
    // each new tip into the bounded channel below; the scanner
    // runtime drains the channel and walks forward through the
    // block-status `next_best` chain between events.
    //
    // Channel depth = 64: plenty of headroom for the burst the
    // initial `blocks` seed produces on subscribe (3-15 entries
    // observed), bounded so a stuck consumer cannot grow the
    // queue without bound.
    let ws_config = ScannerWsConfig::from_network_config(network_config);
    println!(
        "Event-driven scanner: WS={} (sourced from NETWORK_CONFIG; \
         set via ESPLORA_WS_URL — required, no default)",
        ws_config.url
    );
    let (tip_tx, tip_rx) = mpsc::channel::<bitcoin::BlockHash>(64);
    tokio::spawn(run_scanner_ws(ws_config, tip_tx));

    scan_for_inscriptions(network_config, start_block_hash, Some(pool_for_scanner), &move |content_bytes: Vec<u8>, commit_txid, current_block_hash| {
        println!("Received content size: {} bytes", content_bytes.len());

        // Try to deserialize the content as a Commitment
        match bincode::deserialize::<Commitment>(&content_bytes) {
            Ok(commitment) => {
                println!("Successfully deserialized as commitment");
                println!("Public key: {}", commitment.public_key);

                // Verify the commitment
                if !commitment.verify() {
                    println!("Commitment verification failed, not adding to state");
                    return;
                }
                println!("Commitment signature verified successfully");

                // Phase E: if the in-process mint flow has already
                // advanced this inscription through `state.update` (the
                // `pending_inscriptions` row is `complete`), the
                // scanner has nothing to do — its `state.update` call
                // would be a no-op for the SMT (same key + same value
                // → idempotent insert) but would diverge the MMR
                // because `mmr.append` is monotonic. Skipping early
                // also avoids a redundant `persist_state_tx`. Any
                // other status (including a missing row, which covers
                // out-of-band recovery inscriptions and inscriptions
                // from a previous boot whose mint flow crashed before
                // marking the row complete) falls through to the
                // regular state.update path.
                let commit_txid_bytes = commit_txid.as_byte_array();
                let pending_status = persist_pending_status_lookup(
                    &pool_for_callback,
                    commit_txid_bytes,
                );

                // observed_inscriptions: every commitment the scanner
                // extracts from on-chain gets a row, regardless of
                // whether `state.update` runs. `source` flags whether
                // this came from our own publisher (pending row exists)
                // or another operator's node / a recovery CLI. Captured
                // here — once per call — so the row's `commitment` /
                // `public_key` columns survive even if the early-return
                // below short-circuits the rest of the callback.
                {
                    let source: &'static str = if pending_status.is_some() {
                        "own"
                    } else {
                        "external"
                    };
                    let entry = crate::db::ObservedInscriptionEntry {
                        commit_txid: commit_txid_bytes.to_vec(),
                        block_hash: Some(current_block_hash.to_byte_array().to_vec()),
                        block_height: None, // not in scanner callback scope today
                        source,
                        commitment: content_bytes.clone(),
                        public_key: commitment.public_key.serialize().to_vec(),
                        integrated: false, // will be flipped post-state.update below
                    };
                    let pool = (*pool_for_callback).clone();
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async move {
                            if let Err(e) =
                                crate::db::insert_observed_inscription(&pool, &entry).await
                            {
                                eprintln!("Failed to persist observed_inscription: {}", e);
                            }
                        });
                    });
                }

                if crate::scanner::should_skip_scanner_state_update(pending_status.as_deref()) {
                    println!(
                        "scanner: commit {} already integrated by mint_handler — skipping state.update",
                        commit_txid
                    );
                    return;
                }

                // Capture the public_key before moving `commitment` into
                // `state.update` so we can reference it in the Err arm.
                let pubkey_for_log = commitment.public_key;

                // Lock-scope: do the state mutation, capture the bytes
                // needed for persistence, then DROP THE LOCK before the
                // async DB call. Holding `std::sync::Mutex` across an
                // .await is unsound; also we want subsequent commitments
                // to make progress while the previous tx commits.
                let snapshot = {
                    let mut state_guard = state_for_callback.lock().unwrap();
                    match state_guard.update_and_snapshot_for_persist(&[commitment]) {
                        Ok((new_root, smt_bytes, mmr_bytes, root_index_entry)) => {
                            Some((new_root, smt_bytes, mmr_bytes, root_index_entry))
                        }
                        Err(e) => {
                            // Errors are logged but do NOT panic — the scanner is
                            // best-effort and we never want a single bad commitment
                            // (replay, client bug, or a re-scan after crash where
                            // the SMT already has this public_key with a different
                            // leaf value) to take the whole REST API down. The
                            // scanner advances to the next block regardless.
                            eprintln!(
                                "Skipping commitment for public_key {}: state.update failed: {}",
                                pubkey_for_log, e
                            );
                            None
                        }
                    }
                }; // mutex dropped here, BEFORE the async tx below

                if let Some((new_root, smt_bytes, mmr_bytes, root_index_entry)) = snapshot {
                    let block_hash_bytes = current_block_hash.to_byte_array();

                    // The callback runs INSIDE the async
                    // `scan_for_inscriptions` task on a multi_thread
                    // tokio runtime, so we cannot just
                    // `Handle::current().block_on(...)` — the docs say
                    // "may panic when called from a thread that is part
                    // of the current Tokio runtime" and on
                    // `#[tokio::main]` (multi_thread by default) it
                    // does panic the first time a real inscription is
                    // scanned. The fix is the documented
                    // `block_in_place(|| Handle::current().block_on(…))`
                    // pattern, encapsulated in
                    // `persist_state_from_sync_context`.
                    //
                    // The freshly-inserted `mmr_root_index` row rides
                    // along in the SAME transaction (Phase C). Folding
                    // it in here closes the crash window the previous
                    // two-call shape opened: a crash between the state
                    // snapshot and the standalone root_index INSERT
                    // resumed the scanner from a `latest_block` whose
                    // MMR already contained the new leaf, so the
                    // re-scanned commit advanced the MMR a second
                    // time, the new `prev_mmr_root` diverged, and the
                    // originally-missing row was never healed. With
                    // both writes atomic, a crash before COMMIT leaves
                    // the saved `latest_block` BEFORE this block; the
                    // re-scan replays `state.update` against the same
                    // unchanged MMR and writes the same row again
                    // (ON CONFLICT DO NOTHING is a no-op when it
                    // already landed).
                    let root_index_ref = root_index_entry
                        .as_ref()
                        .map(|(p, s, i)| (p, s, *i as u64));
                    let persist_result = persist_state_from_sync_context(
                        &pool_for_callback,
                        &smt_bytes,
                        &mmr_bytes,
                        &block_hash_bytes,
                        root_index_ref,
                    );
                    match persist_result {
                        Ok(()) => {
                            println!(
                                "Persisted state. New MMR root: {}",
                                hex::encode(zkcoins_program::hash::digest_to_bytes(&new_root))
                            );
                            // Phase E: if this commit came from our own
                            // mint flow but crashed between broadcast
                            // Ok and `state.update` (so the row is
                            // still at `reveal_broadcast`), the scanner
                            // has just completed the integration; mark
                            // the row `complete` so a future re-scan
                            // skips its state.update path. For rows
                            // that never existed (external / recovery
                            // inscriptions) the UPDATE simply affects
                            // zero rows, which is correct.
                            if pending_status.is_some() {
                                if let Err(e) = mark_pending_complete_from_sync_context(
                                    &pool_for_callback,
                                    commit_txid_bytes,
                                ) {
                                    eprintln!(
                                        "Failed to mark pending_inscriptions {} complete after scanner state.update: {}",
                                        commit_txid, e
                                    );
                                }
                            }

                            // Flip the matching `observed_inscriptions`
                            // row to `integrated = true, integrated_at
                            // = NOW()`. The row was inserted earlier
                            // in this callback with `integrated =
                            // false`; the UPDATE is the second half of
                            // the two-step lifecycle (insert at
                            // observation, mark integrated after the
                            // SMT/MMR write lands). Idempotent — the
                            // WHERE filter is keyed on `integrated =
                            // FALSE` so re-runs (scanner replay) are a
                            // no-op.
                            let pool_clone = (*pool_for_callback).clone();
                            let txid_bytes = commit_txid_bytes.to_vec();
                            tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(async move {
                                    if let Err(e) = crate::db::mark_observed_inscription_integrated(
                                        &pool_clone,
                                        &txid_bytes,
                                    )
                                    .await
                                    {
                                        eprintln!(
                                            "Failed to flip observed_inscriptions.integrated: {}",
                                            e
                                        );
                                    }
                                });
                            });
                        }
                        Err(e) => eprintln!("persist_state_tx failed: {}", e),
                    }
                }
            }
            Err(e) => {
                // Print more detailed debug information
                println!("Found inscription with our message but failed to deserialize as commitment\nError: {}", e);
            }
        }
    }, tip_rx)
    .await?;

    Ok(())
}

/// Synchronous wrapper around
/// [`db::pending_inscription_status_by_commit_txid`] for the scanner
/// callback's pre-`state.update` lookup (Phase E).
///
/// Mirrors [`persist_state_from_sync_context`]: the scanner callback is
/// a sync `Fn` invoked from a multi_thread tokio worker, and the
/// `Handle::current().block_on(...)` bare form panics there. We use
/// `block_in_place` + `Handle::current().block_on(...)`, exactly as the
/// state-persist helper does. DB errors are swallowed by the call site
/// (the scanner falls through to its normal `state.update` path on
/// `None`), so this helper returns the inner `Option<String>` directly
/// after logging any failure.
fn persist_pending_status_lookup(pool: &sqlx::PgPool, commit_txid_bytes: &[u8]) -> Option<String> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(db::pending_inscription_status_by_commit_txid(
                pool,
                commit_txid_bytes,
            ))
            .unwrap_or_else(|e| {
                eprintln!(
                    "scanner: pending_inscriptions lookup for commit {} failed: {} (falling through to state.update)",
                    hex::encode(commit_txid_bytes),
                    e
                );
                None
            })
    })
}

/// Synchronous wrapper around
/// [`db::update_pending_status`] for the scanner callback's
/// post-`state.update` advance to `complete` (Phase E).
///
/// Same multi_thread tokio bridging story as
/// [`persist_pending_status_lookup`]. Errors propagate to the caller so
/// the callback can log them with the right context line.
fn mark_pending_complete_from_sync_context(
    pool: &sqlx::PgPool,
    commit_txid_bytes: &[u8],
) -> Result<(), sqlx::Error> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(db::update_pending_status(
            pool,
            commit_txid_bytes,
            db::PENDING_STATUS_COMPLETE,
        ))
    })
}
