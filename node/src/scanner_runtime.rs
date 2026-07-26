//! Runtime bootstrap for the inscription scanner.
//!
//! This file is intentionally excluded from the coverage scope. The
//! functions below own the network I/O (HTTP REST calls to Esplora
//! for the per-block `get_block_txids` / `get_tx` lookups) and the
//! infinite scan loop — neither can be exercised by unit tests
//! without spinning up a fake Esplora server.
//!
//! The pure logic that can be tested without a Bitcoin node lives in
//! `scanner.rs` (filter_marker_txids, process_transaction_inscriptions,
//! extract_inscription_content) and is measured normally.
//!
//! Event-driven (issue #84): new chain tips arrive on an
//! `mpsc::Receiver<BlockHash>` fed by `scanner_ws::run_scanner_ws`.
//! Per-tip we walk forward through `get_block_status.next_best` until
//! we catch up with the published hash, then `rx.recv().await` blocks
//! until the next WS event. The chain-tip wait path no longer sleeps;
//! the only remaining sleep is a bounded retry on transient HTTP
//! failures, marked with the `scanner-polling-ok:` token (NOT an
//! `#[allow(...)]` attribute — see issue #84 round-4 MINOR 4) so the
//! CI lint added in the same PR grandfathers it as a last-resort
//! error-backoff, not a poll on the chain tip.

use bitcoin::{BlockHash, Transaction, Txid};
use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::esplora_bound::EsploraReadClient;

/// Hard error returned when the WS-fed `tip_rx` channel closes
/// unexpectedly mid-scan (issue #84, round-2 MAJOR 2). A closed
/// channel means the `scanner_ws::run_scanner_ws` task that owns the
/// `tip_tx` half has died (panic, unrecoverable error). Returning
/// `Ok(())` here used to make the scanner appear healthy while the
/// chain-tip ingestion was effectively dead — exactly the
/// "appears healthy" failure mode issue #84 set out to eliminate.
/// Surfacing a non-zero exit lets the container orchestrator restart
/// the process and alerting fire on the crash-loop, instead of the
/// REST API silently serving stale state for hours.
#[derive(Debug)]
pub struct TipChannelClosed;

impl fmt::Display for TipChannelClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chain-tip stream closed unexpectedly — WS scanner task died \
             (issue #84: 'appears healthy' failure mode — the scanner exits \
             non-zero so the orchestrator restarts the process)"
        )
    }
}

impl std::error::Error for TipChannelClosed {}

use crate::publisher::{EsploraConfig, INSCRIPTION_MARKER_PREFIX};
use crate::scanner::{filter_marker_txids, process_transaction_inscriptions, InscriptionCallback};

/// Bounded retry-sleep for transient HTTP errors against the Esplora
/// REST endpoint (per-block `get_block_txids` / `get_tx`). NOT a poll
/// on the chain tip — that is the WS receiver's job. Kept short so
/// the next WS event can preempt a stuck HTTP call.
const HTTP_RETRY_BACKOFF: Duration = Duration::from_secs(5);

struct InscriptionScanner {
    client: EsploraReadClient,
    processed_blocks: HashSet<BlockHash>,
    current_block_hash: Option<BlockHash>,
    /// Optional Postgres pool for the per-block `block_log` audit row.
    /// `None` short-circuits the persistence (used by unit tests that
    /// run without a DB).
    pool: Option<sqlx::PgPool>,
}

impl InscriptionScanner {
    fn new(client: EsploraReadClient, pool: Option<sqlx::PgPool>) -> Self {
        Self {
            client,
            processed_blocks: HashSet::new(),
            current_block_hash: None,
            pool,
        }
    }

    /// Drive the scanner forever: walk forward from `start_block_hash`,
    /// then wait on the WS-fed `tip_rx` for each subsequent tip.
    ///
    /// `tip_rx.recv().await` is the documented backpressure point: if
    /// the WS reader is faster than this loop, the bounded channel
    /// stalls the WS task instead of dropping notifications.
    async fn scan_from_block(
        &mut self,
        start_block_hash: BlockHash,
        callback: &InscriptionCallback,
        tip_rx: &mut mpsc::Receiver<BlockHash>,
    ) -> Result<(), Box<dyn StdError>> {
        let mut current_hash = start_block_hash;

        loop {
            self.current_block_hash = Some(current_hash);

            if self.processed_blocks.contains(&current_hash) {
                println!("Reached chain tip. Waiting for next WS block event...");
                let next_tip = match tip_rx.recv().await {
                    Some(h) => h,
                    None => {
                        // Hard error, not Ok(()): see TipChannelClosed
                        // docstring for the issue #84 "appears healthy"
                        // failure mode rationale. The top-level
                        // `main()` Err print is the only log; no
                        // intermediate `eprintln!` here (would
                        // double-print the same line — issue #84
                        // round-4 NIT 2).
                        return Err(Box::new(TipChannelClosed));
                    }
                };
                if self.processed_blocks.contains(&next_tip) {
                    continue;
                }
                current_hash = next_tip;
                continue;
            }

            println!("Processing block: {}", current_hash);
            let block_start = std::time::Instant::now();
            let mut inscription_count: i32 = 0;

            let txids = match self.client.get_block_txids(current_hash).await {
                Ok(txids) => txids,
                Err(e) => {
                    // Transient HTTP failure against Esplora — back
                    // off briefly and retry. NOT a poll on the chain
                    // tip; the WS receiver feeds new tips
                    // independently. See module-level docstring for
                    // the CI-lint opt-out rationale.
                    println!("Error fetching block txids {}: {}", current_hash, e);
                    // Bounded retry on HTTP failure, not a tip poll.
                    // See CONTRIBUTING.md § "No polling — events
                    // only" for the CI-lint opt-out rationale; the
                    // `scanner-polling-ok:` marker on the same line
                    // as the sleep is the literal token the grep
                    // step in `.github/workflows/ci.yaml` uses to
                    // grandfather this single allowed sleep.
                    tokio::time::sleep(HTTP_RETRY_BACKOFF).await; // scanner-polling-ok: bounded HTTP-retry backoff, not a chain-tip poll
                    continue;
                }
            };

            let marker_bytes = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap_or_default();
            let matching_txids: Vec<Txid> = filter_marker_txids(txids, &marker_bytes);

            for txid in matching_txids {
                println!("Found transaction with marker prefix: {}", txid);
                match self.client.get_tx(&txid).await {
                    Ok(Some(tx)) => {
                        self.process_transaction(&tx, callback).await?;
                        inscription_count += 1;
                    }
                    Ok(None) => {
                        println!("Transaction {} not found", txid);
                    }
                    Err(e) => {
                        println!("Error fetching transaction {}: {}", txid, e);
                    }
                }
            }

            self.processed_blocks.insert(current_hash);

            let block_status = self
                .client
                .get_block_status(&current_hash)
                .await
                .map_err(|e| e as Box<dyn StdError>)?;

            // Persist a block_log row for this block: hash, height,
            // inscription count, and processing duration. Fire-and-
            // forget — a block_log insert failure must not break the
            // scanner loop (the scanner is the only path to chain-tip
            // catch-up and we never want to wedge it on a DB blip).
            if let Some(pool) = &self.pool {
                let block_entry = crate::db::BlockLogEntry {
                    block_hash: <bitcoin::BlockHash as AsRef<[u8]>>::as_ref(&current_hash).to_vec(),
                    block_height: block_status.height.map(i64::from),
                    inscription_count,
                    processing_duration_us: i64::try_from(block_start.elapsed().as_micros()).ok(),
                };
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::db::insert_block_log(&pool, &block_entry).await {
                        eprintln!("Failed to persist block_log: {}", e);
                    }
                });
            }

            match block_status.next_best {
                Some(next_hash) => current_hash = next_hash,
                None => {
                    // Caught up. Wait for the next WS tip event
                    // instead of polling. The `processed_blocks`
                    // guard at the top of the loop swallows
                    // duplicate publishes from the WS anchor-on-
                    // reconnect path.
                    println!("Reached chain tip. Waiting for next WS block event...");
                    let next_tip = match tip_rx.recv().await {
                        Some(h) => h,
                        None => {
                            // Hard error, not Ok(()): see
                            // TipChannelClosed docstring for the
                            // issue #84 "appears healthy" failure
                            // mode rationale. The top-level `main()`
                            // Err print is the only log; no
                            // intermediate `eprintln!` here (would
                            // double-print the same line — issue #84
                            // round-4 NIT 2).
                            return Err(Box::new(TipChannelClosed));
                        }
                    };
                    if self.processed_blocks.contains(&next_tip) {
                        continue;
                    }
                    current_hash = next_tip;
                }
            }
        }
    }

    async fn process_transaction(
        &self,
        tx: &Transaction,
        callback: &InscriptionCallback,
    ) -> Result<(), Box<dyn StdError>> {
        if let Some(current_hash) = self.current_block_hash {
            process_transaction_inscriptions(tx, current_hash, callback);
        }
        Ok(())
    }
}

/// Scans for inscription transactions in the blockchain.
///
/// `tip_rx` is the WS-fed channel of new chain tips. The scanner
/// walks forward through `next_best` between events and blocks on
/// `tip_rx.recv()` at every chain-tip catch-up — no polling.
pub async fn scan_for_inscriptions(
    config: &EsploraConfig,
    start_block_hash: BlockHash,
    pool: Option<sqlx::PgPool>,
    callback: &InscriptionCallback,
    mut tip_rx: mpsc::Receiver<BlockHash>,
) -> Result<(), Box<dyn StdError>> {
    let client =
        EsploraReadClient::connect(&config.url).map_err(|e| e as Box<dyn StdError>)?;
    let mut scanner = InscriptionScanner::new(client, pool);

    scanner
        .scan_from_block(start_block_hash, callback, &mut tip_rx)
        .await?;

    Ok(())
}
