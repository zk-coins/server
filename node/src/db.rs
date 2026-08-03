// Postgres state-layer for the zkCoins node.
//
// Introduced in PR-A1 of the 3-PR Postgres migration series; the
// schema (see `node/migrations/*.sql`) and the typed API around
// `sqlx::PgPool` were defined there. PR-A2 wired the state-layer
// (`load_smt`, `load_mmr`, `load_latest_block`, `persist_state_tx`)
// into the bootstrap and scanner callback, fixing the cross-file
// inconsistency window flagged as issue #11. PR-A3 wired the
// `load_all_accounts` / `upsert_account` / `load_all_usernames` /
// `claim_username` / `resolve_username` calls into `AccountNode` and
// `UsernameStore`. The Phase-D rework dropped the
// `load_minting_num_pubkeys` / `upsert_minting_num_pubkeys` pair and
// the optimistic counter-bump step inside `commit_mint_tx`: the
// minting account's `num_pubkeys` is now derived from SMT membership
// at runtime (see `state::derive_num_pubkeys_from_smt`). Migration
// 0005 drops the `minting_meta` table outright.
//
// Choice of `sqlx::query` (runtime checked) over `sqlx::query!`
// (compile-time checked): all SQL in this module is short, hand-
// written, and exercised end-to-end by the test suite. Going with
// runtime-checked queries avoids forcing every contributor — and the
// CI Coverage-Gate job — to either run a Postgres container at build
// time or sync an `.sqlx/` offline cache. The trade-off is a slightly
// later failure mode for schema drift, which the tests catch on the
// first run.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes, HashDigest};

use crate::v1::{require_stack_mode_for_update, ScanStackMode};

/// Lock `stack_scan_mode` and require the legacy claim inside an open
/// write transaction. Maps separation refusals onto `sqlx::Error` so the
/// existing persist signatures stay stable for call sites.
async fn require_legacy_stack_mode_in_tx(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    require_stack_mode_for_update(tx, ScanStackMode::Legacy)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))
}

/// Semantic classification of a `pending_inscriptions` row.
///
/// Persisted in the `kind` column added by migration 0006. The two
/// variants correspond one-to-one with the two `create_and_broadcast_inscription`
/// callers:
///
/// * `Mint` — `router::mint_handler` (node signs the commitment with
///   the minting account's index-N private key).
/// * `Send` — `runtime::broadcast_commit_and_deliver`, invoked from
///   `router::commit_handler` (client signs the commitment with their
///   wallet key, node only relays it on-chain).
///
/// Persisting this is the difference between a DB row that tells you
/// *what happened* and one that only tells you *that something happened*.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InscriptionKind {
    Mint,
    Send,
}

impl InscriptionKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Send => "send",
        }
    }

    pub(crate) fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "mint" => Some(Self::Mint),
            "send" => Some(Self::Send),
            _ => None,
        }
    }
}

/// Connect to `url` and run every migration in `./migrations` against
/// the pool. Returns the live pool on success.
///
/// Used in PR-A2 from `main.rs::main` before any state load.
///
/// Retries the inner connect + migrate pair up to
/// `CONNECT_AND_MIGRATE_MAX_ATTEMPTS` times for transient host-level
/// failures. The shared m3-ultra CI runner sits next to ~20
/// production containers and is sometimes hit by manual
/// `cargo nextest` runs from operators; under that load the kernel /
/// Colima vNIC has surfaced two transient failure modes:
///
///   * `sqlx::Error::PoolTimedOut` — the 60s `acquire_timeout` below
///     elapsed before the initial TCP handshake completed.
///   * `sqlx::Error::Protocol("unexpected response from SSLRequest")`
///     — testcontainers reported "ready" the moment Postgres logged
///     `database system is ready to accept connections`, but the
///     bgwriter / autovacuum bootstrap on the same Colima VM was
///     still saturating the loopback link, so the very first wire
///     byte SQLx received was garbage instead of the protocol-version
///     handshake.
///
/// Both errors converge to "Postgres is reachable but not yet
/// answering protocol-correctly"; retrying with a short linear
/// backoff converges in seconds. Other error kinds (auth failure,
/// migration mismatch, unreachable host) are returned immediately so
/// a real configuration bug still surfaces fast.
const CONNECT_AND_MIGRATE_MAX_ATTEMPTS: u32 = 3;

// `coverage(off)`: the retry loop's classification arms only fire
// under transient host-level failures that the deterministic test
// harness cannot reproduce on demand. The happy path (single Ok
// return) is exercised by every test that hits a Postgres
// testcontainer; the retry arms are defensive against shared-host
// load that is not present on the developer machine or under
// `--test-threads 1`.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn connect_and_migrate(url: &str) -> Result<PgPool, sqlx::Error> {
    let mut last_err: Option<sqlx::Error> = None;
    for attempt in 1..=CONNECT_AND_MIGRATE_MAX_ATTEMPTS {
        match try_connect_and_migrate(url).await {
            Ok(pool) => return Ok(pool),
            Err(e) if is_transient_connect_error(&e) => {
                eprintln!(
                    "connect_and_migrate attempt {attempt}/{CONNECT_AND_MIGRATE_MAX_ATTEMPTS} \
                     hit transient error, retrying: {e}"
                );
                last_err = Some(e);
                if attempt < CONNECT_AND_MIGRATE_MAX_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(500u64 * u64::from(attempt))).await;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("retry loop entered without a captured error"))
}

async fn try_connect_and_migrate(url: &str) -> Result<PgPool, sqlx::Error> {
    // `acquire_timeout` defaults to 30s — long enough on a quiet host,
    // but a busy shared host needs more headroom for the initial TCP
    // handshake. 60s covers every observed warm-up window without
    // slowing the healthy path (a healthy host connects in <500ms).
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(60))
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    Ok(pool)
}

/// Classifier for the two transient sqlx errors documented on
/// `connect_and_migrate`. Auth / migration / host-not-found errors
/// stay non-retryable so a real misconfiguration still fails fast.
///
/// `coverage(off)`: only reached from the retry arm in
/// `connect_and_migrate`, which is itself `coverage(off)` because the
/// transient-failure conditions are non-deterministic on a quiet host.
#[cfg_attr(coverage_nightly, coverage(off))]
fn is_transient_connect_error(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::PoolTimedOut)
        || matches!(e, sqlx::Error::Protocol(msg) if msg.contains("SSLRequest"))
}

// ---- Request audit log (migration 0007) ----------------------------------
//
// Persist every HTTP request the node accepts, with the raw body and
// headers and the bytes of the response sent back. The node is not a
// privacy boundary — anyone who wants shielded operation runs their own
// node; the operator-side observation surface is fair game.

/// In-memory view of a `request_log` row. Built by the audit middleware
/// (`audit::audit_log_middleware`) and shipped to `insert_request_log`
/// from a fire-and-forget tokio task so audit writes never block the
/// response back to the client.
#[derive(Debug, Clone)]
pub(crate) struct RequestLogEntry {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub remote_addr: Option<String>,
    /// Real client IP, resolved by the audit middleware from
    /// `CF-Connecting-IP` (Cloudflare Tunnel — the path zkcoins-node
    /// actually serves on) with fallback to the first segment of
    /// `X-Forwarded-For`, then `remote_addr`. Stored separately so
    /// forensics can `WHERE client_ip = …` without parsing JSONB.
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_headers: serde_json::Value,
    pub request_body: Vec<u8>,
    pub response_status: i16,
    pub response_headers: serde_json::Value,
    pub response_body: Vec<u8>,
    pub duration_us: i64,
}

pub(crate) async fn insert_request_log(
    pool: &PgPool,
    entry: &RequestLogEntry,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO request_log \
         (method, path, query, remote_addr, client_ip, user_agent, \
          request_headers, request_body, \
          response_status, response_headers, response_body, \
          duration_us) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(&entry.method)
    .bind(&entry.path)
    .bind(entry.query.as_deref())
    .bind(entry.remote_addr.as_deref())
    .bind(entry.client_ip.as_deref())
    .bind(entry.user_agent.as_deref())
    .bind(&entry.request_headers)
    .bind(&entry.request_body)
    .bind(entry.response_status)
    .bind(&entry.response_headers)
    .bind(&entry.response_body)
    .bind(entry.duration_us)
    .execute(pool)
    .await?;
    Ok(())
}

// ---- Full database trail (migration 0008) ---------------------------------
//
// Helpers for the tables added in `0008_full_database_trail.sql`. Each
// `insert_*` is a single-row insert; the caller decides whether to
// `await` synchronously (mint flow, where the persisted row should land
// before the request returns) or fire-and-forget via `tokio::spawn`
// (high-volume / non-critical paths like esplora REST chatter).

#[derive(Debug, Clone)]
pub(crate) struct TxMiningLogEntry {
    pub target_prefix: String,
    pub nonces_tried: i64,
    pub duration_us: i64,
    pub final_nonce: Option<i64>,
    pub final_txid: Vec<u8>,
    pub commit_txid: Option<Vec<u8>>,
}

pub(crate) async fn insert_tx_mining_log(
    pool: &PgPool,
    entry: &TxMiningLogEntry,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tx_mining_log \
         (target_prefix, nonces_tried, duration_us, final_nonce, final_txid, commit_txid) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&entry.target_prefix)
    .bind(entry.nonces_tried)
    .bind(entry.duration_us)
    .bind(entry.final_nonce)
    .bind(&entry.final_txid)
    .bind(entry.commit_txid.as_deref())
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct BootLogEntry {
    pub event_type: String,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
}

pub(crate) async fn insert_boot_log(
    pool: &PgPool,
    entry: &BootLogEntry,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO boot_log (event_type, message, metadata) VALUES ($1, $2, $3)")
        .bind(&entry.event_type)
        .bind(&entry.message)
        .bind(entry.metadata.as_ref())
        .execute(pool)
        .await?;
    Ok(())
}

/// Record the most recent broadcast error against a
/// `pending_inscriptions` row WITHOUT changing its `status`.
///
/// The status discriminator carries state-machine semantics that the
/// resume path depends on: a `commit_broadcast` row means "commit
/// landed on chain, only the reveal needs to be re-driven" while
/// `constructed` means "neither leg landed yet, broadcast both". A
/// blanket promotion to `status = 'failed'` on every error would
/// erase that distinction and force resume to re-broadcast a commit
/// that already landed (the chain rejects it with
/// `txn-already-known` so the recovery is graceful, but the state
/// machine has lost its truth).
///
/// `failure_reason` is therefore the only column this helper mutates.
/// `status = 'failed'` stays reserved for truly-terminal callers
/// (retry exhaustion, operator-initiated abort) — none of which exist
/// yet, but the CHECK enum keeps the spot ready.
/// **Visibility (Stage 3 Runde 6):** `pub(crate)`. Gated at the SQL sink
/// with [`require_legacy_stack_mode_in_tx`].
pub(crate) async fn update_pending_failure_reason(
    pool: &PgPool,
    commit_txid: &[u8],
    failure_reason: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query(
        "UPDATE pending_inscriptions \
         SET failure_reason = $1, updated_at = NOW() \
         WHERE commit_txid = $2",
    )
    .bind(failure_reason)
    .bind(commit_txid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// ---- State persistence (PR-A2) --------------------------------------------

/// Load the bincode-serialized Sparse Merkle Tree blob.
pub(crate) async fn load_smt(pool: &PgPool) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM smt_state WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(data,)| data))
}

/// Load the bincode-serialized Merkle Mountain Range blob.
pub(crate) async fn load_mmr(pool: &PgPool) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM mmr_state WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(data,)| data))
}

/// Load the block hash for a scanned height from the durable `block_log`
/// audit trail (most recent row at that height, if any).
///
/// Used by the §5.7 attestation anchor locator when the nullifier's
/// inclusion height is below the live tip — `EngineAdapter` only retains
/// `tip_hash`, so historical heights must come from this scanner-written
/// log. Missing row → `Ok(None)` (caller fails loud with the locator edge;
/// never invent a hash).
pub(crate) async fn load_block_hash_at_height(
    pool: &PgPool,
    height: u64,
) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let height_i64 = i64::try_from(height).map_err(|_| {
        sqlx::Error::Decode(format!("block height {height} does not fit i64").into())
    })?;
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT block_hash FROM block_log \
         WHERE block_height = $1 \
         ORDER BY processed_at DESC \
         LIMIT 1",
    )
    .bind(height_i64)
    .fetch_optional(pool)
    .await?;
    match row {
        None => Ok(None),
        Some((bytes,)) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                sqlx::Error::Decode(
                    format!(
                        "block_log.block_hash has unexpected length {} (expected 32)",
                        bytes.len()
                    )
                    .into(),
                )
            })?;
            Ok(Some(arr))
        }
    }
}

/// Phase-E atomic helper used by `mint_handler` after a successful
/// broadcast: writes the SMT, MMR, `mmr_root_index` row AND advances
/// the `pending_inscriptions` row to `complete` — all in one
/// transaction. Leaves `latest_block` untouched (the scanner is the
/// sole writer; the freshly broadcast inscription has not been mined
/// yet, so the mint handler has no business overwriting the resume
/// marker).
///
/// ## Crash-recovery contract (the BLOCKER fix)
///
/// The previous two-step shape (`persist_state_without_block_tx` then
/// a standalone `update_pending_status(... COMPLETE)`) opened a crash
/// window between the SMT/MMR/root_index COMMIT and the mark-complete
/// UPDATE: on restart, `State::load_from_pg` rebuilt in-memory state
/// WITH the new leaf, but the row was still `reveal_broadcast`. When
/// the scanner later re-scanned the block, `should_skip_scanner_state_update`
/// returned `false` and the callback fell through to `state.update` →
/// `mmr.append` appended the same leaf a second time, diverging the
/// MMR root.
///
/// Folding the row advance into the same transaction closes the
/// window: either the SMT/MMR/root_index AND the `complete` row land
/// together, or none of them do. Scanner re-scan after a successful
/// commit observes `complete` and short-circuits cleanly; scanner re-scan
/// after a rolled-back commit observes `reveal_broadcast` and integrates
/// the inscription itself (the in-memory mutation was performed against
/// the live `Arc<Mutex<State>>` but the COMMIT was atomic, so the
/// caller's outer reaction to the Err propagation must be to NOT trust
/// the in-memory snapshot — see `mint_handler`'s 503 path).
///
/// The UPDATE has a guard `status <> 'complete'` so a re-run on an
/// already-complete row is a no-op and does not bump `updated_at`,
/// keeping the audit trail tight.
///
/// ## Arguments
///
/// * `smt` / `mmr` — bincode blobs going into the singleton rows.
/// * `root_index_entry` — `Some((prev_mmr_root, smt_root, leaf_index))`
///   for the freshly-appended leaf. `None` is accepted for symmetry
///   with `persist_state_tx` but `mint_handler` always passes `Some`
///   because every successful `state.update` produces a new root entry.
/// * `commit_txid` — raw 32-byte little-endian commit txid of the
///   inscription, matching the `pending_inscriptions.commit_txid`
///   column.
pub(crate) async fn persist_state_and_mark_complete_tx(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    root_index_entry: Option<(&HashDigest, &HashDigest, u64)>,
    commit_txid: &[u8],
) -> Result<(), sqlx::Error> {
    // See `persist_state_tx` for why the `u64 -> i64` cast is infallible
    // on every target we ship.
    let root_index_bytes = root_index_entry.map(|(prev_root, smt_root, leaf_index)| {
        (
            digest_to_bytes(prev_root),
            digest_to_bytes(smt_root),
            leaf_index as i64,
        )
    });

    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query(
        "INSERT INTO smt_state (id, data, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(smt)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO mmr_state (id, data, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(mmr)
    .execute(&mut *tx)
    .await?;
    if let Some((prev_bytes, smt_bytes, leaf_i64)) = root_index_bytes {
        sqlx::query(
            "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index, created_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (prev_mmr_root) DO NOTHING",
        )
        .bind(&prev_bytes[..])
        .bind(&smt_bytes[..])
        .bind(leaf_i64)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE pending_inscriptions \
         SET status = $1, updated_at = NOW() \
         WHERE commit_txid = $2 AND status <> $1",
    )
    .bind(PENDING_STATUS_COMPLETE)
    .bind(commit_txid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

// ---- Account persistence (PR-A3) ------------------------------------------

/// Load every `(address, data)` pair from the `accounts` table.
///
/// Used at boot in PR-A3 to rebuild the in-memory `AccountNode`
/// map. Returns an empty vector if the table is empty.
pub(crate) async fn load_all_accounts(
    pool: &PgPool,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, sqlx::Error> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT address, data FROM accounts ORDER BY address")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Upsert a single account row. The bincode blob in `data` is
/// considered authoritative — concurrent writers must serialize at
/// the application layer (`Arc<Mutex<AccountNode>>` in main.rs).
/// Upsert an account row and tag the matching `account_history` entry
/// with `source` (one of `'mint','send','receive','scanner','recovery'`).
///
/// The trigger added by migration 0008 reads `current_setting('zkcoins
/// .account_source', TRUE)` so the caller can override the default
/// `'scanner'`. `set_config(..., is_local := true)` is the safe,
/// parameterized equivalent of `SET LOCAL` — the value goes through
/// sqlx's bind path so no string interpolation is involved, and the
/// setting only lives for the duration of this transaction. The
/// surrounding `BEGIN/COMMIT` is required because `is_local := true`
/// is a no-op outside a transaction.
/// **Visibility (Stage 3 Runde 6):** `pub(crate)`. Gated at the SQL sink
/// with [`require_legacy_stack_mode_in_tx`] before any `accounts` write.
pub(crate) async fn upsert_account_with_source(
    pool: &PgPool,
    address: &[u8],
    data: &[u8],
    source: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query("SELECT set_config('zkcoins.account_source', $1, true)")
        .bind(source)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO accounts (address, data, updated_at) \
         VALUES ($1, $2, NOW()) \
         ON CONFLICT (address) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(address)
    .bind(data)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Test helper: scanner-source upsert (production callers use
/// [`upsert_account_with_source`] with an explicit tag).
#[cfg(test)]
pub(crate) async fn upsert_account(
    pool: &PgPool,
    address: &[u8],
    data: &[u8],
) -> Result<(), sqlx::Error> {
    upsert_account_with_source(pool, address, data, "scanner").await
}

// ---- Circuit-digest self-heal (issue: self-healing circuit digest) --------

/// Load the persisted circuit digest blob, or `None` on a fresh
/// database / a database last written by a build that predates the
/// `circuit_digest_meta` table.
///
/// The blob is the bincode encoding of the active circuit's
/// `verifier_only.circuit_digest` (a `HashOut<F>`), written by
/// [`reset_proof_dependent_state_tx`] / [`store_circuit_digest`]. The
/// boot path compares it byte-for-byte against the live circuit's
/// digest to decide whether the persisted proofs are still
/// circuit-compatible — see `crate::self_heal::reset_decision`.
pub(crate) async fn load_circuit_digest(pool: &PgPool) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT digest FROM circuit_digest_meta WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(digest,)| digest))
}

/// Upsert the singleton circuit-digest row WITHOUT touching any other
/// state.
///
/// Used on the "digest matches (or first boot on an otherwise-empty
/// DB)" path: there is nothing to heal, we only record / refresh the
/// digest so the next boot has a baseline to compare against. The
/// "digest mismatch" path goes through [`reset_proof_dependent_state_tx`]
/// instead, which wipes the proof-dependent state and stores the new
/// digest in the same transaction.
pub(crate) async fn store_circuit_digest(pool: &PgPool, digest: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO circuit_digest_meta (id, digest, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET digest = EXCLUDED.digest, updated_at = EXCLUDED.updated_at",
    )
    .bind(digest)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete the singleton circuit-digest row, WITHOUT touching any other
/// state.
///
/// Used by the runtime prover-health watchdog: when the job dispatcher
/// observes [`crate::prover_health::PROVE_FAILURE_THRESHOLD`] consecutive
/// `prove failed` outcomes it clears the persisted digest to *arm* the
/// boot self-heal. Removing the row makes the next boot's
/// [`load_circuit_digest`] return `None`, which routes
/// `heal_circuit_digest` through the canary-recursion branch instead of
/// the steady-state `Keep` fast path — the restart then authoritatively
/// re-checks whether the persisted proofs still recurse and resets to
/// genesis IFF the canary says `Stale` (`Compatible` / `NoSample` just
/// re-record the baseline: no reset, no data loss). Clearing the digest
/// never wipes proof state itself; the destructive reset stays gated
/// behind the canary. Idempotent: deleting an absent row is a no-op.
pub(crate) async fn clear_circuit_digest(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM circuit_digest_meta WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(())
}

/// Reset all proof-dependent state to genesis and store the new circuit
/// digest, atomically, in a single transaction.
///
/// Invoked from the boot path when the live circuit's digest does not
/// match the persisted one (a breaking circuit change). Because a
/// circuit change invalidates EVERY proof in the system at once — each
/// `account.proof`, every queued `CoinProof` source proof, every
/// recipient-held proof — and the global SMT/MMR are append-only and
/// shared across all accounts (they cannot be partially unwound per
/// account without leaving a global-vs-account mismatch), the only
/// provably-consistent recovery is a full reset to genesis. This is
/// exactly the documented `reset-zkcoins-node` tabula rasa, permitted
/// in the closed test env (CONTRIBUTING § "Closed test environment").
///
/// Tables wiped (the proof-dependent state-layer set, mirroring the
/// DEV-recovery `TRUNCATE` in CONTRIBUTING § "DEV state recovery",
/// minus `minting_meta` which migration 0005 dropped):
///
/// * `accounts`      — per-address ledger (carries the stale `proof`).
/// * `smt_state`     — global commitment Sparse Merkle Tree.
/// * `mmr_state`     — global Merkle Mountain Range of SMT roots.
/// * `mmr_root_index`— `prev_mmr_root → (smt_root, leaf_index)` map.
/// * `latest_block`  — scanner resume cursor (re-derived from the tip).
///
/// `_sqlx_migrations` is intentionally left untouched so
/// `connect_and_migrate` skips re-applying the schema. The append-only
/// log/audit tables (`account_history`, `state_update_log`, …) are NOT
/// wiped — they are historical evidence, do not feed proof
/// construction, and stop being appended to until the next user
/// round-trip re-populates `accounts`.
///
/// `usernames` is deliberately PRESERVED (not in the DELETE set above):
/// a `name → address` mapping is a human-facing handle, not
/// proof-dependent state — it does not feed proof construction and
/// survives a genesis reset so a user keeps their handle even though
/// their balance/proof are wiped. (The address it points at simply has
/// no `accounts` row until the next round-trip re-creates one.)
///
/// `coin_proof_store` (migration 0008) is deliberately NOT in the DELETE
/// set either, but for a different reason: it is unused schema
/// groundwork. Migration 0008 only CREATEs the table as a persisted view
/// of the in-memory `ProofStore`; the bootstrap that would populate it is
/// an explicit follow-up (see the migration 0008 comment), so there is no
/// production INSERT today and nothing to wipe. MIGRATION_RESEARCH: if the
/// DB-backed `ProofStore` bootstrap later lands and starts persisting
/// proof bytes here, `coin_proof_store` becomes proof-dependent state and
/// MUST be added to this DELETE set (its rows reference proof ids that a
/// genesis reset invalidates).
///
/// The on-disk per-proof file store (`PROOFS_DIR`) is dropped by the
/// caller (see `crate::self_heal::reset_proof_store_dir`) — it lives
/// outside Postgres so it cannot ride this transaction, but the
/// proof_id space resets cleanly because the files are content-
/// addressed by id and no surviving row references them.
pub(crate) async fn reset_proof_dependent_state_tx(
    pool: &PgPool,
    new_digest: &[u8],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Capability check first: this mutates the four legacy scan tables
    // (smt_state / mmr_state / mmr_root_index / latest_block) plus accounts.
    // Under a missing or v1.1 marker the wipe must refuse — same invariant
    // as every other legacy stack writer (no silent cross-stack mutate).
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query("DELETE FROM accounts")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM smt_state")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mmr_state")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mmr_root_index")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM latest_block")
        .execute(&mut *tx)
        .await?;
    // Fence concurrent job writers (same shape as the v1.1 path): bump the
    // self-heal reset generation so every job-advancing write that still
    // carries a pre-reset generation loses, fail non-terminal jobs, and
    // leave their reset_generation behind the live epoch.
    bump_self_heal_reset_generation_in_tx(&mut tx).await?;
    fail_non_terminal_jobs_for_self_heal_in_tx(&mut tx).await?;
    sqlx::query(
        "INSERT INTO circuit_digest_meta (id, digest, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET digest = EXCLUDED.digest, updated_at = EXCLUDED.updated_at",
    )
    .bind(new_digest)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Bump the process-wide self-heal reset generation inside an open
/// transaction. Returns the new generation.
///
/// Call **before** failing non-terminal jobs so any concurrent admit that
/// stamps the old generation is left behind the live epoch.
///
/// **Locking construct:** this `UPDATE` takes a row-level exclusive lock on
/// the singleton `self_heal_reset_meta` row and holds it until the reset
/// transaction commits. [`crate::job_store::JobStore::create`] admits with
/// `SELECT generation … FOR UPDATE` on the same row, so admit and reset are
/// mutually exclusive (not merely ordered): a concurrent admit either
/// finishes under the pre-bump generation (and is then covered by the
/// fail-UPDATE still in this transaction) or blocks until this commit and
/// then stamps the post-bump generation. Under plain MVCC a scalar SELECT
/// would keep seeing the old committed generation for the whole uncommitted
/// bump window — that is the visibility hole this lock closes.
pub(crate) async fn bump_self_heal_reset_generation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<i64, sqlx::Error> {
    let (gen,): (i64,) = sqlx::query_as(
        "UPDATE self_heal_reset_meta \
         SET generation = generation + 1 \
         WHERE id = 1 \
         RETURNING generation",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(gen)
}

/// Current self-heal reset generation (admission epoch for new jobs).
///
/// Read-only snapshot for diagnostics/tests. Production admit uses
/// `SELECT … FOR UPDATE` inside [`crate::job_store::JobStore::create`] so it
/// serialises with [`bump_self_heal_reset_generation_in_tx`].
#[cfg(test)]
pub(crate) async fn load_self_heal_reset_generation(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (gen,): (i64,) = sqlx::query_as("SELECT generation FROM self_heal_reset_meta WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(gen)
}

/// Fail every non-terminal job and strip durable finalisation / claim
/// envelopes. Does **not** rewrite `reset_generation` — pre-reset rows stay
/// behind the live epoch so job-advancing writes fenced on
/// the job `reset_generation` fence cannot resurrect them.
async fn fail_non_terminal_jobs_for_self_heal_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE jobs SET status = 'failed', phase = 'failed', \
                          error = $1, \
                          request_body = (COALESCE(request_body, '{}'::jsonb) \
                              - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                          updated_at = NOW(), completed_at = NOW() \
         WHERE status IN ('queued', 'proving', 'awaiting_signature', 'broadcasting')",
    )
    .bind(SELF_HEAL_RESET_JOB_ERROR)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Operator-visible error stamped onto every non-terminal `jobs` row when a
/// circuit-digest self-heal reset wipes proof-dependent state.
///
/// A reset must leave **no** job that can later claim success for wiped work
/// (durable `finalisation` capability + cached `completion_result` would
/// otherwise let the dispatcher skip prove/apply and mark `completed`).
pub(crate) const SELF_HEAL_RESET_JOB_ERROR: &str = "\
circuit-digest self-heal reset: proof-dependent state was wiped to genesis; \
this job cannot complete for a transition that no longer exists";

/// v1.1 self-heal reset: wipe **all v1.1 proof-dependent state** plus any
/// leftover legacy proof-bearing `accounts` rows, **fail every non-terminal
/// job** (stripping durable finalisation / completion cache), then store
/// the live digest. Leaves structures the v1.1 stack does not use untouched
/// (SMT / MMR / root index / latest_block).
///
/// Under exclusive v1.1 the full [`reset_proof_dependent_state_tx`] is a
/// legacy-stack writer and must not run (it requires the legacy marker and
/// would wipe scan tables that stack separation already keeps empty). A
/// circuit-digest change on the v1.1 path invalidates every
/// `ComplianceProof` / NfLog-bound opening at once — the only consistent
/// recovery is empty-engine genesis for the v1 tables.
///
/// Tables wiped (derived from migration 0019 / 0021 + legacy leftovers):
///
/// * `v1_delivery_outbox` — durable mesh delivery log (proof-bound ZBE / K_tx)
/// * `v1_sdr_phase_a` — §4.2 SDR Phase-A staging (pre-first-occurrence)
/// * `v1_pending_publishes` — stale nullifier publish recovery rows
/// * `v1_spendable_coins` / `v1_spent_coins` — CoinHist leaves
/// * `v1_accounts` — multi-asset state + last_proof / openings
/// * `v1_nullifier_index` / `v1_nflog_entries` — NfLog
/// * `v1_engine_meta` — tip / network pin row
/// * `accounts` — legacy proof-bearing rows that may still linger
///
/// Jobs reconciled (not deleted — operator retains the row):
///
/// * every non-terminal `jobs` row (`queued` / `proving` /
///   `awaiting_signature` / `broadcasting`) → `failed` with
///   [`SELF_HEAL_RESET_JOB_ERROR`], and `request_body` stripped of
///   `finalisation` / `pending_sign` / `sign` / `finalise_claim` so a
///   cached `completion_result` cannot later flip the job to `completed`
///
/// Does **not** require a legacy stack marker (v1.1 process owns this path).
/// Does **not** DELETE from `smt_state` / `mmr_state` / `mmr_root_index` /
/// `latest_block` (v1.1 does not use them; leave them intact).
pub(crate) async fn reset_v1_proof_dependent_state_tx(
    pool: &PgPool,
    new_digest: &[u8],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Order: children / dependents first, then parents, then meta.
    // v1_pending_publishes has no FK to accounts but is proof-dependent.
    // Delivery outbox holds proof-bound materials (ZBE / K_tx) — wipe with
    // the rest of the proof-dependent surface on self-heal reset.
    // (Self-heal is a full proof-dependent reset, not a delivery drop path.)
    sqlx::query("DELETE FROM v1_delivery_outbox")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_sdr_phase_a")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_pending_publishes")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_inscription_members")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_inscriptions")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_spendable_coins")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_spent_coins")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_accounts")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_nullifier_index")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_nflog_entries")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM v1_engine_meta")
        .execute(&mut *tx)
        .await?;
    // Leftover legacy proof-bearing rows (Stage 1–2 dual surface).
    sqlx::query("DELETE FROM accounts")
        .execute(&mut *tx)
        .await?;
    // Fence concurrent job writers first: bump the self-heal reset
    // generation so every job-advancing write that still carries a
    // pre-reset generation (loaded before this commit) loses the CAS —
    // including unconditional set_status / complete that match public_id
    // only. Then fail non-terminal rows and strip durable finalisation
    // without rewriting their reset_generation (they stay behind the
    // live epoch). A job INSERT that races after the fail-UPDATE with a
    // stale generation is likewise refused by the same fence.
    bump_self_heal_reset_generation_in_tx(&mut tx).await?;
    fail_non_terminal_jobs_for_self_heal_in_tx(&mut tx).await?;
    sqlx::query(
        "INSERT INTO circuit_digest_meta (id, digest, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET digest = EXCLUDED.digest, updated_at = EXCLUDED.updated_at",
    )
    .bind(new_digest)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

// ---- Username persistence (PR-A3) -----------------------------------------

/// Load every `(name, address)` pair from the `usernames` table.
pub(crate) async fn load_all_usernames(
    pool: &PgPool,
) -> Result<Vec<(String, Vec<u8>)>, sqlx::Error> {
    let rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT name, address FROM usernames ORDER BY name")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// One row of `username_claim_log` (feature `username-claim` only).
#[cfg(feature = "username-claim")]
#[derive(Debug, Clone)]
pub(crate) struct UsernameClaimLogEntry {
    pub requested_username: String,
    pub normalized_username: String,
    pub address: Vec<u8>,
    pub signature: Vec<u8>,
    pub success: bool,
    pub reject_reason: Option<String>,
    pub request_log_id: Option<i64>,
}

#[cfg(feature = "username-claim")]
pub(crate) async fn insert_username_claim_log(
    pool: &PgPool,
    entry: &UsernameClaimLogEntry,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO username_claim_log          (requested_username, normalized_username, address, signature,           success, reject_reason, request_log_id)          VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&entry.requested_username)
    .bind(&entry.normalized_username)
    .bind(&entry.address)
    .bind(&entry.signature)
    .bind(entry.success)
    .bind(entry.reject_reason.as_deref())
    .bind(entry.request_log_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Attempt to claim `name` for `address`. Returns `Ok(true)` on a
/// fresh claim, `Ok(false)` if the name is already taken (no row
/// inserted, existing row left untouched). The `ON CONFLICT DO
/// NOTHING` makes this race-free at the SQL level.
///
/// Gated by the `username-claim` Cargo feature so the write path can
/// be excluded from hosted images that don't offer claim as a UX
/// policy. The shared `usernames` table + `resolve_username` /
/// `load_all_usernames` read paths stay unconditional so existing
/// claimed names continue to resolve.
#[cfg(feature = "username-claim")]
pub(crate) async fn claim_username(
    pool: &PgPool,
    name: &str,
    address: &[u8],
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO usernames (name, address, created_at) \
         VALUES ($1, $2, NOW()) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(address)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Resolve a username to its bound address. Returns `Ok(None)` if
/// the name is not registered.
///
/// Currently unused on the read path — `UsernameStore` keeps the full
/// `name → address` map in memory after the bootstrap `load_all_usernames`
/// call, and `resolve` / `get_username` answer locally. Kept exposed
/// so a future `lnurl`-style read-through cache can call it directly
/// without re-introducing a `HashMap` mirror.
#[allow(dead_code)] // re-added when a read-through caller lands
pub(crate) async fn resolve_username(
    pool: &PgPool,
    name: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT address FROM usernames WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(addr,)| addr))
}

// ---- Per-asset creator binding (off-circuit) ------------------------------

/// Returns `Ok(true)` iff `asset_creators` already holds a row for
/// `asset_id` whose `creator_pubkey` DIFFERS from the supplied one.
/// `Ok(false)` when the asset is unregistered (a fresh mint) or when an
/// existing row matches (an idempotent re-submit of the same creator).
///
/// This is the read leg of the off-circuit creator binding
/// (MULTI_ASSET.md §5.3): `flow::mint_flow` calls it before staging a
/// mint and rejects with 409 when it returns `true`, so a second party
/// cannot mint an `asset_id` already claimed by someone else.
pub(crate) async fn asset_creator_conflict(
    pool: &PgPool,
    asset_id: &[u8],
    creator_pubkey: &[u8],
) -> Result<bool, sqlx::Error> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT creator_pubkey FROM asset_creators WHERE asset_id = $1")
            .bind(asset_id)
            .fetch_optional(pool)
            .await?;
    Ok(match row {
        Some((existing,)) => existing != creator_pubkey,
        None => false,
    })
}

/// Record `asset_id -> creator_pubkey` on a successful mint commit.
/// `ON CONFLICT (asset_id) DO NOTHING` makes this idempotent: a re-run
/// (or a concurrent commit that lost the race) leaves the first-writer
/// row untouched. The caller has already verified there is no
/// conflicting creator via [`asset_creator_conflict`].
/// **Visibility (Stage 3 Runde 6):** `pub(crate)`. Gated at the SQL sink.
pub(crate) async fn register_asset_creator(
    pool: &PgPool,
    asset_id: &[u8],
    creator_pubkey: &[u8],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query(
        "INSERT INTO asset_creators (asset_id, creator_pubkey) \
         VALUES ($1, $2) \
         ON CONFLICT (asset_id) DO NOTHING",
    )
    .bind(asset_id)
    .bind(creator_pubkey)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// ---- Minting commit transaction (Phase D) ---------------------------------

// ---- Pending inscription persistence (Phase B) ----------------------------

/// State-machine label persisted in `pending_inscriptions.status`.
///
/// The four in-progress states (`constructed`, `commit_broadcast`,
/// `reveal_broadcast`) track the publisher's progress through the
/// commit + reveal broadcast pair. `complete` is terminal-success;
/// `failed` is reserved for future use (today the resumer treats
/// every non-complete row as retryable).
pub(crate) const PENDING_STATUS_CONSTRUCTED: &str = "constructed";
pub(crate) const PENDING_STATUS_COMMIT_BROADCAST: &str = "commit_broadcast";
pub(crate) const PENDING_STATUS_REVEAL_BROADCAST: &str = "reveal_broadcast";
pub(crate) const PENDING_STATUS_COMPLETE: &str = "complete";

/// In-memory representation of a `pending_inscriptions` row loaded by
/// [`load_pending_in_progress`]. The blob columns are returned raw —
/// callers deserialize via the same `bitcoin::consensus::deserialize`
/// shape used at write time.
#[derive(Debug, Clone)]
pub(crate) struct PendingInscriptionRow {
    pub id: i64,
    pub commit_txid: Vec<u8>,
    pub reveal_txid: Option<Vec<u8>>,
    pub status: String,
    pub kind: InscriptionKind,
    pub commitment: Vec<u8>,
    pub commit_tx: Vec<u8>,
    pub reveal_tx: Vec<u8>,
    pub commit_output_value: i64,
    pub failure_reason: Option<String>,
}

/// Insert a fresh `constructed` row before the publisher attempts the
/// first commit broadcast. `commit_txid` is the deterministic txid of
/// the supplied `commit_tx` bytes; callers compute it once and pass it
/// in so retries can match the UNIQUE constraint.
///
/// On UNIQUE-violation (a previous attempt persisted the same pair and
/// crashed before completing), the function returns `Ok(false)` so the
/// caller can carry on with the existing row instead of double-
/// inserting. Every other DB error propagates.
/// **Visibility (Stage 3 Runde 6):** `pub(crate)`. Gated at the SQL sink.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_pending_inscription(
    pool: &PgPool,
    commit_txid: &[u8],
    reveal_txid: &[u8],
    kind: InscriptionKind,
    commitment: &[u8],
    commit_tx: &[u8],
    reveal_tx: &[u8],
    commit_output_value: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    let result = sqlx::query(
        "INSERT INTO pending_inscriptions \
         (commit_txid, reveal_txid, status, kind, commitment, commit_tx, reveal_tx, commit_output_value) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (commit_txid) DO NOTHING",
    )
    .bind(commit_txid)
    .bind(reveal_txid)
    .bind(PENDING_STATUS_CONSTRUCTED)
    .bind(kind.as_str())
    .bind(commitment)
    .bind(commit_tx)
    .bind(reveal_tx)
    .bind(commit_output_value)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected() == 1)
}

/// Advance a row to the supplied status. The caller is responsible for
/// passing a status that the CHECK constraint accepts — using the
/// `PENDING_STATUS_*` constants guarantees that.
///
/// **Visibility (Stage 3 Runde 6):** `pub(crate)`. Gated at the SQL sink.
pub(crate) async fn update_pending_status(
    pool: &PgPool,
    commit_txid: &[u8],
    status: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query(
        "UPDATE pending_inscriptions \
         SET status = $1, updated_at = NOW() \
         WHERE commit_txid = $2",
    )
    .bind(status)
    .bind(commit_txid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Load every row whose status is not `complete`, ordered by `id` so
/// the resumer walks them in insertion order. The partial index
/// `pending_inscriptions_status_idx` keeps this scan O(pending), not
/// O(total).
pub(crate) async fn load_pending_in_progress(
    pool: &PgPool,
) -> Result<Vec<PendingInscriptionRow>, sqlx::Error> {
    // Tuple layout: (id, commit_txid, reveal_txid, status, kind,
    // commitment, commit_tx, reveal_tx, commit_output_value,
    // failure_reason). Aliased to keep the `sqlx::query_as`
    // annotation under clippy's `type_complexity` threshold.
    type RawRow = (
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<String>,
    );
    let rows: Vec<RawRow> = sqlx::query_as(
        "SELECT id, commit_txid, reveal_txid, status, kind, commitment, commit_tx, reveal_tx, \
                commit_output_value, failure_reason \
         FROM pending_inscriptions \
         WHERE status <> 'complete' \
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(
            |(
                id,
                commit_txid,
                reveal_txid,
                status,
                kind,
                commitment,
                commit_tx,
                reveal_tx,
                commit_output_value,
                failure_reason,
            )| {
                let kind = InscriptionKind::from_db_str(&kind).ok_or_else(|| {
                    sqlx::Error::Decode(
                        format!("invalid pending_inscriptions.kind value: {kind:?}").into(),
                    )
                })?;
                Ok(PendingInscriptionRow {
                    id,
                    commit_txid,
                    reveal_txid,
                    status,
                    kind,
                    commitment,
                    commit_tx,
                    reveal_tx,
                    commit_output_value,
                    failure_reason,
                })
            },
        )
        .collect()
}

/// Lookup the public-facing view of a single inscription by its commit
/// txid. Used by the `GET /api/inscriptions/:txid` endpoint to surface
/// the `(kind, status, value, timestamps)` tuple without exposing the
/// raw commit/reveal/commitment blobs (which are useful for crash
/// recovery but not for operator/forensic queries).
///
/// Returns `Ok(None)` when no row exists — either because this node
/// never originated the inscription (e.g. an external recovery via the
/// `recover_inscription` CLI) or because the txid was never seen here.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub(crate) struct InscriptionSummary {
    /// Commit txid as a lowercase hex string. Mirrors the on-chain
    /// txid shown in block explorers — i.e. big-endian display order,
    /// the reverse of the raw `bytea` stored in the column.
    pub commit_txid: String,
    /// Reveal txid in the same display-order convention. `None` only
    /// for rows that pre-date migration 0008 (no production rows, see
    /// migration 0006 wipe).
    pub reveal_txid: Option<String>,
    pub kind: InscriptionKind,
    pub status: String,
    pub commit_output_value: i64,
    /// Error chain when `status = 'failed'`, otherwise `None`.
    pub failure_reason: Option<String>,
    /// ISO-8601 / RFC-3339 UTC timestamp, formatted in Postgres so we
    /// can stay off the `chrono`/`time` sqlx feature flags. Microsecond
    /// precision; trailing `Z` to make the timezone explicit.
    pub created_at: String,
    pub updated_at: String,
}

// ---- MMR root index persistence (Phase C) ---------------------------------

/// Load every `(prev_mmr_root, smt_root, leaf_index)` row from the
/// `mmr_root_index` table, ordered by `leaf_index` so the caller can
/// rebuild the in-memory map deterministically (and so the highest
/// `leaf_index` entry — used to restore `State::prev_mmr_root` — is
/// always the last element).
///
/// Returns an empty vector when the table has never been written
/// (fresh database). Length / digest decoding mirrors the defensive
/// branch in [`load_latest_block`]: 32 bytes for each digest, with a
/// `sqlx::Error::Decode` surface on length mismatch rather than a
/// panic deep in the bootstrap.
pub(crate) async fn load_root_indices(
    pool: &PgPool,
) -> Result<Vec<(HashDigest, HashDigest, u64)>, sqlx::Error> {
    let rows: Vec<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT prev_mmr_root, smt_root, leaf_index FROM mmr_root_index ORDER BY leaf_index",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (prev_bytes, smt_bytes, leaf_i64) in rows {
        let prev_arr: [u8; 32] = prev_bytes.as_slice().try_into().map_err(|_| {
            sqlx::Error::Decode(
                format!(
                    "mmr_root_index.prev_mmr_root has unexpected length {} (expected 32)",
                    prev_bytes.len()
                )
                .into(),
            )
        })?;
        let smt_arr: [u8; 32] = smt_bytes.as_slice().try_into().map_err(|_| {
            sqlx::Error::Decode(
                format!(
                    "mmr_root_index.smt_root has unexpected length {} (expected 32)",
                    smt_bytes.len()
                )
                .into(),
            )
        })?;
        if leaf_i64 < 0 {
            return Err(sqlx::Error::Decode(
                format!(
                    "mmr_root_index.leaf_index out of u64 range: {} (must be >= 0)",
                    leaf_i64
                )
                .into(),
            ));
        }
        out.push((
            digest_from_bytes(&prev_arr),
            digest_from_bytes(&smt_arr),
            leaf_i64 as u64,
        ));
    }
    Ok(out)
}

// ---- Account history listing (issue #153) ---------------------------------

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
/// Atomically write SMT, MMR, `latest_block`, and (optionally) the
/// freshly-inserted `mmr_root_index` row in one transaction.
///
/// The whole point of moving these blobs into Postgres is the
/// transactional guarantee — issue #11 documents the file-based
/// failure mode where a crash between `smt.bin`, `mmr.bin`, and
/// `latest_block.bin` leaves the three out of sync, and the next
/// start-up either replays already-processed commitments (dup
/// inserts into the SMT) or loses commitments outright. A single
/// `BEGIN; UPSERT; UPSERT; UPSERT; INSERT; COMMIT` removes that window.
///
/// The Phase-C `mmr_root_index` write is part of the SAME transaction
/// because a crash between the state snapshot and the root_index INSERT
/// is catastrophic for replay healing: on restart the scanner resumes
/// from the saved `latest_block` and re-scans the same commit tx →
/// `state.update` runs again → SMT insert is idempotent but `mmr.append`
/// is NOT → MMR diverges → `prev_mmr_root` becomes a NEW key → fresh
/// `root_indices` entry written under the new key → the original
/// missing entry is never healed. Folding the INSERT into the same tx
/// means either both land or neither does; on a crash before COMMIT,
/// the next start-up re-runs `state.update` against the SAME unchanged
/// MMR and writes the SAME `(prev_mmr_root, smt_root, leaf_index)` —
/// `ON CONFLICT (prev_mmr_root) DO NOTHING` makes that a no-op on the
/// row that did land, or a fresh insert on the row that did not.
///
/// `root_index_entry` is `Option<…>` because the first call from a
/// fresh database (no `State::update` has fired yet) has nothing to
/// write — only the bootstrap path which seeds an empty SMT/MMR would
/// hit that case in practice. Today every scanner-callback caller
/// passes `Some(...)`.
pub(crate) async fn persist_state_tx(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    latest_block: &[u8; 32],
    root_index_entry: Option<(&HashDigest, &HashDigest, u64)>,
) -> Result<(), sqlx::Error> {
    // `leaf_index` is a `u64` coming from `mmr.leaf_count()`, which is
    // bounded by the total inscription count (≪ 2^63 in practice). The
    // cast is infallible on 64-bit targets, which is our only deployment
    // target (Linux x86_64 / aarch64).
    let root_index_bytes = root_index_entry.map(|(prev_root, smt_root, leaf_index)| {
        (
            digest_to_bytes(prev_root),
            digest_to_bytes(smt_root),
            leaf_index as i64,
        )
    });

    let mut tx = pool.begin().await?;
    // Capability check first (SELECT … FOR UPDATE on stack_scan_mode): a
    // concurrent v1.1 claim cannot slip past this write, and a missing /
    // mismatching marker aborts before any SMT/MMR row is touched.
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query(
        "INSERT INTO smt_state (id, data, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(smt)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO mmr_state (id, data, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(mmr)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO latest_block (id, block_hash, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET block_hash = EXCLUDED.block_hash, updated_at = EXCLUDED.updated_at",
    )
    .bind(&latest_block[..])
    .execute(&mut *tx)
    .await?;
    if let Some((prev_bytes, smt_bytes, leaf_i64)) = root_index_bytes {
        sqlx::query(
            "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index, created_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (prev_mmr_root) DO NOTHING",
        )
        .bind(&prev_bytes[..])
        .bind(&smt_bytes[..])
        .bind(leaf_i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
/// Load the 32-byte block hash of the last fully-processed block.
pub(crate) async fn load_latest_block(pool: &PgPool) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT block_hash FROM latest_block WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    match row {
        None => Ok(None),
        Some((bytes,)) => {
            // The schema does not enforce a 32-byte length (BYTEA is
            // arbitrary), so we defensively reject anything else here
            // rather than panicking deep in the scanner. In practice
            // only `persist_state_tx` writes this column, and it takes
            // a `&[u8; 32]`, so this branch should be unreachable.
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                sqlx::Error::Decode(
                    format!(
                        "latest_block.block_hash has unexpected length {} (expected 32)",
                        bytes.len()
                    )
                    .into(),
                )
            })?;
            Ok(Some(arr))
        }
    }
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
/// Insert a single `(prev_mmr_root) -> (smt_root, leaf_index)` row.
///
/// Called from the scanner callback right after `State::update`
/// successfully appended a new MMR leaf. `ON CONFLICT DO NOTHING` makes
/// replays idempotent: an MMR append is monotonic, so the same
/// `prev_mmr_root` key cannot legitimately resolve to two distinct
/// `(smt_root, leaf_index)` tuples — the first writer's value is
/// authoritative and a re-entrant retry (e.g. a scanner re-scan after a
/// crash that already persisted this entry) is a no-op.
///
/// `leaf_index` is the in-memory `usize` from `mmr.leaf_count()`. We
/// cast through `i64` because Postgres has no unsigned BIGINT — the
/// load path rejects negative values, so this round-trip is safe up to
/// `i64::MAX`, well above any plausible MMR depth.
pub(crate) async fn insert_root_index(
    pool: &PgPool,
    prev_root: &HashDigest,
    smt_root: &HashDigest,
    leaf_index: u64,
) -> Result<(), sqlx::Error> {
    let prev_bytes = digest_to_bytes(prev_root);
    let smt_bytes = digest_to_bytes(smt_root);
    // MMR leaf_index is bounded by total inscription count (≪ 2^63 in
    // practice); the cast is infallible on 64-bit targets which is our
    // only deployment target.
    let leaf_i64 = leaf_index as i64;
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    sqlx::query(
        "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index, created_at) \
         VALUES ($1, $2, $3, NOW()) \
         ON CONFLICT (prev_mmr_root) DO NOTHING",
    )
    .bind(&prev_bytes[..])
    .bind(&smt_bytes[..])
    .bind(leaf_i64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
/// Insert (or no-op on UNIQUE conflict — replayed blocks land twice
/// when the scanner restarts mid-stream). Marks `processed_at = NOW()`
/// in the same statement so the row reflects "scanner saw + processed
/// this block".
pub(crate) async fn insert_block_log(
    pool: &PgPool,
    entry: &BlockLogEntry,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO block_log \
         (block_hash, block_height, processed_at, inscription_count, processing_duration_us) \
         VALUES ($1, $2, NOW(), $3, $4) \
         ON CONFLICT (block_hash) DO NOTHING",
    )
    .bind(&entry.block_hash)
    .bind(entry.block_height)
    .bind(entry.inscription_count)
    .bind(entry.processing_duration_us)
    .execute(pool)
    .await?;
    Ok(())
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct BlockLogEntry {
    pub block_hash: Vec<u8>,
    /// Block height as reported by Esplora's `get_block_status`. `None`
    /// when the upstream did not return a height — the previous
    /// sentinel `-1` was magic-value-driven, NULL is the type-safe
    /// alternative (migration 0010 drops the NOT NULL).
    pub block_height: Option<i64>,
    pub inscription_count: i32,
    pub processing_duration_us: Option<i64>,
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
/// Atomically upsert every account row mutated by a successful mint.
///
/// Phase D removed the optimistic `minting_meta.num_pubkeys` counter
/// bump that used to sit at the head of this transaction: the
/// minting-account `num_pubkeys` is now derived from SMT membership at
/// runtime (`state::derive_num_pubkeys_from_smt`), so the only DB-side
/// work left is the per-account UPSERT bundle. The signature still
/// returns `Result<(), sqlx::Error>` to keep the call-site shape
/// symmetric with the other helpers; the `bool` "race lost"
/// discriminator on the old API is gone because the in-process
/// concurrency gate has moved out of Postgres (see `mint_handler` for
/// the new gate).
///
/// All UPSERTs share one transaction so the bundle is atomic even on
/// a partial DB failure — either every recipient + the mutated minting
/// account land, or none do.
/// **Visibility (Stage 3 Runde 6):** `pub(crate)`. Gated at the SQL sink
/// before any `accounts` UPSERT.
pub(crate) async fn commit_mint_tx(
    pool: &PgPool,
    accounts: &[(&[u8], &[u8])],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    require_legacy_stack_mode_in_tx(&mut tx).await?;
    // Tag every `account_history` row written by the trigger as
    // `source = 'mint'`. `set_config(..., is_local := true)` only
    // takes effect for the lifetime of THIS transaction, so the
    // tag does not bleed into adjacent / concurrent transactions.
    sqlx::query("SELECT set_config('zkcoins.account_source', 'mint', true)")
        .execute(&mut *tx)
        .await?;
    for (address, data) in accounts {
        sqlx::query(
            "INSERT INTO accounts (address, data, updated_at) \
             VALUES ($1, $2, NOW()) \
             ON CONFLICT (address) DO UPDATE \
             SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
        )
        .bind(*address)
        .bind(*data)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
/// Look up the current `status` value for a `pending_inscriptions` row
/// keyed by its `commit_txid`. Returns `Ok(None)` when no row exists
/// (an external inscription that never went through this node's mint
/// flow, e.g. an out-of-band manual recovery via the `recover_inscription`
/// CLI in PR #106, or a fresh database).
///
/// Phase E (this commit) wires `mint_handler` to advance `state.update`
/// synchronously after the on-chain broadcast succeeds and then mark
/// the row `complete`. The scanner uses this lookup to decide whether
/// it can skip its own `state.update` call when it later observes the
/// same commit on chain: a `complete` row means the SMT/MMR already
/// hold the inscription's entry and a second `smt.insert` / `mmr.append`
/// would either no-op (idempotent SMT path on identical key+value) or
/// — worse — diverge the MMR if any byte differs. Any other status,
/// including a missing row, means the scanner remains responsible for
/// integrating the inscription.
///
/// The `commit_txid` argument is the raw 32-byte little-endian txid of
/// the inscription's commit transaction, identical to the `commit_txid`
/// column written by `insert_pending_inscription`.
pub(crate) async fn pending_inscription_status_by_commit_txid(
    pool: &PgPool,
    commit_txid: &[u8],
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM pending_inscriptions WHERE commit_txid = $1")
            .bind(commit_txid)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(status,)| status))
}

// Stage 4: test-only residual of legacy durable helper.
#[cfg(test)]
pub(crate) async fn get_inscription_summary_by_commit_txid(
    pool: &PgPool,
    commit_txid: &[u8],
) -> Result<Option<InscriptionSummary>, sqlx::Error> {
    type RawRow = (
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        String,
        i64,
        Option<String>,
        String,
        String,
    );
    let row: Option<RawRow> = sqlx::query_as(
        "SELECT commit_txid, \
                reveal_txid, \
                kind, \
                status, \
                commit_output_value, \
                failure_reason, \
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, \
                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at \
         FROM pending_inscriptions \
         WHERE commit_txid = $1",
    )
    .bind(commit_txid)
    .fetch_optional(pool)
    .await?;
    row.map(
        |(
            commit_txid_bytes,
            reveal_txid_bytes,
            kind,
            status,
            commit_output_value,
            failure_reason,
            created_at,
            updated_at,
        )| {
            let kind = InscriptionKind::from_db_str(&kind).ok_or_else(|| {
                sqlx::Error::Decode(
                    format!("invalid pending_inscriptions.kind value: {kind:?}").into(),
                )
            })?;
            // Reverse to display order — txid in explorers is the
            // little-endian-stored bytes shown big-endian.
            let mut commit_display = commit_txid_bytes;
            commit_display.reverse();
            let reveal_txid = reveal_txid_bytes.map(|mut b| {
                b.reverse();
                hex::encode(b)
            });
            Ok(InscriptionSummary {
                commit_txid: hex::encode(commit_display),
                reveal_txid,
                kind,
                status,
                commit_output_value,
                failure_reason,
                created_at,
                updated_at,
            })
        },
    )
    .transpose()
}
