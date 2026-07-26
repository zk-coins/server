//! Binary entrypoint for `node`.
//!
//! Modules live in `lib.rs`; this file only wires the bootstrap
//! (panic hook, Postgres pool, scanner task, REST listener) together.
//! Splitting the modules out of the binary lets out-of-tree
//! integration tests (`node/tests/api_remote.rs`) import the
//! handler response types and the `CoinProof` struct without
//! duplicating definitions or making the binary itself reachable
//! from a `cargo test --test ...` target.

// mimalloc replaces the default allocator process-wide. Scoped to the
// binary (`main.rs`) so the `node` library crate, integration tests,
// and the `program-plonky2` / `script-plonky2` crates continue to use
// the system allocator — keeps unit-test behaviour identical to CI
// and avoids pulling a C build dependency into every test target.
// See the comment on the `mimalloc` line in `node/Cargo.toml` for the
// rationale.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use node::account_node;
use node::db;
use node::publisher::EsploraConfig;
use node::runtime::{start_rest_node, V11Readiness};
use node::scanner_runtime::scan_for_inscriptions;
use node::scanner_ws::{run_scanner_ws, ScannerWsConfig};
use node::state::State;
use node::username;
use node::v11::{self, ScanStackMode, V11ShadowMode};
use node::{persist_state_from_sync_context, DATABASE_URL, NETWORK_CONFIG};
use shared::commitment::Commitment;
use std::error::Error as StdError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// Postgres state-layer carries every persistent slice of node state
// after PR-A3: SMT / MMR / latest_block (PR-A2), accounts + usernames
// (PR-A3), and the minting account's `minting_meta.num_pubkeys` counter
// (PR-A3). The `accounts.bin`, `usernames.bin`, and
// `minting_num_pubkeys.bin` sibling files no longer exist, and the
// `atomic_write` helper that supported them is removed — the only
// remaining on-disk writes are the per-proof files under
// `${PROOFS_DIR:-./proofs}/{id}.bin`, owned by `ProofStore` in
// `router.rs`.
const ACCOUNT_NODE_ADDR: &str = "0.0.0.0:4242";

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use node::esplora_bound::EsploraReadClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    // A panic in any tokio worker — for example the bootstrap task that
    // owns the HTTP listener — by default only kills that task. The rest
    // of the process (notably the chain scanner) keeps running, the
    // container stays `Up`, but the REST port is never bound. Cloudflare
    // sees the upstream as alive-but-unresponsive and serves 502s for
    // hours. Override the panic hook so any panic anywhere aborts the
    // whole process; `restart: unless-stopped` in compose then crash-
    // loops the container until the underlying cause is fixed, which is
    // far easier to spot than a silent zombie.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic_hook(info);
        std::process::exit(1);
    }));

    // Install a `tracing` subscriber so the API handlers' structured
    // `tracing::info!` / `tracing::error!` calls actually emit. Without
    // a subscriber every `tracing::*` macro is a silent no-op, which
    // would drop the request-path logs entirely after the migration
    // away from `eprintln!`. The `fmt` layer writes to stdout and the
    // `env-filter` layer honours `RUST_LOG` (default `info`, matching
    // the previous documented baseline in `CONTRIBUTING.md`). Both
    // crates are direct deps in `node/Cargo.toml`.
    //
    // `try_init` (not `init`) so a test binary that already installed
    // its own subscriber — or a second main invocation in a test
    // harness — does not panic the bootstrap.
    //
    // Partial-migration subscriber: routes `tracing::*` calls through fmt+EnvFilter.
    // Many call sites in this crate still use `println!`/`eprintln!` (see TODO in
    // scanner_ws.rs:11). Those continue to write directly to stdout/stderr and are
    // not affected by RUST_LOG. The 4xx-validation paths in router.rs and
    // account_node.rs are the first wave of the migration.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

    // Open the Postgres pool and run pending migrations BEFORE any
    // state load — `connect_and_migrate` is idempotent (sqlx tracks
    // applied migrations in `_sqlx_migrations`) and so safe to call on
    // every boot. A connect failure here aborts the whole bootstrap;
    // there is no useful "degraded" mode without persistent state.
    let pool = Arc::new(
        db::connect_and_migrate(&DATABASE_URL)
            .await
            .expect("connect and migrate database"),
    );
    println!("Connected to Postgres state-layer");

    // Cutover Stages 1–2: optional v1.1 **exclusive dual stack**.
    // Default is off (unset / empty / "off") → legacy Commitment publisher
    // + Esplora SMT scanner. `ZKCOINS_V11_SHADOW=1` claims the database for
    // AggregateStateNullifierV3 / NfLog only (hard separation). Proving
    // remains legacy until Stage 3. Missing pins fail loud — never fall
    // back silently to the other stack.
    let shadow_mode = v11::mode::v11_shadow_mode_from_env().unwrap_or_else(|e| {
        panic!("{e}");
    });
    let v11_adapter: Option<node::v11::EngineAdapter> = match shadow_mode {
        V11ShadowMode::Off => {
            // Exclusive claim: this DB is the legacy scan stack.
            v11::enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
                .await
                .expect("legacy stack separation gate");
            println!(
                "v1.1 dual stack: off (ZKCOINS_V11_SHADOW unset / empty / off); \
                 legacy Commitment publisher + SMT scanner; proving remains legacy"
            );
            None
        }
        V11ShadowMode::On => {
            // Exclusive claim before any NfLog write.
            v11::enforce_stack_scan_mode(&pool, ScanStackMode::V11)
                .await
                .expect("v1.1 stack separation gate");
            println!(
                "v1.1 dual stack: on (AggregateStateNullifierV3 publisher + NfLog \
                 scanner; proving remains legacy until Stage 3; legacy commitment \
                 publish is refused)"
            );
            let adapter = node::v11::EngineAdapter::load_or_create_from_env((*pool).clone())
                .await
                .expect("v11 EngineAdapter bootstrap");
            // Digests are available via ProverBridge::circuit_digest_bytes /
            // balance_circuit_digest_bytes (§1.7.1). Do not compute them here:
            // each forces a multi-minute circuit build, and Stage 1 still boots
            // the legacy Prover for AccountNode/REST until Stage 3.
            println!(
                "v11 EngineAdapter ready (network={:?}, activation_height={})",
                adapter.network(),
                adapter.activation_height()
            );
            Some(adapter)
        }
    };

    // Build the Plonky2 prover ONCE, up front. Its
    // `circuit_digest_bytes` drives the boot-time self-heal below, and
    // the same instance is reused by the `AccountNode` rehydration so we
    // pay the ~14 s circuit build exactly once.
    //
    // Stage 1 still boots the legacy AccountNode/REST surface even under
    // `ZKCOINS_V11_SHADOW=1` (Stage 3 swaps prove call-sites). The v11
    // adapter above only maintains shadow state; the legacy Prover remains
    // required for the existing REST flows until then.
    let prover = zkcoins_prover::Prover::new();
    let live_digest = prover.circuit_digest_bytes();
    println!("Built Plonky2 prover (circuit ready)");

    // Load existing state from Postgres (PR-A2). When SMT/MMR rows are
    // absent (fresh DB), `load_from_pg` returns an empty State —
    // equivalent to the previous file-based `State::new()` fallback.
    let state = Arc::new(Mutex::new(
        State::load_from_pg(&pool)
            .await
            .expect("load state from Postgres"),
    ));
    println!("Loaded State from Postgres");

    // Reload AccountNode + UsernameStore from Postgres. The matching
    // file-based loaders from PR-A1/A2 are gone — these two calls are
    // the single source of truth after PR-A3. A DB error here aborts
    // the bootstrap (same reasoning as the State load above). The
    // pre-built `prover` is moved in here so the circuit is built once.
    let account_node = account_node::AccountNode::load_from_pg(Arc::clone(&state), &pool, prover)
        .await
        .expect("load account node from Postgres");
    println!("Loaded AccountNode from Postgres");

    // Self-heal on a breaking circuit change. A circuit change makes
    // every persisted proof incompatible with the current circuit; the
    // next AccountUpdate send/mint would fail to prove ("prove failed").
    // The check runs AFTER the state + account load so the canary
    // detector (used on the adoption boundary, when no digest is
    // recorded yet) can recurse a persisted proof through the live
    // circuit with the REAL commitment-merkle witnesses from the loaded
    // state — a `circuit_digest` comparison and `Prover::verify` both
    // miss the failure class where the digest is unchanged but recursion
    // breaks (verified against the live DEV dump). On a mismatch / stale
    // probe this resets the proof-dependent state to genesis (the same
    // consistent tabula rasa as `reset-zkcoins-node`) and stores the new
    // digest, so no future circuit change can brick DEV/PRD and no
    // manual reset is needed. A DB error aborts the bootstrap (serving
    // with half-reset state is worse than failing loudly); proof-store
    // cleanup failures are logged and swallowed inside the helper.
    let proofs_dir = std::env::var("PROOFS_DIR").unwrap_or_else(|_| "./proofs".to_string());

    // The canary recurses a persisted proof through the live circuit's
    // AccountUpdate branch. The §8(b)/(c) state-continuity constraints
    // fix the witnessed account-state pubkey to the key the producing
    // transition rotated TO (== the NEXT transition's `public_key`).
    //
    // Neutral model (Milestone 2): there is NO server-held minting key,
    // so the node cannot derive any account's current key. The resolver
    // therefore returns `None` for every account — the canary then
    // skips each sample (a state-derivation gap, not circuit staleness)
    // and degrades to `NoSample` → `Baseline` (the data-loss-safe
    // direction; no genesis wipe). The boot self-heal's digest fast
    // path (`circuit_digest_meta`) remains the primary staleness signal;
    // the canary is a secondary probe that simply has no usable sample
    // under the neutral model. See `AccountNode::canary_recursion`.
    let current_pubkey_for =
        |_addr: &zkcoins_program::hash::HashDigest,
         _smt: &zkcoins_program::merkle::sparse_merkle_tree::SparseMerkleTree| {
            None::<bitcoin::secp256k1::PublicKey>
        };
    let heal_decision =
        node::self_heal::heal_circuit_digest(&pool, &live_digest, &proofs_dir, &|| {
            account_node.canary_recursion(&current_pubkey_for)
        })
        .await
        .expect("circuit-digest self-heal");
    println!("Circuit-digest self-heal: {:?}", heal_decision);

    // On a reset the in-memory `state` + `account_node` were rehydrated
    // from the pre-reset rows that `heal_circuit_digest` just wiped, so
    // they no longer match Postgres. Reload both from the now-empty DB,
    // recovering the prover (and its ~14 s circuit build) from the stale
    // `account_node` so the circuit is still built exactly once.
    let (state, account_node) = if heal_decision == node::self_heal::ResetDecision::Reset {
        let prover = account_node.take_prover();
        let state = Arc::new(Mutex::new(
            State::load_from_pg(&pool)
                .await
                .expect("reload state after self-heal reset"),
        ));
        let account_node =
            account_node::AccountNode::load_from_pg(Arc::clone(&state), &pool, prover)
                .await
                .expect("reload account node after self-heal reset");
        println!("Reloaded State + AccountNode from genesis after self-heal reset");
        (state, account_node)
    } else {
        (state, account_node)
    };

    let username_store = username::UsernameStore::load_from_pg(&pool)
        .await
        .expect("load username store from Postgres");
    println!("Loaded UsernameStore from Postgres");

    // Spawn the account_node as a separate task. A bootstrap error
    // here (Postgres unreachable, listener bind failure) used to be
    // `eprintln!`'d and dropped on the floor by this `tokio::spawn`
    // block — the scanner kept running, the container stayed `Up`,
    // and Cloudflare served 502s for hours because nothing was bound
    // to the listener port. Aborting the whole process on bootstrap
    // failure means the orchestrator crash-loops the container and
    // alerting fires on the loop, matching the panic-hook behaviour
    // above (zk-coins/node#89 round-2 MAJOR 2).
    let pool_for_rest = Arc::clone(&pool);
    // v1.1 readiness handles: under the exclusive NfLog stack, REST binds
    // before the scanner connects/catches up. Share atomics so
    // `/health/ready` stays 503 until the first successful apply and
    // trips on `finality_broken`. Legacy path leaves both `None`.
    let (v11_readiness, v11_scan_caught_up, v11_finality_ok) = if v11_adapter.is_some() {
        let caught_up = Arc::new(AtomicBool::new(false));
        let finality_ok = Arc::new(AtomicBool::new(true));
        (
            V11Readiness {
                scan_caught_up: Some(Arc::clone(&caught_up)),
                finality_ok: Some(Arc::clone(&finality_ok)),
            },
            Some(caught_up),
            Some(finality_ok),
        )
    } else {
        (V11Readiness::default(), None, None)
    };
    // `proofs_dir` was already read at the binary edge above (for the
    // self-heal proof-store cleanup) and is moved into the spawned
    // task here. `start_rest_node` no longer touches `std::env` so the
    // runtime tests can each pass their own `tempfile::tempdir()` path
    // instead of racing on the process-wide env var under
    // `--test-threads=8` (issue #181 Opt A).
    tokio::spawn(async move {
        if let Err(e) = start_rest_node(
            account_node,
            username_store,
            ACCOUNT_NODE_ADDR,
            pool_for_rest,
            &proofs_dir,
            v11_readiness,
        )
        .await
        {
            eprintln!("Account node error: {}", e);
            std::process::exit(1);
        }
    });

    // Stage 2 dual stack: either the v1.1 NfLog scanner **or** the legacy
    // Commitment/SMT scanner — never both against the same process state.
    if let Some(adapter) = v11_adapter {
        run_v11_scan_loop(adapter, v11_scan_caught_up, v11_finality_ok).await?;
        return Ok(());
    }

    // —— Legacy path (flag off) — Commitment → SMT/MMR via Esplora ——
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
                    let entry = node::db::ObservedInscriptionEntry {
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
                                node::db::insert_observed_inscription(&pool, &entry).await
                            {
                                eprintln!("Failed to persist observed_inscription: {}", e);
                            }
                        });
                    });
                }

                if node::scanner::should_skip_scanner_state_update(pending_status.as_deref()) {
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
                                    if let Err(e) = node::db::mark_observed_inscription_integrated(
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

/// Stage 2 v1.1 exclusive scan loop: bitcoind RPC + script-plonky2
/// [`zkcoins_prover::scanner::Scanner`] → NfLog fold on [`EngineAdapter`].
///
/// **Never** falls back to the Esplora Commitment scanner. Missing RPC
/// pins, connect failures, or infrastructure errors abort the process.
///
/// ## Reorg (live)
/// When `scan_to_tip` reports a reorg, the full post-reorg survivor stream
/// replaces the engine NfLog ([`v11::apply_canonical_survivors`]). Forward
/// progress without reorg appends only newly seen survivors.
/// `ReorgOutcome::finality_broken` stops crediting and fails readiness.
///
/// ## Reorg (restart while down)
/// A fresh scanner has no checkpoint, so a reorg that happened offline is
/// invisible to `report.reorg`. Reconciliation and the first scan are
/// therefore **one observation**: scan first, reconcile the persisted tip
/// against that scan's tip, re-verify the tip is unchanged, then apply
/// from the same survivors. A reorg between a free-standing recon and a
/// later scan cannot slip through — there is no free-standing recon.
async fn run_v11_scan_loop(
    adapter: node::v11::EngineAdapter,
    scan_caught_up: Option<Arc<AtomicBool>>,
    finality_ok: Option<Arc<AtomicBool>>,
) -> Result<(), Box<dyn StdError>> {
    use std::collections::HashSet;
    use std::time::Duration;
    use v11::{
        first_boot_requires_full_replace, folded_keys_from_nflog_mirror,
        observation_tip_still_live, reconcile_persisted_tip, PersistedTipReconciliation,
        TipReconcileOutcome,
    };

    let pins = v11::mode::v11_boot_pins_from_env().map_err(|e| e.to_string())?;
    let (rpc_url, cookie_path) =
        v11::scan::v11_bitcoind_rpc_from_env().map_err(|e| e.to_string())?;

    let scanner_config = zkcoins_prover::scanner::ScannerConfig {
        rpc_url: rpc_url.clone(),
        cookie_path: cookie_path.clone(),
        network: pins.network,
        activation_height: pins.activation_height,
        network_params: pins.network_params.clone(),
        expected_params_identifier: pins.expected_params_identifier,
    };

    println!(
        "v1.1 scanner: connecting bitcoind RPC for AggregateStateNullifierV3 / NfLog \
         (network={:?}, activation_height={})",
        pins.network, pins.activation_height
    );

    // Connect is synchronous (blocking RPC). Keep it off the async worker.
    let mut scanner = tokio::task::spawn_blocking(move || {
        zkcoins_prover::scanner::Scanner::connect(scanner_config)
    })
    .await
    .map_err(|e| format!("v1.1 scanner connect join: {e}"))?
    .map_err(|e| {
        format!(
            "v1.1 Scanner::connect failed: {e:#} — refusing to fall back to the \
             legacy Esplora commitment scanner"
        )
    })?;

    // Track which survivor chain positions we have already folded so a
    // re-scan of the same tip does not re-append (append_nullifier is
    // strict). Reorg / full-replace clears this set and rebuilds.
    let mut folded_keys: HashSet<(u64, u32, u32, u32, [u8; 32])> = HashSet::new();
    // First observation unit not yet committed: recon + first scan share
    // one tip. After commit, the scanner has a checkpoint and `report.reorg`
    // is trustworthy.
    let mut boot_observation_committed = false;
    let activation_height = pins.activation_height;
    // Transient incomplete-view backoff (RPC behind). Not a chain-tip poll.
    const RECON_RETRY_BACKOFF: Duration = Duration::from_secs(5);

    loop {
        let scan_result = tokio::task::spawn_blocking(move || {
            let report = scanner.scan_to_tip();
            (scanner, report)
        })
        .await
        .map_err(|e| format!("v1.1 scan_to_tip join: {e}"))?;

        scanner = scan_result.0;
        let report = match scan_result.1 {
            Ok(r) => r,
            Err(e) => {
                // Infrastructure failure: fail loud (no legacy fall-back).
                return Err(format!(
                    "v1.1 scanner infrastructure failure: {e:#} — refusing to \
                     fall back to the legacy commitment scanner"
                )
                .into());
            }
        };

        // §3.9: finality_broken means callers must stop crediting and
        // readiness must fail. Honour the contract — do not continue the
        // fold loop after a deep reorg displaces final positions.
        if let Some(ref reorg) = report.reorg {
            if reorg.finality_broken {
                if let Some(flag) = &finality_ok {
                    flag.store(false, Ordering::SeqCst);
                }
                return Err(format!(
                    "v1.1 scanner: FINALITY BROKEN after reorg \
                     (displaced_final_count={}) — stopping NfLog credit and \
                     failing readiness (deep_reorg). Manual recovery required; \
                     refusing to continue folding",
                    reorg.displaced_final_count
                )
                .into());
            }
        }

        let tip = scanner
            .scanned_through()
            .ok_or("v1.1 scanner has no scanned_through tip after successful scan_to_tip")?;
        let tip_height = tip.0;
        let tip_hash = tip.1.to_byte_array();
        let survivors = scanner.survivors().to_vec();

        // —— Boot observation unit: bind recon to THIS scan's tip ——
        // Window is closed, not narrowed: we never seed folded keys or
        // choose forward vs full-replace from a recon that observed a
        // different chain than the survivors we are about to apply.
        let mut force_full_replace = report.reorg.is_some();
        if !boot_observation_committed {
            let persisted_height = adapter.with_engine(|e| e.tip_height());
            let persisted_hash = adapter.tip_hash();
            let scan_tip_height = tip_height;
            let scan_tip_hash = tip_hash;
            let rpc_url_b = rpc_url.clone();
            let cookie_path_b = cookie_path.clone();

            let recon_result = tokio::task::spawn_blocking(move || {
                use bitcoincore_rpc::RpcApi;
                use v11::scan::ResolvedBlock;

                let open_client = || {
                    bitcoincore_rpc::Client::new(
                        rpc_url_b.trim_end_matches('/'),
                        bitcoincore_rpc::Auth::CookieFile(cookie_path_b.clone()),
                    )
                    .map_err(|e| anyhow::anyhow!("bitcoind RPC open for tip recon: {e}"))
                };

                let query_live_hash = |h: u64| -> anyhow::Result<Option<[u8; 32]>> {
                    let client = open_client()?;
                    let tip = client
                        .get_block_count()
                        .map_err(|e| anyhow::anyhow!("getblockcount for tip recon: {e}"))?;
                    if h > tip {
                        return Ok(None);
                    }
                    let hash = client
                        .get_block_hash(h)
                        .map_err(|e| anyhow::anyhow!("getblockhash({h}) for tip recon: {e}"))?;
                    Ok(Some(hash.to_byte_array()))
                };

                let resolve_hash = |block_hash: [u8; 32]| -> anyhow::Result<Option<ResolvedBlock>> {
                    let client = open_client()?;
                    let bh = BlockHash::from_byte_array(block_hash);
                    match client.get_block_header_info(&bh) {
                        Ok(info) => {
                            let height = u64::try_from(info.height).map_err(|_| {
                                anyhow::anyhow!(
                                    "getblockheader height {} does not fit u64",
                                    info.height
                                )
                            })?;
                            let prev_hash = info
                                .previous_block_hash
                                .map(|p| p.to_byte_array())
                                .unwrap_or([0u8; 32]);
                            Ok(Some(ResolvedBlock {
                                height,
                                prev_hash,
                            }))
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            let unknown = msg.contains("Block not found")
                                || msg.contains("Block header not found")
                                || msg.contains("not found")
                                || msg.contains("-5");
                            if unknown {
                                Ok(None)
                            } else {
                                Err(anyhow::anyhow!("getblockheader for tip recon: {e}"))
                            }
                        }
                    }
                };

                let outcome = reconcile_persisted_tip(
                    persisted_height,
                    persisted_hash,
                    activation_height,
                    query_live_hash,
                    resolve_hash,
                )?;

                // Tip stability pin: recon and scan must still describe the
                // same tip. If the live hash at the scan height moved, the
                // whole observation is stale — caller retries. Fresh query
                // (query_live_hash was moved into recon above).
                let live_at_scan = {
                    let client = open_client()?;
                    let tip = client
                        .get_block_count()
                        .map_err(|e| anyhow::anyhow!("getblockcount for tip pin: {e}"))?;
                    if scan_tip_height > tip {
                        None
                    } else {
                        let hash = client.get_block_hash(scan_tip_height).map_err(|e| {
                            anyhow::anyhow!("getblockhash({scan_tip_height}) for tip pin: {e}")
                        })?;
                        Some(hash.to_byte_array())
                    }
                };
                let stable = observation_tip_still_live(scan_tip_hash, live_at_scan);
                Ok::<_, anyhow::Error>((outcome, stable))
            })
            .await
            .map_err(|e| format!("v1.1 tip reconciliation join: {e}"))?;

            let (outcome, tip_stable) = match recon_result {
                Ok(v) => v,
                Err(e) => {
                    // Fatal only (deep reorg / unresolvable / corruption).
                    if let Some(flag) = &finality_ok {
                        flag.store(false, Ordering::SeqCst);
                    }
                    return Err(format!("v1.1 tip reconciliation failed: {e:#}").into());
                }
            };

            if !tip_stable {
                println!(
                    "v1.1 boot tip: scan tip height={} hash={} moved during \
                     reconciliation — discarding observation and retrying \
                     (bound recon+scan window closed, not narrowed)",
                    tip_height,
                    hex::encode(tip_hash)
                );
                // scanner-polling-ok: v11 bound-observation tip-stability retry
                tokio::time::sleep(RECON_RETRY_BACKOFF).await;
                continue;
            }

            match outcome {
                TipReconcileOutcome::RetryableIncompleteView {
                    queried_height,
                    detail,
                } => {
                    // Transient: RPC behind. Stay unready, leave finality_ok
                    // alone, never assume canonical or divergent.
                    println!(
                        "v1.1 boot tip: incomplete live view at height \
                         {queried_height} — {detail}; staying unready and retrying"
                    );
                    // scanner-polling-ok: v11 incomplete-view RPC-behind backoff
                    tokio::time::sleep(RECON_RETRY_BACKOFF).await;
                    continue;
                }
                TipReconcileOutcome::Ready(PersistedTipReconciliation::Fresh) => {
                    println!(
                        "v1.1 boot tip: fresh engine (no persisted tip); applying \
                         first scan observation (tip={tip_height})"
                    );
                }
                TipReconcileOutcome::Ready(PersistedTipReconciliation::StillCanonical {
                    tip_height: ph,
                    tip_hash: p_hash,
                }) => {
                    let mirror = adapter.with_engine(|e| e.nflog_mirror());
                    folded_keys = folded_keys_from_nflog_mirror(&mirror);
                    println!(
                        "v1.1 boot tip: still canonical at height={} hash={} \
                         (seeded {} folded keys; bound to scan tip={tip_height})",
                        ph,
                        hex::encode(p_hash),
                        folded_keys.len()
                    );
                }
                TipReconcileOutcome::Ready(PersistedTipReconciliation::ShallowReorg {
                    ancestor_height,
                    ancestor_hash,
                    reorg_depth,
                    persisted_height,
                    persisted_hash,
                }) => {
                    force_full_replace = true;
                    println!(
                        "v1.1 boot tip: shallow offline reorg depth={} (persisted \
                         height={} hash={} → common ancestor height={} hash={}); \
                         full-replace NfLog from this scan's survivors (bound \
                         observation; §3.9 ≤5-block window)",
                        reorg_depth,
                        persisted_height,
                        hex::encode(persisted_hash),
                        ancestor_height,
                        hex::encode(ancestor_hash)
                    );
                    debug_assert!(first_boot_requires_full_replace(
                        &PersistedTipReconciliation::ShallowReorg {
                            ancestor_height,
                            ancestor_hash,
                            reorg_depth,
                            persisted_height,
                            persisted_hash,
                        }
                    ));
                }
            }
            boot_observation_committed = true;
        }

        let do_full_replace = force_full_replace;
        if do_full_replace {
            // Full replace: scanner survivors are the canonical stream.
            let stats = v11::apply_canonical_survivors(
                &adapter,
                tip_height,
                tip_hash,
                &survivors,
            )
            .await
            .map_err(|e| format!("v1.1 reorg/full-replace NfLog apply failed: {e:#}"))?;
            folded_keys.clear();
            for nf in &survivors {
                folded_keys.insert((
                    nf.chain_pos.height,
                    nf.chain_pos.tx_index,
                    nf.chain_pos.vin_index,
                    nf.chain_pos.member_index,
                    nf.pk,
                ));
            }
            println!(
                "v1.1 scanner full-replace applied: tip={} hash={} appended={} dup_ignored={}",
                tip_height,
                tip.1,
                stats.appended,
                stats.duplicate_ignored
            );
        } else {
            let new: Vec<_> = survivors
                .iter()
                .copied()
                .filter(|nf| {
                    !folded_keys.contains(&(
                        nf.chain_pos.height,
                        nf.chain_pos.tx_index,
                        nf.chain_pos.vin_index,
                        nf.chain_pos.member_index,
                        nf.pk,
                    ))
                })
                .collect();
            if !new.is_empty() || tip_height > adapter.with_engine(|e| e.tip_height()) {
                let stats = v11::apply_forward_scan(&adapter, tip_height, tip_hash, &new)
                    .await
                    .map_err(|e| format!("v1.1 forward NfLog apply failed: {e:#}"))?;
                for nf in &new {
                    folded_keys.insert((
                        nf.chain_pos.height,
                        nf.chain_pos.tx_index,
                        nf.chain_pos.vin_index,
                        nf.chain_pos.member_index,
                        nf.pk,
                    ));
                }
                if stats.appended > 0 || stats.duplicate_ignored > 0 {
                    println!(
                        "v1.1 scanner folded: tip={} appended={} dup_ignored={} below_act={}",
                        tip_height, stats.appended, stats.duplicate_ignored, stats.below_activation
                    );
                }
            }
        }

        // First successful catch-up after a committed boot observation:
        // mark readiness so load balancers can send traffic once the NfLog
        // view reflects the chain tip. Incomplete-view retries never reach
        // here (they `continue` before apply / before this flag).
        if let Some(flag) = &scan_caught_up {
            if !flag.load(Ordering::SeqCst) {
                flag.store(true, Ordering::SeqCst);
                println!("v1.1 scanner: catch-up complete; readiness may pass v11_scan gate");
            }
        }

        // Event-driven tip advance is owned by bitcoind; poll interval is a
        // last-resort backoff between successful scan_to_tip calls (no
        // Esplora WS on this path). Marked so CI lint grandfathering matches
        // scanner_runtime's HTTP backoff token style.
        // scanner-polling-ok: v11 bitcoind scan_to_tip idle backoff
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
