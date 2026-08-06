//! Runtime bootstrap: binds a TCP listener and runs the Axum app.
//!
//! This file is intentionally excluded from the coverage scope. The
//! function below cannot be exercised by unit tests — it owns the
//! process lifecycle (port binding, signal-driven shutdown via axum)
//! and exists purely to wire the dependency graph defined in
//! `router.rs` to a real network socket.
//!
//! Anything that is testable in isolation (handlers, helpers, the
//! router construction in `create_router`) stays in `router.rs` and
//! is measured normally.

use dashmap::DashMap;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::job_dispatcher::{self, JobNotifier, DEFAULT_AWAITING_SIGNATURE_TIMEOUT};
use crate::job_store::{JobStatus, JobStore};
use crate::publisher::resume_pending_inscriptions;
use crate::v1::{process_stack_mode, ScanStackMode};
use crate::NETWORK_CONFIG;

use crate::account_node::AccountNode;
use crate::router::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;

#[cfg(all(feature = "coverage-flush", coverage_nightly))]
unsafe extern "C" {
    fn __llvm_profile_write_file() -> libc::c_int;
}

/// Install the lifecycle hook used only by the instrumented integration image.
///
/// LLVM's compiler-rt profiling runtime exports `__llvm_profile_write_file`;
/// it writes the active counters to the path selected by `LLVM_PROFILE_FILE`.
/// The Cargo feature and `coverage_nightly` cfg deliberately form a double
/// gate: a normal production build neither installs signal handlers nor even
/// references the profiling-runtime symbol.
#[cfg(all(feature = "coverage-flush", coverage_nightly))]
fn spawn_coverage_flush_signal_handler() {
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut sigterm = signal(SignalKind::terminate())
            .expect("coverage build must install its SIGTERM listener");
        let mut sigint = signal(SignalKind::interrupt())
            .expect("coverage build must install its SIGINT listener");

        let signal_name = tokio::select! {
            _ = sigterm.recv() => "SIGTERM",
            _ = sigint.recv() => "SIGINT",
        };
        tracing::info!(signal = signal_name, "flushing LLVM coverage profile");

        // SAFETY: LLVM's profiling runtime is linked by `-C instrument-coverage`.
        // This function is compiled only when that flag's companion cfg and the
        // opt-in Cargo feature are both present.
        let status = unsafe { __llvm_profile_write_file() };
        if status != 0 {
            tracing::error!(status, "LLVM coverage profile flush failed");
            std::process::exit(1);
        }
        std::process::exit(0);
    });
}

/// Optional v1.1 readiness handles shared with the exclusive scan loop.
///
/// Under the legacy stack both fields are `None` and readiness ignores
/// NfLog catch-up / deep-reorg. Under `ZKCOINS_V1_SHADOW=1` main wires
/// `Some` atomics so `/health/ready` reflects the NfLog view.
#[derive(Clone, Default)]
pub struct V1Readiness {
    pub scan_caught_up: Option<Arc<AtomicBool>>,
    pub finality_ok: Option<Arc<AtomicBool>>,
}

/// Everything `start_rest_node` needs, resolved at the binary edge.
pub struct RestNodeConfig {
    pub account_node: AccountNode,
    pub username_store: UsernameStore,
    /// REST listen address, parsed inside `start_rest_node`.
    pub addr: String,
    pub pool: Arc<PgPool>,
    /// Proof-store directory. The env read (`PROOFS_DIR`) stays at the
    /// binary edge so parallel test binaries (`runtime_tests.rs` under
    /// issue #181 Opt A's `--test-threads=8`) each pass their own
    /// `tempfile::tempdir()` path instead of racing on a process-wide
    /// env var. Proof files keep using a local directory — the proof
    /// store is append-only and the proofs themselves are large
    /// (bincode-serialized Plonky2 proofs) so a `BYTEA` column would
    /// balloon the Postgres image.
    pub proofs_dir: String,
    pub v1_readiness: V1Readiness,
    /// Shared v1.1 engine (when `ZKCOINS_V1_SHADOW=1`). Used to drive
    /// `StateEngine::finalise` after an accepted `/v1/jobs/{id}/sign`.
    pub v1_engine: Option<Arc<crate::v1::EngineAdapter>>,
    /// Kernel gRPC listen address (**required**, no default).
    /// Validated at the binary edge via `KERNEL_GRPC_ADDR` before this
    /// is called. Served with the same job store + notify map as REST
    /// so `StreamJob` subscribers see dispatcher phase events.
    pub kernel_grpc_addr: SocketAddr,
}

/// Fail-loud check of operational GetInfo env vars at the binary edge.
///
/// Requires `ZKCOINS_RELAY_URL`, `ZKCOINS_BLOSSOM_URL`,
/// `ZKCOINS_MAX_BLOB_BYTES`, `ZKCOINS_KERNEL_PARTS` — each non-empty, no
/// defaults. A missing or invalid value names the variable.
///
/// A complete [`crate::kernel::ChainIdentity`] also needs a verified
/// §4.3 BootstrapManifest (`ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH`). That
/// load + identity install runs later in [`start_rest_node`] before any
/// socket binds: unset path, or a path that does not verify, aborts boot
/// when the exclusive v1 engine is present (no GetInfo without identity).
///
/// Call before expensive bootstrap so a misconfigured deployment fails
/// before circuit construction / DB work completes unused.
pub fn require_chain_identity_ops_from_env() -> Result<(), String> {
    crate::kernel::chain::chain_identity_ops_from_env()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Whether this boot can build a circuit and therefore must validate the
/// mandatory host-wide proving-lease path before expensive work.
///
/// Primary verifier-cache boot always self-heals live digests by constructing
/// both circuits, even when the advertised kernel parts omit `prover`.
pub fn boot_requires_prover_lease() -> Result<bool, String> {
    let ops =
        crate::kernel::chain::chain_identity_ops_from_env().map_err(|e| e.to_string())?;
    let verifier_cache_role =
        crate::v1::verifier_cache_role_from_env().map_err(|e| e.to_string())?;
    Ok(ops
        .kernel_parts
        .contains(&crate::kernel::chain::KernelPart::Prover)
        || verifier_cache_role == crate::v1::VerifierCacheRole::Primary)
}

/// Bind REST + job dispatcher + kernel gRPC, sharing one job store and notify map.
///
/// The normative error table and the closed §7.5 / §7.8 wire vocabularies
/// are hand-written. [`crate::transport::error_contract::validate_table`]
/// and [`crate::kernel::chain::validate_closed_sets`] run before the REST
/// socket is bound so a release built without green tests cannot ship
/// wrong codes or collapsed readiness/part/member tokens. The checks are
/// microseconds once and fail closed.
pub async fn start_rest_node(config: RestNodeConfig) -> anyhow::Result<()> {
    let RestNodeConfig {
        account_node,
        username_store,
        addr,
        pool,
        proofs_dir,
        v1_readiness,
        v1_engine,
        kernel_grpc_addr,
    } = config;

    // Fail closed on a drifted §7.8 error table before any listener binds.
    if let Err(e) = crate::transport::error_contract::validate_table() {
        anyhow::bail!("kernel error contract invalid: {e}");
    }
    // Same start edge: closed ReadyReason / NullifierMemberState / KernelPart
    // wire strings must be non-empty and pairwise distinct.
    if let Err(e) = crate::kernel::chain::validate_closed_sets() {
        anyhow::bail!("kernel closed-set contract invalid: {e}");
    }
    // Access-layer closed sets (RecordType / TransitionKind / SessionAuthority /
    // ReceiptState / ChallengeAction including Pull).
    if let Err(e) = crate::kernel::access::validate_closed_sets() {
        anyhow::bail!("kernel access closed-set contract invalid: {e}");
    }
    // Publisher reject-reason vocabulary (§7.6 closed `reason` set).
    if let Err(e) = crate::kernel::publish::validate_closed_sets() {
        anyhow::bail!("kernel publish closed-set contract invalid: {e}");
    }

    // §4.3 / §7.7 BMF1 bootstrap manifest — optional path, fail-closed when set.
    // Runs before any listener (gRPC or REST) so a bad/missing configured
    // artifact never leaves a half-started node accepting traffic.
    let manifest_store = {
        use crate::kernel::bootstrap::{
            bootstrap_manifest_path_from_env, load_manifest_store, LoadBootstrapManifestConfig,
            ManifestStore, BOOTSTRAP_MANIFEST_PATH_ENV,
        };
        use shared::spec_v1::ManifestClock;
        use std::time::{SystemTime, UNIX_EPOCH};

        let path_env = bootstrap_manifest_path_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
        match path_env {
            None => ManifestStore::shared(),
            Some(path) => {
                // Path set ⇒ need the frozen §3.6 pin to verify under.
                let pins = crate::v1::mode::v1_boot_pins_from_env().map_err(|e| {
                    anyhow::anyhow!(
                        "{BOOTSTRAP_MANIFEST_PATH_ENV} is set but network pins are \
                         unavailable for verification: {e}"
                    )
                })?;
                let pinned = pins.network_params.bootstrap_pubkey();
                let expected_network = crate::v1::mode::network_label(pins.network);
                let clock = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(d) => ManifestClock::UnixSeconds(d.as_secs()),
                    // Clock before epoch is unusable for expiry — skip only
                    // that check (signature + network still enforced).
                    Err(_) => ManifestClock::Unavailable,
                };
                load_manifest_store(LoadBootstrapManifestConfig {
                    path_env: Some(path.as_str()),
                    pinned_bootstrap_pubkey: &pinned,
                    expected_network,
                    clock,
                })
                .map_err(|e| anyhow::anyhow!("{e}"))?
            }
        }
    };
    if let Some(v) = manifest_store.get() {
        // Field accessors stay library-reachable for later GetInfo wiring.
        let m = v.manifest();
        tracing::info!(
            manifest_id = %hex::encode(v.manifest_id()),
            network = %v.network(),
            protocol_version = %v.protocol_version(),
            issued_at = v.issued_at(),
            expires_at = v.expires_at(),
            seed_relays = v.seed_relays().len(),
            blob_stores = v.blob_stores().len(),
            operator_ids = v.operator_ids().len(),
            // seed_relays is non-empty after verify (≥ 1).
            first_seed_relay = %m.seed_relays[0],
            manifest_sig_len = v.manifest_sig().len(),
            "verified BootstrapManifestV1 loaded"
        );
    } else {
        tracing::info!(
            "no BootstrapManifest configured ({} unset) — store empty",
            crate::kernel::bootstrap::BOOTSTRAP_MANIFEST_PATH_ENV
        );
    }

    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    let shared_account_node = Arc::new(Mutex::new(account_node));

    let proof_store = Arc::new(ProofStore::new(&proofs_dir));

    // Process-local delivery stores (same durability class as BundleStore).
    // Shared with the kernel Entrust surface and the post-persist mesh port.
    let shared_bundle_store = crate::kernel::bootstrap::BundleStore::shared();
    let shared_delivery_targets = crate::v1::DeliveryTargetStore::shared();
    let shared_delivery_retention = crate::v1::PendingDeliveryStore::shared();
    // Process mirror of durable `v1_decrypt_index` — filled by the §4.4
    // receive scanner after SQL insert; shared with kernel Pull surfaces.
    let shared_private_index = crate::kernel::access::InMemoryPrivateIndex::shared();
    // Credit-receipt fan-out: scanner publishes after dual persist; kernel
    // SubscribeReceipts filters by server-side session subject + scope.
    let shared_receipt_hub = crate::kernel::access::ReceiptHub::shared();
    // Durable outbox needs the Postgres pool (same durability class as engine).
    let shared_delivery_port: Arc<dyn crate::v1::OutgoingDeliveryPort> =
        Arc::new(crate::v1::MeshDeliveryPort::new(
            (*pool).clone(),
            Arc::clone(&shared_delivery_retention),
            Box::new(crate::v1::OsSecureRandom),
        ));
    // Shared CSPRNG for finalise-time Phase-A change-coin builds and the
    // outbox drive path (process-local; never invent keys).
    let shared_delivery_rng: std::sync::Arc<
        std::sync::Mutex<Box<dyn crate::v1::nostr::nip59::SecureRandom + Send>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(Box::new(crate::v1::OsSecureRandom)));

    // §4.2 ACK return path + §4.2 republish of due outbox rows.
    //
    // Same soft 30 s tick as before (event-driven mesh for scanners/publishers
    // lives elsewhere; this is the ACK/republish guard frame). Due work is
    // selected by `next_attempt_at` on the durable outbox — the tick only
    // wakes the driver; backoff itself is §4.2 (30 s, doubling, cap 1 h).
    {
        let retention = Arc::clone(&shared_delivery_retention);
        let bundles = Arc::clone(&shared_bundle_store);
        let pg: sqlx::PgPool = (*pool).clone();
        let rng = Arc::clone(&shared_delivery_rng);
        let relay_url = crate::kernel::chain::chain_identity_ops_from_env()
            .ok()
            .map(|ops| ops.relay_url);
        tokio::spawn(async move {
            let Some(relay_url) = relay_url else {
                tracing::warn!(
                    "ACK/outbox driver not started: chain identity ops (relay URL) unavailable at boot"
                );
                return;
            };
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;

                // 1) Republish / first-publish due outbox rows.
                let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                    Ok(d) => d.as_secs(),
                    Err(_) => {
                        tracing::error!(
                            "outbox driver: wall clock before UNIX epoch — skipping tick"
                        );
                        continue;
                    }
                };
                match crate::v1::delivery::drive_due_outbox_entries(
                    &pg,
                    bundles.as_ref(),
                    retention.as_ref(),
                    rng.as_ref(),
                    now,
                )
                .await
                {
                    Ok(n) if n > 0 => {
                        tracing::info!(driven = n, "delivery outbox due rows driven");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "delivery outbox drive failed");
                    }
                }

                // 2) ACK inbox → durable outbox completed (row retained).
                let relay_pool =
                    match crate::v1::nostr::relay::RelayPool::new(vec![relay_url.clone()]) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error = %e, "ACK inbox: relay pool construction failed");
                            continue;
                        }
                    };
                for (_subject, bundle) in bundles.list_active() {
                    match crate::v1::delivery::poll_incoming_acks(
                        &relay_pool,
                        &bundle.ivk,
                        retention.as_ref(),
                        Some(&pg),
                        None,
                    )
                    .await
                    {
                        Ok(results) => {
                            for r in results {
                                match r {
                                    crate::v1::delivery::AckInboxResult::Accepted {
                                        blob_id,
                                        ack_nonce,
                                    } => {
                                        tracing::info!(
                                            blob_id = %hex::encode(blob_id),
                                            ack_nonce = %hex::encode(ack_nonce),
                                            "ACK accepted; outbox awaiting k receipts"
                                        );
                                    }
                                    crate::v1::delivery::AckInboxResult::Rejected { error } => {
                                        tracing::debug!(
                                            error = %error,
                                            "ACK candidate rejected"
                                        );
                                    }
                                    crate::v1::delivery::AckInboxResult::Ignored { .. } => {}
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "ACK inbox poll failed");
                        }
                    }
                }
            }
        });
    }

    // §4.5 emergency recovery (operator opt-in only).
    //
    // Why a background task *after* the shared stores exist, not a blocking
    // pre-bind step: a gapless scan over full seed-relay history can take a
    // long time. Blocking socket bind / readiness on that scan would leave
    // the node unready for the entire campaign — also wrong. Without
    // `ZKCOINS_V1_RECOVERY=1` this path is never started (a node that
    // full-history-scans on every boot would be an operational accident).
    //
    // Fail-closed: incomplete config with the flag set aborts boot (named
    // env errors); missing seed relays aborts boot; missing operational
    // bundle is waited on (process-local BundleStore is empty until
    // Entrust) then the campaign refuses `restored=true` on incomplete
    // scan. No silent default page size / earliest bound.
    {
        match crate::v1::recovery::recovery_campaign_config_from_env() {
            Ok(None) => {
                tracing::debug!(
                    "§4.5 recovery not requested ({} unset or not 1)",
                    crate::v1::recovery::RECOVERY_ENV
                );
            }
            Err(e) => {
                anyhow::bail!("{e}");
            }
            Ok(Some(recovery_config)) => {
                let Some(engine) = v1_engine.as_ref() else {
                    anyhow::bail!(
                        "{}=1 requires the v1.1 engine (ScanStackMode::V1) — \
                         recovery cannot verify CoinProofs without it",
                        crate::v1::recovery::RECOVERY_ENV
                    );
                };
                let seed_relays = match manifest_store.get() {
                    Some(v) if !v.seed_relays().is_empty() => v.seed_relays().to_vec(),
                    _ => {
                        anyhow::bail!(
                            "{}=1 requires a verified BootstrapManifest with \
                             non-empty seed_relays (set {} to a BMF1 artifact) \
                             — refusing to invent relay URLs",
                            crate::v1::recovery::RECOVERY_ENV,
                            crate::kernel::bootstrap::BOOTSTRAP_MANIFEST_PATH_ENV
                        );
                    }
                };
                let ops = crate::kernel::chain::chain_identity_ops_from_env().map_err(|e| {
                    anyhow::anyhow!(
                        "{}=1 requires chain identity ops (max_blob_bytes / network \
                         surface): {e}",
                        crate::v1::recovery::RECOVERY_ENV
                    )
                })?;
                let engine = Arc::clone(engine);
                let bundles = Arc::clone(&shared_bundle_store);
                let private_index = Arc::clone(&shared_private_index);
                let receipt_hub = Arc::clone(&shared_receipt_hub);
                let pool = Arc::clone(&pool);
                let network_label = crate::v1::mode::network_label(engine.network()).to_string();
                tracing::info!(
                    page_limit = recovery_config.page_limit,
                    earliest = recovery_config.earliest_account_timestamp,
                    seed_relays = seed_relays.len(),
                    "§4.5 recovery campaign scheduled (background; will wait for \
                     entrusteed operational bundle before scanning)"
                );
                tokio::spawn(async move {
                    loop {
                        // Bounded re-scan for late relay propagation: a complete
                        // gapless scan can still install nothing when the origin
                        // delivery outbox has not yet published the needed
                        // record. Hard errors and partial installs never retry.
                        for attempt in 0..RECOVERY_CAMPAIGN_MAX_ATTEMPTS {
                            let deps = crate::v1::recovery::RecoveryCampaignDeps {
                                seed_relays: seed_relays.clone(),
                                bundles: Arc::clone(&bundles),
                                adapter: Arc::clone(&engine),
                                pool: Arc::clone(&pool),
                                index: Arc::clone(&private_index),
                                receipts: Arc::clone(&receipt_hub),
                                max_blob_bytes: ops.max_blob_bytes,
                                expected_network: network_label.clone(),
                            };
                            match crate::v1::recovery::run_recovery_campaign(
                                recovery_config.clone(),
                                deps,
                            )
                            .await
                            {
                                Ok(report) if report.restored => {
                                    tracing::info!(
                                        accepted = report.coin_proof_accepted,
                                        sdr_discards = report.sdr_discards.len(),
                                        sdr_coins_folded = report.sdr_coins_folded,
                                        replayed_heads = report.replayed_heads.len(),
                                        "§4.5 recovery campaign: restored=true"
                                    );
                                    for discard in &report.sdr_discards {
                                        tracing::warn!(
                                            subject = %hex::encode(discard.subject),
                                            blob_id = %hex::encode(discard.blob_id),
                                            record_kind = ?discard.record_kind,
                                            send_counter = ?discard.send_counter,
                                            reason = %discard.reason,
                                            "§4.5 recovery SDR discard (replay could not accept candidate)"
                                        );
                                    }
                                    break;
                                }
                                Ok(report)
                                    if should_retry_recovery(
                                        &report,
                                        attempt,
                                        RECOVERY_CAMPAIGN_MAX_ATTEMPTS,
                                    ) =>
                                {
                                    // Pure relay-propagation race: complete scan,
                                    // nothing installed — safe to re-scan.
                                    tracing::info!(
                                    attempt = attempt + 1,
                                    max_attempts = RECOVERY_CAMPAIGN_MAX_ATTEMPTS,
                                    "§4.5 recovery: complete scan installed no head yet — re-scanning for late relay propagation"
                                );
                                    for discard in &report.sdr_discards {
                                        tracing::warn!(
                                            subject = %hex::encode(discard.subject),
                                            blob_id = %hex::encode(discard.blob_id),
                                            record_kind = ?discard.record_kind,
                                            send_counter = ?discard.send_counter,
                                            reason = %discard.reason,
                                            "§4.5 recovery SDR discard (replay could not accept candidate)"
                                        );
                                    }
                                    tokio::time::sleep(RECOVERY_PROPAGATION_RETRY_INTERVAL).await;
                                    continue;
                                }
                                Ok(report) => {
                                    tracing::error!(
                                        scan_status = ?report.scan_status,
                                        accepted = report.coin_proof_accepted,
                                        sdr_discards = report.sdr_discards.len(),
                                        sdr_coins_folded = report.sdr_coins_folded,
                                        replayed_heads = report.replayed_heads.len(),
                                        "§4.5 recovery campaign: restored=false — do not \
                                         treat this node as fully recovered"
                                    );
                                    for discard in &report.sdr_discards {
                                        tracing::warn!(
                                            subject = %hex::encode(discard.subject),
                                            blob_id = %hex::encode(discard.blob_id),
                                            record_kind = ?discard.record_kind,
                                            send_counter = ?discard.send_counter,
                                            reason = %discard.reason,
                                            "§4.5 recovery SDR discard (replay could not accept candidate)"
                                        );
                                    }
                                    break;
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "§4.5 recovery campaign failed — node is NOT restored"
                                    );
                                    break;
                                }
                            }
                        }
                        tracing::info!(
                            watch_interval_secs = RECOVERY_CAMPAIGN_WATCH_INTERVAL.as_secs(),
                            "§4.5 recovery campaign pass finished — watching for newly-entrusted \
         subjects before the next pass"
                        );
                        tokio::time::sleep(RECOVERY_CAMPAIGN_WATCH_INTERVAL).await;
                    }
                });
            }
        }
    }

    // §4.4 receive path: poll gift-wraps, match detect_tag under each
    // entrusteed `ivk`, verify CoinProof, durable decrypt-index insert,
    // receipt publish, then ACK. Requires the exclusive v1.1 engine
    // (NfLog for step 4) and operational relay / max_blob. No credit /
    // receipt without verify+persist.
    if let Some(engine) = v1_engine.as_ref() {
        let engine = Arc::clone(engine);
        let bundles = Arc::clone(&shared_bundle_store);
        let private_index = Arc::clone(&shared_private_index);
        let receipt_hub = Arc::clone(&shared_receipt_hub);
        let pool = Arc::clone(&pool);
        let ops = crate::kernel::chain::chain_identity_ops_from_env().ok();
        let network_label = crate::v1::mode::network_label(engine.network()).to_string();
        tokio::spawn(async move {
            let Some(ops) = ops else {
                tracing::warn!(
                    "incoming delivery scanner not started: chain identity ops unavailable at boot"
                );
                return;
            };
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                    Ok(d) => d.as_secs(),
                    Err(_) => {
                        tracing::warn!(
                            "incoming scanner: wall clock before UNIX epoch — skipping tick"
                        );
                        continue;
                    }
                };
                // RNG is required for the *outbound* kind-1421 ACK gift-wrap
                // after durable persist (seal/wrap nonces + ephemeral key) —
                // not for unwrapping inbound 1420s. Stack-local: no mutex, so
                // no guard can span the relay/Blossom awaits inside the poll.
                let mut rng = crate::v1::OsSecureRandom;
                for (subject, bundle) in bundles.list_active() {
                    match crate::v1::poll_incoming_deliveries(crate::v1::incoming::IncomingPoll {
                        relays: std::slice::from_ref(&ops.relay_url),
                        secrets: crate::v1::incoming::CandidateSecrets {
                            subject: &subject.0,
                            ivk: &bundle.ivk,
                            op: &bundle.op,
                        },
                        stores: crate::v1::incoming::CandidateStores {
                            adapter: engine.as_ref(),
                            pool: pool.as_ref(),
                            index: private_index.as_ref(),
                            receipts: receipt_hub.as_ref(),
                        },
                        max_blob_bytes: ops.max_blob_bytes,
                        expected_network: &network_label,
                        now,
                        rng: &mut rng,
                        since: None,
                    })
                    .await
                    {
                        Ok(outcomes) => {
                            for o in outcomes {
                                match o {
                                    crate::v1::incoming::CandidateOutcome::Accepted {
                                        coin_id,
                                        blob_id,
                                        record_id,
                                        replay,
                                        holder_attempts,
                                    } => {
                                        tracing::info!(
                                            coin_id = %hex::encode(coin_id),
                                            blob_id = %hex::encode(blob_id),
                                            record_id = %hex::encode(record_id),
                                            replay,
                                            holders = holder_attempts.len(),
                                            "incoming CoinProof verified, durable, ACK sent"
                                        );
                                        for a in holder_attempts {
                                            if matches!(
                                                a.outcome,
                                                crate::v1::incoming::HolderOutcome::ContentAddressLie { .. }
                                            ) {
                                                tracing::warn!(
                                                    holder = %a.holder,
                                                    outcome = %a.outcome,
                                                    "Blossom holder lied about content address"
                                                );
                                            }
                                        }
                                    }
                                    crate::v1::incoming::CandidateOutcome::Rejected { error } => {
                                        tracing::debug!(
                                            error = %error,
                                            "incoming candidate rejected (no credit, no ACK)"
                                        );
                                    }
                                    crate::v1::incoming::CandidateOutcome::Ignored { .. } => {}
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "incoming delivery poll failed");
                        }
                    }
                }
            }
        });
    }

    // Neutral, permissionless model (Milestone 2): there is NO central
    // minting authority. The node holds no minting key and bootstraps
    // no privileged minting account — anyone creates their own asset
    // and mints their own supply via the creator-signed two-phase mint
    // flow. The legacy `minting_secret.bin` + `MINTING_ADDRESS`
    // bootstrap is therefore gone.

    let shared_username_store = Arc::new(Mutex::new(username_store));

    // Background-warmup readiness flag. Default `false`; flipped to
    // `true` by either the background `spawn_blocking` task below (once
    // `AccountNode::warmup_prover` returns Ok) or immediately if the
    // operator set `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`. Consumed by
    // `/health/ready`; see the field doc on `AppState::prover_warm`.
    let prover_warm = Arc::new(AtomicBool::new(false));

    // Job-API state-layer. The dispatcher is spawned below once
    // the AppState is fully populated; the mpsc channel is owned
    // by `start_rest_node` so the sender clone can be threaded
    // into the AppState before the dispatcher takes ownership of
    // the receiver half.
    let job_store = Arc::new(JobStore::new((*pool).clone()));
    let job_notify_map = Arc::new(DashMap::new());
    let (job_tx, job_rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(32);

    let state = AppState {
        account_node: Arc::clone(&shared_account_node),
        proof_store,
        mint_store: Arc::new(crate::router::MintStore::new()),
        username_store: shared_username_store,
        pool: Arc::clone(&pool),
        // The readiness probe uses this to ping Esplora; in production
        // it points at the same `ESPLORA_URL` as the scanner / publisher.
        esplora_config: Arc::new(NETWORK_CONFIG.clone()),
        prover_warm: Arc::clone(&prover_warm),
        prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
        job_store: Arc::clone(&job_store),
        job_tx: job_tx.clone(),
        job_notify_map: Arc::clone(&job_notify_map),
        v1_scan_caught_up: v1_readiness.scan_caught_up,
        v1_finality_ok: v1_readiness.finality_ok,
        pending_sign_map: Arc::new(DashMap::new()),
        // Production finalise: prove outside the engine lock, then apply
        // with live re-validation (receive-path invariant), stage
        // members_ready, then durable-publish that row — same order as the
        // direct receive path. Under the v1.1 claim a missing driver fails
        // the job loud rather than short-circuiting to "signature_accepted"
        // alone. The publisher handle is connected once at boot so the hook
        // can reach durable_publish without breaking the AppState layering
        // (AppState / V1FinaliseHook still carry no publisher type).
        //
        // §4.2 mesh delivery hangs **after** durable persist (and after the
        // nullifier hand-off) via the same port pattern as the publisher.
        v1_finalise: v1_engine.as_ref().map(|adapter| {
            let adapter = Arc::clone(adapter);
            let network = adapter.network();
            // Fail-loud connect once. An incomplete env / bitcoind outage
            // yields Err on every finalise (after members_ready stage when
            // prove already ran on a prior attempt that left a row — the
            // resume path still stages first). No silent skip of publish.
            //
            // Classification uses a typed [`crate::v1::signature::PublishRejected`]
            // cause so the dispatcher stores `publish_rejected` via downcast —
            // same outward code as a mid-finalise handoff failure. Display
            // text is **diagnostic only**, not a machine-code contract (no
            // `publish_rejected:` prefix dependency).
            //
            // Why `PublishRejected` and not a separate config code: a missing
            // publisher at boot makes the durable nullifier handoff impossible
            // for every finalise; the §7.5 surface the wallet already treats
            // as retryable publish failure is `publish_rejected`. Inventing
            // `internal_error` would change the outward code for the same
            // operational fact (handoff cannot run).
            let publisher_slot: Arc<
                Result<crate::v1::V1Publisher, crate::v1::signature::PublishRejected>,
            > = Arc::new(
                crate::v1::v1_publisher_env_from_env(network)
                    .and_then(crate::v1::connect_v1_publisher)
                    .map_err(
                        |e| crate::v1::signature::PublishRejected::DurableHandoffFailed {
                            detail: format!(
                                "v1.1 finalise publisher unavailable at REST boot \
                                 (nullifier handoff cannot run): {e:#}"
                            ),
                        },
                    ),
            );
            // Shared process-local stores: entrust writes BundleStore; delivery
            // reads it. Target store is filled by profile/Invoice resolution.
            let bundle_store = Arc::clone(&shared_bundle_store);
            let delivery_targets = Arc::clone(&shared_delivery_targets);
            let delivery_port: Arc<dyn crate::v1::OutgoingDeliveryPort> =
                Arc::clone(&shared_delivery_port);
            let delivery_rng = Arc::clone(&shared_delivery_rng);
            let private_index = Arc::clone(&shared_private_index);
            // Self-delivery relays = bootstrap seed relays (non-empty after
            // verified BMF1). Empty → Phase A refuses (no invent).
            let self_relays: Vec<String> = manifest_store
                .get()
                .map(|v| v.seed_relays().to_vec())
                .unwrap_or_default();
            // Blossom holders + max size from the same ops env as GetInfo —
            // no default URL, no default size.
            let ops_for_delivery = crate::kernel::chain::chain_identity_ops_from_env().ok();
            let hook: crate::router::V1FinaliseHook = Arc::new(move |pending, signature, fence| {
                let adapter = Arc::clone(&adapter);
                let publisher_slot = Arc::clone(&publisher_slot);
                let bundle_store = Arc::clone(&bundle_store);
                let delivery_targets = Arc::clone(&delivery_targets);
                let delivery_port = Arc::clone(&delivery_port);
                let delivery_rng = Arc::clone(&delivery_rng);
                let private_index = Arc::clone(&private_index);
                let self_relays = self_relays.clone();
                let ops_for_delivery = ops_for_delivery.clone();
                // publisher_pubkey is filled by the dispatcher from the job
                // request_body after the hook returns.
                // Durable + fenced: prove → apply → engine snapshot +
                // members_ready → durable publish handoff → mesh delivery,
                // only while this claim epoch still holds for the persist step.
                Box::pin(async move {
                    let publisher = match publisher_slot.as_ref() {
                        Ok(p) => p,
                        // Preserve the typed cause for dispatcher downcast.
                        Err(cause) => return Err(anyhow::Error::new(cause.clone())),
                    };
                    let now =
                        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                            Ok(d) => d.as_secs(),
                            Err(_) => {
                                return Err(anyhow::anyhow!(
                                    "v1.1 finalise: wall clock before UNIX epoch — \
                                 refusing delivery timestamps (no silent 0)"
                                ));
                            }
                        };
                    // Always install the delivery port. Missing ops env yields
                    // empty holders → external-coin delivery fails with
                    // `BlobHoldersEmpty` (named), never a silent success.
                    // Ops is required at boot via
                    // `require_chain_identity_ops_from_env`; this is belt-and-
                    // braces for the hook closure.
                    let (blob_holders, max_blob_bytes) = match ops_for_delivery.as_ref() {
                        Some(ops) => (vec![ops.blossom_url.clone()], ops.max_blob_bytes),
                        None => (Vec::new(), 0),
                    };
                    // Network label for post-send profile refresh — same pin
                    // the engine was built with (no silent mainnet default).
                    let expected_network = crate::v1::mode::network_label(network);
                    let delivery_deps = Some(crate::v1::signature::FinaliseDeliveryDeps {
                        port: delivery_port.as_ref(),
                        bundles: bundle_store.as_ref(),
                        targets: delivery_targets.as_ref(),
                        blob_holders,
                        max_blob_bytes,
                        now,
                        expected_network,
                        self_relays,
                        rng: delivery_rng.as_ref(),
                    });
                    crate::v1::finalise_accepted_prove_persist_and_stage(
                        &adapter,
                        pending,
                        signature,
                        None,
                        fence,
                        publisher,
                        private_index.as_ref(),
                        delivery_deps,
                    )
                    .await
                })
            });
            hook
        }),
        // Production post-begin registry: `StateEngine::begin_*` writes a
        // live PendingSignEntry here; the dispatcher takes it when the job
        // enters awaiting_signature and stages via stage_pending_sign.
        // Under the legacy stack the map stays empty and is unused.
        v1_live_pending_after_begin: Arc::new(DashMap::new()),
        // Test-only injection point (Defect 4): never installed in production.
        #[cfg(test)]
        v1_pending_after_prove: None,
        #[cfg(test)]
        receive_creating_proof_loader: None,
        v1_engine: v1_engine.clone(),
        private_index: Arc::clone(&shared_private_index),
        bundles: Arc::clone(&shared_bundle_store),
        attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
        public_hosts: Arc::new(crate::v1::public_hosts_from_env()),
    };

    // No minting-account bootstrap: the neutral model has no
    // privileged minting account. Accounts come into existence lazily
    // — an issuer's first mint creates their `(owner, asset_id)`
    // account; a recipient's first receive creates theirs.

    // Phase D removed the startup `check_minting_state_invariant`:
    // `num_pubkeys` is now derived from SMT membership at runtime
    // (`state::derive_num_pubkeys_from_smt`), so the predicate the
    // check measured ("every pubkey_idx ∈ 0..num_pubkeys has a
    // commitment in the SMT") is a tautology by construction. The
    // pre-Phase-D check existed only because the counter and the SMT
    // could disagree — collapsing them into one removes the disagree
    // mode and the check that measured it.

    // Phase B: re-broadcast any pending inscriptions left over from
    // a previous boot. A crash between commit-broadcast and
    // reveal-broadcast (or between construction and either broadcast)
    // leaves a row in `pending_inscriptions` with status != complete;
    // walk each one to completion before opening the listener so
    // operators do not see a stuck UTXO until the next mint triggers
    // the resumer.
    //
    // Under the v1.1 stack claim this path is **skipped**: resuming
    // would broadcast stored bincode Commitments into a database claimed
    // for AggregateStateNullifierV3. The function itself also refuses
    // (defense in depth); we skip here so boot logs stay clean.
    //
    // Failures here are LOGGED and SWALLOWED — the operator's escape
    // hatch is the PR #106 CLI recovery tool, and a transient
    // Esplora outage on boot must not crash-loop the container.
    if matches!(process_stack_mode(), Some(ScanStackMode::V1)) {
        println!(
            "resume_pending_inscriptions: skipped (process claimed v1.1 scan stack; \
             legacy Commitment recovery is forbidden)"
        );
    } else if let Err(e) = resume_pending_inscriptions(&pool, &NETWORK_CONFIG).await {
        eprintln!(
            "Failed to resume pending inscriptions on bootstrap (continuing anyway): {}",
            e
        );
    }

    // Job-API boot-time resumer. The dispatcher walks each job
    // through the state machine; if the process restarts mid-way
    // through a `proving` / `broadcasting` row, the in-process
    // Plonky2 prover state is lost and the signed wallet payload's
    // timestamp window has expired by the time anyone notices. The
    // safest action is to mark every interrupted row `failed`
    // before serving so the wallet observes a terminal status on
    // its next poll and can re-submit (with a fresh timestamp +
    // fresh idempotency key). Jobs already at `awaiting_signature`
    // are different — the wallet may still come back with a valid
    // signature, so we re-arm the per-job `Notify` channel and
    // hand the public_id back to the dispatcher to park on. See
    // the `list_interrupted_for_resume` doc-comment for the
    // partitioning rationale.
    if let Err(e) = boot_resume_jobs(&job_store, &job_notify_map, &job_tx).await {
        eprintln!("Job-API boot-time resume failed (continuing anyway): {}", e);
    }

    // Spawn the dispatcher. Owns the `mpsc::Receiver` half of the
    // channel created above; the matching senders are held by
    // every cloned `AppState`. Closes cleanly when the last sender
    // is dropped (process shutdown).
    job_dispatcher::spawn(
        Arc::clone(&job_store),
        state.clone(),
        Arc::clone(&job_notify_map),
        DEFAULT_AWAITING_SIGNATURE_TIMEOUT,
        job_rx,
    );

    // Additive kernel.v1 gRPC edge (§7.8). Shares job store + notify map
    // with REST/dispatcher so StreamJob is live, not snapshot-only.
    // Fail-closed: domain façade is constructed with real state only.
    // Block 6: when the exclusive v1.1 engine is present, install it on
    // the façade so GetAccumulator / GetNullifierPath / GetInfo read the
    // live NfLog — never a second derivation. ListInscriptions stays
    // Unimplemented until a scanner-written catalog exists (NfLog has no
    // reveal txid / §3.5 format).
    {
        // Batch interval for §7.6 AcceptFeeLess — required when kernel_parts
        // includes publisher. No silent default (the former hard-coded 60 s
        // at the gRPC edge is gone).
        let publish_batch_eta_secs = match std::env::var("ZKCOINS_PUBLISH_BATCH_ETA_SECS") {
            Ok(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(anyhow::anyhow!(
                        "ZKCOINS_PUBLISH_BATCH_ETA_SECS is set but empty — \
                         refuse to invent a batch interval"
                    ));
                }
                let secs: u64 = trimmed.parse().map_err(|_| {
                    anyhow::anyhow!(
                        "ZKCOINS_PUBLISH_BATCH_ETA_SECS={raw:?} is not a non-negative integer"
                    )
                })?;
                Some(secs)
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "ZKCOINS_PUBLISH_BATCH_ETA_SECS env read failed: {e}"
                ));
            }
        };
        let mut domain = crate::kernel_rpc::domain_from_parts(
            Arc::clone(&job_store),
            Arc::clone(&job_notify_map),
            Arc::clone(&state.pending_sign_map),
            Arc::clone(&state.attest_challenges),
        )
        .with_manifest_store(Arc::clone(&manifest_store))
        .with_bundle_store(Arc::clone(&shared_bundle_store))
        .with_private_index(Arc::clone(&shared_private_index))
        .with_receipt_hub(Arc::clone(&shared_receipt_hub))
        .with_delivery_targets(Arc::clone(&shared_delivery_targets))
        .with_publish_batch_eta_secs(publish_batch_eta_secs);
        // Pull/Records/SubscribeReceipts share the process mirror of
        // `v1_decrypt_index` (migration 0031) and the receipt hub. The
        // §4.4 scanner writes SQL first, then the process index, then
        // publishes a credit receipt, then ACK.
        tracing::info!(
            private_index_refs = Arc::strong_count(domain.private_record_index()),
            receipt_hub_refs = Arc::strong_count(domain.receipt_hub()),
            bootstrap_manifest_refs = Arc::strong_count(domain.manifest_store()),
            bootstrap_manifest_loaded = domain.manifest_store().is_loaded(),
            delivery_target_refs = Arc::strong_count(domain.delivery_targets()),
            delivery_retention_len = shared_delivery_retention.len(),
            "kernel access surfaces installed (Pull/Records/SubscribeReceipts; \
             durable decrypt-index + process mirror + receipt hub)"
        );
        if let Some(engine) = v1_engine.as_ref() {
            use crate::kernel::chain::{chain_identity_ops_from_env, resolve_chain_identity};
            use crate::kernel::types::{Digest32, XOnlyKey};
            use crate::kernel::{ChainHandle, ChainReadinessFlags, KernelNetwork};

            // Operational infra (relay / blossom / max_blob / parts): required
            // at boot — missing var aborts before the listener binds.
            let ops = chain_identity_ops_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

            // Digests, activation_height, bootstrap_pubkey, network: §3.6 pins
            // already validated against the just-built circuits at the binary
            // edge. Re-read here so GetInfo reports the same digests the
            // digest-gate knows — never a second free-form env pair.
            let pins = crate::v1::mode::v1_boot_pins_from_env()
                .map_err(|e| anyhow::anyhow!("v1 boot pins for ChainIdentity: {e}"))?;
            let network = KernelNetwork::from_v1(engine.network());
            let pins_network = KernelNetwork::from_v1(pins.network);
            if pins_network != network {
                anyhow::bail!(
                    "ChainIdentity network pin {} disagrees with engine network {} — \
                     refusing to install identity",
                    pins_network.as_str(),
                    network.as_str()
                );
            }
            if pins.activation_height != engine.activation_height() {
                anyhow::bail!(
                    "ChainIdentity activation_height {} disagrees with engine {} — \
                     refusing to install identity",
                    pins.activation_height,
                    engine.activation_height()
                );
            }

            let digest_c = Digest32(pins.network_params.circuit_digest_c());
            let digest_b = Digest32(pins.network_params.circuit_digest_c_balance());
            let bootstrap_pubkey = XOnlyKey(pins.network_params.bootstrap_pubkey());

            // BootstrapManifest (§4.3): the BMF1 loader may have installed a
            // verified copy on `manifest_store` at the start of this function.
            // Project it into the domain echo type and require a complete
            // ChainIdentity — a node without identity must not serve (GetInfo
            // / readiness would otherwise stay permanently unanswerable).
            let bootstrap = match manifest_store.get() {
                Some(verified) => {
                    use crate::kernel::chain::{
                        bootstrap_manifest_from_verified, VerifiedManifestFields,
                    };
                    bootstrap_manifest_from_verified(VerifiedManifestFields {
                        network_label: verified.network(),
                        protocol_version: verified.protocol_version(),
                        seed_relays: verified.seed_relays(),
                        blob_stores: verified.blob_stores(),
                        operator_ids: verified.operator_ids(),
                        issued_at: verified.issued_at(),
                        expires_at: verified.expires_at(),
                        manifest_sig: verified.manifest_sig(),
                    })
                    .map_err(|e| anyhow::anyhow!("verified BootstrapManifest projection: {e}"))?
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "ChainIdentity requires a verified §4.3 BootstrapManifest — set \
                         {} to a BMF1 artifact that verifies under the pinned \
                         bootstrap_pubkey (no silent empty identity)",
                        crate::kernel::bootstrap::BOOTSTRAP_MANIFEST_PATH_ENV
                    ));
                }
            };
            let identity = resolve_chain_identity(
                network,
                digest_c,
                digest_b,
                pins.activation_height,
                bootstrap_pubkey,
                ops,
                Some(bootstrap),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            tracing::info!(
                network = %identity.network.as_str(),
                relay = %identity.relay_url,
                blossom = %identity.blossom_url,
                max_blob_bytes = identity.max_blob_bytes,
                activation_height = identity.activation_height,
                seed_relays = identity.bootstrap.seed_relays.len(),
                digest_c = %hex::encode(identity.circuit_digest_c.0),
                digest_c_balance = %hex::encode(identity.circuit_digest_c_balance.0),
                "ChainIdentity installed for GetInfo"
            );

            domain = domain.with_chain(ChainHandle {
                engine: Some(Arc::clone(engine)),
                identity: Some(identity),
                readiness: ChainReadinessFlags {
                    scan_caught_up: state.v1_scan_caught_up.clone(),
                    finality_ok: state.v1_finality_ok.clone(),
                },
                network: Some(network),
            });
        }

        // Boot-hydrate the process §7.6 hand-off queue from durable
        // `v1_pending_publishes` so a restart re-enters the multi-member
        // drain (same recovery table the self-publish resume path walks).
        // Fail-closed list: undeterminable is logged loud and leaves the
        // process queue empty (boot resume in main still owns mid-flight
        // constructed/commit_broadcast rows with prepared txs).
        if let Some(engine) = domain.chain_engine() {
            match crate::v1::db_v1::list_resumable_pending_publishes(engine.pool()).await {
                Ok(rows) => {
                    let seed: Vec<(crate::kernel::publish::HandOffMember, String)> = rows
                        .into_iter()
                        .map(|r| {
                            (
                                crate::kernel::publish::HandOffMember {
                                    public_key: crate::kernel::types::XOnlyKey(r.pk),
                                    r: crate::kernel::types::XOnlyKey(r.r),
                                    s: crate::kernel::types::Digest32(r.s),
                                    r_prime: crate::kernel::types::XOnlyKey(r.r_prime),
                                    block_anchor: crate::kernel::publish::PublishBlockAnchor {
                                        block_hash: crate::kernel::types::Digest32(
                                            r.build_tip_hash,
                                        ),
                                        height: r.build_tip_height,
                                    },
                                },
                                r.status,
                            )
                        })
                        .collect();
                    let refs: Vec<(crate::kernel::publish::HandOffMember, &str)> =
                        seed.iter().map(|(m, s)| (*m, s.as_str())).collect();
                    match domain.seed_handoff_queue_from_pending_rows(&refs) {
                        Ok(0) => tracing::info!(
                            "§7.6 hand-off queue: no resumable pending publishes to seed"
                        ),
                        Ok(n) => tracing::info!(
                            seeded = n,
                            "§7.6 hand-off queue seeded from v1_pending_publishes \
                             (list_resumable → from_pending_status)"
                        ),
                        Err(e) => {
                            // Loud but non-fatal: main's boot_resume still
                            // walks PG; the process queue can re-fill on
                            // new accepts. Never invent an empty success.
                            eprintln!(
                                "§7.6 hand-off queue seed from pending publishes failed: {e} \
                                 — continuing; drain will only see new accepts until re-seed"
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "§7.6 hand-off queue: list_resumable_pending_publishes failed \
                         ({e:#}) — not treating as empty; drain starts without hydrate"
                    );
                }
            }
        }

        // Boot-hydrate the process-local `GetAccountState` read cache from the
        // durably-reloaded engine. `shared_private_index` starts empty on every boot; without
        // this, an account that does not transition again after a restart stays invisible to
        // GetAccountState even though the engine already holds its state. Fail-closed: any
        // serialize/hash error aborts boot rather than silently skipping that account (same
        // view-builder the post-finalise mirror uses, so a restarted process and a live
        // finalise agree on the same fields).
        if let Some(engine) = v1_engine.as_ref() {
            let hydrated: Result<
                Vec<(
                    crate::kernel::types::SubjectAddress,
                    crate::kernel::access::AccountStateView,
                )>,
                anyhow::Error,
            > = engine.with_engine(|state_engine| {
                state_engine
                    .accounts()
                    .map(|(owner, rec)| {
                        crate::v1::signature::account_state_view_from_record(rec)
                            .map(|view| (crate::kernel::types::SubjectAddress(owner.0), view))
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "account_state_view_from_record for {}: {e}",
                                    hex::encode(owner.0)
                                )
                            })
                    })
                    .collect()
            });
            match hydrated {
                Ok(views) => {
                    let n = views.len();
                    for (subject, view) in views {
                        shared_private_index
                            .insert_account(subject, view)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "boot-hydrate account-state cache: insert failed: {e}"
                                )
                            })?;
                    }
                    tracing::info!(
                        accounts = n,
                        "GetAccountState read cache hydrated from engine at boot"
                    );
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "boot-hydrate account-state cache from engine failed: {e:#}"
                    ));
                }
            }
        }

        // Multi-member half-agg drain loop (same process as gRPC accept).
        // Transient bitcoind/publisher outages skip the cycle and retry —
        // never pass publisher=None into drain (that would terminal-fail
        // every open member). Inscription errors that occur *with* a
        // connected publisher mark members Failed with a named reason.
        let domain_for_drain = domain.clone();
        tokio::spawn(async move {
            run_handoff_drain_loop(domain_for_drain).await;
        });

        let job_tx_grpc = job_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::kernel_rpc::serve_kernel_grpc_with_domain(
                kernel_grpc_addr,
                domain,
                job_tx_grpc,
            )
            .await
            {
                eprintln!("Kernel gRPC error: {}", e);
                std::process::exit(1);
            }
        });
    }

    let app = create_router(state);

    // boot_log: announce the startup event with the connected network,
    // node version, listen address, and process pid. Best-effort —
    // a failed boot_log insert must NOT prevent the node from
    // starting (the operator would lose access to a real recovery
    // path on a transient DB blip).
    {
        let boot_entry = crate::db::BootLogEntry {
            event_type: "startup".to_string(),
            message: format!(
                "zkcoins-node {} starting on {} (network={})",
                env!("CARGO_PKG_VERSION"),
                socket_addr,
                NETWORK_CONFIG.network_name,
            ),
            metadata: Some(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "network": NETWORK_CONFIG.network_name,
                "socket_addr": socket_addr.to_string(),
                "pid": std::process::id(),
                "is_mainnet": NETWORK_CONFIG.is_mainnet,
            })),
        };
        if let Err(e) = crate::db::insert_boot_log(&pool, &boot_entry).await {
            eprintln!("Failed to persist boot_log startup event: {}", e);
        }
    }

    println!("REST API started at {}", socket_addr);
    let listener = TcpListener::bind(socket_addr).await?;
    tracing::info!("Listener bound on {socket_addr}; API is reachable");

    // Background-warmup. A fresh `Prover` carries a cold Rayon worker
    // pool and uninitialised AOT-compiled Plonky2 evaluator caches;
    // empirically (DEV-host R2 probe, 2026-05-31) the first
    // `prove_initial` after `Prover::new()` takes ~7012 ms vs the
    // steady-state p50 of ~4777 ms for every subsequent call.
    //
    // The previous shape (PR #147, closed) paid that tax synchronously
    // before binding the listener and pushed API offline time per
    // deploy from ~14 s to ~21 s. This shape instead binds the
    // listener FIRST (the API is reachable at ~0.1 s), then spawns
    // `AccountNode::warmup_prover` in a `spawn_blocking` task so the
    // tokio worker that runs `axum::serve` is not starved by the
    // CPU-bound Plonky2 prove. While the task is running a user
    // request still serves correctly — it just pays the ~7 s cold tax
    // — and `/health/ready` returns 503 with `prover: warming` so an
    // LB / Kuma can hold traffic on the previous-gen pod during a
    // rolling deploy.
    //
    // Opt-out via `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`: the smoke tests
    // in `runtime_tests.rs` set this so each `start_rest_node_*` test
    // does not pay the ~7 s prove tax twice over. When set,
    // `prover_warm` is flipped to `true` immediately so the readiness
    // probe matches the production-ready shape.
    let skip_warmup = std::env::var("ZKCOINS_SKIP_BOOTSTRAP_WARMUP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let warmup_handle = if skip_warmup {
        tracing::info!(
            "Bootstrap warmup skipped via ZKCOINS_SKIP_BOOTSTRAP_WARMUP; \
             prover_warm = true (first user request will pay the ~7 s cold tax)"
        );
        prover_warm.store(true, Ordering::SeqCst);
        None
    } else {
        let account_node_for_warmup = Arc::clone(&shared_account_node);
        let prover_warm_flag = Arc::clone(&prover_warm);
        let handle = tokio::task::spawn_blocking(move || {
            let warmup_t = std::time::Instant::now();
            // Hold the sync `Mutex` only for the duration of the
            // prove call. The scanner — spawned in parallel by
            // `main.rs` — locks `state`, not `account_node`, so it
            // does not contend with this guard. The only realistic
            // contender is a user request that lands during the
            // ~7 s warmup window; that request blocks on
            // `account_node.lock()` for the remainder of the warmup
            // (then runs warm), which is the accepted trade-off
            // documented in the function comment. The block is
            // shorter (and aborts cleanly on shutdown) than the
            // previous synchronous-bootstrap shape.
            let result = {
                let guard = account_node_for_warmup
                    .lock()
                    .expect("AccountNode mutex poisoned before bootstrap warmup");
                guard.warmup_prover()
            };
            match result {
                Ok(()) => {
                    tracing::info!(
                        elapsed_ms = warmup_t.elapsed().as_millis() as u64,
                        "Background warmup complete; prover ready"
                    );
                    prover_warm_flag.store(true, Ordering::SeqCst);
                }
                Err(e) => {
                    // Same severity as the previous synchronous
                    // `expect()` — the same Prover serves every
                    // subsequent user request, so a warmup failure
                    // means production requests would also fail.
                    // Crash-loop the container rather than running
                    // a node that serves 5xx for the prove path.
                    tracing::error!(error = %e, "Background warmup failed — exiting");
                    std::process::exit(1);
                }
            }
        });
        tracing::info!("Bootstrap warmup spawned in background; listener serving now");
        Some(handle)
    };
    // `warmup_handle` is intentionally not awaited: `axum::serve`
    // owns the foreground future and the warmup runs to completion
    // on its own. On graceful shutdown `axum::serve` returns first;
    // the warmup task either completes naturally or is dropped when
    // the tokio runtime shuts down. The binding keeps the JoinHandle
    // alive (vs. `let _ =`) so a future shutdown signal can call
    // `.abort()` once a signal handler is wired in.
    let _warmup_handle = warmup_handle;

    #[cfg(all(feature = "coverage-flush", coverage_nightly))]
    spawn_coverage_flush_signal_handler();

    // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
    // peer's TCP socket to extractors — the audit middleware reads it
    // through `ConnectInfo<SocketAddr>` and writes it to
    // `request_log.remote_addr`. Without this the audit row's
    // `remote_addr` column is always NULL (the default `into_make_service`
    // never inserts a `ConnectInfo` extension).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Backoff between §4.5 recovery campaign re-scans when a complete gapless
/// scan installed no head yet (relay-propagation race against the origin
/// delivery outbox's ~30–90s publish cycle).
///
/// Ceiling with [`RECOVERY_CAMPAIGN_MAX_ATTEMPTS`]: 12 × 10s ≈ 120s stays
/// under the recovery journey's test window while covering a worst-case
/// outbox lag plus a few extra scans.
const RECOVERY_PROPAGATION_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Hard upper bound on §4.5 recovery campaign attempts (including the first).
///
/// Statically bounded `for attempt in 0..RECOVERY_CAMPAIGN_MAX_ATTEMPTS` —
/// never an unbounded loop. After exhaustion the existing restored=false
/// fail-closed path fires unchanged.
const RECOVERY_CAMPAIGN_MAX_ATTEMPTS: usize = 12;

/// Idle interval for the OUTER, persistent §4.5 recovery watch loop.
///
/// After the bounded inner retry loop finishes (restored, gave up, or hard
/// error), the driver sleeps this long before re-running the campaign — so a
/// LATER `EntrustOperationalBundle` (a second account served by this node, or
/// portability re-pointing a wallet after an earlier entrust already
/// succeeded) is picked up without a node restart. The task is `tokio::spawn`ed
/// once at startup and is meant to run for the node's lifetime.
const RECOVERY_CAMPAIGN_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// Whether a §4.5 recovery campaign report warrants another bounded re-scan.
///
/// Pure relay-propagation race only: complete gapless scan, nothing installed,
/// and attempts remain. Partial installs and incomplete scans never retry.
pub(crate) fn should_retry_recovery(
    report: &crate::v1::recovery::RecoveryRunReport,
    attempt: usize,
    max_attempts: usize,
) -> bool {
    !report.restored
        && report.replayed_heads.is_empty()
        && matches!(
            report.scan_status,
            crate::v1::recovery::GaplessScanStatus::Complete
        )
        && attempt + 1 < max_attempts
}

/// Idle backoff between §7.6 multi-member drain sweeps.
///
/// Same order of magnitude as the pending-publish resumer in `main` so a
/// stranded `members_ready` row is retried without a tight spin that would
/// flood logs on a permanent publisher / bitcoind outage.
const HANDOFF_DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Periodic multi-member half-agg drain for accepted §7.6 hand-offs.
///
/// ## bitcoind / publisher boundary
///
/// - **Env incomplete or connect failure** with open queue rows: log a named
///   reason and retry next interval. Do **not** call drain with
///   `publisher=None` — that would mark every open member terminal-failed
///   for a transient outage.
/// - **Connected publisher, inscription fails**: `drain_and_inscribe` marks
///   each attempted member `Failed` with the terminal reason (never left as
///   an implicit success / never re-projected as `accepted`).
/// - **Empty queue**: no-op sleep cycle.
async fn run_handoff_drain_loop(domain: crate::kernel::KernelService) {
    use crate::kernel::publish::HandOffQueue;
    use crate::v1::{connect_v1_publisher, v1_publisher_env_from_env};

    loop {
        // scanner-polling-ok: hand-off drain idle backoff (named const)
        tokio::time::sleep(HANDOFF_DRAIN_INTERVAL).await;

        let open = match domain.handoff_queue().list_resumable() {
            Ok(rows) => rows.len(),
            Err(e) => {
                eprintln!(
                    "§7.6 hand-off drain: list_resumable failed ({e}) — \
                     not treating as empty; will retry next interval"
                );
                continue;
            }
        };
        if open == 0 {
            continue;
        }

        let Some(network) = domain.publish_network() else {
            eprintln!(
                "§7.6 hand-off drain: {open} open row(s) but no network pin on \
                 KernelService — cannot half-aggregate; will retry next interval"
            );
            continue;
        };
        let v1_network = match network {
            crate::kernel::KernelNetwork::Mainnet => {
                zkcoins_program::circuit::compliance::Network::Mainnet
            }
            crate::kernel::KernelNetwork::Testnet => {
                zkcoins_program::circuit::compliance::Network::Testnet
            }
            crate::kernel::KernelNetwork::Regtest => {
                zkcoins_program::circuit::compliance::Network::Regtest
            }
        };

        let env = match v1_publisher_env_from_env(v1_network) {
            Ok(env) => env,
            Err(e) => {
                // Named boundary: publisher env incomplete. Retry — do not
                // terminal-fail members for a config blip during boot race.
                eprintln!(
                    "§7.6 hand-off drain: {open} open row(s); publisher env \
                     incomplete ({e:#}) — bitcoind inscription path not ready; \
                     will retry next interval (members left at members_ready)"
                );
                continue;
            }
        };
        let publisher = match connect_v1_publisher(env) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "§7.6 hand-off drain: {open} open row(s); publisher connect \
                     failed ({e:#}) — bitcoind inscription path unavailable; \
                     will retry next interval (members left at members_ready)"
                );
                continue;
            }
        };

        // Blocking inscription work off the async runtime (RPC + sign).
        let domain_sync = domain.clone();
        let result = tokio::task::spawn_blocking(move || {
            domain_sync.drain_handoff_queue(Some(&publisher), None)
        })
        .await;

        match result {
            Ok(Ok(None)) => {
                // Listed open rows, then none drained: statuses may have
                // moved to CommitBroadcast (owned by per-row PG resume) or
                // another writer advanced them.
                tracing::debug!(
                    open,
                    "§7.6 hand-off drain: saw open rows; drain produced no batch"
                );
            }
            Ok(Ok(Some(published))) => {
                tracing::info!(
                    open,
                    members = published.aggregate.members.len(),
                    commit = %published.commit_txid,
                    reveal = %published.reveal_txid,
                    "§7.6 hand-off drain: inscribed multi-member batch"
                );
                // Mirror successful drain into PG so boot resume does not
                // re-publish members already at reveal_broadcast on-chain.
                if let Some(engine) = domain.chain_engine() {
                    for (pk, _) in &published.aggregate.members {
                        if let Err(e) = crate::v1::db_v1::mark_pending_publish_status(
                            engine.pool(),
                            *pk,
                            crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY,
                            crate::v1::db_v1::PENDING_PUBLISH_REVEAL_BROADCAST,
                        )
                        .await
                        {
                            // Loud: process queue is already RevealBroadcast;
                            // PG lag means resume might try again (idempotent
                            // rebroadcast on the self-publish path).
                            eprintln!(
                                "§7.6 hand-off drain: PG mirror to reveal_broadcast \
                                 failed for pk={}: {e:#}",
                                hex::encode(pk)
                            );
                        }
                    }
                }
            }
            Ok(Err(term)) => {
                // Members already marked Failed inside drain_and_inscribe.
                // Named terminal — never re-projected as accepted. PG rows
                // that remain `members_ready` are retried by the pending-
                // publish resumer or re-seeded on restart (process Failed
                // is not silently cleared).
                eprintln!(
                    "§7.6 hand-off drain: inscription terminal with {open} open \
                     row(s) attempted — {term}"
                );
            }
            Err(join_err) => {
                eprintln!(
                    "§7.6 hand-off drain: spawn_blocking join failed ({join_err}) \
                     — will retry next interval"
                );
            }
        }
    }
}

async fn rearm_and_enqueue_v1_finalise(
    public_id: uuid::Uuid,
    job_notify_map: &DashMap<uuid::Uuid, Arc<JobNotifier>>,
    job_tx: &tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
) {
    let notifier = Arc::new(JobNotifier::new());
    job_notify_map.insert(public_id, notifier);
    if let Err(e) = job_tx
        .send(crate::job_dispatcher::JobEnvelope { public_id })
        .await
    {
        eprintln!(
            "boot_resume_jobs: enqueue signed broadcasting {public_id} failed: {e} (continuing)"
        );
    } else {
        tracing::info!(
            "boot_resume_jobs: re-armed signed broadcasting job {public_id} for finalise resume"
        );
    }
}

/// Poll until the exclusive finalise claim is abandoned (or the job leaves
/// broadcasting), then release + enqueue. Prevents stranding after an
/// immediate restart while a dead owner's lease has not yet expired.
///
/// **Durable:** no fixed deadline. A slow-dying owner (lease still renewing
/// or wall-clock lag before abandonment) must not cause silent job loss.
/// This task keeps trying until the claim is free, the job is terminal /
/// non-broadcasting, or the process exits. A later boot re-lists interrupted
/// `broadcasting` rows and schedules reclaim again if needed.
fn spawn_deferred_finalise_reclaim(
    job_store: Arc<JobStore>,
    job_notify_map: Arc<DashMap<uuid::Uuid, Arc<JobNotifier>>>,
    job_tx: tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
    public_id: uuid::Uuid,
) {
    tokio::spawn(async move {
        // Poll frequently enough that a short test lease is reclaimed promptly.
        // No wall-clock deadline: abandoning after N minutes was silent loss.
        let poll = std::time::Duration::from_millis(200);
        loop {
            tokio::time::sleep(poll).await;

            let row = match job_store.load(public_id).await {
                Ok(Some(j)) => j,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(
                        %public_id,
                        error = %e,
                        "boot_resume_jobs: deferred reclaim load failed; retrying"
                    );
                    continue;
                }
            };
            if row.status.is_terminal() {
                return;
            }
            if row.status != JobStatus::Broadcasting {
                return;
            }

            let released = match job_store.release_stale_finalise_claim(public_id).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        %public_id,
                        error = %e,
                        "boot_resume_jobs: deferred release_stale failed; retrying"
                    );
                    continue;
                }
            };
            // When release succeeds the claim is free — enqueue without a
            // second load (a DB error on re-load must not strand a freed row).
            if released {
                tracing::info!(
                    %public_id,
                    "boot_resume_jobs: deferred reclaim — claim free, enqueueing"
                );
                rearm_and_enqueue_v1_finalise(public_id, &job_notify_map, &job_tx).await;
                return;
            }
            // Re-load phase after a no-op release (still need free-vs-owned).
            let phase = match job_store.load(public_id).await {
                Ok(Some(j)) => j.phase,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(
                        %public_id,
                        error = %e,
                        "boot_resume_jobs: deferred reclaim phase reload failed; retrying"
                    );
                    continue;
                }
            };
            match boot_finalise_action_after_release(false, JobStatus::Broadcasting, &phase) {
                BootFinaliseAction::EnqueueNow => {
                    tracing::info!(
                        %public_id,
                        "boot_resume_jobs: deferred reclaim — claim free, enqueueing"
                    );
                    rearm_and_enqueue_v1_finalise(public_id, &job_notify_map, &job_tx).await;
                    return;
                }
                BootFinaliseAction::DeferUntilAbandoned => {
                    // Still live — keep waiting for abandonment evidence.
                }
                BootFinaliseAction::Skip => return,
            }
        }
    });
}

/// Boot decision after a `release_stale_finalise_claim` attempt on a
/// resumable v1.1 broadcasting job.
///
/// | Prior phase | Release result | Action |
/// |-------------|----------------|--------|
/// | `finalise_claimed` | `Ok(true)` (abandoned) | [`BootFinaliseAction::EnqueueNow`] — claim freed |
/// | `finalise_claimed` | `Ok(false)` (lease still live) | [`BootFinaliseAction::DeferUntilAbandoned`] — still owned; do **not** enqueue as free |
/// | `publishing` / `broadcasting` | `Ok(false)` (nothing to release) | [`BootFinaliseAction::EnqueueNow`] — already free |
/// | any free/terminal after error recovery | — | [`BootFinaliseAction::Skip`] |
/// | any | `Err(_)` | caller must not enqueue (fail closed for that row) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootFinaliseAction {
    /// Claim is free — boot may re-arm notify and enqueue for finalise.
    EnqueueNow,
    /// Exclusive claim still held under a live lease. Do not enqueue; a
    /// deferred reclaim must wait for abandonment evidence.
    DeferUntilAbandoned,
    /// Job is no longer a broadcasting finalise candidate.
    Skip,
}

/// Decide boot action from the release outcome and the job row **after**
/// the release attempt. Pure decision table — no I/O.
pub(crate) fn boot_finalise_action_after_release(
    released: bool,
    status: JobStatus,
    phase: &str,
) -> BootFinaliseAction {
    if status != JobStatus::Broadcasting {
        return BootFinaliseAction::Skip;
    }
    if released {
        // Abandoned claim stripped; phase is `publishing`.
        return BootFinaliseAction::EnqueueNow;
    }
    // Ok(false): either still exclusively claimed, or already free.
    if phase == crate::job_store::FINALISE_CLAIM_PHASE {
        BootFinaliseAction::DeferUntilAbandoned
    } else if phase == "publishing" || phase == "broadcasting" {
        BootFinaliseAction::EnqueueNow
    } else {
        // Unknown phase under broadcasting — do not pretend it is free.
        BootFinaliseAction::Skip
    }
}

/// Boot disposition for one interrupted v1.1 edge row, including DB-error
/// paths. Pure — no I/O.
///
/// | `release` | `phase_reload` (only if `Ok(false)`) | Disposition |
/// |-----------|--------------------------------------|-------------|
/// | `Err` | — | [`BootRowDisposition::LeaveUntouchedForRetry`] — no mutation |
/// | `Ok(true)` | ignored | [`BootRowDisposition::Act`]`(EnqueueNow)` — claim freed; enqueue without second load |
/// | `Ok(false)` | `Err` | [`BootRowDisposition::LeaveUntouchedForRetry`] — row not mutated by release |
/// | `Ok(false)` | `Ok(None)` | [`BootRowDisposition::Act`]`(Skip)` — row vanished |
/// | `Ok(false)` | `Ok(Some(phase))` | [`BootRowDisposition::Act`]`(`[`boot_finalise_action_after_release`]`)` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootRowDisposition {
    /// Database error before or without a successful mutation — leave the
    /// row as-is for a later boot/retry. Never half-process.
    LeaveUntouchedForRetry,
    /// A defined action for this row.
    Act(BootFinaliseAction),
}

/// Pure error-path + success-path decision for one resumable v1.1 edge row.
pub(crate) fn boot_finalise_disposition(
    release: Result<bool, ()>,
    phase_reload: Result<Option<&str>, ()>,
) -> BootRowDisposition {
    match release {
        Err(()) => BootRowDisposition::LeaveUntouchedForRetry,
        Ok(true) => BootRowDisposition::Act(BootFinaliseAction::EnqueueNow),
        Ok(false) => match phase_reload {
            Err(()) => BootRowDisposition::LeaveUntouchedForRetry,
            Ok(None) => BootRowDisposition::Act(BootFinaliseAction::Skip),
            Ok(Some(phase)) => BootRowDisposition::Act(boot_finalise_action_after_release(
                false,
                JobStatus::Broadcasting,
                phase,
            )),
        },
    }
}

/// Job-API boot-time resumer. Walks every non-terminal row in the
/// `jobs` table and applies the partition described in
/// `JobStore::list_interrupted_for_resume` /
/// `list_non_terminal_for_resume`:
///
/// * `proving` / `broadcasting` — interrupted in flight; the
///   in-process prover / publisher state is gone. Mark `failed`
///   with a wallet-facing message so the next poll observes a
///   terminal status.
/// * `queued` — the signed payload's timestamp window has expired
///   (the wallet's timestamp gate is 5 minutes, the server may
///   have been down longer). Mark `failed` for the same reason.
/// * `awaiting_signature` — the wallet may still come back with
///   the signature. Re-arm a fresh `Notify` entry and hand the
///   public_id back to the dispatcher so it parks on the channel
///   the same way it did pre-restart.
pub(crate) async fn boot_resume_jobs(
    job_store: &Arc<JobStore>,
    job_notify_map: &Arc<DashMap<uuid::Uuid, Arc<JobNotifier>>>,
    job_tx: &tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
) -> anyhow::Result<()> {
    // Interrupted in-flight rows. Legacy / unsigned work cannot resume
    // (prove output lived only in process memory) → mark failed.
    // v1.1 jobs with a **signed durable FinalisationCapability** can
    // resume finalise after a mid-prove crash (status broadcasting):
    // re-arm and enqueue instead of failing.
    let interrupted = job_store.list_interrupted_for_resume().await?;
    for job in interrupted {
        let resumable_v1 = crate::v1::v1_sign_route_active()
            && job.status == JobStatus::Broadcasting
            && matches!(
                crate::v1::rehydrate_pending_sign(&job.request_body),
                Ok(Some(e)) if e.signature.is_some()
            );
        if resumable_v1 {
            // Honour release_stale: only enqueue when the claim is free.
            // Ignoring Ok(false) re-enqueued still-owned jobs; the loser
            // then exited and the edge job was stranded forever.
            //
            // On a database error the row must stay **entirely untouched**
            // and be retried (next boot) — never half-process (e.g. release
            // then abort before enqueue via `?` on a subsequent load).
            // Decision table: [`boot_finalise_disposition`].
            let release_result = match job_store.release_stale_finalise_claim(job.public_id).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    eprintln!(
                        "boot_resume_jobs: release_stale_finalise_claim({}) failed: {} \
                         (row left untouched for retry; fail closed)",
                        job.public_id, e
                    );
                    Err(())
                }
            };

            // Phase reload only when release was Ok(false). On Ok(true) the
            // disposition enqueues without a second load so a load error
            // cannot strand a just-freed claim.
            let phase_reload: Result<Option<String>, ()> = match release_result {
                Ok(false) => match job_store.load(job.public_id).await {
                    Ok(Some(j)) => Ok(Some(j.phase)),
                    Ok(None) => {
                        tracing::warn!(
                            "boot_resume_jobs: job {} vanished after release attempt",
                            job.public_id
                        );
                        Ok(None)
                    }
                    Err(e) => {
                        eprintln!(
                            "boot_resume_jobs: load({}) after release_stale failed: {} \
                             (row left untouched for retry; fail closed)",
                            job.public_id, e
                        );
                        Err(())
                    }
                },
                // Not consulted when release is Err or Ok(true).
                _ => Ok(None),
            };

            let disposition = boot_finalise_disposition(
                release_result,
                phase_reload.as_ref().map(|o| o.as_deref()).map_err(|_| ()),
            );
            match disposition {
                BootRowDisposition::LeaveUntouchedForRetry => {
                    // Already logged; continue to next interrupted row.
                }
                BootRowDisposition::Act(BootFinaliseAction::EnqueueNow) => {
                    rearm_and_enqueue_v1_finalise(job.public_id, job_notify_map, job_tx).await;
                }
                BootRowDisposition::Act(BootFinaliseAction::DeferUntilAbandoned) => {
                    let phase = phase_reload
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| crate::job_store::FINALISE_CLAIM_PHASE.to_string());
                    tracing::info!(
                        "boot_resume_jobs: job {} still under a live finalise claim \
                         (phase={}); not enqueueing as free — scheduling reclaim",
                        job.public_id,
                        phase
                    );
                    spawn_deferred_finalise_reclaim(
                        Arc::clone(job_store),
                        Arc::clone(job_notify_map),
                        job_tx.clone(),
                        job.public_id,
                    );
                }
                BootRowDisposition::Act(BootFinaliseAction::Skip) => {
                    tracing::info!(
                        "boot_resume_jobs: job {} not enqueued after release \
                         (disposition=Skip)",
                        job.public_id
                    );
                }
            }
            continue;
        }
        // Status-qualified fail against the status observed in this
        // snapshot — never bare `fail`. Between list and write another
        // process can advance the row to `awaiting_signature` and win a
        // finalise claim; bare fail would then terminate an owned epoch.
        // `fail_if_status` refuses any held claim (`phase IS DISTINCT FROM
        // FINALISE_CLAIM_PHASE`) and is a no-op when status has moved on.
        match job_store
            .fail_if_status(
                job.public_id,
                &[job.status],
                "server restarted before processing — please retry",
            )
            .await
        {
            Ok(true) => {
                tracing::info!(
                    "boot_resume_jobs: marked {} ({:?}) failed",
                    job.public_id,
                    job.status
                );
            }
            Ok(false) => {
                tracing::info!(
                    "boot_resume_jobs: skip fail for {} (snapshot status={:?}; \
                     row moved or claimed since list)",
                    job.public_id,
                    job.status
                );
            }
            Err(e) => {
                eprintln!(
                    "boot_resume_jobs: fail_if_status({}) failed: {} (continuing)",
                    job.public_id, e
                );
            }
        }
    }

    // Non-terminal rows still in admit-side states.
    let pending = job_store.list_non_terminal_for_resume().await?;
    for job in pending {
        match job.status {
            JobStatus::Queued => {
                // Same fence as interrupted: snapshot said `queued`, but a
                // concurrent worker may have proven, advertised, signed and
                // claimed before this write. Status-qualified only.
                match job_store
                    .fail_if_status(
                        job.public_id,
                        &[JobStatus::Queued],
                        "server restarted before processing — please retry",
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::info!(
                            "boot_resume_jobs: skip fail for queued {} \
                             (moved or claimed since list)",
                            job.public_id
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "boot_resume_jobs: fail_if_status({}) failed: {} (continuing)",
                            job.public_id, e
                        );
                    }
                }
            }
            JobStatus::AwaitingSignature => {
                let notifier = Arc::new(JobNotifier::new());
                job_notify_map.insert(job.public_id, notifier);
                if let Err(e) = job_tx
                    .send(crate::job_dispatcher::JobEnvelope {
                        public_id: job.public_id,
                    })
                    .await
                {
                    eprintln!(
                        "boot_resume_jobs: enqueue({}) failed: {} (continuing)",
                        job.public_id, e
                    );
                } else {
                    tracing::info!(
                        "boot_resume_jobs: re-armed awaiting_signature job {}",
                        job.public_id
                    );
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
