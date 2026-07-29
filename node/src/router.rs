use axum::{
    async_trait,
    body::Bytes,
    extract::{
        rejection::{JsonRejection, PathRejection},
        FromRequest, FromRequestParts, Json, Path, State,
    },
    http::{header, request::Parts, HeaderMap, Method, Request, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Router,
};
use bitcoin::secp256k1::{self as secp, schnorr::Signature as SchnorrSignature, Message};
use futures_util::stream::Stream;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;
use utoipa::ToSchema;
use uuid::Uuid;
#[cfg(feature = "username-claim")]
use zkcoins_program::hash::digest_from_bytes;
use zkcoins_program::hash::digest_to_bytes;
use zkcoins_prover::Proof;

use crate::account_node::{AccountNode, CoinProof};
use crate::db::InscriptionSummary;
use crate::flow;
use crate::job_dispatcher::{JobEnvelope, JobNotifyMap, JobPhaseEvent};
use crate::job_store::{CreateResult, JobKind, JobStatus, JobStore};
use crate::kernel::{
    CancelPolicy, JobEvent, JobEventHub, JobId, JobRequest, JobState, KernelError, KernelErrorCode,
    KernelService, NormativeJobStatus,
};
use crate::publisher::EsploraConfig;
use crate::transport::error_contract;
use crate::username::UsernameStore;
use crate::{NETWORK_CONFIG, USERNAME_DOMAIN};

/// Maximum allowed clock skew between the wallet's signed timestamp
/// and the server's wall clock. Matches the legacy in-helper window
/// extracted into [`check_timestamp_window`] so the existing app
/// behaviour is unchanged.
pub(crate) const MAX_TIMESTAMP_SKEW_SECS: u64 = 300;

/// Validate that `timestamp` is within [`MAX_TIMESTAMP_SKEW_SECS`] of
/// the server's wall clock. Extracted so signed handlers can run the
/// timestamp gate explicitly BEFORE `verify_send_signature` — emitting
/// the distinct `"Request timestamp too old or in the future"` string
/// the app's `KNOWN_SERVER_ERRORS` table maps. Folding it back into the
/// signature path would collapse both branches to
/// `"Signature verification failed"`, hiding a clock-skew misconfiguration
/// behind a generic crypto failure.
pub(crate) fn check_timestamp_window(timestamp: u64) -> Result<(), &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECS {
        return Err("Request timestamp too old or in the future");
    }
    Ok(())
}

/// Verify a Schnorr signature over send request fields.
/// Message = SHA256(account_address || recipient || amount || timestamp)
///
/// Callers MUST run [`check_timestamp_window`] first — this helper no
/// longer enforces the freshness window so the handler can surface
/// `"Request timestamp too old or in the future"` as its own status,
/// rather than collapsing it into `"Signature verification failed"`.
/// `request.signature` and `request.timestamp` are also required by the
/// time this helper runs (the handler returns 401 with
/// `"Missing signature"` / `"Missing timestamp"` upstream); the
/// `Option`-shaped `?` arms below stay as defence-in-depth.
pub(crate) fn verify_send_signature_pub(request: &SendCoinRequest) -> Result<(), &'static str> {
    verify_send_signature(request)
}

fn verify_send_signature(request: &SendCoinRequest) -> Result<(), &'static str> {
    let signature_hex = request.signature.as_deref().ok_or("Missing signature")?;
    let timestamp = request.timestamp.ok_or("Missing timestamp")?;

    // Build the message: SHA256(account_address || recipient || amount || timestamp)
    let mut hasher = Sha256::new();
    hasher.update(request.account_address.as_bytes());
    hasher.update(request.recipient.as_bytes());
    hasher.update(request.amount.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let sig_bytes = hex::decode(signature_hex).or(Err("Invalid signature hex"))?;
    let sig =
        SchnorrSignature::from_slice(&sig_bytes).or(Err("Invalid Schnorr signature format"))?;

    let (xonly, _parity) = request.public_key.x_only_public_key();
    let secp = secp::Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &xonly)
        .or(Err("Signature verification failed"))
}

/// Verify the BIP-340 Schnorr signature on a [`MintRequest`].
///
/// Mirrors [`verify_send_signature_pub`]. The signed message is
/// `SHA256(creator_pubkey.serialize() || name.as_bytes() || [decimals]
/// || amount.to_le_bytes() || timestamp.to_le_bytes())`, verified
/// against the x-only form of `creator_pubkey`. Callers MUST run
/// [`check_timestamp_window`] first so a stale timestamp surfaces as
/// its own status rather than collapsing into a generic crypto failure.
///
/// This authenticates that the mint was authorised by the holder of
/// `creator_pubkey`; the circuit's issuer gate + the commit-leg
/// soundness check then bind that same key into the on-chain
/// commitment so nobody can forge or inflate a foreign asset.
pub(crate) fn verify_mint_signature_pub(request: &MintRequest) -> Result<(), &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(request.creator_pubkey.serialize());
    hasher.update(request.name.as_bytes());
    hasher.update([request.decimals]);
    hasher.update(request.amount.to_le_bytes());
    hasher.update(request.timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let sig_bytes = hex::decode(&request.signature).or(Err("Invalid signature hex"))?;
    let sig =
        SchnorrSignature::from_slice(&sig_bytes).or(Err("Invalid Schnorr signature format"))?;

    let (xonly, _parity) = request.creator_pubkey.x_only_public_key();
    let secp = secp::Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &xonly)
        .or(Err("Signature verification failed"))
}

/// Lock a mutex, recovering from poison if a previous holder panicked.
/// This prevents cascade failures where one panic takes down all handlers.
pub(crate) fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("WARNING: Recovering from poisoned mutex");
        poisoned.into_inner()
    })
}

// Define a struct for our application state
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) account_node: Arc<Mutex<AccountNode>>,
    pub(crate) proof_store: Arc<ProofStore>,
    /// In-memory staged-mint store for the two-phase, creator-signed
    /// mint (phase 1 builds the proof + stages it here; phase 2 — the
    /// wallet-signed commit — consumes it). See [`MintStore`].
    pub(crate) mint_store: Arc<MintStore>,
    pub(crate) username_store: Arc<Mutex<UsernameStore>>,
    /// Postgres pool for per-account upserts (accounts table); the
    /// minting account's `num_pubkeys` is derived from SMT membership
    /// at runtime (Phase D), no separately-stored counter. Cloned
    /// cheaply via `Arc`; the underlying connections are pooled.
    pub(crate) pool: Arc<PgPool>,
    /// Esplora endpoint configuration consumed by the `/health/ready`
    /// readiness probe and by the mint-flow inscription broadcast in
    /// `mint_handler`. Injecting the config through `AppState` lets
    /// tests redirect Esplora calls at a `wiremock::MockServer`
    /// without having to mutate the process-wide `NETWORK_CONFIG`
    /// lazy_static (which is frozen on first access and shared across
    /// every test in the binary). In production `start_rest_node`
    /// clones `NETWORK_CONFIG` into this slot so the runtime
    /// behaviour is unchanged.
    pub(crate) esplora_config: Arc<EsploraConfig>,
    /// Background-warmup readiness flag. Default `false` at bootstrap
    /// start; flipped to `true` either (a) once the background
    /// `spawn_blocking` task in `runtime::start_rest_node` reports that
    /// `AccountNode::warmup_prover` returned Ok — at which point the
    /// Rayon worker pool is warm and every subsequent `/api/mint` /
    /// `/api/send` proof matches the steady-state ~5 s p50 — or (b)
    /// immediately at bootstrap when `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`
    /// is set (no background task is spawned in that case).
    ///
    /// Consumed by `/health/ready`: while `prover_warm == false` the
    /// handler returns 503 with a `prover: warming` tag so a rolling
    /// deploy can keep the previous-generation pod taking traffic
    /// until the new pod's prover is warm. The liveness probe
    /// `/health` is unaffected — it returns 200 the moment the
    /// listener binds, so container restart loops keyed on liveness
    /// are not triggered during the ~21 s warmup window.
    pub(crate) prover_warm: Arc<AtomicBool>,
    /// Runtime prover-health signal: the count of consecutive
    /// `prove failed` job outcomes (reset by the first success), updated
    /// by the job dispatcher. Unlike `prover_warm` (a one-shot boot
    /// flag), this reflects whether real mint/send proves are actually
    /// succeeding. Consumed by `/health/ready` so a systemically failing
    /// prover is reported as `prover: failing` + 503 instead of the
    /// misleading `prover: ready`; the dispatcher also uses the same
    /// threshold to arm the boot self-heal. See [`crate::prover_health`].
    pub(crate) prover_health: Arc<crate::prover_health::ProverHealth>,
    /// Persistent state-layer wrapper around the `jobs` table.
    /// Routes admit through `JobStore::create`; the dispatcher
    /// reads + advances rows through it; `GET /api/jobs/:id`
    /// reads the most-recent snapshot through it.
    pub(crate) job_store: Arc<JobStore>,
    /// mpsc sender cloned into every admit handler so a fresh job
    /// can be enqueued on the dispatcher channel created in
    /// `runtime::start_rest_node`. Closing every clone (i.e.
    /// dropping the last `AppState`) shuts the dispatcher's recv
    /// loop down cleanly.
    pub(crate) job_tx: mpsc::Sender<JobEnvelope>,
    /// Per-job `JobNotifier` channels populated by the dispatcher (a)
    /// when a send-job reaches `awaiting_signature` (the commit
    /// handler drains its `commit_wake` Notify) and (b) when a SSE
    /// stream subscribes to a non-terminal job (it holds a
    /// `phase_tx.subscribe()` receiver). `DashMap` (rather than
    /// `Mutex<HashMap>`) so concurrent inserts / removes / lookups
    /// stay lock-free on the typical access pattern (one wallet per
    /// job + at most a handful of SSE streams).
    ///
    /// See [`crate::job_dispatcher::JobNotifier`] for the two coordination
    /// primitives the dispatcher and the SSE handler share via this map; see
    /// [`stream_job_handler`] for the subscriber-side wiring.
    pub(crate) job_notify_map: JobNotifyMap,
    /// When `Some`, the v1.1 NfLog scanner has completed at least one
    /// successful catch-up apply. Under `ZKCOINS_V1_SHADOW=1` readiness
    /// requires this flag so the node does not report ready while its
    /// v1.1 view is still empty / behind tip. `None` = legacy stack
    /// (readiness does not wait on NfLog catch-up).
    pub(crate) v1_scan_caught_up: Option<Arc<AtomicBool>>,
    /// When `Some`, set to `false` if the scanner reports
    /// `ReorgOutcome::finality_broken`. Readiness then fails with
    /// `"deep_reorg"` and callers must stop crediting. `None` = legacy.
    pub(crate) v1_finality_ok: Option<Arc<AtomicBool>>,
    /// Staged v1.1 [`PendingSignEntry`](crate::v1::PendingSignEntry)
    /// material keyed by job id. Populated when a job reaches
    /// `awaiting_signature` under a v1.1 claim; consumed by
    /// [`jobs_sign_handler`] and the dispatcher finalise path. Empty /
    /// unused under the legacy stack. Restart-safe: also persisted under
    /// In-memory staging of the durable finalisation capability; also
    /// persisted under `request_body.finalisation` and rehydrated on boot.
    pub(crate) pending_sign_map: crate::v1::PendingSignMap,
    /// Optional v1.1 finalise driver. Under a v1.1 claim an accepted
    /// `/sign` **must** go through this (install signature → prove
    /// outside the engine lock → apply with live re-validation, or a
    /// test double) rather than completing the job with the signature
    /// material alone. `None` under the legacy stack; under v1.1 a
    /// missing driver fails the job loud.
    pub(crate) v1_finalise: Option<V1FinaliseHook>,
    /// Production registry of live [`PendingSignEntry`] values produced
    /// by `StateEngine::begin_*`. Keyed by job id; the dispatcher takes
    /// the entry once when entering `awaiting_signature` and stages it
    /// via [`crate::v1::stage_pending_sign`]. Empty under the legacy
    /// stack. Writers: [`crate::v1::register_live_pending_after_begin`].
    pub(crate) v1_live_pending_after_begin: crate::v1::PendingSignMap,
    /// Test-only extra source of a live pending after the prove leg
    /// (fixtures without a multi-minute prove). Production never
    /// installs this — the live path is
    /// [`Self::v1_live_pending_after_begin`] alone. Kept behind
    /// `cfg(test)` so it cannot be mistaken for a production resolver
    /// input (Defect 4).
    #[cfg(test)]
    pub(crate) v1_pending_after_prove: Option<V1PendingAfterProveHook>,
    /// Shared v1.1 engine for Gap-G6 balance attestation (and later
    /// Stage-3 prove paths). `None` under the legacy stack.
    pub(crate) v1_engine: Option<Arc<crate::v1::EngineAdapter>>,
    /// Single-use `AttestBalanceChallenge` store (§7.5 / §5.1).
    pub(crate) attest_challenges: crate::v1::AttestChallengeMap,
    /// Authoritative hostnames for `chan_bind` (§5.1). From
    /// `ZKCOINS_PUBLIC_HOST`. Empty → attest auth fails loud (no silent
    /// localhost default).
    pub(crate) public_hosts: Arc<Vec<String>>,
}

/// Hook the dispatcher invokes after a verified `/sign` to drive
/// prove → apply → **durable** engine + `v1_pending_publishes` stage.
///
/// The third argument is the exclusive-claim [`crate::job_store::FinaliseFence`]
/// for this acquisition epoch. Production
/// [`crate::v1::finalise_accepted_prove_persist_and_stage`] commits the engine
/// snapshot and `members_ready` only while that fence + lease still hold —
/// the same predicate as job-row host-edge writes. A fence that stops at the
/// job-row boundary is decoration; the engine write is the one that matters.
///
/// Production wires this via the shared [`crate::v1::EngineAdapter`] (async:
/// multi-minute prove on a blocking pool, then atomic fenced persist). Tests
/// inject a spy that records the call without running the multi-minute prove.
pub(crate) type V1FinaliseHook = Arc<
    dyn Fn(
            zkcoins_prover::state_engine::PendingTransition,
            zkcoins_prover::prover_bridge::TransitionSignature,
            crate::job_store::FinaliseFence,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::v1::FinaliseOutcome, String>> + Send,
            >,
        > + Send
        + Sync,
>;

/// Test-only hook the dispatcher may consult after the prove leg under a
/// v1.1 claim. Production uses only
/// [`AppState::v1_live_pending_after_begin`]. Behind `cfg(test)` so it is
/// not compiled into the production binary (Defect 4).
#[cfg(test)]
pub(crate) type V1PendingAfterProveHook =
    Arc<dyn Fn(uuid::Uuid) -> Option<crate::v1::PendingSignEntry> + Send + Sync>;

// Response types for our API
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct BalanceResponse {
    balance: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// Authoritative BIP-32 child-index counter for the queried account.
    ///
    /// Equals the number of times this account has executed a
    /// `/api/send` (`account.num_sends`). The wallet uses this value
    /// as `numPubkeys` for the next signing/derivation: the pubkey
    /// for the next send is at index `num_sends`.
    ///
    /// The wallet does NOT use it to derive `prev_commitment_pubkey`
    /// anymore — the server reads that one from its own state
    /// (`Account::commitment_public_key`) and the legacy
    /// `prev_commitment_pubkey` field on `SendCoinRequest` is
    /// ignored. See the field doc on `Account::commitment_public_key`
    /// for the bug class this eliminated (seed restore +
    /// stale-deploy + TOCTOU drift between local counter and server
    /// state, all surfacing as 400
    /// `"prev_commitment_pubkey required for account update"` in
    /// `07-send.spec.ts::send-success`).
    ///
    /// Always emitted (no `skip_serializing_if`) so the wallet can
    /// rely on its presence — `0` is the canonical value for an
    /// account that has never sent (matches `Account::new()`).
    #[serde(default)]
    num_sends: u32,
}

#[cfg(any(feature = "address-list", feature = "lnurl"))]
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct AddressesResponse {
    addresses: Vec<String>,
}

// ----- /api/history (Stage 3 closed — 410 only) ---------------------------
// Legacy list/detail helpers (`list_account_history`, `history_row_to_item`,
// balance/direction decoders, `TxDetail`, …) deleted in Stage 4. Handlers
// below stay as loud 410 Gone; OpenAPI documents that shape only.

/// `?address=&limit=&offset=` still accepted so clients get 410, not a
/// framework 400 from an unknown query extractor — values are ignored.
#[derive(Deserialize)]
pub(crate) struct HistoryQuery {
    pub address: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Error envelope retained for OpenAPI of the closed history routes.
#[derive(Serialize, ToSchema)]
pub(crate) struct HistoryErrorResponse {
    pub error: &'static str,
}

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub(crate) struct SendCoinRequest {
    /// Sender account address (`0x`-prefixed 32-byte hex).
    pub(crate) account_address: String,
    /// Recipient identifier — `0x`-prefixed 32-byte hex address or a
    /// known username this node can resolve.
    pub(crate) recipient: String,
    /// Amount to send, in atomic zkCoin units.
    pub(crate) amount: u64,
    /// Compressed secp256k1 public key (33 bytes), hex-encoded.
    #[schema(value_type = String, example = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")]
    pub(crate) public_key: bitcoin::secp256k1::PublicKey,
    /// Compressed secp256k1 public key (33 bytes) at the next BIP-32 child index, hex-encoded.
    #[schema(value_type = String, example = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")]
    pub(crate) next_public_key: bitcoin::secp256k1::PublicKey,
    /// Legacy field — IGNORED by the send flow as of the
    /// [`crate::account_node::Account::commitment_public_key`]
    /// refactor. Kept on the wire so deployed wallets still parse.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub(crate) prev_commitment_pubkey: Option<bitcoin::secp256k1::PublicKey>,
    /// Hex-encoded Schnorr signature (64 bytes).
    pub(crate) signature: Option<String>,
    /// Unix epoch seconds the signature was produced at.
    pub(crate) timestamp: Option<u64>,
    /// Asset identifier for multi-asset sends. Defaults to the native
    /// asset when omitted (backward-compatible with single-asset wallets).
    #[serde(default)]
    pub(crate) asset_id: Option<String>,
}

/// Creator-signed mint request (Milestone 2).
///
/// Neutral, permissionless model: anyone creates their own asset and
/// mints their own supply. The `account_address` (owner) and `asset_id`
/// are DERIVED server-side from `creator_pubkey` + `name` + `decimals`
/// — they are NOT accepted from the wire (which would let a forger
/// claim a foreign owner/asset). The request is authenticated by a
/// BIP-340 Schnorr signature over the mint fields, verified against
/// `creator_pubkey` (see [`verify_mint_signature_pub`]).
#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub(crate) struct MintRequest {
    /// Compressed secp256k1 public key (33 bytes) of the asset creator,
    /// hex-encoded. The owner is `H(creator_pubkey)` and the asset_id
    /// is `calculate_asset_id(creator_pubkey, H(name), decimals)`.
    #[schema(value_type = String, example = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")]
    pub(crate) creator_pubkey: bitcoin::secp256k1::PublicKey,
    /// Compressed secp256k1 public key (33 bytes) the mint rotates to,
    /// hex-encoded. The mint's transition commits under
    /// `sha256(next_public_key)` so the creator's first follow-up send
    /// does not collide with the creator key in the insert-only
    /// commitment SMT.
    #[schema(value_type = String, example = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")]
    pub(crate) next_public_key: bitcoin::secp256k1::PublicKey,
    /// Human-facing asset name. Folded into the asset_id via
    /// `calculate_name_hash`; also cached as display metadata.
    pub(crate) name: String,
    /// Asset decimals. Part of the asset_id derivation.
    pub(crate) decimals: u8,
    /// Amount to mint into the creator's own balance, atomic units.
    pub(crate) amount: u64,
    /// Hex-encoded BIP-340 Schnorr signature (64 bytes) over
    /// `SHA256(creator_pubkey || name || [decimals] || amount_le ||
    /// timestamp_le)`.
    pub(crate) signature: String,
    /// Unix epoch seconds the signature was produced at. Subject to the
    /// same freshness window as a send ([`check_timestamp_window`]).
    pub(crate) timestamp: u64,
}

// `ReceiveCoinRequest` was the SP1-era POST body shape for a coin
// drop. It is currently unused — the receive flow is exercised via
// scanner + state.update — but kept as a placeholder for the future
// authenticated push endpoint. Mark `dead_code` to silence the lint.
#[allow(dead_code)]
#[derive(Deserialize)]
pub(crate) struct ReceiveCoinRequest {
    coin_proof: Proof,
}

/// Persistent proof store — survives node restarts.
/// Each proof is stored as an individual file: /data/proofs/{id}.bin
pub(crate) struct ProofStore {
    dir: String,
    next_id: AtomicU64,
}

impl ProofStore {
    pub(crate) fn new(dir: &str) -> Self {
        std::fs::create_dir_all(dir).ok();
        // Scan existing files to find the highest ID
        let max_id = std::fs::read_dir(dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        e.file_name()
                            .to_str()?
                            .strip_suffix(".bin")?
                            .parse::<u64>()
                            .ok()
                    })
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);

        ProofStore {
            dir: dir.to_string(),
            next_id: AtomicU64::new(max_id + 1),
        }
    }

    /// Build a safe file path for a proof ID within the store directory.
    /// The ID is always a node-generated u64 and the suffix is the
    /// literal ".bin", so `base.join(...)` cannot escape `base` — no
    /// extra starts_with check is needed.
    fn proof_path(&self, id: u64) -> Option<std::path::PathBuf> {
        let base = std::path::Path::new(&self.dir).canonicalize().ok()?;
        Some(base.join(format!("{}.bin", id)))
    }

    // Vestigial: `add_proof` is only reachable from the now-removed
    // synchronous `/api/send` handler. The Job-API replacement
    // (`jobs_send_handler` → `dispatcher::process_send_job`) hands
    // the resulting `CoinProof` directly to the wallet via the
    // `proof_id` field on the job row and never writes to the file
    // store. Kept on disk so a wallet that still posts to
    // `/api/receive` with an old `proof_id` hits the legacy path
    // (which now never produces one). Marked `coverage(off)` because
    // an honest test would have to construct a `CoinProof` through
    // the Plonky2 prover, which is a >40-s job for a handler that
    // will be removed in the follow-up wallet-migration PR.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn add_proof(&self, proof_with_commitment: CoinProof) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let path = self
            .proof_path(id)
            .expect("proof store directory exists (created in ProofStore::new)");
        let bytes =
            bincode::serialize(&proof_with_commitment).expect("CoinProof is always serializable");
        Self::persist_proof_bytes(&path, &bytes, id);
        id
    }

    /// Best-effort persist: write `bytes` to `path` atomically, log the
    /// I/O error if the write fails. Extracted so the error arm can be
    /// exercised directly without having to construct a real `CoinProof`
    /// (which requires the Plonky2 prover to run).
    ///
    /// "Atomic" here means write-to-temp + rename. `File::create` +
    /// `sync_all` flushes the data file before the rename, and the
    /// final rename is a single inode swap from the OS's perspective,
    /// so a crash between the two never leaves a half-written
    /// `{id}.bin` for `get_proof` to find. Inlined (rather than calling
    /// a shared `atomic_write` helper) because the only remaining
    /// user after PR-A3 is this proof store — `accounts.bin`,
    /// `usernames.bin`, and `minting_num_pubkeys.bin` all moved to
    /// Postgres.
    fn persist_proof_bytes(path: &std::path::Path, bytes: &[u8], id: u64) {
        let path_str = path.to_str().unwrap_or("");
        let tmp_path = format!("{}.tmp", path_str);
        let result: std::io::Result<()> = (|| {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp_path, path_str)?;
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("Failed to persist proof {}: {}", id, e);
        }
    }

    // Vestigial pair to `add_proof`; the only call site
    // (`get_proof_handler`) is reached via the legacy `/api/proof/:id`
    // endpoint (now 410 Gone — Stage 3 Runde 5). See `add_proof` for the
    // deprecation rationale and the coverage-off reason.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn get_proof(&self, id: u64) -> Option<CoinProof> {
        let path = self.proof_path(id)?;
        let bytes = std::fs::read(&path).ok()?;
        bincode::deserialize(&bytes).ok()
    }

    /// Test-only: plant opaque bytes under `{id}.bin` so closed-handler
    /// tests can prove the HTTP path never returns store contents.
    #[cfg(test)]
    pub(crate) fn plant_raw_for_test(&self, id: u64, bytes: &[u8]) {
        let path = self
            .proof_path(id)
            .expect("proof store directory exists (created in ProofStore::new)");
        std::fs::write(&path, bytes).expect("plant proof bytes for test");
    }
}

/// A staged issuer-mint awaiting the creator's signature (phase 1 → 2
/// of the two-phase mint). Built by `flow::mint_flow`'s prove leg and
/// consumed by `flow::mint_commit_flow` once the wallet returns a
/// signed `Commitment`. Carries everything the commit leg needs to run
/// the off-circuit creator binding and apply the balance increase.
pub(crate) struct StagedMint {
    /// The issuer-mint proof (no out-coins; increases the creator's own
    /// balance). The wallet signs its `account_state_hash ||
    /// output_coins_root`.
    pub(crate) proof: Proof,
    /// Owner address `H(creator_pubkey)` of the creator account.
    pub(crate) owner: zkcoins_program::hash::HashDigest,
    /// Derived asset_id of the asset being minted.
    pub(crate) asset_id: zkcoins_program::types::AssetId,
    /// The tentative mutated creator account to swap in on commit.
    pub(crate) mutated_account: crate::account_node::Account,
    /// The asset creator's secp256k1 pubkey. The commit leg requires the
    /// wallet-signed `commitment.public_key` to equal this (off-circuit
    /// creator binding) and registers the asset_id -> creator_pubkey row.
    pub(crate) creator_pubkey: bitcoin::secp256k1::PublicKey,
}

/// In-memory store of staged mints keyed by `proof_id`. Mirrors the
/// role `ProofStore` plays for sends, but mints carry no on-disk
/// `CoinProof` (there is no out-coin), so the staged state lives in
/// process memory until the commit leg consumes it. A restart between
/// the prove and commit legs drops the staged mint; the wallet's job
/// then times out at `awaiting_signature` and the creator re-submits
/// (same boot-resume semantics as a send).
/// Staged-mint map for residual legacy `mint_commit_flow`. Stage 3 deleted
/// the prove-side `add` path (`prepare_mint` always refuses); the map stays
/// so a commit against an unknown `proof_id` still returns 404 rather than
/// a type-level hole.
#[derive(Default)]
pub(crate) struct MintStore {
    #[cfg(test)]
    next_id: AtomicU64,
    staged: Mutex<HashMap<u64, StagedMint>>,
}

impl MintStore {
    pub(crate) fn new() -> Self {
        MintStore {
            #[cfg(test)]
            next_id: AtomicU64::new(1),
            staged: Mutex::new(HashMap::new()),
        }
    }

    /// Stage a mint, returning its `proof_id` (test / residual legacy only).
    #[cfg(test)]
    pub(crate) fn add(&self, staged: StagedMint) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        lock_or_recover(&self.staged).insert(id, staged);
        id
    }

    /// Remove + return a staged mint by id (consumed by the commit leg).
    pub(crate) fn take(&self, id: u64) -> Option<StagedMint> {
        lock_or_recover(&self.staged).remove(&id)
    }
}

#[derive(Serialize, Deserialize, Default, ToSchema)]
pub(crate) struct SendCoinResponse {
    pub(crate) success: bool,
    /// Structured error message on failure. `None` on success. Mirrors
    /// the body string returned alongside a 4xx/5xx status code, so
    /// clients deserialising a non-2xx response can branch on it without
    /// re-reading the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_id: Option<u64>,
    /// Hex-encoded hash fields the client needs to create a commitment (only set for user sends).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) account_state_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_coins_root: Option<String>,
}

/// Map a `send_coins` error string to an HTTP status code plus a
/// client-safe body message.
///
/// Threat model (memory `feedback_threat_model_over_checklist`):
///
/// - **422 UNPROCESSABLE_ENTITY** — the request is well-formed but the
///   witness is invalid (insufficient balance, in-coin not in source's
///   output_coins_root, source commitment not in history MMR, etc.).
///   The defense-in-depth shim added in PR #26 (Stage 5d-next-5
///   Phase 2b) produces two of these strings in microseconds before
///   the minute-scale prove cost is paid; surfacing the specific
///   string lets clients distinguish "fix your inclusion proof" from
///   "fix your account selection".
/// - **404 NOT_FOUND** — sender address is not known to the node.
/// - **500 INTERNAL_SERVER_ERROR** — the prover failed. Body collapses
///   to a generic `"prove failed"` to avoid leaking prover-internal
///   state to the caller. The full error string is logged via
///   `eprintln!` in the handler.
///
/// The historical 400 `"prev_commitment_pubkey required for account
/// update"` is unreachable as of the
/// [`Account::commitment_public_key`] refactor: the server reads the
/// previous commitment pubkey from its own state instead of trusting
/// the caller. The match arm is therefore gone.
pub(crate) fn map_send_coins_error(err: &str) -> (StatusCode, &'static str) {
    match err {
        "Unknown account address" => (StatusCode::NOT_FOUND, "Unknown account address"),
        "Insufficient funds" => (StatusCode::UNPROCESSABLE_ENTITY, "Insufficient funds"),
        // `get_merkle_proofs` failures — reachable from `send_coins`
        // via the `prev_commitment_pubkey` path. The client supplied
        // the wrong public key, or the previous proof references a
        // history root the node hasn't seen yet (stale snapshot).
        // Both are caller-fixable, hence 422 rather than 500.
        "Unable to get merkle proofs for provided public key" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unable to get merkle proofs for provided public key",
        ),
        "Unable to get mmr inclusion proof for the previous root" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unable to get mmr inclusion proof for the previous root",
        ),
        // Truncated proof public-inputs vector — the proof stored on
        // the account is corrupt or was produced by an incompatible
        // build of the prover. Not caller-fixable; surfaces as 500.
        "Proof public_inputs too short" => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Proof public_inputs too short",
        ),
        "In-coin not present in source's output_coins_root" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "In-coin not present in source's output_coins_root",
        ),
        "Source commitment not present in history MMR" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Source commitment not present in history MMR",
        ),
        "Coin is missing commitment" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Coin is missing commitment",
        ),
        "Should provide an inclusion proof" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Should provide an inclusion proof",
        ),
        "Coin should not exist in coin history tree" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Coin should not exist in coin history tree",
        ),
        "Coin should not exist in tree yet" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Coin should not exist in tree yet",
        ),
        "Too many in-coins for one transition" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Too many in-coins for one transition",
        ),
        "Too many out-coins for one transition" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Too many out-coins for one transition",
        ),
        // Gap G9: residual legacy send under a v1.1 process claim. The
        // body is the full `LEGACY_SEND_REFUSED_UNDER_V1` string; match
        // by prefix so a wording tweak of the tail does not silently
        // become a 500.
        s if s.starts_with("legacy send refused under ZKCOINS_V1_SHADOW=1") => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "legacy send refused under v1.1; use begin_v1_send (CoinHist provenance)",
        ),
        s if s.ends_with("failed") => (StatusCode::INTERNAL_SERVER_ERROR, "prove failed"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Build a `SendCoinResponse` for a request-level failure (hex
/// decode, address length mismatch, etc.). Used by the legacy
/// `/api/receive` handler (the only synchronous data-path route
/// the Job-API refactor kept in place). Lets the receive handler
/// surface a `body.error` string instead of an opaque empty body.
pub(crate) fn handler_error_response(
    status: StatusCode,
    msg: &'static str,
) -> (StatusCode, Json<SendCoinResponse>) {
    (
        status,
        Json(SendCoinResponse {
            success: false,
            error: Some(msg.to_string()),
            ..SendCoinResponse::default()
        }),
    )
}

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub(crate) struct CommitRequest {
    pub(crate) proof_id: u64,
    /// Hex-encoded compressed public key (33 bytes) that signed the commitment.
    #[schema(value_type = String)]
    pub(crate) public_key: bitcoin::secp256k1::PublicKey,
    /// Hex-encoded Schnorr signature (64 bytes).
    pub(crate) signature: String,
    /// Hex-encoded message that was signed (the concatenation of account_state_hash + output_coins_root).
    pub(crate) message: String,
}

/// Normalized, machine-readable Bitcoin network identifier exposed on
/// `/api/info` as `bitcoin_network`. Serializes to the lowercase string
/// `"mainnet"` or `"mutinynet"`.
///
/// This is the typed counterpart to the free-text `network` field
/// (e.g. `"Mainnet"` / `"Mutinynet"` from `NETWORK_CONFIG.network_name`),
/// which stays a human-readable, operator-overridable label. Clients
/// switch behaviour on `bitcoin_network` to avoid the case-sensitivity
/// foot-gun of matching the free-text string.
#[derive(Serialize, Deserialize, ToSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BitcoinNetwork {
    Mainnet,
    Mutinynet,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct InfoResponse {
    /// Human-readable network label (e.g. `"Mainnet"` / `"Mutinynet"`),
    /// sourced from `NETWORK_CONFIG.network_name`. Operator-overridable
    /// and intended for display only — clients gate behaviour on
    /// `bitcoin_network` instead.
    network: String,
    /// Typed, lowercase network identifier derived from the node's
    /// `is_mainnet` flag. One of `"mainnet"` or `"mutinynet"`.
    bitcoin_network: BitcoinNetwork,
    capabilities: Capabilities,
    /// External hostname this node serves, used by the client to render
    /// `<hex|username>@<domain>`. DEV and PRD share the chain identifier
    /// but live behind different external hostnames, so the client cannot
    /// derive this from `network` alone — the node reports it directly.
    username_domain: String,
}

/// Node-side feature gates exposed to clients so the app can render
/// capability-driven UI without a parallel build-time env-flag set.
/// Each bool reflects a compile-time Cargo feature on the node binary.
///
/// Only opt-in features appear here. Permanent MVP endpoints (mint,
/// username resolve) are always available and intentionally have no
/// capability bit — clients must not gate their UI on flags that
/// would always be `true`.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct Capabilities {
    pub address_list: bool,
    /// Username *claim* (write path). Gated by the `username-claim`
    /// Cargo feature; off in hosted DEV + PRD images. Wallet clients
    /// hide the claim input when this is `false`. Always present in
    /// the response so the app does not have to sniff build flags.
    pub username_claim: bool,
    pub lnurl: bool,
    pub multi_asset: bool,
}

// --- Username & LNURL types ---

#[cfg(feature = "username-claim")]
#[derive(Deserialize, ToSchema)]
pub(crate) struct ClaimUsernameRequest {
    username: String,
    address: String,
    #[schema(value_type = String)]
    public_key: bitcoin::secp256k1::PublicKey,
    signature: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct UsernameResponse {
    username: String,
    address: String,
}

#[cfg(feature = "lnurl")]
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct LnurlpResponse {
    tag: String,
    callback: String,
    #[serde(rename = "minSendable")]
    min_sendable: u64,
    #[serde(rename = "maxSendable")]
    max_sendable: u64,
    metadata: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct LnurlErrorResponse {
    status: String,
    reason: String,
}

// Handler functions for our REST API
#[utoipa::path(
    get,
    path = "/api/balance",
    tag = "Accounts",
    params(
        ("address" = String, Query, description = "Account address as `0x`-prefixed 32-byte hex"),
    ),
    responses(
        (status = 200, description = "Balance lookup result. A well-formed address with no \
            on-chain activity returns `balance: 0` (canonical zero), not 404.",
            body = BalanceResponse),
        (status = 422, description = "Malformed address (bad hex, wrong length) or missing query parameter.",
            body = BalanceResponse),
    ),
)]
pub(crate) async fn get_balance_handler(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Stage 3 Runde 5 (R2): legacy single-asset balance read is closed.
    // Spec `read.account` (capability-bound ownership / view-grant) is the
    // replacement surface (`/v1/attest/balance` and later account-state
    // pull). Never return 200 with zeroed or partial ledger fields — that
    // would mask the protocol error.
    let _ = params;
    let _ = &state;
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/balance is removed (Stage 3): legacy AccountNode ledger read is not capability-bound; use the v1 attest / read.account surface"
        })),
    )
}

/// One asset entry in the [`OwnerBalanceResponse`] list.
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct AssetBalance {
    /// Asset identifier, 32-byte digest as 64 lowercase hex chars.
    pub asset_id: String,
    /// Human-facing asset name, if the node learned it at mint time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Asset decimals, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    /// Spendable balance of this asset for the owner, atomic units.
    pub balance: u64,
    /// Per-(owner, asset) BIP-32 child-index counter (number of sends).
    pub num_sends: u32,
}

/// Aggregated per-asset balance list for `GET /api/balance/:address`.
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct OwnerBalanceResponse {
    /// Owner address echoed back, 64 lowercase hex chars.
    pub address: String,
    /// Username bound to the owner, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// One entry per asset the owner holds. Empty for an unobserved
    /// address (canonical, not a 404).
    pub assets: Vec<AssetBalance>,
}

#[utoipa::path(
    get,
    path = "/api/balance/{address}",
    tag = "Accounts",
    params(
        ("address" = String, Path, description = "Owner address as `0x`-prefixed 32-byte hex"),
    ),
    responses(
        (status = 200, description = "Per-asset balance list for the owner. An unobserved \
            address returns `assets: []` (canonical), not 404.",
            body = OwnerBalanceResponse),
        (status = 422, description = "Malformed address (bad hex, wrong length).",
            body = OwnerBalanceResponse),
    ),
)]
/// `GET /api/balance/:address` — formerly listed every asset the owner
/// holds. Stage 3 Runde 5 (R2): closed; same capability-bound
/// `read.account` replacement as [`get_balance_handler`].
pub(crate) async fn get_owner_balance_handler(
    State(state): State<AppState>,
    Path(address_hex): Path<String>,
) -> impl IntoResponse {
    let _ = address_hex;
    let _ = &state;
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/balance/:address is removed (Stage 3): legacy multi-asset AccountNode ledger read is not capability-bound; use the v1 attest / read.account surface"
        })),
    )
}

#[utoipa::path(
    get,
    path = "/api/history",
    tag = "Accounts",
    responses(
        (status = 410, description = "Closed (Stage 3): unauthenticated legacy account history removed.",
            body = HistoryErrorResponse),
    ),
)]
/// `GET /api/history` — **closed (Stage 3 Runde 6)**.
///
/// Previously paginated decoded legacy `account_history` snapshots
/// (amount, balance deltas, …) for any address. Address knowledge is
/// not `read.account` (spec §6.4 / §7.5). Loud HTTP 410; never 200 with
/// rows and never a 422 validation path that re-probes the store.
pub(crate) async fn get_history_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> impl IntoResponse {
    // Touch fields so Deserialize stays intentional; values ignored (410).
    let _ = (state, &query.address, query.limit, query.offset);
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/history is removed (Stage 3): unauthenticated legacy account history is closed; use capability-bound v1 read.account"
        })),
    )
}

#[utoipa::path(
    get,
    path = "/api/history/{id}",
    tag = "Accounts",
    responses(
        (status = 410, description = "Closed (Stage 3): unauthenticated legacy account history detail removed.",
            body = HistoryErrorResponse),
    ),
)]
/// `GET /api/history/{id}` — **closed (Stage 3 Runde 6)**.
///
/// Previously returned decoded legacy snapshots (`balance_before/after`,
/// `num_sends_after`, `commitment_public_key`, …) without ownership proof
/// or view grant. Loud HTTP 410.
pub(crate) async fn get_history_item_handler(
    State(state): State<AppState>,
    Path(id_raw): Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let _ = (state, id_raw, params);
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/history/:id is removed (Stage 3): unauthenticated legacy account history detail is closed; use capability-bound v1 read.account"
        })),
    )
}

#[utoipa::path(
    get,
    path = "/api/address",
    tag = "Accounts",
    responses(
        (status = 200, description = "List of all known account addresses (`0x`-prefixed hex). \
            Only compiled in when the `address-list` Cargo feature is enabled.",
            body = AddressesResponse),
    ),
)]
#[cfg(feature = "address-list")]
pub(crate) async fn get_address_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Stage 3 Runde 6 (C): listing every rehydrated legacy address is
    // unauthenticated account enumeration — not `read.account`. Loud 410.
    let _ = state;
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/address is removed (Stage 3): unauthenticated legacy address list is closed; use capability-bound v1 read.account"
        })),
    )
}

// Vestigial: the wallet's pre-Job-API flow was send-then-receive,
// where the sender called `/api/send`, downloaded the resulting
// `CoinProof` from `/api/proof/:id`, and the recipient POSTed it
// back to `/api/receive` to materialise the inbound coin. The new
// model produces the `CoinProof` server-side via the dispatcher and
// the recipient never round-trips through the file store. The
// endpoint stays mounted so a wallet that has not yet migrated does
// not get a 404; an honest happy-path test would need a real
// `CoinProof` from the Plonky2 prover (>40s) which we will retire
// together with the route in the wallet-migration follow-up. The
// malformed-bincode error arm is still covered by
// `receive_coin_with_invalid_bincode_returns_default_response`.
#[utoipa::path(
    post,
    path = "/api/receive",
    tag = "Coins",
    request_body(
        description = "Bincode-serialised `CoinProof` blob produced by the sender's \
            `POST /api/send` round. The body is binary — NOT JSON.",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (status = 200, description = "On success, returns `{ \"success\": true }`. \
            A malformed binary body returns `{ \"success\": false }` with HTTP 200 \
            for back-compat with deployed wallets.",
            body = SendCoinResponse),
    ),
)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn receive_coin_handler(
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // Stage 3 Runde 4 (B6): legacy `/api/receive` must never mutate durable
    // state. Prefer explicit, loud refusal over silent 200+success:false.
    // Route kept so wallets get a clear protocol error (not a bare 404).
    let _ = body;
    let _ = &state;
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "success": false,
            "error": "POST /api/receive is removed (Stage 3): legacy CoinProof receive no longer mutates account state; use the v1 receive transition path"
        })),
    )
}

// Vestigial: paired with `receive_coin_handler` above. See its
// rationale block — the Job-API exposes proofs through the job-row
// `proof_id` directly, not via this disk-backed endpoint. The
// not-found arm (404) is still covered by
// `get_proof_handler_returns_404_for_unknown_id` so we keep the
// behavioural test green; only the file-found branch is excluded
// from coverage because the prover round-trip needed to populate
// `next_id` and the on-disk `.bin` is the same prohibitive cost as
// the receive happy path.
#[utoipa::path(
    get,
    path = "/api/proof/{id}",
    tag = "Coins",
    params(
        ("id" = u64, Path, description = "`proof_id` returned by a previous `POST /api/send`"),
    ),
    responses(
        (status = 200, description = "Binary `CoinProof` blob (bincode-serialised).",
            content_type = "application/octet-stream",
            body = Vec<u8>),
        (status = 404, description = "No proof exists for this `id`."),
    ),
)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn get_proof_handler(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    // Stage 3 Runde 5 (R2): legacy `/api/proof/:id` handed out a full
    // bincode `CoinProof` — including the cleartext `Coin` — with no
    // capability check. That contradicts capability-bound `read.proof` /
    // `read.account` (spec §6.4). Loud 410; never 200 with empty/partial
    // binary and never a 404 that still probes the store.
    let _ = id;
    let _ = &state;
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/proof/:id is removed (Stage 3): unauthenticated CoinProof download (cleartext Coin) is closed; use capability-bound v1 read.proof / read.account"
        })),
    )
}

// ===========================================================================
// Job-API admit + read handlers
// ===========================================================================
//
// The handlers below are intentionally thin: they validate the
// request shape (signature / timestamp / hex / length / size),
// admit the job to the `JobStore`, hand the public_id to the
// dispatcher via the `job_tx` channel, and return 202 Accepted
// immediately. The actual prove + broadcast work lives in
// `flow::*` and is driven by `job_dispatcher::spawn`.
//
// Idempotency: every admit handler reads an `Idempotency-Key`
// header (case-insensitive). Missing key → 400. A second request
// with the same `(account, key)` pair surfaces the originally
// admitted job (and, when complete, the cached response body) so
// the wallet's retry semantics drive progress without amplifying
// the prove cost.

/// Read the `Idempotency-Key` header off a request. Case-insensitive
/// on the header name (axum's HeaderMap lookup) so `idempotency-key`,
/// `Idempotency-Key`, and any other capitalisation produce the same
/// result. Missing or empty header → `Err`.
fn read_idempotency_key(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<JobErrorResponse>)> {
    let raw = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    match raw {
        Some(k) => Ok(k),
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(JobErrorResponse {
                error: "Idempotency-Key header is required".to_string(),
            }),
        )),
    }
}

/// Generic JSON error body for the Job-API surface. Distinct from
/// `SendCoinResponse` so a wallet client can branch on the shape
/// (`{error: "..."}` vs. the legacy `{success: false, error: "..."}`).
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct JobErrorResponse {
    pub(crate) error: String,
}

/// Body returned by the admit handlers on a fresh enqueue.
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct JobAcceptedResponse {
    #[schema(value_type = String, example = "00000000-0000-0000-0000-000000000000")]
    pub(crate) job_id: Uuid,
    pub(crate) status: &'static str,
}

/// Body returned by `GET /api/jobs/:id`. Optional fields are emitted
/// only when populated so the wire shape mirrors the row state.
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct JobStatusResponse {
    #[schema(value_type = String, example = "00000000-0000-0000-0000-000000000000")]
    pub(crate) job_id: Uuid,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) phase: String,
    pub(crate) progress: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<serde_json::Value>)]
    pub(crate) result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// Admit a fresh `mint` job. The body shape is identical to the
/// pre-refactor `POST /api/mint` body so the wallet's serialisation
/// path stays unchanged; the only delta is the response envelope
/// (202 + `{job_id, status}` instead of 200 + the full mint
/// response). The dispatcher drives the actual prove + broadcast in
/// the background.
#[utoipa::path(
    post,
    path = "/api/jobs/mint",
    tag = "Jobs",
    request_body = MintRequest,
    responses(
        (status = 202, description = "Mint job admitted. The body carries `{job_id, status}`; \
            clients poll `GET /api/jobs/{job_id}` for state transitions.",
            body = JobAcceptedResponse),
        (status = 400, description = "Malformed `Idempotency-Key` header.",
            body = JobErrorResponse),
        (status = 422, description = "Invalid request body (e.g. wrong address shape).",
            body = JobErrorResponse),
        (status = 500, description = "Database error while enqueueing the job.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn jobs_mint_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MintRequest>,
) -> axum::response::Response {
    let idem_key = match read_idempotency_key(&headers) {
        Ok(k) => k,
        Err((code, body)) => return (code, body).into_response(),
    };

    // Pre-flight validation: signature + timestamp gate + derive the
    // owner/asset identity. Returns 401/4xx without burning a job row.
    // The job is scoped to the DERIVED owner address (`H(creator_pubkey)`)
    // — never a wire-supplied address.
    let identity = match flow::validate_mint_request(&request) {
        Ok(id) => id,
        Err(e) => return job_flow_error(e).into_response(),
    };
    let account_bytes = digest_to_bytes(&identity.owner);

    // `MintRequest` derives `Serialize` over a fixed set of strings /
    // primitives; `serde_json::to_value` on such a shape cannot fail
    // (the only error path serde-json itself documents is custom
    // `Serialize` impls returning Err, which we do not have). `.expect`
    // turns the dead match arm into a single line so the coverage
    // gate does not flag it.
    let request_value =
        serde_json::to_value(&request).expect("MintRequest with derived Serialize always encodes");

    admit_and_enqueue(
        &state,
        JobKind::Mint,
        &account_bytes,
        &idem_key,
        request_value,
    )
    .await
}

/// Admit a fresh `send` job. Mirrors `jobs_mint_handler` shape but
/// runs the additional signature + timestamp gate before the row is
/// inserted so a malformed request returns 401 / 4xx before the
/// dispatcher pays any prove cost.
#[utoipa::path(
    post,
    path = "/api/jobs/send",
    tag = "Jobs",
    request_body = SendCoinRequest,
    responses(
        (status = 202, description = "Send job admitted. The body carries `{job_id, status}`.",
            body = JobAcceptedResponse),
        (status = 400, description = "Malformed `Idempotency-Key` header.",
            body = JobErrorResponse),
        (status = 401, description = "Missing or invalid signature / stale timestamp.",
            body = JobErrorResponse),
        (status = 404, description = "Unknown account address.",
            body = JobErrorResponse),
        (status = 422, description = "Invalid request body shape.",
            body = JobErrorResponse),
        (status = 500, description = "Database error while enqueueing the job.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn jobs_send_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SendCoinRequest>,
) -> axum::response::Response {
    let idem_key = match read_idempotency_key(&headers) {
        Ok(k) => k,
        Err((code, body)) => return (code, body).into_response(),
    };

    let (from_address, _to_address) = match flow::validate_send_request(&request) {
        Ok(pair) => pair,
        Err(e) => return job_flow_error(e).into_response(),
    };

    // See `jobs_mint_handler` above — `SendCoinRequest` derives
    // `Serialize`, so `to_value` cannot fail; collapse the dead arm.
    let request_value = serde_json::to_value(&request)
        .expect("SendCoinRequest with derived Serialize always encodes");

    admit_and_enqueue(
        &state,
        JobKind::Send,
        &from_address,
        &idem_key,
        request_value,
    )
    .await
}

/// Shared admit-then-enqueue glue used by `jobs_mint_handler` and
/// `jobs_send_handler`. Hides the `(create → idempotent-replay
/// branch → enqueue)` sequence from the kind-specific handler so the
/// two route handlers stay short and obviously equivalent.
async fn admit_and_enqueue(
    state: &AppState,
    kind: JobKind,
    account: &[u8; 32],
    idem_key: &str,
    request_body: serde_json::Value,
) -> axum::response::Response {
    let create_result = match state
        .job_store
        .create(kind, account, Some(idem_key), request_body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("JobStore::create failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JobErrorResponse {
                    error: "Failed to admit job".to_string(),
                }),
            )
                .into_response();
        }
    };

    let (job, fresh) = match create_result {
        CreateResult::Fresh(j) => (j, true),
        CreateResult::IdempotentReplay(j) => (j, false),
    };

    if !fresh {
        // Replay: if the original job already completed, surface the
        // cached body + status verbatim. Otherwise return the
        // current snapshot so the wallet sees the same job_id.
        if job.status == JobStatus::Completed {
            let status_code = StatusCode::from_u16(job.response_status.unwrap_or(200) as u16)
                .unwrap_or(StatusCode::OK);
            // `JobStore::complete` always sets `response_body` on the row before
            // flipping the status to `Completed`; the matching INSERT in
            // `complete()` is non-nullable on the value side. A `None` here
            // would mean the row was hand-edited or the schema invariant
            // broke — the `.expect()` surfaces that immediately instead of
            // hiding behind a defensive empty-object fallback (which would
            // also cost the 100% line-coverage gate a never-reached closure).
            let body = job
                .response_body
                .clone()
                .expect("response_body is set on every Completed job by JobStore::complete");
            return (status_code, Json(body)).into_response();
        }
        return (
            StatusCode::ACCEPTED,
            [(header::LOCATION, format!("/api/jobs/{}", job.public_id))],
            Json(JobAcceptedResponse {
                job_id: job.public_id,
                status: job.status.as_str(),
            }),
        )
            .into_response();
    }

    if let Err(e) = state
        .job_tx
        .send(JobEnvelope {
            public_id: job.public_id,
        })
        .await
    {
        tracing::error!("Job dispatcher channel send failed: {}", e);
        // The row exists but the dispatcher cannot be reached —
        // mark the job failed so the wallet observes a terminal
        // status on its next poll. Best-effort; the dispatcher
        // would only be down on a shutdown / catastrophic
        // panic-recovery scenario.
        let _ = state
            .job_store
            .fail(job.public_id, "dispatcher unavailable")
            .await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(JobErrorResponse {
                error: "Dispatcher unavailable".to_string(),
            }),
        )
            .into_response();
    }

    (
        StatusCode::ACCEPTED,
        [(header::LOCATION, format!("/api/jobs/{}", job.public_id))],
        Json(JobAcceptedResponse {
            job_id: job.public_id,
            status: job.status.as_str(),
        }),
    )
        .into_response()
}

/// `GET /api/jobs/:id` — poll handler. Returns the current row
/// snapshot. Non-terminal statuses carry a `Retry-After: 2` header
/// so polite wallets back off automatically.
#[utoipa::path(
    get,
    path = "/api/jobs/{job_id}",
    tag = "Jobs",
    params(
        ("job_id" = String, Path, description = "Job UUID returned by the matching admit handler."),
    ),
    responses(
        (status = 200, description = "Current job state. Non-terminal statuses include a \
            `Retry-After: 2` response header.",
            body = JobStatusResponse),
        (status = 404, description = "No job exists for this id.",
            body = JobErrorResponse),
        (status = 500, description = "Database error while loading the job row.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn get_job_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    let service = KernelService::from_store(Arc::clone(&state.job_store));
    let job = match service.get_job(JobRequest { id: JobId(id) }).await {
        Ok(j) => j,
        Err(e) => return legacy_get_job_error(e),
    };

    let response = project_job_legacy(&job);

    if job.state.is_terminal() {
        (StatusCode::OK, Json(response)).into_response()
    } else {
        (StatusCode::OK, [(header::RETRY_AFTER, "2")], Json(response)).into_response()
    }
}

/// Legacy `/api/jobs/:id` JSON projection from a typed domain job.
///
/// Field names, optionality, and wire status vocabulary match the pre-split
/// handler for every well-formed state.
fn project_job_legacy(job: &crate::kernel::Job) -> JobStatusResponse {
    let status = job.normative_status();
    let (proof_id, result, error) = match &job.state {
        // `awaiting_signature` carries the ash/ocr (or v1 surface) the
        // wallet must sign; `completed` carries the cached terminal body.
        JobState::AwaitingSignature { payload, proof_id } => {
            (*proof_id, Some(payload.0.clone()), None)
        }
        JobState::Completed { result } => (None, Some(result.0.clone()), None),
        JobState::Failed { error } => (None, None, error.clone()),
        // Legacy never projected `error` for cancelled; keep that shape.
        JobState::Accepted
        | JobState::Proving
        | JobState::Publishing
        | JobState::Cancelled { .. } => (None, None, None),
    };

    JobStatusResponse {
        job_id: job.id.as_uuid(),
        kind: job.kind.as_str().to_string(),
        status: status.as_legacy_str().to_string(),
        phase: job.phase.clone(),
        progress: job.progress,
        proof_id,
        result,
        error,
    }
}

/// Map a domain error onto the legacy jobs error envelope.
///
/// Legacy bodies use free-text `error` strings (not §7.5 machine codes).
fn legacy_get_job_error(err: KernelError) -> axum::response::Response {
    let desc = error_contract::describe(err.code);
    let status = StatusCode::from_u16(desc.http_status)
        .expect("error_contract http_status values are valid HTTP codes");
    if err.code == KernelErrorCode::InternalError {
        if let Some(ctx) = &err.internal_context {
            tracing::error!("GetJob internal_error: {}", ctx.detail);
        }
    }
    (
        status,
        Json(JobErrorResponse {
            error: err.public_message,
        }),
    )
        .into_response()
}

/// `POST /api/jobs/:id/commit` — attach the wallet-signed
/// commitment to a `send` job that is currently
/// `awaiting_signature`. The handler persists the commit payload
/// onto the row's `request_body` (under a `commit` key) so the
/// dispatcher can pick it up on wake; then calls `notify_one()` on
/// the per-job `Notify` channel so the dispatcher's `wait_for_commit`
/// task is woken.
#[utoipa::path(
    post,
    path = "/api/jobs/{job_id}/commit",
    tag = "Jobs",
    params(
        ("job_id" = String, Path, description = "Job UUID returned by `POST /api/jobs/send`."),
    ),
    request_body = CommitRequest,
    responses(
        (status = 204, description = "Commitment accepted. The dispatcher is now woken; \
            clients should poll `GET /api/jobs/{job_id}` for the resulting state."),
        (status = 404, description = "No job exists for this id.",
            body = JobErrorResponse),
        (status = 409, description = "Job is not in `awaiting_signature` state.",
            body = JobErrorResponse),
        (status = 422, description = "Malformed signature, message, or signature format.",
            body = JobErrorResponse),
        (status = 500, description = "Database error while attaching the commit payload.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn jobs_commit_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(commit_request): Json<CommitRequest>,
) -> axum::response::Response {
    // Gap G4: under a v1.1 process claim the residual ash‖ocr
    // CommitRequest is the wrong signing protocol. Refuse before
    // persisting or waking the dispatcher so a v1.1 boot cannot
    // finalise via the legacy commit route.
    if let Err(e) = crate::v1::refuse_legacy_commitment_under_v1() {
        return (
            StatusCode::CONFLICT,
            Json(JobErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    let job = match state.job_store.load(id).await {
        Ok(Some(j)) => j,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(JobErrorResponse {
                    error: "Job not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("JobStore::load failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JobErrorResponse {
                    error: "Failed to load job".to_string(),
                }),
            )
                .into_response();
        }
    };

    if job.status != JobStatus::AwaitingSignature {
        return (
            StatusCode::CONFLICT,
            Json(JobErrorResponse {
                error: format!(
                    "Job is in status `{}`, not `awaiting_signature`",
                    job.status.as_str()
                ),
            }),
        )
            .into_response();
    }

    // Merge the commit payload into the existing request_body so
    // the dispatcher can pull both halves out on wake. Persist via
    // a direct SQL write — we cannot expose every field through a
    // narrower JobStore method without burning a per-field
    // helper for each commit-leg shape.
    let mut merged = job.request_body.clone();
    // `CommitMintTxRequest` derives `Serialize` over fixed primitives;
    // see `jobs_mint_handler` above for the dead-arm rationale.
    let commit_value = serde_json::to_value(&commit_request)
        .expect("CommitMintTxRequest with derived Serialize always encodes");
    // `request_body` is always a JSON object: the admit handlers
    // (`jobs_mint_handler`, `jobs_send_handler`) only ever insert a
    // value produced by `serde_json::to_value(&MintRequest|SendCoinRequest)`,
    // both of which derive `Serialize` over fixed-field structs that
    // serialise as `{...}`. Collapsing the previous `if let
    // Some(obj) = ... else { merged = json!({"commit": ...}) }` into a
    // single `.expect` keeps the 100%-line/function coverage gate
    // honest without weakening the contract — an unexpected
    // non-object would surface here as a panic at the call site,
    // exactly like every other defensive `.expect` in this file.
    let obj = merged
        .as_object_mut()
        .expect("jobs.request_body is always a JSON object (admit handlers enforce)");
    obj.insert("commit".to_string(), commit_value);

    if let Err(e) =
        sqlx::query("UPDATE jobs SET request_body = $1, updated_at = NOW() WHERE public_id = $2")
            .bind(&merged)
            .bind(id)
            .execute(state.job_store.pool())
            .await
    {
        tracing::error!("Failed to merge commit payload into job row: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(JobErrorResponse {
                error: "Failed to persist commit payload".to_string(),
            }),
        )
            .into_response();
    }

    // Wake the dispatcher's `wait_for_commit` task. If no entry
    // exists in the notify_map — or the handoff CAS fails because the
    // dispatcher already timed out — surface 409 so the wallet does
    // not silently spin.
    let notifier = state.job_notify_map.get(&id).map(|e| e.value().clone());
    match notifier {
        Some(n) if n.try_signal_accept() => {
            n.commit_wake.notify_one();
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "broadcasting"})),
            )
                .into_response()
        }
        Some(_) | None => (
            StatusCode::CONFLICT,
            Json(JobErrorResponse {
                error: "Job is no longer waiting for a signature".to_string(),
            }),
        )
            .into_response(),
    }
}

/// §7.5 outward error body: `{ "error": <machine_code>, "message": <human> }`.
/// No invented fields (`check`, free-form strings outside the enumeration).
fn v1_error_body(code: &str, message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "error": code,
        "message": message.into(),
    })
}

/// §7.5 path extractor for job UUIDs: malformed ids → `400 malformed_request`
/// (Axum's default `Path<Uuid>` rejection is a framework 400/422 without the
/// closed machine code).
pub(crate) struct V1JobId(pub Uuid);

#[async_trait]
impl<S> FromRequestParts<S> for V1JobId
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<Uuid>::from_request_parts(parts, state).await {
            Ok(Path(id)) => Ok(V1JobId(id)),
            Err(PathRejection::FailedToDeserializePathParams(err)) => Err((
                StatusCode::BAD_REQUEST,
                Json(v1_error_body(
                    "malformed_request",
                    format!("job_id is not a valid UUID: {err}"),
                )),
            )
                .into_response()),
            Err(err) => Err((
                StatusCode::BAD_REQUEST,
                Json(v1_error_body(
                    "malformed_request",
                    format!("malformed job_id path parameter: {err}"),
                )),
            )
                .into_response()),
        }
    }
}

/// §7.5 JSON body extractor: missing / malformed / wrong-type JSON →
/// `400 malformed_request` (Axum's default is 422 with a framework body).
pub(crate) struct V1Json<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for V1Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(V1Json(value)),
            Err(err) => {
                let message = match &err {
                    JsonRejection::MissingJsonContentType(_) => {
                        "Content-Type must be application/json".to_string()
                    }
                    JsonRejection::JsonDataError(e) => {
                        format!("request body is not a well-formed JSON value of the expected type: {e}")
                    }
                    JsonRejection::JsonSyntaxError(e) => {
                        format!("request body is not valid JSON: {e}")
                    }
                    JsonRejection::BytesRejection(e) => {
                        format!("failed to read request body: {e}")
                    }
                    _ => format!("malformed request body: {err}"),
                };
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(v1_error_body("malformed_request", message)),
                )
                    .into_response())
            }
        }
    }
}

/// `POST /v1/jobs/:id/sign` — §7.5 wallet transition signature (normative path).
///
/// Active only under a v1.1 process claim (`ScanStackMode::V1`). The body is
/// decoded as [`crate::v1::WalletSignSubmissionWire`] then strictly converted
/// to [`crate::v1::WalletSignSubmission`] so encoding failures surface as the
/// closed §7.5 code `malformed_request` (HTTP 400), not a generic JSON error
/// and never an invented `encoding` code.
///
/// Verification uses [`crate::v1::accept_wallet_transition_signature`] against
/// the staged [`crate::v1::PendingSignEntry`] for this job — provenance is the
/// pending transition alone. On accept the verified signature is persisted and
/// the dispatcher is woken to drive `StateEngine::finalise` (not a bare
/// status flip).
///
/// With the flag off this route refuses at `feature_disabled` / ShadowFlag;
/// the legacy [`jobs_commit_handler`] path is untouched.
#[utoipa::path(
    post,
    path = "/v1/jobs/{job_id}/sign",
    tag = "Jobs",
    params(
        ("job_id" = String, Path, description = "Job UUID returned by the matching admit handler."),
    ),
    responses(
        (status = 200, description = "Signature verified; dispatcher woken to finalise."),
        (status = 400, description = "`malformed_request` — non-canonical hex / wrong width.",
            body = JobErrorResponse),
        (status = 404, description = "`job_not_found`.",
            body = JobErrorResponse),
        (status = 409, description = "`wrong_phase` / `stale_message` / `invalid_signature`.",
            body = JobErrorResponse),
        (status = 500, description = "`internal_error` while attaching the signature payload.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn jobs_sign_handler(
    State(state): State<AppState>,
    V1JobId(id): V1JobId,
    V1Json(wire): V1Json<crate::v1::WalletSignSubmissionWire>,
) -> axum::response::Response {
    // Flag gate: refuse the v1.1 path when the process is not on the v1.1 claim.
    // Legacy `/commit` remains the only active authorisation surface.
    // §7.5: this is a disabled surface (`feature_disabled`), not a job
    // phase mismatch (`wrong_phase`).
    if !crate::v1::v1_sign_route_active() {
        let err = crate::v1::TransitionSignatureError {
            check: crate::v1::SignatureCheck::ShadowFlag,
            message: "POST /v1/jobs/{id}/sign requires ZKCOINS_V1_SHADOW=1 / \
                      ScanStackMode::V1; legacy ash‖ocr uses POST /api/jobs/{id}/commit"
                .to_string(),
        };
        let (status, code) = crate::v1::sign_rejection(&err);
        return (
            StatusCode::from_u16(status).unwrap_or(StatusCode::NOT_FOUND),
            Json(v1_error_body(code, err.message)),
        )
            .into_response();
    }

    // Boundary: documented encoding is what we enforce. §7.5 closed code.
    let submission = match crate::v1::WalletSignSubmission::try_from(&wire) {
        Ok(s) => s,
        Err(err) => {
            let (status, code) = crate::v1::sign_rejection(&err);
            return (
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                Json(v1_error_body(code, err.message)),
            )
                .into_response();
        }
    };

    let job = match state.job_store.load(id).await {
        Ok(Some(j)) => j,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(v1_error_body("job_not_found", "Job not found")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("JobStore::load failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(v1_error_body("internal_error", "Failed to load job")),
            )
                .into_response();
        }
    };

    // §7.5 wrong_phase: only when the job is not in the status that accepts
    // /sign. Missing staging while status is correct is an internal
    // lifecycle failure, not a phase mismatch.
    if job.status != JobStatus::AwaitingSignature {
        return (
            StatusCode::CONFLICT,
            Json(v1_error_body(
                "wrong_phase",
                format!(
                    "Job is in status `{}`, not `awaiting_signature`",
                    job.status.as_str()
                ),
            )),
        )
            .into_response();
    }

    // Prefer the in-memory map; after a restart rehydrate from the
    // persisted envelope under request_body.pending_sign.
    let entry = match state.pending_sign_map.get(&id).map(|e| e.clone()) {
        Some(e) => e,
        None => match crate::v1::rehydrate_pending_sign(&job.request_body) {
            Ok(Some(e)) => {
                state.pending_sign_map.insert(id, e.clone());
                e
            }
            Ok(None) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(v1_error_body(
                        "internal_error",
                        "no PendingTransition staged for this job \
                         (awaiting_signature under v1.1 requires a staged entry)",
                    )),
                )
                    .into_response();
            }
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(v1_error_body("internal_error", err.message)),
                )
                    .into_response();
            }
        },
    };

    let accepted = match crate::v1::accept_wallet_transition_signature(
        crate::v1::V1ShadowMode::On,
        entry.network,
        &entry.pending,
        &submission,
    ) {
        Ok(sig) => sig,
        Err(err) => {
            let (status, code) = crate::v1::sign_rejection(&err);
            return (
                StatusCode::from_u16(status).unwrap_or(StatusCode::CONFLICT),
                Json(v1_error_body(code, err.message)),
            )
                .into_response();
        }
    };

    // Ordering: **install the signature into the durable FinalisationCapability
    // before** claiming the handoff as SIGNALED. A crash between signal and
    // persist must not leave a job marked signalled with nothing durable.
    //
    // The write is status-qualified on `awaiting_signature`: if cancel or
    // timeout already moved the row, the update fails rather than applying.
    //
    // Acceptance still requires a parked dispatcher: reporting
    // signature_accepted when nothing will finalise is worse than failing.
    // §7.5 has no dedicated "dispatcher down" code → internal_error.
    let Some(notifier) = state.job_notify_map.get(&id).map(|e| e.value().clone()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(v1_error_body(
                "internal_error",
                "signature verified but no dispatcher is waiting to finalise this job; \
                 refusing acceptance so the wallet does not treat the work as done",
            )),
        )
            .into_response();
    };

    // Install signature on the in-memory entry and on the durable capability.
    let mut entry = entry;
    if let Err(err) = entry.install_signature(accepted.clone()) {
        return (
            StatusCode::CONFLICT,
            Json(v1_error_body("invalid_signature", err.message)),
        )
            .into_response();
    }
    state.pending_sign_map.insert(id, entry.clone());

    let finalisation_value = match crate::v1::DurableFinalisationPersist::from_entry(&entry) {
        Ok(p) => match serde_json::to_value(p) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(v1_error_body(
                        "internal_error",
                        format!("encode durable finalisation: {e}"),
                    )),
                )
                    .into_response();
            }
        },
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(v1_error_body(
                    "internal_error",
                    format!("encode durable finalisation: {e}"),
                )),
            )
                .into_response();
        }
    };

    let mut merged = job.request_body.clone();
    let obj = merged
        .as_object_mut()
        .expect("jobs.request_body is always a JSON object (admit handlers enforce)");
    obj.insert(
        crate::v1::FINALISATION_BODY_KEY.to_string(),
        finalisation_value,
    );
    // Drop legacy split keys if present.
    obj.remove(crate::v1::PENDING_SIGN_BODY_KEY);
    obj.remove("sign");

    match state
        .job_store
        .replace_request_body_if_status(id, JobStatus::AwaitingSignature, &merged)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // Status moved (cancel / timeout / concurrent finalise).
            return (
                StatusCode::CONFLICT,
                Json(v1_error_body(
                    "wrong_phase",
                    "signature verified but job is no longer awaiting_signature; \
                     status-qualified persist refused",
                )),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to persist durable finalisation signature: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(v1_error_body(
                    "internal_error",
                    "Failed to persist durable finalisation signature",
                )),
            )
                .into_response();
        }
    }

    // Durable first, then CAS. If the dispatcher already timed out, refuse
    // acceptance even though the capability is signed (wallet must not
    // treat the work as done when nothing will finalise).
    if !notifier.try_signal_accept() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(v1_error_body(
                "internal_error",
                "signature verified and persisted but the dispatcher is no longer waiting \
                 to finalise this job (timed out or already signaled); refusing acceptance \
                 so the wallet does not treat the work as done",
            )),
        )
            .into_response();
    }

    // Wake only after durable persist + successful CAS.
    notifier.commit_wake.notify_one();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "signature_accepted",
            "job_id": id,
        })),
    )
        .into_response()
}

/// Map legacy job-store status to the §7.5 closed status set.
///
/// Aliases (`queued`→`accepted`, `broadcasting`→`publishing`) live only in
/// [`NormativeJobStatus::from_store`] — this helper delegates there so SSE
/// and poll cannot drift.
fn v1_status_wire(status: JobStatus) -> &'static str {
    NormativeJobStatus::from_store(status).as_v1_str()
}

/// `progress` as a float in `[0, 1]` (§7.5). The store keeps 0–100.
fn v1_progress_wire(progress: i16) -> f64 {
    (progress as f64 / 100.0).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// §7.5 Gap G6 — balance attestation
// ---------------------------------------------------------------------------

/// Map an [`crate::v1::AttestError`] to the §7.5 error body + HTTP status.
fn attest_error_response(err: crate::v1::AttestError) -> axum::response::Response {
    let (status, code) = err.http_status_and_code();
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(v1_error_body(code, err.message())),
    )
        .into_response()
}

/// FromRequestParts gate for the Gap-G6 attest surface.
///
/// Runs **before** any `FromRequest` body extractor ([`V1Json`]), so a
/// malformed body against a disabled feature still yields
/// `feature_disabled` rather than `malformed_request`.
pub(crate) struct RequireAttestRoute;

#[async_trait]
impl<S> FromRequestParts<S> for RequireAttestRoute
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if !crate::v1::v1_attest_route_active() {
            return Err(attest_error_response(
                crate::v1::AttestError::FeatureDisabled,
            ));
        }
        Ok(RequireAttestRoute)
    }
}

/// `POST /v1/attest/balance/challenge` — §7.5 action-bound challenge.
///
/// Body: `{ subject: <zk-address> }`  
/// Returns: `{ nonce: <hex32>, expiry: <decimal-string u64>, domain: "zkCoins/v1/AttestBalanceChallenge" }`
///
/// `expiry` is a §7.1 decimal **string** (never a JSON number). Body
/// decode uses [`V1Json`] so malformed JSON is `400 malformed_request`
/// **only when the flag is on** — [`RequireAttestRoute`] checks the
/// flag before body extraction.
pub(crate) async fn attest_balance_challenge_handler(
    State(state): State<AppState>,
    _active: RequireAttestRoute,
    V1Json(body): V1Json<crate::v1::AttestChallengeRequest>,
) -> axum::response::Response {
    match crate::v1::issue_attest_challenge(
        &state.attest_challenges,
        &body.subject,
        crate::v1::unix_now(),
    ) {
        Ok((nonce, expiry)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "nonce": hex::encode(nonce),
                "expiry": crate::v1::U64Decimal::format(expiry),
                "domain": crate::v1::ATTEST_BALANCE_CHALLENGE_DOMAIN,
            })),
        )
            .into_response(),
        Err(e) => attest_error_response(e),
    }
}

/// `POST /v1/attest/balance` — §7.5 OwnershipProof-gated admit.
///
/// Returns `202 { job_id }` on success. Auth failures use the closed
/// codes `unauthorized` / `challenge_expired` / `malformed_request`.
/// Body decode uses [`V1Json`] so missing/malformed JSON is the closed
/// `400 malformed_request` (not Axum's 422 rejection) **only when the
/// flag is on** — [`RequireAttestRoute`] checks the flag first.
pub(crate) async fn attest_balance_handler(
    State(state): State<AppState>,
    _active: RequireAttestRoute,
    V1Json(body): V1Json<crate::v1::AttestBalanceRequest>,
) -> axum::response::Response {
    let authorised = match crate::v1::authorise_attest_balance(
        &state.attest_challenges,
        state.public_hosts.as_slice(),
        &body,
        crate::v1::unix_now(),
    ) {
        Ok(b) => b,
        Err(e) => return attest_error_response(e),
    };

    // Engine must be present under a v1.1 claim (wired at boot).
    if state.v1_engine.is_none() {
        return attest_error_response(crate::v1::AttestError::Internal(
            "v1 EngineAdapter not available for attestation".into(),
        ));
    }

    let request_value = match serde_json::to_value(&authorised) {
        Ok(v) => v,
        Err(e) => {
            return attest_error_response(crate::v1::AttestError::Internal(format!(
                "encode AttestJobBody: {e}"
            )));
        }
    };

    let create_result = match state
        .job_store
        .create(
            JobKind::AttestBalance,
            &authorised.subject,
            None,
            request_value,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("JobStore::create (attest_balance) failed: {}", e);
            return attest_error_response(crate::v1::AttestError::Internal(
                "Failed to admit attestation job".into(),
            ));
        }
    };

    let job = match create_result {
        CreateResult::Fresh(j) | CreateResult::IdempotentReplay(j) => j,
    };

    // Enqueue for the dispatcher (same channel as mint/send).
    if let Err(e) = state
        .job_tx
        .send(crate::job_dispatcher::JobEnvelope {
            public_id: job.public_id,
        })
        .await
    {
        tracing::error!("attest job enqueue failed: {}", e);
        let _ = state
            .job_store
            .fail(
                job.public_id,
                &crate::v1::encode_job_error("internal_error", format!("enqueue failed: {e}")),
            )
            .await;
        return attest_error_response(crate::v1::AttestError::Internal(
            "Failed to enqueue attestation job".into(),
        ));
    }

    // §7.5: `202 { job_id }` — no status field on this admit response.
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "job_id": job.public_id.to_string(),
        })),
    )
        .into_response()
}

/// `GET /v1/jobs/:id` — §7.5 poll envelope.
///
/// - `status` is the closed §7.5 set (`accepted` / `publishing` aliases).
/// - `phase` is optional and **absent** in terminal states.
/// - `progress` is a float in `[0, 1]`.
/// - While `awaiting_signature`, the six ProofData digests + handshake
///   fields are under the top-level `awaiting_signature` key (not `result`).
/// - `result` is present only once `status == completed`.
/// - `error` is `{ error, message }` once failed/cancelled.
#[utoipa::path(
    get,
    path = "/v1/jobs/{job_id}",
    tag = "Jobs",
    params(
        ("job_id" = String, Path, description = "Job UUID."),
    ),
    responses(
        (status = 200, description = "Current job state (§7.5 envelope)."),
        (status = 404, description = "`job_not_found`."),
        (status = 500, description = "`internal_error`."),
    ),
)]
pub(crate) async fn get_job_v1_handler(
    State(state): State<AppState>,
    V1JobId(id): V1JobId,
) -> axum::response::Response {
    let service = KernelService::from_store(Arc::clone(&state.job_store));
    let job = match service.get_job(JobRequest { id: JobId(id) }).await {
        Ok(j) => j,
        Err(e) => return v1_get_job_error(e),
    };

    let body = project_job_v1(&job);

    if job.state.is_terminal() {
        (StatusCode::OK, Json(body)).into_response()
    } else {
        // §7.5: Retry-After; RECOMMENDED 0 while awaiting_signature.
        let retry = if matches!(job.state, JobState::AwaitingSignature { .. }) {
            "0"
        } else {
            "2"
        };
        (StatusCode::OK, [(header::RETRY_AFTER, retry)], Json(body)).into_response()
    }
}

/// §7.5 `/v1/jobs/:id` JSON projection from a typed domain job.
///
/// Distinct from the legacy projection: status aliases, float progress,
/// `awaiting_signature` key (not `result`), structured terminal errors.
/// Well-formed states stay field-equal to the pre-split handler.
fn project_job_v1(job: &crate::kernel::Job) -> serde_json::Value {
    let status_wire = job.normative_status().as_v1_str();
    let mut body = serde_json::json!({
        "job_id": job.id.as_uuid(),
        "kind": job.kind.as_str(),
        "status": status_wire,
        "progress": v1_progress_wire(job.progress),
    });
    let obj = body.as_object_mut().expect("object");

    // phase: optional diagnostic; absent in terminal states (§7.5).
    if !job.state.is_terminal() {
        let phase = job.phase.as_str();
        if !phase.is_empty()
            && phase
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && phase.len() <= 64
        {
            obj.insert(
                "phase".to_string(),
                serde_json::Value::String(phase.to_string()),
            );
        }
    }

    match &job.state {
        // Payload presence is enforced by `project_job_row` (fail-closed).
        // Backend-Korrektheit ist fail-closed: lieber ein Fehler als ein
        // Wert, der Vollständigkeit vortäuscht — genau dieses Muster
        // (halbe Antwort, die wie Erfolg aussieht) ist der Grund für den
        // Kernel-Schnitt.
        JobState::AwaitingSignature { payload, .. } => {
            obj.insert("awaiting_signature".to_string(), payload.0.clone());
        }
        JobState::Completed { result } => {
            obj.insert("result".to_string(), result.0.clone());
        }
        JobState::Failed { error } => {
            // §7.5: always present on failed/cancelled; machine codes from
            // the closed enumeration (never invent, never omit).
            obj.insert(
                "error".to_string(),
                crate::v1::decode_job_error(error.as_deref(), JobStatus::Failed),
            );
        }
        JobState::Cancelled { error } => {
            obj.insert(
                "error".to_string(),
                crate::v1::decode_job_error(error.as_deref(), JobStatus::Cancelled),
            );
        }
        JobState::Accepted | JobState::Proving | JobState::Publishing => {}
    }

    body
}

/// Map a domain error onto the §7.5 v1 error envelope via the shared contract.
fn v1_get_job_error(err: KernelError) -> axum::response::Response {
    let desc = error_contract::describe(err.code);
    let status = StatusCode::from_u16(desc.http_status)
        .expect("error_contract http_status values are valid HTTP codes");
    if err.code == KernelErrorCode::InternalError {
        if let Some(ctx) = &err.internal_context {
            tracing::error!("GetJob internal_error: {}", ctx.detail);
        }
    }
    (status, Json(v1_error_body(desc.reason, err.public_message))).into_response()
}

/// `POST /api/jobs/:id/cancel` — cancel a still-queued job. Only
/// succeeds while `status = queued`; once the prove leg starts the
/// dispatcher has paid sunk cost and the row is no longer
/// cancellable. Mid-flight cancel would also leave persistent state
/// inconsistent (proof persisted, partial broadcast).
#[utoipa::path(
    post,
    path = "/api/jobs/{job_id}/cancel",
    tag = "Jobs",
    params(
        ("job_id" = String, Path, description = "Job UUID."),
    ),
    responses(
        (status = 204, description = "Job cancelled."),
        (status = 404, description = "No job exists for this id.",
            body = JobErrorResponse),
        (status = 409, description = "Job is no longer cancellable (prove leg already started).",
            body = JobErrorResponse),
        (status = 500, description = "Database error while updating the job status.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn jobs_cancel_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> axum::response::Response {
    // Legacy policy: only `queued`. Domain distinguishes not-found from
    // wrong-phase; this adapter maps **both** to 409 free-text so the
    // pre-split wire contract (and `jobs_cancel_unknown_returns_409`)
    // stays byte-stable.
    let service = KernelService::from_store(Arc::clone(&state.job_store));
    match service
        .cancel_job(JobRequest { id: JobId(id) }, CancelPolicy::LegacyQueuedOnly)
        .await
    {
        Ok(_job) => {
            // Publish the terminal `cancelled` event to any attached
            // SSE listener BEFORE the dispatcher's notify-map entry
            // drops (it won't drop until the next admit, but the
            // explicit publish here guarantees a listener that was
            // attached before cancel sees the event without waiting
            // on the dispatcher's terminal-cleanup path — cancel
            // succeeds only while `status = queued`, before the
            // dispatcher ever picks the row up).
            crate::job_dispatcher::publish_phase(
                &state.job_notify_map,
                id,
                JobPhaseEvent {
                    status: JobStatus::Cancelled,
                    phase: "cancelled".to_string(),
                    proof_id: None,
                    result: None,
                    error: None,
                },
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "cancelled"})),
            )
                .into_response()
        }
        Err(e) => legacy_cancel_error(e),
    }
}

/// Map domain cancel errors onto the legacy jobs cancel envelope.
///
/// Legacy folds `job_not_found` and `wrong_phase` into a single 409 with
/// free-text `"Job is not in a cancellable state"`.
fn legacy_cancel_error(err: KernelError) -> axum::response::Response {
    match err.code {
        KernelErrorCode::JobNotFound | KernelErrorCode::WrongPhase => (
            StatusCode::CONFLICT,
            Json(JobErrorResponse {
                error: "Job is not in a cancellable state".to_string(),
            }),
        )
            .into_response(),
        KernelErrorCode::InternalError => {
            // Wire contract: legacy cancel always said "Failed to cancel job"
            // for any store failure. Domain may be more precise (e.g. load
            // failed before cancel was attempted) — keep that in logs only.
            if let Some(ctx) = &err.internal_context {
                tracing::error!("CancelJob (legacy) internal_error: {}", ctx.detail);
            } else {
                tracing::error!("CancelJob (legacy) internal_error: {}", err.public_message);
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JobErrorResponse {
                    error: "Failed to cancel job".to_string(),
                }),
            )
                .into_response()
        }
        other => {
            // CancelJob's closed error set is only the three above plus
            // malformed/rate_limited (handled at the extractor). Anything
            // else is a programming error — fail closed as 500.
            tracing::error!(
                "CancelJob (legacy) unexpected domain code {}",
                other.reason()
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JobErrorResponse {
                    error: "Failed to cancel job".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// `POST /v1/jobs/:id/cancel` — §7.5 normative cancel route.
///
/// Cancels a **not-yet-published** job (`queued` | `proving` |
/// `awaiting_signature`). Once the nullifier is broadcast
/// (`broadcasting` / completed), cancel is refused as `wrong_phase`.
/// Outward errors use the closed §7.5 `{error, message}` body.
///
/// Spec foundation: §7.5 `POST /v1/jobs/<job_id>/cancel` — "cancels a
/// not-yet-published job"; §7.8 `CancelJob` — same; wire table maps
/// `wrong_phase` when the job is past the accepting status. The
/// implementation set is exactly the statuses **before** `publishing`
/// (`accepted`/`queued`, `proving`, `awaiting_signature`).
pub(crate) async fn jobs_cancel_v1_handler(
    State(state): State<AppState>,
    V1JobId(id): V1JobId,
) -> axum::response::Response {
    let service = KernelService::from_store(Arc::clone(&state.job_store));
    match service
        .cancel_job(JobRequest { id: JobId(id) }, CancelPolicy::NotYetPublished)
        .await
    {
        Ok(_job) => {
            // Envelope strip is atomic with the status flip in
            // `cancel_not_yet_published`. Drop in-memory staging only.
            state.pending_sign_map.remove(&id);
            state.v1_live_pending_after_begin.remove(&id);
            let err_body = crate::v1::encode_job_error("internal_error", "cancelled");
            crate::job_dispatcher::publish_phase(
                &state.job_notify_map,
                id,
                JobPhaseEvent {
                    status: JobStatus::Cancelled,
                    phase: "cancelled".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(err_body),
                },
            );
            // Wake a parked awaiting_signature dispatcher so it observes
            // the terminal status instead of waiting for timeout.
            if let Some(notifier) = state.job_notify_map.get(&id).map(|e| e.value().clone()) {
                let _ = notifier.try_claim_timeout();
                notifier.commit_wake.notify_one();
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "cancelled", "job_id": id})),
            )
                .into_response()
        }
        Err(e) => v1_cancel_error(e),
    }
}

fn v1_cancel_error(err: KernelError) -> axum::response::Response {
    let desc = error_contract::describe(err.code);
    let status = StatusCode::from_u16(desc.http_status)
        .expect("error_contract http_status values are valid HTTP codes");
    if err.code == KernelErrorCode::InternalError {
        if let Some(ctx) = &err.internal_context {
            tracing::error!("CancelJob (v1) internal_error: {}", ctx.detail);
        }
    }
    (status, Json(v1_error_body(desc.reason, err.public_message))).into_response()
}

/// `GET /v1/jobs/:id/stream` — §7.5 normative SSE route.
///
/// Emits `event: phase` for non-terminal updates, `event: complete` for a
/// successful terminal job, and `event: error` for `failed` / `cancelled`
/// with a closed enumeration `error` object. Unknown ids and DB failures
/// return the closed §7.5 error body (never a bare framework status).
///
/// Domain source: [`KernelService::stream_job`]. Heartbeat is HTTP-only.
pub(crate) async fn stream_job_v1_handler(
    V1JobId(id): V1JobId,
    State(state): State<AppState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use futures_util::StreamExt;

    let service = KernelService::new(
        Arc::clone(&state.job_store),
        JobEventHub::new(Arc::clone(&state.job_notify_map)),
    );
    let domain_stream = match service.stream_job(JobRequest { id: JobId(id) }).await {
        Ok(s) => s,
        Err(e) => return v1_stream_open_error(e),
    };

    let stream = async_stream::stream! {
        let mut domain_stream = domain_stream;
        while let Some(item) = domain_stream.next().await {
            match item {
                Ok(ev) => {
                    let terminal = ev.job.state.is_terminal();
                    yield Ok::<Event, Infallible>(sse_event_from_job_event_v1(&ev));
                    if terminal {
                        return;
                    }
                }
                Err(e) => {
                    // Mid-stream domain failure: log and close (no half-frame).
                    if let Some(ctx) = &e.internal_context {
                        tracing::error!("StreamJob (v1) mid-stream error: {}", ctx.detail);
                    } else {
                        tracing::error!("StreamJob (v1) mid-stream error: {}", e);
                    }
                    return;
                }
            }
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(SSE_HEARTBEAT_INTERVAL))
        .into_response()
}

fn v1_stream_open_error(err: KernelError) -> axum::response::Response {
    let desc = error_contract::describe(err.code);
    let status = StatusCode::from_u16(desc.http_status)
        .expect("error_contract http_status values are valid HTTP codes");
    if err.code == KernelErrorCode::InternalError {
        if let Some(ctx) = &err.internal_context {
            tracing::error!("StreamJob (v1) open internal_error: {}", ctx.detail);
        }
    }
    (status, Json(v1_error_body(desc.reason, err.public_message))).into_response()
}

/// §7.5 SSE frame from a domain [`JobEvent`].
pub(crate) fn sse_event_from_job_event_v1(event: &JobEvent) -> Event {
    let job = &event.job;
    let status_wire = job.normative_status().as_v1_str();
    let event_name = event.kind.as_v1_str();
    let payload = match &job.state {
        JobState::Completed { result } => serde_json::json!({
            "job_id": job.id.as_uuid(),
            "kind": job.kind.as_str(),
            "status": status_wire,
            "result": result.0.clone(),
        }),
        JobState::Failed { error } => serde_json::json!({
            "job_id": job.id.as_uuid(),
            "status": status_wire,
            "error": crate::v1::decode_job_error(error.as_deref(), JobStatus::Failed),
        }),
        JobState::Cancelled { error } => serde_json::json!({
            "job_id": job.id.as_uuid(),
            "status": status_wire,
            "error": crate::v1::decode_job_error(error.as_deref(), JobStatus::Cancelled),
        }),
        JobState::AwaitingSignature { payload, .. } => {
            let mut data = serde_json::json!({
                "status": status_wire,
                "progress": v1_progress_wire(job.progress),
            });
            // Presence enforced by projection — insert, do not `if let Some`.
            data.as_object_mut()
                .expect("object")
                .insert("awaiting_signature".to_string(), payload.0.clone());
            if !job.phase.is_empty() {
                data.as_object_mut().expect("object").insert(
                    "phase".to_string(),
                    serde_json::Value::String(job.phase.clone()),
                );
            }
            data
        }
        JobState::Accepted | JobState::Proving | JobState::Publishing => {
            let mut data = serde_json::json!({
                "status": status_wire,
                "progress": v1_progress_wire(job.progress),
            });
            if !job.phase.is_empty() {
                data.as_object_mut().expect("object").insert(
                    "phase".to_string(),
                    serde_json::Value::String(job.phase.clone()),
                );
            }
            data
        }
    };
    Event::default()
        .event(event_name)
        .json_data(payload)
        .expect("Event::json_data cannot fail for a freshly built serde_json::Value")
}

// =======================================================================
// SSE push channel (PR2 — `/api/jobs/:id/stream`).
// =======================================================================
//
// The poll-based contract from PR1 stays in place; SSE is an additive
// channel for wallets that want push updates without the ~2 s poll tax.
// Layered on top of the dispatcher's per-job
// `tokio::sync::broadcast::Sender<JobPhaseEvent>` (see
// `JobNotifier::phase_tx`) so the stream handler does not have to know
// anything about the dispatcher's internal state machine — it just
// subscribes, forwards events as SSE frames, and closes on the
// first terminal event.

/// Explicit JSON encoding of an optional integer field: `null` means
/// "not present" on the legacy wire (a statement, not a mask).
fn option_i64_json(value: Option<i64>) -> serde_json::Value {
    match value {
        Some(v) => serde_json::Value::from(v),
        None => serde_json::Value::Null,
    }
}

/// Explicit JSON encoding of an optional free-text error on the legacy wire.
fn option_string_json(value: Option<&str>) -> serde_json::Value {
    match value {
        Some(s) => serde_json::Value::String(s.to_string()),
        None => serde_json::Value::Null,
    }
}

/// Legacy SSE frame from a domain [`JobEvent`].
///
/// Field set matches the pre-split `/api/jobs/:id/stream` wire for every
/// well-formed state. Required payloads are already enforced by projection.
pub(crate) fn sse_event_from_job_event_legacy(event: &JobEvent) -> Event {
    let job = &event.job;
    let status = job.normative_status().as_legacy_str();
    let (proof_id, result, error) = match &job.state {
        JobState::AwaitingSignature { payload, proof_id } => (
            option_i64_json(*proof_id),
            payload.0.clone(),
            serde_json::Value::Null,
        ),
        JobState::Completed { result } => (
            serde_json::Value::Null,
            result.0.clone(),
            serde_json::Value::Null,
        ),
        JobState::Failed { error } => (
            serde_json::Value::Null,
            serde_json::Value::Null,
            option_string_json(error.as_deref()),
        ),
        // Legacy initial frames never projected `error` for cancelled.
        // Mid-stream cancel events historically also left error null
        // when the phase event carried none — cancelled with a free-text
        // error is still projected as null on the initial path; for
        // mid-stream phase conversion we keep the same status gate so
        // wire stays equal to the legacy snapshot projection.
        JobState::Accepted
        | JobState::Proving
        | JobState::Publishing
        | JobState::Cancelled { .. } => (
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::Value::Null,
        ),
    };
    let payload = serde_json::json!({
        "status": status,
        "phase": job.phase,
        "proof_id": proof_id,
        "result": result,
        "error": error,
    });
    let event_name = event.kind.as_legacy_str();
    Event::default()
        .event(event_name)
        .json_data(payload)
        .expect("Event::json_data cannot fail for a freshly built serde_json::Value")
}

/// Mid-stream legacy frame: unlike the initial snapshot, historical
/// phase frames surface whatever the phase event carried (proof_id /
/// result / error) without status-gating error to Failed only.
/// Domain projection has already fail-closed required payloads.
pub(crate) fn sse_event_from_job_event_legacy_phase(event: &JobEvent) -> Event {
    let job = &event.job;
    let status = job.normative_status().as_legacy_str();
    let (proof_id, result, error) = match &job.state {
        JobState::AwaitingSignature { payload, proof_id } => (
            option_i64_json(*proof_id),
            payload.0.clone(),
            serde_json::Value::Null,
        ),
        JobState::Completed { result } => (
            serde_json::Value::Null,
            result.0.clone(),
            serde_json::Value::Null,
        ),
        JobState::Failed { error } | JobState::Cancelled { error } => (
            serde_json::Value::Null,
            serde_json::Value::Null,
            option_string_json(error.as_deref()),
        ),
        JobState::Accepted | JobState::Proving | JobState::Publishing => (
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::Value::Null,
        ),
    };
    let payload = serde_json::json!({
        "status": status,
        "phase": job.phase,
        "proof_id": proof_id,
        "result": result,
        "error": error,
    });
    Event::default()
        .event(event.kind.as_legacy_str())
        .json_data(payload)
        .expect("Event::json_data cannot fail for a freshly built serde_json::Value")
}

/// SSE heartbeat interval. Cloudflare Tunnel — the typical
/// PRD-fronting reverse proxy — drops idle HTTP streams after ~100 s
/// of silence. 25 s is the standard reverse-proxy-friendly cadence
/// (Stripe, GitHub, axum's own keep-alive default all sit in the
/// 15-30 s band) and keeps the stream alive through any single
/// dropped heartbeat without doubling the bandwidth cost.
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

/// `GET /api/jobs/:id/stream` — open an SSE channel that pushes phase
/// transitions to the wallet without polling.
///
/// Wire shape:
///
/// ```text
/// event: phase
/// data: {"status":"proving","phase":"proving","proof_id":null,"result":null,"error":null}
///
/// event: phase
/// data: {"status":"awaiting_signature","phase":"awaiting_signature","proof_id":17,...}
///
/// event: complete
/// data: {"status":"completed","phase":"completed","proof_id":null,"result":{...},"error":null}
/// ```
///
/// Plus a `: heartbeat` SSE comment every [`SSE_HEARTBEAT_INTERVAL`]
/// so Cloudflare Tunnel does not idle-kill the connection.
///
/// Initial frame: the handler IMMEDIATELY pushes the current job
/// state on open, so the wallet learns the latest state without
/// waiting for the dispatcher's next transition (matters most when
/// the wallet re-attaches mid-flight after a network blip).
///
/// Closes the stream after the first `event: complete` frame.
///
/// Fallback semantics: when SSE is not available (e.g. corporate
/// proxy stripping `text/event-stream`), the wallet falls back to
/// `GET /api/jobs/:id` polling — the poll contract from PR1 is
/// unchanged.
#[utoipa::path(
    get,
    path = "/api/jobs/{job_id}/stream",
    tag = "Jobs",
    params(
        ("job_id" = String, Path, description = "Job UUID returned by the matching admit handler."),
    ),
    responses(
        (status = 200,
            description = "SSE stream. Frames are `event: phase` (intermediate transitions) and \
                `event: complete` (terminal). The wire body of each frame is a JSON-encoded \
                `JobStatusResponse` snapshot. Streams close after the first `event: complete`. \
                A `: heartbeat` SSE comment is emitted on a fixed interval so reverse proxies \
                (Cloudflare Tunnel, nginx) do not idle-kill the connection.",
            content_type = "text/event-stream"),
        (status = 404, description = "No job exists for this id. Returned as a JSON body \
            rather than an immediately-closed stream so the polling fallback can branch \
            on a plain HTTP error.",
            body = JobErrorResponse),
        (status = 500, description = "Database error loading the job row.",
            body = JobErrorResponse),
    ),
)]
pub(crate) async fn stream_job_handler(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    use futures_util::StreamExt;

    // Domain StreamJob: load + project snapshot, then phase changes.
    // 404 / 500 surface as plain status codes (legacy contract — no JSON body).
    let service = KernelService::new(
        Arc::clone(&state.job_store),
        JobEventHub::new(Arc::clone(&state.job_notify_map)),
    );
    let domain_stream = match service.stream_job(JobRequest { id: JobId(id) }).await {
        Ok(s) => s,
        Err(e) => {
            return Err(legacy_stream_open_status(e));
        }
    };

    // Snapshot uses status-gated error projection; subsequent frames use
    // the historical phase-event shape (error field also on cancelled).
    let stream = async_stream::stream! {
        let mut domain_stream = domain_stream;
        let mut first = true;
        while let Some(item) = domain_stream.next().await {
            match item {
                Ok(ev) => {
                    let terminal = ev.job.state.is_terminal();
                    let frame = if first {
                        first = false;
                        sse_event_from_job_event_legacy(&ev)
                    } else {
                        sse_event_from_job_event_legacy_phase(&ev)
                    };
                    yield Ok::<Event, Infallible>(frame);
                    if terminal {
                        return;
                    }
                }
                Err(e) => {
                    if let Some(ctx) = &e.internal_context {
                        tracing::error!("StreamJob (legacy) mid-stream error: {}", ctx.detail);
                    } else {
                        tracing::error!("StreamJob (legacy) mid-stream error: {}", e);
                    }
                    return;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(SSE_HEARTBEAT_INTERVAL)))
}

fn legacy_stream_open_status(err: KernelError) -> StatusCode {
    match err.code {
        KernelErrorCode::JobNotFound => StatusCode::NOT_FOUND,
        KernelErrorCode::InternalError => {
            if let Some(ctx) = &err.internal_context {
                tracing::error!("StreamJob (legacy) open internal_error: {}", ctx.detail);
            }
            StatusCode::INTERNAL_SERVER_ERROR
        }
        other => {
            tracing::error!(
                "StreamJob (legacy) unexpected open error {}",
                other.reason()
            );
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Map a `flow::FlowError` (from pre-admit validation) into a
/// `Response`. Only invoked by the admit handlers before the job is
/// inserted into the store; once a row exists, the dispatcher's
/// `process_*` path persists the error onto the row instead.
fn job_flow_error(e: flow::FlowError) -> (StatusCode, Json<JobErrorResponse>) {
    (e.status, Json(JobErrorResponse { error: e.message }))
}

#[utoipa::path(
    get,
    path = "/api/inscriptions/{txid}",
    tag = "Inscriptions",
    params(
        ("txid" = String, Path, description = "Commit transaction id (64 hex characters, \
            big-endian display order — matches what block explorers show)"),
    ),
    responses(
        (status = 200, description = "Inscription metadata.", body = InscriptionSummary),
        (status = 404, description = "No inscription matches this `txid`.",
            body = SendCoinResponse),
        (status = 422, description = "Malformed `txid` (not 32-byte hex).",
            body = SendCoinResponse),
        (status = 500, description = "Database error.", body = SendCoinResponse),
    ),
)]
/// `GET /api/inscriptions/:txid` — **closed (Stage 3 Runde 6)**.
///
/// Previously returned legacy `pending_inscriptions` summary (kind,
/// status, txids, amount, failure, timestamps) without capability.
/// **Decision:** 410 Gone rather than rebind to `v1_pending_publishes`.
/// V1 publish rows are operator crash-recovery state for AggregateState
/// NullifierV3, not a public account-read surface; capability-bound
/// `read.account` / job status cover wallet needs. Loud protocol error.
pub(crate) async fn get_inscription_handler(
    State(state): State<AppState>,
    Path(txid_hex): Path<String>,
) -> axum::response::Response {
    let _ = (state, txid_hex);
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "GET /api/inscriptions/:txid is removed (Stage 3): unauthenticated legacy pending_inscriptions lookup is closed; use capability-bound v1 surfaces"
        })),
    )
        .into_response()
}

// ---- Admin: R2 probe history --------------------------------------------
//
// The `probe_r2` binary persists its results into `r2_probe_runs` (see
// `r2_probe.rs` + migration 0013). This endpoint surfaces the most
// recent `limit` rows of the convenience view so the operator can ask
// "did the last few probe runs hit budget?" against a deployed node
// without shelling into the database.
//
// Closed test env (`feedback_zkcoins_closed_test_env`): the endpoint
// is unauthenticated like every other route. The path lives under an
// `/api/admin/` prefix so it is visibly separate from the user-facing
// surface and never accidentally documented as a public contract.
// Read-only — the handler never writes.

/// `?limit=` query for `GET /api/admin/r2-probe/history`. Capped at
/// 200 to bound the response size and the underlying DB scan.
#[derive(Deserialize)]
pub(crate) struct R2ProbeHistoryQuery {
    pub limit: Option<i64>,
}

/// Default page size when `?limit` is omitted.
pub(crate) const R2_PROBE_HISTORY_DEFAULT_LIMIT: i64 = 50;
/// Hard cap on the `?limit` parameter — clamps oversized requests
/// down to a sane scan budget.
pub(crate) const R2_PROBE_HISTORY_MAX_LIMIT: i64 = 200;

/// Normalise a caller-supplied `?limit` into the
/// `[1, R2_PROBE_HISTORY_MAX_LIMIT]` window. Negative / zero /
/// missing inputs collapse to the default; anything above the cap
/// is clamped down. Extracted so the clamp logic is unit-testable
/// without spinning up a Postgres container.
pub(crate) fn clamp_r2_probe_history_limit(raw: Option<i64>) -> i64 {
    match raw {
        Some(n) if n <= 0 => R2_PROBE_HISTORY_DEFAULT_LIMIT,
        Some(n) if n > R2_PROBE_HISTORY_MAX_LIMIT => R2_PROBE_HISTORY_MAX_LIMIT,
        Some(n) => n,
        None => R2_PROBE_HISTORY_DEFAULT_LIMIT,
    }
}

/// `GET /api/admin/r2-probe/history?limit=<int>` — operator-facing
/// trend view over the `r2_probe_runs_summary` view. Returns the
/// `limit` most recent runs newest first as a JSON array. Read-only:
/// no write path exists for this resource through HTTP.
///
/// The endpoint is intentionally unauthenticated — the node sits in
/// a closed test environment where the entire request surface is
/// fair game for the operator. Per
/// `feedback_zkcoins_no_privacy_promise` the server makes no
/// privacy claim; the probe rows are operational telemetry and any
/// future hardening goes alongside the wider auth story.
async fn r2_probe_history_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<R2ProbeHistoryQuery>,
) -> axum::response::Response {
    let limit = clamp_r2_probe_history_limit(query.limit);
    match crate::r2_probe::fetch_recent_summary(&state.pool, limit).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            tracing::warn!("r2_probe_history_handler: db error: {}", e);
            handler_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error while reading R2 probe history",
            )
            .into_response()
        }
    }
}

/// JSON body returned by `GET /health/ready`. `failures` is empty on a
/// fully ready node; each failing dependency contributes one stable
/// short tag (`"db"`, `"esplora"`, `"prover"`, and under the v1.1 stack
/// `"v1_scan"` / `"deep_reorg"`) so a Kuma monitor parses the cause
/// without having to scrape the status code in isolation.
///
/// `prover` is the background-warmup tag (see `AppState::prover_warm`):
/// while the bootstrap warmup task is still running, the readiness
/// probe reports `failures: ["prover"]` with `status: starting` and a
/// 503 so a load balancer keeps holding traffic on the previous-gen
/// pod. `/health` (liveness) is unaffected.
#[derive(Serialize, ToSchema)]
pub(crate) struct ReadyResponse {
    ready: bool,
    failures: Vec<&'static str>,
    /// Lifecycle tag. `"starting"` while any failure is present,
    /// `"ready"` once every dependency probe passes. Distinct from
    /// `ready: bool` so a parsing consumer can branch on a short
    /// string without re-deriving it from the bool + failures shape.
    status: &'static str,
    /// Prover health tag. `"warming"` while
    /// `AppState::prover_warm == false` (one-shot boot warmup), `"ready"`
    /// once warm and proving normally, and `"failing"` once the
    /// dispatcher has seen `prover_health::PROVE_FAILURE_THRESHOLD`
    /// consecutive `prove failed` job outcomes (a systemically failing
    /// prover — e.g. digest-unchanged proof staleness). `"failing"` and
    /// `"warming"` both also add `"prover"` to `failures` and force the
    /// overall 503. Emitted on every response (regardless of overall
    /// readiness) so a deploy dashboard can show prover health separately
    /// from the DB/Esplora probes.
    prover: &'static str,
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    responses(
        (status = 200, description = "Node is ready: DB reachable, Esplora reachable, \
            prover warm. `failures` is empty, `status = \"ready\"`, `prover = \"ready\"`.",
            body = ReadyResponse),
        (status = 503, description = "Node is not ready. `failures` carries one or more of \
            `\"db\"`, `\"esplora\"`, `\"prover\"` (`prover` covers both `\"warming\"` and the \
            systemic-failure `\"failing\"` states). Load balancers / Kuma monitors gate traffic \
            on this status.",
            body = ReadyResponse),
    ),
)]
/// Readiness probe (`GET /health/ready`).
///
/// **Liveness vs readiness.** The pre-existing `/health` endpoint is
/// the Kubernetes-style liveness probe: it returns `"ok"` with 200 as
/// long as the HTTP listener is bound and the tokio runtime is alive.
/// It deliberately does NOT touch the database or Esplora, so an
/// upstream blip never restarts the process — losing the in-memory
/// `account_node` and `state` to a restart would lose every mint /
/// send the scanner has not yet checkpointed.
///
/// `/health/ready` is the complementary readiness probe: it actively
/// pings Postgres (`SELECT 1`) and Esplora (`GET /blocks/tip/height`,
/// re-using the configured `ESPLORA_URL`) and returns 503 if either
/// fails. A load balancer / uptime monitor uses this to decide
/// "should traffic flow?" without using it to decide "should this
/// process die?". An external uptime monitor (Uptime-Kuma) watches
/// `api.zkcoins.app/health/ready` on a 60 s interval — separate alert
/// from the liveness check.
///
/// No caching: each call issues a fresh DB round-trip plus an Esplora
/// HEAD-equivalent. Both are sub-100 ms in steady state, and a cached
/// stale "ready" is worse than a slightly slow honest answer.
pub(crate) async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut failures: Vec<&'static str> = Vec::new();

    if sqlx::query("SELECT 1").execute(&*state.pool).await.is_err() {
        failures.push("db");
    }

    if check_esplora(&state.esplora_config).await.is_err() {
        failures.push("esplora");
    }

    // Background-warmup gate. `prover_warm` is flipped to true by the
    // `spawn_blocking` task that `runtime::start_rest_node` launches
    // immediately after binding the TCP listener (or directly at boot
    // when `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`). Until then a user
    // request still succeeds but pays the ~7 s cold-prove tax — for
    // the rolling-deploy use case the load balancer holds traffic on
    // the previous-gen pod by treating this readiness probe as the
    // gate, not the liveness probe.
    let prover_warm = state.prover_warm.load(Ordering::SeqCst);
    // Runtime prove-health gate. Unlike the one-shot warmup flag above,
    // this reflects whether real mint/send proves are succeeding: the
    // dispatcher counts consecutive `prove failed` outcomes and this
    // trips at the `prover_health::PROVE_FAILURE_THRESHOLD`. Without it
    // a node whose persisted proofs went stale (the digest-unchanged
    // class — see `self_heal.rs`) kept reporting `prover: ready` while
    // failing 100% of jobs, so neither the deploy smoke-test nor
    // monitoring could see the outage.
    let prover_failing = state.prover_health.is_failing();
    if !prover_warm || prover_failing {
        failures.push("prover");
    }

    // v1.1 stack readiness: when the process claimed NfLog, do not report
    // ready until the scanner has caught up at least once, and fail hard
    // if finality was broken by a deep reorg (§3.9 contract).
    if let Some(caught_up) = &state.v1_scan_caught_up {
        if !caught_up.load(Ordering::SeqCst) {
            failures.push("v1_scan");
        }
    }
    if let Some(finality_ok) = &state.v1_finality_ok {
        if !finality_ok.load(Ordering::SeqCst) {
            failures.push("deep_reorg");
        }
    }

    let ready = failures.is_empty();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let lifecycle_status = if ready { "ready" } else { "starting" };
    let prover_status = if prover_failing {
        "failing"
    } else if prover_warm {
        "ready"
    } else {
        "warming"
    };
    (
        status,
        Json(ReadyResponse {
            ready,
            failures,
            status: lifecycle_status,
            prover: prover_status,
        }),
    )
}

/// Ping the configured Esplora endpoint. A successful tip-height fetch
/// proves the upstream is reachable AND serving the public REST API
/// (a TCP-only liveness check would miss a broken nginx upstream).
async fn check_esplora(
    config: &EsploraConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = crate::esplora_bound::EsploraReadClient::connect(&config.url)?;
    client.get_height().await?;
    Ok(())
}

/// JSON body returned by `GET /health/publisher`. Surface enough state
/// for the deploy-dev preflight (and a curious operator) to make the
/// "should I top up the publisher wallet?" decision without scraping
/// Esplora directly. `address` is the publisher's Taproot bech32 — log-
/// only, NOT a secret (the matching key lives in `PUBLISHER_KEY`).
#[derive(Serialize, ToSchema)]
pub(crate) struct PublisherHealthResponse {
    address: String,
    utxo_count: u64,
    total_sats: u64,
}

/// JSON body returned by the 503 branch of `GET /health/publisher`
/// when the configured Esplora endpoint fails the UTXO fetch. Kept
/// distinct from [`PublisherHealthResponse`] so the deploy-dev
/// preflight can branch on the response shape without parsing the
/// HTTP status separately. `address` is echoed back so the failure
/// log still identifies which wallet the operator should top up.
#[derive(Serialize, ToSchema)]
pub(crate) struct PublisherHealthErrorResponse {
    error: &'static str,
    detail: String,
    address: String,
}

#[utoipa::path(
    get,
    path = "/health/publisher",
    tag = "Health",
    responses(
        (status = 200, description = "Publisher wallet state — address (Taproot bech32), \
            spendable UTXO count, total sats.",
            body = PublisherHealthResponse),
        (status = 503, description = "Esplora-side error fetching publisher UTXOs. \
            The `detail` field carries the underlying client error string.",
            body = PublisherHealthErrorResponse),
    ),
)]
/// Operational preflight (`GET /health/publisher`).
///
/// Reads the publisher Taproot wallet's UTXO set via the configured
/// Esplora endpoint and reports `(address, utxo_count, total_sats)`.
/// The deploy-dev workflow probes this BEFORE running the API E2E
/// suite — an empty wallet would otherwise cause every mint to 503
/// and historically masked as a "green" run because the E2E suite
/// itself silently treated 5xx as a skip. Returning 503 on an
/// Esplora-side error is intentional: the operator should see the
/// failure mode, not a fabricated empty response.
pub(crate) async fn publisher_health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let publisher_address = crate::PUBLISHER_ADDRESS.clone();

    match crate::publisher::get_publisher_utxo(&publisher_address, &state.esplora_config, None)
        .await
    {
        Ok(utxos) => {
            let utxo_count = utxos.len() as u64;
            let total_sats: u64 = utxos.iter().map(|(_, sats)| sats).sum();
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(PublisherHealthResponse {
                        address: publisher_address.to_string(),
                        utxo_count,
                        total_sats,
                    })
                    .expect("publisher health response serializes"),
                ),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Esplora-side error fetching publisher UTXOs",
                "detail": e.to_string(),
                "address": publisher_address.to_string(),
            })),
        )
            .into_response(),
    }
}

/// Liveness probe (`GET /health`).
///
/// Returns `"ok"` with 200 as soon as the HTTP listener is bound and
/// the tokio runtime is alive. Deliberately does NOT touch the
/// database or Esplora — see [`ready_handler`] for the dependency
/// probe.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "HTTP listener is bound and the tokio runtime is alive. \
            Body is the literal text `ok`.",
            body = String, content_type = "text/plain"),
    ),
)]
pub(crate) async fn health_handler() -> &'static str {
    "ok"
}

/// Map the node's mainnet flag to the normalized, lowercase
/// `bitcoin_network` enum exposed in `/api/info`. Pure so both arms are
/// unit-testable without touching the env-derived `NETWORK_CONFIG`
/// global.
fn bitcoin_network_label(is_mainnet: bool) -> BitcoinNetwork {
    if is_mainnet {
        BitcoinNetwork::Mainnet
    } else {
        BitcoinNetwork::Mutinynet
    }
}

#[utoipa::path(
    get,
    path = "/api/info",
    tag = "Node",
    responses(
        (status = 200, description = "Node metadata: connected network, per-build \
            capability flags, and external username domain.",
            body = InfoResponse),
    ),
)]
pub(crate) async fn info_handler() -> impl IntoResponse {
    Json(InfoResponse {
        network: NETWORK_CONFIG.network_name.clone(),
        bitcoin_network: bitcoin_network_label(NETWORK_CONFIG.is_mainnet),
        capabilities: Capabilities {
            address_list: cfg!(feature = "address-list"),
            username_claim: cfg!(feature = "username-claim"),
            lnurl: cfg!(feature = "lnurl"),
            // Milestone 2: the node is a neutral, permissionless
            // multi-asset protocol — accounts are per-(owner, asset_id)
            // and the balance surface is per-asset.
            multi_asset: true,
        },
        username_domain: USERNAME_DOMAIN.clone(),
    })
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RootResponse {
    service: &'static str,
    version: &'static str,
    network: String,
    endpoints: RootEndpoints,
    docs: &'static str,
}

/// Endpoint map advertised by [`root_handler`]. Mirrors every
/// always-on route — feature-gated routes (address-list, username
/// claim, LNURL) are intentionally omitted because they are absent
/// from the default build. Meta routes (`/openapi.json`, `/docs`,
/// `/docs/{file}`) and admin endpoints (`/api/admin/*`) are also
/// omitted — the OpenAPI spec is the canonical map for those.
///
/// This type is the **single source of truth** for the pre-G6 / flag-off
/// closed endpoint set. It is registered in OpenAPI as a component
/// schema, so its field list must stay free of Gap-G6 attestation keys
/// (`skip_serializing_if` only hides runtime values, not schema
/// properties). Flag-on `GET /` serialises a separate ordered type
/// ([`RootEndpointsWithAttest`]); attest keys never appear here.
///
/// Serde field order **is** the wire order: never round-trip this type
/// through `serde_json::Value` (without `preserve_order`, `Value::Object`
/// is a sorted map and reorders keys).
#[derive(Serialize, ToSchema, Clone, Copy)]
pub(crate) struct RootEndpoints {
    info: &'static str,
    balance: &'static str,
    history: &'static str,
    receive: &'static str,
    admit_mint: &'static str,
    admit_send: &'static str,
    get_job: &'static str,
    stream_job: &'static str,
    commit: &'static str,
    sign: &'static str,
    cancel: &'static str,
    proof: &'static str,
    inscription: &'static str,
    username_resolve: &'static str,
    health: &'static str,
    health_ready: &'static str,
    health_publisher: &'static str,
    openapi: &'static str,
    docs: &'static str,
}

/// Flag-on endpoint map: pre-G6 closed set plus §7.5 attest keys inserted
/// after `username_resolve`. Not an OpenAPI component — schema stays on
/// [`RootEndpoints`]. Serialised in declaration order (same rule as
/// [`RootEndpoints`]: never via sorted `Value`).
#[derive(Serialize, Clone, Copy)]
struct RootEndpointsWithAttest {
    info: &'static str,
    balance: &'static str,
    history: &'static str,
    receive: &'static str,
    admit_mint: &'static str,
    admit_send: &'static str,
    get_job: &'static str,
    stream_job: &'static str,
    commit: &'static str,
    sign: &'static str,
    cancel: &'static str,
    proof: &'static str,
    inscription: &'static str,
    username_resolve: &'static str,
    attest_balance_challenge: &'static str,
    attest_balance: &'static str,
    health: &'static str,
    health_ready: &'static str,
    health_publisher: &'static str,
    openapi: &'static str,
    docs: &'static str,
}

/// Flag-on outer envelope — same field order as [`RootResponse`].
#[derive(Serialize)]
struct RootResponseWithAttest {
    service: &'static str,
    version: &'static str,
    network: String,
    endpoints: RootEndpointsWithAttest,
    docs: &'static str,
}

/// Canonical always-on endpoint map (pre-G6 / flag-off). Derived from
/// [`RootEndpoints`] so the handler, the OpenAPI component, and the
/// byte-identity tests share one type — not a hand-written second list.
pub(crate) fn root_endpoints_always_on() -> RootEndpoints {
    RootEndpoints {
        info: "GET  /api/info",
        balance: "GET  /api/balance?address={hex}",
        history: "GET  /api/history?address={hex}&limit={n}&offset={n}",
        receive: "POST /api/receive",
        admit_mint: "POST /api/jobs/mint",
        admit_send: "POST /api/jobs/send",
        get_job: "GET  /api/jobs/{job_id}",
        stream_job: "GET  /api/jobs/{job_id}/stream",
        commit: "POST /api/jobs/{job_id}/commit",
        sign: "POST /v1/jobs/{job_id}/sign",
        cancel: "POST /api/jobs/{job_id}/cancel",
        proof: "GET  /api/proof/{id}",
        inscription: "GET  /api/inscriptions/{txid}",
        username_resolve: "GET  /api/username/resolve/{username}",
        health: "GET  /health",
        health_ready: "GET  /health/ready",
        health_publisher: "GET  /health/publisher",
        openapi: "GET  /openapi.json",
        docs: "GET  /docs",
    }
}

/// Additive §7.5 extension of [`root_endpoints_always_on`].
fn root_endpoints_with_attest() -> RootEndpointsWithAttest {
    let b = root_endpoints_always_on();
    RootEndpointsWithAttest {
        info: b.info,
        balance: b.balance,
        history: b.history,
        receive: b.receive,
        admit_mint: b.admit_mint,
        admit_send: b.admit_send,
        get_job: b.get_job,
        stream_job: b.stream_job,
        commit: b.commit,
        sign: b.sign,
        cancel: b.cancel,
        proof: b.proof,
        inscription: b.inscription,
        username_resolve: b.username_resolve,
        attest_balance_challenge: "POST /v1/attest/balance/challenge",
        attest_balance: "POST /v1/attest/balance",
        health: b.health,
        health_ready: b.health_ready,
        health_publisher: b.health_publisher,
        openapi: b.openapi,
        docs: b.docs,
    }
}

#[utoipa::path(
    get,
    path = "/",
    tag = "Node",
    responses(
        (status = 200, description = "Service identification: package name + version, \
            connected network, public endpoint map, and a pointer to the hosted docs.",
            body = RootResponse),
    ),
)]
/// Root handler — anything hitting `https://api.zkcoins.app/` (browser visit,
/// uptime probe, curious operator) gets a small JSON identifying the service,
/// the package version, the connected network, and pointers to the real
/// endpoints. Cheaper than serving a static landing page and still answers the
/// "is this the right host?" question without surfacing a bare 404.
pub(crate) async fn root_handler() -> axum::response::Response {
    // Serialise ordered structs directly. Do **not** build via
    // `serde_json::json!` / `Value`: without `preserve_order`, object keys
    // are sorted and flag-off bytes diverge from the pre-G6 golden
    // (`service`/`version` first → alphabetical `docs`/`endpoints` first).
    // Attest keys live only on `RootEndpointsWithAttest` so the OpenAPI
    // `RootEndpoints` component schema stays pre-G6.
    if crate::v1::v1_attest_route_active() {
        Json(RootResponseWithAttest {
            service: "zkcoins-node",
            version: env!("CARGO_PKG_VERSION"),
            network: NETWORK_CONFIG.network_name.clone(),
            endpoints: root_endpoints_with_attest(),
            docs: "https://docs.zkcoins.com",
        })
        .into_response()
    } else {
        Json(RootResponse {
            service: "zkcoins-node",
            version: env!("CARGO_PKG_VERSION"),
            network: NETWORK_CONFIG.network_name.clone(),
            endpoints: root_endpoints_always_on(),
            docs: "https://docs.zkcoins.com",
        })
        .into_response()
    }
}

// --- Username & LNURL handlers ---

#[utoipa::path(
    post,
    path = "/api/username/claim",
    tag = "Usernames",
    request_body = ClaimUsernameRequest,
    responses(
        (status = 200, description = "Username claimed and bound to the address.",
            body = UsernameResponse),
        (status = 401, description = "Public key does not match address, signature \
            verification failed, or timestamp out of window.",
            body = LnurlErrorResponse),
        (status = 409, description = "Username already taken.",
            body = LnurlErrorResponse),
        (status = 422, description = "Malformed username, address, signature, or public key.",
            body = LnurlErrorResponse),
        (status = 503, description = "Database error while persisting the claim.",
            body = LnurlErrorResponse),
    ),
)]
#[cfg(feature = "username-claim")]
pub(crate) async fn claim_username_handler(
    State(state): State<AppState>,
    Json(request): Json<ClaimUsernameRequest>,
) -> impl IntoResponse {
    // Normalise the username up-front so the Schnorr signature, the
    // in-memory mirror, and the Postgres row all agree on the exact
    // byte string. Hashing the raw `request.username` while persisting
    // `to_lowercase()` lets a wallet that signs over `"Alice"` end up
    // squatting `"alice"` — see PR #76's prod-readiness review.
    let normalized_username = match crate::username::UsernameStore::validate(&request.username) {
        Ok(n) => n,
        Err(err) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: err.into(),
                }),
            )
                .into_response();
        }
    };

    // Decode address
    let address_vec = match hex::decode(request.address.trim_start_matches("0x")) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: "Invalid address hex".into(),
                }),
            )
                .into_response()
        }
    };
    let mut address_bytes = [0u8; 32];
    if address_vec.len() != 32 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Address must be 32 bytes".into(),
            }),
        )
            .into_response();
    }
    address_bytes.copy_from_slice(&address_vec);
    let address = digest_from_bytes(&address_bytes);

    // Verify public key matches address: sha256(compressed_pubkey) == address
    let pk_hash: [u8; 32] = Sha256::digest(request.public_key.serialize()).into();
    if pk_hash != address_bytes {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Public key does not match address".into(),
            }),
        )
            .into_response();
    }

    // Verify timestamp freshness (shared 5 min window with
    // `send_coin_handler`). Uses the same string the send path emits so
    // the app's `KNOWN_SERVER_ERRORS` mapping ladders identically.
    if let Err(e) = check_timestamp_window(request.timestamp) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: e.into(),
            }),
        )
            .into_response();
    }

    // Verify Schnorr signature over sha256("zkcoins:claim_username" || address_hex || normalised_username || timestamp_le).
    // The wallet MUST sign over the lowercase form (same normalisation
    // as `UsernameStore::validate`) — otherwise the same input that the
    // node persists is not what the signature commits to, opening
    // the case-mismatch squat described above.
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(request.address.as_bytes());
    hasher.update(normalized_username.as_bytes());
    hasher.update(request.timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let sig_bytes = match hex::decode(&request.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: "Invalid signature hex".into(),
                }),
            )
                .into_response()
        }
    };
    let sig = match SchnorrSignature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: "Invalid signature format".into(),
                }),
            )
                .into_response()
        }
    };
    let (xonly, _) = request.public_key.x_only_public_key();
    let secp = secp::Secp256k1::verification_only();
    if secp.verify_schnorr(&sig, &msg, &xonly).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Signature verification failed".into(),
            }),
        )
            .into_response();
    }

    // Claim path, three steps. The previous `mem::take` approach left
    // the in-memory `UsernameStore` observable as empty for the full
    // duration of the DB round-trip — every `resolve` / `get_username`
    // request in that window saw a blank mirror, including
    // `get_balance_handler`'s `username` lookup.
    //
    // Split design:
    //   1. short sync lock → `precheck` (read-only)
    //   2. drop lock → async `db::claim_username` (`ON CONFLICT DO NOTHING`)
    //   3. short sync lock → `commit_after_db` (in-memory insert)
    //
    // Reads concurrent with a claim now always see the full mirror.
    // Concurrent writers race at the SQL `ON CONFLICT` boundary as
    // before; the second writer hits `rows_affected == 0` and the
    // handler maps that to a 409. The post-commit insert is idempotent
    // — re-inserting the same `(normalized, address)` is a no-op.
    // Decode signature bytes once so the claim-log row carries the
    // exact signature bytes the caller submitted, regardless of the
    // outcome below.
    let signature_bytes = hex::decode(&request.signature).unwrap_or_default();

    // username_claim_log helper: fire-and-forget, captures every
    // outcome that reaches the in-memory / SQL layer (precheck reject,
    // SQL race-loser, success). Pure-validation rejects above are
    // already captured via request_log on the audit path.
    let log_claim = |success: bool, reject_reason: Option<&str>| {
        let entry = crate::db::UsernameClaimLogEntry {
            requested_username: request.username.clone(),
            normalized_username: normalized_username.clone(),
            address: address_bytes.to_vec(),
            signature: signature_bytes.clone(),
            success,
            reject_reason: reject_reason.map(|s| s.to_string()),
            request_log_id: None,
        };
        let pool = state.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::db::insert_username_claim_log(&pool, &entry).await {
                eprintln!("Failed to persist username_claim_log: {}", e);
            }
        });
    };

    if let Err(reason) =
        lock_or_recover(&state.username_store).precheck(&normalized_username, &address)
    {
        log_claim(false, Some(reason));
        // `precheck` returns the static collision strings the wallet
        // surfaces verbatim. The status is `409 CONFLICT` for either
        // collision variant — same shape as the SQL-layer race below.
        return (
            StatusCode::CONFLICT,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: reason.into(),
            }),
        )
            .into_response();
    }

    let addr_bytes = digest_to_bytes(&address);
    let inserted =
        match crate::db::claim_username(&state.pool, &normalized_username, &addr_bytes).await {
            Ok(b) => b,
            Err(db_err) => {
                eprintln!("Failed to persist username claim: {}", db_err);
                log_claim(false, Some(&format!("db error: {}", db_err)));
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(LnurlErrorResponse {
                        status: "ERROR".into(),
                        reason: "Failed to persist username claim".into(),
                    }),
                )
                    .into_response();
            }
        };
    if !inserted {
        log_claim(false, Some("race lost on ON CONFLICT"));
        // Concurrent claimer won the `ON CONFLICT` race for the same
        // name. Surface as the same 409 a precheck collision would.
        return (
            StatusCode::CONFLICT,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Username already taken".into(),
            }),
        )
            .into_response();
    }

    lock_or_recover(&state.username_store).commit_after_db(normalized_username.clone(), address);

    log_claim(true, None);

    (
        StatusCode::OK,
        Json(UsernameResponse {
            username: normalized_username,
            address: format!("0x{}", hex::encode(digest_to_bytes(&address))),
        }),
    )
        .into_response()
}

/// Resolve an identifier to an address via the **username store only**.
///
/// Stage 3 Runde 6 (C): the hex-prefix scan over `get_addresses()` is
/// removed — address knowledge / prefix matching is not a
/// `read.account` capability and leaked full rehydrated legacy addresses.
/// Username and LNURL resolve exclusively against claimed names.
fn resolve_identifier(
    state: &AppState,
    identifier: &str,
) -> Option<(zkcoins_program::hash::HashDigest, String)> {
    let normalized = identifier.to_lowercase();
    let username_store = lock_or_recover(&state.username_store);
    username_store
        .resolve(&normalized)
        .map(|address| (address, normalized))
}

#[utoipa::path(
    get,
    path = "/api/username/resolve/{username}",
    tag = "Usernames",
    params(
        ("username" = String, Path, description = "Username or hex address prefix to resolve"),
    ),
    responses(
        (status = 200, description = "Resolved address for the identifier.",
            body = UsernameResponse),
        (status = 404, description = "Identifier did not match any known username or address.",
            body = LnurlErrorResponse),
    ),
)]
pub(crate) async fn resolve_username_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match resolve_identifier(&state, &username) {
        Some((address, resolved_name)) => (
            StatusCode::OK,
            Json(UsernameResponse {
                username: resolved_name,
                address: format!("0x{}", hex::encode(digest_to_bytes(&address))),
            }),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Username not found".into(),
            }),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/.well-known/lnurlp/{username}",
    tag = "LNURL",
    params(
        ("username" = String, Path, description = "Username or hex address prefix"),
    ),
    responses(
        (status = 200, description = "LNURL-pay metadata per LUD-06.", body = LnurlpResponse),
        (status = 404, description = "Username not found.", body = LnurlErrorResponse),
    ),
)]
#[cfg(feature = "lnurl")]
pub(crate) async fn lnurlp_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if resolve_identifier(&state, &username).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "User not found".into(),
            }),
        )
            .into_response();
    }

    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("api.zkcoins.app");
    let scheme = if host.contains("localhost") {
        "http"
    } else {
        "https"
    };
    let normalized = username.to_lowercase();
    let callback = format!("{}://{}/lnurl/pay/{}", scheme, host, normalized);
    let metadata = format!(
        "[[\"text/plain\",\"Pay {} on zkCoins\"],[\"text/identifier\",\"{}@zkcoins.app\"]]",
        normalized, normalized
    );

    (
        StatusCode::OK,
        Json(LnurlpResponse {
            tag: "payRequest".into(),
            callback,
            min_sendable: 1_000,
            max_sendable: 1_000_000_000_000,
            metadata,
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/lnurl/pay/{username}",
    tag = "LNURL",
    params(
        ("username" = String, Path, description = "Username or hex address prefix"),
    ),
    responses(
        (status = 200, description = "LNURL-pay callback response. The current implementation \
            is a stub that always returns a phase-2 error.",
            body = LnurlErrorResponse),
    ),
)]
#[cfg(feature = "lnurl")]
pub(crate) async fn lnurl_callback_handler(
    State(_state): State<AppState>,
    Path(_username): Path<String>,
) -> impl IntoResponse {
    Json(LnurlErrorResponse {
        status: "ERROR".into(),
        reason: "Lightning payments coming soon (Phase 2)".into(),
    })
}

/// Build the full application router with all API routes, CORS, health check, and fallback.
/// Extracted so it can be reused in integration tests via `oneshot()`.
pub(crate) fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST])
        // `Idempotency-Key` is required by the jobs-API admit handlers
        // (`POST /api/jobs/{mint,send}`). A browser sending it triggers a
        // CORS preflight; without the header here the preflight fails and the
        // web frontend cannot mint or send.
        .allow_headers([
            header::CONTENT_TYPE,
            header::HeaderName::from_static("idempotency-key"),
        ]);

    // MVP routes — always compiled in.
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/health/ready", get(ready_handler))
        .route("/health/publisher", get(publisher_health_handler))
        .route("/api/info", get(info_handler))
        .route("/api/balance", get(get_balance_handler))
        .route("/api/balance/:address", get(get_owner_balance_handler))
        .route("/api/history", get(get_history_handler))
        // axum 0.7 path-param syntax (`:id`); the OpenAPI annotation uses
        // the spec's `{id}` form — both name the same segment.
        .route("/api/history/:id", get(get_history_item_handler))
        .route("/api/receive", post(receive_coin_handler))
        .route("/api/proof/:id", get(get_proof_handler))
        // Job-API routes — the only path through which a wallet
        // initiates a mint, builds a send proof, or attaches a
        // signed commitment. Replace the legacy
        // `/api/mint` / `/api/send` / `/api/commit` synchronous
        // endpoints (removed in PR1 of the Job-API refactor) so
        // every long-running unit of work is observable through
        // the same poll-based contract.
        .route("/api/jobs/mint", post(jobs_mint_handler))
        .route("/api/jobs/send", post(jobs_send_handler))
        .route("/api/jobs/:id", get(get_job_handler))
        .route("/api/jobs/:id/stream", get(stream_job_handler))
        .route("/api/jobs/:id/commit", post(jobs_commit_handler))
        // §7.5 normative surface (v1.1 claim). Legacy `/api/jobs/*` stays
        // as-is; the v1.1 sign + poll + stream + cancel envelopes live
        // under `/v1/` (never a bare framework 404 for a normative path).
        .route("/v1/jobs/:id", get(get_job_v1_handler))
        .route("/v1/jobs/:id/sign", post(jobs_sign_handler))
        .route("/v1/jobs/:id/stream", get(stream_job_v1_handler))
        .route("/v1/jobs/:id/cancel", post(jobs_cancel_v1_handler))
        // §7.5 Gap G6 — balance attestation (flag-gated inside handlers).
        .route(
            "/v1/attest/balance/challenge",
            post(attest_balance_challenge_handler),
        )
        .route("/v1/attest/balance", post(attest_balance_handler))
        .route("/api/jobs/:id/cancel", post(jobs_cancel_handler))
        .route("/api/inscriptions/:txid", get(get_inscription_handler))
        .route(
            "/api/username/resolve/:username",
            get(resolve_username_handler),
        )
        // Operator-facing R2 probe trend (see `r2_probe_history_handler`
        // doc-comment). Grouped under `/api/admin/` so it is visibly
        // separate from the user-facing surface.
        .route("/api/admin/r2-probe/history", get(r2_probe_history_handler))
        .route("/openapi.json", get(crate::openapi::openapi_json_handler))
        .route("/docs", get(crate::openapi::docs_handler))
        .route("/docs/:file", get(crate::openapi::swagger_asset_handler));

    // Gated routes — only compiled in when their Cargo feature is enabled.
    // With a feature off, the handler does not exist in the binary and the
    // route is not registered, so the endpoint returns 404 via the fallback
    // and there is no code path to execute.
    #[cfg(feature = "address-list")]
    let app = app.route("/api/address", get(get_address_handler));

    #[cfg(feature = "username-claim")]
    let app = app.route("/api/username/claim", post(claim_username_handler));

    #[cfg(feature = "lnurl")]
    let app = app
        .route("/.well-known/lnurlp/:username", get(lnurlp_handler))
        .route("/lnurl/pay/:username", get(lnurl_callback_handler));

    // Audit middleware sits OUTSIDE `with_state` because it carries its
    // own `State<AppState>` extractor. Layered after CORS so the audit
    // log records the final, CORS-decorated response — `Access-Control-*`
    // headers and all. The `from_fn_with_state` adapter clones the
    // state for every request (state itself is `Arc`-backed, so the
    // clone is cheap).
    app.with_state(state.clone())
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::audit::audit_log_middleware,
        ))
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
