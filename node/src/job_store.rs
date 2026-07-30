// Job-API state-layer wrapper around the `jobs` table (migration
// 0014).
//
// The Dispatcher (`crate::job_dispatcher`) drives each row through
// the `queued → proving → ... → completed | failed | cancelled`
// state machine. Routes admit (and idempotently replay) jobs
// through `create`; the dispatcher loads + advances them through
// the typed transition methods; the `GET /api/jobs/:id` handler
// reads back the most recent snapshot via `load`.
//
// Sqlx choice (mirrors `db.rs`): runtime-checked queries via
// `sqlx::query`, not the `query!` macro. Same rationale — no
// build-time Postgres / offline cache required, every query is
// covered by the testcontainers-backed `job_store_tests` suite.

use std::convert::TryFrom;
#[cfg(test)]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(test)]
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Coarse state-machine label persisted in `jobs.status`.
///
/// One-to-one with the CHECK enum in migration 0014. The discrete
/// terminal states (`Completed`, `Failed`, `Cancelled`) are what the
/// resumer uses to decide whether a row needs replay on boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Proving,
    AwaitingSignature,
    Broadcasting,
    Completed,
    Failed,
    Cancelled,
}

/// Result of an exclusive finalise claim on a job row.
///
/// `broadcasting` is not a permission label ("you may run the hook") — it is
/// an exclusive claim that exactly one resumer may hold. A loser must observe
/// [`FinaliseClaim::Lost`] and stop; continuing would double-apply /
/// double-complete side effects that status alone does not make idempotent.
///
/// Owner identity is **not** a write fence: the same process can reclaim after
/// its lease lapses and then hold a new claim under the same owner UUID. Durable
/// writes are gated on the [`FinaliseClaim::Won::fence`] token minted for this
/// acquisition plus a still-valid lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinaliseClaim {
    /// This caller won the CAS and owns finalise for the job.
    ///
    /// `fence` is a monotonic token unique to this acquisition epoch. Carry it
    /// into every durable write for this claim; a stale fence loses even when
    /// the owner identity still matches the current claim.
    Won {
        /// Monotonic fencing token from `finalise_claim_fence_seq`.
        fence: i64,
    },
    /// Another resumer holds (or held) the claim, or the job moved on.
    /// `observed` is the status after the failed CAS — never invent success.
    Lost { observed: JobStatus },
}

/// Acquisition fence for one exclusive finalise claim epoch.
///
/// Carry this into **every** durable write for the claim — job-row transitions
/// **and** the engine snapshot / `members_ready` stage. Owner identity alone
/// is not enough: after same-owner reclaim the old token must lose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinaliseFence {
    /// Job this claim was won for.
    pub job_id: Uuid,
    /// Process-generation owner recorded on the claim.
    pub owner: Uuid,
    /// Monotonic token from [`FinaliseClaim::Won::fence`].
    pub fence: i64,
}

/// Well-known error when a fenced durable stage refuses to commit because the
/// claim epoch is no longer current (or the lease expired). Callers must
/// quiet-exit — never terminal-fail a job another epoch may hold.
pub const FINALISE_FENCE_LOST: &str =
    "finalise_fence_lost: claim epoch no longer current or lease expired";

/// Phase string written when a resumer wins [`JobStore::claim_finalise_exclusive`].
/// Distinct from free-form `"publishing"` / `"broadcasting"` so a second
/// concurrent claim against an already-claimed row fails the CAS.
pub const FINALISE_CLAIM_PHASE: &str = "finalise_claimed";

/// JSON key under `jobs.request_body` for the exclusive finalise claim lease.
///
/// Shape:
/// `{ "owner": "<uuid>", "fence": <i64>, "lease_expires_at": "<RFC3339>" }`.
/// Written atomically with the phase CAS so a claim always has an owner, a
/// fencing token, and a lease.
pub const FINALISE_CLAIM_BODY_KEY: &str = "finalise_claim";

/// Default lease for a live finalise owner.
///
/// Sized for a multi-minute prove; a live owner renews (see
/// [`JobStore::renew_finalise_claim`]) **during** the long operation, not
/// only once at claim time. "Stale" means the lease has elapsed without
/// renew — evidence the owner abandoned the claim — not merely that the
/// phase is [`FINALISE_CLAIM_PHASE`].
pub const FINALISE_CLAIM_LEASE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How often a live owner re-extends [`FINALISE_CLAIM_LEASE`] while prove /
/// apply / durable stage is in flight.
///
/// Chosen as one third of the lease so several renewals fit inside the
/// window even under scheduler jitter; a lease that is only asserted once
/// at the start cannot outlive a multi-minute prove.
pub const FINALISE_CLAIM_RENEW_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5 * 60);

/// Bound on a single `renew_finalise_claim` await inside the lease heartbeat.
///
/// A hung database round-trip must count as liveness failure, not an
/// unbounded pause while prove/apply work continues past lease expiry.
/// Sized well under [`FINALISE_CLAIM_LEASE`] and under one renew interval.
pub const FINALISE_CLAIM_RENEW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Lease seconds as `i64` for Postgres `make_interval(secs => …)`.
fn lease_secs_i64(lease: std::time::Duration) -> i64 {
    i64::try_from(lease.as_secs()).expect("finalise claim lease seconds fit i64")
}

// Lease expiry uses PostgreSQL `NOW()` as the **sole** clock (create, renew,
// and release_stale all compare against the same source). See the SQL in
// [`JobStore::claim_finalise_exclusive_as`] / [`JobStore::renew_finalise_claim`].

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Proving => "proving",
            JobStatus::AwaitingSignature => "awaiting_signature",
            JobStatus::Broadcasting => "broadcasting",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Cancelled => "cancelled",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "queued" => Some(JobStatus::Queued),
            "proving" => Some(JobStatus::Proving),
            "awaiting_signature" => Some(JobStatus::AwaitingSignature),
            "broadcasting" => Some(JobStatus::Broadcasting),
            "completed" => Some(JobStatus::Completed),
            "failed" => Some(JobStatus::Failed),
            "cancelled" => Some(JobStatus::Cancelled),
            _ => None,
        }
    }

    /// `true` for `Completed | Failed | Cancelled` — the same set the
    /// `jobs_status_idx` partial index excludes. Resumer / queue-depth
    /// helpers use this to decide whether a row still needs work.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled
        )
    }
}

/// Kind enum persisted in `jobs.kind`.
///
/// Closed set matches the CHECK constraint (migration 0029):
/// `mint | send | attest_balance | receive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Mint,
    Send,
    /// §7.5 `POST /v1/attest/balance` — `C_balance` proving job (Gap G6).
    AttestBalance,
    /// §7.8 / §7.5 `kind == "receive"` — fold-in transition (migration 0029).
    Receive,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Mint => "mint",
            JobKind::Send => "send",
            JobKind::AttestBalance => "attest_balance",
            JobKind::Receive => "receive",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "mint" => Some(JobKind::Mint),
            "send" => Some(JobKind::Send),
            "attest_balance" => Some(JobKind::AttestBalance),
            "receive" => Some(JobKind::Receive),
            _ => None,
        }
    }
}

/// In-memory representation of a row in `jobs`.
///
/// Mirrors the column order in migration 0014. Decoded by
/// [`Job::from_row`] so every read site shares one decode path.
///
/// [`Debug`] redacts durable finalisation material in `request_body`
/// (`finalisation.capability_bincode_hex` holds bincode of a
/// [`zkcoins_prover::state_engine::FinalisationCapability`], which
/// embeds `op_secret`). Logging/`{:?}` on a `Job` must not print that key.
#[derive(Clone)]
pub struct Job {
    pub id: i64,
    pub public_id: Uuid,
    pub kind: JobKind,
    pub status: JobStatus,
    pub phase: String,
    pub account_address: [u8; 32],
    pub idempotency_key: Option<String>,
    pub request_body: serde_json::Value,
    pub response_body: Option<serde_json::Value>,
    pub response_status: Option<i16>,
    pub proof_id: Option<i64>,
    pub error: Option<String>,
    pub progress: i16,
    /// Self-heal admission epoch stamped at INSERT from a locked read of
    /// `self_heal_reset_meta.generation` (see migration 0023). Job-advancing
    /// writes re-lock that row and require `reset_generation = $locked`.
    pub reset_generation: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job")
            .field("id", &self.id)
            .field("public_id", &self.public_id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("phase", &self.phase)
            .field("account_address", &self.account_address)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_body", &RedactedJobJson(&self.request_body))
            .field(
                "response_body",
                &self.response_body.as_ref().map(RedactedJobJson),
            )
            .field("response_status", &self.response_status)
            .field("proof_id", &self.proof_id)
            .field("error", &self.error)
            .field("progress", &self.progress)
            .field("reset_generation", &self.reset_generation)
            .field("reset_generation", &self.reset_generation)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("completed_at", &self.completed_at)
            .finish()
    }
}

/// `Debug` wrapper that redacts `finalisation.capability_bincode_hex` (and
/// the legacy `pending_sign` key) so `op_secret` inside the bincode blob
/// never appears in log/panic output.
struct RedactedJobJson<'a>(&'a serde_json::Value);

impl std::fmt::Debug for RedactedJobJson<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match redact_job_json_for_debug(self.0.clone()) {
            Ok(v) => write!(f, "{v:?}"),
            Err(_) => f.write_str("<request_body redaction failed>"),
        }
    }
}

fn redact_job_json_for_debug(mut body: serde_json::Value) -> Result<serde_json::Value, ()> {
    const REDACTED: &str = "[REDACTED]";
    if let Some(obj) = body.as_object_mut() {
        for key in ["finalisation", "pending_sign"] {
            if let Some(slot) = obj.get_mut(key) {
                if let Some(inner) = slot.as_object_mut() {
                    if inner.contains_key("capability_bincode_hex") {
                        inner.insert(
                            "capability_bincode_hex".to_string(),
                            serde_json::Value::String(REDACTED.to_string()),
                        );
                    }
                } else {
                    *slot = serde_json::Value::String(REDACTED.to_string());
                }
            }
        }
    }
    Ok(body)
}

impl Job {
    /// Decode a `jobs` row using the `SELECT *` column order so the
    /// helper is shared across `create`, `load`, `load_by_idem`, and
    /// `list_non_terminal_for_resume`. Any future migration that
    /// adds a column lands in exactly one decode site.
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let kind_str: String = row.try_get("kind")?;
        let status_str: String = row.try_get("status")?;
        let addr_bytes: Vec<u8> = row.try_get("account_address")?;
        let addr_arr: [u8; 32] = <[u8; 32]>::try_from(addr_bytes.as_slice()).map_err(|_| {
            sqlx::Error::Decode(
                format!(
                    "jobs.account_address has unexpected length {} (expected 32)",
                    addr_bytes.len()
                )
                .into(),
            )
        })?;
        let kind = JobKind::from_db_str(&kind_str).ok_or_else(|| {
            sqlx::Error::Decode(format!("unknown jobs.kind: {}", kind_str).into())
        })?;
        let status = JobStatus::from_db_str(&status_str).ok_or_else(|| {
            sqlx::Error::Decode(format!("unknown jobs.status: {}", status_str).into())
        })?;
        Ok(Job {
            id: row.try_get("id")?,
            public_id: row.try_get("public_id")?,
            kind,
            status,
            phase: row.try_get("phase")?,
            account_address: addr_arr,
            idempotency_key: row.try_get("idempotency_key")?,
            request_body: row.try_get("request_body")?,
            response_body: row.try_get("response_body")?,
            response_status: row.try_get("response_status")?,
            proof_id: row.try_get("proof_id")?,
            error: row.try_get("error")?,
            progress: row.try_get("progress")?,
            reset_generation: row.try_get("reset_generation")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            completed_at: row.try_get("completed_at")?,
        })
    }
}

/// Result of an admit-side [`JobStore::create`] call.
///
/// Stripe-style idempotency: if the caller supplied an
/// `Idempotency-Key` and the `(account, key)` pair already exists,
/// the existing row is returned via the `IdempotentReplay` variant
/// without inserting a second one **only when the admit body matches**
/// (see [`admit_bodies_equal_for_idempotency`]). A same-key request
/// with a **different** body is [`CreateResult::IdempotencyConflict`]
/// (§7.5 `409 idempotency_conflict`) — never a silent replay of the
/// first request's job.
#[derive(Debug, Clone)]
pub enum CreateResult {
    /// A brand-new row was inserted; the dispatcher should pick it up.
    Fresh(Job),
    /// An existing row matched the `(account, idempotency_key)` pair
    /// **and** the admit body (after stripping server-owned keys).
    /// The caller MUST return the cached response (if any) instead of
    /// enqueuing a second copy.
    IdempotentReplay(Job),
    /// Same `(account, idempotency_key)` as an existing row, but the
    /// admit body is not equal under
    /// [`admit_bodies_equal_for_idempotency`]. No row was inserted.
    /// Map to §7.5 `idempotency_conflict` (HTTP 409).
    IdempotencyConflict,
}

/// Server-owned keys merged into `jobs.request_body` **after** admit.
///
/// Cancel / complete / finalise paths strip these
/// (`finalisation`, `pending_sign`, `sign`, `finalise_claim`). An
/// idempotency retry must not treat their absence (or transient
/// presence) as a different client body.
pub const REQUEST_BODY_SERVER_KEYS: &[&str] =
    &["finalisation", "pending_sign", "sign", "finalise_claim"];

/// Strip server-owned keys from a stored or inbound `request_body` so
/// idempotency compares the **client admit payload** only.
///
/// # Equality procedure (normative for this node)
///
/// 1. Clone the JSON value.
/// 2. If it is a JSON object, remove every key in
///    [`REQUEST_BODY_SERVER_KEYS`] (no-op when already absent).
/// 3. Compare the resulting [`serde_json::Value`] with `==`
///    (object key order independent; array order and scalar values
///    matter; unknown client fields are retained).
///
/// This is **not** a raw HTTP-byte compare (whitespace / key order would
/// false-conflict) and **not** a typed re-parse that drops unknown
/// fields. What is stored is the admit-time `jsonb`; equality is the
/// structural JSON value after removing only the documented
/// server-owned keys.
pub fn strip_server_keys_from_request_body(body: &serde_json::Value) -> serde_json::Value {
    let mut stripped = body.clone();
    if let Some(obj) = stripped.as_object_mut() {
        for key in REQUEST_BODY_SERVER_KEYS {
            obj.remove(*key);
        }
    }
    stripped
}

/// `true` when two admit bodies are the same client payload under
/// [`strip_server_keys_from_request_body`].
pub fn admit_bodies_equal_for_idempotency(
    stored: &serde_json::Value,
    incoming: &serde_json::Value,
) -> bool {
    strip_server_keys_from_request_body(stored) == strip_server_keys_from_request_body(incoming)
}

/// Postgres-backed handle on the `jobs` table.
///
/// Cheap to clone via the inner `PgPool` (which is itself
/// `Arc`-shaped) so the dispatcher, the resumer, and every route
/// handler can each hold a `JobStore` without coordinating.
///
/// `process_owner` is a process-generation identity for exclusive finalise
/// claims: clones of the same store share it; a distinct [`Self::new`] (or
/// [`Self::with_process_owner`]) is a different owner.
#[derive(Clone)]
pub struct JobStore {
    pool: PgPool,
    /// Process-generation token written into every won finalise claim.
    process_owner: Uuid,
    /// Test-only load fault budget. `-1` = unlimited (default). When
    /// non-negative, each successful `load` decrements; at `0` further
    /// loads return a synthetic error. Shared across [`Clone`]s so an
    /// `Arc<JobStore>` arming reaches the same store instance used by
    /// domain code.
    #[cfg(test)]
    test_load_ok_budget: Arc<AtomicI32>,
}

impl JobStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            process_owner: Uuid::new_v4(),
            #[cfg(test)]
            test_load_ok_budget: Arc::new(AtomicI32::new(-1)),
        }
    }

    /// Construct with an explicit process owner (tests that plant a live
    /// claim under a known identity).
    #[cfg(test)]
    pub fn with_process_owner(pool: PgPool, process_owner: Uuid) -> Self {
        Self {
            pool,
            process_owner,
            test_load_ok_budget: Arc::new(AtomicI32::new(-1)),
        }
    }

    /// Arm load failures after `ok_count` successful `load` calls.
    ///
    /// `ok_count = 1` lets CancelJob's pre-check load succeed while any
    /// post-cancel reload would fail — used to prove a successful cancel
    /// is never reported as a store/reload error.
    #[cfg(test)]
    pub fn arm_load_failures_after_ok_count(&self, ok_count: i32) {
        self.test_load_ok_budget.store(ok_count, Ordering::SeqCst);
    }

    /// Clear any armed load-failure budget (unlimited loads again).
    #[cfg(test)]
    pub fn disarm_load_failures(&self) {
        self.test_load_ok_budget.store(-1, Ordering::SeqCst);
    }

    /// Borrow the underlying pool — needed by callers that thread
    /// existing transactions (idempotent reply body lookups) through
    /// the same connection.
    #[cfg(test)]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Process-generation identity this store uses as finalise claim owner.
    pub fn process_owner(&self) -> Uuid {
        self.process_owner
    }

    /// Open a transaction and lock the live self-heal generation.
    ///
    /// **Locking construct (shared with admit + reset):**
    /// `SELECT generation FROM self_heal_reset_meta WHERE id = 1 FOR UPDATE`
    /// takes a conflicting row lock with
    /// [`crate::db::bump_self_heal_reset_generation_in_tx`]'s `UPDATE … generation
    /// = generation + 1`. Every job-advancing write **must** read generation
    /// through this locked path and bind the returned value into the UPDATE
    /// predicate (`reset_generation = $N`). An unlocked scalar subquery
    /// `reset_generation = (SELECT generation …)` is **not** a fence: under
    /// MVCC a statement that began before a concurrent reset committed can
    /// still see the pre-bump generation after the jobs-row lock is released,
    /// resurrect a reset-failed job, and report `rows_affected() == 1`.
    async fn begin_with_locked_generation(
        &self,
    ) -> sqlx::Result<(sqlx::Transaction<'_, sqlx::Postgres>, i64)> {
        let mut tx = self.pool.begin().await?;
        let (generation,): (i64,) =
            sqlx::query_as("SELECT generation FROM self_heal_reset_meta WHERE id = 1 FOR UPDATE")
                .fetch_one(&mut *tx)
                .await?;
        Ok((tx, generation))
    }

    /// Admit a fresh job.
    ///
    /// Stripe-style idempotency: when `idem_key` is `Some` and the
    /// `(account, key)` pair already exists:
    /// - **same body** (see [`admit_bodies_equal_for_idempotency`]) →
    ///   `CreateResult::IdempotentReplay` (no second row);
    /// - **different body** → `CreateResult::IdempotencyConflict`
    ///   (§7.5; no second row, no silent reuse of the first job).
    ///
    /// When `idem_key` is `None`, every call inserts a fresh row.
    ///
    /// The INSERT uses `ON CONFLICT (account_address, idempotency_key)
    /// DO NOTHING` — the partial UNIQUE index from migration 0014
    /// only fires when the key column is present, so the conflict
    /// arm is reachable only for caller-supplied keys.
    ///
    /// Body comparison runs **inside the same transaction** that holds
    /// the self-heal generation lock and `SELECT … FOR UPDATE` on the
    /// existing jobs row, so there is no window between "read stored
    /// body" and "decide replay vs conflict" under concurrent
    /// finalisation-key rewrites.
    pub async fn create(
        &self,
        kind: JobKind,
        account: &[u8; 32],
        idem_key: Option<&str>,
        request_body: serde_json::Value,
    ) -> sqlx::Result<CreateResult> {
        // Mutual exclusion with self-heal reset (not mere ordering):
        // see [`Self::begin_with_locked_generation`].
        let (mut tx, generation) = self.begin_with_locked_generation().await?;

        let public_id = Uuid::new_v4();
        let inserted_row = sqlx::query(
            "INSERT INTO jobs \
             (public_id, kind, status, phase, account_address, idempotency_key, request_body, \
              reset_generation) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (account_address, idempotency_key) \
                 WHERE idempotency_key IS NOT NULL \
                 DO NOTHING \
             RETURNING *",
        )
        .bind(public_id)
        .bind(kind.as_str())
        .bind(JobStatus::Queued.as_str())
        .bind("queued")
        .bind(&account[..])
        .bind(idem_key)
        .bind(&request_body)
        .bind(generation)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = inserted_row {
            tx.commit().await?;
            return Job::from_row(&row).map(CreateResult::Fresh);
        }

        // Conflict path: an existing row with the same
        // `(account_address, idempotency_key)` already exists. The
        // INSERT's `DO NOTHING` swallowed the second insert; lock the
        // original row, compare admit bodies, then surface replay or
        // idempotency_conflict.
        let existing = sqlx::query(
            "SELECT * FROM jobs \
             WHERE account_address = $1 AND idempotency_key = $2 \
             FOR UPDATE",
        )
        .bind(&account[..])
        .bind(idem_key)
        .fetch_one(&mut *tx)
        .await?;
        let existing_job = Job::from_row(&existing)?;
        if !admit_bodies_equal_for_idempotency(&existing_job.request_body, &request_body) {
            tx.commit().await?;
            return Ok(CreateResult::IdempotencyConflict);
        }
        tx.commit().await?;
        Ok(CreateResult::IdempotentReplay(existing_job))
    }

    /// Load a single job by its public UUID. Returns `Ok(None)` if
    /// no row matches.
    pub async fn load(&self, public_id: Uuid) -> sqlx::Result<Option<Job>> {
        #[cfg(test)]
        {
            // Budget semantics: -1 unlimited; 0 fail immediately; n>0 allow
            // n successes then fail. fetch_sub on a positive budget is the
            // decrement; when the pre-decrement value was 0 we fail.
            let budget = self.test_load_ok_budget.load(Ordering::SeqCst);
            if budget == 0 {
                return Err(sqlx::Error::Protocol(
                    "test-injected JobStore::load failure".into(),
                ));
            }
            if budget > 0 {
                // If two loads race, both may pass one slot — tests arm this
                // under single-threaded cancel paths only.
                self.test_load_ok_budget.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let row = sqlx::query("SELECT * FROM jobs WHERE public_id = $1")
            .bind(public_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Job::from_row(&r).map(Some),
            None => Ok(None),
        }
    }

    /// Look up a job by `(account, idempotency_key)`. Used by the
    /// admit handler's pre-INSERT check on the legacy-replay path.
    #[cfg(test)]
    pub async fn load_by_idem(
        &self,
        account: &[u8; 32],
        idem_key: &str,
    ) -> sqlx::Result<Option<Job>> {
        let row = sqlx::query(
            "SELECT * FROM jobs \
             WHERE account_address = $1 AND idempotency_key = $2",
        )
        .bind(&account[..])
        .bind(idem_key)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Job::from_row(&r).map(Some),
            None => Ok(None),
        }
    }

    /// Advance a job to the supplied status + phase **only from** `from`.
    ///
    /// The phase is a free-form refinement of the coarse status enum so the
    /// dispatcher can publish dispatch-level progress milestones without
    /// churning the constraint-enforced status.
    ///
    /// **Compare-and-set:** `WHERE status = $from` is the primary guard
    /// against same-generation races (e.g. a late `queued → proving` after
    /// another process already reached `broadcasting` / finalise claim).
    /// Generation alone does not order concurrent writers within one epoch.
    ///
    /// **Lock + fence:** acquires [`Self::begin_with_locked_generation`]
    /// then binds the locked generation into the UPDATE.
    ///
    /// **Claim defence-in-depth:** never mutates a row whose phase is
    /// [`FINALISE_CLAIM_PHASE`] — even when `from` would otherwise match
    /// `broadcasting`. Terminal complete/fail of a claimed epoch must go
    /// through the fence-qualified APIs.
    ///
    /// Returns `Ok(true)` when exactly one row was updated, `Ok(false)`
    /// when zero rows matched (wrong status, claim phase, stale generation,
    /// missing job). Callers **must** act on `false` — never treat a no-op
    /// write as success and continue side effects against possibly wiped
    /// or foreign state. A miss is not a caller error: someone else moved
    /// the job; log and stop without inventing success.
    pub async fn set_status(
        &self,
        public_id: Uuid,
        from: JobStatus,
        status: JobStatus,
        phase: &str,
    ) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = $1, phase = $2, updated_at = NOW() \
             WHERE public_id = $3 \
               AND status = $4 \
               AND phase IS DISTINCT FROM $5 \
               AND reset_generation = $6",
        )
        .bind(status.as_str())
        .bind(phase)
        .bind(public_id)
        .bind(from.as_str())
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Move a `send` job to `awaiting_signature` and persist the
    /// `proof_id` produced by the dispatcher together with the `result`
    /// JSON the wallet needs to sign.
    ///
    /// `result` carries the `account_state_hash` / `output_coins_root`
    /// hex (see `flow::SendCommitHashes`) so a thin pure-TypeScript
    /// wallet can build the commitment without decoding the binary
    /// `CoinProof` blob `GET /api/proof/{id}` serves. It is stored in
    /// the same `response_body` column the terminal `complete` body
    /// later overwrites, and surfaced on the `awaiting_signature`
    /// `GET /api/jobs/:id` snapshot + SSE phase event. The `proof_id`
    /// is read back by `POST /api/jobs/:id/commit` to look the proof up.
    ///
    /// Returns `Ok(true)` when one row advanced, `Ok(false)` on zero rows
    /// (status CAS miss, generation fence, or missing job). Callers must
    /// act on `false` — no silent fallback.
    pub async fn set_awaiting_signature(
        &self,
        public_id: Uuid,
        proof_id: i64,
        result: serde_json::Value,
    ) -> sqlx::Result<bool> {
        // Only advance from proving (or queued, defensive). Never overwrite
        // a cancelled / terminal row — cancel may have won during prove.
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let q = sqlx::query(
            "UPDATE jobs SET status = 'awaiting_signature', phase = 'awaiting_signature', \
                              proof_id = $1, response_body = $2, updated_at = NOW() \
             WHERE public_id = $3 \
               AND status IN ('queued', 'proving') \
               AND reset_generation = $4",
        )
        .bind(proof_id)
        .bind(&result)
        .bind(public_id)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(q.rows_affected() == 1)
    }

    /// Move a job to the `completed` terminal state **only from** `from`.
    /// Stamps the cached response body + status code so an idempotent
    /// replay returns byte-identical JSON.
    ///
    /// Atomically strips durable finalisation keys from `request_body`
    /// (`finalisation`, legacy `pending_sign` / `sign`): a terminal row
    /// must not retain a restart envelope that boot recovery could treat
    /// as live work.
    ///
    /// **Compare-and-set:** requires `status = $from`. Claim defence-in-depth:
    /// never completes a row under [`FINALISE_CLAIM_PHASE`] — use
    /// [`Self::complete_if_finalise_owner`] for the fenced host edge.
    ///
    /// Returns `Ok(true)` when one row completed, `Ok(false)` when zero
    /// rows matched. Callers **must** act on `false` — never publish a
    /// `completed` event / result against a row that did not advance.
    pub async fn complete(
        &self,
        public_id: Uuid,
        from: JobStatus,
        response_body: serde_json::Value,
        response_status: i16,
    ) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', \
                              response_body = $1, response_status = $2, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              progress = 100, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $3 \
               AND status = $4 \
               AND phase IS DISTINCT FROM $5 \
               AND reset_generation = $6",
        )
        .bind(&response_body)
        .bind(response_status)
        .bind(public_id)
        .bind(from.as_str())
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Status-qualified complete: only applies when the row is still in
    /// one of `expected` **and** is not under an exclusive finalise claim.
    /// Returns `true` if the row was updated.
    ///
    /// Used for pre-claim / status-only paths. Once a row is
    /// [`FINALISE_CLAIM_PHASE`], terminal complete must go through
    /// [`Self::complete_if_finalise_owner`] (token + lease fence).
    #[cfg(test)]
    pub async fn complete_if_status(
        &self,
        public_id: Uuid,
        expected: &[JobStatus],
        response_body: serde_json::Value,
        response_status: i16,
    ) -> sqlx::Result<bool> {
        if expected.is_empty() {
            return Ok(false);
        }
        let statuses: Vec<String> = expected.iter().map(|s| s.as_str().to_string()).collect();
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', \
                              response_body = $1, response_status = $2, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              progress = 100, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $3 AND status = ANY($4::text[]) \
               AND phase IS DISTINCT FROM $5 \
               AND reset_generation = $6",
        )
        .bind(&response_body)
        .bind(response_status)
        .bind(public_id)
        .bind(&statuses)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Fence-qualified complete: the durable host-edge write.
    ///
    /// Applies only while the claim epoch identified by `fence` is still
    /// current **and** the lease has not expired:
    /// `broadcasting` + [`FINALISE_CLAIM_PHASE`] + matching
    /// `request_body.finalise_claim.fence` + `lease_expires_at > NOW()`.
    ///
    /// Owner identity is recorded on the claim for renew/audit but is
    /// **not** sufficient alone: after same-owner reclaim a stale fence
    /// must lose. A current fence with an expired lease must also lose.
    pub async fn complete_if_finalise_owner(
        &self,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        response_body: serde_json::Value,
        response_status: i16,
    ) -> sqlx::Result<bool> {
        let owner_text = owner.to_string();
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', \
                              response_body = $1, response_status = $2, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              progress = 100, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $3 \
               AND status = 'broadcasting' \
               AND phase = $4 \
               AND request_body #>> '{finalise_claim,owner}' = $5 \
               AND (request_body #>> '{finalise_claim,fence}')::bigint = $6 \
               AND (request_body #>> '{finalise_claim,lease_expires_at}') IS NOT NULL \
               AND (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz > NOW() \
               AND reset_generation = $7",
        )
        .bind(&response_body)
        .bind(response_status)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&owner_text)
        .bind(fence)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Move a job to the `failed` terminal state **only from** `from`,
    /// with an error message. The wallet surfaces `error` verbatim in the
    /// `KNOWN_SERVER_ERRORS` mapping table.
    ///
    /// Atomically strips durable finalisation keys from `request_body`
    /// with the status flip so a failed cleanup path cannot leave a
    /// restart envelope on a terminal row.
    ///
    /// **Compare-and-set:** requires `status = $from`. Claim defence-in-depth:
    /// never fails a row under [`FINALISE_CLAIM_PHASE`] — use
    /// [`Self::fail_if_finalise_owner`] for a claimed epoch.
    ///
    /// Returns `Ok(true)` when one row failed, `Ok(false)` on zero rows.
    /// Callers must act on `false` (no silent fallback, no invented event).
    pub async fn fail(&self, public_id: Uuid, from: JobStatus, error: &str) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2 \
               AND status = $3 \
               AND phase IS DISTINCT FROM $4 \
               AND reset_generation = $5",
        )
        .bind(error)
        .bind(public_id)
        .bind(from.as_str())
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Status-qualified fail for **unclaimed** rows only.
    ///
    /// Applies when the row is still in one of `expected` **and** is not
    /// under an exclusive finalise claim (`phase IS DISTINCT FROM`
    /// [`FINALISE_CLAIM_PHASE`]). A terminal fail of a claimed row must go
    /// through [`Self::fail_if_finalise_owner`] (token + lease fence).
    /// Listing `broadcasting` here cannot terminate an owned epoch.
    pub async fn fail_if_status(
        &self,
        public_id: Uuid,
        expected: &[JobStatus],
        error: &str,
    ) -> sqlx::Result<bool> {
        if expected.is_empty() {
            return Ok(false);
        }
        let statuses: Vec<String> = expected.iter().map(|s| s.as_str().to_string()).collect();
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2 AND status = ANY($3::text[]) \
               AND phase IS DISTINCT FROM $4 \
               AND reset_generation = $5",
        )
        .bind(error)
        .bind(public_id)
        .bind(&statuses)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Fence-qualified fail: only while the claim epoch identified by `fence`
    /// is current and the lease is unexpired. Same fence as
    /// [`Self::complete_if_finalise_owner`].
    pub async fn fail_if_finalise_owner(
        &self,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        error: &str,
    ) -> sqlx::Result<bool> {
        let owner_text = owner.to_string();
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2 \
               AND status = 'broadcasting' \
               AND phase = $3 \
               AND request_body #>> '{finalise_claim,owner}' = $4 \
               AND (request_body #>> '{finalise_claim,fence}')::bigint = $5 \
               AND (request_body #>> '{finalise_claim,lease_expires_at}') IS NOT NULL \
               AND (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz > NOW() \
               AND reset_generation = $6",
        )
        .bind(error)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&owner_text)
        .bind(fence)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Exclusive claim of a job for v1.1 finalise (prove → apply → host
    /// §7.5 job result → complete). See [`crate::job_dispatcher`] for the
    /// documented host edge vs on-chain AggregateStateNullifierV3 publish.
    ///
    /// `broadcasting` is a **claim**, not a permission label: exactly one
    /// resumer may win. Two concurrent readers of `awaiting_signature` both
    /// attempt this CAS; only one sees [`FinaliseClaim::Won`].
    ///
    /// The winner's [`Self::process_owner`], a fresh monotonic fencing token
    /// (from `finalise_claim_fence_seq`), and a lease ([`FINALISE_CLAIM_LEASE`])
    /// are written into `request_body.finalise_claim` atomically with the
    /// phase CAS. A live owner renews the lease under the same fence; boot
    /// may release only when the lease has expired (owner abandoned).
    ///
    /// | Prior status / phase | Outcome |
    /// |---------------------|---------|
    /// | `awaiting_signature` | CAS → `broadcasting` + [`FINALISE_CLAIM_PHASE`] + owner/fence/lease; [`FinaliseClaim::Won`] |
    /// | `broadcasting` + unclaimed phase (`publishing` / `broadcasting`) | CAS phase + owner/fence/lease; [`FinaliseClaim::Won`] |
    /// | `broadcasting` + already [`FINALISE_CLAIM_PHASE`] (any owner) | [`FinaliseClaim::Lost`] |
    /// | terminal / other | [`FinaliseClaim::Lost`] with the observed status |
    ///
    /// Crash recovery: boot calls [`Self::release_stale_finalise_claim`] and
    /// **honours** the result before re-enqueue: `Ok(true)` or an already-free
    /// phase → enqueue; `Ok(false)` while still [`FINALISE_CLAIM_PHASE`] → do
    /// not enqueue as free (deferred reclaim waits for abandonment). Release
    /// only succeeds when the lease is expired (or no lease was ever
    /// registered — abandoned pre-lease / corrupt claim). A live concurrent
    /// loser **must not** continue into side-effectful finalise.
    pub async fn claim_finalise_exclusive(&self, public_id: Uuid) -> sqlx::Result<FinaliseClaim> {
        self.claim_finalise_exclusive_as(public_id, self.process_owner, FINALISE_CLAIM_LEASE)
            .await
    }

    /// Claim with an explicit owner + lease (tests; production uses
    /// [`Self::claim_finalise_exclusive`]).
    pub async fn claim_finalise_exclusive_as(
        &self,
        public_id: Uuid,
        owner: Uuid,
        lease: std::time::Duration,
    ) -> sqlx::Result<FinaliseClaim> {
        let path = vec![FINALISE_CLAIM_BODY_KEY.to_string()];
        let owner_text = owner.to_string();
        let lease_secs = lease_secs_i64(lease);
        let (mut tx, generation) = self.begin_with_locked_generation().await?;

        // Path A: fresh claim from awaiting_signature.
        // `lease_expires_at` is `NOW() + lease` — Postgres clock only (the
        // same clock `release_stale_finalise_claim` uses for `<= NOW()`).
        // `fence` is a fresh nextval — unique per acquisition, not per owner.
        let row = sqlx::query(
            "UPDATE jobs SET status = $1, phase = $2, \
                    request_body = jsonb_set( \
                        COALESCE(request_body, '{}'::jsonb), \
                        $3::text[], \
                        jsonb_build_object( \
                            'owner', $4::text, \
                            'fence', nextval('finalise_claim_fence_seq'), \
                            'lease_expires_at', \
                                NOW() + make_interval(secs => $5::double precision) \
                        ), \
                        true \
                    ), \
                    updated_at = NOW() \
             WHERE public_id = $6 AND status = $7 \
               AND reset_generation = $8 \
             RETURNING (request_body #>> '{finalise_claim,fence}')::bigint AS fence",
        )
        .bind(JobStatus::Broadcasting.as_str())
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&path)
        .bind(&owner_text)
        .bind(lease_secs as f64)
        .bind(public_id)
        .bind(JobStatus::AwaitingSignature.as_str())
        .bind(generation)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = row {
            let fence: i64 = row.try_get("fence")?;
            tx.commit().await?;
            return Ok(FinaliseClaim::Won { fence });
        }

        // Path B: crash-resume while already broadcasting with an unclaimed
        // phase. Rows still at FINALISE_CLAIM_PHASE are owned — refuse
        // regardless of who the stored owner is (lease release is separate).
        let row = sqlx::query(
            "UPDATE jobs SET phase = $1, \
                    request_body = jsonb_set( \
                        COALESCE(request_body, '{}'::jsonb), \
                        $2::text[], \
                        jsonb_build_object( \
                            'owner', $3::text, \
                            'fence', nextval('finalise_claim_fence_seq'), \
                            'lease_expires_at', \
                                NOW() + make_interval(secs => $4::double precision) \
                        ), \
                        true \
                    ), \
                    updated_at = NOW() \
             WHERE public_id = $5 \
               AND status = 'broadcasting' \
               AND phase IN ('publishing', 'broadcasting') \
               AND reset_generation = $6 \
             RETURNING (request_body #>> '{finalise_claim,fence}')::bigint AS fence",
        )
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&path)
        .bind(&owner_text)
        .bind(lease_secs as f64)
        .bind(public_id)
        .bind(generation)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = row {
            let fence: i64 = row.try_get("fence")?;
            tx.commit().await?;
            return Ok(FinaliseClaim::Won { fence });
        }

        let status = match sqlx::query("SELECT status FROM jobs WHERE public_id = $1")
            .bind(public_id)
            .fetch_optional(&mut *tx)
            .await?
        {
            Some(r) => {
                let s: String = r.try_get("status")?;
                JobStatus::from_db_str(&s).unwrap_or(JobStatus::Failed)
            }
            None => JobStatus::Failed,
        };
        tx.commit().await?;
        Ok(FinaliseClaim::Lost { observed: status })
    }

    /// Extend the lease of a claim this process already owns **for this fence**.
    ///
    /// Writes `lease_expires_at = NOW() + lease` (Postgres clock — same
    /// source as claim create and stale release) while preserving `owner` and
    /// `fence`. Returns `true` only when the row is still `broadcasting` /
    /// [`FINALISE_CLAIM_PHASE`], owner matches, and fence matches. A stale
    /// epoch (same owner, old fence after reclaim) cannot renew the new claim.
    pub async fn renew_finalise_claim(
        &self,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        lease: std::time::Duration,
    ) -> sqlx::Result<bool> {
        let path = vec![FINALISE_CLAIM_BODY_KEY.to_string()];
        let owner_text = owner.to_string();
        let lease_secs = lease_secs_i64(lease);
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET request_body = jsonb_set( \
                    COALESCE(request_body, '{}'::jsonb), \
                    $1::text[], \
                    jsonb_build_object( \
                        'owner', $2::text, \
                        'fence', $3::bigint, \
                        'lease_expires_at', \
                            NOW() + make_interval(secs => $4::double precision) \
                    ), \
                    true \
                ), \
                    updated_at = NOW() \
             WHERE public_id = $5 \
               AND status = 'broadcasting' \
               AND phase = $6 \
               AND request_body #>> '{finalise_claim,owner}' = $2 \
               AND (request_body #>> '{finalise_claim,fence}')::bigint = $3 \
               AND reset_generation = $7",
        )
        .bind(&path)
        .bind(&owner_text)
        .bind(fence)
        .bind(lease_secs as f64)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Boot-only: release an **abandoned** exclusive finalise claim so a
    /// single restarted resumer can re-acquire it.
    ///
    /// Sets phase from [`FINALISE_CLAIM_PHASE`] back to `publishing` and
    /// strips `finalise_claim` while status remains `broadcasting`.
    ///
    /// ## Evidence of abandonment (required)
    ///
    /// Release applies only when at least one of:
    /// - `lease_expires_at` is present **and** `<= NOW()` (owner failed to renew)
    /// - `finalise_claim` / `lease_expires_at` is absent (claim never registered a
    ///   live owner — pre-lease row or corrupt; not a protected live process)
    ///
    /// Comparison uses Postgres `NOW()` — the same clock that claim/renew
    /// write into `lease_expires_at`. Host clock skew cannot manufacture
    /// abandonment of a still-live owner.
    ///
    /// A live owner's unexpired lease **must not** be released by a boot sweep
    /// in another process: that would reintroduce double-execution.
    pub async fn release_stale_finalise_claim(&self, public_id: Uuid) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET phase = 'publishing', \
                    request_body = COALESCE(request_body, '{}'::jsonb) - 'finalise_claim', \
                    updated_at = NOW() \
             WHERE public_id = $1 \
               AND status = 'broadcasting' \
               AND phase = $2 \
               AND ( \
                     (request_body #>> '{finalise_claim,lease_expires_at}') IS NULL \
                  OR (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz <= NOW() \
               ) \
               AND reset_generation = $3",
        )
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Status-qualified JSON merge into `request_body`. Returns `true` if
    /// the row was updated.
    ///
    /// The whole `request_body` value is replaced with `new_body` only when
    /// the row's status still equals `expected`. Callers load, mutate, and
    /// write back under this CAS so a concurrent status flip (cancel /
    /// timeout) cannot accept a stale body write.
    ///
    /// **Not** a claim fence after exclusive finalise is won — use
    /// [`Self::merge_finalisation_if_finalise_owner`] for completion-capability
    /// persistence under a claim.
    pub async fn replace_request_body_if_status(
        &self,
        public_id: Uuid,
        expected: JobStatus,
        new_body: &serde_json::Value,
    ) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET request_body = $1, updated_at = NOW() \
             WHERE public_id = $2 AND status = $3 \
               AND reset_generation = $4",
        )
        .bind(new_body)
        .bind(public_id)
        .bind(expected.as_str())
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Best-effort `request_body` rewrite for dispatcher leftover cleanup
    /// (`pending_sign` / `sign` strip after an intermediate failure).
    ///
    /// Applies only when the row is **not** still in the live sign handoff
    /// and **not** under an exclusive finalise claim:
    /// `status <> 'awaiting_signature'` **and**
    /// `phase IS DISTINCT FROM` [`FINALISE_CLAIM_PHASE`].
    ///
    /// Without the claim-phase predicate, a worker that lost the race after
    /// `set_awaiting_signature` (another process signed + claimed before the
    /// confirmation load) would rewrite a claimed row and clobber
    /// `finalise_claim` / concurrent capability merges.
    pub async fn replace_request_body_if_cleanup_safe(
        &self,
        public_id: Uuid,
        new_body: &serde_json::Value,
    ) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET request_body = $1, updated_at = NOW() \
             WHERE public_id = $2 \
               AND status <> 'awaiting_signature' \
               AND phase IS DISTINCT FROM $3 \
               AND reset_generation = $4",
        )
        .bind(new_body)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Fence-qualified merge of the durable `finalisation` capability key.
    ///
    /// Uses `jsonb_set` on `{finalisation}` only so a concurrent lease renew
    /// (which rewrites `finalise_claim.lease_expires_at`) is not clobbered.
    /// Applies only while `fence` is still the current claim epoch and the
    /// lease is unexpired. Dropping a future is cooperative; this write is
    /// the real fence (token + lease), not owner identity alone.
    pub async fn merge_finalisation_if_finalise_owner(
        &self,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        finalisation: &serde_json::Value,
    ) -> sqlx::Result<bool> {
        let path = vec![crate::v1::FINALISATION_BODY_KEY.to_string()];
        let owner_text = owner.to_string();
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET request_body = jsonb_set( \
                    COALESCE(request_body, '{}'::jsonb), \
                    $1::text[], \
                    $2::jsonb, \
                    true \
                ), \
                    updated_at = NOW() \
             WHERE public_id = $3 \
               AND status = 'broadcasting' \
               AND phase = $4 \
               AND request_body #>> '{finalise_claim,owner}' = $5 \
               AND (request_body #>> '{finalise_claim,fence}')::bigint = $6 \
               AND (request_body #>> '{finalise_claim,lease_expires_at}') IS NOT NULL \
               AND (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz > NOW() \
               AND reset_generation = $7",
        )
        .bind(&path)
        .bind(finalisation)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&owner_text)
        .bind(fence)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Legacy cancel: only succeeds while the job is still `queued`.
    ///
    /// Flag-off / `/api/jobs/:id/cancel` behaviour is byte-identical to
    /// pre-v1.1: once the prove leg has started the row is no longer
    /// cancellable. Do **not** widen this method — §7.5 not-yet-published
    /// cancellation lives on [`Self::cancel_not_yet_published`] and is
    /// used only by the v1.1 route.
    ///
    /// Returns `Ok(true)` if cancellation applied, `Ok(false)` if the
    /// job was already past `queued` (or not found). The admit handler
    /// maps `false` to `409 Conflict`.
    pub async fn cancel(&self, public_id: Uuid) -> sqlx::Result<bool> {
        // Legacy cancel stays queued-only. Strip keys for rows that never
        // held a finalisation envelope too (no-op on missing keys).
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'cancelled', phase = 'cancelled', \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $1 AND status = 'queued' \
               AND reset_generation = $2",
        )
        .bind(public_id)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// §7.5 cancel for the **v1.1** path only (`POST /v1/jobs/:id/cancel`).
    ///
    /// Succeeds for `queued`, `proving`, and `awaiting_signature` — the
    /// nullifier has not reached the chain. Once the job is
    /// `broadcasting` (or terminal), cancel is refused so a published
    /// nullifier cannot be rolled back by a status flip.
    ///
    /// Atomically strips durable finalisation keys from `request_body` so a
    /// cancelled `awaiting_signature` row cannot resurrect via boot
    /// rehydrate.
    ///
    /// Returns `Ok(true)` if cancellation applied, `Ok(false)` if the
    /// job was already past the cancellable set (or not found). The
    /// v1 cancel handler maps `false` to `409 wrong_phase`.
    pub async fn cancel_not_yet_published(&self, public_id: Uuid) -> sqlx::Result<bool> {
        let (mut tx, generation) = self.begin_with_locked_generation().await?;
        let result = sqlx::query(
            "UPDATE jobs SET status = 'cancelled', phase = 'cancelled', \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $1 \
               AND status IN ('queued', 'proving', 'awaiting_signature') \
               AND reset_generation = $2",
        )
        .bind(public_id)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Count the non-terminal rows the dispatcher would still have
    /// to process. `queued + proving` — `awaiting_signature` and
    /// `broadcasting` represent in-flight work the dispatcher is
    /// already attached to, not depth.
    #[cfg(test)]
    pub async fn queue_depth(&self) -> sqlx::Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*)::BIGINT AS depth FROM jobs \
             WHERE status IN ('queued', 'proving')",
        )
        .fetch_one(&self.pool)
        .await?;
        let depth: i64 = row.try_get("depth")?;
        Ok(depth)
    }

    /// Load every non-terminal job for the boot-time resumer.
    ///
    /// Returns `queued` rows (signed payloads whose timestamp window
    /// is by now expired — resumer will fail them) AND
    /// `awaiting_signature` rows (the wallet may still come back
    /// with the signature, so the dispatcher needs the Notify
    /// channel re-armed).
    ///
    /// `proving` / `broadcasting` rows are intentionally NOT
    /// returned: a dispatcher restart implies the in-flight prove /
    /// broadcast was interrupted, but they cannot be safely resumed
    /// from JobStore state alone (the prove output lives in process
    /// memory). The resumer transitions them to `failed` separately
    /// — see `boot_resume_jobs` in `runtime.rs`.
    pub async fn list_non_terminal_for_resume(&self) -> sqlx::Result<Vec<Job>> {
        let rows = sqlx::query(
            "SELECT * FROM jobs \
             WHERE status IN ('queued', 'awaiting_signature') \
             ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Job::from_row).collect()
    }

    /// Load every interrupted-in-flight row (`proving`,
    /// `broadcasting`). The resumer marks each of these `failed`
    /// before the listener starts serving so the wallet observes a
    /// terminal status on its next poll.
    pub async fn list_interrupted_for_resume(&self) -> sqlx::Result<Vec<Job>> {
        let rows = sqlx::query(
            "SELECT * FROM jobs \
             WHERE status IN ('proving', 'broadcasting') \
             ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Job::from_row).collect()
    }
}

#[cfg(test)]
#[path = "job_store_tests.rs"]
mod tests;

/// Regression: a late same-generation writer must not clobber a live
/// finalise claim (two store instances / process roles).
#[cfg(test)]
mod from_cas_fence_regression {
    use super::*;
    use crate::test_db::setup_pool;

    fn expect_won(claim: FinaliseClaim) -> i64 {
        match claim {
            FinaliseClaim::Won { fence } => fence,
            other => panic!("expected FinaliseClaim::Won, got {other:?}"),
        }
    }

    fn claim_snapshot(job: &Job) -> (String, i64, String) {
        let claim = job
            .request_body
            .get(FINALISE_CLAIM_BODY_KEY)
            .expect("finalise_claim present");
        let owner = claim
            .get("owner")
            .and_then(|v| v.as_str())
            .expect("owner")
            .to_string();
        let fence = claim.get("fence").and_then(|v| v.as_i64()).expect("fence");
        let lease = claim
            .get("lease_expires_at")
            .and_then(|v| v.as_str())
            .expect("lease_expires_at")
            .to_string();
        (owner, fence, lease)
    }

    /// Late `set_status` / `complete` / `fail` from a stale process must
    /// all return `false` and leave status, phase, owner, fence, lease,
    /// and generation untouched — then the fence owner can still complete.
    #[tokio::test]
    async fn late_naked_writes_cannot_clobber_finalise_claim_owner() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();

        // Process A: admits and would still think the job is queued/proving.
        let store_a = JobStore::with_process_owner(pool.clone(), Uuid::new_v4());
        // Process B: wins the exclusive finalise claim.
        let store_b = JobStore::with_process_owner(pool.clone(), Uuid::new_v4());

        let CreateResult::Fresh(job) = store_a
            .create(
                JobKind::Send,
                &[0xF1u8; 32],
                Some("from-cas-fence"),
                serde_json::json!({}),
            )
            .await
            .expect("create")
        else {
            panic!("expected Fresh");
        };
        let job_id = job.public_id;
        let gen_at_admit = job.reset_generation;

        // Reach awaiting_signature so B can claim finalise.
        assert!(
            store_a
                .set_awaiting_signature(job_id, 1, serde_json::json!({"staged": true}))
                .await
                .expect("awaiting_signature"),
            "precondition: A stages awaiting_signature"
        );

        let fence = expect_won(
            store_b
                .claim_finalise_exclusive(job_id)
                .await
                .expect("B claim"),
        );
        let claimed = store_b.load(job_id).await.expect("load").expect("row");
        assert_eq!(claimed.status, JobStatus::Broadcasting);
        assert_eq!(claimed.phase, FINALISE_CLAIM_PHASE);
        assert_eq!(claimed.reset_generation, gen_at_admit);
        let (owner_before, fence_before, lease_before) = claim_snapshot(&claimed);
        assert_eq!(owner_before, store_b.process_owner().to_string());
        assert_eq!(fence_before, fence);
        // Snapshot fields that late fail/complete would plant if they hit.
        // `set_awaiting_signature` already wrote the sign payload into
        // `response_body`; equality (not is_none) is the right post-check.
        let error_before = claimed.error.clone();
        let response_body_before = claimed.response_body.clone();

        // Every formerly-naked write from A must miss.
        assert!(
            !store_a
                .set_status(job_id, JobStatus::Queued, JobStatus::Proving, "proving")
                .await
                .expect("queued→proving"),
            "queued→proving must not hit a claimed row"
        );
        assert!(
            !store_a
                .set_status(job_id, JobStatus::Proving, JobStatus::Proving, "proving")
                .await
                .expect("proving→proving"),
            "proving→proving must not hit a claimed row"
        );
        assert!(
            !store_a
                .set_status(
                    job_id,
                    JobStatus::Broadcasting,
                    JobStatus::Proving,
                    "proving"
                )
                .await
                .expect("broadcasting→proving"),
            "broadcasting→proving must not hit finalise_claimed (phase guard)"
        );
        assert!(
            !store_a
                .fail(job_id, JobStatus::Proving, "late fail from A")
                .await
                .expect("proving→failed"),
            "proving→failed must not hit a claimed row"
        );
        assert!(
            !store_a
                .fail(job_id, JobStatus::Queued, "late fail from A")
                .await
                .expect("queued→failed"),
            "queued→failed must not hit a claimed row"
        );
        assert!(
            !store_a
                .fail(job_id, JobStatus::Broadcasting, "late fail from A")
                .await
                .expect("broadcasting→failed"),
            "broadcasting→failed must not hit finalise_claimed (phase guard)"
        );
        assert!(
            !store_a
                .complete(
                    job_id,
                    JobStatus::Proving,
                    serde_json::json!({"stolen": true}),
                    200
                )
                .await
                .expect("proving→completed"),
            "proving→completed must not hit a claimed row"
        );
        assert!(
            !store_a
                .complete(
                    job_id,
                    JobStatus::Broadcasting,
                    serde_json::json!({"stolen": true}),
                    200
                )
                .await
                .expect("broadcasting→completed"),
            "broadcasting→completed must not hit finalise_claimed (phase guard)"
        );
        assert!(
            !store_a
                .set_status(
                    job_id,
                    JobStatus::AwaitingSignature,
                    JobStatus::Broadcasting,
                    "broadcasting"
                )
                .await
                .expect("awaiting→broadcasting"),
            "awaiting_signature→broadcasting must not hit after claim"
        );

        let after = store_b.load(job_id).await.expect("load").expect("row");
        assert_eq!(after.status, JobStatus::Broadcasting, "status unchanged");
        assert_eq!(after.phase, FINALISE_CLAIM_PHASE, "phase unchanged");
        assert_eq!(after.reset_generation, gen_at_admit, "generation unchanged");
        let (owner_after, fence_after, lease_after) = claim_snapshot(&after);
        assert_eq!(owner_after, owner_before, "owner unchanged");
        assert_eq!(fence_after, fence_before, "fence unchanged");
        assert_eq!(lease_after, lease_before, "lease unchanged");
        assert_eq!(after.error, error_before, "error unchanged by late fail");
        assert_eq!(
            after.response_body, response_body_before,
            "response_body unchanged by late complete"
        );

        // Legitimate fence owner can still complete under the claim.
        assert!(
            store_b
                .complete_if_finalise_owner(
                    job_id,
                    store_b.process_owner(),
                    fence,
                    serde_json::json!({"ok": true}),
                    200
                )
                .await
                .expect("owner complete"),
            "fence owner must still complete after late writers miss"
        );
        let done = store_b.load(job_id).await.expect("load").expect("row");
        assert_eq!(done.status, JobStatus::Completed);
        assert_eq!(done.phase, "completed");
        drop(scope);
    }

    /// A non-matching `from` CAS reports `false` (caller must not invent
    /// success / events). Store-level contract; dispatcher must gate
    /// `publish_phase` on this bool.
    #[tokio::test]
    async fn from_cas_miss_returns_false_without_mutating_row() {
        let scope = setup_pool().await;
        let store = JobStore::new(scope.pool.clone());
        let CreateResult::Fresh(job) = store
            .create(
                JobKind::Mint,
                &[0xF2u8; 32],
                Some("from-cas-miss"),
                serde_json::json!({}),
            )
            .await
            .expect("create")
        else {
            panic!("expected Fresh");
        };
        let job_id = job.public_id;
        let before = store.load(job_id).await.expect("load").expect("row");

        // Wrong from: proving while still queued.
        assert!(
            !store
                .fail(job_id, JobStatus::Proving, "should not apply")
                .await
                .expect("fail"),
            "fail from proving must miss on queued"
        );
        assert!(
            !store
                .complete(
                    job_id,
                    JobStatus::Proving,
                    serde_json::json!({"nope": true}),
                    200
                )
                .await
                .expect("complete"),
            "complete from proving must miss on queued"
        );
        assert!(
            !store
                .set_status(
                    job_id,
                    JobStatus::AwaitingSignature,
                    JobStatus::Broadcasting,
                    "broadcasting"
                )
                .await
                .expect("set_status"),
            "set_status from awaiting_signature must miss on queued"
        );

        let after = store.load(job_id).await.expect("load").expect("row");
        assert_eq!(after.status, before.status);
        assert_eq!(after.phase, before.phase);
        assert_eq!(after.reset_generation, before.reset_generation);
        assert_eq!(after.error, before.error);
        assert_eq!(after.response_body, before.response_body);
        assert_eq!(after.request_body, before.request_body);
        drop(scope);
    }

    /// Happy-path from-CAS still advances when the expected status matches.
    #[tokio::test]
    async fn from_cas_hit_advances_queued_to_proving() {
        let scope = setup_pool().await;
        let store = JobStore::new(scope.pool.clone());
        let CreateResult::Fresh(job) = store
            .create(JobKind::Mint, &[0xF3u8; 32], None, serde_json::json!({}))
            .await
            .expect("create")
        else {
            panic!("expected Fresh");
        };
        assert!(
            store
                .set_status(
                    job.public_id,
                    JobStatus::Queued,
                    JobStatus::Proving,
                    "proving"
                )
                .await
                .expect("set_status"),
            "queued→proving must apply"
        );
        let after = store.load(job.public_id).await.expect("load").expect("row");
        assert_eq!(after.status, JobStatus::Proving);
        assert_eq!(after.phase, "proving");
        drop(scope);
    }

    /// Two stores: B claims; A tries lease-blind broadcasting complete/fail
    /// with matching status but claim phase — must miss (phase guard).
    #[tokio::test]
    async fn phase_guard_blocks_legacy_complete_fail_on_finalise_claimed() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let store_a = JobStore::with_process_owner(pool.clone(), Uuid::new_v4());
        let store_b = JobStore::with_process_owner(pool.clone(), Uuid::new_v4());
        let CreateResult::Fresh(job) = store_a
            .create(
                JobKind::Send,
                &[0xF4u8; 32],
                Some("phase-guard"),
                serde_json::json!({}),
            )
            .await
            .expect("create")
        else {
            panic!("expected Fresh");
        };
        let job_id = job.public_id;
        assert!(store_a
            .set_awaiting_signature(job_id, 1, serde_json::json!({}))
            .await
            .expect("asig"));
        let fence = expect_won(
            store_b
                .claim_finalise_exclusive(job_id)
                .await
                .expect("claim"),
        );
        let claimed = store_b.load(job_id).await.expect("load").expect("row");
        let (owner, f, lease) = claim_snapshot(&claimed);
        assert_eq!(f, fence);

        assert!(!store_a
            .complete(
                job_id,
                JobStatus::Broadcasting,
                serde_json::json!({"x": 1}),
                200
            )
            .await
            .expect("complete"));
        assert!(!store_a
            .fail(job_id, JobStatus::Broadcasting, "nope")
            .await
            .expect("fail"));
        assert!(!store_a
            .set_status(job_id, JobStatus::Broadcasting, JobStatus::Failed, "failed")
            .await
            .expect("set_status"));

        let after = store_b.load(job_id).await.expect("load").expect("row");
        assert_eq!(after.status, JobStatus::Broadcasting);
        assert_eq!(after.phase, FINALISE_CLAIM_PHASE);
        let (o2, f2, l2) = claim_snapshot(&after);
        assert_eq!(o2, owner);
        assert_eq!(f2, f);
        assert_eq!(l2, lease);
        drop(scope);
    }
}
