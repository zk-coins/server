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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinaliseClaim {
    /// This caller won the CAS and owns finalise for the job.
    Won,
    /// Another resumer holds (or held) the claim, or the job moved on.
    /// `observed` is the status after the failed CAS — never invent success.
    Lost { observed: JobStatus },
}

/// Phase string written when a resumer wins [`JobStore::claim_finalise_exclusive`].
/// Distinct from free-form `"publishing"` / `"broadcasting"` so a second
/// concurrent claim against an already-claimed row fails the CAS.
pub const FINALISE_CLAIM_PHASE: &str = "finalise_claimed";

/// JSON key under `jobs.request_body` for the exclusive finalise claim lease.
///
/// Shape: `{ "owner": "<uuid>", "lease_expires_at": "<RFC3339>" }`.
/// Written atomically with the phase CAS so a claim always has an owner.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Mint,
    Send,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Mint => "mint",
            JobKind::Send => "send",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "mint" => Some(JobKind::Mint),
            "send" => Some(JobKind::Send),
            _ => None,
        }
    }
}

/// In-memory representation of a row in `jobs`.
///
/// Mirrors the column order in migration 0014. Decoded by
/// [`Job::from_row`] so every read site shares one decode path.
#[derive(Debug, Clone)]
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
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
/// without inserting a second one. The admit handler responds with
/// the cached body so the wallet's retry semantics drive progress
/// without amplifying the prove cost.
#[derive(Debug, Clone)]
pub enum CreateResult {
    /// A brand-new row was inserted; the dispatcher should pick it up.
    Fresh(Job),
    /// An existing row matched the `(account, idempotency_key)`
    /// pair. The caller MUST return the cached response (if any)
    /// instead of enqueuing a second copy.
    IdempotentReplay(Job),
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
}

impl JobStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            process_owner: Uuid::new_v4(),
        }
    }

    /// Construct with an explicit process owner (tests that plant a live
    /// claim under a known identity).
    pub fn with_process_owner(pool: PgPool, process_owner: Uuid) -> Self {
        Self {
            pool,
            process_owner,
        }
    }

    /// Borrow the underlying pool — needed by callers that thread
    /// existing transactions (idempotent reply body lookups) through
    /// the same connection.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Process-generation identity this store uses as finalise claim owner.
    pub fn process_owner(&self) -> Uuid {
        self.process_owner
    }

    /// Admit a fresh job.
    ///
    /// Stripe-style idempotency: when `idem_key` is `Some` and the
    /// `(account, key)` pair already exists, the existing row is
    /// returned as `CreateResult::IdempotentReplay` — no second row
    /// is inserted. When `idem_key` is `None` (boot-time resumer's
    /// hypothetical caller), every call inserts a fresh row.
    ///
    /// The INSERT uses `ON CONFLICT (account_address, idempotency_key)
    /// DO NOTHING` — the partial UNIQUE index from migration 0014
    /// only fires when the key column is present, so the conflict
    /// arm is reachable only for caller-supplied keys.
    pub async fn create(
        &self,
        kind: JobKind,
        account: &[u8; 32],
        idem_key: Option<&str>,
        request_body: serde_json::Value,
    ) -> sqlx::Result<CreateResult> {
        let public_id = Uuid::new_v4();
        let inserted_row = sqlx::query(
            "INSERT INTO jobs \
             (public_id, kind, status, phase, account_address, idempotency_key, request_body) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
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
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = inserted_row {
            return Job::from_row(&row).map(CreateResult::Fresh);
        }

        // Conflict path: an existing row with the same
        // `(account_address, idempotency_key)` already exists. The
        // INSERT's `DO NOTHING` swallowed the second insert; fetch
        // the original and surface it to the caller.
        let existing = sqlx::query(
            "SELECT * FROM jobs \
             WHERE account_address = $1 AND idempotency_key = $2",
        )
        .bind(&account[..])
        .bind(idem_key)
        .fetch_one(&self.pool)
        .await?;
        Job::from_row(&existing).map(CreateResult::IdempotentReplay)
    }

    /// Load a single job by its public UUID. Returns `Ok(None)` if
    /// no row matches.
    pub async fn load(&self, public_id: Uuid) -> sqlx::Result<Option<Job>> {
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

    /// Advance a job to the supplied status + phase. The phase is a
    /// free-form refinement of the coarse status enum so the
    /// dispatcher can publish dispatch-level progress milestones
    /// without churning the constraint-enforced status.
    pub async fn set_status(
        &self,
        public_id: Uuid,
        status: JobStatus,
        phase: &str,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE jobs SET status = $1, phase = $2, updated_at = NOW() \
             WHERE public_id = $3",
        )
        .bind(status.as_str())
        .bind(phase)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        Ok(())
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
    pub async fn set_awaiting_signature(
        &self,
        public_id: Uuid,
        proof_id: i64,
        result: serde_json::Value,
    ) -> sqlx::Result<()> {
        // Only advance from proving (or queued, defensive). Never overwrite
        // a cancelled / terminal row — cancel may have won during prove.
        sqlx::query(
            "UPDATE jobs SET status = 'awaiting_signature', phase = 'awaiting_signature', \
                              proof_id = $1, response_body = $2, updated_at = NOW() \
             WHERE public_id = $3 \
               AND status IN ('queued', 'proving')",
        )
        .bind(proof_id)
        .bind(&result)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Move a job to the `completed` terminal state. Stamps the
    /// cached response body + status code so an idempotent replay
    /// returns byte-identical JSON.
    ///
    /// Atomically strips durable finalisation keys from `request_body`
    /// (`finalisation`, legacy `pending_sign` / `sign`): a terminal row
    /// must not retain a restart envelope that boot recovery could treat
    /// as live work.
    ///
    /// **Legacy behaviour:** applies regardless of current status (same
    /// SQL shape as pre-v1.1). Status-qualified completion for the v1.1
    /// path lives on [`Self::complete_if_status`].
    pub async fn complete(
        &self,
        public_id: Uuid,
        response_body: serde_json::Value,
        response_status: i16,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', \
                              response_body = $1, response_status = $2, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              progress = 100, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $3",
        )
        .bind(&response_body)
        .bind(response_status)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Status-qualified complete: only applies when the row is still in
    /// one of `expected`. Returns `true` if the row was updated.
    ///
    /// Used by the v1.1 finalise path so a second resume after a terminal
    /// flip is a no-op (idempotent) rather than rewriting `completed`.
    ///
    /// **Not** a claim fence: a worker that lost its exclusive finalise
    /// lease can still match `status = broadcasting`. Host-edge completion
    /// under a claim uses [`Self::complete_if_finalise_owner`].
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
        let result = sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', \
                              response_body = $1, response_status = $2, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              progress = 100, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $3 AND status = ANY($4::text[])",
        )
        .bind(&response_body)
        .bind(response_status)
        .bind(public_id)
        .bind(&statuses)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Owner-qualified complete: the durable host-edge fence.
    ///
    /// Applies only while `owner` still holds the exclusive finalise claim
    /// (`broadcasting` + [`FINALISE_CLAIM_PHASE`] + matching
    /// `request_body.finalise_claim.owner`). A worker that lost its lease —
    /// even if it never noticed and kept running — cannot commit completion.
    /// Status alone is not the fence: after reclaim another owner may still
    /// be `broadcasting`.
    pub async fn complete_if_finalise_owner(
        &self,
        public_id: Uuid,
        owner: Uuid,
        response_body: serde_json::Value,
        response_status: i16,
    ) -> sqlx::Result<bool> {
        let owner_text = owner.to_string();
        let result = sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', \
                              response_body = $1, response_status = $2, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              progress = 100, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $3 \
               AND status = 'broadcasting' \
               AND phase = $4 \
               AND request_body #>> '{finalise_claim,owner}' = $5",
        )
        .bind(&response_body)
        .bind(response_status)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&owner_text)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Move a job to the `failed` terminal state with an error
    /// message. The wallet surfaces `error` verbatim in the
    /// `KNOWN_SERVER_ERRORS` mapping table.
    ///
    /// Atomically strips durable finalisation keys from `request_body`
    /// with the status flip so a failed cleanup path cannot leave a
    /// restart envelope on a terminal row.
    ///
    /// **Legacy behaviour:** applies regardless of current status.
    /// Status-qualified fail for the v1.1 path lives on [`Self::fail_if_status`].
    pub async fn fail(&self, public_id: Uuid, error: &str) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2",
        )
        .bind(error)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Status-qualified fail: only applies when the row is still in one
    /// of `expected`. Returns `true` if the row was updated.
    ///
    /// **Not** a claim fence after exclusive finalise is won — use
    /// [`Self::fail_if_finalise_owner`] so a lost worker cannot fail a job
    /// another owner holds.
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
        let result = sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2 AND status = ANY($3::text[])",
        )
        .bind(error)
        .bind(public_id)
        .bind(&statuses)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Owner-qualified fail: only while `owner` holds the exclusive finalise
    /// claim. Same fence as [`Self::complete_if_finalise_owner`].
    pub async fn fail_if_finalise_owner(
        &self,
        public_id: Uuid,
        owner: Uuid,
        error: &str,
    ) -> sqlx::Result<bool> {
        let owner_text = owner.to_string();
        let result = sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2 \
               AND status = 'broadcasting' \
               AND phase = $3 \
               AND request_body #>> '{finalise_claim,owner}' = $4",
        )
        .bind(error)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&owner_text)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Status-qualified status/phase advance. Returns `true` if applied.
    ///
    /// An update that assumes `from` fails (returns `false`) when the job
    /// has moved on — never silently overwrites a later status.
    pub async fn set_status_if(
        &self,
        public_id: Uuid,
        from: JobStatus,
        to: JobStatus,
        phase: &str,
    ) -> sqlx::Result<bool> {
        let result = sqlx::query(
            "UPDATE jobs SET status = $1, phase = $2, updated_at = NOW() \
             WHERE public_id = $3 AND status = $4",
        )
        .bind(to.as_str())
        .bind(phase)
        .bind(public_id)
        .bind(from.as_str())
        .execute(&self.pool)
        .await?;
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
    /// The winner's [`Self::process_owner`] and a lease
    /// ([`FINALISE_CLAIM_LEASE`]) are written into `request_body.finalise_claim`
    /// atomically with the phase CAS. A live owner renews the lease; boot
    /// may release only when the lease has expired (owner abandoned).
    ///
    /// | Prior status / phase | Outcome |
    /// |---------------------|---------|
    /// | `awaiting_signature` | CAS → `broadcasting` + [`FINALISE_CLAIM_PHASE`] + owner/lease; [`FinaliseClaim::Won`] |
    /// | `broadcasting` + unclaimed phase (`publishing` / `broadcasting`) | CAS phase + owner/lease; [`FinaliseClaim::Won`] |
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
    pub async fn claim_finalise_exclusive(
        &self,
        public_id: Uuid,
    ) -> sqlx::Result<FinaliseClaim> {
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

        // Path A: fresh claim from awaiting_signature.
        // `lease_expires_at` is `NOW() + lease` — Postgres clock only (the
        // same clock `release_stale_finalise_claim` uses for `<= NOW()`).
        let result = sqlx::query(
            "UPDATE jobs SET status = $1, phase = $2, \
                    request_body = jsonb_set( \
                        COALESCE(request_body, '{}'::jsonb), \
                        $3::text[], \
                        jsonb_build_object( \
                            'owner', $4::text, \
                            'lease_expires_at', \
                                NOW() + make_interval(secs => $5::double precision) \
                        ), \
                        true \
                    ), \
                    updated_at = NOW() \
             WHERE public_id = $6 AND status = $7",
        )
        .bind(JobStatus::Broadcasting.as_str())
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&path)
        .bind(&owner_text)
        .bind(lease_secs as f64)
        .bind(public_id)
        .bind(JobStatus::AwaitingSignature.as_str())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(FinaliseClaim::Won);
        }

        // Path B: crash-resume while already broadcasting with an unclaimed
        // phase. Rows still at FINALISE_CLAIM_PHASE are owned — refuse
        // regardless of who the stored owner is (lease release is separate).
        let result = sqlx::query(
            "UPDATE jobs SET phase = $1, \
                    request_body = jsonb_set( \
                        COALESCE(request_body, '{}'::jsonb), \
                        $2::text[], \
                        jsonb_build_object( \
                            'owner', $3::text, \
                            'lease_expires_at', \
                                NOW() + make_interval(secs => $4::double precision) \
                        ), \
                        true \
                    ), \
                    updated_at = NOW() \
             WHERE public_id = $5 \
               AND status = 'broadcasting' \
               AND phase IN ('publishing', 'broadcasting')",
        )
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&path)
        .bind(&owner_text)
        .bind(lease_secs as f64)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(FinaliseClaim::Won);
        }

        let status = match self.load(public_id).await? {
            Some(j) => j.status,
            None => JobStatus::Failed,
        };
        Ok(FinaliseClaim::Lost { observed: status })
    }

    /// Extend the lease of a claim this process already owns.
    ///
    /// Writes `lease_expires_at = NOW() + lease` (Postgres clock — same
    /// source as claim create and stale release). Returns `true` only when
    /// the row is still `broadcasting` / [`FINALISE_CLAIM_PHASE`] and
    /// `request_body.finalise_claim.owner` matches `owner`. A non-owner
    /// cannot renew.
    pub async fn renew_finalise_claim(
        &self,
        public_id: Uuid,
        owner: Uuid,
        lease: std::time::Duration,
    ) -> sqlx::Result<bool> {
        let path = vec![FINALISE_CLAIM_BODY_KEY.to_string()];
        let owner_text = owner.to_string();
        let lease_secs = lease_secs_i64(lease);
        let result = sqlx::query(
            "UPDATE jobs SET request_body = jsonb_set( \
                    COALESCE(request_body, '{}'::jsonb), \
                    $1::text[], \
                    jsonb_build_object( \
                        'owner', $2::text, \
                        'lease_expires_at', \
                            NOW() + make_interval(secs => $3::double precision) \
                    ), \
                    true \
                ), \
                    updated_at = NOW() \
             WHERE public_id = $4 \
               AND status = 'broadcasting' \
               AND phase = $5 \
               AND request_body #>> '{finalise_claim,owner}' = $2",
        )
        .bind(&path)
        .bind(&owner_text)
        .bind(lease_secs as f64)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .execute(&self.pool)
        .await?;
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
               )",
        )
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .execute(&self.pool)
        .await?;
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
        let result = sqlx::query(
            "UPDATE jobs SET request_body = $1, updated_at = NOW() \
             WHERE public_id = $2 AND status = $3",
        )
        .bind(new_body)
        .bind(public_id)
        .bind(expected.as_str())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Owner-qualified merge of the durable `finalisation` capability key.
    ///
    /// Uses `jsonb_set` on `{finalisation}` only so a concurrent lease renew
    /// (which rewrites `finalise_claim.lease_expires_at`) is not clobbered.
    /// Applies only while `owner` still holds the exclusive finalise claim.
    /// Dropping a future is cooperative; this write is the real fence.
    pub async fn merge_finalisation_if_finalise_owner(
        &self,
        public_id: Uuid,
        owner: Uuid,
        finalisation: &serde_json::Value,
    ) -> sqlx::Result<bool> {
        let path = vec![crate::v11::FINALISATION_BODY_KEY.to_string()];
        let owner_text = owner.to_string();
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
               AND request_body #>> '{finalise_claim,owner}' = $5",
        )
        .bind(&path)
        .bind(finalisation)
        .bind(public_id)
        .bind(FINALISE_CLAIM_PHASE)
        .bind(&owner_text)
        .execute(&self.pool)
        .await?;
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
        let result = sqlx::query(
            "UPDATE jobs SET status = 'cancelled', phase = 'cancelled', \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $1 AND status = 'queued'",
        )
        .bind(public_id)
        .execute(&self.pool)
        .await?;
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
        let result = sqlx::query(
            "UPDATE jobs SET status = 'cancelled', phase = 'cancelled', \
                              request_body = (COALESCE(request_body, '{}'::jsonb) \
                                  - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'), \
                              updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $1 \
               AND status IN ('queued', 'proving', 'awaiting_signature')",
        )
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Count the non-terminal rows the dispatcher would still have
    /// to process. `queued + proving` — `awaiting_signature` and
    /// `broadcasting` represent in-flight work the dispatcher is
    /// already attached to, not depth.
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
