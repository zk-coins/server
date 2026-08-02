//! Durable delivery outbox SQL (migration 0032 / `v1_delivery_outbox`).
//!
//! Insert **before** the first mesh send attempt, atomically with the step
//! that owes the delivery (engine + `members_ready` for external coins;
//! Phase-B SDR finalisation for self-delivery). Completion requires a valid
//! §4.2 ACK **and** ≥ `replication_k` distinct operator receipts (§4.6).

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

// ---------------------------------------------------------------------------
// Closed status / kind labels (mirror SQL CHECK)
// ---------------------------------------------------------------------------

/// Closed outbox state machine labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboxStatus {
    Pending,
    AwaitingAck,
    AwaitingReceipts,
    Completed,
    Failed,
}

impl OutboxStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AwaitingAck => "awaiting_ack",
            Self::AwaitingReceipts => "awaiting_receipts",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "awaiting_ack" => Ok(Self::AwaitingAck),
            "awaiting_receipts" => Ok(Self::AwaitingReceipts),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            other => bail!("v1_delivery_outbox: unknown status {other:?}"),
        }
    }

    /// Terminal rows are never republished.
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// Closed delivery kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboxKind {
    ExternalCoin,
    SelfDelivery,
}

impl OutboxKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExternalCoin => "external_coin",
            Self::SelfDelivery => "self_delivery",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "external_coin" => Ok(Self::ExternalCoin),
            "self_delivery" => Ok(Self::SelfDelivery),
            other => bail!("v1_delivery_outbox: unknown kind {other:?}"),
        }
    }

    fn id_tag(self) -> &'static [u8] {
        match self {
            Self::ExternalCoin => b"ext",
            Self::SelfDelivery => b"sdr",
        }
    }
}

// ---------------------------------------------------------------------------
// Backoff (§4.2 RECOMMENDED values — frozen choice, documented)
// ---------------------------------------------------------------------------

/// Initial republish delay: **30 s** (§4.2 RECOMMENDED).
pub(crate) const REPUBLISH_INITIAL_SECS: u64 = 30;
/// Cap: **1 h** (§4.2 RECOMMENDED).
pub(crate) const REPUBLISH_CAP_SECS: u64 = 3_600;
/// Default replication factor **k = 3** (§4.6; MUST NOT be less than 2).
pub(crate) const DEFAULT_REPLICATION_K: i32 = 3;

/// Max time after a valid ACK to collect ≥ `replication_k` distinct operator
/// receipts before the row is marked **failed** with a named reason.
///
/// `awaiting_receipts` is excluded from [`list_due`] (ACK already held; mesh
/// republish must not re-fire). Without this deadline a row that never reaches
/// k receipts would wait forever. Frozen at **24 h** (well above the 1 h
/// republish cap so holders can still finish after the last publish attempt).
/// Receipt re-collection without re-ACK remains a follow-up; this path is the
/// fail-closed progress exit, consistent with [`mark_failed`].
pub(crate) const AWAITING_RECEIPTS_TIMEOUT_SECS: u64 = 86_400;

/// Token embedded in the stale-receipts fail reason (tests + operator logs).
pub(crate) const AWAITING_RECEIPTS_TIMEOUT_REASON: &str = "AWAITING_RECEIPTS_TIMEOUT";

/// Exponential backoff delay after a successful publish attempt `attempt_n`
/// (1-based: first publish → next retry after 30 s).
///
/// §4.2 RECOMMENDED, frozen: initial 30 s, doubling, cap 1 h.
/// `delay = min(30 * 2^(attempt_n - 1), 3600)`. Without the outer `min`,
/// attempt 8 would yield 3840 (= 30·2⁷) and walk past the cap — so the
/// clamp is mandatory, not decorative. `attempt_n == 0` is due immediately
/// (pending first publish).
pub(crate) fn republish_delay_secs(attempt_n: u32) -> u64 {
    if attempt_n == 0 {
        return 0;
    }
    // Bound the exponent so the shift never overflows u64 before the cap min.
    let exp = attempt_n.saturating_sub(1).min(16);
    let calculated = REPUBLISH_INITIAL_SECS.saturating_mul(1u64 << exp);
    calculated.min(REPUBLISH_CAP_SECS)
}

/// Stable outbox id: `SHA-256(kind_tag ‖ subject ‖ coin_id ‖ transition_pk)`.
pub(crate) fn outbox_id(
    kind: OutboxKind,
    subject: &[u8; 32],
    coin_id: &[u8; 32],
    transition_pk: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(kind.id_tag());
    h.update(subject);
    h.update(coin_id);
    h.update(transition_pk);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// One durable outbox row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboxRow {
    pub outbox_id: [u8; 32],
    pub kind: OutboxKind,
    pub subject: [u8; 32],
    pub transition_pk: [u8; 32],
    pub coin_id: [u8; 32],
    pub status: OutboxStatus,
    pub material: Vec<u8>,
    pub blob_id: Option<[u8; 32]>,
    pub detect_tag: Option<[u8; 32]>,
    /// Per-coin ephemeral x-only pubkey (SDR `output_ref.epk`).
    pub epk: Option<[u8; 32]>,
    pub k_tx: Option<[u8; 32]>,
    pub ack_nonce: Option<[u8; 32]>,
    pub event_id: Option<[u8; 32]>,
    pub zbe_ciphertext: Option<Vec<u8>>,
    pub out_ciphertext: Option<Vec<u8>>,
    pub recipient_op_pk: Option<[u8; 32]>,
    pub attempt_n: u32,
    pub replication_k: i32,
    pub fail_reason: Option<String>,
}

/// Insert payload for a new pending row (no artefacts yet).
#[derive(Clone, Debug)]
pub(crate) struct OutboxInsert {
    pub kind: OutboxKind,
    pub subject: [u8; 32],
    pub transition_pk: [u8; 32],
    pub coin_id: [u8; 32],
    pub material: Vec<u8>,
    pub replication_k: i32,
}

/// Artefacts written after a successful mesh publish attempt.
#[derive(Clone, Debug)]
pub(crate) struct PublishArtefacts {
    pub blob_id: [u8; 32],
    pub detect_tag: [u8; 32],
    /// Per-coin ephemeral x-only pubkey (SDR `output_ref.epk`).
    pub epk: [u8; 32],
    pub k_tx: [u8; 32],
    pub ack_nonce: [u8; 32],
    pub event_id: [u8; 32],
    pub zbe_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub recipient_op_pk: [u8; 32],
}

/// One stored ReplicaReceiptV1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredReceipt {
    pub holder_op_pubkey: [u8; 32],
    pub receipt_json: Vec<u8>,
    pub retention_class: String,
    pub stored_at: u64,
}

// ---------------------------------------------------------------------------
// Insert (pool and in-transaction)
// ---------------------------------------------------------------------------

/// Insert pending rows in an **open** transaction (atomic with engine persist).
pub(crate) async fn insert_pending_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    entries: &[OutboxInsert],
) -> Result<()> {
    for e in entries {
        if e.material.is_empty() {
            bail!("v1_delivery_outbox: refuse empty material");
        }
        if e.replication_k < 2 {
            bail!(
                "v1_delivery_outbox: replication_k={} < 2 (§4.6 MUST NOT)",
                e.replication_k
            );
        }
        let id = outbox_id(e.kind, &e.subject, &e.coin_id, &e.transition_pk);
        sqlx::query(
            "INSERT INTO v1_delivery_outbox (\
                 outbox_id, kind, subject, transition_pk, coin_id, status, material, \
                 attempt_n, next_attempt_at, replication_k, created_at, updated_at\
             ) VALUES ($1,$2,$3,$4,$5,'pending',$6,0,NOW(),$7,NOW(),NOW()) \
             ON CONFLICT (outbox_id) DO NOTHING",
        )
        .bind(id.as_slice())
        .bind(e.kind.as_str())
        .bind(e.subject.as_slice())
        .bind(e.transition_pk.as_slice())
        .bind(e.coin_id.as_slice())
        .bind(&e.material)
        .bind(e.replication_k)
        .execute(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "insert v1_delivery_outbox pending outbox_id={}",
                hex::encode(id)
            )
        })?;
    }
    Ok(())
}

/// Insert pending rows on a pool (single-row convenience / tests / SDR Phase B).
pub(crate) async fn insert_pending(pool: &PgPool, entries: &[OutboxInsert]) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin v1_delivery_outbox insert tx")?;
    insert_pending_in_tx(&mut tx, entries).await?;
    tx.commit()
        .await
        .context("commit v1_delivery_outbox insert tx")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

/// Load one row by stable id.
pub(crate) async fn get_by_id(pool: &PgPool, outbox_id: &[u8; 32]) -> Result<Option<OutboxRow>> {
    let row = sqlx::query_as::<_, OutboxSqlRow>(OUTBOX_SELECT)
        .bind(outbox_id.as_slice())
        .fetch_optional(pool)
        .await
        .context("v1_delivery_outbox get_by_id")?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(r.into_row()?)),
    }
}

/// Load by (blob_id, ack_nonce) for the ACK return path.
pub(crate) async fn get_by_blob_and_ack_nonce(
    pool: &PgPool,
    blob_id: &[u8; 32],
    ack_nonce: &[u8; 32],
) -> Result<Option<OutboxRow>> {
    let row = sqlx::query_as::<_, OutboxSqlRow>(&format!(
        "SELECT {OUTBOX_COLUMNS} FROM v1_delivery_outbox \
         WHERE blob_id = $1 AND ack_nonce = $2"
    ))
    .bind(blob_id.as_slice())
    .bind(ack_nonce.as_slice())
    .fetch_optional(pool)
    .await
    .context("v1_delivery_outbox get_by_blob_and_ack_nonce")?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(r.into_row()?)),
    }
}

/// Rows due for first publish or republish (`pending` / `awaiting_ack` with
/// `next_attempt_at <= now`).
///
/// This is the production driver query (runtime tick →
/// [`crate::v1::delivery::drive_due_outbox_entries`]). It is **not** "all
/// open rows": `awaiting_receipts` is open but must never be republished
/// (ACK already held; only k receipts remain), and rows still inside their
/// backoff window stay out until `next_attempt_at`. Transition-scoped
/// crash-resume uses [`list_open_for_transition`] instead.
pub(crate) async fn list_due(pool: &PgPool) -> Result<Vec<OutboxRow>> {
    let rows = sqlx::query_as::<_, OutboxSqlRow>(&format!(
        "SELECT {OUTBOX_COLUMNS} FROM v1_delivery_outbox \
         WHERE status IN ('pending', 'awaiting_ack') \
           AND next_attempt_at <= NOW() \
         ORDER BY next_attempt_at ASC"
    ))
    .fetch_all(pool)
    .await
    .context("v1_delivery_outbox list_due")?;
    rows.into_iter().map(|r| r.into_row()).collect()
}

/// Open rows for one transition (crash-resume after members_ready).
///
/// Used by [`crate::v1::signature`] resume after durable finalise: re-drive
/// every non-terminal outbox row owed by `transition_pk`. Broader than
/// [`list_due`] (no `next_attempt_at` filter) because the caller already
/// owns the transition and wants an immediate re-attempt; narrower than a
/// global open scan (scoped to one pk). `awaiting_receipts` rows may appear
/// here but the publish path refuses republish after ACK.
pub(crate) async fn list_open_for_transition(
    pool: &PgPool,
    transition_pk: &[u8; 32],
) -> Result<Vec<OutboxRow>> {
    let rows = sqlx::query_as::<_, OutboxSqlRow>(&format!(
        "SELECT {OUTBOX_COLUMNS} FROM v1_delivery_outbox \
         WHERE transition_pk = $1 \
           AND status NOT IN ('completed', 'failed') \
         ORDER BY created_at ASC"
    ))
    .bind(transition_pk.as_slice())
    .fetch_all(pool)
    .await
    .context("v1_delivery_outbox list_open_for_transition")?;
    rows.into_iter().map(|r| r.into_row()).collect()
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

/// Record a successful publish / republish attempt.
///
/// - `pending` → `awaiting_ack` with artefacts
/// - `awaiting_ack` → stay, refresh artefacts (fresh ack_nonce) + attempt_n
/// - **refuses** `completed` / `failed` / `awaiting_receipts` (never republish
///   after ACK, never after terminal)
pub(crate) async fn mark_published(
    pool: &PgPool,
    outbox_id: &[u8; 32],
    artefacts: &PublishArtefacts,
) -> Result<()> {
    let row = get_by_id(pool, outbox_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("mark_published: outbox row missing"))?;
    match row.status {
        OutboxStatus::Pending | OutboxStatus::AwaitingAck => {}
        OutboxStatus::Completed => {
            bail!("mark_published: refuse republish of completed outbox entry");
        }
        OutboxStatus::Failed => {
            bail!("mark_published: refuse republish of failed outbox entry");
        }
        OutboxStatus::AwaitingReceipts => {
            bail!("mark_published: refuse republish after ACK (awaiting_receipts)");
        }
    }
    let new_attempt = row.attempt_n.saturating_add(1);
    let delay = republish_delay_secs(new_attempt);
    // next_attempt_at = NOW() + delay seconds (SQL interval).
    let result = sqlx::query(
        "UPDATE v1_delivery_outbox SET \
             status = 'awaiting_ack', \
             blob_id = $2, detect_tag = $3, epk = $4, k_tx = $5, ack_nonce = $6, event_id = $7, \
             zbe_ciphertext = $8, out_ciphertext = $9, recipient_op_pk = $10, \
             attempt_n = $11, \
             last_published_at = NOW(), \
             next_attempt_at = NOW() + make_interval(secs => $12::double precision), \
             updated_at = NOW() \
         WHERE outbox_id = $1 \
           AND status IN ('pending', 'awaiting_ack')",
    )
    .bind(outbox_id.as_slice())
    .bind(artefacts.blob_id.as_slice())
    .bind(artefacts.detect_tag.as_slice())
    .bind(artefacts.epk.as_slice())
    .bind(artefacts.k_tx.as_slice())
    .bind(artefacts.ack_nonce.as_slice())
    .bind(artefacts.event_id.as_slice())
    .bind(&artefacts.zbe_ciphertext)
    .bind(&artefacts.out_ciphertext)
    .bind(artefacts.recipient_op_pk.as_slice())
    .bind(i32::try_from(new_attempt).context("attempt_n fits i32")?)
    .bind(delay as f64)
    .execute(pool)
    .await
    .context("v1_delivery_outbox mark_published")?;
    if result.rows_affected() == 0 {
        bail!("mark_published: row not updated (status race or missing)");
    }
    Ok(())
}

/// Record a valid recipient ACK. Does **not** complete the row — advances to
/// `awaiting_receipts` only. Completion needs k receipts separately.
pub(crate) async fn mark_ack_received(pool: &PgPool, outbox_id: &[u8; 32]) -> Result<()> {
    let result = sqlx::query(
        "UPDATE v1_delivery_outbox SET \
             status = 'awaiting_receipts', \
             ack_received_at = NOW(), \
             updated_at = NOW() \
         WHERE outbox_id = $1 \
           AND status = 'awaiting_ack'",
    )
    .bind(outbox_id.as_slice())
    .execute(pool)
    .await
    .context("v1_delivery_outbox mark_ack_received")?;
    if result.rows_affected() == 0 {
        // Idempotent: already awaiting_receipts / completed is fine for the
        // ACK path, but pending without publish is a named error.
        let row = get_by_id(pool, outbox_id).await?;
        match row.map(|r| r.status) {
            Some(OutboxStatus::AwaitingReceipts) | Some(OutboxStatus::Completed) => Ok(()),
            Some(status) => bail!(
                "mark_ack_received: refuse ACK in status {}",
                status.as_str()
            ),
            None => bail!("mark_ack_received: outbox row missing"),
        }
    } else {
        // Maybe enough receipts already exist (ACK after receipts).
        try_complete_if_ready(pool, outbox_id).await?;
        Ok(())
    }
}

/// Store one ReplicaReceiptV1 under a distinct holder operator id.
///
/// Duplicate `(outbox_id, holder_op_pubkey)` is a no-op (idempotent re-upload).
/// After insert, completes the row when ACK is present and receipt count ≥ k.
pub(crate) async fn store_receipt(
    pool: &PgPool,
    outbox_id: &[u8; 32],
    receipt: &StoredReceipt,
) -> Result<()> {
    if receipt.receipt_json.is_empty() {
        bail!("store_receipt: refuse empty receipt_json");
    }
    if receipt.retention_class != "indefinite" && receipt.retention_class != "policy" {
        bail!(
            "store_receipt: unknown retention_class {:?}",
            receipt.retention_class
        );
    }
    sqlx::query(
        "INSERT INTO v1_delivery_receipts \
             (outbox_id, holder_op_pubkey, receipt_json, retention_class, stored_at) \
         VALUES ($1,$2,$3,$4,$5) \
         ON CONFLICT (outbox_id, holder_op_pubkey) DO NOTHING",
    )
    .bind(outbox_id.as_slice())
    .bind(receipt.holder_op_pubkey.as_slice())
    .bind(&receipt.receipt_json)
    .bind(&receipt.retention_class)
    .bind(i64::try_from(receipt.stored_at).context("stored_at fits i64")?)
    .execute(pool)
    .await
    .context("v1_delivery_receipts insert")?;

    try_complete_if_ready(pool, outbox_id).await?;
    Ok(())
}

/// Count distinct operator receipts for one outbox entry.
pub(crate) async fn receipt_count(pool: &PgPool, outbox_id: &[u8; 32]) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM v1_delivery_receipts WHERE outbox_id = $1",
    )
    .bind(outbox_id.as_slice())
    .fetch_one(pool)
    .await
    .context("v1_delivery_receipts count")?;
    Ok(n)
}

/// List stored `ReplicaReceiptV1` rows for one outbox entry.
///
/// Production completion uses [`receipt_count`] only. This list is the
/// durable read path for the **trust-list / `receipt_sig` verification
/// follow-up** (§4.6: distinct trust-list operator IDs, BIP-340 verify on
/// stored bodies) — not wired yet. Kept as the named façade so that block
/// does not reintroduce ad-hoc SQL. Callers today: unit tests + that
/// follow-up.
#[allow(dead_code)] // trust-list receipt verification follow-up (§4.6)
pub(crate) async fn list_receipts(
    pool: &PgPool,
    outbox_id: &[u8; 32],
) -> Result<Vec<StoredReceipt>> {
    let rows = sqlx::query_as::<_, ReceiptSqlRow>(
        "SELECT holder_op_pubkey, receipt_json, retention_class, stored_at \
         FROM v1_delivery_receipts WHERE outbox_id = $1 \
         ORDER BY received_at ASC",
    )
    .bind(outbox_id.as_slice())
    .fetch_all(pool)
    .await
    .context("v1_delivery_receipts list")?;
    rows.into_iter()
        .map(|r| {
            Ok(StoredReceipt {
                holder_op_pubkey: as_32(&r.holder_op_pubkey, "holder_op_pubkey")?,
                receipt_json: r.receipt_json,
                retention_class: r.retention_class,
                stored_at: u64::try_from(r.stored_at).context("stored_at as u64")?,
            })
        })
        .collect()
}

/// Mark permanently failed with a named reason.
pub(crate) async fn mark_failed(pool: &PgPool, outbox_id: &[u8; 32], reason: &str) -> Result<()> {
    if reason.is_empty() {
        bail!("mark_failed: refuse empty fail_reason");
    }
    sqlx::query(
        "UPDATE v1_delivery_outbox SET \
             status = 'failed', fail_reason = $2, updated_at = NOW() \
         WHERE outbox_id = $1 \
           AND status NOT IN ('completed', 'failed')",
    )
    .bind(outbox_id.as_slice())
    .bind(reason)
    .execute(pool)
    .await
    .context("v1_delivery_outbox mark_failed")?;
    Ok(())
}

/// Terminal progress path for stuck `awaiting_receipts` rows.
///
/// After a valid ACK the row leaves [`list_due`] and must not be republished.
/// If ≥ `replication_k` receipts never arrive within
/// [`AWAITING_RECEIPTS_TIMEOUT_SECS`] of `ack_received_at`, mark the row
/// `failed` with a named reason (no silent eternal wait). Rows with a NULL
/// `ack_received_at` are skipped (corrupt/impossible under the state machine;
/// not silently repaired).
///
/// Returns the number of rows transitioned to `failed`.
pub(crate) async fn fail_stale_awaiting_receipts(pool: &PgPool) -> Result<usize> {
    let reason = format!(
        "{AWAITING_RECEIPTS_TIMEOUT_REASON}: k receipts not collected within \
         {AWAITING_RECEIPTS_TIMEOUT_SECS}s after ACK"
    );
    let result = sqlx::query(
        "UPDATE v1_delivery_outbox SET \
             status = 'failed', \
             fail_reason = $1, \
             updated_at = NOW() \
         WHERE status = 'awaiting_receipts' \
           AND ack_received_at IS NOT NULL \
           AND ack_received_at \
               + make_interval(secs => $2::double precision) < NOW()",
    )
    .bind(&reason)
    .bind(AWAITING_RECEIPTS_TIMEOUT_SECS as f64)
    .execute(pool)
    .await
    .context("v1_delivery_outbox fail_stale_awaiting_receipts")?;
    usize::try_from(result.rows_affected()).context("rows_affected fits usize")
}

/// Complete when status is `awaiting_receipts` and receipt count ≥ k.
async fn try_complete_if_ready(pool: &PgPool, outbox_id: &[u8; 32]) -> Result<()> {
    let Some(row) = get_by_id(pool, outbox_id).await? else {
        return Ok(());
    };
    if row.status != OutboxStatus::AwaitingReceipts {
        return Ok(());
    }
    let n = receipt_count(pool, outbox_id).await?;
    if n < i64::from(row.replication_k) {
        return Ok(());
    }
    sqlx::query(
        "UPDATE v1_delivery_outbox SET \
             status = 'completed', updated_at = NOW() \
         WHERE outbox_id = $1 AND status = 'awaiting_receipts'",
    )
    .bind(outbox_id.as_slice())
    .execute(pool)
    .await
    .context("v1_delivery_outbox complete")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SQL row mapping
// ---------------------------------------------------------------------------

const OUTBOX_SELECT: &str =
    "SELECT outbox_id, kind, subject, transition_pk, coin_id, status, material, \
                blob_id, detect_tag, epk, k_tx, ack_nonce, event_id, zbe_ciphertext, \
                out_ciphertext, recipient_op_pk, attempt_n, replication_k, fail_reason \
         FROM v1_delivery_outbox WHERE outbox_id = $1";

/// Shared SELECT body (columns only) for list queries.
const OUTBOX_COLUMNS: &str = "outbox_id, kind, subject, transition_pk, coin_id, status, material, \
                blob_id, detect_tag, epk, k_tx, ack_nonce, event_id, zbe_ciphertext, \
                out_ciphertext, recipient_op_pk, attempt_n, replication_k, fail_reason";

#[derive(sqlx::FromRow)]
struct OutboxSqlRow {
    outbox_id: Vec<u8>,
    kind: String,
    subject: Vec<u8>,
    transition_pk: Vec<u8>,
    coin_id: Vec<u8>,
    status: String,
    material: Vec<u8>,
    blob_id: Option<Vec<u8>>,
    detect_tag: Option<Vec<u8>>,
    epk: Option<Vec<u8>>,
    k_tx: Option<Vec<u8>>,
    ack_nonce: Option<Vec<u8>>,
    event_id: Option<Vec<u8>>,
    zbe_ciphertext: Option<Vec<u8>>,
    out_ciphertext: Option<Vec<u8>>,
    recipient_op_pk: Option<Vec<u8>>,
    attempt_n: i32,
    replication_k: i32,
    fail_reason: Option<String>,
}

impl OutboxSqlRow {
    fn into_row(self) -> Result<OutboxRow> {
        Ok(OutboxRow {
            outbox_id: as_32(&self.outbox_id, "outbox_id")?,
            kind: OutboxKind::parse(&self.kind)?,
            subject: as_32(&self.subject, "subject")?,
            transition_pk: as_32(&self.transition_pk, "transition_pk")?,
            coin_id: as_32(&self.coin_id, "coin_id")?,
            status: OutboxStatus::parse(&self.status)?,
            material: self.material,
            blob_id: opt_32(self.blob_id, "blob_id")?,
            detect_tag: opt_32(self.detect_tag, "detect_tag")?,
            epk: opt_32(self.epk, "epk")?,
            k_tx: opt_32(self.k_tx, "k_tx")?,
            ack_nonce: opt_32(self.ack_nonce, "ack_nonce")?,
            event_id: opt_32(self.event_id, "event_id")?,
            zbe_ciphertext: self.zbe_ciphertext,
            out_ciphertext: self.out_ciphertext,
            recipient_op_pk: opt_32(self.recipient_op_pk, "recipient_op_pk")?,
            attempt_n: u32::try_from(self.attempt_n).context("attempt_n as u32")?,
            replication_k: self.replication_k,
            fail_reason: self.fail_reason,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ReceiptSqlRow {
    holder_op_pubkey: Vec<u8>,
    receipt_json: Vec<u8>,
    retention_class: String,
    stored_at: i64,
}

fn as_32(v: &[u8], field: &str) -> Result<[u8; 32]> {
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|_| anyhow::anyhow!("v1_delivery_outbox: {field} not 32 bytes"))?;
    Ok(arr)
}

fn opt_32(v: Option<Vec<u8>>, field: &str) -> Result<Option<[u8; 32]>> {
    match v {
        None => Ok(None),
        Some(bytes) => Ok(Some(as_32(&bytes, field)?)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;

    fn sample_insert(coin: u8, k: i32) -> OutboxInsert {
        OutboxInsert {
            kind: OutboxKind::ExternalCoin,
            subject: [0x11; 32],
            transition_pk: [0x22; 32],
            coin_id: [coin; 32],
            material: format!(r#"{{"v":1,"coin":{coin}}}"#).into_bytes(),
            replication_k: k,
        }
    }

    fn sample_artefacts(nonce: u8) -> PublishArtefacts {
        let zbe = vec![0xAB, 0xCD, nonce];
        PublishArtefacts {
            blob_id: crate::v1::blossom::blob_id_of(&zbe),
            detect_tag: [0xD1; 32],
            epk: [0xE0; 32],
            k_tx: [0xC0; 32],
            ack_nonce: [nonce; 32],
            event_id: [0xE1; 32],
            zbe_ciphertext: zbe,
            out_ciphertext: vec![0x01, 0x02],
            recipient_op_pk: [0xB0; 32],
        }
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(republish_delay_secs(0), 0);
        assert_eq!(republish_delay_secs(1), 30);
        assert_eq!(republish_delay_secs(2), 60);
        assert_eq!(republish_delay_secs(3), 120);
        // attempt 7: 30 * 2^6 = 1920 — still under the 1 h cap.
        assert_eq!(republish_delay_secs(7), 1_920);
        // attempt 8: raw 30 * 2^7 = 3840 would overshoot; min(..., 3600) clamps.
        assert_eq!(republish_delay_secs(8), REPUBLISH_CAP_SECS);
        assert_eq!(republish_delay_secs(9), REPUBLISH_CAP_SECS);
        assert_eq!(republish_delay_secs(20), REPUBLISH_CAP_SECS);
    }

    #[tokio::test]
    async fn insert_survives_store_reopen_resume() {
        // Crash simulation: write pending, drop handle, reopen pool schema.
        // Production resume does not scan "all open" rows — the runtime tick
        // uses list_due (pending/awaiting_ack ∧ next_attempt_at ≤ now) and
        // transition crash-resume uses list_open_for_transition. A fresh
        // pending row is immediately due, so list_due is the right probe.
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x71, DEFAULT_REPLICATION_K);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");

        // "Process restart": only the durable store remains.
        drop(pool);
        let pool2 = scope.pool.clone();
        let due = list_due(&pool2).await.expect("list_due after reopen");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].outbox_id, id);
        assert_eq!(due[0].status, OutboxStatus::Pending);
        assert_eq!(due[0].attempt_n, 0);
        // Point load agrees (row fully durable under its stable id).
        let row = get_by_id(&pool2, &id)
            .await
            .expect("get")
            .expect("row survived reopen");
        assert_eq!(row.status, OutboxStatus::Pending);
    }

    #[tokio::test]
    async fn ack_alone_does_not_complete_until_k_receipts() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let k = 2;
        let entry = sample_insert(0x72, k);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");

        let art = sample_artefacts(0xA1);
        mark_published(&pool, &id, &art).await.expect("publish");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::AwaitingAck);
        assert_eq!(row.attempt_n, 1);

        mark_ack_received(&pool, &id).await.expect("ack");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(
            row.status,
            OutboxStatus::AwaitingReceipts,
            "ACK alone must not complete"
        );

        // One receipt — still short of k=2.
        store_receipt(
            &pool,
            &id,
            &StoredReceipt {
                holder_op_pubkey: [0x01; 32],
                receipt_json: br#"{"blob_id":"aa"}"#.to_vec(),
                retention_class: "indefinite".into(),
                stored_at: 1,
            },
        )
        .await
        .expect("receipt1");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::AwaitingReceipts);
        assert_eq!(receipt_count(&pool, &id).await.expect("count"), 1);

        // Second distinct operator → complete.
        store_receipt(
            &pool,
            &id,
            &StoredReceipt {
                holder_op_pubkey: [0x02; 32],
                receipt_json: br#"{"blob_id":"bb"}"#.to_vec(),
                retention_class: "indefinite".into(),
                stored_at: 2,
            },
        )
        .await
        .expect("receipt2");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::Completed);
        assert_eq!(receipt_count(&pool, &id).await.expect("count"), 2);
    }

    #[tokio::test]
    async fn republish_increments_attempt_and_refuses_completed() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x73, 2);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");

        mark_published(&pool, &id, &sample_artefacts(0x01))
            .await
            .expect("p1");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.attempt_n, 1);
        assert_eq!(row.status, OutboxStatus::AwaitingAck);

        mark_published(&pool, &id, &sample_artefacts(0x02))
            .await
            .expect("p2");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.attempt_n, 2);
        assert_eq!(row.ack_nonce, Some([0x02; 32]));

        // Drive to completed.
        mark_ack_received(&pool, &id).await.expect("ack");
        for op in [0x11u8, 0x12u8] {
            store_receipt(
                &pool,
                &id,
                &StoredReceipt {
                    holder_op_pubkey: [op; 32],
                    receipt_json: vec![op],
                    retention_class: "indefinite".into(),
                    stored_at: u64::from(op),
                },
            )
            .await
            .expect("receipt");
        }
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::Completed);

        let err = mark_published(&pool, &id, &sample_artefacts(0x03))
            .await
            .expect_err("completed must never republish");
        assert!(
            err.to_string().contains("completed"),
            "error names completed refuse: {err}"
        );
    }

    #[tokio::test]
    async fn blossom_receipt_is_persisted() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x74, 3);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");
        mark_published(&pool, &id, &sample_artefacts(0x10))
            .await
            .expect("pub");

        let json = br#"{"blob_id":"aa","event_id":"bb","holder_op_pubkey":"cc"}"#.to_vec();
        store_receipt(
            &pool,
            &id,
            &StoredReceipt {
                holder_op_pubkey: [0xCC; 32],
                receipt_json: json.clone(),
                retention_class: "indefinite".into(),
                stored_at: 42,
            },
        )
        .await
        .expect("store");

        let receipts = list_receipts(&pool, &id).await.expect("list");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].holder_op_pubkey, [0xCC; 32]);
        assert_eq!(receipts[0].receipt_json, json);
        assert_eq!(receipts[0].stored_at, 42);
        assert_eq!(receipts[0].retention_class, "indefinite");
    }

    #[tokio::test]
    async fn list_due_returns_pending_and_skips_completed() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let e1 = sample_insert(0x81, 2);
        let e2 = sample_insert(0x82, 2);
        let id1 = outbox_id(e1.kind, &e1.subject, &e1.coin_id, &e1.transition_pk);
        let id2 = outbox_id(e2.kind, &e2.subject, &e2.coin_id, &e2.transition_pk);
        insert_pending(&pool, &[e1, e2]).await.expect("insert");

        // Complete id2 without waiting for backoff.
        mark_published(&pool, &id2, &sample_artefacts(0x20))
            .await
            .expect("p");
        mark_ack_received(&pool, &id2).await.expect("ack");
        for op in [0x21u8, 0x22u8] {
            store_receipt(
                &pool,
                &id2,
                &StoredReceipt {
                    holder_op_pubkey: [op; 32],
                    receipt_json: vec![op],
                    retention_class: "indefinite".into(),
                    stored_at: 1,
                },
            )
            .await
            .expect("r");
        }

        let due = list_due(&pool).await.expect("due");
        let ids: Vec<_> = due.iter().map(|r| r.outbox_id).collect();
        assert!(ids.contains(&id1), "pending must be due");
        assert!(!ids.contains(&id2), "completed must never be due");
    }

    /// After ACK without k receipts the row sits in `awaiting_receipts` and
    /// is invisible to `list_due`. Past the configured deadline it must leave
    /// via named `failed` — never a silent eternal wait.
    #[tokio::test]
    async fn awaiting_receipts_past_timeout_is_named_failed() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let k = 3;
        let entry = sample_insert(0x91, k);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");
        mark_published(&pool, &id, &sample_artefacts(0x91))
            .await
            .expect("publish");
        mark_ack_received(&pool, &id).await.expect("ack");

        // Only one receipt — short of k=3. Row must still be awaiting_receipts.
        store_receipt(
            &pool,
            &id,
            &StoredReceipt {
                holder_op_pubkey: [0x01; 32],
                receipt_json: br#"{"one":1}"#.to_vec(),
                retention_class: "indefinite".into(),
                stored_at: 1,
            },
        )
        .await
        .expect("one receipt");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::AwaitingReceipts);

        // Fresh ACK is inside the window — timeout path must not touch it.
        let n0 = fail_stale_awaiting_receipts(&pool)
            .await
            .expect("fail_stale fresh");
        assert_eq!(n0, 0, "fresh ACK must not be timed out");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::AwaitingReceipts);

        // Backdate ack_received_at past the deadline.
        let backdate_secs = i64::try_from(AWAITING_RECEIPTS_TIMEOUT_SECS + 60)
            .expect("timeout+margin fits i64");
        sqlx::query(
            "UPDATE v1_delivery_outbox SET \
                 ack_received_at = NOW() - make_interval(secs => $2::double precision) \
             WHERE outbox_id = $1",
        )
        .bind(id.as_slice())
        .bind(backdate_secs as f64)
        .execute(&pool)
        .await
        .expect("backdate ack_received_at");

        let n = fail_stale_awaiting_receipts(&pool)
            .await
            .expect("fail_stale expired");
        assert_eq!(n, 1, "one stale awaiting_receipts row must terminal-fail");

        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::Failed);
        let reason = row.fail_reason.expect("named fail_reason");
        assert!(
            reason.contains(AWAITING_RECEIPTS_TIMEOUT_REASON),
            "timeout token in reason: {reason}"
        );
        assert!(
            reason.contains(&AWAITING_RECEIPTS_TIMEOUT_SECS.to_string()),
            "deadline secs in reason: {reason}"
        );

        // Idempotent: second sweep finds nothing.
        let n2 = fail_stale_awaiting_receipts(&pool)
            .await
            .expect("fail_stale again");
        assert_eq!(n2, 0);
    }

    /// Terminal failure: row is `failed` with a named reason and leaves
    /// `list_due` (drive loop). Mirrors the contract
    /// [`crate::v1::delivery::drive_due_outbox_entries`] uses after
    /// `DeliveryError::is_terminal_outbox_failure`.
    #[tokio::test]
    async fn mark_failed_sets_reason_and_excludes_from_list_due() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x83, 2);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");

        // Still due while pending.
        let due_before = list_due(&pool).await.expect("due before");
        assert!(
            due_before.iter().any(|r| r.outbox_id == id),
            "pending must be due before terminal failure"
        );

        let reason = "blossom forbidden (HTTP 403): op key not on holder trust list";
        mark_failed(&pool, &id, reason).await.expect("mark_failed");

        let row = get_by_id(&pool, &id)
            .await
            .expect("get")
            .expect("row must remain durable and visible");
        assert_eq!(row.status, OutboxStatus::Failed);
        assert_eq!(
            row.fail_reason.as_deref(),
            Some(reason),
            "terminal failure must store the named reason (no silent drop)"
        );

        let due_after = list_due(&pool).await.expect("due after");
        assert!(
            !due_after.iter().any(|r| r.outbox_id == id),
            "failed rows must leave the drive/list_due loop"
        );

        // Empty reason is refused (fail closed — no anonymous failed rows).
        let entry2 = sample_insert(0x84, 2);
        let id2 = outbox_id(
            entry2.kind,
            &entry2.subject,
            &entry2.coin_id,
            &entry2.transition_pk,
        );
        insert_pending(&pool, &[entry2]).await.expect("insert2");
        let err = mark_failed(&pool, &id2, "")
            .await
            .expect_err("empty fail_reason");
        assert!(
            err.to_string().contains("empty"),
            "error must name empty reason: {err}"
        );
        let still = get_by_id(&pool, &id2).await.expect("get2").expect("row2");
        assert_eq!(still.status, OutboxStatus::Pending);
    }

    #[tokio::test]
    async fn replication_k_below_two_refused() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let mut entry = sample_insert(0x90, 1);
        entry.replication_k = 1;
        let err = insert_pending(&pool, &[entry])
            .await
            .expect_err("k<2 must fail");
        assert!(err.to_string().contains("replication_k"));
    }
}
