//! Durable delivery outbox SQL (migration 0032 / `v1_delivery_outbox`).
//!
//! Insert **before** the first mesh send attempt, atomically with the step
//! that owes the delivery (engine + `members_ready` for external coins;
//! Phase-B SDR finalisation for self-delivery). For `external_coin` rows,
//! completion requires a valid §4.2 ACK only. For `self_delivery` rows,
//! durable publish (blob stored + gift-wrap on at least one relay) is
//! completion — there is no external counterparty to ACK. Rows remain after
//! `completed` as a delivery log; blob/SDR material is never deleted
//! (data permanence).

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
    Completed,
    Failed,
}

impl OutboxStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AwaitingAck => "awaiting_ack",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "awaiting_ack" => Ok(Self::AwaitingAck),
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
        let id = outbox_id(e.kind, &e.subject, &e.coin_id, &e.transition_pk);
        sqlx::query(
            "INSERT INTO v1_delivery_outbox (\
                 outbox_id, kind, subject, transition_pk, coin_id, status, material, \
                 attempt_n, next_attempt_at, created_at, updated_at\
             ) VALUES ($1,$2,$3,$4,$5,'pending',$6,0,NOW(),NOW(),NOW()) \
             ON CONFLICT (outbox_id) DO NOTHING",
        )
        .bind(id.as_slice())
        .bind(e.kind.as_str())
        .bind(e.subject.as_slice())
        .bind(e.transition_pk.as_slice())
        .bind(e.coin_id.as_slice())
        .bind(&e.material)
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
/// [`crate::v1::delivery::drive_due_outbox_entries`]). Completed / failed
/// rows never appear; rows still inside their backoff window stay out until
/// `next_attempt_at`. Transition-scoped crash-resume uses
/// [`list_open_for_transition`] instead.
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
/// owns the transition and wants an immediate re-attempt.
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
/// - `external_coin`: `pending` → `awaiting_ack` with artefacts; already
///   `awaiting_ack` → stay, refresh artefacts (fresh ack_nonce) + attempt_n
/// - `self_delivery`: `pending` / `awaiting_ack` → `completed` (durable
///   publish is terminal — no external ACK is applicable)
/// - **refuses** `completed` / `failed` (never republish after terminal)
///
/// Does not set `ack_received_at` — only [`mark_ack_received`] writes that
/// column (real §4.2 ACK path for `external_coin`).
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
    }
    let new_status = match row.kind {
        OutboxKind::SelfDelivery => OutboxStatus::Completed,
        OutboxKind::ExternalCoin => OutboxStatus::AwaitingAck,
    };
    let new_attempt = row.attempt_n.saturating_add(1);
    let delay = republish_delay_secs(new_attempt);
    // next_attempt_at = NOW() + delay seconds (SQL interval).
    let result = sqlx::query(
        "UPDATE v1_delivery_outbox SET \
             status = $2, \
             blob_id = $3, detect_tag = $4, epk = $5, k_tx = $6, ack_nonce = $7, event_id = $8, \
             zbe_ciphertext = $9, out_ciphertext = $10, recipient_op_pk = $11, \
             attempt_n = $12, \
             last_published_at = NOW(), \
             next_attempt_at = NOW() + make_interval(secs => $13::double precision), \
             updated_at = NOW() \
         WHERE outbox_id = $1 \
           AND status IN ('pending', 'awaiting_ack')",
    )
    .bind(outbox_id.as_slice())
    .bind(new_status.as_str())
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

/// Record a valid recipient ACK and complete the row.
///
/// Data permanence: the row stays in `v1_delivery_outbox` as a delivery log
/// (`completed`); stored ZBE / out_ciphertext / material are never deleted.
/// Repeated ACKs while already `completed` are a pure no-op.
pub(crate) async fn mark_ack_received(pool: &PgPool, outbox_id: &[u8; 32]) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin v1_delivery_outbox mark_ack_received")?;
    let locked = sqlx::query_as::<_, OutboxSqlRow>(&format!("{OUTBOX_SELECT} FOR UPDATE"))
        .bind(outbox_id.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .context("v1_delivery_outbox mark_ack_received lock")?;
    let Some(locked) = locked else {
        bail!("mark_ack_received: outbox row missing");
    };
    let status = OutboxStatus::parse(&locked.status)?;
    match status {
        OutboxStatus::AwaitingAck => {
            let result = sqlx::query(
                "UPDATE v1_delivery_outbox SET \
                     status = 'completed', \
                     ack_received_at = NOW(), \
                     updated_at = NOW() \
                 WHERE outbox_id = $1 \
                   AND status = 'awaiting_ack'",
            )
            .bind(outbox_id.as_slice())
            .execute(&mut *tx)
            .await
            .context("v1_delivery_outbox mark_ack_received")?;
            if result.rows_affected() == 0 {
                bail!("mark_ack_received: status race under row lock");
            }
        }
        OutboxStatus::Completed => {
            // Already terminal-success — pure no-op (idempotent re-ACK).
        }
        status => bail!(
            "mark_ack_received: refuse ACK in status {}",
            status.as_str()
        ),
    }
    tx.commit()
        .await
        .context("commit v1_delivery_outbox mark_ack_received")?;
    Ok(())
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

// ---------------------------------------------------------------------------
// SQL row mapping
// ---------------------------------------------------------------------------

const OUTBOX_SELECT: &str =
    "SELECT outbox_id, kind, subject, transition_pk, coin_id, status, material, \
                blob_id, detect_tag, epk, k_tx, ack_nonce, event_id, zbe_ciphertext, \
                out_ciphertext, recipient_op_pk, attempt_n, fail_reason \
         FROM v1_delivery_outbox WHERE outbox_id = $1";

/// Shared SELECT body (columns only) for list queries.
const OUTBOX_COLUMNS: &str = "outbox_id, kind, subject, transition_pk, coin_id, status, material, \
                blob_id, detect_tag, epk, k_tx, ack_nonce, event_id, zbe_ciphertext, \
                out_ciphertext, recipient_op_pk, attempt_n, fail_reason";

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
            fail_reason: self.fail_reason,
        })
    }
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

    fn sample_insert(coin: u8) -> OutboxInsert {
        OutboxInsert {
            kind: OutboxKind::ExternalCoin,
            subject: [0x11; 32],
            transition_pk: [0x22; 32],
            coin_id: [coin; 32],
            material: format!(r#"{{"v":1,"coin":{coin}}}"#).into_bytes(),
        }
    }

    fn sample_self_delivery_insert(coin: u8) -> OutboxInsert {
        OutboxInsert {
            kind: OutboxKind::SelfDelivery,
            subject: [0x11; 32],
            transition_pk: [0x22; 32],
            coin_id: [coin; 32],
            material: format!(r#"{{"v":1,"self":{coin}}}"#).into_bytes(),
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

    #[test]
    fn status_parse_rejects_awaiting_receipts() {
        let err = OutboxStatus::parse("awaiting_receipts").expect_err("removed status");
        assert!(
            err.to_string().contains("unknown status"),
            "removed status must fail closed: {err}"
        );
        assert_eq!(OutboxStatus::Completed.as_str(), "completed");
        assert!(!OutboxStatus::AwaitingAck.is_terminal());
        assert!(OutboxStatus::Completed.is_terminal());
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
        let entry = sample_insert(0x71);
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

    /// Self-delivery: durable publish is terminal — no external ACK.
    /// Row reaches `completed` and leaves `list_due` without `mark_ack_received`.
    #[tokio::test]
    async fn self_delivery_publish_completes_and_leaves_list_due() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_self_delivery_insert(0x91);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");

        // Pending self-delivery is due before publish.
        let due_before = list_due(&pool).await.expect("due before");
        assert!(
            due_before.iter().any(|r| r.outbox_id == id),
            "pending self_delivery must be due before publish"
        );

        let art = sample_artefacts(0xB1);
        let zbe = art.zbe_ciphertext.clone();
        let blob = art.blob_id;
        mark_published(&pool, &id, &art)
            .await
            .expect("publish self_delivery");

        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(
            row.status,
            OutboxStatus::Completed,
            "self_delivery must complete on durable publish (no ACK)"
        );
        assert_eq!(row.kind, OutboxKind::SelfDelivery);
        assert_eq!(row.attempt_n, 1);
        assert_eq!(row.blob_id, Some(blob));
        assert_eq!(row.zbe_ciphertext.as_deref(), Some(zbe.as_slice()));
        // No fabricated ACK — only mark_ack_received sets ack_received_at.
        let ack_is_null: bool = sqlx::query_scalar(
            "SELECT ack_received_at IS NULL FROM v1_delivery_outbox WHERE outbox_id = $1",
        )
        .bind(id.as_slice())
        .fetch_one(&pool)
        .await
        .expect("ack_received_at IS NULL");
        assert!(
            ack_is_null,
            "self_delivery completion must leave ack_received_at NULL"
        );

        let due_after = list_due(&pool).await.expect("due after");
        assert!(
            !due_after.iter().any(|r| r.outbox_id == id),
            "completed self_delivery must never be due"
        );

        // Terminal: republish refused.
        let err = mark_published(&pool, &id, &sample_artefacts(0xB2))
            .await
            .expect_err("completed self_delivery must never republish");
        assert!(
            err.to_string().contains("completed"),
            "error names completed refuse: {err}"
        );
    }

    /// Valid ACK completes the row; the row and stored artefacts remain
    /// (data permanence — no drop after ACK).
    #[tokio::test]
    async fn ack_completes_and_retains_row_and_artefacts() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x72);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");

        let art = sample_artefacts(0xA1);
        let zbe = art.zbe_ciphertext.clone();
        let out_ct = art.out_ciphertext.clone();
        let blob = art.blob_id;
        mark_published(&pool, &id, &art).await.expect("publish");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::AwaitingAck);
        assert_eq!(row.attempt_n, 1);

        mark_ack_received(&pool, &id).await.expect("ack");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(
            row.status,
            OutboxStatus::Completed,
            "valid ACK must complete the outbox row"
        );
        // Row is a durable delivery log — never deleted after completed.
        assert_eq!(row.blob_id, Some(blob));
        assert_eq!(row.zbe_ciphertext.as_deref(), Some(zbe.as_slice()));
        assert_eq!(row.out_ciphertext.as_deref(), Some(out_ct.as_slice()));
        assert!(!row.material.is_empty(), "material retained after ACK");

        // Idempotent re-ACK stays completed (no second transition).
        mark_ack_received(&pool, &id).await.expect("re-ack");
        let row = get_by_id(&pool, &id).await.expect("get").expect("row");
        assert_eq!(row.status, OutboxStatus::Completed);
        assert_eq!(row.zbe_ciphertext.as_deref(), Some(zbe.as_slice()));
    }

    #[tokio::test]
    async fn republish_increments_attempt_and_refuses_completed() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x73);
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

        mark_ack_received(&pool, &id).await.expect("ack");
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
    async fn list_due_returns_pending_and_skips_completed() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let e1 = sample_insert(0x81);
        let e2 = sample_insert(0x82);
        let id1 = outbox_id(e1.kind, &e1.subject, &e1.coin_id, &e1.transition_pk);
        let id2 = outbox_id(e2.kind, &e2.subject, &e2.coin_id, &e2.transition_pk);
        insert_pending(&pool, &[e1, e2]).await.expect("insert");

        mark_published(&pool, &id2, &sample_artefacts(0x20))
            .await
            .expect("p");
        mark_ack_received(&pool, &id2).await.expect("ack");

        let due = list_due(&pool).await.expect("due");
        let ids: Vec<_> = due.iter().map(|r| r.outbox_id).collect();
        assert!(ids.contains(&id1), "pending must be due");
        assert!(!ids.contains(&id2), "completed must never be due");
    }

    /// Completed row is a durable log entry — `DELETE` of the outbox row is
    /// not part of the delivery lifecycle (self-heal wipe is a separate path).
    #[tokio::test]
    async fn completed_row_is_not_removed_by_ack_path() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x85);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");
        mark_published(&pool, &id, &sample_artefacts(0x85))
            .await
            .expect("publish");
        mark_ack_received(&pool, &id).await.expect("ack");

        // Point load still finds the row after completion.
        let row = get_by_id(&pool, &id)
            .await
            .expect("get")
            .expect("completed row must remain durable");
        assert_eq!(row.status, OutboxStatus::Completed);

        // Count via SQL: one durable log row, not zero.
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM v1_delivery_outbox WHERE outbox_id = $1",
        )
        .bind(id.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(n, 1, "ACK path must never DELETE the outbox row");
    }

    /// Terminal failure: row is `failed` with a named reason and leaves
    /// `list_due` (drive loop). Mirrors the contract
    /// [`crate::v1::delivery::drive_due_outbox_entries`] uses after
    /// `DeliveryError::is_terminal_outbox_failure`.
    #[tokio::test]
    async fn mark_failed_sets_reason_and_excludes_from_list_due() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let entry = sample_insert(0x83);
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
        let entry2 = sample_insert(0x84);
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

    /// Schema has no receipts table and no replication_k column.
    #[tokio::test]
    async fn schema_has_no_receipts_table_or_replication_k() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();

        let receipts_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.tables
                 WHERE table_schema = current_schema()
                   AND table_name = 'v1_delivery_receipts'
             )",
        )
        .fetch_one(&pool)
        .await
        .expect("receipts table probe");
        assert!(
            !receipts_exists,
            "v1_delivery_receipts must not exist (data permanence / no receipts)"
        );

        let has_k: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = 'v1_delivery_outbox'
                   AND column_name = 'replication_k'
             )",
        )
        .fetch_one(&pool)
        .await
        .expect("replication_k column probe");
        assert!(!has_k, "replication_k column must not exist");

        // Status CHECK must not admit awaiting_receipts.
        let entry = sample_insert(0x99);
        let id = outbox_id(
            entry.kind,
            &entry.subject,
            &entry.coin_id,
            &entry.transition_pk,
        );
        insert_pending(&pool, &[entry]).await.expect("insert");
        let err = sqlx::query(
            "UPDATE v1_delivery_outbox SET status = 'awaiting_receipts' WHERE outbox_id = $1",
        )
        .bind(id.as_slice())
        .execute(&pool)
        .await
        .expect_err("awaiting_receipts must violate CHECK");
        let msg = err.to_string();
        assert!(
            msg.contains("check") || msg.contains("violat") || msg.contains("awaiting_receipts"),
            "CHECK refusal expected: {msg}"
        );
    }
}
