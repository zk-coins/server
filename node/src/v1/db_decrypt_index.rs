//! Durable decrypt-index SQL (migration 0031 / `v1_decrypt_index`).
//!
//! Write **after** §2.3.3 verification, **before** ACK. Replay is a named
//! outcome from the UNIQUE constraints — never a second credit row.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::kernel::access::{IndexedRecord, InsertRecordOutcome, RecordType};
use crate::kernel::types::{Digest32, SubjectAddress};

/// Closed verification status on the wire of the SQL CHECK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecryptVerificationStatus {
    Verified,
    Acked,
}

impl DecryptVerificationStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Acked => "acked",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "verified" => Ok(Self::Verified),
            "acked" => Ok(Self::Acked),
            other => bail!("v1_decrypt_index: unknown verification_status {other:?}"),
        }
    }
}

/// One durable decrypt-index row (CoinProof only on this path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecryptIndexRow {
    pub record_id: [u8; 32],
    pub subject: [u8; 32],
    pub coin_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub detect_tag: [u8; 32],
    pub canonical: Vec<u8>,
    pub asset_id: [u8; 32],
    pub verification_status: DecryptVerificationStatus,
    pub delivery_event_id: [u8; 32],
    pub ack_nonce: [u8; 32],
    pub occurred_at: u64,
}

/// `record_id = SHA-256(subject ‖ coin_id ‖ blob_id)` — stable across restarts.
pub(crate) fn decrypt_record_id(
    subject: &[u8; 32],
    coin_id: &[u8; 32],
    blob_id: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(subject);
    h.update(coin_id);
    h.update(blob_id);
    h.finalize().into()
}

/// Insert a verified CoinProof. Returns whether the row was new or a replay.
///
/// On unique-constraint conflict the existing row is left untouched and
/// [`InsertRecordOutcome::AlreadyPresent`] is returned (named replay).
pub(crate) async fn insert_verified_coin_proof(
    pool: &PgPool,
    row: &DecryptIndexRow,
) -> Result<InsertRecordOutcome> {
    ensure_row_shape(row)?;
    let result = sqlx::query(
        "INSERT INTO v1_decrypt_index (\
             record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
             verification_status, delivery_event_id, ack_nonce, occurred_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
         ON CONFLICT DO NOTHING",
    )
    .bind(row.record_id.as_slice())
    .bind(row.subject.as_slice())
    .bind(row.coin_id.as_slice())
    .bind(row.blob_id.as_slice())
    .bind(row.detect_tag.as_slice())
    .bind(&row.canonical)
    .bind(row.asset_id.as_slice())
    .bind(row.verification_status.as_str())
    .bind(row.delivery_event_id.as_slice())
    .bind(row.ack_nonce.as_slice())
    .bind(i64::try_from(row.occurred_at).context("occurred_at fits i64")?)
    .execute(pool)
    .await
    .context("v1_decrypt_index insert")?;

    if result.rows_affected() == 0 {
        Ok(InsertRecordOutcome::AlreadyPresent)
    } else {
        Ok(InsertRecordOutcome::Inserted)
    }
}

/// Mark a row as ACK-published. No-op when already `acked`.
pub(crate) async fn mark_acked(pool: &PgPool, record_id: &[u8; 32]) -> Result<()> {
    sqlx::query(
        "UPDATE v1_decrypt_index \
         SET verification_status = 'acked', acked_at = now() \
         WHERE record_id = $1 AND verification_status = 'verified'",
    )
    .bind(record_id.as_slice())
    .execute(pool)
    .await
    .context("v1_decrypt_index mark_acked")?;
    Ok(())
}

/// Look up by content-address `blob_id` (replay detection before re-verify).
pub(crate) async fn get_by_blob_id(
    pool: &PgPool,
    blob_id: &[u8; 32],
) -> Result<Option<DecryptIndexRow>> {
    let row = sqlx::query_as::<_, DecryptIndexSqlRow>(
        "SELECT record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                verification_status, delivery_event_id, ack_nonce, occurred_at \
         FROM v1_decrypt_index WHERE blob_id = $1",
    )
    .bind(blob_id.as_slice())
    .fetch_optional(pool)
    .await
    .context("v1_decrypt_index get_by_blob_id")?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(r.into_row()?)),
    }
}

/// Look up by `(subject, coin_id)`.
pub(crate) async fn get_by_subject_coin(
    pool: &PgPool,
    subject: &[u8; 32],
    coin_id: &[u8; 32],
) -> Result<Option<DecryptIndexRow>> {
    let row = sqlx::query_as::<_, DecryptIndexSqlRow>(
        "SELECT record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                verification_status, delivery_event_id, ack_nonce, occurred_at \
         FROM v1_decrypt_index WHERE subject = $1 AND coin_id = $2",
    )
    .bind(subject.as_slice())
    .bind(coin_id.as_slice())
    .fetch_optional(pool)
    .await
    .context("v1_decrypt_index get_by_subject_coin")?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(r.into_row()?)),
    }
}

/// Map a durable row into the kernel [`IndexedRecord`] shape.
pub(crate) fn to_indexed_record(row: &DecryptIndexRow) -> IndexedRecord {
    IndexedRecord {
        subject: SubjectAddress(row.subject),
        record_id: Digest32(row.record_id),
        asset_id: Digest32(row.asset_id),
        occurred_at: row.occurred_at,
        record_type: RecordType::CoinProof,
        transition_kind: None,
        blob_id: Digest32(row.blob_id),
        canonical: Some(row.canonical.clone()),
        coin_id: Some(Digest32(row.coin_id)),
    }
}

fn ensure_row_shape(row: &DecryptIndexRow) -> Result<()> {
    if row.canonical.is_empty() {
        bail!("v1_decrypt_index: refuse empty canonical body");
    }
    if row.verification_status != DecryptVerificationStatus::Verified
        && row.verification_status != DecryptVerificationStatus::Acked
    {
        bail!("v1_decrypt_index: closed verification_status violated");
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct DecryptIndexSqlRow {
    record_id: Vec<u8>,
    subject: Vec<u8>,
    coin_id: Vec<u8>,
    blob_id: Vec<u8>,
    detect_tag: Vec<u8>,
    canonical: Vec<u8>,
    asset_id: Vec<u8>,
    verification_status: String,
    delivery_event_id: Vec<u8>,
    ack_nonce: Vec<u8>,
    occurred_at: i64,
}

impl DecryptIndexSqlRow {
    fn into_row(self) -> Result<DecryptIndexRow> {
        Ok(DecryptIndexRow {
            record_id: exact32(&self.record_id, "record_id")?,
            subject: exact32(&self.subject, "subject")?,
            coin_id: exact32(&self.coin_id, "coin_id")?,
            blob_id: exact32(&self.blob_id, "blob_id")?,
            detect_tag: exact32(&self.detect_tag, "detect_tag")?,
            canonical: self.canonical,
            asset_id: exact32(&self.asset_id, "asset_id")?,
            verification_status: DecryptVerificationStatus::parse(&self.verification_status)?,
            delivery_event_id: exact32(&self.delivery_event_id, "delivery_event_id")?,
            ack_nonce: exact32(&self.ack_nonce, "ack_nonce")?,
            occurred_at: u64::try_from(self.occurred_at).context("occurred_at non-negative")?,
        })
    }
}

fn exact32(bytes: &[u8], field: &str) -> Result<[u8; 32]> {
    let arr: [u8; 32] = bytes
        .try_into()
        .with_context(|| format!("v1_decrypt_index.{field} must be 32 bytes"))?;
    Ok(arr)
}
