//! Durable SQL index for locally finalised self-delivery records (migration 0036).
//!
//! These rows deliberately do not reuse `v1_decrypt_index`: a local
//! self-delivery has no incoming gift-wrap event, ACK nonce, or ACK state.

use anyhow::{bail, Context, Result};
use sqlx::PgPool;

use crate::kernel::access::{
    InMemoryPrivateIndex, IndexedRecord, InsertRecordOutcome, RecordType, TransitionKind,
};
use crate::kernel::types::{Digest32, SubjectAddress};

/// One locally finalised self-delivery record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelfDeliveryIndexRow {
    pub record_id: [u8; 32],
    pub subject: [u8; 32],
    pub coin_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub detect_tag: [u8; 32],
    pub canonical: Vec<u8>,
    pub asset_id: [u8; 32],
    pub transition_kind: TransitionKind,
    pub occurred_at: u64,
}

/// Durably insert one self-delivery and make the durable row visible to Pull.
///
/// SQL is the idempotency source of truth. On crash-resume, a fresh delivery
/// build has a different `blob_id`; the `(subject, coin_id)` constraint keeps
/// the original row. We then mirror that original row, which both avoids a
/// same-process duplicate and repairs a crash between SQL and mirror writes.
pub(crate) async fn insert_and_mirror_self_delivery(
    pool: &PgPool,
    private_index: &InMemoryPrivateIndex,
    row: &SelfDeliveryIndexRow,
) -> Result<InsertRecordOutcome> {
    let sql_outcome = insert_self_delivery(pool, row).await?;
    let durable = match sql_outcome {
        InsertRecordOutcome::Inserted => row.clone(),
        InsertRecordOutcome::AlreadyPresent => {
            get_by_subject_coin(pool, &row.subject, &row.coin_id)
                .await?
                .context(
                    "v1_self_delivery_index conflict without an existing (subject, coin_id) row",
                )?
        }
    };

    private_index
        .insert_record(to_indexed_record(&durable))
        .map_err(|e| anyhow::anyhow!("v1_self_delivery_index mirror insert: {e}"))?;
    Ok(sql_outcome)
}

/// Insert every staged row for one subject's fold set in one SQL transaction.
///
/// Only after the transaction commits are the durable winners (new rows or
/// pre-existing conflict winners) mirrored into `private_index`. Thus a SQL
/// failure cannot leave either a partial durable fold or a mirror of data that
/// did not commit.
pub(crate) async fn insert_and_mirror_self_delivery_batch(
    pool: &PgPool,
    private_index: &InMemoryPrivateIndex,
    rows: &[SelfDeliveryIndexRow],
) -> Result<Vec<(SelfDeliveryIndexRow, InsertRecordOutcome)>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut tx = pool
        .begin()
        .await
        .context("v1_self_delivery_index batch begin")?;
    let mut durable_outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        ensure_row_shape(row)?;
        let result = sqlx::query(
            "INSERT INTO v1_self_delivery_index (\
                 record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                 transition_kind, occurred_at\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT DO NOTHING",
        )
        .bind(row.record_id.as_slice())
        .bind(row.subject.as_slice())
        .bind(row.coin_id.as_slice())
        .bind(row.blob_id.as_slice())
        .bind(row.detect_tag.as_slice())
        .bind(&row.canonical)
        .bind(row.asset_id.as_slice())
        .bind(row.transition_kind.as_str())
        .bind(i64::try_from(row.occurred_at).context("occurred_at fits i64")?)
        .execute(&mut *tx)
        .await
        .context("v1_self_delivery_index batch insert")?;

        let (durable, outcome) = if result.rows_affected() == 0 {
            let existing = sqlx::query_as::<_, SelfDeliveryIndexSqlRow>(
                "SELECT record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                        transition_kind, occurred_at \
                 FROM v1_self_delivery_index WHERE subject = $1 AND coin_id = $2",
            )
            .bind(row.subject.as_slice())
            .bind(row.coin_id.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .context("v1_self_delivery_index batch conflict lookup")?
            .context(
                "v1_self_delivery_index batch conflict without an existing (subject, coin_id) row",
            )?
            .into_row()?;
            (existing, InsertRecordOutcome::AlreadyPresent)
        } else {
            (row.clone(), InsertRecordOutcome::Inserted)
        };
        durable_outcomes.push((durable, outcome));
    }

    tx.commit()
        .await
        .context("v1_self_delivery_index batch commit")?;

    for (durable, _) in &durable_outcomes {
        private_index
            .insert_record(to_indexed_record(durable))
            .map_err(|e| anyhow::anyhow!("v1_self_delivery_index batch mirror insert: {e}"))?;
    }
    Ok(durable_outcomes)
}

/// Insert one row, returning a named replay on any unique conflict.
pub(crate) async fn insert_self_delivery(
    pool: &PgPool,
    row: &SelfDeliveryIndexRow,
) -> Result<InsertRecordOutcome> {
    ensure_row_shape(row)?;
    let result = sqlx::query(
        "INSERT INTO v1_self_delivery_index (\
             record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
             transition_kind, occurred_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT DO NOTHING",
    )
    .bind(row.record_id.as_slice())
    .bind(row.subject.as_slice())
    .bind(row.coin_id.as_slice())
    .bind(row.blob_id.as_slice())
    .bind(row.detect_tag.as_slice())
    .bind(&row.canonical)
    .bind(row.asset_id.as_slice())
    .bind(row.transition_kind.as_str())
    .bind(i64::try_from(row.occurred_at).context("occurred_at fits i64")?)
    .execute(pool)
    .await
    .context("v1_self_delivery_index insert")?;

    if result.rows_affected() == 0 {
        Ok(InsertRecordOutcome::AlreadyPresent)
    } else {
        Ok(InsertRecordOutcome::Inserted)
    }
}

/// Load the durable winner for a self-owned coin.
pub(crate) async fn get_by_subject_coin(
    pool: &PgPool,
    subject: &[u8; 32],
    coin_id: &[u8; 32],
) -> Result<Option<SelfDeliveryIndexRow>> {
    let row = sqlx::query_as::<_, SelfDeliveryIndexSqlRow>(
        "SELECT record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                transition_kind, occurred_at \
         FROM v1_self_delivery_index WHERE subject = $1 AND coin_id = $2",
    )
    .bind(subject.as_slice())
    .bind(coin_id.as_slice())
    .fetch_optional(pool)
    .await
    .context("v1_self_delivery_index get_by_subject_coin")?;
    row.map(SelfDeliveryIndexSqlRow::into_row).transpose()
}

/// All folded self-delivery rows for `subject` — every self-created output
/// coin recorded across the account's reconstructed lineage. §4.5 step 6 head
/// reconstruction only; the online fold path uses `get_by_subject_coin` /
/// the batch insert instead.
pub(crate) async fn list_by_subject(
    pool: &PgPool,
    subject: &[u8; 32],
) -> Result<Vec<SelfDeliveryIndexRow>> {
    let rows: Vec<SelfDeliveryIndexSqlRow> = sqlx::query_as(
        "SELECT record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                transition_kind, occurred_at \
         FROM v1_self_delivery_index WHERE subject = $1",
    )
    .bind(subject.as_slice())
    .fetch_all(pool)
    .await
    .context("v1_self_delivery_index list_by_subject")?;
    rows.into_iter()
        .map(SelfDeliveryIndexSqlRow::into_row)
        .collect()
}

pub(crate) fn to_indexed_record(row: &SelfDeliveryIndexRow) -> IndexedRecord {
    IndexedRecord {
        subject: SubjectAddress(row.subject),
        record_id: Digest32(row.record_id),
        asset_id: Digest32(row.asset_id),
        occurred_at: row.occurred_at,
        record_type: RecordType::SelfDelivery,
        transition_kind: Some(row.transition_kind),
        blob_id: Digest32(row.blob_id),
        canonical: Some(row.canonical.clone()),
        coin_id: Some(Digest32(row.coin_id)),
    }
}

fn ensure_row_shape(row: &SelfDeliveryIndexRow) -> Result<()> {
    if row.canonical.is_empty() {
        bail!("v1_self_delivery_index: refuse empty canonical body");
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct SelfDeliveryIndexSqlRow {
    record_id: Vec<u8>,
    subject: Vec<u8>,
    coin_id: Vec<u8>,
    blob_id: Vec<u8>,
    detect_tag: Vec<u8>,
    canonical: Vec<u8>,
    asset_id: Vec<u8>,
    transition_kind: String,
    occurred_at: i64,
}

impl SelfDeliveryIndexSqlRow {
    fn into_row(self) -> Result<SelfDeliveryIndexRow> {
        Ok(SelfDeliveryIndexRow {
            record_id: exact32(&self.record_id, "record_id")?,
            subject: exact32(&self.subject, "subject")?,
            coin_id: exact32(&self.coin_id, "coin_id")?,
            blob_id: exact32(&self.blob_id, "blob_id")?,
            detect_tag: exact32(&self.detect_tag, "detect_tag")?,
            canonical: self.canonical,
            asset_id: exact32(&self.asset_id, "asset_id")?,
            transition_kind: parse_transition_kind(&self.transition_kind)?,
            occurred_at: u64::try_from(self.occurred_at).context("occurred_at non-negative")?,
        })
    }
}

fn parse_transition_kind(value: &str) -> Result<TransitionKind> {
    match value {
        "mint" => Ok(TransitionKind::Mint),
        "send" => Ok(TransitionKind::Send),
        "receive" => Ok(TransitionKind::Receive),
        other => bail!("v1_self_delivery_index: unknown transition_kind {other:?}"),
    }
}

fn exact32(bytes: &[u8], field: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .with_context(|| format!("v1_self_delivery_index.{field} must be 32 bytes"))
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::access::PrivateIndex;
    use crate::kernel::grants::{GrantAssetScope, GrantScope, SCOPE_NOT_AFTER_UNBOUNDED};
    use crate::test_db::setup_pool;
    use crate::v1::db_decrypt_index::decrypt_record_id;

    #[tokio::test]
    async fn self_delivery_is_durable_disclosable_and_idempotent() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let private_index = InMemoryPrivateIndex::new();
        let subject = [0x11; 32];
        let coin_id = [0x22; 32];
        let asset_id = [0x33; 32];
        let first_blob_id = [0x44; 32];
        let first = SelfDeliveryIndexRow {
            record_id: decrypt_record_id(&subject, &coin_id, &first_blob_id),
            subject,
            coin_id,
            blob_id: first_blob_id,
            detect_tag: [0x55; 32],
            canonical: b"canonical-self-delivery".to_vec(),
            asset_id,
            transition_kind: TransitionKind::Mint,
            occurred_at: 0,
        };

        assert_eq!(
            insert_and_mirror_self_delivery(&pool, &private_index, &first)
                .await
                .expect("first self-delivery insert"),
            InsertRecordOutcome::Inserted
        );
        let durable = get_by_subject_coin(&pool, &subject, &coin_id)
            .await
            .expect("load durable self-delivery")
            .expect("durable self-delivery present");
        assert_eq!(durable, first);

        let admitting_scope = GrantScope {
            assets: GrantAssetScope::Selected(vec![Digest32(asset_id)]),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        };
        let listed = private_index
            .list_records(&SubjectAddress(subject), &admitting_scope)
            .expect("list self-delivery records");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].record_id, Digest32(first.record_id));
        assert_eq!(listed[0].record_type, RecordType::SelfDelivery);
        assert_eq!(listed[0].transition_kind, Some(TransitionKind::Mint));

        // Crash-resume rebuild: fresh randomness changes blob/record ids for
        // the same self-owned coin. SQL keeps the first row and mirroring the
        // durable winner cannot create a second process-local entry.
        let second_blob_id = [0x66; 32];
        let second = SelfDeliveryIndexRow {
            record_id: decrypt_record_id(&subject, &coin_id, &second_blob_id),
            blob_id: second_blob_id,
            detect_tag: [0x77; 32],
            canonical: b"different-randomized-build".to_vec(),
            ..first.clone()
        };
        assert_eq!(
            insert_and_mirror_self_delivery(&pool, &private_index, &second)
                .await
                .expect("idempotent self-delivery replay"),
            InsertRecordOutcome::AlreadyPresent
        );

        let durable_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM v1_self_delivery_index WHERE subject = $1 AND coin_id = $2",
        )
        .bind(subject.as_slice())
        .bind(coin_id.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count durable self-deliveries");
        assert_eq!(durable_count, 1);
        let listed_after_replay = private_index
            .list_records(&SubjectAddress(subject), &admitting_scope)
            .expect("list after replay");
        assert_eq!(listed_after_replay.len(), 1);
        assert_eq!(listed_after_replay[0].record_id, Digest32(first.record_id));
    }
}
