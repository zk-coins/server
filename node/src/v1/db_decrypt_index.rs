//! Durable decrypt-index SQL (migration 0031 / `v1_decrypt_index`).
//!
//! Write **after** §2.3.3 verification, **before** ACK. Replay is a named
//! outcome from the UNIQUE constraints — never a second credit row.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

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
    let mut tx = pool.begin().await.context("v1_decrypt_index begin")?;
    let outcome = insert_verified_coin_proof_in_tx(&mut tx, row).await?;
    tx.commit().await.context("v1_decrypt_index commit")?;
    Ok(outcome)
}

/// Insert a verified CoinProof inside the caller's store-and-ACK transaction.
///
/// The incoming path pairs this with `token_provenance` so a crash or loud
/// provenance conflict can never leave an ACK-eligible CoinProof without the
/// `asset_terms` it carried.
pub(crate) async fn insert_verified_coin_proof_in_tx(
    tx: &mut Transaction<'_, Postgres>,
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
    .execute(&mut **tx)
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

/// All verified received-CoinProof rows for `subject`. §4.5 step 6 head
/// reconstruction only.
pub(crate) async fn list_by_subject(
    pool: &PgPool,
    subject: &[u8; 32],
) -> Result<Vec<DecryptIndexRow>> {
    let rows: Vec<DecryptIndexSqlRow> = sqlx::query_as(
        "SELECT record_id, subject, coin_id, blob_id, detect_tag, canonical, asset_id, \
                verification_status, delivery_event_id, ack_nonce, occurred_at \
         FROM v1_decrypt_index WHERE subject = $1",
    )
    .bind(subject.as_slice())
    .fetch_all(pool)
    .await
    .context("v1_decrypt_index list_by_subject")?;
    rows.into_iter().map(DecryptIndexSqlRow::into_row).collect()
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

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;

    fn sample_row(seed: u8) -> DecryptIndexRow {
        let subject = [seed; 32];
        let coin_id = [seed + 1; 32];
        let blob_id = [seed + 2; 32];
        DecryptIndexRow {
            record_id: decrypt_record_id(&subject, &coin_id, &blob_id),
            subject,
            coin_id,
            blob_id,
            detect_tag: [seed + 3; 32],
            canonical: vec![seed + 4, seed + 5],
            asset_id: [seed + 6; 32],
            verification_status: DecryptVerificationStatus::Verified,
            delivery_event_id: [seed + 7; 32],
            ack_nonce: [seed + 8; 32],
            occurred_at: u64::from(seed),
        }
    }

    fn sample_sql_row(status: &str, occurred_at: i64) -> DecryptIndexSqlRow {
        DecryptIndexSqlRow {
            record_id: vec![0x11; 32],
            subject: vec![0x22; 32],
            coin_id: vec![0x33; 32],
            blob_id: vec![0x44; 32],
            detect_tag: vec![0x55; 32],
            canonical: b"canonical-coin-proof".to_vec(),
            asset_id: vec![0x66; 32],
            verification_status: status.to_owned(),
            delivery_event_id: vec![0x77; 32],
            ack_nonce: vec![0x88; 32],
            occurred_at,
        }
    }

    async fn row_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM v1_decrypt_index")
            .fetch_one(pool)
            .await
            .expect("count decrypt-index rows")
    }

    #[test]
    fn verification_status_roundtrips_and_rejects_unknown_values() {
        for status in [
            DecryptVerificationStatus::Verified,
            DecryptVerificationStatus::Acked,
        ] {
            assert_eq!(
                DecryptVerificationStatus::parse(status.as_str())
                    .expect("serialized verification status must parse"),
                status
            );
        }

        assert_eq!(DecryptVerificationStatus::Verified.as_str(), "verified");
        assert_eq!(DecryptVerificationStatus::Acked.as_str(), "acked");
        let err = DecryptVerificationStatus::parse("pending")
            .expect_err("unknown verification status must fail closed");
        assert!(
            err.to_string().contains("pending"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn record_id_is_deterministic_and_commits_to_every_input() {
        let subject = [0x11; 32];
        let coin_id = [0x22; 32];
        let blob_id = [0x33; 32];
        let first = decrypt_record_id(&subject, &coin_id, &blob_id);

        assert_eq!(first, decrypt_record_id(&subject, &coin_id, &blob_id));
        assert_ne!(
            first,
            decrypt_record_id(&[0x12; 32], &coin_id, &blob_id),
            "subject must affect the record id"
        );
        assert_ne!(
            first,
            decrypt_record_id(&subject, &[0x23; 32], &blob_id),
            "coin id must affect the record id"
        );
        assert_ne!(
            first,
            decrypt_record_id(&subject, &coin_id, &[0x34; 32]),
            "blob id must affect the record id"
        );
    }

    #[test]
    fn indexed_record_maps_every_decrypt_row_field() {
        let mut row = sample_row(0x10);
        row.occurred_at = 1_234;
        row.verification_status = DecryptVerificationStatus::Acked;
        let indexed = to_indexed_record(&row);

        assert_eq!(indexed.subject, SubjectAddress(row.subject));
        assert_eq!(indexed.record_id, Digest32(row.record_id));
        assert_eq!(indexed.asset_id, Digest32(row.asset_id));
        assert_eq!(indexed.occurred_at, row.occurred_at);
        assert_eq!(indexed.record_type, RecordType::CoinProof);
        assert_eq!(indexed.transition_kind, None);
        assert_eq!(indexed.blob_id, Digest32(row.blob_id));
        assert_eq!(indexed.canonical, Some(row.canonical.clone()));
        assert_eq!(indexed.coin_id, Some(Digest32(row.coin_id)));
    }

    #[test]
    fn row_shape_accepts_closed_statuses_and_rejects_empty_canonical() {
        let mut row = sample_row(0x20);
        ensure_row_shape(&row).expect("verified row shape");

        row.verification_status = DecryptVerificationStatus::Acked;
        ensure_row_shape(&row).expect("acked row shape");

        row.canonical.clear();
        let err = ensure_row_shape(&row).expect_err("empty canonical must fail closed");
        assert!(
            err.to_string().contains("refuse empty canonical body"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn exact32_accepts_exact_length_and_names_short_and_long_fields() {
        let exact = [0x42; 32];
        assert_eq!(exact32(&exact, "digest").expect("exact 32 bytes"), exact);

        for bytes in [vec![0x42; 31], vec![0x42; 33]] {
            let err = exact32(&bytes, "record_id")
                .expect_err("non-32-byte field must fail closed");
            let message = err.to_string();
            assert!(message.contains("record_id"), "unexpected error: {err:#}");
            assert!(message.contains("32 bytes"), "unexpected error: {err:#}");
        }
    }

    #[test]
    fn sql_row_conversion_accepts_valid_verified_and_acked_rows() {
        let verified = sample_sql_row("verified", 17)
            .into_row()
            .expect("valid verified SQL row");
        assert_eq!(verified.record_id, [0x11; 32]);
        assert_eq!(verified.subject, [0x22; 32]);
        assert_eq!(verified.coin_id, [0x33; 32]);
        assert_eq!(verified.blob_id, [0x44; 32]);
        assert_eq!(verified.detect_tag, [0x55; 32]);
        assert_eq!(verified.canonical, b"canonical-coin-proof".to_vec());
        assert_eq!(verified.asset_id, [0x66; 32]);
        assert_eq!(
            verified.verification_status,
            DecryptVerificationStatus::Verified
        );
        assert_eq!(verified.delivery_event_id, [0x77; 32]);
        assert_eq!(verified.ack_nonce, [0x88; 32]);
        assert_eq!(verified.occurred_at, 17);

        let acked = sample_sql_row("acked", 0)
            .into_row()
            .expect("valid acked SQL row");
        assert_eq!(
            acked.verification_status,
            DecryptVerificationStatus::Acked
        );
        assert_eq!(acked.occurred_at, 0);
    }

    #[test]
    fn sql_row_conversion_rejects_each_invalid_shape() {
        let mut wrong_length = sample_sql_row("verified", 1);
        wrong_length.record_id = vec![0x11; 31];
        let err = wrong_length
            .into_row()
            .expect_err("short record_id must fail closed");
        let message = err.to_string();
        assert!(message.contains("record_id"), "unexpected error: {err:#}");
        assert!(message.contains("32 bytes"), "unexpected error: {err:#}");

        let err = sample_sql_row("pending", 1)
            .into_row()
            .expect_err("unknown SQL status must fail closed");
        assert!(
            err.to_string().contains("pending"),
            "unexpected error: {err:#}"
        );

        let err = sample_sql_row("verified", -1)
            .into_row()
            .expect_err("negative occurred_at must fail closed");
        assert!(
            err.to_string().contains("occurred_at non-negative"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn insert_is_durable_and_getters_distinguish_present_from_missing() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let row = sample_row(0x10);

        assert_eq!(
            insert_verified_coin_proof(&pool, &row)
                .await
                .expect("insert verified coin proof"),
            InsertRecordOutcome::Inserted
        );
        assert_eq!(
            get_by_blob_id(&pool, &row.blob_id)
                .await
                .expect("get by blob id"),
            Some(row.clone())
        );
        assert_eq!(
            get_by_subject_coin(&pool, &row.subject, &row.coin_id)
                .await
                .expect("get by subject and coin"),
            Some(row.clone())
        );

        assert_eq!(
            get_by_blob_id(&pool, &[0xee; 32])
                .await
                .expect("missing blob lookup"),
            None
        );
        assert_eq!(
            get_by_subject_coin(&pool, &[0xed; 32], &[0xec; 32])
                .await
                .expect("missing subject and coin lookup"),
            None
        );
    }

    #[tokio::test]
    async fn every_replay_constraint_returns_already_present_without_replacing() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let original = sample_row(0x10);
        assert_eq!(
            insert_verified_coin_proof(&pool, &original)
                .await
                .expect("insert original row"),
            InsertRecordOutcome::Inserted
        );

        let mut same_blob = sample_row(0x30);
        same_blob.blob_id = original.blob_id;
        same_blob.record_id =
            decrypt_record_id(&same_blob.subject, &same_blob.coin_id, &same_blob.blob_id);
        assert_ne!(same_blob.record_id, original.record_id);
        assert_ne!(same_blob.delivery_event_id, original.delivery_event_id);
        assert_ne!(same_blob.subject, original.subject);
        assert_ne!(same_blob.coin_id, original.coin_id);
        assert_eq!(
            insert_verified_coin_proof(&pool, &same_blob)
                .await
                .expect("blob-id replay"),
            InsertRecordOutcome::AlreadyPresent
        );

        let mut same_subject_coin = sample_row(0x40);
        same_subject_coin.subject = original.subject;
        same_subject_coin.coin_id = original.coin_id;
        same_subject_coin.record_id = decrypt_record_id(
            &same_subject_coin.subject,
            &same_subject_coin.coin_id,
            &same_subject_coin.blob_id,
        );
        assert_ne!(same_subject_coin.blob_id, original.blob_id);
        assert_ne!(same_subject_coin.record_id, original.record_id);
        assert_ne!(
            same_subject_coin.delivery_event_id,
            original.delivery_event_id
        );
        assert_eq!(
            insert_verified_coin_proof(&pool, &same_subject_coin)
                .await
                .expect("subject-coin replay"),
            InsertRecordOutcome::AlreadyPresent
        );

        let mut same_delivery_event = sample_row(0x50);
        same_delivery_event.delivery_event_id = original.delivery_event_id;
        assert_ne!(same_delivery_event.subject, original.subject);
        assert_ne!(same_delivery_event.coin_id, original.coin_id);
        assert_ne!(same_delivery_event.blob_id, original.blob_id);
        assert_eq!(
            insert_verified_coin_proof(&pool, &same_delivery_event)
                .await
                .expect("delivery-event replay"),
            InsertRecordOutcome::AlreadyPresent
        );

        assert_eq!(row_count(&pool).await, 1);
        assert_eq!(
            get_by_blob_id(&pool, &original.blob_id)
                .await
                .expect("load original winner"),
            Some(original)
        );
    }

    #[tokio::test]
    async fn insert_rejects_invalid_rows_before_any_database_write() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let mut row = sample_row(0x20);
        row.canonical.clear();
        assert_eq!(row_count(&pool).await, 0);

        let err = insert_verified_coin_proof(&pool, &row)
            .await
            .expect_err("empty canonical must be rejected before insert");
        assert!(
            err.to_string().contains("refuse empty canonical body"),
            "unexpected error: {err:#}"
        );
        assert_eq!(row_count(&pool).await, 0);

        let mut overflowing_time = sample_row(0x21);
        overflowing_time.occurred_at = (i64::MAX as u64) + 1;
        let err = insert_verified_coin_proof(&pool, &overflowing_time)
            .await
            .expect_err("occurred_at outside BIGINT must fail before insert");
        assert!(
            err.to_string().contains("occurred_at fits i64"),
            "unexpected error: {err:#}"
        );
        assert_eq!(row_count(&pool).await, 0);
    }

    #[tokio::test]
    async fn mark_acked_updates_once_and_is_idempotent_for_present_and_missing_ids() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let row = sample_row(0x30);
        insert_verified_coin_proof(&pool, &row)
            .await
            .expect("insert row to acknowledge");

        mark_acked(&pool, &row.record_id)
            .await
            .expect("mark verified row acked");
        let acked = get_by_blob_id(&pool, &row.blob_id)
            .await
            .expect("load acked row")
            .expect("acked row present");
        assert_eq!(
            acked.verification_status,
            DecryptVerificationStatus::Acked
        );

        mark_acked(&pool, &row.record_id)
            .await
            .expect("second acknowledgement is a no-op");
        let still_acked = get_by_blob_id(&pool, &row.blob_id)
            .await
            .expect("reload idempotently acked row")
            .expect("idempotently acked row present");
        assert_eq!(
            still_acked.verification_status,
            DecryptVerificationStatus::Acked
        );

        mark_acked(&pool, &[0xee; 32])
            .await
            .expect("missing record acknowledgement is a no-op");
        assert_eq!(row_count(&pool).await, 1);
    }

    #[tokio::test]
    async fn list_by_subject_returns_all_matching_rows_and_empty_for_unknown_subject() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let first = sample_row(0x40);
        let mut second = sample_row(0x50);
        second.subject = first.subject;
        second.record_id = decrypt_record_id(&second.subject, &second.coin_id, &second.blob_id);
        assert_ne!(first.coin_id, second.coin_id);

        assert_eq!(
            insert_verified_coin_proof(&pool, &first)
                .await
                .expect("insert first subject row"),
            InsertRecordOutcome::Inserted
        );
        assert_eq!(
            insert_verified_coin_proof(&pool, &second)
                .await
                .expect("insert second subject row"),
            InsertRecordOutcome::Inserted
        );

        let listed = list_by_subject(&pool, &first.subject)
            .await
            .expect("list subject rows");
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&first));
        assert!(listed.contains(&second));

        let missing = list_by_subject(&pool, &[0xee; 32])
            .await
            .expect("list unknown subject");
        assert!(missing.is_empty());
    }
}
