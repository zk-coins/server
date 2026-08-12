//! Durable raw mint terms staged between `begin_v1_mint` and finalise.
//!
//! Rows are keyed by the mint job's node-assigned, globally unique id, which is
//! never reused across attempts. A cancelled attempt therefore cannot shadow or
//! block a later attempt on the same account. Byte-identical staging under the
//! same job id is idempotent; divergent terms fail loud as corruption. Reads are
//! deliberately non-destructive: the crash-resume branch can build a
//! `DeliverySnapshot` again after a crash between engine apply and SDR Phase-A
//! staging. Retaining one small row per mint attempt is intentional and matches
//! the append-only, non-state-epoch-scoped posture of `token_provenance`.

use anyhow::{bail, Context, Result};
use shared::spec_v1::bundle::{
    deserialize_issuance_terms, serialize_issuance_terms, IssuanceTerms,
};
use sqlx::PgPool;
use uuid::Uuid;

/// Stage canonical terms under the node-assigned mint job id. Byte-identical
/// retries are idempotent; divergent terms under the same job id are corruption
/// and fail loud without overwriting the first row.
pub(crate) async fn stage_mint_issuance_terms(
    pool: &PgPool,
    job_id: Uuid,
    pk_create: &[u8; 32],
    terms: &IssuanceTerms,
) -> Result<()> {
    let canonical = serialize_issuance_terms(terms)
        .context("v1_mint_terms_staging serialize canonical IssuanceTerms")?;
    let result = sqlx::query(
        "INSERT INTO v1_mint_terms_staging (job_id, pk_create, issuance_terms) \
         VALUES ($1, $2, $3) ON CONFLICT (job_id) DO NOTHING",
    )
    .bind(job_id)
    .bind(pk_create.as_slice())
    .bind(&canonical)
    .execute(pool)
    .await
    .context("v1_mint_terms_staging insert")?;

    if result.rows_affected() == 1 {
        return Ok(());
    }
    if result.rows_affected() != 0 {
        bail!(
            "v1_mint_terms_staging insert affected {} rows; expected 0 or 1",
            result.rows_affected()
        );
    }

    let existing: (Vec<u8>,) = sqlx::query_as(
        "SELECT issuance_terms FROM v1_mint_terms_staging WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .context("v1_mint_terms_staging conflict row disappeared")?;
    if existing.0 != canonical {
        bail!(
            "v1_mint_terms_staging corruption: job_id {} already maps to different IssuanceTerms",
            job_id
        );
    }
    Ok(())
}

/// Non-destructive SELECT — never DELETE. `finalise_accepted_prove_persist_and_stage`'s
/// crash-resume branch can call `DeliverySnapshot::from_pending` again for
/// the same job after a crash between engine-apply and SDR-Phase-A staging; a
/// DELETE-on-read here would make that second read fail closed and break
/// crash-resume for mints specifically. Leaving the row is intentional and
/// harmless (small, one row per mint attempt, never state-epoch scoped — same
/// "no delete path" posture as `token_provenance`).
pub(crate) async fn get_staged_mint_issuance_terms(
    pool: &PgPool,
    job_id: Uuid,
) -> Result<Option<IssuanceTerms>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT issuance_terms FROM v1_mint_terms_staging WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .context("v1_mint_terms_staging lookup")?;
    row.map(|(canonical,)| {
        deserialize_issuance_terms(&canonical)
            .context("v1_mint_terms_staging stored IssuanceTerms are corrupt")
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;

    fn v1_terms() -> IssuanceTerms {
        IssuanceTerms {
            creator_pubkey: [0x11; 32],
            decimals: 2,
            issuance_version: 1,
            name: vec![0xff, 0x00, b'Z'],
            cap_total: None,
            terms_salt: None,
        }
    }

    #[tokio::test]
    async fn staged_terms_round_trip() {
        let scope = setup_pool().await;
        let job_id = Uuid::from_bytes([0x41; 16]);
        let pk_create = [0x21; 32];
        let terms = v1_terms();

        stage_mint_issuance_terms(&scope.pool, job_id, &pk_create, &terms)
            .await
            .expect("stage mint terms");
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id)
                .await
                .expect("read staged mint terms"),
            Some(terms)
        );
    }

    #[tokio::test]
    async fn missing_job_id_returns_none() {
        let scope = setup_pool().await;
        let job_id = Uuid::from_bytes([0x42; 16]);
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id)
                .await
                .expect("read missing staged mint terms"),
            None
        );
    }

    #[tokio::test]
    async fn identical_restaging_is_idempotent_and_non_destructive() {
        let scope = setup_pool().await;
        let job_id = Uuid::from_bytes([0x43; 16]);
        let pk_create = [0x31; 32];
        let terms = v1_terms();

        stage_mint_issuance_terms(&scope.pool, job_id, &pk_create, &terms)
            .await
            .expect("first mint terms stage");
        stage_mint_issuance_terms(&scope.pool, job_id, &pk_create, &terms)
            .await
            .expect("idempotent mint terms restage");
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id)
                .await
                .expect("first repeated read"),
            Some(terms.clone())
        );
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id)
                .await
                .expect("second repeated read"),
            Some(terms)
        );
    }

    #[tokio::test]
    async fn distinct_job_ids_same_pk_create_read_back_own_terms() {
        let scope = setup_pool().await;
        let job_id_a = Uuid::from_bytes([0x61; 16]);
        let job_id_b = Uuid::from_bytes([0x62; 16]);
        let pk_create = [0x51; 32];
        let terms_a = v1_terms();
        let mut terms_b = v1_terms();
        terms_b.name = vec![b'd', b'i', b'f', b'f', b'e', b'r', b'e', b'n', b't'];

        stage_mint_issuance_terms(&scope.pool, job_id_a, &pk_create, &terms_a)
            .await
            .expect("stage first mint attempt terms");
        stage_mint_issuance_terms(&scope.pool, job_id_b, &pk_create, &terms_b)
            .await
            .expect("stage second mint attempt terms");

        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id_a)
                .await
                .expect("read first mint attempt terms"),
            Some(terms_a)
        );
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id_b)
                .await
                .expect("read second mint attempt terms"),
            Some(terms_b)
        );
    }

    #[tokio::test]
    async fn divergent_terms_same_attempt_key_is_hard_error() {
        let scope = setup_pool().await;
        let job_id = Uuid::from_bytes([0x72; 16]);
        let pk_create = [0x71; 32];
        let original_terms = v1_terms();
        let mut divergent_terms = v1_terms();
        divergent_terms.name = vec![b'd', b'i', b'v', b'e', b'r', b'g', b'e', b'n', b't'];

        stage_mint_issuance_terms(
            &scope.pool,
            job_id,
            &pk_create,
            &original_terms,
        )
        .await
        .expect("stage original mint terms");
        stage_mint_issuance_terms(
            &scope.pool,
            job_id,
            &pk_create,
            &divergent_terms,
        )
        .await
        .expect_err("divergent terms under one attempt key must fail");

        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, job_id)
                .await
                .expect("read original mint terms after divergent restage"),
            Some(original_terms)
        );
    }
}
