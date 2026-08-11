//! Durable raw mint terms staged between `begin_v1_mint` and finalise.
//!
//! The row is keyed by the mint transition's one-time `pk_create`. Reads are
//! deliberately non-destructive: `finalise_accepted_prove_persist_and_stage`'s
//! crash-resume branch can build a `DeliverySnapshot` again
//! after a crash between engine apply and SDR Phase-A staging. DELETE-on-read
//! would make that retry fail closed specifically for mints. Retaining one small
//! row per mint attempt is intentional, harmless, and matches the append-only,
//! non-state-epoch-scoped posture of `token_provenance`.

use anyhow::{Context, Result};
use shared::spec_v1::bundle::{
    deserialize_issuance_terms, serialize_issuance_terms, IssuanceTerms,
};
use sqlx::PgPool;

/// Idempotent: re-staging under the same `pk_create` (job-dispatcher retry
/// of the same mint attempt) is a silent no-op — `pk_create` is a one-time
/// spend key, so a second stage under it can only be the same request.
pub(crate) async fn stage_mint_issuance_terms(
    pool: &PgPool,
    pk_create: &[u8; 32],
    terms: &IssuanceTerms,
) -> Result<()> {
    let canonical = serialize_issuance_terms(terms)
        .context("v1_mint_terms_staging serialize canonical IssuanceTerms")?;
    sqlx::query(
        "INSERT INTO v1_mint_terms_staging (pk_create, issuance_terms) \
         VALUES ($1, $2) ON CONFLICT (pk_create) DO NOTHING",
    )
    .bind(pk_create.as_slice())
    .bind(&canonical)
    .execute(pool)
    .await
    .context("v1_mint_terms_staging insert")?;
    Ok(())
}

/// Non-destructive SELECT — never DELETE. `finalise_accepted_prove_persist_and_stage`'s
/// crash-resume branch can call `DeliverySnapshot::from_pending` again for
/// the same `pk_create` after a crash between engine-apply and SDR-Phase-A
/// staging; a DELETE-on-read here would make that second read fail closed
/// and break crash-resume for mints specifically. Leaving the row is
/// intentional and harmless (small, one row per mint attempt, never
/// state-epoch scoped — same "no delete path" posture as
/// `token_provenance`).
pub(crate) async fn get_staged_mint_issuance_terms(
    pool: &PgPool,
    pk_create: &[u8; 32],
) -> Result<Option<IssuanceTerms>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT issuance_terms FROM v1_mint_terms_staging WHERE pk_create = $1",
    )
    .bind(pk_create.as_slice())
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
        let pk_create = [0x21; 32];
        let terms = v1_terms();

        stage_mint_issuance_terms(&scope.pool, &pk_create, &terms)
            .await
            .expect("stage mint terms");
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, &pk_create)
                .await
                .expect("read staged mint terms"),
            Some(terms)
        );
    }

    #[tokio::test]
    async fn missing_pk_create_returns_none() {
        let scope = setup_pool().await;
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, &[0xee; 32])
                .await
                .expect("read missing staged mint terms"),
            None
        );
    }

    #[tokio::test]
    async fn identical_restaging_is_idempotent_and_non_destructive() {
        let scope = setup_pool().await;
        let pk_create = [0x31; 32];
        let terms = v1_terms();

        stage_mint_issuance_terms(&scope.pool, &pk_create, &terms)
            .await
            .expect("first mint terms stage");
        stage_mint_issuance_terms(&scope.pool, &pk_create, &terms)
            .await
            .expect("idempotent mint terms restage");
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, &pk_create)
                .await
                .expect("first repeated read"),
            Some(terms.clone())
        );
        assert_eq!(
            get_staged_mint_issuance_terms(&scope.pool, &pk_create)
                .await
                .expect("second repeated read"),
            Some(terms)
        );
    }
}
