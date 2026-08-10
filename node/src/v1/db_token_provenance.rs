//! Durable issuer-originated token provenance (§4.6 Class B / §4.8).
//!
//! Key: the self-authenticated 32-byte `asset_id`. Value: the exact canonical
//! [`IssuanceTerms`] encoding used inside `CoinProof` (§7.1). Rows are
//! append-only and are intentionally not state-epoch scoped: received terms
//! survive every derived-state reset and are never deleted.

use anyhow::{bail, Context, Result};
use shared::spec_v1::bundle::{
    deserialize_issuance_terms, serialize_issuance_terms, IssuanceTerms,
};
use sqlx::{PgPool, Postgres, Transaction};

/// Named outcome for an idempotent provenance write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InsertTokenProvenanceOutcome {
    Inserted,
    AlreadyPresent,
}

/// Insert one self-authenticated provenance row in its own transaction.
///
/// Production receive uses [`insert_token_provenance_in_tx`] so the terms and
/// their verified CoinProof commit atomically before ACK.
pub(crate) async fn insert_token_provenance(
    pool: &PgPool,
    asset_id: &[u8; 32],
    terms: &IssuanceTerms,
) -> Result<InsertTokenProvenanceOutcome> {
    let mut tx = pool.begin().await.context("token_provenance begin")?;
    let outcome = insert_token_provenance_in_tx(&mut tx, asset_id, terms).await?;
    tx.commit().await.context("token_provenance commit")?;
    Ok(outcome)
}

/// Insert inside the caller's store-and-ACK transaction.
///
/// Same `asset_id` + byte-identical terms is an idempotent no-op. Any different
/// canonical value under an existing `asset_id` is corruption and fails loud;
/// the existing row is never overwritten.
pub(crate) async fn insert_token_provenance_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    asset_id: &[u8; 32],
    terms: &IssuanceTerms,
) -> Result<InsertTokenProvenanceOutcome> {
    let canonical = serialize_issuance_terms(terms)
        .context("token_provenance serialize canonical IssuanceTerms")?;
    let result = sqlx::query(
        "INSERT INTO token_provenance (asset_id, issuance_terms) \
         VALUES ($1, $2) ON CONFLICT (asset_id) DO NOTHING",
    )
    .bind(asset_id.as_slice())
    .bind(&canonical)
    .execute(&mut **tx)
    .await
    .context("token_provenance insert")?;

    if result.rows_affected() == 1 {
        return Ok(InsertTokenProvenanceOutcome::Inserted);
    }
    if result.rows_affected() != 0 {
        bail!(
            "token_provenance insert affected {} rows; expected 0 or 1",
            result.rows_affected()
        );
    }

    let existing: (Vec<u8>,) = sqlx::query_as(
        "SELECT issuance_terms FROM token_provenance WHERE asset_id = $1",
    )
    .bind(asset_id.as_slice())
    .fetch_one(&mut **tx)
    .await
    .context("token_provenance conflict row disappeared")?;
    if existing.0 != canonical {
        bail!(
            "token_provenance corruption: asset_id {} already maps to different IssuanceTerms",
            hex::encode(asset_id)
        );
    }
    Ok(InsertTokenProvenanceOutcome::AlreadyPresent)
}

/// Look up and strictly decode retained terms by `asset_id`.
pub(crate) async fn get_token_provenance(
    pool: &PgPool,
    asset_id: &[u8; 32],
) -> Result<Option<IssuanceTerms>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT issuance_terms FROM token_provenance WHERE asset_id = $1",
    )
    .bind(asset_id.as_slice())
    .fetch_optional(pool)
    .await
    .context("token_provenance lookup")?;
    row.map(|(canonical,)| {
        deserialize_issuance_terms(&canonical)
            .context("token_provenance stored IssuanceTerms are corrupt")
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;
    use shared::spec_v1::encoding::digest_to_bytes;
    use shared::spec_v1::hashes::{asset_id_v1, asset_id_v2, name_hash};
    use shared::spec_v1::tags::GENESIS_TAG;

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

    fn v2_terms() -> IssuanceTerms {
        IssuanceTerms {
            creator_pubkey: [0x22; 32],
            decimals: 8,
            issuance_version: 2,
            name: b"Capped Token".to_vec(),
            cap_total: Some(u128::MAX - 7),
            terms_salt: Some([0x33; 32]),
        }
    }

    fn recompute_asset_id(terms: &IssuanceTerms) -> [u8; 32] {
        let name_hash = name_hash(&terms.name).expect("valid test name");
        let digest = match terms.issuance_version {
            1 => asset_id_v1(
                GENESIS_TAG,
                &terms.creator_pubkey,
                &name_hash,
                terms.decimals,
                terms.issuance_version,
            ),
            2 => asset_id_v2(
                GENESIS_TAG,
                &terms.creator_pubkey,
                &name_hash,
                terms.decimals,
                terms.issuance_version,
                terms.cap_total.expect("v2 cap"),
                &terms.terms_salt.expect("v2 salt"),
            ),
            other => panic!("unsupported test issuance version {other}"),
        };
        digest_to_bytes(&digest)
    }

    #[tokio::test]
    async fn v1_and_v2_roundtrip_and_remain_self_verifying() {
        let scope = setup_pool().await;
        for terms in [v1_terms(), v2_terms()] {
            let asset_id = recompute_asset_id(&terms);
            assert_eq!(
                insert_token_provenance(&scope.pool, &asset_id, &terms)
                    .await
                    .expect("insert provenance"),
                InsertTokenProvenanceOutcome::Inserted
            );
            let held = get_token_provenance(&scope.pool, &asset_id)
                .await
                .expect("lookup provenance")
                .expect("held provenance");
            assert_eq!(held, terms);
            assert_eq!(recompute_asset_id(&held), asset_id);
        }
    }

    #[tokio::test]
    async fn missing_is_none_and_identical_second_write_is_one_row() {
        let scope = setup_pool().await;
        assert_eq!(
            get_token_provenance(&scope.pool, &[0xee; 32])
                .await
                .expect("missing lookup"),
            None
        );

        let terms = v1_terms();
        let asset_id = recompute_asset_id(&terms);
        assert_eq!(
            insert_token_provenance(&scope.pool, &asset_id, &terms)
                .await
                .expect("first insert"),
            InsertTokenProvenanceOutcome::Inserted
        );
        assert_eq!(
            insert_token_provenance(&scope.pool, &asset_id, &terms)
                .await
                .expect("idempotent insert"),
            InsertTokenProvenanceOutcome::AlreadyPresent
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM token_provenance")
            .fetch_one(&scope.pool)
            .await
            .expect("count provenance rows");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn conflicting_terms_fail_loud_without_overwrite() {
        let scope = setup_pool().await;
        let original = v1_terms();
        let asset_id = recompute_asset_id(&original);
        insert_token_provenance(&scope.pool, &asset_id, &original)
            .await
            .expect("insert original");

        let mut conflicting = original.clone();
        conflicting.decimals += 1;
        let err = insert_token_provenance(&scope.pool, &asset_id, &conflicting)
            .await
            .expect_err("different terms under one asset id must fail");
        assert!(err.to_string().contains("different IssuanceTerms"), "{err:#}");
        assert_eq!(
            get_token_provenance(&scope.pool, &asset_id)
                .await
                .expect("reload original"),
            Some(original)
        );
    }
}
