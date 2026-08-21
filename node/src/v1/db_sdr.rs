//! Durable §4.2 SDR Phase-A staging (`v1_sdr_phase_a`, migration 0033).
//!
//! Phase A rows are inserted at finalise (keyed by transition nullifier Pk).
//! Phase B (scanner hook after first-occurrence + size_final) finalises them.

use anyhow::{bail, Context, Result};
use sqlx::PgPool;

use super::outbox_material::SdrPhaseAMaterial;

/// Closed Phase-A status labels (mirror SQL CHECK).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SdrPhaseAStatus {
    AwaitingFirstOccurrence,
    Finalised,
    Failed,
}

impl SdrPhaseAStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingFirstOccurrence => "awaiting_first_occurrence",
            Self::Finalised => "finalised",
            Self::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "awaiting_first_occurrence" => Ok(Self::AwaitingFirstOccurrence),
            "finalised" => Ok(Self::Finalised),
            "failed" => Ok(Self::Failed),
            other => bail!("v1_sdr_phase_a: unknown status {other:?}"),
        }
    }
}

/// One staged Phase-A row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SdrPhaseARow {
    pub transition_pk: [u8; 32],
    pub subject: [u8; 32],
    pub status: SdrPhaseAStatus,
    pub material: SdrPhaseAMaterial,
    pub fail_reason: Option<String>,
}

/// Insert Phase A (idempotent on transition_pk — ON CONFLICT DO NOTHING).
pub(crate) async fn insert_phase_a(
    pool: &PgPool,
    transition_pk: &[u8; 32],
    subject: &[u8; 32],
    material: &SdrPhaseAMaterial,
) -> Result<()> {
    let bytes = material
        .encode()
        .context("v1_sdr_phase_a: encode material")?;
    sqlx::query(
        "INSERT INTO v1_sdr_phase_a \
             (transition_pk, subject, status, material, created_at, updated_at) \
         VALUES ($1, $2, 'awaiting_first_occurrence', $3, NOW(), NOW()) \
         ON CONFLICT (transition_pk) DO NOTHING",
    )
    .bind(transition_pk.as_slice())
    .bind(subject.as_slice())
    .bind(&bytes)
    .execute(pool)
    .await
    .context("v1_sdr_phase_a insert")?;
    Ok(())
}

/// Load one row by transition nullifier Pk.
pub(crate) async fn get_phase_a(
    pool: &PgPool,
    transition_pk: &[u8; 32],
) -> Result<Option<SdrPhaseARow>> {
    let row = sqlx::query_as::<_, PhaseASql>(
        "SELECT transition_pk, subject, status, material, fail_reason \
         FROM v1_sdr_phase_a WHERE transition_pk = $1",
    )
    .bind(transition_pk.as_slice())
    .fetch_optional(pool)
    .await
    .context("v1_sdr_phase_a get")?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(r.into_row()?)),
    }
}

/// Open Phase-A rows still waiting for first-occurrence finality.
pub(crate) async fn list_awaiting_first_occurrence(pool: &PgPool) -> Result<Vec<SdrPhaseARow>> {
    let rows = sqlx::query_as::<_, PhaseASql>(
        "SELECT transition_pk, subject, status, material, fail_reason \
         FROM v1_sdr_phase_a \
         WHERE status = 'awaiting_first_occurrence' \
         ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .context("v1_sdr_phase_a list open")?;
    rows.into_iter().map(|r| r.into_row()).collect()
}

/// Mark Phase A finalised after a successful outbox insert.
pub(crate) async fn mark_finalised(pool: &PgPool, transition_pk: &[u8; 32]) -> Result<()> {
    let result = sqlx::query(
        "UPDATE v1_sdr_phase_a SET \
             status = 'finalised', updated_at = NOW() \
         WHERE transition_pk = $1 \
           AND status = 'awaiting_first_occurrence'",
    )
    .bind(transition_pk.as_slice())
    .execute(pool)
    .await
    .context("v1_sdr_phase_a mark_finalised")?;
    if result.rows_affected() == 0 {
        // Idempotent: already finalised is fine.
        if let Some(row) = get_phase_a(pool, transition_pk).await? {
            if row.status == SdrPhaseAStatus::Finalised {
                return Ok(());
            }
            bail!(
                "v1_sdr_phase_a mark_finalised: refuse status {}",
                row.status.as_str()
            );
        }
        bail!("v1_sdr_phase_a mark_finalised: row missing");
    }
    Ok(())
}

/// Terminal failure with a named reason (incomplete material, etc.).
pub(crate) async fn mark_failed(
    pool: &PgPool,
    transition_pk: &[u8; 32],
    reason: &str,
) -> Result<()> {
    if reason.is_empty() {
        bail!("v1_sdr_phase_a mark_failed: refuse empty fail_reason");
    }
    sqlx::query(
        "UPDATE v1_sdr_phase_a SET \
             status = 'failed', fail_reason = $2, updated_at = NOW() \
         WHERE transition_pk = $1 \
           AND status = 'awaiting_first_occurrence'",
    )
    .bind(transition_pk.as_slice())
    .bind(reason)
    .execute(pool)
    .await
    .context("v1_sdr_phase_a mark_failed")?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct PhaseASql {
    transition_pk: Vec<u8>,
    subject: Vec<u8>,
    status: String,
    material: Vec<u8>,
    fail_reason: Option<String>,
}

impl PhaseASql {
    fn into_row(self) -> Result<SdrPhaseARow> {
        let transition_pk: [u8; 32] = self
            .transition_pk
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("v1_sdr_phase_a: transition_pk wrong length"))?;
        let subject: [u8; 32] = self
            .subject
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("v1_sdr_phase_a: subject wrong length"))?;
        Ok(SdrPhaseARow {
            transition_pk,
            subject,
            status: SdrPhaseAStatus::parse(&self.status)?,
            material: SdrPhaseAMaterial::decode(&self.material)?,
            fail_reason: self.fail_reason,
        })
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;
    use crate::v1::outbox_material::{SdrPhaseAMaterial, SdrPhaseAOutputRef};

    fn sample_material() -> SdrPhaseAMaterial {
        SdrPhaseAMaterial {
            v: 1,
            subject_hex: hex::encode([0x11u8; 32]),
            transition_pk_hex: hex::encode([0x22u8; 32]),
            record_kind: 0x02,
            send_counter: 1,
            prev_state_head_hex: hex::encode([0x33u8; 32]),
            account_state_hex: hex::encode([0xAAu8; 140]),
            recursive_proof_hex: hex::encode([0x01u8, 0x02]),
            proof_data_hex: hex::encode([0xBBu8; 192]),
            own_nullifier_pk_hex: hex::encode([0x22u8; 32]),
            own_nullifier_r_hex: hex::encode([0x44u8; 32]),
            own_nullifier_r_prime_hex: hex::encode([0x55u8; 32]),
            proof_block_anchor_hash_hex: hex::encode([0x66u8; 32]),
            proof_block_anchor_height: 10,
            spent_or_folded_coin_ids_hex: vec![],
            output_refs: vec![],
            blob_holders: vec!["https://h.example".into()],
            max_blob_bytes: 1024,
            recipient_ivpk_hex: hex::encode([0x77u8; 32]),
            recipient_op_pk_hex: hex::encode([0x88u8; 32]),
            recipient_relays: vec!["wss://r.example".into()],
        }
    }

    #[tokio::test]
    async fn insert_list_finalise_roundtrip() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let pk = [0x22u8; 32];
        let subject = [0x11u8; 32];
        let mat = sample_material();
        insert_phase_a(&pool, &pk, &subject, &mat)
            .await
            .expect("insert");
        let open = list_awaiting_first_occurrence(&pool).await.expect("list");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].transition_pk, pk);
        mark_finalised(&pool, &pk).await.expect("finalise");
        let open2 = list_awaiting_first_occurrence(&pool).await.expect("list2");
        assert!(open2.is_empty());
        let row = get_phase_a(&pool, &pk).await.expect("get").expect("row");
        assert_eq!(row.status, SdrPhaseAStatus::Finalised);
    }

    #[tokio::test]
    async fn mark_failed_named_reason() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let pk = [0xAAu8; 32];
        let mut mat = sample_material();
        mat.transition_pk_hex = hex::encode(pk);
        insert_phase_a(&pool, &pk, &[0x11u8; 32], &mat)
            .await
            .expect("insert");
        mark_failed(&pool, &pk, "SdrPhaseAMaterial: output_refs incomplete")
            .await
            .expect("fail");
        let row = get_phase_a(&pool, &pk).await.expect("get").expect("row");
        assert_eq!(row.status, SdrPhaseAStatus::Failed);
        assert!(row
            .fail_reason
            .as_deref()
            .is_some_and(|r| r.contains("incomplete")));
    }

    #[tokio::test]
    async fn incomplete_material_refused_at_insert_encode() {
        let mut mat = sample_material();
        mat.output_refs = vec![SdrPhaseAOutputRef {
            coin_id_hex: String::new(),
            blob_id_hex: hex::encode([1u8; 32]),
            epk_hex: hex::encode([2u8; 32]),
            out_ciphertext_hex: hex::encode(b"x"),
            holders: vec!["https://h".into()],
        }];
        let err = mat.encode().expect_err("incomplete output_ref");
        assert!(
            err.to_string().contains("incomplete") || err.to_string().contains("empty"),
            "got {err}"
        );
    }
}
