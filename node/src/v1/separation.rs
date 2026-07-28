//! Hard separation between the legacy scan stack (Commitment → SMT/MMR)
//! and the v1.1 scan stack (`AggregateStateNullifierV3` → NfLog).
//!
//! ## Why a marker **and** data checks
//!
//! Mixing the two enforcers produces a database that *looks* consistent
//! (rows exist, digests hash) while double-spend semantics are wrong:
//! SMT first-write and NfLog first-occurrence disagree on which competing
//! spend wins. Convention ("don't flip the flag") is not enough.
//!
//! 1. **Marker row** (`stack_scan_mode`): claimed only on a **genuinely
//!    empty** database. Once claimed, it is a durable capability: every
//!    writer of stack state must re-validate it **inside the same
//!    transaction** as the write (`SELECT … FOR UPDATE`). A boot-only
//!    check cannot close the window between check and write.
//! 2. **Data presence without a marker is unconditional refusal.** Same-
//!    side sentinel data must never auto-claim a stack. Only a DB with
//!    neither marker nor either side's scan rows may claim.
//! 3. **Opposite-side data** blocks even when the marker matches (defense
//!    in depth after a partial backup restore).
//!
//! Fail loud. Never fall back to the other stack.
//!
//! ## Process claim lives in `stack-policy`
//!
//! The in-process mode registry and
//! [`ensure_legacy_publisher_allowed`](stack_policy::ensure_legacy_publisher_allowed)
//! live in the shared `stack-policy` crate so `esplora-bound` can run the
//! same check inside its broadcast-client constructor. This module owns
//! the **database** marker / data checks and re-exports the process-mode
//! surface for existing `node::v1` call sites.

use anyhow::{bail, Context, Result};
use sqlx::{PgPool, Postgres, Transaction};

// Process-wide claim registry + legacy-publisher policy (shared crate).
// Production surface only — the test-only reset is `#[cfg(test)]` of
// `stack-policy` itself and is intentionally **not** re-exported here.
// Dependency builds never see that symbol (no Cargo feature seam).
pub use stack_policy::{
    ensure_legacy_publisher_allowed, process_stack_mode, set_process_stack_mode, ScanStackMode,
    STACK_SEPARATION_REFUSAL,
};

/// Canonical error prefix when a writer finds no matching marker in-tx.
pub const STACK_CAPABILITY_REFUSAL: &str = "stack separation: refusing write";

/// SQL: any durable legacy scan-stack row across **all** legacy tables.
///
/// `persist_state_tx` writes `smt_state` / `mmr_state` / `latest_block` even
/// when no `mmr_root_index` entry is present, so emptiness must not be
/// decided on the root-index alone.
const LEGACY_SCAN_STATE_COUNT_SQL: &str = "SELECT \
    (SELECT COUNT(*) FROM mmr_root_index) \
  + (SELECT COUNT(*) FROM smt_state) \
  + (SELECT COUNT(*) FROM mmr_state) \
  + (SELECT COUNT(*) FROM latest_block)";

/// SQL: any durable v1.1 scan-stack row across the six engine tables.
const V1_SCAN_STATE_COUNT_SQL: &str = "SELECT \
    (SELECT COUNT(*) FROM v1_engine_meta) \
  + (SELECT COUNT(*) FROM v1_nflog_entries) \
  + (SELECT COUNT(*) FROM v1_nullifier_index) \
  + (SELECT COUNT(*) FROM v1_accounts) \
  + (SELECT COUNT(*) FROM v1_spendable_coins) \
  + (SELECT COUNT(*) FROM v1_spent_coins)";

/// True when any durable legacy scan-stack table has rows
/// (`mmr_root_index`, `smt_state`, `mmr_state`, `latest_block`).
pub async fn legacy_scan_state_present(pool: &PgPool) -> Result<bool> {
    let (n,): (i64,) = sqlx::query_as(LEGACY_SCAN_STATE_COUNT_SQL)
        .fetch_one(pool)
        .await
        .context("count legacy scan tables for stack separation")?;
    Ok(n > 0)
}

/// True when any v1.1 stack table has rows (meta, NfLog, index, accounts,
/// coins). Meta alone is enough: [`crate::v1::adapter::EngineAdapter::
/// load_or_create`] persists an empty genesis snapshot into
/// `v1_engine_meta`, and that must bind the database to v1.1 just as
/// strongly as a non-empty NfLog.
pub async fn v1_scan_state_present(pool: &PgPool) -> Result<bool> {
    let (n,): (i64,) = sqlx::query_as(V1_SCAN_STATE_COUNT_SQL)
        .fetch_one(pool)
        .await
        .context("count v1 tables for stack separation")?;
    Ok(n > 0)
}

/// Load the claimed mode, if any.
pub async fn load_stack_scan_mode(pool: &PgPool) -> Result<Option<ScanStackMode>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT mode FROM stack_scan_mode WHERE id = 1")
            .fetch_optional(pool)
            .await
            .context("load stack_scan_mode")?;
    match row {
        None => Ok(None),
        Some((mode,)) => Ok(Some(
            ScanStackMode::parse(&mode).map_err(|e| anyhow::anyhow!("{e}"))?,
        )),
    }
}

/// Test-only marker seed with the **same emptiness / data invariant** as
/// [`enforce_stack_scan_mode`] (no auto-claim over existing stack data).
///
/// Compiled out of production: a "test helper" that ships is a production
/// API. Production boot must use [`enforce_stack_scan_mode`] only.
/// Does **not** set process mode (tests that need a process claim call
/// [`set_process_stack_mode`] explicitly).
#[cfg(test)]
pub async fn claim_stack_scan_mode(pool: &PgPool, mode: ScanStackMode) -> Result<()> {
    let mut tx = pool.begin().await.context("begin claim_stack_scan_mode tx")?;

    let marker_row: Option<(String,)> =
        sqlx::query_as("SELECT mode FROM stack_scan_mode WHERE id = 1 FOR UPDATE")
            .fetch_optional(&mut *tx)
            .await
            .context("lock stack_scan_mode for claim_stack_scan_mode")?;
    let marker = match marker_row {
        None => None,
        Some((mode_s,)) => Some(
            ScanStackMode::parse(&mode_s).map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
    };

    let (legacy_n,): (i64,) = sqlx::query_as(LEGACY_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count legacy scan tables inside claim_stack_scan_mode")?;
    let (v1_n,): (i64,) = sqlx::query_as(V1_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count v1 tables inside claim_stack_scan_mode")?;
    let legacy_data = legacy_n > 0;
    let v1_data = v1_n > 0;

    if legacy_data && v1_data {
        bail!(
            "{STACK_SEPARATION_REFUSAL}: database carries BOTH legacy and v1.1 \
             scan-stack rows — refusing claim_stack_scan_mode"
        );
    }
    if marker.is_none() && (legacy_data || v1_data) {
        bail!(
            "{STACK_SEPARATION_REFUSAL} {}: stack_scan_mode marker is missing but \
             stack data already exists — claim_stack_scan_mode refuses to \
             auto-claim from data (same invariant as enforce_stack_scan_mode)",
            mode.as_str(),
        );
    }
    match mode {
        ScanStackMode::Legacy => {
            if v1_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy: v1.1 scan state is present; \
                     claim_stack_scan_mode refuses"
                );
            }
            if let Some(ScanStackMode::V1) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy: already claimed as v1; \
                     claim_stack_scan_mode refuses"
                );
            }
        }
        ScanStackMode::V1 => {
            if legacy_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} v1: legacy scan state is present; \
                     claim_stack_scan_mode refuses"
                );
            }
            if let Some(ScanStackMode::Legacy) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} v1: already claimed as legacy; \
                     claim_stack_scan_mode refuses"
                );
            }
        }
    }

    claim_stack_scan_mode_in_tx(&mut tx, mode).await?;
    tx.commit()
        .await
        .context("commit claim_stack_scan_mode tx")?;
    Ok(())
}

async fn claim_stack_scan_mode_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    mode: ScanStackMode,
) -> Result<()> {
    let result = sqlx::query(
        "INSERT INTO stack_scan_mode (id, mode, claimed_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(mode.as_str())
    .execute(&mut **tx)
    .await
    .context("claim stack_scan_mode")?;

    if result.rows_affected() == 0 {
        // Row already present — must match. Re-read under the same tx.
        let row: Option<(String,)> =
            sqlx::query_as("SELECT mode FROM stack_scan_mode WHERE id = 1 FOR UPDATE")
                .fetch_optional(&mut **tx)
                .await
                .context("load stack_scan_mode after claim conflict")?;
        let existing = row
            .map(|(m,)| ScanStackMode::parse(&m).map_err(|e| anyhow::anyhow!("{e}")))
            .transpose()?
            .context("stack_scan_mode row missing after conflict")?;
        if existing != mode {
            bail!(
                "{STACK_SEPARATION_REFUSAL} {want} scan stack: \
                 database is already claimed as {have} (no silent re-claim)",
                want = mode.as_str(),
                have = existing.as_str(),
            );
        }
    }
    Ok(())
}

/// Lock the marker row inside an open transaction and require `required`.
///
/// Call this as the **first** step of every transaction that writes scan
/// state. `SELECT … FOR UPDATE` serialises concurrent writers against the
/// marker and closes the check-then-write window: a concurrent marker
/// flip (or a missing marker) cannot race past a write that has already
/// observed an older snapshot outside the transaction.
///
/// A missing marker is an unconditional refusal — writers never invent a
/// claim. Only [`enforce_stack_scan_mode`] on a genuinely empty database
/// may insert the row.
pub async fn require_stack_mode_for_update(
    tx: &mut Transaction<'_, Postgres>,
    required: ScanStackMode,
) -> Result<()> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT mode FROM stack_scan_mode WHERE id = 1 FOR UPDATE")
            .fetch_optional(&mut **tx)
            .await
            .context("lock stack_scan_mode FOR UPDATE")?;

    match row {
        None => bail!(
            "{STACK_CAPABILITY_REFUSAL}: stack_scan_mode marker is missing; \
             refusing to write {want} scan state without an exclusive claim \
             (no silent claim-from-write)",
            want = required.as_str(),
        ),
        Some((mode_s,)) => {
            let mode = ScanStackMode::parse(&mode_s).map_err(|e| anyhow::anyhow!("{e}"))?;
            if mode != required {
                bail!(
                    "{STACK_CAPABILITY_REFUSAL}: stack_scan_mode is claimed as \
                     {have}; refusing to write {want} scan state in this \
                     transaction (no silent cross-stack write)",
                    have = mode.as_str(),
                    want = required.as_str(),
                );
            }
            Ok(())
        }
    }
}

/// Boot gate: selected path must be the only one that has ever scanned
/// this database. Claims the marker **only** when the DB is still empty
/// (no marker, no either-side scan data).
///
/// Emptiness check (every durable table of **both** stacks) and marker
/// insertion run in **one** transaction so a concurrent writer cannot
/// insert stack data between the check and the claim.
///
/// # Failures (all loud, no fall-back)
///
/// - Marker claims the opposite mode
/// - Opposite-side scan data is present
/// - Both sides have scan data (corrupt dual write)
/// - **Any** stack data exists while the marker is missing (no auto-claim)
pub async fn enforce_stack_scan_mode(pool: &PgPool, selected: ScanStackMode) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin enforce_stack_scan_mode transaction")?;

    // Lock the marker row if present so concurrent enforcers serialise.
    let marker_row: Option<(String,)> =
        sqlx::query_as("SELECT mode FROM stack_scan_mode WHERE id = 1 FOR UPDATE")
            .fetch_optional(&mut *tx)
            .await
            .context("lock stack_scan_mode for enforce")?;
    let marker = match marker_row {
        None => None,
        Some((mode_s,)) => Some(
            ScanStackMode::parse(&mode_s).map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
    };

    let (legacy_n,): (i64,) = sqlx::query_as(LEGACY_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count legacy scan tables inside enforce tx")?;
    let (v1_n,): (i64,) = sqlx::query_as(V1_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count v1 tables inside enforce tx")?;
    let legacy_data = legacy_n > 0;
    let v1_data = v1_n > 0;

    if legacy_data && v1_data {
        bail!(
            "{STACK_SEPARATION_REFUSAL}: database carries BOTH legacy \
             scan-stack rows (mmr_root_index/smt_state/mmr_state/latest_block) \
             and v1.1 tables — mixed Commitment and AggregateStateNullifierV3 \
             accumulators. Manual recovery required; refusing to start either path"
        );
    }

    // Missing marker + any stack data is unconditional refusal. Same-side
    // sentinel rows must never auto-claim (EngineAdapter could otherwise
    // leave v1_engine_meta under a later legacy claim).
    if marker.is_none() && (legacy_data || v1_data) {
        let which = match (legacy_data, v1_data) {
            (true, false) => {
                "legacy scan-stack rows (mmr_root_index/smt_state/mmr_state/latest_block)"
            }
            (false, true) => "v1.1 tables (meta/NfLog/accounts/coins)",
            _ => "stack data",
        };
        bail!(
            "{STACK_SEPARATION_REFUSAL} {want} scan stack: stack_scan_mode \
             marker is missing but {which} already exist. Only a genuinely \
             empty database may claim a stack — refuse rather than \
             claim-from-data (manual recovery required)",
            want = selected.as_str(),
        );
    }

    match selected {
        ScanStackMode::Legacy => {
            if v1_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy scan stack: \
                     v1.1 scan state is present (v1 tables). \
                     A commitment scanner must never write into a database \
                     that already folds AggregateStateNullifierV3"
                );
            }
            if let Some(ScanStackMode::V1) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy scan stack: \
                     stack_scan_mode is claimed as v1. Wipe or restore a \
                     legacy-only database; never flip the flag on a claimed DB"
                );
            }
        }
        ScanStackMode::V1 => {
            if legacy_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} v1.1 scan stack: \
                     legacy SMT/MMR scan state is present \
                     (mmr_root_index/smt_state/mmr_state/latest_block). \
                     An NfLog scanner must never fold into a database that \
                     already enforces Commitment first-write"
                );
            }
            if let Some(ScanStackMode::Legacy) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} v1.1 scan stack: \
                     stack_scan_mode is claimed as legacy. Wipe or restore a \
                     v1.1-only database; never flip the flag on a claimed DB"
                );
            }
        }
    }

    // Claim inside the same transaction as the emptiness / marker checks.
    claim_stack_scan_mode_in_tx(&mut tx, selected).await?;
    tx.commit()
        .await
        .context("commit enforce_stack_scan_mode transaction")?;
    set_process_stack_mode(selected);
    Ok(())
}

/// Establish the process stack claim the same way the node binary does
/// for dual-stack selection — from an already-resolved
/// [`super::mode::V1ShadowMode`].
///
/// Used by `bin/recover_inscription` so the recovery process claims
/// under `ZKCOINS_V1_SHADOW=1` before any broadcast client is built.
/// Tests call this with a pure mode value instead of hand-setting
/// [`set_process_stack_mode`] directly (which would skip the binary path).
pub fn claim_process_stack_from_shadow_mode(mode: super::mode::V1ShadowMode) {
    match mode {
        super::mode::V1ShadowMode::On => set_process_stack_mode(ScanStackMode::V1),
        super::mode::V1ShadowMode::Off => set_process_stack_mode(ScanStackMode::Legacy),
    }
}

/// Read `ZKCOINS_V1_SHADOW` and claim the process stack. Entry point for
/// `bin/recover_inscription` (and any other out-of-band legacy tool).
pub fn claim_process_stack_from_v1_shadow_env() -> Result<()> {
    let mode = super::mode::v1_shadow_mode_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    claim_process_stack_from_shadow_mode(mode);
    Ok(())
}

/// Refuse the v1.1 publisher unless this process claimed v1.1.
pub fn ensure_v1_publisher_allowed() -> Result<()> {
    match process_stack_mode() {
        Some(ScanStackMode::V1) => Ok(()),
        Some(ScanStackMode::Legacy) => bail!(
            "{STACK_SEPARATION_REFUSAL}: process is running the legacy scan stack; \
             AggregateStateNullifierV3 publish is forbidden (no silent fall-back)"
        ),
        None => bail!(
            "{STACK_SEPARATION_REFUSAL}: v1.1 publisher requires a process that \
             claimed ScanStackMode::V1 at boot (ZKCOINS_V1_SHADOW=1). \
             Refusing to publish without an exclusive stack claim"
        ),
    }
}

/// Require an exclusive v1.1 process claim before mutating NfLog state.
///
/// Unset process mode is **not** permitted: an unset mode previously
/// allowed writes that later left v1.1 data under a legacy marker.
/// Shared by scan apply paths and [`super::adapter::EngineAdapter::with_engine_mut`].
pub fn require_v1_process_for_nflog_write() -> Result<()> {
    match process_stack_mode() {
        Some(ScanStackMode::V1) => Ok(()),
        Some(ScanStackMode::Legacy) => bail!(
            "stack separation: refusing to fold NfLog while process \
             is claimed as legacy (no silent cross-stack write)"
        ),
        None => bail!(
            "stack separation: refusing to fold NfLog without a process \
             claim of ScanStackMode::V1 (no silent write under unset mode)"
        ),
    }
}
