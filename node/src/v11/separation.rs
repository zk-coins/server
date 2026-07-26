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

use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use sqlx::{PgPool, Postgres, Transaction};

/// Which exclusive scan stack this process / database is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStackMode {
    /// Commitment inscriptions → global SMT + MMR (node default).
    Legacy,
    /// `AggregateStateNullifierV3` → NfLog first-occurrence (§3.6).
    V11,
}

impl ScanStackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V11 => "v11",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "legacy" => Ok(Self::Legacy),
            "v11" => Ok(Self::V11),
            other => bail!(
                "stack_scan_mode={other:?} is not a known mode \
                 (expected exactly \"legacy\" or \"v11\")"
            ),
        }
    }
}

/// Process-wide mode set at boot after [`enforce_stack_scan_mode`].
///
/// Publish / scan entry points consult this so a v1.1 process cannot
/// silently call the legacy commitment publisher (or the reverse).
///
/// `Mutex` (not `OnceLock`) so unit tests in the same process can reset
/// between cases; production boot still panics on conflicting re-set.
static PROCESS_STACK_MODE: Mutex<Option<ScanStackMode>> = Mutex::new(None);

/// Record the mode this process claimed. Panics if called twice with
/// conflicting values (a single process must not dual-boot).
pub fn set_process_stack_mode(mode: ScanStackMode) {
    let mut guard = PROCESS_STACK_MODE
        .lock()
        .expect("PROCESS_STACK_MODE mutex poisoned");
    match *guard {
        None => *guard = Some(mode),
        Some(existing) if existing == mode => {}
        Some(existing) => panic!(
            "set_process_stack_mode({:?}) conflicts with already-set {:?}",
            mode, existing
        ),
    }
}

/// Mode claimed by this process, if boot has run [`set_process_stack_mode`].
pub fn process_stack_mode() -> Option<ScanStackMode> {
    *PROCESS_STACK_MODE
        .lock()
        .expect("PROCESS_STACK_MODE mutex poisoned")
}

/// Test-only: drop the process claim so the next case can re-enforce.
#[cfg(test)]
pub fn clear_process_stack_mode_for_test() {
    *PROCESS_STACK_MODE
        .lock()
        .expect("PROCESS_STACK_MODE mutex poisoned") = None;
}

/// Canonical error prefix for hard-separation refusals (asserted in tests).
pub const STACK_SEPARATION_REFUSAL: &str = "stack separation: refusing to start";

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
const V11_SCAN_STATE_COUNT_SQL: &str = "SELECT \
    (SELECT COUNT(*) FROM v11_engine_meta) \
  + (SELECT COUNT(*) FROM v11_nflog_entries) \
  + (SELECT COUNT(*) FROM v11_nullifier_index) \
  + (SELECT COUNT(*) FROM v11_accounts) \
  + (SELECT COUNT(*) FROM v11_spendable_coins) \
  + (SELECT COUNT(*) FROM v11_spent_coins)";

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
/// coins). Meta alone is enough: [`crate::v11::adapter::EngineAdapter::
/// load_or_create`] persists an empty genesis snapshot into
/// `v11_engine_meta`, and that must bind the database to v1.1 just as
/// strongly as a non-empty NfLog.
pub async fn v11_scan_state_present(pool: &PgPool) -> Result<bool> {
    let (n,): (i64,) = sqlx::query_as(V11_SCAN_STATE_COUNT_SQL)
        .fetch_one(pool)
        .await
        .context("count v11 tables for stack separation")?;
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
        Some((mode,)) => Ok(Some(ScanStackMode::parse(&mode)?)),
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
        Some((mode_s,)) => Some(ScanStackMode::parse(&mode_s)?),
    };

    let (legacy_n,): (i64,) = sqlx::query_as(LEGACY_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count legacy scan tables inside claim_stack_scan_mode")?;
    let (v11_n,): (i64,) = sqlx::query_as(V11_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count v11 tables inside claim_stack_scan_mode")?;
    let legacy_data = legacy_n > 0;
    let v11_data = v11_n > 0;

    if legacy_data && v11_data {
        bail!(
            "{STACK_SEPARATION_REFUSAL}: database carries BOTH legacy and v1.1 \
             scan-stack rows — refusing claim_stack_scan_mode"
        );
    }
    if marker.is_none() && (legacy_data || v11_data) {
        bail!(
            "{STACK_SEPARATION_REFUSAL} {}: stack_scan_mode marker is missing but \
             stack data already exists — claim_stack_scan_mode refuses to \
             auto-claim from data (same invariant as enforce_stack_scan_mode)",
            mode.as_str(),
        );
    }
    match mode {
        ScanStackMode::Legacy => {
            if v11_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy: v1.1 scan state is present; \
                     claim_stack_scan_mode refuses"
                );
            }
            if let Some(ScanStackMode::V11) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy: already claimed as v11; \
                     claim_stack_scan_mode refuses"
                );
            }
        }
        ScanStackMode::V11 => {
            if legacy_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} v11: legacy scan state is present; \
                     claim_stack_scan_mode refuses"
                );
            }
            if let Some(ScanStackMode::Legacy) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} v11: already claimed as legacy; \
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
            .map(|(m,)| ScanStackMode::parse(&m))
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
            let mode = ScanStackMode::parse(&mode_s)?;
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
        Some((mode_s,)) => Some(ScanStackMode::parse(&mode_s)?),
    };

    let (legacy_n,): (i64,) = sqlx::query_as(LEGACY_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count legacy scan tables inside enforce tx")?;
    let (v11_n,): (i64,) = sqlx::query_as(V11_SCAN_STATE_COUNT_SQL)
        .fetch_one(&mut *tx)
        .await
        .context("count v11 tables inside enforce tx")?;
    let legacy_data = legacy_n > 0;
    let v11_data = v11_n > 0;

    if legacy_data && v11_data {
        bail!(
            "{STACK_SEPARATION_REFUSAL}: database carries BOTH legacy \
             scan-stack rows (mmr_root_index/smt_state/mmr_state/latest_block) \
             and v1.1 tables — mixed Commitment and AggregateStateNullifierV3 \
             accumulators. Manual recovery required; refusing to start either path"
        );
    }

    // Missing marker + any stack data is unconditional refusal. Same-side
    // sentinel rows must never auto-claim (EngineAdapter could otherwise
    // leave v11_engine_meta under a later legacy claim).
    if marker.is_none() && (legacy_data || v11_data) {
        let which = match (legacy_data, v11_data) {
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
            if v11_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy scan stack: \
                     v1.1 scan state is present (v11 tables). \
                     A commitment scanner must never write into a database \
                     that already folds AggregateStateNullifierV3"
                );
            }
            if let Some(ScanStackMode::V11) = marker {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy scan stack: \
                     stack_scan_mode is claimed as v11. Wipe or restore a \
                     legacy-only database; never flip the flag on a claimed DB"
                );
            }
        }
        ScanStackMode::V11 => {
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
/// [`super::mode::V11ShadowMode`].
///
/// Used by `bin/recover_inscription` so the recovery process claims
/// under `ZKCOINS_V11_SHADOW=1` before any broadcast client is built.
/// Tests call this with a pure mode value instead of hand-setting
/// [`set_process_stack_mode`] directly (which would skip the binary path).
pub fn claim_process_stack_from_shadow_mode(mode: super::mode::V11ShadowMode) {
    match mode {
        super::mode::V11ShadowMode::On => set_process_stack_mode(ScanStackMode::V11),
        super::mode::V11ShadowMode::Off => set_process_stack_mode(ScanStackMode::Legacy),
    }
}

/// Read `ZKCOINS_V11_SHADOW` and claim the process stack. Entry point for
/// `bin/recover_inscription` (and any other out-of-band legacy tool).
pub fn claim_process_stack_from_v11_shadow_env() -> Result<()> {
    let mode = super::mode::v11_shadow_mode_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    claim_process_stack_from_shadow_mode(mode);
    Ok(())
}

/// Refuse a publish path that does not match the process stack mode.
///
/// When the process has not claimed a mode yet (unit tests that never
/// boot dual-stack), only the **explicit** `required` check against a
/// known `Some(process)` mismatch fails. Unset process mode allows the
/// legacy publisher so existing tests stay green without a silent
/// cross-stack fall-back: the v1.1 publisher still requires an explicit
/// `ScanStackMode::V11` claim (see [`ensure_v11_publisher_allowed`]).
///
/// On success returns a [`esplora_bound::LegacyBroadcastWitness`]. This
/// function is the **sole production issuer** of that witness: the facade
/// constructor [`esplora_bound::EsploraBroadcastClient::connect`] requires
/// one, so a broadcast-capable client cannot exist without this check
/// having succeeded (or an explicit out-of-band mint under the
/// `issue-legacy-broadcast-witness` feature, which only `node` enables).
pub fn ensure_legacy_publisher_allowed() -> Result<esplora_bound::LegacyBroadcastWitness> {
    match process_stack_mode() {
        None | Some(ScanStackMode::Legacy) => {
            Ok(esplora_bound::LegacyBroadcastWitness::issue())
        }
        Some(ScanStackMode::V11) => bail!(
            "{STACK_SEPARATION_REFUSAL}: process is running the v1.1 scan stack; \
             legacy Commitment publish is forbidden (no silent fall-back to \
             commitment_data inscriptions)"
        ),
    }
}

/// Refuse the v1.1 publisher unless this process claimed v1.1.
pub fn ensure_v11_publisher_allowed() -> Result<()> {
    match process_stack_mode() {
        Some(ScanStackMode::V11) => Ok(()),
        Some(ScanStackMode::Legacy) => bail!(
            "{STACK_SEPARATION_REFUSAL}: process is running the legacy scan stack; \
             AggregateStateNullifierV3 publish is forbidden (no silent fall-back)"
        ),
        None => bail!(
            "{STACK_SEPARATION_REFUSAL}: v1.1 publisher requires a process that \
             claimed ScanStackMode::V11 at boot (ZKCOINS_V11_SHADOW=1). \
             Refusing to publish without an exclusive stack claim"
        ),
    }
}

/// Require an exclusive v1.1 process claim before mutating NfLog state.
///
/// Unset process mode is **not** permitted: an unset mode previously
/// allowed writes that later left v1.1 data under a legacy marker.
/// Shared by scan apply paths and [`super::adapter::EngineAdapter::with_engine_mut`].
pub fn require_v11_process_for_nflog_write() -> Result<()> {
    match process_stack_mode() {
        Some(ScanStackMode::V11) => Ok(()),
        Some(ScanStackMode::Legacy) => bail!(
            "stack separation: refusing to fold NfLog while process \
             is claimed as legacy (no silent cross-stack write)"
        ),
        None => bail!(
            "stack separation: refusing to fold NfLog without a process \
             claim of ScanStackMode::V11 (no silent write under unset mode)"
        ),
    }
}
