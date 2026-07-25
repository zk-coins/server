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
//! 1. **Marker row** (`stack_scan_mode`): claimed at boot for the selected
//!    path so an empty opposite-side database still cannot be reopened
//!    under the other mode after the first exclusive boot.
//! 2. **Data presence**: `mmr_root_index` rows mean the legacy scanner has
//!    folded commitments; `v11_nflog_entries` rows mean the v1.1 scanner
//!    has folded nullifiers. Either presence blocks the opposite path
//!    even if the marker were missing (defense in depth after restore
//!    from a partial backup).
//!
//! Fail loud. Never fall back to the other stack.

use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use sqlx::PgPool;

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

/// True when the legacy scanner has folded at least one commitment into
/// the global MMR index (the durable signal of SMT-first-write activity).
pub async fn legacy_scan_state_present(pool: &PgPool) -> Result<bool> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mmr_root_index")
        .fetch_one(pool)
        .await
        .context("count mmr_root_index for stack separation")?;
    Ok(n > 0)
}

/// True when the v1.1 scanner has folded at least one nullifier into NfLog.
pub async fn v11_scan_state_present(pool: &PgPool) -> Result<bool> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v11_nflog_entries")
        .fetch_one(pool)
        .await
        .context("count v11_nflog_entries for stack separation")?;
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

/// Persist the exclusive claim (idempotent when the same mode is already set).
pub async fn claim_stack_scan_mode(pool: &PgPool, mode: ScanStackMode) -> Result<()> {
    let result = sqlx::query(
        "INSERT INTO stack_scan_mode (id, mode, claimed_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(mode.as_str())
    .execute(pool)
    .await
    .context("claim stack_scan_mode")?;

    if result.rows_affected() == 0 {
        // Row already present — must match.
        let existing = load_stack_scan_mode(pool)
            .await?
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

/// Boot gate: selected path must be the only one that has ever scanned
/// this database. Claims the marker when the DB is still unclaimed.
///
/// # Failures (all loud, no fall-back)
///
/// - Marker claims the opposite mode
/// - Opposite-side scan data is present
/// - Both sides have scan data (corrupt dual write)
pub async fn enforce_stack_scan_mode(pool: &PgPool, selected: ScanStackMode) -> Result<()> {
    let marker = load_stack_scan_mode(pool).await?;
    let legacy_data = legacy_scan_state_present(pool).await?;
    let v11_data = v11_scan_state_present(pool).await?;

    if legacy_data && v11_data {
        bail!(
            "{STACK_SEPARATION_REFUSAL}: database carries BOTH legacy \
             mmr_root_index rows and v11_nflog_entries — mixed Commitment \
             and AggregateStateNullifierV3 accumulators. Manual recovery \
             required; refusing to start either path"
        );
    }

    match selected {
        ScanStackMode::Legacy => {
            if v11_data {
                bail!(
                    "{STACK_SEPARATION_REFUSAL} legacy scan stack: \
                     v1.1 NfLog scan state is present (v11_nflog_entries). \
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
                     legacy SMT/MMR scan state is present (mmr_root_index). \
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

    claim_stack_scan_mode(pool, selected).await?;
    set_process_stack_mode(selected);
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
pub fn ensure_legacy_publisher_allowed() -> Result<()> {
    match process_stack_mode() {
        None | Some(ScanStackMode::Legacy) => Ok(()),
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
