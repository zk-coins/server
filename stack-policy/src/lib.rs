//! Process-wide scan-stack policy shared by `node` and `esplora-bound`.
//!
//! ## Why a separate crate
//!
//! The process claim (legacy vs v1.1) must gate **every** construction of a
//! broadcast-capable Esplora facade. Keeping the registry and
//! [`ensure_legacy_publisher_allowed`] below both consumers means
//! `esplora-bound` can run the check inside its constructor without depending
//! on `node`, and `node` itself cannot bypass the check by calling the facade
//! directly.
//!
//! This crate is deliberately tiny: only the in-process mode registry and the
//! pure policy functions that consult it. Database marker enforcement stays in
//! `node` (sqlx / pool types). Fail loud; never fall back to the other stack.
//!
//! ## Monotonic process claim
//!
//! Production builds export only [`set_process_stack_mode`],
//! [`process_stack_mode`], and the policy check. Once a mode is claimed, no
//! public production API can withdraw it or switch to a different mode
//! (conflicting re-sets panic). The test-only reset is gated solely on
//! `#[cfg(test)]` **of this crate** — never a Cargo feature. `cfg(test)` is
//! not set when this library is compiled as a dependency, so no downstream
//! crate (dev-dependency, build-dependency, integration target, or
//! `--all-features`) can reopen the withdraw path.

use std::fmt;
use std::sync::Mutex;

/// Which exclusive scan stack this process / database is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStackMode {
    /// Commitment inscriptions → global SMT + MMR (node default).
    Legacy,
    /// `AggregateStateNullifierV3` → NfLog first-occurrence (§3.6).
    V1,
}

impl ScanStackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V1 => "v1",
        }
    }

    pub fn parse(s: &str) -> Result<Self, StackPolicyError> {
        match s {
            "legacy" => Ok(Self::Legacy),
            "v1" => Ok(Self::V1),
            other => Err(StackPolicyError::new(format!(
                "stack_scan_mode={other:?} is not a known mode \
                 (expected exactly \"legacy\" or \"v1\")"
            ))),
        }
    }
}

/// Canonical error prefix for hard-separation refusals (asserted in tests).
pub const STACK_SEPARATION_REFUSAL: &str = "stack separation: refusing to start";

/// Error from process-stack policy checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackPolicyError {
    message: String,
}

impl StackPolicyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for StackPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StackPolicyError {}

/// Process-wide mode set at boot after the database stack claim.
///
/// Publish / scan entry points consult this so a v1.1 process cannot
/// silently call the legacy commitment publisher (or the reverse).
///
/// Production claim is **monotonic**: [`set_process_stack_mode`] may only
/// set `None → Some(mode)` or re-affirm the same mode; conflicting re-sets
/// panic. The test-only clear is cfg-gated out of production builds.
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

/// Drop the process claim so the next unit-test case in **this crate** can
/// re-enforce.
///
/// Gated solely on `#[cfg(test)]` of the defining crate. That cfg is never
/// set when this library is compiled as a dependency — no Cargo feature, no
/// transitive activation, and no external test target can open this door.
/// Dependent crates that need isolation rely on process-per-test runners
/// (nextest) and must not withdraw a claim mid-process.
#[cfg(test)]
pub fn clear_process_stack_mode_for_test() {
    // Recover from poison so a `#[should_panic]` conflict test that panics
    // while holding the mutex does not brick later tests in the same
    // process (`cargo test` shares one process; nextest does not care).
    let mut guard = match PROCESS_STACK_MODE.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            PROCESS_STACK_MODE.clear_poison();
            poisoned.into_inner()
        }
    };
    *guard = None;
}

/// Refuse a legacy publish / broadcast path that does not match the process
/// stack mode.
///
/// When the process has not claimed a mode yet (unit tests that never boot
/// dual-stack), unset process mode **allows** the legacy path so existing
/// tests stay green without a silent cross-stack fall-back. A process that
/// claimed [`ScanStackMode::V1`] always refuses.
///
/// Called from the `esplora-bound` broadcast-client constructor so every
/// construction of a broadcast-capable facade runs this check — including
/// callers inside `node` that bypass the node-side wrapper.
pub fn ensure_legacy_publisher_allowed() -> Result<(), StackPolicyError> {
    match process_stack_mode() {
        None | Some(ScanStackMode::Legacy) => Ok(()),
        Some(ScanStackMode::V1) => Err(StackPolicyError::new(format!(
            "{STACK_SEPARATION_REFUSAL}: process is running the v1.1 scan stack; \
             legacy Commitment publish is forbidden (no silent fall-back to \
             commitment_data inscriptions)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_allowed_when_unclaimed_or_legacy() {
        clear_process_stack_mode_for_test();
        ensure_legacy_publisher_allowed().expect("unclaimed");
        set_process_stack_mode(ScanStackMode::Legacy);
        ensure_legacy_publisher_allowed().expect("legacy claim");
        clear_process_stack_mode_for_test();
    }

    #[test]
    fn legacy_refused_under_v1_claim() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V1);
        let err = ensure_legacy_publisher_allowed().expect_err("v1 blocks legacy");
        assert!(
            err.to_string().contains(STACK_SEPARATION_REFUSAL),
            "got: {err}"
        );
        clear_process_stack_mode_for_test();
    }

    /// Once a mode is claimed, no sequence of **production** public APIs
    /// (`set_process_stack_mode`, `process_stack_mode`,
    /// `ensure_legacy_publisher_allowed`) can withdraw the claim or yield a
    /// successful legacy-broadcast allowance under a different/absent mode.
    /// (The test-only clear is used only for fixture isolation here.)
    ///
    /// Conflicting re-set is covered by
    /// [`conflicting_set_process_stack_mode_panics`] — not catch_unwind'd
    /// here, because a panic while holding the registry mutex would poison
    /// it for later tests in the same process.
    #[test]
    fn process_claim_is_monotonic_under_public_production_api() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V1);

        // Re-affirming the same mode is a no-op, not a reset.
        set_process_stack_mode(ScanStackMode::V1);
        assert_eq!(process_stack_mode(), Some(ScanStackMode::V1));

        // Legacy broadcast path stays refused for the life of the claim.
        let err = ensure_legacy_publisher_allowed().expect_err("still v1");
        assert!(
            err.to_string().contains(STACK_SEPARATION_REFUSAL),
            "got: {err}"
        );

        // No production export returns the registry to unclaimed. The only
        // withdraw path is clear_process_stack_mode_for_test, which is
        // cfg(test) of this crate only — absent from every dependency edge.
        clear_process_stack_mode_for_test();
    }

    /// Conflicting `set_process_stack_mode` panics — the claim cannot flip
    /// from V1 to Legacy (or the reverse) via the production API.
    #[test]
    #[should_panic(expected = "conflicts with already-set")]
    fn conflicting_set_process_stack_mode_panics() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V1);
        set_process_stack_mode(ScanStackMode::Legacy);
    }

    /// Inventory of this crate's public surface that can mutate the
    /// process registry: only `set_process_stack_mode` (monotonic) and
    /// `clear_process_stack_mode_for_test` (test-only). Nothing else can
    /// move the registry out from under an existing client.
    #[test]
    fn only_test_clear_can_withdraw_process_claim() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::Legacy);
        assert_eq!(process_stack_mode(), Some(ScanStackMode::Legacy));
        // Production mutators cannot clear:
        set_process_stack_mode(ScanStackMode::Legacy); // re-affirm only
        assert_eq!(process_stack_mode(), Some(ScanStackMode::Legacy));
        // Withdraw is exclusively the test helper:
        clear_process_stack_mode_for_test();
        assert_eq!(process_stack_mode(), None);
    }
}
