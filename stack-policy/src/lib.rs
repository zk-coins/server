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

use std::fmt;
use std::sync::Mutex;

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

    pub fn parse(s: &str) -> Result<Self, StackPolicyError> {
        match s {
            "legacy" => Ok(Self::Legacy),
            "v11" => Ok(Self::V11),
            other => Err(StackPolicyError::new(format!(
                "stack_scan_mode={other:?} is not a known mode \
                 (expected exactly \"legacy\" or \"v11\")"
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

/// Drop the process claim so the next test case can re-enforce.
///
/// Production boot never calls this. Always exported (not `cfg(test)`) so
/// the `node` test suite can reset the registry while depending on this
/// crate as a normal library target.
pub fn clear_process_stack_mode_for_test() {
    *PROCESS_STACK_MODE
        .lock()
        .expect("PROCESS_STACK_MODE mutex poisoned") = None;
}

/// Refuse a legacy publish / broadcast path that does not match the process
/// stack mode.
///
/// When the process has not claimed a mode yet (unit tests that never boot
/// dual-stack), unset process mode **allows** the legacy path so existing
/// tests stay green without a silent cross-stack fall-back. A process that
/// claimed [`ScanStackMode::V11`] always refuses.
///
/// Called from the `esplora-bound` broadcast-client constructor so every
/// construction of a broadcast-capable facade runs this check — including
/// callers inside `node` that bypass the node-side wrapper.
pub fn ensure_legacy_publisher_allowed() -> Result<(), StackPolicyError> {
    match process_stack_mode() {
        None | Some(ScanStackMode::Legacy) => Ok(()),
        Some(ScanStackMode::V11) => Err(StackPolicyError::new(format!(
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
    fn legacy_refused_under_v11_claim() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);
        let err = ensure_legacy_publisher_allowed().expect_err("v11 blocks legacy");
        assert!(
            err.to_string().contains(STACK_SEPARATION_REFUSAL),
            "got: {err}"
        );
        clear_process_stack_mode_for_test();
    }
}
