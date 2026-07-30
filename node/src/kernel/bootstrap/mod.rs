//! Bootstrap-family kernel operations.
//!
//! Block 5 lands the shared challenge store used by action-bound
//! OwnershipProof gates (`AttestBalance`, `IssueViewGrant`). Entrust /
//! revoke of the operational bundle arrive in a later block.

pub(crate) mod challenges;

/// Crate-private bootstrap façade re-exports.
///
/// Invariant: **what is listed here is used via this façade
/// (`crate::kernel::bootstrap::…`); what is used via this façade is
/// listed here.** Callers must not reach the same names through
/// `crate::kernel::bootstrap::challenges::…`. A name used only from
/// `#[cfg(test)]` code does not belong on this list — tests import it
/// from the defining module when needed.
pub(crate) use challenges::{
    ChallengeAction, ChallengeConsumeError, ChallengeStore, IssuedChallenge,
};
