//! Bootstrap-family kernel operations.
//!
//! Shared action-bound challenge store (Pull / AttestBalance / IssueViewGrant /
//! Entrust / Revoke), the process-local operational-bundle store for
//! `EntrustOperationalBundle` / `RevokeOperationalBundle` (§7.7 / §7.8), and
//! the verifying BMF1 bootstrap-manifest loader (§4.3 / §7.7).

pub(crate) mod bundle;
pub(crate) mod challenges;
pub(crate) mod manifest;

/// Crate-private bootstrap façade re-exports.
///
/// Invariant: **what is listed here is used via this façade
/// (`crate::kernel::bootstrap::…`); what is used via this façade is
/// listed here.** Callers must not reach the same names through
/// `crate::kernel::bootstrap::challenges::…` or
/// `crate::kernel::bootstrap::bundle::…`. A name used only from
/// `#[cfg(test)]` code does not belong on this list — tests import it
/// from the defining module when needed.
pub(crate) use bundle::{
    entrust_operational_bundle, revoke_operational_bundle, BundleProcedureDeps, BundleStore,
    EntrustCommand, EntrustResult, RevokeCommand, RevokeResult,
};
pub(crate) use challenges::{
    ChallengeAction, ChallengeConsumeError, ChallengeStore, IssuedChallenge, RedeemedPullChallenge,
};
pub(crate) use manifest::{
    bootstrap_manifest_path_from_env, load_manifest_store, LoadBootstrapManifestConfig,
    ManifestStore, BOOTSTRAP_MANIFEST_PATH_ENV,
};
