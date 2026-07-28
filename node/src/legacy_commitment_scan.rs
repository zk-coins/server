//! Stage 3+4 seal for the legacy Commitment → SMT/MMR scan loop.
//!
//! The production binary claims the exclusive v1 NfLog stack and never
//! obtains a [`LegacyCommitmentScanCap`]. Possession of that type was the
//! only proof a caller may fold a bincode [`shared::commitment::Commitment`]
//! into the SMT/MMR — and the type is unobtainable outside this crate's
//! own `#[cfg(test)]`.
//!
//! Stage 4 deleted the scan-loop body. The cap type remains so compile-fail
//! matrices can prove it is unconstructible at the package edge.

/// Capability token that once gated the legacy Commitment scan fold.
///
/// Private field; the only mint is [`LegacyCommitmentScanCap::mint_for_test`]
/// under `#[cfg(test)]` of this crate. Dependency builds never see that
/// constructor (no Cargo feature).
pub struct LegacyCommitmentScanCap {
    _private: (),
}

#[cfg(test)]
impl LegacyCommitmentScanCap {
    /// Residual unit-test mint. Absent from every dependency edge.
    pub(crate) fn mint_for_test() -> Self {
        Self { _private: () }
    }
}
