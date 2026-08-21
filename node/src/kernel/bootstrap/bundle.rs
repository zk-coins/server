//! Operational-bundle entrust / revoke (§7.7 / §7.8).
//!
//! ## Wire length (normative)
//!
//! ```text
//! serialize(OperationalBundle) :=
//!     version    (1 byte, = 0x01)
//!   ‖ ivk        (32 B)   // A/1' VIEW
//!   ‖ ovk        (32 B)   // A/1' outgoing-view
//!   ‖ op         (32 B)   // A/2' operational signing key
//!   ‖ nk         (32 B)   // A/3' nullifier key
//!   ‖ op_secret  (32 B)   // A/4' nav_rand secret
//! ```
//!
//! Total: `1 + 5×32 = 161` bytes. An unrecognised `version` or any other
//! length is `malformed_request` (expected and actual lengths in the
//! message). None of these five secrets is a SPEND-branch key (`A/0'/i'`);
//! the SPEND branch never crosses the kernel RPC surface.
//!
//! ## Storage
//!
//! Process-local [`BundleStore`] (same durability class as
//! [`ChallengeStore`]). No SQL table holds `{ivk, ovk, op}` today
//! (`v1_accounts` has `nk` + `op_secret` only). A durable full-bundle
//! table would be a **new migration** and is out of scope for this block
//! — see report GAP. In-memory is fail-closed on restart (bundle absent),
//! never a silent re-invention of secrets.
//!
//! ## Irreversibility
//!
//! Revoke is a CAS `Active → Revoked` tombstone under the subject key.
//! A second revoke does not win (`revoked: false`). After `Revoked`,
//! entrust is refused — the same secrets cannot be restored into this
//! process for that subject (structural, not policy text).
//!
//! ## Ordering (Revoke)
//!
//! 1. Redeem the single-use revoke challenge (atomic).
//! 2. Tombstone the slot (irreversible).
//! 3. Return the outcome — no fallible step after the effect that could
//!    mask a successful erase as an error.
//!
//! No `axum`, no `tonic`.

use std::fmt;
use std::sync::Arc;

use dashmap::DashMap;

use crate::kernel::bootstrap::{ChallengeAction, ChallengeStore};
use crate::kernel::types::{ChanBind, SubjectAddress};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};

/// Normative fixed length of `serialize(OperationalBundle)` (§7.7).
///
/// Decomposition: `1 (version) + 32 (ivk) + 32 (ovk) + 32 (op) + 32 (nk)
/// + 32 (op_secret) = 161`.
pub(crate) const OPERATIONAL_BUNDLE_LEN: usize = 161;

/// Sole accepted version byte (§7.7).
pub(crate) const OPERATIONAL_BUNDLE_VERSION: u8 = 0x01;

/// Parsed operational bundle. Secrets are never logged (see [`Debug`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct OperationalBundle {
    pub ivk: [u8; 32],
    pub ovk: [u8; 32],
    pub op: [u8; 32],
    pub nk: [u8; 32],
    pub op_secret: [u8; 32],
}

impl fmt::Debug for OperationalBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperationalBundle { /* redacted */ }")
    }
}

impl OperationalBundle {
    /// Parse the 161-byte §7.7 serialisation.
    ///
    /// Wrong length → `malformed_request` with expected and actual lengths.
    /// Wrong version → `malformed_request` naming the byte.
    pub(crate) fn parse(bytes: &[u8]) -> KernelResult<Self> {
        if bytes.len() != OPERATIONAL_BUNDLE_LEN {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!(
                    "operational bundle must be exactly {OPERATIONAL_BUNDLE_LEN} bytes \
                     (version‖ivk‖ovk‖op‖nk‖op_secret); got {}",
                    bytes.len()
                ),
            ));
        }
        let version = bytes[0];
        if version != OPERATIONAL_BUNDLE_VERSION {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!(
                    "operational bundle version must be 0x{OPERATIONAL_BUNDLE_VERSION:02x}; \
                     got 0x{version:02x}"
                ),
            ));
        }
        let mut ivk = [0u8; 32];
        let mut ovk = [0u8; 32];
        let mut op = [0u8; 32];
        let mut nk = [0u8; 32];
        let mut op_secret = [0u8; 32];
        ivk.copy_from_slice(&bytes[1..33]);
        ovk.copy_from_slice(&bytes[33..65]);
        op.copy_from_slice(&bytes[65..97]);
        nk.copy_from_slice(&bytes[97..129]);
        op_secret.copy_from_slice(&bytes[129..161]);
        Ok(Self {
            ivk,
            ovk,
            op,
            nk,
            op_secret,
        })
    }

    /// Canonical 161-byte serialisation (tests / round-trip).
    pub(crate) fn serialize(self) -> [u8; OPERATIONAL_BUNDLE_LEN] {
        let mut out = [0u8; OPERATIONAL_BUNDLE_LEN];
        out[0] = OPERATIONAL_BUNDLE_VERSION;
        out[1..33].copy_from_slice(&self.ivk);
        out[33..65].copy_from_slice(&self.ovk);
        out[65..97].copy_from_slice(&self.op);
        out[97..129].copy_from_slice(&self.nk);
        out[129..161].copy_from_slice(&self.op_secret);
        out
    }
}

/// Per-subject slot: active bundle or irreversible revoke tombstone.
#[derive(Clone, Debug)]
enum BundleSlot {
    Active(OperationalBundle),
    /// Subject was revoked in this process. Re-entrust is refused.
    Revoked,
}

/// Process-local operational-bundle store.
#[derive(Debug, Default)]
pub(crate) struct BundleStore {
    /// Keyed by subject address raw bytes.
    by_subject: DashMap<[u8; 32], BundleSlot>,
}

impl BundleStore {
    pub(crate) fn new() -> Self {
        Self {
            by_subject: DashMap::new(),
        }
    }

    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Operational signing key when the subject currently holds an active bundle.
    pub(crate) fn op_sk(&self, subject: &SubjectAddress) -> Option<[u8; 32]> {
        match self.by_subject.get(&subject.0)?.value() {
            BundleSlot::Active(b) => Some(b.op),
            BundleSlot::Revoked => None,
        }
    }

    /// Full active operational bundle (`ivk`/`ovk`/`op`/`nk`/`op_secret`).
    ///
    /// `None` when the subject has never been entrusted in this process or has
    /// been revoked. Callers **must** treat absence as a named error — there
    /// is no default key material (BundleStore is process-local only).
    pub(crate) fn get_active(&self, subject: &SubjectAddress) -> Option<OperationalBundle> {
        match self.by_subject.get(&subject.0)?.value() {
            BundleSlot::Active(b) => Some(*b),
            BundleSlot::Revoked => None,
        }
    }

    /// Whether the subject currently has an active (non-revoked) bundle.
    pub(crate) fn is_active(&self, subject: &SubjectAddress) -> bool {
        matches!(
            self.by_subject.get(&subject.0).as_deref(),
            Some(BundleSlot::Active(_))
        )
    }

    /// Test-only install that bypasses the challenge gate.
    ///
    /// Production entrust always goes through
    /// [`entrust_operational_bundle`]. This exists so unit tests for the
    /// §7.5 self-output rule can plant an active bundle without minting a
    /// full OwnershipProof challenge.
    #[cfg(test)]
    pub(crate) fn install_for_test(
        &self,
        subject: &SubjectAddress,
        bundle: OperationalBundle,
    ) -> bool {
        matches!(self.try_install(subject, bundle), InstallOutcome::Installed)
    }

    /// Snapshot every active (subject, bundle) pair — for ACK inbox polling
    /// and other process-local sweeps. Order is unspecified.
    pub(crate) fn list_active(&self) -> Vec<(SubjectAddress, OperationalBundle)> {
        self.by_subject
            .iter()
            .filter_map(|entry| match entry.value() {
                BundleSlot::Active(b) => Some((SubjectAddress(*entry.key()), *b)),
                BundleSlot::Revoked => None,
            })
            .collect()
    }

    /// Whether the subject is under a revoke tombstone.
    pub(crate) fn is_revoked(&self, subject: &SubjectAddress) -> bool {
        matches!(
            self.by_subject.get(&subject.0).as_deref(),
            Some(BundleSlot::Revoked)
        )
    }

    /// Install a bundle. Refuses when the subject is revoked or already active.
    ///
    /// Returns `true` when installed, `false` when the slot was already occupied
    /// (caller maps to a typed error **before** challenge consume when possible).
    fn try_install(&self, subject: &SubjectAddress, bundle: OperationalBundle) -> InstallOutcome {
        use dashmap::mapref::entry::Entry;
        match self.by_subject.entry(subject.0) {
            Entry::Vacant(v) => {
                v.insert(BundleSlot::Active(bundle));
                InstallOutcome::Installed
            }
            Entry::Occupied(o) => match o.get() {
                BundleSlot::Revoked => InstallOutcome::RevokedTombstone,
                BundleSlot::Active(_) => InstallOutcome::AlreadyActive,
            },
        }
    }

    /// CAS `Active → Revoked` (or plant a tombstone when vacant).
    ///
    /// Returns whether **this** call performed the irreversible step.
    /// DashMap `entry` serialises concurrent writers on the same subject.
    fn try_revoke(&self, subject: &SubjectAddress) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.by_subject.entry(subject.0) {
            Entry::Vacant(v) => {
                // Never entrusted here — still plant a tombstone so a later
                // entrust cannot restore secrets after a verified revoke.
                v.insert(BundleSlot::Revoked);
                true
            }
            Entry::Occupied(mut o) => match *o.get() {
                BundleSlot::Active(_) => {
                    o.insert(BundleSlot::Revoked);
                    true
                }
                BundleSlot::Revoked => false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    Installed,
    AlreadyActive,
    RevokedTombstone,
}

/// Already-authorised entrust command (API verified OwnershipProof).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntrustCommand {
    pub subject: SubjectAddress,
    pub nonce: [u8; 32],
    pub chan_bind: ChanBind,
    /// Raw wire bytes — length checked inside the procedure.
    pub bundle_bytes: Vec<u8>,
}

/// Result of a successful entrust RPC (domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EntrustResult {
    pub accepted: bool,
}

/// Already-authorised revoke command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevokeCommand {
    pub subject: SubjectAddress,
    pub nonce: [u8; 32],
    pub chan_bind: ChanBind,
}

/// Result of a revoke RPC (domain).
///
/// `revoked == true` iff **this** call performed the irreversible erase
/// (or planted the tombstone). A second concurrent/serial call returns
/// `revoked == false` while the slot stays revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RevokeResult {
    pub revoked: bool,
}

/// Dependencies for entrust / revoke.
pub(crate) struct BundleProcedureDeps<'a> {
    pub challenges: &'a ChallengeStore,
    pub bundles: &'a BundleStore,
    pub allowed_chan_binds: &'a [[u8; 32]],
    pub now: u64,
}

/// `EntrustOperationalBundle` (§7.8 / §7.7).
///
/// # Ordering
///
/// 1. Parse 161-byte bundle (pure) — do not burn the nonce on bad length.
/// 2. Refuse revoked / already-active subjects (pure against current map).
/// 3. Redeem entrust challenge (atomic).
/// 4. Install bundle (map entry; if a concurrent revoke won, refuse without
///    claiming acceptance).
pub(crate) fn entrust_operational_bundle(
    deps: BundleProcedureDeps<'_>,
    command: EntrustCommand,
) -> KernelResult<EntrustResult> {
    let BundleProcedureDeps {
        challenges,
        bundles,
        allowed_chan_binds,
        now,
    } = deps;

    let bundle = OperationalBundle::parse(&command.bundle_bytes)?;
    // Layout lock: parse ∘ serialize is identity on every accepted wire form.
    // Catches a field-order drift between the two directions without a separate
    // fixture, and keeps `serialize` library-reachable (not test-only).
    let reencoded = bundle.serialize();
    if reencoded.as_slice() != command.bundle_bytes.as_slice() {
        return Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "operational bundle layout inconsistency",
            "OperationalBundle parse/serialize round-trip diverged — field order bug",
        ));
    }

    // Pre-consume checks so a doomed entrust does not burn a fresh nonce
    // when the subject is already sealed. A concurrent race after redeem
    // is re-checked at install.
    if bundles.is_revoked(&command.subject) {
        return Err(KernelError::new(
            KernelErrorCode::WrongPhase,
            "operational bundle for this subject has been revoked and cannot be restored",
        ));
    }
    if bundles.is_active(&command.subject) {
        return Err(KernelError::new(
            KernelErrorCode::WrongPhase,
            "operational bundle already entrusted for this subject",
        ));
    }

    challenges
        .redeem(
            ChallengeAction::Entrust,
            &command.nonce,
            &command.subject,
            &command.chan_bind,
            allowed_chan_binds,
            now,
        )
        .map_err(crate::kernel::bootstrap::ChallengeConsumeError::into_kernel_error)?;

    match bundles.try_install(&command.subject, bundle) {
        InstallOutcome::Installed => Ok(EntrustResult { accepted: true }),
        InstallOutcome::RevokedTombstone => {
            // Challenge already consumed; report the structural refusal.
            // Do not claim accepted — secrets are not held.
            Err(KernelError::new(
                KernelErrorCode::WrongPhase,
                "operational bundle for this subject has been revoked and cannot be restored",
            ))
        }
        InstallOutcome::AlreadyActive => Err(KernelError::new(
            KernelErrorCode::WrongPhase,
            "operational bundle already entrusted for this subject",
        )),
    }
}

/// `RevokeOperationalBundle` (§7.8 / §7.7).
///
/// # Ordering
///
/// 1. Redeem revoke challenge (atomic, single-use nonce).
/// 2. Tombstone / erase (irreversible) — no fallible work after this.
/// 3. Return `{ revoked }` reflecting whether **this** call won the CAS.
pub(crate) fn revoke_operational_bundle(
    deps: BundleProcedureDeps<'_>,
    command: RevokeCommand,
) -> KernelResult<RevokeResult> {
    let BundleProcedureDeps {
        challenges,
        bundles,
        allowed_chan_binds,
        now,
    } = deps;

    challenges
        .redeem(
            ChallengeAction::Revoke,
            &command.nonce,
            &command.subject,
            &command.chan_bind,
            allowed_chan_binds,
            now,
        )
        .map_err(crate::kernel::bootstrap::ChallengeConsumeError::into_kernel_error)?;

    // Irreversible effect. Return value is the CAS outcome — never convert
    // a successful erase into an Err after the fact.
    let revoked = bundles.try_revoke(&command.subject);
    Ok(RevokeResult { revoked })
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    use crate::kernel::bootstrap::ChallengeStore;

    fn subject(b: u8) -> SubjectAddress {
        SubjectAddress([b; 32])
    }

    /// Test helper: a `ChanBind` whose 32 bytes are all `b`.
    ///
    /// Not an authorisation primitive — the entrust/revoke path binds
    /// `(action, nonce, subject, chan_bind)` via [`ChallengeStore::redeem`].
    fn chan_bind_of(b: u8) -> ChanBind {
        ChanBind([b; 32])
    }

    fn sample_bundle() -> OperationalBundle {
        OperationalBundle {
            ivk: [0x11; 32],
            ovk: [0x22; 32],
            op: [0x33; 32],
            nk: [0x44; 32],
            op_secret: [0x55; 32],
        }
    }

    fn sample_bytes() -> Vec<u8> {
        sample_bundle().serialize().to_vec()
    }

    /// Property 4: length 160 and 162 → malformed; 161 accepted.
    #[test]
    fn entrust_length_is_exactly_161() {
        let err160 = OperationalBundle::parse(&[0u8; 160]).expect_err("160");
        assert_eq!(err160.code, KernelErrorCode::MalformedRequest);
        assert!(
            err160.public_message.contains("161") && err160.public_message.contains("160"),
            "message must carry expected and actual lengths: {}",
            err160.public_message
        );

        let err162 = OperationalBundle::parse(&[0u8; 162]).expect_err("162");
        assert_eq!(err162.code, KernelErrorCode::MalformedRequest);
        assert!(
            err162.public_message.contains("161") && err162.public_message.contains("162"),
            "message must carry expected and actual lengths: {}",
            err162.public_message
        );

        let ok = OperationalBundle::parse(&sample_bytes()).expect("161 with version 0x01");
        assert_eq!(ok, sample_bundle());
        // Compile-time lock on the decomposition used in the doc comment.
        const _: () = assert!(OPERATIONAL_BUNDLE_LEN == 1 + 32 + 32 + 32 + 32 + 32);
    }

    /// Field-order lock: `parse(serialize(x)) == x` with distinct per-field bytes.
    #[test]
    fn operational_bundle_serialize_parse_round_trip() {
        let original = OperationalBundle {
            ivk: [0x01; 32],
            ovk: [0x02; 32],
            op: [0x03; 32],
            nk: [0x04; 32],
            op_secret: [0x05; 32],
        };
        let bytes = original.serialize();
        assert_eq!(bytes.len(), OPERATIONAL_BUNDLE_LEN);
        assert_eq!(bytes[0], OPERATIONAL_BUNDLE_VERSION);
        // Distinct field markers — a swapped slice would fail the equality.
        assert_eq!(&bytes[1..33], &[0x01; 32]);
        assert_eq!(&bytes[33..65], &[0x02; 32]);
        assert_eq!(&bytes[65..97], &[0x03; 32]);
        assert_eq!(&bytes[97..129], &[0x04; 32]);
        assert_eq!(&bytes[129..161], &[0x05; 32]);
        let back = OperationalBundle::parse(&bytes).expect("round-trip parse");
        assert_eq!(
            back, original,
            "parse(serialize(x)) must equal x (field order)"
        );
        // Second direction: serialize(parse(wire)) == wire for a valid form.
        assert_eq!(back.serialize().as_slice(), bytes.as_slice());
    }

    #[test]
    fn wrong_version_is_malformed() {
        let mut bytes = sample_bytes();
        bytes[0] = 0x02;
        let err = OperationalBundle::parse(&bytes).expect_err("version");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("0x01") && err.public_message.contains("0x02"),
            "got: {}",
            err.public_message
        );
    }

    #[test]
    fn entrust_then_op_sk_available_and_revoke_clears() {
        let challenges = ChallengeStore::new();
        let bundles = BundleStore::new();
        let now = 1_000u64;
        let cb = chan_bind_of(0xCB);
        let allowed = [cb.0];
        let subj = subject(7);

        let issued = challenges.issue(ChallengeAction::Entrust, subj, now);
        let accepted = entrust_operational_bundle(
            BundleProcedureDeps {
                challenges: &challenges,
                bundles: &bundles,
                allowed_chan_binds: &allowed,
                now,
            },
            EntrustCommand {
                subject: subj,
                nonce: issued.nonce,
                chan_bind: cb,
                bundle_bytes: sample_bytes(),
            },
        )
        .expect("entrust");
        assert!(accepted.accepted);
        assert_eq!(bundles.op_sk(&subj), Some(sample_bundle().op));

        let issued_r = challenges.issue(ChallengeAction::Revoke, subj, now);
        let rev = revoke_operational_bundle(
            BundleProcedureDeps {
                challenges: &challenges,
                bundles: &bundles,
                allowed_chan_binds: &allowed,
                now,
            },
            RevokeCommand {
                subject: subj,
                nonce: issued_r.nonce,
                chan_bind: cb,
            },
        )
        .expect("revoke");
        assert!(rev.revoked, "first revoke must win");
        assert!(bundles.is_revoked(&subj));
        assert_eq!(bundles.op_sk(&subj), None);

        // Property 5 (serial): second revoke does not win; state stays revoked.
        let issued_r2 = challenges.issue(ChallengeAction::Revoke, subj, now);
        let rev2 = revoke_operational_bundle(
            BundleProcedureDeps {
                challenges: &challenges,
                bundles: &bundles,
                allowed_chan_binds: &allowed,
                now,
            },
            RevokeCommand {
                subject: subj,
                nonce: issued_r2.nonce,
                chan_bind: cb,
            },
        )
        .expect("second revoke is Ok");
        assert!(!rev2.revoked, "second revoke must not win");
        assert!(bundles.is_revoked(&subj), "state remains revoked");

        // Structural: re-entrust after revoke is refused.
        let issued_e2 = challenges.issue(ChallengeAction::Entrust, subj, now);
        let err = entrust_operational_bundle(
            BundleProcedureDeps {
                challenges: &challenges,
                bundles: &bundles,
                allowed_chan_binds: &allowed,
                now,
            },
            EntrustCommand {
                subject: subj,
                nonce: issued_e2.nonce,
                chan_bind: cb,
                bundle_bytes: sample_bytes(),
            },
        )
        .expect_err("re-entrust after revoke");
        assert_eq!(err.code, KernelErrorCode::WrongPhase);
        assert!(bundles.is_revoked(&subj));
        assert!(!bundles.is_active(&subj));
    }

    /// Property 5 (concurrent): exactly one revoke wins; both results checked.
    #[test]
    fn concurrent_revoke_exactly_one_wins() {
        let challenges = Arc::new(ChallengeStore::new());
        let bundles = Arc::new(BundleStore::new());
        let now = 2_000u64;
        let cb = chan_bind_of(0xAA);
        let allowed = Arc::new([cb.0]);
        let subj = subject(9);

        // Entrust first so there is something to erase.
        let issued_e = challenges.issue(ChallengeAction::Entrust, subj, now);
        entrust_operational_bundle(
            BundleProcedureDeps {
                challenges: challenges.as_ref(),
                bundles: bundles.as_ref(),
                allowed_chan_binds: allowed.as_slice(),
                now,
            },
            EntrustCommand {
                subject: subj,
                nonce: issued_e.nonce,
                chan_bind: cb,
                bundle_bytes: sample_bytes(),
            },
        )
        .expect("entrust");

        let n1 = challenges.issue(ChallengeAction::Revoke, subj, now).nonce;
        let n2 = challenges.issue(ChallengeAction::Revoke, subj, now).nonce;
        let barrier = Arc::new(Barrier::new(2));

        let spawn = |nonce: [u8; 32],
                     challenges: Arc<ChallengeStore>,
                     bundles: Arc<BundleStore>,
                     allowed: Arc<[[u8; 32]; 1]>,
                     barrier: Arc<Barrier>| {
            thread::spawn(move || {
                barrier.wait();
                revoke_operational_bundle(
                    BundleProcedureDeps {
                        challenges: challenges.as_ref(),
                        bundles: bundles.as_ref(),
                        allowed_chan_binds: allowed.as_slice(),
                        now,
                    },
                    RevokeCommand {
                        subject: subject(9),
                        nonce,
                        chan_bind: ChanBind(allowed[0]),
                    },
                )
            })
        };

        let h1 = spawn(
            n1,
            Arc::clone(&challenges),
            Arc::clone(&bundles),
            Arc::clone(&allowed),
            Arc::clone(&barrier),
        );
        let h2 = spawn(n2, challenges, Arc::clone(&bundles), allowed, barrier);
        let r1 = h1.join().expect("t1");
        let r2 = h2.join().expect("t2");

        let v1 = r1.expect("revoke 1 domain Ok");
        let v2 = r2.expect("revoke 2 domain Ok");
        let wins = [v1.revoked, v2.revoked].into_iter().filter(|w| *w).count();
        let losses = [v1.revoked, v2.revoked].into_iter().filter(|w| !*w).count();
        assert_eq!(
            wins, 1,
            "exactly one concurrent revoke must win; v1={v1:?} v2={v2:?}"
        );
        assert_eq!(losses, 1, "exactly one concurrent revoke must lose");
        assert!(
            bundles.is_revoked(&subj),
            "subject must remain revoked after the race"
        );
        assert_eq!(bundles.op_sk(&subj), None);
    }

    #[test]
    fn entrust_wrong_length_does_not_consume_nonce() {
        let challenges = ChallengeStore::new();
        let bundles = BundleStore::new();
        let now = 3_000u64;
        let cb = chan_bind_of(1);
        let allowed = [cb.0];
        let subj = subject(1);
        let issued = challenges.issue(ChallengeAction::Entrust, subj, now);
        let err = entrust_operational_bundle(
            BundleProcedureDeps {
                challenges: &challenges,
                bundles: &bundles,
                allowed_chan_binds: &allowed,
                now,
            },
            EntrustCommand {
                subject: subj,
                nonce: issued.nonce,
                chan_bind: cb,
                bundle_bytes: vec![0u8; 160],
            },
        )
        .expect_err("160 bytes");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        // Nonce still live — length check precedes redeem.
        assert!(challenges.contains(ChallengeAction::Entrust, &issued.nonce));
    }
}
