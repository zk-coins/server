//! Shared single-use challenge store for action-bound OwnershipProof gates.
//!
//! Normative sources:
//! - §5.1 challenge–response (nonce, expiry RECOMMENDED 60s, single-use)
//! - §5.1 action-bound domains for AttestBalance / IssueGrant
//! - §7.5 closed error codes (`challenge_expired` / `unauthorized`)
//! - §7.8: kernel receives `chan_bind` as an opaque 32-byte equality token
//!
//! ## Structural action binding
//!
//! [`ChallengeAction`] is a closed Rust enum. Each action owns a **separate**
//! map. A nonce issued under [`ChallengeAction::AttestBalance`] is stored
//! only in that map; redeem for [`ChallengeAction::IssueViewGrant`] never
//! consults it. Cross-action reuse is therefore impossible by construction
//! — not by a late string comparison after a successful lookup.
//!
//! ## Race-safe consume
//!
//! Consume uses a single atomic `DashMap::remove` on the action's map
//! (the same "one writer wins" form as the job store's `from`-CAS). Two
//! concurrent redeems of the same nonce: exactly one observes `Some`; the
//! loser gets [`ChallengeConsumeError::UnknownOrConsumed`]. There is no
//! read-check-write window.

use std::sync::Arc;

use dashmap::DashMap;

use crate::kernel::types::{ChanBind, SubjectAddress};
use crate::kernel::{KernelError, KernelErrorCode};

/// §5.1 RECOMMENDED challenge TTL: 60 seconds.
///
/// Spec: "The node sets `expiry` to a short window after issuance
/// (**RECOMMENDED 60 seconds**)" — Access & Explorer §5.1.
pub(crate) const CHALLENGE_TTL_SECS: u64 = 60;

/// Closed set of actions a challenge may authorise.
///
/// New actions (pull, entrust, revoke) land with their own blocks; they are
/// deliberately absent here so an incomplete surface cannot issue them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ChallengeAction {
    /// `POST /v1/attest/balance` — domain `zkCoins/v1/AttestBalanceChallenge`.
    AttestBalance,
    /// `POST /v1/grants` — domain `zkCoins/v1/IssueGrantChallenge`.
    IssueViewGrant,
}

impl ChallengeAction {
    /// §5.1 / §7.5 challenge domain string for this action.
    ///
    /// Sole definition of the action-bound OwnershipProof domain separators.
    /// Callers (HTTP challenge response, signed `chal` preimage) **must**
    /// take the string from here — never re-declare it beside this enum.
    pub(crate) const fn domain(self) -> &'static str {
        match self {
            Self::AttestBalance => "zkCoins/v1/AttestBalanceChallenge",
            Self::IssueViewGrant => "zkCoins/v1/IssueGrantChallenge",
        }
    }
}

/// Server-side record for one issued challenge.
///
/// `action` is **not** stored here: the map identity is the action. That is
/// the structural binding.
#[derive(Clone, Debug)]
struct ChallengeRecord {
    subject: SubjectAddress,
    expiry: u64,
}

/// Outcome of a successful issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IssuedChallenge {
    pub nonce: [u8; 32],
    pub expiry: u64,
    pub action: ChallengeAction,
}

/// Outcome of a successful single-use redeem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedeemedChallenge {
    pub subject: SubjectAddress,
    pub expiry: u64,
    pub action: ChallengeAction,
}

/// Typed consume failure — cause identity, never message-text parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeConsumeError {
    /// Nonce unknown, already consumed, or issued under a different action
    /// (structurally unfindable in this action's map).
    UnknownOrConsumed,
    /// `expiry` has passed (§5.1 / §7.5 `challenge_expired`).
    Expired,
    /// Stored subject does not match the redeem request.
    SubjectMismatch,
    /// Provided `chan_bind` is not one of the node's authoritative binds.
    ChanBindMismatch,
}

impl ChallengeConsumeError {
    pub(crate) fn into_kernel_error(self) -> KernelError {
        match self {
            Self::UnknownOrConsumed => KernelError::new(
                KernelErrorCode::ChallengeExpired,
                "challenge nonce unknown or already consumed",
            ),
            Self::Expired => {
                KernelError::new(KernelErrorCode::ChallengeExpired, "challenge nonce expired")
            }
            Self::SubjectMismatch => KernelError::new(
                KernelErrorCode::Unauthorized,
                "challenge was issued for a different subject",
            ),
            Self::ChanBindMismatch => KernelError::new(
                KernelErrorCode::Unauthorized,
                "chan_bind does not match any authoritative host binding",
            ),
        }
    }
}

impl std::fmt::Display for ChallengeConsumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOrConsumed => f.write_str("challenge nonce unknown or already consumed"),
            Self::Expired => f.write_str("challenge nonce expired"),
            Self::SubjectMismatch => f.write_str("challenge was issued for a different subject"),
            Self::ChanBindMismatch => {
                f.write_str("chan_bind does not match any authoritative host binding")
            }
        }
    }
}

impl std::error::Error for ChallengeConsumeError {}

/// Process-local single-use challenge store.
///
/// No SQL table exists for challenges today (checked migrations 0001–0029);
/// in-memory is the existing G6 surface. A durable table would be a new
/// migration and is out of scope for this block.
#[derive(Debug, Default)]
pub(crate) struct ChallengeStore {
    /// Nonces issued for [`ChallengeAction::AttestBalance`] only.
    attest_balance: DashMap<[u8; 32], ChallengeRecord>,
    /// Nonces issued for [`ChallengeAction::IssueViewGrant`] only.
    issue_view_grant: DashMap<[u8; 32], ChallengeRecord>,
}

impl ChallengeStore {
    pub(crate) fn new() -> Self {
        Self {
            attest_balance: DashMap::new(),
            issue_view_grant: DashMap::new(),
        }
    }

    /// Shared handle used by AppState / KernelService.
    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn map_for(&self, action: ChallengeAction) -> &DashMap<[u8; 32], ChallengeRecord> {
        match action {
            ChallengeAction::AttestBalance => &self.attest_balance,
            ChallengeAction::IssueViewGrant => &self.issue_view_grant,
        }
    }

    /// Issue a fresh single-use challenge for `action` and `subject`.
    ///
    /// `expiry = now + CHALLENGE_TTL_SECS` (§5.1 RECOMMENDED 60s). Nonce is
    /// 32 CSPRNG bytes (two UUID v4 values) — no fixed-nonce fallback.
    pub(crate) fn issue(
        &self,
        action: ChallengeAction,
        subject: SubjectAddress,
        now: u64,
    ) -> IssuedChallenge {
        let mut nonce = [0u8; 32];
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        nonce[..16].copy_from_slice(a.as_bytes());
        nonce[16..].copy_from_slice(b.as_bytes());
        // Saturating: a clock near u64::MAX must not wrap expiry into the past.
        let expiry = now.saturating_add(CHALLENGE_TTL_SECS);
        self.map_for(action)
            .insert(nonce, ChallengeRecord { subject, expiry });
        IssuedChallenge {
            nonce,
            expiry,
            action,
        }
    }

    /// Atomically consume a challenge for **exactly** `action`.
    ///
    /// # Checks (after the atomic take)
    ///
    /// 1. `expiry >= now` — else [`ChallengeConsumeError::Expired`]
    /// 2. stored subject == `subject` — else [`SubjectMismatch`]
    /// 3. `chan_bind` is equal to one of `allowed_chan_binds` — else
    ///    [`ChanBindMismatch`] (checked **on redeem**, not only at issue;
    ///    issue never observes `chan_bind`)
    ///
    /// # Race safety
    ///
    /// `DashMap::remove` is one atomic map operation. Concurrent redeems of
    /// the same `(action, nonce)`: exactly one returns `Ok`; every other
    /// returns [`UnknownOrConsumed`]. No separate read/check/write steps.
    pub(crate) fn redeem(
        &self,
        action: ChallengeAction,
        nonce: &[u8; 32],
        subject: &SubjectAddress,
        chan_bind: &ChanBind,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
    ) -> Result<RedeemedChallenge, ChallengeConsumeError> {
        // Atomic take — structural action binding: wrong-action maps are
        // never consulted, so a foreign-action nonce is unfindable here.
        let record = match self.map_for(action).remove(nonce) {
            Some((_, r)) => r,
            None => return Err(ChallengeConsumeError::UnknownOrConsumed),
        };

        if record.expiry < now {
            return Err(ChallengeConsumeError::Expired);
        }
        if record.subject != *subject {
            return Err(ChallengeConsumeError::SubjectMismatch);
        }
        if !chan_bind_allowed(chan_bind, allowed_chan_binds) {
            return Err(ChallengeConsumeError::ChanBindMismatch);
        }

        Ok(RedeemedChallenge {
            subject: record.subject,
            expiry: record.expiry,
            action,
        })
    }

    /// Test / diagnostics: whether `nonce` is still live for `action`.
    #[cfg(test)]
    pub(crate) fn contains(&self, action: ChallengeAction, nonce: &[u8; 32]) -> bool {
        self.map_for(action).contains_key(nonce)
    }

    /// Test: number of live challenges for `action`.
    #[cfg(test)]
    pub(crate) fn len(&self, action: ChallengeAction) -> usize {
        self.map_for(action).len()
    }
}

fn chan_bind_allowed(chan_bind: &ChanBind, allowed: &[[u8; 32]]) -> bool {
    allowed.iter().any(|b| b == &chan_bind.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn subject(b: u8) -> SubjectAddress {
        SubjectAddress([b; 32])
    }

    fn bind(b: u8) -> ChanBind {
        ChanBind([b; 32])
    }

    #[test]
    fn action_domains_are_distinct_and_closed() {
        assert_eq!(
            ChallengeAction::AttestBalance.domain(),
            "zkCoins/v1/AttestBalanceChallenge"
        );
        assert_eq!(
            ChallengeAction::IssueViewGrant.domain(),
            "zkCoins/v1/IssueGrantChallenge"
        );
        assert_ne!(
            ChallengeAction::AttestBalance.domain(),
            ChallengeAction::IssueViewGrant.domain()
        );
    }

    #[test]
    fn ttl_is_spec_recommended_sixty_seconds() {
        assert_eq!(CHALLENGE_TTL_SECS, 60);
        let store = ChallengeStore::new();
        let now = 1_700_000_000u64;
        let issued = store.issue(ChallengeAction::AttestBalance, subject(1), now);
        assert_eq!(issued.expiry, now + 60);
    }

    #[test]
    fn single_use_second_redeem_is_unknown_or_consumed() {
        let store = ChallengeStore::new();
        let now = 100u64;
        let issued = store.issue(ChallengeAction::AttestBalance, subject(2), now);
        let allowed = [[0xABu8; 32]];
        let cb = ChanBind(allowed[0]);

        let first = store
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject(2),
                &cb,
                &allowed,
                now,
            )
            .expect("first redeem wins");
        assert_eq!(first.action, ChallengeAction::AttestBalance);
        assert_eq!(first.subject, subject(2));

        let second = store
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject(2),
                &cb,
                &allowed,
                now,
            )
            .expect_err("second redeem must fail");
        assert_eq!(
            second,
            ChallengeConsumeError::UnknownOrConsumed,
            "cause must be UnknownOrConsumed, not a bare is_err"
        );
        assert_eq!(
            second.into_kernel_error().code,
            KernelErrorCode::ChallengeExpired
        );
    }

    #[test]
    fn expired_challenge_yields_challenge_expired() {
        let store = ChallengeStore::new();
        let now = 50u64;
        let issued = store.issue(ChallengeAction::AttestBalance, subject(3), now);
        let allowed = [[1u8; 32]];
        let err = store
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject(3),
                &ChanBind(allowed[0]),
                &allowed,
                issued.expiry + 1,
            )
            .expect_err("past expiry");
        assert_eq!(err, ChallengeConsumeError::Expired);
        assert_eq!(
            err.into_kernel_error().code,
            KernelErrorCode::ChallengeExpired
        );
    }

    #[test]
    fn action_a_not_redeemable_as_b_and_reverse() {
        let store = ChallengeStore::new();
        let now = 10u64;
        let allowed = [[9u8; 32]];
        let cb = ChanBind(allowed[0]);

        let attest = store.issue(ChallengeAction::AttestBalance, subject(4), now);
        let grant = store.issue(ChallengeAction::IssueViewGrant, subject(5), now);

        // Attest nonce under IssueViewGrant map → unfindable.
        let err = store
            .redeem(
                ChallengeAction::IssueViewGrant,
                &attest.nonce,
                &subject(4),
                &cb,
                &allowed,
                now,
            )
            .expect_err("attest challenge must not redeem as grant");
        assert_eq!(err, ChallengeConsumeError::UnknownOrConsumed);
        // Still live under its own action.
        assert!(store.contains(ChallengeAction::AttestBalance, &attest.nonce));

        // Grant nonce under AttestBalance map → unfindable.
        let err = store
            .redeem(
                ChallengeAction::AttestBalance,
                &grant.nonce,
                &subject(5),
                &cb,
                &allowed,
                now,
            )
            .expect_err("grant challenge must not redeem as attest");
        assert_eq!(err, ChallengeConsumeError::UnknownOrConsumed);
        assert!(store.contains(ChallengeAction::IssueViewGrant, &grant.nonce));

        // Own-action redeems still succeed.
        store
            .redeem(
                ChallengeAction::AttestBalance,
                &attest.nonce,
                &subject(4),
                &cb,
                &allowed,
                now,
            )
            .expect("own-action attest redeem");
        store
            .redeem(
                ChallengeAction::IssueViewGrant,
                &grant.nonce,
                &subject(5),
                &cb,
                &allowed,
                now,
            )
            .expect("own-action grant redeem");
    }

    #[test]
    fn concurrent_redeem_exactly_one_wins() {
        let store = Arc::new(ChallengeStore::new());
        let now = 1_000u64;
        let issued = store.issue(ChallengeAction::AttestBalance, subject(7), now);
        let allowed = Arc::new([[0xCDu8; 32]]);
        let barrier = Arc::new(Barrier::new(2));

        let make =
            |store: Arc<ChallengeStore>, barrier: Arc<Barrier>, allowed: Arc<[[u8; 32]; 1]>| {
                let nonce = issued.nonce;
                thread::spawn(move || {
                    barrier.wait();
                    store.redeem(
                        ChallengeAction::AttestBalance,
                        &nonce,
                        &subject(7),
                        &ChanBind(allowed[0]),
                        allowed.as_slice(),
                        now,
                    )
                })
            };

        let h1 = make(
            Arc::clone(&store),
            Arc::clone(&barrier),
            Arc::clone(&allowed),
        );
        let h2 = make(Arc::clone(&store), barrier, allowed);
        let r1 = h1.join().expect("thread 1");
        let r2 = h2.join().expect("thread 2");

        let wins = [r1.is_ok(), r2.is_ok()]
            .into_iter()
            .filter(|ok| *ok)
            .count();
        let losses = [r1.is_err(), r2.is_err()]
            .into_iter()
            .filter(|e| *e)
            .count();
        assert_eq!(
            wins, 1,
            "exactly one concurrent redeem must win; r1={r1:?} r2={r2:?}"
        );
        assert_eq!(losses, 1, "exactly one concurrent redeem must lose");

        // Loser cause is UnknownOrConsumed (atomic remove miss), not a
        // success masked as error.
        let loser = if r1.is_err() { r1 } else { r2 };
        assert_eq!(
            loser.expect_err("loser"),
            ChallengeConsumeError::UnknownOrConsumed
        );
    }

    #[test]
    fn wrong_chan_bind_is_rejected_on_redeem() {
        let store = ChallengeStore::new();
        let now = 20u64;
        let issued = store.issue(ChallengeAction::AttestBalance, subject(8), now);
        let allowed = [[0x11u8; 32]];
        let wrong = bind(0x22);
        let err = store
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject(8),
                &wrong,
                &allowed,
                now,
            )
            .expect_err("wrong chan_bind");
        assert_eq!(err, ChallengeConsumeError::ChanBindMismatch);
        assert_eq!(err.into_kernel_error().code, KernelErrorCode::Unauthorized);
        // Challenge is consumed (atomic take before checks) — no second try
        // with the correct bind.
        let err2 = store
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject(8),
                &ChanBind(allowed[0]),
                &allowed,
                now,
            )
            .expect_err("already taken");
        assert_eq!(err2, ChallengeConsumeError::UnknownOrConsumed);
    }

    #[test]
    fn subject_mismatch_is_unauthorized() {
        let store = ChallengeStore::new();
        let now = 30u64;
        let issued = store.issue(ChallengeAction::IssueViewGrant, subject(1), now);
        let allowed = [[0u8; 32]];
        let err = store
            .redeem(
                ChallengeAction::IssueViewGrant,
                &issued.nonce,
                &subject(2),
                &ChanBind(allowed[0]),
                &allowed,
                now,
            )
            .expect_err("wrong subject");
        assert_eq!(err, ChallengeConsumeError::SubjectMismatch);
        assert_eq!(err.into_kernel_error().code, KernelErrorCode::Unauthorized);
    }

    /// Redeem must drop the live record — no long-lived leak after consume.
    #[test]
    fn redeem_empties_store_for_action() {
        let store = ChallengeStore::new();
        let now = 40u64;
        assert_eq!(
            store.len(ChallengeAction::AttestBalance),
            0,
            "fresh store has no live attest challenges"
        );
        let issued = store.issue(ChallengeAction::AttestBalance, subject(9), now);
        assert_eq!(
            store.len(ChallengeAction::AttestBalance),
            1,
            "issue must place exactly one live record"
        );
        // Other action map stays empty (structural isolation).
        assert_eq!(store.len(ChallengeAction::IssueViewGrant), 0);

        let allowed = [[0xAAu8; 32]];
        store
            .redeem(
                ChallengeAction::AttestBalance,
                &issued.nonce,
                &subject(9),
                &ChanBind(allowed[0]),
                &allowed,
                now,
            )
            .expect("redeem");
        assert_eq!(
            store.len(ChallengeAction::AttestBalance),
            0,
            "successful redeem must remove the challenge (no store leak)"
        );
        assert!(
            !store.contains(ChallengeAction::AttestBalance, &issued.nonce),
            "nonce must not remain findable after redeem"
        );
    }
}
