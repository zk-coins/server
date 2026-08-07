//! Pull-session store (§5.1 pull session / §7.5 / §7.8).
//!
//! ## Ownership vs Grant — structural, not order-dependent
//!
//! Sessions are stored as [`ActiveSession`]: an enum whose variants are the
//! two admissible authorities. [`GetAccountState`](super::get_account_state)
//! matches on the variant — a grant session is unauthorised by construction
//! of the match arms, not by a later boolean check that could be reordered
//! past a data release. Record/proof procedures accept either variant via
//! [`ActiveSession::common`].
//!
//! ## Session errors
//!
//! Spec §7.5 collapses **unknown**, **expired**, and **chan_bind mismatch**
//! into a single machine code `session_expired` (HTTP 410). Missing or
//! empty bearer strings are a different class (`unauthorized` / 401) and
//! are rejected before lookup.
//!
//! ## No sliding expiry
//!
//! Spec: session expiry is independent of the challenge window and is set
//! at issue time. There is **no** "refresh on use" — lookup never mutates
//! `expiry`.
//!
//! ## Concurrency
//!
//! Sessions are multi-use credentials (unlike single-use challenges).
//! Concurrent lookups share one immutable snapshot of the record; there is
//! no consume-to-use race. Expired cleanup uses `DashMap::remove` so two
//! concurrent expired looks both observe `SessionError::Expired`.
//!
//! No SQL table exists for sessions (migrations 0001–0029). Process-local
//! only — a durable table would be a new migration (reported as GAP).

use std::sync::Arc;

use dashmap::DashMap;

use crate::kernel::grants::GrantScope;
use crate::kernel::types::{ChanBind, SubjectAddress};
use crate::kernel::{KernelError, KernelErrorCode};

/// §5.1 RECOMMENDED session TTL: a few minutes. Fixed at five minutes;
/// not extended by use.
pub(crate) const SESSION_TTL_SECS: u64 = 300;

/// Which capability opened the session. Closed set.
///
/// Distinct from the challenge action: both ownership and grant proofs
/// consume a `Pull` challenge; the **authority** is what the trusted API
/// layer verified before calling `Pull`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SessionAuthority {
    /// Opened by a verified OwnershipProof (`sk₀`).
    Ownership,
    /// Opened by a verified GrantProof (scoped view grant).
    Grant,
}

impl SessionAuthority {
    /// Every authority. Length is the closed-set contract.
    pub(crate) const ALL: [SessionAuthority; 2] = [Self::Ownership, Self::Grant];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ownership => "ownership",
            Self::Grant => "grant",
        }
    }
}

/// Fields common to every live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionCommon {
    pub subject: SubjectAddress,
    /// Resolved (intersected) scope of the originating `Pull`.
    pub scope: GrantScope,
    pub chan_bind: ChanBind,
    pub expiry: u64,
}

/// Live pull session — authority is the enum discriminant.
///
/// A grant session cannot be turned into an ownership session by reordering
/// checks: the only way to obtain [`SessionCommon`] under ownership is the
/// [`Self::Ownership`] arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActiveSession {
    Ownership(SessionCommon),
    Grant(SessionCommon),
}

impl ActiveSession {
    pub(crate) fn common(&self) -> &SessionCommon {
        match self {
            Self::Ownership(c) | Self::Grant(c) => c,
        }
    }

    /// Ownership vs grant — sole production gate is
    /// [`Self::require_ownership`] (match on the discriminant). This
    /// accessor exists for tests that assert the discriminant without
    /// going through the ownership-only path.
    #[cfg(test)]
    pub(crate) fn authority(&self) -> SessionAuthority {
        match self {
            Self::Ownership(_) => SessionAuthority::Ownership,
            Self::Grant(_) => SessionAuthority::Grant,
        }
    }

    /// Ownership-only access. Grant → typed unauthorised cause.
    ///
    /// **Single authority gate** for `GetAccountState`: the enum
    /// discriminant is the authority; there is no parallel boolean or
    /// string check that could drift from this match.
    pub(crate) fn require_ownership(&self) -> Result<&SessionCommon, GrantSessionRejected> {
        match self {
            Self::Ownership(c) => Ok(c),
            Self::Grant(_) => Err(GrantSessionRejected),
        }
    }
}

/// Typed cause: a grant pull session was presented where only an ownership
/// session is accepted (`GetAccountState`). Downcastable; never derived
/// from message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GrantSessionRejected;

impl std::fmt::Display for GrantSessionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "grant pull session does not authorise GetAccountState \
             (ownership session required; no full-state disclosure under a scoped grant)",
        )
    }
}

impl std::error::Error for GrantSessionRejected {}

impl GrantSessionRejected {
    pub(crate) fn into_kernel_error(self) -> KernelError {
        KernelError::new(KernelErrorCode::Unauthorized, self.to_string())
    }
}

/// Typed session-lookup failure. Spec collapses Unknown / Expired /
/// ChanBindMismatch into `session_expired` (410).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionError {
    Unknown,
    Expired,
    ChanBindMismatch,
}

impl SessionError {
    pub(crate) fn into_kernel_error(self) -> KernelError {
        // Spec §7.5: unknown, expired, and chan_bind mismatch all map to
        // session_expired / 410. Distinct variants exist so tests can assert
        // the *cause* before the collapse.
        let detail = match self {
            Self::Unknown => "pull session token unknown",
            Self::Expired => "pull session token expired",
            Self::ChanBindMismatch => "pull session chan_bind does not match",
        };
        KernelError::new(KernelErrorCode::SessionExpired, detail)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("pull session token unknown"),
            Self::Expired => f.write_str("pull session token expired"),
            Self::ChanBindMismatch => f.write_str("pull session chan_bind does not match"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Opaque session token returned to the client (hex of 32 random bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SessionToken(pub String);

impl SessionToken {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Process-local pull-session store.
#[derive(Debug, Default)]
pub(crate) struct SessionStore {
    sessions: DashMap<String, ActiveSession>,
}

impl SessionStore {
    pub(crate) fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Issue a new session. Token is opaque (64 hex chars); expiry is
    /// `now + SESSION_TTL_SECS` and is **not** extended by later use.
    pub(crate) fn issue(
        &self,
        authority: SessionAuthority,
        subject: SubjectAddress,
        scope: GrantScope,
        chan_bind: ChanBind,
        now: u64,
    ) -> (SessionToken, u64) {
        let mut raw = [0u8; 32];
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        raw[..16].copy_from_slice(a.as_bytes());
        raw[16..].copy_from_slice(b.as_bytes());
        let token = hex::encode(raw);
        let expiry = now.saturating_add(SESSION_TTL_SECS);
        let common = SessionCommon {
            subject,
            scope,
            chan_bind,
            expiry,
        };
        let session = match authority {
            SessionAuthority::Ownership => ActiveSession::Ownership(common),
            SessionAuthority::Grant => ActiveSession::Grant(common),
        };
        self.sessions.insert(token.clone(), session);
        (SessionToken(token), expiry)
    }

    /// Look up a still-valid session bound to `chan_bind`.
    ///
    /// Empty / whitespace-only tokens are **not** looked up here — callers
    /// must reject them as `unauthorized` before calling.
    pub(crate) fn lookup(
        &self,
        token: &str,
        chan_bind: &ChanBind,
        now: u64,
    ) -> Result<ActiveSession, SessionError> {
        // Snapshot under the map lock, then decide. Expired entries are
        // removed so a second concurrent look also sees Unknown/Expired
        // consistently (both map to session_expired).
        let session = match self.sessions.get(token) {
            Some(entry) => entry.clone(),
            None => return Err(SessionError::Unknown),
        };

        let common = session.common();
        if common.expiry < now {
            // Best-effort cleanup; concurrent removes are fine.
            self.sessions.remove(token);
            return Err(SessionError::Expired);
        }
        if common.chan_bind != *chan_bind {
            return Err(SessionError::ChanBindMismatch);
        }
        Ok(session)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::grants::GrantAssetScope;

    fn subject(b: u8) -> SubjectAddress {
        SubjectAddress([b; 32])
    }

    fn bind(b: u8) -> ChanBind {
        ChanBind([b; 32])
    }

    fn unbounded_scope() -> GrantScope {
        GrantScope {
            assets: GrantAssetScope::All,
            not_before: 0,
            not_after: crate::kernel::grants::SCOPE_NOT_AFTER_UNBOUNDED,
        }
    }

    #[test]
    fn ownership_and_grant_are_structurally_distinct() {
        let store = SessionStore::new();
        let now = 1_000u64;
        let (own_tok, _) = store.issue(
            SessionAuthority::Ownership,
            subject(1),
            unbounded_scope(),
            bind(1),
            now,
        );
        let (grant_tok, _) = store.issue(
            SessionAuthority::Grant,
            subject(1),
            unbounded_scope(),
            bind(1),
            now,
        );

        let own = store
            .lookup(own_tok.as_str(), &bind(1), now)
            .expect("ownership session");
        assert!(own.require_ownership().is_ok());
        assert_eq!(own.authority(), SessionAuthority::Ownership);

        let grant = store
            .lookup(grant_tok.as_str(), &bind(1), now)
            .expect("grant session");
        let err = grant
            .require_ownership()
            .expect_err("grant must not pass require_ownership");
        assert_eq!(err, GrantSessionRejected);
        assert_eq!(err.into_kernel_error().code, KernelErrorCode::Unauthorized);
    }

    #[test]
    fn unknown_expired_chan_bind_all_collapse_to_session_expired() {
        let store = SessionStore::new();
        let now = 50u64;
        let (tok, exp) = store.issue(
            SessionAuthority::Ownership,
            subject(2),
            unbounded_scope(),
            bind(9),
            now,
        );

        let unknown = store
            .lookup("deadbeef", &bind(9), now)
            .expect_err("unknown");
        assert_eq!(unknown, SessionError::Unknown);
        assert_eq!(
            unknown.into_kernel_error().code,
            KernelErrorCode::SessionExpired
        );

        let expired = store
            .lookup(tok.as_str(), &bind(9), exp + 1)
            .expect_err("expired");
        assert_eq!(expired, SessionError::Expired);
        assert_eq!(
            expired.into_kernel_error().code,
            KernelErrorCode::SessionExpired
        );

        // Re-issue for chan_bind test (prior token was cleaned on expiry).
        let (tok2, _) = store.issue(
            SessionAuthority::Ownership,
            subject(2),
            unbounded_scope(),
            bind(9),
            now,
        );
        let wrong_bind = store
            .lookup(tok2.as_str(), &bind(0), now)
            .expect_err("wrong chan_bind");
        assert_eq!(wrong_bind, SessionError::ChanBindMismatch);
        assert_eq!(
            wrong_bind.into_kernel_error().code,
            KernelErrorCode::SessionExpired
        );
    }

    #[test]
    fn lookup_does_not_extend_expiry() {
        let store = SessionStore::new();
        let now = 10u64;
        let (tok, exp) = store.issue(
            SessionAuthority::Ownership,
            subject(3),
            unbounded_scope(),
            bind(3),
            now,
        );
        assert_eq!(exp, now + SESSION_TTL_SECS);

        // Use well before expiry.
        let s1 = store
            .lookup(tok.as_str(), &bind(3), now + 1)
            .expect("first use");
        assert_eq!(s1.common().expiry, exp);

        // Use again — expiry unchanged.
        let s2 = store
            .lookup(tok.as_str(), &bind(3), now + 2)
            .expect("second use");
        assert_eq!(s2.common().expiry, exp);

        // At original expiry boundary (expiry < now fails; expiry == now ok).
        store
            .lookup(tok.as_str(), &bind(3), exp)
            .expect("at exact expiry still valid");
        store
            .lookup(tok.as_str(), &bind(3), exp + 1)
            .expect_err("past expiry");
    }

    #[test]
    fn authority_all_is_closed_and_distinct() {
        assert_eq!(SessionAuthority::ALL.len(), 2);
        assert_ne!(
            SessionAuthority::Ownership.as_str(),
            SessionAuthority::Grant.as_str()
        );
        for a in SessionAuthority::ALL {
            assert!(!a.as_str().is_empty());
        }
    }
}
