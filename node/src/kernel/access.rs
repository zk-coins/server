//! Pull, Records, AccountState, Receipts — transport-free domain
//! (§5.1 / §4.9 / §7.5 / §7.8).
//!
//! ## Procedures
//!
//! - [`open_pull_challenge`] — issue a single-use challenge (Pull / Attest / Grant)
//! - [`pull`] — consume pull challenge, list in-scope record refs, issue session
//! - [`get_record`] — one Private record within a still-valid session
//! - [`get_coin_proof`] — one CoinProof within a still-valid session
//! - [`get_account_state`] — ownership sessions **only**
//! - [`subscribe_receipts`] — filtered push stream (ownership **or** grant);
//!   emission is the receive path after durable persist via
//!   [`publish_credit_if_inserted`]
//!
//! ## No second truth
//!
//! Challenges use the **same** [`ChallengeStore`] as Block 5
//! ([`ChallengeAction::Pull`]). Scopes reuse [`GrantScope`] from
//! `grants.rs`. Sessions are typified as [`ActiveSession`] so ownership
//! and grant cannot be confused by check order.
//!
//! ## Subject provenance
//!
//! - `PullRequest` (proto) carries `subject` — the subject the **API layer**
//!   authenticated. The kernel stores it on the session and never trusts a
//!   later client-supplied subject on follow-up calls.
//! - `RecordRequest` / `CoinProofRequest` / `AccountStateRequest` /
//!   `SubscribeReceiptsRequest` carry **no** subject field (proto). Subject
//!   comes only from the server-side session.
//!
//! ## Scope
//!
//! The private index is queried with `(subject, scope)` so out-of-scope
//! rows are not released. A record that exists for the subject but fails
//! the asset/time window yields `scope_exceeded` (metadata check before
//! body release — not fetch-all-then-filter of private bytes).
//!
//! No `axum`, no `tonic`.

pub(crate) mod receipts;
pub(crate) mod session;

use std::sync::Arc;

// Non-façade helpers (not re-exported): import from the defining submodule.
// `scope_admits_asset_and_time`, `should_emit_credit`, and
// `RECEIPT_SUBSCRIBER_BUFFER` stay in `receipts` — only the defining module
// (and its tests) call them; re-exporting would invent unused façade surface.
use crate::kernel::access::receipts::scope_admits_asset_and_time;

// Receipt writer surface — re-exported so callers use `access::…` only.
use crate::kernel::bootstrap::{
    ChallengeAction, ChallengeStore, IssuedChallenge, RedeemedPullChallenge,
};
use crate::kernel::grants::{GrantAssetScope, GrantScope};
use crate::kernel::types::{ChanBind, Digest32, SubjectAddress};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};
pub(crate) use receipts::{
    publish_credit_if_inserted, subscribe_receipts, CreditReceipt, ReceiptHub, ReceiptState,
};

// Access-façade re-exports: also the sole local binding for these names.
// Callers outside `access` must use `crate::kernel::access::…` only.
// SessionError / SESSION_TTL_SECS stay module-private (session.rs); lookup
// maps them via `session::SessionError::into_kernel_error` and issue uses
// the constant at the definition site — no second import path.
// SessionCommon lives only in session.rs — procedures reach it via
// ActiveSession::{common, require_ownership}; no local field access needs
// the type name here, and no external caller imports it from the façade.
pub(crate) use session::{
    ActiveSession, GrantSessionRejected, SessionAuthority, SessionStore, SessionToken,
};

/// Closed `record_type` set (§7.5 / §7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RecordType {
    CoinProof,
    SelfDelivery,
}

impl RecordType {
    pub(crate) const ALL: [RecordType; 2] = [Self::CoinProof, Self::SelfDelivery];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CoinProof => "coinproof",
            Self::SelfDelivery => "self_delivery",
        }
    }
}

/// Closed `transition_kind` set (§7.5 / §7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TransitionKind {
    Mint,
    Send,
    Receive,
}

impl TransitionKind {
    pub(crate) const ALL: [TransitionKind; 3] = [Self::Mint, Self::Send, Self::Receive];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }
}

/// One Private-record locator in a `PullResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordRef {
    pub record_id: Digest32,
    pub record_type: RecordType,
    /// Required for `SelfDelivery`; optional for `CoinProof`.
    pub transition_kind: Option<TransitionKind>,
    pub blob_id: Digest32,
    pub occurred_at: u64,
}

impl RecordRef {
    /// Enforce RecordType / TransitionKind invariants.
    pub(crate) fn validate(&self) -> KernelResult<()> {
        match self.record_type {
            RecordType::SelfDelivery => {
                if self.transition_kind.is_none() {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Corrupt private-record index",
                        "self_delivery record_ref missing transition_kind",
                    ));
                }
            }
            RecordType::CoinProof => {
                // transition_kind optional — no constraint.
            }
        }
        Ok(())
    }
}

/// Canonical Private-record body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordBlob {
    pub canonical: Vec<u8>,
    pub record_type: RecordType,
    pub transition_kind: Option<TransitionKind>,
}

/// Authoritative account-state answer (§7.8 `AccountStateResult`).
///
/// Fields that are not known are `None` / empty — never invented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccountStateView {
    pub account_state: Vec<u8>,
    pub state_head: Digest32,
    pub head_record_id: Option<Digest32>,
    pub send_counter: u64,
    pub current_pubkey: [u8; 32],
    pub last_nullifier_pk: Option<[u8; 32]>,
    pub last_nullifier_r: Option<[u8; 32]>,
}

/// Index entry used by the process-local private-record store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexedRecord {
    pub subject: SubjectAddress,
    pub record_id: Digest32,
    /// Asset for scope checks. For self-delivery this is the primary
    /// asset of the transition when known; required for scope admission.
    pub asset_id: Digest32,
    pub occurred_at: u64,
    pub record_type: RecordType,
    pub transition_kind: Option<TransitionKind>,
    pub blob_id: Digest32,
    /// Canonical body bytes (§7.1). Absent only if the index knows the
    /// locator but not the body — then GetRecord fails closed.
    pub canonical: Option<Vec<u8>>,
    /// Coin id when `record_type == CoinProof`; used by GetCoinProof.
    pub coin_id: Option<Digest32>,
}

/// Outcome of inserting a verified private record into the decrypt index.
///
/// Replay of the same bundle / coin is a **named** outcome, never a silent
/// second credit. The scan path re-ACKs on [`Self::AlreadyPresent`] but
/// does not re-credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsertRecordOutcome {
    /// Row was not present; now durable in this index.
    Inserted,
    /// Same `(subject, coin_id)` or same `record_id` already held — replay.
    AlreadyPresent,
}

/// Transport-free private-record + account-state index.
///
/// Production writer is the §4.4 / §2.3.3 receive path
/// ([`InMemoryPrivateIndex::insert_record`] plus the durable
/// `v1_decrypt_index` table, migration 0031). The scanner fills the index
/// **after** verification and **before** ACK — never the reverse. Kernel
/// procedures only **read**; transport (relay / Blossom) never appears
/// here. Empty by default = opaque replica (no invented ownership map).
pub(crate) trait PrivateIndex: Send + Sync {
    /// List record refs for `subject` that fall inside `scope`.
    ///
    /// Structural: only in-scope refs are returned. Load errors surface as
    /// `Err` — never as an empty list.
    fn list_records(
        &self,
        subject: &SubjectAddress,
        scope: &GrantScope,
    ) -> KernelResult<Vec<RecordRef>>;

    /// Fetch one record by id under `subject` + `scope`.
    ///
    /// - Unknown id → `not_found`
    /// - Known for this subject but outside scope → `scope_exceeded`
    /// - Known for a different subject → `not_found` (no existence leak)
    fn get_record(
        &self,
        subject: &SubjectAddress,
        scope: &GrantScope,
        record_id: &Digest32,
    ) -> KernelResult<RecordBlob>;

    /// Fetch one CoinProof by coin id under `subject` + `scope`.
    fn get_coin_proof(
        &self,
        subject: &SubjectAddress,
        scope: &GrantScope,
        coin_id: &Digest32,
    ) -> KernelResult<Vec<u8>>;

    /// Authoritative account state for `subject`.
    ///
    /// Missing state → `not_found` is wrong for this procedure (error table
    /// has no not_found for GetAccountState). Fail with `internal_error`
    /// when the node should hold the state but does not — never invent.
    fn get_account_state(&self, subject: &SubjectAddress) -> KernelResult<AccountStateView>;
}

/// Process-local private-record index (no migration).
#[derive(Debug, Default)]
pub(crate) struct InMemoryPrivateIndex {
    records: std::sync::Mutex<Vec<IndexedRecord>>,
    accounts: std::sync::Mutex<Vec<(SubjectAddress, AccountStateView)>>,
}

impl InMemoryPrivateIndex {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Production write path for a **already verified** private record.
    ///
    /// Call only after §2.3.3 steps 2–6 pass and the durable SQL insert
    /// (`v1_decrypt_index`, migration 0031) has succeeded. The §4.4 scanner
    /// is the production caller; kernel procedures never invent rows.
    ///
    /// Replay: same `record_id` or same `(subject, coin_id)` for a
    /// `CoinProof` returns [`InsertRecordOutcome::AlreadyPresent`] without
    /// mutating the store — the caller may re-ACK but must not re-credit.
    pub(crate) fn insert_record(&self, record: IndexedRecord) -> KernelResult<InsertRecordOutcome> {
        record.validate_for_insert()?;
        let mut guard = self.records.lock().map_err(|e| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to insert private record",
                format!("private-index mutex poisoned: {e}"),
            )
        })?;
        for existing in guard.iter() {
            if existing.record_id == record.record_id {
                return Ok(InsertRecordOutcome::AlreadyPresent);
            }
            if existing.record_type == RecordType::CoinProof
                && record.record_type == RecordType::CoinProof
                && existing.subject == record.subject
                && existing.coin_id.is_some()
                && existing.coin_id == record.coin_id
            {
                return Ok(InsertRecordOutcome::AlreadyPresent);
            }
        }
        guard.push(record);
        Ok(InsertRecordOutcome::Inserted)
    }

    /// Insert or replace authoritative account state for `subject`.
    ///
    /// Test plant only today — production account state lands via the
    /// receive/finalise engine path, not this process-local index. Kept
    /// under `cfg(test)` so the lib target does not carry a dead writer.
    #[cfg(test)]
    pub(crate) fn insert_account(&self, subject: SubjectAddress, view: AccountStateView) {
        let mut guard = self.accounts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, slot)) = guard.iter_mut().find(|(s, _)| *s == subject) {
            *slot = view;
        } else {
            guard.push((subject, view));
        }
    }

    /// Own-node load of a verified CoinProof body by `(subject, coin_id)`.
    ///
    /// Unscoped (no view-grant): the §2.3.3 fold path is the account's own
    /// node reconstituting receipts it already verified under entrusteed
    /// `ivk`. Grant-scoped [`PrivateIndex::get_coin_proof`] stays the
    /// pull/API surface.
    ///
    /// - `Ok(Some(bytes))` — canonical §7.1 body present
    /// - `Ok(None)` — no row for this pair (caller may fall through to SQL)
    /// - `Err` — mutex / corrupt body (locator without canonical)
    pub(crate) fn load_coin_proof_canonical(
        &self,
        subject: &SubjectAddress,
        coin_id: &[u8; 32],
    ) -> KernelResult<Option<Vec<u8>>> {
        let guard = self.records.lock().map_err(|e| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to load coin proof for receive fold",
                format!("private-index mutex poisoned: {e}"),
            )
        })?;
        let want = Digest32(*coin_id);
        for r in guard.iter() {
            if r.record_type != RecordType::CoinProof {
                continue;
            }
            if &r.subject != subject {
                continue;
            }
            if r.coin_id.as_ref() != Some(&want) {
                continue;
            }
            return match &r.canonical {
                Some(bytes) if !bytes.is_empty() => Ok(Some(bytes.clone())),
                Some(_) | None => Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Corrupt private-record index",
                    "CoinProof row present but canonical body missing/empty — refuse fold",
                )),
            };
        }
        Ok(None)
    }
}

impl IndexedRecord {
    /// Structural checks before insert — body required for CoinProof credit.
    fn validate_for_insert(&self) -> KernelResult<()> {
        match self.record_type {
            RecordType::CoinProof => {
                if self.coin_id.is_none() {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Corrupt private-record index",
                        "CoinProof insert missing coin_id",
                    ));
                }
                if self.canonical.is_none() {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Corrupt private-record index",
                        "CoinProof insert missing canonical body — refuse empty credit",
                    ));
                }
            }
            RecordType::SelfDelivery => {
                if self.transition_kind.is_none() {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Corrupt private-record index",
                        "self_delivery insert missing transition_kind",
                    ));
                }
                if self.canonical.is_none() {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Corrupt private-record index",
                        "self_delivery insert missing canonical body",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl PrivateIndex for InMemoryPrivateIndex {
    fn list_records(
        &self,
        subject: &SubjectAddress,
        scope: &GrantScope,
    ) -> KernelResult<Vec<RecordRef>> {
        let guard = self.records.lock().map_err(|e| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to list private records",
                format!("private-index mutex poisoned: {e}"),
            )
        })?;
        let mut out = Vec::new();
        for r in guard.iter() {
            if &r.subject != subject {
                continue;
            }
            if !scope_admits_asset_and_time(scope, &r.asset_id, r.occurred_at) {
                continue;
            }
            let refer = RecordRef {
                record_id: r.record_id,
                record_type: r.record_type,
                transition_kind: r.transition_kind,
                blob_id: r.blob_id,
                occurred_at: r.occurred_at,
            };
            refer.validate()?;
            out.push(refer);
        }
        Ok(out)
    }

    fn get_record(
        &self,
        subject: &SubjectAddress,
        scope: &GrantScope,
        record_id: &Digest32,
    ) -> KernelResult<RecordBlob> {
        let guard = self.records.lock().map_err(|e| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to load private record",
                format!("private-index mutex poisoned: {e}"),
            )
        })?;
        let found = guard.iter().find(|r| &r.record_id == record_id);
        let rec = match found {
            Some(r) => r,
            None => {
                return Err(KernelError::new(
                    KernelErrorCode::NotFound,
                    "record not found",
                ));
            }
        };
        if &rec.subject != subject {
            // Foreign record: do not confirm existence via scope_exceeded.
            return Err(KernelError::new(
                KernelErrorCode::NotFound,
                "record not found",
            ));
        }
        if !scope_admits_asset_and_time(scope, &rec.asset_id, rec.occurred_at) {
            return Err(KernelError::new(
                KernelErrorCode::ScopeExceeded,
                "record is outside the session resolved scope",
            ));
        }
        let canonical = match &rec.canonical {
            Some(bytes) => bytes.clone(),
            None => {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to load private record",
                    "record locator present but canonical body missing",
                ));
            }
        };
        Ok(RecordBlob {
            canonical,
            record_type: rec.record_type,
            transition_kind: rec.transition_kind,
        })
    }

    fn get_coin_proof(
        &self,
        subject: &SubjectAddress,
        scope: &GrantScope,
        coin_id: &Digest32,
    ) -> KernelResult<Vec<u8>> {
        let guard = self.records.lock().map_err(|e| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to load coin proof",
                format!("private-index mutex poisoned: {e}"),
            )
        })?;
        let found = guard.iter().find(|r| {
            r.record_type == RecordType::CoinProof && r.coin_id.as_ref() == Some(coin_id)
        });
        let rec = match found {
            Some(r) => r,
            None => {
                return Err(KernelError::new(
                    KernelErrorCode::NotFound,
                    "coin proof not found",
                ));
            }
        };
        if &rec.subject != subject {
            return Err(KernelError::new(
                KernelErrorCode::NotFound,
                "coin proof not found",
            ));
        }
        if !scope_admits_asset_and_time(scope, &rec.asset_id, rec.occurred_at) {
            return Err(KernelError::new(
                KernelErrorCode::ScopeExceeded,
                "coin is outside the session resolved scope",
            ));
        }
        match &rec.canonical {
            Some(bytes) => Ok(bytes.clone()),
            None => Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to load coin proof",
                "coin proof locator present but canonical body missing",
            )),
        }
    }

    fn get_account_state(&self, subject: &SubjectAddress) -> KernelResult<AccountStateView> {
        let guard = self.accounts.lock().map_err(|e| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Failed to load account state",
                format!("private-index mutex poisoned: {e}"),
            )
        })?;
        match guard.iter().find(|(s, _)| s == subject) {
            Some((_, view)) => Ok(view.clone()),
            None => Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Account state unavailable",
                "no indexed AccountState for subject; node has no decrypt-index entry \
                 (opaque replica or missing entrust) — not inventing empty state",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Commands / results
// ---------------------------------------------------------------------------

/// Already-authorised `Pull` command (§7.8 `PullRequest` + authority).
///
/// # Authority (proto GAP)
///
/// Normative `PullRequest` carries `subject`, `resolved_scope`, `nonce`,
/// `chan_bind` — **not** whether the API verified an OwnershipProof or a
/// GrantProof. That fact is required for `GetAccountState` and is supplied
/// here as [`Self::authority`] by the trusted API layer (same trust class
/// as `subject` / `resolved_scope`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullCommand {
    pub nonce: [u8; 32],
    pub subject: SubjectAddress,
    pub resolved_scope: GrantScope,
    pub chan_bind: ChanBind,
    pub authority: SessionAuthority,
}

/// Result of a successful `Pull`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullResult {
    pub records: Vec<RecordRef>,
    pub session: SessionToken,
    pub session_expiry: u64,
}

/// Session-bound follow-up request (no subject field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionBoundRequest {
    pub session: String,
    pub chan_bind: ChanBind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GetRecordCommand {
    pub record_id: Digest32,
    pub session: String,
    pub chan_bind: ChanBind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GetCoinProofCommand {
    pub coin_id: Digest32,
    pub session: String,
    pub chan_bind: ChanBind,
}

/// Dependencies shared by the four reading procedures (+ challenge issue).
pub(crate) struct AccessDeps<'a> {
    pub challenges: &'a ChallengeStore,
    pub sessions: &'a SessionStore,
    pub index: &'a dyn PrivateIndex,
    pub allowed_chan_binds: &'a [[u8; 32]],
    pub now: u64,
}

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

/// Reject an empty selected asset list (empty intersection).
fn require_nonempty_resolved_scope(scope: &GrantScope) -> KernelResult<()> {
    match &scope.assets {
        GrantAssetScope::All => Ok(()),
        GrantAssetScope::Selected(ids) if ids.is_empty() => Err(KernelError::new(
            KernelErrorCode::ScopeExceeded,
            "resolved scope asset intersection is empty",
        )),
        GrantAssetScope::Selected(_) => Ok(()),
    }
}

/// Whether `resolved` is entirely within `requested` (defense in depth).
///
/// The API is trusted for access, but a wider resolved scope than the
/// challenge's requested scope is a bug and must not widen disclosure.
fn resolved_within_requested(resolved: &GrantScope, requested: &GrantScope) -> bool {
    // Time window: resolved must be a sub-interval of requested.
    if resolved.not_before < requested.not_before {
        return false;
    }
    if resolved.not_after > requested.not_after {
        return false;
    }
    match (&resolved.assets, &requested.assets) {
        (_, GrantAssetScope::All) => true,
        (GrantAssetScope::All, GrantAssetScope::Selected(_)) => false,
        (GrantAssetScope::Selected(res), GrantAssetScope::Selected(req)) => {
            res.iter().all(|id| req.iter().any(|r| r == id))
        }
    }
}

// ---------------------------------------------------------------------------
// Session gate
// ---------------------------------------------------------------------------

fn reject_empty_session_token(token: &str) -> KernelResult<()> {
    if token.trim().is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::Unauthorized,
            "pull session bearer token missing or empty",
        ));
    }
    Ok(())
}

fn lookup_session(
    sessions: &SessionStore,
    token: &str,
    chan_bind: &ChanBind,
    now: u64,
) -> KernelResult<ActiveSession> {
    reject_empty_session_token(token)?;
    sessions
        .lookup(token, chan_bind, now)
        .map_err(session::SessionError::into_kernel_error)
}

// ---------------------------------------------------------------------------
// OpenPullChallenge (§7.8) — multi-action challenge issue
// ---------------------------------------------------------------------------

/// Issue a single-use challenge for `action` + `subject`.
///
/// - [`ChallengeAction::Pull`]: binds `requested_scope` (§7.5 stores it).
/// - Owner-actions ([`ChallengeAction::AttestBalance`],
///   [`ChallengeAction::IssueViewGrant`], [`ChallengeAction::Entrust`],
///   [`ChallengeAction::Revoke`]): scope is unused; still accepted so the
///   RPC can forward a defaulted body without inventing a second path.
pub(crate) fn open_pull_challenge(
    challenges: &ChallengeStore,
    action: ChallengeAction,
    subject: SubjectAddress,
    requested_scope: GrantScope,
    now: u64,
) -> IssuedChallenge {
    match action {
        ChallengeAction::Pull => challenges.issue_pull(subject, requested_scope, now),
        ChallengeAction::AttestBalance
        | ChallengeAction::IssueViewGrant
        | ChallengeAction::Entrust
        | ChallengeAction::Revoke => {
            // Owner-action maps do not store scope; drop it deliberately.
            let _ = requested_scope;
            challenges.issue(action, subject, now)
        }
    }
}

// ---------------------------------------------------------------------------
// Procedures
// ---------------------------------------------------------------------------

/// `Pull` (§7.8): consume challenge, list in-scope refs, issue session.
///
/// # Ordering
///
/// 1. Validate resolved scope non-empty (pure)
/// 2. Redeem pull challenge (atomic, irreversible)
/// 3. Subject match + resolved ⊆ requested (fail closed)
/// 4. List records under subject + resolved scope (structural)
/// 5. Issue session with authority / subject / scope / chan_bind
pub(crate) fn pull(deps: AccessDeps<'_>, command: PullCommand) -> KernelResult<PullResult> {
    require_nonempty_resolved_scope(&command.resolved_scope)?;

    let redeemed: RedeemedPullChallenge = deps
        .challenges
        .redeem_pull(
            &command.nonce,
            &command.subject,
            &command.chan_bind,
            deps.allowed_chan_binds,
            deps.now,
        )
        .map_err(crate::kernel::bootstrap::ChallengeConsumeError::into_kernel_error)?;

    // Subject already checked inside redeem_pull; re-assert for clarity.
    if redeemed.subject != command.subject {
        return Err(KernelError::new(
            KernelErrorCode::Unauthorized,
            "challenge was issued for a different subject",
        ));
    }
    if !resolved_within_requested(&command.resolved_scope, &redeemed.requested_scope) {
        return Err(KernelError::new(
            KernelErrorCode::ScopeExceeded,
            "resolved scope is wider than the challenge requested scope",
        ));
    }

    let records = deps
        .index
        .list_records(&command.subject, &command.resolved_scope)?;

    let (session, session_expiry) = deps.sessions.issue(
        command.authority,
        command.subject,
        command.resolved_scope,
        command.chan_bind,
        deps.now,
    );

    Ok(PullResult {
        records,
        session,
        session_expiry,
    })
}

/// `GetRecord` (§7.8).
pub(crate) fn get_record(
    deps: AccessDeps<'_>,
    command: GetRecordCommand,
) -> KernelResult<RecordBlob> {
    let session = lookup_session(
        deps.sessions,
        &command.session,
        &command.chan_bind,
        deps.now,
    )?;
    let common = session.common();
    deps.index
        .get_record(&common.subject, &common.scope, &command.record_id)
}

/// `GetCoinProof` (§7.8).
pub(crate) fn get_coin_proof(
    deps: AccessDeps<'_>,
    command: GetCoinProofCommand,
) -> KernelResult<Vec<u8>> {
    let session = lookup_session(
        deps.sessions,
        &command.session,
        &command.chan_bind,
        deps.now,
    )?;
    let common = session.common();
    deps.index
        .get_coin_proof(&common.subject, &common.scope, &command.coin_id)
}

/// `GetAccountState` (§7.8) — ownership sessions only.
///
/// Grant sessions are rejected via [`ActiveSession::require_ownership`] —
/// the match on the enum discriminant, not a re-orderable boolean.
pub(crate) fn get_account_state(
    deps: AccessDeps<'_>,
    request: SessionBoundRequest,
) -> KernelResult<AccountStateView> {
    let session = lookup_session(
        deps.sessions,
        &request.session,
        &request.chan_bind,
        deps.now,
    )?;
    let common = session
        .require_ownership()
        .map_err(GrantSessionRejected::into_kernel_error)?;
    deps.index.get_account_state(&common.subject)
}

/// Fail-closed check of access-layer closed wire vocabularies.
///
/// Called from the process start edge next to the error-table and chain
/// closed-set checks.
pub(crate) fn validate_closed_sets() -> Result<(), String> {
    use crate::kernel::bootstrap::ChallengeAction;
    use crate::kernel::chain::{validate_wire_vocabulary, WireEntry};

    let record_types: [WireEntry; 2] = RecordType::ALL.map(|r| WireEntry {
        label: match r {
            RecordType::CoinProof => "CoinProof",
            RecordType::SelfDelivery => "SelfDelivery",
        },
        wire: r.as_str(),
    });
    validate_wire_vocabulary("RecordType", &record_types)?;

    let kinds: [WireEntry; 3] = TransitionKind::ALL.map(|k| WireEntry {
        label: match k {
            TransitionKind::Mint => "Mint",
            TransitionKind::Send => "Send",
            TransitionKind::Receive => "Receive",
        },
        wire: k.as_str(),
    });
    validate_wire_vocabulary("TransitionKind", &kinds)?;

    let authorities: [WireEntry; 2] = SessionAuthority::ALL.map(|a| WireEntry {
        label: match a {
            SessionAuthority::Ownership => "Ownership",
            SessionAuthority::Grant => "Grant",
        },
        wire: a.as_str(),
    });
    validate_wire_vocabulary("SessionAuthority", &authorities)?;

    let receipt_states: [WireEntry; 3] = receipts::ReceiptState::ALL.map(|s| WireEntry {
        label: match s {
            receipts::ReceiptState::Completed => "Completed",
            receipts::ReceiptState::Pending => "Pending",
            receipts::ReceiptState::Failed => "Failed",
        },
        wire: s.as_str(),
    });
    validate_wire_vocabulary("ReceiptState", &receipt_states)?;

    let actions: [WireEntry; 5] = ChallengeAction::ALL.map(|a| WireEntry {
        label: match a {
            ChallengeAction::Pull => "Pull",
            ChallengeAction::AttestBalance => "AttestBalance",
            ChallengeAction::IssueViewGrant => "IssueViewGrant",
            ChallengeAction::Entrust => "Entrust",
            ChallengeAction::Revoke => "Revoke",
        },
        wire: a.domain(),
    });
    validate_wire_vocabulary("ChallengeAction", &actions)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::bootstrap::ChallengeAction;
    use crate::kernel::grants::SCOPE_NOT_AFTER_UNBOUNDED;
    use crate::transport::error_contract::{self, GrpcStatusCode};

    fn subject(b: u8) -> SubjectAddress {
        SubjectAddress([b; 32])
    }

    fn digest(b: u8) -> Digest32 {
        Digest32([b; 32])
    }

    fn bind(b: u8) -> ChanBind {
        ChanBind([b; 32])
    }

    fn unbounded() -> GrantScope {
        GrantScope {
            assets: GrantAssetScope::All,
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        }
    }

    fn asset_scope(asset: u8) -> GrantScope {
        GrantScope {
            assets: GrantAssetScope::Selected(vec![digest(asset)]),
            not_before: 0,
            not_after: SCOPE_NOT_AFTER_UNBOUNDED,
        }
    }

    /// Grant scope that admits every asset but only the closed time window
    /// `[not_before, not_after]` (inclusive bounds — see `scope_admits_asset_and_time`).
    fn time_scope(not_before: u64, not_after: u64) -> GrantScope {
        GrantScope {
            assets: GrantAssetScope::All,
            not_before,
            not_after,
        }
    }

    fn deps<'a>(
        challenges: &'a ChallengeStore,
        sessions: &'a SessionStore,
        index: &'a InMemoryPrivateIndex,
        allowed: &'a [[u8; 32]],
        now: u64,
    ) -> AccessDeps<'a> {
        AccessDeps {
            challenges,
            sessions,
            index,
            allowed_chan_binds: allowed,
            now,
        }
    }

    fn plant_coin(
        index: &InMemoryPrivateIndex,
        subj: SubjectAddress,
        asset: u8,
        at: u64,
        body: &[u8],
    ) -> (Digest32, Digest32) {
        let record_id = digest(asset.wrapping_add(0x40));
        let coin_id = digest(asset.wrapping_add(0x80));
        index
            .insert_record(IndexedRecord {
                subject: subj,
                record_id,
                asset_id: digest(asset),
                occurred_at: at,
                record_type: RecordType::CoinProof,
                transition_kind: None,
                blob_id: digest(asset.wrapping_add(0xC0)),
                canonical: Some(body.to_vec()),
                coin_id: Some(coin_id),
            })
            .expect("plant coin record");
        (record_id, coin_id)
    }

    /// Test helper inputs for issue-challenge-then-pull. Bundled so a new
    /// field is a compile error at every plant site (same discipline as
    /// `RestNodeConfig` / `KernelServiceConfig`).
    struct OpenAndPullSetup<'a> {
        challenges: &'a ChallengeStore,
        sessions: &'a SessionStore,
        index: &'a InMemoryPrivateIndex,
        /// What the trusted API layer verified (OwnershipProof vs GrantProof).
        authority: SessionAuthority,
        subject: SubjectAddress,
        /// Scope stored on the challenge at issue time.
        requested: GrantScope,
        /// Already-intersected scope the API passes into `Pull`.
        resolved: GrantScope,
        allowed: &'a [[u8; 32]],
        now: u64,
    }

    fn open_and_pull(
        OpenAndPullSetup {
            challenges,
            sessions,
            index,
            authority,
            subject,
            requested,
            resolved,
            allowed,
            now,
        }: OpenAndPullSetup<'_>,
    ) -> PullResult {
        let issued =
            open_pull_challenge(challenges, ChallengeAction::Pull, subject, requested, now);
        pull(
            deps(challenges, sessions, index, allowed, now),
            PullCommand {
                nonce: issued.nonce,
                subject,
                resolved_scope: resolved,
                chan_bind: ChanBind(allowed[0]),
                authority,
            },
        )
        .expect("pull")
    }

    #[test]
    fn ownership_scope_lists_only_in_scope_records() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[0xABu8; 32]];
        let now = 1_000u64;
        let subj = subject(1);

        plant_coin(&index, subj, 0x11, 50, b"coin-a");
        plant_coin(&index, subj, 0x22, 50, b"coin-b");
        plant_coin(&index, subject(2), 0x11, 50, b"foreign");

        let result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Ownership,
            subject: subj,
            requested: unbounded(),
            resolved: asset_scope(0x11),
            allowed: &allowed,
            now,
        });
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].record_type, RecordType::CoinProof);
        assert_eq!(result.records[0].blob_id, digest(0x11u8.wrapping_add(0xC0)));
    }

    #[test]
    fn grant_scope_cannot_see_other_assets() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[1u8; 32]];
        let now = 2_000u64;
        let subj = subject(3);

        let (rid_ok, coin_ok) = plant_coin(&index, subj, 0x10, 10, b"in-grant");
        let (rid_out, coin_out) = plant_coin(&index, subj, 0x20, 10, b"out-grant");

        let result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Grant,
            subject: subj,
            requested: asset_scope(0x10),
            resolved: asset_scope(0x10),
            allowed: &allowed,
            now,
        });
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].record_id, rid_ok);

        // GetRecord in-scope ok.
        let blob = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: rid_ok,
                session: result.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect("in-scope get_record");
        assert_eq!(blob.canonical, b"in-grant");

        // GetRecord out-of-scope → scope_exceeded (cause, not bare is_err).
        let err = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: rid_out,
                session: result.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("out-of-scope record");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded);

        // GetCoinProof out-of-scope → scope_exceeded.
        let err = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetCoinProofCommand {
                coin_id: coin_out,
                session: result.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("out-of-scope coin");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded);

        // In-scope coin ok.
        let bytes = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetCoinProofCommand {
                coin_id: coin_ok,
                session: result.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect("in-scope coin");
        assert_eq!(bytes, b"in-grant");
    }

    #[test]
    fn get_account_state_rejects_grant_session_on_cause() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[2u8; 32]];
        let now = 3_000u64;
        let subj = subject(4);

        index.insert_account(
            subj,
            AccountStateView {
                account_state: vec![1, 2, 3],
                state_head: digest(9),
                head_record_id: None,
                send_counter: 0,
                current_pubkey: [0xEE; 32],
                last_nullifier_pk: None,
                last_nullifier_r: None,
            },
        );

        let grant_pull = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Grant,
            subject: subj,
            requested: unbounded(),
            resolved: unbounded(),
            allowed: &allowed,
            now,
        });
        let err = get_account_state(
            deps(&challenges, &sessions, &index, &allowed, now),
            SessionBoundRequest {
                session: grant_pull.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("grant session on GetAccountState");
        assert_eq!(err.code, KernelErrorCode::Unauthorized);
        // Cause is GrantSessionRejected — not a generic unauthorized.
        assert!(
            err.public_message.contains("grant pull session"),
            "public message must name the grant-session cause, got {:?}",
            err.public_message
        );

        // Ownership session succeeds.
        let own_pull = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Ownership,
            subject: subj,
            requested: unbounded(),
            resolved: unbounded(),
            allowed: &allowed,
            now,
        });
        let view = get_account_state(
            deps(&challenges, &sessions, &index, &allowed, now),
            SessionBoundRequest {
                session: own_pull.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect("ownership GetAccountState");
        assert_eq!(view.account_state, vec![1, 2, 3]);
        assert_eq!(view.send_counter, 0);
    }

    #[test]
    fn session_unknown_expired_wrong_bind_are_session_expired() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[3u8; 32]];
        let now = 4_000u64;
        let subj = subject(5);

        let pull_result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Ownership,
            subject: subj,
            requested: unbounded(),
            resolved: unbounded(),
            allowed: &allowed,
            now,
        });

        // Unknown.
        let err = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: digest(0),
                session: "not-a-real-token".into(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("unknown");
        assert_eq!(err.code, KernelErrorCode::SessionExpired);

        // Wrong chan_bind.
        let err = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: digest(0),
                session: pull_result.session.as_str().to_string(),
                chan_bind: ChanBind([0xFF; 32]),
            },
        )
        .expect_err("wrong bind");
        assert_eq!(err.code, KernelErrorCode::SessionExpired);

        // Expired.
        let err = get_record(
            deps(
                &challenges,
                &sessions,
                &index,
                &allowed,
                pull_result.session_expiry + 1,
            ),
            GetRecordCommand {
                record_id: digest(0),
                session: pull_result.session.as_str().to_string(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("expired");
        assert_eq!(err.code, KernelErrorCode::SessionExpired);
    }

    #[test]
    fn empty_session_token_is_unauthorized_not_session_expired() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[4u8; 32]];
        let err = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, 0),
            GetCoinProofCommand {
                coin_id: digest(1),
                session: "   ".into(),
                chan_bind: ChanBind(allowed[0]),
            },
        )
        .expect_err("empty token");
        assert_eq!(err.code, KernelErrorCode::Unauthorized);
    }

    #[test]
    fn subject_not_on_follow_up_request_types() {
        // Structural: GetRecordCommand / GetCoinProofCommand /
        // SessionBoundRequest (SubscribeReceipts / GetAccountState) have no
        // subject field. Subject is only on PullCommand (API-authenticated)
        // and SessionCommon (server-side). Proto SubscribeReceiptsRequest
        // is likewise { session, chan_bind } only — never read a client
        // subject even if a future field were added without a domain map.
        let rec = GetRecordCommand {
            record_id: digest(1),
            session: "tok".into(),
            chan_bind: bind(1),
        };
        let _ = rec.record_id;
        let _ = rec.session;
        let _ = rec.chan_bind;
        // compile-time: no rec.subject

        let coin = GetCoinProofCommand {
            coin_id: digest(2),
            session: "tok".into(),
            chan_bind: bind(1),
        };
        let _ = coin.coin_id;

        let bound = SessionBoundRequest {
            session: "tok".into(),
            chan_bind: bind(1),
        };
        let _ = bound.session;
        let _ = bound.chan_bind;
        // compile-time: no bound.subject — SubscribeReceipts uses this shape
    }

    #[test]
    fn pull_scope_exceeded_on_empty_selected_intersection() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[5u8; 32]];
        let now = 5_000u64;
        let subj = subject(6);
        let issued =
            open_pull_challenge(&challenges, ChallengeAction::Pull, subj, unbounded(), now);
        let err = pull(
            deps(&challenges, &sessions, &index, &allowed, now),
            PullCommand {
                nonce: issued.nonce,
                subject: subj,
                resolved_scope: GrantScope {
                    assets: GrantAssetScope::Selected(vec![]),
                    not_before: 0,
                    not_after: SCOPE_NOT_AFTER_UNBOUNDED,
                },
                chan_bind: ChanBind(allowed[0]),
                authority: SessionAuthority::Ownership,
            },
        )
        .expect_err("empty selected");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded);
    }

    #[test]
    fn pull_rejects_resolved_wider_than_requested() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[6u8; 32]];
        let now = 6_000u64;
        let subj = subject(7);
        let issued = open_pull_challenge(
            &challenges,
            ChallengeAction::Pull,
            subj,
            asset_scope(0x10),
            now,
        );
        let err = pull(
            deps(&challenges, &sessions, &index, &allowed, now),
            PullCommand {
                nonce: issued.nonce,
                subject: subj,
                resolved_scope: unbounded(), // wider than requested
                chan_bind: ChanBind(allowed[0]),
                authority: SessionAuthority::Grant,
            },
        )
        .expect_err("wider resolved");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded);
    }

    #[test]
    fn scope_exceeded_on_pull_get_record_get_coin_proof() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[7u8; 32]];
        let now = 7_000u64;
        let subj = subject(8);

        let (rid_out, coin_out) = plant_coin(&index, subj, 0x30, 10, b"out");

        // 1. Pull with empty intersection.
        let issued =
            open_pull_challenge(&challenges, ChallengeAction::Pull, subj, unbounded(), now);
        let err = pull(
            deps(&challenges, &sessions, &index, &allowed, now),
            PullCommand {
                nonce: issued.nonce,
                subject: subj,
                resolved_scope: GrantScope {
                    assets: GrantAssetScope::Selected(vec![]),
                    not_before: 0,
                    not_after: SCOPE_NOT_AFTER_UNBOUNDED,
                },
                chan_bind: ChanBind(allowed[0]),
                authority: SessionAuthority::Ownership,
            },
        )
        .expect_err("pull empty");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded, "Pull");

        // Open a narrow grant session for GetRecord / GetCoinProof.
        let result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Grant,
            subject: subj,
            requested: asset_scope(0x99),
            resolved: asset_scope(0x99),
            allowed: &allowed,
            now,
        });
        let tok = result.session.as_str().to_string();
        let cb = ChanBind(allowed[0]);

        // 2. GetRecord out of scope.
        let err = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: rid_out,
                session: tok.clone(),
                chan_bind: cb,
            },
        )
        .expect_err("GetRecord");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded, "GetRecord");

        // 3. GetCoinProof out of scope.
        let err = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetCoinProofCommand {
                coin_id: coin_out,
                session: tok,
                chan_bind: cb,
            },
        )
        .expect_err("GetCoinProof");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded, "GetCoinProof");
    }

    /// Grant time window: record **before** `not_before` is invisible on Pull
    /// and rejected with `scope_exceeded` on GetRecord / GetCoinProof.
    ///
    /// Restores the assurance that lived only on the removed receipt unit
    /// test (`time_window_is_enforced`) onto the remaining reading procedures.
    #[test]
    fn time_window_rejects_record_before_not_before() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[0x10u8; 32]];
        let now = 10_000u64;
        let subj = subject(0x20);
        // Window [1000, 2000]; record at 999 is strictly before.
        let window = time_scope(1_000, 2_000);
        let (rid, coin) = plant_coin(&index, subj, 0x41, 999, b"before-window");

        let result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Grant,
            subject: subj,
            requested: window.clone(),
            resolved: window,
            allowed: &allowed,
            now,
        });
        assert!(
            result.records.is_empty(),
            "Pull must not list a record before not_before"
        );

        let tok = result.session.as_str().to_string();
        let cb = ChanBind(allowed[0]);

        let err = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: rid,
                session: tok.clone(),
                chan_bind: cb,
            },
        )
        .expect_err("GetRecord before window");
        assert_eq!(
            err.code,
            KernelErrorCode::ScopeExceeded,
            "same-subject out-of-window is scope_exceeded, not not_found"
        );

        let err = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetCoinProofCommand {
                coin_id: coin,
                session: tok,
                chan_bind: cb,
            },
        )
        .expect_err("GetCoinProof before window");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded, "GetCoinProof");
    }

    /// Grant time window: record **after** `not_after` is invisible on Pull
    /// and rejected with `scope_exceeded` on GetRecord / GetCoinProof.
    #[test]
    fn time_window_rejects_record_after_not_after() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[0x11u8; 32]];
        let now = 11_000u64;
        let subj = subject(0x21);
        // Window [1000, 2000]; record at 2001 is strictly after (not_after inclusive).
        let window = time_scope(1_000, 2_000);
        let (rid, coin) = plant_coin(&index, subj, 0x42, 2_001, b"after-window");

        let result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Grant,
            subject: subj,
            requested: window.clone(),
            resolved: window,
            allowed: &allowed,
            now,
        });
        assert!(
            result.records.is_empty(),
            "Pull must not list a record after not_after"
        );

        let tok = result.session.as_str().to_string();
        let cb = ChanBind(allowed[0]);

        let err = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: rid,
                session: tok.clone(),
                chan_bind: cb,
            },
        )
        .expect_err("GetRecord after window");
        assert_eq!(
            err.code,
            KernelErrorCode::ScopeExceeded,
            "same-subject out-of-window is scope_exceeded, not not_found"
        );

        let err = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetCoinProofCommand {
                coin_id: coin,
                session: tok,
                chan_bind: cb,
            },
        )
        .expect_err("GetCoinProof after window");
        assert_eq!(err.code, KernelErrorCode::ScopeExceeded, "GetCoinProof");
    }

    /// Grant time window: record **inside** `[not_before, not_after]` is listed
    /// by Pull and released by GetRecord / GetCoinProof. Without this positive
    /// case the two reject tests alone only prove that everything is denied.
    #[test]
    fn time_window_admits_record_inside() {
        let challenges = ChallengeStore::new();
        let sessions = SessionStore::new();
        let index = InMemoryPrivateIndex::new();
        let allowed = [[0x12u8; 32]];
        let now = 12_000u64;
        let subj = subject(0x22);
        // Window [1000, 2000]; record at 1500 is strictly inside (and at both
        // inclusive bounds would also be admitted — see predicate).
        let window = time_scope(1_000, 2_000);
        let (rid, coin) = plant_coin(&index, subj, 0x43, 1_500, b"inside-window");

        let result = open_and_pull(OpenAndPullSetup {
            challenges: &challenges,
            sessions: &sessions,
            index: &index,
            authority: SessionAuthority::Grant,
            subject: subj,
            requested: window.clone(),
            resolved: window,
            allowed: &allowed,
            now,
        });
        assert_eq!(
            result.records.len(),
            1,
            "Pull must list the in-window record"
        );
        assert_eq!(result.records[0].record_id, rid);

        let tok = result.session.as_str().to_string();
        let cb = ChanBind(allowed[0]);

        let blob = get_record(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetRecordCommand {
                record_id: rid,
                session: tok.clone(),
                chan_bind: cb,
            },
        )
        .expect("GetRecord inside window");
        assert_eq!(blob.canonical, b"inside-window");

        let bytes = get_coin_proof(
            deps(&challenges, &sessions, &index, &allowed, now),
            GetCoinProofCommand {
                coin_id: coin,
                session: tok,
                chan_bind: cb,
            },
        )
        .expect("GetCoinProof inside window");
        assert_eq!(bytes, b"inside-window");
    }

    #[test]
    fn record_type_transition_kind_invariants() {
        let ok_sdr = RecordRef {
            record_id: digest(1),
            record_type: RecordType::SelfDelivery,
            transition_kind: Some(TransitionKind::Mint),
            blob_id: digest(2),
            occurred_at: 0,
        };
        ok_sdr.validate().expect("sdr with kind");

        let bad_sdr = RecordRef {
            record_id: digest(1),
            record_type: RecordType::SelfDelivery,
            transition_kind: None,
            blob_id: digest(2),
            occurred_at: 0,
        };
        let err = bad_sdr.validate().expect_err("sdr without kind");
        assert_eq!(err.code, KernelErrorCode::InternalError);

        let coin = RecordRef {
            record_id: digest(1),
            record_type: RecordType::CoinProof,
            transition_kind: None,
            blob_id: digest(2),
            occurred_at: 0,
        };
        coin.validate().expect("coinproof without kind ok");
    }

    #[test]
    fn access_error_triples_match_contract() {
        // Codes used by remaining access procedures (session / scope /
        // unauthorized / internal) must keep the normative describe triple.
        let d = error_contract::describe(KernelErrorCode::InternalError);
        assert_eq!(d.reason, "internal_error");
        assert_eq!(d.http_status, 500);
        assert_eq!(d.grpc_code, GrpcStatusCode::Internal);

        let d = error_contract::describe(KernelErrorCode::SessionExpired);
        assert_eq!(d.reason, "session_expired");
        assert_eq!(d.http_status, 410);
        assert_eq!(d.grpc_code, GrpcStatusCode::Unauthenticated);

        let d = error_contract::describe(KernelErrorCode::ScopeExceeded);
        assert_eq!(d.reason, "scope_exceeded");
        assert_eq!(d.http_status, 403);
        assert_eq!(d.grpc_code, GrpcStatusCode::PermissionDenied);

        let d = error_contract::describe(KernelErrorCode::Unauthorized);
        assert_eq!(d.reason, "unauthorized");
        assert_eq!(d.http_status, 401);
        assert_eq!(d.grpc_code, GrpcStatusCode::Unauthenticated);
    }

    #[test]
    fn validate_closed_sets_accepts_current() {
        validate_closed_sets().expect("closed sets");
    }

    #[test]
    fn pull_challenge_domain_is_distinct() {
        assert_eq!(ChallengeAction::Pull.domain(), "zkCoins/v1/PullChallenge");
        assert_ne!(
            ChallengeAction::Pull.domain(),
            ChallengeAction::AttestBalance.domain()
        );
    }

    #[test]
    fn load_error_does_not_become_empty_list() {
        // PrivateIndex trait contract: InMemory never converts lock failure
        // into Ok([]). Documented by the map_err paths. Smoke: empty index
        // returns Ok([]) only when truly empty, not on error.
        let index = InMemoryPrivateIndex::new();
        let list = index.list_records(&subject(1), &unbounded()).expect("ok");
        assert!(list.is_empty());
    }
}
