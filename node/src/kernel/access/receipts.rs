//! Receipt writer + fan-out hub for `SubscribeReceipts` (§4.8 / §4.9 / §7.8).
//!
//! ## Writer contract (normative)
//!
//! The receive path (`v1::incoming`) verifies an incoming CoinProof, durably
//! persists it (`v1_decrypt_index` / migration 0031), mirrors into the
//! process-local private index, then — **only after that dual insert** —
//! publishes a credit receipt through this hub. Subscriptions without a
//! writer are forbidden (silent empty streams are worse than honest
//! unavailability).
//!
//! 1. Emit **after** verification and durable persist (§4.8 / §4.9), never
//!    before — store-everything holds before any push.
//! 2. Each receipt carries `coin_id`, `asset_id`, `amount`, `state`,
//!    `credited_at` (plus server-side subject for admission only — never
//!    on the wire `Receipt` message).
//! 3. Every emission is filtered by the **server-side** session subject and
//!    the session's resolved scope — never by a client-supplied filter or
//!    wished subject on the subscribe request.
//! 4. A subscription is accepted only when this hub (the writer) is wired
//!    into the façade. Without it the procedure must not open a stream.
//!
//! ## Back-pressure
//!
//! Each subscription has a **bounded** queue
//! ([`RECEIPT_SUBSCRIBER_BUFFER`]). A slow or gone subscriber must never
//! block the writer. When `try_send` finds the queue full the subscription
//! is **dropped** (stream ends); the client re-syncs via pull. Unbounded
//! buffering is forbidden.
//!
//! ## Scope helper
//!
//! [`scope_admits_asset_and_time`] is shared with private-index reads
//! (`Pull` list, `GetRecord`, `GetCoinProof`) and with receipt admission.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use super::session::{ActiveSession, SessionStore};
use super::{InsertRecordOutcome, SessionBoundRequest};
use crate::kernel::grants::{GrantAssetScope, GrantScope};
use crate::kernel::types::{Digest32, SubjectAddress};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult, KernelStream};

/// Per-subscriber queue depth. Full → subscription closed (no unbounded
/// buffer; slow consumers re-sync via pull §5.1 / §7.5).
pub(crate) const RECEIPT_SUBSCRIBER_BUFFER: usize = 16;

/// §3.10 transaction state at emission time (closed set).
///
/// Wire strings match `nullifiers[i].state` / receipt `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiptState {
    Completed,
    Pending,
    Failed,
}

impl ReceiptState {
    /// Every §3.10 state. Length is the closed-set contract.
    pub(crate) const ALL: [ReceiptState; 3] = [Self::Completed, Self::Pending, Self::Failed];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Pending => "pending",
            Self::Failed => "failed",
        }
    }
}

/// One verified credit ready for push (§7.8 `Receipt` + server subject).
///
/// `subject` is used **only** for hub admission / scope filter. It is
/// never serialised onto the proto `Receipt` message (which has no
/// subject field).
///
/// No derived [`Debug`]: `coin_id`, `asset_id`, `amount`, and `subject` are
/// §5 private data. A derived impl would print them into any `{:?}` log or
/// panic — hand-written `Debug` shows only non-private metadata.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CreditReceipt {
    pub subject: SubjectAddress,
    pub coin_id: Digest32,
    pub asset_id: Digest32,
    pub amount: u128,
    pub state: ReceiptState,
    pub credited_at: u64,
}

impl std::fmt::Debug for CreditReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreditReceipt")
            .field("subject", &"<redacted>")
            .field("coin_id", &"<redacted>")
            .field("asset_id", &"<redacted>")
            .field("amount", &"<redacted>")
            .field("state", &self.state)
            .field("credited_at", &self.credited_at)
            .finish()
    }
}

/// Whether a dual-persist outcome authorises a push receipt.
///
/// Only a **fresh** insert on **both** durable SQL and the process mirror
/// may emit. Replay (`AlreadyPresent` on either side) must not re-push
/// (no second credit signal). A failed persist never reaches this gate.
pub(crate) fn should_emit_credit(sql: InsertRecordOutcome, mem: InsertRecordOutcome) -> bool {
    matches!(
        (sql, mem),
        (InsertRecordOutcome::Inserted, InsertRecordOutcome::Inserted)
    )
}

/// Publish `receipt` when `should_emit_credit` is true; otherwise no-op.
///
/// The production receive path calls this **only after** both durable SQL
/// and process-index inserts have returned — never before, never on a
/// failed persist path.
pub(crate) fn publish_credit_if_inserted(
    sql: InsertRecordOutcome,
    mem: InsertRecordOutcome,
    hub: &ReceiptHub,
    receipt: CreditReceipt,
) {
    if should_emit_credit(sql, mem) {
        hub.publish(receipt);
    }
}

/// Asset + time window check for private-index queries and receipt admission.
pub(crate) fn scope_admits_asset_and_time(
    scope: &GrantScope,
    asset_id: &Digest32,
    occurred_at: u64,
) -> bool {
    if occurred_at < scope.not_before {
        return false;
    }
    if occurred_at > scope.not_after {
        return false;
    }
    match &scope.assets {
        GrantAssetScope::All => true,
        GrantAssetScope::Selected(ids) => ids.iter().any(|id| id == asset_id),
    }
}

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

struct Subscription {
    id: u64,
    subject: SubjectAddress,
    scope: GrantScope,
    tx: mpsc::Sender<CreditReceipt>,
}

/// Process-local fan-out for verified credit receipts.
///
/// Writers call [`ReceiptHub::publish`] after durable persist. Subscribers
/// receive only receipts whose subject and (asset, time) fall inside the
/// **server-side** session snapshot recorded at subscribe time.
///
/// No [`Debug`]: subscription slots hold live channels (not useful to log).
pub(crate) struct ReceiptHub {
    next_id: AtomicU64,
    subs: Mutex<Vec<Subscription>>,
}

impl Default for ReceiptHub {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptHub {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            subs: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Fan out one credit. Never blocks: full queues drop that subscriber.
    pub(crate) fn publish(&self, receipt: CreditReceipt) {
        let mut guard = match self.subs.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|sub| {
            if sub.subject != receipt.subject {
                return true;
            }
            if !scope_admits_asset_and_time(&sub.scope, &receipt.asset_id, receipt.credited_at) {
                return true;
            }
            match sub.tx.try_send(receipt.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Lag: drop this subscription. Client re-syncs via pull.
                    tracing::warn!(
                        sub_id = sub.id,
                        "SubscribeReceipts subscriber lagged; closing stream \
                         (bounded buffer full — pull is the durable path)"
                    );
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
    }

    /// Open a filtered subscription for one session subject + resolved scope.
    ///
    /// Returns a live stream that ends when the subscriber lags (buffer full
    /// and publisher drops the sender) or the hub drops the slot.
    pub(crate) fn subscribe(
        &self,
        subject: SubjectAddress,
        scope: GrantScope,
    ) -> KernelStream<CreditReceipt> {
        let (tx, mut rx) = mpsc::channel(RECEIPT_SUBSCRIBER_BUFFER);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut guard = match self.subs.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.push(Subscription {
                id,
                subject,
                scope,
                tx,
            });
        }
        let stream = async_stream::stream! {
            while let Some(receipt) = rx.recv().await {
                yield Ok(receipt);
            }
            // Sender dropped: lag close, explicit unsubscribe, or hub drop.
        };
        Box::pin(stream)
    }

    /// Test/observability: number of live subscription slots.
    #[cfg(test)]
    pub(crate) fn subscriber_count(&self) -> usize {
        let guard = match self.subs.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.len()
    }
}

// ---------------------------------------------------------------------------
// Domain procedure
// ---------------------------------------------------------------------------

/// `SubscribeReceipts` (§7.8): open a filtered push stream for a pull session.
///
/// # Authority
///
/// Ownership **or** grant pull sessions are admissible (§7.5 / §7.8). Subject
/// and resolved scope come exclusively from the **server-side** session
/// record. The request carries no subject field.
///
/// # Ordering relative to credit
///
/// This only **subscribes**. Emission is the receive path after durable
/// persist via [`publish_credit_if_inserted`].
pub(crate) fn subscribe_receipts(
    sessions: &SessionStore,
    hub: &ReceiptHub,
    request: SessionBoundRequest,
    now: u64,
) -> KernelResult<KernelStream<CreditReceipt>> {
    let session = lookup_session(sessions, &request.session, &request.chan_bind, now)?;
    // Both Ownership and Grant: match arms are exhaustive — no authority
    // widening beyond what Pull issued.
    let common = match &session {
        ActiveSession::Ownership(c) | ActiveSession::Grant(c) => c,
    };
    Ok(hub.subscribe(common.subject, common.scope.clone()))
}

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
    chan_bind: &crate::kernel::types::ChanBind,
    now: u64,
) -> KernelResult<ActiveSession> {
    reject_empty_session_token(token)?;
    sessions
        .lookup(token, chan_bind, now)
        .map_err(super::session::SessionError::into_kernel_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Access façade (not `super::session`): `super` here is `receipts`, and
    // the closed façade re-exports session types at `crate::kernel::access`.
    use crate::kernel::access::{SessionAuthority, SessionStore};
    use crate::kernel::grants::SCOPE_NOT_AFTER_UNBOUNDED;
    use crate::kernel::types::ChanBind;
    use futures_util::StreamExt;

    fn subject(b: u8) -> SubjectAddress {
        SubjectAddress([b; 32])
    }

    fn digest(b: u8) -> Digest32 {
        Digest32([b; 32])
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

    fn receipt(subj: u8, asset: u8, amount: u128, at: u64) -> CreditReceipt {
        CreditReceipt {
            subject: subject(subj),
            coin_id: digest(asset.wrapping_add(0x80)),
            asset_id: digest(asset),
            amount,
            state: ReceiptState::Completed,
            credited_at: at,
        }
    }

    async fn next_ok(stream: &mut KernelStream<CreditReceipt>) -> CreditReceipt {
        match stream.next().await {
            Some(Ok(r)) => r,
            other => panic!("expected Ok receipt, got {other:?}"),
        }
    }

    // --- Contract 1: emit only after durable insert (gate) ---------------

    #[test]
    fn should_emit_only_when_both_inserts_are_fresh() {
        use InsertRecordOutcome::*;
        assert!(should_emit_credit(Inserted, Inserted));
        assert!(!should_emit_credit(AlreadyPresent, Inserted));
        assert!(!should_emit_credit(Inserted, AlreadyPresent));
        assert!(!should_emit_credit(AlreadyPresent, AlreadyPresent));
    }

    #[tokio::test]
    async fn failed_or_replay_persist_produces_no_receipt() {
        // Contract point 1: no emission without a fresh dual insert.
        // A failed persist never calls publish_credit_if_inserted; a replay
        // calls it with AlreadyPresent and must not push.
        let hub = ReceiptHub::new();
        let mut stream = hub.subscribe(subject(1), unbounded());

        publish_credit_if_inserted(
            InsertRecordOutcome::AlreadyPresent,
            InsertRecordOutcome::AlreadyPresent,
            &hub,
            receipt(1, 0x11, 100, 50),
        );
        // No matching emission: stream stays open but empty.
        let idle = tokio::time::timeout(std::time::Duration::from_millis(30), stream.next()).await;
        assert!(
            idle.is_err(),
            "replay must not push a receipt; got {idle:?}"
        );

        // Fresh insert does emit (positive control for the same hub).
        publish_credit_if_inserted(
            InsertRecordOutcome::Inserted,
            InsertRecordOutcome::Inserted,
            &hub,
            receipt(1, 0x11, 100, 50),
        );
        let got = next_ok(&mut stream).await;
        assert_eq!(got.amount, 100);
        assert_eq!(got.coin_id, digest(0x11u8.wrapping_add(0x80)));
        assert_eq!(got.state, ReceiptState::Completed);
        assert_eq!(got.credited_at, 50);
        // subject is admission-only on the domain type
        assert_eq!(got.subject, subject(1));
    }

    // --- Contract 2: receipt fields --------------------------------------

    #[tokio::test]
    async fn receipt_carries_required_fields() {
        let hub = ReceiptHub::new();
        let mut stream = hub.subscribe(subject(2), unbounded());
        let r = receipt(2, 0x22, 9_007_199_254_740_991, 1_700_000_000);
        hub.publish(r.clone());
        let got = next_ok(&mut stream).await;
        assert_eq!(got.coin_id, r.coin_id);
        assert_eq!(got.asset_id, r.asset_id);
        assert_eq!(got.amount, r.amount);
        assert_eq!(got.state, r.state);
        assert_eq!(got.credited_at, r.credited_at);
        assert_eq!(got.state.as_str(), "completed");
    }

    // --- Contract 3: server-side subject + scope filter ------------------

    #[tokio::test]
    async fn scope_filter_drops_out_of_scope_asset() {
        let hub = ReceiptHub::new();
        // Session resolved scope: only asset 0x10.
        let mut stream = hub.subscribe(subject(3), asset_scope(0x10));

        hub.publish(receipt(3, 0x20, 1, 10)); // out of scope
        hub.publish(receipt(3, 0x10, 2, 10)); // in scope

        let got = next_ok(&mut stream).await;
        assert_eq!(got.asset_id, digest(0x10));
        assert_eq!(got.amount, 2);

        let idle = tokio::time::timeout(std::time::Duration::from_millis(30), stream.next()).await;
        assert!(idle.is_err(), "out-of-scope asset must not arrive");
    }

    #[tokio::test]
    async fn foreign_subject_never_reaches_subscription() {
        let hub = ReceiptHub::new();
        let mut stream = hub.subscribe(subject(4), unbounded());

        hub.publish(receipt(5, 0x10, 99, 10)); // foreign subject
        hub.publish(receipt(4, 0x10, 1, 10)); // own

        let got = next_ok(&mut stream).await;
        assert_eq!(got.subject, subject(4));
        assert_eq!(got.amount, 1);

        let idle = tokio::time::timeout(std::time::Duration::from_millis(30), stream.next()).await;
        assert!(idle.is_err(), "foreign subject must not arrive");
    }

    #[tokio::test]
    async fn client_cannot_supply_subject_on_subscribe_request() {
        // Proto SubscribeReceiptsRequest = { session, chan_bind } only.
        // Domain uses SessionBoundRequest — no subject field. Subject is
        // taken from the server-side session issued at Pull.
        let sessions = SessionStore::new();
        let hub = ReceiptHub::new();
        let now = 1_000u64;
        let subj = subject(6);
        let bind = ChanBind([0xABu8; 32]);
        let (token, _exp) =
            sessions.issue(SessionAuthority::Ownership, subj, unbounded(), bind, now);

        // Structural: SessionBoundRequest has no subject.
        let request = SessionBoundRequest {
            session: token.0.clone(),
            chan_bind: bind,
        };
        let _ = request.session;
        let _ = request.chan_bind;
        // compile-time: no request.subject

        let mut stream = subscribe_receipts(&sessions, &hub, request, now).expect("subscribe");

        // Emit for the session subject → arrives.
        hub.publish(receipt(6, 0x01, 7, now));
        // Emit for a "wished" foreign subject → must not arrive.
        hub.publish(receipt(0xFF, 0x01, 8, now));

        let got = next_ok(&mut stream).await;
        assert_eq!(got.subject, subj);
        assert_eq!(got.amount, 7);

        let idle = tokio::time::timeout(std::time::Duration::from_millis(30), stream.next()).await;
        assert!(
            idle.is_err(),
            "client cannot redirect the stream to another subject"
        );
    }

    // --- Contract 4: subscription only with a writer (hub) ---------------

    #[tokio::test]
    async fn subscribe_requires_live_session_then_uses_hub_writer() {
        let sessions = SessionStore::new();
        let hub = ReceiptHub::new();
        let now = 2_000u64;
        // No session → unauthorized / session_expired, never an open stream.
        // Match (not `expect_err`): Ok is a `KernelStream` / boxed dyn Stream
        // with no Debug — and must not gain one that could print receipts.
        let err = match subscribe_receipts(
            &sessions,
            &hub,
            SessionBoundRequest {
                session: "missing".into(),
                chan_bind: ChanBind([1u8; 32]),
            },
            now,
        ) {
            Err(e) => e,
            Ok(_) => panic!("unknown session — must fail closed, not open a stream"),
        };
        assert_eq!(err.code, KernelErrorCode::SessionExpired);

        let bind = ChanBind([2u8; 32]);
        let (token, _) = sessions.issue(
            SessionAuthority::Grant,
            subject(7),
            asset_scope(0x33),
            bind,
            now,
        );
        let mut stream = subscribe_receipts(
            &sessions,
            &hub,
            SessionBoundRequest {
                session: token.0,
                chan_bind: bind,
            },
            now,
        )
        .expect("grant session admissible on receipts");
        assert_eq!(hub.subscriber_count(), 1);

        hub.publish(receipt(7, 0x33, 3, now));
        let got = next_ok(&mut stream).await;
        assert_eq!(got.amount, 3);
    }

    // --- Back-pressure: full buffer drops the subscriber -----------------

    #[tokio::test]
    async fn lagged_subscriber_is_dropped_writer_does_not_block() {
        let hub = ReceiptHub::new();
        let mut stream = hub.subscribe(subject(8), unbounded());

        // Fill the bounded buffer without draining.
        for i in 0..RECEIPT_SUBSCRIBER_BUFFER {
            hub.publish(receipt(8, 0x01, i as u128, 1));
        }
        assert_eq!(hub.subscriber_count(), 1);

        // One more matching credit: try_send Full → subscription dropped.
        hub.publish(receipt(8, 0x01, 999, 1));
        assert_eq!(
            hub.subscriber_count(),
            0,
            "lagged subscriber must be removed so the writer never blocks"
        );

        // Drain what was buffered; then the stream ends (sender dropped).
        let mut seen = 0u32;
        while let Some(item) = stream.next().await {
            item.expect("buffered item");
            seen += 1;
        }
        assert_eq!(seen as usize, RECEIPT_SUBSCRIBER_BUFFER);

        // Writer path remains usable for a fresh subscriber.
        let mut stream2 = hub.subscribe(subject(8), unbounded());
        hub.publish(receipt(8, 0x01, 42, 2));
        let got = next_ok(&mut stream2).await;
        assert_eq!(got.amount, 42);
    }

    #[test]
    fn receipt_state_closed_set_is_pairwise_distinct() {
        let wires: Vec<_> = ReceiptState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(wires.len(), 3);
        for (i, a) in wires.iter().enumerate() {
            assert!(!a.is_empty());
            for (j, b) in wires.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn scope_admits_asset_and_time_bounds() {
        let scope = GrantScope {
            assets: GrantAssetScope::Selected(vec![digest(1)]),
            not_before: 10,
            not_after: 20,
        };
        assert!(!scope_admits_asset_and_time(&scope, &digest(1), 9));
        assert!(scope_admits_asset_and_time(&scope, &digest(1), 10));
        assert!(scope_admits_asset_and_time(&scope, &digest(1), 20));
        assert!(!scope_admits_asset_and_time(&scope, &digest(1), 21));
        assert!(!scope_admits_asset_and_time(&scope, &digest(2), 15));
        assert!(scope_admits_asset_and_time(&unbounded(), &digest(9), 0));
    }
}
