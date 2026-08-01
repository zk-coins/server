//! Scope helpers shared by private-index reads — and the **future**
//! `SubscribeReceipts` writer contract (§4.8 / §4.9 / §7.8).
//!
//! ## Why there is no hub here
//!
//! There is no production path that publishes verified credits after
//! durable persist. Accepting a `SubscribeReceipts` subscription without
//! such a writer would open a silent empty stream (the Block-2 empty
//! Notify-Map failure mode). The gRPC edge therefore answers
//! `Unimplemented` and names the missing prerequisite; domain fan-out
//! (broadcast hub, session-scoped filter stream) is not built until a
//! real writer exists. Lane rule since Block 3: a surface that only a
//! later block can wire is not built now.
//!
//! ## Future writer contract (normative for the later block)
//!
//! The durable decrypt-index writer (migration 0031 / §4.4 scanner) now
//! stores verified CoinProofs **before** ACK. Credit (receive transition)
//! and `SubscribeReceipts` still require a separate writer that emits
//! **after** account credit. When that credit writer is introduced, it
//! **must**:
//!
//! 1. Emit the event **after** verification and durable persist (§4.8 /
//!    §4.9), never before — store-everything holds before any push.
//! 2. Carry on each receipt: `coin_id`, `asset_id`, `amount`, `state`,
//!    `credited_at` (plus server-side subject for admission only).
//! 3. Filter every emission by the **server-side** session subject and
//!    the session's resolved scope — never by a client-supplied filter
//!    or wished subject on the subscribe request.
//! 4. Accept a subscription **only** when a writer exists; otherwise the
//!    procedure answers that it cannot (honest `Unimplemented` / named
//!    prerequisite). A writer-less acceptance is forbidden.
//!
//! Point 4 is the lesson of the removed test-only hub: production logic
//! that only tests can reach is confirmed by tests that say nothing about
//! the running service.
//!
//! `scope_admits_asset_and_time` below is **not** receipt machinery — it is
//! the shared asset/time predicate used by the private-index procedures
//! (`Pull` list, `GetRecord`, `GetCoinProof`).

use crate::kernel::grants::{GrantAssetScope, GrantScope};
use crate::kernel::types::Digest32;

/// Asset + time window check for private-index queries (and, later, receipt
/// admission once a writer exists).
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
