//! zkCoins Nostr event kinds from §7.3 that this block owns.
//!
//! | Kind | Module | Notes |
//! |---|---|---|
//! | `1420` | [`delivery`] | delivery rumor payload |
//! | `1421` | [`ack`] | ACK rumor payload (closed four fields) |
//! | `30423` | [`bootstrap`] | addressable bootstrap manifest (tests only) |
//!
//! `30421` (publisher profile) and `30422` (operator endpoint) are
//! intentionally absent — publisher / gossip surface, no caller here.
//!
//! Kind `30423` encode/decode is fully unit-tested under [`bootstrap`], but
//! production boot still loads BMF1 from ops configuration — there is no
//! Nostr mirror caller in this crate yet. The module stays `cfg(test)` so
//! the lib target does not carry unused surface; when discovery-by-relay
//! lands, re-export it as production code with a real caller.

pub(crate) mod ack;
#[cfg(test)]
pub(crate) mod bootstrap;
pub(crate) mod delivery;
