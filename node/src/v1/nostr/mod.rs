//! Nostr transport primitives for the node.
//!
//! | Module | Scope |
//! |---|---|
//! | [`event`] | NIP-01 id serialization, BIP-340 sign / verify |
//! | [`nip44`] | NIP-44 v2 conversation keys + padded AEAD payload |
//! | [`nip59`] | NIP-59 rumor / seal (13) / gift-wrap (1059) |
//! | [`kinds`] | zkCoins kinds `1420`, `1421` (and test-only `30423`) |
//! | [`relay`] | NIP-01 WebSocket client + multi-relay pool |
//! | [`profile`] | kind-0 `zkcoins` object, payment checklist, `Invoice` (no NIP-05) |
//!
//! # Out of scope
//!
//! Blossom lives in [`crate::v1::blossom`] (HTTP, not a Nostr primitive).
//! The send-path builder that wires these primitives is [`crate::v1::delivery`].
//!
//! # Placement
//!
//! Crate-private under `v1` so the public-surface allowlists stay still and
//! the kernel remains transport-free.
//!
//! Spec anchors: §1.3 (`detect_tag` / `epk`), §4.2 (bundle delivery + ACK),
//! §4.3 (addressing, `Invoice`, kind-0 by op — names/NIP-05 are API-layer),
//! §7.3 (event kinds + profile checklists).

pub(crate) mod event;
pub(crate) mod kinds;
pub(crate) mod nip44;
pub(crate) mod nip59;
pub(crate) mod profile;
pub(crate) mod relay;
