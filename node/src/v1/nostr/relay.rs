//! NIP-01 relay client over WebSocket.
//!
//! A relay is an untrusted peer. Every inbound event is re-hashed and
//! BIP-340-verified before it is returned. Subscription ids are checked
//! against the set this client opened. Frame size, open-subscription
//! count, and events-per-subscription are hard limits (named constants;
//! exceed → error, never silent truncate). Every wait uses
//! [`tokio::time::timeout`] (connect, OK, EOSE, read).
//!
//! The pool publishes to every caller-supplied relay and returns one
//! outcome per relay. Queries union results and deduplicate by event
//! `id` after verification. Delivery-success policy is the caller's —
//! this module never decides “enough relays accepted”.
//!
//! Spec: §4.2 (delivery + `zkdt`/`zkepk` local scan tags), §4.3 (relay sets),
//! NIP-01 client protocol.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use super::event::{Event, EventError, EventParts};

// ---------------------------------------------------------------------------
// Hard limits (named; exceed → error)
// ---------------------------------------------------------------------------

/// Maximum WebSocket text-frame size accepted from a relay (1 MiB).
pub(crate) const MAX_FRAME_BYTES: usize = 1_048_576;

/// Maximum concurrently open `REQ` subscriptions on one connection.
pub(crate) const MAX_OPEN_SUBSCRIPTIONS: usize = 16;

/// Maximum verified events accepted for one subscription before error.
pub(crate) const MAX_EVENTS_PER_SUBSCRIPTION: usize = 10_000;

// ---------------------------------------------------------------------------
// Timeouts (named; every wait site)
// ---------------------------------------------------------------------------

/// Bound on WebSocket connect (TCP + optional TLS + handshake).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound waiting for the `OK` frame after `EVENT`.
pub(crate) const OK_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound waiting for `EOSE` after `REQ` (covers the whole collection window).
pub(crate) const EOSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bound on a single WebSocket `read` (`StreamExt::next`).
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Fail-closed reasons for the relay client and pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayError {
    /// Caller passed an empty relay URL list (pool has no default).
    EmptyRelayList,
    /// Relay URL is empty or not a `ws://` / `wss://` URI.
    InvalidRelayUrl { url: String },
    /// Connect exceeded [`CONNECT_TIMEOUT`].
    ConnectTimeout { url: String },
    /// Connect failed before the timeout (DNS, TCP, TLS, handshake).
    ConnectFailed { url: String, message: String },
    /// A single read exceeded [`READ_TIMEOUT`].
    ReadTimeout,
    /// Waiting for `OK` exceeded [`OK_TIMEOUT`].
    OkTimeout { event_id: [u8; 32] },
    /// Waiting for `EOSE` exceeded [`EOSE_TIMEOUT`].
    EoseTimeout { subscription_id: String },
    /// Inbound text frame larger than [`MAX_FRAME_BYTES`].
    FrameTooLarge { size: usize, max: usize },
    /// Frame is not valid JSON or not a NIP-01 array frame.
    MalformedFrame { reason: &'static str },
    /// Hex field width/alphabet wrong inside an event object.
    InvalidEventHex { field: &'static str },
    /// Inbound event failed id recompute and/or BIP-340 verify.
    EventVerification(EventError),
    /// `EVENT` frame named a subscription this client did not open.
    UnknownSubscription { subscription_id: String },
    /// Opening another `REQ` would exceed [`MAX_OPEN_SUBSCRIPTIONS`].
    TooManySubscriptions { open: usize, max: usize },
    /// Verified events for one sub exceeded [`MAX_EVENTS_PER_SUBSCRIPTION`].
    EventsLimitExceeded {
        subscription_id: String,
        count: usize,
        max: usize,
    },
    /// Relay answered `["OK", id, false, message]` — rejection, not success.
    Rejected { event_id: [u8; 32], message: String },
    /// Relay sent `CLOSED` for a subscription we still held.
    SubscriptionClosed {
        subscription_id: String,
        message: String,
    },
    /// WebSocket send failed.
    SendFailed { message: String },
    /// Peer closed the WebSocket while we still expected frames.
    ConnectionClosed,
    /// Unexpected control frame type (binary / ping handling failure).
    UnexpectedMessage { reason: &'static str },
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::EmptyRelayList => write!(f, "relay list is empty (no default relay)"),
            RelayError::InvalidRelayUrl { url } => write!(f, "invalid relay URL: {url}"),
            RelayError::ConnectTimeout { url } => {
                write!(f, "connect to {url} timed out after {CONNECT_TIMEOUT:?}")
            }
            RelayError::ConnectFailed { url, message } => {
                write!(f, "connect to {url} failed: {message}")
            }
            RelayError::ReadTimeout => {
                write!(f, "relay read timed out after {READ_TIMEOUT:?}")
            }
            RelayError::OkTimeout { event_id } => write!(
                f,
                "OK for event {} timed out after {OK_TIMEOUT:?}",
                hex::encode(event_id)
            ),
            RelayError::EoseTimeout { subscription_id } => write!(
                f,
                "EOSE for subscription {subscription_id:?} timed out after {EOSE_TIMEOUT:?}"
            ),
            RelayError::FrameTooLarge { size, max } => {
                write!(f, "relay frame size {size} exceeds max {max}")
            }
            RelayError::MalformedFrame { reason } => write!(f, "malformed relay frame: {reason}"),
            RelayError::InvalidEventHex { field } => {
                write!(f, "invalid hex in relay event field {field}")
            }
            RelayError::EventVerification(e) => write!(f, "inbound event verification failed: {e}"),
            RelayError::UnknownSubscription { subscription_id } => write!(
                f,
                "EVENT for unknown subscription_id {subscription_id:?} (not opened by this client)"
            ),
            RelayError::TooManySubscriptions { open, max } => {
                write!(f, "open subscriptions {open} would exceed max {max}")
            }
            RelayError::EventsLimitExceeded {
                subscription_id,
                count,
                max,
            } => write!(
                f,
                "subscription {subscription_id:?} received {count} events, exceeds max {max}"
            ),
            RelayError::Rejected { event_id, message } => write!(
                f,
                "relay rejected event {}: {message}",
                hex::encode(event_id)
            ),
            RelayError::SubscriptionClosed {
                subscription_id,
                message,
            } => write!(
                f,
                "relay CLOSED subscription {subscription_id:?}: {message}"
            ),
            RelayError::SendFailed { message } => write!(f, "relay send failed: {message}"),
            RelayError::ConnectionClosed => write!(f, "relay closed the WebSocket"),
            RelayError::UnexpectedMessage { reason } => {
                write!(f, "unexpected WebSocket message: {reason}")
            }
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::EventVerification(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Filter (NIP-01)
// ---------------------------------------------------------------------------

/// NIP-01 subscription filter. Tag filters use the wire key `#<name>`.
///
/// NIP-01 requires relays to index only **single-letter** tag names for
/// generic `#X` queries (`#e`, `#p`, `#t`, …). Multi-letter names such as
/// `zkdt` / `zkepk` are cleartext tags **for the recipient's local scan**
/// (§4.2 / §4.4): the client must not rely on relay-side `#zkdt` / `#zkepk`
/// filtering — detection is intentionally not server-side filterable, which
/// is the privacy property that forces a full kind-1059 pull. Serialising a
/// multi-letter tag filter remains valid wire format; a conforming relay
/// simply returns nothing for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Filter {
    pub ids: Option<Vec<[u8; 32]>>,
    pub authors: Option<Vec<[u8; 32]>>,
    pub kinds: Option<Vec<u32>>,
    /// `(tag_name_without_hash, values)` → serialised as `"#tag_name": values`.
    ///
    /// Only single-letter names are NIP-01-indexed on conforming relays.
    /// Do not put `zkdt` / `zkepk` here expecting a server-side pre-filter.
    pub tags: Vec<(String, Vec<String>)>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<u64>,
}

impl Filter {
    pub(crate) fn to_json(&self) -> Value {
        let mut map = Map::new();
        if let Some(ids) = &self.ids {
            let arr: Vec<Value> = ids
                .iter()
                .map(|id| Value::String(hex::encode(id)))
                .collect();
            map.insert("ids".into(), Value::Array(arr));
        }
        if let Some(authors) = &self.authors {
            let arr: Vec<Value> = authors
                .iter()
                .map(|a| Value::String(hex::encode(a)))
                .collect();
            map.insert("authors".into(), Value::Array(arr));
        }
        if let Some(kinds) = &self.kinds {
            let arr: Vec<Value> = kinds.iter().map(|k| json!(k)).collect();
            map.insert("kinds".into(), Value::Array(arr));
        }
        for (name, values) in &self.tags {
            let key = format!("#{name}");
            let arr: Vec<Value> = values.iter().cloned().map(Value::String).collect();
            map.insert(key, Value::Array(arr));
        }
        if let Some(since) = self.since {
            map.insert("since".into(), json!(since));
        }
        if let Some(until) = self.until {
            map.insert("until".into(), json!(until));
        }
        if let Some(limit) = self.limit {
            map.insert("limit".into(), json!(limit));
        }
        Value::Object(map)
    }
}

// ---------------------------------------------------------------------------
// Publish / pool outcomes (no aggregated success policy)
// ---------------------------------------------------------------------------

/// Per-relay result of publishing one event. The pool returns one of these
/// per requested URL; it never collapses them into a single bool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayPublishResult {
    Accepted {
        relay_url: String,
        message: String,
    },
    /// Relay answered `OK` with `false` — rejection with reason.
    Rejected {
        relay_url: String,
        message: String,
    },
    /// Connect, protocol, timeout, or transport failure for this URL only.
    Unreachable {
        relay_url: String,
        error: RelayError,
    },
}

/// Per-relay result of a multi-relay query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayQueryOutcome {
    Ok {
        relay_url: String,
        /// How many verified events this relay contributed (pre-dedup).
        event_count: usize,
    },
    Failed {
        relay_url: String,
        error: RelayError,
    },
}

/// Aggregate query view: verified events deduplicated by `id`, plus one
/// outcome per relay. Success policy is not decided here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayQueryAggregate {
    pub events: Vec<Event>,
    pub per_relay: Vec<RelayQueryOutcome>,
    /// Human-readable `NOTICE` strings observed on any connection.
    pub notices: Vec<String>,
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

fn validate_relay_url(url: &str) -> Result<(), RelayError> {
    if url.is_empty() {
        return Err(RelayError::InvalidRelayUrl {
            url: url.to_string(),
        });
    }
    if !(url.starts_with("ws://") || url.starts_with("wss://")) {
        return Err(RelayError::InvalidRelayUrl {
            url: url.to_string(),
        });
    }
    Ok(())
}

fn event_to_json_value(event: &Event) -> Value {
    json!({
        "id": hex::encode(event.id),
        "pubkey": hex::encode(event.pubkey),
        "created_at": event.created_at,
        "kind": event.kind,
        "tags": event.tags,
        "content": event.content,
        "sig": hex::encode(event.sig),
    })
}

fn parse_hex_exact<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], RelayError> {
    if s.len() != N * 2 {
        return Err(RelayError::InvalidEventHex { field });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(RelayError::InvalidEventHex { field });
    }
    let bytes = hex::decode(s).map_err(|_| RelayError::InvalidEventHex { field })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode an event object from a relay frame and **verify** it.
///
/// This is the trust boundary: claimed `id` is recomputed; signature is
/// checked under the author pubkey. Used by the live reader and by tests
/// that inject a synthetic frame (e.g. tampered content that never passed
/// a honest relay's store path).
pub(crate) fn verify_event_json(obj: &Value) -> Result<Event, RelayError> {
    let map = obj.as_object().ok_or(RelayError::MalformedFrame {
        reason: "event is not a JSON object",
    })?;
    let id = parse_hex_exact::<32>(
        map.get("id")
            .and_then(|v| v.as_str())
            .ok_or(RelayError::MalformedFrame {
                reason: "event.id missing",
            })?,
        "id",
    )?;
    let pubkey = parse_hex_exact::<32>(
        map.get("pubkey")
            .and_then(|v| v.as_str())
            .ok_or(RelayError::MalformedFrame {
                reason: "event.pubkey missing",
            })?,
        "pubkey",
    )?;
    let created_at =
        map.get("created_at")
            .and_then(|v| v.as_u64())
            .ok_or(RelayError::MalformedFrame {
                reason: "event.created_at missing",
            })?;
    let kind = map
        .get("kind")
        .and_then(|v| v.as_u64())
        .ok_or(RelayError::MalformedFrame {
            reason: "event.kind missing",
        })?;
    let kind = u32::try_from(kind).map_err(|_| RelayError::MalformedFrame {
        reason: "event.kind out of u32 range",
    })?;
    let content = map
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or(RelayError::MalformedFrame {
            reason: "event.content missing",
        })?
        .to_string();
    let sig = parse_hex_exact::<64>(
        map.get("sig")
            .and_then(|v| v.as_str())
            .ok_or(RelayError::MalformedFrame {
                reason: "event.sig missing",
            })?,
        "sig",
    )?;
    let tags_val = map.get("tags").ok_or(RelayError::MalformedFrame {
        reason: "event.tags missing",
    })?;
    let tags_arr = tags_val.as_array().ok_or(RelayError::MalformedFrame {
        reason: "event.tags is not an array",
    })?;
    let mut tags = Vec::with_capacity(tags_arr.len());
    for tag in tags_arr {
        let elems = tag.as_array().ok_or(RelayError::MalformedFrame {
            reason: "event tag is not an array",
        })?;
        let mut row = Vec::with_capacity(elems.len());
        for el in elems {
            let s = el.as_str().ok_or(RelayError::MalformedFrame {
                reason: "event tag element is not a string",
            })?;
            row.push(s.to_string());
        }
        tags.push(row);
    }

    let parts = EventParts {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig,
    };
    Event::verify_parts(parts).map_err(RelayError::EventVerification)
}

/// Parsed inbound NIP-01 client message (post-size-check, pre-sub filter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayServerMessage {
    /// `["EVENT", <subscription_id>, <event>]` — event already verified.
    Event {
        subscription_id: String,
        event: Event,
    },
    /// `["OK", <event_id>, <true|false>, <message>]`.
    Ok {
        event_id: [u8; 32],
        accepted: bool,
        message: String,
    },
    /// `["EOSE", <subscription_id>]`.
    Eose { subscription_id: String },
    /// `["CLOSED", <subscription_id>, <message>]`.
    Closed {
        subscription_id: String,
        message: String,
    },
    /// `["NOTICE", <message>]`.
    Notice { message: String },
}

/// Parse one text frame. Enforces [`MAX_FRAME_BYTES`] and verifies any
/// embedded event. Does **not** check subscription membership — the
/// client does that against its open set.
pub(crate) fn parse_server_frame(text: &str) -> Result<RelayServerMessage, RelayError> {
    if text.len() > MAX_FRAME_BYTES {
        return Err(RelayError::FrameTooLarge {
            size: text.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let value: Value = serde_json::from_str(text).map_err(|_| RelayError::MalformedFrame {
        reason: "frame is not JSON",
    })?;
    let arr = value.as_array().ok_or(RelayError::MalformedFrame {
        reason: "frame is not a JSON array",
    })?;
    if arr.is_empty() {
        return Err(RelayError::MalformedFrame {
            reason: "frame array is empty",
        });
    }
    let kind = arr[0].as_str().ok_or(RelayError::MalformedFrame {
        reason: "frame type is not a string",
    })?;
    match kind {
        "EVENT" => {
            if arr.len() != 3 {
                return Err(RelayError::MalformedFrame {
                    reason: "EVENT frame must have 3 elements",
                });
            }
            let subscription_id = arr[1]
                .as_str()
                .ok_or(RelayError::MalformedFrame {
                    reason: "EVENT subscription_id is not a string",
                })?
                .to_string();
            let event = verify_event_json(&arr[2])?;
            Ok(RelayServerMessage::Event {
                subscription_id,
                event,
            })
        }
        "OK" => {
            if arr.len() != 4 {
                return Err(RelayError::MalformedFrame {
                    reason: "OK frame must have 4 elements",
                });
            }
            let event_id = parse_hex_exact::<32>(
                arr[1].as_str().ok_or(RelayError::MalformedFrame {
                    reason: "OK event_id is not a string",
                })?,
                "ok.event_id",
            )?;
            let accepted = arr[2].as_bool().ok_or(RelayError::MalformedFrame {
                reason: "OK accepted flag is not a bool",
            })?;
            let message = arr[3]
                .as_str()
                .ok_or(RelayError::MalformedFrame {
                    reason: "OK message is not a string",
                })?
                .to_string();
            Ok(RelayServerMessage::Ok {
                event_id,
                accepted,
                message,
            })
        }
        "EOSE" => {
            if arr.len() != 2 {
                return Err(RelayError::MalformedFrame {
                    reason: "EOSE frame must have 2 elements",
                });
            }
            let subscription_id = arr[1]
                .as_str()
                .ok_or(RelayError::MalformedFrame {
                    reason: "EOSE subscription_id is not a string",
                })?
                .to_string();
            Ok(RelayServerMessage::Eose { subscription_id })
        }
        "CLOSED" => {
            if arr.len() < 2 {
                return Err(RelayError::MalformedFrame {
                    reason: "CLOSED frame must have at least 2 elements",
                });
            }
            let subscription_id = arr[1]
                .as_str()
                .ok_or(RelayError::MalformedFrame {
                    reason: "CLOSED subscription_id is not a string",
                })?
                .to_string();
            let message = match arr.get(2) {
                None => String::new(),
                Some(v) => v
                    .as_str()
                    .ok_or(RelayError::MalformedFrame {
                        reason: "CLOSED message is not a string",
                    })?
                    .to_string(),
            };
            Ok(RelayServerMessage::Closed {
                subscription_id,
                message,
            })
        }
        "NOTICE" => {
            if arr.len() != 2 {
                return Err(RelayError::MalformedFrame {
                    reason: "NOTICE frame must have 2 elements",
                });
            }
            let message = arr[1]
                .as_str()
                .ok_or(RelayError::MalformedFrame {
                    reason: "NOTICE message is not a string",
                })?
                .to_string();
            Ok(RelayServerMessage::Notice { message })
        }
        _ => Err(RelayError::MalformedFrame {
            reason: "unknown server message type",
        }),
    }
}

// ---------------------------------------------------------------------------
// RelayClient
// ---------------------------------------------------------------------------

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Single-relay NIP-01 client. One WebSocket; open subscriptions tracked
/// explicitly; every inbound event verified before return.
///
/// The connect URL is not retained: errors already carry it, and the pool
/// tracks the URL list. Diagnostic accessors without a production reader
/// are omitted.
pub(crate) struct RelayClient {
    ws: WsStream,
    open_subs: HashSet<String>,
    next_sub: u64,
    /// `NOTICE` messages observed (not swallowed); drained via [`Self::take_notices`].
    notices: Vec<String>,
}

/// Opaque `Debug`: never dump the live WebSocket, open-sub set, or notices
/// into a log (same posture as [`crate::esplora_bound::LegacyBroadcastClient`]).
impl fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayClient { /* inner private */ }")
    }
}

impl RelayClient {
    /// Connect with [`CONNECT_TIMEOUT`]. `url` must be `ws://` or `wss://`.
    pub(crate) async fn connect(url: &str) -> Result<Self, RelayError> {
        validate_relay_url(url)?;
        let connect = connect_async(url);
        match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Err(_) => Err(RelayError::ConnectTimeout {
                url: url.to_string(),
            }),
            Ok(Err(e)) => Err(RelayError::ConnectFailed {
                url: url.to_string(),
                message: e.to_string(),
            }),
            Ok(Ok((ws, _response))) => Ok(Self {
                ws,
                open_subs: HashSet::new(),
                next_sub: 0,
                notices: Vec::new(),
            }),
        }
    }

    pub(crate) fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    /// Open subscription count — used by integration tests to assert CLOSE.
    #[cfg(test)]
    pub(crate) fn open_subscription_count(&self) -> usize {
        self.open_subs.len()
    }

    /// Whether `subscription_id` is currently open on this connection.
    #[cfg(test)]
    pub(crate) fn has_subscription(&self, subscription_id: &str) -> bool {
        self.open_subs.contains(subscription_id)
    }

    async fn send_text(&mut self, text: String) -> Result<(), RelayError> {
        self.ws
            .send(Message::Text(text))
            .await
            .map_err(|e| RelayError::SendFailed {
                message: e.to_string(),
            })
    }

    /// One read with [`READ_TIMEOUT`]. Handles ping/pong; rejects oversized
    /// frames; records NOTICE; returns the next application message.
    async fn read_message(&mut self) -> Result<RelayServerMessage, RelayError> {
        loop {
            let next = tokio::time::timeout(READ_TIMEOUT, self.ws.next())
                .await
                .map_err(|_| RelayError::ReadTimeout)?;
            let msg = match next {
                None => return Err(RelayError::ConnectionClosed),
                Some(Err(e)) => {
                    return Err(RelayError::SendFailed {
                        message: format!("websocket read error: {e}"),
                    })
                }
                Some(Ok(m)) => m,
            };
            match msg {
                Message::Text(text) => {
                    let parsed = parse_server_frame(&text)?;
                    if let RelayServerMessage::Notice { message } = parsed {
                        self.notices.push(message);
                        continue;
                    }
                    return Ok(parsed);
                }
                Message::Ping(payload) => {
                    self.ws.send(Message::Pong(payload)).await.map_err(|e| {
                        RelayError::SendFailed {
                            message: e.to_string(),
                        }
                    })?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Err(RelayError::ConnectionClosed),
                Message::Binary(b) => {
                    if b.len() > MAX_FRAME_BYTES {
                        return Err(RelayError::FrameTooLarge {
                            size: b.len(),
                            max: MAX_FRAME_BYTES,
                        });
                    }
                    return Err(RelayError::UnexpectedMessage {
                        reason: "binary WebSocket frame (NIP-01 uses text)",
                    });
                }
                Message::Frame(_) => {
                    return Err(RelayError::UnexpectedMessage {
                        reason: "raw WebSocket frame",
                    })
                }
            }
        }
    }

    /// Publish `event` and wait for the matching `OK` within [`OK_TIMEOUT`].
    ///
    /// `OK` with `accepted == false` is [`RelayError::Rejected`] — not success.
    pub(crate) async fn publish(&mut self, event: &Event) -> Result<String, RelayError> {
        let frame = json!(["EVENT", event_to_json_value(event)]).to_string();
        self.send_text(frame).await?;

        let deadline = tokio::time::Instant::now() + OK_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(RelayError::OkTimeout { event_id: event.id });
            }
            let msg = match tokio::time::timeout(remaining, self.read_message()).await {
                Err(_) => return Err(RelayError::OkTimeout { event_id: event.id }),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(m)) => m,
            };
            match msg {
                RelayServerMessage::Ok {
                    event_id,
                    accepted,
                    message,
                } if event_id == event.id => {
                    if accepted {
                        return Ok(message);
                    }
                    return Err(RelayError::Rejected { event_id, message });
                }
                RelayServerMessage::Ok { .. } => {
                    // OK for a different event id — ignore and keep waiting.
                }
                RelayServerMessage::Closed {
                    subscription_id,
                    message,
                } => {
                    self.open_subs.remove(&subscription_id);
                    return Err(RelayError::SubscriptionClosed {
                        subscription_id,
                        message,
                    });
                }
                // EVENT / EOSE while waiting for OK: unexpected on a quiet
                // connection; keep waiting only if not for us — still bound
                // by OK_TIMEOUT. Do not accept unverified delivery here.
                RelayServerMessage::Event {
                    subscription_id, ..
                } => {
                    if !self.open_subs.contains(&subscription_id) {
                        return Err(RelayError::UnknownSubscription { subscription_id });
                    }
                }
                RelayServerMessage::Eose { .. } => {}
                RelayServerMessage::Notice { .. } => {
                    // Notices are recorded inside read_message; this arm is
                    // unreachable after that filter.
                }
            }
        }
    }

    fn alloc_subscription_id(&mut self) -> Result<String, RelayError> {
        if self.open_subs.len() >= MAX_OPEN_SUBSCRIPTIONS {
            return Err(RelayError::TooManySubscriptions {
                open: self.open_subs.len(),
                max: MAX_OPEN_SUBSCRIPTIONS,
            });
        }
        let id = format!("zk-sub-{}", self.next_sub);
        self.next_sub = self.next_sub.saturating_add(1);
        Ok(id)
    }

    /// `REQ` with `filters`, collect verified events until `EOSE`, then
    /// `CLOSE`. Hard-fails on unknown subscription ids, event-count
    /// overflow, verification failure, or [`EOSE_TIMEOUT`].
    pub(crate) async fn query(&mut self, filters: &[Filter]) -> Result<Vec<Event>, RelayError> {
        if filters.is_empty() {
            return Err(RelayError::MalformedFrame {
                reason: "REQ requires at least one filter",
            });
        }
        let sub_id = self.alloc_subscription_id()?;
        let mut frame = vec![json!("REQ"), json!(sub_id)];
        for f in filters {
            frame.push(f.to_json());
        }
        let text = Value::Array(frame).to_string();
        self.open_subs.insert(sub_id.clone());
        if let Err(e) = self.send_text(text).await {
            self.open_subs.remove(&sub_id);
            return Err(e);
        }

        let mut events = Vec::new();
        let deadline = tokio::time::Instant::now() + EOSE_TIMEOUT;
        let result = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break Err(RelayError::EoseTimeout {
                    subscription_id: sub_id.clone(),
                });
            }
            let msg = match tokio::time::timeout(remaining, self.read_message()).await {
                Err(_) => {
                    break Err(RelayError::EoseTimeout {
                        subscription_id: sub_id.clone(),
                    })
                }
                Ok(Err(e)) => break Err(e),
                Ok(Ok(m)) => m,
            };
            match msg {
                RelayServerMessage::Event {
                    subscription_id,
                    event,
                } => {
                    if subscription_id != sub_id {
                        if !self.open_subs.contains(&subscription_id) {
                            break Err(RelayError::UnknownSubscription { subscription_id });
                        }
                        // Event for a different open sub — not part of this
                        // query; refuse rather than silently co-mingle.
                        break Err(RelayError::UnknownSubscription { subscription_id });
                    }
                    if events.len() >= MAX_EVENTS_PER_SUBSCRIPTION {
                        break Err(RelayError::EventsLimitExceeded {
                            subscription_id: sub_id.clone(),
                            count: events.len().saturating_add(1),
                            max: MAX_EVENTS_PER_SUBSCRIPTION,
                        });
                    }
                    events.push(event);
                }
                RelayServerMessage::Eose { subscription_id } => {
                    if subscription_id == sub_id {
                        break Ok(());
                    }
                }
                RelayServerMessage::Closed {
                    subscription_id,
                    message,
                } => {
                    if subscription_id == sub_id {
                        self.open_subs.remove(&sub_id);
                        break Err(RelayError::SubscriptionClosed {
                            subscription_id,
                            message,
                        });
                    }
                    self.open_subs.remove(&subscription_id);
                }
                RelayServerMessage::Ok { .. } => {}
                RelayServerMessage::Notice { .. } => {}
            }
        };

        // Always CLOSE our subscription when still open (best-effort send).
        if self.open_subs.remove(&sub_id) {
            let close = json!(["CLOSE", sub_id]).to_string();
            // CLOSE failure after a successful collection is still an error
            // so the caller sees the connection is not clean.
            if let Err(e) = self.send_text(close).await {
                if result.is_ok() {
                    return Err(e);
                }
            }
        }

        result?;
        Ok(events)
    }

    /// Graceful close of the WebSocket.
    pub(crate) async fn close(mut self) -> Result<(), RelayError> {
        self.ws
            .close(None)
            .await
            .map_err(|e| RelayError::SendFailed {
                message: e.to_string(),
            })
    }
}

// ---------------------------------------------------------------------------
// RelayPool
// ---------------------------------------------------------------------------

/// Multi-relay helper. URLs come only from the caller — no default set,
/// no “try the next one” substitution.
#[derive(Clone, Debug)]
pub(crate) struct RelayPool {
    urls: Vec<String>,
}

impl RelayPool {
    /// Build a pool. Empty list is an error (no silent single-relay default).
    pub(crate) fn new(urls: Vec<String>) -> Result<Self, RelayError> {
        if urls.is_empty() {
            return Err(RelayError::EmptyRelayList);
        }
        for u in &urls {
            validate_relay_url(u)?;
        }
        Ok(Self { urls })
    }

    /// Publish `event` to **every** configured relay. Returns one
    /// [`RelayPublishResult`] per URL in order — never an aggregated bool.
    pub(crate) async fn publish_all(&self, event: &Event) -> Vec<RelayPublishResult> {
        let mut out = Vec::with_capacity(self.urls.len());
        for url in &self.urls {
            let outcome = match RelayClient::connect(url).await {
                Err(e) => RelayPublishResult::Unreachable {
                    relay_url: url.clone(),
                    error: e,
                },
                Ok(mut client) => match client.publish(event).await {
                    Ok(message) => {
                        let _ = client.close().await;
                        RelayPublishResult::Accepted {
                            relay_url: url.clone(),
                            message,
                        }
                    }
                    Err(RelayError::Rejected { message, .. }) => {
                        let _ = client.close().await;
                        RelayPublishResult::Rejected {
                            relay_url: url.clone(),
                            message,
                        }
                    }
                    Err(e) => {
                        let _ = client.close().await;
                        RelayPublishResult::Unreachable {
                            relay_url: url.clone(),
                            error: e,
                        }
                    }
                },
            };
            out.push(outcome);
        }
        out
    }

    /// Query every relay with the same filters; verify each event; merge
    /// by `id`. Per-relay failures are reported individually.
    pub(crate) async fn query_all(&self, filters: &[Filter]) -> RelayQueryAggregate {
        let mut by_id: HashMap<[u8; 32], Event> = HashMap::new();
        let mut per_relay = Vec::with_capacity(self.urls.len());
        let mut notices = Vec::new();

        for url in &self.urls {
            match RelayClient::connect(url).await {
                Err(e) => {
                    per_relay.push(RelayQueryOutcome::Failed {
                        relay_url: url.clone(),
                        error: e,
                    });
                }
                Ok(mut client) => match client.query(filters).await {
                    Ok(events) => {
                        let event_count = events.len();
                        for ev in events {
                            by_id.entry(ev.id).or_insert(ev);
                        }
                        notices.extend(client.take_notices());
                        let _ = client.close().await;
                        per_relay.push(RelayQueryOutcome::Ok {
                            relay_url: url.clone(),
                            event_count,
                        });
                    }
                    Err(e) => {
                        notices.extend(client.take_notices());
                        let _ = client.close().await;
                        per_relay.push(RelayQueryOutcome::Failed {
                            relay_url: url.clone(),
                            error: e,
                        });
                    }
                },
            }
        }

        RelayQueryAggregate {
            events: by_id.into_values().collect(),
            per_relay,
            notices,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    fn fixture_sk(label: &[u8]) -> [u8; 32] {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let _ = Keypair::from_secret_key(&secp, &sk);
                return sk_bytes;
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn signed_note(content: &str, tags: Vec<Vec<String>>) -> Event {
        let sk = fixture_sk(b"zkCoins/v1/test-vector/nostr/relay-sk");
        Event::sign(&sk, 1_700_000_100, 1, tags, content.to_string()).expect("sign")
    }

    // -----------------------------------------------------------------------
    // Trust boundary: tampered content rejected before hand-off
    // -----------------------------------------------------------------------

    /// A relay (or MITM) can send JSON whose `id` still looks like the
    /// original event while `content` was rewritten. The client must
    /// recompute the id and reject — this is the property that keeps
    /// NIP-01 authenticity.
    #[test]
    fn rejects_event_with_tampered_content_but_claimed_original_id() {
        let honest = signed_note("honest-payload", vec![]);
        // Build a wire object that keeps the original id + sig, but lies
        // about content. A client that trusts the relay's id would accept.
        let forged = json!({
            "id": hex::encode(honest.id),
            "pubkey": hex::encode(honest.pubkey),
            "created_at": honest.created_at,
            "kind": honest.kind,
            "tags": honest.tags,
            "content": "tampered-payload",
            "sig": hex::encode(honest.sig),
        });

        let err = verify_event_json(&forged).expect_err("tampered content must be rejected");
        match err {
            RelayError::EventVerification(EventError::IdMismatch { claimed, computed }) => {
                assert_eq!(claimed, honest.id, "claimed id must be the original");
                let expect = super::super::event::compute_event_id(
                    &honest.pubkey,
                    honest.created_at,
                    honest.kind,
                    &honest.tags,
                    "tampered-payload",
                );
                assert_eq!(computed, expect);
                assert_ne!(claimed, computed);
            }
            other => panic!("expected EventVerification(IdMismatch), got {other:?}"),
        }
    }

    #[test]
    fn rejects_event_with_bad_signature_after_id_matches() {
        let honest = signed_note("sig-check", vec![]);
        let mut bad_sig = honest.sig;
        bad_sig[0] ^= 0xff;
        let forged = json!({
            "id": hex::encode(honest.id),
            "pubkey": hex::encode(honest.pubkey),
            "created_at": honest.created_at,
            "kind": honest.kind,
            "tags": honest.tags,
            "content": honest.content,
            "sig": hex::encode(bad_sig),
        });
        let err = verify_event_json(&forged).expect_err("bad sig must fail");
        assert_eq!(err, RelayError::EventVerification(EventError::BadSignature));
    }

    // -----------------------------------------------------------------------
    // Frame parser: subscription id, NOTICE, CLOSED, size, OK false
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ok_false_is_rejected_not_accepted() {
        let id = [0xab; 32];
        let text = json!(["OK", hex::encode(id), false, "blocked: pow"]).to_string();
        let msg = parse_server_frame(&text).expect("parse");
        match msg {
            RelayServerMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                assert_eq!(event_id, id);
                assert!(!accepted, "false is rejection, not a soft warning");
                assert_eq!(message, "blocked: pow");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn parse_notice_is_surfaceable_not_dropped_by_parser() {
        let text = json!(["NOTICE", "rate-limited"]).to_string();
        let msg = parse_server_frame(&text).expect("parse");
        assert_eq!(
            msg,
            RelayServerMessage::Notice {
                message: "rate-limited".into()
            }
        );
    }

    #[test]
    fn parse_closed_carries_reason() {
        let text = json!(["CLOSED", "sub-1", "auth-required"]).to_string();
        let msg = parse_server_frame(&text).expect("parse");
        assert_eq!(
            msg,
            RelayServerMessage::Closed {
                subscription_id: "sub-1".into(),
                message: "auth-required".into()
            }
        );
    }

    #[test]
    fn frame_exceeding_max_bytes_is_hard_error() {
        // Just over the limit: a NOTICE with a huge message payload.
        let huge = "x".repeat(MAX_FRAME_BYTES);
        let text = format!(r#"["NOTICE","{huge}"]"#);
        assert!(text.len() > MAX_FRAME_BYTES);
        let err = parse_server_frame(&text).expect_err("oversized frame");
        match err {
            RelayError::FrameTooLarge { size, max } => {
                assert_eq!(max, MAX_FRAME_BYTES);
                assert_eq!(size, text.len());
                assert!(size > max);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    /// Wire shape only: multi-letter names serialise as `#zkdt`. A conforming
    /// relay does not index them (see integration_zkdt_not_relay_filterable…).
    #[test]
    fn filter_serialises_zkdt_scan_tag() {
        let f = Filter {
            kinds: Some(vec![1059]),
            tags: vec![("zkdt".into(), vec!["det-tag-hex".into()])],
            limit: Some(50),
            ..Filter::default()
        };
        let j = f.to_json();
        let obj = j.as_object().expect("object");
        assert_eq!(obj.get("kinds").unwrap(), &json!([1059]));
        assert_eq!(
            obj.get("#zkdt").unwrap(),
            &json!(["det-tag-hex"]),
            "client must serialise multi-letter tag filters as #name on the wire"
        );
        assert_eq!(obj.get("limit").unwrap(), &json!(50));
    }

    #[test]
    fn pool_rejects_empty_relay_list() {
        let err = RelayPool::new(vec![]).expect_err("empty");
        assert_eq!(err, RelayError::EmptyRelayList);
    }

    #[test]
    fn pool_rejects_non_ws_url() {
        let err = RelayPool::new(vec!["https://example.com".into()]).expect_err("scheme");
        match err {
            RelayError::InvalidRelayUrl { url } => assert_eq!(url, "https://example.com"),
            other => panic!("expected InvalidRelayUrl, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_to_closed_port_is_named_failure_not_fallback() {
        // Nothing listens on this port in a normal test host; connect fails
        // fast with ConnectFailed (or ConnectTimeout). Never invents another URL.
        let url = "ws://127.0.0.1:1/";
        let err = RelayClient::connect(url).await.expect_err("must fail");
        match err {
            RelayError::ConnectFailed { url: u, message: _ } => assert_eq!(u, url),
            RelayError::ConnectTimeout { url: u } => assert_eq!(u, url),
            other => panic!("expected connect failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pool_publish_unreachable_reports_each_relay() {
        let pool = RelayPool::new(vec!["ws://127.0.0.1:1/".into(), "ws://127.0.0.1:2/".into()])
            .expect("pool");
        let event = signed_note("pool-unreach", vec![]);
        let results = pool.publish_all(&event).await;
        assert_eq!(results.len(), 2, "one outcome per relay, no collapse");
        for (i, r) in results.iter().enumerate() {
            match r {
                RelayPublishResult::Unreachable { relay_url, error } => {
                    assert!(
                        relay_url.starts_with("ws://127.0.0.1:"),
                        "url preserved: {relay_url}"
                    );
                    match error {
                        RelayError::ConnectFailed { .. } | RelayError::ConnectTimeout { .. } => {}
                        other => panic!("relay {i}: expected connect error, got {other:?}"),
                    }
                }
                other => panic!("relay {i}: expected Unreachable, got {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Integration: real relay via testcontainers (same gate as Postgres)
    // -----------------------------------------------------------------------
    //
    // Pattern matches `node/src/test_db.rs`: spin a container with
    // testcontainers' AsyncRunner; no #[ignore], no extra feature flag,
    // no env opt-in. Docker must be available (as for every DB test).
    // Image is pinned by tag like bitcoind in compose.yaml.
    //
    // ## Readiness (connect loop, not log scrape alone)
    //
    // Log wait (`control message listener started`) is a useful first
    // filter on cold create but is not protocol-correct accept: under
    // parallel load the mapped port can accept TCP while the WebSocket
    // handshake is still unfinished ("Handshake not finished"). Real
    // readiness is a bounded connect probe in
    // [`wait_relay_ready`] — same shape as
    // `test_db::connect_shared_admin_until_ready` (deadline, per-attempt
    // budget, exponential backoff, transient vs permanent, panic with
    // attempt count + last error). All integration tests go through
    // [`start_relay_container`], so the probe covers every consumer.

    /// Pinned Nostr relay image (compose + tests). Tag-fixed; no `latest`.
    const RELAY_IMAGE: &str = "scsibug/nostr-rs-relay";
    const RELAY_TAG: &str = "0.8.13";
    const RELAY_PORT: u16 = 8080;

    /// How long [`wait_relay_ready`] may spend probing WebSocket accept
    /// after the container handle is up before failing loud.
    ///
    /// Single readiness budget for the probe — per-attempt connect
    /// timeouts are slices of this budget (mirrors
    /// `test_db::CONTAINER_READY_SECS`).
    const RELAY_READY_SECS: u64 = 90;

    /// Cap on a single readiness connect attempt. Production
    /// [`CONNECT_TIMEOUT`] is 15 s and would burn the whole deadline on
    /// one hung peer; this only bounds a hung handshake so retries stay
    /// live (mirrors `test_db::ADMIN_CONNECT_ATTEMPT_SECS`).
    const RELAY_CONNECT_ATTEMPT_SECS: u64 = 2;

    /// Initial backoff between transient connect failures; doubles each
    /// retry up to [`RELAY_CONNECT_BACKOFF_MAX`].
    const RELAY_CONNECT_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
    const RELAY_CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(2);

    /// Whether a failed readiness connect should be retried until the
    /// deadline, or fail loud immediately.
    ///
    /// Transient: cold-start window where the port is bound but the
    /// WebSocket accept path is not ready yet (`Handshake not finished`),
    /// connection refused/reset/aborted while the process binds, broken
    /// pipe / unexpected EOF, per-attempt timeout, and OS refuse/reset
    /// codes that tungstenite stringifies into `ConnectFailed.message`.
    ///
    /// Permanent: invalid URL, empty list, and any other `RelayError`
    /// variant that is not a connect-phase race. Those must not be
    /// swallowed by the loop (fail-closed, same posture as
    /// `test_db::is_transient_pg_connect_error`).
    fn is_transient_relay_connect_error(err: &RelayError) -> bool {
        match err {
            // Per-attempt budget exhausted — a slice of the readiness
            // deadline, not a permanent peer failure.
            RelayError::ConnectTimeout { .. } => true,
            RelayError::ConnectFailed { message, .. } => {
                let m = message.to_ascii_lowercase();
                // Observed flake under --test-threads=8: mapped port
                // accepts TCP, handshake returns
                // "WebSocket protocol error: Handshake not finished".
                m.contains("handshake")
                    || m.contains("connection refused")
                    || m.contains("connection reset")
                    || m.contains("connection aborted")
                    || m.contains("broken pipe")
                    || m.contains("not connected")
                    || m.contains("unexpected eof")
                    || m.contains("timed out")
                    || m.contains("timeout")
                    || m.contains("would block")
                    || m.contains("temporarily unavailable")
                    // Stringified OS codes when ErrorKind is not preserved.
                    || m.contains("os error 61") // ECONNREFUSED (macOS)
                    || m.contains("os error 111") // ECONNREFUSED (Linux)
                    || m.contains("os error 104") // ECONNRESET (Linux)
                    || m.contains("os error 54") // ECONNRESET (macOS)
            }
            // Invalid URL, protocol misuse, verification, send, … — fail loud.
            _ => false,
        }
    }

    /// Retry WebSocket connect until `deadline` or a permanent error.
    ///
    /// Panics with attempt count and last transient error when the
    /// deadline expires (same message shape as
    /// `test_db::connect_shared_admin_until_ready`). Never falls back to
    /// "skip the relay" or soft-pass the integration body.
    async fn wait_relay_ready(url: &str, deadline: std::time::Instant) {
        let mut attempts: u32 = 0;
        let mut last_err: Option<RelayError> = None;
        let mut backoff = RELAY_CONNECT_BACKOFF_INITIAL;

        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                let last = match &last_err {
                    Some(e) => e.to_string(),
                    None => "no connection attempt completed before deadline".to_string(),
                };
                panic!(
                    "nostr relay at {url} did not accept WebSocket connections \
                     within {RELAY_READY_SECS}s after {attempts} attempt(s); \
                     last error: {last}\n\
                     Fix: ensure Docker is running; \
                     `docker pull {RELAY_IMAGE}:{RELAY_TAG}`; re-run."
                );
            }

            let remaining = deadline.saturating_duration_since(now);
            let attempt_budget = remaining.min(Duration::from_secs(RELAY_CONNECT_ATTEMPT_SECS));
            // A zero budget means the deadline check above should have fired;
            // keep the loop fail-closed rather than spinning.
            if attempt_budget.is_zero() {
                let last = match &last_err {
                    Some(e) => e.to_string(),
                    None => "no connection attempt completed before deadline".to_string(),
                };
                panic!(
                    "nostr relay at {url} did not accept WebSocket connections \
                     within {RELAY_READY_SECS}s after {attempts} attempt(s); \
                     last error: {last}\n\
                     Fix: ensure Docker is running; \
                     `docker pull {RELAY_IMAGE}:{RELAY_TAG}`; re-run."
                );
            }

            attempts = attempts.saturating_add(1);
            // Outer timeout slices the readiness budget; production
            // CONNECT_TIMEOUT (15 s) must not monopolise one attempt.
            match tokio::time::timeout(attempt_budget, RelayClient::connect(url)).await {
                Ok(Ok(client)) => {
                    // Probe only — drop so the real test body connects clean.
                    let _ = client.close().await;
                    return;
                }
                Ok(Err(e)) if is_transient_relay_connect_error(&e) => {
                    last_err = Some(e);
                    let sleep_for =
                        backoff.min(deadline.saturating_duration_since(std::time::Instant::now()));
                    if !sleep_for.is_zero() {
                        tokio::time::sleep(sleep_for).await;
                    }
                    backoff = (backoff.saturating_mul(2)).min(RELAY_CONNECT_BACKOFF_MAX);
                }
                Ok(Err(e)) => {
                    panic!(
                        "nostr relay at {url} did not accept WebSocket connections: {e}\n\
                         Fix: ensure Docker is running; \
                         `docker pull {RELAY_IMAGE}:{RELAY_TAG}`; re-run."
                    );
                }
                // Attempt budget elapsed without a Result — treat as
                // transient (hung peer during boot), same as ConnectTimeout.
                Err(_) => {
                    last_err = Some(RelayError::ConnectTimeout {
                        url: url.to_string(),
                    });
                    let sleep_for =
                        backoff.min(deadline.saturating_duration_since(std::time::Instant::now()));
                    if !sleep_for.is_zero() {
                        tokio::time::sleep(sleep_for).await;
                    }
                    backoff = (backoff.saturating_mul(2)).min(RELAY_CONNECT_BACKOFF_MAX);
                }
            }
        }
    }

    async fn start_relay_container() -> (
        testcontainers::ContainerAsync<testcontainers::GenericImage>,
        String,
    ) {
        use testcontainers::core::{IntoContainerPort, WaitFor};
        use testcontainers::runners::AsyncRunner;
        use testcontainers::GenericImage;

        // Single readiness budget for log-wait start + connect probe.
        // Nested timeouts would invent a second deadline; everything
        // below shares this Instant (mirrors test_db::init_shared_pg).
        let deadline = std::time::Instant::now() + Duration::from_secs(RELAY_READY_SECS);

        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            panic!(
                "nostr relay init exceeded {RELAY_READY_SECS}s \
                 before container start began.\n\
                 Fix: ensure Docker is running; \
                 `docker pull {RELAY_IMAGE}:{RELAY_TAG}`."
            );
        }
        let container = match tokio::time::timeout(
            remaining,
            GenericImage::new(RELAY_IMAGE, RELAY_TAG)
                .with_exposed_port(RELAY_PORT.tcp())
                // First filter only: last startup line of the image. Still
                // leaves a protocol-flaky window under parallel load; real
                // readiness is the connect loop after the URL is known.
                .with_wait_for(WaitFor::message_on_either_std(
                    "control message listener started",
                ))
                .start(),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => panic!(
                "start {RELAY_IMAGE}:{RELAY_TAG} failed: {e}\n\
                 Fix: ensure Docker is running; \
                 `docker pull {RELAY_IMAGE}:{RELAY_TAG}`."
            ),
            Err(_) => panic!(
                "nostr relay init exceeded {RELAY_READY_SECS}s \
                 waiting for container start/log wait.\n\
                 Fix: ensure Docker is running; \
                 `docker pull {RELAY_IMAGE}:{RELAY_TAG}`."
            ),
        };

        let host = container.get_host().await.expect("relay get_host");
        let port = container
            .get_host_port_ipv4(RELAY_PORT)
            .await
            .expect("relay mapped port");
        let url = format!("ws://{host}:{port}/");

        // Protocol-correct accept (covers log-wait race under load).
        wait_relay_ready(&url, deadline).await;

        (container, url)
    }

    /// Without the classifier treating handshake / refuse / reset as
    /// transient, the readiness loop would still fail closed on the
    /// first hard connect error (the cold-container flake under
    /// `--test-threads=8`). Permanent errors must stay non-retryable
    /// so the loop never masks bad URLs or non-connect failures.
    #[test]
    fn transient_relay_connect_errors_are_retried_permanent_are_not() {
        // --- transient: loop continues ---
        assert!(
            is_transient_relay_connect_error(&RelayError::ConnectFailed {
                url: "ws://127.0.0.1:9/".into(),
                message: "WebSocket protocol error: Handshake not finished".into(),
            }),
            "half-started relay handshake must be retryable"
        );
        assert!(
            is_transient_relay_connect_error(&RelayError::ConnectFailed {
                url: "ws://127.0.0.1:9/".into(),
                message: "IO error: Connection refused (os error 61)".into(),
            }),
            "connection refused during relay bind must be retryable"
        );
        assert!(
            is_transient_relay_connect_error(&RelayError::ConnectFailed {
                url: "ws://127.0.0.1:9/".into(),
                message: "IO error: Connection reset by peer (os error 54)".into(),
            }),
            "connection reset during relay bind must be retryable"
        );
        assert!(
            is_transient_relay_connect_error(&RelayError::ConnectTimeout {
                url: "ws://127.0.0.1:9/".into(),
            }),
            "per-attempt connect timeout is a slice of the deadline, not a permanent failure"
        );

        // --- permanent: loop must fail loud immediately ---
        assert!(
            !is_transient_relay_connect_error(&RelayError::InvalidRelayUrl {
                url: "https://example.com".into(),
            }),
            "invalid URL must not be swallowed by the readiness loop"
        );
        assert!(
            !is_transient_relay_connect_error(&RelayError::EmptyRelayList),
            "empty relay list is a programming error, not a cold-start race"
        );
        assert!(
            !is_transient_relay_connect_error(&RelayError::ConnectionClosed),
            "non-connect error variants must fail loud, not spin"
        );
        assert!(
            !is_transient_relay_connect_error(&RelayError::ConnectFailed {
                url: "ws://127.0.0.1:9/".into(),
                message: "URL error: Invalid URL scheme".into(),
            }),
            "non-transient ConnectFailed messages must fail loud, not spin"
        );
    }

    #[tokio::test]
    async fn integration_publish_then_req_by_id_is_bit_equal() {
        let (_container, url) = start_relay_container().await;
        let event = signed_note(
            "roundtrip-bit-equal",
            vec![vec!["zkdt".into(), "dt-roundtrip".into()]],
        );

        let mut client = RelayClient::connect(&url).await.expect("connect");
        let ok_msg = client.publish(&event).await.expect("publish accepted");
        // Message text is relay-defined; acceptance is the typed Ok path.
        let _ = ok_msg;

        let got = client
            .query(&[Filter {
                ids: Some(vec![event.id]),
                limit: Some(5),
                ..Filter::default()
            }])
            .await
            .expect("query by id");
        assert_eq!(got.len(), 1, "exactly one event for this id");
        assert_eq!(got[0], event, "bit-equal to the published event");
        client.close().await.expect("close");
    }

    /// Client capability: generic NIP-01 single-letter tag filters (`#t`).
    ///
    /// NIP-01 indexes only single-letter tag names. This test uses `#t` so a
    /// conforming relay exercises the client's filter build + reply path —
    /// not a multi-letter name that no relay will answer.
    #[tokio::test]
    async fn integration_filter_single_letter_tag_returns_only_matching() {
        let (_container, url) = start_relay_container().await;
        let mut client = RelayClient::connect(&url).await.expect("connect");

        let match_val = "topic-match-aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other_val = "topic-other-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let e_match = signed_note("with-match-t", vec![vec!["t".into(), match_val.into()]]);
        // Distinct second key so the event id differs.
        let sk2 = fixture_sk(b"zkCoins/v1/test-vector/nostr/relay-sk-2");
        let e_other = Event::sign(
            &sk2,
            1_700_000_101,
            1,
            vec![vec!["t".into(), other_val.into()]],
            "with-other-t".into(),
        )
        .expect("sign other");

        client.publish(&e_match).await.expect("publish match");
        client.publish(&e_other).await.expect("publish other");

        let got = client
            .query(&[Filter {
                tags: vec![("t".into(), vec![match_val.into()])],
                kinds: Some(vec![1]),
                limit: Some(20),
                ..Filter::default()
            }])
            .await
            .expect("query #t");

        assert!(
            got.iter().any(|e| e.id == e_match.id),
            "matching #t event must appear"
        );
        assert!(
            got.iter().all(|e| e.id != e_other.id),
            "non-matching #t event must not appear"
        );
        for e in &got {
            let has = e
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "t" && t[1] == match_val);
            assert!(has, "every returned event must carry the filter tag");
        }
        client.close().await.expect("close");
    }

    /// §4.4 property: `zkdt` is **not** relay-filterable — and that is required.
    ///
    /// A conforming NIP-01 relay indexes only single-letter tag names. `zkdt`
    /// is four letters; `#zkdt` must not surface the event. The same event is
    /// still found via `kinds` (the candidate pull the recipient actually uses).
    /// Locks against a future “optimise with a `#zkdt` tag filter” that would
    /// break the privacy argument of §4.4.
    #[tokio::test]
    async fn integration_zkdt_not_relay_filterable_is_intentional_section_4_4() {
        let (_container, url) = start_relay_container().await;
        let mut client = RelayClient::connect(&url).await.expect("connect");

        let detect = "zkdt-detect-cccccccccccccccccccccccccccc";
        let event = signed_note(
            "zkdt-present-not-filterable",
            vec![vec!["zkdt".into(), detect.into()]],
        );
        client.publish(&event).await.expect("publish");

        // Via kinds: the event is on the relay (full candidate set for local scan).
        let by_kinds = client
            .query(&[Filter {
                kinds: Some(vec![1]),
                limit: Some(50),
                ..Filter::default()
            }])
            .await
            .expect("query by kinds");
        assert!(
            by_kinds.iter().any(|e| e.id == event.id),
            "zkdt-tagged event must be retrievable via kinds (local-scan candidate set)"
        );

        // Via #zkdt: conforming relay returns nothing for this multi-letter name.
        let by_zkdt = client
            .query(&[Filter {
                tags: vec![("zkdt".into(), vec![detect.into()])],
                kinds: Some(vec![1]),
                limit: Some(20),
                ..Filter::default()
            }])
            .await
            .expect("query #zkdt must complete; empty set is the §4.4 success case");

        assert!(
            by_zkdt.iter().all(|e| e.id != event.id),
            "§4.4: #zkdt must not surface the event on a NIP-01-conforming relay; \
             absence of server-side filterability is the privacy property"
        );
        client.close().await.expect("close");
    }

    #[tokio::test]
    async fn integration_eose_then_close_stops_subscription() {
        let (_container, url) = start_relay_container().await;
        let mut client = RelayClient::connect(&url).await.expect("connect");
        let event = signed_note("eose-close", vec![]);
        client.publish(&event).await.expect("publish");

        // query() itself waits for EOSE then sends CLOSE.
        let got = client
            .query(&[Filter {
                ids: Some(vec![event.id]),
                limit: Some(1),
                ..Filter::default()
            }])
            .await
            .expect("query completes at EOSE");
        assert_eq!(got.len(), 1);
        assert_eq!(
            client.open_subscription_count(),
            0,
            "CLOSE must drop the subscription from the open set"
        );

        // After CLOSE, a synthetic EVENT for a never-opened id is rejected
        // by the parser/client path (unknown subscription).
        let rogue = json!(["EVENT", "never-opened-sub", event_to_json_value(&event)]).to_string();
        let parsed = parse_server_frame(&rogue).expect("wire parse + verify ok");
        match parsed {
            RelayServerMessage::Event {
                subscription_id, ..
            } => {
                assert_eq!(subscription_id, "never-opened-sub");
                assert!(
                    !client.has_subscription(&subscription_id),
                    "client must not have this sub open"
                );
            }
            other => panic!("expected Event, got {other:?}"),
        }
        client.close().await.expect("close");
    }

    /// Bad signature on the receive path: relays that verify on store will
    /// not re-serve a forged event. We still prove the **client** rejects
    /// it by feeding a forged EVENT frame through `parse_server_frame` /
    /// `verify_event_json` — the same path used for every inbound EVENT
    /// from a live socket (integration of the trust boundary, not a mock
    /// relay). The live relay is still started so this test only runs in
    /// the same Docker-gated environment as the other container tests.
    #[tokio::test]
    async fn integration_client_rejects_bad_signature_even_if_framed_as_event() {
        let (_container, url) = start_relay_container().await;
        // Prove the relay is up (real peer), then inject a forged frame on
        // the client decode path as if the relay had delivered it.
        let client = RelayClient::connect(&url)
            .await
            .expect("connect live relay");
        client.close().await.expect("close");

        let honest = signed_note("forged-delivery", vec![]);
        let mut bad_sig = honest.sig;
        bad_sig[63] ^= 0x01;
        let forged_frame = json!([
            "EVENT",
            "sub-forged",
            {
                "id": hex::encode(honest.id),
                "pubkey": hex::encode(honest.pubkey),
                "created_at": honest.created_at,
                "kind": honest.kind,
                "tags": honest.tags,
                "content": honest.content,
                "sig": hex::encode(bad_sig),
            }
        ])
        .to_string();

        let err = parse_server_frame(&forged_frame).expect_err("client must reject bad sig");
        assert_eq!(
            err,
            RelayError::EventVerification(EventError::BadSignature),
            "rejection cause must be BadSignature, not a generic parse error"
        );
    }

    #[tokio::test]
    async fn integration_pool_publish_and_query_per_relay_results() {
        let (_container, url) = start_relay_container().await;
        let pool = RelayPool::new(vec![url.clone()]).expect("pool");
        let event = signed_note(
            "pool-one-relay",
            vec![vec!["zkepk".into(), "epk-hex-placeholder".into()]],
        );
        let published = pool.publish_all(&event).await;
        assert_eq!(published.len(), 1);
        match &published[0] {
            RelayPublishResult::Accepted { relay_url, .. } => assert_eq!(relay_url, &url),
            other => panic!("expected Accepted, got {other:?}"),
        }

        let agg = pool
            .query_all(&[Filter {
                ids: Some(vec![event.id]),
                limit: Some(5),
                ..Filter::default()
            }])
            .await;
        assert_eq!(agg.per_relay.len(), 1);
        match &agg.per_relay[0] {
            RelayQueryOutcome::Ok {
                relay_url,
                event_count,
            } => {
                assert_eq!(relay_url, &url);
                assert_eq!(*event_count, 1);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
        assert_eq!(agg.events.len(), 1);
        assert_eq!(agg.events[0], event);
    }
}
