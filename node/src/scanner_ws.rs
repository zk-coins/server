//! Event-driven chain ingestion via the Esplora WebSocket stream.
//!
//! Subscribes to the mempool.space-compatible WebSocket endpoint
//! (`ESPLORA_WS_URL` — required env var, no default; see
//! `lib::build_network_config_from_env`) and publishes each new tip
//! `BlockHash` into an `mpsc::Sender` that the existing
//! `scanner_runtime` drains. Replaces the 30-s tip polling loop that
//! previously gated `/api/mint` and `/api/send` visibility by up to a
//! full block-time + poll-interval (issue #84).
//!
//! TODO(structured-logging): this module still uses `println!` /
//! `eprintln!` for runtime logs, consistent with the rest of the
//! `node` crate's current conventions.
//! Partial structured-logging migration began in router.rs + account_node.rs.
//! This file is still on the old `println!`/`eprintln!` path; switching the
//! reconnect/liveness lines below to `tracing::info!`/`warn!` is the next
//! incremental step.
//!
//! ### Design points
//!
//! - Reconnect-with-backoff is encapsulated here. The outer
//!   `scanner_runtime` never sees a disconnect — it only sees
//!   `BlockHash`es arriving on the channel.
//! - Backpressure-aware `Sender::send().await` (no `try_send`): if
//!   the downstream scanner is busy processing a block, the WS
//!   reader pauses rather than dropping tip notifications.
//! - 90 s liveness watchdog (`liveness_timeout`) wraps every
//!   `ws.next()` in `tokio::time::timeout`. A silent half-open WS
//!   triggers a forced reconnect, which is the only behaviour worth
//!   the `tokio::time::` reference in event-driven code (documented
//!   in CONTRIBUTING.md, enforced by the CI lint added in the same
//!   PR).
//! - 30 s client-side Ping keepalive (`ping_interval`). A tokio
//!   `interval` ticker running alongside the reader sends a
//!   `WsMessage::Ping` to the peer every `ping_interval`. RFC 6455
//!   §5.5 mandates a Pong response, which arrives on the same
//!   reader and resets the liveness watchdog. Without this, a quiet
//!   Mainnet-tier upstream (10-min mean block time) had nothing
//!   flowing in the watchdog window and reconnected every ~2 min;
//!   the keepalive turns the watchdog into the half-open detector
//!   it was always meant to be (no pong + no event = dead).
//! - On reconnect, fetch the current tip via the existing
//!   `EsploraClient::get_tip_hash` and push that hash into the
//!   channel too. This plugs the gap that opened while we were
//!   disconnected — `scanner_runtime` already deduplicates against
//!   `processed_blocks`, so re-publishing an already-processed hash
//!   is a no-op.
//! - Every `connect_async` is wrapped in a 15 s `CONNECT_TIMEOUT`
//!   (issue #84 round-4 MAJOR 1). A half-broken middlebox can stall
//!   the TCP handshake for the kernel SYN-retransmit budget
//!   (60-180 s on Linux/Darwin); bounding it explicitly lets the
//!   reconnect-backoff loop drive recovery instead of stalling on a
//!   single attempt.
//!
//! ### Wire format
//!
//! On subscribe (`{"action":"want","data":["blocks"]}`) the server
//! immediately seeds the new client with the last few blocks in a
//! `{"blocks": [<b1>, <b2>, ...]}` message. Each subsequent tip is
//! pushed as `{"block": <b>}`. Both shapes are handled; unknown
//! frames are logged and ignored.

use std::time::Duration;

use bitcoin::BlockHash;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::esplora_bound::EsploraReadClient;
use crate::publisher::EsploraConfig;
pub use crate::scanner_ws_parse::parse_ws_frame;

/// Default for the liveness watchdog. A real new block arrives at
/// least every ~10 min on any live signet/mainnet, so 90 s with no
/// frame at all (including `pong` / keep-alives) is a strong "the
/// socket is half-open" signal.
pub const DEFAULT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(90);

/// Default cadence of the client-side Ping keepalive. The scanner
/// sends `WsMessage::Ping` to the peer every `DEFAULT_PING_INTERVAL`;
/// the peer's mandatory Pong reply (RFC 6455 §5.5) arrives on the
/// same reader and resets the liveness watchdog. Must stay strictly
/// less than `DEFAULT_LIVENESS_TIMEOUT / 2` so that at least one
/// ping + pong round-trip fits inside every watchdog window even on
/// a marginal link (a single dropped pong should not be enough to
/// trip the watchdog).
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Capacity of the bounded `mpsc` channel feeding the dedicated
/// writer task in `connect_and_drain`. Fixed at `1` on purpose:
///
/// - Strict back-pressure. A second ping cannot queue until the
///   first one has fully flushed onto the wire, so the producer
///   side (the `select!` loop) observes a stalled writer
///   immediately rather than absorbing it into a growing queue.
/// - Latest-ping-wins is acceptable because we never have anything
///   useful to "catch up" on — a stale ping in the queue would buy
///   us nothing the next live ping wouldn't.
/// - No unbounded queue. If the peer accepts TCP but never reads
///   (a stalled writer), the producer's `out_tx.send(...).await`
///   is the natural choke-point; that send is a concurrent `select!`
///   arm alongside the liveness watchdog, so a wedged writer cannot
///   mute the deadline and becomes a reconnect rather than a
///   deadlocked task.
const WRITER_QUEUE_CAPACITY: usize = 1;

/// Compile-time assertion that the ping cadence leaves enough margin
/// inside the watchdog window. Encoded as a `const` evaluation so
/// any future tweak to either constant trips the build instead of
/// quietly drifting into a configuration where the watchdog could
/// fire between pings.
const _PING_INTERVAL_FITS_LIVENESS: () = assert!(
    DEFAULT_PING_INTERVAL.as_millis() < DEFAULT_LIVENESS_TIMEOUT.as_millis() / 2,
    "DEFAULT_PING_INTERVAL must be < DEFAULT_LIVENESS_TIMEOUT / 2"
);

/// Default initial reconnect delay. Doubled on each consecutive
/// failure up to `DEFAULT_RECONNECT_MAX`.
pub const DEFAULT_RECONNECT_MIN: Duration = Duration::from_millis(500);

/// Default cap on the exponential reconnect backoff. 30 s matches
/// the previous polling cadence — if the upstream is genuinely
/// down for that long, we are no worse off than before.
pub const DEFAULT_RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Wall-clock budget for completing a single WS connect handshake.
/// A half-broken middlebox can stall the TCP handshake for the
/// kernel SYN-retransmit budget (60-180 s on Linux/Darwin); bound it
/// explicitly so the reconnect-backoff loop drives recovery instead.
/// Issue #84 review (round 4) MAJOR 1.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Errors surfaced by the block-tip scanner's connect/subscribe/drain
/// cycle. The publisher's commit→reveal broadcast pair no longer uses
/// any of these — it talks REST-only and runs both broadcasts back to
/// back without an inter-tx wait (see `publisher::broadcast_inscription_txs`).
#[derive(Debug)]
pub enum WsError {
    /// `tokio_tungstenite::connect_async` returned an error.
    Connect(String),
    /// The subscribe frame failed to send.
    Subscribe(String),
    /// The peer closed the socket or surfaced an error mid-stream
    /// before the expected event arrived.
    Stream(String),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Connect(e) => write!(f, "WS connect failed: {}", e),
            WsError::Subscribe(e) => write!(f, "WS subscribe failed: {}", e),
            WsError::Stream(e) => write!(f, "WS stream error: {}", e),
        }
    }
}

impl std::error::Error for WsError {}

/// Wrap `connect_async` in a hard wall-clock deadline so a stalled
/// TCP/TLS handshake cannot wedge the surrounding reconnect loop for
/// the kernel SYN-retransmit budget. On timeout the returned error
/// maps to the same `WsError::Connect` shape an actual connect
/// failure would yield, so the caller's reconnect logic is uniform.
async fn connect_with_timeout(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    WsError,
> {
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(url)).await {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(e)) => Err(WsError::Connect(e.to_string())),
        Err(_) => Err(WsError::Connect(format!(
            "connect_async timed out after {:?}",
            CONNECT_TIMEOUT
        ))),
    }
}

/// Runtime knobs for the scanner WS task. The URL pair is sourced
/// from the central `NETWORK_CONFIG` via `from_network_config`; tests
/// construct it directly with shorter timeouts.
#[derive(Clone, Debug)]
pub struct ScannerWsConfig {
    /// Esplora WebSocket URL. Sourced from `ESPLORA_WS_URL` via
    /// `lib::build_network_config_from_env` — no default exists.
    pub url: String,
    /// HTTP Esplora URL used to fetch the current tip after each
    /// reconnect (plugs gaps that opened while disconnected). Sourced
    /// from `ESPLORA_URL` via `lib::build_network_config_from_env` —
    /// no default exists.
    pub http_url: String,
    /// Initial reconnect delay. Doubles up to `reconnect_max`.
    pub reconnect_min: Duration,
    /// Cap on the exponential reconnect backoff.
    pub reconnect_max: Duration,
    /// Force-reconnect deadline for `ws.next()`. A silent half-open
    /// socket would otherwise wedge the scanner indefinitely.
    pub liveness_timeout: Duration,
    /// Cadence of the client-side Ping keepalive. Each tick sends a
    /// `WsMessage::Ping` frame; the peer's Pong reply (RFC 6455
    /// §5.5) flows back through `ws.next()` and resets the liveness
    /// watchdog. Without keepalive a quiet Mainnet upstream produced
    /// nothing on the reader for minutes at a time and the watchdog
    /// reconnected every ~2 min unnecessarily.
    pub ping_interval: Duration,
}

impl ScannerWsConfig {
    /// Build the config from an already-resolved `EsploraConfig`. The
    /// single env-resolution path lives in
    /// `lib::build_network_config_from_env`, which panics on missing
    /// `ESPLORA_URL` / `ESPLORA_WS_URL` — by the time this runs both
    /// URLs are guaranteed non-empty.
    ///
    /// `network_config.ws_url` is `Option<String>` for legacy reasons
    /// (the publisher does not need it); production callers pass a
    /// config built by `build_network_config_from_env`, which always
    /// populates it. The `expect` here documents that invariant —
    /// hitting it means somebody constructed an `EsploraConfig`
    /// manually without setting `ws_url`, which is a programmer
    /// error, not a runtime configuration issue.
    pub fn from_network_config(network_config: &EsploraConfig) -> Self {
        let url = network_config
            .ws_url
            .clone()
            .expect("EsploraConfig.ws_url must be set — production callers go through build_network_config_from_env");
        Self {
            url,
            http_url: network_config.url.clone(),
            reconnect_min: DEFAULT_RECONNECT_MIN,
            reconnect_max: DEFAULT_RECONNECT_MAX,
            liveness_timeout: DEFAULT_LIVENESS_TIMEOUT,
            ping_interval: DEFAULT_PING_INTERVAL,
        }
    }
}

/// Run the WS scanner forever. Connects, subscribes, drains frames,
/// reconnects on any error. Never returns under normal operation —
/// the receiver side decides when to stop draining.
///
/// `tip_tx.send(...).await` is the documented backpressure point: if
/// `scanner_runtime` is busy processing a block, the reader stalls
/// rather than dropping tips.
pub async fn run_scanner_ws(config: ScannerWsConfig, tip_tx: mpsc::Sender<BlockHash>) -> ! {
    // Build the HTTP Esplora client ONCE outside the reconnect loop
    // so a tight reconnect storm does not rebuild it per attempt.
    // Construction is cheap, but rebuilding it on every iteration is
    // wasted work and obscures the fact that the same client is the
    // shared dependency of every anchor-on-reconnect call.
    //
    // Issue #84 review (round 4) MAJOR 4: collapsed the previous
    // duplicated fallback loop into a single state machine by making
    // `http_client` an `Option`. If construction failed the inner
    // anchor call logs a warning and skips the re-anchor; the next
    // session's first WS-pushed block re-establishes the tip.
    let http_client: Option<EsploraReadClient> = match EsploraReadClient::connect(&config.http_url)
    {
        Ok(c) => Some(c),
        Err(e) => {
            // If the HTTP client cannot even be constructed (e.g.
            // an unparseable URL) we have no useful fallback.
            // Stay loud: every reconnect from here on logs that
            // the re-anchor is skipped.
            eprintln!(
                "scanner_ws: failed to build Esplora HTTP client for {}: {}. \
                 Re-anchor on reconnect will be skipped.",
                config.http_url, e
            );
            None
        }
    };

    let mut backoff = config.reconnect_min;
    loop {
        match connect_and_drain(&config, &tip_tx).await {
            Ok(()) => {
                // `connect_and_drain` only returns Ok when the peer
                // closed the socket cleanly — still a reconnect
                // condition, but reset the backoff so we don't punish
                // a graceful close.
                backoff = config.reconnect_min;
                eprintln!("scanner_ws: peer closed cleanly, reconnecting");
            }
            Err(e) => {
                eprintln!(
                    "scanner_ws: session ended ({}). Reconnecting in {:?}",
                    e, backoff
                );
            }
        }

        // After every reconnect — clean or not — re-anchor on the
        // current tip via HTTP. This catches blocks that landed
        // while we were disconnected. `scanner_runtime` deduplicates
        // against `processed_blocks`, so a no-op re-publish is safe.
        if let Some(client) = &http_client {
            if let Err(e) = anchor_on_current_tip(client, &tip_tx).await {
                eprintln!(
                    "scanner_ws: failed to fetch current tip after reconnect: {}",
                    e
                );
            }
        } else {
            eprintln!("scanner_ws: no HTTP client, skipping anchor on reconnect");
        }

        tokio::time::sleep(backoff).await; // scanner-polling-ok: reconnect-with-backoff between failed WS sessions, not a chain-tip poll
        backoff = (backoff * 2).min(config.reconnect_max);
    }
}

/// Sentinel payload sent in every outbound Ping frame. The peer is
/// required by RFC 6455 §5.5 to echo the payload back in its Pong;
/// the value itself is otherwise irrelevant to the scanner.
const PING_PAYLOAD: &[u8] = b"zkcoins-scanner-keepalive";

/// Single connect → subscribe → drain cycle. Returns Ok on a clean
/// close, Err on any failure. Caller schedules the reconnect.
///
/// Architecture: the WS stream is split into a reader (`SplitStream`)
/// and a writer (`SplitSink`). The writer half is moved into a
/// dedicated `tokio::spawn`ed writer task that drains a 1-slot
/// `tokio::sync::mpsc::Receiver<WsMessage>` and runs `feed` + `flush`
/// against the sink. The main loop's `tokio::select!` polls only the
/// reader, the liveness watchdog, and an mpsc `out_tx.send().await`
/// driven by the ping ticker.
///
/// Why the writer-task split (and not `sink.send(...).await` inline
/// in the select): `SinkExt::send` is NOT cancel-safe — if the read
/// arm wins a race against a half-completed send, the send-future is
/// dropped and the sink can be left in a torn state mid-frame. By
/// contrast `tokio::sync::mpsc::Sender::send().await` IS cancel-safe,
/// and the writer task awaits the actual wire-level send to
/// completion outside any `select!` boundary, so the sink is never
/// cancelled mid-poll. The `select!`-on-ticker invariant that the
/// liveness deadline is reset ONLY by inbound frames (never by our
/// own send activity) is preserved exactly as before.
async fn connect_and_drain(
    config: &ScannerWsConfig,
    tip_tx: &mpsc::Sender<BlockHash>,
) -> Result<(), WsError> {
    let ws = connect_with_timeout(&config.url).await?;
    println!("scanner_ws: connected to {}", config.url);

    let (mut sink, mut stream) = ws.split();

    let subscribe = serde_json::json!({ "action": "want", "data": ["blocks"] }).to_string();
    sink.send(WsMessage::Text(subscribe))
        .await
        .map_err(|e| WsError::Subscribe(e.to_string()))?;

    // Outbound writer task. Owns `sink` outright and drives every
    // outbound frame to completion via `feed` + `flush` — the
    // `feed`/`flush` split keeps the partial-write window the
    // narrowest the API allows. The writer's body is plain
    // `loop { rx.recv().await ... }`, with no `select!` around the
    // send, so the send-future is never cancelled mid-poll and the
    // sink can never be left in a torn state.
    //
    // The main loop talks to this task via `tokio::sync::mpsc::Sender`,
    // whose `send().await` IS cancel-safe (documented: dropping the
    // future before completion is sound — the message is never
    // delivered, but the channel and sender remain consistent). This
    // is the cancel-safety argument for the ping arm in the `select!`
    // below: instead of `sink.send(Ping).await` (NOT cancel-safe) we
    // do `out_tx.send(Ping).await`, and the writer task takes care of
    // the actual wire-level send outside any `select!` boundary.
    //
    // The channel is bounded at `WRITER_QUEUE_CAPACITY` (= 1) so a
    // stalled writer applies immediate back-pressure to the main loop
    // (the second ping tick would block) — far preferable to growing
    // an unbounded queue of pings against a peer that cannot drain
    // them. The constant lives at the top of the file alongside the
    // other tunables and carries the full rationale.
    let (out_tx, mut out_rx) = mpsc::channel::<WsMessage>(WRITER_QUEUE_CAPACITY);
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            // `feed` queues the frame into the sink's internal
            // buffer; `flush` drives it onto the wire. Splitting (vs.
            // `send`) bounds the partial-write window and makes the
            // two halves explicit. On error we surface it to the main
            // loop by dropping `out_tx` from the writer side (closing
            // the channel from the producer's perspective is achieved
            // by the writer task exiting); the main loop's next
            // `out_tx.send` will then fail and trigger reconnect.
            sink.feed(msg).await?;
            sink.flush().await?;
        }
        Ok::<(), tokio_tungstenite::tungstenite::Error>(())
    });
    // Always abort the writer when this function returns, regardless
    // of how we exit. Without this, a returning main-loop iteration
    // could leave the writer task parked in `out_rx.recv().await` and
    // leak the `sink` (and thus the underlying TCP socket) until the
    // tokio runtime tears down. `AbortOnDrop` makes that cleanup
    // deterministic and exception-safe.
    struct AbortOnDrop(tokio::task::JoinHandle<Result<(), tokio_tungstenite::tungstenite::Error>>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _writer_guard = AbortOnDrop(writer);

    // Client-side Ping keepalive. The ticker's first tick fires
    // immediately (default tokio behaviour); that's fine — sending an
    // initial ping right after subscribe gives us the fastest possible
    // confirmation that the peer is live. `Burst` is the default
    // missed-tick behaviour; if a tick is missed (e.g. busy reader)
    // we explicitly opt into `Delay` below so we never send a flurry
    // of pings to "catch up". The line below carries the required
    // `scanner-polling-ok:` marker for the CI lint enforcing
    // CONTRIBUTING.md § "No polling — events only".
    let mut ping_ticker = tokio::time::interval(config.ping_interval); // scanner-polling-ok: client-side WS Ping keepalive cadence (RFC 6455 §5.5), not a chain-tip poll
    ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Track the liveness deadline manually rather than wrapping each
    // `stream.next()` in `tokio::time::timeout`, because `select!`
    // drops the losing branch's future on every iteration. With a
    // wrapper-based watchdog the timer would silently reset every
    // time the ping arm fires, defeating the watchdog. The manual
    // deadline is reset ONLY when an inbound frame arrives — exactly
    // the invariant we want.
    let mut deadline = tokio::time::Instant::now() + config.liveness_timeout;

    // When true, the select below holds an `out_tx.send(Ping)` future
    // as a concurrent arm rather than awaiting it inside the tick arm.
    // That keeps the liveness watchdog polled while a send is blocked
    // on a full writer queue (wedged flush / peer not reading). A nested
    // `timeout(...).await` inside the tick arm used to suppress the
    // watchdog for up to a full `liveness_timeout` per blocked send —
    // under load that delayed reconnect past wall-clock test budgets
    // and, in production with 30 s pings / 90 s liveness, stretched the
    // half-open detection window toward ~2× liveness.
    let mut ping_send_pending = false;

    loop {
        tokio::select! {
            biased;

            // Liveness watchdog. Fires only if no inbound frame has
            // arrived for `liveness_timeout`. A live peer answers our
            // pings, so this should only fire on a genuinely dead
            // socket. Always concurrent with the ping-send arm below
            // so a blocked `out_tx.send` cannot mute it.
            _ = tokio::time::sleep_until(deadline) => { // scanner-polling-ok: liveness watchdog deadline, not a chain-tip poll
                return Err(WsError::Stream(format!(
                    "no frame in {:?} (liveness watchdog)",
                    config.liveness_timeout
                )));
            }

            // Outbound ping send. Armed only after a ticker tick sets
            // `ping_send_pending`. RFC 6455 §5.5 requires the peer to
            // reply with a Pong; that Pong arrives on `stream.next()`
            // and resets the deadline.
            //
            // Cancel-safety: `tokio::sync::mpsc::Sender::send().await`
            // is documented as cancel-safe, so if the read or watchdog
            // arm wins this race the half-completed send-future can be
            // dropped without corrupting the channel or the underlying
            // sink. The actual wire-level write happens inside the
            // dedicated writer task above, never inside this `select!`.
            // A send error here means the writer task has exited (e.g.
            // the peer closed mid-write) — surface as a stream error so
            // the reconnect loop kicks in.
            //
            // Backpressure / wedged writer: if the peer accepts TCP but
            // never reads, the writer wedges in `sink.flush()`, the
            // 1-slot `out_tx` fills, and this send stays pending. Because
            // it is a select arm (not a nested await), the watchdog arm
            // above still fires at `deadline` and reconnects — the same
            // upper bound the half-open detector always promised. No
            // separate send-timeout is required.
            result = out_tx.send(WsMessage::Ping(PING_PAYLOAD.to_vec())), if ping_send_pending => {
                ping_send_pending = false;
                if let Err(e) = result {
                    return Err(WsError::Stream(format!("ping send failed: {}", e)));
                }
            }

            // Ticker only arms a send; the send itself is the arm above
            // so it never holds the select exclusively. `if !pending`
            // prevents stacking a second ping while one is still waiting
            // on the 1-slot writer queue (latest-ping-wins is pointless
            // for keepalive; one outstanding ping is enough).
            _ = ping_ticker.tick(), if !ping_send_pending => {
                ping_send_pending = true;
            }

            // Inbound frame. Any frame — Text, Binary, Ping, Pong,
            // Close — counts as evidence the socket is alive and
            // resets the deadline. The frame variant then drives the
            // per-shape handling below.
            //
            // Cancel-safety: `StreamExt::next` is documented as
            // cancel-safe (futures-util 0.3), so dropping this arm's
            // future when another arm wins is sound — no frame is
            // lost.
            next = stream.next() => {
                let frame = match next {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(WsError::Stream(e.to_string())),
                    None => return Ok(()), // clean close
                };
                deadline = tokio::time::Instant::now() + config.liveness_timeout;

                match frame {
                    WsMessage::Text(text) => {
                        for hash in parse_ws_frame(&text) {
                            if tip_tx.send(hash).await.is_err() {
                                // Receiver dropped → scanner_runtime is
                                // shutting down; drop any remaining hashes in
                                // this frame (anchor_on_current_tip on the
                                // next session would replay the latest tip
                                // anyway). Issue #84 review (round 4) MAJOR 3.
                                return Err(WsError::Stream("receiver dropped".into()));
                            }
                        }
                    }
                    WsMessage::Binary(_) => {
                        // Esplora WS does not send binary frames for the
                        // `blocks` subscription, but tungstenite delivers
                        // protocol frames here too. Ignore quietly.
                    }
                    WsMessage::Ping(_) | WsMessage::Pong(_) => {
                        // tungstenite auto-responds to inbound Pings;
                        // inbound Pongs are the response to OUR outbound
                        // keepalive pings. Either way, the deadline
                        // reset above is the whole job — nothing to do.
                    }
                    WsMessage::Close(_) => return Ok(()),
                    // The `Frame` variant of `tungstenite::Message` only
                    // surfaces under the `frame` cargo feature, which we do
                    // not enable. Keep the arm here as a defensive catch-all
                    // so a future tungstenite upgrade that flips the feature
                    // default does not break the build via a non-exhaustive
                    // match warning.
                    #[allow(unreachable_patterns)]
                    WsMessage::Frame(_) => {}
                }
            }
        }
    }
}

/// On reconnect, fetch the current tip via HTTP and push it into
/// the channel so `scanner_runtime` can re-anchor. Bounded by a
/// short timeout — the channel must not stall on a slow tip lookup.
/// The Esplora client is owned by `run_scanner_ws` and passed in by
/// reference so we do not rebuild it on every reconnect.
async fn anchor_on_current_tip(
    client: &EsploraReadClient,
    tip_tx: &mpsc::Sender<BlockHash>,
) -> Result<(), String> {
    let lookup = tokio::time::timeout(Duration::from_secs(10), client.get_tip_hash());
    let hash = match lookup.await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("get_tip_hash timed out".into()),
    };

    if tip_tx.send(hash).await.is_err() {
        return Err("receiver dropped".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "scanner_ws_tests.rs"]
mod tests;
