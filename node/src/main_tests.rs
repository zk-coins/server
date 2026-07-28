// Bootstrap-level tests for `main.rs` and the lib-root helpers it
// invokes (`build_network_config_from_env`, the
// `persist_state_from_sync_context` bridge).

use super::*;
use crate::test_db::setup_pool;
use crate::v1::{claim_stack_scan_mode, ScanStackMode};

// --- build_network_config_from_env -------------------------------
//
// These tests cover the "explicit-or-panic" contract: every chain-
// shaping env var (`IS_MAINNET`, `ESPLORA_URL`, `ESPLORA_WS_URL`) is
// required, with no default. No stage — PRD, DEV, integration, the
// local dev loop — gets a silent Mutinynet fallback.
//
// Tests use a fake `env` closure rather than `std::env::set_var` so
// the panic side-effect cannot poison the `NETWORK_CONFIG`
// lazy_static cell (shared across tests in this binary) and so the
// tests do not race other test threads via the process-wide
// environment.

/// Build a closure-shaped env from a slice so the tests read like a
/// table. Returns the first matching value or `None`.
fn fake_env(entries: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |k| {
        entries.iter().find_map(|(name, value)| {
            if *name == k {
                Some((*value).to_string())
            } else {
                None
            }
        })
    }
}

#[test]
fn build_network_config_full_mutinynet() {
    let cfg = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "false"),
        ("ESPLORA_URL", "http://electrs-mutinynet.test:3000"),
        ("ESPLORA_WS_URL", "ws://mutinynet-ws.test/api/v1/ws"),
    ]));
    assert!(!cfg.is_mainnet);
    assert_eq!(cfg.url, "http://electrs-mutinynet.test:3000");
    assert_eq!(
        cfg.ws_url.as_deref(),
        Some("ws://mutinynet-ws.test/api/v1/ws")
    );
    assert_eq!(cfg.network_name, "Mutinynet");
}

#[test]
fn build_network_config_full_mainnet() {
    let cfg = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
    ]));
    assert!(cfg.is_mainnet);
    assert_eq!(cfg.url, "http://electrs-mainnet.test:3000");
    assert_eq!(
        cfg.ws_url.as_deref(),
        Some("wss://mainnet-ws.test/api/v1/ws")
    );
    assert_eq!(cfg.network_name, "Mainnet");
}

#[test]
fn build_network_config_explicit_network_name_overrides_default_label() {
    // `NETWORK_NAME` is the only env var that remains derived (purely
    // cosmetic — feeds `/api/info`). Operators can override it without
    // touching IS_MAINNET, e.g. "Mainnet-Canary".
    let cfg = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
        ("NETWORK_NAME", "Mainnet-Canary"),
    ]));
    assert!(cfg.is_mainnet);
    assert_eq!(cfg.network_name, "Mainnet-Canary");
}

// --- panic paths: IS_MAINNET ------------------------------------

#[test]
#[should_panic(expected = "IS_MAINNET env var must be set")]
fn build_network_config_panics_on_missing_is_mainnet() {
    // No silent default to false (Mutinynet). Every stage must say
    // explicitly which chain it serves.
    let _ = build_network_config_from_env(fake_env(&[
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
    ]));
}

#[test]
#[should_panic(expected = "IS_MAINNET env var must be set")]
fn build_network_config_panics_on_empty_is_mainnet() {
    // `IS_MAINNET=` in a compose file → empty string → treated as
    // unset, same as missing.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", ""),
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
    ]));
}

#[test]
#[should_panic(expected = "IS_MAINNET must be exactly `true` or `false`")]
fn build_network_config_panics_on_truthy_is_mainnet() {
    // Historical class of bugs: a typed `1`, `TRUE`, or `yes` used
    // to silently mean Mutinynet. Reject ambiguous values loudly.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "1"),
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
    ]));
}

// --- panic paths: ESPLORA_URL -----------------------------------

#[test]
#[should_panic(expected = "ESPLORA_URL env var must be set")]
fn build_network_config_panics_on_missing_esplora_url_mainnet() {
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
    ]));
}

#[test]
#[should_panic(expected = "ESPLORA_URL env var must be set")]
fn build_network_config_panics_on_missing_esplora_url_mutinynet() {
    // Symmetric: even on the non-Mainnet path, an unset ESPLORA_URL
    // now panics. Previously fell back silently to mutinynet.com.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "false"),
        ("ESPLORA_WS_URL", "ws://mutinynet-ws.test/api/v1/ws"),
    ]));
}

#[test]
#[should_panic(expected = "ESPLORA_URL env var must be set")]
fn build_network_config_panics_on_empty_esplora_url() {
    // `ESPLORA_URL=` in a compose file resolves to `Some("")`. Without
    // the empty-string filter in `env_or_unset`, the `expect` would
    // be bypassed and `EsploraConfig.url` would be left as `""` —
    // exactly the silent-misconfiguration class the panic is meant
    // to catch.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", ""),
        ("ESPLORA_WS_URL", "wss://mainnet-ws.test/api/v1/ws"),
    ]));
}

// --- panic paths: ESPLORA_WS_URL --------------------------------

#[test]
#[should_panic(expected = "ESPLORA_WS_URL env var must be set")]
fn build_network_config_panics_on_missing_esplora_ws_url_mainnet() {
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
    ]));
}

#[test]
#[should_panic(expected = "ESPLORA_WS_URL env var must be set")]
fn build_network_config_panics_on_missing_esplora_ws_url_mutinynet() {
    // Symmetric: an unset ESPLORA_WS_URL now panics even on the
    // non-Mainnet path. Previously DEV silently bound to the public
    // `wss://mutinynet.com/api/v1/ws` — an external host we do not
    // operate.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "false"),
        ("ESPLORA_URL", "http://electrs-mutinynet.test:3000"),
    ]));
}

#[test]
#[should_panic(expected = "ESPLORA_WS_URL env var must be set")]
fn build_network_config_panics_on_whitespace_esplora_ws_url() {
    // Whitespace-only values are also rejected — same misconfiguration
    // class as the empty string, just easier to miss in a diff.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet.test:3000"),
        ("ESPLORA_WS_URL", "   "),
    ]));
}

// --- persist_state_from_sync_context -----------------------------
//
// Regression coverage for the `block_in_place(block_on(...))` bridge
// used inside the scanner's synchronous `InscriptionCallback`.
// Without `block_in_place`, the naive
// `Handle::current().block_on(persist_state_tx(…))` form panics at
// runtime on the multi_thread tokio runtime (the default for
// `#[tokio::main]`) — and "runtime" here means "the first time the
// scanner sees a real inscription on Mutinynet". CI did not catch
// the original form because no integration test ever drove the sync
// callback through a real multi_thread worker; this test does.

// Shared-container, per-test-schema infra now lives in
// `crate::test_db::setup_pool` (issue #181 Optimisation B). The
// previously file-local `setup_pool` is gone in favour of the
// shared helper.

/// Regression test for the scanner-callback panic.
///
/// The production scanner calls `persist_state_from_sync_context`
/// from a *synchronous* closure that runs *inline* on a multi_thread
/// tokio worker — the callback is invoked from inside an `async fn`,
/// so it executes on whichever worker thread is currently driving
/// the scanner task. The earlier form — `Handle::current().block_on(...)`
/// without `block_in_place` — panicked the first time a real
/// inscription was processed (see Tokio docs on `Handle::block_on`:
/// "may panic when called from a thread that is part of the current
/// Tokio runtime"). This test reproduces that exact shape:
///
///   1. Stand up a Postgres testcontainer + migrated pool.
///   2. From an `async fn` body running on a multi_thread worker,
///      invoke a synchronous closure that calls
///      `persist_state_from_sync_context` — the same call shape as
///      `scanner_runtime` → `InscriptionCallback`.
///   3. Re-read on the async side and assert the row landed.
///
/// If somebody ever "simplifies" the helper back to a bare
/// `Handle::current().block_on(...)`, this test panics with
/// "Cannot start a runtime from within a runtime" / "may panic" and
/// CI catches it before it ships.
///
/// `flavor = "multi_thread"` is *load-bearing*: `block_in_place`
/// itself panics on the current-thread flavor (`"can call blocking
/// only when running on the multi-threaded runtime"`). The
/// production bootstrap is multi_thread, so this test mirrors it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persist_state_from_sync_context_works_from_sync_closure_on_multi_thread() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    // Production boot claims the stack before any scanner write; the
    // helper under test only bridges sync→async persist.
    claim_stack_scan_mode(&pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy for sync-context persist test");

    let smt = vec![0x11u8; 64];
    let mmr = vec![0x22u8; 128];
    let block = [0x33u8; 32];

    // The scanner's `InscriptionCallback` is a sync `Fn(...)` that
    // gets called from inside an `async fn`. We mimic that here: the
    // outer `async fn` (this test body) is on a multi_thread worker;
    // the closure below is a plain `FnOnce()` invoked inline, so it
    // runs on that same worker thread — exactly the topology where
    // bare `Handle::current().block_on(...)` panics.
    let persist_from_sync_closure = || -> Result<(), sqlx::Error> {
        persist_state_from_sync_context(&pool, &smt, &mmr, &block, None)
    };
    persist_from_sync_closure()
        .expect("persist_state_from_sync_context returned Err (regression: did block_in_place get removed?)");

    // Round-trip verification: the helper actually wrote what we
    // gave it. Without this assertion, a no-op stub would still pass
    // the "no panic" half of the test.
    assert_eq!(db::load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(db::load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(db::load_latest_block(&pool).await.unwrap(), Some(block));
}
