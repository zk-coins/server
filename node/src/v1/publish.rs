//! v1.1 publisher dispatch: `AggregateStateNullifierV3` via script-plonky2.
//!
//! Behind `ZKCOINS_V1_SHADOW=1` the node publishes half-aggregated
//! nullifier batches through the foreign script-plonky2 publisher
//! instead of bincode `Commitment` envelopes. The legacy
//! [`crate::publisher::create_and_broadcast_inscription`] path stays
//! intact for flag-off boots and is **refused** when this process has
//! claimed the v1.1 stack (see [`super::separation`]).
//!
//! Bitcoind RPC credentials are mandatory under v1.1 — missing config
//! fails loud; there is no fall-back to the Esplora commitment publisher.
//!
//! ## Opaque connect surface
//!
//! [`connect_v1_publisher`] returns a node-owned [`V1Publisher`] facade.
//! The foreign `zkcoins_prover::publisher::Publisher` type never leaves
//! this module — its inherent methods (`prepare`, `broadcast_commit`,
//! `broadcast_reveal`, `publish`) are not reachable from a crate that
//! depends only on `node`. Durable publish is driven only through the
//! receive / resume orchestration entry points.

use anyhow::{bail, Context, Result};
use bitcoin::Amount;
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::publisher::{
    BatchMember, PreparedBatch, PublishedBatch, Publisher, PublisherConfig,
    BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
};

use super::scan::{V1_SCANNER_COOKIE_ENV, V1_SCANNER_RPC_URL_ENV};
use super::separation::ensure_v1_publisher_allowed;

/// Optional fee / reveal-output overrides. Every production field still
/// comes from env; tests may assemble a [`V1PublisherEnv`] directly.
#[derive(Clone, Debug)]
pub struct V1PublisherEnv {
    pub rpc_url: String,
    pub cookie_path: std::path::PathBuf,
    pub wallet_name: String,
    pub fee_rate_sat_per_vb: u64,
    pub reveal_output_value_sats: u64,
    pub network: Network,
    pub inclusion_delay_margin: u32,
}

/// Env keys for the v1.1 bitcoind publisher wallet.
pub(crate) const V1_PUBLISHER_WALLET_ENV: &str = "ZKCOINS_V1_BITCOIND_WALLET";
pub(crate) const V1_PUBLISHER_FEE_RATE_ENV: &str = "ZKCOINS_V1_FEE_RATE_SAT_PER_VB";
pub(crate) const V1_PUBLISHER_REVEAL_VALUE_ENV: &str = "ZKCOINS_V1_REVEAL_OUTPUT_SATS";

/// Load publisher config from env. Fails loud on any missing piece.
pub fn v1_publisher_env_from_env(network: Network) -> Result<V1PublisherEnv> {
    ensure_v1_publisher_allowed()?;

    let rpc_url = std::env::var(V1_SCANNER_RPC_URL_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_SCANNER_RPC_URL_ENV} for the \
             AggregateStateNullifierV3 publisher. Refusing to fall back to the \
             legacy Esplora commitment publisher"
        )
    })?;
    if rpc_url.trim().is_empty() {
        bail!("{V1_SCANNER_RPC_URL_ENV} is empty (no silent default)");
    }

    let cookie = std::env::var(V1_SCANNER_COOKIE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_SCANNER_COOKIE_ENV} for the \
             v1.1 publisher cookie auth. Refusing to fall back"
        )
    })?;
    if cookie.trim().is_empty() {
        bail!("{V1_SCANNER_COOKIE_ENV} is empty (no silent default)");
    }

    let wallet_name = std::env::var(V1_PUBLISHER_WALLET_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_PUBLISHER_WALLET_ENV} (bitcoind \
             wallet name funding AggregateStateNullifierV3 commits)"
        )
    })?;
    if wallet_name.trim().is_empty() {
        bail!("{V1_PUBLISHER_WALLET_ENV} is empty (no silent default)");
    }

    let fee_raw = std::env::var(V1_PUBLISHER_FEE_RATE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_PUBLISHER_FEE_RATE_ENV} \
             (sat/vB; no silent default fee rate)"
        )
    })?;
    let fee_rate_sat_per_vb: u64 = fee_raw.trim().parse().map_err(|_| {
        anyhow::anyhow!("{V1_PUBLISHER_FEE_RATE_ENV}={fee_raw:?} is not a non-negative integer")
    })?;
    if fee_rate_sat_per_vb == 0 {
        bail!("{V1_PUBLISHER_FEE_RATE_ENV} must be > 0 (no silent default)");
    }

    let reveal_raw = std::env::var(V1_PUBLISHER_REVEAL_VALUE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V1_SHADOW=1 requires {V1_PUBLISHER_REVEAL_VALUE_ENV} \
             (reveal output sats; no silent default)"
        )
    })?;
    let reveal_output_value_sats: u64 = reveal_raw.trim().parse().map_err(|_| {
        anyhow::anyhow!(
            "{V1_PUBLISHER_REVEAL_VALUE_ENV}={reveal_raw:?} is not a non-negative integer"
        )
    })?;
    if reveal_output_value_sats == 0 {
        bail!("{V1_PUBLISHER_REVEAL_VALUE_ENV} must be > 0 (no silent default)");
    }

    Ok(V1PublisherEnv {
        rpc_url,
        cookie_path: std::path::PathBuf::from(cookie),
        wallet_name,
        fee_rate_sat_per_vb,
        reveal_output_value_sats,
        network,
        // Spec-recommended margin; still explicit (not a publisher silent default).
        inclusion_delay_margin: BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
    })
}

impl V1PublisherEnv {
    /// Convert into the foreign publisher config. **Crate-private** — the
    /// foreign `PublisherConfig` type must not appear on the public surface.
    fn into_config(self) -> PublisherConfig {
        PublisherConfig {
            rpc_url: self.rpc_url,
            cookie_path: self.cookie_path,
            wallet_name: self.wallet_name,
            fee_rate_sat_per_vb: self.fee_rate_sat_per_vb,
            reveal_output_value: Amount::from_sat(self.reveal_output_value_sats),
            network: self.network,
            inclusion_delay_margin: self.inclusion_delay_margin,
        }
    }
}

/// Node-owned opaque publisher facade.
///
/// Wraps the foreign script-plonky2 `Publisher` so that type never crosses
/// the `node` package boundary. This type intentionally exposes **no**
/// inherent prepare / broadcast / publish methods — durable publish is
/// reached only via receive / resume orchestration, which hold the
/// crate-private [`super::receive::NullifierBatchPublisher`] capability
/// for production and test doubles alike.
pub struct V1Publisher {
    inner: Publisher,
}

impl V1Publisher {
    /// Half-aggregate + inscribe. Crate-private sink used by the
    /// [`super::receive::NullifierBatchPublisher`] impl.
    pub(crate) fn publish_batch(&self, members: &[BatchMember]) -> Result<PublishedBatch> {
        publish_v1_batch(&self.inner, members)
    }

    /// Construct a fee-converged commit/reveal pair without broadcasting.
    pub(crate) fn try_prepare(&self, members: &[BatchMember]) -> Result<Option<PreparedBatch>> {
        Ok(Some(self.inner.prepare(members).context(
            "v1.1 Publisher::prepare failed (no legacy fall-back)",
        )?))
    }

    pub(crate) fn broadcast_commit(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
        self.inner
            .broadcast_commit(prepared)
            .context("v1.1 Publisher::broadcast_commit failed (no legacy fall-back)")
    }

    pub(crate) fn broadcast_reveal(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
        self.inner
            .broadcast_reveal(prepared)
            .context("v1.1 Publisher::broadcast_reveal failed (no legacy fall-back)")
    }
}

/// Connect the script-plonky2 publisher. Fails loud on RPC / chain mismatch.
///
/// Returns a node-owned [`V1Publisher`] — never the raw foreign type.
pub fn connect_v1_publisher(env: V1PublisherEnv) -> Result<V1Publisher> {
    ensure_v1_publisher_allowed()?;
    let config = env.into_config();
    let inner = Publisher::connect(config)
        .context("v1.1 Publisher::connect failed (no legacy fall-back)")?;
    Ok(V1Publisher { inner })
}

/// Half-aggregate and inscribe `members` as `AggregateStateNullifierV3`.
///
/// Empty member list fails loud (publisher would also refuse).
///
/// **Crate-private sink.** Downstream callers must not drive publish from a
/// free-standing batch of members; use the receive / resume orchestration
/// entry points that already carry a capability.
pub(crate) fn publish_v1_batch(
    publisher: &Publisher,
    members: &[BatchMember],
) -> Result<PublishedBatch> {
    ensure_v1_publisher_allowed()?;
    if members.is_empty() {
        bail!("publish_v1_batch requires at least one BatchMember (no empty inscription)");
    }
    publisher
        .publish(members)
        .context("v1.1 Publisher::publish failed (no legacy fall-back)")
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use std::{
        env,
        ffi::OsString,
        path::PathBuf,
        sync::{Mutex, MutexGuard},
    };

    use super::*;
    use crate::v1::{mode::V1ShadowMode, separation::claim_process_stack_from_shadow_mode};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const PUBLISHER_ENV_KEYS: [&str; 5] = [
        V1_SCANNER_RPC_URL_ENV,
        V1_SCANNER_COOKIE_ENV,
        V1_PUBLISHER_WALLET_ENV,
        V1_PUBLISHER_FEE_RATE_ENV,
        V1_PUBLISHER_REVEAL_VALUE_ENV,
    ];

    struct PublisherEnvRestore {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl PublisherEnvRestore {
        fn capture() -> Self {
            Self {
                saved: PUBLISHER_ENV_KEYS
                    .into_iter()
                    .map(|key| (key, env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for PublisherEnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn valid_env() {
        env::set_var(V1_SCANNER_RPC_URL_ENV, "http://127.0.0.1:18443");
        env::set_var(V1_SCANNER_COOKIE_ENV, "/tmp/cookie");
        env::set_var(V1_PUBLISHER_WALLET_ENV, "zkcoins");
        env::set_var(V1_PUBLISHER_FEE_RATE_ENV, "2");
        env::set_var(V1_PUBLISHER_REVEAL_VALUE_ENV, "546");
    }

    fn with_v1_claim<R>(f: impl FnOnce() -> R) -> R {
        // The process claim is monotonic; nextest provides process isolation for these tests.
        claim_process_stack_from_shadow_mode(V1ShadowMode::On);
        f()
    }

    fn publisher_env_error() -> String {
        match v1_publisher_env_from_env(Network::Regtest) {
            Ok(_) => panic!("publisher environment unexpectedly loaded"),
            Err(error) => error.to_string(),
        }
    }

    fn assert_error_names(error: &str, key: &str, fragment: &str) {
        assert!(error.contains(key), "error did not name {key}: {error}");
        assert!(
            error.contains(fragment),
            "error for {key} did not contain {fragment:?}: {error}"
        );
    }

    #[test]
    fn publisher_env_rejects_an_unclaimed_process_before_reading_env() {
        let _env_lock = lock_env();
        let _env_restore = PublisherEnvRestore::capture();

        for key in PUBLISHER_ENV_KEYS {
            env::remove_var(key);
        }

        let error = publisher_env_error();
        assert!(
            error.contains("stack separation"),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("ScanStackMode::V1"),
            "unexpected error: {error}"
        );
        assert!(
            !error.contains(&format!("requires {V1_SCANNER_RPC_URL_ENV}")),
            "publisher env was read before the stack-separation guard: {error}"
        );
        assert!(
            !error.contains("Refusing to fall back to the legacy Esplora commitment publisher"),
            "publisher env was read before the stack-separation guard: {error}"
        );
    }

    #[test]
    fn publisher_env_rejects_a_legacy_process_claim() {
        let _env_lock = lock_env();
        let _env_restore = PublisherEnvRestore::capture();

        claim_process_stack_from_shadow_mode(V1ShadowMode::Off);
        valid_env();

        let error = publisher_env_error();
        assert!(
            error.contains("stack separation"),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("legacy scan stack"),
            "unexpected error: {error}"
        );
        assert!(
            error.contains("AggregateStateNullifierV3"),
            "unexpected error: {error}"
        );
        assert!(
            !error.contains("ScanStackMode::V1 at boot"),
            "legacy claim returned the unclaimed-process error: {error}"
        );
        assert!(
            !error.contains(&format!("requires {V1_SCANNER_RPC_URL_ENV}")),
            "legacy claim reached publisher env validation: {error}"
        );
    }

    #[test]
    fn publisher_env_rejects_each_missing_value() {
        let _env_lock = lock_env();
        let _env_restore = PublisherEnvRestore::capture();

        with_v1_claim(|| {
            let cases = [
                (
                    V1_SCANNER_RPC_URL_ENV,
                    "Refusing to fall back to the legacy Esplora commitment publisher",
                ),
                (V1_SCANNER_COOKIE_ENV, "Refusing to fall back"),
                (
                    V1_PUBLISHER_WALLET_ENV,
                    "bitcoind wallet name funding AggregateStateNullifierV3 commits",
                ),
                (
                    V1_PUBLISHER_FEE_RATE_ENV,
                    "sat/vB; no silent default fee rate",
                ),
                (
                    V1_PUBLISHER_REVEAL_VALUE_ENV,
                    "reveal output sats; no silent default",
                ),
            ];

            for (key, fragment) in cases {
                valid_env();
                env::remove_var(key);
                let error = publisher_env_error();
                assert_error_names(&error, key, fragment);
            }
        });
    }

    #[test]
    fn publisher_env_rejects_empty_and_whitespace_only_strings() {
        let _env_lock = lock_env();
        let _env_restore = PublisherEnvRestore::capture();

        with_v1_claim(|| {
            for key in [
                V1_SCANNER_RPC_URL_ENV,
                V1_SCANNER_COOKIE_ENV,
                V1_PUBLISHER_WALLET_ENV,
            ] {
                for value in ["", "   "] {
                    valid_env();
                    env::set_var(key, value);
                    let error = publisher_env_error();
                    assert_error_names(&error, key, "is empty (no silent default)");
                }
            }
        });
    }

    #[test]
    fn publisher_env_rejects_invalid_and_zero_numeric_values() {
        let _env_lock = lock_env();
        let _env_restore = PublisherEnvRestore::capture();

        with_v1_claim(|| {
            let invalid_cases = [
                (V1_PUBLISHER_FEE_RATE_ENV, "abc"),
                (V1_PUBLISHER_FEE_RATE_ENV, ""),
                (V1_PUBLISHER_FEE_RATE_ENV, "   "),
                (V1_PUBLISHER_REVEAL_VALUE_ENV, "xyz"),
                (V1_PUBLISHER_REVEAL_VALUE_ENV, ""),
                (V1_PUBLISHER_REVEAL_VALUE_ENV, "   "),
            ];
            for (key, value) in invalid_cases {
                valid_env();
                env::set_var(key, value);
                let error = publisher_env_error();
                let expected = format!("{key}={value:?} is not a non-negative integer");
                assert_error_names(&error, key, &expected);
            }

            for key in [V1_PUBLISHER_FEE_RATE_ENV, V1_PUBLISHER_REVEAL_VALUE_ENV] {
                valid_env();
                env::set_var(key, "0");
                let error = publisher_env_error();
                assert_error_names(&error, key, "must be > 0 (no silent default)");
            }
        });
    }

    #[test]
    fn publisher_env_loads_and_maps_into_config() {
        let _env_lock = lock_env();
        let _env_restore = PublisherEnvRestore::capture();

        with_v1_claim(|| {
            valid_env();
            let publisher_env = v1_publisher_env_from_env(Network::Regtest)
                .expect("valid publisher environment should load");

            assert_eq!(publisher_env.rpc_url, "http://127.0.0.1:18443");
            assert_eq!(publisher_env.cookie_path, PathBuf::from("/tmp/cookie"));
            assert_eq!(publisher_env.wallet_name, "zkcoins");
            assert_eq!(publisher_env.fee_rate_sat_per_vb, 2);
            assert_eq!(publisher_env.reveal_output_value_sats, 546);
            assert_eq!(publisher_env.network, Network::Regtest);
            assert_eq!(
                publisher_env.inclusion_delay_margin,
                BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN
            );

            let config = publisher_env.into_config();
            assert_eq!(config.rpc_url, "http://127.0.0.1:18443");
            assert_eq!(config.cookie_path, PathBuf::from("/tmp/cookie"));
            assert_eq!(config.wallet_name, "zkcoins");
            assert_eq!(config.fee_rate_sat_per_vb, 2);
            assert_eq!(config.reveal_output_value, Amount::from_sat(546));
            assert_eq!(config.network, Network::Regtest);
            assert_eq!(
                config.inclusion_delay_margin,
                BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN
            );
        });
    }
}
