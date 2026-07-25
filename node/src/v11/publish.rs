//! v1.1 publisher dispatch: `AggregateStateNullifierV3` via script-plonky2.
//!
//! Behind `ZKCOINS_V11_SHADOW=1` the node publishes half-aggregated
//! nullifier batches through [`zkcoins_prover::publisher::Publisher`]
//! instead of bincode `Commitment` envelopes. The legacy
//! [`crate::publisher::create_and_broadcast_inscription`] path stays
//! intact for flag-off boots and is **refused** when this process has
//! claimed the v1.1 stack (see [`super::separation`]).
//!
//! Bitcoind RPC credentials are mandatory under v1.1 — missing config
//! fails loud; there is no fall-back to the Esplora commitment publisher.

use anyhow::{bail, Context, Result};
use bitcoin::Amount;
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::publisher::{
    BatchMember, PublishedBatch, Publisher, PublisherConfig, BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN,
};

use super::scan::{V11_SCANNER_COOKIE_ENV, V11_SCANNER_RPC_URL_ENV};
use super::separation::ensure_v11_publisher_allowed;

/// Optional fee / reveal-output overrides. Every production field still
/// comes from env; tests inject a ready-made [`PublisherConfig`].
#[derive(Clone, Debug)]
pub struct V11PublisherEnv {
    pub rpc_url: String,
    pub cookie_path: std::path::PathBuf,
    pub wallet_name: String,
    pub fee_rate_sat_per_vb: u64,
    pub reveal_output_value_sats: u64,
    pub network: Network,
    pub inclusion_delay_margin: u32,
}

/// Env keys for the v1.1 bitcoind publisher wallet.
pub const V11_PUBLISHER_WALLET_ENV: &str = "ZKCOINS_V11_BITCOIND_WALLET";
pub const V11_PUBLISHER_FEE_RATE_ENV: &str = "ZKCOINS_V11_FEE_RATE_SAT_PER_VB";
pub const V11_PUBLISHER_REVEAL_VALUE_ENV: &str = "ZKCOINS_V11_REVEAL_OUTPUT_SATS";

/// Load publisher config from env. Fails loud on any missing piece.
pub fn v11_publisher_env_from_env(network: Network) -> Result<V11PublisherEnv> {
    ensure_v11_publisher_allowed()?;

    let rpc_url = std::env::var(V11_SCANNER_RPC_URL_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_SCANNER_RPC_URL_ENV} for the \
             AggregateStateNullifierV3 publisher. Refusing to fall back to the \
             legacy Esplora commitment publisher"
        )
    })?;
    if rpc_url.trim().is_empty() {
        bail!("{V11_SCANNER_RPC_URL_ENV} is empty (no silent default)");
    }

    let cookie = std::env::var(V11_SCANNER_COOKIE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_SCANNER_COOKIE_ENV} for the \
             v1.1 publisher cookie auth. Refusing to fall back"
        )
    })?;
    if cookie.trim().is_empty() {
        bail!("{V11_SCANNER_COOKIE_ENV} is empty (no silent default)");
    }

    let wallet_name = std::env::var(V11_PUBLISHER_WALLET_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_PUBLISHER_WALLET_ENV} (bitcoind \
             wallet name funding AggregateStateNullifierV3 commits)"
        )
    })?;
    if wallet_name.trim().is_empty() {
        bail!("{V11_PUBLISHER_WALLET_ENV} is empty (no silent default)");
    }

    let fee_raw = std::env::var(V11_PUBLISHER_FEE_RATE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_PUBLISHER_FEE_RATE_ENV} \
             (sat/vB; no silent default fee rate)"
        )
    })?;
    let fee_rate_sat_per_vb: u64 = fee_raw.trim().parse().map_err(|_| {
        anyhow::anyhow!(
            "{V11_PUBLISHER_FEE_RATE_ENV}={fee_raw:?} is not a non-negative integer"
        )
    })?;
    if fee_rate_sat_per_vb == 0 {
        bail!("{V11_PUBLISHER_FEE_RATE_ENV} must be > 0 (no silent default)");
    }

    let reveal_raw = std::env::var(V11_PUBLISHER_REVEAL_VALUE_ENV).map_err(|_| {
        anyhow::anyhow!(
            "ZKCOINS_V11_SHADOW=1 requires {V11_PUBLISHER_REVEAL_VALUE_ENV} \
             (reveal output sats; no silent default)"
        )
    })?;
    let reveal_output_value_sats: u64 = reveal_raw.trim().parse().map_err(|_| {
        anyhow::anyhow!(
            "{V11_PUBLISHER_REVEAL_VALUE_ENV}={reveal_raw:?} is not a non-negative integer"
        )
    })?;
    if reveal_output_value_sats == 0 {
        bail!("{V11_PUBLISHER_REVEAL_VALUE_ENV} must be > 0 (no silent default)");
    }

    Ok(V11PublisherEnv {
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

impl V11PublisherEnv {
    pub fn into_config(self) -> PublisherConfig {
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

/// Connect the script-plonky2 publisher. Fails loud on RPC / chain mismatch.
pub fn connect_v11_publisher(config: PublisherConfig) -> Result<Publisher> {
    ensure_v11_publisher_allowed()?;
    Publisher::connect(config).context("v1.1 Publisher::connect failed (no legacy fall-back)")
}

/// Half-aggregate and inscribe `members` as `AggregateStateNullifierV3`.
///
/// Empty member list fails loud (publisher would also refuse).
pub fn publish_v11_batch(publisher: &Publisher, members: &[BatchMember]) -> Result<PublishedBatch> {
    ensure_v11_publisher_allowed()?;
    if members.is_empty() {
        bail!("publish_v11_batch requires at least one BatchMember (no empty inscription)");
    }
    publisher
        .publish(members)
        .context("v1.1 Publisher::publish failed (no legacy fall-back)")
}
