//! Spec-v1.1 per-account compliance-circuit skeleton.
//!
//! This module intentionally owns local copies of the protocol constants it
//! needs. `shared` depends on this crate, so using `shared::spec_v1` here would
//! create a dependency cycle. Tests cross-check every local copy against the
//! host reference.

mod serialize;
mod skeleton;
mod targets;

pub use serialize::address_from_pk0_and_nk_commit;
pub use skeleton::{
    build_skeleton_circuit, ComplianceTargets, Network, SkeletonCircuit, MAX_TX_OUTPUTS,
};
pub use targets::{
    AccountStateTarget, BalanceSlotTarget, CoinTarget, OutputTemplateTarget, ProofDataTarget,
    MAX_ACCOUNT_ASSETS,
};

const TAG_ACCOUNT_STATE: &str = "zkCoins/v1/AccountState";
const TAG_COIN: &str = "zkCoins/v1/Coin";
const TAG_COINS_ROOT_LEAF: &str = "zkCoins/v1/CoinsRoot/Leaf";
const TAG_COINS_ROOT_NODE: &str = "zkCoins/v1/CoinsRoot/Node";
const TAG_NETWORK: &str = "zkCoins/v1/Network";
const TAG_NPK_COMMIT: &[u8] = b"zkCoins/v1/NpkCommit";

const NETWORK_TAG_MAINNET: &[u8] = b"zkCoins/v1/mainnet";
const NETWORK_TAG_TESTNET: &[u8] = b"zkCoins/v1/testnet";
const NETWORK_TAG_REGTEST: &[u8] = b"zkCoins/v1/regtest";

#[cfg(test)]
mod tests;
