//! Spec-v1.1 per-account compliance-circuit skeleton.
//!
//! This module intentionally owns local copies of the protocol constants it
//! needs. `shared` depends on this crate, so using `shared::spec_v1` here would
//! create a dependency cycle. Tests cross-check every local copy against the
//! host reference.

mod bindings;
mod serialize;
mod skeleton;
mod targets;

pub use serialize::address_from_pk0_and_nk_commit;
pub use skeleton::{
    build_skeleton_circuit, ComplianceTargets, Network, SkeletonCircuit, MAX_TX_INPUTS,
    MAX_TX_OUTPUTS,
};
pub use targets::{
    AccountStateTarget, AssetIssuanceTarget, BalanceSlotTarget, CoinTarget,
    HistoryUpdatePathTarget, InputAuthTarget, InputCoinTarget, NavOpeningTarget, NavTarget,
    OutputTemplateTarget, PrevProofTargets, PrevStateNullifierTarget, ProofDataTarget,
    ReceivedAuthTarget, ReceivedCoinTarget, MAX_ACCOUNT_ASSETS, MAX_HISTORY_UPDATES,
    MAX_OUTPUT_MERKLE_DEPTH, MAX_RX_COINS,
};

const TAG_ACCOUNT_STATE: &str = "zkCoins/v1/AccountState";
const TAG_COIN: &str = "zkCoins/v1/Coin";
const TAG_COINS_ROOT_LEAF: &str = "zkCoins/v1/CoinsRoot/Leaf";
const TAG_COINS_ROOT_NODE: &str = "zkCoins/v1/CoinsRoot/Node";
const TAG_NK_COMMIT: &str = "zkCoins/v1/NkCommit";
const TAG_NULLIFIER: &str = "zkCoins/v1/Nullifier";
const TAG_NULLIFIERS_ROOT_LEAF: &str = "zkCoins/v1/NullifiersRoot/Leaf";
const TAG_NULLIFIERS_ROOT_NODE: &str = "zkCoins/v1/NullifiersRoot/Node";
const TAG_NETWORK: &str = "zkCoins/v1/Network";
const TAG_ASSET_ID: &str = "zkCoins/v1/AssetId";
const TAG_ASSET_ID_V2: &str = "zkCoins/v1/AssetIdV2";
const TAG_ISSUANCE_TERMS: &str = "zkCoins/v1/IssuanceTerms";
const TAG_ISSUANCE_TERMS_V2: &str = "zkCoins/v1/IssuanceTermsV2";
const TAG_NPK_COMMIT: &[u8] = b"zkCoins/v1/NpkCommit";
const TAG_NAV_COMMIT: &str = "zkCoins/v1/NavCommit";
const TAG_NFLOG_ROOT: &str = "zkCoins/v1/NfLog/Root";
const GENESIS_TAG: &[u8] = b"zkCoins/v1/genesis";

const NETWORK_TAG_MAINNET: &[u8] = b"zkCoins/v1/mainnet";
const NETWORK_TAG_TESTNET: &[u8] = b"zkCoins/v1/testnet";
const NETWORK_TAG_REGTEST: &[u8] = b"zkCoins/v1/regtest";

const M_STATE_MAINNET: &[u8] = b"zkCoins/v1/StateUpdate/mainnet";
const M_STATE_TESTNET: &[u8] = b"zkCoins/v1/StateUpdate/testnet";
const M_STATE_REGTEST: &[u8] = b"zkCoins/v1/StateUpdate/regtest";

#[cfg(test)]
mod tests;
