//! Domain-separation tag catalogue (full prefixed strings).
//!
//! Per §1.1, every `Hc`/`H`/`HKDF` context MUST use the full
//! `"zkCoins/v1/<Context>"` form. Shorthand in the prose is notation only.

// ---------------------------------------------------------------------------
// Hc domain-separation contexts
// ---------------------------------------------------------------------------

pub const TAG_ACCOUNT_STATE: &str = "zkCoins/v1/AccountState";
pub const TAG_COIN: &str = "zkCoins/v1/Coin";
pub const TAG_ASSET_ID: &str = "zkCoins/v1/AssetId";
pub const TAG_ASSET_ID_V2: &str = "zkCoins/v1/AssetIdV2";
pub const TAG_ISSUANCE_TERMS: &str = "zkCoins/v1/IssuanceTerms";
pub const TAG_ISSUANCE_TERMS_V2: &str = "zkCoins/v1/IssuanceTermsV2";
pub const TAG_NK_COMMIT: &str = "zkCoins/v1/NkCommit";
pub const TAG_NULLIFIER: &str = "zkCoins/v1/Nullifier";
pub const TAG_NETWORK: &str = "zkCoins/v1/Network";
pub const TAG_NAV_COMMIT: &str = "zkCoins/v1/NavCommit";
pub const TAG_DETECT_TAG: &str = "zkCoins/v1/DetectTag";

pub const TAG_COINS_ROOT_LEAF: &str = "zkCoins/v1/CoinsRoot/Leaf";
pub const TAG_COINS_ROOT_NODE: &str = "zkCoins/v1/CoinsRoot/Node";
pub const TAG_NULLIFIERS_ROOT_LEAF: &str = "zkCoins/v1/NullifiersRoot/Leaf";
pub const TAG_NULLIFIERS_ROOT_NODE: &str = "zkCoins/v1/NullifiersRoot/Node";

pub const TAG_NFLOG_LEAF: &str = "zkCoins/v1/NfLog/Leaf";
pub const TAG_NFLOG_NODE: &str = "zkCoins/v1/NfLog/Node";
pub const TAG_NFLOG_ROOT: &str = "zkCoins/v1/NfLog/Root";
pub const TAG_NFLOG_EMPTY: &str = "zkCoins/v1/NfLog/Empty";

pub const TAG_COINHIST_LEAF: &str = "zkCoins/v1/CoinHist/Leaf";
pub const TAG_COINHIST_NODE: &str = "zkCoins/v1/CoinHist/Node";

// ---------------------------------------------------------------------------
// Plain byte-string *arguments* (not domain tags)
// ---------------------------------------------------------------------------

/// Genesis tag input to `AssetId` / `AssetIdV2` (18 ASCII bytes).
pub const GENESIS_TAG: &[u8] = b"zkCoins/v1/genesis";

/// Network tag byte strings (inputs to `Hc("Network", …)`).
pub const NETWORK_TAG_MAINNET: &[u8] = b"zkCoins/v1/mainnet";
pub const NETWORK_TAG_TESTNET: &[u8] = b"zkCoins/v1/testnet";
pub const NETWORK_TAG_REGTEST: &[u8] = b"zkCoins/v1/regtest";

// ---------------------------------------------------------------------------
// SHA-256 raw preimage context (not through Hc / E(·))
// ---------------------------------------------------------------------------

/// Raw ASCII prefix for `npk_commit = SHA256(TAG_NPK_COMMIT || next_pubkey || npk_rand)`.
pub const TAG_NPK_COMMIT: &[u8] = b"zkCoins/v1/NpkCommit";

/// Bech32m HRP for addresses (§1.7.7).
pub const ADDRESS_HRP: &str = "zk";
