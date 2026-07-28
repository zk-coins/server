//! zkCoins protocol foundations — protocol version v1, edition spec-v1.2
//! (`shared::spec_v1`).
//!
//! Self-contained namespace for the Poseidon/`Hc` primitive, field encodings,
//! derivation functions, canonical serializations, and the tree/log/SMT
//! hashing helpers defined in the normative specification (`docs` repository,
//! `docs/specification.md` at tag `spec-v1.2`) §§1.1, 1.4–1.7, 2.2,
//! 2.5, 6.5. Does **not** replace the old-model types in `shared::` root or
//! `zkcoins_program::types`.

pub mod accumulator;
pub mod coinhist;
pub mod datastructures;
pub mod encoding;
pub mod error;
pub mod hashes;
pub mod network_params;
pub mod nflog;
/// V.11 boundary-suite fixtures + independent RFC-6962 reference (test support).
///
/// Consumed by `shared` integration tests and the `program-plonky2` gadget
/// differential suite so all three layers share one generator.
///
/// Gated behind the `test-fixtures` feature so a normal library build never
/// compiles or exports a second (non-normative) RFC-6962 derivation path.
#[cfg(feature = "test-fixtures")]
pub mod nflog_boundary;
pub mod serialize;
pub mod tags;
pub mod trees;

pub use accumulator::{
    ChainPosition, FoldOutcome, LookupResult, NfLogAccumulator, PublishedNullifier,
    SpendClassification,
};
pub use coinhist::{
    coinhist_empty_root, coinhist_empty_subtree_roots, coinhist_leaf_hash, coinhist_node_hash,
    coinhist_root_after_first_insert, CoinHistProof, CoinHistState, CoinHistTree,
};
pub use datastructures::{
    AccountState, Address, Coin, CoinTemplate, ProofData, SpendRecord, XOnlyPubKey,
    MAX_ACCOUNT_ASSETS,
};
pub use encoding::{
    digest_from_bytes, digest_to_bytes, encode_byte_string, encode_digest, encode_small_numeric,
    hc, HcInput, MAX_BYTE_STRING_LEN, MAX_SMALL_NUMERIC,
};
pub use error::SpecError;
pub use hashes::{
    account_state_hash, address, asset_id_v1, asset_id_v2, coin_identifier, derive_nav_rand,
    detect_tag, hash_proof_data, hkdf_sha256, name_hash, nav_commitment, network_id,
    network_id_mainnet, network_id_regtest, network_id_testnet, nk_commit, npk_commit, nullifier,
    terms_hash_v1, terms_hash_v2,
};
pub use network_params::NetworkParams;
pub use nflog::{
    consistency_proof, inclusion_path, nflog_empty, nflog_leaf_hash, nflog_mth, nflog_node_hash,
    nflog_root, verify_consistency, verify_inclusion, Nav, NfLogEntry,
};
pub use serialize::{
    deserialize_coin, deserialize_proof_data, deserialize_spend_record, parse_account_state,
    serialize_account_state, serialize_coin, serialize_proof_data, serialize_spend_record,
};
pub use tags::*;
pub use trees::{empty_leaf_hash, leaf_hash, merkle_root, node_hash, TreeKind};

// Re-export the hash/digest primitives used throughout this module so
// callers don't need a second import path for the same types.
// Digest encoding lives in `encoding` (canonical §1.7.1); HashDigest /
// ZERO_HASH remain type aliases / constants from the program crate.
pub use zkcoins_program::hash::{HashDigest, ZERO_HASH};
pub use zkcoins_program::F;
