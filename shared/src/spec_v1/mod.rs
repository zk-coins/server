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
pub mod bootstrap_manifest;
pub mod bundle;
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
pub mod note_encryption;
pub mod serialize;
pub mod tags;
pub mod trees;

pub use accumulator::{
    ChainPosition, FoldOutcome, LookupResult, NfLogAccumulator, PublishedNullifier,
    SpendClassification,
};
pub use bootstrap_manifest::{
    bootstrap_message, deserialize as deserialize_bootstrap_manifest, manifest_id,
    serialize as serialize_bootstrap_manifest, sign_and_serialize_bootstrap_manifest,
    sign_bootstrap_manifest, verify_bootstrap_manifest, BootstrapManifestBody, BootstrapManifestV1,
    ManifestClock, SignBootstrapManifest, VerifyBootstrapManifest, BMF1_MAGIC, BMF1_VERSION,
    BOOTSTRAP_PROTOCOL_VERSION, MAX_BOOTSTRAP_URL_LEN,
};
pub use bundle::{
    deserialize_blob_locator_set, deserialize_coin_proof, deserialize_issuance_terms,
    deserialize_self_delivery_record, serialize_blob_locator_set, serialize_coin_proof,
    serialize_issuance_terms, serialize_self_delivery_record, BlobLocatorSet, BlockAnchor,
    CoinProof, CreatingNullifier, IssuanceTerms, NavOpening, OutputRef, RecordKind,
    SelfDeliveryRecordV1, COIN_WIRE_LEN, MAX_ASSET_NAME_LEN, MAX_BLOB_HOLDERS, MAX_HOLDER_URL_LEN,
    PROOF_DATA_WIRE_LEN, SDR1_MAGIC, SDR1_VERSION,
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
pub use error::{BootstrapStringField, BootstrapUrlKind};
pub use hashes::{
    account_state_hash, address, asset_id_v1, asset_id_v2, coin_identifier, derive_nav_rand,
    detect_tag, hash_proof_data, hkdf_sha256, name_consent_preimage, name_hash, name_message,
    nav_commitment, network_id, network_id_mainnet, network_id_regtest, network_id_testnet,
    nk_commit, normalize_name, npk_commit, nullifier, terms_hash_v1, terms_hash_v2,
};
pub use network_params::NetworkParams;
pub use nflog::{
    consistency_proof, inclusion_path, nflog_empty, nflog_leaf_hash, nflog_mth, nflog_node_hash,
    nflog_root, verify_consistency, verify_inclusion, Nav, NfLogEntry,
};
pub use note_encryption::{
    base64url_decode_no_pad, base64url_encode_no_pad, derive_blob_key, derive_note_key,
    derive_out_key, ecdh_shared_x, envelope_open, envelope_seal, parse_scalar, parse_xonly,
    shared_secret_receiver, shared_secret_sender, xonly_pubkey, zbe_open, zbe_seal,
    COIN_CIPHERTEXT_LEN, ENVELOPE_LABEL_COIN, ENVELOPE_LABEL_K_TX, ENVELOPE_PREFIX,
    OUT_CIPHERTEXT_LEN, ZBE_CHUNK, ZBE_MAGIC,
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
