//! Core data structures for spec v1.1 (§1.4, §1.5, §2.5).
//!
//! Fresh types — intentionally **not** aliases of the old-model
//! `Address`/`AccountState`/`Coin` in `shared` root or `zkcoins_program::types`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::SpecError;
use zkcoins_program::hash::HashDigest;

/// Maximum distinct non-zero `(asset_id, amount)` entries in an account (§2.5).
pub const MAX_ACCOUNT_ASSETS: usize = 32;

/// SHA-256-based account identity (`address = H(Pk₀ ‖ nk_commit)`, §1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 32]);

/// BIP-340 x-only public key (32 bytes) — not the old-model 33-byte compressed form.
pub type XOnlyPubKey = [u8; 32];

/// Account state as defined in §1.5 / §1.7.4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub owner: Address,
    pub nk_commit: HashDigest,
    /// KEY = canonical 32-byte `asset_id` (`digest_to_bytes`); BTreeMap keeps
    /// ascending byte order for §1.7.4. Zero amounts MUST NOT be stored.
    pub balances: BTreeMap<[u8; 32], u128>,
    pub current_pubkey: XOnlyPubKey,
    pub send_counter: u64,
    pub coin_history_root: HashDigest,
}

impl AccountState {
    /// Validate and construct an `AccountState`.
    ///
    /// Rejects `balances.len() > MAX_ACCOUNT_ASSETS` and any zero-amount entry.
    pub fn new(
        owner: Address,
        nk_commit: HashDigest,
        balances: BTreeMap<[u8; 32], u128>,
        current_pubkey: XOnlyPubKey,
        send_counter: u64,
        coin_history_root: HashDigest,
    ) -> Result<Self, SpecError> {
        if balances.len() > MAX_ACCOUNT_ASSETS {
            return Err(SpecError::TooManyBalances {
                count: balances.len(),
                max: MAX_ACCOUNT_ASSETS,
            });
        }
        for (&_aid, &amount) in &balances {
            if amount == 0 {
                return Err(SpecError::ZeroAmountBalance);
            }
        }
        Ok(Self {
            owner,
            nk_commit,
            balances,
            current_pubkey,
            send_counter,
            coin_history_root,
        })
    }
}

/// A coin with its committed identifier (§1.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    pub identifier: HashDigest,
    pub recipient: Address,
    pub amount: u128,
    pub asset_id: HashDigest,
}

/// Output template used at coin creation (no identifier yet).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinTemplate {
    pub recipient: Address,
    pub amount: u128,
    pub asset_id: HashDigest,
}

/// Public inputs of the per-account proof (§1.4).
///
/// `npk_commit` is a SHA-256 output, **not** a Poseidon `HashDigest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofData {
    pub new_account_state_hash: HashDigest,
    pub output_coins_root: HashDigest,
    pub input_nullifiers_root: HashDigest,
    pub coin_history_root: HashDigest,
    pub nav_commitment: HashDigest,
    pub npk_commit: [u8; 32],
}

/// Per-transition authorization record (§1.4 / §1.5).
///
/// Signing itself is out of scope for P1-A; only the type and its
/// serialize/parse are required here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendRecord {
    pub public_key: XOnlyPubKey,
    /// BIP-340 signature (64 bytes). Serde's derive only supports `[T; N]`
    /// for `N ≤ 32`, so this field uses a local helper (same pattern as
    /// `program-plonky2`'s `BigArray33`).
    #[serde(with = "BigArray64")]
    pub signature: [u8; 64],
}

/// Tiny helper module for `#[serde(with = "BigArray64")]` on `[u8; 64]`.
/// Mirrors `program-plonky2::types::BigArray33` — no extra dependency.
struct BigArray64;

impl BigArray64 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(64)?;
        for b in v.iter() {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("[u8; 64]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(64, V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkcoins_program::hash::ZERO_HASH;

    #[test]
    fn account_state_rejects_too_many_balances() {
        let mut balances = BTreeMap::new();
        for i in 0..(MAX_ACCOUNT_ASSETS + 1) {
            let mut key = [0u8; 32];
            key[31] = i as u8;
            balances.insert(key, 1);
        }
        let err = AccountState::new(
            Address([0u8; 32]),
            ZERO_HASH,
            balances,
            [0u8; 32],
            0,
            ZERO_HASH,
        )
        .unwrap_err();
        assert!(matches!(err, SpecError::TooManyBalances { .. }));
    }

    #[test]
    fn account_state_rejects_zero_amount() {
        let mut balances = BTreeMap::new();
        balances.insert([1u8; 32], 0);
        let err = AccountState::new(
            Address([0u8; 32]),
            ZERO_HASH,
            balances,
            [0u8; 32],
            0,
            ZERO_HASH,
        )
        .unwrap_err();
        assert_eq!(err, SpecError::ZeroAmountBalance);
    }
}
