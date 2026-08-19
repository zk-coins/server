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
    use std::collections::{HashMap, HashSet};
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

    #[test]
    fn address_eq_hash_clone_copy_debug_bincode() {
        let a = Address([0x11; 32]);
        let b = Address([0x11; 32]);
        let c = Address([0x22; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&a));
        assert!(!set.contains(&c));

        let mut map = HashMap::new();
        map.insert(a, 1u32);
        map.insert(c, 2u32);
        assert_eq!(map.get(&a), Some(&1));
        assert_eq!(map.get(&c), Some(&2));

        let cloned = a.clone();
        assert_eq!(cloned, a);
        let copied: Address = a;
        assert_eq!(copied, a);

        let debug = format!("{:?}", a);
        assert!(debug.contains("Address"));

        let encoded = bincode::serialize(&a).expect("bincode serialize Address");
        let decoded: Address = bincode::deserialize(&encoded).expect("bincode deserialize Address");
        assert_eq!(decoded, a);
    }

    #[test]
    fn account_state_new_happy_path() {
        let owner = Address([0x01; 32]);
        let mut balances = BTreeMap::new();
        balances.insert([0x10; 32], 100u128);
        balances.insert([0x20; 32], 200u128);
        balances.insert([0x30; 32], 300u128);
        let pubkey = [0xab; 32];
        let state = AccountState::new(owner, ZERO_HASH, balances.clone(), pubkey, 7, ZERO_HASH)
            .expect("valid balances must be accepted");
        assert_eq!(state.owner, owner);
        assert_eq!(state.nk_commit, ZERO_HASH);
        assert_eq!(state.balances, balances);
        assert_eq!(state.current_pubkey, pubkey);
        assert_eq!(state.send_counter, 7);
        assert_eq!(state.coin_history_root, ZERO_HASH);

        let expected = AccountState {
            owner,
            nk_commit: ZERO_HASH,
            balances,
            current_pubkey: pubkey,
            send_counter: 7,
            coin_history_root: ZERO_HASH,
        };
        assert_eq!(state, expected);
    }

    #[test]
    fn account_state_accepts_exactly_max_assets() {
        let mut balances = BTreeMap::new();
        for i in 0..MAX_ACCOUNT_ASSETS {
            let mut key = [0u8; 32];
            key[31] = i as u8;
            balances.insert(key, (i as u128) + 1);
        }
        assert_eq!(balances.len(), MAX_ACCOUNT_ASSETS);
        let state = AccountState::new(
            Address([0u8; 32]),
            ZERO_HASH,
            balances.clone(),
            [0u8; 32],
            0,
            ZERO_HASH,
        )
        .expect("exactly MAX_ACCOUNT_ASSETS must be accepted (len > max, not >=)");
        assert_eq!(state.balances.len(), MAX_ACCOUNT_ASSETS);
        assert_eq!(state.balances, balances);
    }

    #[test]
    fn account_state_bincode_roundtrip() {
        let mut balances = BTreeMap::new();
        balances.insert([0xaa; 32], 42u128);
        balances.insert([0xbb; 32], 99u128);
        let state = AccountState::new(
            Address([0x55; 32]),
            ZERO_HASH,
            balances,
            [0xcc; 32],
            123,
            ZERO_HASH,
        )
        .expect("construct");
        let encoded = bincode::serialize(&state).expect("bincode serialize AccountState");
        let decoded: AccountState =
            bincode::deserialize(&encoded).expect("bincode deserialize AccountState");
        assert_eq!(decoded, state);
    }

    #[test]
    fn big_array64_expecting_on_short_seq() {
        // Visitor::expecting is invoked via invalid_length when the seq ends
        // before 64 elements (private BigArray64 helper, reachable from tests).
        use serde::de::value::{Error as ValueError, SeqDeserializer};
        let short = [0u8; 63];
        let de = SeqDeserializer::<_, ValueError>::new(short.into_iter());
        let err = BigArray64::deserialize(de).expect_err("63 elements");
        let msg = err.to_string();
        assert!(
            msg.contains("[u8; 64]") || msg.contains("invalid length"),
            "expecting() message should surface, got {msg}"
        );
    }

    #[test]
    fn coin_eq_clone_debug_bincode() {
        let coin = Coin {
            identifier: ZERO_HASH,
            recipient: Address([0x01; 32]),
            amount: 1000,
            asset_id: ZERO_HASH,
        };
        let same = coin.clone();
        assert_eq!(coin, same);
        let other = Coin {
            identifier: ZERO_HASH,
            recipient: Address([0x02; 32]),
            amount: 1000,
            asset_id: ZERO_HASH,
        };
        assert_ne!(coin, other);
        let debug = format!("{:?}", coin);
        assert!(debug.contains("Coin"));
        let encoded = bincode::serialize(&coin).expect("bincode serialize Coin");
        let decoded: Coin = bincode::deserialize(&encoded).expect("bincode deserialize Coin");
        assert_eq!(decoded, coin);
    }

    #[test]
    fn coin_template_eq_clone_debug_bincode() {
        let tmpl = CoinTemplate {
            recipient: Address([0x03; 32]),
            amount: 500,
            asset_id: ZERO_HASH,
        };
        let same = tmpl.clone();
        assert_eq!(tmpl, same);
        let other = CoinTemplate {
            recipient: Address([0x03; 32]),
            amount: 501,
            asset_id: ZERO_HASH,
        };
        assert_ne!(tmpl, other);
        let debug = format!("{:?}", tmpl);
        assert!(debug.contains("CoinTemplate"));
        let encoded = bincode::serialize(&tmpl).expect("bincode serialize CoinTemplate");
        let decoded: CoinTemplate =
            bincode::deserialize(&encoded).expect("bincode deserialize CoinTemplate");
        assert_eq!(decoded, tmpl);
    }

    #[test]
    fn proof_data_eq_clone_debug_bincode() {
        let proof = ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0xde; 32],
        };
        let same = proof.clone();
        assert_eq!(proof, same);
        let other = ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0xff; 32],
        };
        assert_ne!(proof, other);
        let debug = format!("{:?}", proof);
        assert!(debug.contains("ProofData"));
        let encoded = bincode::serialize(&proof).expect("bincode serialize ProofData");
        let decoded: ProofData =
            bincode::deserialize(&encoded).expect("bincode deserialize ProofData");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn spend_record_bincode_roundtrip_full_signature() {
        let mut signature = [0u8; 64];
        for (i, slot) in signature.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let record = SpendRecord {
            public_key: [0x42; 32],
            signature,
        };
        let same = record.clone();
        assert_eq!(record, same);
        let other = SpendRecord {
            public_key: [0x42; 32],
            signature: [0u8; 64],
        };
        assert_ne!(record, other);
        let debug = format!("{:?}", record);
        assert!(debug.contains("SpendRecord"));

        let encoded = bincode::serialize(&record).expect("bincode serialize SpendRecord");
        let decoded: SpendRecord =
            bincode::deserialize(&encoded).expect("bincode deserialize SpendRecord");
        assert_eq!(decoded, record);
        assert_eq!(decoded.public_key, [0x42; 32]);
        assert_eq!(decoded.signature, signature);
        for i in 0..64 {
            assert_eq!(decoded.signature[i], i as u8);
        }
    }

    #[test]
    fn spend_record_bincode_rejects_truncated_signature() {
        // Serialize a full SpendRecord, then truncate the buffer so the
        // BigArray64 Visitor::visit_seq loop hits ok_or_else(invalid_length).
        let record = SpendRecord {
            public_key: [0x11; 32],
            signature: [0x22; 64],
        };
        let mut encoded = bincode::serialize(&record).expect("serialize full");
        // public_key is 32 bytes; signature is 64 element-bytes under bincode tuple.
        // Truncating below full length must fail deserialize.
        assert!(encoded.len() > 32);
        encoded.truncate(encoded.len() - 8);
        let result: Result<SpendRecord, _> = bincode::deserialize(&encoded);
        assert!(
            result.is_err(),
            "truncated SpendRecord must fail deserialize"
        );
    }
}
