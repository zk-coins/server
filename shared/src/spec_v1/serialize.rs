//! Canonical serialization / deserialization (§1.7.4, §1.4, §1.7.7).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use super::datastructures::{
    AccountState, Address, Coin, ProofData, SpendRecord, MAX_ACCOUNT_ASSETS,
};
use super::encoding::{digest_from_bytes, digest_to_bytes};
use super::error::SpecError;
use super::tags::ADDRESS_HRP;

// ---------------------------------------------------------------------------
// Coin — fixed 112 bytes
// ---------------------------------------------------------------------------

/// `identifier(32) ‖ recipient(32) ‖ amount_be16(16) ‖ asset_id(32)`.
pub fn serialize_coin(coin: &Coin) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[0..32].copy_from_slice(&digest_to_bytes(&coin.identifier));
    out[32..64].copy_from_slice(&coin.recipient.0);
    out[64..80].copy_from_slice(&coin.amount.to_be_bytes());
    out[80..112].copy_from_slice(&digest_to_bytes(&coin.asset_id));
    out
}

pub fn deserialize_coin(bytes: &[u8]) -> Result<Coin, SpecError> {
    if bytes.len() != 112 {
        return Err(SpecError::WrongLength {
            expected: 112,
            actual: bytes.len(),
        });
    }
    let mut id_b = [0u8; 32];
    id_b.copy_from_slice(&bytes[0..32]);
    let mut recip = [0u8; 32];
    recip.copy_from_slice(&bytes[32..64]);
    let mut amt_b = [0u8; 16];
    amt_b.copy_from_slice(&bytes[64..80]);
    let mut aid_b = [0u8; 32];
    aid_b.copy_from_slice(&bytes[80..112]);
    Ok(Coin {
        identifier: digest_from_bytes(&id_b)?,
        recipient: Address(recip),
        amount: u128::from_be_bytes(amt_b),
        asset_id: digest_from_bytes(&aid_b)?,
    })
}

// ---------------------------------------------------------------------------
// AccountState — variable length, prefix 140 + 48·n
// ---------------------------------------------------------------------------

/// Canonical `serialize(AccountState)` per §1.7.4.
///
/// Prefix is 140 bytes; each balance entry adds 48 bytes.
/// Returns `Err` if `balances.len() > MAX_ACCOUNT_ASSETS`.
pub fn serialize_account_state(state: &AccountState) -> Result<Vec<u8>, SpecError> {
    if state.balances.len() > MAX_ACCOUNT_ASSETS {
        return Err(SpecError::TooManyBalances {
            count: state.balances.len(),
            max: MAX_ACCOUNT_ASSETS,
        });
    }
    for (&_aid, &amount) in &state.balances {
        if amount == 0 {
            return Err(SpecError::ZeroAmountBalance);
        }
    }

    let n = state.balances.len();
    let mut out = Vec::with_capacity(140 + 48 * n);
    out.extend_from_slice(&state.owner.0);
    out.extend_from_slice(&digest_to_bytes(&state.nk_commit));
    out.extend_from_slice(&state.current_pubkey);
    out.extend_from_slice(&state.send_counter.to_be_bytes());
    out.extend_from_slice(&digest_to_bytes(&state.coin_history_root));
    out.extend_from_slice(&(n as u32).to_be_bytes());
    // BTreeMap iteration is ascending by key (asset_id byte order).
    for (asset_id, amount) in &state.balances {
        out.extend_from_slice(asset_id);
        out.extend_from_slice(&amount.to_be_bytes());
    }
    debug_assert_eq!(out.len(), 140 + 48 * n);
    Ok(out)
}

/// Inverse of `serialize_account_state`. Rejects wrong lengths and zero amounts.
pub fn parse_account_state(bytes: &[u8]) -> Result<AccountState, SpecError> {
    if bytes.len() < 140 {
        return Err(SpecError::WrongLength {
            expected: 140,
            actual: bytes.len(),
        });
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&bytes[0..32]);
    let mut nkc = [0u8; 32];
    nkc.copy_from_slice(&bytes[32..64]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[64..96]);
    let mut sc = [0u8; 8];
    sc.copy_from_slice(&bytes[96..104]);
    let mut chr = [0u8; 32];
    chr.copy_from_slice(&bytes[104..136]);
    let mut bc = [0u8; 4];
    bc.copy_from_slice(&bytes[136..140]);
    let count = u32::from_be_bytes(bc) as usize;
    if count > MAX_ACCOUNT_ASSETS {
        return Err(SpecError::TooManyBalances {
            count,
            max: MAX_ACCOUNT_ASSETS,
        });
    }
    let expected = 140 + 48 * count;
    if bytes.len() != expected {
        return Err(SpecError::WrongLength {
            expected,
            actual: bytes.len(),
        });
    }
    let mut balances = std::collections::BTreeMap::new();
    let mut off = 140;
    let mut prev_aid: Option<[u8; 32]> = None;
    for index in 0..count {
        let mut aid = [0u8; 32];
        aid.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let mut amt_b = [0u8; 16];
        amt_b.copy_from_slice(&bytes[off..off + 16]);
        off += 16;
        let amount = u128::from_be_bytes(amt_b);
        if amount == 0 {
            return Err(SpecError::ZeroAmountBalance);
        }
        // Wire order must be strictly ascending by asset_id (byte order) so
        // ash's preimage is canonical (§1.7.4). Also rejects duplicates.
        if let Some(prev) = prev_aid {
            if aid <= prev {
                return Err(SpecError::BalancesNotAscending { index });
            }
        }
        prev_aid = Some(aid);
        balances.insert(aid, amount);
    }
    AccountState::new(
        Address(owner),
        digest_from_bytes(&nkc)?,
        balances,
        pk,
        u64::from_be_bytes(sc),
        digest_from_bytes(&chr)?,
    )
}

// ---------------------------------------------------------------------------
// ProofData — fixed 192 bytes
// ---------------------------------------------------------------------------

/// Six 32-byte fields in §1.4 order.
pub fn serialize_proof_data(pd: &ProofData) -> [u8; 192] {
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&digest_to_bytes(&pd.new_account_state_hash));
    out[32..64].copy_from_slice(&digest_to_bytes(&pd.output_coins_root));
    out[64..96].copy_from_slice(&digest_to_bytes(&pd.input_nullifiers_root));
    out[96..128].copy_from_slice(&digest_to_bytes(&pd.coin_history_root));
    out[128..160].copy_from_slice(&digest_to_bytes(&pd.nav_commitment));
    out[160..192].copy_from_slice(&pd.npk_commit);
    out
}

pub fn deserialize_proof_data(bytes: &[u8]) -> Result<ProofData, SpecError> {
    if bytes.len() != 192 {
        return Err(SpecError::WrongLength {
            expected: 192,
            actual: bytes.len(),
        });
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes[0..32]);
    let mut b = [0u8; 32];
    b.copy_from_slice(&bytes[32..64]);
    let mut c = [0u8; 32];
    c.copy_from_slice(&bytes[64..96]);
    let mut d = [0u8; 32];
    d.copy_from_slice(&bytes[96..128]);
    let mut e = [0u8; 32];
    e.copy_from_slice(&bytes[128..160]);
    let mut f = [0u8; 32];
    f.copy_from_slice(&bytes[160..192]);
    Ok(ProofData {
        new_account_state_hash: digest_from_bytes(&a)?,
        output_coins_root: digest_from_bytes(&b)?,
        input_nullifiers_root: digest_from_bytes(&c)?,
        coin_history_root: digest_from_bytes(&d)?,
        nav_commitment: digest_from_bytes(&e)?,
        npk_commit: f,
    })
}

// ---------------------------------------------------------------------------
// SpendRecord — fixed 96 bytes
// ---------------------------------------------------------------------------

/// `public_key(32) ‖ signature(64)`.
pub fn serialize_spend_record(sr: &SpendRecord) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[0..32].copy_from_slice(&sr.public_key);
    out[32..96].copy_from_slice(&sr.signature);
    out
}

pub fn deserialize_spend_record(bytes: &[u8]) -> Result<SpendRecord, SpecError> {
    if bytes.len() != 96 {
        return Err(SpecError::WrongLength {
            expected: 96,
            actual: bytes.len(),
        });
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[0..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[32..96]);
    Ok(SpendRecord {
        public_key: pk,
        signature: sig,
    })
}

// ---------------------------------------------------------------------------
// Bech32m address encoding (§1.7.7)
// ---------------------------------------------------------------------------

impl Address {
    /// Encode as Bech32m with HRP `"zk"`. Does **not** enforce the 90-char BIP-173 limit.
    pub fn to_bech32m(&self) -> String {
        let hrp = Hrp::parse(ADDRESS_HRP).expect("HRP \"zk\" is valid");
        bech32::encode::<Bech32m>(hrp, &self.0).expect("32-byte payload always encodes")
    }

    /// Decode a Bech32m address. Rejects wrong HRP, non-32-byte payloads, and
    /// legacy Bech32 (non-m) checksums. Does **not** reject solely for
    /// exceeding 90 characters.
    pub fn from_bech32m(s: &str) -> Result<Self, SpecError> {
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| SpecError::Bech32DecodeError(e.to_string()))?;
        let hrp = checked.hrp();
        if hrp.as_str() != ADDRESS_HRP {
            return Err(SpecError::Bech32WrongHrp {
                expected: ADDRESS_HRP,
                actual: hrp.to_string(),
            });
        }
        let data: Vec<u8> = checked.byte_iter().collect();
        if data.len() != 32 {
            return Err(SpecError::WrongLength {
                expected: 32,
                actual: data.len(),
            });
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&data);
        Ok(Address(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_v1::hashes::{address, name_hash, nk_commit};
    use crate::spec_v1::{coinhist_empty_root, AccountState, MAX_ACCOUNT_ASSETS};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use zkcoins_program::hash::ZERO_HASH;

    fn sample_pk0() -> [u8; 32] {
        Sha256::digest(b"zkCoins/v1/test-vector/Pk0").into()
    }
    fn sample_pk1() -> [u8; 32] {
        Sha256::digest(b"zkCoins/v1/test-vector/Pk1").into()
    }
    fn sample_nk() -> [u8; 32] {
        Sha256::digest(b"zkCoins/v1/test-vector/nk").into()
    }

    #[test]
    fn spend_record_layout_v5() {
        let sr = SpendRecord {
            public_key: sample_pk1(),
            signature: [0u8; 64],
        };
        let bytes = serialize_spend_record(&sr);
        assert_eq!(bytes.len(), 96);
        assert_eq!(&bytes[0..32], &sample_pk1());
        assert_eq!(&bytes[32..96], &[0u8; 64]);
        let parsed = deserialize_spend_record(&bytes).unwrap();
        assert_eq!(parsed, sr);
        assert!(deserialize_spend_record(&bytes[..95]).is_err());
        let mut too_long = bytes.to_vec();
        too_long.push(0);
        assert!(deserialize_spend_record(&too_long).is_err());
    }

    #[test]
    fn account_state_layout_v3_structural() {
        let nkc = nk_commit(&sample_nk());
        let owner_bytes = address(&sample_pk0(), nkc);
        let mut balances = BTreeMap::new();
        balances.insert([0xABu8; 32], 1_000_000_000u128);
        let state = AccountState::new(
            Address(owner_bytes),
            nkc,
            balances,
            sample_pk1(),
            1,
            ZERO_HASH,
        )
        .unwrap();
        let ser = serialize_account_state(&state).unwrap();
        assert_eq!(ser.len(), 188); // 140 + 48
        assert_eq!(&ser[64..96], &sample_pk1());
        assert_eq!(&ser[96..104], &1u64.to_be_bytes());
        assert_eq!(&ser[136..140], &1u32.to_be_bytes());
        assert_eq!(&ser[172..188], &1_000_000_000u128.to_be_bytes());
        assert_eq!(
            hex::encode(&ser[172..188]),
            "0000000000000000000000003b9aca00"
        );
        assert_eq!(hex::encode(&ser[96..104]), "0000000000000001");
        assert_eq!(hex::encode(&ser[136..140]), "00000001");

        let empty = AccountState::new(
            Address(owner_bytes),
            nkc,
            BTreeMap::new(),
            sample_pk0(),
            0,
            coinhist_empty_root(),
        )
        .unwrap();
        assert_eq!(serialize_account_state(&empty).unwrap().len(), 140);
    }

    #[test]
    fn account_state_rejects_33_balances_on_serialize() {
        let mut balances = BTreeMap::new();
        for i in 0..=MAX_ACCOUNT_ASSETS {
            let mut k = [0u8; 32];
            k[31] = i as u8;
            balances.insert(k, 1);
        }
        assert!(AccountState::new(
            Address([0u8; 32]),
            ZERO_HASH,
            balances.clone(),
            [0u8; 32],
            0,
            ZERO_HASH,
        )
        .is_err());
        let bad = AccountState {
            owner: Address([0u8; 32]),
            nk_commit: ZERO_HASH,
            balances,
            current_pubkey: [0u8; 32],
            send_counter: 0,
            coin_history_root: ZERO_HASH,
        };
        assert!(matches!(
            serialize_account_state(&bad),
            Err(SpecError::TooManyBalances { .. })
        ));
    }

    #[test]
    fn name_hash_rejects_long() {
        assert!(name_hash(&vec![0u8; 256]).is_err());
    }

    #[test]
    fn address_bech32m_roundtrip_and_hrp_reject() {
        let nkc = nk_commit(&sample_nk());
        let addr = Address(address(&sample_pk0(), nkc));
        let enc = addr.to_bech32m();
        assert!(enc.starts_with("zk1"));
        let dec = Address::from_bech32m(&enc).unwrap();
        assert_eq!(dec, addr);

        let hrp = Hrp::parse("xy").unwrap();
        let wrong = bech32::encode::<Bech32m>(hrp, &addr.0).unwrap();
        assert!(matches!(
            Address::from_bech32m(&wrong),
            Err(SpecError::Bech32WrongHrp { .. })
        ));

        let hrp_zk = Hrp::parse("zk").unwrap();
        let short = bech32::encode::<Bech32m>(hrp_zk, &[]).unwrap();
        assert!(matches!(
            Address::from_bech32m(&short),
            Err(SpecError::WrongLength { .. })
        ));
    }

    #[test]
    fn coin_and_proof_data_roundtrip() {
        let coin = Coin {
            identifier: ZERO_HASH,
            recipient: Address([1u8; 32]),
            amount: 42,
            asset_id: ZERO_HASH,
        };
        let b = serialize_coin(&coin);
        assert_eq!(b.len(), 112);
        assert_eq!(deserialize_coin(&b).unwrap(), coin);

        let pd = ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [9u8; 32],
        };
        let pb = serialize_proof_data(&pd);
        assert_eq!(pb.len(), 192);
        assert_eq!(deserialize_proof_data(&pb).unwrap(), pd);
        assert!(deserialize_proof_data(&pb[..191]).is_err());
    }

    #[test]
    fn v6_nullifier_inscription_arithmetic() {
        // V.6 documentation-consistency (half-aggregated inscription sizes).
        // Per member: (Pk_i, R_i) = 2×32 = 64 bytes; shared s_agg = 32 bytes.
        // Body = (2*32)*m + 32 = 64*m + 32. At m=2: 160; + 42-byte header = 202.
        // Task text wrote `2*64*m + 32`; the numeric claim `== 202` matches
        // `2*32*m + 32` instead (see final report).
        let m = 2usize;
        let half_agg_body = 2 * 32 * m + 32;
        let total_with_header = 42 + half_agg_body;
        assert_eq!(half_agg_body, 160);
        assert_eq!(total_with_header, 202);
        // Raw single-nullifier body (Pk ‖ signature) = 96 bytes.
        assert_eq!(32 + 64, 96);
    }

    #[test]
    fn from_bech32m_rejects_legacy_bech32_checksum() {
        let hrp_zk = Hrp::parse("zk").unwrap();
        let legacy_encoded =
            bech32::encode::<bech32::Bech32>(hrp_zk, &[0u8; 32]).unwrap();
        // Checksum is valid Bech32 (non-m) with correct HRP and payload length,
        // but §1.7.7 requires Bech32m only.
        assert!(Address::from_bech32m(&legacy_encoded).is_err());
    }

    #[test]
    fn parse_account_state_rejects_descending_asset_ids() {
        let nkc = nk_commit(&sample_nk());
        let owner_bytes = address(&sample_pk0(), nkc);
        let mut balances = BTreeMap::new();
        balances.insert([0x01u8; 32], 100u128);
        balances.insert([0x02u8; 32], 200u128);
        let state = AccountState::new(
            Address(owner_bytes),
            nkc,
            balances,
            sample_pk1(),
            0,
            ZERO_HASH,
        )
        .unwrap();
        let mut ser = serialize_account_state(&state).unwrap();
        assert_eq!(ser.len(), 140 + 48 * 2);
        // Swap the two 48-byte balance entries in-place (start at offset 140)
        // to produce a descending-order wire message.
        let entry0 = ser[140..188].to_vec();
        let entry1 = ser[188..236].to_vec();
        ser[140..188].copy_from_slice(&entry1);
        ser[188..236].copy_from_slice(&entry0);
        assert!(matches!(
            parse_account_state(&ser),
            Err(SpecError::BalancesNotAscending { index: 1 })
        ));
    }
}
