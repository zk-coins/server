//! Postgres load/store for the v1.1 StateEngine tables (migration 0019).
//!
//! All writes that replace the engine snapshot run in a single transaction so
//! a crash cannot leave NfLog entries without a matching nullifier index (or
//! accounts without their coin sets).

use anyhow::{bail, Context, Result};
use shared::spec_v1::{
    self as host, AccountState, Address, ChainPosition, Coin, HashDigest, NfLogEntry,
};
use sqlx::{PgPool, Postgres, Transaction};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::prover_bridge::{ComplianceProof, NavOpening, NullifierOpening};
use zkcoins_prover::state_engine::{AccountRecord, StateEngine, TrackedCoin};

use super::mode::{network_label, parse_network_label};

/// Serializable snapshot of one account for the DB layer.
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    pub owner: Address,
    pub state: AccountState,
    pub nk: [u8; 32],
    pub genesis_pubkey: [u8; 32],
    pub spendable: Vec<([u8; 32], TrackedCoin)>,
    pub spent_ids: Vec<[u8; 32]>,
    pub last_proof: Option<ComplianceProof>,
    pub last_nav_opening: Option<NavOpening>,
    pub last_nullifier: Option<NullifierOpening>,
    pub last_nullifier_pos: Option<u64>,
}

/// Full engine snapshot as read from / written to Postgres.
#[derive(Clone, Debug)]
pub struct EngineSnapshot {
    pub network: Network,
    pub activation_height: u64,
    pub tip_height: u64,
    pub fold_seq: u32,
    pub nflog: Vec<(ChainPosition, NfLogEntry)>,
    pub accounts: Vec<AccountSnapshot>,
}

impl EngineSnapshot {
    pub fn from_engine(engine: &StateEngine) -> Self {
        let accounts = engine
            .accounts()
            .map(|(owner, record)| AccountSnapshot {
                owner: *owner,
                state: record.state.clone(),
                nk: record.nk,
                genesis_pubkey: record.genesis_pubkey,
                spendable: record
                    .spendable
                    .iter()
                    .map(|(id, tracked)| (*id, tracked.clone()))
                    .collect(),
                spent_ids: record.spent_ids.iter().copied().collect(),
                last_proof: record.last_proof.clone(),
                last_nav_opening: record.last_nav_opening,
                last_nullifier: record.last_nullifier.clone(),
                last_nullifier_pos: record.last_nullifier_pos,
            })
            .collect();
        Self {
            network: engine.network(),
            activation_height: engine.activation_height(),
            tip_height: engine.tip_height(),
            fold_seq: engine.fold_seq(),
            nflog: engine.nflog_mirror(),
            accounts,
        }
    }

    pub fn into_engine(self) -> Result<StateEngine> {
        let mut records = Vec::with_capacity(self.accounts.len());
        for snap in self.accounts {
            records.push((snap.owner, snap.into_record()?));
        }
        StateEngine::from_persisted(
            self.network,
            self.activation_height,
            self.tip_height,
            self.fold_seq,
            self.nflog,
            records,
        )
    }
}

impl AccountSnapshot {
    fn into_record(self) -> Result<AccountRecord> {
        use std::collections::{BTreeMap, BTreeSet};

        let mut spendable: BTreeMap<[u8; 32], TrackedCoin> = BTreeMap::new();
        for (id, tracked) in self.spendable {
            if spendable.insert(id, tracked).is_some() {
                bail!(
                    "v11 account {}: duplicate spendable coin_id",
                    hex::encode(self.owner.0)
                );
            }
        }
        let spent_ids: BTreeSet<[u8; 32]> = self.spent_ids.into_iter().collect();
        for id in spendable.keys() {
            if spent_ids.contains(id) {
                bail!(
                    "v11 account {}: coin_id is both spendable and spent",
                    hex::encode(self.owner.0)
                );
            }
        }

        let mut leaves: BTreeMap<[u8; 32], host::CoinHistState> = BTreeMap::new();
        for id in &spent_ids {
            leaves.insert(*id, host::CoinHistState::Spent);
        }
        for id in spendable.keys() {
            leaves.insert(*id, host::CoinHistState::Admitted);
        }
        let coinhist = rebuild_coinhist(&leaves)?;
        ensure_coinhist_root(&coinhist, &self.state)?;

        Ok(AccountRecord {
            state: self.state,
            coinhist,
            nk: self.nk,
            genesis_pubkey: self.genesis_pubkey,
            spendable,
            spent_ids,
            last_proof: self.last_proof,
            last_nav_opening: self.last_nav_opening,
            last_nullifier: self.last_nullifier,
            last_nullifier_pos: self.last_nullifier_pos,
        })
    }
}

fn rebuild_coinhist(
    leaves: &std::collections::BTreeMap<[u8; 32], host::CoinHistState>,
) -> Result<host::CoinHistTree> {
    let mut hist = host::CoinHistTree::new();
    for (&id, &state) in leaves {
        match state {
            host::CoinHistState::Admitted => {
                hist.admit(id)
                    .map_err(|e| anyhow::anyhow!("rebuild coinhist admit: {e}"))?;
            }
            host::CoinHistState::Spent => {
                hist.admit(id)
                    .map_err(|e| anyhow::anyhow!("rebuild coinhist admit-before-spend: {e}"))?;
                hist.spend(id)
                    .map_err(|e| anyhow::anyhow!("rebuild coinhist spend: {e}"))?;
            }
            host::CoinHistState::Absent => {
                bail!("Absent must not appear in coinhist leaf map");
            }
        }
    }
    Ok(hist)
}

fn ensure_coinhist_root(coinhist: &host::CoinHistTree, state: &AccountState) -> Result<()> {
    let root = coinhist.root();
    if root != state.coin_history_root {
        bail!(
            "coinhist root after rebuild does not match AccountState.coin_history_root \
             (owner={})",
            hex::encode(state.owner.0)
        );
    }
    Ok(())
}

fn digest_bytes(d: &HashDigest) -> [u8; 32] {
    host::digest_to_bytes(d)
}

fn as_i64_u64(v: u64, field: &str) -> Result<i64> {
    i64::try_from(v).with_context(|| format!("{field}={v} does not fit in Postgres BIGINT"))
}

fn as_i64_u32(v: u32, field: &str) -> Result<i64> {
    // Always fits.
    let _ = field;
    Ok(i64::from(v))
}

fn u64_from_i64(v: i64, field: &str) -> Result<u64> {
    u64::try_from(v).with_context(|| format!("{field}={v} is negative"))
}

fn u32_from_i64(v: i64, field: &str) -> Result<u32> {
    u32::try_from(v).with_context(|| format!("{field}={v} is out of u32 range"))
}

fn fixed_32(bytes: &[u8], field: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .with_context(|| format!("{field} has length {}, expected 32", bytes.len()))
}

/// Load the full engine snapshot, or `None` if `v11_engine_meta` is empty
/// (fresh DB — caller must initialise).
pub async fn load_engine_snapshot(pool: &PgPool) -> Result<Option<EngineSnapshot>> {
    let meta: Option<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT network, activation_height, tip_height, fold_seq \
         FROM v11_engine_meta WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .context("load v11_engine_meta")?;

    let Some((network_s, activation_height, tip_height, fold_seq)) = meta else {
        return Ok(None);
    };

    let network = parse_network_label(&network_s).map_err(|e| anyhow::anyhow!(e))?;
    let activation_height = u64_from_i64(activation_height, "activation_height")?;
    let tip_height = u64_from_i64(tip_height, "tip_height")?;
    let fold_seq = u32_from_i64(fold_seq, "fold_seq")?;

    let nflog_rows: Vec<(i64, i64, i64, i64, i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT position, height, tx_index, vin_index, member_index, pk, r \
         FROM v11_nflog_entries ORDER BY position ASC",
    )
    .fetch_all(pool)
    .await
    .context("load v11_nflog_entries")?;

    let mut nflog = Vec::with_capacity(nflog_rows.len());
    for (i, (position, height, tx_index, vin_index, member_index, pk, r)) in
        nflog_rows.into_iter().enumerate()
    {
        let position = u64_from_i64(position, "nflog.position")?;
        if position != i as u64 {
            bail!(
                "v11_nflog_entries is not a dense 0..n sequence: expected position {i}, got {position}"
            );
        }
        nflog.push((
            ChainPosition {
                height: u64_from_i64(height, "nflog.height")?,
                tx_index: u32_from_i64(tx_index, "nflog.tx_index")?,
                vin_index: u32_from_i64(vin_index, "nflog.vin_index")?,
                member_index: u32_from_i64(member_index, "nflog.member_index")?,
            },
            NfLogEntry {
                pk: fixed_32(&pk, "nflog.pk")?,
                r: fixed_32(&r, "nflog.r")?,
            },
        ));
    }

    // Nullifier index must agree with the first-occurrence fold of the log.
    let index_rows: Vec<(Vec<u8>, i64, Vec<u8>)> =
        sqlx::query_as("SELECT pk, position, r FROM v11_nullifier_index")
            .fetch_all(pool)
            .await
            .context("load v11_nullifier_index")?;
    let mut expected_index: std::collections::BTreeMap<[u8; 32], (u64, [u8; 32])> =
        std::collections::BTreeMap::new();
    for (pos, (_chain_pos, entry)) in nflog.iter().enumerate() {
        // First occurrence only.
        expected_index
            .entry(entry.pk)
            .or_insert((pos as u64, entry.r));
    }
    if index_rows.len() != expected_index.len() {
        bail!(
            "v11_nullifier_index row count {} diverges from first-occurrence set size {}",
            index_rows.len(),
            expected_index.len()
        );
    }
    for (pk_b, pos, r_b) in index_rows {
        let pk = fixed_32(&pk_b, "nullifier_index.pk")?;
        let r = fixed_32(&r_b, "nullifier_index.r")?;
        let pos = u64_from_i64(pos, "nullifier_index.position")?;
        match expected_index.get(&pk) {
            Some(&(epos, er)) if epos == pos && er == r => {}
            Some(&(epos, er)) => bail!(
                "v11_nullifier_index for pk {} has (pos,r)=({pos},{}) but log first-occurrence is ({epos},{})",
                hex::encode(pk),
                hex::encode(r),
                hex::encode(er)
            ),
            None => bail!(
                "v11_nullifier_index has pk {} which is absent from the NfLog",
                hex::encode(pk)
            ),
        }
    }

    let account_rows: Vec<(
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Vec<u8>,
    )> = sqlx::query_as(
        "SELECT owner, account_state, nk, genesis_pubkey, last_proof, \
                last_nav_opening, last_nullifier, last_nullifier_pos, coin_history_root \
         FROM v11_accounts ORDER BY owner",
    )
    .fetch_all(pool)
    .await
    .context("load v11_accounts")?;

    let mut accounts = Vec::with_capacity(account_rows.len());
    for (
        owner_b,
        state_b,
        nk_b,
        genesis_b,
        last_proof_b,
        last_nav_b,
        last_nf_b,
        last_nf_pos,
        ch_root_b,
    ) in account_rows
    {
        let owner_bytes = fixed_32(&owner_b, "account.owner")?;
        let owner = Address(owner_bytes);
        let state: AccountState = bincode::deserialize(&state_b)
            .with_context(|| format!("deserialize AccountState for {}", hex::encode(owner_bytes)))?;
        if state.owner != owner {
            bail!(
                "AccountState.owner does not match v11_accounts.owner key for {}",
                hex::encode(owner_bytes)
            );
        }
        let expected_ch_root = fixed_32(&ch_root_b, "account.coin_history_root")?;
        if digest_bytes(&state.coin_history_root) != expected_ch_root {
            bail!(
                "v11_accounts.coin_history_root column disagrees with account_state for {}",
                hex::encode(owner_bytes)
            );
        }

        let spendable_rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, i32)> = sqlx::query_as(
            "SELECT coin_id, coin, creating_prev_ash, coin_index \
             FROM v11_spendable_coins WHERE owner = $1 ORDER BY coin_id",
        )
        .bind(&owner_b)
        .fetch_all(pool)
        .await
        .with_context(|| format!("load spendable for {}", hex::encode(owner_bytes)))?;

        let mut spendable = Vec::with_capacity(spendable_rows.len());
        for (coin_id_b, coin_b, ash_b, coin_index) in spendable_rows {
            let coin_id = fixed_32(&coin_id_b, "spendable.coin_id")?;
            let coin: Coin = bincode::deserialize(&coin_b).context("deserialize Coin")?;
            if host::digest_to_bytes(&coin.identifier) != coin_id {
                bail!(
                    "spendable coin_id column disagrees with Coin.identifier for owner {}",
                    hex::encode(owner_bytes)
                );
            }
            let creating_prev_ash = host::digest_from_bytes(&fixed_32(&ash_b, "creating_prev_ash")?)
                .map_err(|e| anyhow::anyhow!("creating_prev_ash: {e}"))?;
            if coin_index < 0 {
                bail!("spendable.coin_index is negative");
            }
            spendable.push((
                coin_id,
                TrackedCoin {
                    coin,
                    creating_prev_ash,
                    coin_index: coin_index as u32,
                },
            ));
        }

        let spent_rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT coin_id FROM v11_spent_coins WHERE owner = $1 ORDER BY coin_id")
                .bind(&owner_b)
                .fetch_all(pool)
                .await
                .with_context(|| format!("load spent for {}", hex::encode(owner_bytes)))?;
        let mut spent_ids = Vec::with_capacity(spent_rows.len());
        for (coin_id_b,) in spent_rows {
            spent_ids.push(fixed_32(&coin_id_b, "spent.coin_id")?);
        }

        let last_proof = match last_proof_b {
            None => None,
            Some(b) => Some(
                bincode::deserialize(&b)
                    .context("deserialize last ComplianceProof")?,
            ),
        };
        let last_nav_opening = match last_nav_b {
            None => None,
            Some(b) => Some(bincode::deserialize(&b).context("deserialize NavOpening")?),
        };
        let last_nullifier = match last_nf_b {
            None => None,
            Some(b) => Some(bincode::deserialize(&b).context("deserialize NullifierOpening")?),
        };
        let last_nullifier_pos = match last_nf_pos {
            None => None,
            Some(p) => Some(u64_from_i64(p, "last_nullifier_pos")?),
        };

        accounts.push(AccountSnapshot {
            owner,
            state,
            nk: fixed_32(&nk_b, "account.nk")?,
            genesis_pubkey: fixed_32(&genesis_b, "account.genesis_pubkey")?,
            spendable,
            spent_ids,
            last_proof,
            last_nav_opening,
            last_nullifier,
            last_nullifier_pos,
        });
    }

    Ok(Some(EngineSnapshot {
        network,
        activation_height,
        tip_height,
        fold_seq,
        nflog,
        accounts,
    }))
}

/// Atomically replace the entire v1.1 engine snapshot with `snap`.
///
/// Deletes previous rows and inserts the new set in one transaction so a
/// crash cannot leave a partial NfLog or orphaned coin rows.
pub async fn persist_engine_snapshot(pool: &PgPool, snap: &EngineSnapshot) -> Result<()> {
    let mut tx = pool.begin().await.context("begin v11 persist tx")?;
    clear_all(&mut tx).await?;
    write_all(&mut tx, snap).await?;
    tx.commit().await.context("commit v11 persist tx")?;
    Ok(())
}

async fn clear_all(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    // Children first (FK), then parents, then meta.
    sqlx::query("DELETE FROM v11_spendable_coins")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v11_spent_coins")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v11_accounts")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v11_nullifier_index")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v11_nflog_entries")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v11_engine_meta")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn write_all(tx: &mut Transaction<'_, Postgres>, snap: &EngineSnapshot) -> Result<()> {
    sqlx::query(
        "INSERT INTO v11_engine_meta \
         (id, network, activation_height, tip_height, fold_seq, updated_at) \
         VALUES (1, $1, $2, $3, $4, NOW())",
    )
    .bind(network_label(snap.network))
    .bind(as_i64_u64(snap.activation_height, "activation_height")?)
    .bind(as_i64_u64(snap.tip_height, "tip_height")?)
    .bind(as_i64_u32(snap.fold_seq, "fold_seq")?)
    .execute(&mut **tx)
    .await
    .context("insert v11_engine_meta")?;

    let mut first_occ: std::collections::BTreeMap<[u8; 32], (u64, [u8; 32])> =
        std::collections::BTreeMap::new();

    for (position, (chain_pos, entry)) in snap.nflog.iter().enumerate() {
        let position = position as u64;
        sqlx::query(
            "INSERT INTO v11_nflog_entries \
             (position, height, tx_index, vin_index, member_index, pk, r) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(as_i64_u64(position, "position")?)
        .bind(as_i64_u64(chain_pos.height, "height")?)
        .bind(as_i64_u32(chain_pos.tx_index, "tx_index")?)
        .bind(as_i64_u32(chain_pos.vin_index, "vin_index")?)
        .bind(as_i64_u32(chain_pos.member_index, "member_index")?)
        .bind(entry.pk.as_slice())
        .bind(entry.r.as_slice())
        .execute(&mut **tx)
        .await
        .with_context(|| format!("insert v11_nflog_entries position={position}"))?;

        first_occ.entry(entry.pk).or_insert((position, entry.r));
    }

    for (pk, (position, r)) in &first_occ {
        sqlx::query(
            "INSERT INTO v11_nullifier_index (pk, position, r) VALUES ($1, $2, $3)",
        )
        .bind(pk.as_slice())
        .bind(as_i64_u64(*position, "index.position")?)
        .bind(r.as_slice())
        .execute(&mut **tx)
        .await
        .with_context(|| format!("insert v11_nullifier_index pk={}", hex::encode(pk)))?;
    }

    for account in &snap.accounts {
        let state_bytes =
            bincode::serialize(&account.state).context("serialize AccountState")?;
        let last_proof = match &account.last_proof {
            None => None,
            Some(p) => Some(bincode::serialize(p).context("serialize ComplianceProof")?),
        };
        let last_nav = match &account.last_nav_opening {
            None => None,
            Some(n) => Some(bincode::serialize(n).context("serialize NavOpening")?),
        };
        let last_nf = match &account.last_nullifier {
            None => None,
            Some(n) => Some(bincode::serialize(n).context("serialize NullifierOpening")?),
        };
        let last_nf_pos = match account.last_nullifier_pos {
            None => None,
            Some(p) => Some(as_i64_u64(p, "last_nullifier_pos")?),
        };

        sqlx::query(
            "INSERT INTO v11_accounts \
             (owner, account_state, nk, genesis_pubkey, last_proof, last_nav_opening, \
              last_nullifier, last_nullifier_pos, coin_history_root, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())",
        )
        .bind(account.owner.0.as_slice())
        .bind(&state_bytes)
        .bind(account.nk.as_slice())
        .bind(account.genesis_pubkey.as_slice())
        .bind(last_proof.as_deref())
        .bind(last_nav.as_deref())
        .bind(last_nf.as_deref())
        .bind(last_nf_pos)
        .bind(digest_bytes(&account.state.coin_history_root).as_slice())
        .execute(&mut **tx)
        .await
        .with_context(|| {
            format!(
                "insert v11_accounts owner={}",
                hex::encode(account.owner.0)
            )
        })?;

        for (coin_id, tracked) in &account.spendable {
            let coin_bytes = bincode::serialize(&tracked.coin).context("serialize Coin")?;
            sqlx::query(
                "INSERT INTO v11_spendable_coins \
                 (owner, coin_id, coin, creating_prev_ash, coin_index) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(account.owner.0.as_slice())
            .bind(coin_id.as_slice())
            .bind(&coin_bytes)
            .bind(digest_bytes(&tracked.creating_prev_ash).as_slice())
            .bind(tracked.coin_index as i32)
            .execute(&mut **tx)
            .await
            .with_context(|| {
                format!(
                    "insert spendable owner={} coin={}",
                    hex::encode(account.owner.0),
                    hex::encode(coin_id)
                )
            })?;
        }

        for coin_id in &account.spent_ids {
            sqlx::query(
                "INSERT INTO v11_spent_coins (owner, coin_id) VALUES ($1, $2)",
            )
            .bind(account.owner.0.as_slice())
            .bind(coin_id.as_slice())
            .execute(&mut **tx)
            .await
            .with_context(|| {
                format!(
                    "insert spent owner={} coin={}",
                    hex::encode(account.owner.0),
                    hex::encode(coin_id)
                )
            })?;
        }
    }

    Ok(())
}
