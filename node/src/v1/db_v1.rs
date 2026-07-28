//! Postgres load/store for the v1.1 StateEngine tables (migration 0019).
//!
//! All writes that replace the engine snapshot run in a single transaction so
//! a crash cannot leave NfLog entries without a matching nullifier index (or
//! accounts without their coin sets). Loads use an equivalent transactional
//! snapshot so a concurrent write cannot produce a mixed old/new state.

use anyhow::{bail, ensure, Context, Result};
use shared::spec_v1::{
    self as host, AccountState, Address, ChainPosition, Coin, HashDigest, NfLogEntry,
};
use sqlx::{PgPool, Postgres, Transaction};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::prover_bridge::{
    ComplianceProof, NavOpening, NullifierOpening, ProverBridge,
};
use zkcoins_prover::state_engine::{AccountRecord, OpSecret, StateEngine, TrackedCoin};

use super::mode::{network_label, parse_network_label};
use super::separation::{require_stack_mode_for_update, ScanStackMode};

/// Serializable snapshot of one account for the DB layer.
///
/// `op_secret` is redacted in Debug (via [`OpSecret`]); it must never appear
/// in logs or response bodies.
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    pub owner: Address,
    pub state: AccountState,
    pub nk: [u8; 32],
    /// Operational nav-rand secret. `None` only for pre-0023 rows; use refuses.
    pub op_secret: Option<OpSecret>,
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
    /// Bitcoin block hash at `tip_height` (consensus byte order). All-zero
    /// means "no tip yet" (fresh engine). Required so equal-height forks are
    /// distinguishable on reload.
    pub tip_hash: [u8; 32],
    pub fold_seq: u32,
    pub nflog: Vec<(ChainPosition, NfLogEntry)>,
    pub accounts: Vec<AccountSnapshot>,
}

impl EngineSnapshot {
    /// Snapshot an engine together with its tip block hash.
    ///
    /// Stage 1: the hash is not yet on [`StateEngine`]; callers that persist
    /// after a load must pass the reloaded hash so it is not zeroed.
    pub fn from_engine_with_tip_hash(engine: &StateEngine, tip_hash: [u8; 32]) -> Self {
        let accounts = engine
            .accounts()
            .map(|(owner, record)| AccountSnapshot {
                owner: *owner,
                state: record.state.clone(),
                nk: record.nk,
                op_secret: record.op_secret,
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
            tip_hash,
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
                    "v1 account {}: duplicate spendable coin_id",
                    hex::encode(self.owner.0)
                );
            }
        }
        let spent_ids: BTreeSet<[u8; 32]> = self.spent_ids.into_iter().collect();
        for id in spendable.keys() {
            if spent_ids.contains(id) {
                bail!(
                    "v1 account {}: coin_id is both spendable and spent",
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
            op_secret: self.op_secret,
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

/// Count any row across the v1.1 tables (meta + data). Used to distinguish a
/// genuinely empty database from an inconsistent one that lost its meta row.
async fn count_any_v1_rows(tx: &mut Transaction<'_, Postgres>) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM v1_engine_meta) \
          + (SELECT COUNT(*) FROM v1_nflog_entries) \
          + (SELECT COUNT(*) FROM v1_nullifier_index) \
          + (SELECT COUNT(*) FROM v1_accounts) \
          + (SELECT COUNT(*) FROM v1_spendable_coins) \
          + (SELECT COUNT(*) FROM v1_spent_coins) \
          + (SELECT COUNT(*) FROM v1_pending_publishes)",
    )
    .fetch_one(&mut **tx)
    .await
    .context("count v1 rows for empty/inconsistent check")?;
    Ok(n)
}

/// Load the full engine snapshot, or `None` if every v1.1 table is empty
/// (fresh DB — caller must initialise).
///
/// ## Snapshot consistency
///
/// The load runs inside a single Postgres transaction at **REPEATABLE READ**.
/// Postgres RR is snapshot isolation: all statements see the database as of
/// the transaction's first query. That is sufficient here because the write
/// path replaces every v1 table in one committing transaction — a concurrent
/// reader therefore observes either the complete pre-write state or the
/// complete post-write state, never a mixture of old meta with new leaves
/// (or empty tables mid-clear). Read Committed would re-snapshot per
/// statement and could interleave those commits.
///
/// ## Empty vs inconsistent
///
/// - No meta row **and** no other v1 rows → `Ok(None)` (genuinely empty).
/// - No meta row **but** other v1 data exists → `Err` (inconsistent DB).
/// - Meta present → load the full snapshot (data tables may be empty).
pub async fn load_engine_snapshot(pool: &PgPool) -> Result<Option<EngineSnapshot>> {
    let mut tx = pool.begin().await.context("begin v1 load tx")?;
    // REPEATABLE READ = snapshot isolation in Postgres: one MVCC snapshot for
    // the whole transaction. Must be the first statement after BEGIN.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .context("set v1 load isolation to REPEATABLE READ")?;

    let meta: Option<(String, i64, i64, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT network, activation_height, tip_height, tip_hash, fold_seq \
         FROM v1_engine_meta WHERE id = 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .context("load v1_engine_meta")?;

    let Some((network_s, activation_height, tip_height, tip_hash_b, fold_seq)) = meta else {
        let n = count_any_v1_rows(&mut tx).await?;
        if n != 0 {
            // Roll back before returning; the transaction is not needed further.
            tx.rollback()
                .await
                .context("rollback v1 load tx after inconsistent meta")?;
            bail!(
                "v1_engine_meta is missing but {n} other v1 row(s) exist — \
                 the database is inconsistent (refusing to load as an empty engine; \
                 no silent fall-back)"
            );
        }
        tx.commit().await.context("commit empty v1 load tx")?;
        return Ok(None);
    };

    let network = parse_network_label(&network_s).map_err(|e| anyhow::anyhow!(e))?;
    let activation_height = u64_from_i64(activation_height, "activation_height")?;
    let tip_height = u64_from_i64(tip_height, "tip_height")?;
    let tip_hash = fixed_32(&tip_hash_b, "tip_hash")?;
    let fold_seq = u32_from_i64(fold_seq, "fold_seq")?;

    let nflog_rows: Vec<(i64, i64, i64, i64, i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT position, height, tx_index, vin_index, member_index, pk, r \
         FROM v1_nflog_entries ORDER BY position ASC",
    )
    .fetch_all(&mut *tx)
    .await
    .context("load v1_nflog_entries")?;

    let mut nflog = Vec::with_capacity(nflog_rows.len());
    for (i, (position, height, tx_index, vin_index, member_index, pk, r)) in
        nflog_rows.into_iter().enumerate()
    {
        let position = u64_from_i64(position, "nflog.position")?;
        if position != i as u64 {
            bail!(
                "v1_nflog_entries is not a dense 0..n sequence: expected position {i}, got {position}"
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
        sqlx::query_as("SELECT pk, position, r FROM v1_nullifier_index")
            .fetch_all(&mut *tx)
            .await
            .context("load v1_nullifier_index")?;
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
            "v1_nullifier_index row count {} diverges from first-occurrence set size {}",
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
                "v1_nullifier_index for pk {} has (pos,r)=({pos},{}) but log first-occurrence is ({epos},{})",
                hex::encode(pk),
                hex::encode(r),
                hex::encode(er)
            ),
            None => bail!(
                "v1_nullifier_index has pk {} which is absent from the NfLog",
                hex::encode(pk)
            ),
        }
    }

    let account_rows: Vec<(
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Vec<u8>,
    )> = sqlx::query_as(
        "SELECT owner, account_state, nk, op_secret, genesis_pubkey, last_proof, \
                last_nav_opening, last_nullifier, last_nullifier_pos, coin_history_root \
         FROM v1_accounts ORDER BY owner",
    )
    .fetch_all(&mut *tx)
    .await
    .context("load v1_accounts")?;

    let mut accounts = Vec::with_capacity(account_rows.len());
    for (
        owner_b,
        state_b,
        nk_b,
        op_secret_b,
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
        let state: AccountState = bincode::deserialize(&state_b).with_context(|| {
            format!("deserialize AccountState for {}", hex::encode(owner_bytes))
        })?;
        if state.owner != owner {
            bail!(
                "AccountState.owner does not match v1_accounts.owner key for {}",
                hex::encode(owner_bytes)
            );
        }
        let expected_ch_root = fixed_32(&ch_root_b, "account.coin_history_root")?;
        if digest_bytes(&state.coin_history_root) != expected_ch_root {
            bail!(
                "v1_accounts.coin_history_root column disagrees with account_state for {}",
                hex::encode(owner_bytes)
            );
        }

        let spendable_rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, i32)> = sqlx::query_as(
            "SELECT coin_id, coin, creating_prev_ash, coin_index \
             FROM v1_spendable_coins WHERE owner = $1 ORDER BY coin_id",
        )
        .bind(&owner_b)
        .fetch_all(&mut *tx)
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
            let creating_prev_ash =
                host::digest_from_bytes(&fixed_32(&ash_b, "creating_prev_ash")?)
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
            sqlx::query_as("SELECT coin_id FROM v1_spent_coins WHERE owner = $1 ORDER BY coin_id")
                .bind(&owner_b)
                .fetch_all(&mut *tx)
                .await
                .with_context(|| format!("load spent for {}", hex::encode(owner_bytes)))?;
        let mut spent_ids = Vec::with_capacity(spent_rows.len());
        for (coin_id_b,) in spent_rows {
            spent_ids.push(fixed_32(&coin_id_b, "spent.coin_id")?);
        }

        // Stage 3: last_proof must be bound to circuit C identity. Raw
        // bincode of a well-formed *legacy* Proof (same type alias, wrong
        // circuit) must not become prev_proof. Uses ProverBridge's
        // construction-time pin / cyclic verifier-data check — not a
        // parallel mechanism.
        let last_proof = match last_proof_b {
            None => None,
            Some(b) => Some(
                ProverBridge::new(network)
                    .bind_loaded_prev_proof(&b)
                    .with_context(|| {
                        format!(
                            "v1_accounts.last_proof for owner {} failed circuit-C identity bind                              (refusing as prev_proof)",
                            hex::encode(owner_bytes)
                        )
                    })?,
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

        let op_secret = match op_secret_b {
            None => None,
            Some(b) => Some(OpSecret::from_account_row_bytea(fixed_32(
                &b,
                "account.op_secret",
            )?)),
        };

        accounts.push(AccountSnapshot {
            owner,
            state,
            nk: fixed_32(&nk_b, "account.nk")?,
            op_secret,
            genesis_pubkey: fixed_32(&genesis_b, "account.genesis_pubkey")?,
            spendable,
            spent_ids,
            last_proof,
            last_nav_opening,
            last_nullifier,
            last_nullifier_pos,
        });
    }

    tx.commit().await.context("commit v1 load tx")?;

    Ok(Some(EngineSnapshot {
        network,
        activation_height,
        tip_height,
        tip_hash,
        fold_seq,
        nflog,
        accounts,
    }))
}

/// Atomically replace the entire v1.1 engine snapshot with `snap`.
///
/// Deletes previous rows and inserts the new set in one transaction so a
/// crash cannot leave a partial NfLog or orphaned coin rows.
///
/// ## Stack capability (transactional)
///
/// The first statement locks `stack_scan_mode` with `SELECT … FOR UPDATE`
/// and requires mode `v1`. A missing or mismatching marker aborts the
/// transaction before any v1.1 table is touched. This is the binding
/// capability check: a process-local boot pin alone cannot close the
/// window between an advisory check and a later write.
/// **Crate-private durable-write sink.** Downstream durable engine writes
/// go through receive / scan orchestration only.
pub(crate) async fn persist_engine_snapshot(
    pool: &PgPool,
    snap: &EngineSnapshot,
) -> Result<()> {
    let mut tx = pool.begin().await.context("begin v1 persist tx")?;
    require_stack_mode_for_update(&mut tx, ScanStackMode::V1)
        .await
        .context("v1 persist: stack_scan_mode capability check")?;
    clear_all(&mut tx).await?;
    write_all(&mut tx, snap).await?;
    tx.commit().await.context("commit v1 persist tx")?;
    Ok(())
}

/// Atomically persist the engine snapshot **and** a `members_ready` rebroadcast
/// intent in one transaction.
///
/// Closes the crash window where the account is advanced on disk but the
/// Schnorr `s` / BatchMember fields are not yet durable — that row was
/// previously unrecoverable. Either both land or neither does.
/// **Crate-private durable-write sink** (engine + members_ready intent).
///
/// Receive-path / non-job writers use this unfenced form. The job finalise
/// path **must** use
/// [`persist_engine_with_pending_members_ready_if_finalise_fence`] so a stale
/// claim epoch cannot advance the engine after reclaim.
pub(crate) async fn persist_engine_with_pending_members_ready(
    pool: &PgPool,
    snap: &EngineSnapshot,
    owner: Address,
    pk: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    r_prime: [u8; 32],
    build_tip_height: u32,
    build_tip_hash: [u8; 32],
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin engine+members_ready persist tx")?;
    require_stack_mode_for_update(&mut tx, ScanStackMode::V1)
        .await
        .context("engine+members_ready persist: stack_scan_mode capability check")?;
    clear_all(&mut tx).await?;
    write_all(&mut tx, snap).await?;
    insert_members_ready_row(
        &mut tx,
        owner,
        pk,
        r,
        s,
        r_prime,
        build_tip_height,
        build_tip_hash,
    )
    .await?;
    tx.commit()
        .await
        .context("commit engine+members_ready persist tx")?;
    Ok(())
}

/// Job-path durable stage: same atomic engine + `members_ready` write as
/// [`persist_engine_with_pending_members_ready`], but only while the exclusive
/// finalise claim identified by `fence` is still current **and** the lease is
/// unexpired.
///
/// Returns `Ok(true)` if the write committed, `Ok(false)` if the fence/lease
/// check lost (no engine or `members_ready` rows written). Same fence predicate
/// as [`crate::job_store::JobStore::complete_if_finalise_owner`]: token + lease,
/// not owner identity alone.
///
/// The fence check and the engine write share one transaction so a reclaim
/// between check and commit cannot race the durable stage in.
pub(crate) async fn persist_engine_with_pending_members_ready_if_finalise_fence(
    pool: &PgPool,
    snap: &EngineSnapshot,
    account_owner: Address,
    pk: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    r_prime: [u8; 32],
    build_tip_height: u32,
    build_tip_hash: [u8; 32],
    fence: crate::job_store::FinaliseFence,
) -> Result<bool> {
    use crate::job_store::FINALISE_CLAIM_PHASE;

    let mut tx = pool
        .begin()
        .await
        .context("begin fenced engine+members_ready persist tx")?;
    require_stack_mode_for_update(&mut tx, ScanStackMode::V1)
        .await
        .context("fenced engine+members_ready: stack_scan_mode capability check")?;

    // Lock the job row and refuse unless this acquisition epoch still holds.
    // FOR UPDATE serialises against concurrent reclaim / renew rewrites of
    // finalise_claim on the same row.
    let owner_text = fence.owner.to_string();
    let held = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM jobs \
         WHERE public_id = $1 \
           AND status = 'broadcasting' \
           AND phase = $2 \
           AND request_body #>> '{finalise_claim,owner}' = $3 \
           AND (request_body #>> '{finalise_claim,fence}')::bigint = $4 \
           AND (request_body #>> '{finalise_claim,lease_expires_at}') IS NOT NULL \
           AND (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz > NOW() \
         FOR UPDATE",
    )
    .bind(fence.job_id)
    .bind(FINALISE_CLAIM_PHASE)
    .bind(&owner_text)
    .bind(fence.fence)
    .fetch_optional(&mut *tx)
    .await
    .context("fenced engine+members_ready: claim fence check")?;

    if held.is_none() {
        // Explicit rollback so a lost fence never leaves an open write tx.
        tx.rollback()
            .await
            .context("rollback fenced engine+members_ready on fence loss")?;
        return Ok(false);
    }

    clear_all(&mut tx).await?;
    write_all(&mut tx, snap).await?;
    insert_members_ready_row(
        &mut tx,
        account_owner,
        pk,
        r,
        s,
        r_prime,
        build_tip_height,
        build_tip_hash,
    )
    .await?;
    tx.commit()
        .await
        .context("commit fenced engine+members_ready persist tx")?;
    Ok(true)
}

async fn insert_members_ready_row(
    tx: &mut Transaction<'_, Postgres>,
    owner: Address,
    pk: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    r_prime: [u8; 32],
    build_tip_height: u32,
    build_tip_hash: [u8; 32],
) -> Result<()> {
    sqlx::query(
        "INSERT INTO v1_pending_publishes \
         (pk, owner, r, s, r_prime, build_tip_height, build_tip_hash, \
          commit_tx, reveal_tx, commit_txid, reveal_txid, status, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, NULL, $8, NOW(), NOW())",
    )
    .bind(pk.as_slice())
    .bind(owner.0.as_slice())
    .bind(r.as_slice())
    .bind(s.as_slice())
    .bind(r_prime.as_slice())
    .bind(i64::from(build_tip_height))
    .bind(build_tip_hash.as_slice())
    .bind(PENDING_PUBLISH_MEMBERS_READY)
    .execute(&mut **tx)
    .await
    .with_context(|| {
        format!(
            "insert v1_pending_publishes members_ready (atomic with engine) pk={}",
            hex::encode(pk)
        )
    })?;
    Ok(())
}

async fn clear_all(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    // Children first (FK), then parents, then meta.
    sqlx::query("DELETE FROM v1_spendable_coins")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v1_spent_coins")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v1_accounts")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v1_nullifier_index")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v1_nflog_entries")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM v1_engine_meta")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn write_all(tx: &mut Transaction<'_, Postgres>, snap: &EngineSnapshot) -> Result<()> {
    sqlx::query(
        "INSERT INTO v1_engine_meta \
         (id, network, activation_height, tip_height, tip_hash, fold_seq, updated_at) \
         VALUES (1, $1, $2, $3, $4, $5, NOW())",
    )
    .bind(network_label(snap.network))
    .bind(as_i64_u64(snap.activation_height, "activation_height")?)
    .bind(as_i64_u64(snap.tip_height, "tip_height")?)
    .bind(snap.tip_hash.as_slice())
    .bind(as_i64_u32(snap.fold_seq, "fold_seq")?)
    .execute(&mut **tx)
    .await
    .context("insert v1_engine_meta")?;

    let mut first_occ: std::collections::BTreeMap<[u8; 32], (u64, [u8; 32])> =
        std::collections::BTreeMap::new();

    for (position, (chain_pos, entry)) in snap.nflog.iter().enumerate() {
        let position = position as u64;
        sqlx::query(
            "INSERT INTO v1_nflog_entries \
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
        .with_context(|| format!("insert v1_nflog_entries position={position}"))?;

        first_occ.entry(entry.pk).or_insert((position, entry.r));
    }

    for (pk, (position, r)) in &first_occ {
        sqlx::query("INSERT INTO v1_nullifier_index (pk, position, r) VALUES ($1, $2, $3)")
            .bind(pk.as_slice())
            .bind(as_i64_u64(*position, "index.position")?)
            .bind(r.as_slice())
            .execute(&mut **tx)
            .await
            .with_context(|| format!("insert v1_nullifier_index pk={}", hex::encode(pk)))?;
    }

    for account in &snap.accounts {
        let state_bytes = bincode::serialize(&account.state).context("serialize AccountState")?;
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

        let op_secret_bytes = account.op_secret.map(|s| s.to_account_row_bytea());
        sqlx::query(
            "INSERT INTO v1_accounts \
             (owner, account_state, nk, op_secret, genesis_pubkey, last_proof, last_nav_opening, \
              last_nullifier, last_nullifier_pos, coin_history_root, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())",
        )
        .bind(account.owner.0.as_slice())
        .bind(&state_bytes)
        .bind(account.nk.as_slice())
        .bind(op_secret_bytes.as_ref().map(|b| b.as_slice()))
        .bind(account.genesis_pubkey.as_slice())
        .bind(last_proof.as_deref())
        .bind(last_nav.as_deref())
        .bind(last_nf.as_deref())
        .bind(last_nf_pos)
        .bind(digest_bytes(&account.state.coin_history_root).as_slice())
        .execute(&mut **tx)
        .await
        .with_context(|| format!("insert v1_accounts owner={}", hex::encode(account.owner.0)))?;

        for (coin_id, tracked) in &account.spendable {
            let coin_bytes = bincode::serialize(&tracked.coin).context("serialize Coin")?;
            sqlx::query(
                "INSERT INTO v1_spendable_coins \
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
            sqlx::query("INSERT INTO v1_spent_coins (owner, coin_id) VALUES ($1, $2)")
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

// ---------------------------------------------------------------------------
// Pending nullifier-publish recovery (migration 0021)
// ---------------------------------------------------------------------------

/// Status labels for [`v1_pending_publishes`] (CHECK-constrained).
pub const PENDING_PUBLISH_MEMBERS_READY: &str = "members_ready";
pub const PENDING_PUBLISH_CONSTRUCTED: &str = "constructed";
pub const PENDING_PUBLISH_COMMIT_BROADCAST: &str = "commit_broadcast";
pub const PENDING_PUBLISH_REVEAL_BROADCAST: &str = "reveal_broadcast";
pub const PENDING_PUBLISH_COMPLETE: &str = "complete";
pub const PENDING_PUBLISH_FAILED: &str = "failed";

/// Durable rebroadcast intent for one account-state nullifier.
#[derive(Clone, Debug)]
pub struct PendingPublishRow {
    pub pk: [u8; 32],
    pub owner: Address,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub r_prime: [u8; 32],
    pub build_tip_height: u32,
    pub build_tip_hash: [u8; 32],
    pub commit_tx: Option<Vec<u8>>,
    pub reveal_tx: Option<Vec<u8>>,
    pub commit_txid: Option<[u8; 32]>,
    pub reveal_txid: Option<[u8; 32]>,
    pub status: String,
}

/// Insert `members_ready` row: Schnorr `s` + BatchMember fields durable,
/// no raw transactions yet.
///
/// **Crate-private durable-write sink.** Production receive uses the atomic
/// [`persist_engine_with_pending_members_ready`]; this insert remains for
/// crash-window fixtures that stage a row without rewriting the engine.
#[allow(dead_code)] // crate-test staging path
pub(crate) async fn insert_pending_publish_members_ready(
    pool: &PgPool,
    owner: Address,
    pk: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    r_prime: [u8; 32],
    build_tip_height: u32,
    build_tip_hash: [u8; 32],
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin insert pending publish members_ready")?;
    require_stack_mode_for_update(&mut tx, ScanStackMode::V1)
        .await
        .context("pending publish insert: stack_scan_mode capability check")?;
    sqlx::query(
        "INSERT INTO v1_pending_publishes \
         (pk, owner, r, s, r_prime, build_tip_height, build_tip_hash, \
          commit_tx, reveal_tx, commit_txid, reveal_txid, status, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, NULL, $8, NOW(), NOW())",
    )
    .bind(pk.as_slice())
    .bind(owner.0.as_slice())
    .bind(r.as_slice())
    .bind(s.as_slice())
    .bind(r_prime.as_slice())
    .bind(i64::from(build_tip_height))
    .bind(build_tip_hash.as_slice())
    .bind(PENDING_PUBLISH_MEMBERS_READY)
    .execute(&mut *tx)
    .await
    .with_context(|| {
        format!(
            "insert v1_pending_publishes members_ready pk={}",
            hex::encode(pk)
        )
    })?;
    tx.commit()
        .await
        .context("commit insert pending publish members_ready")?;
    Ok(())
}

/// Persist constructed commit/reveal pair and advance to `constructed`.
///
/// **Crate-private durable-write sink.**
pub(crate) async fn mark_pending_publish_constructed(
    pool: &PgPool,
    pk: [u8; 32],
    commit_tx: &[u8],
    reveal_tx: &[u8],
    commit_txid: [u8; 32],
    reveal_txid: [u8; 32],
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("begin mark pending publish constructed")?;
    require_stack_mode_for_update(&mut tx, ScanStackMode::V1)
        .await
        .context("pending publish constructed: stack_scan_mode capability check")?;
    let result = sqlx::query(
        "UPDATE v1_pending_publishes \
         SET commit_tx = $2, reveal_tx = $3, commit_txid = $4, reveal_txid = $5, \
             status = $6, updated_at = NOW() \
         WHERE pk = $1 AND status = $7",
    )
    .bind(pk.as_slice())
    .bind(commit_tx)
    .bind(reveal_tx)
    .bind(commit_txid.as_slice())
    .bind(reveal_txid.as_slice())
    .bind(PENDING_PUBLISH_CONSTRUCTED)
    .bind(PENDING_PUBLISH_MEMBERS_READY)
    .execute(&mut *tx)
    .await
    .context("update pending publish to constructed")?;
    ensure!(
        result.rows_affected() == 1,
        "mark_pending_publish_constructed: no members_ready row for pk={}",
        hex::encode(pk)
    );
    tx.commit()
        .await
        .context("commit mark pending publish constructed")?;
    Ok(())
}

/// Advance status after a successful commit (or reveal) broadcast.
///
/// **Crate-private durable-write sink.**
pub(crate) async fn mark_pending_publish_status(
    pool: &PgPool,
    pk: [u8; 32],
    from_status: &str,
    to_status: &str,
) -> Result<()> {
    ensure!(
        matches!(
            to_status,
            PENDING_PUBLISH_COMMIT_BROADCAST
                | PENDING_PUBLISH_REVEAL_BROADCAST
                | PENDING_PUBLISH_COMPLETE
                | PENDING_PUBLISH_FAILED
        ),
        "mark_pending_publish_status: invalid to_status={to_status}"
    );
    let mut tx = pool
        .begin()
        .await
        .context("begin mark pending publish status")?;
    require_stack_mode_for_update(&mut tx, ScanStackMode::V1)
        .await
        .context("pending publish status: stack_scan_mode capability check")?;
    let result = sqlx::query(
        "UPDATE v1_pending_publishes \
         SET status = $2, updated_at = NOW() \
         WHERE pk = $1 AND status = $3",
    )
    .bind(pk.as_slice())
    .bind(to_status)
    .bind(from_status)
    .execute(&mut *tx)
    .await
    .context("update pending publish status")?;
    ensure!(
        result.rows_affected() == 1,
        "mark_pending_publish_status: no row pk={} with status={from_status}",
        hex::encode(pk)
    );
    tx.commit()
        .await
        .context("commit mark pending publish status")?;
    Ok(())
}

/// Load one pending publish by Pk, or `None` if absent.
pub async fn load_pending_publish(pool: &PgPool, pk: [u8; 32]) -> Result<Option<PendingPublishRow>> {
    let row = sqlx::query(
        "SELECT pk, owner, r, s, r_prime, build_tip_height, build_tip_hash, \
                commit_tx, reveal_tx, commit_txid, reveal_txid, status \
         FROM v1_pending_publishes WHERE pk = $1",
    )
    .bind(pk.as_slice())
    .fetch_optional(pool)
    .await
    .context("load pending publish")?;
    let Some(row) = row else {
        return Ok(None);
    };
    use sqlx::Row;
    Ok(Some(PendingPublishRow {
        pk: fixed_32(row.get::<Vec<u8>, _>("pk").as_slice(), "pending.pk")?,
        owner: Address(fixed_32(
            row.get::<Vec<u8>, _>("owner").as_slice(),
            "pending.owner",
        )?),
        r: fixed_32(row.get::<Vec<u8>, _>("r").as_slice(), "pending.r")?,
        s: fixed_32(row.get::<Vec<u8>, _>("s").as_slice(), "pending.s")?,
        r_prime: fixed_32(row.get::<Vec<u8>, _>("r_prime").as_slice(), "pending.r_prime")?,
        build_tip_height: u32_from_i64(row.get("build_tip_height"), "pending.build_tip_height")?,
        build_tip_hash: fixed_32(
            row.get::<Vec<u8>, _>("build_tip_hash").as_slice(),
            "pending.build_tip_hash",
        )?,
        commit_tx: row.get("commit_tx"),
        reveal_tx: row.get("reveal_tx"),
        commit_txid: match row.get::<Option<Vec<u8>>, _>("commit_txid") {
            None => None,
            Some(b) => Some(fixed_32(&b, "pending.commit_txid")?),
        },
        reveal_txid: match row.get::<Option<Vec<u8>>, _>("reveal_txid") {
            None => None,
            Some(b) => Some(fixed_32(&b, "pending.reveal_txid")?),
        },
        status: row.get("status"),
    }))
}

/// Rows that still need rebroadcast work on boot (`status` not terminal).
pub async fn list_resumable_pending_publishes(pool: &PgPool) -> Result<Vec<PendingPublishRow>> {
    let rows = sqlx::query(
        "SELECT pk, owner, r, s, r_prime, build_tip_height, build_tip_hash, \
                commit_tx, reveal_tx, commit_txid, reveal_txid, status \
         FROM v1_pending_publishes \
         WHERE status IN ($1, $2, $3) \
         ORDER BY created_at ASC",
    )
    .bind(PENDING_PUBLISH_MEMBERS_READY)
    .bind(PENDING_PUBLISH_CONSTRUCTED)
    .bind(PENDING_PUBLISH_COMMIT_BROADCAST)
    .fetch_all(pool)
    .await
    .context("list resumable pending publishes")?;
    use sqlx::Row;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(PendingPublishRow {
            pk: fixed_32(row.get::<Vec<u8>, _>("pk").as_slice(), "pending.pk")?,
            owner: Address(fixed_32(
                row.get::<Vec<u8>, _>("owner").as_slice(),
                "pending.owner",
            )?),
            r: fixed_32(row.get::<Vec<u8>, _>("r").as_slice(), "pending.r")?,
            s: fixed_32(row.get::<Vec<u8>, _>("s").as_slice(), "pending.s")?,
            r_prime: fixed_32(row.get::<Vec<u8>, _>("r_prime").as_slice(), "pending.r_prime")?,
            build_tip_height: u32_from_i64(
                row.get("build_tip_height"),
                "pending.build_tip_height",
            )?,
            build_tip_hash: fixed_32(
                row.get::<Vec<u8>, _>("build_tip_hash").as_slice(),
                "pending.build_tip_hash",
            )?,
            commit_tx: row.get("commit_tx"),
            reveal_tx: row.get("reveal_tx"),
            commit_txid: match row.get::<Option<Vec<u8>>, _>("commit_txid") {
                None => None,
                Some(b) => Some(fixed_32(&b, "pending.commit_txid")?),
            },
            reveal_txid: match row.get::<Option<Vec<u8>>, _>("reveal_txid") {
                None => None,
                Some(b) => Some(fixed_32(&b, "pending.reveal_txid")?),
            },
            status: row.get("status"),
        });
    }
    Ok(out)
}
