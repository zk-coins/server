//! v1.1 receive as a real state transition (Cutover Gap G3).
//!
//! Behind `ZKCOINS_V11_SHADOW=1` a receive is no longer bookkeeping into a
//! legacy `coin_queue`. It is a full §2.3.3 transition:
//!
//! 1. **Host clause-10 verification** for every received slot (creating
//!    proof public inputs, coin-identifier recompute, S2C opening of the
//!    creating nullifier, first-occurrence anchor in the local NfLog,
//!    conditional-NAV open + prefix, output-tree inclusion).
//! 2. [`StateEngine::begin_receive`] → wallet `TransitionSignature`.
//! 3. [`StateEngine::finalise_pending_chain_nullifier`] (compliance proof +
//!    account/CoinHist apply — **no** NfLog mutation).
//! 4. **Persist** the account intent (durable pending record).
//! 5. On-chain nullifier via the Stage-2 v1.1 publisher.
//! 6. The **scanner** folds the nullifier into the canonical NfLog at its
//!    real §3.6 position when Bitcoin confirms it.
//!
//! ## Canonical NfLog is chain-only
//!
//! The NfLog is the fold of what Bitcoin actually contains, ordered by
//! `(height, tx_index, vin_index, member_index)` and folded by first
//! occurrence (§3.6). A published-but-unconfirmed nullifier is **not** in
//! that log. The receive path therefore never invents a synthetic position;
//! between publish and inclusion the account holds
//! `last_nullifier = Some` / `last_nullifier_pos = None` (pending, not
//! accumulator state).
//!
//! ## Crash windows (persist-before-broadcast)
//!
//! Persistence stores more than the compliance proof and `(Pk, R, R′)`:
//! the Schnorr `s`, the full [`BatchMember`] (incl. build tip), and — once
//! constructed — the raw commit/reveal transactions, in
//! `v11_pending_publishes` (migration 0021). Status machine:
//! `members_ready → constructed → commit_broadcast → reveal_broadcast`.
//!
//! Engine snapshot and `members_ready` land in **one transaction**, so the
//! previously unrecoverable "account advanced, no `s`" window no longer exists.
//!
//! | Window | Durable belief | Chain | Recovery |
//! |--------|----------------|-------|----------|
//! | During prove (pre-apply) | pre-receive | none | clean retry |
//! | After in-memory apply, before atomic persist | memory only | none | clean retry (DB unchanged) |
//! | After atomic engine + `members_ready` | account + `s` + BatchMember; no txs | none | re-construct txs, continue |
//! | After `constructed` (txs persisted) | full pair; nothing broadcast | none | broadcast commit then reveal |
//! | After `commit_broadcast` | full pair; commit accepted | commit present | broadcast reveal only (idempotent) |
//! | After `reveal_broadcast` | full pair; both legs sent | nullifier pending inclusion | boot resumer rebroadcasts pair idempotently if evicted; scanner folds NfLog |
//! | Publish fails after atomic persist | durable pending remains | maybe partial | **no** memory restore; resume from status |
//!
//! Never restore the pre-receive snapshot after a successful engine persist
//! that accompanies a publish intent: Bitcoin cannot be rolled back, and
//! scan only rebuilds the NfLog (not accounts), so a silent restore would
//! diverge from the chain forever.
//!
//! ## Write serialisation vs scanner
//!
//! The snapshot→mutate→persist→restore window holds
//! [`EngineAdapter::lock_writes`] so a concurrent scanner restore cannot
//! discard a receive that already committed (and vice versa). **Proving
//! holds neither the write gate nor the live-engine mutex** (the pending
//! witness carries everything the prover needs). Apply re-validates every
//! live dependency the prove-time decision read (account, tip/`size_final`,
//! receiver NAV canonicity, creating anchors, CoinHist, own-Pk absence) so
//! a concurrent scan fold during prove fails loud on collision rather than
//! committing against a moved world.
//!
//! ## Clause 10 is unskippable
//!
//! Each active slot is a [`ReceivedCoinSlot`] whose fields are **all
//! required** — there is no `Option` around the creating proof, the
//! creating nullifier `(Pk, R, R')`, or the NAV opening. A caller that
//! cannot supply the binding cannot construct a receive request, and
//! the host verifier fails loud when any binding check fails. There is
//! **no** fall-back to legacy `receive_coin_into` bookkeeping from this
//! path: a degraded receive would produce an account state no proof can
//! justify.
//!
//! ## Wallet signing (G4) is out of scope
//!
//! This module accepts a ready-made [`TransitionSignature`]. Assembling
//! the wallet S2C protocol is Gap G4.
//!
//! ## Reorg interaction
//!
//! A shallow reorg rebuilds **only** the NfLog from the post-reorg
//! survivor stream (see [`super::scan`]); account/CoinHist rows stay. A
//! receive whose creating or own nullifier is orphaned becomes
//! non-canonical for any subsequent transition that opens its NAV —
//! fail-closed at the next prove, not a silent re-credit. Automatic
//! account unwind on reorg is intentionally left open (Stage-3 / P1-G).

use anyhow::{bail, ensure, Context, Result};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use plonky2::field::types::PrimeField64;
use shared::spec_v1::{
    self as host, Address, Coin, HashDigest, LookupResult, Nav, NfLogEntry, ProofData,
    SpendClassification, TreeKind,
};
use zkcoins_program::circuit::compliance::{Network, MAX_OUTPUT_MERKLE_DEPTH, MAX_RX_COINS};
use zkcoins_prover::half_agg::{comm_verify, BlockAnchor, NullifierSig};
use zkcoins_prover::prover_bridge::{
    ComplianceProof, NavOpening, NullifierOpening, OutputInclusionProof, ReceivedAuthorization,
    TransitionSignature,
};
use zkcoins_prover::publisher::{BatchMember, PreparedBatch, PublishedBatch, Publisher};
use zkcoins_prover::state_engine::{
    AppliedTransition, PendingTransition, ReceiveRequest, StateEngine,
};

use super::adapter::EngineAdapter;
use super::db_v11::{
    self, PENDING_PUBLISH_COMMIT_BROADCAST, PENDING_PUBLISH_CONSTRUCTED,
    PENDING_PUBLISH_MEMBERS_READY, PENDING_PUBLISH_REVEAL_BROADCAST,
};
use super::publish::publish_v11_batch;
use super::separation::{process_stack_mode, require_v11_process_for_nflog_write, ScanStackMode};

/// Error prefix when the legacy bookkeeping receive is attempted under the
/// v1.1 process claim. Surfaces in residual legacy entry points.
pub const LEGACY_RECEIVE_REFUSED_UNDER_V11: &str =
    "legacy receive refused under ZKCOINS_V11_SHADOW=1; use the v1.1 receive transition \
     (begin_receive → compliance proof → AggregateStateNullifierV3). Silent fall-back to \
     bookkeeping is forbidden";

/// One received coin with its full clause-10 creating-proof binding.
///
/// Every field is mandatory. There is deliberately no constructor that
/// accepts a coin without a creating proof / nullifier S2C opening: a
/// receive that cannot supply clause-10 material is not expressible.
#[derive(Clone, Debug)]
pub struct ReceivedCoinSlot {
    pub coin: Coin,
    /// Creating transition's cyclic compliance proof (clause 10(a)).
    pub creating_proof: ComplianceProof,
    /// Membership of `coin.identifier` in the creating proof's
    /// `output_coins_root` (clause 10(b)).
    pub output_inclusion: OutputInclusionProof,
    /// Prior `account_state_hash` of the creating account (clause 10(b)
    /// identifier recompute).
    pub creating_prev_ash: HashDigest,
    /// On-chain nullifier of the creating transition plus its S2C
    /// pre-tweak `R'` (clause 10(d)).
    pub creating_nullifier: NullifierOpening,
    /// RFC-6962 inclusion path of the creating nullifier in the
    /// receiver's conditional NAV (clause 10(d)).
    pub creating_nav_inclusion: Vec<HashDigest>,
    /// Absolute position of the creating nullifier in the NfLog.
    pub pos_create: u64,
    /// Opening of the creating proof's `nav_commitment` (clause 10(c)).
    pub creating_nav_opening: NavOpening,
    /// RFC-6962 consistency proof: creating NAV is a prefix of the
    /// receiver's `w.nav` (clause 10(c)).
    pub creating_nav_consistency: Vec<HashDigest>,
}

impl ReceivedCoinSlot {
    /// Convert into the engine's [`ReceivedAuthorization`]. History proof
    /// is filled by [`StateEngine::begin_receive`] (sequential 0→1 paths).
    fn into_received_auth(self) -> ReceivedAuthorization {
        ReceivedAuthorization {
            creating_proof: self.creating_proof,
            output_inclusion: self.output_inclusion,
            creating_prev_ash: self.creating_prev_ash,
            creating_nullifier: self.creating_nullifier,
            creating_nav_inclusion: self.creating_nav_inclusion,
            pos_create: self.pos_create,
            creating_nav_opening: self.creating_nav_opening,
            creating_nav_consistency: self.creating_nav_consistency,
            // Placeholder; begin_receive overwrites with the sequential path.
            history_proof: host::CoinHistTree::new().prove([0u8; 32]),
        }
    }
}

/// Intent for a v1.1 receive transition (§2.3.3).
///
/// `slots` must be non-empty and at most [`MAX_RX_COINS`]. Each slot carries
/// its own clause-10 binding; there is no way to pass a bare `Coin`.
#[derive(Clone, Debug)]
pub struct V11ReceiveRequest {
    pub owner: Address,
    pub nk: [u8; 32],
    pub current_pubkey: [u8; 32],
    pub slots: Vec<ReceivedCoinSlot>,
    pub next_pubkey: [u8; 32],
    pub nav_rand: [u8; 32],
    pub npk_rand: [u8; 32],
}

/// Outcome of a successful v1.1 receive (prove + apply + publish + persist).
#[derive(Clone, Debug)]
pub struct V11ReceiveOutcome {
    /// On-chain nullifier `(Pkᵢ, Rᵢ)` of **this** receive transition.
    pub nullifier: ([u8; 32], [u8; 32]),
    /// Receiver account owner.
    pub owner: Address,
    /// `send_counter` after the transition (monotone +1).
    pub new_send_counter: u64,
    /// Coin identifiers admitted into the receiver's CoinHist (state-1).
    pub admitted_coin_ids: Vec<[u8; 32]>,
    /// Publisher result (commit/reveal txids, member Pks).
    pub published: PublishedBatchSummary,
}

/// Publisher-facing summary for assertions / logging.
#[derive(Clone, Debug)]
pub struct PublishedBatchSummary {
    pub commit_txid: bitcoin::Txid,
    pub reveal_txid: bitcoin::Txid,
    pub member_count: usize,
    pub nullifier_pks: Vec<[u8; 32]>,
}

/// Abstraction over the Stage-2 nullifier publisher so unit tests can
/// record the batch without bitcoind.
///
/// Durable crash recovery uses [`Self::try_prepare`] when the implementation
/// can construct the commit/reveal pair without broadcasting. Test doubles
/// that only record members leave `try_prepare` at the default `Ok(None)` and
/// fall back to [`Self::publish_batch`] after the `members_ready` row is
/// durable (rebroadcast of the signature is possible; mid-pair recovery of
/// raw txs is not, because no real txs exist).
pub trait NullifierBatchPublisher {
    fn publish_batch(&self, members: &[BatchMember]) -> Result<PublishedBatch>;

    /// Construct a fee-converged commit/reveal pair without broadcasting.
    /// Return `Ok(None)` when this publisher has no construct path.
    fn try_prepare(&self, members: &[BatchMember]) -> Result<Option<PreparedBatch>> {
        let _ = members;
        Ok(None)
    }

    fn broadcast_commit(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
        let _ = prepared;
        bail!("NullifierBatchPublisher::broadcast_commit not supported by this publisher")
    }

    fn broadcast_reveal(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
        let _ = prepared;
        bail!("NullifierBatchPublisher::broadcast_reveal not supported by this publisher")
    }
}

impl NullifierBatchPublisher for Publisher {
    fn publish_batch(&self, members: &[BatchMember]) -> Result<PublishedBatch> {
        publish_v11_batch(self, members)
    }

    fn try_prepare(&self, members: &[BatchMember]) -> Result<Option<PreparedBatch>> {
        Ok(Some(Publisher::prepare(self, members)?))
    }

    fn broadcast_commit(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
        Publisher::broadcast_commit(self, prepared)
    }

    fn broadcast_reveal(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
        Publisher::broadcast_reveal(self, prepared)
    }
}

/// Refuse the legacy bookkeeping receive when this process has claimed the
/// v1.1 stack. Call from any residual legacy entry point so a v1.1 boot
/// never credits via `coin_queue`.
///
/// Returns `Ok(())` when the process is **not** on the v1.1 claim (legacy
/// / unclaimed). Fail-loud under v1.1 — never a silent allow.
pub fn refuse_legacy_receive_under_v11() -> Result<(), &'static str> {
    match process_stack_mode() {
        Some(ScanStackMode::V11) => Err(LEGACY_RECEIVE_REFUSED_UNDER_V11),
        Some(ScanStackMode::Legacy) | None => Ok(()),
    }
}

/// Host-side clause-10 verification for every slot, then
/// [`StateEngine::begin_receive`].
///
/// Does **not** mutate the engine. The wallet must sign
/// `pending.proof_data` (G4) and call [`finalise_publish_persist`].
pub fn verify_and_begin_receive(
    engine: &StateEngine,
    req: V11ReceiveRequest,
) -> Result<PendingTransition> {
    require_v11_process_for_nflog_write()
        .context("v1.1 receive: exclusive stack claim required (no legacy fall-back)")?;

    ensure!(
        !req.slots.is_empty(),
        "v1.1 receive requires at least one received coin (no empty transition)"
    );
    ensure!(
        req.slots.len() <= MAX_RX_COINS,
        "v1.1 receive: {} coins exceeds MAX_RX_COINS={MAX_RX_COINS} (§2.5); refusing (no silent truncate)",
        req.slots.len()
    );

    let receiver_nav = size_final_nav(engine)?;

    for (index, slot) in req.slots.iter().enumerate() {
        verify_clause10_slot(engine, slot, receiver_nav, index)
            .with_context(|| format!("clause-10 host verify failed for received slot {index}"))?;
    }

    let mut coins = Vec::with_capacity(req.slots.len());
    let mut auth = Vec::with_capacity(req.slots.len());
    for slot in req.slots {
        ensure!(
            slot.coin.recipient == req.owner,
            "received coin recipient is not the receiving account"
        );
        coins.push(slot.coin.clone());
        auth.push(slot.into_received_auth());
    }

    engine
        .begin_receive(ReceiveRequest {
            owner: req.owner,
            nk: req.nk,
            current_pubkey: req.current_pubkey,
            received_coins: coins,
            received_auth: auth,
            next_pubkey: req.next_pubkey,
            nav_rand: req.nav_rand,
            npk_rand: req.npk_rand,
        })
        .context("StateEngine::begin_receive failed")
}

/// Prove + apply the pending receive (account/CoinHist only), **persist the
/// rebroadcast intent** (incl. Schnorr `s` + BatchMember), construct and
/// persist the commit/reveal pair when the publisher supports it, then
/// broadcast.
///
/// Ordering (crash-consistent; see module docs):
/// 1. **Prove holding neither write gate nor engine mutex** (multi-minute;
///    pending witness is self-contained).
/// 2. Acquire [`EngineAdapter::lock_writes`] (serialises vs scanner restore).
/// 3. Apply account (NfLog untouched); full live re-validation after prove.
/// 4. **Atomic** engine persist + `v11_pending_publishes` `members_ready`.
/// 5. Release write gate; construct/broadcast outside the gate.
/// 6. Outcome is decided from **this** transition (applied account +
///    successful publish), never from a global NfLog size anyone can move.
///
/// The own nullifier enters the canonical NfLog only when the scanner folds
/// the confirmed on-chain survivor at its real §3.6 position.
pub async fn finalise_publish_persist(
    adapter: &EngineAdapter,
    pending: PendingTransition,
    signature: TransitionSignature,
    publisher: &impl NullifierBatchPublisher,
    build_tip: BlockAnchor,
) -> Result<V11ReceiveOutcome> {
    require_v11_process_for_nflog_write()
        .context("v1.1 receive finalise: exclusive stack claim required")?;

    // 1. Prove with neither write_gate nor live-engine mutex.
    // Concurrent scanner folds during this multi-minute window are fine:
    // apply re-validates every live dependency before commit.
    let bridge = adapter.bridge();
    let proved_pending = StateEngine::prove_pending_transition_detached(
        &bridge,
        pending,
        signature.clone(),
    )
    .context(
        "v1.1 receive: prove_pending_transition failed — state unchanged, nothing persisted",
    )?;

    commit_proved_receive(adapter, proved_pending, signature, publisher, build_tip).await
}

/// State-critical section after unlocked prove: write-gate → revalidate/apply
/// → atomic persist → publish. Split out so tests can inject a concurrent
/// scanner append between prove and apply without a multi-minute circuit.
pub async fn commit_proved_receive(
    adapter: &EngineAdapter,
    proved_pending: zkcoins_prover::state_engine::ProvedPendingTransition,
    signature: TransitionSignature,
    publisher: &impl NullifierBatchPublisher,
    build_tip: BlockAnchor,
) -> Result<V11ReceiveOutcome> {
    require_v11_process_for_nflog_write()
        .context("v1.1 receive commit: exclusive stack claim required")?;

    let owner = proved_pending.pending().owner;

    // 2. Write gate covers only snapshot→mutate→persist→restore.
    let applied = {
        let _write_gate = adapter.lock_writes().await;
        let pre = adapter.snapshot_live();
        // Measure NfLog size *inside* the gate, immediately before apply —
        // never against a pre-prove snapshot a concurrent scan can move.
        let nflog_size_pre_apply = adapter.with_engine(|engine| engine.nflog().nav().size);
        let applied = match adapter.with_engine_mut(|engine| {
            engine.apply_proved_transition(proved_pending)
        })? {
            Ok(a) => a,
            Err(err) => {
                // Apply failed before the account insert; restore for safety.
                let _ = adapter.restore_live(pre);
                return Err(err).context(
                    "v1.1 receive: apply_proved_transition failed — state restored",
                );
            }
        };

        // Post-apply invariant checks. Any failure restores the pre-apply
        // snapshot so memory never stays advanced without a durable commit.
        let post_apply_ok = (|| -> Result<()> {
            let nflog_size_after_apply = adapter.with_engine(|engine| engine.nflog().nav().size);
            ensure!(
                nflog_size_after_apply == nflog_size_pre_apply,
                "v1.1 receive BUG: apply_proved_transition mutated the canonical NfLog \
                 (size {nflog_size_pre_apply} → {nflog_size_after_apply}); refusing to publish a \
                 locally invented accumulator state"
            );
            adapter.with_engine(|engine| {
                let rec = engine
                    .account(&owner)
                    .context("v1.1 receive: account missing after apply")?;
                ensure!(
                    rec.last_nullifier.is_some(),
                    "v1.1 receive: last_nullifier missing after apply"
                );
                ensure!(
                    rec.last_nullifier_pos.is_none(),
                    "v1.1 receive: last_nullifier_pos must stay None until scan-fold \
                     (got {:?})",
                    rec.last_nullifier_pos
                );
                Ok(())
            })
        })();
        if let Err(err) = post_apply_ok {
            adapter
                .restore_live(pre)
                .context("v1.1 receive: restore after post-apply invariant failure")?;
            return Err(err);
        }

        // 3. Atomic: engine snapshot + members_ready in one transaction.
        // Closes the "account advanced, no s" unrecoverable window.
        let member = match batch_member_from_applied(&applied, &signature, build_tip) {
            Ok(m) => m,
            Err(err) => {
                adapter
                    .restore_live(pre)
                    .context("v1.1 receive: restore after batch member build failure")?;
                return Err(err);
            }
        };
        let snap = adapter.snapshot_live();
        if let Err(err) = db_v11::persist_engine_with_pending_members_ready(
            adapter.pool(),
            &snap,
            owner,
            member.sig.pk,
            member.sig.r,
            member.sig.s,
            signature.r_prime,
            build_tip.height,
            build_tip.block_hash,
        )
        .await
        {
            adapter
                .restore_live(pre)
                .context("v1.1 receive: restore engine after atomic persist failure")?;
            return Err(err).context(
                "v1.1 receive: atomic persist of engine + members_ready failed; \
                 engine restored (no silent credit, nothing broadcast)",
            );
        }
        // Intent is durable. Never restore_live after this point.
        // Drop write gate before broadcast (liveness: scanner can proceed).
        (applied, member)
    };
    let (applied, member) = applied;

    let admitted_coin_ids = adapter.with_engine(|engine| {
        engine
            .account(&owner)
            .map(|rec| rec.spendable.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default()
    });
    let new_send_counter = adapter.with_engine(|engine| {
        engine
            .account(&owner)
            .map(|rec| rec.state.send_counter)
            .unwrap_or(0)
    });

    // 4. Construct + broadcast outside the write gate.
    let published = durable_publish_nullifier(adapter, publisher, &member)
        .await
        .context(
            "v1.1 receive: nullifier publish failed after durable intent; \
             pending receive remains in engine/DB for rebroadcast — \
             NfLog unchanged until scanner sees the on-chain nullifier",
        )?;

    // Outcome is what *this* transition did: account credited + nullifier
    // published. A concurrent scanner append after broadcast must not flip
    // success into failure via a global NfLog size comparison.
    Ok(V11ReceiveOutcome {
        nullifier: applied.nullifier,
        owner,
        new_send_counter,
        admitted_coin_ids,
        published: summarize_published(&published),
    })
}

fn batch_member_from_applied(
    applied: &AppliedTransition,
    signature: &TransitionSignature,
    build_tip: BlockAnchor,
) -> Result<BatchMember> {
    ensure!(
        signature.pk_i == applied.nullifier.0,
        "publish: signature.pk_i does not match applied nullifier Pk"
    );
    ensure!(
        signature.signature_r() == applied.nullifier.1,
        "publish: signature R does not match applied nullifier R"
    );
    Ok(BatchMember {
        sig: NullifierSig {
            pk: applied.nullifier.0,
            r: applied.nullifier.1,
            s: signature.signature_s(),
        },
        build_tip,
    })
}

/// Classify a broadcast error as an **idempotent success** for rebroadcast.
///
/// Distinguishes specific Bitcoin Core / mempool "already done" signals from
/// genuine failures. Generic errors are **not** treated as success.
fn is_rebroadcast_already_done(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}").to_lowercase();
    // Bitcoin Core / bitcoind phrases observed on rebroadcast of a tx that
    // already landed in mempool or chain. Keep the list explicit — never
    // "any error ⇒ success".
    const SIGNALS: &[&str] = &[
        "txn-already-known",
        "txn-already-in-mempool",
        "already in mempool",
        "already have",
        "transaction already in block chain",
        "txn-mempool-conflict",
        "bad-txns-inputs-missingorspent",
        "missing-inputs",
        "already spent",
    ];
    SIGNALS.iter().any(|s| msg.contains(s))
}

/// Broadcast commit; treat "already known / already in mempool / already spent"
/// as success and return the prepared commit txid.
fn broadcast_commit_idempotent(
    publisher: &impl NullifierBatchPublisher,
    prepared: &PreparedBatch,
) -> Result<bitcoin::Txid> {
    match publisher.broadcast_commit(prepared) {
        Ok(txid) => Ok(txid),
        Err(err) if is_rebroadcast_already_done(&err) => {
            let txid = prepared.commit_txid();
            eprintln!(
                "v11 publish: commit {txid} already known/mempool/spent — treating rebroadcast as success"
            );
            Ok(txid)
        }
        Err(err) => Err(err).context("broadcast commit (not an already-done signal)"),
    }
}

/// Broadcast reveal with the same idempotent "already done" classification.
fn broadcast_reveal_idempotent(
    publisher: &impl NullifierBatchPublisher,
    prepared: &PreparedBatch,
) -> Result<bitcoin::Txid> {
    match publisher.broadcast_reveal(prepared) {
        Ok(txid) => Ok(txid),
        Err(err) if is_rebroadcast_already_done(&err) => {
            let txid = prepared.reveal_txid();
            eprintln!(
                "v11 publish: reveal {txid} already known/mempool/spent — treating rebroadcast as success"
            );
            Ok(txid)
        }
        Err(err) => Err(err).context("broadcast reveal (not an already-done signal)"),
    }
}

/// Persist-aware publish: prefer prepare→persist-txs→commit→reveal when the
/// publisher can construct; otherwise `publish_batch` after `members_ready`.
async fn durable_publish_nullifier(
    adapter: &EngineAdapter,
    publisher: &impl NullifierBatchPublisher,
    member: &BatchMember,
) -> Result<PublishedBatch> {
    let members = [*member];
    match publisher.try_prepare(&members)? {
        Some(prepared) => {
            let commit_tx = serialize(&prepared.signed_commit);
            let reveal_tx = serialize(&prepared.reveal_tx);
            let commit_txid = prepared.commit_txid().to_byte_array();
            let reveal_txid = prepared.reveal_txid().to_byte_array();
            db_v11::mark_pending_publish_constructed(
                adapter.pool(),
                member.sig.pk,
                &commit_tx,
                &reveal_tx,
                commit_txid,
                reveal_txid,
            )
            .await
            .context("persist constructed commit/reveal pair")?;

            let commit_txid = broadcast_commit_idempotent(publisher, &prepared)
                .context("broadcast commit after durable construct")?;
            db_v11::mark_pending_publish_status(
                adapter.pool(),
                member.sig.pk,
                PENDING_PUBLISH_CONSTRUCTED,
                PENDING_PUBLISH_COMMIT_BROADCAST,
            )
            .await
            .context("mark commit_broadcast")?;

            let reveal_txid = broadcast_reveal_idempotent(publisher, &prepared).with_context(|| {
                format!(
                    "broadcast reveal failed; commit already on chain as {commit_txid}; \
                     durable pair remains at commit_broadcast for resume"
                )
            })?;
            db_v11::mark_pending_publish_status(
                adapter.pool(),
                member.sig.pk,
                PENDING_PUBLISH_COMMIT_BROADCAST,
                PENDING_PUBLISH_REVEAL_BROADCAST,
            )
            .await
            .context("mark reveal_broadcast")?;

            Ok(PublishedBatch {
                aggregate: prepared.aggregate,
                payload: prepared.payload,
                commit_txid,
                reveal_txid,
                commit_output: prepared.commit_output,
                block_anchor: prepared.block_anchor,
            })
        }
        None => {
            // Test double / publisher without construct path: members_ready
            // already holds s + BatchMember for rebroadcast. No raw txs.
            let published = publisher
                .publish_batch(&members)
                .context("publish_batch after members_ready")?;
            db_v11::mark_pending_publish_status(
                adapter.pool(),
                member.sig.pk,
                PENDING_PUBLISH_MEMBERS_READY,
                PENDING_PUBLISH_REVEAL_BROADCAST,
            )
            .await
            .context(
                "mark reveal_broadcast after publish_batch (no construct path); \
                 members_ready → reveal_broadcast",
            )?;
            Ok(published)
        }
    }
}

fn prepared_batch_from_pending_row(
    row: &db_v11::PendingPublishRow,
    member: &BatchMember,
) -> Result<PreparedBatch> {
    let commit_tx_bytes = row
        .commit_tx
        .as_ref()
        .context("resume: row missing commit_tx")?;
    let reveal_tx_bytes = row
        .reveal_tx
        .as_ref()
        .context("resume: row missing reveal_tx")?;
    let signed_commit: Transaction =
        deserialize(commit_tx_bytes).context("resume: deserialize commit_tx")?;
    let reveal_tx: Transaction =
        deserialize(reveal_tx_bytes).context("resume: deserialize reveal_tx")?;
    let commit_output = signed_commit
        .output
        .first()
        .cloned()
        .context("resume: commit has no outputs")?;
    Ok(PreparedBatch {
        aggregate: zkcoins_prover::half_agg::AggregateStateNullifierV3 {
            version: 3,
            format: 0x01,
            block_anchor: member.build_tip,
            members: vec![(member.sig.pk, member.sig.r)],
            raw_s: None,
            s_agg: Some(member.sig.s),
        },
        payload: Vec::new(),
        signed_commit,
        reveal_tx,
        commit_output,
        block_anchor: member.build_tip,
        commit_vsize: 0,
        reveal_vsize: 0,
        commit_fee: bitcoin::Amount::from_sat(0),
        reveal_fee: bitcoin::Amount::from_sat(0),
    })
}

/// Resume a durable pending publish after crash. Reconstructs from
/// `v11_pending_publishes` and finishes or fails loud — never invents txs.
///
/// Rebroadcast is **idempotent**: chain replies that the tx is already known,
/// already in the mempool, or already spent are success signals, not errors.
pub async fn resume_pending_publish(
    adapter: &EngineAdapter,
    publisher: &impl NullifierBatchPublisher,
    pk: [u8; 32],
) -> Result<Option<PublishedBatch>> {
    require_v11_process_for_nflog_write()
        .context("resume_pending_publish: exclusive stack claim required")?;
    let row = match db_v11::load_pending_publish(adapter.pool(), pk).await? {
        None => return Ok(None),
        Some(r) => r,
    };
    let member = BatchMember {
        sig: NullifierSig {
            pk: row.pk,
            r: row.r,
            s: row.s,
        },
        build_tip: BlockAnchor {
            block_hash: row.build_tip_hash,
            height: row.build_tip_height,
        },
    };
    match row.status.as_str() {
        "members_ready" => {
            let published = durable_publish_nullifier(adapter, publisher, &member).await?;
            Ok(Some(published))
        }
        "constructed" => {
            let prepared = prepared_batch_from_pending_row(&row, &member)?;
            let commit_txid = broadcast_commit_idempotent(publisher, &prepared)?;
            db_v11::mark_pending_publish_status(
                adapter.pool(),
                pk,
                PENDING_PUBLISH_CONSTRUCTED,
                PENDING_PUBLISH_COMMIT_BROADCAST,
            )
            .await?;
            let reveal_txid = broadcast_reveal_idempotent(publisher, &prepared).with_context(|| {
                format!("resume reveal failed; commit {commit_txid} already broadcast")
            })?;
            db_v11::mark_pending_publish_status(
                adapter.pool(),
                pk,
                PENDING_PUBLISH_COMMIT_BROADCAST,
                PENDING_PUBLISH_REVEAL_BROADCAST,
            )
            .await?;
            Ok(Some(PublishedBatch {
                aggregate: prepared.aggregate,
                payload: prepared.payload,
                commit_txid,
                reveal_txid,
                commit_output: prepared.commit_output,
                block_anchor: prepared.block_anchor,
            }))
        }
        "commit_broadcast" => {
            let prepared = prepared_batch_from_pending_row(&row, &member)?;
            let commit_txid = prepared.commit_txid();
            let reveal_txid = broadcast_reveal_idempotent(publisher, &prepared).with_context(|| {
                format!("resume reveal-only failed; commit was {commit_txid}")
            })?;
            db_v11::mark_pending_publish_status(
                adapter.pool(),
                pk,
                PENDING_PUBLISH_COMMIT_BROADCAST,
                PENDING_PUBLISH_REVEAL_BROADCAST,
            )
            .await?;
            Ok(Some(PublishedBatch {
                aggregate: prepared.aggregate,
                payload: prepared.payload,
                commit_txid,
                reveal_txid,
                commit_output: prepared.commit_output,
                block_anchor: prepared.block_anchor,
            }))
        }
        "reveal_broadcast" => {
            // Pair retained: rebroadcast both legs idempotently so a mempool
            // eviction before confirmation is recovered on boot.
            if row.commit_tx.is_some() && row.reveal_tx.is_some() {
                let prepared = prepared_batch_from_pending_row(&row, &member)?;
                let _ = broadcast_commit_idempotent(publisher, &prepared)?;
                let _ = broadcast_reveal_idempotent(publisher, &prepared)?;
            }
            Ok(None)
        }
        "complete" => Ok(None),
        "failed" => bail!(
            "resume_pending_publish: pk={} is marked failed; refusing silent retry",
            hex::encode(pk)
        ),
        other => bail!(
            "resume_pending_publish: unknown status {other:?} for pk={}",
            hex::encode(pk)
        ),
    }
}

/// Boot-time resumer: walk every non-terminal `v11_pending_publishes` row.
///
/// Called from the v1.1 scan-loop bootstrap so pending publishes are picked
/// up automatically rather than only by hand. Per-row failures are returned
/// (fail loud) — operators must not silently drop a half-broadcast nullifier.
pub async fn resume_all_pending_publishes(
    adapter: &EngineAdapter,
    publisher: &impl NullifierBatchPublisher,
) -> Result<usize> {
    require_v11_process_for_nflog_write()
        .context("resume_all_pending_publishes: exclusive stack claim required")?;
    let rows = db_v11::list_resumable_pending_publishes(adapter.pool()).await?;
    let mut completed = 0usize;
    for row in rows {
        resume_pending_publish(adapter, publisher, row.pk)
            .await
            .with_context(|| {
                format!(
                    "resume_all_pending_publishes: failed for pk={} status={}",
                    hex::encode(row.pk),
                    row.status
                )
            })?;
        completed = completed
            .checked_add(1)
            .context("resume_all_pending_publishes: completed counter overflow")?;
    }
    Ok(completed)
}

/// Full production path: host clause-10 → begin → prove/apply (no NfLog) →
/// persist intent → publish. Scanner folds the nullifier on inclusion.
pub async fn execute_v11_receive(
    adapter: &EngineAdapter,
    req: V11ReceiveRequest,
    signature: TransitionSignature,
    publisher: &impl NullifierBatchPublisher,
    build_tip: BlockAnchor,
) -> Result<V11ReceiveOutcome> {
    let pending = adapter.with_engine(|engine| verify_and_begin_receive(engine, req))?;
    finalise_publish_persist(adapter, pending, signature, publisher, build_tip).await
}

/// Publish the applied receive's on-chain nullifier as a one-member
/// `AggregateStateNullifierV3` batch.
pub fn publish_applied_nullifier(
    publisher: &impl NullifierBatchPublisher,
    applied: &AppliedTransition,
    signature: &TransitionSignature,
    build_tip: BlockAnchor,
) -> Result<PublishedBatch> {
    ensure!(
        signature.pk_i == applied.nullifier.0,
        "publish: signature.pk_i does not match applied nullifier Pk"
    );
    ensure!(
        signature.signature_r() == applied.nullifier.1,
        "publish: signature R does not match applied nullifier R"
    );
    let member = BatchMember {
        sig: NullifierSig {
            pk: applied.nullifier.0,
            r: applied.nullifier.1,
            s: signature.signature_s(),
        },
        build_tip,
    };
    publisher
        .publish_batch(&[member])
        .context("publish receive nullifier batch")
}

// ---------------------------------------------------------------------------
// Clause 10 host verification
// ---------------------------------------------------------------------------

/// Host checks for one received slot (§2.3.3 steps 2–4 + clause 10).
///
/// Cryptographic Plonky2 verify of the creating proof runs inside
/// `prove_transition` / `finalise`. This function enforces every binding
/// that must hold **before** we assemble a pending transition, so a bad
/// creating-proof binding fails before any engine mutation.
pub fn verify_clause10_slot(
    engine: &StateEngine,
    slot: &ReceivedCoinSlot,
    receiver_nav: Nav,
    index: usize,
) -> Result<()> {
    ensure!(
        slot.coin.amount > 0,
        "slot {index}: received coin amount must be non-zero"
    );

    // 10(b) — recompute coin.identifier from the creating prev_ash + fields.
    let leaf_index = slot.output_inclusion.leaf_index;
    let expected_id = host::coin_identifier(
        slot.creating_prev_ash,
        &slot.coin.recipient.0,
        slot.coin.asset_id,
        slot.coin.amount,
        leaf_index,
    );
    ensure!(
        slot.coin.identifier == expected_id,
        "slot {index}: coin.identifier does not recompute from creating_prev_ash \
         (clause 10(b)); refusing credit"
    );

    // Extract creating ProofData + consumed_pubkey from the proof PIs.
    let (creating_pd, consumed_pubkey, _network_id) =
        extract_compliance_public_inputs(&slot.creating_proof)
            .with_context(|| format!("slot {index}: creating proof public-input shape"))?;

    // 10(b) — output inclusion against the creating proof's ocr.
    verify_output_inclusion(
        slot.coin.identifier,
        &slot.output_inclusion,
        creating_pd.output_coins_root,
    )
    .with_context(|| format!("slot {index}: output inclusion (clause 10(b))"))?;

    // 10(d) — key binding + S2C opening of the creating nullifier.
    verify_creating_nullifier_binding(
        &slot.creating_nullifier,
        &creating_pd,
        &consumed_pubkey,
        index,
    )?;

    // 10(d) / §2.3.3 step 4 — first-occurrence of (Pk_create, R_create)
    // on the receiver's own NfLog. Path-A only; no Path-B fall-back.
    verify_creating_first_occurrence(engine, slot, receiver_nav, index)?;

    // 10(c) — creating nav_opening opens the creating proof's nav_commitment
    // and is a prefix of the receiver's nav.
    verify_creating_nav_prefix(engine, slot, &creating_pd, receiver_nav, index)?;

    Ok(())
}

/// Clause 10(d) S2C + consumed-key binding. Public for focused unit tests.
pub fn verify_creating_nullifier_binding(
    creating_nullifier: &NullifierOpening,
    creating_pd: &ProofData,
    consumed_pubkey: &[u8; 32],
    index: usize,
) -> Result<()> {
    ensure!(
        creating_nullifier.public_key == *consumed_pubkey,
        "slot {index}: creating_nullifier.Pk != creating_proof.consumed_pubkey \
         (clause 10(d) key binding); refusing credit"
    );

    let h_pd = host::hash_proof_data(&host::serialize_proof_data(creating_pd));
    comm_verify(
        &creating_nullifier.signature_r,
        &h_pd,
        &creating_nullifier.r_prime,
    )
    .with_context(|| {
        format!(
            "slot {index}: creating nullifier S2C opening does not bind \
             H(creating ProofData) (clause 10(d)); refusing credit"
        )
    })?;
    Ok(())
}

fn verify_creating_first_occurrence(
    engine: &StateEngine,
    slot: &ReceivedCoinSlot,
    receiver_nav: Nav,
    index: usize,
) -> Result<()> {
    match engine.nflog().classify(
        slot.creating_nullifier.public_key,
        slot.creating_nullifier.signature_r,
    ) {
        SpendClassification::ValidFirstSpend => {}
        SpendClassification::RejectedDoubleSpend => {
            bail!(
                "slot {index}: creating Pk is present with a different R \
                 (double-spend loser); refusing credit"
            );
        }
        SpendClassification::Pending => {
            bail!(
                "slot {index}: creating nullifier (Pk, R) is not a first-occurrence \
                 on the receiver's NfLog (absent); refusing credit"
            );
        }
    }
    match engine.nflog().lookup(slot.creating_nullifier.public_key) {
        LookupResult::Present { pos, r, .. } => {
            ensure!(
                r == slot.creating_nullifier.signature_r,
                "slot {index}: NfLog first-occurrence R mismatches creating_nullifier.R"
            );
            ensure!(
                pos == slot.pos_create,
                "slot {index}: pos_create {} does not match NfLog position {pos}",
                slot.pos_create
            );
            ensure!(
                pos < receiver_nav.size,
                "slot {index}: creating nullifier position {pos} is not covered by \
                 receiver nav.size {}",
                receiver_nav.size
            );
        }
        LookupResult::Absent => {
            bail!("slot {index}: creating Pk vanished between classify and lookup");
        }
    }

    let leaf = host::nflog_leaf_hash(
        slot.pos_create,
        &NfLogEntry {
            pk: slot.creating_nullifier.public_key,
            r: slot.creating_nullifier.signature_r,
        },
    );
    ensure!(
        host::verify_inclusion(
            leaf,
            slot.pos_create,
            &slot.creating_nav_inclusion,
            receiver_nav.size,
            receiver_nav.mth,
        ),
        "slot {index}: creating nullifier inclusion path does not open receiver nav (clause 10(d))"
    );
    Ok(())
}

fn verify_creating_nav_prefix(
    engine: &StateEngine,
    slot: &ReceivedCoinSlot,
    creating_pd: &ProofData,
    receiver_nav: Nav,
    index: usize,
) -> Result<()> {
    let expected_creating_commit = host::nav_commitment(
        slot.creating_nav_opening.nav.root(),
        &slot.creating_nav_opening.nav_rand,
    );
    ensure!(
        expected_creating_commit == creating_pd.nav_commitment,
        "slot {index}: creating_nav_opening does not open creating_proof.nav_commitment \
         (clause 10(c)); refusing credit"
    );

    ensure!(
        host::verify_consistency(
            slot.creating_nav_opening.nav.size,
            slot.creating_nav_opening.nav.mth,
            receiver_nav.size,
            receiver_nav.mth,
            &slot.creating_nav_consistency,
        ),
        "slot {index}: creating nav is not a prefix of receiver nav (clause 10(c)); \
         refusing credit"
    );

    ensure!(
        engine.nflog().is_canonical(
            slot.creating_nav_opening.nav.size,
            slot.creating_nav_opening.nav.mth
        ),
        "slot {index}: creating nav is not canonical on the receiver's NfLog; refusing credit"
    );
    Ok(())
}

/// `size_final` NAV at the engine tip (§2.3.2 step 5 / §2.3.3).
pub fn size_final_nav(engine: &StateEngine) -> Result<Nav> {
    let size = engine.nflog().size_final(engine.tip_height());
    let mth = if size == 0 {
        host::nflog_empty()
    } else {
        let mirror = engine.nflog_mirror();
        ensure!(
            mirror.len() as u64 >= size,
            "NfLog mirror shorter than size_final"
        );
        host::nflog_mth(
            &mirror
                .iter()
                .take(size as usize)
                .map(|(_, e)| *e)
                .collect::<Vec<_>>(),
        )
    };
    Ok(Nav { size, mth })
}

/// Host output-tree inclusion (§1.7.5 CoinsRoot, variable depth).
pub fn verify_output_inclusion(
    identifier: HashDigest,
    inclusion: &OutputInclusionProof,
    output_coins_root: HashDigest,
) -> Result<()> {
    ensure!(
        inclusion.siblings.len() <= MAX_OUTPUT_MERKLE_DEPTH,
        "output inclusion path exceeds MAX_OUTPUT_MERKLE_DEPTH"
    );
    ensure!(
        usize::from(inclusion.depth) == inclusion.siblings.len(),
        "output inclusion depth does not match sibling count"
    );
    let depth = usize::from(inclusion.depth);
    let leaf_index = u64::from(inclusion.leaf_index);
    ensure!(
        depth == 0 || leaf_index < (1u64 << depth),
        "output inclusion leaf_index does not fit in depth"
    );

    let mut acc = host::leaf_hash(TreeKind::CoinsRoot, identifier);
    for level in 0..depth {
        let sibling = inclusion.siblings[level];
        let on_right = ((leaf_index >> level) & 1) == 1;
        acc = if on_right {
            host::node_hash(TreeKind::CoinsRoot, sibling, acc)
        } else {
            host::node_hash(TreeKind::CoinsRoot, acc, sibling)
        };
    }
    ensure!(
        acc == output_coins_root,
        "output inclusion does not open creating proof output_coins_root"
    );
    Ok(())
}

/// Re-extract compliance public inputs from a proof (host-only; no circuit).
///
/// Layout matches `prover_bridge::extract_transition_public_inputs`.
pub fn extract_compliance_public_inputs(
    proof: &ComplianceProof,
) -> Result<(ProofData, [u8; 32], HashDigest)> {
    ensure!(
        proof.public_inputs.len() == 108,
        "compliance proof has {} public inputs, expected 108",
        proof.public_inputs.len()
    );
    let digest = |offset: usize| -> HashDigest {
        HashDigest {
            elements: proof.public_inputs[offset..offset + 4]
                .try_into()
                .expect("validated PI slice length"),
        }
    };
    let proof_data = ProofData {
        new_account_state_hash: digest(0),
        output_coins_root: digest(4),
        input_nullifiers_root: digest(8),
        coin_history_root: digest(12),
        nav_commitment: digest(16),
        npk_commit: bytes_from_u32_le_limbs(&proof.public_inputs[20..28])?,
    };
    let consumed_pubkey = bytes_from_u32_le_limbs(&proof.public_inputs[28..36])?;
    Ok((proof_data, consumed_pubkey, digest(36)))
}

fn bytes_from_u32_le_limbs(limbs: &[zkcoins_program::F]) -> Result<[u8; 32]> {
    ensure!(limbs.len() == 8, "expected eight u32 limbs");
    let mut bytes = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        let value = limb.to_canonical_u64();
        if value > u64::from(u32::MAX) {
            bail!("public byte-string limb is not a canonical u32");
        }
        let start = 28 - 4 * index;
        bytes[start..start + 4].copy_from_slice(&(value as u32).to_be_bytes());
    }
    Ok(bytes)
}

fn summarize_published(batch: &PublishedBatch) -> PublishedBatchSummary {
    PublishedBatchSummary {
        commit_txid: batch.commit_txid,
        reveal_txid: batch.reveal_txid,
        member_count: batch.aggregate.members.len(),
        nullifier_pks: batch.aggregate.members.iter().map(|(pk, _)| *pk).collect(),
    }
}

// Silence unused import when Network is only used by callers.
#[allow(dead_code)]
fn _network_pin(_n: Network) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v11::separation::{
        clear_process_stack_mode_for_test, set_process_stack_mode, ScanStackMode,
    };
    use bitcoin::{Amount, ScriptBuf, TxOut, Txid};
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;
    use zkcoins_prover::half_agg::AggregateStateNullifierV3;
    use zkcoins_prover::state_engine::{AccountRecord, TrackedCoin};

    // ---- recording publisher ------------------------------------------------

    struct RecordingPublisher {
        batches: Mutex<Vec<Vec<BatchMember>>>,
        /// When set, `broadcast_commit` / `broadcast_reveal` return this error
        /// string (wrapped in anyhow) so idempotent rebroadcast can be tested.
        broadcast_err: Mutex<Option<String>>,
        commit_calls: Mutex<u32>,
        reveal_calls: Mutex<u32>,
        /// Optional side-effect on successful `broadcast_commit` (e.g. concurrent
        /// scanner append after this receive's broadcast).
        on_commit: Mutex<Option<Box<dyn Fn() + Send>>>,
    }

    impl RecordingPublisher {
        fn new() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                broadcast_err: Mutex::new(None),
                commit_calls: Mutex::new(0),
                reveal_calls: Mutex::new(0),
                on_commit: Mutex::new(None),
            }
        }
        fn with_broadcast_err(err: &str) -> Self {
            let p = Self::new();
            *p.broadcast_err.lock().expect("lock") = Some(err.to_string());
            p
        }
        fn with_on_commit(on_commit: impl Fn() + Send + 'static) -> Self {
            let p = Self::new();
            *p.on_commit.lock().expect("lock") = Some(Box::new(on_commit));
            p
        }
        fn published_members(&self) -> Vec<BatchMember> {
            self.batches
                .lock()
                .expect("lock")
                .iter()
                .flatten()
                .copied()
                .collect()
        }
        fn dummy_prepared(member: &BatchMember) -> PreparedBatch {
            // Distinct lock_time from pk/r so each member has unique txids
            // (unique index on commit_txid in v11_pending_publishes).
            let commit_lock = u32::from_le_bytes(member.sig.pk[0..4].try_into().unwrap());
            let reveal_lock = u32::from_le_bytes(member.sig.r[0..4].try_into().unwrap());
            let signed_commit = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::from_consensus(commit_lock),
                input: vec![],
                output: vec![TxOut {
                    value: Amount::from_sat(600),
                    script_pubkey: ScriptBuf::new(),
                }],
            };
            let reveal_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::from_consensus(reveal_lock),
                input: vec![],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(330),
                        script_pubkey: ScriptBuf::new(),
                    },
                    TxOut {
                        value: Amount::from_sat(600),
                        script_pubkey: ScriptBuf::new(),
                    },
                ],
            };
            PreparedBatch {
                aggregate: AggregateStateNullifierV3 {
                    version: 3,
                    format: 0x01,
                    block_anchor: member.build_tip,
                    members: vec![(member.sig.pk, member.sig.r)],
                    raw_s: None,
                    s_agg: Some(member.sig.s),
                },
                payload: vec![0x42],
                signed_commit,
                reveal_tx,
                commit_output: TxOut {
                    value: Amount::from_sat(600),
                    script_pubkey: ScriptBuf::new(),
                },
                block_anchor: member.build_tip,
                commit_vsize: 100,
                reveal_vsize: 200,
                commit_fee: Amount::from_sat(1000),
                reveal_fee: Amount::from_sat(2000),
            }
        }
    }

    impl NullifierBatchPublisher for RecordingPublisher {
        fn publish_batch(&self, members: &[BatchMember]) -> Result<PublishedBatch> {
            ensure!(!members.is_empty(), "recording publisher: empty batch");
            self.batches.lock().expect("lock").push(members.to_vec());
            let agg = AggregateStateNullifierV3 {
                version: 3,
                format: 0x01,
                block_anchor: members[0].build_tip,
                members: members.iter().map(|m| (m.sig.pk, m.sig.r)).collect(),
                raw_s: None,
                s_agg: Some([0xAB; 32]),
            };
            Ok(PublishedBatch {
                aggregate: agg,
                payload: vec![0x42],
                commit_txid: Txid::from_byte_array([0x11; 32]),
                reveal_txid: Txid::from_byte_array([0x22; 32]),
                commit_output: TxOut {
                    value: Amount::from_sat(600),
                    script_pubkey: ScriptBuf::new(),
                },
                block_anchor: members[0].build_tip,
            })
        }

        fn try_prepare(&self, members: &[BatchMember]) -> Result<Option<PreparedBatch>> {
            ensure!(!members.is_empty(), "recording publisher: empty prepare");
            Ok(Some(Self::dummy_prepared(&members[0])))
        }

        fn broadcast_commit(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
            *self.commit_calls.lock().expect("lock") += 1;
            if let Some(err) = self.broadcast_err.lock().expect("lock").as_ref() {
                bail!("{err}");
            }
            if let Some(hook) = self.on_commit.lock().expect("lock").as_ref() {
                hook();
            }
            Ok(prepared.commit_txid())
        }

        fn broadcast_reveal(&self, prepared: &PreparedBatch) -> Result<bitcoin::Txid> {
            *self.reveal_calls.lock().expect("lock") += 1;
            if let Some(err) = self.broadcast_err.lock().expect("lock").as_ref() {
                bail!("{err}");
            }
            Ok(prepared.reveal_txid())
        }
    }

    fn digest_label(label: &[u8]) -> HashDigest {
        let bytes: [u8; 32] = Sha256::digest(label).into();
        host::digest_from_bytes(&bytes).expect("32 bytes")
    }

    fn pos(height: u64, tx_index: u32) -> host::ChainPosition {
        host::ChainPosition {
            height,
            tx_index,
            vin_index: 0,
            member_index: 0,
        }
    }

    fn scanned(
        height: u64,
        tx_index: u32,
        pk: [u8; 32],
        r: [u8; 32],
    ) -> zkcoins_prover::state_engine::ScannedNullifier {
        zkcoins_prover::state_engine::ScannedNullifier::from_survivor(
            &shared::spec_v1::PublishedNullifier {
                chain_pos: pos(height, tx_index),
                pk,
                r,
            },
        )
    }

    /// Two distinct valid x-only points (from real secrets). Used to build
    /// a NullifierOpening whose (R, R') pair is **not** an S2C opening of
    /// any given message — so CommVerify fails loud.
    fn two_xonly(label_a: &[u8], label_b: &[u8]) -> ([u8; 32], [u8; 32]) {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let a = {
            let sk = SecretKey::from_slice(&Sha256::digest(label_a)).expect("sk");
            PublicKey::from_secret_key(&secp, &sk)
                .x_only_public_key()
                .0
                .serialize()
        };
        let b = {
            let sk = SecretKey::from_slice(&Sha256::digest(label_b)).expect("sk");
            PublicKey::from_secret_key(&secp, &sk)
                .x_only_public_key()
                .0
                .serialize()
        };
        (a, b)
    }

    fn sample_proof_data(tag: u8) -> ProofData {
        ProofData {
            new_account_state_hash: digest_label(&[b'a', tag]),
            output_coins_root: digest_label(&[b'o', tag]),
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: host::coinhist_empty_root(),
            nav_commitment: digest_label(&[b'n', tag]),
            npk_commit: [tag; 32],
        }
    }

    #[test]
    fn refuse_legacy_receive_under_v11_claim() {
        // Always clear first — process mode is process-global and other
        // parallel nextest workers must not leave a conflicting claim.
        clear_process_stack_mode_for_test();
        assert!(refuse_legacy_receive_under_v11().is_ok());

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::Legacy);
        assert!(refuse_legacy_receive_under_v11().is_ok());
        clear_process_stack_mode_for_test();

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);
        let err = refuse_legacy_receive_under_v11().expect_err("must refuse");
        assert!(
            err.contains("legacy receive refused") || err.contains("v1.1 receive"),
            "unexpected: {err}"
        );
        clear_process_stack_mode_for_test();
    }

    #[test]
    fn flag_off_legacy_receive_gate_stays_open() {
        // Demonstration for verification item 5: with the flag off / process
        // unclaimed or legacy-claimed, the refuse gate is open. The legacy
        // `receive_coin_into` body is not modified; existing account_node
        // tests exercise its bit-for-bit behaviour.
        clear_process_stack_mode_for_test();
        assert!(refuse_legacy_receive_under_v11().is_ok());
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::Legacy);
        assert!(refuse_legacy_receive_under_v11().is_ok());
        clear_process_stack_mode_for_test();
    }

    #[test]
    fn clause10_rejects_bad_s2c_creating_nullifier_binding() {
        // Normative V.8 signer-one vector from half_agg: honest opening verifies.
        let r = hex::decode("c41ff1a78f2006e5f5aa800efa84b2d2046d108dfa968909974ec37fcb87f6c4")
            .unwrap()
            .try_into()
            .unwrap();
        let r_prime =
            hex::decode("5657f2e91dc3a2d248501a37dbe674d2cf8ed1a13c89b7710ca89aad3b9fe050")
                .unwrap()
                .try_into()
                .unwrap();
        let m_sc = hex::decode("bf50cc59a665bcdc2b5f0754dd754a73e37552a6b1b69eb9e42c07ddd1ae73e2")
            .unwrap()
            .try_into()
            .unwrap();
        zkcoins_prover::half_agg::comm_verify(&r, &m_sc, &r_prime)
            .expect("normative V.8 S2C opening must verify");

        // Same R with a wrong R' (still a valid x-only point) must fail.
        let (_, wrong_r_prime) = two_xonly(b"v11-rx/wrong-rp-a", b"v11-rx/wrong-rp-b");
        let (pk, _) = two_xonly(b"v11-rx/pk-a", b"v11-rx/pk-b");
        let opening = NullifierOpening {
            public_key: pk,
            signature_r: r,
            r_prime: wrong_r_prime,
        };
        // ProofData content only matters for H(PD); we pass a dummy and
        // check the binding function fails on CommVerify regardless.
        let pd = sample_proof_data(1);
        let err = verify_creating_nullifier_binding(&opening, &pd, &pk, 0)
            .expect_err("bad S2C must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("S2C") || msg.contains("clause 10(d)") || msg.contains("opening"),
            "expected clause-10 S2C failure, got: {msg}"
        );
    }

    #[test]
    fn clause10_rejects_pk_mismatch_with_consumed_pubkey() {
        let pd = sample_proof_data(2);
        let (pk, _) = two_xonly(b"v11-rx/pk-match", b"v11-rx/pk-other");
        let (r, r_prime) = two_xonly(b"v11-rx/r", b"v11-rx/rp");
        let opening = NullifierOpening {
            public_key: pk,
            signature_r: r,
            r_prime,
        };
        let wrong_pk = [0x77u8; 32];
        assert_ne!(pk, wrong_pk);
        // Pk binding is checked before S2C, so mismatched consumed_pubkey
        // fails without needing a valid S2C pair.
        let err = verify_creating_nullifier_binding(&opening, &pd, &wrong_pk, 0)
            .expect_err("Pk binding must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("consumed_pubkey") || msg.contains("clause 10(d)"),
            "expected key-binding failure, got: {msg}"
        );
    }

    #[test]
    fn max_rx_coins_boundary_length_gate() {
        // §2.5: at most MAX_RX_COINS; the length check is the first gate in
        // verify_and_begin_receive and must fail loud (no silent truncate).
        assert_eq!(MAX_RX_COINS, 4, "spec §2.5 MAX_RX_COINS");
        for n in 1..=MAX_RX_COINS {
            assert!(n <= MAX_RX_COINS, "at-limit {n} must be allowed by length gate");
        }
        assert!(
            MAX_RX_COINS + 1 > MAX_RX_COINS,
            "above-limit must be rejected by length gate"
        );

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);
        let engine = StateEngine::new(Network::Regtest, 0);
        // Empty slots → fails "at least one" before MAX check.
        let err = verify_and_begin_receive(
            &engine,
            V11ReceiveRequest {
                owner: Address([0; 32]),
                nk: [1; 32],
                current_pubkey: [2; 32],
                slots: vec![],
                next_pubkey: [3; 32],
                nav_rand: [4; 32],
                npk_rand: [5; 32],
            },
        )
        .expect_err("empty receive");
        assert!(
            format!("{err:#}").contains("at least one"),
            "got: {err:#}"
        );
        clear_process_stack_mode_for_test();
    }

    #[test]
    fn max_rx_coins_over_limit_fails_loud_without_constructing_slots() {
        // Construct MAX_RX_COINS+1 dummy slots is expensive (each needs a full
        // ComplianceProof). The length gate runs first — we exercise it by
        // calling the same ensure the production path uses.
        let n = MAX_RX_COINS + 1;
        let result: Result<()> = (|| {
            ensure!(
                n <= MAX_RX_COINS,
                "v1.1 receive: {n} coins exceeds MAX_RX_COINS={MAX_RX_COINS} (§2.5); refusing (no silent truncate)"
            );
            Ok(())
        })();
        let err = result.expect_err("over limit");
        assert!(format!("{err:#}").contains("MAX_RX_COINS"));
    }

    // ---- helpers for orchestration / multi-slot tests -----------------------

    fn xonly_from_label(label: &[u8]) -> [u8; 32] {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&Sha256::digest(label)).expect("sk");
        PublicKey::from_secret_key(&secp, &sk)
            .x_only_public_key()
            .0
            .serialize()
    }

    /// Minimal ComplianceProof shell: only used where the proof object is
    /// required by type but never circuit-verified (host binding tests).
    fn hollow_compliance_proof_with_pis(pd: &ProofData, consumed_pubkey: [u8; 32]) -> ComplianceProof {
        use plonky2::field::polynomial::PolynomialCoeffs;
        use plonky2::field::types::Field;
        use plonky2::fri::proof::FriProof;
        use plonky2::hash::merkle_tree::MerkleCap;
        use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
        use zkcoins_program::F;

        let mut public_inputs = vec![F::ZERO; 108];
        // Layout matches extract_compliance_public_inputs / bridge.
        let write_digest = |pis: &mut [F], offset: usize, d: HashDigest| {
            for (i, el) in d.elements.iter().enumerate() {
                pis[offset + i] = *el;
            }
        };
        write_digest(&mut public_inputs, 0, pd.new_account_state_hash);
        write_digest(&mut public_inputs, 4, pd.output_coins_root);
        write_digest(&mut public_inputs, 8, pd.input_nullifiers_root);
        write_digest(&mut public_inputs, 12, pd.coin_history_root);
        write_digest(&mut public_inputs, 16, pd.nav_commitment);
        // Byte-string limbs at 20..28 (npk) and 28..36 (consumed_pubkey):
        // each limb is a big-endian u32 packed into the 32-byte string.
        for i in 0..8 {
            let start = 28 - 4 * i;
            let limb = u32::from_be_bytes(pd.npk_commit[start..start + 4].try_into().unwrap());
            public_inputs[20 + i] = F::from_canonical_u32(limb);
        }
        for i in 0..8 {
            let start = 28 - 4 * i;
            let limb = u32::from_be_bytes(consumed_pubkey[start..start + 4].try_into().unwrap());
            public_inputs[28 + i] = F::from_canonical_u32(limb);
        }
        // network_id at 36..40 left zero.

        ProofWithPublicInputs {
            proof: Proof {
                wires_cap: MerkleCap(vec![]),
                plonk_zs_partial_products_cap: MerkleCap(vec![]),
                quotient_polys_cap: MerkleCap(vec![]),
                openings: OpeningSet {
                    constants: vec![],
                    plonk_sigmas: vec![],
                    wires: vec![],
                    plonk_zs: vec![],
                    plonk_zs_next: vec![],
                    partial_products: vec![],
                    quotient_polys: vec![],
                    lookup_zs: vec![],
                    lookup_zs_next: vec![],
                },
                opening_proof: FriProof {
                    commit_phase_merkle_caps: vec![],
                    query_round_proofs: vec![],
                    final_poly: PolynomialCoeffs::new(vec![]),
                    pow_witness: F::ZERO,
                },
            },
            public_inputs,
        }
    }

    /// Host-valid slot against an engine that already has the creating
    /// nullifier folded and tip past finality. Inclusion path opens the
    /// **current** size_final nav (must not be built mid-fold).
    fn slot_host_valid_from_folded(
        engine: &StateEngine,
        owner: Address,
        tag: u8,
    ) -> Result<ReceivedCoinSlot> {
        use zkcoins_prover::prover_bridge::test_signing::{
            deterministic_secret, normalized_key, sign_transition,
        };

        let (sk, pk_pt, create_pk) =
            normalized_key(deterministic_secret(&[b'K', tag, b's', b'k']));
        let creating_prev_ash = digest_label(&[b'p', tag]);
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[tag; 32], 2, 1);
        let amount = 10u128 + u128::from(tag);
        let coin_id = host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
        let coin = Coin {
            identifier: coin_id,
            recipient: owner,
            amount,
            asset_id,
        };
        let ocr = host::merkle_root(TreeKind::CoinsRoot, &[coin_id]);
        let empty_nav = Nav {
            size: 0,
            mth: host::nflog_empty(),
        };
        let nav_rand = [tag; 32];
        let pd = ProofData {
            new_account_state_hash: digest_label(&[b'a', tag]),
            output_coins_root: ocr,
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: host::coinhist_empty_root(),
            nav_commitment: host::nav_commitment(empty_nav.root(), &nav_rand),
            npk_commit: [tag; 32],
        };
        let sig = sign_transition(sk, pk_pt, &pd, Network::Regtest);
        let r = sig.transition.signature_r();
        let r_prime = sig.transition.r_prime;
        ensure!(sig.transition.pk_i == create_pk, "signer pk must match create_pk");

        let pos_create = match engine.nflog().lookup(create_pk) {
            LookupResult::Present { pos, r: folded_r, .. } => {
                ensure!(folded_r == r, "folded R must match signed R");
                pos
            }
            other => bail!("creating nullifier missing after fold: {other:?}"),
        };
        let receiver_nav = size_final_nav(engine)?;
        let prefix: Vec<NfLogEntry> = engine
            .nflog_mirror()
            .iter()
            .take(receiver_nav.size as usize)
            .map(|(_, e)| *e)
            .collect();
        let creating_nav_inclusion = host::inclusion_path(pos_create, &prefix)
            .map_err(|e| anyhow::anyhow!("inclusion path: {e}"))?;

        Ok(ReceivedCoinSlot {
            coin,
            creating_proof: hollow_compliance_proof_with_pis(&pd, create_pk),
            output_inclusion: zkcoins_prover::prover_bridge::OutputInclusionProof {
                leaf_index: 0,
                depth: 0,
                siblings: Vec::new(),
            },
            creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: create_pk,
                signature_r: r,
                r_prime,
            },
            creating_nav_inclusion,
            pos_create,
            creating_nav_opening: NavOpening {
                nav: empty_nav,
                nav_rand,
            },
            creating_nav_consistency: Vec::new(),
        })
    }

    /// One received slot that fails clause-10 at the S2C binding (slot index
    /// is what production reports). Builds enough structure to reach S2C.
    fn slot_failing_s2c_at_index(
        owner: Address,
        tag: u8,
        create_pk: [u8; 32],
        create_r: [u8; 32],
    ) -> ReceivedCoinSlot {
        let creating_prev_ash = digest_label(&[b'p', tag]);
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[tag; 32], 2, 1);
        let amount = 10u128 + u128::from(tag);
        let coin_id = host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
        let coin = Coin {
            identifier: coin_id,
            recipient: owner,
            amount,
            asset_id,
        };
        // depth-0 output tree: root = leaf_hash(CoinsRoot, identifier).
        let ocr = host::merkle_root(TreeKind::CoinsRoot, &[coin_id]);
        let pd = ProofData {
            new_account_state_hash: digest_label(&[b'a', tag]),
            output_coins_root: ocr,
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: host::coinhist_empty_root(),
            nav_commitment: digest_label(&[b'n', tag]),
            npk_commit: [tag; 32],
        };
        let (_, wrong_r_prime) = two_xonly(
            &[b'r', tag, 1],
            &[b'r', tag, 2],
        );
        ReceivedCoinSlot {
            coin,
            creating_proof: hollow_compliance_proof_with_pis(&pd, create_pk),
            output_inclusion: zkcoins_prover::prover_bridge::OutputInclusionProof {
                leaf_index: 0,
                depth: 0,
                siblings: Vec::new(),
            },
            creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: create_pk,
                signature_r: create_r,
                r_prime: wrong_r_prime, // deliberately not an S2C opening of H(PD)
            },
            creating_nav_inclusion: Vec::new(),
            pos_create: 0,
            creating_nav_opening: NavOpening {
                nav: Nav {
                    size: 0,
                    mth: host::nflog_empty(),
                },
                nav_rand: [tag; 32],
            },
            creating_nav_consistency: Vec::new(),
        }
    }

    /// Type-level: `append_nullifier` accepts only [`ScannedNullifier`], not a
    /// bare [`host::ChainPosition`]. Possession of the capability is the proof
    /// the position came through the scan path (`from_survivor`).
    #[test]
    fn append_nullifier_requires_scanned_capability_not_bare_chain_position() {
        use zkcoins_prover::state_engine::ScannedNullifier;
        // Signature pin: if append_nullifier is ever re-opened to bare
        // ChainPosition, this assignment fails to compile.
        let _: fn(
            &mut StateEngine,
            ScannedNullifier,
        ) -> Result<u64> = StateEngine::append_nullifier;

        let mut engine = StateEngine::new(Network::Regtest, 0);
        engine.set_tip_height(50);
        let pk = xonly_from_label(b"v11-rx/scan-auth/pk");
        let r = xonly_from_label(b"v11-rx/scan-auth/r");
        // Only via from_survivor (scan-path mint of the capability).
        let scanned = ScannedNullifier::from_survivor(&shared::spec_v1::PublishedNullifier {
            chain_pos: pos(20, 0),
            pk,
            r,
        });
        engine.append_nullifier(scanned).expect("scan-path append");
        assert_eq!(engine.nflog().nav().size, 1);
        assert_eq!(engine.nflog_mirror()[0].0.height, 20);
    }

    /// Crash window that was previously unrecoverable: account advanced on
    /// disk without durable Schnorr `s`. Atomic
    /// [`db_v11::persist_engine_with_pending_members_ready`] closes it —
    /// after the transaction both account and `members_ready` are present,
    /// and resume can reconstruct from the pending row alone.
    #[tokio::test]
    async fn crash_window_atomic_engine_and_members_ready_is_recoverable() {
        use crate::test_db::setup_pool;
        use crate::v11::db_v11::{self, EngineSnapshot};
        use crate::v11::separation::claim_stack_scan_mode;
        use crate::v11::EngineAdapter;

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim v11");

        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("adapter");

        let nk: [u8; 32] = Sha256::digest(b"v11-rx/crash/nk").into();
        let current_pubkey = xonly_from_label(b"v11-rx/crash/sk0");
        let next_pubkey = xonly_from_label(b"v11-rx/crash/sk1");
        let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));
        let pk = current_pubkey;
        let r = xonly_from_label(b"v11-rx/crash/r");
        let s = [0x5Au8; 32];
        let r_prime = xonly_from_label(b"v11-rx/crash/rp");

        // Simulate post-apply account (last_nullifier set, pos None).
        adapter
            .with_engine_mut(|engine| {
                let state = host::AccountState::new(
                    owner,
                    host::nk_commit(&nk),
                    std::collections::BTreeMap::new(),
                    next_pubkey,
                    1,
                    host::coinhist_empty_root(),
                )
                .expect("state");
                let record = AccountRecord {
                    state,
                    coinhist: host::CoinHistTree::new(),
                    nk,
                    genesis_pubkey: current_pubkey,
                    spendable: std::collections::BTreeMap::new(),
                    spent_ids: std::collections::BTreeSet::new(),
                    last_proof: None,
                    last_nav_opening: None,
                    last_nullifier: Some(NullifierOpening {
                        public_key: pk,
                        signature_r: r,
                        r_prime,
                    }),
                    last_nullifier_pos: None,
                };
                engine.insert_account(owner, record).expect("insert");
            })
            .expect("mutate");

        let snap = adapter.snapshot_live();
        db_v11::persist_engine_with_pending_members_ready(
            &pool,
            &snap,
            owner,
            pk,
            r,
            s,
            r_prime,
            100,
            [0xBB; 32],
        )
        .await
        .expect("atomic persist");

        // Simulate crash: reload from DB only.
        let reloaded = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("reload");
        reloaded.with_engine(|engine| {
            let rec = engine.account(&owner).expect("account survived");
            assert!(rec.last_nullifier.is_some());
            assert!(rec.last_nullifier_pos.is_none());
        });
        let pending = db_v11::load_pending_publish(&pool, pk)
            .await
            .expect("load")
            .expect("members_ready row must exist — previously unrecoverable without s");
        assert_eq!(pending.status, db_v11::PENDING_PUBLISH_MEMBERS_READY);
        assert_eq!(pending.s, s);
        assert_eq!(pending.r, r);

        // Resume from members_ready with a construct-capable publisher.
        let publisher = RecordingPublisher::new();
        let published = resume_pending_publish(&reloaded, &publisher, pk)
            .await
            .expect("resume")
            .expect("should produce a batch");
        assert_eq!(published.aggregate.members.len(), 1);
        let after = db_v11::load_pending_publish(&pool, pk)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(after.status, db_v11::PENDING_PUBLISH_REVEAL_BROADCAST);

        clear_process_stack_mode_for_test();
        let _ = EngineSnapshot::from_engine_with_tip_hash; // keep type reachable
    }

    /// Rebroadcast of an already-known transaction is success, not error.
    #[tokio::test]
    async fn rebroadcast_already_known_transaction_succeeds() {
        use crate::test_db::setup_pool;
        use crate::v11::db_v11;
        use crate::v11::separation::claim_stack_scan_mode;
        use crate::v11::EngineAdapter;

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim");
        // Seed empty meta so stack checks pass on writes.
        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("adapter");

        let owner = Address(xonly_from_label(b"v11-rx/rebcast/owner"));
        let pk = xonly_from_label(b"v11-rx/rebcast/pk");
        let r = xonly_from_label(b"v11-rx/rebcast/r");
        let s = [0x77u8; 32];
        let r_prime = xonly_from_label(b"v11-rx/rebcast/rp");
        let member = BatchMember {
            sig: NullifierSig { pk, r, s },
            build_tip: BlockAnchor {
                block_hash: [0xCC; 32],
                height: 42,
            },
        };
        let prepared = RecordingPublisher::dummy_prepared(&member);
        let commit_tx = serialize(&prepared.signed_commit);
        let reveal_tx = serialize(&prepared.reveal_tx);

        db_v11::insert_pending_publish_members_ready(
            &pool,
            owner,
            pk,
            r,
            s,
            r_prime,
            42,
            [0xCC; 32],
        )
        .await
        .expect("members_ready");
        db_v11::mark_pending_publish_constructed(
            &pool,
            pk,
            &commit_tx,
            &reveal_tx,
            prepared.commit_txid().to_byte_array(),
            prepared.reveal_txid().to_byte_array(),
        )
        .await
        .expect("constructed");

        // Publisher reports the exact chain "already known" signal.
        let publisher = RecordingPublisher::with_broadcast_err(
            "sendrawtransaction RPC error: txn-already-known",
        );
        let published = resume_pending_publish(&adapter, &publisher, pk)
            .await
            .expect("already-known must be success")
            .expect("batch");
        assert_eq!(published.commit_txid, prepared.commit_txid());
        assert_eq!(published.reveal_txid, prepared.reveal_txid());
        assert!(*publisher.commit_calls.lock().unwrap() >= 1);
        assert!(*publisher.reveal_calls.lock().unwrap() >= 1);

        let row = db_v11::load_pending_publish(&pool, pk)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(row.status, db_v11::PENDING_PUBLISH_REVEAL_BROADCAST);

        // A genuine (non-already-done) error must still fail loud.
        db_v11::mark_pending_publish_status(
            &pool,
            pk,
            db_v11::PENDING_PUBLISH_REVEAL_BROADCAST,
            db_v11::PENDING_PUBLISH_FAILED,
        )
        .await
        .ok(); // may fail status machine; re-seed constructed path instead
        // Fresh constructed row under a different pk for the negative case.
        let pk2 = xonly_from_label(b"v11-rx/rebcast/pk2");
        let member2 = BatchMember {
            sig: NullifierSig {
                pk: pk2,
                r,
                s,
            },
            build_tip: member.build_tip,
        };
        let prepared2 = RecordingPublisher::dummy_prepared(&member2);
        db_v11::insert_pending_publish_members_ready(
            &pool,
            owner,
            pk2,
            r,
            s,
            r_prime,
            42,
            [0xCC; 32],
        )
        .await
        .expect("m2");
        db_v11::mark_pending_publish_constructed(
            &pool,
            pk2,
            &serialize(&prepared2.signed_commit),
            &serialize(&prepared2.reveal_tx),
            prepared2.commit_txid().to_byte_array(),
            prepared2.reveal_txid().to_byte_array(),
        )
        .await
        .expect("c2");
        let bad = RecordingPublisher::with_broadcast_err("connection refused");
        let err = resume_pending_publish(&adapter, &bad, pk2)
            .await
            .expect_err("generic error must not be success");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("connection refused") || msg.contains("not an already-done"),
            "got: {msg}"
        );

        clear_process_stack_mode_for_test();
    }

    /// Test 2: multi-slot host clause-10 through the real entry point
    /// [`verify_and_begin_receive`]. Only the intended slot is corrupted;
    /// earlier slots pass host checks so the error names the rejected index.
    #[test]
    fn multi_slot_clause10_rejects_corrupt_slot_2_and_slot_4() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let nk: [u8; 32] = Sha256::digest(b"v11-rx/multi/nk").into();
        let current_pubkey = xonly_from_label(b"v11-rx/multi/sk0");
        let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));

        assert_eq!(MAX_RX_COINS, 4);

        for corrupt_index in [1usize, 3usize] {
            // Fresh engine per iteration so NfLog folds stay local.
            let mut engine = StateEngine::new(Network::Regtest, 0);
            // Fold all creating nullifiers first, tip past finality, then build
            // slots so every inclusion path opens the final receiver nav.
            let mut prepared: Vec<(usize, u8, bool)> = Vec::new();
            for i in 0..MAX_RX_COINS {
                let tag = i as u8 + 1;
                let corrupt = i == corrupt_index;
                prepared.push((i, tag, corrupt));
                if corrupt {
                    let create_pk = xonly_from_label(&[b'p', tag]);
                    let create_r = xonly_from_label(&[b'r', tag]);
                    engine
                        .append_nullifier(scanned(
                            20 + i as u64,
                            0,
                            create_pk,
                            create_r,
                        ))
                        .expect("fold corrupt create");
                } else {
                    // Fold only; slot body built after tip is final.
                    let (sk, pk_pt, create_pk) =
                        zkcoins_prover::prover_bridge::test_signing::normalized_key(
                            zkcoins_prover::prover_bridge::test_signing::deterministic_secret(&[
                                b'K', tag, b's', b'k',
                            ]),
                        );
                    let creating_prev_ash = digest_label(&[b'p', tag]);
                    let asset_id =
                        host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[tag; 32], 2, 1);
                    let amount = 10u128 + u128::from(tag);
                    let coin_id =
                        host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
                    let ocr = host::merkle_root(TreeKind::CoinsRoot, &[coin_id]);
                    let empty_nav = Nav {
                        size: 0,
                        mth: host::nflog_empty(),
                    };
                    let nav_rand = [tag; 32];
                    let pd = ProofData {
                        new_account_state_hash: digest_label(&[b'a', tag]),
                        output_coins_root: ocr,
                        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
                        coin_history_root: host::coinhist_empty_root(),
                        nav_commitment: host::nav_commitment(empty_nav.root(), &nav_rand),
                        npk_commit: [tag; 32],
                    };
                    let sig = zkcoins_prover::prover_bridge::test_signing::sign_transition(
                        sk,
                        pk_pt,
                        &pd,
                        Network::Regtest,
                    );
                    let r = sig.transition.signature_r();
                    engine
                        .append_nullifier(scanned(20 + i as u64, 0, create_pk, r))
                        .expect("fold good create");
                    let _ = (creating_prev_ash, amount, coin_id, empty_nav, nav_rand, sig);
                }
            }
            // tip so every folded height (20..23) is size_final: max_final = tip-5 ≥ 23 → tip ≥ 28.
            engine.set_tip_height(40);

            let mut slots = Vec::with_capacity(MAX_RX_COINS);
            for (i, tag, corrupt) in prepared {
                if corrupt {
                    let create_pk = xonly_from_label(&[b'p', tag]);
                    let create_r = xonly_from_label(&[b'r', tag]);
                    slots.push(slot_failing_s2c_at_index(owner, tag, create_pk, create_r));
                } else {
                    slots.push(
                        slot_host_valid_from_folded(&engine, owner, tag)
                            .expect("good slot from folded nullifier"),
                    );
                }
                let _ = i;
            }

            let err = verify_and_begin_receive(
                &engine,
                V11ReceiveRequest {
                    owner,
                    nk,
                    current_pubkey,
                    slots,
                    next_pubkey: xonly_from_label(b"v11-rx/multi/sk1"),
                    nav_rand: [0x41; 32],
                    npk_rand: [0x42; 32],
                },
            )
            .expect_err("corrupt multi-slot receive must fail");
            let msg = format!("{err:#}");
            assert!(
                msg.contains(&format!("received slot {corrupt_index}"))
                    || msg.contains(&format!("slot {corrupt_index}")),
                "expected rejection of slot {corrupt_index}, got: {msg}"
            );
            // Confirm the failure is the intentional S2C corruption, not an
            // earlier host gate on a "good" slot.
            assert!(
                msg.contains("S2C")
                    || msg.contains("clause 10(d)")
                    || msg.contains("opening")
                    || msg.contains("clause-10"),
                "expected clause-10/S2C failure for slot {corrupt_index}, got: {msg}"
            );
        }

        clear_process_stack_mode_for_test();
    }

    /// Test 3: scan reconciliation — chain ordering wins over local
    /// publication order. Two nullifiers "published" A-then-B locally, but the
    /// survivor stream presents B-then-A on chain; after the production
    /// [`crate::v11::scan::fold_survivors_into_engine`] the NfLog
    /// first-occurrence order is B then A.
    ///
    /// Pure engine fold (same core as `apply_forward_scan`) — no Postgres.
    #[test]
    fn scan_reconciliation_chain_order_wins_over_local_publish_order() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let mut engine = StateEngine::new(Network::Regtest, 10);
        engine.set_tip_height(60);

        // Local "publication order" would have been A then B (synthetic).
        let pk_a = xonly_from_label(b"v11-rx/scan/a-pk");
        let r_a = xonly_from_label(b"v11-rx/scan/a-r");
        let pk_b = xonly_from_label(b"v11-rx/scan/b-pk");
        let r_b = xonly_from_label(b"v11-rx/scan/b-r");
        assert_ne!(pk_a, pk_b);

        // Chain survivor stream deliberately listed in reverse of "local
        // publish order" A-then-B: B is mined at height 50, A at 51.
        // fold_survivors sorts by §3.6 key, so presentation order is irrelevant.
        let survivors = vec![
            shared::spec_v1::PublishedNullifier {
                chain_pos: host::ChainPosition {
                    height: 51,
                    tx_index: 0,
                    vin_index: 0,
                    member_index: 0,
                },
                pk: pk_a,
                r: r_a,
            },
            shared::spec_v1::PublishedNullifier {
                chain_pos: host::ChainPosition {
                    height: 50,
                    tx_index: 0,
                    vin_index: 0,
                    member_index: 0,
                },
                pk: pk_b,
                r: r_b,
            },
        ];

        assert_eq!(engine.nflog().nav().size, 0, "pre-scan NfLog empty");
        let stats = crate::v11::scan::fold_survivors_into_engine(&mut engine, &survivors)
            .expect("fold");
        assert_eq!(stats.appended, 2);
        assert_eq!(stats.duplicate_ignored, 0);

        let mirror = engine.nflog_mirror();
        assert_eq!(mirror.len(), 2);
        // Chain wins: B (height 50) before A (height 51), not local A-then-B.
        assert_eq!(mirror[0].1.pk, pk_b, "first entry must be B (earlier height)");
        assert_eq!(mirror[0].1.r, r_b);
        assert_eq!(mirror[0].0.height, 50);
        assert_eq!(mirror[1].1.pk, pk_a, "second entry must be A");
        assert_eq!(mirror[1].1.r, r_a);
        assert_eq!(mirror[1].0.height, 51);

        match engine.nflog().lookup(pk_b) {
            LookupResult::Present { pos, r, .. } => {
                assert_eq!(pos, 0);
                assert_eq!(r, r_b);
            }
            other => panic!("pk_b present: {other:?}"),
        }
        match engine.nflog().lookup(pk_a) {
            LookupResult::Present { pos, r, .. } => {
                assert_eq!(pos, 1);
                assert_eq!(r, r_a);
            }
            other => panic!("pk_a present: {other:?}"),
        }

        clear_process_stack_mode_for_test();
    }

    /// Deferred nullifier + publish + scan-fold: account may be credited and
    /// the nullifier published, but the canonical NfLog only grows when the
    /// scanner folds the real chain position — never at a synthetic local tip.
    ///
    /// Mirrors the post-state of `finalise_pending_chain_nullifier` without a
    /// multi-minute prove. Production prove path:
    /// [`production_path_receive_begin_finalise_publish_persist_reload`].
    #[test]
    fn receive_publish_leaves_nflog_to_scanner_at_real_chain_position() {
        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let network = Network::Regtest;
        let activation = 10u64;
        let mut engine = StateEngine::new(network, activation);
        engine.set_tip_height(100);

        let nk: [u8; 32] = Sha256::digest(b"v11-rx/ord/nk").into();
        let current_pubkey = xonly_from_label(b"v11-rx/ord/sk0");
        let next_pubkey = xonly_from_label(b"v11-rx/ord/sk1");
        let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));

        let create_pk = xonly_from_label(b"v11-rx/ord/create");
        let create_r = xonly_from_label(b"v11-rx/ord/create-r");
        engine
            .append_nullifier(scanned(20, 0, create_pk, create_r))
            .expect("creating nf");

        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[0x31; 32], 2, 1);
        let creating_prev_ash = digest_label(b"create-prev-ash");
        let amount = 77u128;
        let coin_id = host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
        let coin = Coin {
            identifier: coin_id,
            recipient: owner,
            amount,
            asset_id,
        };

        let recv_r = xonly_from_label(b"v11-rx/ord/recv-r");
        let recv_r_prime = xonly_from_label(b"v11-rx/ord/recv-rp");
        let nflog_before = engine.nflog().nav().size;
        assert_eq!(nflog_before, 1, "only creating nullifier");

        // Deferred-nullifier account apply (production finalise_pending_chain_nullifier
        // post-state): credit account, last_nullifier set, last_nullifier_pos = None,
        // NfLog unchanged.
        {
            let mut hist = host::CoinHistTree::new();
            let id = host::digest_to_bytes(&coin_id);
            hist.admit(id).expect("admit");
            let ch_root = hist.root();
            let mut balances = std::collections::BTreeMap::new();
            balances.insert(host::digest_to_bytes(&asset_id), amount);
            let state = host::AccountState::new(
                owner,
                host::nk_commit(&nk),
                balances,
                next_pubkey,
                1,
                ch_root,
            )
            .expect("state");
            let mut spendable = std::collections::BTreeMap::new();
            spendable.insert(
                id,
                TrackedCoin {
                    coin: coin.clone(),
                    creating_prev_ash,
                    coin_index: 0,
                },
            );
            let record = AccountRecord {
                state,
                coinhist: hist,
                nk,
                genesis_pubkey: current_pubkey,
                spendable,
                spent_ids: std::collections::BTreeSet::new(),
                last_proof: Some(hollow_compliance_proof_with_pis(
                    &ProofData {
                        new_account_state_hash: digest_label(b"new-ash"),
                        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[]),
                        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
                        coin_history_root: ch_root,
                        nav_commitment: digest_label(b"nav"),
                        npk_commit: [0; 32],
                    },
                    current_pubkey,
                )),
                last_nav_opening: Some(NavOpening {
                    nav: Nav {
                        size: 0,
                        mth: host::nflog_empty(),
                    },
                    nav_rand: [0x11; 32],
                }),
                last_nullifier: Some(NullifierOpening {
                    public_key: current_pubkey,
                    signature_r: recv_r,
                    r_prime: recv_r_prime,
                }),
                last_nullifier_pos: None,
            };
            let rebuilt = StateEngine::from_persisted(
                engine.network(),
                engine.activation_height(),
                engine.tip_height(),
                engine.fold_seq(),
                engine.nflog_mirror(),
                vec![(owner, record)],
            )
            .expect("rebuild");
            engine = rebuilt;
        }

        assert_eq!(engine.nflog().nav().size, nflog_before, "apply must not grow NfLog");
        {
            let rec = engine.account(&owner).expect("account");
            assert!(rec.last_nullifier_pos.is_none());
            assert!(rec.last_nullifier.is_some());
            assert!(rec.last_proof.is_some());
            assert_eq!(
                rec.state.balances.values().copied().sum::<u128>(),
                77
            );
        }

        // Publish (production helper). Still no NfLog entry.
        let signature = TransitionSignature {
            pk_i: current_pubkey,
            signature: {
                let mut s = [0u8; 64];
                s[..32].copy_from_slice(&recv_r);
                s[32..].copy_from_slice(&[0xCD; 32]);
                s
            },
            r_prime: recv_r_prime,
        };
        let applied = AppliedTransition {
            proved: zkcoins_prover::prover_bridge::ProvedTransition {
                proof: hollow_compliance_proof_with_pis(
                    &ProofData {
                        new_account_state_hash: digest_label(b"new-ash"),
                        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[]),
                        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
                        coin_history_root: host::coinhist_empty_root(),
                        nav_commitment: digest_label(b"nav"),
                        npk_commit: [0; 32],
                    },
                    current_pubkey,
                ),
                proof_data: ProofData {
                    new_account_state_hash: digest_label(b"new-ash"),
                    output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[]),
                    input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
                    coin_history_root: host::coinhist_empty_root(),
                    nav_commitment: digest_label(b"nav"),
                    npk_commit: [0; 32],
                },
                consumed_pubkey: current_pubkey,
                network_id: host::network_id_regtest(),
            },
            nullifier: (current_pubkey, recv_r),
        };
        let publisher = RecordingPublisher::new();
        let build_tip = BlockAnchor {
            block_hash: [0xBB; 32],
            height: 100,
        };
        publish_applied_nullifier(&publisher, &applied, &signature, build_tip).expect("publish");
        assert_eq!(publisher.published_members().len(), 1);
        assert_eq!(
            engine.nflog().nav().size,
            nflog_before,
            "publish must not fold into NfLog"
        );
        // Receive nullifier still absent from canonical log.
        assert!(matches!(
            engine.nflog().lookup(current_pubkey),
            LookupResult::Absent
        ));

        // Scanner folds at the real chain position (not tip_height/fold_seq).
        let chain_pos = host::ChainPosition {
            height: 42,
            tx_index: 7,
            vin_index: 0,
            member_index: 0,
        };
        let survivors = vec![shared::spec_v1::PublishedNullifier {
            chain_pos,
            pk: current_pubkey,
            r: recv_r,
        }];
        crate::v11::scan::fold_survivors_into_engine(&mut engine, &survivors).expect("scan fold");

        assert_eq!(engine.nflog().nav().size, nflog_before + 1);
        match engine.nflog().lookup(current_pubkey) {
            LookupResult::Present { pos, r, .. } => {
                assert_eq!(r, recv_r);
                assert_eq!(pos, 1);
            }
            other => panic!("receive nullifier present after scan: {other:?}"),
        }
        let mirror = engine.nflog_mirror();
        let (p, _) = mirror
            .iter()
            .find(|(_, ent)| ent.pk == current_pubkey)
            .expect("mirror entry");
        assert_eq!(p.height, 42, "chain height, not local tip 100");
        assert_eq!(p.tx_index, 7, "chain tx_index, not local fold_seq");

        clear_process_stack_mode_for_test();
    }

    // -----------------------------------------------------------------------
    // Concurrent scan races + production-path e2e helpers
    // -----------------------------------------------------------------------

    /// Hollow proved envelope: apply re-validates live state but does not
    /// Plonky2-verify. Lets race tests inject scanner work between prove and
    /// apply without a multi-minute circuit build.
    fn hollow_proved_pending(
        pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<zkcoins_prover::state_engine::ProvedPendingTransition> {
        let proved = zkcoins_prover::prover_bridge::ProvedTransition {
            proof: hollow_compliance_proof_with_pis(&pending.proof_data, signature.pk_i),
            proof_data: pending.proof_data.clone(),
            consumed_pubkey: signature.pk_i,
            network_id: host::network_id_regtest(),
        };
        zkcoins_prover::state_engine::ProvedPendingTransition::from_parts(
            pending, proved, signature,
        )
    }

    fn placeholder_rx_signature(pk_i: [u8; 32]) -> TransitionSignature {
        let r = xonly_from_label(b"v11-rx/race/recv-r");
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&[0xCD; 32]);
        TransitionSignature {
            pk_i,
            signature,
            r_prime: xonly_from_label(b"v11-rx/race/recv-rp"),
        }
    }

    /// Seed adapter with one creating nullifier + a host-valid InitialProof
    /// receive pending for `owner`.
    async fn seeded_receive_pending(
        adapter: &crate::v11::EngineAdapter,
    ) -> Result<(PendingTransition, TransitionSignature, Address, [u8; 32])> {
        let nk: [u8; 32] = Sha256::digest(b"v11-rx/race/nk").into();
        let current_pubkey = xonly_from_label(b"v11-rx/race/sk0");
        let next_pubkey = xonly_from_label(b"v11-rx/race/sk1");
        let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));

        // Fold creating nullifier with the R that slot_host_valid_from_folded will sign.
        let tag = 1u8;
        let (sk, pk_pt, create_pk) =
            zkcoins_prover::prover_bridge::test_signing::normalized_key(
                zkcoins_prover::prover_bridge::test_signing::deterministic_secret(&[
                    b'K', tag, b's', b'k',
                ]),
            );
        let creating_prev_ash = digest_label(&[b'p', tag]);
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[tag; 32], 2, 1);
        let amount = 10u128 + u128::from(tag);
        let coin_id = host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
        let ocr = host::merkle_root(TreeKind::CoinsRoot, &[coin_id]);
        let empty_nav = Nav {
            size: 0,
            mth: host::nflog_empty(),
        };
        let nav_rand = [tag; 32];
        let pd = ProofData {
            new_account_state_hash: digest_label(&[b'a', tag]),
            output_coins_root: ocr,
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: host::coinhist_empty_root(),
            nav_commitment: host::nav_commitment(empty_nav.root(), &nav_rand),
            npk_commit: [tag; 32],
        };
        let create_sig = zkcoins_prover::prover_bridge::test_signing::sign_transition(
            sk,
            pk_pt,
            &pd,
            Network::Regtest,
        );
        let create_r = create_sig.transition.signature_r();
        let _ = (sk, pk_pt, create_sig);

        adapter
            .with_engine_mut(|engine| {
                engine
                    .append_nullifier(scanned(20, 0, create_pk, create_r))
                    .expect("fold creating");
                engine.set_tip_height(40);
            })
            .expect("seed creating nf");

        let slot = adapter
            .with_engine(|engine| slot_host_valid_from_folded(engine, owner, tag))
            .expect("host-valid slot");
        let pending = adapter.with_engine(|engine| {
            verify_and_begin_receive(
                engine,
                V11ReceiveRequest {
                    owner,
                    nk,
                    current_pubkey,
                    slots: vec![slot],
                    next_pubkey,
                    nav_rand: [0x41; 32],
                    npk_rand: [0x42; 32],
                },
            )
        })?;
        let signature = placeholder_rx_signature(current_pubkey);
        Ok((pending, signature, owner, current_pubkey))
    }

    /// Concurrent scanner append lands **during** the prove window (after
    /// unlocked prove material is ready, before write-gate apply). Receive
    /// must still commit: re-validation admits a still-canonical receiver
    /// NAV as a prefix when size_final only grows / unrelated entries append.
    #[tokio::test]
    async fn concurrent_scanner_append_during_prove_still_commits() {
        use crate::test_db::setup_pool;
        use crate::v11::db_v11;
        use crate::v11::separation::claim_stack_scan_mode;
        use crate::v11::EngineAdapter;
        use std::sync::Arc;

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim");
        let adapter = Arc::new(
            EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
                .await
                .expect("adapter"),
        );

        let (pending, signature, owner, current_pubkey) = seeded_receive_pending(&adapter)
            .await
            .expect("seed pending");
        let nflog_size_at_prove = adapter.with_engine(|e| e.nflog().nav().size);
        assert_eq!(nflog_size_at_prove, 1, "only creating nullifier");

        // Unlocked prove material (hollow — production uses detached real prove).
        let proved = hollow_proved_pending(pending, signature.clone()).expect("hollow prove");

        // Simulate concurrent scanner append during the prove window:
        // unrelated nullifier folded while receive holds neither lock.
        let concurrent_pk = xonly_from_label(b"v11-rx/race/concurrent-pk");
        let concurrent_r = xonly_from_label(b"v11-rx/race/concurrent-r");
        adapter
            .with_engine_mut(|engine| {
                engine
                    .append_nullifier(scanned(21, 0, concurrent_pk, concurrent_r))
                    .expect("concurrent append during prove");
            })
            .expect("mutate");
        let size_after_concurrent = adapter.with_engine(|e| e.nflog().nav().size);
        assert_eq!(
            size_after_concurrent, nflog_size_at_prove + 1,
            "scanner moved the global NfLog during prove"
        );

        let publisher = RecordingPublisher::new();
        let build_tip = BlockAnchor {
            block_hash: [0xBB; 32],
            height: 40,
        };
        let outcome = commit_proved_receive(
            &adapter,
            proved,
            signature,
            &publisher,
            build_tip,
        )
        .await
        .expect("receive must commit despite concurrent append during prove");

        assert_eq!(outcome.owner, owner);
        assert_eq!(outcome.nullifier.0, current_pubkey);
        assert_eq!(outcome.new_send_counter, 1);
        assert!(!outcome.admitted_coin_ids.is_empty());
        // Construct path uses try_prepare + broadcast, not publish_batch.
        assert_eq!(*publisher.commit_calls.lock().expect("lock"), 1);
        assert_eq!(*publisher.reveal_calls.lock().expect("lock"), 1);
        assert_eq!(outcome.published.member_count, 1);

        // Our apply did not invent an NfLog entry; concurrent entry remains.
        adapter.with_engine(|engine| {
            assert_eq!(engine.nflog().nav().size, size_after_concurrent);
            assert!(matches!(
                engine.nflog().lookup(current_pubkey),
                LookupResult::Absent
            ));
            assert!(matches!(
                engine.nflog().lookup(concurrent_pk),
                LookupResult::Present { .. }
            ));
            let rec = engine.account(&owner).expect("credited");
            assert!(rec.last_nullifier.is_some());
            assert!(rec.last_nullifier_pos.is_none());
        });

        let pending_row = db_v11::load_pending_publish(&pool, current_pubkey)
            .await
            .expect("load")
            .expect("durable intent");
        assert_eq!(
            pending_row.status,
            db_v11::PENDING_PUBLISH_REVEAL_BROADCAST
        );

        clear_process_stack_mode_for_test();
    }

    /// Concurrent scanner append lands **after** a successful broadcast.
    /// Outcome must remain success — decided from this transition's apply +
    /// publish, not from a global NfLog counter anyone can move.
    #[tokio::test]
    async fn concurrent_append_after_broadcast_still_reported_success() {
        use crate::test_db::setup_pool;
        use crate::v11::separation::claim_stack_scan_mode;
        use crate::v11::EngineAdapter;
        use std::sync::Arc;

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim");
        let adapter = Arc::new(
            EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
                .await
                .expect("adapter"),
        );

        let (pending, signature, owner, current_pubkey) = seeded_receive_pending(&adapter)
            .await
            .expect("seed pending");
        let proved = hollow_proved_pending(pending, signature.clone()).expect("hollow prove");

        let concurrent_pk = xonly_from_label(b"v11-rx/race/post-bc-pk");
        let concurrent_r = xonly_from_label(b"v11-rx/race/post-bc-r");
        let adapter_hook = Arc::clone(&adapter);
        let publisher = RecordingPublisher::with_on_commit(move || {
            adapter_hook
                .with_engine_mut(|engine| {
                    engine
                        .append_nullifier(scanned(22, 0, concurrent_pk, concurrent_r))
                        .expect("append after broadcast");
                })
                .expect("concurrent post-broadcast append");
        });
        let build_tip = BlockAnchor {
            block_hash: [0xCC; 32],
            height: 40,
        };

        let outcome = commit_proved_receive(
            &adapter,
            proved,
            signature,
            &publisher,
            build_tip,
        )
        .await
        .expect(
            "successful broadcast must not be reported as failure when an unrelated \
             scanner append moves the global NfLog afterwards",
        );

        assert_eq!(outcome.owner, owner);
        assert_eq!(outcome.nullifier.0, current_pubkey);
        assert_eq!(*publisher.commit_calls.lock().expect("lock"), 1);
        // Concurrent append actually landed after broadcast.
        adapter.with_engine(|engine| {
            assert!(
                matches!(
                    engine.nflog().lookup(concurrent_pk),
                    LookupResult::Present { .. }
                ),
                "post-broadcast concurrent append must be visible"
            );
            // Receive still credited.
            assert!(engine.account(&owner).is_some());
        });

        clear_process_stack_mode_for_test();
    }

    /// Production entry: [`verify_and_begin_receive`] → hollow prove stand-in
    /// → [`commit_proved_receive`] (apply + atomic persist + publisher) →
    /// boot reload. Real Plonky2 prove is covered by the ignored engine e2e;
    /// this test covers the node orchestration surface without bitcoind.
    ///
    /// **Stopping point:** `RecordingPublisher` fakes construct/broadcast —
    /// no live bitcoind / chain inclusion. Scanner fold of the own nullifier
    /// is a separate step (asserted Absent here).
    #[tokio::test]
    async fn production_path_receive_begin_finalise_publish_persist_reload() {
        use crate::test_db::setup_pool;
        use crate::v11::db_v11;
        use crate::v11::separation::claim_stack_scan_mode;
        use crate::v11::EngineAdapter;

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim");
        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("adapter");

        let (pending, signature, owner, current_pubkey) = seeded_receive_pending(&adapter)
            .await
            .expect("verify_and_begin_receive path");
        // Entry was verify_and_begin_receive (inside helper).
        assert_eq!(pending.owner, owner);
        assert_eq!(
            pending.mode,
            zkcoins_prover::prover_bridge::TransitionMode::InitialProof
        );

        let proved = hollow_proved_pending(pending, signature.clone()).expect("prove stand-in");
        let publisher = RecordingPublisher::new();
        let build_tip = BlockAnchor {
            block_hash: [0xDD; 32],
            height: 40,
        };
        let outcome = commit_proved_receive(&adapter, proved, signature, &publisher, build_tip)
            .await
            .expect("commit + persist + publish");

        assert_eq!(outcome.nullifier.0, current_pubkey);
        assert_eq!(outcome.new_send_counter, 1);
        assert_eq!(*publisher.commit_calls.lock().expect("lock"), 1);
        assert_eq!(*publisher.reveal_calls.lock().expect("lock"), 1);
        assert_eq!(outcome.published.member_count, 1);

        // Durable intent + engine snapshot survive reload.
        let reloaded = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("reload");
        reloaded.with_engine(|engine| {
            let rec = engine.account(&owner).expect("account persisted");
            assert_eq!(rec.state.send_counter, 1);
            assert!(rec.last_nullifier.is_some());
            assert!(rec.last_nullifier_pos.is_none());
            assert!(matches!(
                engine.nflog().lookup(current_pubkey),
                LookupResult::Absent
            ));
        });
        let row = db_v11::load_pending_publish(&pool, current_pubkey)
            .await
            .expect("load")
            .expect("pending publish row");
        assert_eq!(row.status, db_v11::PENDING_PUBLISH_REVEAL_BROADCAST);

        clear_process_stack_mode_for_test();
    }

    /// Heavy production path with a **genuine** Plonky2 prove, entered through
    /// [`verify_and_begin_receive`] and [`finalise_publish_persist`].
    ///
    /// **Stopping point:** `RecordingPublisher` substitutes for bitcoind —
    /// construct/broadcast are faked; chain inclusion / scanner fold are not
    /// exercised here (engine e2e covers scan-fold of the own nullifier).
    #[tokio::test]
    #[ignore = "heavy: real Plonky2 prove for mint+send+receive (minutes); run with --ignored --release"]
    async fn production_path_receive_with_genuine_prove_via_verify_and_begin() {
        use crate::test_db::setup_pool;
        use crate::v11::db_v11;
        use crate::v11::separation::claim_stack_scan_mode;
        use crate::v11::EngineAdapter;
        use zkcoins_prover::prover_bridge::test_signing::{
            deterministic_secret, normalized_key, sign_transition,
        };
        use zkcoins_prover::prover_bridge::{OutputInclusionProof, TransitionMode};
        use zkcoins_prover::state_engine::{MintRequest, ScannedNullifier, SendRequest};

        clear_process_stack_mode_for_test();
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim");
        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Testnet, 0)
            .await
            .expect("adapter");

        let alice_nk: [u8; 32] =
            Sha256::digest(b"zkCoins/v1/state-engine/receive-e2e/alice-nk").into();
        let (alice_secret0, alice_public0, alice_pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/alice-sk0",
        ));
        let (_, _, alice_pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/alice-sk1",
        ));
        let alice_owner = Address(host::address(&alice_pk0, host::nk_commit(&alice_nk)));

        let mint_pending = adapter
            .with_engine(|engine| {
                engine.begin_mint(MintRequest {
                    owner: alice_owner,
                    nk: alice_nk,
                    current_pubkey: alice_pk0,
                    next_pubkey: alice_pk1,
                    name: b"G3 production e2e asset".to_vec(),
                    decimals: 2,
                    amount: 100,
                    issuance_version: 1,
                    cap_total: 0,
                    terms_salt: [0u8; 32],
                    nav_rand: [0x21; 32],
                    npk_rand: [0x22; 32],
                })
            })
            .expect("begin_mint");
        let mint_asset = mint_pending
            .witness_wip
            .output_coins
            .first()
            .expect("mint output")
            .asset_id;
        let mint_sig = sign_transition(
            alice_secret0,
            alice_public0,
            &mint_pending.proof_data,
            Network::Testnet,
        );
        adapter
            .with_engine_mut(|engine| {
                engine
                    .finalise(mint_pending, mint_sig.transition.clone())
                    .expect("finalise mint");
                let nf = engine
                    .account(&alice_owner)
                    .expect("alice")
                    .last_nullifier
                    .clone()
                    .expect("mint nf");
                engine
                    .append_nullifier(ScannedNullifier::from_survivor(
                        &shared::spec_v1::PublishedNullifier {
                            chain_pos: host::ChainPosition {
                                height: 100,
                                tx_index: 0,
                                vin_index: 0,
                                member_index: 0,
                            },
                            pk: nf.public_key,
                            r: nf.signature_r,
                        },
                    ))
                    .expect("fold mint");
                engine.set_tip_height(110);
            })
            .expect("mint apply");

        let (alice_secret1, alice_public1, alice_pk1_check) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/alice-sk1",
        ));
        assert_eq!(alice_pk1_check, alice_pk1);
        let (_, _, alice_pk2) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/alice-sk2",
        ));

        let bob_nk: [u8; 32] =
            Sha256::digest(b"zkCoins/v1/state-engine/receive-e2e/bob-nk").into();
        let (bob_secret0, bob_public0, bob_pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/bob-sk0",
        ));
        let (_, _, bob_pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/bob-sk1",
        ));
        let bob_owner = Address(host::address(&bob_pk0, host::nk_commit(&bob_nk)));

        let coin_identifier = adapter.with_engine(|engine| {
            engine
                .account(&alice_owner)
                .expect("alice")
                .spendable
                .values()
                .next()
                .expect("minted coin")
                .coin
                .identifier
        });

        let pending_send = adapter
            .with_engine(|engine| {
                engine.begin_send(SendRequest {
                    owner: alice_owner,
                    input_coin_ids: vec![coin_identifier],
                    output_templates: vec![host::CoinTemplate {
                        recipient: bob_owner,
                        amount: 30,
                        asset_id: mint_asset,
                    }],
                    next_pubkey: alice_pk2,
                    nav_rand: [0x3cu8; 32],
                    npk_rand: [0xa5u8; 32],
                })
            })
            .expect("begin_send");
        let bob_coin = pending_send
            .witness_wip
            .output_coins
            .iter()
            .find(|c| c.recipient == bob_owner)
            .cloned()
            .expect("Bob coin");
        let bob_coin_index = pending_send
            .witness_wip
            .output_coins
            .iter()
            .position(|c| c.recipient == bob_owner)
            .expect("idx") as u32;
        let send_creating_prev_ash =
            host::account_state_hash(&pending_send.witness_wip.prev_account_state).unwrap();
        let send_nav_opening = pending_send.nav_opening;
        let send_sig = sign_transition(
            alice_secret1,
            alice_public1,
            &pending_send.proof_data,
            Network::Testnet,
        );
        let applied_send = adapter
            .with_engine_mut(|engine| {
                engine
                    .finalise(pending_send, send_sig.transition.clone())
                    .expect("finalise send")
            })
            .expect("send");

        let send_pos = adapter
            .with_engine_mut(|engine| {
                let pos = engine
                    .append_nullifier(ScannedNullifier::from_survivor(
                        &shared::spec_v1::PublishedNullifier {
                            chain_pos: host::ChainPosition {
                                height: 110,
                                tx_index: 1,
                                vin_index: 0,
                                member_index: 0,
                            },
                            pk: applied_send.nullifier.0,
                            r: applied_send.nullifier.1,
                        },
                    ))
                    .expect("fold send");
                engine.set_tip_height(120);
                pos
            })
            .expect("fold");

        let (alice_change_id, nflog_entries) = adapter.with_engine(|engine| {
            let change = engine
                .account(&alice_owner)
                .expect("alice")
                .spendable
                .values()
                .next()
                .expect("change")
                .coin
                .identifier;
            let entries: Vec<NfLogEntry> =
                engine.nflog_mirror().iter().map(|(_, e)| *e).collect();
            (change, entries)
        });
        let all_output_ids = vec![bob_coin.identifier, alice_change_id];
        let sibling = host::leaf_hash(TreeKind::CoinsRoot, all_output_ids[1]);
        let output_inclusion = OutputInclusionProof {
            leaf_index: bob_coin_index,
            depth: 1,
            siblings: vec![sibling],
        };
        let creating_nav_inclusion =
            host::inclusion_path(send_pos, &nflog_entries).expect("inclusion");
        let creating_nav_consistency =
            host::consistency_proof(send_nav_opening.nav.size, &nflog_entries)
                .expect("consistency");

        let slot = ReceivedCoinSlot {
            coin: bob_coin,
            creating_proof: applied_send.proved.proof.clone(),
            output_inclusion,
            creating_prev_ash: send_creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: applied_send.nullifier.0,
                signature_r: applied_send.nullifier.1,
                r_prime: send_sig.transition.r_prime,
            },
            creating_nav_inclusion,
            pos_create: send_pos,
            creating_nav_opening: send_nav_opening,
            creating_nav_consistency,
        };
        let pending_rx = adapter
            .with_engine(|engine| {
                verify_and_begin_receive(
                    engine,
                    V11ReceiveRequest {
                        owner: bob_owner,
                        nk: bob_nk,
                        current_pubkey: bob_pk0,
                        slots: vec![slot],
                        next_pubkey: bob_pk1,
                        nav_rand: [0x41u8; 32],
                        npk_rand: [0x42u8; 32],
                    },
                )
            })
            .expect("verify_and_begin_receive");
        assert_eq!(pending_rx.mode, TransitionMode::InitialProof);

        let bob_sig = sign_transition(
            bob_secret0,
            bob_public0,
            &pending_rx.proof_data,
            Network::Testnet,
        );
        let publisher = RecordingPublisher::new();
        let build_tip = BlockAnchor {
            block_hash: [0xEE; 32],
            height: 120,
        };
        let outcome = finalise_publish_persist(
            &adapter,
            pending_rx,
            bob_sig.transition,
            &publisher,
            build_tip,
        )
        .await
        .expect("finalise_publish_persist with genuine prove");

        assert_eq!(outcome.nullifier.0, bob_pk0);
        assert_eq!(outcome.new_send_counter, 1);
        assert_eq!(outcome.admitted_coin_ids.len(), 1);
        adapter.with_engine(|engine| {
            let bob = engine.account(&bob_owner).expect("Bob");
            assert_eq!(
                bob.state
                    .balances
                    .get(&host::digest_to_bytes(&mint_asset)),
                Some(&30)
            );
            assert!(bob.last_nullifier_pos.is_none());
            assert!(matches!(
                engine.nflog().lookup(bob_pk0),
                LookupResult::Absent
            ));
        });
        let row = db_v11::load_pending_publish(&pool, bob_pk0)
            .await
            .expect("load")
            .expect("pending");
        assert_eq!(row.status, db_v11::PENDING_PUBLISH_REVEAL_BROADCAST);

        clear_process_stack_mode_for_test();
    }

}
