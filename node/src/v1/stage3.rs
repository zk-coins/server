//! Stage 3 — atomic switch properties (cutover-plan §6).
//!
//! Three properties define "switched":
//!
//! 1. no legacy `Proof` is ever loaded as `prev_proof`,
//! 2. the scanner folds only V3 payloads (legacy Commitment fold is sealed),
//! 3. `Prover::new()` is **not reachable** outside the defining crate's
//!    `#[cfg(test)]`.
//!
//! Each is enforced by type / sealed sink / circuit-identity bind — not by
//! comment or source grep. Tests below pin that; compile-fail matrices in
//! `node/tests` and `script-plonky2/tests` pin the edges.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::field::types::Field;
use plonky2::fri::proof::FriProof;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
use std::collections::BTreeMap;

use shared::spec_v1::{self as host, AccountState, Address, ZERO_HASH};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::prover_bridge::{
    ComplianceProof, ProverBridge, TransitionMode, TransitionSignature, TransitionWitness,
};

/// Well-formed bincode of a **legacy-shaped** Plonky2 proof: same Rust
/// type as `zkcoins_prover::Proof` / `ComplianceProof`, non-empty proof
/// shell, public-input length of the legacy outer circuit class (not
/// C's 108). Deserializes; must **not** bind as `prev_proof`.
fn well_formed_legacy_shaped_proof_bytes() -> Vec<u8> {
    // Legacy outer PI count is `N_PROOF_DATA_PUBLIC_INPUTS + cyclic tail`
    // and is **not** 108. Any non-108 length that still bincode-roundtrips
    // as `ProofWithPublicInputs` is a well-formed proof of the wrong
    // circuit for the C load gate.
    let legacy_pi_len = 20 + 4 + 4 * 16; // typical outer shape family, ≠ 108
    let proof: ComplianceProof = ProofWithPublicInputs {
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
                pow_witness: GoldilocksField::ZERO,
            },
        },
        public_inputs: vec![GoldilocksField::ZERO; legacy_pi_len],
    };
    bincode::serialize(&proof).expect("legacy-shaped Proof bincode is infallible")
}

/// Property 1: a well-formed legacy-shaped proof is refused as `prev_proof`.
///
/// Threat model: replace a valid v1 account's `last_proof` bytes with a
/// serialized genuine legacy `Proof` (same type alias, wrong circuit).
/// Garbage-byte rejection is not enough — bincode of a wrong-circuit
/// proof must fail the **circuit-identity bind** used on load.
#[test]
fn well_formed_legacy_proof_refused_as_prev_proof() {
    let bytes = well_formed_legacy_shaped_proof_bytes();

    // Sanity: bincode accepts it as the shared proof type (the load path
    // before Stage 3 stopped here and cloned it as prev_proof).
    let _: ComplianceProof =
        bincode::deserialize(&bytes).expect("legacy-shaped proof must deserialize");

    let bridge = ProverBridge::new(Network::Regtest);
    let err = bridge
        .bind_loaded_prev_proof(&bytes)
        .expect_err("well-formed wrong-circuit proof must not bind as prev_proof");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("public inputs")
            || msg.contains("circuit C")
            || msg.contains("prev_proof")
            || msg.contains("wrong circuit")
            || msg.contains("identity"),
        "refusal must name circuit identity / wrong-circuit; got: {msg}"
    );
}

/// B2: the DB load path refuses a well-formed foreign proof stored in
/// `v1_accounts.last_proof`. Goes through [`crate::v1::db_v1::load_engine_snapshot`]
/// — not a direct bridge helper call — so a regression that swaps
/// `bind_loaded_prev_proof` for bare `bincode::deserialize` turns this red.
#[tokio::test]
async fn load_engine_snapshot_refuses_foreign_last_proof_in_db() {
    use crate::test_db::setup_pool;
    use crate::v1::db_v1::{self, AccountSnapshot, EngineSnapshot};
    use crate::v1::{set_process_stack_mode, ScanStackMode};
    use shared::spec_v1::{self as host, AccountState, Address, ZERO_HASH};
    use std::collections::BTreeMap;

    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    // Durable write sink requires the v1 stack claim on the DB marker.
    crate::v1::claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1 stack marker");
    set_process_stack_mode(ScanStackMode::V1);

    let owner = Address([0xABu8; 32]);
    let state = AccountState::new(
        owner,
        ZERO_HASH,
        BTreeMap::new(),
        [0xB1; 32],
        0,
        host::CoinHistTree::new().root(),
    )
    .expect("AccountState");
    let foreign = well_formed_legacy_shaped_proof_bytes();
    let foreign_proof: ComplianceProof =
        bincode::deserialize(&foreign).expect("foreign proof bincode");

    let snap = EngineSnapshot {
        network: Network::Regtest,
        activation_height: 0,
        tip_height: 0,
        tip_hash: [0u8; 32],
        fold_seq: 0,
        nflog: vec![],
        accounts: vec![AccountSnapshot {
            owner,
            state,
            nk: [0xD1; 32],
            op_secret: Some(zkcoins_prover::state_engine::OpSecret::new([0xD2; 32])),
            genesis_pubkey: [0xB0; 32],
            spendable: vec![],
            spent_ids: vec![],
            last_proof: Some(foreign_proof),
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        }],
    };
    // persist serializes last_proof as raw bincode (no bind on write).
    db_v1::persist_engine_snapshot(&pool, &snap)
        .await
        .expect("persist snapshot with foreign last_proof bytes");

    let err = db_v1::load_engine_snapshot(&pool)
        .await
        .expect_err("load must refuse foreign last_proof via bind gate");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("last_proof")
            || msg.contains("public inputs")
            || msg.contains("circuit C")
            || msg.contains("prev_proof")
            || msg.contains("identity")
            || msg.contains("wrong circuit"),
        "DB load refusal must name the bind gate; got: {msg}"
    );
}

/// Property 1 (garbage still fails — complementary, not the threat).
#[test]
fn last_proof_load_rejects_non_compliance_bytes() {
    let garbage = b"legacy-circuit-main-proof-bytes-not-compliance";
    let err = ProverBridge::new(Network::Regtest)
        .bind_loaded_prev_proof(garbage)
        .expect_err("non-ComplianceProof bytes must not load as last_proof");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("deserialize") || msg.contains("bincode") || msg.contains("last_proof"),
        "garbage refusal must name deserialize; got: {msg}"
    );
}

/// R3: direct Serde entry for `TransitionWitness` must bind `prev_proof`.
///
/// Existing coverage hits DB load (`load_engine_snapshot`) and durable
/// resume (`FinalisationCapability::from_durable_bytes`). This test is
/// the free-standing byte → witness path that formerly was bare
/// `bincode::deserialize::<TransitionWitness>` (unbound). Public
/// `Deserialize` is gone; [`TransitionWitness::decode_bound`] is the
/// only entry and must refuse a well-formed foreign prev_proof.
#[test]
fn transition_witness_decode_bound_refuses_foreign_prev_proof() {
    let foreign: ComplianceProof = bincode::deserialize(&well_formed_legacy_shaped_proof_bytes())
        .expect("legacy-shaped proof must deserialize as ComplianceProof");

    let owner = Address([0x11u8; 32]);
    let account = AccountState::new(
        owner,
        ZERO_HASH,
        BTreeMap::new(),
        [0x22; 32],
        0,
        host::CoinHistTree::new().root(),
    )
    .expect("AccountState");

    let witness = TransitionWitness {
        mode: TransitionMode::AccountUpdateProof,
        prev_account_state: account.clone(),
        new_account_state: account,
        input_coins: vec![],
        input_auth: vec![],
        output_templates: vec![],
        output_coins: vec![],
        output_history_proofs: vec![],
        received_coins: vec![],
        received_auth: vec![],
        asset_issuance: None,
        nk: [0x33; 32],
        nav: host::Nav {
            size: 0,
            mth: ZERO_HASH,
        },
        nav_rand: [0x44; 32],
        prev_nav_opening: None,
        nav_consistency: vec![],
        next_pubkey: [0x55; 32],
        npk_rand: [0x66; 32],
        transition_signature: TransitionSignature {
            pk_i: [0x22; 32],
            signature: [0u8; 64],
            r_prime: [0u8; 32],
        },
        prev_proof: Some(foreign),
        predecessor_nullifier: None,
    };

    // Encode via public Serialize (byte-compatible with the private wire
    // layout used by durable resume). Public Deserialize is gone — only
    // decode_bound may load these bytes as a TransitionWitness.
    let bytes = bincode::serialize(&witness)
        .expect("TransitionWitness Serialize bincode is infallible for this shape");

    let bridge = ProverBridge::new(Network::Regtest);
    let err = TransitionWitness::decode_bound(&bytes, &bridge)
        .expect_err("foreign prev_proof must not load via TransitionWitness::decode_bound");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("public inputs")
            || msg.contains("circuit C")
            || msg.contains("prev_proof")
            || msg.contains("wrong circuit")
            || msg.contains("identity"),
        "decode_bound refusal must name the identity bind; got: {msg}"
    );
}

/// R3 companion: receipt `creating_proof` is bound on the same path.
#[test]
fn transition_witness_decode_bound_refuses_foreign_creating_proof() {
    use zkcoins_prover::prover_bridge::{
        NavOpening, NullifierOpening, OutputInclusionProof, ReceivedAuthorization,
    };

    let foreign: ComplianceProof = bincode::deserialize(&well_formed_legacy_shaped_proof_bytes())
        .expect("legacy-shaped proof must deserialize as ComplianceProof");

    let owner = Address([0x11u8; 32]);
    let account = AccountState::new(
        owner,
        ZERO_HASH,
        BTreeMap::new(),
        [0x22; 32],
        0,
        host::CoinHistTree::new().root(),
    )
    .expect("AccountState");

    let received_auth = ReceivedAuthorization {
        creating_proof: foreign,
        output_inclusion: OutputInclusionProof {
            leaf_index: 0,
            depth: 0,
            siblings: vec![],
        },
        creating_prev_ash: ZERO_HASH,
        creating_nullifier: NullifierOpening {
            public_key: [0x77; 32],
            signature_r: [0x88; 32],
            r_prime: [0x99; 32],
        },
        creating_nav_inclusion: vec![],
        pos_create: 0,
        creating_nav_opening: NavOpening {
            nav: host::Nav {
                size: 0,
                mth: ZERO_HASH,
            },
            nav_rand: [0xAA; 32],
        },
        creating_nav_consistency: vec![],
        history_proof: host::CoinHistTree::new().prove([0xBBu8; 32]),
    };

    let witness = TransitionWitness {
        mode: TransitionMode::AccountUpdateProof,
        prev_account_state: account.clone(),
        new_account_state: account,
        input_coins: vec![],
        input_auth: vec![],
        output_templates: vec![],
        output_coins: vec![],
        output_history_proofs: vec![],
        received_coins: vec![],
        received_auth: vec![received_auth],
        asset_issuance: None,
        nk: [0x33; 32],
        nav: host::Nav {
            size: 0,
            mth: ZERO_HASH,
        },
        nav_rand: [0x44; 32],
        prev_nav_opening: None,
        nav_consistency: vec![],
        next_pubkey: [0x55; 32],
        npk_rand: [0x66; 32],
        transition_signature: TransitionSignature {
            pk_i: [0x22; 32],
            signature: [0u8; 64],
            r_prime: [0u8; 32],
        },
        prev_proof: None,
        predecessor_nullifier: None,
    };

    let bytes = bincode::serialize(&witness)
        .expect("TransitionWitness Serialize bincode is infallible for this shape");
    let bridge = ProverBridge::new(Network::Regtest);
    let err = TransitionWitness::decode_bound(&bytes, &bridge)
        .expect_err("foreign creating_proof must not load via decode_bound");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("creating_proof")
            || msg.contains("public inputs")
            || msg.contains("circuit C")
            || msg.contains("identity")
            || msg.contains("wrong circuit"),
        "decode_bound refusal must name creating_proof bind; got: {msg}"
    );
}

/// Property 2: non-V3 payloads are rejected by the
/// `AggregateStateNullifierV3` deserialize path the scanner uses
/// (not folded into NfLog). The legacy Commitment fold is additionally
/// sealed behind [`crate::legacy_commitment_scan::LegacyCommitmentScanCap`]
/// — see compile-fail matrix.
#[test]
fn scanner_rejects_non_v3_payload() {
    use zkcoins_prover::half_agg::AggregateStateNullifierV3;

    let garbage = b"not-a-v3-aggregate-nullifier";
    let err = AggregateStateNullifierV3::deserialize(garbage)
        .expect_err("garbage must not parse as AggregateStateNullifierV3");
    let msg = format!("{err:#}");
    assert!(!msg.is_empty(), "rejection must carry a reason (fail loud)");

    let bad_marker = [0x00u8; 8];
    assert!(
        AggregateStateNullifierV3::deserialize(&bad_marker).is_err(),
        "non-V3 marker must be rejected"
    );
}

/// Property 3 (runtime half): production AccountNode constructors that
/// the binary uses carry no legacy Prover. Construction of `Prover`
/// itself is sealed — see compile-fail matrix for `Prover::new`.
#[test]
fn stage3_account_node_has_no_legacy_prover() {
    use crate::account_node::AccountNode;
    use crate::state::State;
    use std::sync::{Arc, Mutex};

    let node = AccountNode::new(Arc::new(Mutex::new(State::new())));
    // Under no process claim, prepare_mint reaches the prover borrow and
    // refuses because Stage-3 nodes carry `prover: None`.
    let err = node
        .prepare_mint(&[0x02; 33], "x", 0, 1, &[0x03; 33])
        .expect_err("prepare_mint without prover must refuse");
    assert!(
        err.contains("Stage-3")
            || err.contains("unreachable")
            || err.contains("legacy")
            || err.contains("Prover"),
        "unexpected refuse message: {err}"
    );
}

/// Property 2 (capability half): the sealed legacy scan cap is only
/// mintable under this crate's `#[cfg(test)]` — which this unit test
/// is. That does **not** reopen the production edge; compile-fail
/// matrices prove dependency builds cannot mint.
#[test]
fn legacy_commitment_scan_cap_is_test_only_mint() {
    let cap = crate::legacy_commitment_scan::LegacyCommitmentScanCap::mint_for_test();
    // Cap is a ZST token; possession is the proof. Drop without running
    // the multi-minute scan loop (Stage 4 deletes the body).
    drop(cap);
}

#[cfg(test)]
mod genesis_fence_tests {
    use crate::db;
    use crate::job_store::{CreateResult, JobKind, JobStatus, JobStore};
    use crate::self_heal::{heal_circuit_digest, ResetDecision};
    use crate::test_db::setup_pool;
    use crate::v1::{set_process_stack_mode, ScanStackMode};

    /// Migration 0028 is the Stage-3 cutover genesis reset. sqlx records it
    /// in `_sqlx_migrations` and never re-applies it. Evidence that the
    /// bump is **once at switch**, not every boot:
    ///
    /// 1. Fresh migrate → generation == 1 (0024 seed 0 + 0028 +1).
    /// 2. Re-run migrate on the same schema → generation stays 1.
    /// 3. Boot self-heal with a stable baseline digest → Keep, gen stays 1.
    ///
    /// Would go red if 0028 ran outside sqlx, or if heal re-bumped on Keep.
    #[tokio::test]
    async fn stage3_genesis_reset_runs_once_not_every_boot() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();

        let gen_after_migrate = db::load_self_heal_reset_generation(&pool)
            .await
            .expect("load generation after first migrate");
        assert_eq!(
            gen_after_migrate, 1,
            "post-Stage-3 schema: 0024 seeds 0, 0028 one-shot bumps to 1"
        );

        // Second migrate is a no-op (checksum already in `_sqlx_migrations`).
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("re-run migrations must be idempotent");
        let gen_after_remigrate = db::load_self_heal_reset_generation(&pool)
            .await
            .expect("load after remigrate");
        assert_eq!(
            gen_after_remigrate, gen_after_migrate,
            "re-applying migrations must not re-run 0028 / re-bump generation"
        );

        // Simulated second boot: digest already matches baseline → Keep.
        let digest = crate::v1::encode_v1_live_digest(&[0x11; 32], &[0x22; 32]);
        db::store_circuit_digest(&pool, &digest)
            .await
            .expect("store baseline digest");
        let proofs = tempfile::tempdir().expect("tempdir");
        let decision =
            heal_circuit_digest(&pool, &digest, proofs.path().to_str().unwrap(), &|| {
                panic!("canary must not run on digest Keep path")
            })
            .await
            .expect("heal Keep");
        assert_eq!(decision, ResetDecision::Keep);
        let gen_after_keep_boot = db::load_self_heal_reset_generation(&pool)
            .await
            .expect("load after Keep heal");
        assert_eq!(
            gen_after_keep_boot, gen_after_migrate,
            "Keep heal (second boot, same digest) must not bump generation"
        );
    }

    /// Stage-3 genesis reset uses the **same** G5 generation fence as
    /// self-heal: bump generation, fail in-flight jobs (leave their
    /// `reset_generation` behind the live epoch), wipe proof state.
    /// A concurrent writer holding a pre-reset job cannot complete.
    #[tokio::test]
    async fn stage3_genesis_reset_fences_job_in_flight() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        set_process_stack_mode(ScanStackMode::V1);

        // Admit a job under the live generation (in flight).
        let store = JobStore::new(pool.clone());
        let job = match store
            .create(
                JobKind::Mint,
                &[0u8; 32],
                None,
                serde_json::json!({"stage3": "in_flight"}),
            )
            .await
            .expect("admit job before reset")
        {
            CreateResult::Fresh(j) | CreateResult::IdempotentReplay(j) => j,
        };
        assert_eq!(job.status, JobStatus::Queued);
        let gen_before = job.reset_generation;
        // Post-0028 live epoch is 1 on a freshly migrated schema.
        assert_eq!(
            gen_before, 1,
            "in-flight job before a runtime reset sits on the cutover epoch"
        );
        let public_id = job.public_id;

        // Same helper migration 0028 mirrors (G5 fence — do not invent
        // a second mechanism). Runtime call models a digest-mismatch
        // self-heal after cutover, not a re-run of 0028 itself.
        let live_digest = vec![0xCCu8; 68];
        db::reset_v1_proof_dependent_state_tx(&pool, &live_digest)
            .await
            .expect("stage3 genesis reset via G5 helper");

        let gen_after = db::load_self_heal_reset_generation(&pool)
            .await
            .expect("load generation");
        assert_eq!(
            gen_after,
            gen_before + 1,
            "runtime G5 reset must bump generation exactly once (before={gen_before}, after={gen_after})"
        );

        // In-flight job is failed and stays on the pre-bump generation.
        let row = store.load(public_id).await.expect("load").expect("row");
        assert_eq!(row.status, JobStatus::Failed);
        assert_eq!(
            row.reset_generation, gen_before,
            "failed job must keep pre-reset generation (fence leaves it behind)"
        );
        assert!(
            row.error.as_deref().is_some_and(|e| {
                e.contains("self-heal") || e.contains("wiped") || e.contains("genesis")
            }),
            "error must name the wipe; got {:?}",
            row.error
        );

        // Pre-reset worker cannot resurrect: set_status / complete lose the CAS.
        let advanced = store
            .set_status(public_id, JobStatus::Proving, "proving")
            .await
            .expect("set_status");
        assert!(
            !advanced,
            "set_status must return false when generation fence matches 0 rows"
        );
        let completed = store
            .complete(public_id, serde_json::json!({}), 200)
            .await
            .expect("complete");
        assert!(
            !completed,
            "complete must return false when generation fence matches 0 rows"
        );

        // Post-reset admit stamps the new generation and can proceed.
        let fresh = match store
            .create(
                JobKind::Mint,
                &[1u8; 32],
                None,
                serde_json::json!({"stage3": "post_reset"}),
            )
            .await
            .expect("admit after reset")
        {
            CreateResult::Fresh(j) | CreateResult::IdempotentReplay(j) => j,
        };
        assert_eq!(fresh.reset_generation, gen_after);
        assert_eq!(fresh.status, JobStatus::Queued);
    }

    /// Concurrent G5 interleaving across a Stage-3 reset: a job loaded
    /// (admitted) before the reset must not complete against wiped state
    /// when `complete` races an open generation bump.
    ///
    /// Mirrors the self-heal open-tx interleaving test, but drives the
    /// Stage-3 wipe helper's fence pieces (bump + fail non-terminal)
    /// while a pre-reset `complete` is blocked on the meta lock.
    #[tokio::test]
    async fn stage3_reset_concurrent_complete_cannot_finish_against_wiped_state() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        set_process_stack_mode(ScanStackMode::V1);

        let store = JobStore::new(pool.clone());
        let job = match store
            .create(
                JobKind::Mint,
                &[0xABu8; 32],
                Some("stage3-concurrent-complete"),
                serde_json::json!({"stage3": "race"}),
            )
            .await
            .expect("admit before open reset")
        {
            CreateResult::Fresh(j) | CreateResult::IdempotentReplay(j) => j,
        };
        let job_id = job.public_id;
        let gen_before = job.reset_generation;

        // Advance to proving so `complete` is a legal transition shape.
        assert!(
            store
                .set_status(job_id, JobStatus::Proving, "proving")
                .await
                .expect("set proving"),
            "pre-reset set_status must land on live generation"
        );

        // Open reset-shaped tx: bump + fail non-terminal (same order as
        // `reset_v1_proof_dependent_state_tx`), hold locks, do not commit yet.
        let mut reset_tx = pool.begin().await.expect("begin reset tx");
        let bumped = db::bump_self_heal_reset_generation_in_tx(&mut reset_tx)
            .await
            .expect("bump");
        assert_eq!(bumped, gen_before + 1);
        sqlx::query(
            "UPDATE jobs SET status = 'failed', phase = 'failed', \
                              error = $1, updated_at = NOW(), completed_at = NOW() \
             WHERE public_id = $2 \
               AND status IN ('queued', 'proving', 'awaiting_signature', 'broadcasting')",
        )
        .bind(db::SELF_HEAL_RESET_JOB_ERROR)
        .bind(job_id)
        .execute(&mut *reset_tx)
        .await
        .expect("fail job in open reset");

        let complete_fut = store.complete(job_id, serde_json::json!({"should": "not land"}), 200);
        tokio::pin!(complete_fut);
        let blocked =
            tokio::time::timeout(std::time::Duration::from_millis(200), &mut complete_fut).await;
        assert!(
            blocked.is_err(),
            "complete must block on self_heal_reset_meta while Stage-3 reset holds the row lock"
        );

        reset_tx.commit().await.expect("commit open Stage-3 reset");
        let completed = complete_fut.await.expect("complete after commit");
        assert!(
            !completed,
            "after open Stage-3 bump commits, complete must see post-bump generation and match 0 rows"
        );
        let row = store.load(job_id).await.unwrap().unwrap();
        assert_eq!(
            row.status,
            JobStatus::Failed,
            "pre-reset job must not complete against wiped state"
        );
        assert_ne!(row.status, JobStatus::Completed);
        assert_eq!(row.reset_generation, gen_before);
    }
}
