//! Stage 3 — atomic switch properties (cutover-plan §6).
//!
//! Three properties define "switched":
//!
//! 1. no legacy `Proof` is ever loaded as `prev_proof`,
//! 2. the scanner folds only V3 payloads,
//! 3. `Prover::new()` is **not reachable** on the binary path.
//!
//! Each is enforced by type / control-flow / sealed load, not by comment.
//! Tests below pin that; the binary boot in `main.rs` never constructs
//! a legacy [`zkcoins_prover::Prover`].

use std::path::Path;

/// Source-level evidence that the production binary entrypoint does not
/// call `Prover::new`. Reachability, not convention: if someone re-adds
/// the call, this test fails in a normal `cargo test` run.
#[test]
fn binary_main_does_not_call_prover_new() {
    // Resolve from this file: node/src/v1/stage3.rs → node/src/main.rs
    let main_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let src = std::fs::read_to_string(&main_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", main_rs.display()));
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }
        assert!(
            !trimmed.contains("Prover::new()"),
            "main.rs:{} must not call Prover::new() on the Stage-3 binary path; got: {trimmed}",
            i + 1
        );
        assert!(
            !trimmed.contains("zkcoins_prover::Prover::new"),
            "main.rs:{} must not construct zkcoins_prover::Prover; got: {trimmed}",
            i + 1
        );
    }
}

/// Property 1: legacy account `proof` blobs live only in the legacy
/// `accounts` table; v1 `prev_proof` is loaded exclusively from
/// `v1_accounts.last_proof` as [`ComplianceProof`]. There is no convert
/// path from legacy `zkcoins_prover::Proof` bytes into that column on the
/// Stage-3 write surface.
#[test]
fn legacy_proof_has_no_convert_path_into_v1_last_proof() {
    // Production writers of `v1_accounts.last_proof` are only in
    // `db_v1` (bincode of ComplianceProof from AccountRecord). Grep the
    // node crate for accidental reinterprets.
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for entry in walkdir_rs_files(&src_root) {
        let text = std::fs::read_to_string(&entry).expect("read");
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            // Forbidden: feeding a legacy `zkcoins_prover::Proof` (or
            // Account.proof) into last_proof / ComplianceProof without
            // going through the engine.
            if t.contains("last_proof")
                && (t.contains("account.proof")
                    || t.contains("Account.proof")
                    || t.contains("as ComplianceProof")
                    || t.contains("transmute"))
            {
                offenders.push(format!("{}:{}: {t}", entry.display(), i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "no convert path from legacy Proof into v1 last_proof/prev_proof; found:\n{}",
        offenders.join("\n")
    );
}

/// Property 1 (load path): `db_v1` deserialises `last_proof` only as
/// [`ComplianceProof`]. Garbage / non-proof bytes fail loud — never
/// become a usable `prev_proof`.
#[test]
fn last_proof_load_rejects_non_compliance_bytes() {
    use zkcoins_prover::prover_bridge::ComplianceProof;

    let garbage = b"legacy-circuit-main-proof-bytes-not-compliance";
    let err = bincode::deserialize::<ComplianceProof>(garbage)
        .expect_err("non-ComplianceProof bytes must not load as last_proof");
    let _ = err; // fail loud is enough
}

/// Property 2: non-V3 payloads are rejected by the
/// `AggregateStateNullifierV3` deserialize path the scanner uses
/// (not folded into NfLog).
#[test]
fn scanner_rejects_non_v3_payload() {
    use zkcoins_prover::half_agg::AggregateStateNullifierV3;

    let garbage = b"not-a-v3-aggregate-nullifier";
    let err = AggregateStateNullifierV3::deserialize(garbage)
        .expect_err("garbage must not parse as AggregateStateNullifierV3");
    let msg = format!("{err:#}");
    assert!(
        !msg.is_empty(),
        "rejection must carry a reason (fail loud)"
    );

    // Wrong format marker / truncated header (scanner discards whole payload).
    let bad_marker = [0x00u8; 8];
    assert!(
        AggregateStateNullifierV3::deserialize(&bad_marker).is_err(),
        "non-V3 marker must be rejected"
    );
}

/// Property 3 (runtime half): production AccountNode constructors that
/// the binary uses carry no legacy Prover.
#[test]
fn stage3_account_node_has_no_legacy_prover() {
    use crate::account_node::AccountNode;
    use crate::state::State;
    use std::sync::{Arc, Mutex};

    let node = AccountNode::new_without_legacy_prover(Arc::new(Mutex::new(State::new())));
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

fn walkdir_rs_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    walk(root, &mut out);
    out
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
        let decision = heal_circuit_digest(
            &pool,
            &digest,
            proofs.path().to_str().unwrap(),
            &|| panic!("canary must not run on digest Keep path"),
        )
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
}
