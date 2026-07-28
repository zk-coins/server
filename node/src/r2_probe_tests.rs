// Tests for the R2-probe persistence layer.
//
// Strategy mirrors `db_tests`: every test gets its own UUID-named
// schema inside a `postgres:17` container shared per test binary
// (issue #181 Optimisation B). The per-test isolation removes any
// cross-test ordering risk; the container-boot cost is paid once
// per binary instead of once per test.

use super::*;
use crate::test_db::setup_pool;
use sqlx::Row;

fn sample_host(suffix: &str) -> HostInfo {
    HostInfo {
        hostname: format!("test-host-{suffix}"),
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        cpu_brand: "Apple M3 Ultra".to_string(),
        cpu_cores: 24,
        total_ram_gb: Some(96),
    }
}

fn sample_run(host_id: i32) -> ProbeRun {
    ProbeRun {
        host_id,
        git_sha: "deadbeefcafe".to_string(),
        binary_version: "0.1.0".to_string(),
        rustc_version: "rustc 1.81.0".to_string(),
        build_profile: "release".to_string(),
        allocator: "mimalloc".to_string(),
        prover_mode: "legacy".to_string(),
        max_in_coins: 8,
        max_out_coins: 8,
        inner_pad_bits: 15,
        max_tx_inputs: None,
        max_tx_outputs: None,
        max_rx_coins: None,
        compliance_gate_count: None,
        warm_calls_requested: 5,
        circuit_build_wall_ms: 9_500,
        prove_cold_wall_ms: 18_000,
        verify_wall_ms: 25,
        peak_rss_kb: 40 * 1024 * 1024,
        prove_warm_p50_ms: Some(900),
        prove_warm_p90_ms: Some(1_100),
        prove_warm_p99_ms: Some(1_300),
        succeeded: true,
        error_message: None,
        notes: Some("smoke".to_string()),
        tags: vec!["smoke".to_string(), "local".to_string()],
        r2_warm_budget_ms: 5_000,
        r2_cold_budget_ms: 30_000,
        r2_mem_budget_kb: 64 * 1024 * 1024,
    }
}

#[tokio::test]
async fn detect_returns_a_host_struct() {
    // `detect()` now sits on top of the `sysinfo` crate (cross-platform
    // host introspection). Every field has exactly one success path and
    // a conservative fallback, so the assertions below pin the actual
    // observable contract — not just "the function didn't panic":
    //
    //   * `hostname` is non-empty (either the OS-reported value or the
    //     `"unknown"` fallback when `sysinfo::System::host_name()` is
    //     `None` / empty);
    //   * `os` / `arch` come from `std::env::consts::{OS,ARCH}` which
    //     are compile-time constants and always non-empty;
    //   * `cpu_brand` is non-empty for the same reason (real brand or
    //     the `"unknown"` fallback);
    //   * `cpu_cores >= 1` — any host that can run this test has at
    //     least one schedulable thread, so `available_parallelism()`
    //     returning 0 would be a real bug, not a CI quirk;
    //   * `total_ram_gb` is either `None` (sysinfo couldn't read it)
    //     or `>= 1` (the `> 0` filter in `detect()` collapses the
    //     zero-reading case into `None`).
    let info = detect();
    assert!(!info.hostname.is_empty(), "hostname must be non-empty");
    assert!(!info.os.is_empty(), "os must be non-empty");
    assert!(!info.arch.is_empty(), "arch must be non-empty");
    assert!(!info.cpu_brand.is_empty(), "cpu_brand must be non-empty");
    assert!(
        info.cpu_cores >= 1,
        "cpu_cores must be at least 1 on any host that runs this test, got {}",
        info.cpu_cores,
    );
    if let Some(g) = info.total_ram_gb {
        assert!(
            g >= 1,
            "total_ram_gb Some(_) must be >= 1 (zero is collapsed to None), got {}",
            g,
        );
    }
}

#[test]
fn detect_impl_uses_fallbacks_when_inputs_are_none() {
    // Drives every `unwrap_or_else` / `unwrap_or` fallback path in
    // `detect_impl`. On the CI runner the live `detect()` inputs are
    // always populated (host_name() returns `Some(_)`, the CPU list is
    // non-empty, available_parallelism() returns `Ok(_)`), so without
    // this synthetic call those closures would never execute and the
    // 100 % coverage gate would mark them as uncovered functions.
    let info = detect_impl(None, None, 0, None);
    assert_eq!(info.hostname, "unknown");
    assert_eq!(info.cpu_brand, "unknown");
    assert_eq!(info.cpu_cores, 0);
    assert_eq!(info.total_ram_gb, None);
    // `os` / `arch` come from compile-time constants, so they remain
    // non-empty regardless of the synthetic inputs above.
    assert!(!info.os.is_empty());
    assert!(!info.arch.is_empty());
}

#[test]
fn detect_impl_uses_fallback_when_inputs_are_empty_strings() {
    // Exercises the `.filter(|s| !s.is_empty())` branch on both string
    // fields: a `Some("")` from sysinfo must collapse to `"unknown"`
    // the same way a `None` does.
    let info = detect_impl(Some(String::new()), Some(String::new()), 0, None);
    assert_eq!(info.hostname, "unknown");
    assert_eq!(info.cpu_brand, "unknown");
    assert_eq!(info.cpu_cores, 0);
    assert_eq!(info.total_ram_gb, None);
}

#[test]
fn detect_impl_uses_inputs_when_provided() {
    // Pins the happy path: every value flows through unchanged. 96 GiB
    // exact bytes (96 * 1024^3) divides to `Some(96)` after the GiB
    // collapse; the `> 0` filter keeps it as `Some(_)`.
    let info = detect_impl(
        Some("ci-runner.local".to_string()),
        Some("Apple M3 Ultra".to_string()),
        96 * 1024 * 1024 * 1024,
        Some(32),
    );
    assert_eq!(info.hostname, "ci-runner.local");
    assert_eq!(info.cpu_brand, "Apple M3 Ultra");
    assert_eq!(info.cpu_cores, 32);
    assert_eq!(info.total_ram_gb, Some(96));
    assert!(!info.os.is_empty());
    assert!(!info.arch.is_empty());
}

#[tokio::test]
async fn upsert_host_returns_same_id_on_natural_key_match() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host = sample_host("alpha");
    let id1 = upsert_host(&pool, &host).await.expect("first upsert");
    let id2 = upsert_host(&pool, &host).await.expect("second upsert");
    assert_eq!(id1, id2, "same natural key must map to the same id");

    // Confirm only one row exists.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM r2_probe_hosts")
        .fetch_one(&pool)
        .await
        .expect("count query");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn upsert_host_updates_payload_fields_on_conflict() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let mut host = sample_host("beta");
    host.cpu_cores = 16;
    host.total_ram_gb = Some(64);
    let id1 = upsert_host(&pool, &host).await.expect("first upsert");

    // Same natural key, different payload — should update in place.
    host.cpu_cores = 24;
    host.total_ram_gb = Some(96);
    let id2 = upsert_host(&pool, &host).await.expect("second upsert");
    assert_eq!(id1, id2);

    let row = sqlx::query("SELECT cpu_cores, total_ram_gb FROM r2_probe_hosts WHERE id = $1")
        .bind(id1)
        .fetch_one(&pool)
        .await
        .expect("select after upsert");
    let cpu_cores: i32 = row.get("cpu_cores");
    let total_ram_gb: Option<i32> = row.get("total_ram_gb");
    assert_eq!(cpu_cores, 24);
    assert_eq!(total_ram_gb, Some(96));
}

#[tokio::test]
async fn upsert_host_distinguishes_different_natural_keys() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_a = sample_host("alpha");
    let mut host_b = sample_host("alpha");
    host_b.cpu_brand = "Intel Xeon Platinum 8488C".to_string();

    let id_a = upsert_host(&pool, &host_a).await.expect("upsert a");
    let id_b = upsert_host(&pool, &host_b).await.expect("upsert b");
    assert_ne!(id_a, id_b);
}

#[tokio::test]
async fn upsert_host_accepts_null_total_ram() {
    // The probe falls back to None on platforms it can't introspect;
    // the row must still land.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let mut host = sample_host("ramless");
    host.total_ram_gb = None;
    let id = upsert_host(&pool, &host).await.expect("upsert");
    let ram: Option<i32> =
        sqlx::query_scalar("SELECT total_ram_gb FROM r2_probe_hosts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("select ram");
    assert!(ram.is_none());
}

#[tokio::test]
async fn insert_run_writes_full_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("ins")).await.expect("host");
    let run_id = insert_run(&pool, &sample_run(host_id))
        .await
        .expect("insert run");
    assert!(run_id > 0);

    // Spot-check a handful of fields landed correctly.
    let row = sqlx::query(
        "SELECT git_sha, build_profile, allocator, succeeded, \
                circuit_build_wall_ms, prove_warm_p50_ms, tags \
         FROM r2_probe_runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("select run");

    assert_eq!(row.get::<String, _>("git_sha"), "deadbeefcafe");
    assert_eq!(row.get::<String, _>("build_profile"), "release");
    assert_eq!(row.get::<String, _>("allocator"), "mimalloc");
    assert!(row.get::<bool, _>("succeeded"));
    assert_eq!(row.get::<i64, _>("circuit_build_wall_ms"), 9_500);
    assert_eq!(row.get::<Option<i64>, _>("prove_warm_p50_ms"), Some(900));
    let tags: Vec<String> = row.get("tags");
    assert_eq!(tags, vec!["smoke".to_string(), "local".to_string()]);
}

#[tokio::test]
async fn insert_run_handles_failure_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("fail"))
        .await
        .expect("host");
    let mut run = sample_run(host_id);
    run.succeeded = false;
    run.error_message = Some("prove_initial: panicked".to_string());
    run.prove_warm_p50_ms = None;
    run.prove_warm_p90_ms = None;
    run.prove_warm_p99_ms = None;
    let run_id = insert_run(&pool, &run).await.expect("insert err run");

    let row = sqlx::query(
        "SELECT succeeded, error_message, prove_warm_p50_ms \
         FROM r2_probe_runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("select err run");
    assert!(!row.get::<bool, _>("succeeded"));
    assert_eq!(
        row.get::<Option<String>, _>("error_message").as_deref(),
        Some("prove_initial: panicked")
    );
    assert!(row.get::<Option<i64>, _>("prove_warm_p50_ms").is_none());
}

#[tokio::test]
async fn insert_warm_calls_empty_is_noop() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("empty"))
        .await
        .expect("host");
    let run_id = insert_run(&pool, &sample_run(host_id)).await.expect("run");
    insert_warm_calls(&pool, run_id, &[])
        .await
        .expect("empty insert");
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM r2_probe_warm_calls WHERE probe_run_id = $1")
            .bind(run_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn insert_warm_calls_writes_indexed_rows() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("warm"))
        .await
        .expect("host");
    let run_id = insert_run(&pool, &sample_run(host_id)).await.expect("run");
    let calls = vec![900_i64, 950, 1000, 1100, 1300];
    insert_warm_calls(&pool, run_id, &calls)
        .await
        .expect("warm insert");

    let rows = sqlx::query(
        "SELECT call_index, wall_ms FROM r2_probe_warm_calls \
         WHERE probe_run_id = $1 ORDER BY call_index",
    )
    .bind(run_id)
    .fetch_all(&pool)
    .await
    .expect("warm select");
    assert_eq!(rows.len(), 5);
    for (i, r) in rows.iter().enumerate() {
        let idx: i32 = r.get("call_index");
        let wall: i64 = r.get("wall_ms");
        assert_eq!(idx, i as i32);
        assert_eq!(wall, calls[i]);
    }
}

#[tokio::test]
async fn cascade_delete_drops_warm_calls() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("cascade"))
        .await
        .expect("host");
    let run_id = insert_run(&pool, &sample_run(host_id)).await.expect("run");
    insert_warm_calls(&pool, run_id, &[100, 200, 300])
        .await
        .expect("warm");

    sqlx::query("DELETE FROM r2_probe_runs WHERE id = $1")
        .bind(run_id)
        .execute(&pool)
        .await
        .expect("delete run");

    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM r2_probe_warm_calls WHERE probe_run_id = $1")
            .bind(run_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(remaining, 0, "child rows must cascade");
}

#[tokio::test]
async fn fetch_recent_summary_returns_desc_with_budget_pass() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("sum")).await.expect("host");

    // Two runs that pass every budget.
    let _id_a = insert_run(&pool, &sample_run(host_id))
        .await
        .expect("run a");
    let _id_b = insert_run(&pool, &sample_run(host_id))
        .await
        .expect("run b");

    // One run that explicitly fails warm + cold + mem budgets.
    let mut over = sample_run(host_id);
    over.prove_cold_wall_ms = 60_000;
    over.prove_warm_p50_ms = Some(7_500);
    over.peak_rss_kb = 80 * 1024 * 1024;
    let id_over = insert_run(&pool, &over).await.expect("run over");

    let rows = fetch_recent_summary(&pool, 10).await.expect("summary");
    assert_eq!(rows.len(), 3);

    // Newest row first — id_over was the last insert.
    assert_eq!(rows[0].id, id_over);
    assert!(!rows[0].r2_warm_pass);
    assert!(!rows[0].r2_cold_pass);
    assert!(!rows[0].r2_mem_pass);

    // The earlier two passed every budget.
    assert!(rows[1].r2_warm_pass);
    assert!(rows[1].r2_cold_pass);
    assert!(rows[1].r2_mem_pass);
    assert!(rows[2].r2_warm_pass);
    assert!(rows[2].r2_cold_pass);
    assert!(rows[2].r2_mem_pass);

    // Each row carries the joined host info.
    assert_eq!(rows[0].hostname, "test-host-sum");
    assert_eq!(rows[0].cpu_brand, "Apple M3 Ultra");
    // Flag-off / legacy rows surface prover_mode = "legacy" (migration 0023).
    assert_eq!(rows[0].prover_mode, "legacy");
}

#[tokio::test]
async fn insert_run_persists_v1_shape_columns() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("v1shape"))
        .await
        .expect("host");
    let mut run = sample_run(host_id);
    run.prover_mode = "v1".to_string();
    run.max_tx_inputs = Some(8);
    run.max_tx_outputs = Some(8);
    run.max_rx_coins = Some(4);
    run.compliance_gate_count = Some(1_403_783);
    // v1 budgets are larger; persist what the probe would have checked.
    run.r2_warm_budget_ms = 600_000;
    run.r2_cold_budget_ms = 900_000;
    let run_id = insert_run(&pool, &run).await.expect("insert v1 run");

    let row = sqlx::query(
        "SELECT prover_mode, max_tx_inputs, max_tx_outputs, max_rx_coins, \
                compliance_gate_count, r2_warm_budget_ms \
         FROM r2_probe_runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_one(&pool)
    .await
    .expect("select v1 run");

    assert_eq!(row.get::<String, _>("prover_mode"), "v1");
    assert_eq!(row.get::<Option<i32>, _>("max_tx_inputs"), Some(8));
    assert_eq!(row.get::<Option<i32>, _>("max_tx_outputs"), Some(8));
    assert_eq!(row.get::<Option<i32>, _>("max_rx_coins"), Some(4));
    assert_eq!(
        row.get::<Option<i32>, _>("compliance_gate_count"),
        Some(1_403_783)
    );
    assert_eq!(row.get::<i64, _>("r2_warm_budget_ms"), 600_000);

    let summary = fetch_recent_summary(&pool, 1).await.expect("summary");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].prover_mode, "v1");
}

#[tokio::test]
async fn fetch_recent_summary_respects_limit() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("lim")).await.expect("host");
    for _ in 0..4 {
        insert_run(&pool, &sample_run(host_id)).await.expect("run");
    }
    let rows = fetch_recent_summary(&pool, 2).await.expect("summary");
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn fetch_recent_summary_cold_budget_covers_build_plus_prove() {
    // Regression guard for the view's `r2_cold_pass` formula. The
    // cold-start budget (`BUDGET_COLD_START_MS`, ROADMAP §Step 9) is
    // defined against `circuit_build_wall_ms + prove_cold_wall_ms`,
    // not against `prove_cold_wall_ms` alone. An earlier revision of
    // the view compared only the prove leg, which let a row with a
    // long build + over-budget total slip through with `r2_cold_pass
    // = true`. Run B below picks exactly that edge case so a
    // regression would flip its expected `false` back to `true`.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("coldsum"))
        .await
        .expect("host");

    // Run A: build 5_000 + prove 20_000 = 25_000 <= 30_000 budget ⇒ PASS.
    let mut run_a = sample_run(host_id);
    run_a.circuit_build_wall_ms = 5_000;
    run_a.prove_cold_wall_ms = 20_000;
    run_a.r2_cold_budget_ms = 30_000;
    let id_a = insert_run(&pool, &run_a).await.expect("run a");

    // Run B: build 15_000 + prove 25_000 = 40_000 > 30_000 budget ⇒ FAIL.
    // Note: prove_cold_wall_ms (25_000) alone is <= the budget. The
    // buggy old formula (prove-leg only) would mis-flag this row as
    // PASS; the correct formula (build + prove) flags it FAIL.
    let mut run_b = sample_run(host_id);
    run_b.circuit_build_wall_ms = 15_000;
    run_b.prove_cold_wall_ms = 25_000;
    run_b.r2_cold_budget_ms = 30_000;
    let id_b = insert_run(&pool, &run_b).await.expect("run b");

    let rows = fetch_recent_summary(&pool, 10).await.expect("summary");
    assert_eq!(rows.len(), 2);

    // Newest first — id_b was the last insert.
    assert_eq!(rows[0].id, id_b);
    assert_eq!(rows[1].id, id_a);

    assert!(
        !rows[0].r2_cold_pass,
        "build 15_000 + prove 25_000 = 40_000 > 30_000 budget must FAIL the cold-start check",
    );
    assert!(
        rows[1].r2_cold_pass,
        "build 5_000 + prove 20_000 = 25_000 <= 30_000 budget must PASS the cold-start check",
    );
}

#[tokio::test]
async fn fetch_recent_summary_null_warm_marks_warm_fail() {
    // A run with no warm samples must NOT silently pass the warm
    // budget — the view checks `IS NOT NULL` first.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let host_id = upsert_host(&pool, &sample_host("nullwarm"))
        .await
        .expect("host");
    let mut run = sample_run(host_id);
    run.prove_warm_p50_ms = None;
    run.prove_warm_p90_ms = None;
    run.prove_warm_p99_ms = None;
    insert_run(&pool, &run).await.expect("run");
    let rows = fetch_recent_summary(&pool, 1).await.expect("summary");
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].r2_warm_pass);
    assert!(rows[0].prove_warm_p50_ms.is_none());
}
