//! R2 probe result persistence layer.
//!
//! The `probe_r2` binary (`node/src/bin/probe_r2.rs`) measures the
//! three ROADMAP step 9 budgets — warm `prove_*` wall, cold-start
//! wall, peak RSS — against the M3 Ultra reference hardware. Until
//! migration 0013 the only durable output was a JSON file on disk;
//! regression tracking meant grepping through a tree of timestamped
//! files. This module persists the same data into Postgres so the
//! operator can answer trend / regression queries in SQL.
//!
//! ## Schema overview (3 tables + 1 view)
//!
//! * [`HostInfo`] / `r2_probe_hosts` — normalised per-machine
//!   identity. The `(hostname, os, arch, cpu_brand)` natural key
//!   matches [`upsert_host`]'s `ON CONFLICT` clause, so re-running
//!   the probe on the same box returns the same `id` instead of
//!   piling up duplicate rows.
//! * [`ProbeRun`] / `r2_probe_runs` — one row per probe execution.
//!   Holds every scalar measurement, the run-time context (git sha,
//!   rustc version, allocator, circuit params), and the R2 budgets
//!   the run was checked against. The budgets are persisted on the
//!   row so a future budget tweak does NOT retroactively flip the
//!   pass/fail in [`SummaryRow`]. Migration 0023 adds `prover_mode`
//!   (`legacy` | `v11`) plus nullable v1.1 shape columns so both
//!   circuits can coexist without false-red reclassification.
//! * `r2_probe_warm_calls` — one row per warm call (call_index +
//!   wall_ms). Lets the operator recompute percentiles or inspect
//!   outliers later. FK ON DELETE CASCADE so pruning a single run
//!   row cleans up its children atomically.
//!
//! [`fetch_recent_summary`] reads from the `r2_probe_runs_summary`
//! view, which joins host + run and inlines the three budget-pass
//! booleans the admin endpoint surfaces.
//!
//! Budget selection lives in [`crate::r2_budgets`] — legacy constants
//! stay the flag-off default; v1.1 budgets come only from sealed
//! measurement samples (never a silent fall-back to the legacy set).
//!
//! ## Callers
//!
//! The `probe_r2` binary writes via [`upsert_host`], [`insert_run`],
//! and [`insert_warm_calls`] when invoked with `--persist`, and reads
//! the last few rows via [`fetch_recent_summary`] for the console
//! trend table. The router's `r2_probe_history_handler` reads via
//! [`fetch_recent_summary`] to back the `GET
//! /api/admin/r2-probe/history` endpoint.

use serde::Serialize;
use sqlx::PgPool;

/// Per-machine identity persisted in `r2_probe_hosts`. The natural
/// key `(hostname, os, arch, cpu_brand)` is captured here; the
/// remaining fields (`cpu_cores`, `total_ram_gb`) are payload and
/// updated on conflict so a hardware add (more RAM, a CPU swap) is
/// reflected without manual cleanup.
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cpu_brand: String,
    pub cpu_cores: i32,
    /// `None` when the platform path that reads RAM size is
    /// unavailable. The DB column is nullable for the same reason.
    pub total_ram_gb: Option<i32>,
}

/// Best-effort detection of the host running the probe.
///
/// Backed by the [`sysinfo`] crate, which wraps the per-platform host
/// introspection APIs (sysctl on macOS, `/proc` on Linux, Win32 on
/// Windows) behind a single Rust surface. Every leg has exactly one
/// success path — there are no subprocess- or FS-error arms that the
/// test gate can't reach on a healthy CI host, so the 100% line /
/// function coverage gate is satisfied without any `coverage(off)`
/// markers. The earlier shape shelled out to `hostname` / `sysctl` /
/// `/proc/...` directly and had to opt the per-platform helpers out
/// of the gate; that's gone now.
///
/// Fallbacks are conservative: an unknown hostname becomes
/// `"unknown"`, an empty CPU brand becomes `"unknown"`, a zero or
/// missing total-RAM reading becomes `None` (matching the nullable
/// DB column). The row still lands so the operator can correct it
/// later.
pub fn detect() -> HostInfo {
    // `RefreshKind::nothing().with_cpu(...).with_memory(...)` keeps
    // the constructor from touching the (expensive) process list. The
    // CPU refresh asks for frequency only — the CPU `brand` field is
    // populated as a side-effect of the first CPU refresh on every
    // backend (apple sysctl, linux `/proc/cpuinfo`), and we don't need
    // usage / per-core stats.
    let mut sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing()
            .with_cpu(sysinfo::CpuRefreshKind::nothing().with_frequency())
            .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram()),
    );
    // Explicit refresh calls are belt-and-braces over the constructor
    // refresh: on platforms where `new_with_specifics` is a no-op for
    // a given kind (rare, but documented for some embedded targets)
    // this guarantees the fields we read below are populated.
    sys.refresh_cpu_all();
    sys.refresh_memory();

    // Pull every sysinfo-sourced datum into a plain Option / scalar
    // value before handing off to [`detect_impl`]. The split is
    // deliberate: on a healthy host every leg below resolves to
    // `Some(_)` / a non-zero number, which means the `"unknown"` /
    // zero fallback paths inside `detect_impl` are unreachable from
    // `detect()`'s call site on the CI runner. Threading the values
    // through a separate function lets the test suite drive the
    // fallback closures with synthetic `None` / empty inputs, so the
    // 100 % line / function coverage gate stays green without
    // platform-specific test scaffolding.
    detect_impl(
        sysinfo::System::host_name(),
        sys.cpus().first().map(|c| c.brand().trim().to_string()),
        sys.total_memory(),
        std::thread::available_parallelism()
            .map(|n| n.get() as i32)
            .ok(),
    )
}

/// Pure assembly of [`HostInfo`] from the four host-introspection
/// readings [`detect`] pulls out of `sysinfo` and `std`. Split out so
/// the `"unknown"` / zero fallbacks below are reachable from unit
/// tests that pass synthetic `None` / empty-string inputs — the live
/// `detect()` call on the CI runner never lands on those branches.
///
/// * `hostname_opt` — value from `sysinfo::System::host_name()`.
///   `None` or `Some("")` collapses to the `"unknown"` fallback.
/// * `cpu_brand_opt` — value from
///   `sys.cpus().first().map(|c| c.brand().trim().to_string())`.
///   `None` or `Some("")` collapses to the `"unknown"` fallback.
/// * `total_memory_bytes` — value from `sys.total_memory()`. Divided
///   down to whole GiB; a zero reading collapses to `None` so a
///   sysinfo backend that failed to populate the field doesn't
///   persist a nonsense `0`.
/// * `cpu_cores_opt` — value from
///   `std::thread::available_parallelism().map(|n| n.get() as i32).ok()`.
///   `None` falls back to `0`.
fn detect_impl(
    hostname_opt: Option<String>,
    cpu_brand_opt: Option<String>,
    total_memory_bytes: u64,
    cpu_cores_opt: Option<i32>,
) -> HostInfo {
    HostInfo {
        hostname: hostname_opt
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_brand: cpu_brand_opt
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        cpu_cores: cpu_cores_opt.unwrap_or(0),
        total_ram_gb: Some((total_memory_bytes / (1024 * 1024 * 1024)) as i32).filter(|&g| g > 0),
    }
}

/// Full row written to `r2_probe_runs`. Every field maps 1:1 to a
/// column; nullable columns are `Option<...>` here.
#[derive(Debug, Clone)]
pub struct ProbeRun {
    pub host_id: i32,
    pub git_sha: String,
    pub binary_version: String,
    pub rustc_version: String,
    pub build_profile: String,
    pub allocator: String,
    /// `"legacy"` or `"v11"` — see [`crate::r2_budgets::ProverMode`].
    /// Defaults to `"legacy"` at the DB layer so pre-0023 insert paths
    /// and historical rows stay valid.
    pub prover_mode: String,
    pub max_in_coins: i32,
    pub max_out_coins: i32,
    pub inner_pad_bits: i32,
    /// v1.1 shape (`MAX_TX_INPUTS`); `None` on legacy rows.
    pub max_tx_inputs: Option<i32>,
    /// v1.1 shape (`MAX_TX_OUTPUTS`); `None` on legacy rows.
    pub max_tx_outputs: Option<i32>,
    /// v1.1 shape (`MAX_RX_COINS`); `None` on legacy rows.
    pub max_rx_coins: Option<i32>,
    /// v1.1 `ProverBridge::compliance_gate_count`; `None` on legacy.
    pub compliance_gate_count: Option<i32>,
    pub warm_calls_requested: i32,
    pub circuit_build_wall_ms: i64,
    pub prove_cold_wall_ms: i64,
    pub verify_wall_ms: i64,
    pub peak_rss_kb: i64,
    pub prove_warm_p50_ms: Option<i64>,
    pub prove_warm_p90_ms: Option<i64>,
    pub prove_warm_p99_ms: Option<i64>,
    pub succeeded: bool,
    pub error_message: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub r2_warm_budget_ms: i64,
    pub r2_cold_budget_ms: i64,
    pub r2_mem_budget_kb: i64,
}

/// Materialised row returned by [`fetch_recent_summary`]. Mirrors
/// the columns of the `r2_probe_runs_summary` view.
#[derive(Debug, Clone, Serialize)]
pub struct SummaryRow {
    pub id: i64,
    /// RFC-3339 timestamp formatted in Postgres so we stay off the
    /// chrono/time sqlx feature flags.
    pub ran_at: String,
    pub hostname: String,
    pub cpu_brand: String,
    pub git_sha: String,
    pub build_profile: String,
    pub allocator: String,
    /// `"legacy"` or `"v11"` (migration 0023).
    pub prover_mode: String,
    pub circuit_build_wall_ms: i64,
    pub prove_cold_wall_ms: i64,
    pub prove_warm_p50_ms: Option<i64>,
    pub prove_warm_p90_ms: Option<i64>,
    pub prove_warm_p99_ms: Option<i64>,
    pub peak_rss_kb: i64,
    pub r2_cold_pass: bool,
    pub r2_warm_pass: bool,
    pub r2_mem_pass: bool,
    pub succeeded: bool,
}

/// Insert or update a host row keyed on the natural identity
/// `(hostname, os, arch, cpu_brand)`. Returns the row id either way
/// — the `ON CONFLICT ... DO UPDATE` is required (over `DO NOTHING`)
/// so the `RETURNING id` clause fires on the conflict path too.
pub async fn upsert_host(pool: &PgPool, host: &HostInfo) -> sqlx::Result<i32> {
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO r2_probe_hosts \
            (hostname, os, arch, cpu_brand, cpu_cores, total_ram_gb) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (hostname, os, arch, cpu_brand) DO UPDATE \
         SET cpu_cores = EXCLUDED.cpu_cores, \
             total_ram_gb = EXCLUDED.total_ram_gb \
         RETURNING id",
    )
    .bind(&host.hostname)
    .bind(&host.os)
    .bind(&host.arch)
    .bind(&host.cpu_brand)
    .bind(host.cpu_cores)
    .bind(host.total_ram_gb)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Insert a single `r2_probe_runs` row and return its id. Callers
/// pass the host id obtained from a prior [`upsert_host`] call.
pub async fn insert_run(pool: &PgPool, run: &ProbeRun) -> sqlx::Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO r2_probe_runs ( \
             host_id, git_sha, binary_version, rustc_version, build_profile, allocator, \
             prover_mode, \
             max_in_coins, max_out_coins, inner_pad_bits, warm_calls_requested, \
             max_tx_inputs, max_tx_outputs, max_rx_coins, compliance_gate_count, \
             circuit_build_wall_ms, prove_cold_wall_ms, verify_wall_ms, peak_rss_kb, \
             prove_warm_p50_ms, prove_warm_p90_ms, prove_warm_p99_ms, \
             succeeded, error_message, notes, tags, \
             r2_warm_budget_ms, r2_cold_budget_ms, r2_mem_budget_kb \
         ) VALUES ( \
             $1, $2, $3, $4, $5, $6, \
             $7, \
             $8, $9, $10, $11, \
             $12, $13, $14, $15, \
             $16, $17, $18, $19, \
             $20, $21, $22, \
             $23, $24, $25, $26, \
             $27, $28, $29 \
         ) RETURNING id",
    )
    .bind(run.host_id)
    .bind(&run.git_sha)
    .bind(&run.binary_version)
    .bind(&run.rustc_version)
    .bind(&run.build_profile)
    .bind(&run.allocator)
    .bind(&run.prover_mode)
    .bind(run.max_in_coins)
    .bind(run.max_out_coins)
    .bind(run.inner_pad_bits)
    .bind(run.warm_calls_requested)
    .bind(run.max_tx_inputs)
    .bind(run.max_tx_outputs)
    .bind(run.max_rx_coins)
    .bind(run.compliance_gate_count)
    .bind(run.circuit_build_wall_ms)
    .bind(run.prove_cold_wall_ms)
    .bind(run.verify_wall_ms)
    .bind(run.peak_rss_kb)
    .bind(run.prove_warm_p50_ms)
    .bind(run.prove_warm_p90_ms)
    .bind(run.prove_warm_p99_ms)
    .bind(run.succeeded)
    .bind(run.error_message.as_deref())
    .bind(run.notes.as_deref())
    .bind(&run.tags)
    .bind(run.r2_warm_budget_ms)
    .bind(run.r2_cold_budget_ms)
    .bind(run.r2_mem_budget_kb)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Batch-insert per-warm-call samples. No-op (no SQL round-trip)
/// when `calls` is empty so a `--warm-calls 0` run cleanly persists
/// an empty child set. Uses `UNNEST` so the whole batch lands in a
/// single statement regardless of `calls.len()`.
pub async fn insert_warm_calls(pool: &PgPool, run_id: i64, calls: &[i64]) -> sqlx::Result<()> {
    if calls.is_empty() {
        return Ok(());
    }
    let indices: Vec<i32> = (0..calls.len() as i32).collect();
    sqlx::query(
        "INSERT INTO r2_probe_warm_calls (probe_run_id, call_index, wall_ms) \
         SELECT $1, idx, wall \
         FROM UNNEST($2::int[], $3::bigint[]) AS t(idx, wall)",
    )
    .bind(run_id)
    .bind(&indices)
    .bind(calls)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch the most recent `limit` rows from the `r2_probe_runs_summary`
/// view, newest first. Backs the admin trend endpoint and the probe
/// binary's console trend table after `--persist`.
///
/// `sqlx`'s tuple `FromRow` impl tops out at 16 columns; the summary
/// has 17, so this helper drives `sqlx::query` and uses `Row::get`
/// for the column extraction. The trade-off is one untyped layer
/// over named columns — exactly the shape `db.rs` uses for the
/// pending-inscription summary read.
pub async fn fetch_recent_summary(pool: &PgPool, limit: i64) -> sqlx::Result<Vec<SummaryRow>> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, \
                to_char(ran_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS ran_at, \
                hostname, cpu_brand, git_sha, build_profile, allocator, \
                prover_mode, \
                circuit_build_wall_ms, prove_cold_wall_ms, \
                prove_warm_p50_ms, prove_warm_p90_ms, prove_warm_p99_ms, \
                peak_rss_kb, \
                r2_cold_pass, r2_warm_pass, r2_mem_pass, succeeded \
         FROM r2_probe_runs_summary \
         ORDER BY ran_at DESC \
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| SummaryRow {
            id: r.get("id"),
            ran_at: r.get("ran_at"),
            hostname: r.get("hostname"),
            cpu_brand: r.get("cpu_brand"),
            git_sha: r.get("git_sha"),
            build_profile: r.get("build_profile"),
            allocator: r.get("allocator"),
            prover_mode: r.get("prover_mode"),
            circuit_build_wall_ms: r.get("circuit_build_wall_ms"),
            prove_cold_wall_ms: r.get("prove_cold_wall_ms"),
            prove_warm_p50_ms: r.get("prove_warm_p50_ms"),
            prove_warm_p90_ms: r.get("prove_warm_p90_ms"),
            prove_warm_p99_ms: r.get("prove_warm_p99_ms"),
            peak_rss_kb: r.get("peak_rss_kb"),
            r2_cold_pass: r.get("r2_cold_pass"),
            r2_warm_pass: r.get("r2_warm_pass"),
            r2_mem_pass: r.get("r2_mem_pass"),
            succeeded: r.get("succeeded"),
        })
        .collect())
}

#[cfg(test)]
#[path = "r2_probe_tests.rs"]
mod tests;
