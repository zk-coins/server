//! R2 budget selection for the legacy prover and the v1.1 `ProverBridge`.
//!
//! ## Why two budget sets
//!
//! The ROADMAP step-9 budgets (`LEGACY_*`) were calibrated against the
//! Poseidon-only legacy circuit (`Prover::new` + `prove_initial` /
//! `prove_account_update`, shape `MAX_IN_COINS` / `MAX_OUT_COINS`).
//! v1.1 transitions verify BIP-340 + S2C **in-circuit** and therefore
//! have materially different wall times. Applying the legacy 5 s warm /
//! 30 s cold budgets to a healthy v1.1 prove produces **false reds in
//! operations** — the failure mode this module exists to prevent.
//!
//! ## Flag decides which set applies
//!
//! [`budgets_for_mode`] returns the legacy constants when the mode is
//! [`ProverMode::Legacy`] (default; flag off). Under [`ProverMode::V1`]
//! it returns budgets **derived from stored measurement samples**. There
//! is no silent fall-back from v1.1 to legacy numbers: a missing or
//! under-sampled calibration refuses loudly via [`BudgetUnavailable`].
//!
//! ## Derivation contract
//!
//! A single sample is not a budget. [`derive_budget_from_samples`]
//! requires at least [`MIN_SAMPLES_FOR_BUDGET`] non-negative samples and
//! returns `max(samples)` inflated by a documented headroom percent.
//! Operators can re-run `probe_r2 --prover v1` and re-seal the sample
//! arrays below when hardware or the circuit changes.

use std::fmt;

/// Minimum number of wall-time (or RSS) samples required before a value
/// may be treated as a budget basis. One sample is never enough: it
/// cannot show spread and would bake a one-off spike or stall into the
/// operator alert threshold.
pub const MIN_SAMPLES_FOR_BUDGET: usize = 2;

/// Headroom applied on top of `max(samples)` when sealing a budget.
/// 25 % absorbs ordinary host noise without letting a single cold
/// outlier dominate; the raw samples stay visible in
/// [`V1_CALIBRATION`] so operators can re-derive.
pub const BUDGET_HEADROOM_PERCENT: u32 = 25;

/// ROADMAP step 9 warm-prove budget (legacy Poseidon circuit), ms.
pub const LEGACY_BUDGET_WARM_PROVE_MS: i64 = 5_000;
/// ROADMAP step 9 cold-start budget (legacy: build + first prove), ms.
pub const LEGACY_BUDGET_COLD_START_MS: i64 = 30_000;
/// ROADMAP step 9 peak-RSS budget (legacy), KB.
pub const LEGACY_BUDGET_PEAK_RSS_KB: i64 = 64 * 1024 * 1024; // 64 GiB

/// Which prover the probe measures and whose budgets apply.
///
/// Selected by `probe_r2 --prover legacy|v1` or, when the CLI omits
/// `--prover`, by `ZKCOINS_V1_SHADOW` (`1` → v1, unset/empty/`off` →
/// legacy). Unknown values fail loud — no silent default to legacy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverMode {
    /// Legacy `zkcoins_prover::Prover` (`circuit::main`).
    Legacy,
    /// v1.1 `ProverBridge` (`C` / `prove_transition`).
    V1,
}

impl ProverMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ProverMode::Legacy => "legacy",
            ProverMode::V1 => "v1",
        }
    }

    /// Parse a closed vocabulary. Unknown tokens fail loud.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "legacy" => Ok(ProverMode::Legacy),
            "v1" => Ok(ProverMode::V1),
            other => Err(format!(
                "unknown prover mode {other:?}: expected exactly \"legacy\" or \"v1\" \
                 (no silent default)"
            )),
        }
    }
}

impl fmt::Display for ProverMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolve the probe/warmup prover mode from optional CLI override and
/// the `ZKCOINS_V1_SHADOW` env value (already resolved to a string
/// snapshot so tests need not mutate process env).
///
/// Precedence:
/// 1. `cli_prover` if `Some` — explicit `--prover` wins.
/// 2. `v1_shadow_raw` — `Some("1")` → V1; `None` / `""` / `"off"` → Legacy.
/// 3. Anything else in the shadow slot fails loud (same contract as
///    [`crate::v1::mode::resolve_v1_shadow_mode`]).
pub fn resolve_prover_mode(
    cli_prover: Option<&str>,
    v1_shadow_raw: Option<&str>,
) -> Result<ProverMode, String> {
    if let Some(raw) = cli_prover {
        return ProverMode::parse(raw);
    }
    match v1_shadow_raw {
        None => Ok(ProverMode::Legacy),
        Some(s) if s.is_empty() || s == "off" => Ok(ProverMode::Legacy),
        Some("1") => Ok(ProverMode::V1),
        Some(other) => Err(format!(
            "ZKCOINS_V1_SHADOW={other:?} is not supported when selecting R2 probe mode — \
             use unset / empty / \"off\" for legacy, or \"1\" for v1.1. Refusing to \
             silently fall back to legacy budgets (that is the false-red this block prevents)"
        )),
    }
}

/// The three ROADMAP step-9 budgets the probe checks and persists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R2BudgetSet {
    pub warm_prove_ms: i64,
    pub cold_start_ms: i64,
    pub peak_rss_kb: i64,
}

/// Why a budget could not be produced. Always fail loud — never
/// substitute the legacy number under a v1.1 mode selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetUnavailable {
    pub mode: ProverMode,
    pub metric: &'static str,
    pub detail: String,
}

impl fmt::Display for BudgetUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "R2 budget unavailable for mode={} metric={}: {} \
             (refusing silent fall-back to another circuit's numbers)",
            self.mode, self.metric, self.detail
        )
    }
}

impl std::error::Error for BudgetUnavailable {}

/// Evidence backing a sealed v1.1 budget set. Every number the operator
/// alert uses must be traceable to these samples.
#[derive(Clone, Copy, Debug)]
pub struct V1CalibrationEvidence {
    /// Host / date / notes for the measurement campaign.
    pub note: &'static str,
    /// Warm `prove_transition` (AccountUpdate) wall samples, ms.
    pub warm_prove_ms: &'static [i64],
    /// Cold-start samples (`circuit build` + first `prove_transition`), ms.
    /// Each entry is one process-lifetime cold start (OnceLock makes
    /// in-process repeats free — multiple process runs are required).
    pub cold_start_ms: &'static [i64],
    /// Peak RSS samples at end of probe, KB.
    pub peak_rss_kb: &'static [i64],
    /// Headroom percent applied to `max(samples)` when sealing.
    pub headroom_percent: u32,
}

/// Sealed v1.1 calibration.
///
/// **How these numbers were obtained** (see also the report in the G8
/// change description):
///
/// * Host: Mac Studio class aarch64 Darwin (same class as ROADMAP step 9).
/// * Binary: `cargo build --release -p node --bin probe_r2`, mimalloc.
/// * Path: `ProverBridge::new(Testnet)` → force `compliance_gate_count`
///   (circuit build) → `prove_transition` Initial (cold) → N×
///   `prove_transition` AccountUpdate (warm, same witness reused).
/// * Shape: `MAX_TX_INPUTS=8`, `MAX_TX_OUTPUTS=8`, `MAX_RX_COINS=4`.
/// * Sample counts and spreads are whatever the arrays below hold;
///   [`budgets_for_mode`] refuses if any array has fewer than
///   [`MIN_SAMPLES_FOR_BUDGET`] entries.
///
/// Arrays start empty until a measurement campaign seals them. An empty
/// array is an explicit "not yet measured" state — **not** a zero-ms
/// budget and **not** a fall-back to legacy.
pub const V1_CALIBRATION: V1CalibrationEvidence = V1CalibrationEvidence {
    note: "v1.1 ProverBridge prove_transition calibration — see V1_*_SAMPLES arrays",
    warm_prove_ms: V1_WARM_SAMPLES_MS,
    cold_start_ms: V1_COLD_SAMPLES_MS,
    peak_rss_kb: V1_RSS_SAMPLES_KB,
    headroom_percent: BUDGET_HEADROOM_PERCENT,
};

// ---------------------------------------------------------------------------
// Sealed measurement samples. Replace only after a multi-run campaign on
// the reference host; never invent scaled guesses from the legacy 5 s /
// 30 s targets. Empty = not calibrated → budgets_for_mode(V1) errors.
// ---------------------------------------------------------------------------

/// Warm AccountUpdate `prove_transition` walls (ms). Fill from probe runs.
const V1_WARM_SAMPLES_MS: &[i64] = &[];

/// Cold-start walls (circuit build + first Initial prove), ms. One entry
/// per process run.
const V1_COLD_SAMPLES_MS: &[i64] = &[];

/// Peak RSS (KB) at end of each process run.
const V1_RSS_SAMPLES_KB: &[i64] = &[];

/// Derive a single budget from raw samples.
///
/// * Refuses when `samples.len() < MIN_SAMPLES_FOR_BUDGET`.
/// * Refuses when any sample is negative (clock / unit bug).
/// * Budget = `ceil_div(max * (100 + headroom_percent), 100)` via
///   integer arithmetic (`max * (100 + h) / 100`).
pub fn derive_budget_from_samples(
    samples: &[i64],
    headroom_percent: u32,
    metric: &'static str,
    mode: ProverMode,
) -> Result<i64, BudgetUnavailable> {
    if samples.len() < MIN_SAMPLES_FOR_BUDGET {
        return Err(BudgetUnavailable {
            mode,
            metric,
            detail: format!(
                "need at least {MIN_SAMPLES_FOR_BUDGET} samples to seal a budget, got {}; \
                 a single sample is not a budget",
                samples.len()
            ),
        });
    }
    if let Some((idx, bad)) = samples.iter().enumerate().find(|(_, s)| **s < 0) {
        return Err(BudgetUnavailable {
            mode,
            metric,
            detail: format!("sample[{idx}]={bad} is negative; refusing to seal a budget"),
        });
    }
    let max = samples.iter().copied().max().expect("len checked above");
    let factor = 100i64 + i64::from(headroom_percent);
    // Saturating mul avoids overflow on pathological multi-hour samples;
    // division truncates toward zero (budgets are whole milliseconds).
    let budget = max.saturating_mul(factor) / 100;
    Ok(budget)
}

/// Sample-count / min / max / mean helper for operator reports and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleSpread {
    pub count: usize,
    pub min_ms: i64,
    pub max_ms: i64,
    pub mean_ms: i64,
}

impl SampleSpread {
    pub fn from_samples(samples: &[i64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let min_ms = samples.iter().copied().min().expect("non-empty");
        let max_ms = samples.iter().copied().max().expect("non-empty");
        let sum: i64 = samples.iter().sum();
        let mean_ms = sum / samples.len() as i64;
        Some(Self {
            count: samples.len(),
            min_ms,
            max_ms,
            mean_ms,
        })
    }
}

/// Return the budget set for `mode`, or a structured error when the
/// mode's calibration is missing / under-sampled.
///
/// Legacy budgets are the fixed ROADMAP step-9 constants (historical
/// contract; flag-off path must stay byte-identical).
///
/// v1.1 budgets are derived from [`V1_CALIBRATION`] samples. Empty or
/// single-sample arrays produce [`BudgetUnavailable`] — never the
/// legacy 5 s / 30 s / 64 GiB numbers.
pub fn budgets_for_mode(mode: ProverMode) -> Result<R2BudgetSet, BudgetUnavailable> {
    match mode {
        ProverMode::Legacy => Ok(R2BudgetSet {
            warm_prove_ms: LEGACY_BUDGET_WARM_PROVE_MS,
            cold_start_ms: LEGACY_BUDGET_COLD_START_MS,
            peak_rss_kb: LEGACY_BUDGET_PEAK_RSS_KB,
        }),
        ProverMode::V1 => {
            let cal = V1_CALIBRATION;
            let warm = derive_budget_from_samples(
                cal.warm_prove_ms,
                cal.headroom_percent,
                "warm_prove_ms",
                ProverMode::V1,
            )?;
            let cold = derive_budget_from_samples(
                cal.cold_start_ms,
                cal.headroom_percent,
                "cold_start_ms",
                ProverMode::V1,
            )?;
            let rss = derive_budget_from_samples(
                cal.peak_rss_kb,
                cal.headroom_percent,
                "peak_rss_kb",
                ProverMode::V1,
            )?;
            Ok(R2BudgetSet {
                warm_prove_ms: warm,
                cold_start_ms: cold,
                peak_rss_kb: rss,
            })
        }
    }
}

/// Human-readable calibration summary for the console / JSON report.
/// Returns `Err` with the same refuse-loud contract when samples are
/// insufficient (so a "report calibration" path cannot paper over a
/// missing measurement).
pub fn v1_calibration_summary() -> Result<String, BudgetUnavailable> {
    let cal = V1_CALIBRATION;
    let warm = SampleSpread::from_samples(cal.warm_prove_ms).ok_or_else(|| BudgetUnavailable {
        mode: ProverMode::V1,
        metric: "warm_prove_ms",
        detail: "no warm samples sealed in V1_CALIBRATION".into(),
    })?;
    let cold = SampleSpread::from_samples(cal.cold_start_ms).ok_or_else(|| BudgetUnavailable {
        mode: ProverMode::V1,
        metric: "cold_start_ms",
        detail: "no cold-start samples sealed in V1_CALIBRATION".into(),
    })?;
    let rss = SampleSpread::from_samples(cal.peak_rss_kb).ok_or_else(|| BudgetUnavailable {
        mode: ProverMode::V1,
        metric: "peak_rss_kb",
        detail: "no peak-RSS samples sealed in V1_CALIBRATION".into(),
    })?;
    // Touch the derivation so a summary claim always matches the budget.
    let budgets = budgets_for_mode(ProverMode::V1)?;
    Ok(format!(
        "v1 calibration ({note}): warm n={wn} min={wmin} max={wmax} mean={wmean} → budget {wb} ms; \
         cold n={cn} min={cmin} max={cmax} mean={cmean} → budget {cb} ms; \
         rss n={rn} min={rmin} max={rmax} mean={rmean} → budget {rb} KB; \
         headroom={h}%",
        note = cal.note,
        wn = warm.count,
        wmin = warm.min_ms,
        wmax = warm.max_ms,
        wmean = warm.mean_ms,
        wb = budgets.warm_prove_ms,
        cn = cold.count,
        cmin = cold.min_ms,
        cmax = cold.max_ms,
        cmean = cold.mean_ms,
        cb = budgets.cold_start_ms,
        rn = rss.count,
        rmin = rss.min_ms,
        rmax = rss.max_ms,
        rmean = rss.mean_ms,
        rb = budgets.peak_rss_kb,
        h = cal.headroom_percent,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_budgets_match_roadmap_constants() {
        let b = budgets_for_mode(ProverMode::Legacy).expect("legacy always available");
        assert_eq!(b.warm_prove_ms, 5_000);
        assert_eq!(b.cold_start_ms, 30_000);
        assert_eq!(b.peak_rss_kb, 64 * 1024 * 1024);
    }

    #[test]
    fn derive_refuses_zero_samples() {
        let err = derive_budget_from_samples(&[], 25, "warm_prove_ms", ProverMode::V1)
            .expect_err("empty must refuse");
        assert!(err.detail.contains("at least"));
        assert_eq!(err.mode, ProverMode::V1);
        assert_eq!(err.metric, "warm_prove_ms");
    }

    #[test]
    fn derive_refuses_single_sample() {
        let err = derive_budget_from_samples(&[1_000], 25, "warm_prove_ms", ProverMode::V1)
            .expect_err("single sample must refuse");
        assert!(
            err.detail.contains("single sample is not a budget")
                || err.detail.contains("at least"),
            "unexpected detail: {}",
            err.detail
        );
    }

    #[test]
    fn derive_uses_max_plus_headroom() {
        // max=1000, headroom 25 % → 1250
        let b = derive_budget_from_samples(&[800, 1000, 900], 25, "warm_prove_ms", ProverMode::V1)
            .expect("enough samples");
        assert_eq!(b, 1_250);
    }

    #[test]
    fn derive_refuses_negative_sample() {
        let err = derive_budget_from_samples(&[100, -1], 25, "warm_prove_ms", ProverMode::V1)
            .expect_err("negative must refuse");
        assert!(err.detail.contains("negative"));
    }

    #[test]
    fn v1_budgets_refuse_when_uncalibrated() {
        // The sealed arrays start empty (or stay empty until a campaign
        // lands). Either way, under-sampled calibration must not return
        // the legacy 5 s / 30 s numbers.
        match budgets_for_mode(ProverMode::V1) {
            Ok(b) => {
                // If a campaign has sealed samples, the returned set must
                // still differ from a silent legacy fall-back *or* be
                // measurement-backed. Assert the derivation path ran by
                // checking headroom-consistency with the sealed samples.
                let warm_spread = SampleSpread::from_samples(V1_CALIBRATION.warm_prove_ms)
                    .expect("Ok branch requires samples");
                assert!(b.warm_prove_ms >= warm_spread.max_ms);
                assert_ne!(
                    (b.warm_prove_ms, b.cold_start_ms, b.peak_rss_kb),
                    (
                        LEGACY_BUDGET_WARM_PROVE_MS,
                        LEGACY_BUDGET_COLD_START_MS,
                        LEGACY_BUDGET_PEAK_RSS_KB
                    ),
                    "v1 budgets must not be a silent copy of legacy ROADMAP numbers"
                );
            }
            Err(e) => {
                assert_eq!(e.mode, ProverMode::V1);
                assert!(
                    e.to_string().contains("refusing silent fall-back")
                        || e.detail.contains("at least")
                        || e.detail.contains("no warm samples")
                        || e.detail.contains("samples"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    #[test]
    fn resolve_mode_cli_overrides_shadow() {
        assert_eq!(
            resolve_prover_mode(Some("legacy"), Some("1")).unwrap(),
            ProverMode::Legacy
        );
        assert_eq!(
            resolve_prover_mode(Some("v1"), None).unwrap(),
            ProverMode::V1
        );
    }

    #[test]
    fn resolve_mode_shadow_one_selects_v1() {
        assert_eq!(
            resolve_prover_mode(None, Some("1")).unwrap(),
            ProverMode::V1
        );
    }

    #[test]
    fn resolve_mode_default_is_legacy() {
        assert_eq!(resolve_prover_mode(None, None).unwrap(), ProverMode::Legacy);
        assert_eq!(
            resolve_prover_mode(None, Some("")).unwrap(),
            ProverMode::Legacy
        );
        assert_eq!(
            resolve_prover_mode(None, Some("off")).unwrap(),
            ProverMode::Legacy
        );
    }

    #[test]
    fn resolve_mode_unknown_shadow_fails_loud() {
        let err = resolve_prover_mode(None, Some("true")).expect_err("true must fail");
        assert!(err.contains("not supported"));
        assert!(err.contains("false-red") || err.contains("fall back"));
    }

    #[test]
    fn resolve_mode_unknown_cli_fails_loud() {
        let err = resolve_prover_mode(Some("bridge"), None).expect_err("bridge must fail");
        assert!(err.contains("unknown prover mode"));
    }

    #[test]
    fn sample_spread_none_on_empty() {
        assert!(SampleSpread::from_samples(&[]).is_none());
    }

    #[test]
    fn sample_spread_reports_count_and_range() {
        let s = SampleSpread::from_samples(&[10, 30, 20]).unwrap();
        assert_eq!(s.count, 3);
        assert_eq!(s.min_ms, 10);
        assert_eq!(s.max_ms, 30);
        assert_eq!(s.mean_ms, 20);
    }
}
