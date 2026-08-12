-- R2 probe: coexist legacy and v1.1 measurement rows without false-red
-- budget reclassification.
--
-- Gap G8: v1.1 `ProverBridge` proves (BIP-340 in-circuit) have different
-- wall times from the legacy Poseidon circuit. The probe must record
-- *which* circuit a run measured and the v1.1 shape parameters, while
-- leaving every legacy column default and every historical row
-- byte-identical in meaning (prover_mode defaults to 'legacy').
--
-- New columns are nullable except `prover_mode` (DEFAULT 'legacy' so
-- existing INSERT paths and historical rows stay valid without rewrite).
-- The summary view gains `prover_mode` so the admin trend endpoint can
-- filter by circuit; pass/fail still uses each row's own persisted
-- budgets (no retroactive flip).

ALTER TABLE r2_probe_runs
    ADD COLUMN prover_mode TEXT NOT NULL DEFAULT 'legacy';

ALTER TABLE r2_probe_runs
    ADD COLUMN max_tx_inputs INT;

ALTER TABLE r2_probe_runs
    ADD COLUMN max_tx_outputs INT;

ALTER TABLE r2_probe_runs
    ADD COLUMN max_rx_coins INT;

ALTER TABLE r2_probe_runs
    ADD COLUMN compliance_gate_count INT;

-- Replace the summary view to surface prover_mode. Pass columns keep the
-- same formulas (row-local budgets) so historical verdicts stay put.
DROP VIEW IF EXISTS r2_probe_runs_summary;
CREATE VIEW r2_probe_runs_summary AS
SELECT
    r.id,
    r.ran_at,
    h.hostname,
    h.cpu_brand,
    r.git_sha,
    r.build_profile,
    r.allocator,
    r.prover_mode,
    r.circuit_build_wall_ms,
    r.prove_cold_wall_ms,
    r.prove_warm_p50_ms,
    r.prove_warm_p90_ms,
    r.prove_warm_p99_ms,
    r.peak_rss_kb,
    ((r.circuit_build_wall_ms + r.prove_cold_wall_ms) <= r.r2_cold_budget_ms) AS r2_cold_pass,
    (r.prove_warm_p50_ms IS NOT NULL
         AND r.prove_warm_p50_ms <= r.r2_warm_budget_ms)                   AS r2_warm_pass,
    (r.peak_rss_kb <= r.r2_mem_budget_kb)                                  AS r2_mem_pass,
    r.succeeded
FROM r2_probe_runs r
JOIN r2_probe_hosts h ON h.id = r.host_id;
