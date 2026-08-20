# Coverage baseline (G16)

This file is the **measured** coverage floor for the `Tests + Coverage Gate`
job in `.github/workflows/ci.yaml` and the live copy in
`.github/workflows/pull-request.yaml`. It exists so the gate cannot silently
claim 100 % while carving production modules out of the measurement
(plan.md §5a.1 / v1.2-delta G16 / audit issue #1).

## Rules

1. **Production modules are measured.** The only `--ignore-filename-regex`
   entries allowed without a written justification *in this file* are
   pure test infrastructure and crate entrypoints:
   - `*_tests.rs` — co-located unit-test modules
   - `test_db.rs` — shared Postgres test helper
   - `bin/.*\.rs$` — binary entrypoints
   - `main.rs` / `lib.rs` — crate surface (not production logic under test)
2. **Prover-circuit packages are excluded — with justification.**
   `program-plonky2/` and `script-plonky2/` are the only non-trivial
   carve-out. Their correctness is secured by:
   - the §1.7.9 circuit-digest generator (committed digests verified
     in the heavy CI job),
   - the Plonky2 prove-driven suite (mint / send / receive flows),
   - the D-05 differential test against the reference implementation.
   Line-coverage over circuit gadgets and gate tables does not add
   signal comparable to those checks; counting those packages would
   drown the floor in structurally un-executable paths. This is the
   only package-level exclusion and must stay justified here if it
   remains.
3. **No silent carve-outs.** If a production file must be excluded, the
   reason is documented here — never only encoded in a regex.
4. **Floor does not sink.** CI enforces integer floors of the measured
   totals via `--fail-under-lines` / `--fail-under-functions`. Raising
   the floor toward 100 % is follow-up work; lowering it is a regression
   that needs an explicit decision and an update to this file.

## CI trigger note

The heavy gate runs on every non-draft PR. Drafts stay quiet unless they
carry `ci` or `ci:full` — those labels start the same suite without
leaving draft. Ready-for-review is not a CI switch.

## Measurement record

Latest honest run (self-hosted gate, 1802 tests passed, 0 failed):

| Field | Value |
|---|---|
| Date | 2026-08-20 |
| Branch | `feat/mtp-ready` |
| Commit | `1e07489ef68cc6f0ff93b3bed17b9996cd32cdaa` (`1e07489`) |
| Scope | `-p node -p shared --all-features` |
| Ignore regex | `_tests\.rs$\|test_db\.rs$\|bin/.*\.rs$\|main\.rs$\|lib\.rs$\|program-plonky2/\|script-plonky2/` |
| Nextest filter | `not binary(api_remote)` |
| Notes | `scan.rs` inline `#[cfg(test)]` module carries `coverage(off)` |

Previous measurement (kept for history). **Lines:** 75.26 %
(31577 / 41959) on `6656fdd` before the `scan.rs` test module was
excluded; the new Lines total is 75.20 % (31476 / 41859).
**Functions:** 76.02 % (2638 / 3470) → 75.94 % (2626 / 3458) for the
same reason: inline tests were inflating the function count (see
methodology 2026-08-07). `--fail-under-functions 76` fails 75.94 %
as a real integer miss, not a column mix-up.

**Rule-4 decision (2026-08-20, second re-measure):** keep lines at
75 and lower functions 76 → 75, the integer floor of 75.94 %. This
is an explicit sink after excluding inline tests from the corpus,
not a greenwash: all 1802 tests passed.

| Field | Value |
|---|---|
| Date | 2026-08-02 |
| Branch | `feat/v1-spec-rebuild` |
| Commit | `18131ebeb4f0e717f2baba6856b0680ed3637fba` (`18131eb`) |
| Scope | `-p node -p shared --all-features` |
| Lines | 77.28% (39142 / 50651) |
| Functions | 77.82% (3038 / 3904) |

## CI floor (what the gate enforces)

| Metric | Measured | CI `--fail-under-*` (integer floor) |
|---|---|---|
| **Lines** | **75.20%** (31476 / 41859) | **75** |
| **Functions** | **75.94%** (2626 / 3458) | **75** |

llvm-cov's table is Regions / Functions / Lines (not Lines first).
A regression under 75 % lines or 75 % functions fails the gate. There
is no 100 % fiction: the integers sit just under the honest measurement.

## Previously illegitimate ignore list (removed)

These patterns used to hide production code from a false 100 % claim
and are **no longer** in `--ignore-filename-regex`:

| Pattern | Why it was wrong |
|---|---|
| `publisher.rs` | Core Bitcoin inscription publisher |
| `flow.rs` | Mint/send/commit job flow bodies |
| `job_dispatcher.rs` | Background job state machine |
| `runtime.rs` | Process bootstrap / readiness |
| `scanner_runtime.rs` | Scanner orchestration |
| `scanner_ws.rs` | Chain-tip WebSocket path |
| `shared/src/.*` | Protocol types + commitment helpers |

## Weakest 25 files (from the 2026-08-02 measurement)

Generated from commit `18131eb`, not from the 2026-08-20 re-measure.
Closing these is follow-up; the gate only prevents regression below
the floor.

| File | Lines % | Functions % | Lines (instrumented) |
|---|---|---|---|
| `node/src/v1/publish.rs` | 0.0 | 0.0 | 110 |
| `shared/src/spec_v1/error.rs` | 5.9 | 33.3 | 221 |
| `node/src/flow.rs` | 11.3 | 9.4 | 451 |
| `node/src/v1/db_decrypt_index.rs` | 20.5 | 18.8 | 146 |
| `node/src/v1/incoming.rs` | 25.0 | 29.5 | 816 |
| `node/src/runtime.rs` | 33.3 | 41.5 | 891 |
| `node/src/kernel/service.rs` | 38.4 | 48.3 | 521 |
| `node/src/job_dispatcher.rs` | 46.1 | 53.5 | 3184 |
| `node/src/v1/scan.rs` | 47.0 | 45.5 | 585 |
| `node/src/v1/sdr.rs` | 50.2 | 29.2 | 727 |
| `node/src/transport/grpc/convert.rs` | 52.1 | 62.1 | 1263 |
| `node/src/v1/mode.rs` | 56.0 | 50.0 | 268 |
| `node/src/v1/delivery.rs` | 57.1 | 53.6 | 1558 |
| `node/src/v1/signature.rs` | 60.1 | 56.0 | 2421 |
| `node/src/v1/recovery.rs` | 67.0 | 78.6 | 798 |
| `shared/src/spec_v1/datastructures.rs` | 68.0 | 37.5 | 75 |
| `node/src/v1/receive.rs` | 71.0 | 55.3 | 2585 |
| `node/src/v1/nostr/relay.rs` | 76.3 | 86.9 | 1120 |
| `node/src/v1/self_heal.rs` | 76.3 | 68.2 | 465 |
| `node/src/v1/reconstitute.rs` | 76.4 | 74.3 | 533 |
| `node/src/v1/nostr/kinds/delivery.rs` | 76.5 | 81.5 | 319 |
| `node/src/publisher.rs` | 79.1 | 84.4 | 535 |
| `node/src/esplora_bound.rs` | 79.2 | 66.7 | 48 |
| `node/src/v1/attest.rs` | 79.9 | 73.9 | 1351 |
| `node/src/v1/nostr/profile.rs` | 80.2 | 80.3 | 983 |

## How to re-measure

```bash
export PUBLISHER_KEY=0000000000000000000000000000000000000000000000000000000000000001
export IS_MAINNET=false
export ESPLORA_URL=http://127.0.0.1:1/api
export ESPLORA_WS_URL=ws://127.0.0.1:1/api/v1/ws
export USERNAME_DOMAIN=test.zkcoins.local
export RUSTFLAGS="--cfg coverage_nightly"
IGNORE='_tests\.rs$|test_db\.rs$|bin/.*\.rs$|main\.rs$|lib\.rs$|program-plonky2/|script-plonky2/'

cargo llvm-cov nextest --release -p node -p shared --all-features \
  --ignore-filename-regex "$IGNORE" \
  --fail-under-lines 0 --fail-under-functions 0 \
  --test-threads 8 \
  -E 'not binary(api_remote)'

cargo llvm-cov report --release --json --ignore-filename-regex "$IGNORE"
```

After a higher measurement, raise the `--fail-under-*` integers in
`ci.yaml` **and** `pull-request.yaml` and update the tables above in
the same PR. Never lower them to greenwash a drop; a re-measure of a
grown corpus belongs in the tables above with the old numbers kept.

## Shared crate: reachable code covered, residual is provably unreachable

As of 2026-08-06 the `shared` crate's own files (`spec_v1/*`, `commitment.rs`)
are covered at ~99% lines; `error`, `network_params`, `trees`, `datastructures`,
`nflog` are at 100%. The remaining uncovered lines are **provably-unreachable
defensive code** — not test gaps. They are documented here (rule 3) rather than
silently ignored, and are NOT worth artificial tests:

- `commitment.rs:71` — `Err(_)` after `Message::from_digest_slice(msg_hash)`; the
  input is always exactly 32 bytes, so the conversion cannot fail.
- `spec_v1/encoding.rs:41` — `ByteStringTooLong` needs a ~72 PB slice (not allocatable).
- `spec_v1/hashes.rs:406-407` — `NameTooLong` via `u32::try_from` needs a >4 GiB local-part.
- `spec_v1/bootstrap_manifest.rs:611-612` — `fixture_sk` rehash second iteration needs a
  SHA-256 digest outside `[1,n)` (~2⁻¹²⁸).
- `spec_v1/coinhist.rs:155` — `Absent` is never stored in `leaves`; no public path reaches it.
- `spec_v1/bundle.rs:444-453,485,497,605-608,615-616` — defensive arms after a preceding
  `validate_*` / bounds check already guarantees the non-divergent branch.
- `spec_v1/accumulator.rs:427,1006`, `spec_v1/serialize.rs:141` — implicit else-region of an
  `if let` whose predecessor assert guarantees no divergence / block whose only content is a
  terminating `return` (llvm-cov closing-brace region artifact).
- `spec_v1/nflog_boundary.rs:51,107,369,380,773,860` — test-fixture module (`test-fixtures`
  feature) defensive `assert!`/overflow guards on inputs the suite never violates.

Reaching a literal 100% would require `#[cfg_attr(coverage_nightly, coverage(off))]` on these
functions (the established mechanism in this repo) — deferred, since annotating single defensive
arms inside otherwise-covered functions would over-exclude their covered lines.

## Node crate: unit + integration coverage (2026-08-07)

A large part of the `node` crate is integration code (Scanner/bitcoind RPC, PgPool, the async
job-dispatcher) that a pure unit test cannot reach — it only runs against the live stack. That code
IS exercised by the end-to-end journey, but a normal `cargo llvm-cov nextest` run does not instrument
the journey, so it was counted as uncovered. The **integration-coverage pipeline** closes this:

- `deploy/local-e2e/collect-integration-coverage.sh` builds the node image with coverage
  instrumentation scoped to **workspace crates only** (`RUSTC_WORKSPACE_WRAPPER`, so the external
  `plonky2` prover is NOT instrumented and stays fast; the circuit workspace crates carry crate-level
  `#![cfg_attr(coverage_nightly, coverage(off))]`), runs the journey 1→9 against it, flushes coverage
  on SIGTERM (a `coverage-flush`-feature handler calling `__llvm_profile_write_file`), and merges the
  resulting `integration.lcov` with the unit-test `unit.lcov`.
- Reproduce: bring the dev stack (`zkcoins-local`) down first (port 18443), `source` env.local.sh,
  `export COMPOSE_PROJECT_NAME=zkcoins-local-coverage`, `brew install lcov`, then run the script.

**Measured node-src line coverage (updated 2026-08-07, wave 4):**

| Source | Coverage |
|---|---|
| Unit tests only | 79.51% |
| Journey/integration only | 23.97%¹ |
| **Combined (unit ∪ integration)** | **85.35%** (44294 / 51894) |

Wave-4 unit gains: `v1/attest.rs` 82 → **88.01%**, `v1/nostr/profile.rs` 83 → **89.51%** (each with an
adversarial-review pass, all error-branch assertions pinned to the exact variant/message), `v1/recovery.rs`
§4.5 +11 error-branch tests.

**Methodology fix applied (2026-08-07): inline test modules excluded from coverage.** All 46 inline
`#[cfg(test)] mod tests` blocks in node-src now carry `#[cfg_attr(coverage_nightly, coverage(off))]`
(same mechanism the shared/script/program crates already use). This measures honest **production**
coverage. Counter-intuitively this *lowered* the reported number: the inline test modules were ~95%
covered (tests run their own code) and were inflating the figure, not deflating it.

**Honest production node-src line coverage (2026-08-07, test modules excluded):**

| Source | Coverage |
|---|---|
| Unit tests only | 68.81% |
| Journey/integration only | 40.33% |
| **Combined (unit ∪ integration)** | **78.63%** (24257 / 30848) |

The earlier 85.35% figure counted test code and was inflated. Production coverage is 78.63% combined.
The remaining ~21% is dominated by **integration-only** production code (Scanner/bitcoind RPC, the async
job dispatcher, the Blossom/Nostr network path, the C-prover) with no test hook — e.g. `recovery.rs`
production is 35.5%, `signature.rs` 52.5%, the rest being Scanner/network/prover paths. Their *correctness*
is covered by the green journey + the reorg matrix (§3.9) + the fail-closed gates; their *lines* are only
reachable via the live stack. Path to higher honest production coverage: (1) the remaining unit-testable
pure/DB branches; (2) live-stack fault injection for the integration error branches; (3) documented
`coverage(off)` for the provably-only-live defensive arms (never over-excluding unit-reachable code).

¹ integration-only measured against the *union* instrumented-line base (larger denominator than
Update 9's integ-only-base 47.8%); the combined figure is the honest, comparable metric.

Wave-2 unit gains: `v1/sdr.rs` 50.2 → **93.09%** (+49 tests), `v1/db_decrypt_index.rs` 20.5 → **99.79%** (+12).
Wave-3 unit gains (each behind an adversarial codex-reviewer pass): `v1/signature.rs` 60.1 → **74.85%**
(6 review-found error-branch gaps closed), `flow.rs` 18 → **65.33%** (admit-validators + a real production
bug fixed: `validate_send_request` reported "Missing signature" for an absent timestamp, against the
router.rs contract), `kernel/service.rs` 38 → **51.79%** (chain-less getters/builders/fail-closed reads;
async/DB paths deferred), `self_heal_tests.rs` (+2 error-branch tests).

**Latest measurement (2026-08-07, node HEAD `efb2781`, fault-injection journey stages):**

| Source | Coverage |
|---|---|
| Unit tests only | 69.0% (21226/30770) |
| Journey/integration only | 42.5% (11073/26024) |
| **Combined (unit ∪ integration, node-only, official lcov merge)** | **77.5%** (23833/30770) |

Progress vs. the prior measurement: integration-only 40.3% → 42.5% — the newly covered
bitcoind/postgres fault-recovery paths from journey stages `fault-bitcoind` and
`fault-postgres` (gated behind `ZKCOINS_JOURNEY_FAULTS=1`). 1721 unit tests green; journey
stages 1–9 plus both fault stages green.

Methodology note: only the **lines** figure above is meaningful. The lcov `functions` merge
figure is an artifact — it adds together the denominators of two distinct binaries (the
host unit-test binary and the Linux integration binary), which do not share a function set.

**The path to 100% is four layers** (largest combined-uncovered blocks first):
1. **Unit-testable pure logic** (sequential codex lanes; parallel lanes collide via the nested
   `node/node/src` path): `signature.rs` 79% (BIP-340 pure), `kernel/service.rs` 67%, `v1/attest.rs`
   82%, `v1/nostr/profile.rs` 83%, `self_heal.rs`, `reconstitute.rs`.
2. **Fault-injection integration tests** for the integration-dominated files the happy-path journey
   only partially hits: `job_dispatcher.rs` 57%, `v1/recovery.rs` 70%, `v1/receive.rs` 73%,
   `runtime.rs` 65%, `v1/incoming.rs` 67% (make regtest bitcoind / the DB fail on purpose).
3. **Journey extension** for paths neither unit nor journey reaches today: `flow.rs` **18%**,
   `v1/attest_verify.rs` **39%** (Scanner-backed `verify_balance_attestation` — the journey has no
   attest-verify leg).
4. **Documented `coverage(off)`** for provably-unreachable defensive code (same mechanism as the
   `shared` crate — never over-excluding covered lines).

Known-flaky historically: `router::tests::health_publisher_*` (esplora-dependent) — this wave's
1606-test run passed all 1606 (14 skipped), flaky tests included.
