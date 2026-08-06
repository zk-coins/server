# Coverage baseline (G16)

This file is the **measured** coverage floor for the `Tests + Coverage Gate`
job in `.github/workflows/ci.yaml`. It exists so the gate cannot silently
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

## CI trigger note (endgame — not yet applied)

Today the heavy gate still runs only when the `ci:full` label is present
(or on push paths that already carry it). Expanding it to every
non-draft PR (instead of label-gated only) belongs to the **CI endgame**
when the workflow is un-paused; do not flip that condition while the
workflow is still `workflow_dispatch`-only / PR-trigger-commented, or a
60–90 min gate would fire on every PR against paused runners. Recorded
here so the un-pause PR cannot claim the floor was fixed without also
planning the trigger expansion.

## Measurement record

| Field | Value |
|---|---|
| Date | 2026-08-02 |
| Branch | `feat/v1-spec-rebuild` |
| Commit | `18131ebeb4f0e717f2baba6856b0680ed3637fba` (`18131eb`) |
| Scope | `-p node -p shared --all-features` |
| Ignore regex | `_tests\.rs$\|test_db\.rs$\|bin/.*\.rs$\|main\.rs$\|lib\.rs$\|program-plonky2/\|script-plonky2/` |
| Nextest filter | `not binary(api_remote)` |

## CI floor (what the gate enforces)

| Metric | Measured | CI `--fail-under-*` (integer floor) |
|---|---|---|
| **Lines** | **77.28%** (39142 / 50651) | **77** |
| **Functions** | **77.82%** (3038 / 3904) | **77** |

A regression under 77 % lines or functions fails the gate. There is no
100 % fiction: the integers sit just under the honest measurement.

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

## Weakest 25 files (from measurement)

Generated from the measurement above. Closing these is follow-up; the
gate only prevents regression below the floor.

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
`ci.yaml` and update the tables above in the same PR. Never lower them
to greenwash a drop.

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
