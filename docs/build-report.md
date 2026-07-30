# Build report — circuit builds, end-to-end proof, and circuit test suite

Measurement report for the Implementation Mandate §4 artefact. Numbers below
are single-run wall-clock and peak-RSS observations on one host. They are not
benchmarks, not means, and not capacity claims for other machines.

## Machine and tools

| | |
|---|---|
| Host | Apple M5 Max, 18 cores, 128 GB RAM |
| rustc | `1.98.0-nightly (c1b22f44c 2026-06-17)` |
| Toolchain pin | `rust-toolchain` → `nightly-2026-06-18` |
| Backend | `plonky2 = "1.1.0"` (crates.io pin) |
| Profile | `--release` |
| Measured revisions | `879eb54` (circuit builds and suite), `2a97412` (end-to-end proof) |

## Circuit metrics

Identical across mainnet, testnet, and regtest:

| Circuit | Gates | `degree_bits` |
|---|---|---|
| `C` (compliance) | 1 382 481 | 21 |
| `C_balance` | 191 268 | 18 |

## Run 1 — six real circuit builds

`C` and `C_balance` × mainnet / testnet / regtest. Digests checked against the
pinned file `script-plonky2/tests/generated_circuit_digests.txt`.

| | |
|---|---|
| Wall clock | 9 544.59 s (2 h 39 min) |
| Peak RSS | 94 856 232 960 B ≈ 88.3 GiB |
| Result | all six `circuit_digest` values match the pinned file |

## Run 2 — real end-to-end proof

mint + send + receive through the prover bridge, one process,
`--test-threads=1`.

| | |
|---|---|
| Test time | 3 083.41 s |
| Wall clock | 3 130.96 s (52 min) |
| Peak RSS | 95 429 853 184 B ≈ 88.9 GiB |

## Run 3 — circuit test suite

`program-plonky2`, 166 tests: all compliance-clause negative cases, the
clause-10 receive, `C_balance` with eight negative cases, and the NfLog
gadget boundary suite over `k = 0…63`.

| | |
|---|---|
| Result | 166 passed, 0 failed |
| Wall clock | 10 828.87 s (3 h 01 min) |
| Peak RSS | 99 310 649 344 B ≈ 92.5 GiB |

## Memory is the hard limit

Peak RSS on the suite is 92.5 GiB of 128 GB — 72 % of this machine’s RAM. Time
is large but secondary: a host with less memory must lower test parallelism or
the process will thrash or be killed. The suite peak (92.5 GiB) exceeds the
circuit-build peak (88.3 GiB) and the end-to-end peak (88.9 GiB).

## `cargo test`, not `cargo nextest`

The suite shares the circuit through a process-wide `OnceLock`. `cargo nextest`
starts one process per test and therefore rebuilds the 1.4-million-gate
circuit for every test. That is not a style preference: it is the difference
between about three hours and a run that is effectively unusable. Use
`cargo test` with an explicit `--test-threads` for this crate.

## First execution of the circuit suite

Until these runs, the circuit suite had not been executed — neither locally nor
in CI. CI gates only run `-p node -p shared`. The numbers above are therefore
the first observed wall-clock and RSS figures for this suite on this tree, not
a confirmation of prior practice.

## What this report does not contain

- Proof size in bytes
- Verification time
- Memory of a single proof isolated from circuit build
- Distributions: only single measurements; no repeats, no variance, no
  percentiles

Absence of those figures does not mean they are small or free.

## Reproduction

```bash
# Run 1 — circuit builds and digest check
cargo test --release -p zkcoins-prover-plonky2 \
  --test generated_circuit_digests_test -- --ignored --nocapture

# Run 2 — end-to-end proof
cargo test --release -p zkcoins-prover-plonky2 --lib \
  prover_bridge_real_end_to_end -- --ignored --nocapture --test-threads=1

# Run 3 — circuit test suite
cargo test --release -p zkcoins-program-plonky2 -- --test-threads=8
```

Re-running on another host or revision will produce different wall-clock and
RSS values; only the digest equality check is content-defined against the
pinned file.
