# Contributing to `program-plonky2/`

Operational handoff: how to build, test, lint, and not blow up the
machine. This crate is **excluded from the parent workspace** and
carries its own toolchain pin.

> **Fresh contributor?** Read [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
> first for the trust model, coding standards, and PR flow. This file is the
> operational *how* for the circuit crate, but the rules in the repo-root
> CONTRIBUTING constrain what you may change here.
>
> **Design-doc references.** Comments in this crate cite `SPEC.md` (the
> circuit/single-asset spec) and `MIGRATION_RESEARCH.md`/`ROADMAP.md`. Those
> documents were archived out of the node repo into
> [`zk-coins/research` → `zkcoins-design/`](https://github.com/zk-coins/research/tree/develop/zkcoins-design)
> (verbatim, same section numbers); the published protocol spec and roadmap live
> at [docs.zkcoins.com/specification](https://docs.zkcoins.com/specification) and
> [docs.zkcoins.com/roadmap](https://docs.zkcoins.com/roadmap).

## Toolchain

Plonky2 1.1.0 requires nightly Rust because `plonky2_field` uses
`#![feature(specialization)]`. After PR [#17](https://github.com/zk-coins/node/pull/17)
the entire workspace was unified to nightly via a single root
`rust-toolchain` file; the standalone `program-plonky2/rust-toolchain.toml`
was removed. This crate is now a regular workspace member
(`members = ["program-plonky2", ...]` in the root `Cargo.toml`)
rather than the excluded standalone it was during the migration. Cargo
commands work from the workspace root or from inside `program-plonky2/`.

## First-time setup

```bash
rustup install nightly-2025-04-15 --profile minimal
```

The pin is in `program-plonky2/rust-toolchain.toml`. Bumping the
nightly date is fine but verify Plonky2 still builds and tests pass
before committing.

## Build / test / lint

All commands run from `program-plonky2/` (NOT from the workspace root):

```bash
cd program-plonky2

# Build
cargo build

# Run all tests serially (circuit tests are memory-heavy)
cargo test -- --test-threads=1

# Run just the off-circuit / non-circuit tests (fast)
cargo test hash
cargo test merkle
cargo test types
cargo test inputs

# Run just the circuit gadget tests (slow — each ~10 s circuit build)
cargo test circuit -- --test-threads=1

# Format check (used by CI gate)
cargo fmt --check

# Lint (used by CI gate). MUST be clean before pushing.
cargo clippy --all-targets -- -D warnings

# Coverage check (will become a CI gate alongside the existing node gate).
# Per ROADMAP "Definition of MVP", 100% coverage on the activated surface
# is non-negotiable. Run this before opening any PR that adds new code:
cargo +nightly-2025-04-15 install cargo-llvm-cov   # one-time
cargo llvm-cov --fail-under-lines 100 -- --test-threads=1
```

## Coverage gate

Same standard as `program/` and `node/` in the parent workspace:
**100% line coverage on the activated surface**. The "activated surface"
is everything compiled in by default features — i.e. the entire crate at
the moment, since `program-plonky2` has no feature gates yet.

Acceptable exclusions:

- Genuinely-unreachable defensive code → `#[cfg(...)]` or
  `#[allow(dead_code)]` with a written reason; auditor must verify the
  exclusion is necessary, not lazy.
- Code that requires external services (live Bitcoin node) → mark with
  `#[cfg(feature = "integration-tests")]` and the integration tests run
  separately in step 9's e2e plan. Note on hardware: the M3 Ultra has
  its integrated GPU (Metal) available on the box, but Plonky2 currently
  ships only CPU and CUDA backends. So in practice proving runs on CPU.
  External NVIDIA / CUDA hardware and external cloud provers are out of
  scope regardless.

NOT acceptable: "I'll add tests later", "this is just MVP scaffolding",
"the next gadget will cover it". MVP includes coverage; see ROADMAP
"Definition of MVP".

## Test runtime characteristics

| Module                      | Speed                | Why                                            |
| --------------------------- | -------------------- | ---------------------------------------------- |
| `hash::tests`               | <1 s                 | Just Poseidon hashes; no circuit.              |
| `merkle::*`                 | <2 s                 | Off-circuit SMT/MMR operations.                |
| `types::tests`              | <1 s                 | Pure data shapes; one Poseidon per test.       |
| `inputs::tests`             | <2 s                 | Same plus a small e2e SMT+MMR roundtrip.       |
| `circuit::mmr`, `circuit::smt` | **5–30 s per test** | Builds a small (no cyclic-recursion) circuit and runs one prove + verify. |
| `circuit::main` cyclic positive | **3–15 min per test** | Builds the full monolithic state-transition circuit (`INNER_PAD_BITS = 14`, `1 << 14 = 16 384`-gate inner shape) and runs a real cyclic-recursive prove + verify. Time scales with the number of active in-coin / out-coin slots. |
| `circuit::main` cyclic negative | **2–10 min per test** | Same build cost, but the prover fails early at the unsatisfied constraint instead of generating a full proof. |
| `circuit::main` panic guards | **~30 s per test** | Just `build_circuit()` then immediate `should_panic`. |

A full circuit-test sweep at production parameters (`MAX_IN_COINS = MAX_OUT_COINS = 8`)
runs ~22 cyclic tests at 3–15 min each. Serial runtime is multiple hours;
parallel runtime is bounded by CPU + RAM (each test holds ~2 GB live).

**Always use `--test-threads=1` for circuit tests on a memory-constrained
machine.** See `feedback_cleanup_test_binaries.md` in `~/.claude/.../memory/`
for the orphan-binary issue: if you abort a circuit test, the prover
process can leak ~30 GB of swap-resident memory and survive for hours.

When iterating on `circuit::main`, prefer running a single test by name
rather than the whole module (`cargo test stage_5d_initial_with_one_active_in_coin`).
The build-cache hits across runs make the second invocation near-instant
for cargo itself; the prove is what dominates.

```bash
# After interrupted test runs:
pgrep -f "target/debug/deps/zkcoins_program_plonky2"
# If any output: kill -TERM <PID>
```

## Project layout

```
program-plonky2/
├── Cargo.toml            # plonky2 = "1.1.0", anyhow only
├── Cargo.lock            # commit it — lock transitive deps
├── rust-toolchain.toml   # nightly-2025-04-15
└── src/
    ├── lib.rs            # Prelude: F, C, D type aliases
    ├── hash.rs           # Poseidon HashDigest + byte conversions
    ├── types.rs          # AccountState, Coin, ProofData
    ├── inputs.rs         # ProgramInputs, CommitmentMerkleProofs, ProofType
    ├── merkle/
    │   ├── mod.rs
    │   ├── sparse_merkle_tree.rs    # off-circuit Poseidon SMT
    │   └── merkle_mountain_range.rs # off-circuit Poseidon MMR
    └── circuit/
        ├── mod.rs
        ├── util.rs                    # swap_if shared helper (pub(crate))
        ├── mmr.rs                     # in-circuit MMR inclusion gadget
        ├── smt.rs                     # in-circuit SMT inclusion + non-inclusion + insert
        ├── main.rs                    # monolithic StateTransitionCircuit (cyclic recursion)
        ├── source_aggregator.rs       # Stage 5d-next-5 per-slot source aggregator (non-cyclic)
        └── recursion_shape_probe.rs   # diagnostic probes for Plonky2 1.1.0 shape blockers
```

## Adding a new gadget

The established pattern (see `circuit/mmr.rs` and `circuit/smt.rs`):

1. Mirror an off-circuit verifier method (e.g. `MMRProof::verify`).
2. Take `&mut CircuitBuilder<F, D>` plus typed targets in, no returns.
3. Use `builder.connect_hashes(...)` to assert the final equality.
4. Use `super::util::swap_if` for conditional hash-output swapping.
5. For bit decomposition, use `key_bits_msb_first` from `smt.rs` (MSB
   ordering matches `crate::merkle::sparse_merkle_tree::get_bit` on the
   big-endian byte serialisation — this matters for cross-checking
   against off-circuit code).
6. Write at least one positive test (round-trip through prove+verify)
   and one negative test (assert `data.prove(pw).is_err()` on tampered
   witness).

## Pinning + version philosophy

- `plonky2 = "1.1.0"` is the latest crates.io release. BitVM's reference
  was on `0.2.0` which is several majors stale; we tested that 1.1.0
  still works with the nightly date pinned here.
- Don't switch to plonky2 from git or a fork without a recorded reason
  in `MIGRATION_RESEARCH.md`. The crate is intentionally upstream-mature.
- `anyhow` is the only non-plonky2 runtime dep — keep it that way until
  there's a concrete need.

## CI integration

The root workspace's CI (`.github/workflows/ci.yaml`) clippies this
crate's libs as part of `Lint & Build` (the only required check on
`develop` per PR [#48](https://github.com/zk-coins/node/pull/48)).
The cyclic-recursion test sweep at production parameters (~22 cyclic
tests × 3–15 min each) is NOT in CI — `Node + Shared Tests` runs
`-p node -p shared` only. Decision on whether/how to gate the sweep
in CI is tracked in [issue #50](https://github.com/zk-coins/node/issues/50);
until that lands, contributors run the sweep locally before opening /
updating a PR that touches this crate (see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) § "Setup").

## Common pitfalls

See `MIGRATION_RESEARCH.md` § "Lessons Learned" for the gotchas
discovered during this migration. Most relevant for hacking on this
crate:

- Don't seed `DEFAULT_HASHES[TREE_DEPTH]` with `ZERO_HASH` — Poseidon's
  zero-state behaviour causes a structural collision. Use a domain-
  separated `hash_bytes(b"...")` instead. The SMT module already does
  this; the regression test `leaf_hash_never_collides_with_defaults`
  pins the invariant.
- `pw.set_target(target, value)` returns `Result` in plonky2 1.x. The
  unwrap-or-handle is required; clippy `unused_must_use` catches it.
- Field-element packing for byte inputs: pack 7 bytes per Goldilocks
  element (LE), never 8. 8-byte chunks can exceed the modulus
  (`from_canonical_u64` will panic in debug).
