# Contributing to zkCoins Node

This guide covers how to set up, build, test, and ship changes to the zkCoins
backend. It is intentionally limited to **developer setup, coding standards, and
the PR flow** — protocol design, roadmap, and migration research live in the
[docs site](https://docs.zkcoins.com) and the
[research repo](https://github.com/zk-coins/research).

## Trust model — run your own node

zkCoins follows the **Bitcoin full-node model: your wallet trusts _your_ node, exactly as a Bitcoin wallet trusts your own `bitcoind`.** "Trusted node" means _your_ node — never a third party. Running your own node is the trustless, private path, and it is the model the whole system is designed around. The node↔wallet split is packaging (a heavy validator process vs. a thin key-holder), not a trust boundary. The only line the node never crosses is the wallet's private key — that stays in the wallet.

This is a hard project rule. It shapes every design and implementation decision:

- **Self-hosting gives you trustlessness and privacy at once.** Your own node verifies your transactions and sees your plaintext — and _you_ are the operator, so nothing leaks. The wallet must always be able to switch to a different node by changing a single configuration value.
- **Using someone else's node is a trade-off you choose, not a flaw.** A public operator can never steal, forge, or double-spend your coins — that is enforced cryptographically (recursive proofs + Bitcoin-anchored nullifiers). What a foreign operator can see is your privacy, and it can affect liveness — the same spectrum as using an Electrum/SPV server instead of your own Bitcoin node.
- **The thin wallet and SDK are not a compromise.** No anti-node logic: no client-side proof verification, no scan loops, no view-key / spend-key splits, no consistency checks against a second node, no "node integrity" indicators in the UI. Trustlessness comes from running your own node, not from bolting verification onto a thin client. Anything that exists to reduce trust in the node belongs node-side — or the answer is self-hosting.
- **The node is built so that self-hosting is easy.** Single container, documented configuration, deterministic state, no operator-specific dependencies.
- **The SDK and wallet stay thin.** They expose seed + address + the small set of operations every familiar wallet SDK exposes. Integrators (Cake Wallet, LayerZ, BlueWallet, …) should be able to wire zkCoins up with the same effort as adding a second Bitcoin-family chain.

When in doubt about whether a feature belongs in the wallet, SDK, or node: if it exists to reduce trust in the node, build it node-side, or document self-hosting as the answer. This rule is mirrored verbatim in [`zk-coins/node`](https://github.com/zk-coins/node/blob/develop/CONTRIBUTING.md), [`zk-coins/sdk`](https://github.com/zk-coins/sdk/blob/develop/CONTRIBUTING.md), [`zk-coins/app`](https://github.com/zk-coins/app/blob/develop/CONTRIBUTING.md), and [`zk-coins/docs`](https://github.com/zk-coins/docs/blob/develop/CONTRIBUTING.md).

## Quick Start

```bash
git clone https://github.com/zk-coins/node.git
cd node
USERNAME_DOMAIN=test.zkcoins.local cargo run -p node
# Node starts on http://0.0.0.0:4242
```

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust | nightly (pinned via `rust-toolchain`) | Required for Plonky2 (`feature(specialization)`) |
| Docker | any recent | `db_tests` spin up a `postgres:17` testcontainer |
| Bitcoin node | — | Blockchain scanning (or use an Esplora-compatible API) |

## Setup

Enable the repo's pre-push hook. It runs `cargo fmt --check`, `cargo clippy`
(all three feature scopes), and `cargo check --workspace --all-features` —
fast enough to stay out of the way (< 30 s warm) while catching lint and type
regressions before they reach CI.

```bash
git config core.hooksPath .githooks
```

The authoritative test + coverage gate runs in CI on a self-hosted M3 Ultra
runner pool, not in this hook (see [CI/CD](#cicd)). You can bypass the hook with
`git push --no-verify` in genuine emergencies — CI is the real gate.

### Local development with Postgres

The state layer expects a PostgreSQL instance reachable at `DATABASE_URL`. For
ad-hoc work:

```bash
docker run --name zkcoins-pg -e POSTGRES_PASSWORD=dev -p 5432:5432 -d postgres:17
export DATABASE_URL=postgres://postgres:dev@localhost:5432/postgres

# Apply migrations:
cargo install sqlx-cli --no-default-features --features rustls,postgres
cd node && sqlx migrate run
```

The `db_tests` spin up their own `postgres:17` container via
`testcontainers-modules`; each test gets a UUID-named schema inside one shared,
reused container. The schema lives in `node/migrations/*.sql` and is
forward-only (no `down` migrations in the MVP).

```bash
cargo test -p node db -- --test-threads=8
```

That command is a **subset** — useful and correct for DB work. It is not the
full `node` + `shared` suite. The line for the full suite is below.

### Running tests

**Full hermetic suite.** CI's authoritative gate
(`cargo llvm-cov nextest` under the `ci:full` label — see [CI/CD](#cicd))
drives `node` + `shared` through nextest, not plain `cargo test`. Locally,
mirror that selection with:

```bash
cargo nextest run -p node -p shared --all-features --test-threads 8 -E 'not binary(api_remote)'
```

`-E 'not binary(api_remote)'` drops the `api_remote` integration target
(`node/tests/api_remote.rs`). That suite talks to the live DEV node and does
not belong in a hermetic run; the CI workflow excludes it with the same
expression for the same reason (post-deploy coverage lives in
`deploy-dev.yaml` / `deploy-prd.yaml`).

`cargo nextest` is not a built-in Cargo subcommand. Install it the way the
self-hosted CI runners do, or from crates.io:

```bash
brew install cargo-nextest
# or:
cargo install cargo-nextest --locked
```

**Why nextest is required here — not a preference.**
`stack-policy` records the stack mode as a **process-wide, monotonic claim**
(`PROCESS_STACK_MODE` via `set_process_stack_mode`): a process must not
dual-boot Legacy and V1, and a conflicting re-set **panics on purpose**. The
test-only reset (`clear_process_stack_mode_for_test`) is gated on
`#[cfg(test)]` of the **defining** crate, so dependents such as `node` cannot
clear the claim from their own test binaries.

Under plain `cargo test`, every case shares one process. A Legacy case and a
V1 case collide; the mutex poisons (`PoisonError`), and every later test in
that process fails — a cascade from a single intentional panic, not a broken
tree. `cargo nextest` gives each test its own process, so the collision
cannot occur. That is why the CI gate uses nextest rather than `cargo test`.
If you run `cargo test -p node -p shared --all-features` and see a large red
swath, read it as this process-wide claim issue first.

**When `cargo test` is still the right tool.** Targeted subsets remain valid
and preferred for day-to-day work, for example the DB filter above or a
single integration binary:

```bash
cargo test -p node db -- --test-threads=8
cargo test -p node --test openapi_smoke
```

The boundary is stack modes: as soon as a run includes cases that claim
**both** Legacy and V1, it needs nextest (process-per-test isolation).
Single-mode or non-claiming subsets can stay on `cargo test`.

**Prove path outside `-p node -p shared`.** The recommended command above
scopes only to the `node` and `shared` packages. Heavy prove-flow tests live
in `zkcoins-prover-plonky2` (`script-plonky2/`) and are not selected by that
run. Include the package explicitly when you need those flows:

```bash
cargo nextest run -p zkcoins-prover-plonky2
```

A run without `zkcoins-prover-plonky2` is **not** a complete verification of
the prove path. The CI gate matches the same package scope
(`cargo llvm-cov nextest … -p node -p shared`); it does not execute the
prover package's prove-flow suite.

**`#[ignore]` tests in the `node` + `shared` scope.** Four cases in `node`
are marked `#[ignore]`. They do not run under the recommended command above
and do not run in the CI gate today:

- `node v1::receive::tests::concurrent_append_after_broadcast_still_reported_success`
- `node v1::receive::tests::concurrent_scanner_append_during_prove_still_commits`
- `node v1::receive::tests::production_path_receive_with_genuine_prove_via_verify_and_begin`
- `node v1::self_heal::unit_tests::resolve_v1_live_digest_via_real_prover_bridge_refuses_pin_mismatch`

Run them with nextest's ignored-test controls (`--run-ignored all` includes
them with the rest of the suite; `--run-ignored only` runs just the ignored
set):

```bash
cargo nextest run -p node -p shared --all-features --test-threads 8 \
  -E 'not binary(api_remote)' --run-ignored all
```

## Code style

### Rust

- **Edition 2021**, `opt-level = 3` for dev (heavy crypto).
- **`cargo fmt`** before every commit.
- **`cargo clippy`** — treat warnings as errors.
- **No `unwrap()` in production paths** — use `?` or `expect("descriptive message")`.
- **No `println!`** — use `tracing::info!`, `tracing::warn!`, etc.

### Naming

| Item | Convention | Example |
|---|---|---|
| Crate | kebab-case | `zkcoins-program-plonky2` |
| Module | snake_case | `account_node` |
| Struct | PascalCase | `AccountState`, `CoinProof` |
| Function | snake_case | `process_block`, `send_coins` |
| Constant | SCREAMING_SNAKE | `ACCOUNT_NODE_ADDR` |

### Error handling

```rust
// Good — propagate with context
let block = fetch_block(hash).map_err(|e| anyhow!("Failed to fetch block {}: {}", hash, e))?;

// Bad — panic in production
let block = fetch_block(hash).unwrap();
```

### Dependencies

- Workspace dependencies in root `Cargo.toml`; individual crates reference `{ workspace = true }`.
- Pin exact versions for security-critical crates (`bitcoin`, `sha2`).
- `plonky2 = "1.1.0"` from crates.io; no `[patch.crates-io]` entries.

### No polling — events only

Bitcoin / Esplora signals on the node's hot path are **subscribed to, never
polled**. The scanner consumes block events from the Esplora-compatible
WebSocket stream (`scanner_ws.rs`, `ESPLORA_WS_URL`); the publisher broadcasts
commit and reveal transactions back-to-back and never sleeps or polls between
them. (History: a 30-s tip-poll once gated `/api/mint` and `/api/send`
visibility by up to a full block-time — issue [#84](https://github.com/zk-coins/node/issues/84).)

CI enforces this with a `grep` step in the `Lint & Build` job
(`.github/workflows/ci.yaml`):

```bash
grep -rEn 'tokio::time::(sleep|sleep_until|interval)|std::thread::sleep' \
  node/src/scanner.rs node/src/scanner_runtime.rs node/src/scanner_ws.rs \
  node/src/scanner_ws_parse.rs node/src/publisher.rs \
  | grep -v 'scanner-polling-ok:'
```

Any match without a `scanner-polling-ok:` comment marker on the same line fails
the build. The marker is the documented per-line opt-out for genuinely justified
exceptions (today: the WS-reconnect backoff in `scanner_ws` and the bounded
HTTP-retry sleep in `scanner_runtime`); the same line must carry a comment
explaining why this particular sleep is not a chain-tip poll.

### Hardware target

The node targets a single **Mac Studio M3 Ultra** (96 GB unified RAM): all
on-box compute (P/E cores, Apple GPU via Metal, Neural Engine, AMX), **no
external GPU/CUDA, no cloud proving services**. Performance budget: warm proof
≤ 5 s (target ≤ 1 s), cold-start ≤ 30 s, memory peak < 64 GB. If a design
overshoots the budget, the design changes — we do not add external hardware.

## Project structure

```
node/
├── node/                  # Axum REST API (router, account_node, state, scanner, publisher)
├── shared/                # Shared types (Commitment, Invoice, ClientAccount)
├── program-plonky2/       # Plonky2 + Poseidon cyclic-recursion state-transition circuit
│   └── CONTRIBUTING.md    # Toolchain/build/test/coverage handoff for the circuit crate
├── script-plonky2/        # Host-side Plonky2 prover wrapper (zkcoins-prover-plonky2)
├── Cargo.toml             # Workspace root (nightly toolchain)
├── Dockerfile             # Multi-stage Rust build (linux/arm64, FEATURES build-arg)
└── rust-toolchain         # Pinned nightly date
```

When working inside `program-plonky2/`, read
[`program-plonky2/CONTRIBUTING.md`](./program-plonky2/CONTRIBUTING.md) for the
crate's toolchain, coverage gate, and gadget-authoring pattern. Protocol-level
context lives in the spec at [docs.zkcoins.com/specification](https://docs.zkcoins.com/specification).

## REST API & OpenAPI

The HTTP surface is documented by an OpenAPI 3.x spec **generated at compile
time** from `#[utoipa::path]` annotations and `#[derive(ToSchema)]` impls — there
is no separately maintained YAML/JSON, so the wire contract and the docs cannot
drift. The spec is served at `GET /openapi.json` and rendered with bundled
Swagger UI at `GET /docs` (assets vendored, zero-CDN).

Adding an endpoint:

1. Annotate the handler in `node/src/router.rs` with `#[utoipa::path(...)]`; reuse
   the sibling endpoints' `tag`; enumerate every status code and bind it to a
   response schema; bump visibility to `pub(crate)`.
2. Derive `ToSchema` on every request/response struct. For foreign types
   (`bitcoin::secp256k1::PublicKey`, …) override at the use site with
   `#[schema(value_type = String, example = "02a34b…")]`.
3. Register the handler under `paths(...)` and new schemas under
   `components(schemas(...))` in `node/src/openapi.rs`.
4. Extend the network-free smoke test in `node/tests/openapi_smoke.rs`
   (`spec_lists_every_always_on_route`, `spec_registers_critical_schemas`) — it
   runs on every PR and fails fast on wire-contract drift.

## Environment variables

The node reads configuration **exclusively from environment variables** (no
`.env` is loaded). Required variables panic the bootstrap on startup if unset —
there is no silent fallback.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | _(required)_ | Postgres connection string for the state layer. |
| `PUBLISHER_KEY` | _(required)_ | 32-byte hex private key for Taproot inscription publishing. Required on every network. **Never commit a real key**; generate via `openssl rand -hex 32`, source deployed values from a secret manager. |
| `USERNAME_DOMAIN` | _(required)_ | External hostname returned by `/api/info`. |
| `IS_MAINNET` | _(required)_ | Exact string `true` or `false`; any other value panics. |
| `ESPLORA_URL` | _(required)_ | HTTP Esplora endpoint (electrs or compatible). |
| `ESPLORA_WS_URL` | _(required)_ | Esplora-compatible WebSocket endpoint consumed by `scanner_ws` (issue #84). |
| `NETWORK_NAME` | derived | Human-readable name returned by `/api/info`. Cosmetic. |
| `PROOFS_DIR` | `./proofs` | Directory for per-proof bincode files. |
| `ZKCOINS_SKIP_BOOTSTRAP_WARMUP` | `false` | When `1`/`true`, skip the Plonky2 prover warmup so `/health/ready` returns 200 immediately. Used by smoke tests; leave unset in production. |
| `RUST_LOG` | `info` | Log level. |

```bash
export DATABASE_URL="postgresql://postgres:dev@localhost:5432/postgres"
export PUBLISHER_KEY="$(openssl rand -hex 32)"
export USERNAME_DOMAIN="test.zkcoins.local"
export IS_MAINNET="false"
export ESPLORA_URL="http://localhost:3000"
export ESPLORA_WS_URL="ws://localhost:8999/api/v1/ws"
cargo run -p node
```

## Docker

```bash
docker build -t zkcoins/node .
docker run -p 4242:4242 --network bitcoin \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  -e USERNAME_DOMAIN=zkcoins.app \
  zkcoins/node
```

Docker builds use nightly Rust auto-installed via the workspace `rust-toolchain`
— no Succinct toolchain, no zkVM target. The node connects to Bitcoin Core with
an Esplora-compatible indexer (electrs) over the shared Docker network `bitcoin`;
the underlying bitcoind needs `txindex=1`, `rest=1`, `server=1`.

## Git workflow

### Branches

| Branch | Purpose | Deploy target |
|---|---|---|
| `staging` | Integration buffer — feature PRs land here first | none |
| `develop` | Active development, promoted from `staging` in batches | DEV node |
| `main` | Production releases, promoted from `develop` | PRD node |

- **Open feature PRs against `staging`** by default — it is the integration buffer where feature branches accumulate before being batched into a single `develop` promotion. (Repo-hygiene/cleanup PRs that target develop-only files may go directly to `develop`; note the reason in the PR body.)
- **`develop` and `main` are protected** — no direct pushes, no force-pushes, no deletions. `develop` is auto-PR'd from `staging` (`auto-release-pr-staging.yaml`, `ci:full` applied); `main` is auto-PR'd from `develop` (`auto-release-pr.yaml`).
- **Maintainers merge PRs; agents open them as drafts.** Never force-push, never amend, never `--no-verify` on a real change.

### Commit messages

English, concise, *what* not *how*:

```
# Good
Bind to 0.0.0.0 instead of 127.0.0.1 for Docker access
Decouple node from SP1: optional zkvm feature, stub prover

# Bad
fix build
wip
```

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `ci.yaml` — **Lint & Build** | Any ready PR, push to develop | `cargo fmt --check`, clippy (MVP + all-features + program), build, the no-polling grep. Fast GitHub-hosted tier, no label needed. |
| `ci.yaml` — **Tests + Coverage Gate** | Ready PR with `ci:full` label, push to develop | Full `node` + `shared` nextest suite under `llvm-cov` on the self-hosted M3 Ultra pool, 100% line + function gate. |
| `deploy-dev.yaml` | Push to develop | Docker build (ARM64) → `zkcoins/node:beta` → DEV |
| `deploy-prd.yaml` | Push to main | Docker build (ARM64) → `zkcoins/node:latest` → PRD |
| `auto-release-pr-staging.yaml` | Push to staging | Promote PR (staging → develop), `ci:full` |
| `auto-release-pr.yaml` | Push to develop | Release PR (develop → main), `ci:full` |

**Draft PRs skip every `ci.yaml` job** — CI fires once the PR is marked
ready-for-review. Apply the `ci:full` label when the PR is ready to run against
the authoritative gate. After push, watch CI until green; never abandon a red run.

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application (frontend).
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation ([docs.zkcoins.com](https://docs.zkcoins.com)).
- [zk-coins/research](https://github.com/zk-coins/research) — Protocol research, design drafts, upstream repos, paper PDFs.
