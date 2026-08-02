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

A bare `cargo run -p node` is **not** startable: the binary fails closed without
Postgres migrations, kernel gRPC bind, chain-identity ops, Stage-3 v1 pins,
bitcoind RPC, a verified **BMF1** bootstrap manifest
(`ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH`), and related env. Use the local stack.

**Layout prerequisite:** `deploy/local-e2e/up.sh` and `compose.yaml` build the
public REST edge from the **sibling** checkout `../api` (`build.context: ../api`;
preflight dies if `../api/Dockerfile` is missing). A node-only clone is not
enough — clone `api` next to `node` under the same parent directory:

```bash
# Required sibling layout (compose build.context: ../api):
#   <parent>/
#     api/   ← https://github.com/zk-coins/api
#     node/  ← this repo
mkdir -p zk-coins && cd zk-coins
git clone https://github.com/zk-coins/api.git
git clone https://github.com/zk-coins/node.git
cd node
# Full unmocked stack (postgres, bitcoind regtest, nostr-relay, node, api):
# see deploy/local-e2e/README.md and docs/local-stack.md
cp deploy/local-e2e/env.example.sh deploy/local-e2e/env.local.sh
# Edit env.local.sh (PUBLISHER_KEY, bootstrap pubkey/priv, params id, …)
# Generate/sign BMF1 via up.sh / gen_bootstrap_manifest (required at boot)
bash -c 'set -a && source deploy/local-e2e/env.local.sh && set +a && ./deploy/local-e2e/up.sh'
```

Kernel gRPC listens on `KERNEL_GRPC_ADDR` (compose publishes **50051**). Residual
HTTP on `0.0.0.0:4242` is legacy and not the §7.8 surface — public REST is the
sibling **api** service.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust | nightly (pinned via `rust-toolchain`) | Required for Plonky2 (`feature(specialization)`) |
| Docker | any recent | `db_tests` spin up a `postgres:17` testcontainer; `deploy/local-e2e` full stack |
| Bitcoin node | bitcoind (regtest via compose) | Stage-3 NfLog scan + AggregateStateNullifierV3 publish (RPC + cookie) |

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

**Full hermetic suite.** CI's authoritative heavy gate (`test-and-coverage` in
`ci.yaml`) runs on **every non-draft PR** (no `ci:full` label required — see
[CI/CD](#cicd)). It drives `node` + `shared` under `cargo llvm-cov nextest`,
then the release-mode prover package and ignored prove flows. Locally, mirror
the hermetic `node` + `shared` selection with:

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

**Prove path outside `-p node -p shared`.** The recommended local command above
scopes only to the `node` and `shared` packages. Heavy prove-flow tests live
in `zkcoins-prover-plonky2` (`script-plonky2/`) and are not selected by that
run. Include the package explicitly when you need those flows:

```bash
cargo nextest run -p zkcoins-prover-plonky2 --release
```

A local run without `zkcoins-prover-plonky2` is **not** a complete verification
of the prove path. The CI heavy gate **does** run that package in release mode
after the llvm-cov nextest step (see `.github/workflows/ci.yaml`).

**`#[ignore]` prove flows.** Several multi-minute prove paths are marked
`#[ignore]` so the default hermetic nextest stays fast. The CI heavy gate
runs them explicitly with `--run-ignored ignored-only` (node + shared) and
also verifies live circuit digests against the committed file. Locally:

```bash
cargo nextest run -p node -p shared --all-features --release \
  --run-ignored ignored-only
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

Bitcoin tip advance on the node's hot path should be **event-driven** (bitcoind
block signals / ZMQ), not a silent sleep-loop. The legacy Esplora WebSocket
scanner modules are gone; Stage-3 scan is bitcoind RPC via `main.rs`
(`scan_to_tip`). The publisher still broadcasts commit and reveal back-to-back
without sleeping between them. (History: a 30-s tip-poll once gated mint/send
visibility by up to a full block-time — issue
[#84](https://github.com/zk-coins/node/issues/84).)

CI enforces this with a `grep` step in the `Lint & Build` job
(`.github/workflows/ci.yaml`) over the **active** hotpaths:

```bash
grep -rEn 'tokio::time::(sleep|sleep_until|interval)|std::thread::sleep' \
  node/src/main.rs node/src/publisher.rs \
  | grep -v 'scanner-polling-ok:'
```

Any match without a `scanner-polling-ok:` comment marker **on the same line**
fails the build. The marker is the documented per-line opt-out for genuinely
justified exceptions. Today the grandfathered case is the v1 `scan_to_tip` idle
backoff in `main.rs` (and related resume/retry backoffs): bitcoind block-signal
subscription is **follow-up work**; until then the sleep is an explicit,
named poll — never a silent one. The same line must explain why the sleep is
not an unacknowledged tip poll.

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
there is no silent fallback. The authoritative full set for a running stack is
`deploy/local-e2e/env.example.sh` and [`docs/local-stack.md`](./docs/local-stack.md).
A non-exhaustive subset:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | _(required)_ | Postgres connection string for the state layer. |
| `KERNEL_GRPC_ADDR` | _(required)_ | Kernel gRPC bind address (no default host/port). |
| `PUBLISHER_KEY` | _(required)_ | 32-byte hex private key for Taproot inscription publishing. Required on every network. **Never commit a real key**; generate via `openssl rand -hex 32`, source deployed values from a secret manager. |
| `USERNAME_DOMAIN` | _(required)_ | External hostname returned by residual `/api/info`. |
| `IS_MAINNET` | _(required)_ | Exact string `true` or `false`; any other value panics. |
| `ZKCOINS_V1_SHADOW` | _(required for Stage 3)_ | Must be `1` / on; Stage-3 binary refuses the legacy dual stack. |
| `ZKCOINS_NETWORK` / activation / circuit digests | _(required)_ | §3.6 pins — see `docs/local-stack.md`. |
| `ZKCOINS_V1_BITCOIND_RPC_URL` / cookie / wallet | _(required)_ | bitcoind RPC for scan + publish (not Esplora WS). |
| `ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH` | _(required when engine present)_ | Path to a verified **BMF1** artifact; `ChainIdentity` install fails closed without it. |
| `ESPLORA_URL` | residual boot pin | HTTP Esplora endpoint (legacy residual; Stage-3 scan is bitcoind). |
| `PROOFS_DIR` | `./proofs` | Directory for per-proof bincode files. |
| `ZKCOINS_SKIP_BOOTSTRAP_WARMUP` | `false` | When `1`/`true`, skip the Plonky2 prover warmup so `/health/ready` returns 200 immediately. Used by smoke tests; leave unset in production. |
| `RUST_LOG` | `info` | Log level. |

Do **not** use a minimal `export … && cargo run -p node` snippet as the
supported operator path — it will panic on missing pins/manifest. Use
`deploy/local-e2e/` (or an equivalent full env from `docs/local-stack.md`).

### Mainnet function restriction (SDR Phase B)

Stage-3 SDR Phase B seals `SelfDeliveryRecordV1` only when first-occurrence
inclusion + BIP-113 MTP are available. Until bitcoind supplies that path, the
node uses a **named provisional** stand-in (`tip_hash` + wall-clock) that is
**fail-closed on mainnet**:

- **Regtest / testnet:** provisional Inclusion/MTP may finalise Phase A → seal
  → `self_delivery` outbox.
- **Mainnet:** `finalize_due_phase_b_adapter` refuses provisional seal
  (`PROVISIONAL_MTP_MAINNET_REFUSED`), returns `Ok(0)`, leaves Phase-A rows in
  `awaiting_first_occurrence` (does **not** `mark_failed`). Operators will see
  open Phase-A rows and error logs until real MTP is wired — this is intentional,
  not a silent success.

See `node/src/v1/sdr.rs` (`provisional_inclusion_mtp_for_network`,
`finalize_due_phase_b_adapter`).

## Docker

A single-container `docker run` with only `ESPLORA_URL` / `USERNAME_DOMAIN` is
**not startable**: the binary fails closed without `DATABASE_URL`,
`PUBLISHER_KEY`, `KERNEL_GRPC_ADDR`, Stage-3 pins, bitcoind RPC, and a verified
BMF1 bootstrap manifest. Do not treat a minimal `docker run` as an operator path.

**Supported local stack** (postgres, bitcoind regtest, nostr-relay, node, api):

```bash
# Full env + compose — see deploy/local-e2e/README.md and docs/local-stack.md
cp deploy/local-e2e/env.example.sh deploy/local-e2e/env.local.sh
# Edit env.local.sh (required secrets/pins), then:
bash -c 'set -a && source deploy/local-e2e/env.local.sh && set +a && ./deploy/local-e2e/up.sh'
```

Or the workspace Compose path documented in `docs/local-stack.md`
(`docker compose up --build` after generating/signing BMF1 and filling env).

Image builds use nightly Rust via the workspace `rust-toolchain` — no Succinct
toolchain, no zkVM target. Stage-3 scan + publish use **bitcoind RPC** (not
Esplora WS); residual `ESPLORA_URL` is a boot pin only.

## Git workflow

### Branches

| Branch | Purpose | Deploy target |
|---|---|---|
| `staging` | Integration buffer — feature PRs land here first | none |
| `develop` | Active development, promoted from `staging` in batches | DEV node |
| `main` | Production releases, promoted from `develop` | PRD node |

- **Open feature PRs against `staging`** by default — it is the integration buffer where feature branches accumulate before being batched into a single `develop` promotion. (Repo-hygiene/cleanup PRs that target develop-only files may go directly to `develop`; note the reason in the PR body.)
- **`develop` and `main` are protected** — no direct pushes, no force-pushes, no deletions. `develop` is auto-PR'd from `staging` (`auto-release-pr-staging.yaml`); `main` is auto-PR'd from `develop` (`auto-release-pr.yaml`). Non-draft PRs always get the heavy CI gate (no label).
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
| `ci.yaml` — **Lint & Build** | Every non-draft PR (`pull_request` opened/synchronize/reopened/ready_for_review/…) | `cargo fmt --check`, clippy (MVP + all-features + program/prover), build, the no-polling grep over `node/src/main.rs` + `node/src/publisher.rs` (same-line `scanner-polling-ok:` opt-out). Fast GitHub-hosted tier. |
| `ci.yaml` — **Tests + Coverage Gate** | Every non-draft PR (same draft guard; **no** `ci:full` label) | Full `node` + `shared` nextest under `llvm-cov` on the self-hosted M3 Ultra pool, measured coverage floor (see `.github/coverage-baseline.md`), then release-mode `zkcoins-prover-plonky2`, ignored prove flows (`--run-ignored ignored-only`), and circuit-digest verify. |
| `deploy-dev.yaml` | Push to develop | Docker build (ARM64) → `zkcoins/node:beta` → DEV |
| `deploy-prd.yaml` | Push to main | Docker build (ARM64) → `zkcoins/node:latest` → PRD |
| `auto-release-pr-staging.yaml` | Push to staging | Promote PR (staging → develop) |
| `auto-release-pr.yaml` | Push to develop | Release PR (develop → main) |

**Draft PRs skip every `ci.yaml` job** — CI fires once the PR is marked
ready-for-review (or on synchronize of a ready PR). The heavy gate is the
default for non-draft PRs; there is no label opt-in. After push, watch CI until
green; never abandon a red run.

**No-polling gate (Lint & Build).** Matches the workflow step exactly:

```bash
grep -rEn 'tokio::time::(sleep|sleep_until|interval)|std::thread::sleep' \
  node/src/main.rs node/src/publisher.rs \
  | grep -v 'scanner-polling-ok:'
```

Any hit without a same-line `scanner-polling-ok:` comment fails the build
(see [No polling — events only](#no-polling--events-only)).

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application (frontend).
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation ([docs.zkcoins.com](https://docs.zkcoins.com)).
- [zk-coins/research](https://github.com/zk-coins/research) — Protocol research, design drafts, upstream repos, paper PDFs.
