# zkCoins node

[![Docker Image Version](https://img.shields.io/docker/v/zkcoins/node/latest?logo=docker&label=zkcoins%2Fnode&color=2496ED)](https://hub.docker.com/r/zkcoins/node)
[![Docker Pulls](https://img.shields.io/docker/pulls/zkcoins/node?logo=docker&color=2496ED)](https://hub.docker.com/r/zkcoins/node)

**Private Bitcoin payments via Shielded CSV** — no new chain, no token, no consensus change, no trusted operator. Only Bitcoin, zero-knowledge proofs, and the user's own keys.

The **trustless kernel** of zkCoins: Bitcoin chain scanner, nullifier accumulator, recursive-proof verifier and prover, data store, and the publisher/broadcaster — built in Rust (Axum, Plonky2 + Poseidon-Goldilocks).

> Full system docs: **[docs.zkcoins.com](https://docs.zkcoins.com)** · Specification: **[docs.zkcoins.com/specification](https://docs.zkcoins.com/specification)**

## What zkCoins is

zkCoins lets you send value on Bitcoin without anyone seeing the amount, the asset, who paid, or who received. Bitcoin stores only opaque markers that a spend happened — not the coin's contents, which travel privately between sender and receiver as a small encrypted bundle. Double-spend protection is the chain's job; your seed derives every key, your wallet is the only thing that can spend, any node can serve you, and you verify everything against Bitcoin yourself. Built on the zkCoins concept (Robin Linus) and the Shielded CSV construction (Jonas Nick, Liam Eagen, Robin Linus).

## The system, end to end

| Layer | What it is | Repo |
|---|---|---|
| **App · Explorer** | end-user wallet (LNURL receive) · public explorer web-app | [`zk-coins/app`](https://github.com/zk-coins/app) · `zk-coins/explorer` *(planned)* |
| **SDK** | thin TypeScript client — on-device keys, signing, node/API calls | [`zk-coins/sdk`](https://github.com/zk-coins/sdk) |
| **zkCoins API** | public REST + LNURL, hosted-wallet service (optional) | currently in **`zk-coins/node`**; a separate API layer is the target design |
| **zkCoins node** | trustless kernel — scan · accumulator · verify · prove · store · publisher | **[`zk-coins/node`](https://github.com/zk-coins/node)** ← this repo |
| **bitcoind · Nostr relay** | Bitcoin L1 settlement and ordering · off-chain transport and data availability | upstream (own or external) |

Supporting repos: [`zk-coins/research`](https://github.com/zk-coins/research), [`zk-coins/plonky2`](https://github.com/zk-coins/plonky2), [`zk-coins/docs`](https://github.com/zk-coins/docs).

## This repository (node)

The node is the **Rust/Axum backend** behind [zkcoins.app](https://zkcoins.app): it scans Bitcoin for Taproot-inscription commitments, maintains the nullifier accumulator and account state, generates and verifies the recursive ZK proofs for every mint/send/receive, persists state to Postgres, and broadcasts the commit/reveal inscription pair back to the chain. It is a single self-hostable container — running your own node is the trustless, private path the whole system is designed around.

### Trust model — run your own node

zkCoins follows the **Bitcoin full-node model: your wallet trusts _your_ node, exactly as a Bitcoin wallet trusts your own `bitcoind`.** Proof generation runs inside this process, so the node sees, in cleartext, the sender, recipient, and amount of every movement plus the full witness — the trust boundary is the **node operator, not the chain**. The on-chain footprint stays private: block explorers see only opaque 64-byte commitments. A foreign operator can never steal, forge, or double-spend your coins (that is enforced cryptographically), but it can see your privacy and affect liveness — the same trade-off as using someone else's Electrum/SPV server instead of your own. **If you need full transaction privacy, run your own node.** Full rationale: [`CONTRIBUTING.md` § Trust model](./CONTRIBUTING.md#trust-model--run-your-own-node).

|  | Hosted (`api.zkcoins.app`) | Self-hosted |
| --- | --- | --- |
| On-chain privacy (vs. block explorers) | ✅ | ✅ |
| Operator sees plaintext transaction data | ❌ Yes — operated by [zkcoins.app](https://zkcoins.app) | ✅ No |
| Setup effort | ✅ None | ⚠️ Postgres + electrs + Bitcoin node |

### Live deployments

| Environment | URL | Bitcoin chain | Image |
| --- | --- | --- | --- |
| **PRD** | [api.zkcoins.app](https://api.zkcoins.app) | Mainnet | [`zkcoins/node:latest`](https://hub.docker.com/r/zkcoins/node/tags?name=latest) |
| **DEV** | [dev-api.zkcoins.app](https://dev-api.zkcoins.app) | Mutinynet | [`zkcoins/node:beta`](https://hub.docker.com/r/zkcoins/node/tags?name=beta) |

Container images: **[hub.docker.com/r/zkcoins/node](https://hub.docker.com/r/zkcoins/node)**

### Tech stack

| Layer | Technology | Why |
| --- | --- | --- |
| Language | Rust nightly (pinned via `rust-toolchain`) | Required for Plonky2 (`feature(specialization)`) |
| Web framework | Axum | Built on Tokio, idiomatic async Rust |
| ZK proofs | Plonky2 + Poseidon-Goldilocks (cyclic recursion) | Node-side, no zkVM, no external prover dependency |
| Data structures | SMT + MMR (Poseidon) | Non-inclusion proofs + append-only history |
| State store | PostgreSQL (`sqlx`) | Deterministic, atomic SMT/MMR/checkpoint writes |
| Bitcoin | Taproot inscriptions | 64-byte nullifiers, Esplora API scanning |
| Bitcoin index | electrs (Esplora) | Esplora REST + WebSocket over the shared Docker network `bitcoin` |

Full rationale: [docs.zkcoins.com/tech-decisions](https://docs.zkcoins.com/tech-decisions).

### Build & run

Prerequisites: nightly Rust (auto-installed via `rust-toolchain`), Docker (for the Postgres testcontainer), and access to a Bitcoin node with an Esplora-compatible indexer (electrs). The node reads configuration **exclusively from environment variables** — required ones panic the bootstrap on startup if unset, there is no silent fallback.

```bash
git clone https://github.com/zk-coins/node.git
cd node

# Local Postgres for the state layer
docker run --name zkcoins-pg -e POSTGRES_PASSWORD=dev -p 5432:5432 -d postgres:17

export DATABASE_URL="postgresql://postgres:dev@localhost:5432/postgres"
export PUBLISHER_KEY="$(openssl rand -hex 32)"   # 32-byte hex; never commit a real key
export USERNAME_DOMAIN="test.zkcoins.local"      # external hostname returned by /api/info
export IS_MAINNET="false"                        # exact "true" / "false"; anything else panics
export ESPLORA_URL="http://localhost:3000"       # HTTP Esplora endpoint
export ESPLORA_WS_URL="ws://localhost:8999/api/v1/ws"  # Esplora WebSocket (issue #84)

cargo run -p node
# Node starts on http://0.0.0.0:4242
```

Or with Docker:

```bash
docker build -t zkcoins/node .
docker run -p 4242:4242 --network bitcoin \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  -e USERNAME_DOMAIN=zkcoins.app \
  zkcoins/node
```

The Docker build is multi-stage Rust → `linux/arm64` and forwards a `FEATURES` build-arg to `cargo build --features`. Both DEV and PRD ship the identical **MVP-only binary** (no Cargo features); the underlying bitcoind needs `txindex=1`, `rest=1`, `server=1`.

Key configuration variables (full table in [`CONTRIBUTING.md` § Environment variables](./CONTRIBUTING.md#environment-variables)):

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | _(required)_ | Postgres connection string for the state layer. |
| `PUBLISHER_KEY` | _(required)_ | 32-byte hex private key for Taproot inscription publishing. Never commit a real key. |
| `USERNAME_DOMAIN` | _(required)_ | External hostname returned by `/api/info`. |
| `IS_MAINNET` | _(required)_ | Exact string `true` / `false`; selects Mainnet vs. signet/Mutinynet address derivation. Anything else panics. |
| `ESPLORA_URL` | _(required)_ | HTTP Esplora endpoint (electrs or compatible). |
| `ESPLORA_WS_URL` | _(required)_ | Esplora WebSocket endpoint the scanner subscribes to for new-tip events. |
| `RUST_LOG` | `info` | Log level. |

### Test

```bash
cargo test -p node                 # MVP code paths — what the DEV + PRD binary contains
cargo test -p node --all-features  # including the gated address-list and lnurl routes
cargo llvm-cov -p node             # coverage: measured floor on node + shared (see .github/coverage-baseline.md)
```

The `db_tests` spin up their own `postgres:17` container via `testcontainers-modules`. CI enforces a **measured coverage floor** (currently 77 % lines + functions; full record in [`.github/coverage-baseline.md`](.github/coverage-baseline.md)) over `-p node -p shared --all-features`. Legitimate exclusions are test infrastructure (`*_tests.rs`, `test_db.rs`, `bin/`), crate entrypoints (`main.rs`, `lib.rs`), and the Plonky2 circuit packages (`program-plonky2/`, `script-plonky2/`) — those circuits are secured by the §1.7.9 digest generator, prove tests, and the D-05 differential test, not by line coverage. Production modules such as `publisher.rs`, `runtime.rs`, `flow.rs`, `job_dispatcher.rs`, and the scanners are **included** in the measurement. Enable the pre-push hook (`git config core.hooksPath .githooks`) to run `cargo fmt --check`, clippy, and `cargo check` before push. CI also enforces a **no-polling** rule: scanner/publisher hot paths subscribe to events, they never poll the chain tip (issue [#84](https://github.com/zk-coins/node/issues/84)).

### HTTP surface

The REST + LNURL API is documented by an **OpenAPI 3.x spec generated at compile time** from `#[utoipa::path]` annotations (the wire contract cannot drift from the docs). Served at `GET /openapi.json` and rendered with bundled Swagger UI at `GET /docs`. User sends are admitted to a **Job API** (`POST /api/jobs/send` → poll `GET /api/jobs/:id` → `POST /api/jobs/:id/commit`) so the thin wallet never holds an HTTP connection across the multi-second prove call. Mint follows the same admit-then-poll pattern (`POST /api/jobs/mint`); the node holds the minting key, so the signing phase is skipped.

### Repository layout

```
node/
├── node/                  # Axum REST API (router, account_node, state, scanner, publisher, job dispatcher)
│   ├── src/
│   │   ├── main.rs        # Entry point, chain scanner, bind 0.0.0.0:4242
│   │   ├── router.rs      # REST endpoints + /health
│   │   ├── runtime.rs     # Bootstrap: lazy_statics, Postgres pool, REST listener
│   │   ├── account_node.rs# Account logic, coin proofs, prover calls
│   │   ├── state.rs       # Sparse Merkle Tree + Merkle Mountain Range (Poseidon)
│   │   ├── scanner.rs     # Bitcoin block scanner (event-driven, prefix 4242)
│   │   ├── scanner_ws.rs  # Esplora WebSocket subscriber (issue #84, replaces polling)
│   │   ├── publisher.rs   # Taproot inscription broadcaster (commit/reveal)
│   │   ├── job_dispatcher.rs / job_store.rs  # Async Job API for sends
│   │   └── openapi.rs     # Compile-time OpenAPI 3.x spec
│   └── migrations/        # Forward-only SQL migrations (no down-migrations in the MVP)
├── shared/                # Shared types (Commitment, Invoice, ClientAccount)
├── program-plonky2/       # Plonky2 + Poseidon cyclic-recursion state-transition circuit
│   └── CONTRIBUTING.md    # Toolchain/build/test/coverage handoff for the circuit crate
├── script-plonky2/        # Host-side Plonky2 prover wrapper (zkcoins-prover-plonky2)
├── Cargo.toml             # Workspace root (nightly toolchain, tuned release profile)
├── Dockerfile             # Multi-stage Rust build (linux/arm64, FEATURES build-arg)
└── rust-toolchain         # Pinned nightly
```

### Proving strategy

zkCoins is **node-heavy**: this node generates all proofs; the wallet holds only the private key and signs BIP-340 Schnorr over the proof outputs. There is no in-browser Poseidon, no wasm verifier, no in-app ZK gadget. The hardware target is a single **Mac Studio M3 Ultra** (96 GB unified RAM): all on-box compute, no external GPU/CUDA, no cloud proving services. Performance budget: warm proof ≤ 5 s (target ≤ 1 s), cold-start ≤ 30 s, memory peak < 64 GB — if a design overshoots, the design changes. See [docs.zkcoins.com/specification](https://docs.zkcoins.com/specification).

### Branch flow

Feature PRs land on **`staging`** first (the integration buffer), are batched into **`develop`** (auto-PR'd, deploys to the DEV node), and promoted to **`main`** (auto-PR'd, deploys to the PRD node). `develop` and `main` are protected — no direct pushes. Maintainers merge PRs; contributors open them as drafts. See [`CONTRIBUTING.md` § Git workflow](./CONTRIBUTING.md#git-workflow) for the full table and conventions.

| Branch | Purpose | Deploy target |
| --- | --- | --- |
| `staging` | Integration buffer — feature PRs land here first | none |
| `develop` | Active development, promoted from `staging` in batches | DEV node |
| `main` | Production releases, promoted from `develop` | PRD node |

## Protocol

Based on [Shielded CSV](https://eprint.iacr.org/2025/068) by Jonas Nick (Blockstream), Liam Eagen (Alpen Labs), and Robin Linus (ZeroSync). Node code derived from [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins). Protocol design drafts and the spec live in [`zk-coins/research`](https://github.com/zk-coins/research/tree/develop/zkcoins-design) and on the docs site: [docs.zkcoins.com/specification](https://docs.zkcoins.com/specification) · [docs.zkcoins.com/roadmap](https://docs.zkcoins.com/roadmap).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for setup, coding standards, the coverage gate, and the PR flow. Security policy: [`SECURITY.md`](./SECURITY.md).

## License

MIT — see [`LICENSE`](./LICENSE).
