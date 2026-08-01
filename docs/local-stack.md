# Local stack (`compose.yaml`) — full unmocked pass

Bring up **PostgreSQL 17**, **bitcoind regtest**, a **Nostr relay**
(`scsibug/nostr-rs-relay:0.8.13`), and the **node** process with the
environment the Stage-3 binary actually demands. Run the **api** beside Compose
(no Dockerfile in `zk-coins/api`). Goal of this document: a **complete** path

> mint → signature → job `completed` → nullifier visible on
> `GET /v1/chain/nullifier/<pubkey>` after chain inclusion and scanner fold.

Nothing here invents chain endpoints, circuit pins, publisher secrets, or
wallet key material.

## What this stack is

| Service | Role | Why it is here |
| --- | --- | --- |
| `postgres` | State layer | `db::connect_and_migrate` on every boot (`node/src/main.rs`, `node/src/db.rs`). Schema: `node/migrations/`. Image tag **17** matches testcontainers (`node/src/test_db.rs` `.with_tag("17")`). |
| `bitcoind` | Regtest L1 | Stage-3 NfLog scan + AggregateStateNullifierV3 publish are **bitcoind RPC + cookie** (`node/src/v1/scan.rs` `v1_bitcoind_rpc_from_env`, `node/src/v1/publish.rs` `v1_publisher_env_from_env`). Image **`bitcoin/bitcoin:31.1`** (pinned; repo has no bitcoind version — see below). |
| `nostr-relay` | NIP-01 WebSocket relay | Local §4.2 / §4.3 delivery peer. Image **`scsibug/nostr-rs-relay:0.8.13`** (pinned; same tag as testcontainers in `node/src/v1/nostr/relay.rs`). Listens on **8080**. The node process does **not** yet wire the relay client into send/receive (later block); the service is here for local stack + client integration tests. |
| `node` | Kernel binary | Built from repo `Dockerfile`. REST **`0.0.0.0:4242`** (`ACCOUNT_NODE_ADDR`). Kernel gRPC on `KERNEL_GRPC_ADDR` (published as host **50051**). |

## What this stack is not (compose services)

| Missing as a service | Why | How you get it |
| --- | --- | --- |
| **`zk-coins/api`** | That repo has **no Dockerfile** and is a sibling directory, not this compose context. Inventing a build context that points outside this tree is out of scope. | Host `cargo run` against the published kernel port (below). |
| **Esplora / electrs** | Still **required** by residual `NETWORK_CONFIG` (`lib.rs` `build_network_config_from_env`) and by `/health/ready` (`router.rs` `check_esplora`). Stage-3 **scan does not use Esplora**. No electrs image/config in this repo. | Operator-supplied; set `ESPLORA_URL` / `ESPLORA_WS_URL`. |
| **Mainnet** | `IS_MAINNET` is hard-set to `false`. Do not override to `true`. | — |
| **Funded wallet / mined blocks** | Compose does **not** create wallets or mine blocks at start. Silent funding would hide operator setup. | Operator steps below. |
| **Signed §4.3 BootstrapManifest** | No BMF1 loader; process must not invent `manifest_sig` (`kernel/chain.rs` `BOOTSTRAP_MANIFEST_UNAVAILABLE_REASON`). Operational env is still required so identity assembly has something real to attach later. | `GetInfo` / complete `ChainIdentity` stay fail-closed; jobs + `GetNullifierPath` do not need identity. |

## How the node reaches bitcoind (boot path)

Production env names (not the live-test aliases):

| Env (production binary) | Live-test alias (script-plonky2 only) | Form |
| --- | --- | --- |
| `ZKCOINS_V1_BITCOIND_RPC_URL` | `ZKCOINS_REGTEST_URL` | Base HTTP URL, e.g. `http://127.0.0.1:18443` — **no** `/wallet/<name>` suffix (`publisher.rs` / `scanner.rs` configs). |
| `ZKCOINS_V1_BITCOIND_COOKIE_PATH` | `ZKCOINS_REGTEST_COOKIE` | Filesystem path to bitcoind `.cookie` (cookie-file auth only). |
| `ZKCOINS_V1_BITCOIND_WALLET` | `ZKCOINS_REGTEST_WALLET` | Loaded wallet name; publisher appends `/wallet/<name>` to the base URL. |

Boot path (node process):

1. `main.rs` requires `KERNEL_GRPC_ADDR` and chain-identity **ops** env, then migrates Postgres, then exclusive v1 stack (`ZKCOINS_V1_SHADOW=1`).
2. REST + gRPC bind via `start_rest_node` (gRPC address from step 1).
3. `run_v1_scan_loop` → `v1_bitcoind_rpc_from_env()` → `Scanner::connect` with RPC URL + cookie path. Failure exits the process (no Esplora fallback).
4. Publish path (mint/send finalise) → `v1_publisher_env_from_env` (same RPC URL + cookie + wallet + fee + reveal). Missing wallet/fee/reveal aborts that path; with empty pending table, scan-only boot used to log and continue — **this compose requires them** so a mint can finish.

In Compose, URL is fixed to the service DNS name:

```text
ZKCOINS_V1_BITCOIND_RPC_URL=http://bitcoind:18443
ZKCOINS_V1_BITCOIND_COOKIE_PATH=/run/bitcoind-data/regtest/.cookie
```

Cookie volume: named volume `bitcoind_data` → bitcoind datadir `/home/bitcoin/.bitcoin`; node mounts it read-only at `/run/bitcoind-data`.

### bitcoind image version

No version is named in this repo’s CI, docs, or tests. Compose pins **`bitcoin/bitcoin:31.1`** (Bitcoin Core 31.1, multi-platform Debian image on Docker Hub; **not** `latest`). Client library in-tree is `bitcoincore-rpc = "0.19.0"`. Flags match README/CONTRIBUTING: `txindex=1`, `rest=1`, `server=1`, plus `rpcallowip` / `rpcbind` so other containers can use cookie HTTP Basic over the compose network.

### nostr-relay image version

Compose and the relay integration tests pin **`scsibug/nostr-rs-relay:0.8.13`** (not `latest`). Default image config listens on `0.0.0.0:8080` with on-disk SQLite under the `nostr_relay_data` volume. Readiness: TCP accept on port 8080 (`compose.yaml` healthcheck). From the host: `ws://127.0.0.1:8080/`. From another compose service: `ws://nostr-relay:8080/`.

For `ZKCOINS_RELAY_URL` (GetInfo / identity ops pin — still required at boot even though the NIP-01 client is not yet wired into send/receive) a local-stack choice is:

```bash
export ZKCOINS_RELAY_URL=ws://nostr-relay:8080/
```

(host-side clients that are not in the compose network use `ws://127.0.0.1:8080/` instead).

## api (sibling process)

### Env (from `api/src/config.rs` — only these four)

| Variable | Rules |
| --- | --- |
| `ZKCOINS_BIND_ADDR` | Required, non-empty, parseable `SocketAddr` (e.g. `0.0.0.0:8080`). No default. |
| `ZKCOINS_KERNEL_ADDR` | Required, non-empty tonic URI. Tests use `http://127.0.0.1:50051`. Point at the published kernel port. |
| `ZKCOINS_FEATURES` | Required **as a variable** (may be empty string = all off). Closed set: `wallet`, `explorer`, `publisher`, `lightning_bridge`, `mail_bridge`. Full pass needs at least **`wallet,explorer`**. |
| `ZKCOINS_PUBLIC_HOST` | Required **as a variable** (may be empty). Authoritative hosts for §5.1 `chan_bind`; never taken from the HTTP `Host` header. Empty ⇒ ownership-auth surfaces fail loud; mint/sign/nullifier do not need it. |

The api does **not** take node identity vars (`ZKCOINS_RELAY_URL`, …). Those are kernel-side.

### Dockerfile

**None** in `zk-coins/api` (verified: no `Dockerfile` at repo root). Start on the host:

```bash
# From the zk-coins/api checkout (sibling of this node worktree).
export ZKCOINS_BIND_ADDR=0.0.0.0:8080
export ZKCOINS_KERNEL_ADDR=http://127.0.0.1:50051
export ZKCOINS_FEATURES=wallet,explorer
export ZKCOINS_PUBLIC_HOST=
# Optional: RUST_LOG=info
cargo run
```

Kernel must already be listening on host port **50051** (`KERNEL_GRPC_ADDR=0.0.0.0:50051` in compose + published port).

## Prerequisites

1. Docker with Compose v2.
2. Disk and RAM for a **first** node image build (multi-stage Rust + Plonky2 circuits). Expect **many minutes to hours** on a cold machine; subsequent boots reuse the image and `/data/proofs` volume but still pay migration + scanner connect. Be honest: the first circuit construction is the long pole (see also `docs/build-report.md` for historical full-build wall times).
3. An Esplora-compatible HTTP + WebSocket endpoint the node container can reach (residual config + readiness only).
4. A sibling checkout of `zk-coins/api` with a working Rust toolchain (`rust-toolchain` in that repo).
5. Ability to produce a BIP-340 creator signature for the mint (wallet / SDK / tooling you control). This document describes the **HTTP wire**, not a full wallet implementation.

## Required environment (host → compose)

Compose uses `${VAR:?…}` so a missing variable **fails at parse time**.

### Crypto / identity (never committed)

| Variable | Panic / fail site | How to set |
| --- | --- | --- |
| `PUBLISHER_KEY` | `node/src/lib.rs` `PUBLISHER_KEY` | `export PUBLISHER_KEY="$(openssl rand -hex 32)"` — real secp256k1 secret; no compose default |
| `USERNAME_DOMAIN` | `node/src/lib.rs` `USERNAME_DOMAIN` | e.g. `export USERNAME_DOMAIN=local.zkcoins.test` |

### Residual Esplora (still mandatory at boot)

| Variable | Fail site | Notes |
| --- | --- | --- |
| `ESPLORA_URL` | `build_network_config_from_env` | HTTP base; `/health/ready` pings tip height |
| `ESPLORA_WS_URL` | same | Still required even though Stage-3 scan does not use the legacy WS scanner |

No invented third-party URLs in this document. Point at an Esplora **you** run for the same regtest chain if you have one; if you only care about the mint/nullifier path, expect `/health/ready` to stay non-ready while jobs still run against bitcoind.

### §3.6 boot pins

Compose sets `ZKCOINS_V1_SHADOW=1`, `ZKCOINS_NETWORK=regtest`, `ZKCOINS_ACTIVATION_HEIGHT=0`.

You supply:

| Variable | Fail site |
| --- | --- |
| `ZKCOINS_CIRCUIT_DIGEST_C` | `v1_boot_pins_from_env` — 64 lowercase hex |
| `ZKCOINS_CIRCUIT_DIGEST_C_BALANCE` | same |
| `ZKCOINS_BOOTSTRAP_PUBKEY` | same — 64 lowercase hex BIP-340 x-only |
| `ZKCOINS_EXPECTED_PARAMS_IDENTIFIER` | same — `SHA-256(canonical_encoding(NetworkParams))` |

#### Circuit digests for this tree (regtest)

From `script-plonky2/tests/generated_circuit_digests.txt` (drop the `0x` prefix):

```text
ZKCOINS_CIRCUIT_DIGEST_C=9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352
ZKCOINS_CIRCUIT_DIGEST_C_BALANCE=bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d
```

#### Computing `ZKCOINS_EXPECTED_PARAMS_IDENTIFIER`

Canonical encoding (`shared/src/spec_v1/network_params.rs`):

```text
u8(len(tag)) || tag || digest_c || digest_c_balance || u64_be(activation_height) || u8(6) || bootstrap_pubkey
```

Regtest tag bytes: `zkCoins/v1/regtest` (`NETWORK_TAG_REGTEST`). `activation_height` must be `0`.

```bash
python3 - <<'PY'
import hashlib, os
tag = b"zkCoins/v1/regtest"
c  = bytes.fromhex(os.environ["ZKCOINS_CIRCUIT_DIGEST_C"])
cb = bytes.fromhex(os.environ["ZKCOINS_CIRCUIT_DIGEST_C_BALANCE"])
boot = bytes.fromhex(os.environ["ZKCOINS_BOOTSTRAP_PUBKEY"])
enc = bytes([len(tag)]) + tag + c + cb + (0).to_bytes(8, "big") + bytes([6]) + boot
print(hashlib.sha256(enc).hexdigest())
PY
export ZKCOINS_EXPECTED_PARAMS_IDENTIFIER="$(…output…)"
```

`ZKCOINS_BOOTSTRAP_PUBKEY` is **your** 32-byte x-only network bootstrap key for this local network — generate or load from your operator material; this doc does not invent one.

### GetInfo operational pins (required at node boot since `3acd71d`)

| Variable | Fail site | Notes |
| --- | --- | --- |
| `ZKCOINS_RELAY_URL` | `chain_identity_ops_from_env` | Operator-chosen advertised Nostr relay URL |
| `ZKCOINS_BLOSSOM_URL` | same | Operator-chosen advertised Blossom base URL |
| `ZKCOINS_MAX_BLOB_BYTES` | same | Integer **> 0** |
| `ZKCOINS_KERNEL_PARTS` | same | Comma-separated closed set: `scanner`, `prover`, `publisher` (at least one) |
| `KERNEL_GRPC_ADDR` | `kernel_grpc_addr_from_env` | Bind address; for this stack use `0.0.0.0:50051` |

### Publish path (required by this compose for a completable mint)

| Variable | Meaning |
| --- | --- |
| `ZKCOINS_V1_BITCOIND_WALLET` | bitcoind wallet name funding AggregateStateNullifierV3 commits |
| `ZKCOINS_V1_FEE_RATE_SAT_PER_VB` | sat/vB, integer > 0 |
| `ZKCOINS_V1_REVEAL_OUTPUT_SATS` | reveal output sats, integer > 0 |

### Fixed inside compose

| Variable | Value | Why |
| --- | --- | --- |
| `IS_MAINNET` | `false` | Local stack never mainnet |
| `ZKCOINS_V1_SHADOW` | `1` | Stage-3 refuses legacy dual stack |
| `ZKCOINS_NETWORK` | `regtest` | Local target |
| `ZKCOINS_ACTIVATION_HEIGHT` | `0` | §3.6 regtest pin |
| `DATABASE_URL` | internal to `postgres` | User `zkcoins` / password `localdev` / db `zkcoins` — local-only |
| `ZKCOINS_V1_BITCOIND_RPC_URL` | `http://bitcoind:18443` | Compose DNS |
| `ZKCOINS_V1_BITCOIND_COOKIE_PATH` | `/run/bitcoind-data/regtest/.cookie` | Shared volume |

## Start

### 1. Export host env

```bash
export PUBLISHER_KEY="$(openssl rand -hex 32)"
export USERNAME_DOMAIN=local.zkcoins.test

# Residual Esplora (you operate)
export ESPLORA_URL=…          # your Esplora HTTP base
export ESPLORA_WS_URL=…       # your Esplora WS URL

# §3.6 pins
export ZKCOINS_CIRCUIT_DIGEST_C=9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352
export ZKCOINS_CIRCUIT_DIGEST_C_BALANCE=bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d
export ZKCOINS_BOOTSTRAP_PUBKEY=…   # 64 lowercase hex x-only — your material
export ZKCOINS_EXPECTED_PARAMS_IDENTIFIER=…  # compute as above

# Operational pins (operator-chosen URLs for *this* local node — not invented)
# Compose service `nostr-relay` → ws://nostr-relay:8080/ (host tools: ws://127.0.0.1:8080/)
export ZKCOINS_RELAY_URL=ws://nostr-relay:8080/
export ZKCOINS_BLOSSOM_URL=…
export ZKCOINS_MAX_BLOB_BYTES=1048576
export ZKCOINS_KERNEL_PARTS=scanner,prover,publisher
export KERNEL_GRPC_ADDR=0.0.0.0:50051

# Publish path — wallet name must match the wallet you create in step 3
export ZKCOINS_V1_BITCOIND_WALLET=zkcoins
export ZKCOINS_V1_FEE_RATE_SAT_PER_VB=2
export ZKCOINS_V1_REVEAL_OUTPUT_SATS=1000
```

### 2. Bring Compose up

```bash
docker compose up --build
```

First build builds the node image (Rust + circuits). Leave it running.

### 3. Operator bitcoind steps (no silent funding in compose)

Create a wallet, mine blocks for coinbase maturity, confirm the cookie path the node sees.

```bash
# Wallet name must equal ZKCOINS_V1_BITCOIND_WALLET
docker compose exec bitcoind \
  bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin \
  createwallet zkcoins

# Mine enough blocks for mature coinbase (regtest: 100+ is the usual operator habit;
# exact maturity rules are Bitcoin Core’s — fund until the wallet can pay fees).
docker compose exec bitcoind \
  bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin \
  -rpcwallet=zkcoins getnewaddress
# Then generatetoaddress N <that-address>  (N large enough for spendable balance)

docker compose exec bitcoind \
  bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin \
  -rpcwallet=zkcoins getbalance
```

If the node was already running before the wallet existed, restart the **node** service after the wallet is ready so a first publish does not fail against a missing wallet:

```bash
docker compose restart node
```

### 4. Start the api (host)

```bash
export ZKCOINS_BIND_ADDR=0.0.0.0:8080
export ZKCOINS_KERNEL_ADDR=http://127.0.0.1:50051
export ZKCOINS_FEATURES=wallet,explorer
export ZKCOINS_PUBLIC_HOST=
cargo run   # in zk-coins/api
```

## Probes — when is each piece actually up?

Do not “wait a bit”. Use these checks:

| Piece | Probe | Expected |
| --- | --- | --- |
| Postgres | `docker compose exec postgres pg_isready -U zkcoins -d zkcoins` | exit 0 / “accepting connections” |
| bitcoind | `docker compose exec bitcoind bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin getblockchaininfo` | JSON with `"chain": "regtest"` |
| bitcoind cookie | `docker compose exec bitcoind test -f /home/bitcoin/.bitcoin/regtest/.cookie` | exit 0 |
| nostr-relay | `docker compose exec nostr-relay bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080'` | exit 0 (TCP accept on 8080) |
| node liveness | `curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4242/health` | `200`, body `ok` (`router.rs` `health_handler`) |
| node gRPC port | TCP connect to `127.0.0.1:50051` (e.g. `nc -z 127.0.0.1 50051`) | open once REST/gRPC task bound |
| node readiness | `curl -sS http://127.0.0.1:4242/health/ready` | `200` only when Postgres, **Esplora tip**, prover warm, v1 scan caught up, no deep reorg — else `503`. Liveness can be green while ready is red. |
| api liveness | `curl -sS http://127.0.0.1:8080/health` | body `ok` (`api` `GET /health`) |
| api readiness | `curl -sS http://127.0.0.1:8080/health/ready` | Kernel `GetInfo`. While BootstrapManifest is missing, kernel `GetInfo` stays fail-closed → expect **503** `{ ready: false, … }` (api `docs/rest-surface.md`). That does **not** mean jobs are dead. |
| api discovery | `curl -sS http://127.0.0.1:8080/` | JSON with `endpoints` for registered surfaces only |

## Full pass (mint → sign → completed → nullifier)

All api calls below assume `http://127.0.0.1:8080` and features `wallet,explorer`.

### A. Mint — `POST /v1/tx`

Shape enforced in `api/src/jobs.rs` (`TransitionRequestJson`, kind `mint`):

- Required: `kind`, `subject`, `next_pubkey` (32-byte hex), `npk_rand` (32-byte hex), non-empty `output_templates`, `issuance`
- Forbidden for mint: `input_coins`, `fold_coin_ids`, `fee_address`
- Optional: `publisher_pubkey`, `Idempotency-Key` header (≤ 64 bytes)

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/tx \
  -H 'content-type: application/json' \
  -H 'idempotency-key: <your-key>' \
  -d '{
    "kind": "mint",
    "subject": "<your-account-subject>",
    "next_pubkey": "<64-hex>",
    "npk_rand": "<64-hex>",
    "output_templates": [{
      "recipient": "<recipient-subject>",
      "asset_id": "<64-hex>",
      "amount": "<decimal-string>"
    }],
    "issuance": {
      "name": "<asset-name>",
      "decimals": 8,
      "issuance_version": 1,
      "amount": "<decimal-string>"
    }
  }'
```

**Expected:** HTTP **202** body `{ "job_id": "…", "status": "accepted" }`.

> Placeholders only — no example keys that look like live secrets. Field widths are from the api validator (`decode_hex_exact` 32 bytes for pubkey digests). How you derive `subject` / keys is wallet/SDK work (**open** if you do not have that tooling).

### B. Wait for signature challenge — `GET /v1/jobs/<job_id>`

```bash
curl -sS http://127.0.0.1:8080/v1/jobs/<job_id>
```

Poll until `status` is `awaiting_signature`. The object then includes `awaiting_signature` with
(`api/src/jobs.rs` `awaiting_signature_json`):

- `new_account_state_hash`, `output_coins_root`, `input_nullifiers_root`,
  `coin_history_root`, `nav_commitment`, `npk_commit`, `proof_data_hash`,
  `txn_pubkey` (each 32-byte hex), and `send_counter`

Alternatively: `GET /v1/jobs/<job_id>/stream` (SSE: `phase` / `complete` / `error`).

### C. Sign — `POST /v1/jobs/<job_id>/sign`

Body (`SignBodyJson`): `{ "signature": "<128-hex = 64 bytes>", "s2c_nonce": "<64-hex = 32 bytes>" }` — BIP-340 creator signature + x-only even-y `R'` (`node/src/v1/signature.rs` wire rules: lowercase hex, no `0x`).

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/jobs/<job_id>/sign \
  -H 'content-type: application/json' \
  -d '{"signature":"<128-hex>","s2c_nonce":"<64-hex>"}'
```

**Expected:** HTTP **200** with updated job JSON. Production path then finalises (prove/apply, durable `members_ready`, construct/broadcast handoff).

> How to compute the signature from `awaiting_signature` fields is protocol/wallet logic (domain-separated BIP-340 over proof-data). Exact local signing command **open** without a wallet binary in this stack — use your SDK or the signing code paths under `script-plonky2` / `node/src/v1/signature.rs` as the source of truth.

### D. Job reaches `completed`

```bash
curl -sS http://127.0.0.1:8080/v1/jobs/<job_id>
```

**Expected:** `status: "completed"` and a `result` object (digest fields + `output_coin_ids`, …).

**What `completed` means** (`node/src/job_dispatcher.rs` `JOB_FINALISE_HOST_EDGE`):

> Host edge after durable engine + `members_ready` **and** nullifier broadcast handoff (construct/broadcast).  
> **Not** on-chain AggregateStateNullifierV3 confirmation.  
> **Not** NfLog scan-fold.  
> Those need bitcoind inclusion + the scanner.

If the job stays short of `completed` with pending publish still `members_ready`, check bitcoind wallet balance, fee/reveal env, and node logs for publish errors.

### E. Mine blocks (include commit/reveal)

```bash
# Address from the publisher wallet; mine at least enough to include mempool txs
ADDR=$(docker compose exec -T bitcoind \
  bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin \
  -rpcwallet=zkcoins getnewaddress | tr -d '\r')
docker compose exec bitcoind \
  bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin \
  -rpcwallet=zkcoins generatetoaddress 1 "$ADDR"
```

Repeat as needed until commit/reveal leave the mempool. For **finality** (protocol pin **6** confirmations — `FINALITY_CONFIRMATIONS` in `node/src/kernel/chain.rs`), mine additional blocks so the inclusion height sits ≥ 6 deep under tip. One block is inclusion, not finality.

### F. Prove the nullifier on the canonical chain view

```bash
curl -sS "http://127.0.0.1:8080/v1/chain/nullifier/<pubkey-hex>"
```

- Path segment: **32-byte hex** account pubkey for the nullifier index (`api/src/chain.rs` `get_nullifier` → kernel `GetNullifierPath`).
- Which pubkey? The NfLog first-occurrence key for the transition (account state nullifier `pk`). For a mint this is the account public key whose state was nullified — typically the signing account’s x-only pubkey for that transition, **not** the bech32 `subject` string as-is. Mapping from wallet material → this 32-byte key is wallet/SDK territory (**open** if your tooling does not already expose it).

**Expected after scanner fold of an included nullifier:**

- `present: true`
- `position`, `leaf`, `audit_path`, plus `root` / `tip_block_hash` / `tip_height` / `tree_size`

**Before** inclusion/fold: `present: false` with empty `audit_path` (unauthenticated local-index absence — not a proof of non-existence on another node).

Kernel `internal_error` is **not** rewritten as absent.

Optional cross-check: `GET /v1/chain/accumulator` → `{ size, root, tip_block_hash, tip_height }` (pass-through of kernel `nav_root`).

## What the pass proves — and what it does not

| Claim | Proved by this pass? |
| --- | --- |
| api accepts mint, returns a job, and projects kernel status | Yes, if steps A–D succeed |
| Wallet signature verified; host applied state; broadcast handoff recorded | Yes when status is `completed` (`JOB_FINALISE_HOST_EDGE`) |
| Commit/reveal in a mined block on **this** regtest bitcoind | Yes only after step E and mempool/chain checks you perform |
| Nullifier folded into the node’s NfLog and served with inclusion path | Yes when step F returns `present: true` |
| Six-confirmation finality | Only if you mined depth ≥ 6 under tip; one block is not finality |
| `completed` alone = chain inclusion | **No** — that is why step F exists |
| Full `GetInfo` / signed network bootstrap | **No** — BootstrapManifest still missing |
| Production readiness (`/health/ready` green without Esplora) | **No** — Esplora still on the residual path |
| Mainnet safety | **No** — regtest only; never set `IS_MAINNET=true` |

## Cleanup

```bash
# Stop containers; keep volumes
docker compose down

# Stop and remove volumes (Postgres state, node /data/proofs, bitcoind regtest)
docker compose down -v
```

Re-creating volumes wipes the regtest chain, cookie, wallet, and node state. After `-v`, re-run wallet create, funding, and pin exports from scratch.

## Fail-loud behaviour (by design)

- Missing compose-required env → **parse-time** error (`${VAR:?…}`).
- Missing `PUBLISHER_KEY` / Esplora / §3.6 pins / identity ops / bitcoind RPC env → process panic or `Err`.
- Unreachable bitcoind after boot → scanner connect fails → process exits (`run_v1_scan_loop`). No `restart: always`.
- Wrong circuit digests vs the binary → self-heal / boot refusal.
- api missing any of its four env vars → exit code 1 with named error (`Config::from_env`).

## Gaps / open items

1. **No api image** — host `cargo run` only until `zk-coins/api` grows a Dockerfile.
2. **Esplora not bundled** — residual boot + readiness still need operator Esplora; scan/publish use bitcoind.
3. **BootstrapManifest** — `GetInfo` / api `/health/ready` stay fail-closed; job + nullifier paths do not.
4. **Wallet signing CLI** — this stack does not ship a mint signer; signature computation is open without external wallet/SDK.
5. **Exact pubkey for `/v1/chain/nullifier/<pubkey>`** after a mint depends on wallet key layout; not derivable from compose alone.
6. **Legacy residual network label** — `IS_MAINNET=false` still maps residual `EsploraConfig::network()` to **Signet** for Taproot address derivation (`publisher.rs`), while v1 pins use `regtest` (existing node behaviour).
7. **First boot time** — circuit build dominates; not fixed to a single number in compose.

## Policy reminders

- Never set `IS_MAINNET=true` in this file or a local override for this stack.
- Never commit a real `PUBLISHER_KEY`.
- Do not add `restart: always` to paper over boot failures.
- Do not replace `/health` with a `true` healthcheck.
- Do not invent URLs, digests, or example keys that look live.
