# Local stack (`compose.yaml`)

Bring up **PostgreSQL 17** and the **node** process with the same environment the Stage-3 binary actually demands. Nothing here invents chain endpoints, circuit pins, or a publisher secret.

> **Do not treat a green `docker compose up` as proof that the full protocol works.** The node still needs a live bitcoind (NfLog scan) and a live Esplora (config + readiness). Those are **operator-supplied**, not part of this compose file.

## What this stack is

| Service | Role | Why it is here |
| --- | --- | --- |
| `postgres` | State layer | `db::connect_and_migrate` runs on every boot (`node/src/main.rs`, `node/src/db.rs`). Schema: `node/migrations/` (0001–0028). Image tag **17** matches testcontainers (`node/src/test_db.rs` `.with_tag("17")`) and the README. |
| `node` | Kernel binary (HTTP today) | Built from the repo `Dockerfile`. Listens on **`0.0.0.0:4242`** (`node/src/main.rs` `ACCOUNT_NODE_ADDR`; `Dockerfile` `EXPOSE 4242`). |

## What this stack is not

| Missing | Why |
| --- | --- |
| **API layer** (`zk-coins/api`) | Built in parallel; not runnable yet. Spec §6.1 / §7.5 public REST will sit in front of the kernel; today the node still exposes its own HTTP surface. Including a non-starting service would make the whole compose worthless. |
| **bitcoind** | Stage-3 scan is **bitcoind RPC** (`ZKCOINS_V1_BITCOIND_RPC_URL` + cookie), not Esplora (`node/src/main.rs` `run_v1_scan_loop`, `node/src/v1/scan.rs`). This repo has no bitcoind image or regtest recipe; cookie auth and wallet funding are operator-owned. |
| **Esplora / electrs** | Still **required** by `NETWORK_CONFIG` and `/health/ready`, but there is no electrs Dockerfile or config in this repo. Point `ESPLORA_URL` / `ESPLORA_WS_URL` at an instance you run or already have. |
| **Mainnet** | `IS_MAINNET` is hard-set to `false`. Do not override to `true`. |
| **gRPC kernel edge** | Kernel/API split is in flight; this binary still speaks HTTP. |

## Prerequisites

1. Docker with Compose v2.
2. A **bitcoind** the node can reach (regtest or testnet). Needs RPC + cookie auth; README notes `txindex=1`, `rest=1`, `server=1` for the broader stack.
3. An **Esplora-compatible HTTP + WebSocket** endpoint for that same chain (for config bootstrap and readiness).
4. The §3.6 pin values for the circuit digests of **this** tree (see below).

## Required environment (host)

Compose uses `${VAR:?…}` so a missing variable **fails at parse time** — it does not start with a phantom default.

### Crypto / identity (never committed)

| Variable | Panic / fail site | How to set |
| --- | --- | --- |
| `PUBLISHER_KEY` | `node/src/lib.rs` `PUBLISHER_KEY` lazy_static — process panics if unset | `export PUBLISHER_KEY="$(openssl rand -hex 32)"` |
| `USERNAME_DOMAIN` | `node/src/lib.rs` `USERNAME_DOMAIN` | e.g. `export USERNAME_DOMAIN=local.zkcoins.test` |

`PUBLISHER_KEY` is a real secp256k1 secret. There is **no** compose default. The previous hard-coded placeholder was a public test key that drainer bots swept (see comment on `PUBLISHER_KEY` in `lib.rs`).

### Chain endpoints (no silent Mutinynet / third-party fallback)

| Variable | Fail site | Notes |
| --- | --- | --- |
| `ESPLORA_URL` | `build_network_config_from_env` (`lib.rs`) — panic if unset/empty | HTTP base for readiness (`router.rs` `check_esplora` → tip height). |
| `ESPLORA_WS_URL` | same | Still required even though Stage-3 scan does not use the legacy WS scanner. |
| `ZKCOINS_V1_BITCOIND_RPC_URL` | `v1_bitcoind_rpc_from_env` (`v1/scan.rs`) | e.g. `http://host.docker.internal:18443` for a host regtest bitcoind from Docker Desktop. |
| `BITCOIND_COOKIE_HOST_PATH` | compose bind mount | Absolute host path to bitcoind’s `.cookie` file. Mounted read-only at `/run/bitcoind/cookie` inside the node container. |

### §3.6 boot pins (Stage 3)

The production binary **requires** `ZKCOINS_V1_SHADOW=1` (`main.rs` refuses `Off`). Compose sets that and `ZKCOINS_NETWORK=regtest` / `ZKCOINS_ACTIVATION_HEIGHT=0` (regtest pin is height **0** per `validate_v1_boot_pins`).

You must still supply:

| Variable | Fail site |
| --- | --- |
| `ZKCOINS_CIRCUIT_DIGEST_C` | `v1_boot_pins_from_env` (`v1/mode.rs`) — 64 lowercase hex |
| `ZKCOINS_CIRCUIT_DIGEST_C_BALANCE` | same |
| `ZKCOINS_BOOTSTRAP_PUBKEY` | same — 64 lowercase hex BIP-340 x-only |
| `ZKCOINS_EXPECTED_PARAMS_IDENTIFIER` | same — must equal `SHA-256(canonical_encoding(NetworkParams))` |

#### Circuit digests for this tree (regtest)

From `script-plonky2/tests/generated_circuit_digests.txt` (drop the `0x` prefix):

```text
ZKCOINS_CIRCUIT_DIGEST_C=9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352
ZKCOINS_CIRCUIT_DIGEST_C_BALANCE=bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d
```

If you change circuits, regenerate that file and update the pins. A mismatch against the digests of the just-built circuits fails boot / triggers self-heal.

#### Computing `ZKCOINS_EXPECTED_PARAMS_IDENTIFIER`

Canonical encoding (`shared/src/spec_v1/network_params.rs`):

```text
u8(len(tag)) || tag || digest_c || digest_c_balance || u64_be(activation_height) || u8(6) || bootstrap_pubkey
```

For regtest the tag is the bytes of `zkCoins/v1/regtest` (`NETWORK_TAG_REGTEST` in `shared/src/spec_v1/tags.rs`), and `activation_height` must be `0`.

Example (Python; replace `BOOTSTRAP` with your 32-byte hex pubkey):

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

### GetInfo / ChainIdentity operational pins

Required by `require_chain_identity_ops_from_env` (`runtime.rs` / `kernel/chain.rs`) and re-checked when the exclusive v1 engine is installed. **No defaults** — missing or blank aborts at compose parse or process start and names the variable.

| Variable | Fail site | Notes |
| --- | --- | --- |
| `ZKCOINS_RELAY_URL` | `chain_identity_ops_from_env` | This node's advertised Nostr relay URL (`Info.relay_url`). Non-empty; max 2048 bytes. |
| `ZKCOINS_BLOSSOM_URL` | same | This node's advertised Blossom base URL (`Info.blossom_url`). |
| `ZKCOINS_MAX_BLOB_BYTES` | same | Advertised Blossom upload limit (`Info.max_blob_bytes`); integer **> 0**. |
| `ZKCOINS_KERNEL_PARTS` | same | Comma-separated closed set: `scanner`, `prover`, `publisher` (at least one; no duplicates). |
| `KERNEL_GRPC_ADDR` | `kernel_grpc_addr_from_env` | gRPC bind address (e.g. `0.0.0.0:50051`); no default host/port. |

**Not from env (protocol / node-owned):** `protocol_version` (`"v1"`), `finality_confirmations` (`6`), `max_tx_inputs` / `max_tx_outputs` / `max_rx_coins` / `max_account_assets` (circuit constants), circuit digests (from §3.6 pins after the live digest gate), tip / NAV / readiness (running engine).

**Still fail-closed for `GetInfo`:** the signed §4.3 `BootstrapManifest`. This tree has no BMF1 loader and must not invent `manifest_sig`. Operational pins above are still required so a future signed-manifest loader has a complete identity to install; until then `ChainIdentity` stays unset and `GetInfo` fails closed.

### Optional (publish path)

Required by `v1_publisher_env_from_env` (`v1/publish.rs`) when you publish or when resumable pending rows exist:

| Variable | Meaning |
| --- | --- |
| `ZKCOINS_V1_BITCOIND_WALLET` | bitcoind wallet name funding AggregateStateNullifierV3 commits |
| `ZKCOINS_V1_FEE_RATE_SAT_PER_VB` | sat/vB, integer &gt; 0 |
| `ZKCOINS_V1_REVEAL_OUTPUT_SATS` | reveal output sats, integer &gt; 0 |

If these are missing and the pending-publish table is empty, boot **logs** and continues scan (`main.rs`). If pending rows exist, boot **aborts**.

### Fixed inside compose (do not “fix” toward mainnet)

| Variable | Value | Why |
| --- | --- | --- |
| `IS_MAINNET` | `false` | Exact string; only `true`/`false` accepted (`lib.rs`). |
| `ZKCOINS_V1_SHADOW` | `1` | Stage-3 binary refuses legacy dual stack (`main.rs`). |
| `ZKCOINS_NETWORK` | `regtest` | Local stack target. |
| `ZKCOINS_ACTIVATION_HEIGHT` | `0` | §3.6 regtest pin. |
| `DATABASE_URL` | internal URL to `postgres` | User `zkcoins` / password `localdev` / db `zkcoins` — **local-only DB password**, not a publisher key. |
| `ZKCOINS_V1_BITCOIND_COOKIE_PATH` | `/run/bitcoind/cookie` | Matches the bind mount. |

## Start

```bash
# 1. Secrets and domains
export PUBLISHER_KEY="$(openssl rand -hex 32)"
export USERNAME_DOMAIN=local.zkcoins.test

# 2. Chain (you operate these)
export ESPLORA_URL=http://…          # Esplora HTTP
export ESPLORA_WS_URL=ws://…         # Esplora WS
export ZKCOINS_V1_BITCOIND_RPC_URL=http://host.docker.internal:18443
export BITCOIND_COOKIE_HOST_PATH=/path/to/bitcoind/regtest/.cookie

# 3. §3.6 pins (digests from generated_circuit_digests.txt + your bootstrap)
export ZKCOINS_CIRCUIT_DIGEST_C=9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352
export ZKCOINS_CIRCUIT_DIGEST_C_BALANCE=bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d
export ZKCOINS_BOOTSTRAP_PUBKEY=…    # 64 hex
export ZKCOINS_EXPECTED_PARAMS_IDENTIFIER=…  # see computation above

# 4. GetInfo operational pins (no invented relay/blossom; BootstrapManifest still fail-closed)
export ZKCOINS_RELAY_URL=ws://host.docker.internal:7777
export ZKCOINS_BLOSSOM_URL=http://host.docker.internal:3000
export ZKCOINS_MAX_BLOB_BYTES=1048576
export ZKCOINS_KERNEL_PARTS=scanner,prover,publisher
export KERNEL_GRPC_ADDR=0.0.0.0:50051

# 5. Optional publish wallet
# export ZKCOINS_V1_BITCOIND_WALLET=…
# export ZKCOINS_V1_FEE_RATE_SAT_PER_VB=1
# export ZKCOINS_V1_REVEAL_OUTPUT_SATS=546

docker compose up --build
```

## Probes

| Endpoint | Meaning | Code |
| --- | --- | --- |
| `GET /health` | Liveness — TCP listener bound, body `ok` | `router.rs` `health_handler` |
| `GET /health/ready` | Readiness — Postgres `SELECT 1`, Esplora tip height, prover warm, v1 scan caught up, no deep reorg | `router.rs` `ready_handler` |
| `GET /health/publisher` | Publisher Taproot address + UTXO sum via Esplora | `router.rs` `publisher_health_handler` |

Compose healthcheck uses **`GET /health` only** (real liveness). A node can be “healthy” in Docker while `/health/ready` is still `503` (e.g. Esplora down, prover warming, scan not caught up). That is intentional: readiness must not be faked green.

```bash
curl -sS http://127.0.0.1:4242/health
curl -sS http://127.0.0.1:4242/health/ready
```

## Fail-loud behaviour (by design)

- Missing `PUBLISHER_KEY` / Esplora / §3.6 pins / bitcoind RPC env → process **panics or returns Err** (no Mutinynet default, no placeholder key).
- Unreachable bitcoind after boot → scanner connect fails → process exits (`main.rs` `run_v1_scan_loop`). No `restart: always` hides that.
- Wrong circuit digests vs the binary → self-heal / boot refusal (`main.rs`, `v1` self-heal path).

## Gaps (what the stack still cannot do)

1. **No public API layer** — wallets that expect the §7.5 API service must wait for `zk-coins/api`.
2. **No bundled Bitcoin / Esplora** — you must already have (or run separately) bitcoind + Esplora; this compose only wires the node and Postgres.
3. **Node speaks HTTP, not gRPC** — the kernel/API split is parallel work; this binary is still the HTTP node (kernel gRPC binds when `KERNEL_GRPC_ADDR` is set).
4. **Legacy residual config** — `IS_MAINNET=false` still maps residual `EsploraConfig::network()` to **Signet** for Taproot address derivation (`publisher.rs`), while v1 pins use `regtest`. That is existing node behaviour, not introduced by compose.
5. **Publish path incomplete without wallet env** — scan can run without `ZKCOINS_V1_BITCOIND_WALLET` / fee / reveal; publishing and mid-flight resume need them.
6. **No warm-prove guarantee on first request** unless you wait for `/health/ready` (`prover` not `warming`).
7. **Signed §4.3 BootstrapManifest not loadable** — operational GetInfo env is required, but `GetInfo` / complete `ChainIdentity` stays fail-closed until a BMF1 (or equivalent) loader accepts a **real** network-signed manifest (no invented `manifest_sig`).

## Policy reminders

- Never set `IS_MAINNET=true` in this file or a local override for this stack.
- Never commit a real `PUBLISHER_KEY`.
- Do not add `restart: always` to paper over boot failures.
- Do not replace `/health` with a `true` healthcheck.
