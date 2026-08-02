# `deploy/local-e2e/` — full stack entry point

Ordered entry point for an **unmocked** local pass of the zkCoins stack
(postgres, bitcoind regtest, nostr-relay, node, api) and the mandate §3
A-to-Z machine-evaluable assertions.

This directory is the **mechanism** the audit asked for: not a narrative that
the journey works, but scripts that hard-fail when a numbered assertion does
not hold.

Operator background: [`docs/local-stack.md`](../../docs/local-stack.md).  
Pass predicate: `docs-vectors/docs/implementation-mandate.md` §3.

## Layout

| Path | Role |
| --- | --- |
| `env.example.sh` | Every compose `${VAR:?}` pin + generator-only bootstrap secret path. Placeholders only. |
| `up.sh` | Preflight → BMF1 (`gen_bootstrap_manifest`) → `docker compose up` → health waits → regtest wallet + mature coinbase → node restart. |
| `journey.sh` / `journey.mjs` | A-to-Z hard pass/fail chain via `@zkcoins/sdk` (`file:../../../sdk`). |
| `down.sh` | `compose down`; `--wipe` also removes volumes. |
| `package.json` | Private journey deps (`@zkcoins/sdk` + noble/scure). |
| `data/` | Local-only BMF1 + bootstrap.priv (create yourself; never commit). |

## Ordered runbook

### 1. Environment

```bash
cp deploy/local-e2e/env.example.sh deploy/local-e2e/env.local.sh
# Edit env.local.sh:
#   - PUBLISHER_KEY          = $(openssl rand -hex 32)
#   - ZKCOINS_BOOTSTRAP_PUBKEY + matching privkey file (64 hex, mode 0600)
#   - ZKCOINS_EXPECTED_PARAMS_IDENTIFIER  (formula in docs/local-stack.md)
#   - ESPLORA_URL / ESPLORA_WS_URL         (operator Esplora; residual boot pin)
#   - ZKCOINS_BOOTSTRAP_OPERATOR_ID
# Never commit env.local.sh or data/*.priv

mkdir -p deploy/local-e2e/data
# Write bootstrap.priv (64 lowercase hex), chmod 0600
# Point ZKCOINS_BOOTSTRAP_PRIVKEY_FILE at it (default path in env.example.sh)

set -a && source deploy/local-e2e/env.local.sh && set +a
```

Regtest circuit digests are **tree-pinned** in `env.example.sh` from
`script-plonky2/tests/generated_circuit_digests.txt`. The params identifier
is **not** pinned in-tree: it includes *your* `ZKCOINS_BOOTSTRAP_PUBKEY`.

### 2. Start the stack

```bash
./deploy/local-e2e/up.sh
```

What `up.sh` does, fail-closed:

1. Checks docker compose + every required env (refuses `REPLACE_ME_*`).
2. Builds/signs BMF1 with `gen_bootstrap_manifest` if the host path is empty
   (secret only via `ZKCOINS_BOOTSTRAP_PRIVKEY_FILE` — never argv).
3. `docker compose up -d --build`.
4. Waits for health: postgres → bitcoind → nostr-relay → node `/health` →
   api `/health` (named timeouts; no silent continue).
5. Creates/loads `ZKCOINS_V1_BITCOIND_WALLET`, mines ~110 blocks for mature
   coinbase, restarts `node` so the publisher sees the funded wallet.

### 3. Journey

```bash
./deploy/local-e2e/journey.sh              # default: stages 1 + 2
./deploy/local-e2e/journey.sh --list
./deploy/local-e2e/journey.sh --stage 1 --stage 2
./deploy/local-e2e/journey.sh --stage 7    # named control (may be TODO)
```

Signing and key derivation use **`@zkcoins/sdk`** against the live api
(`http://127.0.0.1:8080`). The stack does not sign (custody boundary).

### 4. Stop

```bash
./deploy/local-e2e/down.sh          # keep volumes (proofs, DB, regtest chain)
./deploy/local-e2e/down.sh --wipe   # also remove named volumes
```

## Cold-start cost (honest)

| Step | Expectation |
| --- | --- |
| First **node** image build | Multi-stage Rust + Plonky2 circuits — **many minutes to hours** on a cold machine. Dominant cost. |
| First **api** image build | Multi-stage Rust + protoc — shorter than node, still cold-cache heavy. |
| Subsequent `up.sh` | Reuses images and volumes; still pays migrations + scanner connect + optional circuit warm. |
| `gen_bootstrap_manifest` | Fast if `target/release/…` already built; otherwise one release crate build. |
| Journey stage 2 (mint prove) | Real Plonky2 proof — can take minutes per transition on modest hardware. |

Do not treat a multi-hour first boot as a script bug.

## What each journey stage asserts

| Stage | Mandate §3 | Status in this tree |
| --- | --- | --- |
| **1** | `GET /v1/info` equals pinned `circuit_digests` (`C`, `C_balance`) and bounds | **Hard** — digests + `finality_confirmations=6`, `max_tx_*=8`, `max_rx_coins=4`, `max_account_assets=32`, `activation_height=0` |
| **2** | Alice mint → job `completed` → nullifier inscribed → §3.10 `completed` after 6 blocks → balance `1_000_000_000` | **Hard driver** — entrust bundle, mint, SDK `refuseOrSignAndSubmit` (awaiting_signature recompute), mine, `/v1/chain/nullifier` + inscriptions, pull + parse balances |
| **2b** | Carol EUR-Demo token-standard-2 genesis + Alice receive; two-asset map | **TODO skeleton** — needs non-self mint delivery |
| **3–4** | Alice fee-less send to Bob (case (c)); publisher half-agg + inscription; Alice balance `999_750_000` | **Partial**: fee_address **negative** control is hard; positive send is **TODO** (Nostr/Blossom delivery gap) |
| **5** | Bob receive fold → balance `250_000` | **TODO skeleton** (depends on 3–4) |
| **6** | Confirmation link reports §3.10 `completed` for the payment | **TODO skeleton** for payment; mint §3.10 already checked in stage 2 |
| **7** | Reorg control N-09 | **TODO skeleton** |
| **8** | Recovery control Req 6 | **TODO skeleton** |
| **9** | Portability control Req 10 | **TODO skeleton** |
| **10** | Attestation control Req 9(b) | **TODO skeleton** (challenge surface probed) |
| **11** | Grant control Req 9(c) | **TODO skeleton** (challenge surface probed) |

Default `journey.sh` runs **1 + 2 only**, so a green default run does **not**
claim the full A-to-Z suite. Requesting a TODO stage exits non-zero with a
named message — never a silent pass.

## Fixtures (mandate §3)

- Mnemonic: BIP-39 V.2-ext  
  `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- Alice `account' = 0`, Bob `1`, Carol `2`
- Asset: `USD-Demo`, `decimals = 2`, `issuance_version = 1`, supply `1_000_000_000`
- Fee-less (D9): no fee coin; send with `fee_address` is rejected

## Fail-closed policy

- Missing env / placeholder → abort before compose parse or at `up.sh` preflight.
- BMF1 generation failure → no compose up.
- Health wait timeout → abort with service name and log hint.
- Journey: first failed assertion → exit 1 with `journey FAIL [stage N]: …`.
- No `|| true` on real errors. No protocol mocks.

## Known stack gaps (not hidden by these scripts)

See `docs/local-stack.md` “Gaps / open items”. Material to journey completeness:

1. Esplora not bundled (residual boot + node `/health/ready`).
2. Nostr delivery client not fully wired into send/receive (blocks stages 3–6, 2b).
3. Recipient `IVPK` / Invoice off REST inventory — wallet must supply delivery credentials.
4. Kernel operational-bundle store is process-local (lost on node restart).
5. Empty `ZKCOINS_BLOSSOM_ALLOWED_OPS` → uploads 403 (set op pubkeys when delivery is live).

## Verification (syntax)

```bash
bash -n deploy/local-e2e/up.sh
bash -n deploy/local-e2e/journey.sh
bash -n deploy/local-e2e/down.sh
bash -n deploy/local-e2e/env.example.sh
# if available:
shellcheck deploy/local-e2e/*.sh
```

A real stack start is the orchestrator’s job after these files land.
