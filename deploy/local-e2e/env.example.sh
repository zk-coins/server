#!/usr/bin/env bash
# env.example.sh — template for every compose `${VAR:?…}` pin.
#
# Copy, fill, then source before up.sh:
#
#   cp deploy/local-e2e/env.example.sh deploy/local-e2e/env.local.sh
#   # edit env.local.sh — never commit secrets
#   set -a && source deploy/local-e2e/env.local.sh && set +a
#   ./deploy/local-e2e/up.sh
#
# Placeholders use REPLACE_ME_* so a half-filled file fails loudly.
# Never put real secrets in this file or any committed path.
#
# Full operator context: docs/local-stack.md

set -euo pipefail

# ─── Crypto secrets (operator material — never invent defaults) ───────────

# 32-byte secp256k1 secret as 64 lowercase hex.
# Generate:  openssl rand -hex 32
export PUBLISHER_KEY="REPLACE_ME_PUBLISHER_KEY_64_LOWERCASE_HEX"

# Username domain returned by residual /api/info surfaces.
export USERNAME_DOMAIN="local.zkcoins.test"

# ─── Residual Esplora (still required at node boot; Stage-3 scan is bitcoind) ─
# Operator-supplied HTTP + WS endpoints the *node container* can reach.
# No invented third-party URLs. Point at your Esplora for this regtest, or
# expect node /health/ready to stay non-ready while jobs still run on bitcoind.
export ESPLORA_URL="REPLACE_ME_ESPLORA_HTTP_BASE"
export ESPLORA_WS_URL="REPLACE_ME_ESPLORA_WS_URL"

# ─── §3.6 boot pins (regtest digests are tree-pinned) ─────────────────────
# Source: script-plonky2/tests/generated_circuit_digests.txt (drop 0x).
export ZKCOINS_CIRCUIT_DIGEST_C="9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352"
export ZKCOINS_CIRCUIT_DIGEST_C_BALANCE="bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d"

# BIP-340 x-only public key of the local-network bootstrap secret (64 hex).
# Must match the secret used to sign the BMF1 artifact below.
export ZKCOINS_BOOTSTRAP_PUBKEY="REPLACE_ME_BOOTSTRAP_PUBKEY_64_LOWERCASE_HEX_XONLY"

# SHA-256 of canonical NetworkParams encoding. Formula and python snippet:
#   docs/local-stack.md → "Computing ZKCOINS_EXPECTED_PARAMS_IDENTIFIER"
# Inputs: tag zkCoins/v1/regtest, digests above, activation_height=0,
#         bootstrap_pubkey (this network's pin).
export ZKCOINS_EXPECTED_PARAMS_IDENTIFIER="REPLACE_ME_PARAMS_IDENTIFIER_64_HEX"

# ─── §4.3 BootstrapManifest (BMF1) ────────────────────────────────────────
# Host path of the signed BMF1 file. up.sh generates it when missing, using
# gen_bootstrap_manifest + the secret file below.
# Prefer an absolute path.
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "${_SCRIPT_DIR}/../.." && pwd)"
export ZKCOINS_V1_BOOTSTRAP_MANIFEST_HOST_PATH="${_REPO_ROOT}/deploy/local-e2e/data/bootstrap.bmf1"

# Bootstrap *secret* for gen_bootstrap_manifest only (never mounted into node).
# File must contain exactly 64 lowercase hex characters, mode 0600.
# Generate a keypair offline; put the public form in ZKCOINS_BOOTSTRAP_PUBKEY.
export ZKCOINS_BOOTSTRAP_PRIVKEY_FILE="${_REPO_ROOT}/deploy/local-e2e/data/bootstrap.priv"

# Operator id(s) embedded in the BMF1 body (≥1 required by the generator).
# Local convention: use the same x-only key as ZKCOINS_BOOTSTRAP_PUBKEY, or
# another operator pubkey you control for this regtest network.
export ZKCOINS_BOOTSTRAP_OPERATOR_ID="REPLACE_ME_OPERATOR_ID_64_LOWERCASE_HEX_XONLY"

# ─── GetInfo operational pins ─────────────────────────────────────────────
# Compose-internal Nostr relay (host tools use ws://127.0.0.1:18080/).
export ZKCOINS_RELAY_URL="ws://nostr-relay:8080/"
# Advertised Blossom base (host-facing api is :8080).
export ZKCOINS_BLOSSOM_URL="http://127.0.0.1:8080/"
export ZKCOINS_MAX_BLOB_BYTES="1048576"
export ZKCOINS_KERNEL_PARTS="scanner,prover,publisher"
# Required when KERNEL_PARTS includes publisher — no invented default.
export ZKCOINS_PUBLISH_BATCH_ETA_SECS="60"
export KERNEL_GRPC_ADDR="0.0.0.0:50051"

# ─── Publish path (bitcoind wallet must match up.sh createwallet) ──────────
export ZKCOINS_V1_BITCOIND_WALLET="zkcoins"
export ZKCOINS_V1_FEE_RATE_SAT_PER_VB="2"
export ZKCOINS_V1_REVEAL_OUTPUT_SATS="1000"

# ─── api (compose service) ────────────────────────────────────────────────
export ZKCOINS_FEATURES="wallet,explorer"
# Host-side wallets dial http://127.0.0.1:8080 → chan_bind host "127.0.0.1:8080".
export ZKCOINS_PUBLIC_HOST="127.0.0.1:8080"
export ZKCOINS_BLOSSOM_MAX_BLOB_BYTES="1048576"
# Comma-separated op pubkeys allowed to upload Blossom blobs.
# Empty = surface up, every upload 403. Journey send/delivery needs real ops.
export ZKCOINS_BLOSSOM_ALLOWED_OPS=""

# ─── Optional / journey ───────────────────────────────────────────────────
export RUST_LOG="${RUST_LOG:-info}"

# Public REST base used by journey.sh / journey.mjs (host → published ports).
export ZKCOINS_API_URL="${ZKCOINS_API_URL:-http://127.0.0.1:8080}"
export ZKCOINS_NODE_URL="${ZKCOINS_NODE_URL:-http://127.0.0.1:4242}"

# Compose project file (repo root). up.sh / down.sh honour this.
export COMPOSE_FILE="${COMPOSE_FILE:-${_REPO_ROOT}/compose.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zkcoins-local}"

unset _SCRIPT_DIR _REPO_ROOT
