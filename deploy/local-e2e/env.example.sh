#!/usr/bin/env bash
# env.example.sh — template for every compose `${VAR:?…}` pin.
#
# Copy, fill, then source under **bash** before up.sh (not zsh — see guard):
#
#   cp deploy/local-e2e/env.example.sh deploy/local-e2e/env.local.sh
#   # edit env.local.sh — never commit secrets
#   bash -c 'set -a && source deploy/local-e2e/env.local.sh && set +a && ./deploy/local-e2e/up.sh'
#
# Or stay inside a bash shell:
#
#   bash
#   set -a && source deploy/local-e2e/env.local.sh && set +a
#   ./deploy/local-e2e/up.sh
#
# Placeholders use REPLACE_ME_* so a half-filled file fails loudly.
# Never put real secrets in this file or any committed path.
#
# Full operator context: docs/local-stack.md

# Bash-only: path derivation uses ${BASH_SOURCE[0]}. Sourcing under zsh leaves
# that unset, yields an empty _SCRIPT_DIR, and points COMPOSE_FILE at the wrong
# tree. Refuse loudly — never silent wrong paths.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "env.example.sh / env.local.sh: ERROR: must be sourced or run under bash (not zsh/sh)." >&2
  echo "  source under bash:" >&2
  echo "    bash -c 'set -a && source deploy/local-e2e/env.local.sh && set +a && ./deploy/local-e2e/up.sh'" >&2
  echo "  or run the scripts directly (they have #!/usr/bin/env bash)." >&2
  return 1 2>/dev/null || exit 1
fi

set -euo pipefail

# ─── Crypto secrets (operator material — never invent defaults) ───────────

# 32-byte secp256k1 secret as 64 lowercase hex.
# Generate:  openssl rand -hex 32
export PUBLISHER_KEY="REPLACE_ME_PUBLISHER_KEY_64_LOWERCASE_HEX"

# 32-byte secp256k1 secret as 64 lowercase hex, for node2's identity — DISTINCT from
# PUBLISHER_KEY above (two nodes must not share a publisher key).
# Generate:  openssl rand -hex 32
export PUBLISHER_KEY_2="REPLACE_ME_PUBLISHER_KEY_2_64_LOWERCASE_HEX"

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
# node-container-reachable Blossom base: the node and api are separate
# compose services: 127.0.0.1 inside the node container is the node
# itself, not the api container. "api" is the compose DNS name for the
# api service, which serves Blossom on :8080 in-network (compose.yaml).
export ZKCOINS_BLOSSOM_URL="http://api:8080/"
# node2 Blossom base (compose-internal DNS to api2). Required by node2's
# ZKCOINS_BLOSSOM_URL env pin (compose ${ZKCOINS_BLOSSOM_URL_2:?…}).
export ZKCOINS_BLOSSOM_URL_2="http://api2:8080/"
export ZKCOINS_MAX_BLOB_BYTES="1048576"
export ZKCOINS_KERNEL_PARTS="scanner,prover,publisher"
# Required when KERNEL_PARTS includes publisher — no invented default.
export ZKCOINS_PUBLISH_BATCH_ETA_SECS="60"
export KERNEL_GRPC_ADDR="0.0.0.0:50051"

# ─── Publish path (bitcoind wallet must match up.sh createwallet) ──────────
export ZKCOINS_V1_BITCOIND_WALLET="zkcoins"
# node2's own funded bitcoind wallet on the SHARED bitcoind (separate wallet name from
# ZKCOINS_V1_BITCOIND_WALLET above — must not collide, up.sh creates/funds both).
export ZKCOINS_V1_BITCOIND_WALLET_2="zkcoins2"
export ZKCOINS_V1_FEE_RATE_SAT_PER_VB="2"
export ZKCOINS_V1_REVEAL_OUTPUT_SATS="1000"

# ─── api (compose service) ────────────────────────────────────────────────
export ZKCOINS_FEATURES="wallet,explorer"
# Host-side wallets dial http://127.0.0.1:8080 → chan_bind host "127.0.0.1:8080".
export ZKCOINS_PUBLIC_HOST="127.0.0.1:8080"
export ZKCOINS_BLOSSOM_MAX_BLOB_BYTES="1048576"
# Alice (account'=0), Bob (account'=1), and Carol (account'=2) op_pubkey,
# derived from the journey's fixed V.2-ext test mnemonic via
# m/1798'/<account>'/2' (same derivation as journey.mjs buildAccount's
# `op`/`opPubkey`). All three must be listed: this one shared node holds all
# three wallets' operational bundles in this local-stack topology. Carol is
# the token-standard-2 issuer in journey stage 2b (non-owner emission →
# mesh delivery → Blossom upload). Empty allow-list = surface up, every
# Blossom upload 403 (docs/local-stack.md gap 8).
#
# Changing ZKCOINS_BLOSSOM_URL or ZKCOINS_BLOSSOM_ALLOWED_OPS (node-service
# env) requires recreating the node container, not just a process restart:
#   docker compose up -d --force-recreate node
# The node reads these env vars only at container creation.
export ZKCOINS_BLOSSOM_ALLOWED_OPS="6424b41eea59c6a3aa6169b802c96ff5194962d3bf5f941130e4ebc86de3b485,d91ad56adb703a1b31c40c7cd1d3c42d075c5bcd1c03d02e5e096856b6570f25,43b816d0cbf5a71f775678c267318441e9a98178d033a59a39832adb766a7c8e"

# ─── Optional / journey ───────────────────────────────────────────────────
export RUST_LOG="${RUST_LOG:-info}"

# Public REST base used by journey.sh / journey.mjs (host → published ports).
export ZKCOINS_API_URL="${ZKCOINS_API_URL:-http://127.0.0.1:8080}"
export ZKCOINS_NODE_URL="${ZKCOINS_NODE_URL:-http://127.0.0.1:4242}"

# Public REST base / node URL for node2 (host → published ports 8081 / 4243).
export ZKCOINS_API_URL_2="${ZKCOINS_API_URL_2:-http://127.0.0.1:8081}"
export ZKCOINS_NODE_URL_2="${ZKCOINS_NODE_URL_2:-http://127.0.0.1:4243}"

# Compose project file (repo root). up.sh / down.sh honour this.
export COMPOSE_FILE="${COMPOSE_FILE:-${_REPO_ROOT}/compose.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zkcoins-local}"

unset _SCRIPT_DIR _REPO_ROOT
