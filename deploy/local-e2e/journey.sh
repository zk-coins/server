#!/usr/bin/env bash
# journey.sh — launch the A-to-Z hard pass/fail suite (mandate §3).
#
# Requires: stack already up (up.sh), env still sourced, Node.js ≥ 22,
# sibling ../sdk available via package.json file: dependency.
#
# Usage:
#   ./deploy/local-e2e/journey.sh                 # core steps 1–6
#   ./deploy/local-e2e/journey.sh --stage 1       # single stage
#   ./deploy/local-e2e/journey.sh --stage 7       # reorg control (may be TODO)
#   ./deploy/local-e2e/journey.sh --list           # list stages

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

die() {
  echo "journey.sh: ERROR: $*" >&2
  exit 1
}

log() {
  echo "journey.sh: $*" >&2
}

command -v node >/dev/null 2>&1 || die "required command not found: node (need ≥ 22)"
command -v npm >/dev/null 2>&1 || die "required command not found: npm"

NODE_MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if (( NODE_MAJOR < 22 )); then
  die "Node.js ≥ 22 required (got $(node -v))"
fi

export ZKCOINS_API_URL="${ZKCOINS_API_URL:-http://127.0.0.1:8080}"
export ZKCOINS_NODE_URL="${ZKCOINS_NODE_URL:-http://127.0.0.1:4242}"
export COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/compose.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zkcoins-local}"
export ZKCOINS_V1_BITCOIND_WALLET="${ZKCOINS_V1_BITCOIND_WALLET:-zkcoins}"

# Pin expected regtest digests if not already in env (same as env.example.sh).
export ZKCOINS_CIRCUIT_DIGEST_C="${ZKCOINS_CIRCUIT_DIGEST_C:-9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352}"
export ZKCOINS_CIRCUIT_DIGEST_C_BALANCE="${ZKCOINS_CIRCUIT_DIGEST_C_BALANCE:-bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d}"

[[ -d "${REPO_ROOT}/../sdk" ]] \
  || die "sibling sdk checkout missing at ${REPO_ROOT}/../sdk (file: dependency)"

cd "${SCRIPT_DIR}"

if [[ ! -d node_modules/@zkcoins/sdk ]]; then
  log "installing journey dependencies (file: ../../../sdk)…"
  npm install --no-fund --no-audit \
    || die "npm install failed in deploy/local-e2e"
fi

exec node "${SCRIPT_DIR}/journey.mjs" "$@"
