#!/usr/bin/env bash
# up.sh — ordered local-e2e stack start (fail-closed at every stage).
#
# Prerequisites: env sourced (see env.example.sh), Docker Compose v2, cargo
# (only if gen_bootstrap_manifest is not already built).
#
# Does not invent secrets. Does not silent-continue past health timeouts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

# ─── helpers ──────────────────────────────────────────────────────────────

die() {
  echo "up.sh: ERROR: $*" >&2
  exit 1
}

log() {
  echo "up.sh: $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    die "required env ${name} is unset or empty (see deploy/local-e2e/env.example.sh)"
  fi
  if [[ "${!name}" == REPLACE_ME_* ]]; then
    die "env ${name} still holds placeholder ${!name} — set a real value"
  fi
}

# Wait until the compose service reports Health=healthy. Named timeout —
# never silent continue. Optional third arg: progress note re-logged every 60s
# (used for node cold-start circuit construction so the wait is not mistaken
# for a hang).
wait_healthy() {
  local service="$1"
  local timeout_s="$2"
  local progress_note="${3:-}"
  local start now elapsed cid health last_progress=0
  start="$(date +%s)"
  log "waiting for service '${service}' healthy (timeout ${timeout_s}s)…"
  if [[ -n "${progress_note}" ]]; then
    log "${progress_note}"
  fi
  while true; do
    now="$(date +%s)"
    elapsed=$((now - start))
    if (( elapsed > timeout_s )); then
      die "timeout after ${timeout_s}s waiting for service '${service}' healthy — inspect: docker compose -f ${COMPOSE_FILE} logs ${service}"
    fi
    health="unknown"
    cid="$(docker compose -f "${COMPOSE_FILE}" ps -q "${service}" 2>/dev/null | head -n 1 || true)"
    if [[ -n "${cid}" ]]; then
      health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${cid}" 2>/dev/null || echo missing)"
      if [[ "${health}" == "healthy" ]]; then
        log "service '${service}' is healthy (${elapsed}s)"
        return 0
      fi
      if [[ "${health}" == "unhealthy" ]]; then
        die "service '${service}' is unhealthy — inspect: docker compose -f ${COMPOSE_FILE} logs ${service}"
      fi
    fi
    # Periodic progress — multi-minute cold starts must not look hung.
    if (( elapsed - last_progress >= 60 )); then
      log "still waiting for '${service}' (${elapsed}s / ${timeout_s}s, health=${health})…"
      if [[ -n "${progress_note}" ]]; then
        log "  note: ${progress_note}"
      fi
      last_progress=$elapsed
    fi
    sleep 2
  done
}

wait_http_ok() {
  local name="$1"
  local url="$2"
  local timeout_s="$3"
  local expect_body="${4:-}"
  local start now elapsed code body
  start="$(date +%s)"
  log "waiting for HTTP ${name} at ${url} (timeout ${timeout_s}s)…"
  while true; do
    now="$(date +%s)"
    elapsed=$((now - start))
    if (( elapsed > timeout_s )); then
      die "timeout after ${timeout_s}s waiting for ${name} (${url}) — stack is not ready"
    fi
    code="000"
    body=""
    if body="$(curl -fsS --max-time 5 "${url}" 2>/dev/null)"; then
      code="200"
    else
      code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${url}" 2>/dev/null || echo 000)"
    fi
    if [[ "${code}" == "200" ]]; then
      if [[ -n "${expect_body}" && "${body}" != "${expect_body}" ]]; then
        sleep 2
        continue
      fi
      log "${name} is up (${elapsed}s)"
      return 0
    fi
    sleep 2
  done
}

# ─── preflight ────────────────────────────────────────────────────────────

require_cmd docker
require_cmd curl
require_cmd cargo
require_cmd date

docker compose version >/dev/null 2>&1 \
  || die "docker compose (v2) is required"

export COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/compose.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zkcoins-local}"
[[ -f "${COMPOSE_FILE}" ]] || die "compose file not found: ${COMPOSE_FILE}"

# Non-fatal: cold §1.7.9 circuit construction (C + C_balance) OOMs under a
# lean Docker VM. Observed exit 137 / OOMKilled=true at ~15.6 GiB. Exact
# threshold is build-dependent — warn, do not hard-abort.
warn_docker_memory_if_low() {
  local total_bytes total_gib
  total_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
  if [[ -z "${total_bytes}" || "${total_bytes}" == "0" ]]; then
    log "WARNING: could not read Docker Total Memory — ensure the Docker VM has ≥ 24 GiB (see deploy/local-e2e/README.md Prerequisites → Memory)"
    return 0
  fi
  total_gib=$((total_bytes / 1024 / 1024 / 1024))
  if (( total_gib < 20 )); then
    log "WARNING: Docker VM reports ~${total_gib} GiB Total Memory."
    log "WARNING: cold-start circuit construction needs well more than 16 GiB (OOM observed at 15.6 GiB)."
    log "WARNING: assign ≥ 24 GiB to the Docker VM (OrbStack: VM memory; Docker Desktop: Resources → Memory), then restart the VM."
    log "WARNING: details: deploy/local-e2e/README.md Prerequisites → Memory"
  fi
}
warn_docker_memory_if_low

# Every ${VAR:?} pin from compose.yaml (host-supplied).
require_env PUBLISHER_KEY
require_env USERNAME_DOMAIN
require_env ESPLORA_URL
require_env ESPLORA_WS_URL
require_env ZKCOINS_CIRCUIT_DIGEST_C
require_env ZKCOINS_CIRCUIT_DIGEST_C_BALANCE
require_env ZKCOINS_BOOTSTRAP_PUBKEY
require_env ZKCOINS_EXPECTED_PARAMS_IDENTIFIER
require_env ZKCOINS_V1_BOOTSTRAP_MANIFEST_HOST_PATH
require_env ZKCOINS_V1_BITCOIND_WALLET
require_env ZKCOINS_V1_FEE_RATE_SAT_PER_VB
require_env ZKCOINS_V1_REVEAL_OUTPUT_SATS
require_env ZKCOINS_RELAY_URL
require_env ZKCOINS_BLOSSOM_URL
require_env ZKCOINS_MAX_BLOB_BYTES
require_env ZKCOINS_KERNEL_PARTS
require_env ZKCOINS_PUBLISH_BATCH_ETA_SECS
require_env KERNEL_GRPC_ADDR
require_env ZKCOINS_FEATURES
require_env ZKCOINS_BLOSSOM_MAX_BLOB_BYTES

# Generator-only material (not in compose ${…:?}, but required to produce BMF1).
require_env ZKCOINS_BOOTSTRAP_PRIVKEY_FILE
require_env ZKCOINS_BOOTSTRAP_OPERATOR_ID

[[ -f "${ZKCOINS_BOOTSTRAP_PRIVKEY_FILE}" ]] \
  || die "bootstrap privkey file missing: ${ZKCOINS_BOOTSTRAP_PRIVKEY_FILE} (create with 64 lowercase hex, mode 0600)"

# Sibling api build context.
[[ -f "${REPO_ROOT}/../api/Dockerfile" ]] \
  || die "sibling api Dockerfile not found at ${REPO_ROOT}/../api/Dockerfile (compose build.context: ../api)"

# ─── BMF1 artifact ────────────────────────────────────────────────────────

MANIFEST_HOST="${ZKCOINS_V1_BOOTSTRAP_MANIFEST_HOST_PATH}"
MANIFEST_DIR="$(dirname "${MANIFEST_HOST}")"
mkdir -p "${MANIFEST_DIR}"

if [[ -f "${MANIFEST_HOST}" ]]; then
  log "BMF1 already present at ${MANIFEST_HOST} — reusing (delete to regenerate)"
else
  log "generating signed BMF1 via gen_bootstrap_manifest → ${MANIFEST_HOST}"
  GEN_BIN="${REPO_ROOT}/target/release/gen_bootstrap_manifest"
  if [[ ! -x "${GEN_BIN}" ]]; then
    log "building gen_bootstrap_manifest (release)…"
    cargo build --release -p node --bin gen_bootstrap_manifest \
      || die "cargo build of gen_bootstrap_manifest failed"
  fi
  [[ -x "${GEN_BIN}" ]] || die "gen_bootstrap_manifest binary missing after build: ${GEN_BIN}"

  NOW="$(date +%s)"
  EXPIRES="$((NOW + 31536000))"
  SEED_RELAY="${ZKCOINS_RELAY_URL}"
  BLOB_STORE="${ZKCOINS_BLOSSOM_URL}"

  # Secret only via env/file — never argv.
  # Prefer file form (already required above).
  export ZKCOINS_BOOTSTRAP_PRIVKEY_FILE
  # Ensure the env form is not also set (tool refuses both).
  unset ZKCOINS_BOOTSTRAP_PRIVKEY || true

  if ! "${GEN_BIN}" \
    --output "${MANIFEST_HOST}" \
    --network regtest \
    --bootstrap-pubkey "${ZKCOINS_BOOTSTRAP_PUBKEY}" \
    --seed-relay "${SEED_RELAY}" \
    --blob-store "${BLOB_STORE}" \
    --operator-id "${ZKCOINS_BOOTSTRAP_OPERATOR_ID}" \
    --issued-at "${NOW}" \
    --expires-at "${EXPIRES}"; then
    die "gen_bootstrap_manifest failed — refusing to start stack without a valid BMF1"
  fi
  [[ -f "${MANIFEST_HOST}" ]] || die "gen_bootstrap_manifest reported success but ${MANIFEST_HOST} is missing"
  log "BMF1 written (${MANIFEST_HOST})"
fi

# ─── compose up ───────────────────────────────────────────────────────────

log "docker compose up -d --build (first node image build can take a long time)…"
docker compose -f "${COMPOSE_FILE}" up -d --build \
  || die "docker compose up failed"

# Dependency order: infra → node → api. depends_on already gates node/api,
# but we still wait explicitly with named timeouts.

wait_healthy "postgres" 120
wait_healthy "bitcoind" 120
wait_healthy "nostr-relay" 120

# Node cold start: §1.7.9 circuit construction (C + C_balance, full Plonky2
# recursion) runs before /health is served — often many minutes on a cold
# machine. 20 min deadline; still fail-closed with compose-logs hint after.
# Progress is re-logged every 60s so a waiting operator does not assume a hang.
NODE_HEALTH_TIMEOUT_S=1200
NODE_COLD_START_NOTE="cold-start circuit construction (C / C_balance) may take many minutes; /health is served only after circuits stand — not a hang"
wait_healthy "node" "${NODE_HEALTH_TIMEOUT_S}" "${NODE_COLD_START_NOTE}"
wait_http_ok "node /health" "http://127.0.0.1:4242/health" 120 "ok"

wait_healthy "api" 300
wait_http_ok "api /health" "http://127.0.0.1:8080/health" 120 "ok"

# ─── regtest wallet + mature coinbase for publisher inscriptions ──────────

WALLET="${ZKCOINS_V1_BITCOIND_WALLET}"
BTC_CLI=(docker compose -f "${COMPOSE_FILE}" exec -T bitcoind
  bitcoin-cli -regtest -datadir=/home/bitcoin/.bitcoin)

log "ensuring bitcoind wallet '${WALLET}' exists…"
# createwallet is not fully idempotent across Core versions; load if present.
if ! "${BTC_CLI[@]}" -rpcwallet="${WALLET}" getwalletinfo >/dev/null 2>&1; then
  if ! "${BTC_CLI[@]}" loadwallet "${WALLET}" >/dev/null 2>&1; then
    "${BTC_CLI[@]}" createwallet "${WALLET}" \
      || die "failed to create bitcoind wallet '${WALLET}'"
  fi
fi

# Confirm wallet answers RPC.
"${BTC_CLI[@]}" -rpcwallet="${WALLET}" getwalletinfo >/dev/null \
  || die "wallet '${WALLET}' not usable after create/load"

ADDR="$("${BTC_CLI[@]}" -rpcwallet="${WALLET}" getnewaddress | tr -d '\r\n')"
[[ -n "${ADDR}" ]] || die "getnewaddress returned empty"

# Mine enough for coinbase maturity (100) plus headroom for inscription fees.
MINE_COUNT="${ZKCOINS_REGTEST_MINE_BLOCKS:-110}"
log "mining ${MINE_COUNT} regtest blocks to ${ADDR} (coinbase maturity + fees)…"
"${BTC_CLI[@]}" -rpcwallet="${WALLET}" generatetoaddress "${MINE_COUNT}" "${ADDR}" >/dev/null \
  || die "generatetoaddress failed"

BAL="$("${BTC_CLI[@]}" -rpcwallet="${WALLET}" getbalance | tr -d '\r\n')"
log "publisher wallet balance: ${BAL} BTC"
# Fail-closed if still zero after mining (wallet mismatch / immature).
if [[ "${BAL}" == "0" || "${BAL}" == "0.00000000" ]]; then
  die "publisher wallet balance is zero after mining — cannot fund inscriptions"
fi

# Node may have started before the wallet existed; restart so publish path sees it.
log "restarting node so publisher binds the funded wallet…"
docker compose -f "${COMPOSE_FILE}" restart node \
  || die "docker compose restart node failed"
# Same generous deadline: process-local circuit state is lost on restart.
wait_healthy "node" "${NODE_HEALTH_TIMEOUT_S}" \
  "post-restart circuit rebuild may take many minutes; /health waits until circuits stand"
wait_http_ok "node /health (post-restart)" "http://127.0.0.1:4242/health" 120 "ok"
wait_healthy "api" 300
wait_http_ok "api /health (post-restart)" "http://127.0.0.1:8080/health" 120 "ok"

log "stack is up."
log "  api:  http://127.0.0.1:8080/health"
log "  node: http://127.0.0.1:4242/health"
log "  next: ./deploy/local-e2e/journey.sh"
exit 0
