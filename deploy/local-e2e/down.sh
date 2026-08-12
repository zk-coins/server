#!/usr/bin/env bash
# down.sh — stop the local-e2e stack.
#
# Usage:
#   ./deploy/local-e2e/down.sh           # stop containers; keep volumes
#   ./deploy/local-e2e/down.sh --wipe    # stop and remove volumes (proofs, DB, regtest, Blossom)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

die() {
  echo "down.sh: ERROR: $*" >&2
  exit 1
}

log() {
  echo "down.sh: $*" >&2
}

command -v docker >/dev/null 2>&1 || die "required command not found: docker"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) is required"

export COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/compose.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zkcoins-local}"
[[ -f "${COMPOSE_FILE}" ]] || die "compose file not found: ${COMPOSE_FILE}"

WIPE=0
for arg in "$@"; do
  case "${arg}" in
    --wipe|-v|--volumes)
      WIPE=1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: down.sh [--wipe]

  (default)  docker compose down          — stop containers; keep named volumes
  --wipe     docker compose down -v       — also remove volumes:
               postgres_data, node_data (/data/proofs), bitcoind_data,
               nostr_relay_data, api_blossom_data

Does not delete host-side BMF1 / bootstrap.priv under deploy/local-e2e/data/
unless you remove them yourself.
EOF
      exit 0
      ;;
    *)
      die "unknown argument: ${arg} (try --help)"
      ;;
  esac
done

if (( WIPE == 1 )); then
  log "stopping stack and removing volumes…"
  docker compose -f "${COMPOSE_FILE}" down -v \
    || die "docker compose down -v failed"
  log "volumes removed. Next up.sh must re-create the bitcoind wallet and re-mine."
else
  log "stopping stack (volumes preserved)…"
  docker compose -f "${COMPOSE_FILE}" down \
    || die "docker compose down failed"
  log "volumes kept. Use --wipe to drop postgres/node/bitcoind/nostr/blossom data."
fi

exit 0
