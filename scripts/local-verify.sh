#!/usr/bin/env bash
# Local-First hermetic node+shared suite. Same isolation and
# selection as the heavy CI job, without llvm-cov.
set -euo pipefail
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:${HOME}/.orbstack/bin:${PATH}"
cd "$(dirname "$0")/.."

export PUBLISHER_KEY="${PUBLISHER_KEY:-0000000000000000000000000000000000000000000000000000000000000001}"
export IS_MAINNET="${IS_MAINNET:-false}"
export ESPLORA_URL="${ESPLORA_URL:-http://127.0.0.1:1/api}"
export ESPLORA_WS_URL="${ESPLORA_WS_URL:-ws://127.0.0.1:1/api/v1/ws}"
export USERNAME_DOMAIN="${USERNAME_DOMAIN:-test.zkcoins.local}"

echo "local-verify: nextest node+shared (not api_remote) PUBLISHER_KEY=set"
exec cargo nextest run -p node -p shared --all-features --test-threads 8 \
  -E 'not binary(api_remote)'
