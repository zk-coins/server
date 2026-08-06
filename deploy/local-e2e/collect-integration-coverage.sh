#!/usr/bin/env bash
# Build and run the real local journey under LLVM source-based coverage,
# flush both node processes, and merge the result with unit-test LCOV data.
#
# This script intentionally performs the expensive work; do not invoke it for
# a quick compile check. Before running it, source env.example.sh (with every
# placeholder replaced) exactly as for up.sh.
# Prerequisites: Docker Compose v2, Node.js/npm as required by journey.sh,
# cargo-llvm-cov + cargo-nextest, the pinned Rust llvm-tools component, and the
# standalone LCOV toolkit (`brew install lcov` on the intended macOS host).
#
# By default the unit suite is run as part of this pipeline, so unit.lcov and
# integration.lcov use the same checkout and ignore policy. To reuse an LCOV
# file produced by the documented cargo-llvm-cov command instead, set both:
#
#   ZKCOINS_REUSE_UNIT_LCOV=1
#   ZKCOINS_UNIT_LCOV=/absolute/path/to/unit.lcov
#
# A reused file must have been produced from this checkout with the IGNORE
# expression below; the script deliberately has no silent "unit data absent"
# fallback.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BASE_COMPOSE="${REPO_ROOT}/compose.yaml"
COVERAGE_COMPOSE="${SCRIPT_DIR}/compose.coverage.yaml"
COVERAGE_BASE="${SCRIPT_DIR}/coverage-data"
IGNORE='_tests\.rs$|test_db\.rs$|bin/.*\.rs$|main\.rs$|lib\.rs$|program-plonky2/|script-plonky2/'
cd "${REPO_ROOT}"

# The Docker builder and host tools must resolve the same pinned
# nightly-2026-06-18 LLVM profile format. Override LLVM_TOOLS_DIR only when the
# host triple differs; do not point it at an unrelated LLVM installation.
LLVM_TOOLS_DIR="${LLVM_TOOLS_DIR:-${HOME}/.rustup/toolchains/nightly-2026-06-18-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin}"
LLVM_PROFDATA="${LLVM_TOOLS_DIR}/llvm-profdata"
LLVM_COV="${LLVM_TOOLS_DIR}/llvm-cov"

die() {
  echo "collect-integration-coverage.sh: ERROR: $*" >&2
  exit 1
}

log() {
  echo "collect-integration-coverage.sh: $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_file() {
  [[ -f "$1" ]] || die "required file not found: $1"
}

require_cmd docker
require_cmd cargo
require_cmd lcov
require_cmd cmp
require_cmd find
require_cmd grep
require_cmd mktemp
[[ -x "${LLVM_PROFDATA}" ]] || die "llvm-profdata not executable: ${LLVM_PROFDATA}"
[[ -x "${LLVM_COV}" ]] || die "llvm-cov not executable: ${LLVM_COV}"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
require_file "${BASE_COMPOSE}"
require_file "${COVERAGE_COMPOSE}"

mkdir -p "${COVERAGE_BASE}"
RUN_DIR="$(mktemp -d "${COVERAGE_BASE}/run-XXXXXXXX")"
mkdir -p "${RUN_DIR}/node1" "${RUN_DIR}/node2"
export ZKCOINS_COVERAGE_DATA_DIR="${RUN_DIR}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zkcoins-local-coverage}"

# up.sh and journey.sh accept only one literal -f argument. Compose therefore
# resolves both source files into one private temporary file which those
# existing lifecycle scripts can consume. `docker compose config` may expand
# secret-valued environment entries, so the file is created under umask 077
# and is always deleted by the EXIT trap.
umask 077
MERGED_COMPOSE="$(mktemp "${TMPDIR:-/tmp}/zkcoins-compose-coverage.XXXXXXXX")"
STACK_MAY_EXIST=0
NODES_STOPPED=0

cleanup() {
  local status="$1"
  set +e
  if (( STACK_MAY_EXIST == 1 && NODES_STOPPED == 0 )); then
    log "stopping coverage nodes after an interrupted/failed run"
    docker compose -f "${MERGED_COMPOSE}" stop -t 60 node node2 >/dev/null 2>&1
  fi
  rm -f "${MERGED_COMPOSE}"
  exit "${status}"
}
trap 'cleanup $?' EXIT

COMPOSE=(docker compose -f "${BASE_COMPOSE}" -f "${COVERAGE_COMPOSE}")

log "coverage artifacts will be written to ${RUN_DIR}"
log "building the instrumented node and node2 images"
"${COMPOSE[@]}" build node node2 \
  || die "instrumented Docker image build failed"

"${COMPOSE[@]}" config >"${MERGED_COMPOSE}" \
  || die "could not merge base and coverage Compose files"
[[ -s "${MERGED_COMPOSE}" ]] || die "merged Compose file is empty"
grep -Fq 'LLVM_PROFILE_FILE: /cov/node1/' "${MERGED_COMPOSE}" \
  || die "merged Compose file lost node's coverage environment"
grep -Fq "${RUN_DIR}/node2" "${MERGED_COMPOSE}" \
  || die "merged Compose file lost node2's coverage bind mount"
export COMPOSE_FILE="${MERGED_COMPOSE}"

# Reuse all ordered BMF1 generation, dependency health checks, wallet funding,
# and node2 setup from the canonical stack launcher. Its second --build is a
# cache hit for the images explicitly built above.
STACK_MAY_EXIST=1
log "starting the coverage stack through deploy/local-e2e/up.sh"
bash "${SCRIPT_DIR}/up.sh" \
  || die "coverage stack startup failed"

NODE1_CID="$(docker compose -f "${MERGED_COMPOSE}" ps -q node)"
NODE2_CID="$(docker compose -f "${MERGED_COMPOSE}" ps -q node2)"
[[ -n "${NODE1_CID}" ]] || die "could not resolve the node container id"
[[ -n "${NODE2_CID}" ]] || die "could not resolve the node2 container id"

# "1 through 9" includes the catalogued 2b stage between 2 and 3. Stages 3
# and 4 intentionally share one implementation; journey.mjs suppresses the
# duplicate call while retaining both stage assertions.
log "running journey stages 1, 2, 2b, 3, 4, 5, 6, 7, 8, and 9"
bash "${SCRIPT_DIR}/journey.sh" \
  --stage 1 \
  --stage 2 \
  --stage 2b \
  --stage 3 \
  --stage 4 \
  --stage 5 \
  --stage 6 \
  --stage 7 \
  --stage 8 \
  --stage 9 \
  || die "journey failed; coverage nodes will still be stopped by the EXIT trap"

log "sending SIGTERM to node and node2 so their coverage handlers flush"
docker compose -f "${MERGED_COMPOSE}" stop -t 60 node node2 \
  || die "failed to stop coverage nodes"
NODES_STOPPED=1

profiles_ready() {
  [[ -n "$(find "${RUN_DIR}/node1" -type f -name '*.profraw' -size +0c -print -quit)" ]] &&
    [[ -n "$(find "${RUN_DIR}/node2" -type f -name '*.profraw' -size +0c -print -quit)" ]]
}

log "waiting up to 30 seconds for non-empty node1 and node2 .profraw files"
PROFILE_WAIT_START="${SECONDS}"
until profiles_ready; do
  if (( SECONDS - PROFILE_WAIT_START >= 30 )); then
    die "timed out waiting for .profraw files under ${RUN_DIR}/{node1,node2}"
  fi
  sleep 1
done

PROFRAW_FILES=()
while IFS= read -r profile; do
  PROFRAW_FILES+=("${profile}")
done < <(find "${RUN_DIR}/node1" "${RUN_DIR}/node2" -type f -name '*.profraw' -size +0c -print | sort)
(( ${#PROFRAW_FILES[@]} > 0 )) || die "profile discovery returned no files"

INTEGRATION_PROFDATA="${RUN_DIR}/integration.profdata"
log "merging ${#PROFRAW_FILES[@]} raw profiles"
"${LLVM_PROFDATA}" merge -sparse "${PROFRAW_FILES[@]}" -o "${INTEGRATION_PROFDATA}" \
  || die "llvm-profdata merge failed"
[[ -s "${INTEGRATION_PROFDATA}" ]] || die "integration.profdata is empty"

# Extract both service binaries and prove byte identity before one is used as
# llvm-cov's object. This makes the profile/object hash invariant explicit:
# no locally rebuilt or merely similar binary is accepted.
NODE1_BINARY="${RUN_DIR}/zkcoins-node.node1"
NODE2_BINARY="${RUN_DIR}/zkcoins-node.node2"
docker cp "${NODE1_CID}:/usr/local/bin/zkcoins-node" "${NODE1_BINARY}" \
  || die "failed to copy the instrumented node binary"
docker cp "${NODE2_CID}:/usr/local/bin/zkcoins-node" "${NODE2_BINARY}" \
  || die "failed to copy the instrumented node2 binary"
[[ -s "${NODE1_BINARY}" ]] || die "copied node binary is empty"
[[ -s "${NODE2_BINARY}" ]] || die "copied node2 binary is empty"
cmp -s "${NODE1_BINARY}" "${NODE2_BINARY}" \
  || die "node and node2 instrumented binaries differ; refusing a hash-unsafe export"

INTEGRATION_LCOV="${RUN_DIR}/integration.lcov"
log "exporting integration LCOV with Docker /app paths mapped to this checkout"
"${LLVM_COV}" export \
  --format=lcov \
  --instr-profile="${INTEGRATION_PROFDATA}" \
  -path-equivalence="/app,${REPO_ROOT}" \
  --ignore-filename-regex="${IGNORE}" \
  "${NODE1_BINARY}" >"${INTEGRATION_LCOV}" \
  || die "llvm-cov integration export failed"
[[ -s "${INTEGRATION_LCOV}" ]] || die "integration.lcov is empty"

UNIT_LCOV="${ZKCOINS_UNIT_LCOV:-${RUN_DIR}/unit.lcov}"
REUSE_UNIT_LCOV="${ZKCOINS_REUSE_UNIT_LCOV:-0}"
case "${REUSE_UNIT_LCOV}" in
  0)
    log "running the unit-test coverage suite (same scope as the CI baseline)"
    RUSTFLAGS="--cfg coverage_nightly" cargo llvm-cov nextest \
      --release \
      -p node \
      -p shared \
      --all-features \
      --ignore-filename-regex "${IGNORE}" \
      --fail-under-lines 0 \
      --fail-under-functions 0 \
      --test-threads 8 \
      -E 'not binary(api_remote)' \
      || die "unit-test coverage run failed"
    RUSTFLAGS="--cfg coverage_nightly" cargo llvm-cov report \
      --release \
      --lcov \
      --output-path "${UNIT_LCOV}" \
      --ignore-filename-regex "${IGNORE}" \
      || die "unit LCOV export failed"
    ;;
  1)
    [[ -n "${ZKCOINS_UNIT_LCOV:-}" ]] \
      || die "ZKCOINS_REUSE_UNIT_LCOV=1 requires an explicit ZKCOINS_UNIT_LCOV"
    log "reusing caller-supplied unit LCOV: ${UNIT_LCOV}"
    ;;
  *)
    die "ZKCOINS_REUSE_UNIT_LCOV must be 0 or 1 (got ${REUSE_UNIT_LCOV})"
    ;;
esac
require_file "${UNIT_LCOV}"
[[ -s "${UNIT_LCOV}" ]] || die "unit LCOV is empty: ${UNIT_LCOV}"

# Host test binaries and the Linux integration binary are distinct objects, so
# their profdata cannot be merged safely. LCOV is the correct common layer.
# First restrict both inputs to node/ (the unit command also measures shared),
# then add line hit counts for identical SF paths. -path-equivalence above is
# what makes Docker's /app/node/... paths match the host checkout paths here.
UNIT_NODE_LCOV="${RUN_DIR}/unit-node.lcov"
INTEGRATION_NODE_LCOV="${RUN_DIR}/integration-node.lcov"
COMBINED_LCOV="${RUN_DIR}/combined.lcov"
grep -Fq "SF:${REPO_ROOT}/node/" "${UNIT_LCOV}" \
  || die "unit LCOV paths do not name this checkout's node crate"
grep -Fq "SF:${REPO_ROOT}/node/" "${INTEGRATION_LCOV}" \
  || die "integration path equivalence did not map /app to this checkout"
lcov --extract "${UNIT_LCOV}" "${REPO_ROOT}/node/*" --output-file "${UNIT_NODE_LCOV}" \
  || die "could not restrict unit LCOV to the node crate"
lcov --extract "${INTEGRATION_LCOV}" "${REPO_ROOT}/node/*" --output-file "${INTEGRATION_NODE_LCOV}" \
  || die "could not restrict integration LCOV to the node crate"
[[ -s "${UNIT_NODE_LCOV}" ]] || die "node-only unit LCOV is empty"
[[ -s "${INTEGRATION_NODE_LCOV}" ]] || die "node-only integration LCOV is empty"
lcov \
  --add-tracefile "${UNIT_NODE_LCOV}" \
  --add-tracefile "${INTEGRATION_NODE_LCOV}" \
  --output-file "${COMBINED_LCOV}" \
  || die "LCOV merge failed"
[[ -s "${COMBINED_LCOV}" ]] || die "combined.lcov is empty"

log "combined node line coverage"
lcov --summary "${COMBINED_LCOV}" \
  || die "could not summarize combined LCOV"
log "complete: ${COMBINED_LCOV}"
log "node services are stopped; the remaining local-e2e services stay running"
