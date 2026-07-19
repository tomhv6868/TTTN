#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly ARTIFACT_ROOT="$PROJECT_ROOT/run_log/t3.3"
readonly SCRATCH_ROOT="${TMPDIR:-/tmp}"
readonly CONTRACT="$PROJECT_ROOT/config/cicids2017-label-join-contract.json"
readonly EXPORT_SCRIPT="$PROJECT_ROOT/scripts/export_t33_flow_shards.py"

BUILD_DIR=""
ATTEMPT_ROOT=""

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$BUILD_DIR" && "$BUILD_DIR" == "$SCRATCH_ROOT/"nids-t33-flow-export.* ]]; then
        rm -rf -- "$BUILD_DIR"
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

(($# == 0)) || die "usage: bash scripts/run_t33_flow_export_ubuntu.sh"
((EUID != 0)) || die "run as the normal Ubuntu user"
[[ "$PROJECT_ROOT" == "/mnt/hgfs/TTTN" ]] \
    || die "run from the approved VMware shared workspace: /mnt/hgfs/TTTN"

for command in bash cmake ctest date mktemp ninja python3 shellcheck tee; do
    command -v "$command" >/dev/null || die "missing required command: $command"
done

shellcheck --severity=error "$0"
[[ -f "$HOME/.local/nids-toolchain/env.sh" ]] || die "missing locked toolchain environment"

mkdir -p -- "$ARTIFACT_ROOT/attempts"
ATTEMPT_ROOT="$ARTIFACT_ROOT/attempts/ubuntu-flow-export-$(date -u +%Y%m%dT%H%M%S%NZ)"
[[ ! -e "$ATTEMPT_ROOT" ]] || die "attempt directory already exists: $ATTEMPT_ROOT"
mkdir -p -- "$ATTEMPT_ROOT"
BUILD_DIR="$(mktemp -d "$SCRATCH_ROOT/nids-t33-flow-export.XXXXXXXX")"

printf '[T3.3 export] stage=environment status=running log=%s\n' \
    "$ATTEMPT_ROOT/environment-verifier.log"
bash "$PROJECT_ROOT/scripts/setup_toolchain_ubuntu.sh" --verify \
    --receipt "$ATTEMPT_ROOT/environment-verifier.json" \
    2>&1 | tee "$ATTEMPT_ROOT/environment-verifier.log"

# shellcheck disable=SC1091
source "$HOME/.local/nids-toolchain/env.sh"

printf '[T3.3 export] stage=build status=running log=%s\n' "$ATTEMPT_ROOT/build.log"
cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON \
    -DNIDS_BUILD_DPDK=OFF \
    -DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF \
    2>&1 | tee "$ATTEMPT_ROOT/configure.log"
cmake --build "$BUILD_DIR" --parallel 2 \
    --target nids_t33_flow_export nids_t33_flow_export_test \
    2>&1 | tee "$ATTEMPT_ROOT/build.log"
ctest --test-dir "$BUILD_DIR" -R '^nids_dataset\.flow_export$' --output-on-failure \
    2>&1 | tee "$ATTEMPT_ROOT/ctest.log"
python3 -B -m unittest discover -s "$PROJECT_ROOT/tests" \
    -p 'test_t33*.py' -v \
    2>&1 | tee "$ATTEMPT_ROOT/python-tests.log"

CAPTURE_LIST="$BUILD_DIR/captures.txt"
python3 -B "$EXPORT_SCRIPT" list \
    --project-root "$PROJECT_ROOT" \
    --contract "$CONTRACT" >"$CAPTURE_LIST"
mapfile -t CAPTURE_IDS <"$CAPTURE_LIST"
((${#CAPTURE_IDS[@]} == 5)) || die "contract must list exactly five captures"

PIPELINE_STARTED="$(date +%s)"
for index in "${!CAPTURE_IDS[@]}"; do
    capture_id="${CAPTURE_IDS[$index]}"
    ordinal=$((index + 1))
    printf '[T3.3 export] stage=capture completed=%d total=%d capture=%s status=running\n' \
        "$index" "${#CAPTURE_IDS[@]}" "$capture_id"
    python3 -B "$EXPORT_SCRIPT" export \
        --project-root "$PROJECT_ROOT" \
        --contract "$CONTRACT" \
        --capture-id "$capture_id" \
        --exporter "$BUILD_DIR/nids_t33_flow_export" \
        --scratch-root "$SCRATCH_ROOT" \
        2>&1 | tee "$ATTEMPT_ROOT/$capture_id.log"
    elapsed=$(($(date +%s) - PIPELINE_STARTED))
    printf '[T3.3 export] stage=capture completed=%d total=%d capture=%s status=passed elapsed=%ds\n' \
        "$ordinal" "${#CAPTURE_IDS[@]}" "$capture_id" "$elapsed"
done

python3 -B "$EXPORT_SCRIPT" status \
    --project-root "$PROJECT_ROOT" \
    --contract "$CONTRACT" \
    --exporter "$BUILD_DIR/nids_t33_flow_export" \
    2>&1 | tee "$ATTEMPT_ROOT/status.log"

printf '[T3.3 export] status=passed completed=%d total=%d checkpoints=%s\n' \
    "${#CAPTURE_IDS[@]}" "${#CAPTURE_IDS[@]}" \
    "$ARTIFACT_ROOT/checkpoints/flow-shards"
printf '[T3.3 export] attempt_logs=%s\n' "$ATTEMPT_ROOT"
