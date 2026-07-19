#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly ARTIFACT_ROOT="$PROJECT_ROOT/run_log/t3.3"
readonly SCRATCH_ROOT="${TMPDIR:-/tmp}"

BUILD_DIR=""
ATTEMPT_ROOT=""
ENVIRONMENT_RECEIPT=""

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$BUILD_DIR" && "$BUILD_DIR" == "$SCRATCH_ROOT/"nids-t33-acceptance.* ]]; then
        rm -rf -- "$BUILD_DIR"
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

(($# == 0)) || die "usage: bash scripts/run_t33_acceptance_ubuntu.sh"
((EUID != 0)) || die "run as the normal Ubuntu user"
[[ "$PROJECT_ROOT" == "/mnt/hgfs/TTTN" ]] \
    || die "run from the approved VMware shared workspace: /mnt/hgfs/TTTN"

for command in bash cmake ctest date mktemp ninja python3 shellcheck tee; do
    command -v "$command" >/dev/null || die "missing required command: $command"
done

shellcheck --severity=error "$0"
[[ -f "$HOME/.local/nids-toolchain/env.sh" ]] || die "missing locked toolchain environment"

for artifact in \
    "$ARTIFACT_ROOT/build.json" \
    "$ARTIFACT_ROOT/label-join.sqlite3" \
    "$ARTIFACT_ROOT/acceptance.json"; do
    [[ ! -e "$artifact" ]] || die "refusing to overwrite existing artifact: $artifact"
done

mkdir -p -- "$ARTIFACT_ROOT"
ATTEMPT_ROOT="$ARTIFACT_ROOT/attempts/ubuntu-acceptance-$(date -u +%Y%m%dT%H%M%S%NZ)"
[[ ! -e "$ATTEMPT_ROOT" ]] || die "attempt directory already exists: $ATTEMPT_ROOT"
mkdir -p -- "$ATTEMPT_ROOT"
BUILD_DIR="$(mktemp -d "$SCRATCH_ROOT/nids-t33-acceptance.XXXXXXXX")"

ENVIRONMENT_RECEIPT="$ATTEMPT_ROOT/environment-verifier.json"
if [[ ! -e "$ARTIFACT_ROOT/environment-verifier.json" ]]; then
    ENVIRONMENT_RECEIPT="$ARTIFACT_ROOT/environment-verifier.json"
fi
bash "$PROJECT_ROOT/scripts/setup_toolchain_ubuntu.sh" --verify \
    --receipt "$ENVIRONMENT_RECEIPT" \
    2>&1 | tee "$ATTEMPT_ROOT/environment-verifier.log"

# shellcheck disable=SC1091
source "$HOME/.local/nids-toolchain/env.sh"

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
    -p 'test_t33_label_join.py' -v \
    2>&1 | tee "$ATTEMPT_ROOT/python-tests.log"

python3 -B "$PROJECT_ROOT/scripts/build_t33_label_join.py" \
    --project-root "$PROJECT_ROOT" \
    --contract "$PROJECT_ROOT/config/cicids2017-label-join-contract.json" \
    --exporter "$BUILD_DIR/nids_t33_flow_export" \
    --scratch-root "$SCRATCH_ROOT" \
    2>&1 | tee "$ATTEMPT_ROOT/label-join-build.log"

python3 -B "$PROJECT_ROOT/scripts/verify_t33_label_join.py" accept \
    --project-root "$PROJECT_ROOT" \
    --input "$ARTIFACT_ROOT/build.json" \
    --database "$ARTIFACT_ROOT/label-join.sqlite3" \
    --output "$ARTIFACT_ROOT/acceptance.json" \
    2>&1 | tee "$ATTEMPT_ROOT/acceptance.log"

printf '[T3.3] acceptance passed: %s\n' "$ARTIFACT_ROOT/acceptance.json"
printf '[T3.3] attempt logs: %s\n' "$ATTEMPT_ROOT"
