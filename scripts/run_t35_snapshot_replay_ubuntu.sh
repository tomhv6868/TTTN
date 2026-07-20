#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly CONTRACT="$PROJECT_ROOT/config/cicids2017-snapshot-contract.json"
readonly BUILDER="$PROJECT_ROOT/scripts/build_t35_snapshot_shard.py"
readonly ARTIFACT_ROOT="$PROJECT_ROOT/run_log/t3.5"
readonly TOOLING_ROOT="$ARTIFACT_ROOT/tooling"
readonly STABLE_EXPORTER="$TOOLING_ROOT/nids_t35_snapshot_export"
readonly SCRATCH_ROOT="${TMPDIR:-/tmp}"

BUILD_DIR=""
ATTEMPT_ROOT=""
BUILD_ONLY=0
declare -a SELECTED_CAPTURES=()

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$BUILD_DIR" && "$BUILD_DIR" == "$SCRATCH_ROOT/"nids-t35-replay.* ]]; then
        rm -rf -- "$BUILD_DIR"
    fi
    exit "$status"
}

usage() {
    printf 'usage: bash scripts/run_t35_snapshot_replay_ubuntu.sh [--build-only] [--capture-id TOKEN ...]\n'
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while (($# > 0)); do
    case "$1" in
        --build-only)
            BUILD_ONLY=1
            shift
            ;;
        --capture-id)
            (($# >= 2)) || die "--capture-id requires a value"
            SELECTED_CAPTURES+=("$2")
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
done

((EUID != 0)) || die "run as the normal Ubuntu user"
[[ "$PROJECT_ROOT" == "/mnt/hgfs/TTTN" ]] \
    || die "run from the approved VMware shared workspace: /mnt/hgfs/TTTN"

for command in bash cmake ctest cut date install mktemp mv ninja python3 sha256sum shellcheck tee; do
    command -v "$command" >/dev/null || die "missing required command: $command"
done

shellcheck --severity=error "$0"
[[ -f "$HOME/.local/nids-toolchain/env.sh" ]] || die "missing locked toolchain environment"
[[ -d "$SCRATCH_ROOT" && -w "$SCRATCH_ROOT" ]] || die "scratch root is not writable: $SCRATCH_ROOT"

mkdir -p -- "$ARTIFACT_ROOT/attempts" "$TOOLING_ROOT"
ATTEMPT_ROOT="$ARTIFACT_ROOT/attempts/ubuntu-snapshot-replay-$(date -u +%Y%m%dT%H%M%S%NZ)"
[[ ! -e "$ATTEMPT_ROOT" ]] || die "attempt directory already exists: $ATTEMPT_ROOT"
mkdir -p -- "$ATTEMPT_ROOT"
BUILD_DIR="$(mktemp -d "$SCRATCH_ROOT/nids-t35-replay.XXXXXXXX")"

printf '[T3.5 replay] stage=environment status=running log=%s\n' \
    "$ATTEMPT_ROOT/environment-verifier.log"
bash "$PROJECT_ROOT/scripts/setup_toolchain_ubuntu.sh" --verify \
    --receipt "$ATTEMPT_ROOT/environment-verifier.json" \
    2>&1 | tee "$ATTEMPT_ROOT/environment-verifier.log"

# shellcheck disable=SC1091
source "$HOME/.local/nids-toolchain/env.sh"

printf '[T3.5 replay] stage=build status=running log=%s\n' "$ATTEMPT_ROOT/build.log"
cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON \
    -DNIDS_BUILD_DPDK=OFF \
    -DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF \
    2>&1 | tee "$ATTEMPT_ROOT/configure.log"
cmake --build "$BUILD_DIR" --parallel 2 \
    --target nids_t35_snapshot_export nids_t35_snapshot_export_test nids_t33_flow_export_test \
    2>&1 | tee "$ATTEMPT_ROOT/build.log"
ctest --test-dir "$BUILD_DIR" \
    -R '^nids_dataset\.(flow_export|snapshot_export)$' --output-on-failure \
    2>&1 | tee "$ATTEMPT_ROOT/ctest.log"
python3 -B -W error "$PROJECT_ROOT/tests/test_t35_snapshot_shard.py" -v \
    2>&1 | tee "$ATTEMPT_ROOT/python-tests.log"

if [[ -e "$STABLE_EXPORTER" ]]; then
    fresh_hash="$(sha256sum "$BUILD_DIR/nids_t35_snapshot_export" | cut -d ' ' -f 1)"
    stable_hash="$(sha256sum "$STABLE_EXPORTER" | cut -d ' ' -f 1)"
    [[ "$fresh_hash" == "$stable_hash" ]] \
        || die "rebuilt exporter differs from the stable replay exporter; preserve receipts and investigate"
else
    temporary_exporter="$TOOLING_ROOT/.nids_t35_snapshot_export.$$"
    install -m 0755 "$BUILD_DIR/nids_t35_snapshot_export" "$temporary_exporter"
    mv -- "$temporary_exporter" "$STABLE_EXPORTER"
fi

printf '[T3.5 replay] stage=build status=passed exporter=%s sha256=%s\n' \
    "$STABLE_EXPORTER" "$(sha256sum "$STABLE_EXPORTER" | cut -d ' ' -f 1)"

if ((BUILD_ONLY)); then
    printf '[T3.5 replay] status=passed mode=build-only attempt_logs=%s\n' "$ATTEMPT_ROOT"
    exit 0
fi

mapfile -t CONTRACT_CAPTURES < <(
    python3 -c \
        'import json,sys; print("\n".join(item["id"] for item in json.load(open(sys.argv[1], encoding="utf-8"))["captures"]))' \
        "$CONTRACT"
)
((${#CONTRACT_CAPTURES[@]} == 5)) || die "contract must list exactly five captures"

if ((${#SELECTED_CAPTURES[@]} == 0)); then
    SELECTED_CAPTURES=("${CONTRACT_CAPTURES[@]}")
fi

declare -A SEEN_CAPTURES=()
for capture_id in "${SELECTED_CAPTURES[@]}"; do
    [[ -z "${SEEN_CAPTURES[$capture_id]:-}" ]] || die "duplicate capture selection: $capture_id"
    SEEN_CAPTURES["$capture_id"]=1
    found=0
    for contract_capture in "${CONTRACT_CAPTURES[@]}"; do
        if [[ "$capture_id" == "$contract_capture" ]]; then
            found=1
            break
        fi
    done
    ((found)) || die "capture is not in the contract: $capture_id"
done

pipeline_started="$(date +%s)"
total="${#SELECTED_CAPTURES[@]}"
for index in "${!SELECTED_CAPTURES[@]}"; do
    capture_id="${SELECTED_CAPTURES[$index]}"
    ordinal=$((index + 1))
    printf '[T3.5 replay] stage=capture completed=%d total=%d capture=%s status=running log=%s\n' \
        "$index" "$total" "$capture_id" "$ATTEMPT_ROOT/$capture_id.log"
    python3 -B "$BUILDER" run \
        --project-root "$PROJECT_ROOT" \
        --contract "$CONTRACT" \
        --capture-id "$capture_id" \
        --exporter "$STABLE_EXPORTER" \
        --scratch "$SCRATCH_ROOT" \
        2>&1 | tee "$ATTEMPT_ROOT/$capture_id.log"
    elapsed=$(($(date +%s) - pipeline_started))
    printf '[T3.5 replay] stage=capture completed=%d total=%d capture=%s status=passed elapsed=%ds\n' \
        "$ordinal" "$total" "$capture_id" "$elapsed"
done

printf '[T3.5 replay] status=passed completed=%d total=%d shards=%s attempt_logs=%s\n' \
    "$total" "$total" "$ARTIFACT_ROOT/checkpoints/snapshot-shards" "$ATTEMPT_ROOT"
printf '[T3.5 replay] next=windows-parquet command="python -B scripts/package_t35_parquet.py"\n'
