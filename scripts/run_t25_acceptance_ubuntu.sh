#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly HUGEPAGE_MOUNT="/dev/hugepages"
readonly HUGEPAGE_TOTAL_PATH="/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
readonly HUGEPAGE_FREE_PATH="/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages"
readonly HUGEPAGE_TARGET=64
readonly CALLER_UID="$(id -u)"
readonly CALLER_GID="$(id -g)"
readonly ARTIFACT_ROOT="$PROJECT_ROOT/run_log/t2.5"

HUGE_DIR=""
ORIGINAL_HUGEPAGES=""
HUGE_DIR_OWNED=0
RESTORE_REQUIRED=0

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

read_uint() {
    local path="$1" value
    [[ -r "$path" ]] || die "cannot read $path"
    value="$(<"$path")"
    [[ "$value" =~ ^[0-9]+$ ]] || die "non-integer value in $path: $value"
    printf '%s\n' "$value"
}

cleanup() {
    local status=$? cleanup_failed=0 restored=""
    trap - EXIT INT TERM
    set +e

    if ((HUGE_DIR_OWNED)); then
        case "$HUGE_DIR" in
            "$HUGEPAGE_MOUNT"/nids-t25-"$CALLER_UID"-*)
                find "$HUGE_DIR" -xdev -mindepth 1 -maxdepth 1 -type f -delete \
                    || cleanup_failed=1
                sudo rmdir -- "$HUGE_DIR" || cleanup_failed=1
                ;;
            *)
                printf 'error: refusing to clean unexpected hugepage directory: %s\n' "$HUGE_DIR" >&2
                cleanup_failed=1
                ;;
        esac
    fi

    if ((RESTORE_REQUIRED)); then
        printf '%s\n' "$ORIGINAL_HUGEPAGES" | sudo tee "$HUGEPAGE_TOTAL_PATH" >/dev/null \
            || cleanup_failed=1
        restored="$(<"$HUGEPAGE_TOTAL_PATH")"
        if [[ "$restored" != "$ORIGINAL_HUGEPAGES" ]]; then
            printf 'error: hugepage restore mismatch: expected=%s observed=%s\n' \
                "$ORIGINAL_HUGEPAGES" "$restored" >&2
            cleanup_failed=1
        else
            printf '[T2.5] restored 2 MiB hugepages to %s\n' "$restored"
        fi
    fi

    if ((status == 0 && cleanup_failed != 0)); then
        status=1
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

MODE="acceptance"
if (($# == 1)) && [[ "$1" == "--capture-debug" ]]; then
    MODE="capture-debug"
elif (($# != 0)); then
    die "usage: bash scripts/run_t25_acceptance_ubuntu.sh [--capture-debug]"
fi
readonly MODE
((EUID != 0)) || die "run as the normal Ubuntu user; sudo is requested only for hugepage setup"

for command in cmake date find findmnt install ninja python3 shellcheck sudo tee; do
    command -v "$command" >/dev/null || die "missing required command: $command"
done

shellcheck --severity=error "$0"
[[ -f "$HOME/.local/nids-toolchain/env.sh" ]] || die "missing locked toolchain environment"
# shellcheck disable=SC1091
source "$HOME/.local/nids-toolchain/env.sh"

[[ "$(findmnt -rn -T "$HUGEPAGE_MOUNT" -o FSTYPE)" == "hugetlbfs" ]] \
    || die "$HUGEPAGE_MOUNT is not a hugetlbfs mount"
[[ "$(awk '/^Hugepagesize:/ { print $2 }' /proc/meminfo)" == "2048" ]] \
    || die "the default hugepage size must be 2048 kB"

ORIGINAL_HUGEPAGES="$(read_uint "$HUGEPAGE_TOTAL_PATH")"
readonly ORIGINAL_HUGEPAGES
[[ "$ORIGINAL_HUGEPAGES" == "0" ]] \
    || die "refusing to alter a host that already has configured 2 MiB hugepages"
[[ "$(read_uint "$HUGEPAGE_FREE_PATH")" == "0" ]] \
    || die "refusing to alter a host with existing free 2 MiB hugepages"
if [[ "$MODE" == "acceptance" ]]; then
    [[ ! -e "$ARTIFACT_ROOT/acceptance.json" ]] \
        || die "refusing to overwrite existing T2.5 acceptance"
fi

sudo -v
HUGE_DIR="$HUGEPAGE_MOUNT/nids-t25-$CALLER_UID-$$"
[[ ! -e "$HUGE_DIR" ]] || die "private hugepage directory already exists: $HUGE_DIR"
HUGE_DIR_OWNED=1
sudo install -d -m 0700 -o "$CALLER_UID" -g "$CALLER_GID" -- "$HUGE_DIR"

RESTORE_REQUIRED=1
printf '%s\n' "$HUGEPAGE_TARGET" | sudo tee "$HUGEPAGE_TOTAL_PATH" >/dev/null
[[ "$(read_uint "$HUGEPAGE_TOTAL_PATH")" == "$HUGEPAGE_TARGET" ]] \
    || die "kernel did not reserve exactly $HUGEPAGE_TARGET hugepages"
[[ "$(read_uint "$HUGEPAGE_FREE_PATH")" == "$HUGEPAGE_TARGET" ]] \
    || die "reserved hugepages are not all free before acceptance"
printf '[T2.5] temporarily reserved %s x 2 MiB hugepages\n' "$HUGEPAGE_TARGET"

mkdir -p -- "$ARTIFACT_ROOT"
export NIDS_T25_HUGE_DIR="$HUGE_DIR"

if [[ "$MODE" == "capture-debug" ]]; then
    DEBUG_ROOT="$ARTIFACT_ROOT/debug/capture-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    BUILD_DIR="$DEBUG_ROOT/build"
    readonly DEBUG_ROOT BUILD_DIR
    mkdir -p -- "$DEBUG_ROOT"

    python3 -B "$PROJECT_ROOT/scripts/verify_t25_dpdk_adapter.py" check \
        --source "$PROJECT_ROOT" \
        2>&1 | tee "$DEBUG_ROOT/00-source-contract.log"
    cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=ON \
        -DNIDS_BUILD_DPDK=ON \
        -DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF \
        2>&1 | tee "$DEBUG_ROOT/01-configure.log"
    cmake --build "$BUILD_DIR" --parallel 2 \
        --target nids_dpdk_adapter_probe nids_dpdk_adapter_test \
        2>&1 | tee "$DEBUG_ROOT/02-build.log"

    export NIDS_T25_CAPTURE_OUTPUT="$DEBUG_ROOT/sample.pcapng"
    python3 -B "$PROJECT_ROOT/scripts/verify_t25_dpdk_adapter.py" capture-test \
        --source "$PROJECT_ROOT" \
        --probe "$BUILD_DIR/nids_dpdk_adapter_probe" \
        --validator "$BUILD_DIR/nids_dpdk_adapter_test" \
        --trace-dir "$DEBUG_ROOT/capture-trace" \
        2>&1 | tee "$DEBUG_ROOT/03-capture-driver.log"
    printf '[T2.5] capture debug passed: %s\n' "$DEBUG_ROOT"
    exit 0
fi

python3 -B "$PROJECT_ROOT/scripts/verify_t25_dpdk_adapter.py" run \
    --source "$PROJECT_ROOT" \
    --artifact-root "$ARTIFACT_ROOT" \
    2>&1 | tee "$ARTIFACT_ROOT/acceptance-run.log"
python3 -B "$PROJECT_ROOT/scripts/verify_t25_dpdk_adapter.py" validate \
    --input "$ARTIFACT_ROOT/acceptance.json" \
    2>&1 | tee -a "$ARTIFACT_ROOT/acceptance-run.log"
