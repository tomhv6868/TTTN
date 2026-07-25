#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    printf 'usage: bash scripts/run_t85_live_sensor_ubuntu.sh --bundle DIR\n' >&2
    exit 2
}

[[ $# -eq 2 && "$1" == "--bundle" ]] || usage
readonly BUNDLE="$(realpath -e -- "$2")"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly BINARY="$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_dpdk_live"
readonly TOOLCHAIN_ENV="$HOME/.local/nids-toolchain/env.sh"
readonly THRESHOLDS="$(realpath -e -- "$PROJECT_ROOT/run_log/t6.1/thresholds.json")"
readonly THRESHOLDS_SHA256="82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4"
readonly OBSERVED_THRESHOLDS_SHA256="$(
    sha256sum -- "$THRESHOLDS" | cut -d' ' -f1
)"

((EUID != 0)) || {
    printf 'error: run as the normal Ubuntu user; this wrapper requests sudo only for reversible resource actions\n' >&2
    exit 2
}
[[ -f "$TOOLCHAIN_ENV" ]] || {
    printf 'error: missing locked toolchain environment: %s\n' "$TOOLCHAIN_ENV" >&2
    exit 2
}
# shellcheck disable=SC1090
source "$TOOLCHAIN_ENV"
[[ -x "$BINARY" ]] || {
    printf 'error: build nids_dpdk_live first: %s\n' "$BINARY" >&2
    exit 2
}
[[ "$OBSERVED_THRESHOLDS_SHA256" == "$THRESHOLDS_SHA256" ]] || {
    printf 'error: T6.1 threshold SHA-256 mismatch: expected=%s observed=%s\n' \
        "$THRESHOLDS_SHA256" \
        "$OBSERVED_THRESHOLDS_SHA256" >&2
    exit 2
}

readonly RUN_PARENT="$PROJECT_ROOT/run_log/t0.4/live-demo"
mkdir -p -- "$RUN_PARENT"
readonly RUN_ROOT="$(mktemp -d "$RUN_PARENT/live-sensor.XXXXXXXX")"
readonly PREFLIGHT="$RUN_ROOT/preflight.json"
readonly STATE="$RUN_ROOT/state.json"
readonly ROLLBACK="$RUN_ROOT/rollback.json"
readonly SENSOR_LOG="$RUN_ROOT/sensor.jsonl"

APPLIED=0

cleanup() {
    local status=$? rollback_status=0
    trap - EXIT INT TERM
    set +e
    if ((APPLIED)); then
        sudo python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" rollback \
            --state "$STATE" \
            --output "$ROLLBACK"
        rollback_status=$?
    fi
    if ((status == 0 && rollback_status != 0)); then
        status=$rollback_status
    fi
    printf '[T8.5] artifacts: %s\n' "$RUN_ROOT"
    exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 -B "$PROJECT_ROOT/scripts/dpdk_passive_probe.py" preflight \
    --config "$PROJECT_ROOT/config/dpdk-passive.json" \
    --output "$PREFLIGHT"

sudo -v
sudo python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" apply \
    --preflight "$PREFLIGHT" \
    --state "$STATE"
APPLIED=1

PCI_ADDRESS="$(
    python3 -B -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["original"]["pci_address"])' \
        "$STATE"
)"
readonly PCI_ADDRESS
[[ "$PCI_ADDRESS" =~ ^0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] || {
    printf 'error: invalid PCI address in applied state: %s\n' "$PCI_ADDRESS" >&2
    exit 1
}

printf '[T8.5] sensor will arm for five minutes; start the Kali sender after the ready JSON appears\n'
printf '[T8.5] the sensor stops automatically after the first alert and then rolls back the NIC\n'

sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    "$BINARY" \
    -l 0 \
    -n 2 \
    -a "$PCI_ADDRESS" \
    -m 256 \
    --file-prefix=nids-t03 \
    --huge-unlink=always \
    --no-telemetry \
    '--log-level=*:warning' \
    -- \
    --bundle "$BUNDLE" \
    --thresholds "$THRESHOLDS" \
    --thresholds-sha256 "$THRESHOLDS_SHA256" \
    --port-id 0 \
    --max-packets 4096 \
    --min-packets 9 \
    --min-f9 1 \
    --min-alerts 1 \
    --max-parser-errors 64 \
    --idle-timeout-ms 300000 \
    --mtu 9000 \
    --require-promiscuous \
    --stop-after-alert \
    | tee "$SENSOR_LOG"
