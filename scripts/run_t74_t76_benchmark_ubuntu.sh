#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    printf 'usage: bash scripts/run_t74_t76_benchmark_ubuntu.sh --mode baseline|full|stability --attempt ID --bundle DIR --expected-flows N [--parser-error-budget N]\n' >&2
    exit 2
}

MODE=
ATTEMPT=
BUNDLE=
EXPECTED_FLOWS=
PARSER_ERROR_BUDGET=4096
while (($#)); do
    case "$1" in
        --mode) [[ $# -ge 2 ]] || usage; MODE="$2"; shift 2 ;;
        --attempt) [[ $# -ge 2 ]] || usage; ATTEMPT="$2"; shift 2 ;;
        --bundle) [[ $# -ge 2 ]] || usage; BUNDLE="$2"; shift 2 ;;
        --expected-flows) [[ $# -ge 2 ]] || usage; EXPECTED_FLOWS="$2"; shift 2 ;;
        --parser-error-budget) [[ $# -ge 2 ]] || usage; PARSER_ERROR_BUDGET="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$MODE" == baseline || "$MODE" == full || "$MODE" == stability ]] || usage
[[ "$ATTEMPT" =~ ^[a-z0-9][a-z0-9._-]{2,63}$ ]] || usage
[[ "$EXPECTED_FLOWS" =~ ^[0-9]+$ ]] && ((EXPECTED_FLOWS >= 1 && EXPECTED_FLOWS <= 1000000)) || usage
[[ "$PARSER_ERROR_BUDGET" =~ ^[0-9]+$ ]] && ((PARSER_ERROR_BUDGET <= 1000000)) || usage

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly RUN_ROOT="$PROJECT_ROOT/run_log/t0.4/t7.4-t7.6/$MODE/$ATTEMPT"
readonly BINARY="$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_dpdk_live"
readonly TOOLCHAIN_ENV="$HOME/.local/nids-toolchain/env.sh"
readonly THRESHOLDS="$PROJECT_ROOT/run_log/t6.1/thresholds.json"
readonly THRESHOLDS_SHA256="82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4"
readonly BUNDLE="$(realpath -e -- "$BUNDLE")"
readonly EXPECTED_PACKETS="$((EXPECTED_FLOWS * 9))"
readonly MAX_PACKETS="$((EXPECTED_PACKETS + PARSER_ERROR_BUDGET))"
readonly PREFLIGHT="$RUN_ROOT/preflight.json"
readonly STATE="$RUN_ROOT/state.json"
readonly ROLLBACK="$RUN_ROOT/rollback.json"
readonly SENSOR_LOG="$RUN_ROOT/sensor.jsonl"

((EUID != 0)) || { printf 'error: run as the normal Ubuntu user\n' >&2; exit 2; }
[[ "$PROJECT_ROOT" == /mnt/hgfs/TTTN ]] || {
    printf 'error: run from /mnt/hgfs/TTTN on the approved Ubuntu VMware guest\n' >&2
    exit 2
}
[[ -f "$TOOLCHAIN_ENV" ]] || { printf 'error: missing toolchain environment\n' >&2; exit 2; }
# shellcheck disable=SC1090
source "$TOOLCHAIN_ENV"
[[ -x "$BINARY" ]] || { printf 'error: build nids_dpdk_live first\n' >&2; exit 2; }
[[ "$(sha256sum -- "$THRESHOLDS" | cut -d ' ' -f 1)" == "$THRESHOLDS_SHA256" ]] || {
    printf 'error: threshold artifact SHA-256 mismatch\n' >&2
    exit 2
}
[[ ! -e "$RUN_ROOT" ]] || { printf 'error: refusing to overwrite %s\n' "$RUN_ROOT" >&2; exit 2; }
mkdir -p -- "$RUN_ROOT"

APPLIED=0
cleanup() {
    local status=$? rollback_status=0
    trap - EXIT INT TERM
    set +e
    if ((APPLIED)); then
        sudo python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" rollback \
            --state "$STATE" --output "$ROLLBACK"
        rollback_status=$?
    fi
    ((status != 0 || rollback_status == 0)) || status=$rollback_status
    printf '[T7.4-T7.6] artifacts: %s\n' "$RUN_ROOT"
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
    --preflight "$PREFLIGHT" --state "$STATE"
APPLIED=1

PCI_ADDRESS="$(
    python3 -B -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["original"]["pci_address"])' \
        "$STATE"
)"
readonly PCI_ADDRESS
[[ "$PCI_ADDRESS" =~ ^0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] || {
    printf 'error: invalid PCI address: %s\n' "$PCI_ADDRESS" >&2
    exit 1
}

declare -a PIPELINE_OPTIONS=(--benchmark-metrics)
if [[ "$MODE" == baseline ]]; then
    PIPELINE_OPTIONS+=(--disable-inference)
fi

printf '[T7.4-T7.6] launching sensor mode=%s attempt=%s expected_flows=%s expected_packets=%s\n' \
    "$MODE" "$ATTEMPT" "$EXPECTED_FLOWS" "$EXPECTED_PACKETS"
printf '[T7.4-T7.6] wait for event_type=nids_dpdk_live_ready before starting Kali\n'

sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$BINARY" \
    -l 0 -n 2 -a "$PCI_ADDRESS" -m 256 \
    --file-prefix=nids-t74-t76 --huge-unlink=always --no-telemetry '--log-level=*:warning' \
    -- \
    --bundle "$BUNDLE" \
    --thresholds "$THRESHOLDS" \
    --thresholds-sha256 "$THRESHOLDS_SHA256" \
    --port-id 0 \
    --max-packets "$MAX_PACKETS" \
    --min-packets "$EXPECTED_PACKETS" \
    --min-f9 "$EXPECTED_FLOWS" \
    --min-alerts 0 \
    --max-parser-errors "$PARSER_ERROR_BUDGET" \
    --arm-timeout-ms 300000 \
    --idle-timeout-ms 5000 \
    --mtu 1500 \
    --require-promiscuous \
    "${PIPELINE_OPTIONS[@]}" \
    | tee "$SENSOR_LOG"
