#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    printf 'usage: bash scripts/run_t85_scenario_sensor_ubuntu.sh --run-id ID --bundle DIR [--attempt ID] [--duration-seconds N] [--max-packets N]\n' >&2
    exit 2
}

RUN_ID=
BUNDLE=
ATTEMPT=default
DURATION_SECONDS=300
MAX_PACKETS=100000000
while (($#)); do
    case "$1" in
        --run-id) [[ $# -ge 2 ]] || usage; RUN_ID="$2"; shift 2 ;;
        --bundle) [[ $# -ge 2 ]] || usage; BUNDLE="$2"; shift 2 ;;
        --attempt) [[ $# -ge 2 ]] || usage; ATTEMPT="$2"; shift 2 ;;
        --duration-seconds) [[ $# -ge 2 ]] || usage; DURATION_SECONDS="$2"; shift 2 ;;
        --max-packets) [[ $# -ge 2 ]] || usage; MAX_PACKETS="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9._-]{2,63}$ ]] || usage
[[ "$ATTEMPT" =~ ^[a-z0-9][a-z0-9._-]{2,63}$ ]] || usage
[[ "$DURATION_SECONDS" =~ ^[0-9]+$ ]] && ((DURATION_SECONDS >= 60 && DURATION_SECONDS <= 3600)) || usage
[[ "$MAX_PACKETS" =~ ^[0-9]+$ ]] && ((MAX_PACKETS >= 9 && MAX_PACKETS <= 100000000)) || usage

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly RUN_ROOT="$PROJECT_ROOT/run_log/t8.5/scenarios/$RUN_ID/ubuntu/$ATTEMPT"
readonly SCENARIO="$PROJECT_ROOT/run_log/t8.5/scenarios/$RUN_ID/scenario.json"
readonly BINARY="$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_dpdk_live"
readonly TOOLCHAIN_ENV="$HOME/.local/nids-toolchain/env.sh"
readonly BUNDLE="$(realpath -e -- "$BUNDLE")"

((EUID != 0)) || { printf 'error: run as the normal Ubuntu user\n' >&2; exit 2; }
[[ -f "$SCENARIO" ]] || { printf 'error: initialize scenario first: %s\n' "$SCENARIO" >&2; exit 2; }
[[ -f "$TOOLCHAIN_ENV" ]] || { printf 'error: missing toolchain environment\n' >&2; exit 2; }
# shellcheck disable=SC1090
source "$TOOLCHAIN_ENV"
[[ -x "$BINARY" ]] || { printf 'error: build nids_dpdk_live first\n' >&2; exit 2; }
mkdir -p -- "$RUN_ROOT"

readonly PREFLIGHT="$RUN_ROOT/preflight.json"
readonly RESOURCE_CONFIG="$RUN_ROOT/resource-config.json"
readonly STATE="$RUN_ROOT/state.json"
readonly ROLLBACK="$RUN_ROOT/rollback.json"
readonly SENSOR_LOG="$RUN_ROOT/sensor.jsonl"
[[ ! -e "$PREFLIGHT" && ! -e "$RESOURCE_CONFIG" && ! -e "$STATE" && ! -e "$ROLLBACK" && ! -e "$SENSOR_LOG" ]] || {
    printf 'error: refusing to overwrite scenario sensor evidence\n' >&2
    exit 2
}

APPLIED=0
cleanup() {
    local status=$? rollback_status=0
    trap - EXIT INT TERM
    set +e
    if ((APPLIED)); then
        sudo -n python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" rollback --state "$STATE" --output "$ROLLBACK"
        rollback_status=$?
    fi
    ((status != 0 || rollback_status == 0)) || status=$rollback_status
    printf '[T8.5 scenario] artifacts: %s\n' "$RUN_ROOT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 -B "$PROJECT_ROOT/scripts/t85_demo_scenario.py" resource-config \
    --run-id "$RUN_ID" \
    --attempt "$ATTEMPT"
python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" preflight \
    --config "$RESOURCE_CONFIG" \
    --data-interface ens160 \
    --output "$PREFLIGHT"
python3 -B -c \
    'import json,sys
preflight=json.load(open(sys.argv[1], encoding="utf-8"))
base=json.load(open(sys.argv[2], encoding="utf-8"))
name=base["ubuntu_sensor"]["data_interface"]
observed=preflight["discovery"]["interfaces"][name]["mac"].lower()
expected=base["ubuntu_sensor"]["expected_mac"].lower()
if observed != expected:
    raise SystemExit(f"sensor MAC mismatch: expected {expected}, observed {observed}")' \
    "$PREFLIGHT" "$PROJECT_ROOT/config/dpdk-passive.json"
sudo -n true
sudo -n python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" apply --preflight "$PREFLIGHT" --state "$STATE"
APPLIED=1

PCI_ADDRESS="$(python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["original"]["pci_address"])' "$STATE")"
readonly PCI_ADDRESS
[[ "$PCI_ADDRESS" =~ ^0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] || {
    printf 'error: invalid PCI address: %s\n' "$PCI_ADDRESS" >&2
    exit 1
}

printf '[T8.5 scenario] sensor armed attempt=%s max_packets=%s idle_seconds=%s\n' "$ATTEMPT" "$MAX_PACKETS" "$DURATION_SECONDS"
sudo -n env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$BINARY" \
    -l 0 -n 2 -a "$PCI_ADDRESS" -m 256 \
    --file-prefix=nids-t85-scenario --huge-unlink=always --no-telemetry '--log-level=*:warning' \
    -- --bundle "$BUNDLE" --port-id 0 --max-packets "$MAX_PACKETS" --min-packets 0 \
    --min-f9 0 --min-alerts 0 --max-parser-errors "$MAX_PACKETS" \
    --idle-timeout-ms "$((DURATION_SECONDS * 1000))" --mtu 9000 --require-promiscuous \
    | tee "$SENSOR_LOG"
