#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    printf 'usage: bash scripts/ubuntu_t85_detection.sh --segment-id ID [--bundle DIR]\n' >&2
    exit 2
}

BUNDLE="$HOME/.cache/nids-partial-flow/t5.2/bundles/F9"
SEGMENT_ID=""

while (($#)); do
    case "$1" in
        --segment-id) [[ $# -ge 2 ]] || usage; SEGMENT_ID="$2"; shift 2 ;;
        --bundle) [[ $# -ge 2 ]] || usage; BUNDLE="$2"; shift 2 ;;
        -h|--help)
            printf 'usage: bash scripts/ubuntu_t85_detection.sh --segment-id ID [--bundle DIR]\n'
            exit 0
            ;;
        *) usage ;;
    esac
done

case "$SEGMENT_ID" in
    monday|tuesday|wednesday|thursday|friday) ;;
    *) printf 'error: --segment-id must be monday, tuesday, wednesday, thursday, or friday\n' >&2; exit 2 ;;
esac

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly TOOLCHAIN_ENV="$HOME/.local/nids-toolchain/env.sh"
readonly BINARY="$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_dpdk_live"
readonly CONFIG="$PROJECT_ROOT/config/dpdk-passive.json"
readonly SEGMENT_ID
readonly SEGMENT_ROOT="$PROJECT_ROOT/run_log/t8.5/segments/$SEGMENT_ID"
readonly RUNTIME_ROOT="$SEGMENT_ROOT/ubuntu-runtime"
readonly RESOURCE_CONFIG="$RUNTIME_ROOT/resource-config.json"
readonly PREFLIGHT="$RUNTIME_ROOT/preflight.json"
readonly STATE="$RUNTIME_ROOT/state.json"
readonly ROLLBACK="$RUNTIME_ROOT/rollback.json"
readonly DETECTION_LOG="$SEGMENT_ROOT/detection.jsonl"
readonly BUNDLE="$(realpath -e -- "$BUNDLE")"

((EUID != 0)) || {
    printf 'error: run as the normal Ubuntu user\n' >&2
    exit 2
}
[[ -f "$TOOLCHAIN_ENV" ]] || {
    printf 'error: missing toolchain environment: %s\n' "$TOOLCHAIN_ENV" >&2
    exit 1
}

# shellcheck disable=SC1090
source "$TOOLCHAIN_ENV"

cd -- "$PROJECT_ROOT"
for evidence in \
    "$RESOURCE_CONFIG" \
    "$PREFLIGHT" \
    "$STATE" \
    "$ROLLBACK" \
    "$DETECTION_LOG"; do
    [[ ! -e "$evidence" ]] || {
        printf 'error: segment evidence already exists; preserve it and use a clean segment directory: %s\n' "$evidence" >&2
        exit 1
    }
done
mkdir -p -- "$RUNTIME_ROOT"

cmake --build --preset ubuntu-release --target nids_dpdk_live -j 2

python3 -B -c \
    'import json,sys
from pathlib import Path
root=Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
import dpdk_passive_probe
import kali_passive_traffic
config=kali_passive_traffic.load_and_validate_config(root / "config/dpdk-passive.json")
document=dpdk_passive_probe.build_resource_config(config)
Path(sys.argv[2]).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")' \
    "$PROJECT_ROOT" "$RESOURCE_CONFIG"

python3 -B scripts/dpdk_smoke.py preflight \
    --config "$RESOURCE_CONFIG" \
    --data-interface "$(
        python3 -B -c \
            'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["ubuntu_sensor"]["data_interface"])' \
            "$CONFIG"
    )" \
    --output "$PREFLIGHT" \
    --force

python3 -B -c \
    'import json,sys
preflight=json.load(open(sys.argv[1], encoding="utf-8"))
config=json.load(open(sys.argv[2], encoding="utf-8"))
name=config["ubuntu_sensor"]["data_interface"]
observed=preflight["discovery"]["interfaces"][name]["mac"].lower()
expected=config["ubuntu_sensor"]["expected_mac"].lower()
if observed != expected:
    raise SystemExit(f"sensor MAC mismatch: expected {expected}, observed {observed}")' \
    "$PREFLIGHT" "$CONFIG"

sudo -v

APPLIED=0
cleanup() {
    local status=$? rollback_status=0
    trap - EXIT INT TERM
    set +e
    printf '[NIDS] shutting down DPDK...\n'
    if ((APPLIED)); then
        sudo python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" rollback \
            --state "$STATE" \
            --output "$ROLLBACK" \
            --force
        rollback_status=$?
    fi
    if ((status == 0 && rollback_status != 0)); then
        status=$rollback_status
    fi
    if ((APPLIED == 0)); then
        printf '[NIDS] stopped before sensor NIC binding\n'
    elif ((rollback_status == 0)); then
        printf '[NIDS] sensor NIC restored\n'
        printf '[NIDS] stopped cleanly\n'
    else
        printf '[NIDS] ERROR: sensor NIC rollback failed\n' >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'printf "\n[NIDS] stopping...\n"; exit 130' INT
trap 'printf "\n[NIDS] stopping...\n"; exit 143' TERM

sudo python3 -B scripts/dpdk_smoke.py apply \
    --preflight "$PREFLIGHT" \
    --state "$STATE" \
    --force

APPLIED=1

PCI_ADDRESS="$(
    python3 -B -c \
        'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["original"]["pci_address"])' \
        "$STATE"
)"
readonly PCI_ADDRESS
[[ "$PCI_ADDRESS" =~ ^0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] || {
    printf 'error: invalid PCI address in runtime state: %s\n' "$PCI_ADDRESS" >&2
    exit 1
}

printf '[NIDS] initializing DPDK...\n'
printf '[NIDS] segment: %s (new process; flow state starts empty)\n' "$SEGMENT_ID"
printf '[NIDS] loading F9 model bundle: %s\n' "$BUNDLE"
printf '[NIDS] alerts: %s\n' "$DETECTION_LOG"

sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$BINARY" \
    -l 0 -n 2 -a "$PCI_ADDRESS" -m 256 \
    "--file-prefix=nids-t85-$SEGMENT_ID" --huge-unlink=always --no-telemetry \
    '--log-level=*:warning' \
    -- --bundle "$BUNDLE" --port-id 0 \
    --max-packets 0 --min-packets 0 --min-f9 0 --min-alerts 0 \
    --idle-timeout-ms 0 --mtu 9000 --require-promiscuous \
    | tee "$DETECTION_LOG"
