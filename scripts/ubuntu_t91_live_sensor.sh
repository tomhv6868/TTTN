#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage:
  bash scripts/ubuntu_t91_live_sensor.sh start --contract PATH
  bash scripts/ubuntu_t91_live_sensor.sh status --contract PATH
  bash scripts/ubuntu_t91_live_sensor.sh stop --contract PATH
  bash scripts/ubuntu_t91_live_sensor.sh recover --contract PATH
  bash scripts/ubuntu_t91_live_sensor.sh supervise --contract PATH --contract-sha256 HEX
EOF
}

ACTION="${1:-}"
[[ -n "$ACTION" ]] || { usage; exit 2; }
shift

CONTRACT=""
CONTRACT_SHA256=""
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
TOOLCHAIN_ENV="$HOME/.local/nids-toolchain/env.sh"

while (($#)); do
    case "$1" in
        --contract) [[ $# -ge 2 ]] || { usage; exit 2; }; CONTRACT="$2"; shift 2 ;;
        --contract-sha256) [[ $# -ge 2 ]] || { usage; exit 2; }; CONTRACT_SHA256="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'error: unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$CONTRACT" ]] || { usage; exit 2; }
[[ -f "$CONTRACT" ]] || { printf 'error: missing contract: %s\n' "$CONTRACT" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || { printf 'error: this wrapper must run inside Ubuntu\n' >&2; exit 1; }
((EUID != 0)) || { printf 'error: run as the Ubuntu user; sudo is invoked only for DPDK operations\n' >&2; exit 2; }

for command_name in cmake date flock kill python3 setsid sha256sum sudo timeout; do
    command -v "$command_name" >/dev/null || {
        printf 'error: required command is not installed: %s\n' "$command_name" >&2
        exit 1
    }
done
[[ -f "$TOOLCHAIN_ENV" ]] || {
    printf 'error: missing toolchain environment: %s\n' "$TOOLCHAIN_ENV" >&2
    exit 1
}

contract_env() {
    python3 -B - "$CONTRACT" <<'PY'
import hashlib
import ipaddress
import json
import re
import shlex
import sys
from pathlib import Path

contract_path = Path(sys.argv[1]).resolve()
document = json.loads(contract_path.read_text(encoding="utf-8"))
if document.get("schema_version") != "2.0.0" or document.get("task") != "T9.1":
    raise SystemExit("invalid contract header")
if document.get("kind") != "terminal_live_run_contract":
    raise SystemExit("invalid contract kind")
for key in ("attempt_id", "run_token", "case_id", "scenario_label", "expected_model_family"):
    if not isinstance(document.get(key), str) or not document[key].strip():
        raise SystemExit(f"contract missing {key}")
token = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
if not token.fullmatch(document["attempt_id"]) or not token.fullmatch(document["run_token"]):
    raise SystemExit("invalid token")
topology = document["topology"]
scope_mode = topology.get("scope_mode", "endpoint_pair")
target = str(ipaddress.ip_address(topology["target_ip"]))
if scope_mode == "endpoint_pair":
    source = str(ipaddress.ip_address(topology["source_ip"]))
    if source == target:
        raise SystemExit("source and target IP must differ")
elif scope_mode == "target_ip":
    if topology.get("source_ip") is not None:
        raise SystemExit("target_ip scope must not contain source_ip")
    source = ""
else:
    raise SystemExit(f"invalid scope mode: {scope_mode}")
output = document.get("output", {"mode": "diagnostic"})
if not isinstance(output, dict) or set(output) != {"mode"}:
    raise SystemExit("invalid output contract")
output_mode = output["mode"]
if output_mode not in {"diagnostic", "alerts_only"}:
    raise SystemExit(f"invalid output mode: {output_mode}")
bounds = document["bounds"]
if not isinstance(bounds, dict):
    raise SystemExit("invalid bounds contract")


def bounded_integer(name, minimum, maximum):
    value = bounds.get(name)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise SystemExit(f"invalid bound: {name}")
    return value


ready_timeout_seconds = bounded_integer(
    "ready_timeout_seconds", 1, 300
)
lifecycle = document.get("lifecycle")
if lifecycle is None:
    lifecycle_mode = "bounded"
elif not isinstance(lifecycle, dict):
    raise SystemExit("invalid lifecycle contract")
else:
    lifecycle_mode = lifecycle.get("mode")

if lifecycle_mode == "bounded":
    if lifecycle is not None and set(lifecycle) != {"mode"}:
        raise SystemExit("invalid bounded lifecycle contract")
    max_packets = bounded_integer("max_packets", 1, 100_000_000)
    max_runtime_ms = bounded_integer("max_runtime_ms", 1, 300_000)
    arm_timeout_ms = bounded_integer(
        "arm_timeout_ms", 1, max_runtime_ms
    )
    idle_timeout_ms = bounded_integer(
        "idle_timeout_ms", 1, max_runtime_ms
    )
    sensor_outer_timeout_seconds = bounded_integer(
        "sensor_outer_timeout_seconds", 1, 600
    )
    shutdown_grace_ms = 0
    lease_timeout_seconds = 0
elif lifecycle_mode == "signal_only":
    if (
        set(lifecycle)
        != {
            "lease_timeout_seconds",
            "mode",
            "shutdown_grace_ms",
        }
        or output_mode != "alerts_only"
        or set(bounds) != {"ready_timeout_seconds"}
    ):
        raise SystemExit("invalid signal-only lifecycle contract")
    shutdown_grace_ms = lifecycle["shutdown_grace_ms"]
    lease_timeout_seconds = lifecycle["lease_timeout_seconds"]
    for name, value, minimum, maximum in (
        ("shutdown_grace_ms", shutdown_grace_ms, 1, 30_000),
        ("lease_timeout_seconds", lease_timeout_seconds, 3, 300),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < minimum
            or value > maximum
        ):
            raise SystemExit(f"invalid lifecycle value: {name}")
    max_packets = 0
    max_runtime_ms = 0
    arm_timeout_ms = 0
    idle_timeout_ms = 0
    sensor_outer_timeout_seconds = 0
else:
    raise SystemExit(f"invalid lifecycle mode: {lifecycle_mode}")
values = {
    "ATTEMPT_ID": document["attempt_id"],
    "RUN_TOKEN": document["run_token"],
    "CASE_ID": document["case_id"],
    "SCOPE_MODE": scope_mode,
    "OUTPUT_MODE_CLI": output_mode.replace("_", "-"),
    "LIFECYCLE_MODE": lifecycle_mode,
    "LIFECYCLE_MODE_CLI": lifecycle_mode.replace("_", "-"),
    "LEASE_TIMEOUT_SECONDS": str(lease_timeout_seconds),
    "SHUTDOWN_GRACE_MS": str(shutdown_grace_ms),
    "SOURCE_IP": source,
    "TARGET_IP": target,
    "UBUNTU_INTERFACE": document["topology"]["ubuntu_interface"],
    "UBUNTU_EXPECTED_MAC": document["topology"]["ubuntu_expected_mac"],
    "BUNDLE_DIR": document["model"]["bundle_directory"],
    "MANIFEST_SHA256": document["model"]["bundle_manifest_sha256"],
    # Optional. Absent field means off, so every existing contract keeps
    # its behaviour and only a contract that asks for it samples latency.
    "BENCHMARK_METRICS": "1" if document.get("benchmark_metrics") else "",
    "DPDK_CONFIG": document["dpdk"]["resource_config"],
    "DPDK_CONFIG_SHA256": document["dpdk"]["resource_config_sha256"],
    "BINARY": document["dpdk"]["binary"],
    "PORT_ID": str(document["dpdk"]["port_id"]),
    "LCORES": document["dpdk"]["lcores"],
    "MEMORY_CHANNELS": str(document["dpdk"]["memory_channels"]),
    "MEMORY_MB": str(document["dpdk"]["memory_mb"]),
    "MTU": str(document["dpdk"]["mtu"]),
    "FILE_PREFIX": document["dpdk"]["file_prefix"],
    "SENSOR_OUTER_TIMEOUT_SECONDS": str(sensor_outer_timeout_seconds),
    "READY_TIMEOUT_SECONDS": str(ready_timeout_seconds),
    "MAX_PACKETS": str(max_packets),
    "MAX_RUNTIME_MS": str(max_runtime_ms),
    "ARM_TIMEOUT_MS": str(arm_timeout_ms),
    "IDLE_TIMEOUT_MS": str(idle_timeout_ms),
    "ATTEMPT_DIR": str(contract_path.parent),
    "CONTRACT_ABS": str(contract_path),
    "CONTRACT_SHA256_ACTUAL": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
}
for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
}

CONTRACT_ENV="$(contract_env)" || exit $?
eval "$CONTRACT_ENV"

UBUNTU_DIR="$ATTEMPT_DIR/ubuntu"
SUPERVISOR_PID="$UBUNTU_DIR/supervisor.pid"
SENSOR_PID_FILE="$UBUNTU_DIR/sensor.pid"
READY_JSON="$UBUNTU_DIR/ready.json"
SENSOR_JSON="$UBUNTU_DIR/sensor.json"
SENSOR_LOG="$UBUNTU_DIR/sensor.jsonl"
SUPERVISOR_LOG="$UBUNTU_DIR/supervisor.log"
STATE_JSON="$UBUNTU_DIR/state.json"
PREFLIGHT_JSON="$UBUNTU_DIR/preflight.json"
RESOURCE_CONFIG="$UBUNTU_DIR/resource-config.json"
ROLLBACK_JSON="$UBUNTU_DIR/rollback.json"
ALERTS_LOG="$ATTEMPT_DIR/alerts.jsonl"
HEARTBEAT="$ATTEMPT_DIR/operator.heartbeat"
STOP_REQUEST="$UBUNTU_DIR/stop.requested"
LEASE_EXPIRED="$UBUNTU_DIR/lease.expired"
SUPERVISOR_FAILED="$UBUNTU_DIR/supervisor.failed"
RECOVERY_LOCK="${XDG_RUNTIME_DIR:-/tmp}/nids-t91-recovery-${ATTEMPT_ID}.lock"

actual_contract_sha() {
    sha256sum -- "$CONTRACT" | awk '{print $1}'
}

write_status_json() {
    python3 -B - "$UBUNTU_DIR" "$ATTEMPT_ID" <<'PY'
import json
import os
import sys
from pathlib import Path
root = Path(sys.argv[1])
pid_path = root / "supervisor.pid"
pid = None
running = False
if pid_path.exists():
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        running = True
    except Exception:
        running = False
print(json.dumps({
    "schema_version": "1.0.0",
    "operation": "status",
    "role": "ubuntu",
    "attempt_id": sys.argv[2],
    "status": "running" if running else ("complete" if (root / "sensor.json").exists() else "pending"),
    "ready": (root / "ready.json").exists(),
    "supervisor_pid": pid,
    "sensor_receipt": str(root / "sensor.json"),
    "rollback": str(root / "rollback.json"),
}, sort_keys=True))
PY
}

extract_event() {
    local event_type="$1" destination="$2"
    python3 -B - "$SENSOR_LOG" "$event_type" "$destination" <<'PY'
import json
import sys
from pathlib import Path
log_path = Path(sys.argv[1])
event_type = sys.argv[2]
destination = Path(sys.argv[3])
if not log_path.exists():
    raise SystemExit(1)
with log_path.open("r", encoding="utf-8", errors="replace") as source:
    for line in source:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == event_type:
            destination.write_text(
                json.dumps(event, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            raise SystemExit(0)
raise SystemExit(1)
PY
}

heartbeat_is_fresh() {
    local heartbeat_epoch="" now=""
    [[ -f "$HEARTBEAT" && ! -L "$HEARTBEAT" ]] || return 1
    IFS= read -r heartbeat_epoch <"$HEARTBEAT" || return 1
    [[ "$heartbeat_epoch" =~ ^[0-9]{10}$ ]] || return 1
    now="$(date +%s)"
    ((heartbeat_epoch <= now + 5)) || return 1
    ((now - heartbeat_epoch < LEASE_TIMEOUT_SECONDS))
}

read_sensor_pgid() {
    [[ -e "$SENSOR_PID_FILE" || -L "$SENSOR_PID_FILE" ]] || return 1
    [[ -f "$SENSOR_PID_FILE" && ! -L "$SENSOR_PID_FILE" ]] || return 2
    local pgid=""
    pgid="$(<"$SENSOR_PID_FILE")" || return 2
    [[ "$pgid" =~ ^[1-9][0-9]*$ ]] && ((pgid > 1)) || return 2
    printf '%s\n' "$pgid"
}

matching_sensor_groups() {
    local expected_pgid="${1:-}"
    NIDS_T91_ATTEMPT_ID="$ATTEMPT_ID" \
    NIDS_T91_RUN_TOKEN="$RUN_TOKEN" \
    NIDS_T91_CONTRACT_SHA256="$CONTRACT_SHA256_ACTUAL" \
    NIDS_T91_EXPECTED_PGID="$expected_pgid" \
        python3 -B - <<'PY'
import os
from pathlib import Path

required = {
    b"--attempt-id": os.environ["NIDS_T91_ATTEMPT_ID"].encode(),
    b"--run-token": os.environ["NIDS_T91_RUN_TOKEN"].encode(),
    b"--run-contract-sha256": os.environ[
        "NIDS_T91_CONTRACT_SHA256"
    ].encode(),
}
expected_text = os.environ.get("NIDS_T91_EXPECTED_PGID", "")
expected = int(expected_text) if expected_text else None
matching = set()
expected_seen = False
expected_unreadable = False

for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    pid = int(entry.name)
    try:
        process_state = (
            (entry / "stat")
            .read_text(encoding="ascii", errors="replace")
            .split(") ", 1)[1]
            .split(maxsplit=1)[0]
        )
    except (IndexError, OSError, ProcessLookupError, PermissionError):
        continue
    if process_state == "Z":
        continue
    try:
        pgid = os.getpgid(pid)
    except (OSError, ProcessLookupError, PermissionError):
        continue
    if pgid <= 1:
        continue
    if pgid == expected:
        expected_seen = True
    try:
        arguments = [
            value
            for value in (entry / "cmdline").read_bytes().split(b"\0")
            if value
        ]
    except PermissionError:
        if pgid == expected:
            expected_unreadable = True
        continue
    except (OSError, ProcessLookupError):
        continue
    option_values = {}
    for index, argument in enumerate(arguments[:-1]):
        if argument in required:
            option_values.setdefault(argument, []).append(
                arguments[index + 1]
            )
    if all(option_values.get(name) == [value] for name, value in required.items()):
        matching.add(pgid)

if expected is not None and expected_seen and expected not in matching:
    detail = (
        "unreadable members"
        if expected_unreadable
        else "identity mismatch"
    )
    raise SystemExit(
        f"recorded sensor process group {expected} is alive with {detail}"
    )
for pgid in sorted(matching):
    print(pgid)
PY
}

verified_sensor_group() {
    local recorded_pgid="" groups=""
    recorded_pgid="$(read_sensor_pgid)" || return 1
    groups="$(matching_sensor_groups "$recorded_pgid")" || return 1
    [[ "$groups" == "$recorded_pgid" ]] || return 1
    printf '%s\n' "$recorded_pgid"
}

verified_supervisor() {
    python3 -B - "$SUPERVISOR_PID" "$CONTRACT_ABS" \
        "$CONTRACT_SHA256_ACTUAL" <<'PY'
import os
import sys
from pathlib import Path

pid_path = Path(sys.argv[1])
if not pid_path.is_file():
    raise SystemExit(1)
try:
    pid = int(pid_path.read_text(encoding="ascii").strip())
    arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    os.kill(pid, 0)
except (OSError, ValueError):
    raise SystemExit(1)
required = (
    b"supervise",
    sys.argv[2].encode(),
    sys.argv[3].encode(),
)
if pid <= 1 or not all(value in arguments for value in required):
    raise SystemExit(1)
print(pid)
PY
}

sensor_group_alive() {
    local pgid="$1" groups=""
    groups="$(matching_sensor_groups "$pgid")" || return 2
    while IFS= read -r observed; do
        [[ "$observed" == "$pgid" ]] && return 0
    done <<<"$groups"
    return 1
}

signal_sensor_group() {
    local signal_name="$1" pgid="$2"
    [[ "$pgid" =~ ^[1-9][0-9]*$ ]] && ((pgid > 1)) || return 1
    kill "-$signal_name" -- "-$pgid" 2>/dev/null \
        || sudo -n kill "-$signal_name" -- "-$pgid" 2>/dev/null
}

wait_sensor_group_exit() {
    local pgid="$1" wait_ms="$2" observed_status=0
    local deadline=$((SECONDS + (wait_ms + 999) / 1000))
    while ((SECONDS < deadline)); do
        if sensor_group_alive "$pgid"; then
            sleep 0.1
            continue
        else
            observed_status=$?
        fi
        ((observed_status == 1)) && return 0
        return 2
    done
    if sensor_group_alive "$pgid"; then
        return 1
    else
        observed_status=$?
    fi
    ((observed_status == 1)) && return 0
    return 2
}

stop_sensor_group() {
    local pgid="$1" grace_ms="$2" observed_status=0
    [[ "$pgid" =~ ^[1-9][0-9]*$ ]] && ((pgid > 1)) || return 1
    if sensor_group_alive "$pgid"; then
        :
    else
        observed_status=$?
        ((observed_status == 1)) && return 0
        return 1
    fi
    if signal_sensor_group TERM "$pgid"; then
        :
    else
        if sensor_group_alive "$pgid"; then
            :
        else
            observed_status=$?
            ((observed_status == 1)) && return 0
        fi
        return 1
    fi
    if wait_sensor_group_exit "$pgid" "$grace_ms"; then
        return 0
    else
        observed_status=$?
    fi
    ((observed_status == 2)) && return 1
    if signal_sensor_group KILL "$pgid"; then
        :
    else
        if sensor_group_alive "$pgid"; then
            :
        else
            observed_status=$?
            ((observed_status == 1)) && return 0
        fi
        return 1
    fi
    wait_sensor_group_exit "$pgid" 2000
}

stop_discovered_sensor_groups() {
    local grace_ms="$1" groups="" pgid=""
    groups="$(matching_sensor_groups)" || return 1
    [[ -n "$groups" ]] || return 0
    while IFS= read -r pgid; do
        stop_sensor_group "$pgid" "$grace_ms" || return 1
    done <<<"$groups"
    groups="$(matching_sensor_groups)" || return 1
    [[ -z "$groups" ]]
}

ensure_sensor_quiescent() {
    local groups="" recorded_pgid="" observed_status=0
    groups="$(matching_sensor_groups)" || return 1
    if [[ -n "$groups" ]]; then
        printf 'error: matching orphan sensor group(s) remain: %s\n' \
            "${groups//$'\n'/,}" >&2
        return 1
    fi
    if [[ -e "$SENSOR_PID_FILE" || -L "$SENSOR_PID_FILE" ]]; then
        recorded_pgid="$(read_sensor_pgid)" || {
            printf 'error: sensor PGID evidence is not a valid regular file\n' >&2
            return 1
        }
        if sensor_group_alive "$recorded_pgid"; then
            printf 'error: recorded sensor process group remains alive: %s\n' \
                "$recorded_pgid" >&2
            return 1
        else
            observed_status=$?
        fi
        if ((observed_status != 1)); then
            printf 'error: recorded sensor process group cannot be verified quiescent: %s\n' \
                "$recorded_pgid" >&2
            return 1
        fi
    fi
}

case "$ACTION" in
    start)
        mkdir -p -- "$UBUNTU_DIR"
        [[ ! -e "$SENSOR_JSON" && ! -e "$READY_JSON" ]] || {
            printf 'error: Ubuntu evidence already exists for attempt %s\n' "$ATTEMPT_ID" >&2
            exit 1
        }
        ensure_sensor_quiescent || {
            printf 'error: refusing to start while prior sensor state is unsafe\n' >&2
            exit 1
        }
        CONTRACT_SHA256="$(actual_contract_sha)"
        # shellcheck disable=SC1090
        source "$TOOLCHAIN_ENV"
        (
            cd "$PROJECT_ROOT"
            cmake --preset ubuntu-release \
                -DNIDS_BUILD_MODEL_RUNTIME=ON \
                -DNIDS_BUILD_DPDK=ON
            cmake --build --preset ubuntu-release --target nids_t91_terminal_live -j 2
        )
        nohup bash "$0" supervise --contract "$CONTRACT_ABS" --contract-sha256 "$CONTRACT_SHA256" >"$SUPERVISOR_LOG" 2>&1 &
        echo "$!" >"$SUPERVISOR_PID"
        deadline=$((SECONDS + READY_TIMEOUT_SECONDS))
        while ((SECONDS < deadline)); do
            if [[ -s "$READY_JSON" ]]; then
                printf '{"operation":"start","status":"ready","attempt_id":"%s","ready":"%s"}\n' "$ATTEMPT_ID" "$READY_JSON"
                exit 0
            fi
            if ! kill -0 "$(cat "$SUPERVISOR_PID")" 2>/dev/null; then
                printf 'error: supervisor exited before READY; see %s\n' "$SUPERVISOR_LOG" >&2
                exit 1
            fi
            sleep 0.2
        done
        printf 'error: READY timeout after %s seconds; see %s\n' "$READY_TIMEOUT_SECONDS" "$SUPERVISOR_LOG" >&2
        exit 1
        ;;
    supervise)
        [[ "$CONTRACT_SHA256" =~ ^[0-9a-f]{64}$ ]] || { printf 'error: missing contract hash\n' >&2; exit 2; }
        [[ "$CONTRACT_SHA256_ACTUAL" == "$CONTRACT_SHA256" ]] || {
            printf 'error: contract hash drift: expected %s observed %s\n' "$CONTRACT_SHA256" "$CONTRACT_SHA256_ACTUAL" >&2
            exit 1
        }
        mkdir -p -- "$UBUNTU_DIR"
        exec 8>"$RECOVERY_LOCK"
        flock 8
        # shellcheck disable=SC1090
        source "$TOOLCHAIN_ENV"
        [[ "$(sha256sum -- "$PROJECT_ROOT/$DPDK_CONFIG" | awk '{print $1}')" == "$DPDK_CONFIG_SHA256" ]] || {
            printf 'error: DPDK resource config hash mismatch\n' >&2
            exit 1
        }
        if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
            [[ -f "$ALERTS_LOG" && ! -L "$ALERTS_LOG" && ! -s "$ALERTS_LOG" ]] || {
                printf 'error: signal-only alerts file must be empty and regular\n' >&2
                exit 1
            }
            if ! heartbeat_is_fresh; then
                : >"$LEASE_EXPIRED"
                printf 'error: signal-only heartbeat is missing or stale\n' >&2
                exit 1
            fi
        fi
        APPLIED=0
        SENSOR_PID=0
        SENSOR_PGID=0
        cleanup() {
            local status=$?
            local group_stopped=1
            local stop_grace_ms=3000
            trap - EXIT INT TERM
            set +e
            if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
                stop_grace_ms="$((SHUTDOWN_GRACE_MS + 2000))"
            fi
            if ((SENSOR_PID > 0)); then
                if ((SENSOR_PGID == 0)); then
                    SENSOR_PGID="$(verified_sensor_group 2>/dev/null || printf '0')"
                fi
                if ((SENSOR_PGID > 0)); then
                    stop_sensor_group "$SENSOR_PGID" "$stop_grace_ms" \
                        || group_stopped=0
                else
                    stop_discovered_sensor_groups "$stop_grace_ms" \
                        || group_stopped=0
                fi
                if ((group_stopped)); then
                    wait "$SENSOR_PID" 2>/dev/null
                fi
            fi
            if ((APPLIED && group_stopped)); then
                ensure_sensor_quiescent || group_stopped=0
            fi
            if ((!group_stopped)); then
                status=1
                printf 'error: sensor group remains alive; rollback withheld because the group is alive or unverifiable\n' >&2
            fi
            if ((APPLIED && group_stopped)); then
                sudo -n python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" rollback \
                    --state "$STATE_JSON" --output "$ROLLBACK_JSON" --force
                rollback_status=$?
            else
                rollback_status=0
            fi
            if ((status == 0 && rollback_status != 0)); then
                status=$rollback_status
            fi
            exit "$status"
        }
        trap cleanup EXIT
        trap 'exit 143' TERM
        trap 'exit 130' INT
        python3 -B - "$PROJECT_ROOT" "$RESOURCE_CONFIG" "$PROJECT_ROOT/$DPDK_CONFIG" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
import dpdk_passive_probe
import kali_passive_traffic
config_path = Path(sys.argv[3]).resolve()
config_path.relative_to(root)
config = kali_passive_traffic.load_and_validate_config(config_path)
document = dpdk_passive_probe.build_resource_config(config)
Path(sys.argv[2]).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
PY
        if [[ "$LIFECYCLE_MODE" == signal_only ]] && ! heartbeat_is_fresh; then
            : >"$LEASE_EXPIRED"
            printf 'error: launcher lease expired before preflight\n' >&2
            exit 1
        fi
        python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" preflight \
            --config "$RESOURCE_CONFIG" \
            --data-interface "$UBUNTU_INTERFACE" \
            --output "$PREFLIGHT_JSON" \
            --force
        python3 -B - "$PREFLIGHT_JSON" "$UBUNTU_INTERFACE" "$UBUNTU_EXPECTED_MAC" <<'PY'
import json
import sys
preflight = json.load(open(sys.argv[1], encoding="utf-8"))
observed = preflight["discovery"]["interfaces"][sys.argv[2]]["mac"].lower()
expected = sys.argv[3].lower()
if observed != expected:
    raise SystemExit(f"sensor MAC mismatch: expected {expected}, observed {observed}")
PY
        if [[ "$LIFECYCLE_MODE" == signal_only ]] && ! heartbeat_is_fresh; then
            : >"$LEASE_EXPIRED"
            printf 'error: launcher lease expired before DPDK apply\n' >&2
            exit 1
        fi
        sudo -n python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" apply \
            --preflight "$PREFLIGHT_JSON" --state "$STATE_JSON" --force
        APPLIED=1
        if [[ "$LIFECYCLE_MODE" == signal_only ]] && ! heartbeat_is_fresh; then
            : >"$LEASE_EXPIRED"
            printf 'error: launcher lease expired after DPDK apply\n' >&2
            exit 1
        fi
        PCI_ADDRESS="$(python3 -B -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["original"]["pci_address"])' "$STATE_JSON")"
        if [[ "$SCOPE_MODE" == target_ip ]]; then
            SCOPE_ARGUMENTS=(--any-source --target-ip "$TARGET_IP")
        else
            SCOPE_ARGUMENTS=(--source-ip "$SOURCE_IP" --target-ip "$TARGET_IP")
        fi
        BENCHMARK_ARGUMENTS=()
        if [[ -n "${BENCHMARK_METRICS:-}" ]]; then
            BENCHMARK_ARGUMENTS=(--benchmark-metrics)
        fi
        LIFECYCLE_ARGUMENTS=(--lifecycle-mode "$LIFECYCLE_MODE_CLI")
        if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
            LIFECYCLE_ARGUMENTS+=(
                --shutdown-grace-ms "$SHUTDOWN_GRACE_MS"
                --alerts-file "$ALERTS_LOG"
            )
            KILL_AFTER_SECONDS=$(( (SHUTDOWN_GRACE_MS + 999) / 1000 + 2 ))
        else
            LIFECYCLE_ARGUMENTS+=(
                --max-packets "$MAX_PACKETS"
                --max-runtime-ms "$MAX_RUNTIME_MS"
                --arm-timeout-ms "$ARM_TIMEOUT_MS"
                --idle-timeout-ms "$IDLE_TIMEOUT_MS"
            )
            KILL_AFTER_SECONDS=3
        fi
        setsid timeout --signal=TERM \
            --kill-after="${KILL_AFTER_SECONDS}s" \
            "${SENSOR_OUTER_TIMEOUT_SECONDS}s" \
            sudo -n env LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" "$BINARY" \
            -l "$LCORES" -n "$MEMORY_CHANNELS" -a "$PCI_ADDRESS" -m "$MEMORY_MB" \
            --file-prefix="$FILE_PREFIX" --huge-unlink=always --no-telemetry \
            '--log-level=*:warning' \
            -- --bundle "$PROJECT_ROOT/$BUNDLE_DIR" \
            --manifest-sha256 "$MANIFEST_SHA256" \
            "${SCOPE_ARGUMENTS[@]}" \
            --output-mode "$OUTPUT_MODE_CLI" \
            "${LIFECYCLE_ARGUMENTS[@]}" \
            --attempt-id "$ATTEMPT_ID" --run-token "$RUN_TOKEN" \
            --run-contract-sha256 "$CONTRACT_SHA256" \
            --port-id "$PORT_ID" --mtu "$MTU" --require-promiscuous \
            "${BENCHMARK_ARGUMENTS[@]}" \
            >"$SENSOR_LOG" 2>"$UBUNTU_DIR/sensor.stderr" &
        SENSOR_PID=$!
        echo "$SENSOR_PID" >"$SENSOR_PID_FILE"
        for _ in {1..20}; do
            SENSOR_PGID="$(verified_sensor_group 2>/dev/null || printf '0')"
            ((SENSOR_PGID > 0)) && break
            sleep 0.05
        done
        [[ "$SENSOR_PGID" == "$SENSOR_PID" ]] || {
            printf 'error: failed to verify the sensor process group\n' >&2
            exit 1
        }
        STOP_SENT=0
        while kill -0 "$SENSOR_PID" 2>/dev/null; do
            if [[ ! -e "$READY_JSON" ]] && extract_event nids_terminal_live_ready "$READY_JSON.tmp"; then
                mv -- "$READY_JSON.tmp" "$READY_JSON"
            fi
            if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
                SHOULD_STOP=0
                if [[ -e "$STOP_REQUEST" ]]; then
                    SHOULD_STOP=1
                elif ! heartbeat_is_fresh; then
                    : >"$LEASE_EXPIRED"
                    SHOULD_STOP=1
                fi
                if ((SHOULD_STOP)); then
                    if ((STOP_SENT == 0)); then
                        signal_sensor_group TERM "$SENSOR_PGID" || true
                        STOP_SENT=1
                    fi
                fi
            fi
            sleep 0.2
        done
        set +e
        wait "$SENSOR_PID"
        SENSOR_STATUS=$?
        set -e
        extract_event nids_terminal_live_summary "$UBUNTU_DIR/summary.json.tmp" && mv -- "$UBUNTU_DIR/summary.json.tmp" "$UBUNTU_DIR/summary.json" || true
        python3 -B - "$SENSOR_JSON" "$CONTRACT" "$CONTRACT_SHA256" \
            "$SENSOR_STATUS" "$SENSOR_LOG" "$READY_JSON" \
            "$UBUNTU_DIR/summary.json" "$ALERTS_LOG" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
(
    receipt,
    contract,
    contract_sha,
    status,
    log_path,
    ready_path,
    summary_path,
    alerts_path,
) = sys.argv[1:]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


contract_doc = json.loads(Path(contract).read_text(encoding="utf-8"))
log = Path(log_path)
alerts = Path(alerts_path)
ubuntu_root = Path(receipt).parent
lifecycle_mode = contract_doc.get("lifecycle", {}).get("mode", "bounded")
if lifecycle_mode == "signal_only":
    if (ubuntu_root / "lease.expired").exists():
        termination_cause = "lease_expired"
    elif (ubuntu_root / "supervisor.failed").exists():
        termination_cause = "supervisor_failed"
    elif (ubuntu_root / "stop.requested").exists():
        termination_cause = "operator_request"
    else:
        termination_cause = "unexpected_signal"
else:
    termination_cause = "bounded_runtime"
document = {
    "schema_version": "2.0.0",
    "task": "T9.1",
    "kind": "ubuntu_sensor_receipt",
    "status": "passed" if int(status) == 0 else "failed",
    "attempt_id": contract_doc["attempt_id"],
    "run_token": contract_doc["run_token"],
    "case_id": contract_doc["case_id"],
    "scenario_label": contract_doc["scenario_label"],
    "expected_model_family": contract_doc["expected_model_family"],
    "sensor_return_code": int(status),
    "termination_cause": termination_cause,
    "run_contract_sha256": contract_sha,
    "ready_observed": Path(ready_path).exists(),
    "summary_observed": Path(summary_path).exists(),
    "sensor_log": {
        "path": str(log.resolve()),
        "sha256": sha256(log) if log.exists() else None,
    },
    "alert_log": {
        "path": str(alerts.resolve()),
        "sha256": sha256(alerts) if alerts.exists() else None,
    },
}
with Path(receipt).open("x", encoding="utf-8", newline="\n") as output:
    json.dump(document, output, indent=2, sort_keys=True)
    output.write("\n")
PY
        exit "$SENSOR_STATUS"
        ;;
    status)
        write_status_json
        ;;
    stop)
        : >"$STOP_REQUEST"
        SENSOR_GROUPS="$(matching_sensor_groups)"
        if [[ -n "$SENSOR_GROUPS" ]]; then
            if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
                stop_discovered_sensor_groups "$((SHUTDOWN_GRACE_MS + 2000))"
            else
                stop_discovered_sensor_groups 3000
            fi
        else
            SUPERVISOR="$(verified_supervisor 2>/dev/null || printf '0')"
            ((SUPERVISOR > 0)) && kill -TERM "$SUPERVISOR" 2>/dev/null || true
        fi
        write_status_json
        ;;
    recover)
        : >"$SUPERVISOR_FAILED"
        if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
            stop_discovered_sensor_groups "$((SHUTDOWN_GRACE_MS + 2000))"
        else
            stop_discovered_sensor_groups 3000
        fi
        SUPERVISOR="$(verified_supervisor 2>/dev/null || printf '0')"
        ((SUPERVISOR > 0)) && kill -TERM "$SUPERVISOR" 2>/dev/null || true
        RECOVERY_WAIT_SECONDS=15
        if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
            RECOVERY_WAIT_SECONDS=$(( (SHUTDOWN_GRACE_MS + 999) / 1000 + 15 ))
        fi
        exec 8>"$RECOVERY_LOCK"
        flock -w "$RECOVERY_WAIT_SECONDS" 8 || {
            printf 'error: recovery owner did not release its lock\n' >&2
            exit 1
        }
        if [[ "$LIFECYCLE_MODE" == signal_only ]]; then
            stop_discovered_sensor_groups "$((SHUTDOWN_GRACE_MS + 2000))"
        else
            stop_discovered_sensor_groups 3000
        fi
        ensure_sensor_quiescent || {
            printf 'error: refusing rollback while sensor state is unsafe\n' >&2
            exit 1
        }
        if [[ -f "$STATE_JSON" && ! -f "$ROLLBACK_JSON" ]]; then
            sudo -n python3 -B "$PROJECT_ROOT/scripts/dpdk_smoke.py" rollback \
                --state "$STATE_JSON" --output "$ROLLBACK_JSON" --force
        fi
        write_status_json
        ;;
    *) usage; exit 2 ;;
esac
