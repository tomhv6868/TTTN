#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    printf 'usage: bash scripts/run_t91_live_engine_ubuntu.sh\n' >&2
}

if (($#)); then
    case "$1" in
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
fi

[[ "$(uname -s)" == Linux ]] || {
    printf 'error: this launcher must run inside Ubuntu\n' >&2
    exit 1
}
((EUID != 0)) || {
    printf 'error: run as the Ubuntu user; the sensor wrapper manages sudo\n' >&2
    exit 2
}

for command_name in bash date flock kill mv python3 sleep; do
    command -v "$command_name" >/dev/null || {
        printf 'error: required command is not installed: %s\n' "$command_name" >&2
        exit 1
    }
done

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly CONFIG="$PROJECT_ROOT/config/t91-live-campaign.json"
readonly RUN_ROOT="$PROJECT_ROOT/run_log/full-flow-v1/live-engine"
readonly SENSOR_WRAPPER="$SCRIPT_DIR/ubuntu_t91_live_sensor.sh"
readonly LOCK_PATH="${XDG_RUNTIME_DIR:-/tmp}/nids-t91-live-engine-${UID}.lock"

exec 9>"$LOCK_PATH"
flock -n 9 || {
    printf 'error: another live engine run is active\n' >&2
    exit 1
}

CONTRACT="$(
    python3 -B - "$PROJECT_ROOT" "$CONFIG" "$RUN_ROOT" <<'PY'
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


project_root = Path(sys.argv[1]).resolve()
config_path = Path(sys.argv[2]).resolve()
run_root = Path(sys.argv[3])
config = json.loads(
    config_path.read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicate_keys,
)
if (
    config.get("schema_version") != "2.0.0"
    or config.get("task") != "T9.1"
    or config.get("kind") != "terminal_live_campaign_config"
):
    raise SystemExit("invalid live campaign config")

target_ip = str(
    ipaddress.IPv4Address(config["topology"]["windows"]["target_ip"])
)
model = dict(config["model"])
dpdk = dict(config["dpdk"])
bundle_manifest = (
    project_root / model["bundle_directory"] / "manifest.json"
).resolve()
resource_config = (project_root / dpdk["resource_config"]).resolve()
for path in (bundle_manifest, resource_config):
    path.relative_to(project_root)
    if not path.is_file():
        raise SystemExit(f"missing locked artifact: {path}")
if sha256(bundle_manifest) != model["bundle_manifest_sha256"]:
    raise SystemExit("bundle manifest SHA-256 mismatch")
if sha256(resource_config) != dpdk["resource_config_sha256"]:
    raise SystemExit("DPDK resource config SHA-256 mismatch")

if run_root.exists() and run_root.is_symlink():
    raise SystemExit(f"run root must not be a symlink: {run_root}")
run_root.mkdir(parents=True, exist_ok=True)
if not run_root.is_dir():
    raise SystemExit(f"run root is not a directory: {run_root}")

state_path = run_root / ".next-id"
next_id = 1
if state_path.exists():
    if state_path.is_symlink() or not state_path.is_file():
        raise SystemExit("invalid live engine ID state")
    state_text = state_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[1-9][0-9]*", state_text):
        raise SystemExit("invalid live engine next ID")
    next_id = int(state_text)

for entry in run_root.iterdir():
    match = re.fullmatch(r"run-([0-9]{6})", entry.name)
    if match:
        next_id = max(next_id, int(match.group(1)) + 1)
if next_id > 999_999:
    raise SystemExit("live engine run ID space is exhausted")

run_id = f"run-{next_id:06d}"
run_dir = run_root / run_id
run_dir.mkdir()

state_tmp = run_root / f".next-id.{os.getpid()}.tmp"
try:
    with state_tmp.open("x", encoding="ascii", newline="\n") as output:
        output.write(f"{next_id + 1}\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(state_tmp, state_path)
finally:
    state_tmp.unlink(missing_ok=True)

bounds = {
    "ready_timeout_seconds": config["bounds"]["ready_timeout_seconds"],
}
dpdk["file_prefix"] = f"nids-{run_id}"
contract = {
    "schema_version": "2.0.0",
    "task": "T9.1",
    "kind": "terminal_live_run_contract",
    "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    ),
    "case_id": "live-engine",
    "scenario_label": "Live engine",
    "expected_model_family": "observational",
    "attempt_id": f"t91-live-engine-{next_id:06d}",
    "run_token": f"rt-live-engine-{next_id:06d}",
    "config": {
        "path": str(config_path),
        "sha256": sha256(config_path),
    },
    "artifact_root": "run_log/full-flow-v1/live-engine",
    "topology": {
        "network": config["topology"]["data_network"]["name"],
        "scope_mode": "target_ip",
        "target_ip": target_ip,
        "ubuntu_interface": config["topology"]["ubuntu"]["interface"],
        "ubuntu_expected_mac": config["topology"]["ubuntu"]["expected_mac"],
    },
    "model": model,
    "dpdk": dpdk,
    "bounds": bounds,
    "lifecycle": {
        "mode": "signal_only",
        "lease_timeout_seconds": 10,
        "shutdown_grace_ms": 5_000,
    },
    "output": {"mode": "alerts_only"},
    "acceptance": {"mode": "observational"},
    "tool": {"name": "external", "bounded": False},
}
contract_path = run_dir / "contract.json"
with contract_path.open("x", encoding="utf-8", newline="\n") as output:
    json.dump(contract, output, indent=2, sort_keys=True)
    output.write("\n")
(run_dir / "alerts.jsonl").open("x", encoding="utf-8").close()
print(contract_path.resolve())
PY
)"

readonly CONTRACT
readonly RUN_DIR="$(dirname -- "$CONTRACT")"
readonly RUN_ID="$(basename -- "$RUN_DIR")"
readonly SUPERVISOR_PID="$RUN_DIR/ubuntu/supervisor.pid"
readonly SENSOR_LOG="$RUN_DIR/ubuntu/sensor.jsonl"
readonly ALERTS="$RUN_DIR/alerts.jsonl"
readonly HEARTBEAT="$RUN_DIR/operator.heartbeat"
readonly HEARTBEAT_STAGING="$RUN_DIR/.operator.heartbeat.$$"

HEARTBEAT_PID=0

write_heartbeat() {
    printf '%s\n' "$(date +%s)" >"$HEARTBEAT_STAGING"
    mv -f -- "$HEARTBEAT_STAGING" "$HEARTBEAT"
}

heartbeat_loop() {
    local owner_pid="$1"
    while kill -0 "$owner_pid" 2>/dev/null; do
        sleep 2
        kill -0 "$owner_pid" 2>/dev/null || return 0
        write_heartbeat
    done
}

start_heartbeat() {
    write_heartbeat
    heartbeat_loop "$$" &
    HEARTBEAT_PID=$!
}

stop_heartbeat() {
    if ((HEARTBEAT_PID > 0)); then
        kill -TERM "$HEARTBEAT_PID" 2>/dev/null || true
        wait "$HEARTBEAT_PID" 2>/dev/null || true
        HEARTBEAT_PID=0
    fi
}

stop_sensor() {
    bash "$SENSOR_WRAPPER" stop --contract "$CONTRACT" >/dev/null 2>&1 || true
}

recover_sensor() {
    bash "$SENSOR_WRAPPER" recover --contract "$CONTRACT" >/dev/null 2>&1 || true
}

wait_for_supervisor() {
    local pid=""
    if [[ -s "$SUPERVISOR_PID" ]]; then
        pid="$(<"$SUPERVISOR_PID")"
    fi
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
        while kill -0 "$pid" 2>/dev/null; do
            sleep 0.2 || true
        done
    fi
}

SIGNAL_STATUS=0
handle_signal() {
    SIGNAL_STATUS="$1"
    stop_heartbeat
    stop_sensor
}
trap stop_heartbeat EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

printf '[live-engine] id: %s\n' "$RUN_ID"
printf '[live-engine] output: %s\n' "$RUN_DIR"
printf '[live-engine] alerts: %s\n' "$ALERTS"
printf '[live-engine] stop: Ctrl+C\n'

start_heartbeat
set +e
bash "$SENSOR_WRAPPER" start --contract "$CONTRACT"
START_STATUS=$?
set -e
if ((START_STATUS != 0)); then
    stop_heartbeat
    if ((SIGNAL_STATUS)); then
        stop_sensor
    else
        recover_sensor
    fi
fi
wait_for_supervisor
stop_heartbeat
if ((SIGNAL_STATUS == 0)); then
    recover_sensor
fi
trap - HUP INT TERM

set +e
FINAL_STATUS="$(
    python3 -B - "$SENSOR_LOG" "$ALERTS" \
        "$RUN_DIR/ubuntu/sensor.json" \
        "$RUN_DIR/ubuntu/summary.json" \
        "$RUN_DIR/ubuntu/rollback.json" \
        "$CONTRACT" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    sensor_log,
    alerts_path,
    receipt_path,
    summary_path,
    rollback_path,
    contract_path,
) = map(
    Path, sys.argv[1:]
)


def load(path):
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON document is not an object: {path}")
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_alert(event, line_number, source_name, expected_ordinal):
    if not isinstance(event, dict):
        raise SystemExit(
            f"{source_name} event is not an object at line {line_number}"
        )
    if event.get("event_type") != "nids_terminal_flow_alert":
        raise SystemExit(
            f"{source_name} contains a non-alert event at line {line_number}"
        )
    for key, expected in expected_identity.items():
        if event.get(key) != expected:
            raise SystemExit(
                f"{source_name} alert identity mismatch at line "
                f"{line_number}: {key}"
            )
    if event.get("alert_ordinal") != expected_ordinal:
        raise SystemExit(
            f"{source_name} alert ordinal mismatch at line {line_number}"
        )


def parse_line(raw_line, line_number, source_name):
    if not raw_line.endswith(b"\n"):
        raise SystemExit(
            f"{source_name} has an unterminated line at {line_number}"
        )
    try:
        event = json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(
            f"invalid {source_name} JSONL at line {line_number}: {error}"
        )
    if not isinstance(event, dict):
        raise SystemExit(
            f"{source_name} event is not an object at line {line_number}"
        )
    return event


contract = load(contract_path)
receipt = load(receipt_path)
summary = load(summary_path)
rollback = load(rollback_path)
operator_stop = summary_path.parent / "stop.requested"
lease_expired = summary_path.parent / "lease.expired"
supervisor_failed = summary_path.parent / "supervisor.failed"
contract_sha256 = (
    sha256(contract_path)
    if contract_path.is_file()
    else None
)
expected_identity = {
    "attempt_id": contract.get("attempt_id"),
    "run_token": contract.get("run_token"),
    "run_contract_sha256": contract_sha256,
}

sensor_log_sha256 = None
sensor_alert_sha256 = None
sensor_alert_count = 0
if sensor_log.is_file():
    sensor_digest = hashlib.sha256()
    sensor_alert_digest = hashlib.sha256()
    with sensor_log.open("rb") as source:
        for line_number, raw_line in enumerate(source, start=1):
            sensor_digest.update(raw_line)
            event = parse_line(raw_line, line_number, "sensor")
            if event.get("event_type") == "nids_terminal_flow_alert":
                sensor_alert_count += 1
                validate_alert(
                    event,
                    line_number,
                    "sensor",
                    sensor_alert_count,
                )
                sensor_alert_digest.update(raw_line)
    sensor_log_sha256 = sensor_digest.hexdigest()
    sensor_alert_sha256 = sensor_alert_digest.hexdigest()

alert_log_sha256 = None
alert_count = 0
if alerts_path.is_file():
    alert_digest = hashlib.sha256()
    with alerts_path.open("rb") as source:
        for line_number, raw_line in enumerate(source, start=1):
            alert_digest.update(raw_line)
            event = parse_line(raw_line, line_number, "alert log")
            alert_count += 1
            validate_alert(event, line_number, "alert log", alert_count)
    alert_log_sha256 = alert_digest.hexdigest()

sensor_log_record = receipt.get("sensor_log")
if not isinstance(sensor_log_record, dict):
    sensor_log_record = {}
alert_log_record = receipt.get("alert_log")
if not isinstance(alert_log_record, dict):
    alert_log_record = {}
identity_matches = all(
    receipt.get(key) == expected
    and summary.get(key) == expected
    for key, expected in expected_identity.items()
)
sensor_log_matches = (
    sensor_log.is_file()
    and sensor_log_record.get("path") == str(sensor_log.resolve())
    and sensor_log_record.get("sha256") == sensor_log_sha256
)
alert_log_matches = (
    alerts_path.is_file()
    and alert_log_record.get("path") == str(alerts_path.resolve())
    and alert_log_record.get("sha256") == alert_log_sha256
)
alert_count_matches = (
    summary.get("alerts") == alert_count
    and sensor_alert_count == alert_count
    and sensor_alert_sha256 == alert_log_sha256
)
lifecycle = contract.get("lifecycle")
lifecycle_contract_matches = (
    isinstance(lifecycle, dict)
    and set(lifecycle) == {
        "mode",
        "lease_timeout_seconds",
        "shutdown_grace_ms",
    }
    and lifecycle.get("mode") == "signal_only"
    and isinstance(lifecycle.get("lease_timeout_seconds"), int)
    and not isinstance(lifecycle.get("lease_timeout_seconds"), bool)
    and 3 <= lifecycle["lease_timeout_seconds"] <= 300
    and isinstance(lifecycle.get("shutdown_grace_ms"), int)
    and not isinstance(lifecycle.get("shutdown_grace_ms"), bool)
    and 1 <= lifecycle["shutdown_grace_ms"] <= 30_000
    and contract.get("tool") == {"name": "external", "bounded": False}
)
lifecycle_summary_matches = (
    lifecycle_contract_matches
    and summary.get("bounded") is False
    and summary.get("lifecycle_mode") == "signal_only"
    and summary.get("shutdown_grace_ms")
        == lifecycle["shutdown_grace_ms"]
)
termination_matches = (
    receipt.get("termination_cause") == "operator_request"
    and operator_stop.is_file()
    and not lease_expired.exists()
    and not supervisor_failed.exists()
)
accounting_names = (
    "alerts",
    "attack_decisions",
    "benign_decisions",
    "decision_diagnostics_suppressed",
    "decision_event_limit",
    "decision_event_limit_rejections",
    "decision_events",
    "inferences",
)
accounting = {name: summary.get(name) for name in accounting_names}
accounting_is_unsigned = all(
    isinstance(value, int)
    and not isinstance(value, bool)
    and value >= 0
    for value in accounting.values()
)
runtime_accounting_matches = (
    contract.get("output") == {"mode": "alerts_only"}
    and summary.get("output_mode") == "alerts_only"
    and summary.get("decision_event_policy") == "disabled_alerts_only"
    and summary.get("decision_diagnostics_complete") is False
    and summary.get("alerts_complete") is True
    and accounting_is_unsigned
    and accounting["decision_event_limit"] == 0
    and accounting["decision_event_limit_rejections"] == 0
    and accounting["decision_events"] == 0
    and accounting["decision_diagnostics_suppressed"]
        == accounting["inferences"]
    and accounting["alerts"] == accounting["attack_decisions"]
    and accounting["benign_decisions"] + accounting["attack_decisions"]
        == accounting["inferences"]
)
integrity_verified = (
    identity_matches
    and sensor_log_matches
    and alert_log_matches
    and alert_count_matches
    and lifecycle_summary_matches
    and termination_matches
    and runtime_accounting_matches
)
passed = (
    receipt.get("status") == "passed"
    and summary.get("status") == "passed"
    and summary.get("stop_reason") == "signal"
    and rollback.get("status") == "passed"
    and integrity_verified
)
failure_reasons = []
if receipt.get("status") != "passed":
    failure_reasons.append("sensor_receipt_failed")
if receipt.get("sensor_return_code") not in (None, 0):
    failure_reasons.append(
        f"sensor_return_code:{receipt['sensor_return_code']}"
    )
if summary.get("status") != "passed":
    failure_reasons.append("summary_failed")
for key in ("pipeline_failure", "inference_failure"):
    if summary.get(key):
        failure_reasons.append(f"{key}:{summary[key]}")
if summary.get("shutdown_complete") is False:
    failure_reasons.append("shutdown_incomplete")
if summary.get("decision_event_limit_rejections", 0):
    failure_reasons.append(
        "decision_event_limit_rejections:"
        f"{summary['decision_event_limit_rejections']}"
    )
errors = summary.get("errors")
if isinstance(errors, dict):
    for key, value in sorted(errors.items()):
        if value:
            failure_reasons.append(f"error_{key}:{value}")
port_stats = summary.get("port_stats")
if isinstance(port_stats, dict):
    for key in ("imissed", "ierrors", "rx_nombuf", "oerrors"):
        value = port_stats.get(key)
        if value:
            failure_reasons.append(f"dpdk_{key}:{value}")
if rollback.get("status") != "passed":
    failure_reasons.append("rollback_failed")
if not sensor_log_matches:
    failure_reasons.append("sensor_log_integrity_failed")
if not alert_log_matches:
    failure_reasons.append("alert_log_integrity_failed")
if not alert_count_matches:
    failure_reasons.append("alert_accounting_failed")
if not lifecycle_contract_matches:
    failure_reasons.append("lifecycle_contract_failed")
elif not lifecycle_summary_matches:
    failure_reasons.append("lifecycle_summary_failed")
if not termination_matches:
    failure_reasons.append("termination_evidence_failed")
if (
    summary.get("status") == "passed"
    and summary.get("stop_reason") != "signal"
):
    failure_reasons.append(
        f"unexpected_stop_reason:{summary.get('stop_reason')}"
    )
if not runtime_accounting_matches:
    failure_reasons.append("runtime_accounting_failed")
if not integrity_verified:
    failure_reasons.append("integrity_failed")
print(
    json.dumps(
        {
            "alert_count": alert_count,
            "failure_reasons": failure_reasons,
            "integrity_verified": integrity_verified,
            "status": "passed" if passed else "failed",
        },
        sort_keys=True,
    )
)
raise SystemExit(0 if passed else 1)
PY
)"
COLLECT_STATUS=$?
set -e

printf '[live-engine] result: %s\n' "$FINAL_STATUS"
if ((SIGNAL_STATUS)); then
    exit "$SIGNAL_STATUS"
fi
if ((START_STATUS != 0 || COLLECT_STATUS != 0)); then
    exit 1
fi
