#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage:
  bash scripts/kali_t91_live_campaign.sh init --case ftp-patator|portscan [--config PATH]
  bash scripts/kali_t91_live_campaign.sh send --contract PATH
  bash scripts/kali_t91_live_campaign.sh status --contract PATH
EOF
}

ACTION="${1:-}"
[[ -n "$ACTION" ]] || { usage; exit 2; }
shift

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
CONFIG="$PROJECT_ROOT/config/t91-live-campaign.json"
CASE_ID=""
CONTRACT=""

while (($#)); do
    case "$1" in
        --case) [[ $# -ge 2 ]] || { usage; exit 2; }; CASE_ID="$2"; shift 2 ;;
        --config) [[ $# -ge 2 ]] || { usage; exit 2; }; CONFIG="$2"; shift 2 ;;
        --contract) [[ $# -ge 2 ]] || { usage; exit 2; }; CONTRACT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'error: unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
done

require_command() {
    command -v "$1" >/dev/null || {
        printf 'error: required command is not installed: %s\n' "$1" >&2
        exit 1
    }
}

for command_name in awk date ip mktemp od python3 readlink sed seq sha256sum timeout tr; do
    require_command "$command_name"
done

[[ "$(uname -s)" == Linux ]] || {
    printf 'error: this wrapper must run inside the Kali Linux VM\n' >&2
    exit 1
}
((EUID != 0)) || {
    printf 'error: run as the Kali user; sudo is invoked only for nmap SYN scan\n' >&2
    exit 2
}

load_case_env() {
    python3 -B - "$CONFIG" "$CASE_ID" <<'PY'
import hashlib
import ipaddress
import json
import re
import shlex
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
case_id = sys.argv[2]
document = json.loads(config_path.read_text(encoding="utf-8"))
if document.get("schema_version") != "2.0.0" or document.get("task") != "T9.1":
    raise SystemExit("invalid config header")
if document.get("kind") != "terminal_live_campaign_config":
    raise SystemExit("invalid config kind")
cases = {item["id"]: item for item in document["cases"]}
if case_id not in cases:
    raise SystemExit(f"unknown case: {case_id}")
case = cases[case_id]
if case.get("status") != "supported":
    raise SystemExit(f"case is not supported by this harness: {case_id}")
for key in ("scenario_label", "expected_model_family", "tool"):
    if not isinstance(case.get(key), str) or not case[key].strip():
        raise SystemExit(f"case missing {key}: {case_id}")
target_ip = document["topology"]["windows"]["target_ip"]
ipaddress.ip_address(target_ip)
values = {
    "ARTIFACT_ROOT": document["artifact_root"],
    "KALI_INTERFACE": document["topology"]["kali"]["interface"],
    "KALI_EXPECTED_DRIVER": document["topology"]["kali"]["expected_driver"],
    "TARGET_IP": target_ip,
    "SCENARIO_LABEL": case["scenario_label"],
    "EXPECTED_MODEL_FAMILY": case["expected_model_family"],
    "TOOL": case["tool"],
    "CONFIG_SHA256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
    "SENDER_TIMEOUT_SECONDS": str(document["bounds"]["sender_timeout_seconds"]),
    "FTP_WRONG_PASSWORDS": str(document["bounds"]["ftp_wrong_passwords"]),
    "FTP_THREADS": str(document["bounds"]["ftp_threads"]),
    "FTP_USERNAME": document["target"]["ftp_username"],
    "PORTSCAN_PORTS": document["bounds"]["portscan_ports"],
    "PORTSCAN_MAX_RATE": str(document["bounds"]["portscan_max_rate"]),
    "PORTSCAN_MAX_RETRIES": str(document["bounds"]["portscan_max_retries"]),
    "PORTSCAN_HOST_TIMEOUT_SECONDS": str(document["bounds"]["portscan_host_timeout_seconds"]),
}
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", values["KALI_INTERFACE"]):
    raise SystemExit("invalid Kali interface in config")
for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
}

load_contract_env() {
    python3 -B - "$CONTRACT" <<'PY'
import json
import re
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
document = json.loads(path.read_text(encoding="utf-8"))
required = (
    "attempt_id",
    "run_token",
    "case_id",
    "scenario_label",
    "expected_model_family",
)
for key in required:
    if not isinstance(document.get(key), str) or not document[key].strip():
        raise SystemExit(f"contract missing {key}")
if document.get("schema_version") != "2.0.0" or document.get("task") != "T9.1":
    raise SystemExit("invalid contract header")
if document.get("kind") != "terminal_live_run_contract":
    raise SystemExit("invalid contract kind")
token = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
if not token.fullmatch(document["attempt_id"]) or not token.fullmatch(document["run_token"]):
    raise SystemExit("invalid run token in contract")
values = {
    "ATTEMPT_ID": document["attempt_id"],
    "CASE_ID": document["case_id"],
    "SOURCE_IP": document["topology"]["source_ip"],
    "TARGET_IP": document["topology"]["target_ip"],
    "KALI_INTERFACE": document["topology"]["kali_interface"],
    "TOOL": document["tool"]["name"],
    "SENDER_TIMEOUT_SECONDS": str(document["bounds"]["sender_timeout_seconds"]),
    "FTP_WRONG_PASSWORDS": str(document["bounds"]["ftp_wrong_passwords"]),
    "FTP_THREADS": str(document["bounds"]["ftp_threads"]),
    "FTP_USERNAME": document["target"]["ftp_username"],
    "PORTSCAN_PORTS": document["bounds"]["portscan_ports"],
    "PORTSCAN_MAX_RATE": str(document["bounds"]["portscan_max_rate"]),
    "PORTSCAN_MAX_RETRIES": str(document["bounds"]["portscan_max_retries"]),
    "PORTSCAN_HOST_TIMEOUT_SECONDS": str(document["bounds"]["portscan_host_timeout_seconds"]),
    "ATTEMPT_DIR": str(path.parent),
}
for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
}

route_source() {
    local route_line source_ip
    route_line="$(ip -4 route get "$TARGET_IP" oif "$KALI_INTERFACE" 2>/dev/null || true)"
    [[ -n "$route_line" ]] || {
        printf 'error: cannot resolve route to %s through %s\n' "$TARGET_IP" "$KALI_INTERFACE" >&2
        exit 1
    }
    source_ip="$(python3 -B - "$route_line" <<'PY'
import ipaddress
import re
import sys
match = re.search(r"(?:^| )src ([0-9.]+)(?: |$)", sys.argv[1])
if not match:
    raise SystemExit("route has no source address")
address = ipaddress.ip_address(match.group(1))
if address.version != 4:
    raise SystemExit("route source is not IPv4")
print(address)
PY
)"
    [[ "$route_line" == *" dev $KALI_INTERFACE "* ]] || {
        printf 'error: route does not use expected interface: %s\n' "$route_line" >&2
        exit 1
    }
    printf '%s\n%s\n' "$source_ip" "$route_line"
}

write_receipt() {
    local receipt_path="$1" status="$2" return_code="$3" started="$4" ended="$5" log_path="$6" command_text="$7"
    local log_sha
    log_sha="$(sha256sum -- "$log_path" | awk '{print $1}')"
    python3 -B - \
        "$receipt_path" "$CONTRACT" "$status" "$return_code" "$started" "$ended" \
        "$log_path" "$log_sha" "$command_text" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

receipt, contract, status, return_code, started, ended, log_path, log_sha, command_text = sys.argv[1:]
contract_path = Path(contract).resolve()
document = json.loads(contract_path.read_text(encoding="utf-8"))
receipt_doc = {
    "schema_version": "2.0.0",
    "task": "T9.1",
    "kind": "kali_sender_receipt",
    "status": status,
    "attempt_id": document["attempt_id"],
    "run_token": document["run_token"],
    "case_id": document["case_id"],
    "scenario_label": document["scenario_label"],
    "expected_model_family": document["expected_model_family"],
    "started_at_utc": started,
    "ended_at_utc": ended,
    "tool_return_code": int(return_code),
    "run_contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
    "source_ip": document["topology"]["source_ip"],
    "target_ip": document["topology"]["target_ip"],
    "command": command_text,
    "log": {"path": str(Path(log_path).resolve()), "sha256": log_sha},
}
with Path(receipt).open("x", encoding="utf-8", newline="\n") as output:
    json.dump(receipt_doc, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}

case "$ACTION" in
    init)
        [[ -n "$CASE_ID" ]] || { usage; exit 2; }
        CASE_ENV="$(load_case_env)" || exit $?
        eval "$CASE_ENV"
        require_command "$TOOL"
        if [[ "$TOOL" == nmap ]]; then
            require_command sudo
        fi
        DRIVER_PATH="$(readlink -f -- "/sys/class/net/$KALI_INTERFACE/device/driver" 2>/dev/null || true)"
        [[ "${DRIVER_PATH##*/}" == "$KALI_EXPECTED_DRIVER" ]] || {
            printf 'error: %s driver must be %s, observed %s\n' \
                "$KALI_INTERFACE" "$KALI_EXPECTED_DRIVER" "${DRIVER_PATH##*/}" >&2
            exit 1
        }
        mapfile -t ROUTE_FACTS < <(route_source)
        SOURCE_IP="${ROUTE_FACTS[0]}"
        ROUTE_LINE="${ROUTE_FACTS[1]}"
        STAMP="$(date -u +%Y%m%d%H%M%S)"
        NONCE="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
        ATTEMPT_ID="t91-${CASE_ID}-${STAMP}-${NONCE}"
        RUN_TOKEN="rt-${STAMP}-${NONCE}"
        ATTEMPT_DIR="$PROJECT_ROOT/$ARTIFACT_ROOT/$CASE_ID/$ATTEMPT_ID"
        CONTRACT_PATH="$ATTEMPT_DIR/contract.json"
        mkdir -p -- "$ATTEMPT_DIR"
        python3 -B - \
            "$CONTRACT_PATH" "$CONFIG" "$CONFIG_SHA256" "$CASE_ID" "$SCENARIO_LABEL" \
            "$EXPECTED_MODEL_FAMILY" "$ATTEMPT_ID" "$RUN_TOKEN" "$SOURCE_IP" "$TARGET_IP" \
            "$KALI_INTERFACE" "$ROUTE_LINE" "$SENDER_TIMEOUT_SECONDS" \
            "$FTP_WRONG_PASSWORDS" "$FTP_THREADS" "$FTP_USERNAME" "$PORTSCAN_PORTS" \
            "$PORTSCAN_MAX_RATE" "$PORTSCAN_MAX_RETRIES" "$PORTSCAN_HOST_TIMEOUT_SECONDS" <<'PY'
import datetime as dt
import json
import sys
from pathlib import Path

(
    contract_path, config_path, config_sha256, case_id, scenario_label, expected_model_family,
    attempt_id, run_token, source_ip, target_ip, kali_interface, route_line,
    sender_timeout, ftp_wrong, ftp_threads, ftp_user, ports, max_rate,
    max_retries, host_timeout,
) = sys.argv[1:]
config = json.loads(Path(config_path).read_text(encoding="utf-8"))
document = {
    "schema_version": "2.0.0",
    "task": "T9.1",
    "kind": "terminal_live_run_contract",
    "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "case_id": case_id,
    "scenario_label": scenario_label,
    "expected_model_family": expected_model_family,
    "attempt_id": attempt_id,
    "run_token": run_token,
    "config": {"path": str(Path(config_path).resolve()), "sha256": config_sha256},
    "artifact_root": config["artifact_root"],
    "topology": {
        "network": config["topology"]["data_network"]["name"],
        "source_ip": source_ip,
        "target_ip": target_ip,
        "kali_interface": kali_interface,
        "route": route_line,
        "ubuntu_interface": config["topology"]["ubuntu"]["interface"],
        "ubuntu_expected_mac": config["topology"]["ubuntu"]["expected_mac"],
    },
    "model": config["model"],
    "dpdk": config["dpdk"],
    "bounds": config["bounds"],
    "target": config["target"],
    "acceptance": {
        "minimum_terminal_flows": config["acceptance"]["minimum_terminal_flows"][case_id],
        "require_non_eof_exact_model_family_alert": config["acceptance"][
            "require_non_eof_exact_model_family_alert"
        ],
        "require_clean_dpdk_counters": config["acceptance"]["require_clean_dpdk_counters"],
        "require_rollback": config["acceptance"]["require_rollback"],
    },
    "tool": {
        "name": "patator" if case_id == "ftp-patator" else "nmap",
        "bounded": True,
    },
}
with Path(contract_path).open("x", encoding="utf-8", newline="\n") as output:
    json.dump(document, output, indent=2, sort_keys=True)
    output.write("\n")
print(json.dumps({
    "schema_version": "2.0.0",
    "operation": "init",
    "status": "ok",
    "attempt_id": attempt_id,
    "run_token": run_token,
    "case_id": case_id,
    "source_ip": source_ip,
    "target_ip": target_ip,
    "contract": str(Path(contract_path).resolve()),
}, sort_keys=True))
PY
        ;;
    send)
        [[ -n "$CONTRACT" ]] || { usage; exit 2; }
        CONTRACT_ENV="$(load_contract_env)" || exit $?
        eval "$CONTRACT_ENV"
        case "$CASE_ID" in
            ftp-patator) [[ "$TOOL" == patator ]] || exit 2 ;;
            portscan) [[ "$TOOL" == nmap ]] || exit 2 ;;
            *) printf 'error: unsupported case in contract: %s\n' "$CASE_ID" >&2; exit 2 ;;
        esac
        require_command "$TOOL"
        [[ "$(route_source | sed -n '1p')" == "$SOURCE_IP" ]] || {
            printf 'error: current route source no longer matches contract source %s\n' "$SOURCE_IP" >&2
            exit 1
        }
        KALI_DIR="$ATTEMPT_DIR/kali"
        mkdir -p -- "$KALI_DIR"
        LOG="$KALI_DIR/sender.log"
        RECEIPT="$KALI_DIR/sender.json"
        [[ ! -e "$LOG" && ! -e "$RECEIPT" ]] || {
            printf 'error: sender evidence already exists for attempt %s\n' "$ATTEMPT_ID" >&2
            exit 1
        }
        STARTED="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
        set +e
        if [[ "$CASE_ID" == ftp-patator ]]; then
            USERS="$(mktemp "$KALI_DIR/users.XXXXXXXX")"
            PASSWORDS="$(mktemp "$KALI_DIR/passwords.XXXXXXXX")"
            printf '%s\n' "$FTP_USERNAME" >"$USERS"
            for attempt in $(seq 1 "$FTP_WRONG_PASSWORDS"); do
                printf 'Nids-Wrong-%03d!\n' "$attempt"
            done >"$PASSWORDS"
            COMMAND_TEXT="timeout ${SENDER_TIMEOUT_SECONDS}s patator ftp_login host=${TARGET_IP} port=21 user=FILE0 password=FILE1 persistent=0 -t ${FTP_THREADS}"
            timeout --signal=TERM --kill-after=2s "${SENDER_TIMEOUT_SECONDS}s" \
                patator ftp_login host="$TARGET_IP" port=21 user=FILE0 password=FILE1 \
                0="$USERS" 1="$PASSWORDS" persistent=0 -t "$FTP_THREADS" \
                -x ignore,reset:code=530 >"$LOG" 2>&1
            STATUS=$?
            rm -f -- "$USERS" "$PASSWORDS"
        else
            require_command sudo
            COMMAND_TEXT="timeout ${SENDER_TIMEOUT_SECONDS}s sudo -n nmap -n -Pn -sS -p ${PORTSCAN_PORTS} --max-rate ${PORTSCAN_MAX_RATE} --max-retries ${PORTSCAN_MAX_RETRIES} --host-timeout ${PORTSCAN_HOST_TIMEOUT_SECONDS}s -e ${KALI_INTERFACE} -S ${SOURCE_IP} ${TARGET_IP}"
            timeout --signal=TERM --kill-after=2s "${SENDER_TIMEOUT_SECONDS}s" \
                sudo -n nmap -n -Pn -sS -p "$PORTSCAN_PORTS" \
                --max-rate "$PORTSCAN_MAX_RATE" \
                --max-retries "$PORTSCAN_MAX_RETRIES" \
                --host-timeout "${PORTSCAN_HOST_TIMEOUT_SECONDS}s" \
                -e "$KALI_INTERFACE" -S "$SOURCE_IP" "$TARGET_IP" >"$LOG" 2>&1
            STATUS=$?
        fi
        set -e
        ENDED="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
        if [[ "$STATUS" == 0 ]]; then
            RECEIPT_STATUS="passed"
        else
            RECEIPT_STATUS="failed"
        fi
        write_receipt "$RECEIPT" "$RECEIPT_STATUS" "$STATUS" "$STARTED" "$ENDED" "$LOG" "$COMMAND_TEXT"
        printf '{"operation":"send","status":"%s","attempt_id":"%s","receipt":"%s"}\n' \
            "$RECEIPT_STATUS" "$ATTEMPT_ID" "$RECEIPT"
        exit "$STATUS"
        ;;
    status)
        [[ -n "$CONTRACT" ]] || { usage; exit 2; }
        CONTRACT_ENV="$(load_contract_env)" || exit $?
        eval "$CONTRACT_ENV"
        python3 -B - "$ATTEMPT_DIR/kali/sender.json" "$ATTEMPT_ID" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
print(json.dumps({
    "operation": "status",
    "role": "kali",
    "attempt_id": sys.argv[2],
    "status": "complete" if path.exists() else "pending",
    "receipt": str(path),
}, sort_keys=True))
PY
        ;;
    *) usage; exit 2 ;;
esac
