#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
usage:
  bash scripts/kali_t85_live_attacks.sh \
    --run-id ID \
    --attack hping3|ftp-patator \
    [--count 1000] \
    [--interval-us 10000] \
    [--source-cidr 192.168.252.129/24] \
    [--attempts 20]
EOF
}

RUN_ID=""
ATTACK=""
COUNT=1000
INTERVAL_US=10000
SOURCE_CIDR=192.168.252.129/24
ATTEMPTS=20

while (($#)); do
    case "$1" in
        --run-id) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RUN_ID="$2"; shift 2 ;;
        --attack) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; ATTACK="$2"; shift 2 ;;
        --count) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; COUNT="$2"; shift 2 ;;
        --interval-us) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; INTERVAL_US="$2"; shift 2 ;;
        --source-cidr) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; SOURCE_CIDR="$2"; shift 2 ;;
        --attempts) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; ATTEMPTS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'error: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9._-]{2,63}$ ]] || {
    printf 'error: --run-id must contain 3-64 lowercase letters, digits, dots, underscores, or hyphens\n' >&2
    exit 2
}
case "$ATTACK" in
    hping3) TOOL_NAME=hping3 ;;
    ftp-patator) TOOL_NAME=patator ;;
    *) printf 'error: --attack must be hping3 or ftp-patator\n' >&2; exit 2 ;;
esac
[[ "$COUNT" =~ ^[0-9]+$ ]] && ((COUNT >= 9 && COUNT <= 3000)) || {
    printf 'error: --count must be an integer from 9 through 3000\n' >&2
    exit 2
}
[[ "$INTERVAL_US" =~ ^[0-9]+$ ]] && ((INTERVAL_US >= 10000 && INTERVAL_US <= 1000000)) || {
    printf 'error: --interval-us must be an integer from 10000 through 1000000 (at most 100 pps)\n' >&2
    exit 2
}
[[ "$SOURCE_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || {
    printf 'error: --source-cidr must look like 192.168.252.129/24\n' >&2
    exit 2
}
[[ "$ATTEMPTS" =~ ^[0-9]+$ ]] && ((ATTEMPTS >= 9 && ATTEMPTS <= 100)) || {
    printf 'error: --attempts must be an integer from 9 through 100\n' >&2
    exit 2
}
[[ "$(uname -s)" == Linux ]] || {
    printf 'error: this sender must run inside the Kali Linux VM\n' >&2
    exit 1
}
((EUID != 0)) || {
    printf 'error: run as the normal Kali user; the wrapper invokes sudo only where required\n' >&2
    exit 2
}

readonly INTERFACE=eth1
readonly EXPECTED_DRIVER=vmxnet3
SOURCE_IP="${SOURCE_CIDR%/*}"
readonly SOURCE_CIDR SOURCE_IP
readonly TARGET=192.168.252.20
readonly FTP_USER=nidslab
readonly HPING_SOURCE_PORT=44444
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly RUN_ID ATTACK TOOL_NAME COUNT INTERVAL_US ATTEMPTS
readonly ATTACK_ROOT="$PROJECT_ROOT/run_log/t8.5/live-attacks/$RUN_ID/$ATTACK"
readonly KALI_ROOT="$ATTACK_ROOT/kali"
readonly ATTACK_LOG="$KALI_ROOT/attack.log"
readonly RECEIPT="$KALI_ROOT/receipt.json"

for command_name in ip readlink grep date tee sha256sum python3 sudo mktemp; do
    command -v "$command_name" >/dev/null || {
        printf 'error: required command is not installed: %s\n' "$command_name" >&2
        exit 1
    }
done
command -v "$TOOL_NAME" >/dev/null || {
    printf 'error: %s is not installed; this wrapper does not install dependencies\n' "$TOOL_NAME" >&2
    exit 1
}
[[ -d "/sys/class/net/$INTERFACE" ]] || {
    printf 'error: Kali data interface does not exist: %s\n' "$INTERFACE" >&2
    exit 1
}
DRIVER_PATH="$(readlink -f -- "/sys/class/net/$INTERFACE/device/driver")"
readonly DRIVER_PATH
[[ "${DRIVER_PATH##*/}" == "$EXPECTED_DRIVER" ]] || {
    printf 'error: %s driver must be %s, observed %s\n' \
        "$INTERFACE" "$EXPECTED_DRIVER" "${DRIVER_PATH##*/}" >&2
    exit 1
}
if ip -4 route show default | grep -Eq "(^|[[:space:]])dev[[:space:]]+$INTERFACE([[:space:]]|$)"; then
    printf 'error: refusing to use %s because it owns a default route\n' "$INTERFACE" >&2
    exit 1
fi
[[ ! -e "$ATTACK_LOG" && ! -e "$RECEIPT" ]] || {
    printf 'error: live attack evidence already exists; preserve it and use a new --run-id\n' >&2
    exit 1
}

mkdir -p -- "$KALI_ROOT"
sudo -v

has_source_ip() {
    ip -o -4 address show dev "$INTERFACE" |
        grep -Fq " inet $SOURCE_CIDR "
}

SOURCE_IP_RESTORED=false
if ! has_source_ip; then
    set +e
    sudo ip address add "$SOURCE_CIDR" dev "$INTERFACE"
    ADD_STATUS=$?
    set -e
    if ! has_source_ip; then
        printf 'error: failed to restore locked Kali data address %s on %s (ip exit %s)\n' \
            "$SOURCE_CIDR" "$INTERFACE" "$ADD_STATUS" >&2
        exit 1
    fi
    SOURCE_IP_RESTORED=true
fi
readonly SOURCE_IP_RESTORED

ROUTE_LINE="$(ip -4 route get "$TARGET" oif "$INTERFACE" 2>/dev/null || true)"
readonly ROUTE_LINE
[[ -n "$ROUTE_LINE" ]] || {
    printf 'error: cannot resolve route to %s through %s\n' "$TARGET" "$INTERFACE" >&2
    exit 1
}
if [[ "$ROUTE_LINE" != *" dev $INTERFACE "* || "$ROUTE_LINE" != *" src $SOURCE_IP "* ]]; then
    printf 'error: route to %s must use dev %s src %s\n' "$TARGET" "$INTERFACE" "$SOURCE_IP" >&2
    printf 'observed route: %s\n' "$ROUTE_LINE" >&2
    printf 'hint: rerun with --source-cidr matching the real eth1 source address, or make the locked address primary on eth1\n' >&2
    exit 1
fi

TEMP_USER=""
TEMP_PASSWORDS=""
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    [[ -z "$TEMP_USER" || ! -e "$TEMP_USER" ]] || rm -f -- "$TEMP_USER"
    [[ -z "$TEMP_PASSWORDS" || ! -e "$TEMP_PASSWORDS" ]] || rm -f -- "$TEMP_PASSWORDS"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

TOOL_PATH="$(realpath -e -- "$(command -v "$TOOL_NAME")")"
TOOL_HASH_LINE="$(sha256sum -- "$TOOL_PATH")"
TOOL_SHA256="${TOOL_HASH_LINE%% *}"
readonly TOOL_PATH TOOL_SHA256
STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
readonly STARTED_AT_UTC

{
    printf 'run_id=%s attack=%s\n' "$RUN_ID" "$ATTACK"
    printf 'interface=%s driver=%s source=%s target=%s\n' \
        "$INTERFACE" "$EXPECTED_DRIVER" "$SOURCE_CIDR" "$TARGET"
    printf 'tool=%s tool_sha256=%s\n' "$TOOL_PATH" "$TOOL_SHA256"
    printf 'source_ip_restored=%s\n' "$SOURCE_IP_RESTORED"
    printf 'route=%s\n' "$ROUTE_LINE"
} | tee "$ATTACK_LOG"

set +e
if [[ "$ATTACK" == hping3 ]]; then
    printf 'command=hping3 -S -p 80 -s %s -c %s -i u%s -I %s %s\n' \
        "$HPING_SOURCE_PORT" "$COUNT" "$INTERVAL_US" "$INTERFACE" "$TARGET" |
        tee -a "$ATTACK_LOG"
    sudo hping3 \
        -S -p 80 -s "$HPING_SOURCE_PORT" -c "$COUNT" -i "u$INTERVAL_US" -I "$INTERFACE" "$TARGET" \
        2>&1 | tee -a "$ATTACK_LOG"
    ATTACK_STATUS=${PIPESTATUS[0]}
else
    TEMP_USER="$(mktemp "$KALI_ROOT/patator-user.XXXXXXXX")"
    TEMP_PASSWORDS="$(mktemp "$KALI_ROOT/patator-passwords.XXXXXXXX")"
    printf '%s\n' "$FTP_USER" >"$TEMP_USER"
    for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
        printf 'Nids-Wrong-%03d!\n' "$attempt"
    done >"$TEMP_PASSWORDS"
    printf 'command=patator ftp_login host=%s port=21 user=FILE0 password=FILE1 attempts=%s\n' \
        "$TARGET" "$ATTEMPTS" |
        tee -a "$ATTACK_LOG"
    patator ftp_login \
        host="$TARGET" port=21 user=FILE0 password=FILE1 \
        0="$TEMP_USER" 1="$TEMP_PASSWORDS" \
        -x ignore:mesg='Login incorrect.' \
        2>&1 | tee -a "$ATTACK_LOG"
    ATTACK_STATUS=${PIPESTATUS[0]}
fi
set -e
readonly ATTACK_STATUS

ENDED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
LOG_HASH_LINE="$(sha256sum -- "$ATTACK_LOG")"
LOG_SHA256="${LOG_HASH_LINE%% *}"
readonly ENDED_AT_UTC LOG_SHA256

python3 -B - \
    "$RECEIPT" "$PROJECT_ROOT" "$RUN_ID" "$ATTACK" "$STARTED_AT_UTC" \
    "$ENDED_AT_UTC" "$ATTACK_STATUS" "$INTERFACE" "$EXPECTED_DRIVER" \
    "$SOURCE_CIDR" "$TARGET" "$SOURCE_IP_RESTORED" "$ROUTE_LINE" "$TOOL_PATH" \
    "$TOOL_SHA256" "$ATTACK_LOG" "$LOG_SHA256" "$COUNT" "$INTERVAL_US" \
    "$ATTEMPTS" <<'PY'
import json
import sys
from pathlib import Path

(
    receipt_arg,
    root_arg,
    run_id,
    attack,
    started_at,
    ended_at,
    return_code_arg,
    interface,
    driver,
    source_cidr,
    target,
    source_ip_restored_arg,
    route_line,
    tool_path,
    tool_sha256,
    log_arg,
    log_sha256,
    count_arg,
    interval_us_arg,
    attempts_arg,
) = sys.argv[1:]
root = Path(root_arg)
log_path = Path(log_arg)
parameters = (
    {
        "packet_count": int(count_arg),
        "interval_us": int(interval_us_arg),
        "maximum_packets_per_second": 100,
        "tcp_flags": "SYN",
        "destination_port": 80,
    }
    if attack == "hping3"
    else {
        "attempts": int(attempts_arg),
        "username": "nidslab",
        "password_set": "deterministic_invalid_demo_values",
        "destination_port": 21,
    }
)
document = {
    "schema_version": "1.0.0",
    "kind": "diagnostic_demo_evidence",
    "mode": "t8.5_live_attack",
    "formal_acceptance": False,
    "status": "observed" if int(return_code_arg) == 0 else "failed",
    "run_id": run_id,
    "attack_id": attack,
    "started_at_utc": started_at,
    "ended_at_utc": ended_at,
    "tool_return_code": int(return_code_arg),
    "bounded": True,
    "parameters": parameters,
    "network": {
        "interface": interface,
        "driver": driver,
        "source_cidr": source_cidr,
        "target": target,
        "source_ip_restored": source_ip_restored_arg == "true",
        "route": route_line,
    },
    "tool": {"path": tool_path, "sha256": tool_sha256},
    "output": {
        "path": log_path.relative_to(root).as_posix(),
        "sha256": log_sha256,
    },
    "isolated_sensor_process_required": True,
    "model_classification_claimed": False,
}
with Path(receipt_arg).open("x", encoding="utf-8", newline="\n") as destination:
    json.dump(document, destination, indent=2)
    destination.write("\n")
PY

printf 'receipt=%s status=%s\n' \
    "$RECEIPT" "$([[ "$ATTACK_STATUS" == 0 ]] && printf observed || printf failed)"
exit "$ATTACK_STATUS"
