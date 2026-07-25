#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
usage:
  bash scripts/kali_t85_bulk_replay.sh \
    --interface IFACE \
    --destination-mac MAC \
    --pcap-dir DIR \
    --pcap-id monday|tuesday|wednesday|thursday|friday \
    --speed 1|5|topspeed

Examples:
  bash scripts/kali_t85_bulk_replay.sh \
    --interface eth1 \
    --destination-mac 00:0c:29:eb:d8:c4 \
    --pcap-dir /mnt/hgfs/TTTN/pcap \
    --pcap-id monday \
    --speed topspeed
EOF
}

INTERFACE=
DESTINATION_MAC=
PCAP_DIR=
PCAP_ID=
SPEED=

while (($#)); do
    case "$1" in
        --interface)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            INTERFACE="$2"
            shift 2
            ;;
        --destination-mac)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            DESTINATION_MAC="${2,,}"
            shift 2
            ;;
        --pcap-dir)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            PCAP_DIR="$2"
            shift 2
            ;;
        --pcap-id)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            PCAP_ID="$2"
            shift 2
            ;;
        --speed)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            SPEED="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ "$INTERFACE" =~ ^[a-zA-Z0-9_.:-]+$ ]] || {
    printf 'error: invalid or missing interface\n' >&2
    exit 2
}
[[ "$DESTINATION_MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || {
    printf 'error: invalid or missing destination MAC\n' >&2
    exit 2
}
[[ "$SPEED" == 1 || "$SPEED" == 5 || "$SPEED" == topspeed ]] || {
    printf 'error: speed must be exactly 1, 5 or topspeed\n' >&2
    exit 2
}
[[ -n "$PCAP_DIR" ]] || {
    printf 'error: pcap-dir is required\n' >&2
    exit 2
}
case "$PCAP_ID" in
    monday) PCAP_NAME="Monday-WorkingHours.pcap" ;;
    tuesday) PCAP_NAME="Tuesday-WorkingHours.pcap" ;;
    wednesday) PCAP_NAME="Wednesday-workingHours.pcap" ;;
    thursday) PCAP_NAME="Thursday-WorkingHours.pcap" ;;
    friday) PCAP_NAME="Friday-WorkingHours.pcap" ;;
    *) printf 'error: --pcap-id must be monday, tuesday, wednesday, thursday, or friday\n' >&2; exit 2 ;;
esac
[[ -d "/sys/class/net/$INTERFACE" ]] || {
    printf 'error: interface does not exist: %s\n' "$INTERFACE" >&2
    exit 1
}
command -v tcpreplay-edit >/dev/null || {
    printf 'error: tcpreplay-edit is not installed\n' >&2
    exit 1
}
command -v sha256sum >/dev/null || {
    printf 'error: sha256sum is not installed\n' >&2
    exit 1
}

readonly SOURCE_MAC="$(<"/sys/class/net/$INTERFACE/address")"
readonly PCAP_DIR="$(realpath -e -- "$PCAP_DIR")"
readonly PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly PCAP_ID
readonly PCAP_NAME
readonly PCAP="$PCAP_DIR/$PCAP_NAME"
readonly LOG_ROOT="$PROJECT_ROOT/run_log/t8.5/segments/$PCAP_ID"
readonly REPLAY_LOG="$LOG_ROOT/replay.log"
[[ -f "$PCAP" ]] || {
    printf 'error: missing PCAP: %s\n' "$PCAP" >&2
    exit 1
}
[[ ! -e "$REPLAY_LOG" ]] || {
    printf 'error: replay evidence already exists; preserve it and use a clean segment directory: %s\n' "$REPLAY_LOG" >&2
    exit 1
}

readonly ORIGINAL_MTU="$(<"/sys/class/net/$INTERFACE/mtu")"
MTU_CHANGED=0
TEMP_LOG=
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    if [[ -n "$TEMP_LOG" && -f "$TEMP_LOG" ]]; then
        rm -f -- "$TEMP_LOG"
    fi
    if ((MTU_CHANGED)); then
        sudo ip link set dev "$INTERFACE" mtu "$ORIGINAL_MTU"
        if [[ "$(<"/sys/class/net/$INTERFACE/mtu")" != "$ORIGINAL_MTU" ]]; then
            printf 'error: failed to restore %s MTU to %s\n' \
                "$INTERFACE" "$ORIGINAL_MTU" |
                tee -a "$REPLAY_LOG" >&2
            status=1
        else
            printf 'kali_mtu_rollback=passed interface=%s restored_mtu=%s\n' \
                "$INTERFACE" "$ORIGINAL_MTU" |
                tee -a "$REPLAY_LOG"
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$SPEED" == topspeed ]]; then
    readonly -a SPEED_ARGUMENT=(--topspeed)
    readonly TIMING_SEMANTICS=receiver_arrival_compressed_not_source_pcap
else
    readonly -a SPEED_ARGUMENT=(--multiplier="$SPEED")
    readonly TIMING_SEMANTICS=receiver_arrival_paced_not_source_pcap_timestamp_transport
fi

mkdir -p -- "$LOG_ROOT"
{
    printf 'pcap_id=%s\n' "$PCAP_ID"
    printf 'pcap=%s\n' "$PCAP"
    printf 'pcap_sha256=%s\n' "$(sha256sum -- "$PCAP" | awk '{print $1}')"
    printf 'interface=%s source_mac=%s destination_mac=%s speed=%s\n' \
        "$INTERFACE" "$SOURCE_MAC" "$DESTINATION_MAC" "$SPEED"
    printf 'timing_semantics=%s\n' "$TIMING_SEMANTICS"
} | tee "$REPLAY_LOG"

sudo -v
sudo ip link set dev "$INTERFACE" mtu 9000
MTU_CHANGED=1
[[ "$(<"/sys/class/net/$INTERFACE/mtu")" == 9000 ]] || {
    printf 'error: interface did not retain MTU 9000\n' >&2
    exit 1
}
printf 'log=%s\n' "$REPLAY_LOG"

printf '\n=== Replaying %s ===\n' "$PCAP_NAME" | tee -a "$REPLAY_LOG"
TEMP_LOG="$(mktemp "$LOG_ROOT/replay-current.XXXXXXXX")"
set +e
sudo tcpreplay-edit \
    --intf1="$INTERFACE" \
    --enet-smac="$SOURCE_MAC" \
    --enet-dmac="$DESTINATION_MAC" \
    "${SPEED_ARGUMENT[@]}" \
    --stats=5 \
    "$PCAP" 2>&1 |
    tee -a "$REPLAY_LOG" "$TEMP_LOG"
REPLAY_STATUS=${PIPESTATUS[0]}
set -e
((REPLAY_STATUS == 0)) || {
    printf 'error: tcpreplay-edit failed for %s\n' "$PCAP" >&2
    exit "$REPLAY_STATUS"
}
FAILED_PACKETS="$(
    awk '/Failed packets:/ {total += $3} END {print total + 0}' "$TEMP_LOG"
)"
OVERSIZED_PACKETS="$(
    awk '/Message too long \(errno = 90\)/ {total++} END {print total + 0}' \
        "$TEMP_LOG"
)"
FLOW_DECODE_WARNINGS="$(
    awk '/flow_decode/ {total++} END {print total + 0}' "$TEMP_LOG"
)"
rm -f -- "$TEMP_LOG"
TEMP_LOG=
((FAILED_PACKETS == OVERSIZED_PACKETS)) || {
    printf 'error: %s send failure(s), but only %s were explained by MTU/EMSGSIZE for %s\n' \
        "$FAILED_PACKETS" "$OVERSIZED_PACKETS" "$PCAP" >&2
    exit 1
}
if ((OVERSIZED_PACKETS)); then
    printf 'warning: %s frame(s) exceeded vmxnet3 MTU 9000 and could not be replayed unchanged\n' \
        "$OVERSIZED_PACKETS" >&2
fi
if ((FLOW_DECODE_WARNINGS)); then
    printf 'warning: tcpreplay reported %s flow-decode warning(s); these are not send failures\n' \
        "$FLOW_DECODE_WARNINGS" >&2
fi

{
    printf '\nReplay complete: one PCAP segment processed.\n'
    printf 'hardware_unreplayable_oversized_frames=%s\n' "$OVERSIZED_PACKETS"
    printf 'flow_decode_warnings=%s\n' "$FLOW_DECODE_WARNINGS"
    printf 'unexplained_send_failures=%s\n' \
        "$((FAILED_PACKETS - OVERSIZED_PACKETS))"
} | tee -a "$REPLAY_LOG"
