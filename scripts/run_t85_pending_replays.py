#!/usr/bin/env python3
"""Replay the T8.5 scenario families that still have no Ubuntu sensor evidence.

For each family: arm the DPDK sensor on Ubuntu (detached), replay the nine-frame
scenario PCAP from Kali, wait for the sensor's idle timeout, then record how many
nids_alert records landed. Everything is written under the run-id's own tree so
the existing rebuild-20260808 receipts are never overwritten.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABCTL = ROOT / "tools" / "labctl.py"
BUNDLE = "/home/wang/.cache/nids-partial-flow/t5.2/bundles/F9"
SENSOR_MAC = "00:0c:29:30:b9:d3"
REMOTE_ROOT = "/mnt/hgfs/TTTN"
# 1500, not 9000. Four scenario PCAPs carry frames above 1518 bytes (ddos 8814,
# dos-goldeneye and portscan 5858, dos-hulk 4421) because the original capture
# recorded LRO-coalesced segments rather than wire frames. Raising the link to
# 9000 to fit them makes vmnet drop everything - the sensor then records
# packets_seen=0, not even background noise - so those four cannot be replayed
# over this link at all, and the remaining ten run at the MTU that works.
REPLAY_MTU = 1500
# Bracketed first letter so the pattern does not match the shell command that
# carries it. "pkill -f nids_dpdk_live" sent over ssh matches its own command
# line and kills the session running it: the sudo form killed the collect step
# before it could summarise, and every attempt then reported packets_seen=0,
# which reads as a capture miss. "[n]ids_dpdk_live" matches the sensor and not
# the string "[n]ids_dpdk_live" sitting in the invoking command line.
PATTERN = "[n]ids_dpdk_live"


def labctl(host: str, command: str, timeout_seconds: int) -> dict:
    proc = subprocess.run(
        [sys.executable, str(LABCTL), "exec", "--timeout-seconds",
         str(timeout_seconds), host, command],
        capture_output=True, text=True, timeout=timeout_seconds + 60,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "unparsed", "stdout": proc.stdout, "stderr": proc.stderr}


def attempt_id(family: str, suffix: str) -> str:
    # A retry gets its own attempt directory: the sensor script refuses to
    # overwrite evidence, and a failed attempt is kept rather than deleted.
    return f"f9-{family}{suffix}"


def clear_sensor(timeout_seconds: int = 90) -> str:
    """Kill any sensor left over from an earlier attempt and wait for release.

    The sensor runs under sudo because it binds the NIC to vfio-pci, so a plain
    pkill answers "Operation not permitted" and leaves it running. That is how
    seven r3 attempts in a row failed to start at all - the previous sensor
    still held ens160 - and how ftp-patator-r9's nine frames were counted by the
    ddos-r8t3 sensor, which was still inside its own window when they arrived.
    """
    result = labctl(
        "ubuntu",
        f"sudo -n pkill -f '{PATTERN}' >/dev/null 2>&1; "
        f"for i in $(seq 1 30); do "
        f"  pgrep -f '{PATTERN}' >/dev/null 2>&1 || break; sleep 1; "
        f"done; "
        f"sleep 3; "
        f"echo \"remaining=$(pgrep -cf '{PATTERN}') "
        f"hugefree=$(awk '/HugePages_Free/{{print $2}}' /proc/meminfo)\"",
        timeout_seconds,
    )
    return (result.get("stdout") or "").strip()


def arm_sensor(run_id: str, family: str, idle_seconds: int, suffix: str) -> bool:
    attempt = attempt_id(family, suffix)
    inner = (
        f"bash scripts/run_t85_scenario_sensor_ubuntu.sh --run-id {run_id} "
        f"--bundle {BUNDLE} --attempt {attempt} "
        f"--duration-seconds {idle_seconds} --max-packets 100000 "
        f">/tmp/sensor-{attempt}.log 2>&1"
    )
    log = f"{REMOTE_ROOT}/run_log/t8.5/scenarios/{run_id}/ubuntu/{attempt}/sensor.jsonl"
    # setsid + disown so the sensor survives the ssh session labctl closes.
    # Waiting for nids_dpdk_live_ready instead of a fixed sleep: a fixed sleep
    # let three families replay before the port was bound, and they recorded
    # packets_seen=0, which reads as a model miss but is a capture miss.
    cmd = (
        f"cd {REMOTE_ROOT} && setsid bash -c \"{inner}\" </dev/null "
        f">/dev/null 2>&1 & disown; "
        f"for i in $(seq 1 60); do "
        f"grep -q nids_dpdk_live_ready {log} 2>/dev/null && {{ echo READY; break; }}; "
        f"sleep 1; done; tail -1 /tmp/sensor-{attempt}.log"
    )
    residue = clear_sensor()
    result = labctl("ubuntu", cmd, 120)
    stdout = result.get("stdout", "")
    if "READY" not in stdout:
        print(f"    [WARN] sensor never reported ready ({residue}): "
              f"{stdout.strip()[-160:]}", flush=True)
        return False
    print(f"    arm: ready ({residue})", flush=True)
    return True


def replay(run_id: str, family: str, attempt: str, mtu: int = REPLAY_MTU) -> bool:
    cmd = (
        f"cd {REMOTE_ROOT} && sudo -n python3 scripts/kali_t85_scenario_replay.py "
        f"--run-id {run_id} --case {family} --interface eth1 "
        f"--destination-mac {SENSOR_MAC} --mtu {mtu} --attempt {attempt}"
    )
    result = labctl("kali", cmd, 120)
    ok = result.get("exit_code") == 0
    if not ok:
        print(f"    replay FAILED: {result.get('stderr', '')[:200]}", flush=True)
    return ok


def prepare_link(mtu: int = REPLAY_MTU) -> None:
    """Park the Kali data NIC at the replay MTU once, before any sending.

    The replay sets the link itself, but doing that immediately before a
    nine-frame send costs the first frames while vmnet converges. Setting it
    here, once, makes the per-replay call a no-op.
    """
    result = labctl(
        "kali",
        f"sudo -n ip link set dev eth1 down && "
        f"sudo -n ip link set dev eth1 mtu {mtu} && "
        f"sudo -n ip link set dev eth1 up && sleep 3 && ip -br link show eth1",
        90,
    )
    print(f"  link: {(result.get('stdout') or '').strip()}", flush=True)


def collect(run_id: str, family: str, idle_seconds: int, suffix: str) -> dict:
    attempt = attempt_id(family, suffix)
    log = f"{REMOTE_ROOT}/run_log/t8.5/scenarios/{run_id}/ubuntu/{attempt}/sensor.jsonl"
    # The extra settle is for hgfs: a grep issued immediately after the sensor
    # exits read 0 on three families whose log already held an alert.
    cmd = (
        f"sleep {idle_seconds + 15}; sudo -n pkill -f '{PATTERN}' >/dev/null 2>&1; "
        f"sleep 10; sync; "
        f"python3 -B {REMOTE_ROOT}/scripts/summarize_sensor_log.py {log}"
    )
    result = labctl("ubuntu", cmd, idle_seconds + 120)
    stats = {"packets_seen": 0, "packets_parsed": 0, "alerts": 0}
    for line in reversed((result.get("stdout") or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                stats = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    return {"family": family, "attempt": attempt, **stats}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", default="20260808-194942")
    ap.add_argument("--families", nargs="+", required=True)
    ap.add_argument("--idle-seconds", type=int, default=60)
    ap.add_argument("--attempt-suffix", default="",
                    help="appended to the attempt id, e.g. -r2 for a retry")
    ap.add_argument("--expect-packets", type=int, default=9,
                    help="a capture below this is a capture miss, not a model miss")
    ap.add_argument("--max-tries", type=int, default=3)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    prepare_link()

    results = []
    for index, family in enumerate(args.families, start=1):
        print(f"[{index}/{len(args.families)}] {family}", flush=True)
        record = None
        for try_index in range(1, args.max_tries + 1):
            # A short capture is retried in a brand new sensor session, never by
            # sending the nine frames again: the replay rewrites only the MAC
            # header, so a second send repeats the same 5-tuple and the engine
            # appends to the flow that already passed its F9 checkpoint. That
            # produces no second alert and corrupts the packet-count and
            # inter-arrival features of the one sample being measured.
            suffix = args.attempt_suffix if try_index == 1 else \
                f"{args.attempt_suffix}t{try_index}"
            # Never send into an unarmed sensor. Sending anyway is what let
            # ftp-patator-r9's frames be counted by the previous attempt's
            # sensor, which then reported an FTP-Patator alert under the ddos
            # attempt id and consumed the only clean shot that family had.
            if not arm_sensor(args.run_id, family, args.idle_seconds, suffix):
                record = {"family": family, "attempt": attempt_id(family, suffix),
                          "alerts": 0, "packets_seen": 0, "status": "arm_failed"}
                print(f"    arm failed, not sending "
                      f"(try {try_index}/{args.max_tries})", flush=True)
                time.sleep(5)
                continue
            if not replay(args.run_id, family, attempt_id(family, suffix)):
                record = {"family": family, "attempt": attempt_id(family, suffix),
                          "alerts": 0, "status": "replay_failed"}
                clear_sensor()
                break
            record = collect(args.run_id, family, args.idle_seconds, suffix)
            seen = record.get("packets_seen", 0)
            if seen >= args.expect_packets:
                record["status"] = "ok"
                break
            record["status"] = "capture_miss"
            print(f"    capture miss: packets_seen={seen} < {args.expect_packets}"
                  f" (try {try_index}/{args.max_tries})", flush=True)
            time.sleep(5)
        print(f"    {record['status']}: seen={record.get('packets_seen')} "
              f"alerts={record.get('alerts')}", flush=True)
        results.append(record)
        time.sleep(3)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
