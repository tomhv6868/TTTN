#!/usr/bin/env python3
"""One command: replay a small PCAP and print inference and alert latency.

Small on purpose. The FTP-Patator family window is 5.8k packets over about
three minutes and lost zero packets in the reference run, so the numbers land
in the normal regime instead of the saturated one. That makes it the shortest
replay that still produces hundreds of samples.

    python scripts/run_latency_benchmark.py                 # run it, print the table
    python scripts/run_latency_benchmark.py --report-only   # re-print the last run

Requires both VMs to be up. Check with: python tools/labctl.py status
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.run_terminal_matched_replays import (  # noqa: E402
    CAMPAIGN_CONFIG,
    KALI_INTERFACE,
    KALI_SOURCE_MAC,
    PCAP_ROOT,
    REMOTE_ROOT,
    UBUNTU_MAC,
    remote_bash,
    remote_path,
    sha256,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = ROOT / "run_log" / "full-flow-v1" / "latency-live"
DEFAULT_CASE = "ftp-patator"
PCAP_TARGET_IP = "192.168.10.50"
KALI_STAGE = "/home/kali/latency-benchmark"


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")


def build_contract(case: str, attempt_id: str) -> dict:
    config = json.loads(CAMPAIGN_CONFIG.read_text(encoding="utf-8"))
    dpdk = dict(config["dpdk"])
    dpdk["file_prefix"] = "nids-lat"
    dpdk["memory_mb"] = 128
    return {
        "schema_version": "2.0.0",
        "task": "T9.1",
        "kind": "terminal_live_run_contract",
        "created_at_utc": dt.datetime.now(dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "case_id": case,
        "scenario_label": f"{case} latency benchmark",
        "expected_model_family": "FTP-Bruteforce",
        "attempt_id": attempt_id,
        "run_token": f"rt-{attempt_id[4:]}",
        # The flag the sensor wrapper forwards as --benchmark-metrics.
        "benchmark_metrics": True,
        "config": {
            "path": remote_path(CAMPAIGN_CONFIG),
            "sha256": sha256(CAMPAIGN_CONFIG),
        },
        "artifact_root": "run_log/full-flow-v1/latency-live",
        "topology": {
            "network": config["topology"]["data_network"]["name"],
            "scope_mode": "target_ip",
            "source_ip": None,
            "target_ip": PCAP_TARGET_IP,
            "ubuntu_interface": config["topology"]["ubuntu"]["interface"],
            "ubuntu_expected_mac": config["topology"]["ubuntu"]["expected_mac"],
        },
        "model": dict(config["model"]),
        "dpdk": dpdk,
        "bounds": {"ready_timeout_seconds": 30},
        "lifecycle": {
            "mode": "signal_only",
            "lease_timeout_seconds": 300,
            "shutdown_grace_ms": 30000,
        },
        "output": {"mode": "alerts_only"},
        "acceptance": {"mode": "observational"},
        "tool": {"name": "tcpreplay-edit", "bounded": True},
    }


def wait_for(path: Path, seconds: int) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if path.is_file():
            return True
        time.sleep(1.0)
    return path.is_file()


def read_summary(sensor_log: Path) -> dict | None:
    if not sensor_log.is_file():
        return None
    for line in sensor_log.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event_type") == "nids_terminal_live_summary":
            return record
    return None


def human_ns(value: int) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f} s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} ms"
    if value >= 1_000:
        return f"{value / 1_000:.2f} us"
    return f"{value} ns"


def print_report(summary: dict, source: Path) -> bool:
    latency = summary.get("latency_ns")
    stats = summary.get("port_stats") or {}
    ipackets = stats.get("ipackets") or 0
    imissed = stats.get("imissed") or 0
    loss = (imissed / ipackets * 100.0) if ipackets else 0.0

    print()
    print("=" * 74)
    print("  DO TRE SUY LUAN VA DO TRE CANH BAO - Terminal V1")
    print("=" * 74)
    print(f"  Nguon      : {source.relative_to(ROOT).as_posix()}")
    print(f"  Trang thai : {summary.get('status')}")
    def group(value: int) -> str:
        return f"{value:,}".replace(",", ".")

    percent = f"{loss:.2f}".replace(".", ",")
    print(f"  Packet     : nhan {group(ipackets)}, mat {group(imissed)} ({percent}%)")
    print(
        f"  Suy luan   : {summary.get('inferences')} luot"
        f" | Canh bao: {summary.get('alerts')}"
    )
    print()

    if not latency:
        print("  KHONG CO KHOI latency_ns.")
        print("  Cam bien chua chay voi --benchmark-metrics, hoac binary cu chua duoc build lai.")
        print("=" * 74)
        return False

    header = f"  {'Giai doan':<34}{'Mau':>7}{'p50':>12}{'p95':>12}{'p99':>12}{'Max':>12}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    labels = (
        ("inference", "Suy luan (chi loi goi model)"),
        ("alert", "Canh bao (gom cho flow dong)"),
    )
    for key, label in labels:
        block = latency.get(key) or {}
        if not block.get("observations"):
            print(f"  {label:<34}{'0':>7}{'khong co mau':>48}")
            continue
        print(
            f"  {label:<34}{block['observations']:>7}"
            f"{human_ns(block['p50']):>12}{human_ns(block['p95']):>12}"
            f"{human_ns(block['p99']):>12}{human_ns(block['max']):>12}"
        )

    print()
    print("  DOC KY TRUOC KHI TRICH DAN")
    print(f"    inference_scope = {latency.get('inference_scope')}")
    print(f"    alert_scope     = {latency.get('alert_scope')}")
    print("    - 'Suy luan' o day CHI la loi goi model; dac trung da dung san truoc do.")
    print("      Cot cung ten cua F9 con gom ca buoc dung dac trung -> KHONG so truc tiep.")
    print("    - 'Canh bao' gom ca thoi gian cho flow dong, nen duoi rat dai la dung thiet ke,")
    print("      khong phai thoi gian tinh toan.")
    if loss > 0.0:
        print(f"    - CANH BAO: lan chay mat {loss:.2f}% packet -> so do la khi qua tai.".replace(".", ","))
    else:
        print("    - Mat 0 packet -> so do o che do binh thuong.")
    print("=" * 74)
    return True


def latest_run() -> Path | None:
    candidates = sorted(BENCHMARK_ROOT.glob("*/*/ubuntu/sensor.jsonl"))
    return candidates[-1] if candidates else None


def preflight() -> str | None:
    """Return a human-readable reason the lab is not usable, or None if it is.

    Checked first because every later failure looks the same from the outside:
    a powered-off VM and a broken script both surface as 'copy failed'.
    """
    rc, doc = remote_bash("ubuntu", "true\n", 60)
    hosts = doc.get("hosts") or {}
    host = next(iter(hosts.values()), doc)
    status = host.get("status")
    if status == "powered_off":
        return "VM Ubuntu dang TAT. Mo VMware Workstation va bat nids-ubuntu."
    if rc != 0 or status != "ok":
        return f"Khong ket noi duoc Ubuntu (status={status}). Chay: python tools/labctl.py status"

    rc, doc = remote_bash("kali", "true\n", 60)
    hosts = doc.get("hosts") or {}
    host = next(iter(hosts.values()), doc)
    status = host.get("status")
    if status == "powered_off":
        return "VM Kali dang TAT. Mo VMware Workstation va bat nids-kali."
    if rc != 0 or status != "ok":
        return f"Khong ket noi duoc Kali (status={status}). Chay: python tools/labctl.py status"
    return None


def run_benchmark(case: str, run_id: str) -> tuple[int, Path | None]:
    pcap = PCAP_ROOT / f"{case}.pcap"
    if not pcap.is_file():
        print(f"KHONG TIM THAY PCAP: {pcap}")
        return 2, None

    print("[0/4] Kiem tra hai VM")
    reason = preflight()
    if reason is not None:
        print(f"  DUNG LAI: {reason}")
        print("  Chua dung toi VM nao, chua tao thu muc run nao.")
        return 2, None
    print("  Ubuntu va Kali deu san sang")

    attempt = BENCHMARK_ROOT / run_id / case
    attempt.mkdir(parents=True, exist_ok=True)
    (attempt / "ubuntu").mkdir(exist_ok=True)
    control = attempt / "control"
    control.mkdir(exist_ok=True)

    attempt_id = f"t91-latency-{case}-{run_id}"
    contract_path = attempt / "contract.json"
    write_json(contract_path, build_contract(case, attempt_id))
    (attempt / "alerts.jsonl").touch(exist_ok=True)
    (attempt / "operator.heartbeat").write_bytes(f"{int(time.time())}\n".encode("ascii"))
    contract_remote = remote_path(contract_path)

    print(f"[1/4] Chuan bi PCAP tren Kali: {case}.pcap")
    stage_script = (
        "set -Eeuo pipefail\n"
        f"mkdir -p {KALI_STAGE}\n"
        f"cp -f {REMOTE_ROOT}/run_log/full-flow-v1/family-windows/{case}.pcap {KALI_STAGE}/\n"
        f"chmod 0644 {KALI_STAGE}/{case}.pcap\n"
        f"ls -l {KALI_STAGE}/{case}.pcap\n"
    )
    stage_rc, stage_doc = remote_bash("kali", stage_script, 180)
    write_json(control / "stage.json", {"return_code": stage_rc, "labctl": stage_doc})
    if stage_rc != 0:
        print("  THAT BAI khi chep PCAP sang Kali.")
        return 1, None

    print("[2/4] Khoi dong cam bien Ubuntu voi --benchmark-metrics")
    start_script = (
        f"cd {REMOTE_ROOT}\n"
        f"bash scripts/ubuntu_t91_live_sensor.sh start --contract {contract_remote}\n"
    )
    start_rc, start_doc = remote_bash("ubuntu", start_script, 120)
    write_json(control / "start.json", {"return_code": start_rc, "labctl": start_doc})
    if start_rc != 0:
        print("  THAT BAI khi khoi dong cam bien. Xem control/start.json.")
        return 1, None

    print("[3/4] Phat lai PCAP tu Kali (1x, mat khoang 3 phut)")
    replay_script = f"""set -Eeuo pipefail
original_mtu=$(cat /sys/class/net/{KALI_INTERFACE}/mtu)
cleanup() {{ ip link set dev {KALI_INTERFACE} mtu "$original_mtu"; }}
trap cleanup EXIT INT TERM
ip link set dev {KALI_INTERFACE} mtu 9000
su - kali -c 'sudo -n /usr/bin/tcpreplay-edit --intf1={KALI_INTERFACE} --enet-smac={KALI_SOURCE_MAC} --enet-dmac={UBUNTU_MAC} --multiplier=1 --stats=30 {KALI_STAGE}/{case}.pcap'
"""
    replay_rc, replay_doc = remote_bash("kali", replay_script, 420)
    write_json(control / "replay.json", {"return_code": replay_rc, "labctl": replay_doc})
    (attempt / "kali").mkdir(exist_ok=True)
    (attempt / "kali" / "replay.log").write_text(
        str(replay_doc.get("stdout") or ""), encoding="utf-8"
    )

    print("[4/4] Dung cam bien va thu ket qua")
    stop_script = (
        f"cd {REMOTE_ROOT}\n"
        f"bash scripts/ubuntu_t91_live_sensor.sh stop --contract {contract_remote}\n"
    )
    stop_rc, stop_doc = remote_bash("ubuntu", stop_script, 120)
    write_json(control / "stop.json", {"return_code": stop_rc, "labctl": stop_doc})

    sensor_receipt = attempt / "ubuntu" / "sensor.json"
    if not wait_for(sensor_receipt, 120):
        print("  Khong thay sensor.json, chay recover de tra NIC ve trang thai cu.")
        recover_script = (
            f"cd {REMOTE_ROOT}\n"
            f"bash scripts/ubuntu_t91_live_sensor.sh recover --contract {contract_remote}\n"
        )
        recover_rc, recover_doc = remote_bash("ubuntu", recover_script, 120)
        write_json(
            control / "recover.json",
            {"return_code": recover_rc, "labctl": recover_doc},
        )

    return 0, attempt / "ubuntu" / "sensor.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", default=DEFAULT_CASE, help="ten PCAP trong family-windows")
    parser.add_argument("--run-id", default=None, help="mac dinh: latency-<case>-<UTC>")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="chi in lai ket qua lan chay gan nhat, khong dung toi VM",
    )
    args = parser.parse_args(argv)

    if args.report_only:
        sensor_log = latest_run()
        if sensor_log is None:
            print("Chua co lan chay nao duoi run_log/full-flow-v1/latency-live/")
            return 1
        summary = read_summary(sensor_log)
        if summary is None:
            print(f"Khong tim thay summary trong {sensor_log}")
            return 1
        return 0 if print_report(summary, sensor_log) else 1

    run_id = args.run_id or f"latency-{args.case}-{utc_stamp()}"
    code, sensor_log = run_benchmark(args.case, run_id)
    if sensor_log is None:
        return code

    summary = read_summary(sensor_log)
    if summary is None:
        print()
        print("Chay xong nhung khong doc duoc summary. Xem:")
        print(f"  {sensor_log.relative_to(ROOT).as_posix()}")
        return 1

    ok = print_report(summary, sensor_log)
    receipt = {
        "schema_version": "1.0.0",
        "kind": "latency_benchmark_receipt",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_id": run_id,
        "case": args.case,
        "status": summary.get("status"),
        "port_stats": summary.get("port_stats"),
        "inferences": summary.get("inferences"),
        "alerts": summary.get("alerts"),
        "latency_ns": summary.get("latency_ns"),
        "sensor_log": sensor_log.relative_to(ROOT).as_posix(),
    }
    write_json(BENCHMARK_ROOT / run_id / "latency-receipt.json", receipt)
    print(f"  Receipt: run_log/full-flow-v1/latency-live/{run_id}/latency-receipt.json")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
