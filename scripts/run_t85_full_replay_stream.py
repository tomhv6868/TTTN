#!/usr/bin/env python3
"""
T8.5 Full Replay + Stream + Compare Orchestrator

Luồng:
  1. Tạo folder mới với timestamp
  2. Copy manifest từ rebuild-20260808
  3. Copy cut PCAPs đã có (5 families)
  4. Chạy Kali replay từng family còn thiếu (8 families)
  5. Ubuntu sensor capture vào file log
  6. Chạy offline F9 trên tất cả 13 families
  7. So sánh online vs offline vs GT → evidence file

Usage:
  python scripts/run_t85_full_replay_stream.py --run-id 20260808-194942
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

LABCTL = ROOT / "tools" / "labctl.py"
KALI_REPLAY = ROOT / "scripts" / "kali_t85_scenario_replay.py"
UBUNTU_SENSOR_SCRIPT = ROOT / "scripts" / "run_t85_scenario_sensor_ubuntu.sh"
BUNDLE = "/home/wang/.cache/nids-partial-flow/t5.2/bundles/F9"

# 13 families có model (không tính heartbleed)
FAMILIES = [
    "bot", "ddos", "dos-goldeneye", "dos-hulk", "dos-slowhttptest",
    "dos-slowloris", "ftp-patator", "infiltration", "portscan",
    "ssh-patator", "web-brute-force", "web-sql-injection", "web-xss",
]

# Families đã có từ rebuild-20260808
DONE_FAMILIES = {"ddos", "dos-goldeneye", "dos-hulk", "ftp-patator", "ssh-patator"}
PENDING_FAMILIES = [f for f in FAMILIES if f not in DONE_FAMILIES]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def labctl(role: str, cmd: str, timeout: int = 60) -> dict:
    """Chạy lệnh trên VM qua labctl."""
    result = subprocess.run(
        [sys.executable, str(LABCTL), "exec", "--timeout-seconds", str(timeout), role, cmd],
        capture_output=True, text=True, timeout=timeout + 10
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "error", "stdout": result.stdout, "stderr": result.stderr}


def labctl_ok(role: str, cmd: str, timeout: int = 60) -> bool:
    r = labctl(role, cmd, timeout)
    return r.get("status") == "ok"


def check_ubuntu_sensor_ready() -> bool:
    """Kiểm tra Ubuntu sensor có thể chạy."""
    r = labctl("ubuntu", "source ~/.local/nids-toolchain/env.sh && $HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_dpdk_live --help 2>&1 | head -3", 15)
    return r.get("status") == "ok" and "usage" in r.get("stdout", "")


def check_kali_ready() -> bool:
    """Kiểm tra Kali có thể replay."""
    r = labctl("kali", "python3 --version 2>&1", 10)
    return r.get("status") == "ok"


def stop_ubuntu_sensor():
    """Dừng sensor đang chạy nếu có."""
    labctl("ubuntu", "pkill -f nids_dpdk_live 2>/dev/null; pkill -f nids_dpdk_native 2>/dev/null; echo STOPPED", 10)


def get_kali_iface() -> Optional[str]:
    """Lấy interface Kali dùng để replay."""
    r = labctl("kali", "ip link show | grep -E 'eth|ens|enp' | grep UP | head -3", 10)
    if r.get("status") != "ok":
        return None
    for line in r.get("stdout", "").split("\n"):
        parts = line.split(":")
        if len(parts) >= 2:
            iface = parts[1].strip()
            if iface:
                return iface
    return None


def setup_folder(run_id: str) -> Path:
    """Tạo folder structure cho run mới."""
    scenario_root = ROOT / "run_log/t8.5/scenarios" / run_id
    (scenario_root / "kali").mkdir(parents=True, exist_ok=True)
    (scenario_root / "ubuntu").mkdir(parents=True, exist_ok=True)
    (scenario_root / "offline-flows").mkdir(parents=True, exist_ok=True)
    (scenario_root / "confusion").mkdir(parents=True, exist_ok=True)
    (scenario_root / "pcaps").mkdir(parents=True, exist_ok=True)
    return scenario_root


def copy_existing_pcaps(run_id: str, source_run: str = "rebuild-20260808"):
    """Copy cut PCAPs đã có từ source run."""
    src_pcap = ROOT / f"run_log/t8.5/scenarios/{source_run}/pcap/original"
    dst_pcap = ROOT / f"run_log/t8.5/scenarios/{run_id}/pcaps"

    if not src_pcap.exists():
        print(f"  [WARN] Source PCAP dir not found: {src_pcap}")
        return

    for pcap_file in src_pcap.glob("*.pcap"):
        dst = dst_pcap / pcap_file.name
        if not dst.exists():
            dst.write_bytes(pcap_file.read_bytes())
            print(f"  Copied {pcap_file.name} ({pcap_file.stat().st_size} bytes)")


def copy_manifest(run_id: str, source_run: str = "rebuild-20260808"):
    """Copy manifest.json từ source."""
    src = ROOT / f"run_log/t8.5/scenarios/{source_run}/pcap/manifest.json"
    dst = ROOT / f"run_log/t8.5/scenarios/{run_id}/manifest.json"

    if src.exists():
        dst.write_bytes(src.read_bytes())
        print(f"  Copied manifest.json")
    else:
        print(f"  [WARN] Manifest not found: {src}")


def run_offline_f9(run_id: str) -> dict:
    """Chạy offline F9 trên tất cả PCAPs."""
    pcaps_dir = ROOT / f"run_log/t8.5/scenarios/{run_id}/pcaps"
    offline_dir = ROOT / f"run_log/t8.5/scenarios/{run_id}/offline-flows"

    results = {}

    for pcap_file in sorted(pcaps_dir.glob("*.pcap")):
        case_id = pcap_file.stem  # "ftp-patator" from "ftp-patator.pcap"

        # Copy to Ubuntu local SSD
        r = labctl_ok("ubuntu", f"cp /mnt/hgfs/TTTN/run_log/t8.5/scenarios/{run_id}/pcaps/{pcap_file.name} /tmp/offline-{pcap_file.name}", 30)
        if not r:
            print(f"  [SKIP] {case_id}: failed to copy to Ubuntu")
            results[case_id] = {"status": "copy_failed"}
            continue

        # Run nids_demo_replay
        print(f"  Running offline F9: {case_id}...")
        r = labctl("ubuntu",
            f"source ~/.local/nids-toolchain/env.sh && "
            f"$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay "
            f"--input /tmp/offline-{pcap_file.name} "
            f"--bundle {BUNDLE} "
            f"--max-records 1000 --expect-records 9 --expect-f9 1 2>&1",
            timeout=120
        )

        if r.get("status") == "ok":
            stdout = r.get("stdout", "")
            # Parse alert from output
            for line in stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                    if ev.get("event_type") == "nids_alert":
                        results[case_id] = {
                            "status": "ok",
                            "decision": ev.get("decision"),
                            "candidate": ev.get("evidence", {}).get("known_family", {}).get("top_candidate"),
                            "confidence": ev.get("evidence", {}).get("known_family", {}).get("confidence"),
                            "checkpoint": ev.get("checkpoint"),
                            "flow": ev.get("flow"),
                        }
                        print(f"    -> {case_id}: {ev.get('decision')} -> {ev.get('evidence',{}).get('known_family',{}).get('top_candidate')}")
                        break
            else:
                results[case_id] = {"status": "no_alert"}
                print(f"    -> {case_id}: no alert")
        else:
            results[case_id] = {"status": "error", "stderr": r.get("stderr", "")[:200]}
            print(f"    -> {case_id}: error")

    # Save offline results
    offline_file = offline_dir / "offline-f9-results.json"
    offline_file.write_text(json.dumps({
        "kind": "offline_f9_results",
        "run_id": run_id,
        "generated_at": utcnow(),
        "results": results,
    }, indent=2, ensure_ascii=False))
    print(f"  Saved: {offline_file}")

    return results


def run_online_replay_pending(run_id: str) -> dict:
    """
    Chạy Kali replay cho 8 families còn thiếu.
    Mỗi family: replay từ Kali + capture từ Ubuntu sensor.
    """
    results = {}
    iface = get_kali_iface()
    if not iface:
        print("  [ERROR] Cannot determine Kali interface")
        return results

    # Get Ubuntu sensor MAC (destination for replay)
    r = labctl("ubuntu", "ip link show | grep ether | head -3", 10)
    if r.get("status") != "ok":
        print("  [ERROR] Cannot get Ubuntu MAC")
        return results

    # Parse Ubuntu MAC from output
    ubuntu_mac = None
    for line in r.get("stdout", "").split("\n"):
        if "ether" in line:
            parts = line.split("ether")
            if len(parts) >= 2:
                ubuntu_mac = parts[1].strip().split()[0]
                break

    if not ubuntu_mac:
        # Fallback
        ubuntu_mac = "00:0c:29:eb:d8:c4"  # Common VMware MAC prefix

    print(f"  Kali interface: {iface}")
    print(f"  Ubuntu MAC: {ubuntu_mac}")

    for family in PENDING_FAMILIES:
        print(f"\n  === Replaying: {family} ===")

        attempt = f"f9-{family}"
        sensor_log = ROOT / f"run_log/t8.5/scenarios/{run_id}/ubuntu/{attempt}/sensor.jsonl"

        # Skip if sensor log already exists
        if sensor_log.exists():
            with sensor_log.open(encoding="utf-8") as f:
                lines = [l for l in f if l.strip()]
            alert_count = sum(1 for l in lines if json.loads(l).get("event_type") == "nids_alert")
            print(f"    Already exists: {alert_count} alerts")
            results[family] = {"status": "already_done", "alerts": alert_count}
            continue

        # Create attempt dir
        sensor_log.parent.mkdir(parents=True, exist_ok=True)

        # Stop any running sensor
        stop_ubuntu_sensor()

        # Start sensor on Ubuntu (background)
        print(f"    Starting sensor on Ubuntu...")
        sensor_cmd = (
            f"cd /mnt/hgfs/TTTN && "
            f"bash scripts/run_t85_scenario_sensor_ubuntu.sh "
            f"--run-id {run_id} --bundle {BUNDLE} --attempt {attempt} "
            f"--duration-seconds 120 --max-packets 10000 2>&1 | tee /tmp/sensor-{attempt}.log &"
        )
        r = labctl("ubuntu", sensor_cmd, 10)
        if r.get("status") != "ok":
            print(f"    [ERROR] Failed to start sensor: {r.get('stderr','')[:100]}")
            results[family] = {"status": "sensor_start_failed"}
            continue

        # Wait for sensor to be ready
        print(f"    Waiting for sensor to start (10s)...")
        time.sleep(10)

        # Replay from Kali
        print(f"    Replaying from Kali...")
        kali_cmd = (
            f"cd /mnt/hgfs/TTTN && "
            f"sudo python3 scripts/kali_t85_scenario_replay.py "
            f"--run-id rebuild-20260808 "
            f"--case {family} "
            f"--interface {iface} "
            f"--destination-mac {ubuntu_mac} "
            f"--mtu 1500 2>&1"
        )
        r = labctl("kali", kali_cmd, timeout=120)

        if r.get("status") != "ok":
            print(f"    [ERROR] Kali replay failed: {r.get('stderr','')[:200]}")
            results[family] = {"status": "replay_failed", "stderr": r.get("stderr", "")[:200]}
            stop_ubuntu_sensor()
            continue

        # Wait for sensor to finish processing
        print(f"    Waiting for sensor to finish (30s)...")
        time.sleep(30)

        # Stop sensor
        stop_ubuntu_sensor()

        # Check results
        if sensor_log.exists():
            with sensor_log.open(encoding="utf-8") as f:
                lines = [l for l in f if l.strip()]
            alert_count = sum(1 for l in lines if json.loads(l).get("event_type") == "nids_alert")
            print(f"    Done: {alert_count} alerts")
            results[family] = {"status": "ok", "alerts": alert_count}
        else:
            print(f"    [WARN] No sensor log found")
            results[family] = {"status": "no_sensor_log"}

    return results


def build_evidence(run_id: str, online_results: dict, offline_results: dict) -> dict:
    """
    Build evidence file: so sánh online vs offline vs GT.
    """
    manifest = json.loads((ROOT / f"run_log/t8.5/scenarios/{run_id}/manifest.json").read_text())
    manifest_map = {o["case_id"]: o for o in manifest["outputs"]}

    # Ground truth comes from the manifest, never from a hardcoded table: the
    # oracle writes en-dash labels ("Web Attack – XSS") and a hyphen copy here
    # would silently score three web families as wrong.
    GT = {case_id: o["label"] for case_id, o in manifest_map.items()}

    rows = []
    for family in FAMILIES:
        gt = GT.get(family, "?")
        on = online_results.get(family, {})
        off = offline_results.get(family, {})

        # Online
        if on.get("status") == "ok" and on.get("alerts", 0) > 0:
            # Read sensor log to get candidates
            sensor_log = ROOT / f"run_log/t8.5/scenarios/{run_id}/ubuntu/f9-{family}/sensor.jsonl"
            if sensor_log.exists():
                with sensor_log.open(encoding="utf-8") as f:
                    from collections import Counter
                    lines = [json.loads(l) for l in f if l.strip() and json.loads(l).get("event_type") == "nids_alert"]
                cands = Counter(e.get("evidence", {}).get("known_family", {}).get("top_candidate", "?") for e in lines)
                on_top = cands.most_common(1)[0][0] if cands else "?"
                on_acc = cands.get(gt, 0) / len(lines) if lines else 0
                on_total = len(lines)
            else:
                on_top, on_acc, on_total = "?", 0, 0
        else:
            on_top, on_acc, on_total = "N/A", None, on.get("alerts", 0)

        # Offline
        off_cand = off.get("candidate", "N/A") if off.get("status") == "ok" else "N/A"
        off_conf = off.get("confidence") if off.get("status") == "ok" else None

        rows.append({
            "family": family,
            "gt": gt,
            "online": {"top": on_top, "acc": on_acc, "total": on_total},
            "offline": {"candidate": off_cand, "confidence": off_conf},
        })

    evidence = {
        "kind": "t85_evidence",
        "run_id": run_id,
        "generated_at": utcnow(),
        "families_tested": len(FAMILIES),
        "online_families": sum(1 for r in rows if r["online"]["total"] > 0),
        "offline_families": sum(1 for r in rows if r["offline"]["candidate"] != "N/A"),
        "rows": rows,
    }

    out = ROOT / f"run_log/t8.5/scenarios/{run_id}/confusion/evidence.json"
    out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False))

    # Also write markdown summary
    md_lines = [
        "# T8.5 Evidence — Online vs Offline F9",
        "",
        f"**Run:** `{run_id}` · **Generated:** {evidence['generated_at']}",
        "",
        f"| Family | GT | Online | Acc | Offline |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        on_acc = f"{r['online']['acc']*100:.1f}%" if r["online"]["acc"] is not None else "—"
        md_lines.append(
            f"| {r['family']} | {r['gt']} | "
            f"{r['online']['top']} ({r['online']['total']}) | {on_acc} | "
            f"{r['offline']['candidate']} |"
        )

    md_out = ROOT / f"run_log/t8.5/scenarios/{run_id}/confusion/evidence.md"
    md_out.write_text("\n".join(md_lines) + "\n")

    return evidence


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", default="20260808-194942")
    ap.add_argument("--skip-replay", action="store_true", help="Skip Kali replay (use existing sensor logs)")
    ap.add_argument("--skip-offline", action="store_true", help="Skip offline F9 run")
    args = ap.parse_args()

    run_id = args.run_id
    print(f"\n{'='*60}")
    print(f"T8.5 Full Replay + Stream + Compare")
    print(f"Run ID: {run_id}")
    print(f"{'='*60}\n")

    # Step 1: Setup folder
    print(f"[1] Setting up folder...")
    scenario_root = setup_folder(run_id)
    print(f"  Folder: {scenario_root}")

    # Step 2: Copy manifest + existing PCAPs
    print(f"[2] Copying manifest and existing PCAPs...")
    copy_manifest(run_id)
    copy_existing_pcaps(run_id)

    # Step 3: Check prerequisites
    print(f"[3] Checking prerequisites...")
    kali_ok = check_kali_ready()
    sensor_ok = check_ubuntu_sensor_ready()
    print(f"  Kali ready: {kali_ok}")
    print(f"  Ubuntu sensor ready: {sensor_ok}")

    if not kali_ok or not sensor_ok:
        print(f"\n[ERROR] Prerequisites not met. Cannot continue.")
        print(f"  Kali: {kali_ok}, Sensor: {sensor_ok}")
        return 1

    # Step 4: Run online replay for pending families
    online_results = {}
    if not args.skip_replay:
        print(f"[4] Running online replay for {len(PENDING_FAMILIES)} pending families...")
        online_results = run_online_replay_pending(run_id)
    else:
        print(f"[4] Skipping replay (--skip-replay)")
        # Still load existing sensor logs
        for family in FAMILIES:
            attempt = f"f9-{family}"
            sensor_log = ROOT / f"run_log/t8.5/scenarios/{run_id}/ubuntu/{attempt}/sensor.jsonl"
            if sensor_log.exists():
                with sensor_log.open(encoding="utf-8") as f:
                    lines = [l for l in f if l.strip()]
                online_results[family] = {
                    "status": "ok",
                    "alerts": sum(1 for l in lines if json.loads(l).get("event_type") == "nids_alert")
                }

    # Also load existing sensor logs from DONE families
    for family in DONE_FAMILIES:
        attempt = f"f9-{family}" if family != "dos-hulk" else "fh-hulk"
        if family == "dos-hulk":
            attempt = "fh-hulk"  # The dos-hulk attempt dir
        sensor_log = ROOT / f"run_log/t8.5/scenarios/{run_id}/ubuntu/{attempt}/sensor.jsonl"
        if sensor_log.exists() and family not in online_results:
            with sensor_log.open(encoding="utf-8") as f:
                lines = [l for l in f if l.strip()]
            online_results[family] = {
                "status": "ok",
                "alerts": sum(1 for l in lines if json.loads(l).get("event_type") == "nids_alert")
            }

    print(f"\n[4b] Online results: {sum(1 for v in online_results.values() if v.get('alerts',0)>0)} families with alerts")

    # Step 5: Run offline F9
    offline_results = {}
    if not args.skip_offline:
        print(f"\n[5] Running offline F9 on all PCAPs...")
        offline_results = run_offline_f9(run_id)
    else:
        print(f"[5] Skipping offline F9 (--skip-offline)")

    # Step 6: Build evidence
    print(f"\n[6] Building evidence...")
    evidence = build_evidence(run_id, online_results, offline_results)
    print(f"  Online families: {evidence['online_families']}/{len(FAMILIES)}")
    print(f"  Offline families: {evidence['offline_families']}/{len(FAMILIES)}")

    print(f"\n{'='*60}")
    print(f"Done! Evidence: {ROOT}/run_log/t8.5/scenarios/{run_id}/confusion/evidence.json")
    print(f"{'='*60}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
