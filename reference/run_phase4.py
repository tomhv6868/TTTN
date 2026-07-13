"""
run_phase4.py — Phase 4: Zeek + Suricata baseline validation.

Runs pre-flight checks, starts the IDS engine, monitors alerts in real-time,
and prints a detection summary on exit (Ctrl+C).

Usage (on Ubuntu VM, run as root for raw socket access):
    cd /mnt/hgfs/ATMNCDOAN
    sudo ~/ids-venv/bin/python run_phase4.py
    sudo ~/ids-venv/bin/python run_phase4.py --iface ens33 --duration 120

Then launch attacks from the Kali VM using scripts/kali_attacks.sh.
"""

import argparse
import json
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

ROOT = Path(__file__).parent
ALERT_LOG = Path("/var/log/multilayer_ids/alerts.jsonl")
SURICATA_FAST = Path("/var/log/suricata/fast.log")
ZEEK_CONN = Path("/opt/zeek/logs/current/conn.log")


# ── Pre-flight checks ─────────────────────────────────────────────────────────

def preflight() -> bool:
    ok = True

    models_needed = [
        "layer1_dt.pkl", "layer1_scaler.pkl",
        "layer2_lgbm.pkl", "layer2_scaler.pkl",
        "layer3_lgbm.pkl", "layer3_scaler.pkl",
    ]
    missing = [m for m in models_needed if not (ROOT / "models" / m).exists()]
    if missing:
        print(f"[!] Missing model files: {missing}")
        print("    Train models on Windows first, then re-run.")
        ok = False
    else:
        print("[✓] All model files present")

    if ZEEK_CONN.exists():
        print(f"[✓] Zeek conn.log found: {ZEEK_CONN}")
    else:
        print(f"[!] Zeek conn.log not found at {ZEEK_CONN}")
        print("    Start Zeek: sudo /opt/zeek/bin/zeekctl deploy")
        ok = False

    result = subprocess.run(
        ["systemctl", "is-active", "suricata"],
        capture_output=True, text=True
    )
    if result.stdout.strip() == "active":
        print("[✓] Suricata is active")
    else:
        print("[!] Suricata is not running")
        print("    Start it: sudo systemctl start suricata")
        ok = False

    return ok


# ── Alert monitor ─────────────────────────────────────────────────────────────

class AlertMonitor:
    """Tails alerts.jsonl and counts detections per layer in real-time."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = defaultdict(int)
        self.total = 0
        self._stop = threading.Event()

    def run(self) -> None:
        ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
        ALERT_LOG.touch(exist_ok=True)
        with open(ALERT_LOG, encoding="utf-8") as f:
            f.seek(0, 2)  # start at end
            while not self._stop.is_set():
                line = f.readline()
                if not line:
                    self._stop.wait(0.3)
                    continue
                try:
                    alert = json.loads(line)
                    self.total += 1
                    for layer in alert.get("layers", []):
                        self.counts[layer] += 1
                    src = alert.get("src_ip", "?")
                    dst = alert.get("dst_ip", "?")
                    port = alert.get("dst_port", "?")
                    conf = alert.get("confidence", 0)
                    layers = ",".join(alert.get("layers", []))
                    print(
                        f"  [ALERT #{self.total}] {src} → {dst}:{port} "
                        f"| layers={layers} | conf={conf:.3f}"
                    )
                except json.JSONDecodeError:
                    pass

    def stop(self) -> None:
        self._stop.set()

    def summary(self) -> None:
        print("\n" + "=" * 55)
        print(" Phase 4 Detection Summary")
        print("=" * 55)
        print(f"  Total alerts fired : {self.total}")
        for layer, count in sorted(self.counts.items()):
            print(f"  {layer} detections    : {count}")
        if SURICATA_FAST.exists():
            suricata_lines = SURICATA_FAST.read_text(errors="replace").strip().splitlines()
            print(f"  Suricata fast.log  : {len(suricata_lines)} entries")
        print("=" * 55)


# ── Engine launcher ───────────────────────────────────────────────────────────

def start_engine(iface: str, venv: str) -> subprocess.Popen:
    python = Path(venv) / "bin" / "python"
    if not python.exists():
        # Fall back to system python if venv not found at expected path
        python = Path(sys.executable)
    cmd = [
        str(python), str(ROOT / "run_phase3.py"),
        "--iface", iface,
        "--zeek-log", str(ZEEK_CONN),
        "--alert-log", str(ALERT_LOG),
    ]
    print(f"[*] Starting IDS engine on {iface}...")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def stream_engine_output(proc: subprocess.Popen) -> None:
    """Forward engine stdout to our stdout in a background thread."""
    for line in proc.stdout:  # type: ignore[union-attr]
        print("  [engine]", line.rstrip())


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 4: Zeek + Suricata baseline + IDS engine validation"
    )
    parser.add_argument("--iface",    default="ens33",
                        help="Network interface (default: ens33)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Auto-stop after N seconds (0 = run until Ctrl+C)")
    parser.add_argument("--venv",     default="/root/ids-venv",
                        help="Path to Python venv used to launch run_phase3.py")
    parser.add_argument("--no-engine", action="store_true",
                        help="Skip engine launch — just monitor existing alert log")
    args = parser.parse_args()

    print("=" * 55)
    print(" Phase 4 — Pre-flight checks")
    print("=" * 55)
    if not preflight():
        sys.exit(1)

    monitor = AlertMonitor()
    monitor_thread = threading.Thread(target=monitor.run, daemon=True, name="AlertMonitor")
    monitor_thread.start()

    engine_proc = None
    if not args.no_engine:
        engine_proc = start_engine(args.iface, args.venv)
        threading.Thread(
            target=stream_engine_output, args=(engine_proc,),
            daemon=True, name="EngineLog"
        ).start()

    print("\n" + "=" * 55)
    print(" Monitoring — launch attacks from Kali now")
    print(f" Alert log: {ALERT_LOG}")
    print(" Press Ctrl+C to stop and show summary")
    print("=" * 55 + "\n")

    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")

    monitor.stop()
    if engine_proc:
        engine_proc.terminate()
        try:
            engine_proc.wait(timeout=30)
        except Exception:
            engine_proc.kill()

    monitor.summary()


if __name__ == "__main__":
    main()
