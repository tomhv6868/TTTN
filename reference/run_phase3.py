"""
run_phase3.py — Phase 3 launcher: RT-FLID 3-layer live detection engine.

Requires root/admin privileges for raw packet capture (Scapy).
Zeek must be running and writing to the configured conn.log path.

Usage:
    sudo python run_phase3.py
    sudo python run_phase3.py --iface ens33
    sudo python run_phase3.py --iface ens33 --zeek-log /opt/zeek/logs/current/conn.log
    sudo python run_phase3.py --iface ens33 --alert-log /var/log/multilayer_ids/alerts.jsonl
    sudo python run_phase3.py --iface ens33 --filter "ip and not arp"
"""

import argparse
import sys
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.inference.engine import IDSEngine  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 3: Live 3-layer IDS engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--iface",      default="eth0",
                        help="Network interface to sniff")
    parser.add_argument("--zeek-log",   default="/opt/zeek/logs/current/conn.log",
                        help="Path to Zeek conn.log (tailed for Layer 3)")
    parser.add_argument("--alert-log",  default="/var/log/multilayer_ids/alerts.jsonl",
                        help="Path for JSON alert output (Wazuh localfile input)")
    parser.add_argument("--filter",     default="ip",
                        help="BPF filter for Scapy packet capture")
    args = parser.parse_args()

    # Verify models are present before starting
    models_dir = ROOT / "models"
    required = [
        "layer1_dt.pkl", "layer1_scaler.pkl",
        "layer2_lgbm.pkl", "layer2_scaler.pkl",
        "layer3_lgbm.pkl", "layer3_scaler.pkl",
    ]
    missing = [m for m in required if not (models_dir / m).exists()]
    if missing:
        print(f"[!] Missing model files: {missing}")
        print("    Run 'python run_phase2.py' first to train all layers.")
        sys.exit(1)

    engine = IDSEngine(
        iface=args.iface,
        zeek_log=Path(args.zeek_log),
        alert_log=Path(args.alert_log),
        bpf_filter=args.filter,
    )
    engine.run()


if __name__ == "__main__":
    main()
