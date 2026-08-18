#!/usr/bin/env python3
"""
Re-cut full flows từ original CICIDS PCAP bằng oracle flow_id + timestamp.

Dùng để:
  1. Extract all packets cho mỗi manifest flow_id từ original CICIDS PCAP
  2. Gửi lên Ubuntu, chạy nids_demo_replay để get offline F9 decision
  3. Compare: online F9 vs offline F9 vs manifest ground truth (3-way)

Usage:
  python scripts/cut_full_flows.py --output-dir run_log/t8.5/scenarios/rebuild-20260808/offline-flows
  # Sau đó chạy trên Ubuntu:
  bash scripts/run_offline_f9.sh
"""
from __future__ import annotations

import argparse
import json
import struct
import sqlite3
import datetime as dt
from collections import defaultdict
from pathlib import Path

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp"}


# ---------------------------------------------------------------------------
# 1. PCAP reader (no external deps — pure struct)
# ---------------------------------------------------------------------------

def read_pcap_packets(pcap_path: Path):
    """Yield (ts_ns, packet_bytes) for each packet in a classic pcap."""
    data = pcap_path.read_bytes()
    if len(data) < 24:
        return

    magic_le = struct.unpack('<I', data[:4])[0]
    magic_be = struct.unpack('>I', data[:4])[0]

    if magic_le == 0xa1b2c3d4:
        byte_order = '<'
    elif magic_be == 0xa1b2c3d4:
        byte_order = '>'
    else:
        # Try to detect
        return

    off = 24  # skip global header
    fmt = byte_order + 'IIII'
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(fmt, data, off)
        if incl_len < 14 or incl_len > 65535:
            break
        if off + 16 + incl_len > len(data):
            break
        ts_ns = ts_sec * 1_000_000_000 + ts_usec * 1000
        pkt = data[off + 16: off + 16 + incl_len]
        yield ts_ns, pkt
        off += 16 + incl_len


def get_ip_pair(pkt_bytes: bytes):
    """Return (src_ip_int, dst_ip_int, proto, src_port, dst_port) from IP header."""
    if len(pkt_bytes) < 20:
        return None
    ver = (pkt_bytes[0] >> 4) & 0xF
    if ver != 4:
        return None
    ihl = (pkt_bytes[0] & 0xF) * 4
    if ihl < 20 or len(pkt_bytes) < ihl + 4:
        return None
    proto = pkt_bytes[9]
    src_ip = struct.unpack('>I', pkt_bytes[12:16])[0]
    dst_ip = struct.unpack('>I', pkt_bytes[16:20])[0]
    src_port = dst_port = 0
    if proto in (6, 17) and len(pkt_bytes) >= ihl + 4:
        src_port = struct.unpack('>H', pkt_bytes[ihl:ihl + 2])[0]
        dst_port = struct.unpack('>H', pkt_bytes[ihl + 2:ihl + 4])[0]
    return src_ip, dst_ip, proto, src_port, dst_port


def tuple_key(sip: int, spt: int, dip: int, dpt: int, proto: int):
    a, b = (sip, spt), (dip, dpt)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], proto)


# ---------------------------------------------------------------------------
# 2. Write a cut PCAP (classic format)
# ---------------------------------------------------------------------------

def write_pcap(output_path: Path, packets: list):
    """Write a classic pcap with given (ts_ns, pkt_bytes) list."""
    with output_path.open("wb") as f:
        # Global header
        f.write(struct.pack('<I', 0xa1b2c3d4))  # magic
        f.write(struct.pack('<HH', 2, 4))       # version 2.4
        f.write(struct.pack('<i', 0))          # this zone
        f.write(struct.pack('<I', 0))          # sigfigs
        f.write(struct.pack('<I', 65535))       # snaplen
        f.write(struct.pack('<I', 1))           # link type: Ethernet
        for ts_ns, pkt in packets:
            ts_sec = ts_ns // 1_000_000_000
            ts_usec = (ts_ns % 1_000_000_000) // 1000
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)


# ---------------------------------------------------------------------------
# 3. Load manifest
# ---------------------------------------------------------------------------

def load_manifest(manifest_path: Path) -> dict:
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {out["case_id"]: out for out in doc["outputs"]}


# ---------------------------------------------------------------------------
# 4. Load oracle flow metadata (only specific flow_ids needed)
# ---------------------------------------------------------------------------

def load_flow_metadata(oracle_db: Path, flow_ids: list[int]) -> dict:
    """flow_id → {capture_id, tuple, creation_ts_ns, last_capture_ts_ns, packet_count}"""
    db = sqlite3.connect(f"file:{oracle_db}?mode=ro", uri=True)
    flows = {}
    if flow_ids:
        placeholders = ','.join('?' * len(flow_ids))
        for (fid, cap, proto, lip, lpt, hip, hpt,
             creation_ts, last_capture_ts, packet_count) in db.execute(
                f"SELECT flow_id, capture_id, protocol, low_ip, low_port, high_ip, high_port,"
                f" creation_timestamp_ns, last_capture_timestamp_ns, packet_count"
                f" FROM flow WHERE flow_id IN ({placeholders})",
                flow_ids
        ):
            flows[fid] = {
                "capture_id": cap,
                "protocol": proto,
                "low_ip": lip, "low_port": lpt,
                "high_ip": hip, "high_port": hpt,
                "creation_ts_ns": creation_ts,
                "last_capture_ts_ns": last_capture_ts,
                "packet_count": packet_count,
                "tuple": tuple_key(lip, lpt, hip, hpt, proto),
            }
    db.close()
    return flows


# ---------------------------------------------------------------------------
# 5. Map capture_id → original PCAP path (on Windows hgfs path for Ubuntu)
# ---------------------------------------------------------------------------

CAPTURE_PCAP_MAP = {
    "monday-working-hours":    "pcap/Monday-WorkingHours.pcap",
    "tuesday-working-hours":  "pcap/Tuesday-WorkingHours.pcap",
    "wednesday-working-hours": "pcap/Wednesday-workingHours.pcap",
    "thursday-working-hours":  "pcap/Thursday-WorkingHours.pcap",
    "friday-working-hours":    "pcap/Friday-WorkingHours.pcap",
}


# ---------------------------------------------------------------------------
# 6. Extract full flow from PCAP
# ---------------------------------------------------------------------------

def extract_full_flow(pcap_path: Path, flow_meta: dict,
                      margin_ns: int = 5_000_000_000) -> list:
    """
    Extract all packets for a flow from original PCAP.
    Uses creation_ts_ns as start, last_capture_ts_ns as end,
    with margin_ns on each side.
    Matches by 5-tuple (direction-insensitive).
    """
    start_ns = flow_meta["creation_ts_ns"] - margin_ns
    end_ns = flow_meta["last_capture_ts_ns"] + margin_ns
    target_tuple = flow_meta["tuple"]

    # Build (ts_ns, pkt_bytes) list
    packets = []
    for ts_ns, pkt in read_pcap_packets(pcap_path):
        if ts_ns < start_ns or ts_ns > end_ns:
            continue
        ip_info = get_ip_pair(pkt)
        if ip_info is None:
            continue
        sip, dip, proto, spt, dpt = ip_info
        tk = tuple_key(sip, spt, dip, dpt, proto)
        if tk == target_tuple:
            packets.append((ts_ns, pkt))

    # Sort by timestamp
    packets.sort(key=lambda x: x[0])
    return packets


# ---------------------------------------------------------------------------
# 7. Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest",
                    default="run_log/t8.5/scenarios/rebuild-20260808/pcap/manifest.json",
                    type=Path)
    ap.add_argument("--oracle-db",
                    default="run_log/t3.3/label-join.sqlite3",
                    type=Path)
    ap.add_argument("--output-dir",
                    default="run_log/t8.5/scenarios/rebuild-20260808/offline-flows",
                    type=Path)
    ap.add_argument("--case", action="append",
                    help="Limit to specific case_id(s)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    manifest = load_manifest(args.manifest)
    flow_ids_needed = [out["flow_id"] for out in manifest.values()
                       if out.get("flow_id")]
    flows = load_flow_metadata(args.oracle_db, flow_ids_needed)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cases = {k: v for k, v in manifest.items()
             if args.case is None or k in args.case}
    cases = {k: v for k, v in cases.items() if v.get("flow_id") and v.get("tuple")}

    print(f"Processing {len(cases)} cases...", flush=True)

    results = []
    shell_commands = []

    for case_id, case in sorted(cases.items()):
        fid = case["flow_id"]
        cap = case["capture_id"]
        pcap_rel = CAPTURE_PCAP_MAP.get(cap)
        if not pcap_rel:
            print(f"  SKIP {case_id}: unknown capture {cap}")
            continue

        pcap_path = Path(pcap_rel)
        if not pcap_path.exists():
            print(f"  SKIP {case_id}: PCAP not found at {pcap_path}")
            continue

        flow_meta = flows.get(fid)
        if not flow_meta:
            print(f"  SKIP {case_id}: flow_id {fid} not in oracle")
            continue

        print(f"  {case_id}: fid={fid} cap={cap} "
              f"pc={flow_meta['packet_count']} "
              f"ts={flow_meta['creation_ts_ns']}", flush=True)

        packets = extract_full_flow(pcap_path, flow_meta)
        if not packets:
            print(f"    WARNING: 0 packets extracted!")
            continue

        output_pcap = output_dir / f"{case_id}.pcap"
        if not args.dry_run:
            write_pcap(output_pcap, packets)
        print(f"    -> {output_pcap}: {len(packets)} packets, "
              f"{output_pcap.stat().st_size / 1024:.1f} KB")

        # Shell command to run nids_demo_replay on Ubuntu
        # Bundle path on Ubuntu: /home/wang/.cache/nids-partial-flow/t5.2/bundles/F9
        # HGFS path: /mnt/hgfs/TTTN/...
        hgfs_pcap = f"/mnt/hgfs/TTTN/{output_pcap}"
        bundle = "/home/wang/.cache/nids-partial-flow/t5.2/bundles/F9"
        out_json = f"/mnt/hgfs/TTTN/run_log/t8.5/scenarios/rebuild-20260808/offline-flows/{case_id}-offline.json"
        max_records = len(packets) + 100
        shell_commands.append(
            f"# {case_id}: {len(packets)} packets, GT={case['label']}\n"
            f"echo '=== {case_id} ===' && "
            f"source ~/.local/nids-toolchain/env.sh && "
            f"$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay "
            f"--input '{hgfs_pcap}' --bundle '{bundle}' --max-records {max_records} "
            f"--expect-records {len(packets)} "
            f"--expect-f9 1 2>&1 | tee /tmp/offline-{case_id}.log"
        )

        results.append({
            "case_id": case_id,
            "label": case["label"],
            "capture_id": cap,
            "flow_id": fid,
            "pcap_path": str(output_pcap),
            "packet_count": len(packets),
            "oracle_packet_count": flow_meta["packet_count"],
            "shell_cmd": shell_commands[-1],
            "output_json": out_json,
        })

    # Write metadata
    meta_path = output_dir / "manifest.json"
    meta = {
        "kind": "offline_flows",
        "description": "Full flows extracted from original CICIDS PCAP using oracle flow_id + timestamp",
        "cases": results,
        "shell_commands": shell_commands,
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {meta_path} ({len(results)} flows extracted)")

    # Write run script
    script_path = output_dir / "run_offline_f9.sh"
    script = [
        "#!/usr/bin/env bash",
        "# Auto-generated by cut_full_flows.py",
        "# Run on Ubuntu VM: cd /mnt/hgfs/TTTN && bash run_log/t8.5/scenarios/rebuild-20260808/offline-flows/run_offline_f9.sh",
        "",
    ]
    for cmd in shell_commands:
        script.append(cmd)
    script_path.write_text("\n".join(script) + "\n", encoding="utf-8")
    print(f"wrote {script_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
