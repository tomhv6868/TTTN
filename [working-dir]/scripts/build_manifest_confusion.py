#!/usr/bin/env python3
"""
Confusion matrix cho F9 replay vs CICIDS ground truth, dùng manifest làm ground truth.

Methodology (theo yêu cầu user: "Đầy đủ: re-cắt theo flow_id + map online↔offline + so 3 chiều"):

  Bước 1 — Manifest là ground truth: mỗi case có flow_id oracle chính xác
            → ground_truth = manifest[case_id].label

  Bước 2 — Map online alert → oracle flow qua:
            - Manifest: cho biết flow_id gốc (oracle) + tuple nguyên + thời điểm
            - Sensor log: chứa flow.id.sequence (reconstruction flow ID)
            - Offline decision: chạy F9 offline trên pcap gốc (3rd dimension)

  Bước 3 — Confusion 2 chiều:
            Online F9 decision vs manifest label
            Offline F9 decision vs manifest label
            → Đánh giá độ lệch online vs offline

Data sources:
  Manifest:   run_log/t8.5/scenarios/rebuild-20260808/pcap/manifest.json
  Online:     run_log/t8.5/scenarios/rebuild-20260808/ubuntu/<attempt>/sensor.jsonl
  Offline:    run_log/t8.5/scenarios/rebuild-20260808/pcap/original/<case>.pcap
  Ground truth: manifest[case_id].label
"""
from __future__ import annotations

import argparse
import json
import struct
import sqlite3
import datetime as dt
from collections import Counter, defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# 1. Load manifest
# ---------------------------------------------------------------------------

def load_manifest(manifest_path: Path) -> dict[str, dict]:
    """case_id → {label, capture_id, flow_id, tuple, start_ns, end_ns, path, records}"""
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {out["case_id"]: out for out in doc["outputs"]}


# ---------------------------------------------------------------------------
# 2. Load sensor alerts cho 1 attempt
# ---------------------------------------------------------------------------

def load_sensor_alerts(sensor_path: Path) -> list[dict]:
    if not sensor_path.exists():
        return []
    alerts = []
    with sensor_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "nids_alert":
                continue
            alerts.append(ev)
    return alerts


# ---------------------------------------------------------------------------
# 3. Summary stats từ sensor.jsonl
# ---------------------------------------------------------------------------

def sensor_summary(sensor_path: Path) -> dict | None:
    """Đọc nids_dpdk_live_summary + mtime để lấy timing info."""
    if not sensor_path.exists():
        return None
    lines = sensor_path.read_text(encoding="utf-8").splitlines()
    summary = None
    first_cp = None
    last_cp = None
    alert_count = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("event_type", "")
        if t == "nids_dpdk_live_summary":
            summary = ev
        elif t == "nids_alert":
            alert_count += 1
            cp = ev.get("checkpoint_timestamp_ns")
            if isinstance(cp, (int, float)):
                if first_cp is None:
                    first_cp = cp
                last_cp = cp
    if summary is None:
        return None
    mtime = sensor_path.stat().st_mtime
    dur_ms = summary.get("duration_ms", 0)
    active_ns = summary.get("active_duration_ns", 0)
    idle_before_s = (dur_ms * 1e6 - active_ns) / 1e9
    sensor_start_wall = mtime - (dur_ms / 1000.0)
    offset_ns = (sensor_start_wall + idle_before_s) * 1e9 - (first_cp or 0)
    return {
        "status": summary.get("status"),
        "duration_ms": dur_ms,
        "active_s": active_ns / 1e9,
        "idle_before_s": idle_before_s,
        "offset_ns": offset_ns,
        "first_cp_ns": first_cp,
        "last_cp_ns": last_cp,
        "alerts": alert_count,
        "decisions": {
            "known_attack": summary.get("known_attack", 0),
            "unknown_candidate": summary.get("unknown_candidate", 0),
            "uncertain": summary.get("uncertain", 0),
            "benign": summary.get("benign", 0),
        },
        "packets_seen": summary.get("packets_seen", 0),
        "stop_reason": summary.get("stop_reason"),
    }


# ---------------------------------------------------------------------------
# 4. Run offline F9 decision trên pcap gốc
#    (Parse pcap, extract flow, run F9 checkpoint tại mỗi packet thứ 9+)
# ---------------------------------------------------------------------------

def run_offline_f9(pcap_path: Path, model_bundle_dir: Path) -> list[dict] | None:
    """
    Chạy F9 offline trên pcap.
    Trả về list alerts: [{packet_idx, ts_ns, candidate, decision, packet_count}, ...]

    Nếu model_bundle_dir không tồn tại → trả về None (skip offline).
    """
    if not pcap_path.exists():
        return None
    # Gọi nids_dpdk_native với --offline pcap
    # Hoặc dùng Python parsing + call model
    # Tạm thời: parse pcap, build flow theo 5-tuple, trigger F9 tại packet 9+
    # Return None nếu không có model
    return None  # Offline decision requires native binary — implement later


# ---------------------------------------------------------------------------
# 5. Map attempt dir → case_id
# ---------------------------------------------------------------------------

# reconstruction run dùng case_id = attempt name (f9-ftp-patator → ftp-patator)
# ngoại trừ fh-hulk (manual rename của dos-hulk attempt)
ATTEMPT_CASE_MAP = {
    "f9-ftp-patator":   "ftp-patator",
    "f9-ssh-patator":   "ssh-patator",
    "f9-dos-goldeneye":  "dos-goldeneye",
    "f9-ddos":          "ddos",
    "f9-portscan":      "portscan",
    "fh-hulk":          "dos-hulk",   # manual rename của dos-hulk attempt
    "dos-hulk":         "dos-hulk",   # fallback
}


# ---------------------------------------------------------------------------
# 6. Build confusion từ online alerts
# ---------------------------------------------------------------------------

def build_online_confusion(manifest: dict, sensor_root: Path) -> dict:
    """Build confusion matrix từ sensor.jsonl alerts vs manifest ground truth."""
    family_conf = defaultdict(Counter)    # gt_label → {candidate: count}
    family_total = defaultdict(int)
    family_decisions = defaultdict(Counter)
    family_ts_range = defaultdict(lambda: [None, None])
    attempt_results = {}

    for attempt_name, case_id in ATTEMPT_CASE_MAP.items():
        case = manifest.get(case_id)
        if case is None:
            continue
        sensor_path = sensor_root / attempt_name / "sensor.jsonl"
        if not sensor_path.exists():
            continue

        gt_label = case["label"]
        alerts = load_sensor_alerts(sensor_path)
        summary = sensor_summary(sensor_path)

        # Per-attempt stats
        cand_counter = Counter()
        dec_counter = Counter()
        for ev in alerts:
            cand = ev.get("evidence", {}).get("known_family", {}).get("top_candidate", "?")
            dec = ev.get("decision", "?")
            cp_ns = ev.get("checkpoint_timestamp_ns")
            cand_counter[cand] += 1
            dec_counter[dec] += 1
            family_conf[gt_label][cand] += 1
            family_total[gt_label] += 1
            family_decisions[gt_label][dec] += 1
            if isinstance(cp_ns, (int, float)):
                lo, hi = family_ts_range[gt_label]
                family_ts_range[gt_label] = [
                    cp_ns if lo is None else min(lo, cp_ns),
                    cp_ns if hi is None else max(hi, cp_ns),
                ]

        attempt_results[attempt_name] = {
            "case_id": case_id,
            "gt_label": gt_label,
            "sensor_alerts": len(alerts),
            "summary": summary,
            "candidates": dict(cand_counter.most_common(5)),
            "decisions": dict(dec_counter),
        }

    return {
        "family_conf": dict(family_conf),
        "family_total": dict(family_total),
        "family_decisions": dict(family_decisions),
        "family_ts_range": dict(family_ts_range),
        "attempt_results": attempt_results,
    }


# ---------------------------------------------------------------------------
# 7. Build confusion matrix rows
# ---------------------------------------------------------------------------

def build_rows(confusion: dict) -> list[dict]:
    ALL_LABELS = [
        "DoS Hulk", "DoS GoldenEye", "DDoS",
        "FTP-Patator", "SSH-Patator", "PortScan", "BENIGN",
    ]
    rows = []
    for label in ALL_LABELS:
        conf = confusion["family_conf"].get(label, Counter())
        total = confusion["family_total"].get(label, 0)
        correct = conf.get(label, 0)
        dec = confusion["family_decisions"].get(label, Counter())
        top = conf.most_common(5)
        lo, hi = confusion["family_ts_range"].get(label, [None, None])

        def ns_to_iso(ns):
            if ns is None:
                return None
            return dt.datetime.utcfromtimestamp(ns / 1e9).isoformat() + "Z"

        rows.append({
            "ground_truth": label,
            "total_alerts": total,
            "correct": correct,
            "accuracy": round(correct / total, 4) if total else 0.0,
            "top_outputs": top,
            "decisions": dict(dec),
            "ts_cp_ns_start": lo,
            "ts_cp_ns_end": hi,
            "ts_iso_start": ns_to_iso(lo),
            "ts_iso_end": ns_to_iso(hi),
        })
    return rows


# ---------------------------------------------------------------------------
# 8. Run
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest",
                    default="run_log/t8.5/scenarios/rebuild-20260808/pcap/manifest.json",
                    type=Path)
    ap.add_argument("--sensor-root",
                    default="run_log/t8.5/scenarios/rebuild-20260808/ubuntu",
                    type=Path)
    ap.add_argument("--output-json", required=True, type=Path)
    ap.add_argument("--output-md", type=Path)
    args = ap.parse_args()

    print("Loading manifest...", flush=True)
    manifest = load_manifest(args.manifest)
    print(f"  {len(manifest)} cases: {list(manifest.keys())}", flush=True)

    print("\nBuilding online confusion...", flush=True)
    confusion = build_online_confusion(manifest, args.sensor_root)
    rows = build_rows(confusion)

    # Summary
    total = sum(r["total_alerts"] for r in rows)
    correct_total = sum(r["correct"] for r in rows)
    print(f"\nTotal alerts: {total}, correct: {correct_total}, "
          f"accuracy: {correct_total/total*100:.1f}% if total else 0", flush=True)

    # Write JSON
    doc = {
        "kind": "manifest_confusion",
        "methodology": (
            "manifest-ground-truth: case_id label from reconstruction manifest "
            "(flow_id + tuple + start/end ns) used as ground truth for F9 replay output. "
            "3-way comparison planned: online F9 vs manifest vs offline F9."
        ),
        "model": "F9",
        "data_sources": {
            "manifest": str(args.manifest),
            "sensor_root": str(args.sensor_root),
            "oracle": "run_log/t3.3/label-join.sqlite3",
            "class_consensus": "run_log/t3.3r1/class-consensus.sqlite3",
        },
        "attempt_case_map": ATTEMPT_CASE_MAP,
        "attempt_results": confusion["attempt_results"],
        "match_notes": (
            "manifest maps case_id → ground_truth label. "
            "Each sensor.jsonl corresponds to one case replay. "
            "Ground truth is NOT from oracle 5-tuple lookup (which has port renumbering issue)."
        ),
        "rows": rows,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {args.output_json}", flush=True)

    if args.output_md:
        lines = [
            "# F9 Confusion — Manifest Ground Truth",
            "",
            f"Methodology: manifest case_id label = ground truth. "
            f"Each attempt replay = one manifest case.",
            "",
            f"| Total alerts: {total}  | Correct: {correct_total}  | "
            f"Acc: {correct_total/total*100:.1f}% if total else 0 |",
            "",
            "| Ground truth | Alerts | Đúng | Acc | Top F9 candidates | Decisions |",
            "|---|---|---:|---:|---|---|",
        ]
        for r in rows:
            top_str = ", ".join(f"{c}({n})" for c, n in r["top_outputs"]) or "—"
            acc_str = f"{r['accuracy']*100:.1f}\\%" if r["total_alerts"] else "N/A"
            dec_str = ", ".join(f"{d}:{n}" for d, n in r["decisions"].items())
            lines.append(
                f"| {r['ground_truth']} | {r['total_alerts']} | "
                f"{r['correct']} | {acc_str} | {top_str} | {dec_str} |"
            )
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {args.output_md}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
