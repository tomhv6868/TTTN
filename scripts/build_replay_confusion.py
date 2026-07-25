#!/usr/bin/env python3
"""Build a confusion-matrix evidence file from a bridged replay detection log.

Reads a dashboard-flat detection jsonl (each row has replay_family = the CICIDS
ground-truth family that was replayed, and candidate/decision = the model
output), computes the per-ground-truth confusion + accuracy, and writes a JSON
(and a readable markdown table) so the comparison is auditable, not just printed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

PROTO_NUM = {"TCP": 6, "UDP": 17}


def flow_key(sip: int, spt: int, dip: int, dpt: int, proto: int):
    a, b = (sip, spt), (dip, dpt)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], proto)


def load_oracle(db: Path) -> dict:
    """Map direction-insensitive 5-tuple -> CICIDS label from label_row."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    m = {}
    try:
        for sip, spt, dip, dpt, proto, label in con.execute(
            "SELECT source_ip, source_port, destination_ip, destination_port, protocol, label FROM label_row"
        ):
            try:
                k = flow_key(int(sip), int(spt), int(dip), int(dpt), int(proto))
            except (TypeError, ValueError):
                continue
            m[k] = label
    finally:
        con.close()
    return m


def alert_key(ev: dict):
    try:
        s_ip, s_pt = ev.get("source", "").rsplit(":", 1)
        d_ip, d_pt = ev.get("destination", "").rsplit(":", 1)
        sip = int(ipaddress.IPv4Address(s_ip))
        dip = int(ipaddress.IPv4Address(d_ip))
        proto = PROTO_NUM.get((ev.get("protocol") or "").upper())
        if proto is None:
            return None
        return flow_key(sip, int(s_pt), dip, int(d_pt), proto)
    except (ValueError, ipaddress.AddressValueError):
        return None

# attempt-dir slug -> CICIDS ground-truth label
GROUND_TRUTH = {
    "fh-hulk": "DoS Hulk",
    "dos-hulk": "DoS Hulk",
    "dos-goldeneye": "DoS GoldenEye",
    "ddos": "DDoS",
    "portscan": "PortScan",
    "ftp-patator": "FTP-Patator",
    "ssh-patator": "SSH-Patator",
}
ORDER = ["DoS Hulk", "DoS GoldenEye", "DDoS", "FTP-Patator", "SSH-Patator", "PortScan"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detection", required=True, type=Path,
                    help="bridged detection jsonl (live-detection-f9.jsonl or archive)")
    ap.add_argument("--model", default="F9")
    ap.add_argument("--output-json", required=True, type=Path)
    ap.add_argument("--output-md", type=Path)
    ap.add_argument("--oracle-db", type=Path,
                    help="if set, ground truth per flow is looked up from this "
                         "label-join.sqlite3 by 5-tuple (per-flow, strict)")
    args = ap.parse_args()

    oracle = load_oracle(args.oracle_db) if args.oracle_db else None
    per_flow_stats = {"matched": 0, "unlabeled": 0} if oracle is not None else None

    conf = defaultdict(Counter)
    ts_range = defaultdict(lambda: [None, None])
    for line in args.detection.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if oracle is not None:
            k = alert_key(e)
            lbl = oracle.get(k) if k else None
            if lbl is None:
                per_flow_stats["unlabeled"] += 1
                gt = "(unlabeled/ambient)"
            else:
                per_flow_stats["matched"] += 1
                gt = lbl
        else:
            gt = GROUND_TRUTH.get(e.get("replay_family"), e.get("replay_family") or "?")
        out = e.get("candidate") or e.get("decision") or "?"
        conf[gt][out] += 1
        t = e.get("ts")
        if isinstance(t, (int, float)):
            lo, hi = ts_range[gt]
            ts_range[gt] = [t if lo is None else min(lo, t),
                            t if hi is None else max(hi, t)]

    families = [f for f in ORDER if f in conf] + [f for f in conf if f not in ORDER]
    rows = []
    for gt in families:
        total = sum(conf[gt].values())
        correct = conf[gt].get(gt, 0)
        lo, hi = ts_range[gt]
        rows.append({
            "ground_truth": gt,
            "total_alerts": total,
            "correct": correct,
            "accuracy": round(correct / total, 4) if total else 0.0,
            "top_outputs": conf[gt].most_common(5),
            "ts_start": dt.datetime.fromtimestamp(lo).isoformat() if lo else None,
            "ts_end": dt.datetime.fromtimestamp(hi).isoformat() if hi else None,
        })
    # families with zero alerts (e.g. PortScan) — record explicitly
    for gt in ORDER:
        if gt not in conf:
            rows.append({
                "ground_truth": gt, "total_alerts": 0, "correct": 0,
                "accuracy": 0.0, "top_outputs": [],
                "note": "0 alert (flow shorter than checkpoint requirement)",
                "ts_start": None, "ts_end": None,
            })

    doc = {
        "kind": "replay_confusion",
        "model": args.model,
        "source": str(args.detection),
        "generated_at_utc": dt.datetime.utcnow().isoformat() + "Z",
        "ground_truth_mode": "per_flow_oracle_5tuple" if oracle is not None else "per_replay_family",
        "ground_truth_source": "run_log/t3.3/label-join.sqlite3 (CICIDS2017 labels)",
        "per_flow_stats": per_flow_stats,
        "rows": rows,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.output_md:
        lines = [f"# Confusion — {args.model} replay vs CICIDS ground truth", "",
                 f"Source: `{args.detection}`  ", f"Generated: {doc['generated_at_utc']}", "",
                 "| Ground truth | Alert | Đúng | Acc | Nhầm nhiều nhất | ts |",
                 "|---|---:|---:|---:|---|---|"]
        for r in rows:
            top = r["top_outputs"]
            misp = ", ".join(f"{c} ({n})" for c, n in top if c != r["ground_truth"])[:60] or "—"
            tsr = ""
            if r["ts_start"]:
                tsr = f"{r['ts_start'][11:19]}–{r['ts_end'][11:19]}"
            lines.append(f"| {r['ground_truth']} | {r['total_alerts']} | {r['correct']} | "
                         f"{r['accuracy']*100:.1f}% | {misp} | {tsr} |")
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {args.output_json}"
          + (f" + {args.output_md}" if args.output_md else ""), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
