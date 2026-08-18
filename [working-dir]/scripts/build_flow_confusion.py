#!/usr/bin/env python3
"""
Offline-online per-flow confusion matrix for F9 replay vs CICIDS ground truth.

Methodology (user-validated):
  Online alert  →  5-tuple + timestamp proximity  →  offline flow_id
  flow_id  →  candidate_edge  →  label_row  →  assigned_class (CICIDS ground truth)
  Compare: F9 candidate vs assigned_class

Key fix vs v1 (DEMO):
  - Loads ALL captures (not just monday-working-hours)
  - Uses direction-insensitive 5-tuple matching with timestamp proximity
    (same 5-tuple appears across different captures at different times)
  - Correct CAPTURE_MAP from flow_assignment analysis:
      DoS Hulk        → wednesday-working-hours
      DoS GoldenEye    → wednesday-working-hours
      DDoS            → friday-working-hours
      FTP-Patator     → tuesday-working-hours
      SSH-Patator     → tuesday-working-hours
      PortScan        → friday-working-hours
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

PROTO_NUM = {"TCP": 6, "UDP": 17}


# ---------------------------------------------------------------------------
# Capture mapping: family → (capture_id, ground_truth_label)
# Derived from flow_assignment analysis: each attack family lives in one capture
# ---------------------------------------------------------------------------
CAPTURE_MAP = {
    # attempt_dir prefix → (capture_id, CICIDS label)
    "fh-hulk":       ("wednesday-working-hours", "DoS Hulk"),
    "dos-hulk":      ("wednesday-working-hours", "DoS Hulk"),
    "dos-goldeneye": ("wednesday-working-hours", "DoS GoldenEye"),
    "ddos":          ("friday-working-hours",   "DDoS"),
    "portscan":      ("friday-working-hours",   "PortScan"),
    "ftp-patator":   ("tuesday-working-hours",  "FTP-Patator"),
    "ssh-patator":   ("tuesday-working-hours",  "SSH-Patator"),
}


# ---------------------------------------------------------------------------
# 1. Build offline oracle indexed by (capture_id, 5-tuple_key) → flows
# ---------------------------------------------------------------------------

def tuple_key(lip: int, lpt: int, hip: int, hpt: int, proto: int):
    """Direction-insensitive 5-tuple key matching YOUR parser's convention."""
    a, b = (lip, lpt), (hip, hpt)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], proto)


def load_oracle(label_join_db: Path, class_consensus_db: Path,
                captures: list[str] | None = None):
    """
    Load oracle: (capture_id, tuple_key) → sorted list of (flow_id, assigned_class, creation_ts_ns)
    filtered to specific captures. Sorted by creation_ts_ns ascending.
    """
    lj = sqlite3.connect(f"file:{label_join_db}?mode=ro", uri=True)
    cc = sqlite3.connect(f"file:{class_consensus_db}?mode=ro", uri=True)

    try:
        # Load flow_assignment: flow_id → assigned_class (all captures)
        assignment = {}
        for fid, cls in cc.execute(
                "SELECT flow_id, assigned_class FROM flow_assignment"):
            assignment[fid] = cls
    finally:
        cc.close()

    # Load flow table with optional capture filter
    where = ""
    params: tuple = ()
    if captures:
        placeholders = ",".join("?" * len(captures))
        where = f" WHERE f.capture_id IN ({placeholders})"
        params = tuple(captures)

    # Index: (capture_id, tuple_key) → list of (flow_id, assigned_class, creation_ts_ns)
    oracle: dict = defaultdict(list)

    rows = lj.execute(f"""
        SELECT f.flow_id, f.capture_id, f.protocol,
               f.low_ip, f.low_port, f.high_ip, f.high_port,
               f.creation_timestamp_ns
        FROM flow f
        {where}
    """, params)

    for (fid, cap, proto, lip, lpt, hip, hpt, cts) in rows:
        tk = tuple_key(lip, lpt, hip, hpt, proto)
        cls = assignment.get(fid)
        if cls is not None:
            oracle[(cap, tk)].append((fid, cls, cts))

    # Sort each list by creation_ts_ns so earliest flow is first
    for key in oracle:
        oracle[key].sort(key=lambda x: x[2])

    total_flows = sum(len(v) for v in oracle.values())
    print(f"  oracle: {len(oracle)} (cap,tuple) entries, {total_flows} flows with GT", flush=True)
    lj.close()
    return oracle


# ---------------------------------------------------------------------------
# 2. Compute sensor wall-clock offset from summary event + mtime
# ---------------------------------------------------------------------------

def compute_offset(sensor_path: Path):
    """
    Derive monotonic→wall-clock offset from the sensor's summary event + file mtime.

    The sensor emits:
      - checkpoint_timestamp_ns  (monotonic, from 0 at sensor init)
      - duration_ms               (wall-clock ms from start to stop)
      - active_duration_ns        (monotonic ns of actual packet processing)
    File mtime = wall-clock at sensor stop (when file was written).

    Algorithm:
      active_end_cp_ns  = last checkpoint_timestamp_ns from nids_alert
      sensor_stop_wall  = file_mtime
      sensor_start_wall = file_mtime - duration_ms/1000
      idle_before       = (duration_ms*1e6 - active_duration_ns) / 1e9  (seconds)
      first_alert_wall  = sensor_start_wall + idle_before
      offset_ns         = first_alert_wall_ns - first_alert_cp_ns
                          = (sensor_start_wall*1e9 + idle_before*1e9) - first_alert_cp_ns
    """
    mtime = sensor_path.stat().st_mtime

    # Read all lines once
    lines = sensor_path.read_text(encoding="utf-8").splitlines()

    # Find summary
    summary = None
    alerts = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") == "nids_dpdk_live_summary":
            summary = ev
        elif ev.get("event_type") == "nids_alert":
            alerts.append(ev)

    if summary is None or not alerts:
        return None

    dur_ms = summary["duration_ms"]
    active_ns = summary["active_duration_ns"]
    active_s = active_ns / 1e9

    # Idle time before first packet
    idle_before_s = (dur_ms * 1e6 - active_ns) / 1e9

    # First and last alert checkpoint_ns
    first_cp_ns = min(ev["checkpoint_timestamp_ns"] for ev in alerts
                      if isinstance(ev.get("checkpoint_timestamp_ns"), (int, float)))
    last_cp_ns = max(ev["checkpoint_timestamp_ns"] for ev in alerts
                     if isinstance(ev.get("checkpoint_timestamp_ns"), (int, float)))

    # Anchor: last alert's estimated wall-clock = sensor_stop_wall - idle_after
    idle_after_s = (dur_ms * 1e6 - active_ns) / 1e9 - idle_before_s
    # This should be ~0 if the sensor stops shortly after last alert
    # Actually, the sensor stays idle until idle_timeout fires
    # So: sensor_stop_wall ≈ last_alert_wall + idle_timeout
    # For simplicity: use sensor_stop_wall as approximation of last alert wall
    # (with small error = idle_after)

    # Better approach: derive offset from known timing
    # active_ns spans from first packet to last packet
    # active_end_cp_ns - active_start_cp_ns ≈ active_ns (within measurement error)
    # So: active_rate = active_ns / (last_cp_ns - first_cp_ns) ≈ 1.0
    # Then: first_alert_wall = sensor_start_wall + idle_before
    # offset = first_alert_wall*1e9 - first_cp_ns

    sensor_start_wall = mtime - (dur_ms / 1000.0)
    first_alert_wall = sensor_start_wall + idle_before_s

    offset_ns = (first_alert_wall * 1e9) - first_cp_ns

    return {
        "offset_ns": offset_ns,
        "first_cp_ns": first_cp_ns,
        "last_cp_ns": last_cp_ns,
        "first_alert_wall": first_alert_wall,
        "sensor_start_wall": sensor_start_wall,
        "idle_before_s": idle_before_s,
        "active_s": active_s,
        "dur_ms": dur_ms,
    }


# ---------------------------------------------------------------------------
# 3. Alert → tuple key
# ---------------------------------------------------------------------------

def alert_tuple_key(ev: dict):
    """Build (sip, spt, dip, dpt, proto) from a sensor alert's flow."""
    fl = ev.get("flow", {})
    src = fl.get("source", {})
    dst = fl.get("destination", {})
    try:
        sip = int(ipaddress.IPv4Address(src.get("ip", "")))
        dip = int(ipaddress.IPv4Address(dst.get("ip", "")))
    except (ValueError, ipaddress.AddressValueError):
        return None
    proto = PROTO_NUM.get((fl.get("protocol") or "").upper())
    if proto is None:
        return None
    spt = int(src.get("port", 0))
    dpt = int(dst.get("port", 0))
    # Direction-insensitive key
    return tuple_key(sip, spt, dip, dpt, proto)


# ---------------------------------------------------------------------------
# 4. Map attempt → (capture_id, gt_label)
# ---------------------------------------------------------------------------

def resolve_attempt(attempt_name: str):
    """Map attempt dir name to (capture_id, ground_truth_label)."""
    key = attempt_name[3:] if attempt_name.startswith("f9-") else attempt_name
    result = CAPTURE_MAP.get(key)
    if result is None:
        return None, None
    return result


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------

def run(args) -> int:
    label_join_db = Path(args.label_join_db)
    class_consensus_db = Path(args.class_consensus_db)
    sensor_root = Path(args.sensor_root)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md) if args.output_md else None

    # Determine which captures to load
    all_caps = list({v[0] for v in CAPTURE_MAP.values()})
    print(f"Loading oracle for captures: {all_caps}", flush=True)
    oracle = load_oracle(label_join_db, class_consensus_db, all_caps)

    # Process sensor logs
    attempts = sorted(
        (d for d in sensor_root.iterdir() if d.is_dir() and d.name != "confusion"),
        key=lambda p: p.name
    )
    if args.attempts:
        attempts = [sensor_root / a for a in args.attempts
                    if (sensor_root / a).is_dir()]

    family_conf = defaultdict(Counter)
    family_ts_cp = defaultdict(lambda: [None, None])
    family_total = defaultdict(int)
    match_stats = {"matched": 0, "no_tuple": 0, "no_gt": 0, "ts_miss": 0}

    for attempt_dir in attempts:
        sensor_path = attempt_dir / "sensor.jsonl"
        if not sensor_path.exists():
            continue

        attempt_name = attempt_dir.name
        capture_id, gt_label = resolve_attempt(attempt_name)
        if gt_label is None:
            print(f"  SKIP {attempt_name}: unknown family mapping", flush=True)
            continue

        print(f"\n{attempt_name}: gt={gt_label}, capture={capture_id}", flush=True)

        # Compute offset
        offset_info = compute_offset(sensor_path)
        if offset_info:
            offset_ns = offset_info["offset_ns"]
            print(f"  offset={offset_ns/1e9:.3f}s, "
                  f"active={offset_info['active_s']:.1f}s, "
                  f"idle_before={offset_info['idle_before_s']:.1f}s", flush=True)
        else:
            offset_ns = None
            print(f"  WARNING: could not compute offset", flush=True)

        # Build per-capture oracle index
        # (capture_id, tuple_key) → list of (flow_id, cls, creation_ts)
        cap_key = (capture_id,)
        cap_oracle = {
            tk: entries
            for (cap, tk), entries in oracle.items()
            if cap == capture_id
        }

        local = {"matched": 0, "no_tuple": 0, "no_gt": 0, "ts_miss": 0}

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

                tk = alert_tuple_key(ev)
                if tk is None:
                    continue

                cp_ns = ev.get("checkpoint_timestamp_ns")
                if not isinstance(cp_ns, (int, float)):
                    continue

                # Convert monotonic checkpoint_ns → estimated wall-clock ns
                if offset_ns is not None:
                    est_wall_ns = cp_ns + offset_ns
                else:
                    est_wall_ns = None

                entries = cap_oracle.get(tk, [])
                best = None
                if entries and est_wall_ns is not None:
                    # Find flow whose creation_ts is closest to estimated wall-clock
                    best = min(entries, key=lambda e: abs(e[2] - est_wall_ns))
                    # Tolerance: 30 seconds
                    if abs(best[2] - est_wall_ns) > 30_000_000_000:
                        local["ts_miss"] += 1
                        best = None
                elif entries:
                    # Fallback: first flow (earliest timestamp)
                    best = entries[0]
                    local["ts_miss"] += 1

                if best is None:
                    local["no_tuple"] += 1
                    continue

                fid, gt_cls, _ = best
                family_conf[gt_cls][ev["evidence"]["known_family"]["top_candidate"]] += 1
                family_total[gt_cls] += 1

                # Track checkpoint ns range
                lo, hi = family_ts_cp[gt_cls]
                family_ts_cp[gt_cls] = [
                    cp_ns if lo is None else min(lo, cp_ns),
                    cp_ns if hi is None else max(hi, cp_ns),
                ]

                local["matched"] += 1

        for k, v in local.items():
            match_stats[k] += v
        print(f"  matched={local['matched']}, ts_miss={local['ts_miss']}, "
              f"no_tuple={local['no_tuple']}", flush=True)

    # -------------------------------------------------------------------------
    # Build output
    # -------------------------------------------------------------------------
    ALL_CLASSES = [
        "DoS Hulk", "DoS GoldenEye", "DDoS", "FTP-Patator",
        "SSH-Patator", "PortScan", "BENIGN",
    ]

    def ns_to_iso(ns):
        if ns is None:
            return None
        return dt.datetime.utcfromtimestamp(ns / 1e9).isoformat() + "Z"

    rows = []
    for cls in ALL_CLASSES:
        conf = family_conf.get(cls, Counter())
        total = family_total.get(cls, 0)
        correct = conf.get(cls, 0)
        top = conf.most_common(5)
        lo, hi = family_ts_cp.get(cls, [None, None])
        rows.append({
            "ground_truth": cls,
            "total_alerts": total,
            "correct": correct,
            "accuracy": round(correct / total, 4) if total else 0.0,
            "top_outputs": top,
            "ts_cp_ns_start": lo,
            "ts_cp_ns_end": hi,
            "ts_iso_start": ns_to_iso(lo),
            "ts_iso_end": ns_to_iso(hi),
        })

    doc = {
        "kind": "flow_confusion",
        "methodology": (
            "offline-online-per-flow: online alert → 5-tuple+timestamp → "
            "offline flow_id → assigned_class (CICIDS class-consensus)"
        ),
        "model": "F9",
        "data_sources": {
            "oracle": str(label_join_db),
            "class_consensus": str(class_consensus_db),
            "sensor_root": str(sensor_root),
        },
        "capture_map": {k: v for k, v in CAPTURE_MAP.items()},
        "match_stats": match_stats,
        "rows": rows,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {output_json}", flush=True)

    if output_md:
        lines = [
            "# F9 Flow Confusion — Offline-Online Per-Flow",
            "",
            f"Methodology: online alert → 5-tuple+timestamp → offline flow_id → assigned_class",
            "",
            f"| Matched: {match_stats['matched']}  "
            f"| TS miss (no wall-clock): {match_stats['ts_miss']}  "
            f"| No tuple match: {match_stats['no_tuple']} |",
            "",
            "| Ground truth | Alerts | Đúng | Acc | Top outputs |",
            "|---|---|---:|---:|---|",
        ]
        for r in rows:
            top_str = ", ".join(f"{c}({n})" for c, n in r["top_outputs"]) or "—"
            acc = f"{r['accuracy']*100:.1f}\%" if r["total_alerts"] else "N/A"
            lines.append(
                f"| {r['ground_truth']} | {r['total_alerts']} | "
                f"{r['correct']} | {acc} | {top_str} |"
            )
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {output_md}", flush=True)

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--label-join-db",
                    default="run_log/t3.3/label-join.sqlite3", type=Path)
    ap.add_argument("--class-consensus-db",
                    default="run_log/t3.3r1/class-consensus.sqlite3", type=Path)
    ap.add_argument("--sensor-root",
                    default="run_log/t8.5/scenarios/rebuild-20260808/ubuntu",
                    type=Path)
    ap.add_argument("--attempts", action="append")
    ap.add_argument("--output-json", required=True, type=Path)
    ap.add_argument("--output-md", type=Path)
    return run(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
