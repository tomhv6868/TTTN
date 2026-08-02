#!/usr/bin/env python3
"""Bridge an F9 nids_dpdk_live sensor.jsonl into the dashboard-flat live stream.

Reads all nids_alert events from one or more sensor.jsonl files, converts the
nested F9 alert schema to the flat dashboard schema
(model/decision/candidate/flow_rf_probability/confidence/source/destination/
protocol/run/ts), and writes them to the dashboard's live-detection-f9.jsonl.

Timestamps are spread just before "now" so the dashboard tail shows them as a
live burst. Read-only on the sensor logs.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def convert(event: dict, run_label: str, replay_family: str, replay_run: str) -> dict | None:
    if event.get("event_type") != "nids_alert":
        return None
    ev = event.get("evidence", {})
    kf = ev.get("known_family", {})
    frf = ev.get("flow_rf", {})
    fl = event.get("flow", {})
    src = fl.get("source", {})
    dst = fl.get("destination", {})
    prob = frf.get("attack_probability")
    conf = kf.get("confidence")
    return {
        "model": "F9",
        "decision": event.get("decision"),
        "candidate": kf.get("top_candidate"),
        "flow_rf_probability": round(prob, 6) if isinstance(prob, (int, float)) else None,
        "confidence": round(conf, 6) if isinstance(conf, (int, float)) else None,
        "source": f"{src.get('ip')}:{src.get('port')}",
        "destination": f"{dst.get('ip')}:{dst.get('port')}",
        "protocol": (fl.get("protocol") or "?").upper(),
        "run": run_label,
        "replay_family": replay_family,
        "replay_run": replay_run,
        "packet_count": event.get("packet_count"),
    }


def follow(args) -> int:
    """Tail one sensor.jsonl and append each new alert with ts=now, so the
    dashboard shows alerts jumping in live during the replay."""
    path = args.sensor[0]
    label = (args.run_label or [f"replay {path.parent.name} (F9)"])[0]
    attempt = path.parent.name
    family = attempt[3:] if attempt.startswith("f9-") else attempt
    replay_run = f"{attempt} @ {time.strftime('%Y-%m-%d %H:%M')}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pos = 0
    last_new = time.time()
    written = 0
    print(f"follow start: {path} -> {args.output}", flush=True)
    while time.time() - last_new < args.follow_seconds:
        if not path.is_file():
            time.sleep(0.5)
            continue
        with path.open("r", encoding="utf-8") as f:
            f.seek(pos)
            new_lines = f.readlines()
            pos = f.tell()
        batch = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            flat = convert(e, label, family, replay_run)
            if flat:
                flat["ts"] = time.time()
                batch.append(flat)
        if batch:
            with args.output.open("a", encoding="utf-8") as out:
                for r in batch:
                    out.write(json.dumps(r, ensure_ascii=False) + "\n")
            written += len(batch)
            last_new = time.time()
            print(f"  +{len(batch)} (total {written})", flush=True)
        time.sleep(1.0)
    print(f"follow done: {written} alerts appended", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sensor", action="append", required=True, type=Path,
                    help="sensor.jsonl path (repeatable)")
    ap.add_argument("--run-label", action="append", default=None,
                    help="run label per --sensor (repeatable, aligned)")
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--append", action="store_true",
                    help="append to output instead of overwriting")
    ap.add_argument("--follow", action="store_true",
                    help="tail the first --sensor live, appending each new alert "
                         "with ts=now so the dashboard shows it in real time")
    ap.add_argument("--follow-seconds", type=float, default=300.0,
                    help="stop following after this long with no new data")
    args = ap.parse_args()

    if args.follow:
        return follow(args)

    labels = args.run_label or []
    rows = []
    for i, path in enumerate(args.sensor):
        label = labels[i] if i < len(labels) else f"replay {path.parent.name} (F9)"
        # family name derived from the attempt dir (f9-<family>) or label
        attempt = path.parent.name
        family = attempt[3:] if attempt.startswith("f9-") else attempt
        replay_run = f"{attempt} @ {time.strftime('%Y-%m-%d %H:%M', time.localtime(path.stat().st_mtime))}" if path.is_file() else attempt
        if not path.is_file():
            print(f"WARN missing sensor log: {path}", flush=True)
            continue
        # base wall-clock for this replay = sensor.jsonl mtime minus its span,
        # so alert ts reflect the real emission time (pacing preserved).
        mtime = path.stat().st_mtime
        per_sensor = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                flat = convert(e, label, family, replay_run)
                if flat:
                    cp = e.get("checkpoint_timestamp_ns")
                    flat["_cp_ns"] = cp if isinstance(cp, (int, float)) else None
                    per_sensor.append(flat)
        # assign real emission ts from monotonic checkpoint offsets, anchored so
        # the last alert lands at this sensor's mtime (end of replay).
        cps = [r["_cp_ns"] for r in per_sensor if r["_cp_ns"] is not None]
        if cps:
            last_cp = max(cps)
            for r in per_sensor:
                cp = r["_cp_ns"]
                r["ts"] = mtime + ((cp - last_cp) / 1e9 if cp is not None else 0.0)
                del r["_cp_ns"]
        else:
            for j, r in enumerate(per_sensor):
                r["ts"] = mtime - (len(per_sensor) - j) * 0.3
                r.pop("_cp_ns", None)
        rows.extend(per_sensor)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    with args.output.open(mode, encoding="utf-8") as out:
        for r in rows:
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"bridged {len(rows)} alerts -> {args.output} (mode={mode})", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
