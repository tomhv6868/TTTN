#!/usr/bin/env python3
"""Bridge Terminal V1 decisions/alerts into the dashboard terminal stream."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


TERMINAL_EVENTS = {"nids_terminal_flow_decision", "nids_terminal_flow_alert"}


def convert(event: dict, run_label: str, replay_family: str) -> dict | None:
    event_type = event.get("event_type")
    if event_type not in TERMINAL_EVENTS:
        return None
    flow = event.get("flow", {})
    source = flow.get("source", {})
    destination = flow.get("destination", {})
    scores = event.get("scores", {})
    terminal_class = event.get("decision")
    if event_type == "nids_terminal_flow_decision":
        candidate = scores.get("top_attack_candidate", {}).get("class_name")
        attack_score = scores.get("attack_gate", {}).get("attack_score")
        confidence = scores.get("gated_decision", {}).get("class_confidence")
    else:
        candidate = event.get("decision")
        attack_score = scores.get("attack_score")
        confidence = scores.get("class_confidence")
    timestamp_ns = event.get("last_event_timestamp_ns")
    return {
        "model": "terminal",
        "decision": (
            "benign"
            if str(terminal_class).strip().casefold() == "benign"
            else "known_attack"
        ),
        "candidate": candidate,
        "terminal_class": terminal_class,
        "flow_rf_probability": round(attack_score, 6)
        if isinstance(attack_score, (int, float)) else None,
        "confidence": round(confidence, 6)
        if isinstance(confidence, (int, float)) else None,
        "source": f"{source.get('ip')}:{source.get('port')}",
        "destination": f"{destination.get('ip')}:{destination.get('port')}",
        "protocol": (flow.get("protocol") or "?").upper(),
        "run": run_label,
        "attempt": event.get("attempt_id"),
        "replay_family": replay_family,
        "packet_count": event.get("packet_count"),
        "close_reason": event.get("close_reason"),
        "acceptance_eligible": event.get("acceptance_eligible"),
        "source_event_type": event_type,
        "_timestamp_ns": timestamp_ns if isinstance(timestamp_ns, (int, float)) else None,
    }


def read_sensor(path: Path, run_label: str, replay_family: str) -> list[dict]:
    decisions: list[dict] = []
    alerts: list[dict] = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = convert(event, run_label, replay_family)
            if row is None:
                continue
            if event["event_type"] == "nids_terminal_flow_decision":
                decisions.append(row)
            else:
                alerts.append(row)
    # Diagnostic mode emits a decision and then an alert for each attack.
    # Prefer decisions to avoid duplicates. Alerts-only mode has no decisions.
    rows = decisions if decisions else alerts
    timestamps = [row["_timestamp_ns"] for row in rows if row["_timestamp_ns"] is not None]
    anchor = path.stat().st_mtime
    last = max(timestamps) if timestamps else None
    for ordinal, row in enumerate(rows):
        timestamp = row.pop("_timestamp_ns")
        row["ts"] = (
            anchor + (timestamp - last) / 1e9
            if timestamp is not None and last is not None
            else anchor - (len(rows) - ordinal) * 0.001
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor", action="append", required=True, type=Path)
    parser.add_argument("--run-label", action="append", default=[])
    parser.add_argument("--replay-family", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--append", action="store_true")
    args = parser.parse_args()

    rows = []
    for index, sensor in enumerate(args.sensor):
        label = args.run_label[index] if index < len(args.run_label) else sensor.parent.parent.name
        family = args.replay_family[index] if index < len(args.replay_family) else "portscan"
        rows.extend(read_sensor(sensor, label, family))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    with args.output.open(mode, encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"bridged {len(rows)} terminal rows -> {args.output} (mode={mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
