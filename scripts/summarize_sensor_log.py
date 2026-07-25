#!/usr/bin/env python3
"""Print one JSON line summarising a nids_dpdk_live sensor.jsonl.

Runs on the sensor host so the orchestrator never has to guess: packets_seen
separates a capture miss from a model miss, and both read very differently from
an alert count alone.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: summarize_sensor_log.py SENSOR_JSONL"}))
        return 2
    path = Path(sys.argv[1])
    summary = {
        "path": str(path),
        "exists": path.is_file(),
        "packets_seen": 0,
        "packets_parsed": 0,
        "parser_errors": 0,
        "alerts": 0,
        "ready": False,
        "stop_reason": None,
        "candidates": [],
    }
    if not summary["exists"]:
        print(json.dumps(summary))
        return 0

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = event.get("event_type")
            if kind == "nids_dpdk_live_ready":
                summary["ready"] = True
            elif kind == "nids_dpdk_live_summary":
                summary["packets_seen"] = event.get("packets_seen", 0)
                summary["packets_parsed"] = event.get("packets_parsed", 0)
                summary["parser_errors"] = event.get("parser_errors", 0)
                summary["stop_reason"] = event.get("stop_reason")
            elif kind == "nids_alert":
                summary["alerts"] += 1
                known = event.get("evidence", {}).get("known_family", {})
                summary["candidates"].append({
                    "top_candidate": known.get("top_candidate"),
                    "confidence": known.get("confidence"),
                    "decision": event.get("decision"),
                })

    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
