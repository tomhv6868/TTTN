#!/usr/bin/env python3
"""
3-way confusion matrix: Online F9 vs Offline F9 vs Manifest Ground Truth.

Data sources:
  Online:   run_log/t8.5/scenarios/rebuild-20260808/ubuntu/<attempt>/sensor.jsonl
  Offline:  nids_demo_replay on cut PCAPs (9-packet F9 prefix, original CICIDS timestamps)
  GT:       manifest case_id label (from reconstruction)
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Offline F9 results from nids_demo_replay batch run
# Extracted from background task bdplt9hnu output
# ---------------------------------------------------------------------------

OFFLINE_RESULTS = {
    "ftp-patator":         {"decision": "known_attack", "candidate": "FTP-Patator", "confidence": 0.99999916553497314},
    "ssh-patator":         {"decision": "known_attack", "candidate": "SSH-Patator", "confidence": 0.99999916553497314},
    "bot":                 {"decision": "known_attack", "candidate": "Bot",           "confidence": 0.99999916553497314},
    "ddos":               {"decision": "known_attack", "candidate": "DDoS",          "confidence": 0.9966658353805542},
    "dos-goldeneye":      {"decision": "known_attack", "candidate": "DoS GoldenEye","confidence": 0.99999916553497314},
    "dos-hulk":           {"decision": "known_attack", "candidate": "DoS Hulk",      "confidence": 0.99999916553497314},
    "dos-slowhttptest":   None,   # no output (slow HTTP - partial flow?)
    "dos-slowloris":      {"decision": "known_attack", "candidate": "DoS slowloris", "confidence": 0.99999916553497314},
    "infiltration":        {"decision": "known_attack", "candidate": "Infiltration",  "confidence": 0.74333274364471436},
    "portscan":           {"decision": "known_attack", "candidate": "PortScan",       "confidence": 0.99999916553497314},
    "web-brute-force":    {"decision": "known_attack", "candidate": "Web Attack – Brute Force", "confidence": 0.92666590213775635},
    "web-sql-injection":  {"decision": "known_attack", "candidate": "Web Attack – Sql Injection","confidence": 0.59666621685028076},
    "web-xss":            {"decision": "known_attack", "candidate": "Web Attack – XSS",          "confidence": 0.66666615009307861},
    "heartbleed":         None,   # no model
}


# ---------------------------------------------------------------------------
# Attempt → case_id mapping
# ---------------------------------------------------------------------------

ATTEMPT_CASE = {
    "f9-ftp-patator":   "ftp-patator",
    "f9-ssh-patator":   "ssh-patator",
    "f9-dos-goldeneye": "dos-goldeneye",
    "f9-ddos":         "ddos",
    "f9-portscan":     "portscan",
    "fh-hulk":         "dos-hulk",
}


# ---------------------------------------------------------------------------
# Manifest ground truth
# ---------------------------------------------------------------------------

GT_LABELS = {
    "bot":                 "Bot",
    "ddos":               "DDoS",
    "dos-goldeneye":      "DoS GoldenEye",
    "dos-hulk":           "DoS Hulk",
    "dos-slowhttptest":   "DoS Slowhttptest",
    "dos-slowloris":      "DoS slowloris",
    "ftp-patator":        "FTP-Patator",
    "heartbleed":         "Heartbleed",
    "infiltration":        "Infiltration",
    "portscan":           "PortScan",
    "ssh-patator":        "SSH-Patator",
    "web-brute-force":    "Web Attack – Brute Force",
    "web-sql-injection":  "Web Attack – Sql Injection",
    "web-xss":            "Web Attack – XSS",
}


# ---------------------------------------------------------------------------
# Load online results
# ---------------------------------------------------------------------------

def load_online(case_id: str, sensor_root: Path) -> dict:
    """Load aggregated online F9 results for a case."""
    attempt = next((k for k, v in ATTEMPT_CASE.items() if v == case_id), None)
    if not attempt:
        return None
    sp = sensor_root / attempt / "sensor.jsonl"
    if not sp.exists():
        return None

    alerts = []
    with sp.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "nids_alert":
                alerts.append(ev)

    if not alerts:
        return None

    candidates = Counter(
        e.get("evidence", {}).get("known_family", {}).get("top_candidate", "?")
        for e in alerts
    )
    decisions = Counter(e.get("decision", "?") for e in alerts)
    return {
        "count": len(alerts),
        "candidates": candidates,
        "decisions": decisions,
        "top_candidate": candidates.most_common(1)[0][0] if candidates else None,
    }


# ---------------------------------------------------------------------------
# Build 3-way table
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sensor-root",
                    default="run_log/t8.5/scenarios/rebuild-20260808/ubuntu",
                    type=Path)
    ap.add_argument("--output-json",
                    default="run_log/t8.5/scenarios/rebuild-20260808/confusion/f9-3way-confusion.json",
                    type=Path)
    ap.add_argument("--output-md",
                    default="run_log/t8.5/scenarios/rebuild-20260808/confusion/f9-3way-confusion.md",
                    type=Path)
    args = ap.parse_args()

    sensor_root = Path(args.sensor_root)

    rows = []
    online_correct = 0
    online_total = 0
    offline_correct = 0
    offline_total = 0

    for case_id, gt in sorted(GT_LABELS.items()):
        offline = OFFLINE_RESULTS.get(case_id)
        online = load_online(case_id, sensor_root)

        # Online
        if online:
            on_cand = online["top_candidate"]
            on_correct = (on_cand == gt)
            on_acc = online["candidates"].get(gt, 0) / online["count"]
            online_correct += online["candidates"].get(gt, 0)
            online_total += online["count"]
            on_top5 = online["candidates"].most_common(5)
        else:
            on_cand = "N/A"
            on_correct = None
            on_acc = None
            on_top5 = []

        # Offline
        if offline:
            off_cand = offline["candidate"]
            off_correct = (off_cand == gt)
            off_conf = offline["confidence"]
            offline_correct += 1 if off_correct else 0
            offline_total += 1
        else:
            off_cand = "N/A"
            off_correct = None
            off_conf = None

        # Note on discrepancies
        if online and offline and on_cand != "N/A" and off_cand != "N/A" and on_cand != off_cand:
            note = f"ONLINE={on_cand} vs OFFLINE={off_cand} vs GT={gt}"
        elif on_correct is False and off_correct is True:
            note = f"Offline OK, online misclassifies as {on_cand}"
        elif on_correct is None and off_correct is False:
            note = f"Offline misclassified as {off_cand}"
        else:
            note = ""

        rows.append({
            "case_id": case_id,
            "gt": gt,
            "online": {
                "count": online["count"] if online else 0,
                "top_candidate": on_cand,
                "correct": on_correct,
                "accuracy": on_acc,
                "top5": on_top5,
            },
            "offline": {
                "candidate": off_cand,
                "correct": off_correct,
                "confidence": off_conf,
            },
            "note": note,
        })

    # Summary
    overall_online_acc = round(online_correct / online_total, 4) if online_total else 0
    overall_offline_acc = round(offline_correct / offline_total, 4) if offline_total else 0

    doc = {
        "kind": "3way_confusion",
        "methodology": (
            "Online F9 = DPDK sensor running on live-replayed traffic. "
            "Offline F9 = nids_demo_replay on cut 9-packet PCAP from original CICIDS capture "
            "(with original unix_epoch timestamps). "
            "GT = manifest case label from reconstruction."
        ),
        "model": "F9 (partial-flow)",
        "online_total": online_total,
        "online_correct": online_correct,
        "online_accuracy": overall_online_acc,
        "offline_total": offline_total,
        "offline_correct": offline_correct,
        "offline_accuracy": overall_offline_acc,
        "rows": rows,
    }

    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"wrote {args.output_json}", flush=True)

    # Markdown
    lines = [
        "# F9 3-Way Confusion: Online vs Offline vs Ground Truth",
        "",
        f"**Online:** {online_correct}/{online_total} correct = {overall_online_acc*100:.1f}%",
        f"**Offline:** {offline_correct}/{offline_total} correct = {overall_offline_acc*100:.1f}%",
        "",
        "| Case | GT | Online (top→acc) | Online Acc | Offline | ✓? | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        on_acc_str = f"{r['online']['accuracy']*100:.0f}%" if r['online']['accuracy'] is not None else "N/A"
        on_top = r['online']['top_candidate'] if r['online']['count'] else "—"
        on_cnt = r['online']['count'] or "—"
        off_cand = r['offline']['candidate']
        off_ok = "✓" if r['offline']['correct'] else ("✗" if r['offline']['correct'] is False else "—")
        note = r['note'][:50] if r['note'] else ""
        lines.append(
            f"| {r['case_id']} | {r['gt']} | {on_top} ({on_cnt}) | {on_acc_str} | "
            f"{off_cand} | {off_ok} | {note} |"
        )

    Path(args.output_md).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.output_md}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
