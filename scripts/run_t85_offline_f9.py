#!/usr/bin/env python3
"""Run the offline F9 decision over the T8.5 scenario PCAPs and persist the result.

The offline half of the online-vs-offline comparison. Every case's raw stdout is
kept alongside the parsed decision so the numbers can be re-derived from the file
instead of from a console transcript.

Two things this deliberately does not assume:
  * nids_demo_replay exits 1 whenever its expect-records check disagrees, while
    still emitting a valid nids_alert on stdout, so the exit code is recorded but
    never used to decide success.
  * /mnt/hgfs is slow enough to time the run out, so each PCAP is copied to the
    Ubuntu local disk first.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABCTL = ROOT / "tools" / "labctl.py"
BUNDLE = "/home/wang/.cache/nids-partial-flow/t5.2/bundles/F9"
BINARY = "$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay"
REMOTE_ROOT = "/mnt/hgfs/TTTN"


def labctl(command: str, timeout_seconds: int = 120) -> dict:
    proc = subprocess.run(
        [sys.executable, str(LABCTL), "exec", "--timeout-seconds",
         str(timeout_seconds), "ubuntu", command],
        capture_output=True, text=True, timeout=timeout_seconds + 60,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "unparsed", "stdout": proc.stdout, "stderr": proc.stderr}


def run_case(run_id: str, case_id: str, remote_pcap: str) -> dict:
    local = f"/tmp/offline-{case_id}.pcap"
    labctl(f"cp {remote_pcap} {local}", 90)
    command = (
        f"source $HOME/.local/nids-toolchain/env.sh && "
        f"{BINARY} --input {local} --bundle {BUNDLE} "
        f"--max-records 1000 --expect-records 9 --expect-f9 1; "
        f"echo \"__EXIT__$?\""
    )
    result = labctl(command, 120)
    stdout = result.get("stdout", "") or ""

    exit_code = None
    alert = None
    summary = None
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("__EXIT__"):
            try:
                exit_code = int(line.removeprefix("__EXIT__"))
            except ValueError:
                pass
            continue
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "nids_alert" and alert is None:
            alert = event
        elif event.get("event_type") == "nids_replay_summary":
            summary = event

    record: dict = {
        "case_id": case_id,
        "remote_pcap": remote_pcap,
        "process_exit_code": exit_code,
        "raw_stdout": stdout,
        "raw_stderr": (result.get("stderr") or "")[:2000],
    }
    if summary is not None:
        record["replay_summary_status"] = summary.get("status")
        record["records_replayed"] = summary.get("records")
    if alert is None:
        record["status"] = "no_alert"
        return record
    known = alert.get("evidence", {}).get("known_family", {})
    record.update({
        "status": "ok",
        "decision": alert.get("decision"),
        "candidate": known.get("top_candidate"),
        "confidence": known.get("confidence"),
        "checkpoint": alert.get("checkpoint"),
        "flow": alert.get("flow"),
    })
    return record


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", default="20260808-194942")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    scenario = ROOT / "run_log/t8.5/scenarios" / args.run_id
    manifest = json.loads((scenario / "pcap/manifest.json").read_text(encoding="utf-8"))
    output = args.output or (
        ROOT / "run_log/full-flow-v1/replay-runs" / args.run_id / "offline-f9-results.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for index, item in enumerate(manifest["outputs"], start=1):
        case_id = item["case_id"]
        remote = f"{REMOTE_ROOT}/{item['path'].replace(chr(92), '/')}"
        print(f"[{index}/{len(manifest['outputs'])}] {case_id}", flush=True)
        row = run_case(args.run_id, case_id, remote)
        row["ground_truth"] = item["label"]
        row["correct"] = (row.get("candidate") == item["label"])
        rows.append(row)
        print(f"    {row['status']} -> {row.get('candidate')} "
              f"(exit={row.get('process_exit_code')})", flush=True)

    decided = [r for r in rows if r["status"] == "ok"]
    document = {
        "kind": "offline_f9_results",
        "run_id": args.run_id,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "ground_truth_source": "run_log/t8.5/scenarios/%s/pcap/manifest.json" % args.run_id,
        "cases_total": len(rows),
        "cases_with_alert": len(decided),
        "cases_correct": sum(1 for r in decided if r["correct"]),
        "rows": rows,
    }
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {output}", flush=True)
    print(f"alerts {document['cases_with_alert']}/{document['cases_total']}, "
          f"correct {document['cases_correct']}/{document['cases_with_alert']}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
