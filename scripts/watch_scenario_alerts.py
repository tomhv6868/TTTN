#!/usr/bin/env python3
"""Tail every per-family sensor.jsonl in a T8.5 scenario run into the dashboard stream.

bridge_sensor_to_dashboard.py --follow only tails one file; a scenario replay
writes a fresh sensor.jsonl per family as it goes. This watcher polls the whole
ubuntu/f9-*/ tree, remembers how far it has read in each file, and appends any
new nids_alert with ts=now so the dashboard shows the burst while the replay is
still running. Read-only on the sensor logs.
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from bridge_sensor_to_dashboard import convert  # noqa: E402


class SingleInstanceLock:
    '''Hold a non-blocking one-byte lock for the watcher lifetime.'''

    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open('a+b')
        if self.handle.seek(0, os.SEEK_END) == 0:
            self.handle.write(b'X')
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            raise

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def dedupe_key(event: dict, attempt: str) -> tuple | None:
    if event.get('event_type') != 'nids_alert':
        return None
    flow = event.get('flow', {})
    source = flow.get('source', {})
    destination = flow.get('destination', {})
    candidate = event.get('evidence', {}).get('known_family', {}).get('top_candidate')
    return (
        attempt,
        source.get('ip'), source.get('port'),
        destination.get('ip'), destination.get('port'),
        flow.get('protocol'), candidate, event.get('decision'),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", default="20260808-194942")
    ap.add_argument("--poll-seconds", type=float, default=2.0)
    ap.add_argument("--idle-exit-seconds", type=float, default=900.0)
    ap.add_argument("--output", type=Path,
                    help="dashboard stream to append to; defaults to the "
                         "full-flow-v1 live stream the rest of the pipeline uses")
    ap.add_argument("--archive", type=Path,
                    help="second copy of the same rows, kept per replay run")
    ap.add_argument("--pass-label", default="",
                    help="which replay pass this is, e.g. r8; it names the "
                         "archive and is carried on every row so the dashboard "
                         "shows which pass an alert came from")
    ap.add_argument('--lock-file', type=Path,
                    help='single-instance lock; defaults beside --output')
    args = ap.parse_args()

    # Raw sensor receipts stay under run_log/t8.5 because the lab scripts write
    # there; the derived stream belongs with the rest of the pipeline in
    # run_log/full-flow-v1, which is what the dashboard reads.
    scenario = ROOT / "run_log/t8.5/scenarios" / args.run_id
    output = args.output or (ROOT / "run_log/full-flow-v1/live-detection-f9.jsonl")
    archive = args.archive or (
        ROOT / "run_log/full-flow-v1/replay-runs" / args.run_id /
        (f"f9-{args.pass_label}.jsonl" if args.pass_label else "f9.jsonl"))
    output.parent.mkdir(parents=True, exist_ok=True)
    archive.parent.mkdir(parents=True, exist_ok=True)
    lock = SingleInstanceLock(
        args.lock_file or output.with_name(output.name + '.watch.lock')
    )
    try:
        lock.acquire()
    except OSError:
        print(f'error: another watcher already holds {lock.path}', file=sys.stderr)
        return 3
    atexit.register(lock.release)

    offsets: dict[Path, int] = {}
    # Files that already exist at startup are historical: record their length so
    # only alerts produced from now on are streamed as live.
    for path in sorted(scenario.glob("ubuntu/f9-*/sensor.jsonl")):
        offsets[path] = path.stat().st_size

    last_new = time.monotonic()
    seen: set[tuple] = set()
    print(f"watching {scenario}/ubuntu/f9-*/sensor.jsonl -> {output}", flush=True)
    while time.monotonic() - last_new < args.idle_exit_seconds:
        for path in sorted(scenario.glob("ubuntu/f9-*/sensor.jsonl")):
            start = offsets.get(path, 0)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= start:
                continue
            attempt = path.parent.name.removeprefix("f9-")
            # Strip the -rN retry suffix so a family keeps one name on the
            # dashboard no matter which pass produced the alert; the pass itself
            # is carried separately.
            family = re.sub(r"-r\d+(t\d+)?$", "", attempt)
            written = 0
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(start)
                chunk = handle.read()
                offsets[path] = start + len(chunk.encode("utf-8"))
                with output.open("a", encoding="utf-8") as sink, \
                        archive.open("a", encoding="utf-8") as run_sink:
                    for line in chunk.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        key = dedupe_key(event, attempt)
                        if key is not None and key in seen:
                            continue
                        if key is not None:
                            seen.add(key)
                        run_label = f"{args.run_id}/{args.pass_label}" \
                            if args.pass_label else args.run_id
                        row = convert(event, family, family, run_label)
                        if row is None:
                            continue
                        row["ts"] = time.time()
                        row["attempt"] = attempt
                        row["replay_pass"] = args.pass_label or None
                        encoded = json.dumps(row, ensure_ascii=False) + "\n"
                        sink.write(encoded)
                        run_sink.write(encoded)
                        written += 1
            if written:
                last_new = time.monotonic()
                print(f"  +{written} alert(s) from {family}", flush=True)
        time.sleep(args.poll_seconds)

    print("idle timeout reached, stopping watcher", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
