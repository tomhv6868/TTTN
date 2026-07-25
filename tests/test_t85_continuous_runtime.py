#!/usr/bin/env python3
"""Verify that the live DPDK runtime survives alerts and stops on SIGTERM."""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Sequence


def command(args: argparse.Namespace) -> list[str]:
    return [
        str(args.binary),
        "-l",
        "0",
        "--no-pci",
        "--no-huge",
        "--in-memory",
        "--no-telemetry",
        "--log-level=*:warning",
        "--file-prefix=nids_runtime_continuous_test",
        f"--vdev=net_pcap_continuous,rx_pcap={args.pcap}",
        "--",
        "--bundle",
        str(args.bundle),
        "--port-id",
        "0",
        "--max-packets",
        "0",
        "--min-packets",
        "0",
        "--min-f9",
        "0",
        "--min-alerts",
        "0",
        "--idle-timeout-ms",
        "0",
    ]


def run(args: argparse.Namespace) -> None:
    process = subprocess.Popen(
        command(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    output: list[str] = []
    errors: list[str] = []
    lines: queue.Queue[str] = queue.Queue()

    def read_stdout() -> None:
        for line in process.stdout:
            output.append(line)
            lines.put(line)

    def read_stderr() -> None:
        errors.extend(process.stderr)

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    ready = False
    alert = False
    deadline = time.monotonic() + 20.0
    try:
        while time.monotonic() < deadline and not (ready and alert):
            if process.poll() is not None:
                break
            try:
                line = lines.get(timeout=0.2)
            except queue.Empty:
                continue
            event = json.loads(line)
            ready |= event.get("event_type") == "nids_dpdk_live_ready"
            alert |= event.get("event_type") == "nids_alert"

        if not ready or not alert:
            raise RuntimeError(
                "runtime did not emit ready and alert before exit; "
                f"stdout={output!r}; stderr={errors!r}"
            )
        time.sleep(0.5)
        if process.poll() is not None:
            raise RuntimeError("continuous runtime exited after its first alert")

        process.terminate()
        process.wait(timeout=10.0)
        if process.returncode != 0:
            raise RuntimeError(
                f"runtime returned {process.returncode}; stderr={errors!r}"
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5.0)
        stdout_thread.join(timeout=2.0)
        stderr_thread.join(timeout=2.0)

    events = [json.loads(line) for line in output if line.strip()]
    ready_event = next(
        event
        for event in events
        if event.get("event_type") == "nids_dpdk_live_ready"
    )
    summary = next(
        event
        for event in events
        if event.get("event_type") == "nids_dpdk_live_summary"
    )
    if ready_event.get("continuous") is not True:
        raise RuntimeError(f"ready event is not continuous: {ready_event}")
    if ready_event.get("max_packets") != 0:
        raise RuntimeError(f"max_packets is not unlimited: {ready_event}")
    if ready_event.get("idle_timeout_ms") != 0:
        raise RuntimeError(f"idle timeout is not disabled: {ready_event}")
    if summary.get("continuous") is not True:
        raise RuntimeError(f"summary is not continuous: {summary}")
    if summary.get("stop_reason") != "signal":
        raise RuntimeError(f"runtime did not stop on signal: {summary}")
    if summary.get("alerts", 0) < 1:
        raise RuntimeError(f"runtime emitted no alert: {summary}")


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--pcap", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        run(args)
        print("continuous runtime lifecycle: passed")
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"continuous runtime lifecycle: failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
