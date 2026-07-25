#!/usr/bin/env python3
"""Replay the accepted nine-frame F9 attack fixture from the Kali data NIC."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_t85_live_pcap import (  # noqa: E402
    EXPECTED_INPUT_SHA256,
    EXPECTED_RECORDS,
    parse_pcap,
    sha256_bytes,
)


DEFAULT_INPUT = PROJECT_ROOT / "run_log/t3.2/attack-tcp-f9.pcap"
DEFAULT_RECEIPT_ROOT = PROJECT_ROOT / "run_log/t8.5/live-demo"
ETHERNET_HEADER_BYTES = 14
VLAN_HEADER_ALLOWANCE_BYTES = 4


@dataclass(frozen=True)
class SendResult:
    records: int
    bytes: int
    duration_seconds: float
    observed_offsets_ns: tuple[int, ...]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def request_interrupt(signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt(f"received signal {signum}")


def parse_mac(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value.replace(":", ""))
    except ValueError as error:
        raise ValueError(f"invalid MAC address: {value}") from error
    if len(raw) != 6 or raw[0] & 1:
        raise ValueError(f"MAC address must be a unicast address: {value}")
    return raw


def run_checked(arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"command failed to start: {' '.join(arguments)}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise RuntimeError(
            f"command failed ({' '.join(arguments)}): {detail}"
        )
    return result.stdout


def interface_facts(name: str) -> dict[str, Any]:
    base = Path("/sys/class/net") / name
    if not base.is_dir():
        raise ValueError(f"interface does not exist: {name}")
    links = json.loads(run_checked(("ip", "-json", "link", "show", "dev", name)))
    if len(links) != 1:
        raise RuntimeError(f"expected one link record for {name}, observed {len(links)}")
    routes = json.loads(run_checked(("ip", "-json", "route", "show", "default")))
    driver_link = base / "device" / "driver"
    return {
        "name": name,
        "mac": (base / "address").read_text(encoding="ascii").strip().lower(),
        "driver": driver_link.resolve().name if driver_link.exists() else None,
        "has_default_route": any(route.get("dev") == name for route in routes),
        "mtu": int((base / "mtu").read_text(encoding="ascii").strip()),
        "up": "UP" in links[0].get("flags", []),
    }


def load_frames(
    input_path: Path,
    source_mac: str,
    destination_mac: str,
    mtu: int,
) -> tuple[list[bytes], list[int], int]:
    source = input_path.read_bytes()
    observed_hash = sha256_bytes(source)
    if observed_hash != EXPECTED_INPUT_SHA256:
        raise ValueError(
            "input is not the accepted T3.2 attack fixture: "
            f"observed SHA-256 {observed_hash}"
        )
    pcap_format, _, records = parse_pcap(source)
    if len(records) != EXPECTED_RECORDS:
        raise ValueError(f"expected {EXPECTED_RECORDS} records")

    source_bytes = parse_mac(source_mac)
    destination_bytes = parse_mac(destination_mac)
    maximum_frame = mtu + ETHERNET_HEADER_BYTES + VLAN_HEADER_ALLOWANCE_BYTES
    if any(len(record.data) > maximum_frame for record in records):
        raise ValueError(f"accepted fixture contains a frame larger than MTU {mtu}")

    scale = 1_000_000_000 if pcap_format.nanosecond_resolution else 1_000_000
    first_tick = records[0].timestamp_seconds * scale + records[0].timestamp_fraction
    offsets: list[int] = []
    frames: list[bytes] = []
    previous = 0
    for record in records:
        tick = record.timestamp_seconds * scale + record.timestamp_fraction
        offset = tick - first_tick
        if offset < previous:
            raise ValueError("accepted fixture timestamps are not monotonic")
        previous = offset
        offsets.append(offset)
        frames.append(destination_bytes + source_bytes + record.data[12:])
    return frames, offsets, scale


LINK_SETTLE_SECONDS = 2.0


def set_link(name: str, mtu: int, up: bool) -> None:
    facts = interface_facts(name)
    if facts["mtu"] == mtu and facts["up"] == up:
        # Nothing to change. Bouncing the link anyway costs the first frames of
        # whatever is sent next: a nine-frame scenario replay measured
        # packets_seen=4 on eleven of fourteen families because the send began
        # before the vmnet link had converged.
        return
    run_checked(("ip", "link", "set", "dev", name, "down"))
    run_checked(("ip", "link", "set", "dev", name, "mtu", str(mtu)))
    if up:
        run_checked(("ip", "link", "set", "dev", name, "up"))
        time.sleep(LINK_SETTLE_SECONDS)


def send_frames(
    interface: str,
    frames: Sequence[bytes],
    offsets: Sequence[int],
    tick_hz: int,
) -> SendResult:
    sent = 0
    sent_bytes = 0
    observed_offsets_ns: list[int] = []
    with socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(0x0003),
    ) as raw_socket:
        raw_socket.bind((interface, 0))
        started_ns = time.monotonic_ns()
        for frame, offset in zip(frames, offsets, strict=True):
            target_offset_ns = offset * 1_000_000_000 // tick_hz
            delay_ns = started_ns + target_offset_ns - time.monotonic_ns()
            if delay_ns > 0:
                time.sleep(delay_ns / 1_000_000_000)
            send_offset_ns = time.monotonic_ns() - started_ns
            written = raw_socket.send(frame)
            if written != len(frame):
                raise RuntimeError(
                    f"short raw-frame send: expected {len(frame)}, wrote {written}"
                )
            observed_offsets_ns.append(send_offset_ns)
            sent += 1
            sent_bytes += written
    return SendResult(
        records=sent,
        bytes=sent_bytes,
        duration_seconds=(time.monotonic_ns() - started_ns) / 1_000_000_000,
        observed_offsets_ns=tuple(observed_offsets_ns),
    )


def write_receipt(document: dict[str, Any]) -> Path:
    DEFAULT_RECEIPT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = DEFAULT_RECEIPT_ROOT / f"kali-sender.{stamp}.json"
    with path.open("x", encoding="utf-8", newline="\n") as destination:
        json.dump(document, destination, indent=2)
        destination.write("\n")
    return path


def replay(args: argparse.Namespace) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise RuntimeError("the live sender must run inside the Kali Linux VM")
    if os.geteuid() != 0:
        raise RuntimeError("raw Ethernet replay and reversible MTU changes require root")
    if not 1500 <= args.mtu <= 9000:
        raise ValueError("MTU must be between 1500 and 9000")

    original = interface_facts(args.interface)
    if original["has_default_route"]:
        raise RuntimeError("refusing to mutate an interface that owns a default route")
    if original["driver"] != "vmxnet3":
        raise RuntimeError(
            f"data interface driver must be vmxnet3, observed {original['driver']!r}"
        )
    frames, offsets, tick_hz = load_frames(
        args.input.resolve(),
        original["mac"],
        args.destination_mac,
        args.mtu,
    )

    started_at = utc_now()
    primary_error: BaseException | None = None
    result: SendResult | None = None
    try:
        set_link(args.interface, args.mtu, True)
        prepared = interface_facts(args.interface)
        if prepared["mtu"] != args.mtu or not prepared["up"]:
            raise RuntimeError("data interface did not retain the requested live state")
        result = send_frames(args.interface, frames, offsets, tick_hz)
    except BaseException as error:
        primary_error = error
    restore_error: BaseException | None = None
    try:
        set_link(args.interface, original["mtu"], original["up"])
    except BaseException as error:
        restore_error = error

    if primary_error is not None or restore_error is not None:
        details = []
        if primary_error is not None:
            details.append(f"replay failed: {primary_error}")
        if restore_error is not None:
            details.append(f"MTU/link rollback failed: {restore_error}")
        raise RuntimeError("; ".join(details))

    restored = interface_facts(args.interface)
    if restored["mtu"] != original["mtu"] or restored["up"] != original["up"]:
        raise RuntimeError("MTU/link rollback verification failed")
    assert result is not None
    if result.records != EXPECTED_RECORDS:
        raise RuntimeError(
            f"expected to send {EXPECTED_RECORDS} frames, sent {result.records}"
        )
    scheduled_offsets_ns = [
        offset * 1_000_000_000 // tick_hz for offset in offsets
    ]
    schedule_errors_ns = [
        observed - scheduled
        for observed, scheduled in zip(
            result.observed_offsets_ns,
            scheduled_offsets_ns,
            strict=True,
        )
    ]
    return {
        "event_type": "nids_kali_live_sender",
        "status": "passed",
        "started_at_utc": started_at,
        "ended_at_utc": utc_now(),
        "input": str(args.input.resolve()),
        "input_sha256": EXPECTED_INPUT_SHA256,
        "interface": args.interface,
        "driver": original["driver"],
        "source_mac": original["mac"],
        "destination_mac": args.destination_mac.lower(),
        "requested_mtu": args.mtu,
        "original_mtu": original["mtu"],
        "restored_mtu": restored["mtu"],
        "original_link_up": original["up"],
        "restored_link_up": restored["up"],
        "records_sent": result.records,
        "bytes_sent": result.bytes,
        "scheduled_offsets_ns": scheduled_offsets_ns,
        "observed_send_offsets_ns": list(result.observed_offsets_ns),
        "maximum_schedule_lateness_ns": max(schedule_errors_ns),
        "scheduled_duration_seconds": scheduled_offsets_ns[-1] / 1_000_000_000,
        "duration_seconds": round(result.duration_seconds, 6),
        "layer2_rewrite_only": True,
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--interface", default="eth1")
    parser.add_argument("--destination-mac", default="00:0c:29:d5:43:8b")
    parser.add_argument("--mtu", type=int, default=9000)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, request_interrupt)
    signal.signal(signal.SIGHUP, request_interrupt)
    try:
        receipt = replay(parse_arguments(argv))
        path = write_receipt(receipt)
        receipt["receipt"] = str(path)
        print(json.dumps(receipt, separators=(",", ":")))
        return 0
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
