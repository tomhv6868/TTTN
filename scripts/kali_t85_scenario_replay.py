#!/usr/bin/env python3
"""Replay one extracted T8.5 scenario PCAP from the Kali data NIC."""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import sys
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from build_t85_live_pcap import parse_pcap, sha256_bytes  # noqa: E402
from kali_t85_golden_sender import (  # noqa: E402
    interface_facts,
    parse_mac,
    request_interrupt,
    send_frames,
    set_link,
    utc_now,
)


def load_case(run_id: str, case_id: str) -> tuple[Path, dict[str, Any]]:
    root = ROOT / "run_log/t8.5/scenarios" / run_id
    manifest_path = root / "pcap/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    matches = [item for item in manifest["outputs"] if item["case_id"] == case_id]
    if len(matches) != 1:
        raise ValueError(f"expected one extracted case {case_id}")
    record = matches[0]
    path = (ROOT / record["path"]).resolve()
    path.relative_to(root.resolve())
    data = path.read_bytes()
    if sha256_bytes(data) != record["sha256"]:
        raise ValueError("extracted PCAP hash mismatch")
    return path, record


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def parse_destination_mac(value: str) -> bytes:
    """Accept the broadcast address as a replay destination.

    parse_mac() rejects it, and for the golden sender that is right. Here it is
    the only address that reliably reaches the sensor: once ens160 is bound to
    DPDK the kernel stops transmitting from it, the vmnet switch ages its MAC
    out of the forwarding table, and unicast addressed to that MAC is dropped
    while broadcast and multicast keep being flooded. tcpdump on the kernel
    interface sees all nine frames; the DPDK sensor on the same NIC sees only
    the flooded noise. Only the 6-byte destination changes, so the 5-tuple,
    the payload and the inter-arrival timing that F9 measures are untouched.
    """
    if value.lower() == BROADCAST_MAC:
        return b"\xff" * 6
    return parse_mac(value)


def load_frames(
    path: Path,
    source_mac: str,
    destination_mac: str,
    mtu: int,
) -> tuple[list[bytes], list[int], int]:
    pcap_format, _, records = parse_pcap(path.read_bytes())
    if len(records) != 9:
        raise ValueError(f"expected 9 records, observed {len(records)}")
    maximum_frame = mtu + 18
    if any(len(record.data) > maximum_frame for record in records):
        raise ValueError(f"scenario PCAP contains a frame larger than MTU {mtu}")
    source = parse_mac(source_mac)
    destination = parse_destination_mac(destination_mac)
    scale = 1_000_000_000 if pcap_format.nanosecond_resolution else 1_000_000
    first = records[0].timestamp_seconds * scale + records[0].timestamp_fraction
    offsets: list[int] = []
    frames: list[bytes] = []
    for record in records:
        tick = record.timestamp_seconds * scale + record.timestamp_fraction
        if offsets and tick - first < offsets[-1]:
            raise ValueError("scenario timestamps are not monotonic")
        offsets.append(tick - first)
        frames.append(destination + source + record.data[12:])
    return frames, offsets, scale


def replay(args: argparse.Namespace) -> dict[str, Any]:
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("run this replay as root inside the Kali VM")
    path, case = load_case(args.run_id, args.case)
    original = interface_facts(args.interface)
    if original["has_default_route"] or original["driver"] != "vmxnet3":
        raise RuntimeError("refusing to use a management or non-vmxnet3 interface")
    frames, offsets, tick_hz = load_frames(
        path, original["mac"], args.destination_mac, args.mtu
    )
    primary_error: BaseException | None = None
    result = None
    started = utc_now()
    try:
        set_link(args.interface, args.mtu, True)
        result = send_frames(args.interface, frames, offsets, tick_hz)
    except BaseException as error:
        primary_error = error
    rollback_error: BaseException | None = None
    try:
        set_link(args.interface, original["mtu"], original["up"])
    except BaseException as error:
        rollback_error = error
    if primary_error or rollback_error:
        raise RuntimeError(
            "; ".join(
                text
                for text in (
                    f"replay failed: {primary_error}" if primary_error else "",
                    f"rollback failed: {rollback_error}" if rollback_error else "",
                )
                if text
            )
        )
    restored = interface_facts(args.interface)
    if restored["mtu"] != original["mtu"] or restored["up"] != original["up"]:
        raise RuntimeError("Kali interface rollback verification failed")
    assert result is not None
    return {
        "schema_version": "1.0.0",
        "kind": "diagnostic_demo_evidence",
        "mode": "demo_critical_path",
        "formal_acceptance": False,
        "roadmap_mutated": False,
        "status": "observed",
        "run_id": args.run_id,
        "case": case,
        "started_at_utc": started,
        "ended_at_utc": utc_now(),
        "records_sent": result.records,
        "bytes_sent": result.bytes,
        "layer2_rewrite_only": True,
        "historical_layer3_session": True,
        "windows_session_participation_claimed": False,
        "dataset_equivalence_claimed": False,
        "original_mtu": original["mtu"],
        "restored_mtu": restored["mtu"],
    }


def write_receipt(args: argparse.Namespace, document: dict[str, Any]) -> Path:
    # Create-new is deliberate: a replay receipt is never silently overwritten.
    # A repeat of the same case therefore has to name itself, which --attempt
    # does, rather than displacing the receipt already on disk.
    name = f"{args.case}.json" if not args.attempt \
        else f"{args.case}.{args.attempt}.json"
    path = (
        ROOT
        / "run_log/t8.5/scenarios"
        / args.run_id
        / "kali/replay"
        / name
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as destination:
        json.dump(document, destination, indent=2, ensure_ascii=False)
        destination.write("\n")
    return path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--interface", default="eth1")
    parser.add_argument("--destination-mac", default="00:0c:29:d5:43:8b")
    parser.add_argument("--mtu", type=int, default=9000)
    parser.add_argument("--attempt", default="",
                        help="names the receipt so a repeat of the same case "
                             "does not collide with the receipt already stored")
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, request_interrupt)
    signal.signal(signal.SIGHUP, request_interrupt)
    try:
        receipt = replay(args)
        path = write_receipt(args, receipt)
        print(json.dumps({**receipt, "receipt": str(path)}, separators=(",", ":")))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
