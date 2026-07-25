#!/usr/bin/env python3
"""Send bounded multi-flow traffic for the T7.4-T7.6 VMware speed-run."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


PACKETS_PER_FLOW = 9


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_mac(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value.replace(":", ""))
    except ValueError as error:
        raise ValueError(f"invalid MAC address: {value}") from error
    if len(raw) != 6 or raw[0] & 1:
        raise ValueError(f"MAC address must be unicast: {value}")
    return raw


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def flow_ports(flow_index: int) -> tuple[int, int]:
    width = 64_000
    return (
        1_024 + flow_index % width,
        1_024 + (flow_index // width) % width,
    )


def build_tcp_frame(
    source_mac: str,
    destination_mac: str,
    source_ip: str,
    destination_ip: str,
    flow_index: int,
    packet_index: int,
) -> bytes:
    source_port, destination_port = flow_ports(flow_index)
    sequence = flow_index * PACKETS_PER_FLOW + packet_index
    tcp_flags = 0x04 if packet_index == PACKETS_PER_FLOW - 1 else 0x10
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence & 0xFFFFFFFF,
        0,
        0x50,
        tcp_flags,
        65_535,
        0,
        0,
    )
    total_length = 20 + len(tcp)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        sequence & 0xFFFF,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    checksum = internet_checksum(header)
    ipv4 = header[:10] + struct.pack("!H", checksum) + header[12:]
    ethernet = (
        parse_mac(destination_mac)
        + parse_mac(source_mac)
        + struct.pack("!H", 0x0800)
    )
    return (ethernet + ipv4 + tcp).ljust(64, b"\x00")


def run_json(arguments: Sequence[str]) -> Any:
    result = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=5.0,
    )
    return json.loads(result.stdout) if result.returncode == 0 else []


def interface_facts(name: str) -> dict[str, Any]:
    base = Path("/sys/class/net") / name
    if not base.is_dir():
        raise ValueError(f"interface does not exist: {name}")
    routes = run_json(("ip", "-json", "route", "show", "default"))
    driver_link = base / "device" / "driver"
    return {
        "name": name,
        "mac": (base / "address").read_text(encoding="ascii").strip().lower(),
        "driver": driver_link.resolve().name if driver_link.exists() else None,
        "has_default_route": any(route.get("dev") == name for route in routes),
    }


def validate(args: argparse.Namespace) -> int:
    if platform.system() != "Linux":
        raise RuntimeError("benchmark traffic must run inside the Kali VM")
    if os.geteuid() != 0:
        raise RuntimeError("raw Ethernet traffic requires root")
    if not 1 <= args.flows <= 1_000_000:
        raise ValueError("--flows must be between 1 and 1000000")
    if not 1 <= args.pps <= 100_000:
        raise ValueError("--pps must be between 1 and 100000")
    subnet = ipaddress.ip_network(args.subnet, strict=True)
    if (
        ipaddress.ip_address(args.source_ip) not in subnet
        or ipaddress.ip_address(args.destination_ip) not in subnet
    ):
        raise ValueError("source and destination IP must be inside --subnet")
    facts = interface_facts(args.interface)
    if facts["has_default_route"]:
        raise RuntimeError("refusing to use an interface with a default route")
    if facts["driver"] != "vmxnet3":
        raise RuntimeError(
            f"data interface driver must be vmxnet3, observed {facts['driver']!r}"
        )
    parse_mac(args.destination_mac)
    if args.output.exists():
        raise ValueError(f"refusing to overwrite receipt: {args.output}")
    return args.flows * PACKETS_PER_FLOW


def send(args: argparse.Namespace) -> dict[str, Any]:
    packet_count = validate(args)
    facts = interface_facts(args.interface)
    interval_ns = 1_000_000_000 / args.pps
    maximum_lateness_ns = 0
    sent_bytes = 0
    started_at_utc = utc_now()
    with socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(0x0003),
    ) as raw_socket:
        raw_socket.bind((args.interface, 0))
        started_ns = time.monotonic_ns()
        for sequence in range(packet_count):
            target_ns = started_ns + int(sequence * interval_ns)
            delay_ns = target_ns - time.monotonic_ns()
            if delay_ns > 0:
                time.sleep(delay_ns / 1_000_000_000)
            observed_ns = time.monotonic_ns()
            maximum_lateness_ns = max(
                maximum_lateness_ns,
                observed_ns - target_ns,
            )
            frame = build_tcp_frame(
                facts["mac"],
                args.destination_mac,
                args.source_ip,
                args.destination_ip,
                sequence // PACKETS_PER_FLOW,
                sequence % PACKETS_PER_FLOW,
            )
            written = raw_socket.send(frame)
            if written != len(frame):
                raise RuntimeError(
                    f"short raw-frame send: expected {len(frame)}, wrote {written}"
                )
            sent_bytes += written
    duration_seconds = (time.monotonic_ns() - started_ns) / 1_000_000_000
    return {
        "schema_version": "1.0.0",
        "task": "T7.4-T7.6",
        "kind": "kali_benchmark_sender",
        "status": "passed",
        "mode": args.mode,
        "attempt": args.attempt,
        "started_at_utc": started_at_utc,
        "ended_at_utc": utc_now(),
        "interface": facts,
        "destination_mac": args.destination_mac.lower(),
        "source_ip": args.source_ip,
        "destination_ip": args.destination_ip,
        "flows": args.flows,
        "packets_per_flow": PACKETS_PER_FLOW,
        "packets_sent": packet_count,
        "bytes_sent": sent_bytes,
        "requested_pps": args.pps,
        "observed_pps": packet_count / duration_seconds,
        "duration_seconds": duration_seconds,
        "maximum_schedule_lateness_ns": maximum_lateness_ns,
    }


def write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(receipt, output, ensure_ascii=False, indent=2)
        output.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline", "full", "stability"), required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--flows", type=int, required=True)
    parser.add_argument("--pps", type=int, required=True)
    parser.add_argument("--interface", default="eth1")
    parser.add_argument("--destination-mac", default="00:0c:29:d5:43:8b")
    parser.add_argument("--source-ip", default="192.168.252.10")
    parser.add_argument("--destination-ip", default="192.168.252.20")
    parser.add_argument("--subnet", default="192.168.252.0/24")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = send(args)
        write_receipt(args.output, receipt)
        print(
            f"[T7.4-T7.6 sender] status=passed mode={args.mode} "
            f"packets={receipt['packets_sent']} pps={receipt['observed_pps']:.1f}"
        )
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
