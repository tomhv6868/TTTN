#!/usr/bin/env python3
"""Send bounded raw UDP test traffic from Kali to the T0.3 DPDK data NIC."""

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


SCHEMA_VERSION = "1.0.0"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_mac(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value.replace(":", ""))
    except ValueError as error:
        raise ValueError(f"invalid MAC address: {value}") from error
    if len(raw) != 6:
        raise ValueError(f"invalid MAC address: {value}")
    return raw


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_udp_frame(
    source_mac: str,
    destination_mac: str,
    source_ip: str,
    destination_ip: str,
    sequence: int,
    source_port: int = 40000,
    destination_port: int = 9000,
) -> bytes:
    payload = struct.pack("!IQ", sequence & 0xFFFFFFFF, time.monotonic_ns() & 0xFFFFFFFFFFFFFFFF)
    udp_length = 8 + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0) + payload
    total_length = 20 + udp_length
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        sequence & 0xFFFF,
        0x4000,
        64,
        socket.IPPROTO_UDP,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    checksum = internet_checksum(header_without_checksum)
    ipv4 = header_without_checksum[:10] + struct.pack("!H", checksum) + header_without_checksum[12:]
    ethernet = parse_mac(destination_mac) + parse_mac(source_mac) + struct.pack("!H", 0x0800)
    frame = ethernet + ipv4 + udp
    return frame.ljust(60, b"\x00")


def run_json(arguments: Sequence[str]) -> Any:
    try:
        result = subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=5.0)
        return json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def interface_facts(name: str) -> dict[str, Any]:
    base = Path("/sys/class/net") / name
    if not base.is_dir():
        raise ValueError(f"interface does not exist: {name}")
    routes = run_json(("ip", "-json", "route", "show", "default"))
    has_default = any(route.get("dev") == name for route in routes)
    driver_link = base / "device" / "driver"
    driver = driver_link.resolve().name if driver_link.exists() else None
    return {
        "name": name,
        "mac": (base / "address").read_text(encoding="ascii").strip(),
        "driver": driver,
        "has_default_route": has_default,
    }


def write_new_json(path: Path, document: Mapping[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"refusing to overwrite existing file: {path}; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def send_traffic(args: argparse.Namespace) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise RuntimeError("traffic generation must run inside the Kali Linux VM")
    if os.geteuid() != 0:
        raise RuntimeError("raw traffic generation requires root")
    if args.duration <= 0 or args.pps <= 0:
        raise ValueError("duration and pps must be positive")
    source_ip = ipaddress.ip_address(args.source_ip)
    destination_ip = ipaddress.ip_address(args.destination_ip)
    subnet = ipaddress.ip_network(args.subnet, strict=True)
    if source_ip not in subnet or destination_ip not in subnet:
        raise ValueError("source and destination IP must be inside the configured data-network subnet")
    facts = interface_facts(args.interface)
    if facts["has_default_route"]:
        raise RuntimeError("refusing to use an interface that owns a default route")
    if facts["driver"] != "vmxnet3":
        raise RuntimeError(f"data interface driver must be vmxnet3, observed {facts['driver']!r}")
    parse_mac(args.destination_mac)
    interval = 1.0 / args.pps
    sent = 0
    errors = 0
    started_at = utc_now()
    start = time.monotonic()
    deadline = start + args.duration
    next_send = start
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw_socket:
        raw_socket.bind((args.interface, 0))
        while time.monotonic() < deadline:
            frame = build_udp_frame(
                facts["mac"],
                args.destination_mac,
                str(source_ip),
                str(destination_ip),
                sent,
            )
            try:
                raw_socket.send(frame)
                sent += 1
            except OSError:
                errors += 1
            next_send += interval
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    elapsed = time.monotonic() - start
    return {
        "schema_version": SCHEMA_VERSION,
        "task": "T0.3",
        "kind": "traffic",
        "status": "passed" if sent > 0 and errors == 0 else "failed",
        "generated_at_utc": utc_now(),
        "started_at_utc": started_at,
        "ended_at_utc": utc_now(),
        "duration_seconds": round(elapsed, 3),
        "requested_duration_seconds": args.duration,
        "packets_per_second": args.pps,
        "sent_packets": sent,
        "send_errors": errors,
        "interface": facts,
        "source_ip": str(source_ip),
        "destination_ip": str(destination_ip),
        "destination_mac": args.destination_mac.lower(),
        "subnet": str(subnet),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--destination-mac", required=True)
    parser.add_argument("--source-ip", default="192.168.252.10")
    parser.add_argument("--destination-ip", default="192.168.252.20")
    parser.add_argument("--subnet", default="192.168.252.0/24")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--pps", type=int, default=100)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = send_traffic(args)
        write_new_json(args.output, receipt, args.force)
        print(f"wrote {args.output} ({receipt['status']}); sent={receipt['sent_packets']}")
        return 0 if receipt["status"] == "passed" else 1
    except (RuntimeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
