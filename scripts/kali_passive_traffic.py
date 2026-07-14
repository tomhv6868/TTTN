#!/usr/bin/env python3
"""Send the bounded T0.4 Kali-to-Windows passive-observation traffic."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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
TASK = "T0.4"
KIND = "kali_sender"
DEFAULT_CONFIG_PATH = Path("config/dpdk-passive.json")
DEFAULT_OUTPUT_PATH = Path("run_log/t0.4/kali-sender.json")

LOCKED_CONFIG_VALUES: tuple[tuple[tuple[str, ...], object], ...] = (
    (("schema_version",), SCHEMA_VERSION),
    (("task",), TASK),
    (("topology", "data_network", "name"), "VMnet1"),
    (("topology", "data_network", "mode"), "host-only"),
    (("topology", "data_network", "subnet"), "192.168.252.0/24"),
    (("kali", "data_interface"), "eth1"),
    (("kali", "data_ipv4"), "192.168.252.128"),
    (("kali", "expected_driver"), "vmxnet3"),
    (("kali", "udp_source_port"), 40000),
    (("windows_victim", "data_ipv4"), "192.168.252.20"),
    (("windows_victim", "expected_mac"), "00:0c:29:13:8d:4f"),
    (("windows_victim", "udp_port"), 9000),
    (("ubuntu_sensor", "expected_mac"), "00:0c:29:30:b9:d3"),
    (("traffic", "packet_count"), 200),
    (("traffic", "packets_per_second"), 10),
    (("traffic", "payload_magic_ascii"), "NIDST04!"),
    (("traffic", "payload_size_bytes"), 12),
    (("artifacts", "workspace_root"), "run_log/t0.4"),
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nested_value(document: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = document
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            raise ValueError(f"missing config field: {'.'.join(path)}")
        value = value[key]
    return value


def load_and_validate_config(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"config file does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON config: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("config root must be an object")

    for field_path, expected in LOCKED_CONFIG_VALUES:
        observed = nested_value(document, field_path)
        if type(observed) is not type(expected) or observed != expected:
            name = ".".join(field_path)
            raise ValueError(f"locked config mismatch for {name}: expected {expected!r}, observed {observed!r}")

    subnet = ipaddress.ip_network(document["topology"]["data_network"]["subnet"], strict=True)
    source_ip = ipaddress.ip_address(document["kali"]["data_ipv4"])
    destination_ip = ipaddress.ip_address(document["windows_victim"]["data_ipv4"])
    if source_ip not in subnet or destination_ip not in subnet:
        raise ValueError("Kali and victim IPv4 addresses must be inside the locked data subnet")

    magic = document["traffic"]["payload_magic_ascii"].encode("ascii")
    if len(magic) != 8 or document["traffic"]["payload_size_bytes"] != len(magic) + 4:
        raise ValueError("payload contract must be 8-byte ASCII magic plus a 4-byte sequence")

    victim_mac = parse_mac(document["windows_victim"]["expected_mac"])
    sensor_mac = parse_mac(document["ubuntu_sensor"]["expected_mac"])
    if victim_mac == sensor_mac:
        raise ValueError("victim MAC must differ from sensor MAC")
    if victim_mac == b"\x00" * 6 or victim_mac[0] & 1:
        raise ValueError("victim MAC must be a nonzero unicast address")
    return document


def parse_mac(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value.replace(":", "").replace("-", ""))
    except ValueError as error:
        raise ValueError(f"invalid MAC address: {value}") from error
    if len(raw) != 6:
        raise ValueError(f"invalid MAC address: {value}")
    return raw


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_payload(magic_ascii: str, sequence: int) -> bytes:
    if not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError("sequence must fit in an unsigned 32-bit integer")
    magic = magic_ascii.encode("ascii")
    if len(magic) != 8:
        raise ValueError("payload magic must encode to exactly 8 ASCII bytes")
    return magic + struct.pack("!I", sequence)


def build_udp_frame(
    source_mac: str,
    destination_mac: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    magic_ascii: str,
    sequence: int,
) -> bytes:
    payload = build_payload(magic_ascii, sequence)
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
    return (ethernet + ipv4 + udp).ljust(60, b"\x00")


def run_json(arguments: Sequence[str]) -> Any:
    try:
        result = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=5.0)
        return json.loads(result.stdout)
    except FileNotFoundError as error:
        raise RuntimeError(f"required command is unavailable: {arguments[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or f"exit {error.returncode}"
        raise RuntimeError(f"command failed ({' '.join(arguments)}): {detail}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out: {' '.join(arguments)}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"command returned invalid JSON: {' '.join(arguments)}") from error


def run_checked(arguments: Sequence[str]) -> None:
    try:
        subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=5.0)
    except FileNotFoundError as error:
        raise RuntimeError(f"required command is unavailable: {arguments[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip() or f"exit {error.returncode}"
        raise RuntimeError(f"command failed ({' '.join(arguments)}): {detail}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out: {' '.join(arguments)}") from error


def interface_facts(name: str) -> dict[str, Any]:
    base = Path("/sys/class/net") / name
    if not base.is_dir():
        raise ValueError(f"interface does not exist: {name}")

    driver_link = base / "device" / "driver"
    try:
        driver = driver_link.resolve(strict=True).name
    except FileNotFoundError as error:
        raise RuntimeError(f"interface has no bound driver: {name}") from error

    routes = run_json(("ip", "-json", "route", "show", "default"))
    addresses = run_json(("ip", "-json", "address", "show", "dev", name))
    if not isinstance(routes, list) or not isinstance(addresses, list) or len(addresses) != 1:
        raise RuntimeError("unexpected JSON structure returned by iproute2")
    ipv4_addresses = [
        entry["local"]
        for entry in addresses[0].get("addr_info", [])
        if entry.get("family") == "inet" and isinstance(entry.get("local"), str)
    ]
    return {
        "name": name,
        "mac": (base / "address").read_text(encoding="ascii").strip().lower(),
        "driver": driver,
        "has_default_route": any(route.get("dev") == name for route in routes),
        "ipv4_addresses": ipv4_addresses,
    }


def resolve_artifact_paths(config_path: Path, output_path: Path, config: Mapping[str, Any]) -> tuple[Path, Path]:
    project_root = config_path.resolve().parent.parent
    workspace_root = (project_root / config["artifacts"]["workspace_root"]).resolve()
    candidate = output_path if output_path.is_absolute() else project_root / output_path
    resolved_output = candidate.resolve()
    if resolved_output == workspace_root or workspace_root not in resolved_output.parents:
        raise ValueError(f"output must be a JSON file under {workspace_root}")
    if resolved_output.suffix.lower() != ".json":
        raise ValueError("output must have a .json extension")
    return workspace_root, resolved_output


def validate_runtime(config: Mapping[str, Any]) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise RuntimeError("traffic generation must run inside the Kali Linux VM")
    if os.geteuid() != 0:
        raise RuntimeError("raw traffic generation requires root")

    kali = config["kali"]
    facts = interface_facts(kali["data_interface"])
    if facts["driver"] != kali["expected_driver"]:
        raise RuntimeError(
            f"data interface driver must be {kali['expected_driver']}, observed {facts['driver']!r}"
        )
    if facts["has_default_route"]:
        raise RuntimeError("refusing to use a data interface that owns a default route")
    address_prepared = False
    if facts["ipv4_addresses"].count(kali["data_ipv4"]) != 1:
        prefix_length = ipaddress.ip_network(config["topology"]["data_network"]["subnet"]).prefixlen
        run_checked(("ip", "link", "set", "dev", kali["data_interface"], "up"))
        run_checked(
            ("ip", "address", "replace", f"{kali['data_ipv4']}/{prefix_length}", "dev", kali["data_interface"])
        )
        facts = interface_facts(kali["data_interface"])
        address_prepared = True
        if facts["has_default_route"] or facts["ipv4_addresses"].count(kali["data_ipv4"]) != 1:
            raise RuntimeError(f"could not safely prepare source IPv4 {kali['data_ipv4']} on the data interface")
    if parse_mac(facts["mac"]) == parse_mac(config["windows_victim"]["expected_mac"]):
        raise RuntimeError("source and victim MAC addresses must differ")
    facts["source_address_prepared"] = address_prepared
    return facts


def send_traffic(config: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    kali = config["kali"]
    victim = config["windows_victim"]
    traffic = config["traffic"]
    packet_count = traffic["packet_count"]
    interval = 1.0 / traffic["packets_per_second"]
    sent = 0
    errors = 0
    started_at = utc_now()
    start = time.monotonic()
    next_send = start

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw_socket:
        raw_socket.bind((kali["data_interface"], 0))
        for sequence in range(packet_count):
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            frame = build_udp_frame(
                facts["mac"],
                victim["expected_mac"],
                kali["data_ipv4"],
                victim["data_ipv4"],
                kali["udp_source_port"],
                victim["udp_port"],
                traffic["payload_magic_ascii"],
                sequence,
            )
            try:
                raw_socket.send(frame)
                sent += 1
            except OSError:
                errors += 1
            next_send += interval

    return {
        "started_at_utc": started_at,
        "ended_at_utc": utc_now(),
        "duration_seconds": round(time.monotonic() - start, 3),
        "sent_packets": sent,
        "send_errors": errors,
    }


def build_receipt(
    config_path: Path,
    config: Mapping[str, Any],
    facts: Mapping[str, Any],
    result: Mapping[str, Any],
) -> dict[str, Any]:
    kali = config["kali"]
    victim = config["windows_victim"]
    traffic = config["traffic"]
    passed = result["sent_packets"] == traffic["packet_count"] and result["send_errors"] == 0
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "status": "passed" if passed else "failed",
        "generated_at_utc": utc_now(),
        "started_at_utc": result["started_at_utc"],
        "ended_at_utc": result["ended_at_utc"],
        "duration_seconds": result["duration_seconds"],
        "interface": dict(facts),
        "source": {"ipv4": kali["data_ipv4"], "udp_port": kali["udp_source_port"]},
        "destination": {
            "ipv4": victim["data_ipv4"],
            "mac": victim["expected_mac"].lower(),
            "udp_port": victim["udp_port"],
        },
        "traffic": {
            "requested_packets": traffic["packet_count"],
            "packets_per_second": traffic["packets_per_second"],
            "payload_magic_ascii": traffic["payload_magic_ascii"],
            "payload_size_bytes": traffic["payload_size_bytes"],
        },
        "sent_packets": result["sent_packets"],
        "send_errors": result["send_errors"],
        "sequence_range": {"first": 0, "last": traffic["packet_count"] - 1},
        "config": {"file": str(config_path), "sha256": sha256_file(config_path)},
        "error": None,
    }


def write_new_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as destination:
            json.dump(document, destination, indent=2)
            destination.write("\n")
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite existing receipt: {path}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config_path = args.config.resolve()
        config = load_and_validate_config(config_path)
        _, output_path = resolve_artifact_paths(config_path, args.output, config)
        if output_path.exists():
            raise ValueError(f"refusing to overwrite existing receipt: {output_path}")
        facts = validate_runtime(config)
        result = send_traffic(config, facts)
        receipt = build_receipt(config_path, config, facts, result)
        write_new_json(output_path, receipt)
        print(f"wrote {output_path} ({receipt['status']}); sent={receipt['sent_packets']}")
        return 0 if receipt["status"] == "passed" else 1
    except (RuntimeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
