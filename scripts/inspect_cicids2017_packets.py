#!/usr/bin/env python3
"""Inspect CIC-IDS2017 PCAPNG files without extracting flows or payload content."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import struct
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T1.1"
KIND = "cicids2017_packet_inventory"
INSPECTOR_REVISION = "1.0.1"
LOCKED_SCAPY_VERSION = "2.7.0"
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
EXPECTED_FILES = {
    "friday-workinghours.pcap",
    "monday-workinghours.pcap",
    "thursday-workinghours.pcap",
    "tuesday-workinghours.pcap",
    "wednesday-workinghours.pcap",
}
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
PAYLOAD_BUCKETS = (
    (0, 0, "0"),
    (1, 15, "1-15"),
    (16, 31, "16-31"),
    (32, 63, "32-63"),
    (64, 127, "64-127"),
    (128, 255, "128-255"),
    (256, 511, "256-511"),
    (512, 1023, "512-1023"),
    (1024, 1499, "1024-1499"),
    (1500, 65535, "1500-65535"),
)


@dataclass(frozen=True)
class FrameFacts:
    outer_ethertype: int | None = None
    inner_ethertype: int | None = None
    vlan_depth: int = 0
    ipv4: bool = False
    ipv6: bool = False
    ip_protocol: int | None = None
    ipv4_fragmented: bool = False
    ipv4_options: bool = False
    transport: str | None = None
    tcp_options: bool = False
    header_length: int | None = None
    payload_length: int | None = None
    error: str | None = None


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("!H", data, offset)[0]


def payload_bucket(length: int) -> str:
    for minimum, maximum, label in PAYLOAD_BUCKETS:
        if minimum <= length <= maximum:
            return label
    return ">65535"


def inspect_frame(data: bytes) -> FrameFacts:
    if len(data) < 14:
        return FrameFacts(error="truncated_ethernet_header")

    outer_ethertype = read_u16(data, 12)
    ethertype = outer_ethertype
    offset = 14
    vlan_depth = 0
    while ethertype in VLAN_ETHERTYPES:
        if len(data) < offset + 4:
            return FrameFacts(
                outer_ethertype=outer_ethertype,
                inner_ethertype=ethertype,
                vlan_depth=vlan_depth,
                error="truncated_vlan_header",
            )
        ethertype = read_u16(data, offset + 2)
        vlan_depth += 1
        offset += 4

    base = {
        "outer_ethertype": outer_ethertype,
        "inner_ethertype": ethertype,
        "vlan_depth": vlan_depth,
    }
    if ethertype == 0x86DD:
        return FrameFacts(**base, ipv6=True)
    if ethertype != 0x0800:
        return FrameFacts(**base)
    if len(data) < offset + 20:
        return FrameFacts(**base, ipv4=True, error="truncated_ipv4_header")

    version_ihl = data[offset]
    version = version_ihl >> 4
    ihl_words = version_ihl & 0x0F
    if version != 4:
        return FrameFacts(**base, error="invalid_ipv4_version")
    if ihl_words < 5:
        return FrameFacts(**base, ipv4=True, error="invalid_ipv4_ihl")

    ip_header_length = ihl_words * 4
    if len(data) < offset + ip_header_length:
        return FrameFacts(**base, ipv4=True, error="truncated_ipv4_options")
    total_length = read_u16(data, offset + 2)
    if total_length < ip_header_length:
        return FrameFacts(**base, ipv4=True, error="invalid_ipv4_total_length")

    flags_fragment = read_u16(data, offset + 6)
    fragment_offset = flags_fragment & 0x1FFF
    more_fragments = bool(flags_fragment & 0x2000)
    fragmented = more_fragments or fragment_offset != 0
    protocol = data[offset + 9]
    ip_end = offset + total_length
    ipv4_base = {
        **base,
        "ipv4": True,
        "ip_protocol": protocol,
        "ipv4_fragmented": fragmented,
        "ipv4_options": ip_header_length > 20,
    }
    if len(data) < min(ip_end, offset + ip_header_length):
        return FrameFacts(**ipv4_base, error="truncated_ipv4_packet")
    if fragmented:
        transport = "tcp" if protocol == 6 else "udp" if protocol == 17 else None
        return FrameFacts(**ipv4_base, transport=transport)

    transport_offset = offset + ip_header_length
    ip_payload_length = total_length - ip_header_length
    if protocol == 6:
        if ip_payload_length < 20:
            return FrameFacts(**ipv4_base, transport="tcp", error="invalid_tcp_length")
        if len(data) < transport_offset + 20:
            return FrameFacts(**ipv4_base, transport="tcp", error="truncated_tcp_header")
        tcp_header_length = (data[transport_offset + 12] >> 4) * 4
        if tcp_header_length < 20:
            return FrameFacts(**ipv4_base, transport="tcp", error="invalid_tcp_data_offset")
        if ip_payload_length < tcp_header_length:
            return FrameFacts(**ipv4_base, transport="tcp", error="tcp_header_exceeds_ipv4_length")
        if len(data) < transport_offset + tcp_header_length:
            return FrameFacts(**ipv4_base, transport="tcp", error="truncated_tcp_options")
        payload_length = ip_payload_length - tcp_header_length
        error = "truncated_tcp_payload" if len(data) < ip_end else None
        return FrameFacts(
            **ipv4_base,
            transport="tcp",
            tcp_options=tcp_header_length > 20,
            header_length=offset + ip_header_length + tcp_header_length,
            payload_length=payload_length,
            error=error,
        )

    if protocol == 17:
        if ip_payload_length < 8:
            return FrameFacts(**ipv4_base, transport="udp", error="invalid_udp_ip_length")
        if len(data) < transport_offset + 8:
            return FrameFacts(**ipv4_base, transport="udp", error="truncated_udp_header")
        udp_length = read_u16(data, transport_offset + 4)
        if udp_length < 8:
            return FrameFacts(**ipv4_base, transport="udp", error="invalid_udp_length")
        if udp_length > ip_payload_length:
            return FrameFacts(**ipv4_base, transport="udp", error="udp_length_exceeds_ipv4_length")
        payload_length = udp_length - 8
        udp_end = transport_offset + udp_length
        error = "truncated_udp_payload" if len(data) < udp_end else None
        return FrameFacts(
            **ipv4_base,
            transport="udp",
            header_length=offset + ip_header_length + 8,
            payload_length=payload_length,
            error=error,
        )

    error = "truncated_ipv4_packet" if len(data) < ip_end else None
    return FrameFacts(**ipv4_base, error=error)


def new_statistics() -> dict[str, Any]:
    return {
        "packet_count": 0,
        "captured_bytes": 0,
        "wire_bytes": 0,
        "capture_truncated_packets": 0,
        "timestamp_duplicate_count": 0,
        "timestamp_regression_count": 0,
        "timestamp_rounding_count": 0,
        "first_timestamp_ns": None,
        "last_timestamp_ns": None,
        "minimum_timestamp_ns": None,
        "maximum_timestamp_ns": None,
        "linktype_counts": Counter(),
        "timestamp_resolution_counts": Counter(),
        "outer_ethertype_counts": Counter(),
        "inner_ethertype_counts": Counter(),
        "vlan_depth_counts": Counter(),
        "ip_protocol_counts": Counter(),
        "transport_counts": Counter(),
        "header_length_counts": Counter(),
        "payload_length_histogram": Counter(),
        "errors": Counter(),
        "ipv4_packets": 0,
        "ipv6_packets": 0,
        "ipv4_fragmented_packets": 0,
        "ipv4_option_packets": 0,
        "tcp_option_packets": 0,
    }


def update_statistics(
    statistics: dict[str, Any],
    raw: bytes,
    metadata: Any,
    previous_timestamp_ns: int | None,
) -> int:
    statistics["packet_count"] += 1
    statistics["captured_bytes"] += len(raw)
    wire_length = int(metadata.wirelen) if metadata.wirelen is not None else len(raw)
    statistics["wire_bytes"] += wire_length
    if len(raw) < wire_length:
        statistics["capture_truncated_packets"] += 1

    resolution = int(metadata.tsresol)
    timestamp_ticks = (int(metadata.tshigh) << 32) | int(metadata.tslow)
    scaled_timestamp = timestamp_ticks * 1_000_000_000
    timestamp_ns, remainder = divmod(scaled_timestamp, resolution)
    if remainder:
        statistics["timestamp_rounding_count"] += 1
    statistics["timestamp_resolution_counts"][str(resolution)] += 1
    if statistics["first_timestamp_ns"] is None:
        statistics["first_timestamp_ns"] = timestamp_ns
        statistics["minimum_timestamp_ns"] = timestamp_ns
        statistics["maximum_timestamp_ns"] = timestamp_ns
    else:
        statistics["minimum_timestamp_ns"] = min(statistics["minimum_timestamp_ns"], timestamp_ns)
        statistics["maximum_timestamp_ns"] = max(statistics["maximum_timestamp_ns"], timestamp_ns)
    if previous_timestamp_ns is not None:
        if timestamp_ns == previous_timestamp_ns:
            statistics["timestamp_duplicate_count"] += 1
        elif timestamp_ns < previous_timestamp_ns:
            statistics["timestamp_regression_count"] += 1
    statistics["last_timestamp_ns"] = timestamp_ns

    statistics["linktype_counts"][str(int(metadata.linktype))] += 1
    if int(metadata.linktype) != 1:
        statistics["errors"]["unsupported_linktype"] += 1
        return timestamp_ns

    facts = inspect_frame(raw)
    if facts.outer_ethertype is not None:
        statistics["outer_ethertype_counts"][f"0x{facts.outer_ethertype:04x}"] += 1
    if facts.inner_ethertype is not None:
        statistics["inner_ethertype_counts"][f"0x{facts.inner_ethertype:04x}"] += 1
    statistics["vlan_depth_counts"][str(facts.vlan_depth)] += 1
    if facts.ipv4:
        statistics["ipv4_packets"] += 1
    if facts.ipv6:
        statistics["ipv6_packets"] += 1
    if facts.ip_protocol is not None:
        statistics["ip_protocol_counts"][str(facts.ip_protocol)] += 1
    if facts.ipv4_fragmented:
        statistics["ipv4_fragmented_packets"] += 1
    if facts.ipv4_options:
        statistics["ipv4_option_packets"] += 1
    if facts.transport is not None:
        statistics["transport_counts"][facts.transport] += 1
    if facts.tcp_options:
        statistics["tcp_option_packets"] += 1
    if facts.header_length is not None:
        statistics["header_length_counts"][str(facts.header_length)] += 1
    if facts.payload_length is not None:
        statistics["payload_length_histogram"][payload_bucket(facts.payload_length)] += 1
    if facts.error is not None:
        statistics["errors"][facts.error] += 1
    return timestamp_ns


def json_ready(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(sorted(value.items()))
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    if isinstance(value, tuple):
        return [json_ready(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def interface_descriptions(reader: Any) -> list[dict[str, Any]]:
    descriptions = []
    for index, interface in enumerate(reader.interfaces):
        linktype, snaplen, options = interface
        descriptions.append(
            {
                "index": index,
                "linktype": int(linktype),
                "snaplen": int(snaplen),
                "timestamp_resolution": int(options.get("tsresol", 1_000_000)),
                "name": json_ready(options.get("name")),
            }
        )
    return descriptions


def load_scapy() -> tuple[str, Any]:
    try:
        import scapy
        from scapy.utils import RawPcapNgReader
    except ImportError as error:
        raise RuntimeError("Scapy 2.7.0 is required for PCAPNG container reading") from error
    if scapy.__version__ != LOCKED_SCAPY_VERSION:
        raise RuntimeError(
            f"Scapy version must equal {LOCKED_SCAPY_VERSION}, found {scapy.__version__}"
        )

    class InventoryPcapNgReader(RawPcapNgReader):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.section_count = 0
            super().__init__(*args, **kwargs)

        def _read_block_shb(self) -> None:
            self.section_count += 1
            super()._read_block_shb()

    return scapy.__version__, InventoryPcapNgReader


def source_identity(path: Path) -> dict[str, Any]:
    stat = path.stat()
    with path.open("rb") as source:
        magic = source.read(4)
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "size_bytes": stat.st_size,
        "modified_time_ns": stat.st_mtime_ns,
        "magic_hex": magic.hex(),
    }


def reusable_receipt(path: Path, identity: Mapping[str, Any]) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot resume from invalid receipt {path}: {error}") from error
    if (
        document.get("status") != "passed"
        or document.get("inspector_revision") != INSPECTOR_REVISION
        or document.get("source") != dict(identity)
    ):
        raise ValueError(f"refusing to overwrite stale or incomplete receipt: {path}")
    print(f"REUSE {identity['name']} from {path}", flush=True)
    return document


def write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(json_ready(document), output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise


def receipt_name(path: Path) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", path.stem.lower()).strip("-")
    return f"{slug}.json"


def inspect_pcapng_file(
    path: Path,
    receipt_path: Path,
    raw_reader_type: Any,
    scapy_version: str,
    progress_every: int,
) -> dict[str, Any]:
    identity = source_identity(path)
    if identity["magic_hex"] != PCAPNG_MAGIC.hex():
        raise ValueError(f"{path} is not a PCAPNG file")
    reused = reusable_receipt(receipt_path, identity)
    if reused is not None:
        return reused

    print(f"START {path.name} ({identity['size_bytes']} bytes)", flush=True)
    started = time.monotonic()
    statistics = new_statistics()
    previous_timestamp_ns: int | None = None
    reader = raw_reader_type(str(path))
    try:
        for raw, metadata in reader:
            previous_timestamp_ns = update_statistics(statistics, raw, metadata, previous_timestamp_ns)
            count = statistics["packet_count"]
            if count % progress_every == 0:
                elapsed = time.monotonic() - started
                rate = count / elapsed if elapsed else 0.0
                print(f"PROGRESS {path.name} packets={count} rate={rate:.0f}/s", flush=True)
        interfaces = interface_descriptions(reader)
    finally:
        reader.close()

    duration = time.monotonic() - started
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "cicids2017_packet_file_inventory",
        "inspector_revision": INSPECTOR_REVISION,
        "status": "passed",
        "generated_at_utc": utc_now(),
        "source": identity,
        "reader": {"name": "Scapy RawPcapNgReader", "version": scapy_version},
        "section_count": reader.section_count,
        "interfaces": interfaces,
        "statistics": json_ready(statistics),
        "duration_seconds": round(duration, 3),
    }
    write_json_atomic(receipt_path, receipt)
    print(
        f"DONE {path.name} packets={statistics['packet_count']} "
        f"duration={duration:.1f}s receipt={receipt_path}",
        flush=True,
    )
    return receipt


def merge_counts(receipts: Iterable[Mapping[str, Any]], name: str) -> dict[str, int]:
    merged: Counter[str] = Counter()
    for receipt in receipts:
        merged.update(receipt["statistics"].get(name, {}))
    return dict(sorted(merged.items()))


def aggregate_receipts(receipts: Sequence[Mapping[str, Any]], scapy_version: str) -> dict[str, Any]:
    scalar_names = (
        "packet_count",
        "captured_bytes",
        "wire_bytes",
        "capture_truncated_packets",
        "timestamp_duplicate_count",
        "timestamp_regression_count",
        "timestamp_rounding_count",
        "ipv4_packets",
        "ipv6_packets",
        "ipv4_fragmented_packets",
        "ipv4_option_packets",
        "tcp_option_packets",
    )
    counter_names = (
        "linktype_counts",
        "timestamp_resolution_counts",
        "outer_ethertype_counts",
        "inner_ethertype_counts",
        "vlan_depth_counts",
        "ip_protocol_counts",
        "transport_counts",
        "header_length_counts",
        "payload_length_histogram",
        "errors",
    )
    totals = {
        name: sum(int(receipt["statistics"].get(name, 0)) for receipt in receipts)
        for name in scalar_names
    }
    totals.update({name: merge_counts(receipts, name) for name in counter_names})
    checks = [
        {
            "name": "source.file_count",
            "status": "passed" if len(receipts) == len(EXPECTED_FILES) else "failed",
        },
        {
            "name": "source.pcapng_magic",
            "status": "passed"
            if all(receipt["source"]["magic_hex"] == PCAPNG_MAGIC.hex() for receipt in receipts)
            else "failed",
        },
        {
            "name": "scan.all_files_complete",
            "status": "passed"
            if all(receipt.get("status") == "passed" for receipt in receipts)
            else "failed",
        },
    ]
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "inspector_revision": INSPECTOR_REVISION,
        "status": status,
        "generated_at_utc": utc_now(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "reader": {"name": "Scapy RawPcapNgReader", "version": scapy_version},
        "files": [receipt["source"] for receipt in receipts],
        "totals": totals,
        "checks": checks,
    }


def require_expected_sources(input_dir: Path) -> list[Path]:
    if not input_dir.is_dir():
        raise ValueError(f"input directory does not exist: {input_dir}")
    files = sorted(input_dir.glob("*.pcap"), key=lambda path: path.name.lower())
    names = {path.name.lower() for path in files}
    if names != EXPECTED_FILES:
        missing = sorted(EXPECTED_FILES - names)
        unexpected = sorted(names - EXPECTED_FILES)
        raise ValueError(f"expected the five CIC-IDS2017 PCAP files; missing={missing}, unexpected={unexpected}")
    return files


def run_self_test() -> None:
    scapy_version, _ = load_scapy()
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ipv4_tcp = bytes.fromhex("4500002c0000400040060000c0a80101c0a80102")
    tcp = bytes.fromhex("04d2005000000001000000005018200000000000")
    tcp_facts = inspect_frame(ethernet + ipv4_tcp + tcp + b"test")
    assert tcp_facts.transport == "tcp"
    assert tcp_facts.header_length == 54
    assert tcp_facts.payload_length == 4
    assert tcp_facts.error is None

    vlan = bytes.fromhex("00112233445566778899aabb810000640800")
    ipv4_udp = bytes.fromhex("4500001f0000000040110000c0a80101c0a80102")
    udp = bytes.fromhex("04d2162e000b0000")
    udp_facts = inspect_frame(vlan + ipv4_udp + udp + b"udp")
    assert udp_facts.vlan_depth == 1
    assert udp_facts.transport == "udp"
    assert udp_facts.header_length == 46
    assert udp_facts.payload_length == 3

    fragmented = bytearray(ethernet + ipv4_tcp + tcp + b"test")
    fragmented[20:22] = bytes.fromhex("2000")
    fragmented_facts = inspect_frame(bytes(fragmented))
    assert fragmented_facts.ipv4_fragmented
    assert fragmented_facts.transport == "tcp"
    assert fragmented_facts.payload_length is None
    assert fragmented_facts.error is None
    assert inspect_frame(ethernet[:10]).error == "truncated_ethernet_header"
    invalid_ihl = bytearray(ethernet + ipv4_tcp + tcp + b"test")
    invalid_ihl[14] = 0x44
    assert inspect_frame(bytes(invalid_ihl)).error == "invalid_ipv4_ihl"
    print(f"self-test passed (Scapy {scapy_version})")


def command_scan(args: argparse.Namespace) -> int:
    project_root = Path(__file__).resolve().parents[1]
    expected_input = (project_root / "pcap").resolve()
    expected_output_root = (project_root / "run_log" / "t1.1").resolve()
    input_dir = args.input_dir.resolve()
    output = args.output.resolve()
    if input_dir != expected_input:
        raise ValueError(f"input directory must equal {expected_input}")
    if output == expected_output_root or expected_output_root not in output.parents:
        raise ValueError(f"output must be a file below {expected_output_root}")
    if os.path.lexists(output):
        raise ValueError(f"refusing to overwrite existing aggregate receipt: {output}")
    files = require_expected_sources(input_dir)
    scapy_version, raw_reader_type = load_scapy()
    receipt_dir = output.parent / "inventory"
    receipts = [
        inspect_pcapng_file(
            path,
            receipt_dir / receipt_name(path),
            raw_reader_type,
            scapy_version,
            args.progress_every,
        )
        for path in files
    ]
    aggregate = aggregate_receipts(receipts, scapy_version)
    write_json_atomic(output, aggregate)
    print(f"wrote {output} ({aggregate['status']})", flush=True)
    return 0 if aggregate["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run bounded internal checks and exit")
    parser.add_argument("--input-dir", type=Path, default=project_root / "pcap")
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "run_log" / "t1.1" / "pcap-inventory.json",
    )
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.progress_every <= 0:
            raise ValueError("--progress-every must be positive")
        if args.self_test:
            run_self_test()
            return 0
        return command_scan(args)
    except (AssertionError, OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
