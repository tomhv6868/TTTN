#!/usr/bin/env python3
"""Build the content-addressed CIC-IDS2017 golden prefixes for T3.2."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import struct
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from survey_cicids2017_flows import load_scapy, parse_flow_packet, timestamp_ns  # noqa: E402


SCHEMA_VERSION = "1.0.0"
TASK = "T3.2"
KIND = "cicids2017_golden_build"
READ_SIZE = 8 * 1024 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PCAP_MAGIC = 0xA1B23C4D
CHECK_NAMES = (
    "contract.valid",
    "prerequisite.t31_content_addressed",
    "source.pcap_content_addressed",
    "source.labels_content_addressed",
    "labels.structure_and_unique_rows",
    "pcap.full_scan_complete",
    "selection.unique_exact_flow_windows",
    "outputs.prefix_packet_count",
    "outputs.raw_source_evidence",
    "repository.raw_payload_untracked",
)


@dataclass(frozen=True)
class CapturedPacket:
    timestamp_ns: int
    captured_length: int
    original_length: int
    data: bytes
    source_ip: int
    source_port: int
    destination_ip: int
    destination_port: int
    protocol: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            document = json.load(source, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return document


def sha256_stream(source: BinaryIO, progress_bytes: int = 0, name: str = "") -> str:
    digest = hashlib.sha256()
    processed = 0
    next_progress = progress_bytes
    while chunk := source.read(READ_SIZE):
        digest.update(chunk)
        processed += len(chunk)
        if progress_bytes and processed >= next_progress:
            print(f"HASH {name} bytes={processed}", flush=True)
            while next_progress <= processed:
                next_progress += progress_bytes
    return digest.hexdigest()


def sha256_path(path: Path, progress_bytes: int = 0) -> str:
    with path.open("rb") as source:
        return sha256_stream(source, progress_bytes, path.name)


def resolve_path(project_root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("contract path must be a nonempty string")
    root = project_root.resolve()
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return path


def relative_path(path: Path, project_root: Path) -> str:
    return path.resolve().relative_to(project_root.resolve()).as_posix()


def canonical_key(
    source_ip: Any,
    source_port: Any,
    destination_ip: Any,
    destination_port: Any,
    protocol: Any,
) -> tuple[int, int, int, int, int]:
    source_address = ipaddress.ip_address(
        source_ip if isinstance(source_ip, int) else str(source_ip)
    )
    destination_address = ipaddress.ip_address(
        destination_ip if isinstance(destination_ip, int) else str(destination_ip)
    )
    if source_address.version != 4 or destination_address.version != 4:
        raise ValueError("golden selectors require IPv4 endpoints")
    source = (int(source_address), int(source_port))
    destination = (int(destination_address), int(destination_port))
    if not 0 <= source[1] <= 65535 or not 0 <= destination[1] <= 65535:
        raise ValueError("port is outside uint16 range")
    protocol_number = int(protocol)
    if not 0 <= protocol_number <= 255:
        raise ValueError("IP protocol is outside uint8 range")
    low, high = sorted((source, destination))
    return low[0], low[1], high[0], high[1], protocol_number


def sample_key(sample: Mapping[str, Any]) -> tuple[int, int, int, int, int]:
    row = sample["row"]
    return canonical_key(
        row["Source IP"],
        row["Source Port"],
        row["Destination IP"],
        row["Destination Port"],
        row["Protocol"],
    )


def selector_signature(row: Mapping[str, Any]) -> tuple[Any, ...]:
    canonical_key(
        row["Source IP"],
        row["Source Port"],
        row["Destination IP"],
        row["Destination Port"],
        row["Protocol"],
    )
    return (
        int(ipaddress.ip_address(row["Source IP"])),
        int(row["Source Port"]),
        int(ipaddress.ip_address(row["Destination IP"])),
        int(row["Destination Port"]),
        int(row["Protocol"]),
        int(row["Flow Duration"]),
        int(row["Total Fwd Packets"]),
        int(row["Total Backward Packets"]),
        row["Label"],
    )


def sample_signature(sample: Mapping[str, Any]) -> tuple[Any, ...]:
    return selector_signature(sample["row"])


def validate_contract(contract: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append("contract.schema_version")
    if contract.get("task") != TASK or contract.get("dataset") != "CIC-IDS2017":
        errors.append("contract.task_or_dataset")
    prerequisite = contract.get("prerequisite")
    if not isinstance(prerequisite, Mapping) or prerequisite.get("task") != "T3.1":
        errors.append("contract.prerequisite")
    elif SHA256_PATTERN.fullmatch(str(prerequisite.get("sha256", ""))) is None:
        errors.append("contract.prerequisite.sha256")
    sources = contract.get("sources")
    pcap = sources.get("pcap") if isinstance(sources, Mapping) else None
    labels = sources.get("labels") if isinstance(sources, Mapping) else None
    if not isinstance(pcap, Mapping) or pcap.get("magic_hex") != "0a0d0d0a":
        errors.append("contract.sources.pcap")
    elif pcap.get("linktype") != 1 or pcap.get("scapy_version") != "2.7.0":
        errors.append("contract.sources.pcap.reader")
    if not isinstance(labels, Mapping):
        errors.append("contract.sources.labels")
    else:
        if labels.get("encoding") != "cp1252" or labels.get("header_field_count") != 85:
            errors.append("contract.sources.labels.structure")
        if labels.get("all_empty_record_policy") != "skip_only_if_every_field_is_empty":
            errors.append("contract.sources.labels.empty_policy")
        if labels.get("nonempty_malformed_record_policy") != "fail":
            errors.append("contract.sources.labels.malformed_policy")
        required = labels.get("required_columns")
        if not isinstance(required, list) or len(required) != len(set(required)):
            errors.append("contract.sources.labels.required_columns")
    for source in (pcap, labels):
        if isinstance(source, Mapping):
            if SHA256_PATTERN.fullmatch(str(source.get("sha256", ""))) is None:
                errors.append("contract.sources.sha256")
            if (
                not isinstance(source.get("size_bytes"), int)
                or source["size_bytes"] <= 0
            ):
                errors.append("contract.sources.size_bytes")
    selection = contract.get("selection")
    if not isinstance(selection, Mapping):
        errors.append("contract.selection")
    else:
        expected = {
            "flow_key": "canonical_bidirectional_ipv4_5tuple",
            "csv_row_uniqueness": "directed IPv4 5-tuple, flow duration, forward/backward packet counts, and label occur exactly once among nonempty CSV records",
            "source_window": "consecutive packets for the canonical flow key with exact direction counts and first-to-last duration",
            "source_window_cardinality": 1,
            "duration_unit": "microseconds_exact",
            "prefix_packet_count": 9,
            "checkpoints": [3, 5, 7, 9],
            "timestamp_timezone_join": "not_used",
        }
        if any(selection.get(key) != value for key, value in expected.items()):
            errors.append("contract.selection.lock")
    samples = contract.get("samples")
    categories = {"benign_tcp", "benign_udp", "attack_tcp"}
    required_columns = (
        labels.get("required_columns", []) if isinstance(labels, Mapping) else []
    )
    if not isinstance(samples, list) or len(samples) != 3:
        errors.append("contract.samples")
    else:
        ids = [sample.get("id") for sample in samples if isinstance(sample, Mapping)]
        names = [
            sample.get("output_name")
            for sample in samples
            if isinstance(sample, Mapping)
        ]
        observed_categories = {
            sample.get("category") for sample in samples if isinstance(sample, Mapping)
        }
        if len(ids) != 3 or len(set(ids)) != 3 or len(set(names)) != 3:
            errors.append("contract.samples.unique")
        if observed_categories != categories:
            errors.append("contract.samples.categories")
        for sample in samples:
            try:
                row = sample["row"]
                if set(row) != set(required_columns):
                    errors.append(f"contract.samples.{sample.get('id')}.row")
                    continue
                protocol = int(row["Protocol"])
                label = row["Label"]
                category = sample["category"]
                if (
                    (category == "benign_tcp" and (protocol != 6 or label != "BENIGN"))
                    or (
                        category == "benign_udp"
                        and (protocol != 17 or label != "BENIGN")
                    )
                    or (
                        category == "attack_tcp"
                        and (protocol != 6 or label == "BENIGN")
                    )
                ):
                    errors.append(f"contract.samples.{sample.get('id')}.category")
                if (
                    int(row["Total Fwd Packets"]) + int(row["Total Backward Packets"])
                    < 9
                ):
                    errors.append(f"contract.samples.{sample.get('id')}.packet_count")
                if int(row["Flow Duration"]) < 0 or int(sample["csv_line"]) < 2:
                    errors.append(f"contract.samples.{sample.get('id')}.numeric")
                sample_key(sample)
            except (KeyError, TypeError, ValueError):
                errors.append("contract.samples.invalid")
    output = contract.get("output")
    if (
        not isinstance(output, Mapping)
        or output.get("format") != "classic_pcap_nanosecond"
    ):
        errors.append("contract.output")
    else:
        expected_output = {
            "directory": "run_log/t3.2",
            "build_receipt": "run_log/t3.2/build.json",
            "acceptance_receipt": "run_log/t3.2/acceptance.json",
            "magic_hex": "4d3cb2a1",
            "byte_order": "little",
            "timestamp_resolution": "nanoseconds",
            "snaplen": 262144,
            "linktype": 1,
            "preserve_source_packet_bytes": True,
            "preserve_source_timestamps": True,
            "preserve_source_wire_lengths": True,
        }
        if any(output.get(key) != value for key, value in expected_output.items()):
            errors.append("contract.output.pcap")
    policy = contract.get("repository_payload_policy")
    if (
        not isinstance(policy, Mapping)
        or policy.get("raw_payload_tracked") is not False
    ):
        errors.append("contract.repository_payload_policy")
    elif policy.get("raw_payload_allowed_directory") != "run_log/t3.2":
        errors.append("contract.repository_payload_policy.directory")
    shared = contract.get("shared_parser")
    if (
        not isinstance(shared, Mapping)
        or shared.get("required_for_acceptance") is not True
    ):
        errors.append("contract.shared_parser")
    elif (
        shared.get("expected_record_count_per_file") != 9
        or shared.get("expected_accepted_count_per_file") != 9
    ):
        errors.append("contract.shared_parser.counts")
    return errors


def content_identity(
    path: Path,
    project_root: Path,
    expected: Mapping[str, Any],
    progress_bytes: int,
) -> dict[str, Any]:
    before = path.stat()
    with path.open("rb") as source:
        magic = source.read(4).hex()
    digest = sha256_path(path, progress_bytes)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"source changed while hashing: {path}")
    if after.st_size != expected["size_bytes"] or digest != expected["sha256"]:
        raise ValueError(f"source content identity mismatch: {path}")
    expected_magic = expected.get("magic_hex")
    if expected_magic is not None and magic != expected_magic:
        raise ValueError(f"source magic mismatch: {path}")
    return {
        "path": relative_path(path, project_root),
        "size_bytes": after.st_size,
        "modified_time_ns": after.st_mtime_ns,
        "magic_hex": magic,
        "sha256": digest,
    }


def verify_t31_prerequisite(
    project_root: Path,
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    prerequisite = contract["prerequisite"]
    path = resolve_path(project_root, prerequisite["path"])
    digest = sha256_path(path)
    document = load_json(path)
    if digest != prerequisite["sha256"]:
        raise ValueError("T3.1 acceptance receipt hash mismatch")
    if (
        document.get("task") != prerequisite["task"]
        or document.get("status") != "passed"
    ):
        raise ValueError("T3.1 prerequisite did not pass")
    pcap_spec = contract["sources"]["pcap"]
    pcap_record = next(
        (
            item
            for item in document.get("source", {}).get("pcaps", [])
            if item.get("path") == pcap_spec["path"]
        ),
        None,
    )
    members = document.get("source", {}).get("labels", {}).get("members", [])
    label_spec = contract["sources"]["labels"]
    label_record = next(
        (item for item in members if item.get("path") == label_spec["archive_member"]),
        None,
    )
    if not isinstance(pcap_record, Mapping) or any(
        pcap_record.get(key) != pcap_spec[key]
        for key in ("path", "size_bytes", "sha256")
    ):
        raise ValueError("T3.1 PCAP evidence disagrees with T3.2 contract")
    if (
        not isinstance(label_record, Mapping)
        or label_record.get("path") != label_spec["archive_member"]
        or label_record.get("uncompressed_size_bytes") != label_spec["size_bytes"]
        or label_record.get("sha256") != label_spec["sha256"]
    ):
        raise ValueError("T3.1 label evidence disagrees with T3.2 contract")
    return {
        "path": prerequisite["path"],
        "sha256": digest,
        "task": document["task"],
        "status": document["status"],
    }


def scan_label_csv(
    path: Path,
    labels_contract: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    targets: dict[tuple[int, int, int, int, int], list[Mapping[str, Any]]] = (
        defaultdict(list)
    )
    for sample in samples:
        targets[sample_key(sample)].append(sample)
    signature_counts: Counter[tuple[Any, ...]] = Counter()
    exact_counts: Counter[str] = Counter()
    physical_count = 0
    blank_count = 0
    with path.open("r", encoding=labels_contract["encoding"], newline="") as source:
        reader = csv.reader(source)
        try:
            header = next(reader)
        except StopIteration as error:
            raise ValueError("label CSV is empty") from error
        trimmed_header = [value.strip() for value in header]
        if len(header) != labels_contract["header_field_count"]:
            raise ValueError("label CSV header field count mismatch")
        duplicates = Counter(trimmed_header)
        observed_duplicates = {
            key: value for key, value in duplicates.items() if value > 1
        }
        if observed_duplicates != labels_contract["duplicate_trimmed_headers"]:
            raise ValueError("label CSV duplicate header contract mismatch")
        indices: dict[str, int] = {}
        for column in labels_contract["required_columns"]:
            matches = [
                index for index, value in enumerate(trimmed_header) if value == column
            ]
            if len(matches) != 1:
                raise ValueError(f"required label column is not unique: {column}")
            indices[column] = matches[0]
        for line, fields in enumerate(reader, start=2):
            physical_count += 1
            if all(value.strip() == "" for value in fields):
                blank_count += 1
                continue
            if len(fields) != len(header):
                raise ValueError(f"nonempty malformed CSV record at line {line}")
            row = {name: fields[index].strip() for name, index in indices.items()}
            try:
                key = canonical_key(
                    row["Source IP"],
                    row["Source Port"],
                    row["Destination IP"],
                    row["Destination Port"],
                    row["Protocol"],
                )
                int(row["Flow Duration"])
                int(row["Total Fwd Packets"])
                int(row["Total Backward Packets"])
                signature = selector_signature(row)
            except ValueError as error:
                raise ValueError(
                    f"invalid required label value at line {line}: {error}"
                ) from error
            if key in targets:
                signature_counts[signature] += 1
                for sample in targets[key]:
                    if line == sample["csv_line"] and row == sample["row"]:
                        exact_counts[sample["id"]] += 1
    if physical_count != labels_contract["data_record_count"]:
        raise ValueError("label CSV data record count mismatch")
    if blank_count != labels_contract["all_empty_record_count"]:
        raise ValueError("label CSV all-empty record count mismatch")
    for sample in samples:
        if signature_counts[sample_signature(sample)] != 1:
            raise ValueError(f"CSV selector signature is ambiguous for {sample['id']}")
        if exact_counts[sample["id"]] != 1:
            raise ValueError(f"locked CSV row mismatch for {sample['id']}")
    return {
        "header_field_count": len(header),
        "data_record_count": physical_count,
        "nonempty_record_count": physical_count - blank_count,
        "all_empty_record_count": blank_count,
        "selected_rows": [
            {
                "id": sample["id"],
                "csv_line": sample["csv_line"],
                "selector_signature_occurrences": signature_counts[
                    sample_signature(sample)
                ],
                "exact_row_occurrences": exact_counts[sample["id"]],
            }
            for sample in samples
        ],
    }


def collect_candidate_packets(
    path: Path,
    pcap_contract: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
    progress_packets: int,
) -> tuple[dict[str, list[CapturedPacket]], dict[str, Any]]:
    target_ids = {sample_key(sample): sample["id"] for sample in samples}
    if len(target_ids) != len(samples):
        raise ValueError("sample flow keys must be distinct")
    hits: dict[str, list[CapturedPacket]] = {sample["id"]: [] for sample in samples}
    scapy_version, reader_type = load_scapy()
    if scapy_version != pcap_contract["scapy_version"]:
        raise ValueError("Scapy version disagrees with contract")
    before = path.stat()
    packet_count = 0
    rounding_count = 0
    linktypes: set[int] = set()
    reader = reader_type(str(path))
    try:
        for raw, metadata in reader:
            packet_count += 1
            linktypes.add(int(metadata.linktype))
            current_timestamp, rounded = timestamp_ns(metadata)
            rounding_count += int(rounded)
            raw_bytes = bytes(raw)
            parsed, _ = parse_flow_packet(raw_bytes, current_timestamp)
            if parsed is not None:
                key = canonical_key(
                    parsed.source_ip,
                    parsed.source_port,
                    parsed.destination_ip,
                    parsed.destination_port,
                    parsed.protocol,
                )
                sample_id = target_ids.get(key)
                if sample_id is not None:
                    wire_length = int(metadata.wirelen)
                    if wire_length < len(raw_bytes):
                        raise ValueError(
                            "source wire length is smaller than captured bytes"
                        )
                    hits[sample_id].append(
                        CapturedPacket(
                            timestamp_ns=current_timestamp,
                            captured_length=len(raw_bytes),
                            original_length=wire_length,
                            data=raw_bytes,
                            source_ip=parsed.source_ip,
                            source_port=parsed.source_port,
                            destination_ip=parsed.destination_ip,
                            destination_port=parsed.destination_port,
                            protocol=parsed.protocol,
                        )
                    )
            if progress_packets and packet_count % progress_packets == 0:
                print(f"SCAN {path.name} packets={packet_count}", flush=True)
    finally:
        reader.close()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("source PCAP changed during full scan")
    if packet_count != pcap_contract["packet_count"]:
        raise ValueError("source PCAP packet count mismatch")
    if linktypes != {pcap_contract["linktype"]}:
        raise ValueError(f"source PCAP linktype mismatch: {sorted(linktypes)}")
    if rounding_count != 0:
        raise ValueError(
            "source PCAP timestamps cannot be represented exactly in nanoseconds"
        )
    return hits, {
        "reader": "scapy.RawPcapNgReader",
        "scapy_version": scapy_version,
        "packet_count": packet_count,
        "linktypes": sorted(linktypes),
        "timestamp_rounding_count": rounding_count,
        "candidate_packet_counts": {key: len(value) for key, value in hits.items()},
    }


def packet_is_forward(packet: CapturedPacket, row: Mapping[str, Any]) -> bool:
    return (
        packet.source_ip == int(ipaddress.ip_address(row["Source IP"]))
        and packet.source_port == int(row["Source Port"])
        and packet.destination_ip == int(ipaddress.ip_address(row["Destination IP"]))
        and packet.destination_port == int(row["Destination Port"])
    )


def find_unique_window(
    packets: Sequence[CapturedPacket],
    sample: Mapping[str, Any],
) -> tuple[int, list[CapturedPacket]]:
    row = sample["row"]
    forward_count = int(row["Total Fwd Packets"])
    backward_count = int(row["Total Backward Packets"])
    packet_count = forward_count + backward_count
    duration_ns = int(row["Flow Duration"]) * 1_000
    matches: list[int] = []
    for start in range(max(0, len(packets) - packet_count + 1)):
        window = packets[start : start + packet_count]
        if any(
            right.timestamp_ns < left.timestamp_ns
            for left, right in zip(window, window[1:])
        ):
            continue
        if window[-1].timestamp_ns - window[0].timestamp_ns != duration_ns:
            continue
        observed_forward = sum(packet_is_forward(packet, row) for packet in window)
        if (
            observed_forward == forward_count
            and packet_count - observed_forward == backward_count
        ):
            matches.append(start)
    if len(matches) != 1:
        raise ValueError(
            f"expected one exact source window for {sample['id']}, found {len(matches)}"
        )
    start = matches[0]
    return start, list(packets[start : start + packet_count])


def write_classic_pcap_atomic(
    path: Path,
    packets: Sequence[CapturedPacket],
    snaplen: int,
    linktype: int,
) -> None:
    if path.exists() or os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as output:
            temporary_name = output.name
            output.write(
                struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype)
            )
            for packet in packets:
                seconds, nanoseconds = divmod(packet.timestamp_ns, 1_000_000_000)
                if (
                    packet.captured_length != len(packet.data)
                    or packet.captured_length > snaplen
                ):
                    raise ValueError("packet captured length violates output contract")
                output.write(
                    struct.pack(
                        "<IIII",
                        seconds,
                        nanoseconds,
                        packet.captured_length,
                        packet.original_length,
                    )
                )
                output.write(packet.data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
        raise


def read_classic_pcap(path: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) != 24:
            raise ValueError(f"truncated PCAP global header: {path}")
        magic, major, minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(
            "<IHHIIII", header
        )
        if magic != PCAP_MAGIC or (major, minor, thiszone, sigfigs) != (2, 4, 0, 0):
            raise ValueError(f"invalid nanosecond PCAP global header: {path}")
        while record_header := source.read(16):
            if len(record_header) != 16:
                raise ValueError(f"truncated PCAP record header: {path}")
            seconds, nanoseconds, captured_length, original_length = struct.unpack(
                "<IIII", record_header
            )
            if nanoseconds >= 1_000_000_000 or captured_length > snaplen:
                raise ValueError(f"invalid PCAP record metadata: {path}")
            data = source.read(captured_length)
            if len(data) != captured_length:
                raise ValueError(f"truncated PCAP packet data: {path}")
            records.append(
                {
                    "timestamp_ns": seconds * 1_000_000_000 + nanoseconds,
                    "captured_length": captured_length,
                    "original_length": original_length,
                    "data": data,
                }
            )
    return {"snaplen": snaplen, "linktype": linktype}, records


def packet_manifest(packet: CapturedPacket, index: int) -> dict[str, Any]:
    return {
        "index": index,
        "timestamp_ns": packet.timestamp_ns,
        "captured_length": packet.captured_length,
        "original_length": packet.original_length,
        "sha256": hashlib.sha256(packet.data).hexdigest(),
    }


def write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists() or os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
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
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
        raise


def build_dataset(
    project_root: Path,
    contract_path: Path,
    progress_bytes: int = 0,
    progress_packets: int = 0,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    contract = load_json(contract_path)
    errors = validate_contract(contract)
    if errors:
        raise ValueError(f"invalid T3.2 contract: {errors}")
    contract_sha256 = sha256_path(contract_path)
    prerequisite = verify_t31_prerequisite(project_root, contract)
    pcap_spec = contract["sources"]["pcap"]
    label_spec = contract["sources"]["labels"]
    pcap_path = resolve_path(project_root, pcap_spec["path"])
    label_path = resolve_path(project_root, label_spec["path"])
    pcap_identity = content_identity(pcap_path, project_root, pcap_spec, progress_bytes)
    label_identity = content_identity(
        label_path, project_root, label_spec, progress_bytes
    )
    label_scan = scan_label_csv(label_path, label_spec, contract["samples"])
    hits, pcap_scan = collect_candidate_packets(
        pcap_path, pcap_spec, contract["samples"], progress_packets
    )
    prefix_count = contract["selection"]["prefix_packet_count"]
    windows: dict[str, tuple[int, list[CapturedPacket]]] = {}
    for sample in contract["samples"]:
        windows[sample["id"]] = find_unique_window(hits[sample["id"]], sample)

    output_contract = contract["output"]
    output_dir = resolve_path(project_root, output_contract["directory"])
    receipt_path = resolve_path(project_root, output_contract["build_receipt"])
    destinations = [
        output_dir / sample["output_name"] for sample in contract["samples"]
    ]
    if any(
        path.exists() or os.path.lexists(path) for path in [*destinations, receipt_path]
    ):
        raise ValueError("refusing to overwrite existing T3.2 build artifacts")
    artifacts: list[dict[str, Any]] = []
    created: list[Path] = []
    try:
        for sample, path in zip(contract["samples"], destinations):
            start, full_window = windows[sample["id"]]
            prefix = full_window[:prefix_count]
            write_classic_pcap_atomic(
                path, prefix, output_contract["snaplen"], output_contract["linktype"]
            )
            created.append(path)
            header, written = read_classic_pcap(path)
            if (
                header
                != {
                    "snaplen": output_contract["snaplen"],
                    "linktype": output_contract["linktype"],
                }
                or len(written) != prefix_count
            ):
                raise ValueError(f"output PCAP structure mismatch: {path}")
            for source_packet, output_packet in zip(prefix, written):
                if (
                    output_packet["timestamp_ns"] != source_packet.timestamp_ns
                    or output_packet["captured_length"] != source_packet.captured_length
                    or output_packet["original_length"] != source_packet.original_length
                    or output_packet["data"] != source_packet.data
                ):
                    raise ValueError(f"output packet differs from source: {path}")
            artifacts.append(
                {
                    "id": sample["id"],
                    "category": sample["category"],
                    "label": sample["row"]["Label"],
                    "csv_line": sample["csv_line"],
                    "source_match": {
                        "candidate_packet_count": len(hits[sample["id"]]),
                        "window_start_index": start,
                        "flow_packet_count": len(full_window),
                        "flow_duration_ns": full_window[-1].timestamp_ns
                        - full_window[0].timestamp_ns,
                        "forward_packet_count": int(sample["row"]["Total Fwd Packets"]),
                        "backward_packet_count": int(
                            sample["row"]["Total Backward Packets"]
                        ),
                    },
                    "file": {
                        "path": relative_path(path, project_root),
                        "size_bytes": path.stat().st_size,
                        "magic_hex": path.read_bytes()[:4].hex(),
                        "sha256": sha256_path(path),
                        "record_count": len(written),
                    },
                    "packets": [
                        packet_manifest(packet, index)
                        for index, packet in enumerate(prefix, start=1)
                    ],
                }
            )
        checks = [{"name": name, "status": "passed"} for name in CHECK_NAMES]
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "task": TASK,
            "kind": KIND,
            "status": "passed",
            "acceptance_status": "pending_shared_parser",
            "generated_at_utc": utc_now(),
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
            },
            "contract": {
                "path": relative_path(contract_path, project_root),
                "sha256": contract_sha256,
            },
            "prerequisite": prerequisite,
            "sources": {"pcap": pcap_identity, "labels": label_identity},
            "label_scan": label_scan,
            "pcap_scan": pcap_scan,
            "samples": artifacts,
            "repository_payload_policy": contract["repository_payload_policy"],
            "shared_parser": {
                "required": True,
                "status": "pending",
                "target": contract["shared_parser"]["target"],
            },
            "checks": checks,
        }
        write_json_atomic(receipt_path, receipt)
        return receipt
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--contract",
        type=Path,
        default=project_root / "config" / "cicids2017-golden-contract.json",
    )
    parser.add_argument("--progress-bytes", type=int, default=1 << 30)
    parser.add_argument("--progress-packets", type=int, default=2_000_000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = build_dataset(
            args.project_root,
            args.contract,
            args.progress_bytes,
            args.progress_packets,
        )
    except (OSError, ValueError, struct.error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"built {len(receipt['samples'])} T3.2 golden prefixes; shared-parser acceptance pending"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
