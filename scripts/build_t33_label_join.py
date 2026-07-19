#!/usr/bin/env python3
"""Build the fail-closed CIC-IDS2017 flow-to-label join evidence for T3.3."""

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
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Mapping, Sequence
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SCHEMA_VERSION = "1.0.0"
TASK = "T3.3"
KIND = "label_join_build"
READ_SIZE = 8 * 1024 * 1024
BATCH_SIZE = 10_000
CAPTURE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
SHA256 = re.compile(r"[0-9a-f]{64}")
FLOW_KEYS = {
    "schema_version", "task", "kind", "capture_id", "protocol", "low_ip",
    "low_port", "high_ip", "high_port", "forward_source_ip",
    "forward_source_port", "generation", "clock_domain",
    "creation_timestamp_ns", "last_capture_timestamp_ns",
    "last_event_timestamp_ns", "packet_count", "forward_packet_count",
    "reverse_packet_count", "close_reason",
}
SUMMARY_KEYS = {
    "schema_version", "task", "kind", "status", "input", "capture_id",
    "pcap", "flows", "exported_flows", "parser_errors", "ingest_errors",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_stream(source: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(READ_SIZE):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def sha256_path(path: Path) -> str:
    with path.open("rb") as source:
        return sha256_stream(source)[0]


def resolve_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError(f"expected relative project path: {value!r}")
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"path escapes project root: {value}")
    return path


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ValueError(f"path escapes project root: {path}") from error


def integer(value: Any, name: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def validate_contract(contract: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    if contract.get("task") != TASK or contract.get("dataset") != "CIC-IDS2017":
        errors.append("task_or_dataset")
    captures = contract.get("captures")
    if not isinstance(captures, list) or len(captures) != 5:
        errors.append("captures")
        captures = []
    ids: list[str] = []
    csv_paths: list[str] = []
    pcap_paths: list[str] = []
    known_labels: set[str] = set()
    for capture in captures:
        if not isinstance(capture, Mapping):
            errors.append("capture_object")
            continue
        capture_id = capture.get("id")
        if not isinstance(capture_id, str) or CAPTURE_ID.fullmatch(capture_id) is None:
            errors.append("capture_id")
        else:
            ids.append(capture_id)
        pcap = capture.get("pcap")
        if not isinstance(pcap, Mapping):
            errors.append("pcap")
        else:
            pcap_paths.append(str(pcap.get("path", "")))
            if integer_or_none(pcap.get("size_bytes")) is None or SHA256.fullmatch(
                str(pcap.get("sha256", ""))
            ) is None:
                errors.append("pcap_identity")
        csv_specs = capture.get("csv")
        if not isinstance(csv_specs, list) or not csv_specs:
            errors.append("csv_mapping")
            continue
        for spec in csv_specs:
            if not isinstance(spec, Mapping):
                errors.append("csv_object")
                continue
            csv_paths.append(str(spec.get("path", "")))
            counts = spec.get("label_counts")
            if not isinstance(counts, Mapping) or not counts:
                errors.append("label_counts")
                continue
            protocol_counts = spec.get("protocol_counts")
            if not isinstance(protocol_counts, Mapping) or not protocol_counts:
                errors.append("protocol_counts")
                continue
            negative_duration_count = integer_or_none(spec.get("negative_duration_count"))
            if negative_duration_count is None:
                errors.append("negative_duration_count")
            known_labels.update(str(label) for label in counts)
            numeric = (
                integer_or_none(spec.get("size_bytes")),
                integer_or_none(spec.get("physical_record_count")),
                integer_or_none(spec.get("all_empty_record_count")),
                integer_or_none(spec.get("nonempty_record_count")),
            )
            if numeric[3] is not None and negative_duration_count is not None:
                if negative_duration_count > numeric[3]:
                    errors.append("negative_duration_count")
            if any(value is None for value in numeric) or SHA256.fullmatch(
                str(spec.get("sha256", ""))
            ) is None:
                errors.append("csv_identity")
            elif numeric[1] != numeric[2] + numeric[3]:
                errors.append("csv_record_accounting")
            if sum(counts.values()) != spec.get("nonempty_record_count") or any(
                integer_or_none(value) is None for value in counts.values()
            ):
                errors.append("csv_label_accounting")
            if sum(protocol_counts.values()) != spec.get("nonempty_record_count") or any(
                key not in {"0", "6", "17"} or integer_or_none(value) is None
                for key, value in protocol_counts.items()
            ):
                errors.append("csv_protocol_accounting")
    if len(ids) != len(set(ids)) or len(pcap_paths) != len(set(pcap_paths)):
        errors.append("capture_uniqueness")
    if len(csv_paths) != 8 or len(csv_paths) != len(set(csv_paths)):
        errors.append("csv_set")
    join = contract.get("join")
    if not isinstance(join, Mapping):
        errors.append("join")
    else:
        if join.get("tolerance_sweep_seconds") != [0, 1, 5, 10, 30, 60]:
            errors.append("tolerance_sweep")
        if join.get("maximum_candidate_tolerance_seconds") != 60:
            errors.append("maximum_tolerance")
        if join.get("bare_hour_ambiguity") != (
            "hours_01_through_11_create_as_written_and_plus_12h_variants"
        ):
            errors.append("bare_hour_ambiguity")
        if join.get("unsupported_label_protocol_policy") != {
            "values": [0],
            "action": "quarantine_without_join_or_training",
            "reason": "unsupported_protocol",
            "retain_source_label": True,
            "other_values": "fail",
        }:
            errors.append("unsupported_label_protocol_policy")
        if join.get("invalid_flow_duration_policy") != {
            "negative_values": "quarantine",
            "action": "quarantine_without_join_or_training",
            "reason": "invalid_flow_duration",
            "retain_source_value": True,
            "retain_source_label": True,
            "non_decimal_values": "fail",
        }:
            errors.append("invalid_flow_duration_policy")
        timezone = join.get("candidate_timezone")
        if not isinstance(timezone, Mapping) or timezone.get("status") != (
            "inference_to_be_audited_not_publisher_metadata"
        ):
            errors.append("candidate_timezone")
    csv_schema = contract.get("csv_schema")
    if not isinstance(csv_schema, Mapping) or csv_schema.get("header_field_count") != 85:
        errors.append("csv_schema")
    audit = contract.get("attack_audit")
    events = audit.get("events") if isinstance(audit, Mapping) else None
    event_labels = {
        str(label)
        for event in events or []
        if isinstance(event, Mapping)
        for label in event.get("labels", [])
    }
    benign = audit.get("benign_label") if isinstance(audit, Mapping) else None
    if not isinstance(events, list) or known_labels - {benign} != event_labels:
        errors.append("attack_event_label_coverage")
    exporter_spec = contract.get("exporter")
    exclusion_policy = (
        exporter_spec.get("parser_exclusion_policy")
        if isinstance(exporter_spec, Mapping)
        else None
    )
    expected_exclusions = (
        exclusion_policy.get("expected_by_capture")
        if isinstance(exclusion_policy, Mapping)
        else None
    )
    expected_file_receipts = {
        "monday-working-hours": {
            "path": "run_log/t1.2/flow-survey/monday-workinghours.json",
            "sha256": "058977878141e674d3f9185cd0f7b9e2b35817046ded6182cd1de8ae402675fe",
        },
        "tuesday-working-hours": {
            "path": "run_log/t1.2/flow-survey/tuesday-workinghours.json",
            "sha256": "002d7f08b75fd0679155d24323b03a03b19229e62e5a954846f145ef27a76a64",
        },
        "wednesday-working-hours": {
            "path": "run_log/t1.2/flow-survey/wednesday-workinghours.json",
            "sha256": "007a6cfee0d2f3275fd014de74bca257a340494cd3b232c7215a8466444c76a7",
        },
        "thursday-working-hours": {
            "path": "run_log/t1.2/flow-survey/thursday-workinghours.json",
            "sha256": "3bdb3d4b16ce5abdec511a6affaa4e2af03ba862acf1caacb0527f55fb6e36a1",
        },
        "friday-working-hours": {
            "path": "run_log/t1.2/flow-survey/friday-workinghours.json",
            "sha256": "46c81d1a72fba9b6c49b308a6892a1951dbcd51bebb914a6db66611fd44d4a7b",
        },
    }
    exclusion_evidence = (
        exclusion_policy.get("evidence")
        if isinstance(exclusion_policy, Mapping)
        else None
    )
    if (
        not isinstance(exporter_spec, Mapping)
        or exporter_spec.get("ingest_errors_allowed") != 0
        or not isinstance(exclusion_policy, Mapping)
        or exclusion_policy.get("action")
        != "exclude_from_flow_reconstruction_and_label_join"
        or exclusion_policy.get("accounting")
        != "exact_by_capture_from_locked_t1_2_full_scan"
        or exclusion_policy.get("allowed_categories")
        != ["non_ipv4", "ipv4_fragmented", "unsupported_transport"]
        or not isinstance(exclusion_evidence, Mapping)
        or {
            key: exclusion_evidence.get(key)
            for key in ("path", "sha256", "task", "status")
        }
        != {
            "path": "run_log/t1.2/flow-survey.json",
            "sha256": "e92a3183caf1c2075da6f071eeaebf026787047a882985b45529a40ce2826afc",
            "task": "T1.2",
            "status": "passed",
        }
        or exclusion_evidence.get("file_receipts") != expected_file_receipts
        or not isinstance(expected_exclusions, Mapping)
        or set(expected_exclusions) != set(ids)
    ):
        errors.append("exporter_parser_exclusion_policy")
    else:
        exclusion_fields = {
            "non_ipv4", "ipv4_fragmented", "unsupported_transport", "total"
        }
        valid_exclusions = True
        for counts in expected_exclusions.values():
            if (
                not isinstance(counts, Mapping)
                or set(counts) != exclusion_fields
                or any(integer_or_none(value) is None for value in counts.values())
                or counts.get("total")
                != counts.get("non_ipv4", 0)
                + counts.get("ipv4_fragmented", 0)
                + counts.get("unsupported_transport", 0)
            ):
                valid_exclusions = False
        if not valid_exclusions or sum(
            counts["total"] for counts in expected_exclusions.values()
        ) != 418873:
            errors.append("exporter_parser_exclusion_accounting")
    sqlite_spec = contract.get("sqlite")
    if not isinstance(sqlite_spec, Mapping) or sqlite_spec.get("raw_packet_or_payload_storage") is not False:
        errors.append("sqlite")
    source = contract.get("source_evidence")
    schedule = source.get("official_schedule") if isinstance(source, Mapping) else None
    if not isinstance(schedule, Mapping) or schedule.get("timezone_published") is not False:
        errors.append("official_timezone_limit")
    return sorted(set(errors))


def integer_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def read_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                result[key] = value.strip().strip('"')
    except OSError:
        pass
    return result


def inspect_host() -> dict[str, Any]:
    release = read_os_release()
    product = ""
    try:
        product = Path("/sys/class/dmi/id/product_name").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return {
        "system": platform.system(),
        "os_id": release.get("ID"),
        "os_version": release.get("VERSION_ID"),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "virtualization_product": product,
    }


def require_supported_host(host: Mapping[str, Any]) -> None:
    uid = host.get("effective_uid")
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        raise RuntimeError("T3.3 build must run as a normal user")
    if host.get("system") != "Linux" or host.get("os_id") != "ubuntu" or not str(
        host.get("os_version", "")
    ).startswith("24.04"):
        raise RuntimeError("T3.3 build requires the Ubuntu 24.04 VMware guest")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T3.3 build requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T3.3 build requires Python 3.12.x")
    if "vmware" not in str(host.get("virtualization_product", "")).casefold():
        raise RuntimeError("T3.3 build requires the approved VMware guest")


def mount_type(path: Path) -> str | None:
    try:
        entries = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    resolved = path.resolve()
    matches: list[tuple[int, str]] = []
    for line in entries:
        fields = line.split()
        if "-" not in fields or len(fields) < 7:
            continue
        separator = fields.index("-")
        mountpoint = Path(fields[4].replace("\\040", " "))
        try:
            resolved.relative_to(mountpoint)
        except ValueError:
            continue
        matches.append((len(mountpoint.parts), fields[separator + 1]))
    return max(matches)[1] if matches else None


def require_local_scratch(scratch_root: Path, project_root: Path, output_root: Path) -> None:
    root = scratch_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    for forbidden in (project_root.resolve(), output_root.resolve()):
        if root == forbidden or forbidden in root.parents or root in forbidden.parents:
            raise ValueError("scratch root must be outside the shared project/output tree")
    if root.as_posix().startswith("/mnt/hgfs/"):
        raise ValueError("scratch root must not be on VMware Shared Folders")
    filesystem = mount_type(root)
    if filesystem is not None and (
        filesystem in {"nfs", "nfs4", "cifs", "smb3"} or "fuse" in filesystem or "hgfs" in filesystem
    ):
        raise ValueError(f"scratch root must use a local filesystem, not {filesystem}")


def validate_timezone(contract: Mapping[str, Any]) -> ZoneInfo:
    spec = contract["join"]["candidate_timezone"]
    try:
        zone = ZoneInfo(spec["iana_name"])
    except ZoneInfoNotFoundError as error:
        raise ValueError(f"timezone unavailable: {spec['iana_name']}") from error
    expected = dt.timedelta(seconds=spec["expected_utc_offset_seconds_for_capture_dates"])
    for value in spec["validation_dates"]:
        observed = dt.datetime.fromisoformat(f"{value}T12:00:00").replace(tzinfo=zone).utcoffset()
        if observed != expected:
            raise ValueError(f"candidate timezone offset mismatch on {value}: {observed}")
    return zone


def validate_sources(root: Path, contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    prerequisite = contract["source_evidence"]["inventory_receipt"]
    prerequisite_path = resolve_path(root, prerequisite["path"])
    if sha256_path(prerequisite_path) != prerequisite["sha256"]:
        raise ValueError("T3.1 inventory receipt hash mismatch")
    inventory = load_json(prerequisite_path)
    if inventory.get("task") != prerequisite["task"] or inventory.get("status") != prerequisite["status"]:
        raise ValueError("T3.1 inventory receipt did not pass")
    survey_evidence = contract["exporter"]["parser_exclusion_policy"]["evidence"]
    survey_path = resolve_path(root, survey_evidence["path"])
    if sha256_path(survey_path) != survey_evidence["sha256"]:
        raise ValueError("T1.2 flow survey hash mismatch")
    survey = load_json(survey_path)
    if survey.get("task") != survey_evidence["task"] or survey.get("status") != survey_evidence["status"]:
        raise ValueError("T1.2 flow survey did not pass")
    captures_by_id = {capture["id"]: capture for capture in contract["captures"]}
    expected_exclusions = contract["exporter"]["parser_exclusion_policy"][
        "expected_by_capture"
    ]
    for capture_id, receipt_spec in survey_evidence["file_receipts"].items():
        receipt_path = resolve_path(root, receipt_spec["path"])
        if sha256_path(receipt_path) != receipt_spec["sha256"]:
            raise ValueError(f"T1.2 file survey hash mismatch: {capture_id}")
        receipt = load_json(receipt_path)
        ignored = receipt.get("statistics", {}).get("ignored_packets", {})
        expected = expected_exclusions[capture_id]
        observed = {
            "non_ipv4": ignored.get("non_ipv4"),
            "ipv4_fragmented": ignored.get("ipv4_fragmented"),
            "unsupported_transport": ignored.get("unsupported_transport"),
        }
        if (
            receipt.get("task") != "T1.2"
            or receipt.get("status") != "passed"
            or receipt.get("source", {}).get("name")
            != Path(captures_by_id[capture_id]["pcap"]["path"]).name
            or observed
            != {key: expected[key] for key in observed}
            or sum(observed.values()) != expected["total"]
        ):
            raise ValueError(f"T1.2 file survey evidence mismatch: {capture_id}")
    identities: list[dict[str, Any]] = []
    for capture in contract["captures"]:
        for kind, spec in [("pcap", capture["pcap"]), *[("csv", item) for item in capture["csv"]]]:
            path = resolve_path(root, spec["path"])
            before = path.stat()
            if before.st_size != spec["size_bytes"]:
                raise ValueError(f"source size mismatch: {spec['path']}")
            digest = sha256_path(path)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError(f"source changed while hashing: {spec['path']}")
            if digest != spec["sha256"]:
                raise ValueError(f"source SHA-256 mismatch: {spec['path']}")
            identities.append({
                "capture_id": capture["id"], "kind": kind, "path": spec["path"],
                "size_bytes": after.st_size, "sha256": digest,
            })
    return identities


def create_schema(connection: sqlite3.Connection, contract: Mapping[str, Any]) -> None:
    sqlite_spec = contract["sqlite"]
    connection.execute(f"PRAGMA page_size={sqlite_spec['page_size']}")
    connection.execute(f"PRAGMA application_id={sqlite_spec['application_id']}")
    connection.execute(f"PRAGMA user_version={sqlite_spec['user_version']}")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript("""
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
        CREATE TABLE input_file(
            input_id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL, kind TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL
        ) STRICT;
        CREATE TABLE flow(
            flow_id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL, export_ordinal INTEGER NOT NULL,
            protocol INTEGER NOT NULL, low_ip INTEGER NOT NULL, low_port INTEGER NOT NULL,
            high_ip INTEGER NOT NULL, high_port INTEGER NOT NULL,
            forward_source_ip INTEGER NOT NULL, forward_source_port INTEGER NOT NULL,
            generation INTEGER NOT NULL, creation_timestamp_ns INTEGER NOT NULL,
            last_capture_timestamp_ns INTEGER NOT NULL, last_event_timestamp_ns INTEGER NOT NULL,
            packet_count INTEGER NOT NULL, forward_packet_count INTEGER NOT NULL,
            reverse_packet_count INTEGER NOT NULL, close_reason TEXT NOT NULL,
            UNIQUE(capture_id, export_ordinal)
        ) STRICT;
        CREATE TABLE label_row(
            label_id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL, csv_path TEXT NOT NULL,
            csv_line INTEGER NOT NULL, flow_id_text TEXT NOT NULL,
            source_ip INTEGER NOT NULL, source_port INTEGER NOT NULL,
            destination_ip INTEGER NOT NULL, destination_port INTEGER NOT NULL,
            protocol INTEGER NOT NULL, low_ip INTEGER NOT NULL, low_port INTEGER NOT NULL,
            high_ip INTEGER NOT NULL, high_port INTEGER NOT NULL, timestamp_text TEXT NOT NULL,
            duration_us INTEGER NOT NULL, forward_packet_count INTEGER NOT NULL,
            backward_packet_count INTEGER NOT NULL, label TEXT NOT NULL,
            UNIQUE(csv_path, csv_line)
        ) STRICT;
        CREATE TABLE quarantined_label_row(
            quarantine_id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL,
            csv_path TEXT NOT NULL, csv_line INTEGER NOT NULL, flow_id_text TEXT NOT NULL,
            source_ip INTEGER NOT NULL, source_port INTEGER NOT NULL,
            destination_ip INTEGER NOT NULL, destination_port INTEGER NOT NULL,
            protocol INTEGER NOT NULL, low_ip INTEGER NOT NULL, low_port INTEGER NOT NULL,
            high_ip INTEGER NOT NULL, high_port INTEGER NOT NULL, timestamp_text TEXT NOT NULL,
            duration_us INTEGER NOT NULL, forward_packet_count INTEGER NOT NULL,
            backward_packet_count INTEGER NOT NULL, label TEXT NOT NULL, reason TEXT NOT NULL,
            UNIQUE(csv_path, csv_line)
        ) STRICT;
        CREATE TABLE label_time_variant(
            label_id INTEGER NOT NULL REFERENCES label_row(label_id), variant TEXT NOT NULL,
            start_min_ns INTEGER NOT NULL, start_max_ns INTEGER NOT NULL,
            end_min_ns INTEGER NOT NULL, end_max_ns INTEGER NOT NULL,
            schedule_conflict INTEGER NOT NULL, role_conflict INTEGER NOT NULL,
            event_ids_json TEXT NOT NULL,
            PRIMARY KEY(label_id, variant)
        ) STRICT;
        CREATE TABLE exporter_summary(
            capture_id TEXT PRIMARY KEY, records_read INTEGER NOT NULL,
            packets_parsed INTEGER NOT NULL, parser_errors INTEGER NOT NULL,
            packets_accepted INTEGER NOT NULL, ingest_errors INTEGER NOT NULL,
            exported_flows INTEGER NOT NULL, flows_closed INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE candidate_edge(
            flow_id INTEGER NOT NULL REFERENCES flow(flow_id),
            label_id INTEGER NOT NULL REFERENCES label_row(label_id), variant TEXT NOT NULL,
            required_tolerance_ns INTEGER NOT NULL, schedule_conflict INTEGER NOT NULL,
            role_conflict INTEGER NOT NULL,
            PRIMARY KEY(flow_id, label_id, variant),
            FOREIGN KEY(label_id, variant) REFERENCES label_time_variant(label_id, variant)
        ) STRICT;
        CREATE TABLE sweep_summary(
            tolerance_seconds INTEGER PRIMARY KEY, raw_edge_count INTEGER NOT NULL,
            eligible_edge_count INTEGER NOT NULL, matched_count INTEGER NOT NULL,
            flow_total INTEGER NOT NULL, flow_unmatched INTEGER NOT NULL,
            flow_ambiguous INTEGER NOT NULL, flow_audit_conflict INTEGER NOT NULL,
            label_total INTEGER NOT NULL, label_unmatched INTEGER NOT NULL,
            label_ambiguous INTEGER NOT NULL, label_audit_conflict INTEGER NOT NULL
        ) STRICT;
    """)


def ipv4_int(value: str, name: str) -> int:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError(f"invalid {name}: {value!r}") from error
    if address.version != 4:
        raise ValueError(f"{name} must be IPv4")
    return int(address)


def decimal(value: str, name: str, maximum: int | None = None) -> int:
    text = value.strip()
    if re.fullmatch(r"\d+", text) is None:
        raise ValueError(f"invalid {name}: {value!r}")
    result = int(text)
    if maximum is not None and result > maximum:
        raise ValueError(f"{name} exceeds {maximum}")
    return result


def signed_decimal(value: str, name: str) -> int:
    text = value.strip()
    if re.fullmatch(r"-?\d+", text) is None:
        raise ValueError(f"invalid {name}: {value!r}")
    return int(text)


def canonical(source_ip: int, source_port: int, destination_ip: int, destination_port: int) -> tuple[int, int, int, int]:
    source = (source_ip, source_port)
    destination = (destination_ip, destination_port)
    low, high = sorted((source, destination))
    return low[0], low[1], high[0], high[1]


def datetime_ns(value: dt.datetime) -> int:
    return int(value.timestamp()) * 1_000_000_000 + value.microsecond * 1_000


def timestamp_variants(text: str, contract: Mapping[str, Any], zone: ZoneInfo) -> list[tuple[str, int, int]]:
    parsed: dt.datetime | None = None
    resolution: str | None = None
    for format_text in contract["join"]["timestamp_formats"]:
        try:
            parsed = dt.datetime.strptime(text.strip(), format_text)
            resolution = "second" if "%S" in format_text else "minute"
            break
        except ValueError:
            continue
    if parsed is None or resolution is None:
        raise ValueError(f"invalid DMY timestamp: {text!r}")
    candidates = [("as_written", parsed)]
    if 1 <= parsed.hour <= 11:
        candidates.append(("plus_12h", parsed.replace(hour=parsed.hour + 12)))
    resolution_ns = contract["join"]["timestamp_resolution_ns"][resolution]
    return [(name, datetime_ns(value.replace(tzinfo=zone)), resolution_ns) for name, value in candidates]


def compile_events(contract: Mapping[str, Any], zone: ZoneInfo) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    inclusive_end_ns = (
        60_000_000_000
        if contract["attack_audit"]["schedule_published_minute_end_inclusive"]
        else 0
    )
    for event in contract["attack_audit"]["events"]:
        compiled = {
            "id": event["id"],
            "intervals": [
                (datetime_ns(dt.datetime.fromisoformat(start).replace(tzinfo=zone)),
                 datetime_ns(dt.datetime.fromisoformat(end).replace(tzinfo=zone))
                 + inclusive_end_ns)
                for start, end in event["intervals"]
            ],
            "role_assertion": event["role_assertion"],
            "attackers": {int(ipaddress.ip_address(value)) for value in event["attackers"]},
            "victims": {int(ipaddress.ip_address(value)) for value in event["victims"]},
        }
        for label in event["labels"]:
            result.setdefault(label, []).append(compiled)
    return result


def audit_variant(
    label: str,
    source_ip: int,
    destination_ip: int,
    start_ns: int,
    end_ns: int,
    contract: Mapping[str, Any],
    events: Mapping[str, list[dict[str, Any]]],
) -> tuple[int, int, str]:
    if label == contract["attack_audit"]["benign_label"]:
        return 0, 0, "[]"
    tolerance = contract["attack_audit"]["schedule_audit_tolerance_seconds"] * 1_000_000_000
    scheduled: list[dict[str, Any]] = []
    for event in events[label]:
        if any(start_ns < end + tolerance and end_ns > start - tolerance for start, end in event["intervals"]):
            scheduled.append(event)
    if not scheduled:
        return 1, 0, "[]"
    endpoints = {source_ip, destination_ip}
    role_ok = any(
        event["role_assertion"] == "not_asserted"
        or bool(endpoints & event["attackers"]) and bool(endpoints & event["victims"])
        for event in scheduled
    )
    return 0, 0 if role_ok else 1, json.dumps(
        sorted(event["id"] for event in scheduled), separators=(",", ":")
    )


def flush_rows(
    connection: sqlite3.Connection,
    labels: list[tuple[Any, ...]],
    variants: list[tuple[Any, ...]],
    quarantined: list[tuple[Any, ...]],
) -> None:
    connection.executemany("INSERT INTO label_row VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", labels)
    connection.executemany("INSERT INTO label_time_variant VALUES(?,?,?,?,?,?,?,?,?)", variants)
    connection.executemany(
        "INSERT INTO quarantined_label_row VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        quarantined,
    )
    connection.commit()
    labels.clear()
    variants.clear()
    quarantined.clear()


def ingest_labels(connection: sqlite3.Connection, root: Path, contract: Mapping[str, Any], zone: ZoneInfo) -> dict[str, Any]:
    schema = contract["csv_schema"]
    events = compile_events(contract, zone)
    label_id = 0
    quarantine_id = 0
    totals = {"physical_records": 0, "all_empty_records": 0, "nonempty_records": 0, "timestamp_variants": 0}
    for capture in contract["captures"]:
        for spec in capture["csv"]:
            path = resolve_path(root, spec["path"])
            physical = empty = nonempty = 0
            counts: Counter[str] = Counter()
            protocol_counts: Counter[str] = Counter()
            negative_duration_count = 0
            label_batch: list[tuple[Any, ...]] = []
            variant_batch: list[tuple[Any, ...]] = []
            quarantine_batch: list[tuple[Any, ...]] = []
            with path.open("r", encoding=schema["encoding"], newline="") as source:
                reader = csv.reader(source)
                try:
                    header = [value.strip() for value in next(reader)]
                except StopIteration as error:
                    raise ValueError(f"empty CSV: {spec['path']}") from error
                if len(header) != schema["header_field_count"]:
                    raise ValueError(f"CSV header width mismatch: {spec['path']}")
                duplicates = Counter(header)
                observed = {name: count for name, count in duplicates.items() if count > 1}
                if observed != schema["duplicate_trimmed_headers"]:
                    raise ValueError(f"CSV duplicate header mismatch: {spec['path']}")
                positions = {}
                for name in schema["required_columns"]:
                    if header.count(name) != 1:
                        raise ValueError(f"required CSV column is not unique: {name}")
                    positions[name] = header.index(name)
                for csv_line, row in enumerate(reader, start=2):
                    physical += 1
                    if len(row) == schema["header_field_count"] and all(not value.strip() for value in row):
                        empty += 1
                        continue
                    if len(row) != schema["header_field_count"]:
                        raise ValueError(f"nonempty malformed CSV record {spec['path']}:{csv_line}")
                    values = {name: row[index].strip() for name, index in positions.items()}
                    if any(not value for value in values.values()):
                        raise ValueError(f"empty required field {spec['path']}:{csv_line}")
                    source_ip = ipv4_int(values["Source IP"], "Source IP")
                    destination_ip = ipv4_int(values["Destination IP"], "Destination IP")
                    source_port = decimal(values["Source Port"], "Source Port", 65535)
                    destination_port = decimal(values["Destination Port"], "Destination Port", 65535)
                    protocol = decimal(values["Protocol"], "Protocol", 255)
                    duration_us = signed_decimal(values["Flow Duration"], "Flow Duration")
                    forward = decimal(values["Total Fwd Packets"], "Total Fwd Packets")
                    backward = decimal(values["Total Backward Packets"], "Total Backward Packets")
                    label = values["Label"]
                    if label not in spec["label_counts"]:
                        raise ValueError(f"unexpected label {label!r} in {spec['path']}")
                    low_ip, low_port, high_ip, high_port = canonical(
                        source_ip, source_port, destination_ip, destination_port
                    )
                    nonempty += 1
                    counts[label] += 1
                    protocol_counts[str(protocol)] += 1
                    if duration_us < 0:
                        negative_duration_count += 1
                    if str(protocol) not in contract["join"]["protocols"]:
                        policy = contract["join"]["unsupported_label_protocol_policy"]
                        if protocol not in policy["values"]:
                            raise ValueError(
                                f"unsupported label protocol {protocol} at {spec['path']}:{csv_line}"
                            )
                        if duration_us < 0:
                            raise ValueError(
                                f"unsupported protocol with negative Flow Duration at "
                                f"{spec['path']}:{csv_line}"
                            )
                    elif duration_us < 0:
                        policy = contract["join"]["invalid_flow_duration_policy"]
                    else:
                        policy = None
                    if policy is not None:
                        timestamp_variants(values["Timestamp"], contract, zone)
                        quarantine_id += 1
                        quarantine_batch.append((
                            quarantine_id, capture["id"], spec["path"], csv_line,
                            values["Flow ID"], source_ip, source_port, destination_ip,
                            destination_port, protocol, low_ip, low_port, high_ip, high_port,
                            values["Timestamp"], duration_us, forward, backward, label,
                            policy["reason"],
                        ))
                        if len(quarantine_batch) >= BATCH_SIZE:
                            flush_rows(
                                connection, label_batch, variant_batch, quarantine_batch
                            )
                        continue
                    label_id += 1
                    label_batch.append((
                        label_id, capture["id"], spec["path"], csv_line, values["Flow ID"],
                        source_ip, source_port, destination_ip, destination_port, protocol,
                        low_ip, low_port, high_ip, high_port, values["Timestamp"], duration_us,
                        forward, backward, label,
                    ))
                    for variant, start_min, resolution_ns in timestamp_variants(
                        values["Timestamp"], contract, zone
                    ):
                        start_max = start_min + resolution_ns
                        end_min = start_min + duration_us * 1_000
                        end_max = start_max + duration_us * 1_000
                        schedule_conflict, role_conflict, event_ids = audit_variant(
                            label, source_ip, destination_ip, start_min, end_max,
                            contract, events,
                        )
                        variant_batch.append((
                            label_id, variant, start_min, start_max, end_min, end_max,
                            schedule_conflict, role_conflict, event_ids,
                        ))
                    if len(label_batch) >= BATCH_SIZE:
                        flush_rows(connection, label_batch, variant_batch, quarantine_batch)
            if label_batch or quarantine_batch:
                flush_rows(connection, label_batch, variant_batch, quarantine_batch)
            if (
                physical != spec["physical_record_count"]
                or empty != spec["all_empty_record_count"]
                or nonempty != spec["nonempty_record_count"]
                or dict(sorted(counts.items())) != dict(sorted(spec["label_counts"].items()))
                or dict(sorted(protocol_counts.items()))
                != dict(sorted(spec["protocol_counts"].items()))
                or negative_duration_count != spec["negative_duration_count"]
            ):
                raise ValueError(f"CSV accounting mismatch: {spec['path']}")
            totals["physical_records"] += physical
            totals["all_empty_records"] += empty
            totals["nonempty_records"] += nonempty
    totals["timestamp_variants"] = connection.execute(
        "SELECT COUNT(*) FROM label_time_variant"
    ).fetchone()[0]
    totals["eligible_records"] = connection.execute(
        "SELECT COUNT(*) FROM label_row"
    ).fetchone()[0]
    totals["quarantined_records"] = connection.execute(
        "SELECT COUNT(*) FROM quarantined_label_row"
    ).fetchone()[0]
    totals["quarantine_reason_counts"] = dict(
        connection.execute(
            "SELECT reason,COUNT(*) FROM quarantined_label_row GROUP BY reason ORDER BY reason"
        )
    )
    if totals["nonempty_records"] != totals["eligible_records"] + totals["quarantined_records"]:
        raise ValueError("eligible/quarantine label accounting failed")
    return totals


def parse_json_line(line: str, context: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid exporter JSON at {context}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"exporter JSON is not an object at {context}")
    return value


def exporter_command(exporter: Path, pcap: Path, capture_id: str) -> list[str]:
    prefix = [sys.executable, str(exporter)] if exporter.suffix.casefold() == ".py" else [str(exporter)]
    return [*prefix, "--input", str(pcap), "--capture-id", capture_id]


def validate_flow(value: Mapping[str, Any], capture_id: str) -> tuple[Any, ...]:
    if set(value) != FLOW_KEYS or value.get("schema_version") != 1 or value.get("task") != TASK or value.get("kind") != "flow":
        raise ValueError("exporter flow schema mismatch")
    if value.get("capture_id") != capture_id or value.get("clock_domain") != "unix_epoch":
        raise ValueError("exporter flow identity/clock mismatch")
    protocol_name = value.get("protocol")
    if protocol_name not in {"tcp", "udp"}:
        raise ValueError("exporter flow protocol mismatch")
    protocol = 6 if protocol_name == "tcp" else 17
    low_ip = ipv4_int(str(value.get("low_ip")), "low_ip")
    high_ip = ipv4_int(str(value.get("high_ip")), "high_ip")
    low_port = integer(value.get("low_port"), "low_port")
    high_port = integer(value.get("high_port"), "high_port")
    if low_port > 65535 or high_port > 65535 or (low_ip, low_port) > (high_ip, high_port):
        raise ValueError("exporter canonical tuple mismatch")
    forward_ip = ipv4_int(str(value.get("forward_source_ip")), "forward_source_ip")
    forward_port = integer(value.get("forward_source_port"), "forward_source_port")
    if (forward_ip, forward_port) not in {(low_ip, low_port), (high_ip, high_port)}:
        raise ValueError("exporter forward source is not a tuple endpoint")
    fields = [
        integer(value.get("generation"), "generation"),
        integer(value.get("creation_timestamp_ns"), "creation_timestamp_ns", -(1 << 63)),
        integer(value.get("last_capture_timestamp_ns"), "last_capture_timestamp_ns", -(1 << 63)),
        integer(value.get("last_event_timestamp_ns"), "last_event_timestamp_ns", -(1 << 63)),
        integer(value.get("packet_count"), "packet_count", 1),
        integer(value.get("forward_packet_count"), "forward_packet_count"),
        integer(value.get("reverse_packet_count"), "reverse_packet_count"),
    ]
    if fields[1] > fields[3]:
        raise ValueError(
            "exporter flow event-time bounds mismatch: "
            f"creation_timestamp_ns={fields[1]} "
            f"last_capture_timestamp_ns={fields[2]} "
            f"last_event_timestamp_ns={fields[3]}"
        )
    if fields[4] != fields[5] + fields[6]:
        raise ValueError(
            "exporter flow packet accounting mismatch: "
            f"packet_count={fields[4]} "
            f"forward_packet_count={fields[5]} "
            f"reverse_packet_count={fields[6]}"
        )
    close_reason = value.get("close_reason")
    if close_reason not in {
        "idle_timeout", "maximum_age", "tcp_reset", "tcp_fin_handshake",
        "tuple_reuse", "capacity_eviction", "end_of_input",
    }:
        raise ValueError("exporter close reason mismatch")
    return (
        protocol, low_ip, low_port, high_ip, high_port, forward_ip, forward_port,
        *fields, close_reason,
    )


def validate_summary(
    value: Mapping[str, Any],
    capture_id: str,
    flow_count: int,
    expected_input: Path | None = None,
    expected_parser_exclusions: int = 0,
) -> dict[str, int]:
    if set(value) != SUMMARY_KEYS or value.get("schema_version") != 1 or value.get("task") != TASK or value.get("kind") != "summary":
        raise ValueError("exporter summary schema mismatch")
    if value.get("capture_id") != capture_id or value.get("status") != "passed":
        raise ValueError("exporter summary status/capture mismatch")
    if expected_input is not None:
        input_value = value.get("input")
        if not isinstance(input_value, str) or Path(input_value).resolve() != expected_input.resolve():
            raise ValueError("exporter summary input mismatch")
    pcap = value.get("pcap")
    flows = value.get("flows")
    if not isinstance(pcap, Mapping) or not isinstance(flows, Mapping):
        raise ValueError("exporter summary counters missing")
    counters = {
        "records_read": integer(pcap.get("records_read"), "records_read"),
        "packets_parsed": integer(pcap.get("packets_parsed"), "packets_parsed"),
        "parser_errors": integer(value.get("parser_errors"), "parser_errors"),
        "packets_accepted": integer(flows.get("packets_accepted"), "packets_accepted"),
        "ingest_errors": integer(value.get("ingest_errors"), "ingest_errors"),
        "exported_flows": integer(value.get("exported_flows"), "exported_flows"),
        "flows_closed": integer(flows.get("flows_closed"), "flows_closed"),
    }
    if pcap.get("parser_errors") != counters["parser_errors"]:
        raise ValueError(
            f"exporter parser counters disagree for {capture_id}: "
            f"pcap.parser_errors={pcap.get('parser_errors')} "
            f"parser_errors={counters['parser_errors']}"
        )
    if counters["parser_errors"] != expected_parser_exclusions:
        raise ValueError(
            f"exporter parser exclusion count mismatch for {capture_id}: "
            f"expected={expected_parser_exclusions} "
            f"observed={counters['parser_errors']}"
        )
    if counters["ingest_errors"] != 0:
        raise ValueError(
            f"exporter ingest errors are fatal for {capture_id}: "
            f"ingest_errors={counters['ingest_errors']}"
        )
    if (
        counters["records_read"]
        != counters["packets_parsed"] + counters["parser_errors"]
        or counters["packets_accepted"] != counters["packets_parsed"]
    ):
        raise ValueError(
            f"exporter packet accounting mismatch for {capture_id}: "
            f"records_read={counters['records_read']} "
            f"packets_parsed={counters['packets_parsed']} "
            f"parser_exclusions={counters['parser_errors']} "
            f"packets_accepted={counters['packets_accepted']}"
        )
    if counters["exported_flows"] != flow_count or counters["flows_closed"] != flow_count:
        raise ValueError("exporter flow accounting mismatch")
    if flows.get("flow_generations_created") != flow_count or flows.get("active_flow_count") != 0:
        raise ValueError("exporter flow lifecycle mismatch")
    return counters


def ingest_flows(
    connection: sqlite3.Connection,
    root: Path,
    exporter: Path,
    contract: Mapping[str, Any],
    scratch: Path,
) -> list[dict[str, Any]]:
    flow_id = 0
    summaries: list[dict[str, Any]] = []
    for capture in contract["captures"]:
        pcap = resolve_path(root, capture["pcap"]["path"])
        stderr_path = scratch / f"{capture['id']}.stderr"
        batch: list[tuple[Any, ...]] = []
        flow_count = 0
        summary: dict[str, Any] | None = None
        with stderr_path.open("w+", encoding="utf-8", newline="\n") as stderr:
            process = subprocess.Popen(
                exporter_command(exporter, pcap, capture["id"]),
                cwd=root, stdout=subprocess.PIPE, stderr=stderr, text=True,
                encoding="utf-8", errors="strict", bufsize=1,
            )
            assert process.stdout is not None
            try:
                for line_number, line in enumerate(process.stdout, start=1):
                    if len(line) > 1024 * 1024:
                        raise ValueError("exporter JSON line exceeds 1 MiB")
                    value = parse_json_line(line, f"{capture['id']}:{line_number}")
                    if value.get("kind") == "summary":
                        if summary is not None:
                            raise ValueError("exporter emitted more than one summary")
                        summary = value
                        continue
                    if summary is not None:
                        raise ValueError("exporter emitted flow after summary")
                    try:
                        fields = validate_flow(value, capture["id"])
                    except ValueError as error:
                        raise ValueError(
                            f"invalid exporter flow at {capture['id']}:{line_number}: {error}"
                        ) from error
                    flow_id += 1
                    flow_count += 1
                    batch.append((flow_id, capture["id"], flow_count, *fields))
                    if len(batch) >= BATCH_SIZE:
                        connection.executemany("INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                        connection.commit()
                        batch.clear()
                return_code = process.wait()
            except Exception:
                process.terminate()
                process.wait(timeout=10)
                raise
            finally:
                process.stdout.close()
            if batch:
                connection.executemany("INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                connection.commit()
            stderr.seek(0)
            error_text = stderr.read()
        if return_code != 0:
            raise ValueError(f"exporter failed for {capture['id']} rc={return_code}: {error_text[-2000:]}")
        if summary is None:
            raise ValueError(f"exporter omitted summary for {capture['id']}")
        expected_parser_exclusions = contract["exporter"][
            "parser_exclusion_policy"
        ]["expected_by_capture"][capture["id"]]["total"]
        counters = validate_summary(
            summary,
            capture["id"],
            flow_count,
            pcap,
            expected_parser_exclusions,
        )
        connection.execute(
            "INSERT INTO exporter_summary VALUES(?,?,?,?,?,?,?,?)",
            (capture["id"], *counters.values()),
        )
        connection.commit()
        summaries.append({"capture_id": capture["id"], **counters})
    return summaries


def build_edges(connection: sqlite3.Connection, contract: Mapping[str, Any]) -> int:
    maximum = contract["join"]["maximum_candidate_tolerance_seconds"] * 1_000_000_000
    connection.executescript("""
        CREATE INDEX flow_join_idx ON flow(capture_id, protocol, low_ip, low_port, high_ip, high_port, creation_timestamp_ns, last_event_timestamp_ns);
        CREATE INDEX label_join_idx ON label_row(capture_id, protocol, low_ip, low_port, high_ip, high_port);
        CREATE INDEX variant_time_idx ON label_time_variant(start_min_ns, end_max_ns);
    """)
    connection.execute("""
        INSERT INTO candidate_edge
        SELECT f.flow_id, l.label_id, v.variant,
               CASE
                   WHEN f.last_event_timestamp_ns < v.start_min_ns THEN v.start_min_ns - f.last_event_timestamp_ns
                   WHEN v.end_max_ns <= f.creation_timestamp_ns THEN f.creation_timestamp_ns - v.end_max_ns + 1
                   ELSE 0
               END,
               v.schedule_conflict, v.role_conflict
        FROM flow AS f
        JOIN label_row AS l
          ON l.capture_id=f.capture_id AND l.protocol=f.protocol
         AND l.low_ip=f.low_ip AND l.low_port=f.low_port
         AND l.high_ip=f.high_ip AND l.high_port=f.high_port
        JOIN label_time_variant AS v ON v.label_id=l.label_id
        WHERE f.last_event_timestamp_ns + ? >= v.start_min_ns
          AND v.end_max_ns + ? > f.creation_timestamp_ns
    """, (maximum, maximum))
    connection.commit()
    connection.execute("CREATE INDEX edge_tolerance_idx ON candidate_edge(required_tolerance_ns, schedule_conflict, role_conflict)")
    connection.execute("CREATE INDEX edge_label_idx ON candidate_edge(label_id, required_tolerance_ns)")
    connection.commit()
    return connection.execute("SELECT COUNT(*) FROM candidate_edge").fetchone()[0]


def compute_sweeps(connection: sqlite3.Connection, contract: Mapping[str, Any]) -> list[dict[str, int]]:
    flow_total = connection.execute("SELECT COUNT(*) FROM flow").fetchone()[0]
    label_total = connection.execute("SELECT COUNT(*) FROM label_row").fetchone()[0]
    results: list[dict[str, int]] = []
    for seconds in contract["join"]["tolerance_sweep_seconds"]:
        tolerance = seconds * 1_000_000_000
        connection.executescript("""
            DROP TABLE IF EXISTS temp.raw_pair;
            DROP TABLE IF EXISTS temp.eligible_pair;
            DROP TABLE IF EXISTS temp.raw_flow_degree;
            DROP TABLE IF EXISTS temp.raw_label_degree;
            DROP TABLE IF EXISTS temp.flow_degree;
            DROP TABLE IF EXISTS temp.label_degree;
            DROP TABLE IF EXISTS temp.matched_pair;
            CREATE TEMP TABLE raw_pair(flow_id INTEGER, label_id INTEGER, PRIMARY KEY(flow_id,label_id)) WITHOUT ROWID;
            CREATE TEMP TABLE eligible_pair(flow_id INTEGER, label_id INTEGER, PRIMARY KEY(flow_id,label_id)) WITHOUT ROWID;
        """)
        connection.execute(
            "INSERT INTO raw_pair SELECT DISTINCT flow_id,label_id FROM candidate_edge WHERE required_tolerance_ns<=?",
            (tolerance,),
        )
        connection.execute(
            "INSERT INTO eligible_pair SELECT DISTINCT flow_id,label_id FROM candidate_edge WHERE required_tolerance_ns<=? AND schedule_conflict=0 AND role_conflict=0",
            (tolerance,),
        )
        connection.executescript("""
            CREATE TEMP TABLE raw_flow_degree AS SELECT flow_id,COUNT(*) degree FROM raw_pair GROUP BY flow_id;
            CREATE TEMP TABLE raw_label_degree AS SELECT label_id,COUNT(*) degree FROM raw_pair GROUP BY label_id;
            CREATE TEMP TABLE flow_degree AS SELECT flow_id,COUNT(*) degree FROM eligible_pair GROUP BY flow_id;
            CREATE TEMP TABLE label_degree AS SELECT label_id,COUNT(*) degree FROM eligible_pair GROUP BY label_id;
            CREATE TEMP TABLE matched_pair AS
                SELECT e.flow_id,e.label_id FROM eligible_pair e
                JOIN flow_degree f ON f.flow_id=e.flow_id AND f.degree=1
                JOIN label_degree l ON l.label_id=e.label_id AND l.degree=1;
        """)
        def scalar(sql: str) -> int:
            return connection.execute(sql).fetchone()[0]
        matched = scalar("SELECT COUNT(*) FROM matched_pair")
        flow_unmatched = flow_total - scalar("SELECT COUNT(*) FROM raw_flow_degree")
        flow_conflict = scalar("SELECT COUNT(*) FROM raw_flow_degree r LEFT JOIN flow_degree e USING(flow_id) WHERE e.flow_id IS NULL")
        flow_ambiguous = flow_total - matched - flow_unmatched - flow_conflict
        label_unmatched = label_total - scalar("SELECT COUNT(*) FROM raw_label_degree")
        label_conflict = scalar("SELECT COUNT(*) FROM raw_label_degree r LEFT JOIN label_degree e USING(label_id) WHERE e.label_id IS NULL")
        label_ambiguous = label_total - matched - label_unmatched - label_conflict
        row = {
            "tolerance_seconds": seconds,
            "raw_edge_count": scalar("SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<=" + str(tolerance)),
            "eligible_edge_count": scalar("SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<=" + str(tolerance) + " AND schedule_conflict=0 AND role_conflict=0"),
            "matched_count": matched,
            "flow_total": flow_total,
            "flow_unmatched": flow_unmatched,
            "flow_ambiguous": flow_ambiguous,
            "flow_audit_conflict": flow_conflict,
            "label_total": label_total,
            "label_unmatched": label_unmatched,
            "label_ambiguous": label_ambiguous,
            "label_audit_conflict": label_conflict,
        }
        if flow_total != matched + flow_unmatched + flow_ambiguous + flow_conflict:
            raise ValueError("flow sweep accounting failed")
        if label_total != matched + label_unmatched + label_ambiguous + label_conflict:
            raise ValueError("label sweep accounting failed")
        connection.execute(
            "INSERT INTO sweep_summary VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(row.values()),
        )
        results.append(row)
    connection.commit()
    return results


def write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists() or os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary = output.name
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
        raise


def copy_atomic(source: Path, destination: Path) -> None:
    if destination.exists() or os.path.lexists(destination):
        raise ValueError(f"refusing to overwrite existing file: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with source.open("rb") as input_file, tempfile.NamedTemporaryFile(
            "wb", dir=destination.parent, prefix=f".{destination.name}.",
            suffix=".tmp", delete=False,
        ) as output:
            temporary = output.name
            shutil.copyfileobj(input_file, output, READ_SIZE)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except Exception:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
        raise


def check_database(path: Path) -> None:
    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if integrity != [("ok",)] or foreign_keys:
            raise ValueError("SQLite integrity or foreign-key check failed")
    finally:
        connection.close()


@contextmanager
def scratch_directory(root: Path) -> Iterable[Path]:
    path = root.resolve() / f"nids-t3.3-{uuid.uuid4().hex}"
    path.mkdir(parents=False, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def build_join(
    project_root: Path,
    contract_path: Path,
    exporter: Path,
    scratch_root: Path,
    enforce_environment: bool = True,
) -> dict[str, Any]:
    root = project_root.resolve()
    contract_path = contract_path.resolve()
    contract = load_json(contract_path)
    errors = validate_contract(contract)
    if errors:
        raise ValueError(f"invalid T3.3 contract: {errors}")
    if contract_path != root / "config" / "cicids2017-label-join-contract.json":
        raise ValueError("contract must be the project T3.3 contract")
    output_db = resolve_path(root, contract["sqlite"]["artifact"])
    output_receipt = resolve_path(root, contract["sqlite"]["build_receipt"])
    if output_db.exists() or output_receipt.exists():
        raise ValueError("refusing to overwrite T3.3 build artifacts")
    host = inspect_host()
    if enforce_environment:
        require_supported_host(host)
        require_local_scratch(scratch_root, root, output_db.parent)
    if not exporter.resolve().is_file():
        raise ValueError(f"exporter does not exist: {exporter}")
    zone = validate_timezone(contract)
    source_identities = validate_sources(root, contract)
    contract_sha256 = sha256_path(contract_path)
    exporter_sha256 = sha256_path(exporter)
    created_db = False
    with scratch_directory(scratch_root) as scratch:
        database = scratch / "label-join.sqlite3"
        connection = sqlite3.connect(database)
        try:
            create_schema(connection, contract)
            connection.executemany(
                "INSERT INTO metadata VALUES(?,?)",
                [
                    ("schema_version", SCHEMA_VERSION), ("task", TASK),
                    ("contract_sha256", contract_sha256),
                    ("exporter_sha256", exporter_sha256),
                    ("candidate_timezone", contract["join"]["candidate_timezone"]["iana_name"]),
                    ("timezone_status", contract["join"]["candidate_timezone"]["status"]),
                    ("decision", contract["join"]["decision"]),
                ],
            )
            connection.executemany(
                "INSERT INTO input_file(capture_id,kind,path,size_bytes,sha256) VALUES(?,?,?,?,?)",
                [(item["capture_id"], item["kind"], item["path"], item["size_bytes"], item["sha256"]) for item in source_identities],
            )
            connection.commit()
            label_totals = ingest_labels(connection, root, contract, zone)
            exporter_summaries = ingest_flows(connection, root, exporter.resolve(), contract, scratch)
            edge_count = build_edges(connection, contract)
            sweeps = compute_sweeps(connection, contract)
            connection.execute("PRAGMA optimize")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("VACUUM")
            connection.commit()
        finally:
            connection.close()
        if database.with_name(database.name + "-wal").exists() or database.with_name(database.name + "-shm").exists():
            raise ValueError("SQLite WAL/SHM remained after clean close")
        check_database(database)
        copy_atomic(database, output_db)
        created_db = True
    try:
        artifact = {
            "path": relative_path(output_db, root),
            "size_bytes": output_db.stat().st_size,
            "sha256": sha256_path(output_db),
            "application_id": contract["sqlite"]["application_id"],
            "user_version": contract["sqlite"]["user_version"],
            "journal_mode": "delete",
            "integrity_check": "ok",
        }
        flow_total = sum(item["exported_flows"] for item in exporter_summaries)
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "task": TASK,
            "kind": KIND,
            "status": "passed",
            "generated_at_utc": utc_now(),
            "host": host,
            "contract": {"path": relative_path(contract_path, root), "sha256": contract_sha256},
            "exporter": {"path": str(exporter.resolve()), "sha256": exporter_sha256, "summaries": exporter_summaries},
            "sources": source_identities,
            "labels": label_totals,
            "flows": {"total": flow_total},
            "candidate_edges": edge_count,
            "sweeps": sweeps,
            "sqlite": artifact,
            "checks": [
                {"name": "sources.content_addressed_before_processing", "status": "passed"},
                {"name": "exporter.strict_jsonl_contract", "status": "passed"},
                {"name": "exporter.exact_parser_exclusions_and_zero_ingest_errors", "status": "passed"},
                {"name": "labels.unsupported_protocol_quarantined", "status": "passed"},
                {"name": "labels.invalid_flow_duration_quarantined", "status": "passed"},
                {"name": "join.fail_closed_mutual_uniqueness", "status": "passed"},
                {"name": "join.sweep_accounting", "status": "passed"},
                {"name": "sqlite.local_single_writer_then_copy", "status": "passed"},
                {"name": "sqlite.integrity", "status": "passed"},
            ],
        }
        write_json_atomic(output_receipt, receipt)
        return receipt
    except Exception:
        if created_db:
            output_db.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root)
    parser.add_argument("--contract", type=Path, default=root / "config" / "cicids2017-label-join-contract.json")
    parser.add_argument("--exporter", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, default=Path("/tmp"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = build_join(
            args.project_root, args.contract, args.exporter, args.scratch_root,
            enforce_environment=True,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {receipt['sqlite']['path']} and T3.3 build receipt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
