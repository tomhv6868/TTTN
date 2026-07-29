#!/usr/bin/env python3
"""Build and validate one atomic T9.1 terminal-flow SQLite shard."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import platform
import shutil
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T9.1"
KIND = "terminal_flow_shard"
MANIFEST_KIND = "terminal_flow_shard_manifest"
DATABASE_NAME = "terminal-flow-shard.sqlite3"
MANIFEST_NAME = "manifest.json"
APPLICATION_ID = 0x4E543931
USER_VERSION = 1
FEATURE_SCHEMA_ID = "nids.terminal_flow_features.v1"
FEATURE_COUNT = 70
FEATURE_BLOB_SIZE = FEATURE_COUNT * 8
FEATURE_SCHEMA_PATH = Path("config/terminal-flow-feature-schema-v1.json")
FEATURE_SCHEMA_SHA256 = (
    "ebe260327df74e265c2dc89178e3d038c3183de55603187c4b1e503e06173dfc"
)
SOURCE_DATABASE_PATH = Path("run_log/t3.3/label-join.sqlite3")
SOURCE_DATABASE_SIZE = 2_656_702_464
SOURCE_DATABASE_SHA256 = (
    "a97054a39fe25c8c96e42b2f335069d964b65b898e77783167cd9aa61eb097ca"
)
SOURCE_APPLICATION_ID = 1_313_424_467
SOURCE_USER_VERSION = 304
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
MAX_JSON_LINE_BYTES = 64 * 1024
COMMIT_ROWS = 10_000
HEARTBEAT_SECONDS = 30

PROTOCOLS = {"tcp": 6, "udp": 17}
CLOCK_DOMAIN = "unix_epoch"
CLOSE_REASONS = (
    "idle_timeout",
    "maximum_age",
    "tcp_reset",
    "tcp_fin_handshake",
    "tuple_reuse",
    "capacity_eviction",
    "end_of_input",
)
IDENTITY_FIELDS = {
    "protocol",
    "low_ip",
    "low_port",
    "high_ip",
    "high_port",
    "forward_source_ip",
    "forward_source_port",
}
TERMINAL_FLOW_FIELDS = {
    "schema_version",
    "task",
    "kind",
    "feature_schema_id",
    "feature_count",
    "capture_id",
    "export_ordinal",
    *IDENTITY_FIELDS,
    "generation",
    "clock_domain",
    "creation_timestamp_ns",
    "last_capture_timestamp_ns",
    "last_event_timestamp_ns",
    "packet_count",
    "forward_packet_count",
    "reverse_packet_count",
    "close_reason",
    "features",
}
SUMMARY_FIELDS = {
    "schema_version",
    "task",
    "kind",
    "status",
    "feature_schema_id",
    "feature_count",
    "input",
    "capture_id",
    "pcap",
    "flows",
    "exported_flows",
    "parser_errors",
    "ingest_errors",
    "terminal_feature_errors",
}
FAILURE_ONLY_FIELDS = {
    "failure",
    "failure_record_number",
    "ingest_status",
    "terminal_feature_error",
    "pcap_error",
    "pcap_error_detail",
}
PCAP_SUMMARY_FIELDS = {
    "records_read",
    "packets_parsed",
    "parser_errors",
    "captured_bytes",
    "wire_bytes",
}
FLOW_SUMMARY_FIELDS = {
    "packets_accepted",
    "packets_rejected_clock_domain",
    "packets_rejected_timestamp_overflow",
    "packets_rejected_feature_update",
    "packets_rejected_resource_exhausted",
    "flow_generations_created",
    "flows_closed",
    "active_flow_count",
    "peak_active_flow_count",
    "fixed_memory_bytes",
    "current_allocator_bytes",
    "peak_allocator_bytes",
    "current_memory_bytes",
    "peak_memory_bytes",
    "memory_budget_bytes",
    "close_reason_count",
}
SOURCE_FLOW_FIELDS = (
    "capture_id",
    "export_ordinal",
    "protocol",
    "low_ip",
    "low_port",
    "high_ip",
    "high_port",
    "forward_source_ip",
    "forward_source_port",
    "generation",
    "creation_timestamp_ns",
    "last_capture_timestamp_ns",
    "last_event_timestamp_ns",
    "packet_count",
    "forward_packet_count",
    "reverse_packet_count",
    "close_reason",
)
SUMMARY_VALUE_COLUMNS = (
    "records_read",
    "packets_parsed",
    "parser_errors",
    "captured_bytes",
    "wire_bytes",
    "packets_accepted",
    "packets_rejected_clock_domain",
    "packets_rejected_timestamp_overflow",
    "packets_rejected_feature_update",
    "packets_rejected_resource_exhausted",
    "flow_generations_created",
    "flows_closed",
    "active_flow_count",
    "peak_active_flow_count",
    "fixed_memory_bytes",
    "current_allocator_bytes",
    "peak_allocator_bytes",
    "current_memory_bytes",
    "peak_memory_bytes",
    "memory_budget_bytes",
    "close_idle_timeout",
    "close_maximum_age",
    "close_tcp_reset",
    "close_tcp_fin_handshake",
    "close_tuple_reuse",
    "close_capacity_eviction",
    "close_end_of_input",
    "exported_flows",
    "ingest_errors",
    "terminal_feature_errors",
)
TABLE_COLUMNS = {
    "metadata": {"key", "value"},
    "terminal_flow": {
        "flow_id",
        "export_ordinal",
        "generation",
        "capture_id",
        "protocol",
        "low_ip",
        "low_port",
        "high_ip",
        "high_port",
        "forward_source_ip",
        "forward_source_port",
        "clock_domain",
        "creation_timestamp_ns",
        "last_capture_timestamp_ns",
        "last_event_timestamp_ns",
        "packet_count",
        "forward_packet_count",
        "reverse_packet_count",
        "close_reason",
        "features",
    },
    "exporter_summary": {"capture_id", *SUMMARY_VALUE_COLUMNS},
}
METADATA_KEYS = {
    "schema_version",
    "task",
    "kind",
    "capture_id",
    "feature_schema_id",
    "feature_schema_sha256",
    "producer_sha256",
    "exporter_sha256",
    "source_database_sha256",
    "source_pcap_sha256",
    "float_encoding",
}
MANIFEST_FIELDS = {
    "schema_version",
    "task",
    "kind",
    "status",
    "capture_id",
    "generated_at_utc",
    "elapsed_seconds",
    "producer",
    "exporter",
    "feature_schema",
    "source_database",
    "source",
    "database",
    "summary",
    "oracle_reconciliation",
}
REQUIRED_SOURCE_COLUMNS = {
    "input_file": {"capture_id", "kind", "path", "size_bytes", "sha256"},
    "flow": {"flow_id", *SOURCE_FLOW_FIELDS},
    "exporter_summary": {
        "capture_id",
        "records_read",
        "packets_parsed",
        "parser_errors",
        "packets_accepted",
        "ingest_errors",
        "exported_flows",
        "flows_closed",
    },
}


@dataclass(frozen=True)
class FeatureSchema:
    path: Path
    sha256: str
    unsigned_limits: tuple[int | None, ...]


@dataclass(frozen=True)
class CaptureSource:
    capture_id: str
    path_text: str
    path: Path
    size_bytes: int
    sha256: str
    summary: Mapping[str, int]


@dataclass(frozen=True)
class BuildInputs:
    root: Path
    source_database: Path
    source_database_sha256: str
    feature_schema: FeatureSchema
    capture: CaptureSource
    exporter: Path
    exporter_sha256: str
    producer_sha256: str


def progress(message: str) -> None:
    print(f"[T9.1 terminal-shard] {message}", flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_path(path: Path, label: str | None = None) -> str:
    digest = hashlib.sha256()
    total = path.stat().st_size
    completed = 0
    last_report = time.monotonic()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            completed += len(chunk)
            now = time.monotonic()
            if label is not None and now - last_report >= 5:
                progress(
                    f"stage=hash label={label} bytes={completed}/{total}"
                )
                last_report = now
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def resolve_inside(root: Path, value: str | Path) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def immutable_uri(path: Path) -> str:
    return f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"


def open_immutable(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(immutable_uri(path), uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


def is_int(
    value: Any,
    minimum: int = INT64_MIN,
    maximum: int = INT64_MAX,
) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def require_int(
    value: Any,
    name: str,
    minimum: int = INT64_MIN,
    maximum: int = INT64_MAX,
) -> int:
    if not is_int(value, minimum, maximum):
        raise ValueError(
            f"{name} must be an integer in range [{minimum}, {maximum}]"
        )
    return value


def require_exact_fields(
    value: Mapping[str, Any],
    expected: set[str],
    kind: str,
) -> None:
    if set(value) != expected:
        raise ValueError(
            f"{kind} fields mismatch: {sorted(set(value) ^ expected)}"
        )


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_line(line: str, location: str) -> dict[str, Any]:
    try:
        value = json.loads(
            line,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid exporter JSON at {location}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"exporter JSON must be an object at {location}")
    return value


def ipv4_integer(value: Any, name: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a canonical IPv4 string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a canonical IPv4 string") from error
    if address.version != 4 or str(address) != value:
        raise ValueError(f"{name} must be a canonical IPv4 string")
    return int(address)


def output_directory(root: Path, capture_id: str) -> Path:
    return (
        root.resolve()
        / "run_log"
        / "full-flow-v1"
        / "terminal-shards"
        / capture_id
    )


def require_production_host(root: Path) -> None:
    if platform.system() != "Linux":
        raise RuntimeError("T9.1 replay requires Ubuntu 24.04 VMware")
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(
            encoding="utf-8"
        ).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError as error:
        raise RuntimeError("cannot identify the Ubuntu replay host") from error
    if (
        os_release.get("ID") != "ubuntu"
        or os_release.get("VERSION_ID") != "24.04"
        or root.resolve() != Path("/mnt/hgfs/TTTN").resolve()
    ):
        raise RuntimeError(
            "T9.1 replay requires the approved Ubuntu 24.04 VMware workspace"
        )


def require_local_scratch(scratch: Path, root: Path, output: Path) -> None:
    scratch = scratch.resolve()
    if not scratch.is_dir():
        raise ValueError("scratch directory does not exist")
    for forbidden in (root.resolve(), output.resolve()):
        try:
            scratch.relative_to(forbidden)
        except ValueError:
            continue
        raise ValueError("scratch must be outside the shared project/output tree")
    if scratch.stat().st_dev == root.resolve().stat().st_dev:
        raise ValueError(
            "scratch must be on a local filesystem distinct from the shared workspace"
        )


def load_feature_schema(path: Path, expected_sha256: str) -> FeatureSchema:
    if not path.is_file():
        raise ValueError("terminal feature schema is missing")
    observed_sha256 = sha256_path(path)
    if observed_sha256 != expected_sha256:
        raise ValueError("terminal feature schema hash mismatch")
    value = load_json(path)
    vector = value.get("feature_vector")
    features = value.get("features")
    if (
        value.get("schema_id") != FEATURE_SCHEMA_ID
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("task") != TASK
        or not isinstance(vector, Mapping)
        or vector.get("length") != FEATURE_COUNT
        or vector.get("encoded_type") != "float64"
        or vector.get("finite_only") is not True
        or not isinstance(features, list)
        or len(features) != FEATURE_COUNT
    ):
        raise ValueError("terminal feature schema contract mismatch")
    indices: list[int] = []
    names: list[str] = []
    unsigned_limits: list[int | None] = []
    limits = {
        "uint8": (1 << 8) - 1,
        "uint16": (1 << 16) - 1,
        "uint32": (1 << 32) - 1,
        "uint64": (1 << 64) - 1,
    }
    for expected_index, feature in enumerate(features):
        if not isinstance(feature, Mapping):
            raise ValueError("terminal feature schema entry is not an object")
        index = feature.get("index")
        name = feature.get("name")
        logical_type = feature.get("logical_type")
        if index != expected_index or not isinstance(name, str) or not name:
            raise ValueError("terminal feature schema index/name mismatch")
        if logical_type not in {*limits, "float64"}:
            raise ValueError("terminal feature schema logical type mismatch")
        indices.append(index)
        names.append(name)
        unsigned_limits.append(limits.get(logical_type))
    if indices != list(range(FEATURE_COUNT)) or len(set(names)) != FEATURE_COUNT:
        raise ValueError("terminal feature schema ordering/name mismatch")
    return FeatureSchema(path.resolve(), observed_sha256, tuple(unsigned_limits))


def source_table_columns(
    connection: sqlite3.Connection,
    table: str,
) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def validate_source_database(
    path: Path,
    expected_sha256: str,
    expected_size: int,
) -> str:
    if not path.is_file() or path.stat().st_size != expected_size:
        raise ValueError("T3.3 source database size mismatch")
    for suffix in ("-wal", "-shm"):
        if path.with_name(path.name + suffix).exists():
            raise ValueError("T3.3 source database has mutable sidecars")
    observed_sha256 = sha256_path(path, "t3.3-oracle")
    if observed_sha256 != expected_sha256:
        raise ValueError("T3.3 source database hash mismatch")
    with contextlib.closing(open_immutable(path)) as connection:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != SOURCE_APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != SOURCE_USER_VERSION
            or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
        ):
            raise ValueError("T3.3 source database SQLite identity mismatch")
        for table, required_columns in REQUIRED_SOURCE_COLUMNS.items():
            if not required_columns <= source_table_columns(connection, table):
                raise ValueError(
                    f"T3.3 source database {table} columns mismatch"
                )
    return observed_sha256


def read_capture_source(
    root: Path,
    source_database: Path,
    capture_id: str,
) -> CaptureSource:
    with contextlib.closing(open_immutable(source_database)) as connection:
        files = connection.execute(
            "SELECT path,size_bytes,sha256 FROM input_file "
            "WHERE capture_id=? AND kind='pcap'",
            (capture_id,),
        ).fetchall()
        if len(files) != 1:
            raise ValueError(f"unknown or ambiguous capture id: {capture_id}")
        summary_row = connection.execute(
            "SELECT records_read,packets_parsed,parser_errors,packets_accepted,"
            "ingest_errors,exported_flows,flows_closed "
            "FROM exporter_summary WHERE capture_id=?",
            (capture_id,),
        ).fetchone()
        if summary_row is None:
            raise ValueError("T3.3 source exporter summary is missing")
    path_text, size_bytes, source_sha256 = files[0]
    if (
        not isinstance(path_text, str)
        or not is_int(size_bytes, 0, INT64_MAX)
        or not isinstance(source_sha256, str)
        or len(source_sha256) != 64
    ):
        raise ValueError("T3.3 source PCAP identity is invalid")
    names = (
        "records_read",
        "packets_parsed",
        "parser_errors",
        "packets_accepted",
        "ingest_errors",
        "exported_flows",
        "flows_closed",
    )
    summary = dict(zip(names, summary_row, strict=True))
    for name, item in summary.items():
        summary[name] = require_int(item, f"T3.3 {name}", 0, INT64_MAX)
    if (
        summary["records_read"]
        != summary["packets_parsed"] + summary["parser_errors"]
        or summary["packets_accepted"] != summary["packets_parsed"]
        or summary["ingest_errors"] != 0
        or summary["exported_flows"] != summary["flows_closed"]
    ):
        raise ValueError("T3.3 source exporter accounting mismatch")
    return CaptureSource(
        capture_id,
        path_text,
        resolve_inside(root, path_text),
        size_bytes,
        source_sha256,
        summary,
    )


def validate_source_file(capture: CaptureSource, rehash: bool) -> None:
    if not capture.path.is_file():
        raise ValueError("source PCAP is missing")
    before = capture.path.stat()
    if before.st_size != capture.size_bytes:
        raise ValueError("source PCAP size mismatch")
    if not rehash:
        return
    digest = sha256_path(capture.path, capture.capture_id)
    after = capture.path.stat()
    if (
        digest != capture.sha256
        or (before.st_size, before.st_mtime_ns)
        != (after.st_size, after.st_mtime_ns)
    ):
        raise ValueError("source PCAP identity or stability mismatch")


def prepare_inputs(
    root: Path,
    capture_id: str,
    exporter: Path,
    *,
    source_database: Path,
    feature_schema: Path,
    expected_source_database_sha256: str,
    expected_source_database_size: int,
    expected_feature_schema_sha256: str,
) -> BuildInputs:
    root = root.resolve()
    exporter = exporter.resolve()
    source_database = source_database.resolve()
    feature_schema = feature_schema.resolve()
    if not exporter.is_file():
        raise ValueError("terminal flow exporter does not exist")
    schema = load_feature_schema(
        feature_schema,
        expected_feature_schema_sha256,
    )
    source_hash = validate_source_database(
        source_database,
        expected_source_database_sha256,
        expected_source_database_size,
    )
    capture = read_capture_source(root, source_database, capture_id)
    return BuildInputs(
        root,
        source_database,
        source_hash,
        schema,
        capture,
        exporter,
        sha256_path(exporter),
        sha256_path(Path(__file__).resolve()),
    )


def validate_envelope(
    value: Mapping[str, Any],
    kind: str,
    capture_id: str,
) -> None:
    if (
        value.get("schema_version") != 1
        or isinstance(value.get("schema_version"), bool)
        or value.get("task") != TASK
        or value.get("kind") != kind
        or value.get("feature_schema_id") != FEATURE_SCHEMA_ID
        or value.get("feature_count") != FEATURE_COUNT
        or isinstance(value.get("feature_count"), bool)
        or value.get("capture_id") != capture_id
    ):
        raise ValueError(f"invalid {kind} envelope")


def validate_feature_values(
    raw: Any,
    schema: FeatureSchema,
    flow: Mapping[str, int | str],
) -> tuple[float, ...]:
    if not isinstance(raw, list) or len(raw) != FEATURE_COUNT:
        raise ValueError("terminal flow must contain exactly 70 features")
    values: list[float] = []
    for index, item in enumerate(raw):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError(f"feature[{index}] must be numeric")
        try:
            number = float(item)
        except OverflowError as error:
            raise ValueError(f"feature[{index}] must be finite") from error
        if not math.isfinite(number):
            raise ValueError(f"feature[{index}] must be finite")
        limit = schema.unsigned_limits[index]
        if limit is not None and (
            not number.is_integer() or number < 0 or number > limit
        ):
            raise ValueError(
                f"feature[{index}] violates unsigned logical type"
            )
        values.append(number)
    if (
        values[1] != float(flow["packet_count"])
        or values[2] != float(flow["forward_packet_count"])
        or values[3] != float(flow["reverse_packet_count"])
    ):
        raise ValueError("terminal feature packet accounting mismatch")
    if values[54] != float(flow["protocol"]):
        raise ValueError("terminal feature protocol mismatch")
    if any(not values[index].is_integer() or values[index] < 1 for index in (61, 62, 63)):
        raise ValueError("terminal feature causal context count mismatch")
    forward_endpoint = (
        int(flow["forward_source_ip"]),
        int(flow["forward_source_port"]),
    )
    low_endpoint = (int(flow["low_ip"]), int(flow["low_port"]))
    destination_port = (
        int(flow["high_port"])
        if forward_endpoint == low_endpoint
        else int(flow["low_port"])
    )
    if (
        values[64] != float(flow["forward_source_port"])
        or values[65] != float(destination_port)
    ):
        raise ValueError("terminal feature first-observed port mismatch")
    lifecycle = values[66:70]
    if any(item not in (0.0, 1.0) for item in lifecycle) or sum(lifecycle) != 1.0:
        raise ValueError("terminal feature lifecycle one-hot mismatch")
    protocol = int(flow["protocol"])
    if (
        (protocol == 17 and lifecycle != [0.0, 0.0, 0.0, 1.0])
        or (protocol == 6 and lifecycle[3] != 0.0)
        or (
            flow["close_reason"] == "tcp_reset"
            and lifecycle[0] != 1.0
        )
        or (
            flow["close_reason"] == "tcp_fin_handshake"
            and lifecycle[1] != 1.0
        )
    ):
        raise ValueError("terminal feature lifecycle protocol/reason mismatch")
    return tuple(values)


def validate_terminal_flow(
    value: Mapping[str, Any],
    capture_id: str,
    schema: FeatureSchema,
) -> tuple[dict[str, int | str], bytes, tuple[Any, ...]]:
    require_exact_fields(value, TERMINAL_FLOW_FIELDS, "terminal_flow")
    validate_envelope(value, "terminal_flow", capture_id)
    protocol_name = value.get("protocol")
    if protocol_name not in PROTOCOLS:
        raise ValueError("terminal flow protocol must be tcp or udp")
    protocol = PROTOCOLS[protocol_name]
    low_ip = ipv4_integer(value.get("low_ip"), "low_ip")
    high_ip = ipv4_integer(value.get("high_ip"), "high_ip")
    low_port = require_int(value.get("low_port"), "low_port", 0, 65_535)
    high_port = require_int(value.get("high_port"), "high_port", 0, 65_535)
    if (low_ip, low_port) > (high_ip, high_port):
        raise ValueError("terminal flow tuple is not canonical")
    forward_ip = ipv4_integer(
        value.get("forward_source_ip"),
        "forward_source_ip",
    )
    forward_port = require_int(
        value.get("forward_source_port"),
        "forward_source_port",
        0,
        65_535,
    )
    if (forward_ip, forward_port) not in {
        (low_ip, low_port),
        (high_ip, high_port),
    }:
        raise ValueError("terminal flow forward source is not an endpoint")
    export_ordinal = require_int(
        value.get("export_ordinal"),
        "export_ordinal",
        1,
        INT64_MAX,
    )
    generation = require_int(
        value.get("generation"),
        "generation",
        1,
        INT64_MAX,
    )
    if value.get("clock_domain") != CLOCK_DOMAIN:
        raise ValueError("terminal flow clock_domain must be unix_epoch")
    creation = require_int(
        value.get("creation_timestamp_ns"),
        "creation_timestamp_ns",
    )
    last_capture = require_int(
        value.get("last_capture_timestamp_ns"),
        "last_capture_timestamp_ns",
    )
    last_event = require_int(
        value.get("last_event_timestamp_ns"),
        "last_event_timestamp_ns",
    )
    if creation > last_event:
        raise ValueError("terminal flow event-time bounds mismatch")
    packet_count = require_int(
        value.get("packet_count"),
        "packet_count",
        1,
        INT64_MAX,
    )
    forward_count = require_int(
        value.get("forward_packet_count"),
        "forward_packet_count",
        0,
        INT64_MAX,
    )
    reverse_count = require_int(
        value.get("reverse_packet_count"),
        "reverse_packet_count",
        0,
        INT64_MAX,
    )
    if forward_count + reverse_count != packet_count:
        raise ValueError("terminal flow directional packet accounting mismatch")
    close_reason = value.get("close_reason")
    if close_reason not in CLOSE_REASONS:
        raise ValueError("terminal flow close_reason mismatch")
    flow: dict[str, int | str] = {
        "export_ordinal": export_ordinal,
        "generation": generation,
        "capture_id": capture_id,
        "protocol": protocol,
        "low_ip": low_ip,
        "low_port": low_port,
        "high_ip": high_ip,
        "high_port": high_port,
        "forward_source_ip": forward_ip,
        "forward_source_port": forward_port,
        "clock_domain": CLOCK_DOMAIN,
        "creation_timestamp_ns": creation,
        "last_capture_timestamp_ns": last_capture,
        "last_event_timestamp_ns": last_event,
        "packet_count": packet_count,
        "forward_packet_count": forward_count,
        "reverse_packet_count": reverse_count,
        "close_reason": close_reason,
    }
    features = validate_feature_values(value.get("features"), schema, flow)
    blob = struct.pack("<70d", *features)
    comparison = (
        capture_id,
        export_ordinal,
        protocol,
        low_ip,
        low_port,
        high_ip,
        high_port,
        forward_ip,
        forward_port,
        generation,
        creation,
        last_capture,
        last_event,
        packet_count,
        forward_count,
        reverse_count,
        close_reason,
    )
    return flow, blob, comparison


def source_flow_cursor(
    connection: sqlite3.Connection,
    capture_id: str,
) -> sqlite3.Cursor:
    columns = ",".join(("flow_id", *SOURCE_FLOW_FIELDS))
    return connection.execute(
        f"SELECT {columns} FROM flow WHERE capture_id=? ORDER BY export_ordinal",
        (capture_id,),
    )


def assert_source_match(
    source_row: Sequence[Any] | None,
    comparison: tuple[Any, ...],
) -> int:
    if source_row is None:
        raise ValueError("terminal exporter emitted more rows than T3.3 oracle")
    flow_id = require_int(source_row[0], "source flow_id", 1, INT64_MAX)
    observed = tuple(source_row[1:])
    if observed != comparison:
        for index, (expected, actual) in enumerate(
            zip(observed, comparison, strict=True)
        ):
            if expected != actual:
                field = SOURCE_FLOW_FIELDS[index]
                raise ValueError(
                    "T3.3 oracle close record mismatch: "
                    f"field={field} expected={expected!r} observed={actual!r}"
                )
        raise ValueError("T3.3 oracle close record mismatch")
    return flow_id


def failed_summary_error(value: Mapping[str, Any]) -> ValueError:
    details = []
    for field in (
        "failure",
        "failure_record_number",
        "ingest_status",
        "terminal_feature_error",
        "pcap_error",
        "pcap_error_detail",
    ):
        if field in value:
            details.append(f"{field}={value[field]!r}")
    suffix = " ".join(details) if details else "without failure detail"
    return ValueError(f"exporter reported failed summary: {suffix}")


def validate_summary(
    value: Mapping[str, Any],
    capture: CaptureSource,
    flow_count: int,
    observed_close_reasons: Mapping[str, int],
) -> dict[str, int]:
    if value.get("status") != "passed":
        raise failed_summary_error(value)
    require_exact_fields(value, SUMMARY_FIELDS, "summary")
    if FAILURE_ONLY_FIELDS & set(value):
        raise ValueError("passed summary contains failure-only fields")
    validate_envelope(value, "summary", capture.capture_id)
    input_value = value.get("input")
    if (
        not isinstance(input_value, str)
        or Path(input_value).resolve() != capture.path.resolve()
    ):
        raise ValueError("summary input mismatch")
    pcap = value.get("pcap")
    flows = value.get("flows")
    if not isinstance(pcap, Mapping) or not isinstance(flows, Mapping):
        raise ValueError("summary nested counters are missing")
    require_exact_fields(pcap, PCAP_SUMMARY_FIELDS, "summary.pcap")
    require_exact_fields(flows, FLOW_SUMMARY_FIELDS, "summary.flows")
    close_reasons = flows.get("close_reason_count")
    if not isinstance(close_reasons, Mapping):
        raise ValueError("summary close_reason_count is missing")
    require_exact_fields(
        close_reasons,
        set(CLOSE_REASONS),
        "summary.flows.close_reason_count",
    )
    counters: dict[str, int] = {}
    for name in PCAP_SUMMARY_FIELDS:
        counters[name] = require_int(
            pcap.get(name),
            f"summary.pcap.{name}",
            0,
            INT64_MAX,
        )
    for name in FLOW_SUMMARY_FIELDS - {"close_reason_count"}:
        counters[name] = require_int(
            flows.get(name),
            f"summary.flows.{name}",
            0,
            INT64_MAX,
        )
    for reason in CLOSE_REASONS:
        counters[f"close_{reason}"] = require_int(
            close_reasons.get(reason),
            f"summary.flows.close_reason_count.{reason}",
            0,
            INT64_MAX,
        )
    for name in (
        "exported_flows",
        "parser_errors",
        "ingest_errors",
        "terminal_feature_errors",
    ):
        counters[name] = require_int(
            value.get(name),
            f"summary.{name}",
            0,
            INT64_MAX,
        )
    rejected = (
        counters["packets_rejected_clock_domain"]
        + counters["packets_rejected_timestamp_overflow"]
        + counters["packets_rejected_feature_update"]
        + counters["packets_rejected_resource_exhausted"]
    )
    source = capture.summary
    if (
        counters["records_read"]
        != counters["packets_parsed"] + counters["parser_errors"]
        or counters["packets_accepted"] != counters["packets_parsed"]
        or rejected != 0
        or counters["parser_errors"] != value.get("parser_errors")
        or counters["captured_bytes"] > counters["wire_bytes"]
        or counters["ingest_errors"] != 0
        or counters["terminal_feature_errors"] != 0
    ):
        raise ValueError("terminal exporter packet/error accounting mismatch")
    for name in (
        "records_read",
        "packets_parsed",
        "parser_errors",
        "packets_accepted",
        "ingest_errors",
        "flows_closed",
        "exported_flows",
    ):
        if counters[name] != source[name]:
            raise ValueError(
                f"terminal exporter T3.3 counter mismatch: {name} "
                f"expected={source[name]} observed={counters[name]}"
            )
    if (
        counters["flow_generations_created"] != flow_count
        or counters["flows_closed"] != flow_count
        or counters["exported_flows"] != flow_count
        or counters["active_flow_count"] != 0
        or (
            flow_count > 0
            and not 1 <= counters["peak_active_flow_count"] <= flow_count
        )
    ):
        raise ValueError("terminal exporter flow lifecycle accounting mismatch")
    if (
        counters["current_memory_bytes"]
        != counters["fixed_memory_bytes"]
        + counters["current_allocator_bytes"]
        or counters["peak_memory_bytes"]
        != counters["fixed_memory_bytes"] + counters["peak_allocator_bytes"]
        or counters["current_allocator_bytes"]
        > counters["peak_allocator_bytes"]
        or counters["current_memory_bytes"] > counters["peak_memory_bytes"]
        or counters["peak_memory_bytes"] > counters["memory_budget_bytes"]
    ):
        raise ValueError("terminal exporter memory accounting mismatch")
    close_total = 0
    for reason in CLOSE_REASONS:
        observed = observed_close_reasons.get(reason, 0)
        reported = counters[f"close_{reason}"]
        if reported != observed:
            raise ValueError(
                "terminal exporter close-reason accounting mismatch: "
                f"{reason} expected={observed} observed={reported}"
            )
        close_total += reported
    if close_total != counters["flows_closed"]:
        raise ValueError("terminal exporter close-reason total mismatch")
    return {name: counters[name] for name in SUMMARY_VALUE_COLUMNS}


class Heartbeat:
    def __init__(self, capture_id: str) -> None:
        self.capture_id = capture_id
        self.started = time.monotonic()
        self.rows = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop.wait(HEARTBEAT_SECONDS):
            progress(
                f"capture={self.capture_id} stage=replay status=running "
                f"rows={self.rows} elapsed={time.monotonic() - self.started:.1f}s"
            )

    def __enter__(self) -> "Heartbeat":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop.set()
        self.thread.join(timeout=1)


def exporter_command(exporter: Path, pcap: Path, capture_id: str) -> list[str]:
    prefix = (
        [sys.executable, str(exporter)]
        if exporter.suffix.casefold() == ".py"
        else [str(exporter)]
    )
    return [*prefix, "--input", str(pcap), "--capture-id", capture_id]


def insert_terminal_flow(
    connection: sqlite3.Connection,
    flow_id: int,
    flow: Mapping[str, int | str],
    blob: bytes,
) -> None:
    connection.execute(
        "INSERT INTO terminal_flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            flow_id,
            flow["export_ordinal"],
            flow["generation"],
            flow["capture_id"],
            flow["protocol"],
            flow["low_ip"],
            flow["low_port"],
            flow["high_ip"],
            flow["high_port"],
            flow["forward_source_ip"],
            flow["forward_source_port"],
            flow["clock_domain"],
            flow["creation_timestamp_ns"],
            flow["last_capture_timestamp_ns"],
            flow["last_event_timestamp_ns"],
            flow["packet_count"],
            flow["forward_packet_count"],
            flow["reverse_packet_count"],
            flow["close_reason"],
            blob,
        ),
    )


def consume_exporter(
    connection: sqlite3.Connection,
    source_connection: sqlite3.Connection,
    inputs: BuildInputs,
    stderr_path: Path,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> dict[str, int]:
    stderr_output = stderr_path.open("w", encoding="utf-8", newline="\n")
    try:
        process = popen_factory(
            exporter_command(
                inputs.exporter,
                inputs.capture.path,
                inputs.capture.capture_id,
            ),
            cwd=inputs.capture.path.parent,
            stdout=subprocess.PIPE,
            stderr=stderr_output,
            text=True,
            encoding="utf-8",
            errors="strict",
            bufsize=1,
        )
    except Exception:
        stderr_output.close()
        raise
    if process.stdout is None:
        stderr_output.close()
        raise ValueError("exporter stdout pipe is unavailable")
    source_rows = source_flow_cursor(
        source_connection,
        inputs.capture.capture_id,
    )
    flow_count = 0
    close_reasons = {reason: 0 for reason in CLOSE_REASONS}
    summary: Mapping[str, Any] | None = None
    try:
        with Heartbeat(inputs.capture.capture_id) as heartbeat:
            for line_number, line in enumerate(process.stdout, start=1):
                if len(line.encode("utf-8")) > MAX_JSON_LINE_BYTES:
                    raise ValueError("exporter JSON line exceeds 64 KiB")
                value = parse_json_line(
                    line,
                    f"{inputs.capture.capture_id}:{line_number}",
                )
                if summary is not None:
                    raise ValueError("exporter emitted a record after summary")
                kind = value.get("kind")
                if kind == "terminal_flow":
                    flow, blob, comparison = validate_terminal_flow(
                        value,
                        inputs.capture.capture_id,
                        inputs.feature_schema,
                    )
                    expected_ordinal = flow_count + 1
                    if flow["export_ordinal"] != expected_ordinal:
                        raise ValueError(
                            "terminal export ordinal sequence mismatch: "
                            f"expected={expected_ordinal} "
                            f"observed={flow['export_ordinal']}"
                        )
                    flow_id = assert_source_match(
                        source_rows.fetchone(),
                        comparison,
                    )
                    insert_terminal_flow(connection, flow_id, flow, blob)
                    flow_count += 1
                    close_reasons[str(flow["close_reason"])] += 1
                    heartbeat.rows = flow_count
                    if flow_count % COMMIT_ROWS == 0:
                        connection.commit()
                elif kind == "summary":
                    summary = value
                else:
                    raise ValueError(
                        f"unknown exporter record kind: {kind!r}"
                    )
            return_code = process.wait()
    except Exception:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        process.stdout.close()
        stderr_output.close()
    if summary is not None and summary.get("status") != "passed":
        raise failed_summary_error(summary)
    if return_code != 0:
        error_text = stderr_path.read_text(encoding="utf-8")
        raise ValueError(
            f"exporter failed rc={return_code}: {error_text[-2000:]}"
        )
    if summary is None:
        raise ValueError("exporter omitted summary")
    if source_rows.fetchone() is not None:
        raise ValueError("terminal exporter omitted rows present in T3.3 oracle")
    counters = validate_summary(
        summary,
        inputs.capture,
        flow_count,
        close_reasons,
    )
    connection.execute(
        "INSERT INTO exporter_summary VALUES("
        + ",".join("?" for _ in range(len(SUMMARY_VALUE_COLUMNS) + 1))
        + ")",
        (
            inputs.capture.capture_id,
            *(counters[name] for name in SUMMARY_VALUE_COLUMNS),
        ),
    )
    connection.commit()
    return counters


def create_database(
    path: Path,
    inputs: BuildInputs,
    metadata: Mapping[str, str],
) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA page_size=4096")
    connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
    connection.execute(f"PRAGMA user_version={USER_VERSION}")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(
        """
        CREATE TABLE metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) STRICT;
        CREATE TABLE terminal_flow(
            flow_id INTEGER PRIMARY KEY CHECK(flow_id>=1),
            export_ordinal INTEGER NOT NULL UNIQUE CHECK(export_ordinal>=1),
            generation INTEGER NOT NULL UNIQUE CHECK(generation>=1),
            capture_id TEXT NOT NULL,
            protocol INTEGER NOT NULL CHECK(protocol IN (6,17)),
            low_ip INTEGER NOT NULL CHECK(low_ip BETWEEN 0 AND 4294967295),
            low_port INTEGER NOT NULL CHECK(low_port BETWEEN 0 AND 65535),
            high_ip INTEGER NOT NULL CHECK(high_ip BETWEEN 0 AND 4294967295),
            high_port INTEGER NOT NULL CHECK(high_port BETWEEN 0 AND 65535),
            forward_source_ip INTEGER NOT NULL
                CHECK(forward_source_ip BETWEEN 0 AND 4294967295),
            forward_source_port INTEGER NOT NULL
                CHECK(forward_source_port BETWEEN 0 AND 65535),
            clock_domain TEXT NOT NULL CHECK(clock_domain='unix_epoch'),
            creation_timestamp_ns INTEGER NOT NULL,
            last_capture_timestamp_ns INTEGER NOT NULL,
            last_event_timestamp_ns INTEGER NOT NULL,
            packet_count INTEGER NOT NULL CHECK(packet_count>=1),
            forward_packet_count INTEGER NOT NULL CHECK(forward_packet_count>=0),
            reverse_packet_count INTEGER NOT NULL CHECK(reverse_packet_count>=0),
            close_reason TEXT NOT NULL CHECK(close_reason IN (
                'idle_timeout','maximum_age','tcp_reset','tcp_fin_handshake',
                'tuple_reuse','capacity_eviction','end_of_input'
            )),
            features BLOB NOT NULL CHECK(length(features)=560),
            CHECK(
                low_ip<high_ip OR (low_ip=high_ip AND low_port<=high_port)
            ),
            CHECK(
                (forward_source_ip=low_ip AND forward_source_port=low_port)
                OR
                (forward_source_ip=high_ip AND forward_source_port=high_port)
            ),
            CHECK(creation_timestamp_ns<=last_event_timestamp_ns),
            CHECK(
                packet_count=forward_packet_count+reverse_packet_count
            )
        ) STRICT;
        CREATE TABLE exporter_summary(
            capture_id TEXT PRIMARY KEY,
            records_read INTEGER NOT NULL,
            packets_parsed INTEGER NOT NULL,
            parser_errors INTEGER NOT NULL,
            captured_bytes INTEGER NOT NULL,
            wire_bytes INTEGER NOT NULL,
            packets_accepted INTEGER NOT NULL,
            packets_rejected_clock_domain INTEGER NOT NULL,
            packets_rejected_timestamp_overflow INTEGER NOT NULL,
            packets_rejected_feature_update INTEGER NOT NULL,
            packets_rejected_resource_exhausted INTEGER NOT NULL,
            flow_generations_created INTEGER NOT NULL,
            flows_closed INTEGER NOT NULL,
            active_flow_count INTEGER NOT NULL,
            peak_active_flow_count INTEGER NOT NULL,
            fixed_memory_bytes INTEGER NOT NULL,
            current_allocator_bytes INTEGER NOT NULL,
            peak_allocator_bytes INTEGER NOT NULL,
            current_memory_bytes INTEGER NOT NULL,
            peak_memory_bytes INTEGER NOT NULL,
            memory_budget_bytes INTEGER NOT NULL,
            close_idle_timeout INTEGER NOT NULL,
            close_maximum_age INTEGER NOT NULL,
            close_tcp_reset INTEGER NOT NULL,
            close_tcp_fin_handshake INTEGER NOT NULL,
            close_tuple_reuse INTEGER NOT NULL,
            close_capacity_eviction INTEGER NOT NULL,
            close_end_of_input INTEGER NOT NULL,
            exported_flows INTEGER NOT NULL,
            ingest_errors INTEGER NOT NULL,
            terminal_feature_errors INTEGER NOT NULL
        ) STRICT;
        """
    )
    values = {**metadata, "capture_id": inputs.capture.capture_id}
    connection.executemany(
        "INSERT INTO metadata VALUES(?,?)",
        values.items(),
    )
    connection.commit()
    return connection


def validate_blob(
    row: Sequence[Any],
    schema: FeatureSchema,
) -> None:
    (
        flow_id,
        protocol,
        low_ip,
        low_port,
        high_ip,
        high_port,
        forward_source_ip,
        forward_source_port,
        packet_count,
        forward_packet_count,
        reverse_packet_count,
        close_reason,
        blob,
    ) = row
    if not isinstance(blob, bytes) or len(blob) != FEATURE_BLOB_SIZE:
        raise ValueError(f"terminal feature BLOB size mismatch: flow_id={flow_id}")
    values = struct.unpack("<70d", blob)
    flow: dict[str, int | str] = {
        "protocol": protocol,
        "low_ip": low_ip,
        "low_port": low_port,
        "high_ip": high_ip,
        "high_port": high_port,
        "forward_source_ip": forward_source_ip,
        "forward_source_port": forward_source_port,
        "packet_count": packet_count,
        "forward_packet_count": forward_packet_count,
        "reverse_packet_count": reverse_packet_count,
        "close_reason": close_reason,
    }
    try:
        validate_feature_values(list(values), schema, flow)
    except ValueError as error:
        raise ValueError(
            f"terminal feature BLOB mismatch: flow_id={flow_id}: {error}"
        ) from error


def validate_database_contents(
    connection: sqlite3.Connection,
    inputs: BuildInputs,
    metadata: Mapping[str, str],
    expected_summary: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("terminal shard integrity_check failed")
    if (
        connection.execute("PRAGMA application_id").fetchone()[0]
        != APPLICATION_ID
        or connection.execute("PRAGMA user_version").fetchone()[0]
        != USER_VERSION
    ):
        raise ValueError("terminal shard SQLite identity mismatch")
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        )
    }
    if tables != set(TABLE_COLUMNS):
        raise ValueError("terminal shard table set mismatch")
    for table, expected_columns in TABLE_COLUMNS.items():
        if source_table_columns(connection, table) != expected_columns:
            raise ValueError(f"terminal shard {table} columns mismatch")
    stored_metadata = dict(
        connection.execute("SELECT key,value FROM metadata")
    )
    expected_metadata = {**metadata, "capture_id": inputs.capture.capture_id}
    if (
        set(stored_metadata) != METADATA_KEYS
        or stored_metadata != expected_metadata
    ):
        raise ValueError("terminal shard metadata mismatch")
    (
        flow_count,
        minimum_generation,
        maximum_generation,
        minimum_ordinal,
        maximum_ordinal,
    ) = connection.execute(
        "SELECT COUNT(*),MIN(generation),MAX(generation),"
        "MIN(export_ordinal),MAX(export_ordinal) FROM terminal_flow"
    ).fetchone()
    if flow_count == 0:
        if any(
            value is not None
            for value in (
                minimum_generation,
                maximum_generation,
                minimum_ordinal,
                maximum_ordinal,
            )
        ):
            raise ValueError("empty terminal shard sequence mismatch")
    elif (
        minimum_generation != 1
        or maximum_generation != flow_count
        or minimum_ordinal != 1
        or maximum_ordinal != flow_count
    ):
        raise ValueError("terminal generation/export ordinal sequence mismatch")
    scanned = 0
    for row in connection.execute(
        "SELECT flow_id,protocol,low_ip,low_port,high_ip,high_port,"
        "forward_source_ip,forward_source_port,packet_count,"
        "forward_packet_count,reverse_packet_count,close_reason,features "
        "FROM terminal_flow ORDER BY flow_id"
    ):
        validate_blob(row, inputs.feature_schema)
        scanned += 1
    if scanned != flow_count:
        raise ValueError("terminal shard feature scan count mismatch")
    summary_row = connection.execute(
        "SELECT "
        + ",".join(SUMMARY_VALUE_COLUMNS)
        + " FROM exporter_summary WHERE capture_id=?",
        (inputs.capture.capture_id,),
    ).fetchone()
    if (
        summary_row is None
        or connection.execute(
            "SELECT COUNT(*) FROM exporter_summary"
        ).fetchone()[0]
        != 1
    ):
        raise ValueError("terminal shard exporter summary row mismatch")
    summary = dict(zip(SUMMARY_VALUE_COLUMNS, summary_row, strict=True))
    if expected_summary is not None and summary != dict(expected_summary):
        raise ValueError("terminal shard manifest summary mismatch")
    close_counts = {
        reason: count
        for reason, count in connection.execute(
            "SELECT close_reason,COUNT(*) FROM terminal_flow "
            "GROUP BY close_reason"
        )
    }
    for reason in CLOSE_REASONS:
        close_counts.setdefault(reason, 0)
        if close_counts[reason] != summary[f"close_{reason}"]:
            raise ValueError("terminal shard close-reason summary mismatch")
    if (
        summary["exported_flows"] != flow_count
        or summary["flow_generations_created"] != flow_count
        or summary["flows_closed"] != flow_count
        or summary["active_flow_count"] != 0
        or summary["ingest_errors"] != 0
        or summary["terminal_feature_errors"] != 0
        or summary["records_read"]
        != summary["packets_parsed"] + summary["parser_errors"]
        or summary["packets_accepted"] != summary["packets_parsed"]
    ):
        raise ValueError("terminal shard stored summary mismatch")
    return {
        "rows": flow_count,
        "summary": summary,
        "close_reason_count": {
            reason: close_counts[reason] for reason in CLOSE_REASONS
        },
    }


def finalize_database(
    path: Path,
    connection: sqlite3.Connection,
    inputs: BuildInputs,
    metadata: Mapping[str, str],
    expected_summary: Mapping[str, int],
) -> dict[str, Any]:
    metrics = validate_database_contents(
        connection,
        inputs,
        metadata,
        expected_summary,
    )
    connection.execute("PRAGMA optimize")
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
        raise ValueError("terminal shard could not enter DELETE journal mode")
    connection.commit()
    connection.close()
    for suffix in ("-wal", "-shm"):
        if path.with_name(path.name + suffix).exists():
            raise ValueError("terminal shard WAL/SHM remained after close")
    with contextlib.closing(open_immutable(path)) as check:
        if check.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise ValueError("terminal shard journal mode is not DELETE")
        validate_database_contents(
            check,
            inputs,
            metadata,
            expected_summary,
        )
    return metrics


def metadata_values(inputs: BuildInputs) -> dict[str, str]:
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "feature_schema_sha256": inputs.feature_schema.sha256,
        "producer_sha256": inputs.producer_sha256,
        "exporter_sha256": inputs.exporter_sha256,
        "source_database_sha256": inputs.source_database_sha256,
        "source_pcap_sha256": inputs.capture.sha256,
        "float_encoding": "ieee754_little_endian_float64",
    }


def build_manifest(
    inputs: BuildInputs,
    database: Path,
    metrics: Mapping[str, Any],
    elapsed_seconds: float,
) -> dict[str, Any]:
    output = output_directory(inputs.root, inputs.capture.capture_id)
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": MANIFEST_KIND,
        "status": "passed",
        "capture_id": inputs.capture.capture_id,
        "generated_at_utc": utc_now(),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "producer": {
            "path": display_path(Path(__file__), inputs.root),
            "sha256": inputs.producer_sha256,
        },
        "exporter": {
            "path": str(inputs.exporter),
            "sha256": inputs.exporter_sha256,
        },
        "feature_schema": {
            "path": display_path(inputs.feature_schema.path, inputs.root),
            "sha256": inputs.feature_schema.sha256,
            "schema_id": FEATURE_SCHEMA_ID,
            "feature_count": FEATURE_COUNT,
        },
        "source_database": {
            "path": display_path(inputs.source_database, inputs.root),
            "size_bytes": inputs.source_database.stat().st_size,
            "sha256": inputs.source_database_sha256,
            "application_id": SOURCE_APPLICATION_ID,
            "user_version": SOURCE_USER_VERSION,
            "journal_mode": "delete",
        },
        "source": {
            "path": inputs.capture.path_text,
            "size_bytes": inputs.capture.size_bytes,
            "sha256": inputs.capture.sha256,
        },
        "database": {
            "path": display_path(output / DATABASE_NAME, inputs.root),
            "size_bytes": database.stat().st_size,
            "sha256": sha256_path(database),
            "application_id": APPLICATION_ID,
            "user_version": USER_VERSION,
            "journal_mode": "delete",
            "integrity_check": "ok",
            "rows": metrics["rows"],
        },
        "summary": metrics["summary"],
        "oracle_reconciliation": {
            "key": "capture_id_export_ordinal_then_exact_close_record",
            "matched_rows": metrics["rows"],
            "mismatches": 0,
        },
    }


def validate_manifest_records(
    manifest: Mapping[str, Any],
    inputs: BuildInputs,
    database: Path,
) -> Mapping[str, int]:
    require_exact_fields(manifest, MANIFEST_FIELDS, "manifest")
    feature = manifest.get("feature_schema")
    source_database = manifest.get("source_database")
    source = manifest.get("source")
    database_record = manifest.get("database")
    producer = manifest.get("producer")
    exporter = manifest.get("exporter")
    reconciliation = manifest.get("oracle_reconciliation")
    summary = manifest.get("summary")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("task") != TASK
        or manifest.get("kind") != MANIFEST_KIND
        or manifest.get("status") != "passed"
        or manifest.get("capture_id") != inputs.capture.capture_id
        or not isinstance(manifest.get("generated_at_utc"), str)
        or not isinstance(manifest.get("elapsed_seconds"), (int, float))
        or not isinstance(feature, Mapping)
        or not isinstance(source_database, Mapping)
        or not isinstance(source, Mapping)
        or not isinstance(database_record, Mapping)
        or not isinstance(producer, Mapping)
        or not isinstance(exporter, Mapping)
        or not isinstance(reconciliation, Mapping)
        or not isinstance(summary, Mapping)
    ):
        raise ValueError("terminal shard manifest envelope mismatch")
    if (
        producer
        != {
            "path": display_path(Path(__file__), inputs.root),
            "sha256": inputs.producer_sha256,
        }
        or exporter
        != {
            "path": str(inputs.exporter),
            "sha256": inputs.exporter_sha256,
        }
        or feature
        != {
            "path": display_path(inputs.feature_schema.path, inputs.root),
            "sha256": inputs.feature_schema.sha256,
            "schema_id": FEATURE_SCHEMA_ID,
            "feature_count": FEATURE_COUNT,
        }
        or source_database
        != {
            "path": display_path(inputs.source_database, inputs.root),
            "size_bytes": inputs.source_database.stat().st_size,
            "sha256": inputs.source_database_sha256,
            "application_id": SOURCE_APPLICATION_ID,
            "user_version": SOURCE_USER_VERSION,
            "journal_mode": "delete",
        }
        or source
        != {
            "path": inputs.capture.path_text,
            "size_bytes": inputs.capture.size_bytes,
            "sha256": inputs.capture.sha256,
        }
    ):
        raise ValueError("terminal shard manifest provenance mismatch")
    expected_database_path = display_path(
        output_directory(inputs.root, inputs.capture.capture_id)
        / DATABASE_NAME,
        inputs.root,
    )
    if (
        set(database_record)
        != {
            "path",
            "size_bytes",
            "sha256",
            "application_id",
            "user_version",
            "journal_mode",
            "integrity_check",
            "rows",
        }
        or database_record.get("path") != expected_database_path
        or database_record.get("size_bytes") != database.stat().st_size
        or database_record.get("sha256") != sha256_path(database)
        or database_record.get("application_id") != APPLICATION_ID
        or database_record.get("user_version") != USER_VERSION
        or database_record.get("journal_mode") != "delete"
        or database_record.get("integrity_check") != "ok"
        or not is_int(database_record.get("rows"), 0, INT64_MAX)
    ):
        raise ValueError("terminal shard manifest database mismatch")
    if reconciliation != {
        "key": "capture_id_export_ordinal_then_exact_close_record",
        "matched_rows": database_record["rows"],
        "mismatches": 0,
    }:
        raise ValueError("terminal shard manifest reconciliation mismatch")
    if set(summary) != set(SUMMARY_VALUE_COLUMNS):
        raise ValueError("terminal shard manifest summary fields mismatch")
    normalized_summary = {
        name: require_int(
            summary.get(name),
            f"manifest.summary.{name}",
            0,
            INT64_MAX,
        )
        for name in SUMMARY_VALUE_COLUMNS
    }
    return normalized_summary


def validate_checkpoint(
    root: Path,
    capture_id: str,
    exporter: Path,
    *,
    source_database: Path | None = None,
    feature_schema: Path | None = None,
    expected_source_database_sha256: str = SOURCE_DATABASE_SHA256,
    expected_source_database_size: int = SOURCE_DATABASE_SIZE,
    expected_feature_schema_sha256: str = FEATURE_SCHEMA_SHA256,
    rehash_source: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    source_database = (
        source_database.resolve()
        if source_database is not None
        else resolve_inside(root, SOURCE_DATABASE_PATH)
    )
    feature_schema = (
        feature_schema.resolve()
        if feature_schema is not None
        else resolve_inside(root, FEATURE_SCHEMA_PATH)
    )
    inputs = prepare_inputs(
        root,
        capture_id,
        exporter,
        source_database=source_database,
        feature_schema=feature_schema,
        expected_source_database_sha256=expected_source_database_sha256,
        expected_source_database_size=expected_source_database_size,
        expected_feature_schema_sha256=expected_feature_schema_sha256,
    )
    validate_source_file(inputs.capture, rehash_source)
    output = output_directory(root, capture_id)
    database = output / DATABASE_NAME
    manifest_path = output / MANIFEST_NAME
    if not database.is_file() or not manifest_path.is_file():
        raise ValueError("terminal shard checkpoint is incomplete")
    for suffix in ("-wal", "-shm"):
        if database.with_name(database.name + suffix).exists():
            raise ValueError("terminal shard checkpoint has WAL/SHM sidecars")
    manifest = load_json(manifest_path)
    expected_summary = validate_manifest_records(
        manifest,
        inputs,
        database,
    )
    with contextlib.closing(open_immutable(database)) as connection:
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise ValueError("terminal shard checkpoint journal mode mismatch")
        metrics = validate_database_contents(
            connection,
            inputs,
            metadata_values(inputs),
            expected_summary,
        )
    if metrics["rows"] != manifest["database"]["rows"]:
        raise ValueError("terminal shard manifest row count mismatch")
    return manifest


def build_capture(
    root: Path,
    capture_id: str,
    exporter: Path,
    scratch_root: Path,
    *,
    source_database: Path | None = None,
    feature_schema: Path | None = None,
    expected_source_database_sha256: str = SOURCE_DATABASE_SHA256,
    expected_source_database_size: int = SOURCE_DATABASE_SIZE,
    expected_feature_schema_sha256: str = FEATURE_SCHEMA_SHA256,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> tuple[dict[str, Any], bool]:
    root = root.resolve()
    exporter = exporter.resolve()
    scratch_root = scratch_root.resolve()
    source_database = (
        source_database.resolve()
        if source_database is not None
        else resolve_inside(root, SOURCE_DATABASE_PATH)
    )
    feature_schema = (
        feature_schema.resolve()
        if feature_schema is not None
        else resolve_inside(root, FEATURE_SCHEMA_PATH)
    )
    require_production_host(root)
    output = output_directory(root, capture_id)
    if output.exists():
        return (
            validate_checkpoint(
                root,
                capture_id,
                exporter,
                source_database=source_database,
                feature_schema=feature_schema,
                expected_source_database_sha256=expected_source_database_sha256,
                expected_source_database_size=expected_source_database_size,
                expected_feature_schema_sha256=expected_feature_schema_sha256,
            ),
            True,
        )
    require_local_scratch(scratch_root, root, output)
    inputs = prepare_inputs(
        root,
        capture_id,
        exporter,
        source_database=source_database,
        feature_schema=feature_schema,
        expected_source_database_sha256=expected_source_database_sha256,
        expected_source_database_size=expected_source_database_size,
        expected_feature_schema_sha256=expected_feature_schema_sha256,
    )
    progress(
        f"capture={capture_id} stage=source-hash status=running "
        f"bytes={inputs.capture.size_bytes}"
    )
    validate_source_file(inputs.capture, True)
    started = time.monotonic()
    progress(f"capture={capture_id} stage=replay status=running")
    temporary_root = scratch_root / f"t91-terminal-{uuid.uuid4().hex}"
    temporary_root.mkdir()
    metadata = metadata_values(inputs)
    try:
        database = temporary_root / DATABASE_NAME
        connection = create_database(database, inputs, metadata)
        try:
            with contextlib.closing(
                open_immutable(inputs.source_database)
            ) as source_connection:
                counters = consume_exporter(
                    connection,
                    source_connection,
                    inputs,
                    temporary_root / "exporter.stderr",
                    popen_factory,
                )
            metrics = finalize_database(
                database,
                connection,
                inputs,
                metadata,
                counters,
            )
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                connection.close()
            raise
        output.parent.mkdir(parents=True, exist_ok=True)
        staging = output.parent / f".{capture_id}.{uuid.uuid4().hex}.tmp"
        staging.mkdir()
        try:
            staged_database = staging / DATABASE_NAME
            shutil.copyfile(database, staged_database)
            with staged_database.open("r+b") as copied:
                os.fsync(copied.fileno())
            manifest = build_manifest(
                inputs,
                staged_database,
                metrics,
                time.monotonic() - started,
            )
            write_json_atomic(staging / MANIFEST_NAME, manifest)
            os.replace(staging, output)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    progress(
        f"capture={capture_id} stage=publish status=passed "
        f"rows={metrics['rows']} elapsed={manifest['elapsed_seconds']:.1f}s "
        f"artifact={output}"
    )
    return manifest, False


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--capture-id", required=True)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument("--exporter", type=Path, required=True)
        command.add_argument(
            "--scratch",
            type=Path,
            default=Path("/tmp"),
        )
        command.add_argument("--rehash-source", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            if args.rehash_source:
                raise ValueError(
                    "--rehash-source is implicit for run and only valid for validate"
                )
            build_capture(
                args.project_root,
                args.capture_id,
                args.exporter,
                args.scratch,
            )
        else:
            validate_checkpoint(
                args.project_root,
                args.capture_id,
                args.exporter,
                rehash_source=args.rehash_source,
            )
        return 0
    except (
        OSError,
        OverflowError,
        RuntimeError,
        ValueError,
        sqlite3.Error,
        struct.error,
    ) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
