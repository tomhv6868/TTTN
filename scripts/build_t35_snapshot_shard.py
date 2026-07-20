#!/usr/bin/env python3
"""Build and validate one content-addressed T3.5 replay snapshot shard."""

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T3.5"
KIND = "snapshot_shard_checkpoint"
DATABASE_NAME = "snapshot-shard.sqlite3"
RECEIPT_NAME = "receipt.json"
CHECKPOINTS = {"F3": 3, "F5": 5, "F7": 7, "F9": 9}
CHECKPOINT_ORDER = ("F3", "F5", "F7", "F9")
FEATURE_COUNT = 54
FEATURE_BLOB_SIZE = FEATURE_COUNT * 8
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
PROTOCOLS = {"tcp", "udp"}
CLOCK_DOMAINS = {"unix_epoch", "monotonic"}
CLOSE_REASONS = {
    "idle_timeout",
    "maximum_age",
    "tcp_reset",
    "tcp_fin_handshake",
    "tuple_reuse",
    "capacity_eviction",
    "end_of_input",
}
IDENTITY_FIELDS = (
    "protocol",
    "low_ip",
    "low_port",
    "high_ip",
    "high_port",
    "forward_source_ip",
    "forward_source_port",
)
SNAPSHOT_FIELDS = {
    "schema_version", "task", "kind", "capture_id", *IDENTITY_FIELDS,
    "generation", "clock_domain", "checkpoint", "packet_count",
    "checkpoint_timestamp_ns", "features",
}
FLOW_FIELDS = {
    "schema_version", "task", "kind", "capture_id", "export_ordinal",
    *IDENTITY_FIELDS, "generation", "clock_domain", "creation_timestamp_ns",
    "last_capture_timestamp_ns", "last_event_timestamp_ns", "packet_count",
    "forward_packet_count", "reverse_packet_count", "close_reason",
}
SUMMARY_FIELDS = {
    "schema_version", "task", "kind", "status", "input", "capture_id",
    "pcap", "flows", "exported_flows", "exported_checkpoints",
    "parser_errors", "ingest_errors",
}
PCAP_SUMMARY_FIELDS = {
    "records_read", "packets_parsed", "parser_errors", "captured_bytes", "wire_bytes"
}
FLOW_SUMMARY_FIELDS = {"packets_accepted", "flow_generations_created", "flows_closed"}
TABLE_COLUMNS = {
    "metadata": {"key", "value"},
    "snapshot": {
        "generation", "checkpoint", "capture_id", "protocol", "low_ip", "low_port",
        "high_ip", "high_port", "forward_source_ip", "forward_source_port",
        "clock_domain", "packet_count", "checkpoint_timestamp_ns", "features",
    },
    "flow": {
        "export_ordinal", "generation", "capture_id", "protocol", "low_ip", "low_port",
        "high_ip", "high_port", "forward_source_ip", "forward_source_port",
        "clock_domain", "creation_timestamp_ns", "last_capture_timestamp_ns",
        "last_event_timestamp_ns", "packet_count", "forward_packet_count",
        "reverse_packet_count", "close_reason",
    },
    "exporter_summary": {
        "capture_id", "records_read", "packets_parsed", "parser_errors",
        "captured_bytes", "wire_bytes", "packets_accepted", "flow_generations_created",
        "flows_closed", "exported_flows", "exported_checkpoints", "ingest_errors",
    },
}
METADATA_KEYS = {
    "schema_version", "task", "contract_sha256", "exporter_sha256",
    "producer_sha256", "source_sha256", "capture_id",
}


def progress(message: str) -> None:
    print(f"[T3.5 snapshot-shard] {message}", flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
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


def resolve_path(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def is_int(value: Any, minimum: int = INT64_MIN, maximum: int = INT64_MAX) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def require_int(
    value: Any, name: str, minimum: int = INT64_MIN, maximum: int = INT64_MAX
) -> int:
    if not is_int(value, minimum, maximum):
        raise ValueError(f"{name} must be an integer in range [{minimum}, {maximum}]")
    return value


def require_exact_fields(value: Mapping[str, Any], expected: set[str], kind: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{kind} fields mismatch: {sorted(set(value) ^ expected)}")


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


def require_ipv4(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a canonical IPv4 string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a canonical IPv4 string") from error
    if address.version != 4 or str(address) != value:
        raise ValueError(f"{name} must be a canonical IPv4 string")
    return value


def validate_identity(value: Mapping[str, Any]) -> tuple[Any, ...]:
    protocol = value.get("protocol")
    if protocol not in PROTOCOLS:
        raise ValueError("protocol must be tcp or udp")
    low_ip = require_ipv4(value.get("low_ip"), "low_ip")
    high_ip = require_ipv4(value.get("high_ip"), "high_ip")
    low_port = require_int(value.get("low_port"), "low_port", 0, 65535)
    high_port = require_int(value.get("high_port"), "high_port", 0, 65535)
    forward_ip = require_ipv4(value.get("forward_source_ip"), "forward_source_ip")
    forward_port = require_int(
        value.get("forward_source_port"), "forward_source_port", 0, 65535
    )
    if (forward_ip, forward_port) not in {
        (low_ip, low_port),
        (high_ip, high_port),
    }:
        raise ValueError("forward source is not one of the canonical endpoints")
    return protocol, low_ip, low_port, high_ip, high_port, forward_ip, forward_port


def validate_common(value: Mapping[str, Any], kind: str, capture_id: str) -> None:
    if (
        value.get("schema_version") != 1
        or isinstance(value.get("schema_version"), bool)
        or value.get("task") != TASK
        or value.get("kind") != kind
        or value.get("capture_id") != capture_id
    ):
        raise ValueError(f"invalid {kind} envelope")


def validate_snapshot(value: Mapping[str, Any], capture_id: str) -> tuple[Any, ...]:
    require_exact_fields(value, SNAPSHOT_FIELDS, "snapshot")
    validate_common(value, "snapshot", capture_id)
    identity = validate_identity(value)
    generation = require_int(value.get("generation"), "generation", 1, INT64_MAX)
    clock = value.get("clock_domain")
    if clock not in CLOCK_DOMAINS:
        raise ValueError("invalid snapshot clock_domain")
    checkpoint = value.get("checkpoint")
    if checkpoint not in CHECKPOINTS:
        raise ValueError("invalid checkpoint")
    packet_count = require_int(value.get("packet_count"), "packet_count", 0, INT64_MAX)
    if packet_count != CHECKPOINTS[checkpoint]:
        raise ValueError("checkpoint packet_count mismatch")
    timestamp = require_int(
        value.get("checkpoint_timestamp_ns"), "checkpoint_timestamp_ns"
    )
    features = value.get("features")
    if not isinstance(features, list) or len(features) != FEATURE_COUNT:
        raise ValueError("snapshot must contain exactly 54 features")
    normalized: list[float] = []
    for index, item in enumerate(features):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError(f"feature[{index}] must be numeric")
        number = float(item)
        if not math.isfinite(number):
            raise ValueError(f"feature[{index}] must be finite")
        normalized.append(number)
    if normalized[1] != float(packet_count):
        raise ValueError("feature[1] must equal checkpoint packet_count")
    feature_blob = struct.pack("<54d", *normalized)
    return (
        generation,
        checkpoint,
        capture_id,
        *identity,
        clock,
        packet_count,
        timestamp,
        feature_blob,
    )


def validate_flow(value: Mapping[str, Any], capture_id: str) -> tuple[Any, ...]:
    require_exact_fields(value, FLOW_FIELDS, "flow")
    validate_common(value, "flow", capture_id)
    ordinal = require_int(value.get("export_ordinal"), "export_ordinal", 1, INT64_MAX)
    identity = validate_identity(value)
    generation = require_int(value.get("generation"), "generation", 1, INT64_MAX)
    clock = value.get("clock_domain")
    if clock not in CLOCK_DOMAINS:
        raise ValueError("invalid flow clock_domain")
    creation = require_int(value.get("creation_timestamp_ns"), "creation_timestamp_ns")
    last_capture = require_int(
        value.get("last_capture_timestamp_ns"), "last_capture_timestamp_ns"
    )
    last_event = require_int(value.get("last_event_timestamp_ns"), "last_event_timestamp_ns")
    packet_count = require_int(value.get("packet_count"), "packet_count", 1, INT64_MAX)
    forward_count = require_int(
        value.get("forward_packet_count"), "forward_packet_count", 0, INT64_MAX
    )
    reverse_count = require_int(
        value.get("reverse_packet_count"), "reverse_packet_count", 0, INT64_MAX
    )
    if forward_count + reverse_count != packet_count:
        raise ValueError("flow directional packet accounting mismatch")
    reason = value.get("close_reason")
    if reason not in CLOSE_REASONS:
        raise ValueError("invalid close_reason")
    return (
        ordinal,
        generation,
        capture_id,
        *identity,
        clock,
        creation,
        last_capture,
        last_event,
        packet_count,
        forward_count,
        reverse_count,
        reason,
    )


def validate_summary_envelope(
    value: Mapping[str, Any], capture_id: str, pcap: Path
) -> dict[str, int]:
    require_exact_fields(value, SUMMARY_FIELDS, "summary")
    validate_common(value, "summary", capture_id)
    if value.get("status") != "passed" or not isinstance(value.get("input"), str):
        raise ValueError("summary status/input mismatch")
    try:
        input_matches = Path(value["input"]).resolve() == pcap.resolve()
    except (OSError, ValueError):
        input_matches = False
    if not input_matches:
        raise ValueError("summary input mismatch")
    pcap_counts = value.get("pcap")
    flow_counts = value.get("flows")
    if not isinstance(pcap_counts, Mapping) or not isinstance(flow_counts, Mapping):
        raise ValueError("summary nested counters are missing")
    require_exact_fields(pcap_counts, PCAP_SUMMARY_FIELDS, "summary.pcap")
    require_exact_fields(flow_counts, FLOW_SUMMARY_FIELDS, "summary.flows")
    counters: dict[str, int] = {}
    for name in PCAP_SUMMARY_FIELDS:
        counters[name] = require_int(pcap_counts.get(name), f"pcap.{name}", 0, INT64_MAX)
    nested_parser_errors = counters["parser_errors"]
    for name in FLOW_SUMMARY_FIELDS:
        counters[name] = require_int(flow_counts.get(name), f"flows.{name}", 0, INT64_MAX)
    for name in ("exported_flows", "exported_checkpoints", "parser_errors", "ingest_errors"):
        counters[name] = require_int(value.get(name), name, 0, INT64_MAX)
    if (
        counters["records_read"]
        != counters["packets_parsed"] + counters["parser_errors"]
        or counters["packets_accepted"] != counters["packets_parsed"]
        or nested_parser_errors != counters["parser_errors"]
        or counters["ingest_errors"] != 0
    ):
        raise ValueError("summary packet accounting mismatch")
    return counters


def capture_spec(contract: Mapping[str, Any], capture_id: str) -> Mapping[str, Any]:
    captures = contract.get("captures")
    if not isinstance(captures, list):
        raise ValueError("contract captures are missing")
    matches = [item for item in captures if isinstance(item, Mapping) and item.get("id") == capture_id]
    if len(matches) != 1:
        raise ValueError(f"unknown or duplicate capture id: {capture_id}")
    return matches[0]


def staging_spec(contract: Mapping[str, Any]) -> Mapping[str, Any]:
    execution = contract.get("execution_pipeline")
    replay = contract.get("replay")
    if not isinstance(execution, Mapping) or not isinstance(replay, Mapping):
        raise ValueError("contract replay pipeline is missing")
    staging = replay.get("staging")
    schedule = replay.get("checkpoint_schedule")
    if (
        contract.get("schema_version") != SCHEMA_VERSION
        or contract.get("task") != TASK
        or execution.get("mode") != "checkpointed_hybrid"
        or execution.get("replay_host") != "ubuntu_24_04_vmware"
        or execution.get("scratch_policy")
        != "ubuntu_local_scratch_then_atomic_copy_to_workspace"
        or not is_int(execution.get("progress_heartbeat_seconds"), 1, 3600)
        or schedule != [
            {"name": name, "packet_count": CHECKPOINTS[name]}
            for name in CHECKPOINT_ORDER
        ]
        or replay.get("emit_only_reached_checkpoints") is not True
        or replay.get("synthetic_terminal_checkpoint_allowed") is not False
        or replay.get("float_serialization")
        != "max_digits10_json_to_ieee754_little_endian_float64_blob"
        or not isinstance(staging, Mapping)
        or staging.get("database_name") != DATABASE_NAME
        or staging.get("receipt_name") != RECEIPT_NAME
        or staging.get("checkpoint_granularity") != "one_capture"
        or not is_int(staging.get("application_id"), 1, INT64_MAX)
        or not is_int(staging.get("user_version"), 1, INT64_MAX)
        or staging.get("raw_packets_or_payload_stored") is not False
    ):
        raise ValueError("invalid T3.5 snapshot staging contract")
    return staging


def validate_contract_references(root: Path, contract: Mapping[str, Any]) -> Mapping[str, Any]:
    reference = contract.get("prerequisites", {}).get("label_join_contract")
    if not isinstance(reference, Mapping):
        raise ValueError("label join contract reference is missing")
    path = resolve_path(root, reference.get("path", ""))
    if not path.is_file() or sha256_path(path) != reference.get("sha256"):
        raise ValueError("label join contract reference mismatch")
    label_contract = load_json(path)
    if label_contract.get("task") != "T3.3":
        raise ValueError("referenced label join contract is invalid")
    return label_contract


def expected_parser_exclusions(
    label_contract: Mapping[str, Any], capture_id: str
) -> int:
    try:
        value = label_contract["exporter"]["parser_exclusion_policy"][
            "expected_by_capture"
        ][capture_id]["total"]
    except (KeyError, TypeError) as error:
        raise ValueError("expected parser exclusions are missing") from error
    return require_int(value, "expected parser exclusions", 0, INT64_MAX)


def output_directory(root: Path, contract: Mapping[str, Any], capture_id: str) -> Path:
    staging = staging_spec(contract)
    return resolve_path(root, staging["directory"]) / capture_id


def validate_source(root: Path, capture: Mapping[str, Any]) -> dict[str, Any]:
    pcap_spec = capture.get("pcap")
    if not isinstance(pcap_spec, Mapping):
        raise ValueError("capture PCAP specification is missing")
    path = resolve_path(root, pcap_spec.get("path", ""))
    if not path.is_file():
        raise ValueError("capture PCAP is missing")
    before = path.stat()
    digest = sha256_path(path)
    after = path.stat()
    if (
        before.st_size != pcap_spec.get("size_bytes")
        or digest != pcap_spec.get("sha256")
        or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
    ):
        raise ValueError("capture PCAP identity mismatch")
    return {"path": pcap_spec["path"], "size_bytes": after.st_size, "sha256": digest}


def require_production_host(root: Path, contract: Mapping[str, Any]) -> None:
    if platform.system() != "Linux":
        raise RuntimeError("T3.5 replay requires Ubuntu 24.04 VMware")
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError as error:
        raise RuntimeError("cannot identify the Ubuntu replay host") from error
    workspace = contract["execution_pipeline"].get("replay_workspace")
    if (
        os_release.get("ID") != "ubuntu"
        or os_release.get("VERSION_ID") != "24.04"
        or root.resolve() != Path(workspace).resolve()
    ):
        raise RuntimeError("T3.5 replay requires the approved Ubuntu 24.04 VMware workspace")


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
        raise ValueError("scratch must be on a local filesystem distinct from the shared workspace")


class Heartbeat:
    def __init__(self, capture_id: str, interval: int) -> None:
        self.capture_id = capture_id
        self.interval = interval
        self.started = time.monotonic()
        self.stop = threading.Event()
        self.counts = {"flows": 0, "snapshots": 0}
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop.wait(self.interval):
            progress(
                f"capture={self.capture_id} status=running "
                f"flows={self.counts['flows']} snapshots={self.counts['snapshots']} "
                f"elapsed={time.monotonic() - self.started:.1f}s"
            )

    def __enter__(self) -> "Heartbeat":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop.set()
        self.thread.join(timeout=1)


def create_database(
    path: Path,
    contract: Mapping[str, Any],
    capture_id: str,
    metadata: Mapping[str, str],
) -> sqlite3.Connection:
    staging = staging_spec(contract)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA page_size=4096")
    connection.execute(f"PRAGMA application_id={staging['application_id']}")
    connection.execute(f"PRAGMA user_version={staging['user_version']}")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript("""
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
        CREATE TABLE snapshot(
            generation INTEGER NOT NULL,
            checkpoint TEXT NOT NULL CHECK(checkpoint IN ('F3','F5','F7','F9')),
            capture_id TEXT NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
            low_ip TEXT NOT NULL, low_port INTEGER NOT NULL,
            high_ip TEXT NOT NULL, high_port INTEGER NOT NULL,
            forward_source_ip TEXT NOT NULL, forward_source_port INTEGER NOT NULL,
            clock_domain TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            checkpoint_timestamp_ns INTEGER NOT NULL,
            features BLOB NOT NULL CHECK(length(features)=432),
            PRIMARY KEY(generation,checkpoint)
        ) STRICT;
        CREATE TABLE flow(
            export_ordinal INTEGER PRIMARY KEY,
            generation INTEGER NOT NULL UNIQUE,
            capture_id TEXT NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
            low_ip TEXT NOT NULL, low_port INTEGER NOT NULL,
            high_ip TEXT NOT NULL, high_port INTEGER NOT NULL,
            forward_source_ip TEXT NOT NULL, forward_source_port INTEGER NOT NULL,
            clock_domain TEXT NOT NULL,
            creation_timestamp_ns INTEGER NOT NULL,
            last_capture_timestamp_ns INTEGER NOT NULL,
            last_event_timestamp_ns INTEGER NOT NULL,
            packet_count INTEGER NOT NULL,
            forward_packet_count INTEGER NOT NULL,
            reverse_packet_count INTEGER NOT NULL,
            close_reason TEXT NOT NULL
        ) STRICT;
        CREATE TABLE exporter_summary(
            capture_id TEXT PRIMARY KEY,
            records_read INTEGER NOT NULL,
            packets_parsed INTEGER NOT NULL,
            parser_errors INTEGER NOT NULL,
            captured_bytes INTEGER NOT NULL,
            wire_bytes INTEGER NOT NULL,
            packets_accepted INTEGER NOT NULL,
            flow_generations_created INTEGER NOT NULL,
            flows_closed INTEGER NOT NULL,
            exported_flows INTEGER NOT NULL,
            exported_checkpoints INTEGER NOT NULL,
            ingest_errors INTEGER NOT NULL
        ) STRICT;
    """)
    values = {**metadata, "capture_id": capture_id}
    connection.executemany("INSERT INTO metadata VALUES(?,?)", values.items())
    connection.commit()
    return connection


def exporter_command(exporter: Path, pcap: Path, capture_id: str) -> list[str]:
    prefix = [sys.executable, str(exporter)] if exporter.suffix.lower() == ".py" else [str(exporter)]
    return [*prefix, "--input", str(pcap), "--capture-id", capture_id]


def consume_exporter(
    connection: sqlite3.Connection,
    exporter: Path,
    pcap: Path,
    capture_id: str,
    expected_exclusions: int,
    stderr_path: Path,
    heartbeat_seconds: int,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> dict[str, int]:
    stderr_output = stderr_path.open("w", encoding="utf-8", newline="\n")
    try:
        process = popen_factory(
            exporter_command(exporter, pcap, capture_id),
            cwd=pcap.parent,
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
    flow_count = 0
    snapshot_count = 0
    summary: dict[str, Any] | None = None
    try:
        with Heartbeat(capture_id, heartbeat_seconds) as heartbeat:
            for line_number, line in enumerate(process.stdout, start=1):
                if len(line) > 1024 * 1024:
                    raise ValueError("exporter JSON line exceeds 1 MiB")
                value = parse_json_line(line, f"{capture_id}:{line_number}")
                kind = value.get("kind")
                if summary is not None:
                    raise ValueError("exporter emitted a record after summary")
                if kind == "snapshot":
                    connection.execute(
                        "INSERT INTO snapshot VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        validate_snapshot(value, capture_id),
                    )
                    snapshot_count += 1
                    heartbeat.counts["snapshots"] = snapshot_count
                elif kind == "flow":
                    connection.execute(
                        "INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        validate_flow(value, capture_id),
                    )
                    flow_count += 1
                    heartbeat.counts["flows"] = flow_count
                elif kind == "summary":
                    summary = value
                else:
                    raise ValueError(f"unknown exporter record kind: {kind}")
                if (flow_count + snapshot_count) % 10_000 == 0:
                    connection.commit()
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
    if return_code != 0:
        error_text = stderr_path.read_text(encoding="utf-8")
        raise ValueError(f"exporter failed rc={return_code}: {error_text[-2000:]}")
    if summary is None:
        raise ValueError("exporter omitted summary")
    counters = validate_summary_envelope(summary, capture_id, pcap)
    if (
        counters["parser_errors"] != expected_exclusions
        or counters["exported_flows"] != flow_count
        or counters["flow_generations_created"] != flow_count
        or counters["flows_closed"] != flow_count
        or counters["exported_checkpoints"] != snapshot_count
    ):
        raise ValueError("summary replay accounting mismatch")
    connection.execute(
        "INSERT INTO exporter_summary VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            capture_id,
            counters["records_read"], counters["packets_parsed"],
            counters["parser_errors"], counters["captured_bytes"], counters["wire_bytes"],
            counters["packets_accepted"], counters["flow_generations_created"],
            counters["flows_closed"], counters["exported_flows"],
            counters["exported_checkpoints"], counters["ingest_errors"],
        ),
    )
    connection.commit()
    return counters


def validate_database_contents(
    connection: sqlite3.Connection,
    contract: Mapping[str, Any],
    capture_id: str,
    expected_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    staging = staging_spec(contract)
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("snapshot shard integrity_check failed")
    if (
        connection.execute("PRAGMA application_id").fetchone()[0] != staging["application_id"]
        or connection.execute("PRAGMA user_version").fetchone()[0] != staging["user_version"]
    ):
        raise ValueError("snapshot shard SQLite identity mismatch")
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if tables != {"metadata", "snapshot", "flow", "exporter_summary"}:
        raise ValueError("snapshot shard table set mismatch")
    for table, expected_columns in TABLE_COLUMNS.items():
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if columns != expected_columns:
            raise ValueError(f"snapshot shard {table} column set mismatch")
    metadata_keys = {row[0] for row in connection.execute("SELECT key FROM metadata")}
    if metadata_keys != METADATA_KEYS:
        raise ValueError("snapshot shard metadata key set mismatch")
    flow_count, minimum_generation, maximum_generation, minimum_ordinal, maximum_ordinal = connection.execute(
        "SELECT COUNT(*),MIN(generation),MAX(generation),MIN(export_ordinal),MAX(export_ordinal) FROM flow"
    ).fetchone()
    if flow_count == 0:
        if any(value is not None for value in (minimum_generation, maximum_generation, minimum_ordinal, maximum_ordinal)):
            raise ValueError("empty flow generation accounting mismatch")
    elif (
        minimum_generation != 1
        or maximum_generation != flow_count
        or minimum_ordinal != 1
        or maximum_ordinal != flow_count
    ):
        raise ValueError("flow generation/export ordinal sequence is not contiguous")
    mismatch = connection.execute("""
        SELECT COUNT(*) FROM snapshot s LEFT JOIN flow f USING(generation)
        WHERE f.generation IS NULL OR s.capture_id<>f.capture_id OR s.protocol<>f.protocol
           OR s.low_ip<>f.low_ip OR s.low_port<>f.low_port
           OR s.high_ip<>f.high_ip OR s.high_port<>f.high_port
           OR s.forward_source_ip<>f.forward_source_ip
           OR s.forward_source_port<>f.forward_source_port
           OR s.clock_domain<>f.clock_domain
    """).fetchone()[0]
    invalid_schedule = connection.execute("""
        SELECT COUNT(*) FROM snapshot s JOIN flow f USING(generation)
        WHERE s.packet_count<>CASE s.checkpoint WHEN 'F3' THEN 3 WHEN 'F5' THEN 5
             WHEN 'F7' THEN 7 WHEN 'F9' THEN 9 END
           OR f.packet_count<s.packet_count
    """).fetchone()[0]
    snapshot_count = connection.execute("SELECT COUNT(*) FROM snapshot").fetchone()[0]
    expected_snapshot_count = connection.execute("""
        SELECT COALESCE(SUM((packet_count>=3)+(packet_count>=5)+(packet_count>=7)+(packet_count>=9)),0)
        FROM flow
    """).fetchone()[0]
    if mismatch or invalid_schedule or snapshot_count != expected_snapshot_count:
        raise ValueError("snapshot identity, schedule, or completeness mismatch")
    by_checkpoint = {
        name: count
        for name, count in connection.execute(
            "SELECT checkpoint,COUNT(*) FROM snapshot GROUP BY checkpoint"
        )
    }
    for name in CHECKPOINT_ORDER:
        by_checkpoint.setdefault(name, 0)
    scanned = 0
    for generation, checkpoint, packet_count, blob in connection.execute(
        "SELECT generation,checkpoint,packet_count,features FROM snapshot ORDER BY generation,checkpoint"
    ):
        if not isinstance(blob, bytes) or len(blob) != FEATURE_BLOB_SIZE:
            raise ValueError("snapshot feature BLOB size mismatch")
        features = struct.unpack("<54d", blob)
        if not all(math.isfinite(item) for item in features):
            raise ValueError("snapshot feature BLOB contains non-finite value")
        if features[1] != float(packet_count):
            raise ValueError(
                f"snapshot feature packet_count mismatch: generation={generation} checkpoint={checkpoint}"
            )
        scanned += 1
    summary_row = connection.execute(
        "SELECT records_read,packets_parsed,parser_errors,captured_bytes,wire_bytes,"
        "packets_accepted,flow_generations_created,flows_closed,exported_flows,"
        "exported_checkpoints,ingest_errors FROM exporter_summary WHERE capture_id=?",
        (capture_id,),
    ).fetchone()
    if summary_row is None or connection.execute("SELECT COUNT(*) FROM exporter_summary").fetchone()[0] != 1:
        raise ValueError("snapshot shard summary row mismatch")
    names = (
        "records_read", "packets_parsed", "parser_errors", "captured_bytes", "wire_bytes",
        "packets_accepted", "flow_generations_created", "flows_closed", "exported_flows",
        "exported_checkpoints", "ingest_errors",
    )
    summary = dict(zip(names, summary_row, strict=True))
    if (
        summary["exported_flows"] != flow_count
        or summary["exported_checkpoints"] != snapshot_count
        or summary["flow_generations_created"] != flow_count
        or summary["flows_closed"] != flow_count
        or summary["ingest_errors"] != 0
        or summary["records_read"] != summary["packets_parsed"] + summary["parser_errors"]
        or summary["packets_accepted"] != summary["packets_parsed"]
    ):
        raise ValueError("snapshot shard stored summary mismatch")
    if expected_summary is not None and summary != dict(expected_summary):
        raise ValueError("snapshot shard receipt summary mismatch")
    return {
        "flows": flow_count,
        "snapshots": scanned,
        "by_checkpoint": {name: by_checkpoint[name] for name in CHECKPOINT_ORDER},
        "summary": summary,
    }


def finalize_database(
    path: Path, connection: sqlite3.Connection, contract: Mapping[str, Any], capture_id: str
) -> dict[str, Any]:
    metrics = validate_database_contents(connection, contract, capture_id)
    connection.execute("PRAGMA optimize")
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.commit()
    connection.close()
    if path.with_name(path.name + "-wal").exists() or path.with_name(path.name + "-shm").exists():
        raise ValueError("snapshot shard WAL/SHM remained after clean close")
    with contextlib.closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)) as check:
        if check.execute("PRAGMA journal_mode").fetchone() != ("delete",):
            raise ValueError("snapshot shard journal mode is not DELETE")
        validate_database_contents(check, contract, capture_id, metrics["summary"])
    return metrics


def validate_checkpoint(
    root: Path,
    contract_path: Path,
    capture_id: str,
    exporter: Path,
    output: Path,
    rehash_source: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    exporter = exporter.resolve()
    output = output.resolve()
    contract = load_json(contract_path)
    staging_spec(contract)
    capture = capture_spec(contract, capture_id)
    expected_output = output_directory(root, contract, capture_id).resolve()
    if output != expected_output:
        raise ValueError("output must match the contract capture shard directory")
    database = output / DATABASE_NAME
    receipt_path = output / RECEIPT_NAME
    if not database.is_file() or not receipt_path.is_file():
        raise ValueError("snapshot checkpoint is incomplete")
    if database.with_name(database.name + "-wal").exists() or database.with_name(database.name + "-shm").exists():
        raise ValueError("snapshot checkpoint has WAL/SHM sidecars")
    receipt = load_json(receipt_path)
    sqlite_record = receipt.get("sqlite")
    receipt_summary = receipt.get("summary")
    receipt_checkpoints = receipt.get("snapshots_by_checkpoint")
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("task") != TASK
        or receipt.get("kind") != KIND
        or receipt.get("status") != "passed"
        or receipt.get("capture_id") != capture_id
        or receipt.get("producer", {}).get("sha256") != sha256_path(Path(__file__))
        or receipt.get("task_contract", {}).get("sha256") != sha256_path(contract_path)
        or receipt.get("exporter", {}).get("path") != str(exporter)
        or receipt.get("exporter", {}).get("sha256") != sha256_path(exporter)
        or not isinstance(sqlite_record, Mapping)
        or sqlite_record.get("sha256") != sha256_path(database)
        or sqlite_record.get("size_bytes") != database.stat().st_size
        or sqlite_record.get("journal_mode") != "delete"
        or sqlite_record.get("application_id") != staging_spec(contract)["application_id"]
        or sqlite_record.get("user_version") != staging_spec(contract)["user_version"]
        or sqlite_record.get("integrity_check") != "ok"
        or not isinstance(receipt_summary, Mapping)
        or set(receipt_summary) != {
            "records_read", "packets_parsed", "parser_errors", "captured_bytes",
            "wire_bytes", "packets_accepted", "flow_generations_created",
            "flows_closed", "exported_flows", "exported_checkpoints", "ingest_errors",
        }
        or not isinstance(receipt_checkpoints, Mapping)
        or set(receipt_checkpoints) != set(CHECKPOINT_ORDER)
        or receipt.get("source", {}).get("path") != capture["pcap"]["path"]
        or receipt.get("source", {}).get("size_bytes") != capture["pcap"]["size_bytes"]
        or receipt.get("source", {}).get("sha256") != capture["pcap"]["sha256"]
    ):
        raise ValueError("snapshot checkpoint receipt mismatch")
    label_contract = validate_contract_references(root, contract)
    if receipt_summary["parser_errors"] != expected_parser_exclusions(
        label_contract, capture_id
    ):
        raise ValueError("snapshot checkpoint parser exclusion provenance mismatch")
    if rehash_source:
        validate_source(root, capture)
    with contextlib.closing(
        sqlite3.connect(f"file:{database.as_posix()}?mode=ro&immutable=1", uri=True)
    ) as connection:
        if connection.execute("PRAGMA journal_mode").fetchone() != ("delete",):
            raise ValueError("snapshot checkpoint journal mode mismatch")
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        if (
            metadata.get("capture_id") != capture_id
            or metadata.get("contract_sha256") != sha256_path(contract_path)
            or metadata.get("exporter_sha256") != sha256_path(exporter)
            or metadata.get("producer_sha256") != sha256_path(Path(__file__))
            or metadata.get("source_sha256") != capture["pcap"]["sha256"]
        ):
            raise ValueError("snapshot checkpoint metadata mismatch")
        metrics = validate_database_contents(
            connection, contract, capture_id, receipt_summary
        )
    if metrics["by_checkpoint"] != receipt_checkpoints:
        raise ValueError("snapshot checkpoint metric mismatch")
    return receipt


def build_capture(
    root: Path,
    contract_path: Path,
    capture_id: str,
    exporter: Path,
    scratch_root: Path,
    output: Path,
    popen_factory: Callable[..., Any] = subprocess.Popen,
) -> tuple[dict[str, Any], bool]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    exporter = exporter.resolve()
    scratch_root = scratch_root.resolve()
    output = output.resolve()
    contract = load_json(contract_path)
    staging_spec(contract)
    require_production_host(root, contract)
    expected_output = output_directory(root, contract, capture_id).resolve()
    if output != expected_output:
        raise ValueError("output must match the contract capture shard directory")
    if not exporter.is_file():
        raise ValueError("snapshot exporter does not exist")
    if output.exists():
        return validate_checkpoint(root, contract_path, capture_id, exporter, output), True
    require_local_scratch(scratch_root, root, output)
    capture = capture_spec(contract, capture_id)
    label_contract = validate_contract_references(root, contract)
    source = validate_source(root, capture)
    expected_exclusions = expected_parser_exclusions(label_contract, capture_id)
    contract_sha256 = sha256_path(contract_path)
    exporter_sha256 = sha256_path(exporter)
    producer_sha256 = sha256_path(Path(__file__))
    started = time.monotonic()
    progress(f"capture={capture_id} status=running")
    temporary_root = scratch_root / f"t35-snapshot-{uuid.uuid4().hex}"
    temporary_root.mkdir()
    try:
        database = temporary_root / DATABASE_NAME
        connection = create_database(
            database,
            contract,
            capture_id,
            {
                "schema_version": SCHEMA_VERSION,
                "task": TASK,
                "contract_sha256": contract_sha256,
                "exporter_sha256": exporter_sha256,
                "producer_sha256": producer_sha256,
                "source_sha256": source["sha256"],
            },
        )
        try:
            counters = consume_exporter(
                connection,
                exporter,
                resolve_path(root, capture["pcap"]["path"]),
                capture_id,
                expected_exclusions,
                temporary_root / "exporter.stderr",
                contract["execution_pipeline"]["progress_heartbeat_seconds"],
                popen_factory,
            )
            metrics = finalize_database(database, connection, contract, capture_id)
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
            receipt = {
                "schema_version": SCHEMA_VERSION,
                "task": TASK,
                "kind": KIND,
                "status": "passed",
                "capture_id": capture_id,
                "generated_at_utc": utc_now(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "producer": {
                    "path": "scripts/build_t35_snapshot_shard.py",
                    "sha256": producer_sha256,
                },
                "task_contract": {
                    "path": relative_path(contract_path, root),
                    "sha256": contract_sha256,
                },
                "exporter": {"path": str(exporter), "sha256": exporter_sha256},
                "source": source,
                "summary": counters,
                "snapshots_by_checkpoint": metrics["by_checkpoint"],
                "sqlite": {
                    "path": relative_path(output / DATABASE_NAME, root),
                    "size_bytes": staged_database.stat().st_size,
                    "sha256": sha256_path(staged_database),
                    "application_id": staging_spec(contract)["application_id"],
                    "user_version": staging_spec(contract)["user_version"],
                    "integrity_check": "ok",
                    "journal_mode": "delete",
                },
                "checks": [
                    {"name": "source.content_addressed", "status": "passed"},
                    {"name": "exporter.strict_jsonl", "status": "passed"},
                    {"name": "replay.identity_schedule_and_accounting", "status": "passed"},
                    {"name": "snapshot.features_finite_little_endian_float64", "status": "passed"},
                    {"name": "sqlite.integrity_and_no_wal", "status": "passed"},
                ],
            }
            write_json_atomic(staging / RECEIPT_NAME, receipt)
            os.replace(staging, output)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    progress(
        f"capture={capture_id} status=passed flows={counters['exported_flows']} "
        f"snapshots={counters['exported_checkpoints']} elapsed={receipt['elapsed_seconds']:.1f}s"
    )
    return receipt, False


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--capture-id", required=True)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument(
            "--contract", type=Path, default=root / "config/cicids2017-snapshot-contract.json"
        )
        command.add_argument("--exporter", type=Path, required=True)
        command.add_argument("--scratch", type=Path, default=Path("/tmp"))
        command.add_argument("--output", type=Path)
        command.add_argument("--rehash-source", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract = load_json(args.contract.resolve())
        output = args.output or output_directory(root, contract, args.capture_id)
        if args.command == "run":
            build_capture(
                root,
                args.contract,
                args.capture_id,
                args.exporter,
                args.scratch,
                output,
            )
        else:
            validate_checkpoint(
                root,
                args.contract,
                args.capture_id,
                args.exporter,
                output,
                rehash_source=args.rehash_source,
            )
        return 0
    except (OSError, RuntimeError, ValueError, sqlite3.Error, struct.error) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
