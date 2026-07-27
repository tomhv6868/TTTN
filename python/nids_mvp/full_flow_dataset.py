"""Build the immutable T9.1 terminal-flow Parquet dataset."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import shutil
import sqlite3
import struct
import sys
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T9.1"
FEATURE_SCHEMA_ID = "nids.terminal_flow_features.v1"
FEATURE_SCHEMA_SHA256 = "ebe260327df74e265c2dc89178e3d038c3183de55603187c4b1e503e06173dfc"
SNAPSHOT_CONTRACT_SHA256 = "5b3fef6e8539b78227810c44facb6e8583d8b7417b76a65685f1be84e0e93a08"
PYARROW_VERSION = "23.0.1"
FEATURE_COUNT = 70
FEATURE_BLOB_SIZE = FEATURE_COUNT * 8
FETCH_ROWS = 16_384
ROW_GROUP_ROWS = 65_536
TERMINAL_SHARD_APPLICATION_ID = 0x4E543931
TERMINAL_SHARD_USER_VERSION = 1
PARTITIONS = ("train", "validation", "test")
EXPECTED_CAPTURE_ROWS = {
    "monday-working-hours": 425_166,
    "tuesday-working-hours": 357_558,
    "wednesday-working-hours": 664_163,
    "thursday-working-hours": 411_141,
    "friday-working-hours": 578_024,
}
EXPECTED_TOTAL_ROWS = 2_436_052
EXPECTED_ASSIGNED_ROWS = 2_366_094
EXPECTED_QUARANTINE_ROWS = 69_958
EXPECTED_FAMILY_COUNTS = {
    "Benign": 1_848_412,
    "FTP-Bruteforce": 4_942,
    "SSH-Bruteforce": 2_503,
    "PortScan": 158_976,
    "DoS": 350_338,
    "Other": 923,
}
EXPECTED_QUARANTINE_COUNTS = {
    "audit_conflict": 2_218,
    "mixed_candidate_classes": 66_035,
    "no_eligible_candidate": 1_705,
}
FAMILY_BY_ASSIGNED_CLASS = {
    "BENIGN": "Benign",
    "FTP-Patator": "FTP-Bruteforce",
    "SSH-Patator": "SSH-Bruteforce",
    "PortScan": "PortScan",
    "DDoS": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Hulk": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "Bot": "Other",
    "Infiltration": "Other",
    "Web Attack – Brute Force": "Other",
    "Web Attack – Sql Injection": "Other",
    "Web Attack – XSS": "Other",
}
REQUIRED_TERMINAL_COLUMNS = (
    ("flow_id", "INTEGER"),
    ("export_ordinal", "INTEGER"),
    ("generation", "INTEGER"),
    ("capture_id", "TEXT"),
    ("protocol", "INTEGER"),
    ("low_ip", "INTEGER"),
    ("low_port", "INTEGER"),
    ("high_ip", "INTEGER"),
    ("high_port", "INTEGER"),
    ("forward_source_ip", "INTEGER"),
    ("forward_source_port", "INTEGER"),
    ("clock_domain", "TEXT"),
    ("creation_timestamp_ns", "INTEGER"),
    ("last_capture_timestamp_ns", "INTEGER"),
    ("last_event_timestamp_ns", "INTEGER"),
    ("packet_count", "INTEGER"),
    ("forward_packet_count", "INTEGER"),
    ("reverse_packet_count", "INTEGER"),
    ("close_reason", "TEXT"),
    ("features", "BLOB"),
)
METADATA_FIELDS = (
    ("flow_id", pa.uint64(), False),
    ("capture_id", pa.string(), False),
    ("export_ordinal", pa.uint64(), False),
    ("flow_generation", pa.uint64(), False),
    ("protocol", pa.uint8(), False),
    ("low_ip", pa.uint32(), False),
    ("low_port", pa.uint16(), False),
    ("high_ip", pa.uint32(), False),
    ("high_port", pa.uint16(), False),
    ("forward_source_ip", pa.uint32(), False),
    ("forward_source_port", pa.uint16(), False),
    ("clock_domain", pa.string(), False),
    ("creation_timestamp_ns", pa.int64(), False),
    ("last_capture_timestamp_ns", pa.int64(), False),
    ("last_event_timestamp_ns", pa.int64(), False),
    ("packet_count", pa.uint64(), False),
    ("forward_packet_count", pa.uint64(), False),
    ("reverse_packet_count", pa.uint64(), False),
    ("paired_f9", pa.bool_(), False),
    ("close_reason", pa.string(), False),
    ("label_status", pa.string(), False),
    ("assigned_class", pa.string(), True),
    ("label_family", pa.string(), True),
    ("label_binary", pa.bool_(), True),
    ("assignment_method", pa.string(), True),
    ("quarantine_reason", pa.string(), True),
    ("partition", pa.string(), True),
)
DICTIONARY_COLUMNS = [
    "capture_id",
    "clock_domain",
    "close_reason",
    "label_status",
    "assigned_class",
    "label_family",
    "assignment_method",
    "quarantine_reason",
    "partition",
]


@dataclass(frozen=True)
class DatabaseReference:
    path: Path
    size_bytes: int
    sha256: str
    application_id: int
    user_version: int


@dataclass(frozen=True)
class DatasetInputs:
    root: Path
    source: DatabaseReference
    assignment: DatabaseReference
    feature_schema_path: Path
    feature_schema_sha256: str
    split_map_path: Path
    split_map_sha256: str
    split_manifest_path: Path
    shard_root: Path
    output_root: Path
    capture_ids: tuple[str, ...]
    expected_capture_rows: Mapping[str, int] | None = None
    enforce_production_accounting: bool = False


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
            json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def resolve_inside(root: Path, value: str | Path) -> Path:
    candidate = Path(value)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def immutable_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro&immutable=1"


def open_immutable(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(immutable_uri(path), uri=True)


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def verify_database(reference: DatabaseReference, label: str) -> None:
    path = reference.path
    if (
        not path.is_file()
        or path.stat().st_size != reference.size_bytes
        or sha256_path(path) != reference.sha256
    ):
        raise ValueError(f"{label} content address mismatch")
    with contextlib.closing(open_immutable(path)) as connection:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != reference.application_id
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != reference.user_version
        ):
            raise ValueError(f"{label} SQLite identity mismatch")


def schema_fingerprint(schema: pa.Schema) -> str:
    payload = {
        "fields": [
            {"name": field.name, "type": str(field.type), "nullable": field.nullable}
            for field in schema
        ],
        "metadata": {
            key.decode(): value.decode()
            for key, value in sorted((schema.metadata or {}).items())
        },
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_feature_schema(path: Path, expected_sha256: str) -> tuple[list[str], list[dict[str, Any]]]:
    if not path.is_file() or sha256_path(path) != expected_sha256:
        raise ValueError("terminal feature schema content address mismatch")
    document = load_json(path)
    vector = document.get("feature_vector", {})
    features = document.get("features")
    profiles = document.get("feature_profiles")
    if (
        document.get("schema_id") != FEATURE_SCHEMA_ID
        or vector.get("length") != FEATURE_COUNT
        or vector.get("encoded_type") != "float64"
        or vector.get("finite_only") is not True
        or not isinstance(features, list)
        or len(features) != FEATURE_COUNT
        or not isinstance(profiles, list)
    ):
        raise ValueError("terminal feature schema mismatch")
    names: list[str] = []
    for index, feature in enumerate(features):
        if not isinstance(feature, Mapping) or feature.get("index") != index:
            raise ValueError("terminal feature ordering mismatch")
        name = feature.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("invalid terminal feature name")
        names.append(name)
    expected_profiles = [
        ("A", 0, 53, 54),
        ("B", 0, 60, 61),
        ("C", 0, 63, 64),
        ("D", 0, 65, 66),
        ("E", 0, 69, 70),
    ]
    observed_profiles = [
        (
            profile.get("id"),
            profile.get("start_index"),
            profile.get("end_index"),
            profile.get("length"),
        )
        for profile in profiles
        if isinstance(profile, Mapping)
    ]
    if observed_profiles != expected_profiles:
        raise ValueError("terminal feature profile mismatch")
    return names, [dict(profile) for profile in profiles]


def arrow_schema(
    feature_names: Sequence[str],
    feature_schema_sha256: str,
    split_map_sha256: str,
    profiles: Sequence[Mapping[str, Any]],
) -> pa.Schema:
    fields = [
        pa.field(name, data_type, nullable=nullable)
        for name, data_type, nullable in METADATA_FIELDS
    ]
    fields.extend(pa.field(name, pa.float64(), nullable=False) for name in feature_names)
    metadata = {
        b"nids.task": TASK.encode(),
        b"nids.feature_schema_id": FEATURE_SCHEMA_ID.encode(),
        b"nids.feature_schema_sha256": feature_schema_sha256.encode(),
        b"nids.split_map_sha256": split_map_sha256.encode(),
        b"nids.model_feature_columns": json.dumps(
            list(feature_names), ensure_ascii=False, separators=(",", ":")
        ).encode(),
        b"nids.feature_profiles": json.dumps(
            list(profiles), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode(),
        b"nids.test_partition_policy": b"sealed_until_model_lock",
    }
    return pa.schema(fields, metadata=metadata)


def database_reference(root: Path, value: Mapping[str, Any]) -> DatabaseReference:
    return DatabaseReference(
        path=resolve_inside(root, str(value.get("path", ""))),
        size_bytes=int(value.get("size_bytes", -1)),
        sha256=str(value.get("sha256", "")),
        application_id=int(value.get("application_id", -1)),
        user_version=int(value.get("user_version", -1)),
    )


def production_inputs(root: Path) -> DatasetInputs:
    root = root.resolve()
    if pa.__version__ != PYARROW_VERSION:
        raise RuntimeError(
            f"PyArrow version mismatch: observed={pa.__version__} expected={PYARROW_VERSION}"
        )
    snapshot_contract_path = root / "config/cicids2017-snapshot-contract.json"
    if sha256_path(snapshot_contract_path) != SNAPSHOT_CONTRACT_SHA256:
        raise ValueError("immutable T3.5 contract content address mismatch")
    contract = load_json(snapshot_contract_path)
    prerequisites = contract.get("prerequisites", {})
    captures = contract.get("captures")
    if not isinstance(captures, list):
        raise ValueError("T3.5 capture inventory missing")
    capture_ids = tuple(
        item.get("id") for item in captures if isinstance(item, Mapping)
    )
    if (
        len(capture_ids) != len(captures)
        or any(not isinstance(item, str) for item in capture_ids)
        or capture_ids != tuple(EXPECTED_CAPTURE_ROWS)
    ):
        raise ValueError("T3.5 capture inventory mismatch")
    split_manifest_path = root / "run_log/full-flow-v1/split/manifest.json"
    split_manifest = load_json(split_manifest_path)
    map_record = split_manifest.get("flow_map", {})
    split_map_path = resolve_inside(root, str(map_record.get("path", "")))
    if (
        split_manifest.get("task") != TASK
        or split_manifest.get("kind") != "terminal_flow_split_manifest"
        or split_manifest.get("status") != "complete"
        or map_record.get("rows") != EXPECTED_ASSIGNED_ROWS
        or not split_map_path.is_file()
        or split_map_path.stat().st_size != map_record.get("size_bytes")
        or sha256_path(split_map_path) != map_record.get("sha256")
    ):
        raise ValueError("terminal split manifest mismatch")
    return DatasetInputs(
        root=root,
        source=database_reference(root, prerequisites["source_database"]),
        assignment=database_reference(root, prerequisites["assignment_database"]),
        feature_schema_path=root / "config/terminal-flow-feature-schema-v1.json",
        feature_schema_sha256=FEATURE_SCHEMA_SHA256,
        split_map_path=split_map_path,
        split_map_sha256=str(map_record["sha256"]),
        split_manifest_path=split_manifest_path,
        shard_root=root / "run_log/full-flow-v1/terminal-shards",
        output_root=root / "run_log/full-flow-v1/dataset",
        capture_ids=capture_ids,
        expected_capture_rows=EXPECTED_CAPTURE_ROWS,
        enforce_production_accounting=True,
    )


def validate_terminal_table(connection: sqlite3.Connection) -> None:
    observed = [
        (row[1], row[2].upper())
        for row in connection.execute("PRAGMA table_info(terminal_flow)")
    ]
    if observed != list(REQUIRED_TERMINAL_COLUMNS):
        raise ValueError("terminal shard table schema mismatch")


def verify_shard(
    inputs: DatasetInputs, capture_id: str
) -> tuple[Path, dict[str, Any]]:
    directory = inputs.shard_root / capture_id
    database = directory / "terminal-flow-shard.sqlite3"
    manifest_path = directory / "manifest.json"
    if (
        not database.is_file()
        or not manifest_path.is_file()
        or database.with_name(database.name + "-wal").exists()
        or database.with_name(database.name + "-shm").exists()
    ):
        raise ValueError(f"terminal shard incomplete: {capture_id}")
    manifest = load_json(manifest_path)
    database_record = manifest.get("database", {})
    feature_record = manifest.get("feature_schema", {})
    source_record = manifest.get("source_database", {})
    producer_record = manifest.get("producer", {})
    exporter_record = manifest.get("exporter", {})
    reconciliation = manifest.get("oracle_reconciliation", {})
    expected_rows = (
        inputs.expected_capture_rows.get(capture_id)
        if inputs.expected_capture_rows is not None
        else database_record.get("rows")
    )
    if (
        manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_shard_manifest"
        or manifest.get("status") != "passed"
        or manifest.get("capture_id") != capture_id
        or database_record.get("size_bytes") != database.stat().st_size
        or database_record.get("sha256") != sha256_path(database)
        or database_record.get("application_id") != TERMINAL_SHARD_APPLICATION_ID
        or database_record.get("user_version") != TERMINAL_SHARD_USER_VERSION
        or database_record.get("journal_mode") != "delete"
        or database_record.get("integrity_check") != "ok"
        or database_record.get("rows") != expected_rows
        or feature_record.get("schema_id") != FEATURE_SCHEMA_ID
        or feature_record.get("sha256") != inputs.feature_schema_sha256
        or feature_record.get("feature_count") != FEATURE_COUNT
        or source_record.get("size_bytes") != inputs.source.size_bytes
        or source_record.get("sha256") != inputs.source.sha256
        or source_record.get("application_id") != inputs.source.application_id
        or source_record.get("user_version") != inputs.source.user_version
        or source_record.get("journal_mode") != "delete"
        or not is_sha256(producer_record.get("sha256"))
        or not is_sha256(exporter_record.get("sha256"))
        or reconciliation.get("key")
        != "capture_id_export_ordinal_then_exact_close_record"
        or reconciliation.get("matched_rows") != expected_rows
        or reconciliation.get("mismatches") != 0
    ):
        raise ValueError(f"terminal shard manifest mismatch: {capture_id}")
    with contextlib.closing(open_immutable(database)) as connection:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != TERMINAL_SHARD_APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != TERMINAL_SHARD_USER_VERSION
            or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
            or connection.execute("PRAGMA integrity_check").fetchone() != ("ok",)
        ):
            raise ValueError(f"terminal shard SQLite validation failed: {capture_id}")
        validate_terminal_table(connection)
    return database, manifest


def reconcile_terminal_source(
    shard: Path, source: Path, capture_id: str
) -> None:
    connection = sqlite3.connect(":memory:", uri=True)
    try:
        connection.execute("ATTACH DATABASE ? AS source", (immutable_uri(source),))
        connection.execute("ATTACH DATABASE ? AS shard", (immutable_uri(shard),))
        terminal_rows = """
            SELECT flow_id,capture_id,export_ordinal,protocol,low_ip,low_port,
                   high_ip,high_port,forward_source_ip,forward_source_port,generation,
                   creation_timestamp_ns,last_capture_timestamp_ns,last_event_timestamp_ns,
                   packet_count,forward_packet_count,reverse_packet_count,close_reason
            FROM shard.terminal_flow WHERE capture_id=?
        """
        source_rows = """
            SELECT flow_id,capture_id,export_ordinal,protocol,low_ip,low_port,
                   high_ip,high_port,forward_source_ip,forward_source_port,generation,
                   creation_timestamp_ns,last_capture_timestamp_ns,last_event_timestamp_ns,
                   packet_count,forward_packet_count,reverse_packet_count,close_reason
            FROM source.flow WHERE capture_id=?
        """
        shard_only = connection.execute(
            f"SELECT COUNT(*) FROM ({terminal_rows} EXCEPT {source_rows})",
            (capture_id, capture_id),
        ).fetchone()[0]
        source_only = connection.execute(
            f"SELECT COUNT(*) FROM ({source_rows} EXCEPT {terminal_rows})",
            (capture_id, capture_id),
        ).fetchone()[0]
        if shard_only or source_only:
            raise ValueError(
                f"terminal/source reconciliation failed: {capture_id} "
                f"shard_only={shard_only} source_only={source_only}"
            )
    finally:
        connection.close()


def load_capture_partitions(
    split_map: Path, capture_id: str
) -> dict[int, tuple[str, str]]:
    table = pq.read_table(
        split_map,
        columns=["capture_id", "flow_id", "partition", "partition_source"],
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    )
    values = table.to_pydict()
    result: dict[int, tuple[str, str]] = {}
    for row_capture, flow_id, partition, source in zip(
        values["capture_id"],
        values["flow_id"],
        values["partition"],
        values["partition_source"],
        strict=True,
    ):
        if (
            row_capture != capture_id
            or partition not in PARTITIONS
            or source
            not in {
                "legacy_f3",
                "locked_block_inheritance",
                "short_only_block_allocation",
            }
            or flow_id in result
        ):
            raise ValueError(f"invalid split row: {capture_id}/{flow_id}")
        result[int(flow_id)] = (str(partition), str(source))
    return result


def terminal_row_cursor(
    inputs: DatasetInputs, shard: Path, capture_id: str
) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    connection = sqlite3.connect(":memory:", uri=True)
    try:
        connection.execute("ATTACH DATABASE ? AS assignment", (immutable_uri(inputs.assignment.path),))
        connection.execute("ATTACH DATABASE ? AS shard", (immutable_uri(shard),))
        cursor = connection.execute(
            """
            SELECT t.flow_id,t.capture_id,t.export_ordinal,t.generation,t.protocol,
                   t.low_ip,t.low_port,t.high_ip,t.high_port,t.forward_source_ip,
                   t.forward_source_port,t.clock_domain,t.creation_timestamp_ns,
                   t.last_capture_timestamp_ns,t.last_event_timestamp_ns,t.packet_count,
                   t.forward_packet_count,t.reverse_packet_count,t.close_reason,t.features,
                   a.capture_id,a.assigned_class,a.assignment_method,
                   q.capture_id,q.reason
            FROM shard.terminal_flow t
            LEFT JOIN assignment.flow_assignment a ON a.flow_id=t.flow_id
            LEFT JOIN assignment.quarantine q ON q.flow_id=t.flow_id
            WHERE t.capture_id=?
            ORDER BY t.flow_id
            """,
            (capture_id,),
        )
        return connection, cursor
    except Exception:
        connection.close()
        raise


def destination_port(row: Sequence[Any]) -> int:
    low_ip, low_port = int(row[5]), int(row[6])
    high_ip, high_port = int(row[7]), int(row[8])
    forward_ip, forward_port = int(row[9]), int(row[10])
    if (forward_ip, forward_port) == (low_ip, low_port):
        return high_port
    if (forward_ip, forward_port) == (high_ip, high_port):
        return low_port
    raise ValueError(f"forward source is not a canonical endpoint: flow_id={row[0]}")


def decode_features(row: Sequence[Any]) -> tuple[float, ...]:
    blob = row[19]
    if not isinstance(blob, bytes) or len(blob) != FEATURE_BLOB_SIZE:
        raise ValueError(f"terminal feature BLOB mismatch: flow_id={row[0]}")
    features = struct.unpack("<70d", blob)
    if not all(math.isfinite(value) for value in features):
        raise ValueError(f"non-finite terminal feature: flow_id={row[0]}")
    exact = {
        1: int(row[15]),
        2: int(row[16]),
        3: int(row[17]),
        54: int(row[4]),
        64: int(row[10]),
        65: destination_port(row),
    }
    for index, expected in exact.items():
        if features[index] != float(expected):
            raise ValueError(
                f"terminal feature/metadata mismatch: flow_id={row[0]} index={index}"
            )
    lifecycle = features[66:70]
    if any(value not in (0.0, 1.0) for value in lifecycle) or sum(lifecycle) != 1.0:
        raise ValueError(f"terminal lifecycle one-hot mismatch: flow_id={row[0]}")
    return features


def normalized_row(
    row: Sequence[Any],
    partitions: dict[int, tuple[str, str]],
) -> tuple[tuple[Any, ...], str, str | None]:
    flow_id = int(row[0])
    assigned_capture, assigned_class, assignment_method = row[20:23]
    quarantine_capture, quarantine_reason = row[23:25]
    assigned = assigned_class is not None
    quarantined = quarantine_reason is not None
    if assigned == quarantined:
        raise ValueError(f"flow must be assignment XOR quarantine: flow_id={flow_id}")
    if row[1] != (assigned_capture if assigned else quarantine_capture):
        raise ValueError(f"label capture mismatch: flow_id={flow_id}")
    if row[11] != "unix_epoch" or row[4] not in (6, 17):
        raise ValueError(f"terminal clock/protocol mismatch: flow_id={flow_id}")
    features = decode_features(row)
    if assigned:
        family = FAMILY_BY_ASSIGNED_CLASS.get(str(assigned_class))
        if family is None:
            raise ValueError(f"unmapped assigned class: {assigned_class}")
        partition_record = partitions.pop(flow_id, None)
        if partition_record is None:
            raise ValueError(f"assigned flow missing from split map: flow_id={flow_id}")
        partition = partition_record[0]
        label_status = "assigned"
        binary: bool | None = assigned_class != "BENIGN"
        quarantine_value = None
        part_key = f"assigned/partition={partition}"
    else:
        if flow_id in partitions:
            raise ValueError(f"quarantine flow present in split map: flow_id={flow_id}")
        if quarantine_reason not in EXPECTED_QUARANTINE_COUNTS:
            raise ValueError(f"invalid quarantine reason: {quarantine_reason}")
        family = None
        partition = None
        label_status = "quarantine"
        binary = None
        assignment_method = None
        assigned_class = None
        quarantine_value = str(quarantine_reason)
        part_key = "quarantine"
    metadata = (
        flow_id,
        str(row[1]),
        int(row[2]),
        int(row[3]),
        int(row[4]),
        int(row[5]),
        int(row[6]),
        int(row[7]),
        int(row[8]),
        int(row[9]),
        int(row[10]),
        str(row[11]),
        int(row[12]),
        int(row[13]),
        int(row[14]),
        int(row[15]),
        int(row[16]),
        int(row[17]),
        int(row[15]) >= 9,
        str(row[18]),
        label_status,
        assigned_class,
        family,
        binary,
        assignment_method,
        quarantine_value,
        partition,
    )
    return (*metadata, *features), part_key, family or quarantine_value


def rows_to_table(rows: Sequence[tuple[Any, ...]], schema: pa.Schema) -> pa.Table:
    columns = list(zip(*rows, strict=True))
    arrays = [
        pa.array(values, type=field.type)
        for values, field in zip(columns, schema, strict=True)
    ]
    return pa.Table.from_arrays(arrays, schema=schema)


class PartWriter:
    def __init__(self, path: Path, schema: pa.Schema) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        sorting = pq.SortingColumn.from_ordering(schema, [("flow_id", "ascending")])
        self.path = path
        self.schema = schema
        self.rows = 0
        self.buffer: list[tuple[Any, ...]] = []
        self.writer = pq.ParquetWriter(
            path,
            schema,
            version="2.6",
            compression="zstd",
            compression_level=3,
            use_dictionary=DICTIONARY_COLUMNS,
            write_statistics=True,
            data_page_version="1.0",
            write_batch_size=FETCH_ROWS,
            store_schema=True,
            use_byte_stream_split=False,
            write_page_index=False,
            write_page_checksum=False,
            sorting_columns=sorting,
        )

    def append(self, row: tuple[Any, ...]) -> None:
        self.buffer.append(row)
        if len(self.buffer) >= ROW_GROUP_ROWS:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        table = rows_to_table(self.buffer, self.schema)
        self.writer.write_table(table, row_group_size=ROW_GROUP_ROWS)
        self.rows += table.num_rows
        self.buffer.clear()

    def close(self) -> None:
        self.flush()
        self.writer.close()


def capture_directory(inputs: DatasetInputs, capture_id: str) -> Path:
    return inputs.output_root / f"capture_id={capture_id}"


def paired_membership_bytes(capture_id: str, flow_id: int) -> bytes:
    return f"{capture_id}|{flow_id}\n".encode()


def paired_membership_sha256(
    capture_id: str, flow_ids: Iterable[int]
) -> str:
    digest = hashlib.sha256()
    for flow_id in sorted(flow_ids):
        digest.update(paired_membership_bytes(capture_id, flow_id))
    return digest.hexdigest()


def validate_capture_manifest(
    inputs: DatasetInputs,
    capture_id: str,
    schema: pa.Schema,
) -> dict[str, Any]:
    directory = capture_directory(inputs, capture_id)
    manifest_path = directory / "manifest.json"
    manifest = load_json(manifest_path)
    parts = manifest.get("parts")
    if (
        manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_capture_manifest"
        or manifest.get("status") != "complete"
        or manifest.get("capture_id") != capture_id
        or manifest.get("feature_schema", {}).get("sha256")
        != inputs.feature_schema_sha256
        or manifest.get("split_map", {}).get("sha256") != inputs.split_map_sha256
        or not isinstance(parts, list)
    ):
        raise ValueError(f"dataset capture manifest mismatch: {capture_id}")
    rows = 0
    paired_flow_ids: list[int] = []
    assigned_paired_flow_ids: list[int] = []
    expected_schema_hash = schema_fingerprint(schema)
    observed_paths: set[Path] = set()
    for record in parts:
        path = resolve_inside(inputs.root, str(record.get("path", "")))
        if (
            path in observed_paths
            or not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
            or record.get("schema_sha256") != expected_schema_hash
        ):
            raise ValueError(f"dataset part mismatch: {record.get('path')}")
        with pq.ParquetFile(path) as parquet:
            if (
                not parquet.schema_arrow.equals(schema, check_metadata=True)
                or parquet.metadata.num_rows != record.get("rows")
            ):
                raise ValueError(
                    f"dataset part schema/accounting mismatch: {path}"
                )
            membership = parquet.read(
                columns=[
                    "capture_id",
                    "flow_id",
                    "packet_count",
                    "paired_f9",
                    "label_status",
                ]
            ).to_pydict()
        for row_capture, flow_id, packet_count, paired_f9, label_status in zip(
            membership["capture_id"],
            membership["flow_id"],
            membership["packet_count"],
            membership["paired_f9"],
            membership["label_status"],
            strict=True,
        ):
            expected_paired = packet_count >= 9
            if row_capture != capture_id or paired_f9 != expected_paired:
                raise ValueError(
                    f"paired F9 metadata mismatch: {capture_id}/{flow_id}"
                )
            if paired_f9:
                paired_flow_ids.append(int(flow_id))
                if label_status == "assigned":
                    assigned_paired_flow_ids.append(int(flow_id))
        observed_paths.add(path)
        rows += int(record["rows"])
    actual_paths = set(directory.rglob("*.parquet"))
    if actual_paths != observed_paths or rows != manifest.get("rows"):
        raise ValueError(f"dataset capture part set mismatch: {capture_id}")
    expected = (
        inputs.expected_capture_rows.get(capture_id)
        if inputs.expected_capture_rows is not None
        else None
    )
    if expected is not None and rows != expected:
        raise ValueError(f"dataset capture row count mismatch: {capture_id}")
    paired_record = manifest.get("paired_f9", {})
    if paired_record != {
        "definition": "packet_count >= 9",
        "rows": len(paired_flow_ids),
        "assigned_rows": len(assigned_paired_flow_ids),
        "membership_sha256": paired_membership_sha256(
            capture_id, paired_flow_ids
        ),
        "assigned_membership_sha256": paired_membership_sha256(
            capture_id, assigned_paired_flow_ids
        ),
        "model_input": False,
    }:
        raise ValueError(f"paired F9 manifest mismatch: {capture_id}")
    return manifest


def package_capture(
    inputs: DatasetInputs,
    capture_id: str,
    schema: pa.Schema,
) -> tuple[dict[str, Any], bool]:
    final_directory = capture_directory(inputs, capture_id)
    if final_directory.exists():
        return validate_capture_manifest(inputs, capture_id, schema), True
    shard, shard_manifest = verify_shard(inputs, capture_id)
    reconcile_terminal_source(shard, inputs.source.path, capture_id)
    partitions = load_capture_partitions(inputs.split_map_path, capture_id)
    staging = inputs.output_root / f".{capture_id}.{uuid.uuid4().hex}.tmp"
    staging.mkdir(parents=True)
    writers: dict[str, PartWriter] = {}
    family_counts: Counter[str] = Counter()
    quarantine_counts: Counter[str] = Counter()
    paired_flow_ids: list[int] = []
    assigned_paired_flow_ids: list[int] = []
    assigned_rows = 0
    quarantine_rows = 0
    connection: sqlite3.Connection | None = None
    try:
        connection, cursor = terminal_row_cursor(inputs, shard, capture_id)
        while True:
            batch = cursor.fetchmany(FETCH_ROWS)
            if not batch:
                break
            for source_row in batch:
                normalized, part_key, accounting_key = normalized_row(
                    source_row, partitions
                )
                if int(source_row[15]) >= 9:
                    paired_flow_ids.append(int(source_row[0]))
                    if part_key != "quarantine":
                        assigned_paired_flow_ids.append(int(source_row[0]))
                writer = writers.get(part_key)
                if writer is None:
                    writer = PartWriter(
                        staging / part_key / "part-00000.parquet", schema
                    )
                    writers[part_key] = writer
                writer.append(normalized)
                if part_key == "quarantine":
                    quarantine_counts[str(accounting_key)] += 1
                    quarantine_rows += 1
                else:
                    family_counts[str(accounting_key)] += 1
                    assigned_rows += 1
        if partitions:
            first = next(iter(partitions))
            raise ValueError(f"split map contains non-dataset flow: flow_id={first}")
        for writer in writers.values():
            writer.close()
        writers.clear()
        rows = assigned_rows + quarantine_rows
        expected = (
            inputs.expected_capture_rows.get(capture_id)
            if inputs.expected_capture_rows is not None
            else None
        )
        if expected is not None and rows != expected:
            raise ValueError(
                f"unexpected terminal capture rows: {capture_id} {rows} != {expected}"
            )
        part_records: list[dict[str, Any]] = []
        for part_key, path in sorted(
            (
                (key, staging / key / "part-00000.parquet")
                for key in set(
                    ["quarantine"]
                    + [f"assigned/partition={name}" for name in PARTITIONS]
                )
            ),
            key=lambda item: item[0],
        ):
            if not path.is_file():
                continue
            with pq.ParquetFile(path) as parquet:
                part_rows = parquet.metadata.num_rows
            final_path = final_directory / path.relative_to(staging)
            part_records.append(
                {
                    "kind": "quarantine" if part_key == "quarantine" else "assigned",
                    "partition": (
                        None
                        if part_key == "quarantine"
                        else part_key.rsplit("=", 1)[1]
                    ),
                    "path": relative(final_path, inputs.root),
                    "rows": part_rows,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_path(path),
                    "schema_sha256": schema_fingerprint(schema),
                }
            )
        manifest = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "terminal_flow_capture_manifest",
            "status": "complete",
            "generated_at_utc": utc_now(),
            "capture_id": capture_id,
            "rows": rows,
            "assigned_rows": assigned_rows,
            "quarantine_rows": quarantine_rows,
            "family_counts": dict(sorted(family_counts.items())),
            "quarantine_counts": dict(sorted(quarantine_counts.items())),
            "paired_f9": {
                "definition": "packet_count >= 9",
                "rows": len(paired_flow_ids),
                "assigned_rows": len(assigned_paired_flow_ids),
                "membership_sha256": paired_membership_sha256(
                    capture_id, paired_flow_ids
                ),
                "assigned_membership_sha256": paired_membership_sha256(
                    capture_id, assigned_paired_flow_ids
                ),
                "model_input": False,
            },
            "feature_schema": {
                "path": relative(inputs.feature_schema_path, inputs.root),
                "schema_id": FEATURE_SCHEMA_ID,
                "sha256": inputs.feature_schema_sha256,
                "feature_count": FEATURE_COUNT,
            },
            "split_map": {
                "path": relative(inputs.split_map_path, inputs.root),
                "sha256": inputs.split_map_sha256,
            },
            "terminal_shard": {
                "path": relative(shard, inputs.root),
                "sha256": shard_manifest["database"]["sha256"],
            },
            "source_database_sha256": inputs.source.sha256,
            "assignment_database_sha256": inputs.assignment.sha256,
            "parts": part_records,
        }
        write_json_atomic(staging / "manifest.json", manifest)
        inputs.output_root.mkdir(parents=True, exist_ok=True)
        os.replace(staging, final_directory)
        return validate_capture_manifest(inputs, capture_id, schema), False
    finally:
        if connection is not None:
            connection.close()
        for writer in writers.values():
            with contextlib.suppress(Exception):
                writer.close()
        shutil.rmtree(staging, ignore_errors=True)


def aggregate_manifests(
    inputs: DatasetInputs,
    manifests: Sequence[Mapping[str, Any]],
    schema: pa.Schema,
) -> dict[str, Any]:
    total_rows = sum(int(item["rows"]) for item in manifests)
    assigned_rows = sum(int(item["assigned_rows"]) for item in manifests)
    quarantine_rows = sum(int(item["quarantine_rows"]) for item in manifests)
    family_counts: Counter[str] = Counter()
    quarantine_counts: Counter[str] = Counter()
    paired_rows = 0
    assigned_paired_rows = 0
    paired_capture_records: list[dict[str, Any]] = []
    parts: list[dict[str, Any]] = []
    for manifest in manifests:
        family_counts.update(manifest["family_counts"])
        quarantine_counts.update(manifest["quarantine_counts"])
        paired = manifest["paired_f9"]
        paired_rows += int(paired["rows"])
        assigned_paired_rows += int(paired["assigned_rows"])
        paired_capture_records.append(
            {
                "capture_id": manifest["capture_id"],
                "rows": paired["rows"],
                "assigned_rows": paired["assigned_rows"],
                "membership_sha256": paired["membership_sha256"],
                "assigned_membership_sha256": paired[
                    "assigned_membership_sha256"
                ],
            }
        )
        parts.extend(manifest["parts"])
    paired_capture_records.sort(key=lambda item: item["capture_id"])
    paired_rollup = hashlib.sha256(
        json.dumps(
            paired_capture_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if inputs.enforce_production_accounting and (
        total_rows != EXPECTED_TOTAL_ROWS
        or assigned_rows != EXPECTED_ASSIGNED_ROWS
        or quarantine_rows != EXPECTED_QUARANTINE_ROWS
        or dict(family_counts) != EXPECTED_FAMILY_COUNTS
        or dict(quarantine_counts) != EXPECTED_QUARANTINE_COUNTS
    ):
        raise ValueError("terminal dataset global accounting mismatch")
    return {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "terminal_flow_dataset_manifest",
        "status": "complete",
        "generated_at_utc": utc_now(),
        "root": relative(inputs.output_root, inputs.root),
        "rows": total_rows,
        "assigned_rows": assigned_rows,
        "quarantine_rows": quarantine_rows,
        "family_counts": dict(sorted(family_counts.items())),
        "quarantine_counts": dict(sorted(quarantine_counts.items())),
        "paired_f9": {
            "definition": "packet_count >= 9",
            "rows": paired_rows,
            "assigned_rows": assigned_paired_rows,
            "capture_memberships": paired_capture_records,
            "membership_rollup_sha256": paired_rollup,
            "model_input": False,
        },
        "capture_count": len(manifests),
        "captures": [item["capture_id"] for item in manifests],
        "feature_schema": {
            "path": relative(inputs.feature_schema_path, inputs.root),
            "schema_id": FEATURE_SCHEMA_ID,
            "sha256": inputs.feature_schema_sha256,
            "feature_count": FEATURE_COUNT,
        },
        "split_manifest": {
            "path": relative(inputs.split_manifest_path, inputs.root),
            "sha256": sha256_path(inputs.split_manifest_path),
        },
        "split_map": {
            "path": relative(inputs.split_map_path, inputs.root),
            "sha256": inputs.split_map_sha256,
        },
        "schema_sha256": schema_fingerprint(schema),
        "model_feature_columns": json.loads(
            (schema.metadata or {})[b"nids.model_feature_columns"].decode()
        ),
        "test_partition": {
            "status": "sealed",
            "policy": "do not open test parts until profile, algorithm, hyperparameters, and threshold are locked",
            "parts": [
                record["path"]
                for record in parts
                if record.get("partition") == "test"
            ],
        },
        "training_parts": [
            record["path"]
            for record in parts
            if record.get("partition") == "train"
        ],
        "validation_parts": [
            record["path"]
            for record in parts
            if record.get("partition") == "validation"
        ],
        "quarantine_parts": [
            record["path"] for record in parts if record.get("kind") == "quarantine"
        ],
        "parts": parts,
    }


def build_dataset(
    inputs: DatasetInputs, selected: Iterable[str] | None = None
) -> dict[str, Any]:
    verify_database(inputs.source, "T3.3 source database")
    verify_database(inputs.assignment, "T3.3R1 assignment database")
    if (
        not inputs.split_map_path.is_file()
        or sha256_path(inputs.split_map_path) != inputs.split_map_sha256
    ):
        raise ValueError("terminal split map content address mismatch")
    names, profiles = load_feature_schema(
        inputs.feature_schema_path, inputs.feature_schema_sha256
    )
    schema = arrow_schema(
        names, inputs.feature_schema_sha256, inputs.split_map_sha256, profiles
    )
    requested = inputs.capture_ids if selected is None else tuple(selected)
    if (
        not requested
        or len(set(requested)) != len(requested)
        or any(capture_id not in inputs.capture_ids for capture_id in requested)
    ):
        raise ValueError("invalid terminal capture selection")
    for capture_id in requested:
        manifest, skipped = package_capture(inputs, capture_id, schema)
        print(
            f"[T9.1 dataset] capture={capture_id} "
            f"status={'skipped' if skipped else 'complete'} rows={manifest['rows']}",
            flush=True,
        )
    if set(requested) != set(inputs.capture_ids):
        return {
            "task": TASK,
            "kind": "terminal_flow_dataset_partial_build",
            "status": "complete",
            "captures": list(requested),
        }
    manifests = [
        validate_capture_manifest(inputs, capture_id, schema)
        for capture_id in inputs.capture_ids
    ]
    manifest = aggregate_manifests(inputs, manifests, schema)
    manifest_path = inputs.output_root / "manifest.json"
    if manifest_path.exists():
        existing = load_json(manifest_path)
        stable_keys = (
            "task",
            "kind",
            "status",
            "rows",
            "assigned_rows",
            "quarantine_rows",
            "family_counts",
            "quarantine_counts",
            "paired_f9",
            "feature_schema",
            "split_map",
            "schema_sha256",
            "model_feature_columns",
            "test_partition",
            "training_parts",
            "validation_parts",
            "quarantine_parts",
            "parts",
        )
        if any(existing.get(key) != manifest.get(key) for key in stable_keys):
            raise ValueError("existing terminal dataset manifest mismatch")
        return existing
    write_json_atomic(manifest_path, manifest)
    return manifest


def validate_dataset(inputs: DatasetInputs) -> dict[str, Any]:
    names, profiles = load_feature_schema(
        inputs.feature_schema_path, inputs.feature_schema_sha256
    )
    schema = arrow_schema(
        names, inputs.feature_schema_sha256, inputs.split_map_sha256, profiles
    )
    manifests = [
        validate_capture_manifest(inputs, capture_id, schema)
        for capture_id in inputs.capture_ids
    ]
    expected = aggregate_manifests(inputs, manifests, schema)
    observed = load_json(inputs.output_root / "manifest.json")
    for key in (
        "rows",
        "assigned_rows",
        "quarantine_rows",
        "family_counts",
        "quarantine_counts",
        "paired_f9",
        "schema_sha256",
        "model_feature_columns",
        "test_partition",
        "training_parts",
        "validation_parts",
        "quarantine_parts",
        "parts",
    ):
        if observed.get(key) != expected.get(key):
            raise ValueError(f"terminal dataset manifest drift: {key}")
    return observed


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument("--capture-id", action="append")
    args = parser.parse_args(argv)
    try:
        inputs = production_inputs(args.project_root)
        if args.command == "build":
            result = build_dataset(inputs, args.capture_id)
        else:
            if args.capture_id:
                raise ValueError("--capture-id is only valid for build")
            result = validate_dataset(inputs)
        print(
            f"[T9.1 dataset] status=complete kind={result['kind']}",
            flush=True,
        )
        return 0
    except (OSError, RuntimeError, ValueError, sqlite3.Error, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
