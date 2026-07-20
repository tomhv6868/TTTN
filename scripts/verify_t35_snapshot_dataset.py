#!/usr/bin/env python3
"""Independently verify every T3.5 Parquet row group against SQLite oracles."""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import sqlite3
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T3.5"
PYARROW_VERSION = "23.0.1"
CHECKPOINTS = {"F3": 3, "F5": 5, "F7": 7, "F9": 9}
FEATURE_COUNT = 54
FEATURE_BLOB_SIZE = FEATURE_COUNT * 8
ROW_GROUP_ROWS = 65536
CAPTURE_RECEIPT_KIND = "parquet_capture_checkpoint"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_inside(root: Path, value: str) -> Path:
    path = Path(value)
    result = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        result.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return result


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def feature_names(root: Path, contract: Mapping[str, Any]) -> list[str]:
    reference = contract["prerequisites"]["feature_schema"]
    path = resolve_inside(root, reference["path"])
    if sha256_path(path) != reference["sha256"]:
        raise ValueError("feature schema content address mismatch")
    document = load_json(path)
    features = document.get("features")
    if not isinstance(features, list) or len(features) != FEATURE_COUNT:
        raise ValueError("feature schema length mismatch")
    result: list[str] = []
    for index, feature in enumerate(features):
        if not isinstance(feature, Mapping) or feature.get("index") != index:
            raise ValueError("feature schema ordering mismatch")
        name = feature.get("name")
        if not isinstance(name, str) or not name or name in result:
            raise ValueError("invalid feature name")
        result.append(name)
    return result


def expected_schema(names: Sequence[str], contract_hash: str) -> pa.Schema:
    fields = [
        pa.field("flow_id", pa.uint64(), False),
        pa.field("capture_id", pa.string(), False),
        pa.field("checkpoint", pa.uint8(), False),
        pa.field("flow_start_timestamp_ns", pa.int64(), False),
        pa.field("checkpoint_timestamp_ns", pa.int64(), False),
        pa.field("assigned_class", pa.string(), False),
        pa.field("label_binary", pa.bool_(), False),
        pa.field("assignment_method", pa.string(), False),
    ]
    fields.extend(pa.field(name, pa.float64(), False) for name in names)
    return pa.schema(fields, metadata={
        b"nids.task": TASK.encode(),
        b"nids.contract_sha256": contract_hash.encode(),
        b"nids.model_feature_columns": json.dumps(
            list(names), ensure_ascii=False, separators=(",", ":")
        ).encode(),
    })


def schema_hash(schema: pa.Schema) -> str:
    fields = [
        {"name": field.name, "type": str(field.type), "nullable": field.nullable}
        for field in schema
    ]
    metadata = {
        key.decode(): value.decode()
        for key, value in sorted((schema.metadata or {}).items())
    }
    encoded = json.dumps(
        {"fields": fields, "metadata": metadata},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def open_immutable(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(immutable_uri(path), uri=True)


def immutable_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro&immutable=1"


def prerequisite(root: Path, reference: Mapping[str, Any], label: str) -> Path:
    path = resolve_inside(root, reference.get("path", ""))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{label} content address mismatch")
    with contextlib.closing(open_immutable(path)) as connection:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != reference.get("application_id")
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != reference.get("user_version")
        ):
            raise ValueError(f"{label} SQLite identity mismatch")
    return path


def captures(contract: Mapping[str, Any]) -> list[str]:
    raw = contract.get("captures")
    if not isinstance(raw, list):
        raise ValueError("captures missing")
    result = [item.get("id") for item in raw if isinstance(item, Mapping)]
    if (
        len(result) != len(raw)
        or any(not isinstance(item, str) for item in result)
        or len(set(result)) != len(result)
        or contract.get("parquet", {}).get("parts") != len(result) * len(CHECKPOINTS)
    ):
        raise ValueError("invalid capture/part contract")
    return result


def part_path(root: Path, contract: Mapping[str, Any], capture_id: str, checkpoint: str) -> Path:
    base = resolve_inside(root, contract["parquet"]["root"])
    return base / f"checkpoint={checkpoint}" / f"capture_id={capture_id}" / "part-00000.parquet"


def receipt_path(root: Path, contract: Mapping[str, Any], capture_id: str) -> Path:
    value = contract["parquet"]["capture_commit_receipt"].replace("{capture_id}", capture_id)
    return resolve_inside(root, value)


def shard_path(
    root: Path, contract: Mapping[str, Any], contract_hash: str, capture_id: str
) -> Path:
    base = resolve_inside(root, contract["replay"]["staging"]["directory"])
    path = base / capture_id / contract["replay"]["staging"]["database_name"]
    receipt_path = base / capture_id / contract["replay"]["staging"]["receipt_name"]
    if (
        not path.is_file()
        or not receipt_path.is_file()
        or path.with_name(path.name + "-wal").exists()
        or path.with_name(path.name + "-shm").exists()
    ):
        raise ValueError(f"invalid snapshot shard: {capture_id}")
    receipt = load_json(receipt_path)
    sqlite_record = receipt.get("sqlite", {})
    if (
        receipt.get("task") != TASK
        or receipt.get("status") != "passed"
        or receipt.get("capture_id") != capture_id
        or receipt.get("task_contract", {}).get("sha256") != contract_hash
        or sqlite_record.get("size_bytes") != path.stat().st_size
        or sqlite_record.get("sha256") != sha256_path(path)
        or sqlite_record.get("journal_mode") != "delete"
    ):
        raise ValueError(f"snapshot shard receipt mismatch: {capture_id}")
    return path


def ipv4_int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def reconcile_close_records(shard: Path, source: Path, capture_id: str) -> None:
    connection = open_immutable(shard)
    try:
        connection.create_function("ipv4_int", 1, ipv4_int, deterministic=True)
        connection.execute("ATTACH DATABASE ? AS source", (immutable_uri(source),))
        shard_rows = """
            SELECT capture_id,export_ordinal,CASE protocol WHEN 'tcp' THEN 6 ELSE 17 END,
                   ipv4_int(low_ip),low_port,ipv4_int(high_ip),high_port,
                   ipv4_int(forward_source_ip),forward_source_port,generation,
                   creation_timestamp_ns,last_capture_timestamp_ns,last_event_timestamp_ns,
                   packet_count,forward_packet_count,reverse_packet_count,close_reason FROM flow
        """
        source_rows = """
            SELECT capture_id,export_ordinal,protocol,low_ip,low_port,high_ip,high_port,
                   forward_source_ip,forward_source_port,generation,creation_timestamp_ns,
                   last_capture_timestamp_ns,last_event_timestamp_ns,packet_count,
                   forward_packet_count,reverse_packet_count,close_reason
            FROM source.flow WHERE capture_id=?
        """
        shard_only = connection.execute(
            f"SELECT COUNT(*) FROM ({shard_rows} EXCEPT {source_rows})", (capture_id,)
        ).fetchone()[0]
        source_only = connection.execute(
            f"SELECT COUNT(*) FROM ({source_rows} EXCEPT {shard_rows})", (capture_id,)
        ).fetchone()[0]
        if shard_only or source_only:
            raise ValueError(f"independent close-record reconciliation failed: {capture_id}")
    finally:
        connection.close()


def expected_cursor(
    source: Path, assignment: Path, shard: Path, capture_id: str, checkpoint: str
) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    connection = sqlite3.connect(":memory:", uri=True)
    try:
        connection.execute("ATTACH DATABASE ? AS source", (immutable_uri(source),))
        connection.execute("ATTACH DATABASE ? AS assignment", (immutable_uri(assignment),))
        connection.execute("ATTACH DATABASE ? AS shard", (immutable_uri(shard),))
        cursor = connection.execute(
            """
            SELECT f.flow_id,f.capture_id,?,f.creation_timestamp_ns,
                   s.checkpoint_timestamp_ns,a.assigned_class,
                   a.assigned_class<>'BENIGN',a.assignment_method,s.features
            FROM source.flow f
            JOIN assignment.flow_assignment a ON a.flow_id=f.flow_id AND a.capture_id=f.capture_id
            JOIN shard.snapshot s ON s.generation=f.generation AND s.capture_id=f.capture_id
            WHERE f.capture_id=? AND s.checkpoint=? AND f.packet_count>=?
            ORDER BY f.flow_id
            """,
            (CHECKPOINTS[checkpoint], capture_id, checkpoint, CHECKPOINTS[checkpoint]),
        )
        return connection, cursor
    except Exception:
        connection.close()
        raise


def compare_row(
    columns: Mapping[str, list[Any]], index: int, expected: tuple[Any, ...], names: Sequence[str]
) -> None:
    metadata_names = (
        "flow_id", "capture_id", "checkpoint", "flow_start_timestamp_ns",
        "checkpoint_timestamp_ns", "assigned_class", "label_binary", "assignment_method",
    )
    for name, value in zip(metadata_names, expected[:8], strict=True):
        if columns[name][index] != value:
            raise ValueError(f"Parquet metadata mismatch: column={name}")
    blob = expected[8]
    if not isinstance(blob, bytes) or len(blob) != FEATURE_BLOB_SIZE:
        raise ValueError("oracle feature BLOB mismatch")
    expected_features = struct.unpack("<54d", blob)
    for name, value in zip(names, expected_features, strict=True):
        actual = columns[name][index]
        if not math.isfinite(actual) or struct.pack("<d", actual) != struct.pack("<d", value):
            raise ValueError(f"Parquet feature bit mismatch: column={name}")


def verify_part(
    path: Path, source: Path, assignment: Path, shard: Path, capture_id: str,
    checkpoint: str, schema: pa.Schema, names: Sequence[str], distributions: dict[str, collections.Counter]
) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing Parquet part: {path}")
    parquet = pq.ParquetFile(path)
    if not parquet.schema_arrow.equals(schema, check_metadata=True):
        raise ValueError(f"Parquet schema mismatch: {path}")
    if parquet.metadata.format_version != "2.6":
        raise ValueError("Parquet format version mismatch")
    connection, cursor = expected_cursor(source, assignment, shard, capture_id, checkpoint)
    rows = 0
    previous_flow_id: int | None = None
    try:
        for row_group_index in range(parquet.num_row_groups):
            metadata = parquet.metadata.row_group(row_group_index)
            if metadata.num_rows <= 0 or metadata.num_rows > ROW_GROUP_ROWS:
                raise ValueError("invalid Parquet row-group size")
            if row_group_index + 1 < parquet.num_row_groups and metadata.num_rows != ROW_GROUP_ROWS:
                raise ValueError("non-final Parquet row group is not full")
            sorting = metadata.sorting_columns
            if len(sorting) != 1 or sorting[0].column_index != 0 or sorting[0].descending:
                raise ValueError("Parquet sorting metadata mismatch")
            dictionary_columns = {"capture_id", "assigned_class", "assignment_method"}
            for column_index, field in enumerate(schema):
                column = metadata.column(column_index)
                has_dictionary = "RLE_DICTIONARY" in column.encodings
                if (
                    column.compression != "ZSTD"
                    or not column.is_stats_set
                    or has_dictionary != (field.name in dictionary_columns)
                    or column.has_column_index
                    or column.has_offset_index
                ):
                    raise ValueError(f"Parquet writer evidence mismatch: column={field.name}")
            table = parquet.read_row_group(row_group_index)
            columns = table.to_pydict()
            expected_rows = cursor.fetchmany(table.num_rows)
            if len(expected_rows) != table.num_rows:
                raise ValueError("Parquet has more rows than SQLite oracle")
            for index, expected in enumerate(expected_rows):
                compare_row(columns, index, expected, names)
                flow_id = columns["flow_id"][index]
                if previous_flow_id is not None and flow_id <= previous_flow_id:
                    raise ValueError("flow_id is not strictly increasing")
                previous_flow_id = flow_id
                assigned_class = columns["assigned_class"][index]
                method = columns["assignment_method"][index]
                binary = columns["label_binary"][index]
                distributions["checkpoint"][checkpoint] += 1
                distributions["capture_and_checkpoint"][(capture_id, checkpoint)] += 1
                distributions["class_and_checkpoint"][(assigned_class, checkpoint)] += 1
                distributions["method_and_checkpoint"][(method, checkpoint)] += 1
                distributions["capture_class_method_and_checkpoint"][
                    (capture_id, assigned_class, method, checkpoint)
                ] += 1
                distributions["binary_and_checkpoint"][(str(bool(binary)).lower(), checkpoint)] += 1
                rows += 1
        if cursor.fetchone() is not None:
            raise ValueError("Parquet has fewer rows than SQLite oracle")
    finally:
        connection.close()
    return {
        "path": str(path), "rows": rows, "row_groups": parquet.num_row_groups,
        "size_bytes": path.stat().st_size, "sha256": sha256_path(path),
        "schema_sha256": schema_hash(schema),
    }


def serialized_counter(counter: collections.Counter) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, value in sorted(counter.items(), key=lambda item: str(item[0])):
        encoded = "|".join(key) if isinstance(key, tuple) else str(key)
        result[encoded] = value
    return result


def short_flow_distribution(source: Path, assignment: Path) -> dict[str, int]:
    connection = sqlite3.connect(":memory:", uri=True)
    try:
        connection.execute("ATTACH DATABASE ? AS source", (immutable_uri(source),))
        connection.execute("ATTACH DATABASE ? AS assignment", (immutable_uri(assignment),))
        return {
            str(packet_count): count
            for packet_count, count in connection.execute(
                """
                SELECT f.packet_count,COUNT(*) FROM source.flow f
                JOIN assignment.flow_assignment a USING(flow_id)
                WHERE f.packet_count<3 GROUP BY f.packet_count ORDER BY f.packet_count
                """
            )
        }
    finally:
        connection.close()


def verify(root: Path, contract_path: Path, write_outputs: bool = False) -> dict[str, Any]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    contract = load_json(contract_path)
    if contract.get("task") != TASK or pa.__version__ != PYARROW_VERSION:
        raise RuntimeError("T3.5 contract/runtime mismatch")
    contract_hash = sha256_path(contract_path)
    names = feature_names(root, contract)
    schema = expected_schema(names, contract_hash)
    schema_digest = schema_hash(schema)
    prerequisites = contract["prerequisites"]
    source = prerequisite(root, prerequisites["source_database"], "source database")
    assignment = prerequisite(root, prerequisites["assignment_database"], "assignment database")
    capture_ids = captures(contract)
    parquet_root = resolve_inside(root, contract["parquet"]["root"])
    expected_paths = {
        part_path(root, contract, capture_id, checkpoint).resolve()
        for capture_id in capture_ids for checkpoint in CHECKPOINTS
    }
    actual_paths = {path.resolve() for path in parquet_root.rglob("*.parquet")}
    if actual_paths != expected_paths:
        raise ValueError("Parquet part set mismatch")
    distributions = {
        name: collections.Counter()
        for name in (
            "checkpoint", "capture_and_checkpoint", "class_and_checkpoint",
            "method_and_checkpoint", "capture_class_method_and_checkpoint",
            "binary_and_checkpoint",
        )
    }
    part_records: list[dict[str, Any]] = []
    for capture_id in capture_ids:
        shard = shard_path(root, contract, contract_hash, capture_id)
        reconcile_close_records(shard, source, capture_id)
        receipt = load_json(receipt_path(root, contract, capture_id))
        if (
            receipt.get("task") != TASK
            or receipt.get("kind") != CAPTURE_RECEIPT_KIND
            or receipt.get("status") != "passed"
            or receipt.get("contract_sha256") != contract_hash
            or receipt.get("capture_id") != capture_id
            or receipt.get("pyarrow_version") != PYARROW_VERSION
            or receipt.get("source_database_sha256") != prerequisites["source_database"]["sha256"]
            or receipt.get("assignment_database_sha256")
            != prerequisites["assignment_database"]["sha256"]
            or receipt.get("snapshot_shard_sha256") != sha256_path(shard)
        ):
            raise ValueError(f"capture receipt envelope mismatch: {capture_id}")
        receipt_parts = {part.get("checkpoint"): part for part in receipt.get("parts", [])}
        if set(receipt_parts) != set(CHECKPOINTS):
            raise ValueError(f"capture receipt part set mismatch: {capture_id}")
        for checkpoint in CHECKPOINTS:
            path = part_path(root, contract, capture_id, checkpoint)
            record = verify_part(
                path, source, assignment, shard, capture_id, checkpoint,
                schema, names, distributions,
            )
            record["path"] = relative(path, root)
            expected_record = receipt_parts[checkpoint]
            for key in ("path", "rows", "size_bytes", "sha256", "schema_sha256"):
                if record[key] != expected_record.get(key):
                    raise ValueError(f"capture receipt evidence mismatch: {capture_id}/{checkpoint}/{key}")
            expected_rows = contract["expected_accounting"]["by_capture_and_checkpoint"][capture_id][checkpoint]
            if record["rows"] != expected_rows:
                raise ValueError(f"contract row count mismatch: {capture_id}/{checkpoint}")
            part_records.append(record)
    checkpoint_counts = serialized_counter(distributions["checkpoint"])
    if checkpoint_counts != contract["expected_accounting"]["by_checkpoint"]:
        raise ValueError("global checkpoint distribution mismatch")
    for method, values in contract["expected_accounting"]["by_method_and_checkpoint"].items():
        for checkpoint, count in values.items():
            key = (method, checkpoint)
            if distributions["method_and_checkpoint"][key] != count:
                raise ValueError("assignment-method distribution mismatch")
            distributions["method_and_checkpoint"][key] += 0
    class_counts = distributions["class_and_checkpoint"]
    for class_name, expected in contract["expected_accounting"]["required_warning_metrics"].items():
        for checkpoint in CHECKPOINTS:
            if class_counts[(class_name, checkpoint)] != expected[checkpoint]:
                raise ValueError(f"warning class distribution mismatch: {class_name}/{checkpoint}")
    zero_class = contract["expected_accounting"]["explicit_zero_snapshot_class"]
    if any(class_counts[(zero_class, checkpoint)] for checkpoint in CHECKPOINTS):
        raise ValueError("explicit-zero snapshot class is nonzero")
    short = short_flow_distribution(source, assignment)
    expected_short = {
        str(key): value
        for key, value in contract["expected_accounting"]["assigned_final_packet_count"].items()
    }
    if short != expected_short or sum(short.values()) != contract["expected_accounting"]["assigned_flows_below_f3"]:
        raise ValueError("short-flow distribution mismatch")
    serialized = {
        name: serialized_counter(counter) for name, counter in distributions.items()
    }
    serialized["short_flow_final_packet_count"] = short
    manifest = {
        "schema_version": "1.0.0", "task": TASK, "kind": "snapshot_dataset_manifest",
        "status": "passed", "generated_at_utc": utc_now(),
        "contract": {"path": relative(contract_path, root), "sha256": contract_hash},
        "pyarrow_version": pa.__version__, "schema_sha256": schema_digest,
        "model_feature_columns": names, "parts": part_records,
        "part_count": len(part_records), "row_count": sum(item["rows"] for item in part_records),
        "distributions": serialized,
        "checks": [
            "all_row_groups_scanned", "sqlite_oracle_row_exact", "float64_bit_exact",
            "flow_id_strictly_sorted_unique", "receipt_hash_size_schema_exact",
            "privacy_allowlist_exact", "short_flow_exclusion_exact",
        ],
    }
    if write_outputs:
        manifest_path = resolve_inside(root, contract["outputs"]["manifest"])
        write_json_atomic(manifest_path, manifest)
        build = {
            "schema_version": "1.0.0", "task": TASK, "kind": "snapshot_dataset_build",
            "status": "passed", "generated_at_utc": utc_now(),
            "contract_sha256": contract_hash,
            "manifest": {"path": relative(manifest_path, root), "sha256": sha256_path(manifest_path)},
            "part_count": manifest["part_count"], "row_count": manifest["row_count"],
        }
        write_json_atomic(resolve_inside(root, contract["outputs"]["build_receipt"]), build)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path,
        default=root_default / "config/cicids2017-snapshot-contract.json",
    )
    parser.add_argument("--write-outputs", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = verify(args.project_root, args.contract, args.write_outputs)
        print(
            f"[T3.5 verify] status=passed parts={manifest['part_count']} rows={manifest['row_count']}",
            flush=True,
        )
        return 0
    except (OSError, RuntimeError, ValueError, sqlite3.Error, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
