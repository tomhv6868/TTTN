#!/usr/bin/env python3
"""Package validated T3.5 snapshot shards into deterministic Parquet parts."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import math
import os
import shutil
import sqlite3
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T3.5"
PYARROW_VERSION = "23.0.1"
CHECKPOINTS = {"F3": 3, "F5": 5, "F7": 7, "F9": 9}
FEATURE_COUNT = 54
FEATURE_BLOB_SIZE = 432
DATABASE_NAME = "snapshot-shard.sqlite3"
RECEIPT_NAME = "receipt.json"
CAPTURE_RECEIPT_KIND = "parquet_capture_checkpoint"
FETCH_ROWS = 16384
ROW_GROUP_ROWS = 65536


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


def resolve_inside(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def open_immutable(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(immutable_uri(path), uri=True)


def immutable_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro&immutable=1"


def verify_runtime(contract: Mapping[str, Any]) -> None:
    runtime = contract.get("execution_pipeline", {}).get("parquet_runtime", {})
    parquet = contract.get("parquet", {})
    if (
        pa.__version__ != PYARROW_VERSION
        or runtime.get("pyarrow_exact_version") != PYARROW_VERSION
        or runtime.get("python_major_minor") != f"{sys.version_info.major}.{sys.version_info.minor}"
        or parquet.get("writer_batch_rows") != FETCH_ROWS
        or parquet.get("row_group_rows") != ROW_GROUP_ROWS
        or parquet.get("compression") != "zstd"
        or parquet.get("compression_level") != 3
    ):
        raise RuntimeError("T3.5 Parquet runtime/contract mismatch")


def load_feature_names(root: Path, contract: Mapping[str, Any]) -> list[str]:
    reference = contract.get("prerequisites", {}).get("feature_schema", {})
    path = resolve_inside(root, reference.get("path", ""))
    if not path.is_file() or sha256_path(path) != reference.get("sha256"):
        raise ValueError("feature schema content address mismatch")
    schema = load_json(path)
    features = schema.get("features")
    if (
        schema.get("schema_id") != reference.get("schema_id")
        or schema.get("schema_version") != reference.get("schema_version")
        or not isinstance(features, list)
        or len(features) != FEATURE_COUNT
    ):
        raise ValueError("feature schema mismatch")
    names: list[str] = []
    for index, feature in enumerate(features):
        if not isinstance(feature, Mapping) or feature.get("index") != index:
            raise ValueError("feature ordering mismatch")
        name = feature.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("invalid or duplicate feature name")
        names.append(name)
    return names


def arrow_schema(feature_names: Sequence[str], contract_hash: str) -> pa.Schema:
    fields = [
        pa.field("flow_id", pa.uint64(), nullable=False),
        pa.field("capture_id", pa.string(), nullable=False),
        pa.field("checkpoint", pa.uint8(), nullable=False),
        pa.field("flow_start_timestamp_ns", pa.int64(), nullable=False),
        pa.field("checkpoint_timestamp_ns", pa.int64(), nullable=False),
        pa.field("assigned_class", pa.string(), nullable=False),
        pa.field("label_binary", pa.bool_(), nullable=False),
        pa.field("assignment_method", pa.string(), nullable=False),
    ]
    fields.extend(pa.field(name, pa.float64(), nullable=False) for name in feature_names)
    metadata = {
        b"nids.task": TASK.encode(),
        b"nids.contract_sha256": contract_hash.encode(),
        b"nids.model_feature_columns": json.dumps(
            list(feature_names), ensure_ascii=False, separators=(",", ":")
        ).encode(),
    }
    return pa.schema(fields, metadata=metadata)


def schema_hash(schema: pa.Schema) -> str:
    fields = [
        {"name": field.name, "type": str(field.type), "nullable": field.nullable}
        for field in schema
    ]
    metadata = {
        key.decode(): value.decode()
        for key, value in sorted((schema.metadata or {}).items())
    }
    payload = json.dumps(
        {"fields": fields, "metadata": metadata},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def verify_prerequisite(root: Path, reference: Mapping[str, Any], name: str) -> Path:
    path = resolve_inside(root, reference.get("path", ""))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{name} content address mismatch")
    with contextlib.closing(open_immutable(path)) as connection:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != reference.get("application_id")
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != reference.get("user_version")
        ):
            raise ValueError(f"{name} SQLite identity mismatch")
    return path


def capture_ids(contract: Mapping[str, Any]) -> list[str]:
    captures = contract.get("captures")
    if not isinstance(captures, list):
        raise ValueError("contract captures are missing")
    result = [item.get("id") for item in captures if isinstance(item, Mapping)]
    if len(result) != len(captures) or any(not isinstance(item, str) for item in result):
        raise ValueError("invalid capture ids")
    if len(set(result)) != len(result):
        raise ValueError("duplicate capture id")
    if contract.get("parquet", {}).get("parts") != len(result) * len(CHECKPOINTS):
        raise ValueError("contract Parquet part count mismatch")
    return result


def shard_paths(root: Path, contract: Mapping[str, Any], capture_id: str) -> tuple[Path, Path]:
    directory = resolve_inside(root, contract["replay"]["staging"]["directory"]) / capture_id
    return directory / DATABASE_NAME, directory / RECEIPT_NAME


def validate_shard(root: Path, contract: Mapping[str, Any], contract_hash: str, capture_id: str) -> Path:
    database, receipt_path = shard_paths(root, contract, capture_id)
    if not database.is_file() or not receipt_path.is_file():
        raise ValueError(f"snapshot shard is incomplete: {capture_id}")
    if database.with_name(database.name + "-wal").exists() or database.with_name(database.name + "-shm").exists():
        raise ValueError(f"snapshot shard has WAL/SHM sidecars: {capture_id}")
    receipt = load_json(receipt_path)
    sqlite_record = receipt.get("sqlite", {})
    if (
        receipt.get("task") != TASK
        or receipt.get("status") != "passed"
        or receipt.get("capture_id") != capture_id
        or receipt.get("task_contract", {}).get("sha256") != contract_hash
        or sqlite_record.get("size_bytes") != database.stat().st_size
        or sqlite_record.get("sha256") != sha256_path(database)
        or sqlite_record.get("journal_mode") != "delete"
    ):
        raise ValueError(f"snapshot shard receipt mismatch: {capture_id}")
    with contextlib.closing(open_immutable(database)) as connection:
        if (
            connection.execute("PRAGMA integrity_check").fetchone() != ("ok",)
            or connection.execute("PRAGMA journal_mode").fetchone() != ("delete",)
            or connection.execute("PRAGMA application_id").fetchone()[0]
            != contract["replay"]["staging"]["application_id"]
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != contract["replay"]["staging"]["user_version"]
        ):
            raise ValueError(f"snapshot shard SQLite validation failed: {capture_id}")
    return database


def ipv4_int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def reconcile_close_records(shard: Path, source: Path, capture_id: str) -> None:
    connection = open_immutable(shard)
    try:
        connection.create_function("ipv4_int", 1, ipv4_int, deterministic=True)
        connection.execute("ATTACH DATABASE ? AS source", (immutable_uri(source),))
        left = """
            SELECT capture_id,export_ordinal,CASE protocol WHEN 'tcp' THEN 6 ELSE 17 END,
                   ipv4_int(low_ip),low_port,ipv4_int(high_ip),high_port,
                   ipv4_int(forward_source_ip),forward_source_port,generation,
                   creation_timestamp_ns,last_capture_timestamp_ns,last_event_timestamp_ns,
                   packet_count,forward_packet_count,reverse_packet_count,close_reason FROM flow
        """
        right = """
            SELECT capture_id,export_ordinal,protocol,low_ip,low_port,high_ip,high_port,
                   forward_source_ip,forward_source_port,generation,creation_timestamp_ns,
                   last_capture_timestamp_ns,last_event_timestamp_ns,packet_count,
                   forward_packet_count,reverse_packet_count,close_reason
            FROM source.flow WHERE capture_id=?
        """
        missing_source = connection.execute(
            f"SELECT COUNT(*) FROM ({left} EXCEPT {right})", (capture_id,)
        ).fetchone()[0]
        missing_shard = connection.execute(
            f"SELECT COUNT(*) FROM ({right} EXCEPT {left})", (capture_id,)
        ).fetchone()[0]
        if missing_source or missing_shard:
            raise ValueError(
                f"close-record reconciliation failed for {capture_id}: "
                f"shard_only={missing_source} source_only={missing_shard}"
            )
    finally:
        connection.close()


def output_part(root: Path, contract: Mapping[str, Any], capture_id: str, checkpoint: str) -> Path:
    parquet_root = resolve_inside(root, contract["parquet"]["root"])
    return parquet_root / f"checkpoint={checkpoint}" / f"capture_id={capture_id}" / "part-00000.parquet"


def capture_receipt_path(root: Path, contract: Mapping[str, Any], capture_id: str) -> Path:
    template = contract["parquet"]["capture_commit_receipt"]
    return resolve_inside(root, template.replace("{capture_id}", capture_id))


def validate_capture_receipt(
    root: Path, contract: Mapping[str, Any], contract_hash: str, capture_id: str, expected_schema_hash: str
) -> dict[str, Any]:
    path = capture_receipt_path(root, contract, capture_id)
    receipt = load_json(path)
    parts = receipt.get("parts")
    if (
        receipt.get("task") != TASK
        or receipt.get("kind") != CAPTURE_RECEIPT_KIND
        or receipt.get("status") != "passed"
        or receipt.get("capture_id") != capture_id
        or receipt.get("contract_sha256") != contract_hash
        or receipt.get("pyarrow_version") != PYARROW_VERSION
        or receipt.get("source_database_sha256")
        != contract["prerequisites"]["source_database"]["sha256"]
        or receipt.get("assignment_database_sha256")
        != contract["prerequisites"]["assignment_database"]["sha256"]
        or not isinstance(parts, list)
        or len(parts) != len(CHECKPOINTS)
        or {record.get("checkpoint") for record in parts} != set(CHECKPOINTS)
    ):
        raise ValueError(f"capture receipt mismatch: {capture_id}")
    for record in parts:
        checkpoint = record["checkpoint"]
        part = resolve_inside(root, record.get("path", ""))
        if (
            record.get("schema_sha256") != expected_schema_hash
            or part != output_part(root, contract, capture_id, checkpoint).resolve()
            or record.get("rows")
            != contract["expected_accounting"]["by_capture_and_checkpoint"][capture_id][checkpoint]
            or not part.is_file()
            or part.stat().st_size != record.get("size_bytes")
            or sha256_path(part) != record.get("sha256")
        ):
            raise ValueError(f"capture receipt part mismatch: {capture_id}")
    shard, _ = shard_paths(root, contract, capture_id)
    if receipt.get("snapshot_shard_sha256") != sha256_path(shard):
        raise ValueError(f"capture receipt shard mismatch: {capture_id}")
    return receipt


def row_source(
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


def rows_to_table(rows: Sequence[tuple[Any, ...]], schema: pa.Schema) -> pa.Table:
    columns: list[list[Any]] = [[] for _ in schema]
    for row in rows:
        blob = row[8]
        if not isinstance(blob, bytes) or len(blob) != FEATURE_BLOB_SIZE:
            raise ValueError("invalid snapshot feature BLOB")
        features = struct.unpack("<54d", blob)
        if not all(math.isfinite(value) for value in features):
            raise ValueError("non-finite snapshot feature")
        if features[1] != float(row[2]):
            raise ValueError("checkpoint packet-count feature mismatch")
        values = (*row[:6], bool(row[6]), row[7], *features)
        for column, value in zip(columns, values, strict=True):
            column.append(value)
    arrays = [pa.array(values, type=field.type) for values, field in zip(columns, schema, strict=True)]
    return pa.Table.from_arrays(arrays, schema=schema)


def write_part(
    path: Path, source: Path, assignment: Path, shard: Path, capture_id: str,
    checkpoint: str, schema: pa.Schema
) -> int:
    connection, cursor = row_source(source, assignment, shard, capture_id, checkpoint)
    rows_written = 0
    buffered: list[tuple[Any, ...]] = []
    sorting = pq.SortingColumn.from_ordering(schema, [("flow_id", "ascending")])
    writer = pq.ParquetWriter(
        path, schema, version="2.6", compression="zstd", compression_level=3,
        use_dictionary=["capture_id", "assigned_class", "assignment_method"],
        write_statistics=True, data_page_version="1.0", write_batch_size=FETCH_ROWS,
        store_schema=True, use_byte_stream_split=False, write_page_index=False,
        write_page_checksum=False, sorting_columns=sorting,
    )
    try:
        while True:
            batch = cursor.fetchmany(FETCH_ROWS)
            if not batch:
                break
            buffered.extend(batch)
            while len(buffered) >= ROW_GROUP_ROWS:
                table = rows_to_table(buffered[:ROW_GROUP_ROWS], schema)
                writer.write_table(table, row_group_size=ROW_GROUP_ROWS)
                rows_written += table.num_rows
                del buffered[:ROW_GROUP_ROWS]
        if buffered:
            table = rows_to_table(buffered, schema)
            writer.write_table(table, row_group_size=ROW_GROUP_ROWS)
            rows_written += table.num_rows
    finally:
        writer.close()
        connection.close()
    return rows_written


def package_capture(
    root: Path, contract_path: Path, capture_id: str, source: Path, assignment: Path,
    feature_names: Sequence[str]
) -> tuple[dict[str, Any], bool]:
    contract = load_json(contract_path)
    contract_hash = sha256_path(contract_path)
    schema = arrow_schema(feature_names, contract_hash)
    expected_schema_hash = schema_hash(schema)
    receipt_path = capture_receipt_path(root, contract, capture_id)
    if receipt_path.is_file():
        return validate_capture_receipt(
            root, contract, contract_hash, capture_id, expected_schema_hash
        ), True
    shard = validate_shard(root, contract, contract_hash, capture_id)
    reconcile_close_records(shard, source, capture_id)
    parquet_root = resolve_inside(root, contract["parquet"]["root"])
    parquet_root.mkdir(parents=True, exist_ok=True)
    staging = parquet_root / f".{capture_id}.{uuid.uuid4().hex}.tmp"
    staging.mkdir()
    records: list[dict[str, Any]] = []
    try:
        for checkpoint in CHECKPOINTS:
            staged_part = staging / f"{checkpoint}.parquet"
            rows = write_part(
                staged_part, source, assignment, shard, capture_id, checkpoint, schema
            )
            expected = contract["expected_accounting"]["by_capture_and_checkpoint"][capture_id][checkpoint]
            if rows != expected:
                raise ValueError(
                    f"unexpected assigned row count for {capture_id}/{checkpoint}: {rows} != {expected}"
                )
            final_part = output_part(root, contract, capture_id, checkpoint)
            final_part.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged_part, final_part)
            records.append({
                "checkpoint": checkpoint,
                "path": relative(final_part, root),
                "rows": rows,
                "size_bytes": final_part.stat().st_size,
                "sha256": sha256_path(final_part),
                "schema_sha256": expected_schema_hash,
            })
        receipt = {
            "schema_version": "1.0.0", "task": TASK,
            "kind": CAPTURE_RECEIPT_KIND, "status": "passed",
            "capture_id": capture_id, "generated_at_utc": utc_now(),
            "contract_sha256": contract_hash, "pyarrow_version": pa.__version__,
            "source_database_sha256": contract["prerequisites"]["source_database"]["sha256"],
            "assignment_database_sha256": contract["prerequisites"]["assignment_database"]["sha256"],
            "snapshot_shard_sha256": sha256_path(shard), "parts": records,
        }
        write_json_atomic(receipt_path, receipt)
        return receipt, False
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def run(root: Path, contract_path: Path, selected: Iterable[str] | None = None) -> list[dict[str, Any]]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T3.5 contract")
    verify_runtime(contract)
    ids = capture_ids(contract)
    requested = ids if selected is None else list(selected)
    if not requested or any(item not in ids for item in requested) or len(set(requested)) != len(requested):
        raise ValueError("invalid capture selection")
    prerequisites = contract["prerequisites"]
    source = verify_prerequisite(root, prerequisites["source_database"], "source database")
    assignment = verify_prerequisite(root, prerequisites["assignment_database"], "assignment database")
    feature_names = load_feature_names(root, contract)
    results = []
    for capture_id in requested:
        receipt, skipped = package_capture(
            root, contract_path, capture_id, source, assignment, feature_names
        )
        print(
            f"[T3.5 parquet] capture={capture_id} status={'skipped' if skipped else 'passed'} "
            f"rows={sum(part['rows'] for part in receipt['parts'])}", flush=True
        )
        results.append(receipt)
    return results


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path,
        default=root_default / "config/cicids2017-snapshot-contract.json",
    )
    parser.add_argument("--capture-id", action="append")
    args = parser.parse_args(argv)
    try:
        run(args.project_root, args.contract, args.capture_id)
        return 0
    except (OSError, RuntimeError, ValueError, sqlite3.Error, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
