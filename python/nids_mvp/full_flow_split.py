"""Extend the immutable T3.6 split to every assigned terminal flow."""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import os
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq

from nids_mvp import full_flow_dataset as dataset


TASK = "T9.1"
SEED = 3607
BLOCK_NS = 60_000_000_000
PARTITIONS = ("train", "validation", "test")
RATIOS = {"train": 70, "validation": 10, "test": 20}
ROW_GROUP_ROWS = 65_536
LEGACY_ACCEPTANCE_SHA256 = "9e6249d65dfc7fab7a31d411c6fd27e18e3320edde0b823776d4261e31df69ca"
LEGACY_MAP_SHA256 = "8137ce83b2d38424405f20ecc36f0e6227573b0f39aedf05043d4942c181d10a"
LEGACY_MAP_SIZE_BYTES = 9_011_968
LEGACY_MAP_ROWS = 1_504_210
LEGACY_MAP_SCHEMA_SHA256 = "ad09beff6396e5c043187bb8a44eb64f5c27570201dea48b0b33449fb093cf46"
EXPECTED_ASSIGNED_ROWS = 2_366_094
LEGACY_COLUMNS = (
    "capture_id",
    "flow_id",
    "flow_start_timestamp_ns",
    "time_block_index",
    "time_block_start_timestamp_ns",
    "partition",
    "assigned_class",
    "label_binary",
    "assignment_method",
)


@dataclass(frozen=True)
class LegacyMapReference:
    path: Path
    size_bytes: int
    sha256: str
    rows: int
    schema_sha256: str | None = None


@dataclass(frozen=True)
class SplitInputs:
    root: Path
    source: dataset.DatabaseReference
    assignment: dataset.DatabaseReference
    legacy_map: LegacyMapReference
    output_root: Path
    capture_ids: tuple[str, ...]
    expected_assigned_rows: int | None = None
    enforce_production_accounting: bool = False


@dataclass(frozen=True)
class FlowDescriptor:
    capture_id: str
    flow_id: int
    creation_timestamp_ns: int
    packet_count: int
    assigned_class: str
    assignment_method: str

    @property
    def block_index(self) -> int:
        return self.creation_timestamp_ns // BLOCK_NS

    @property
    def label_family(self) -> str:
        family = dataset.FAMILY_BY_ASSIGNED_CLASS.get(self.assigned_class)
        if family is None:
            raise ValueError(f"unmapped assigned class: {self.assigned_class}")
        return family


@dataclass(frozen=True)
class SplitRow:
    flow: FlowDescriptor
    partition: str
    partition_source: str


def split_schema(legacy_map_sha256: str) -> pa.Schema:
    metadata = {
        b"nids.task": TASK.encode(),
        b"nids.protocol": b"terminal_flow_locked_extension_v1",
        b"nids.seed": str(SEED).encode(),
        b"nids.block_ns": str(BLOCK_NS).encode(),
        b"nids.ratios": b"70/10/20",
        b"nids.legacy_map_sha256": legacy_map_sha256.encode(),
        b"nids.feature_columns_copied": b"false",
        b"nids.test_partition_policy": b"sealed_until_model_lock",
    }
    return pa.schema(
        [
            pa.field("capture_id", pa.string(), nullable=False),
            pa.field("flow_id", pa.uint64(), nullable=False),
            pa.field("creation_timestamp_ns", pa.int64(), nullable=False),
            pa.field("time_block_index", pa.int64(), nullable=False),
            pa.field("time_block_start_timestamp_ns", pa.int64(), nullable=False),
            pa.field("partition", pa.string(), nullable=False),
            pa.field("partition_source", pa.string(), nullable=False),
            pa.field("packet_count", pa.uint64(), nullable=False),
            pa.field("assigned_class", pa.string(), nullable=False),
            pa.field("label_family", pa.string(), nullable=False),
            pa.field("label_binary", pa.bool_(), nullable=False),
            pa.field("assignment_method", pa.string(), nullable=False),
        ],
        metadata=metadata,
    )


def production_inputs(root: Path) -> SplitInputs:
    root = root.resolve()
    if pa.__version__ != dataset.PYARROW_VERSION:
        raise RuntimeError(
            f"PyArrow version mismatch: observed={pa.__version__} "
            f"expected={dataset.PYARROW_VERSION}"
        )
    contract_path = root / "config/cicids2017-snapshot-contract.json"
    if dataset.sha256_path(contract_path) != dataset.SNAPSHOT_CONTRACT_SHA256:
        raise ValueError("immutable T3.5 contract content address mismatch")
    contract = dataset.load_json(contract_path)
    captures = contract.get("captures")
    if not isinstance(captures, list):
        raise ValueError("T3.5 capture inventory missing")
    capture_ids = tuple(
        item.get("id") for item in captures if isinstance(item, Mapping)
    )
    if (
        len(capture_ids) != len(captures)
        or any(not isinstance(item, str) for item in capture_ids)
        or capture_ids != tuple(dataset.EXPECTED_CAPTURE_ROWS)
    ):
        raise ValueError("T3.5 capture inventory mismatch")
    acceptance_path = root / "run_log/t3.6/acceptance.json"
    if dataset.sha256_path(acceptance_path) != LEGACY_ACCEPTANCE_SHA256:
        raise ValueError("immutable T3.6 acceptance content address mismatch")
    acceptance = dataset.load_json(acceptance_path)
    map_record = acceptance.get("known_flow_map", {})
    legacy_path = dataset.resolve_inside(root, str(map_record.get("path", "")))
    if (
        acceptance.get("task") != "T3.6"
        or acceptance.get("status") != "passed"
        or map_record.get("sha256") != LEGACY_MAP_SHA256
        or map_record.get("size_bytes") != LEGACY_MAP_SIZE_BYTES
        or map_record.get("rows") != LEGACY_MAP_ROWS
        or map_record.get("schema_sha256") != LEGACY_MAP_SCHEMA_SHA256
    ):
        raise ValueError("immutable T3.6 map reference mismatch")
    prerequisites = contract["prerequisites"]
    return SplitInputs(
        root=root,
        source=dataset.database_reference(root, prerequisites["source_database"]),
        assignment=dataset.database_reference(
            root, prerequisites["assignment_database"]
        ),
        legacy_map=LegacyMapReference(
            path=legacy_path,
            size_bytes=LEGACY_MAP_SIZE_BYTES,
            sha256=LEGACY_MAP_SHA256,
            rows=LEGACY_MAP_ROWS,
            schema_sha256=LEGACY_MAP_SCHEMA_SHA256,
        ),
        output_root=root / "run_log/full-flow-v1/split",
        capture_ids=capture_ids,
        expected_assigned_rows=EXPECTED_ASSIGNED_ROWS,
        enforce_production_accounting=True,
    )


def verify_legacy_map(reference: LegacyMapReference) -> None:
    if (
        not reference.path.is_file()
        or reference.path.stat().st_size != reference.size_bytes
        or dataset.sha256_path(reference.path) != reference.sha256
    ):
        raise ValueError("legacy T3.6 map content address mismatch")
    with pq.ParquetFile(reference.path) as parquet:
        if parquet.metadata.num_rows != reference.rows:
            raise ValueError("legacy T3.6 map row count mismatch")
        missing = set(LEGACY_COLUMNS) - set(parquet.schema_arrow.names)
        if missing:
            raise ValueError(
                f"legacy T3.6 map schema missing columns: {sorted(missing)}"
            )
        if (
            reference.schema_sha256 is not None
            and dataset.schema_fingerprint(parquet.schema_arrow)
            != reference.schema_sha256
        ):
            raise ValueError("legacy T3.6 map schema fingerprint mismatch")


def read_assigned_flows(
    inputs: SplitInputs, capture_id: str
) -> list[FlowDescriptor]:
    connection = sqlite3.connect(":memory:", uri=True)
    try:
        connection.execute(
            "ATTACH DATABASE ? AS source",
            (dataset.immutable_uri(inputs.source.path),),
        )
        connection.execute(
            "ATTACH DATABASE ? AS assignment",
            (dataset.immutable_uri(inputs.assignment.path),),
        )
        rows = connection.execute(
            """
            SELECT f.capture_id,f.flow_id,f.creation_timestamp_ns,f.packet_count,
                   a.capture_id,a.assigned_class,a.assignment_method
            FROM source.flow f
            JOIN assignment.flow_assignment a ON a.flow_id=f.flow_id
            WHERE f.capture_id=?
            ORDER BY f.flow_id
            """,
            (capture_id,),
        )
        result: list[FlowDescriptor] = []
        previous_flow_id: int | None = None
        for (
            source_capture,
            flow_id,
            timestamp,
            packet_count,
            assignment_capture,
            assigned_class,
            assignment_method,
        ) in rows:
            if (
                source_capture != capture_id
                or assignment_capture != capture_id
                or not isinstance(flow_id, int)
                or flow_id < 0
                or previous_flow_id is not None
                and flow_id <= previous_flow_id
                or not isinstance(packet_count, int)
                or packet_count < 1
                or assigned_class not in dataset.FAMILY_BY_ASSIGNED_CLASS
                or assignment_method not in {"mutual_unique", "class_consensus"}
            ):
                raise ValueError(f"invalid assigned source flow: {capture_id}/{flow_id}")
            result.append(
                FlowDescriptor(
                    capture_id=capture_id,
                    flow_id=flow_id,
                    creation_timestamp_ns=int(timestamp),
                    packet_count=packet_count,
                    assigned_class=str(assigned_class),
                    assignment_method=str(assignment_method),
                )
            )
            previous_flow_id = flow_id
        return result
    finally:
        connection.close()


def read_legacy_capture(path: Path, capture_id: str) -> pa.Table:
    return pq.read_table(
        path,
        columns=list(LEGACY_COLUMNS),
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    )


def seeded_tie(seed: int, capture_id: str, block_index: int) -> int:
    payload = f"{seed}|{capture_id}|{block_index}".encode()
    return int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "big")


def allocation_score(
    candidate: str,
    block: collections.Counter[str],
    assigned: Mapping[str, collections.Counter[str]],
    assigned_totals: Mapping[str, int],
    class_totals: Mapping[str, int],
    total_flows: int,
    ratios: Mapping[str, int],
) -> float:
    score = 0.0
    block_total = sum(block.values())
    for partition, ratio in ratios.items():
        new_total = assigned_totals[partition] + (
            block_total if partition == candidate else 0
        )
        total_target = total_flows * ratio / 100.0
        score += ((new_total - total_target) / max(total_target, 1.0)) ** 2
        for assigned_class, class_total in class_totals.items():
            new_count = assigned[partition][assigned_class] + (
                block[assigned_class] if partition == candidate else 0
            )
            target = class_total * ratio / 100.0
            score += ((new_count - target) / max(target, 1.0)) ** 2
    return score


def validate_legacy_rows(
    flows: Sequence[FlowDescriptor],
    legacy: pa.Table,
) -> tuple[dict[int, str], dict[int, str]]:
    by_id = {flow.flow_id: flow for flow in flows}
    expected_f3_ids = {flow.flow_id for flow in flows if flow.packet_count >= 3}
    values = legacy.to_pydict()
    legacy_partitions: dict[int, str] = {}
    locked_blocks: dict[int, str] = {}
    for (
        capture_id,
        flow_id,
        timestamp,
        block_index,
        block_start,
        partition,
        assigned_class,
        label_binary,
        assignment_method,
    ) in zip(*(values[name] for name in LEGACY_COLUMNS), strict=True):
        flow = by_id.get(int(flow_id))
        if (
            flow is None
            or flow.packet_count < 3
            or capture_id != flow.capture_id
            or timestamp != flow.creation_timestamp_ns
            or block_index != flow.block_index
            or block_start != flow.block_index * BLOCK_NS
            or partition not in PARTITIONS
            or assigned_class != flow.assigned_class
            or label_binary != (flow.assigned_class != "BENIGN")
            or assignment_method != flow.assignment_method
            or flow.flow_id in legacy_partitions
        ):
            raise ValueError(
                f"legacy F3/source mismatch: {capture_id}/{flow_id}"
            )
        previous = locked_blocks.setdefault(flow.block_index, str(partition))
        if previous != partition:
            raise ValueError(
                f"legacy time-block leakage: {capture_id}/{flow.block_index}"
            )
        legacy_partitions[flow.flow_id] = str(partition)
    if set(legacy_partitions) != expected_f3_ids:
        missing = expected_f3_ids - set(legacy_partitions)
        extra = set(legacy_partitions) - expected_f3_ids
        raise ValueError(
            f"legacy F3 coverage mismatch: missing={len(missing)} extra={len(extra)}"
        )
    return legacy_partitions, locked_blocks


def extend_capture(
    flows: Sequence[FlowDescriptor],
    legacy: pa.Table,
    ratios: Mapping[str, int] = RATIOS,
    seed: int = SEED,
) -> list[SplitRow]:
    if (
        tuple(ratios) != PARTITIONS
        or dict(ratios) != RATIOS
        or sum(ratios.values()) != 100
        or seed != SEED
    ):
        raise ValueError("terminal split policy mismatch")
    if not flows:
        raise ValueError("capture has no assigned flows")
    capture_ids = {flow.capture_id for flow in flows}
    if len(capture_ids) != 1:
        raise ValueError("split extension requires exactly one capture")
    capture_id = next(iter(capture_ids))
    if len({flow.flow_id for flow in flows}) != len(flows):
        raise ValueError(f"duplicate assigned flow id: {capture_id}")
    legacy_partitions, locked_blocks = validate_legacy_rows(flows, legacy)
    block_counts: dict[int, collections.Counter[str]] = {}
    block_flows: dict[int, list[FlowDescriptor]] = {}
    class_totals: collections.Counter[str] = collections.Counter()
    for flow in flows:
        block_counts.setdefault(flow.block_index, collections.Counter())[
            flow.assigned_class
        ] += 1
        block_flows.setdefault(flow.block_index, []).append(flow)
        class_totals[flow.assigned_class] += 1
    assigned = {
        partition: collections.Counter() for partition in PARTITIONS
    }
    assigned_totals = {partition: 0 for partition in PARTITIONS}
    block_partitions = dict(locked_blocks)
    for block_index, partition in locked_blocks.items():
        counts = block_counts.get(block_index)
        if counts is None:
            raise ValueError(f"locked block missing source flows: {capture_id}/{block_index}")
        assigned[partition].update(counts)
        assigned_totals[partition] += sum(counts.values())
    unlocked = set(block_counts) - set(locked_blocks)
    if any(
        flow.packet_count >= 3
        for block_index in unlocked
        for flow in block_flows[block_index]
    ):
        raise ValueError(f"unlocked block contains F3 flow: {capture_id}")
    ordered = sorted(
        unlocked,
        key=lambda block_index: (
            -max(
                block_counts[block_index][assigned_class]
                / class_totals[assigned_class]
                for assigned_class in block_counts[block_index]
            ),
            -sum(block_counts[block_index].values()),
            seeded_tie(seed, capture_id, block_index),
            block_index,
        ),
    )
    total_flows = len(flows)
    for block_index in ordered:
        counts = block_counts[block_index]
        partition = min(
            PARTITIONS,
            key=lambda candidate: (
                allocation_score(
                    candidate,
                    counts,
                    assigned,
                    assigned_totals,
                    class_totals,
                    total_flows,
                    ratios,
                ),
                PARTITIONS.index(candidate),
            ),
        )
        block_partitions[block_index] = partition
        assigned[partition].update(counts)
        assigned_totals[partition] += sum(counts.values())
    if set(block_partitions) != set(block_counts):
        raise RuntimeError(f"incomplete block allocation: {capture_id}")
    result: list[SplitRow] = []
    for flow in sorted(flows, key=lambda item: item.flow_id):
        partition = block_partitions[flow.block_index]
        if flow.flow_id in legacy_partitions:
            source = "legacy_f3"
            if partition != legacy_partitions[flow.flow_id]:
                raise RuntimeError(f"legacy partition changed: {capture_id}/{flow.flow_id}")
        elif flow.block_index in locked_blocks:
            source = "locked_block_inheritance"
        else:
            source = "short_only_block_allocation"
        result.append(
            SplitRow(
                flow=flow,
                partition=partition,
                partition_source=source,
            )
        )
    return result


def rows_to_table(rows: Sequence[SplitRow], schema: pa.Schema) -> pa.Table:
    values = {
        "capture_id": [row.flow.capture_id for row in rows],
        "flow_id": [row.flow.flow_id for row in rows],
        "creation_timestamp_ns": [
            row.flow.creation_timestamp_ns for row in rows
        ],
        "time_block_index": [row.flow.block_index for row in rows],
        "time_block_start_timestamp_ns": [
            row.flow.block_index * BLOCK_NS for row in rows
        ],
        "partition": [row.partition for row in rows],
        "partition_source": [row.partition_source for row in rows],
        "packet_count": [row.flow.packet_count for row in rows],
        "assigned_class": [row.flow.assigned_class for row in rows],
        "label_family": [row.flow.label_family for row in rows],
        "label_binary": [
            row.flow.assigned_class != "BENIGN" for row in rows
        ],
        "assignment_method": [row.flow.assignment_method for row in rows],
    }
    arrays = [pa.array(values[field.name], type=field.type) for field in schema]
    return pa.Table.from_arrays(arrays, schema=schema)


def write_split_map(
    path: Path,
    rows_by_capture: Mapping[str, Sequence[SplitRow]],
    legacy_map_sha256: str,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    schema = split_schema(legacy_map_sha256)
    sorting = pq.SortingColumn.from_ordering(
        schema, [("capture_id", "ascending"), ("flow_id", "ascending")]
    )
    writer = pq.ParquetWriter(
        temporary,
        schema,
        version="2.6",
        compression="zstd",
        compression_level=3,
        use_dictionary=[
            "capture_id",
            "partition",
            "partition_source",
            "assigned_class",
            "label_family",
            "assignment_method",
        ],
        write_statistics=True,
        data_page_version="1.0",
        write_batch_size=16_384,
        store_schema=True,
        use_byte_stream_split=False,
        write_page_index=False,
        write_page_checksum=False,
        sorting_columns=sorting,
    )
    total_rows = 0
    try:
        for capture_id in sorted(rows_by_capture):
            rows = rows_by_capture[capture_id]
            if any(row.flow.capture_id != capture_id for row in rows):
                raise ValueError(f"split capture row mismatch: {capture_id}")
            table = rows_to_table(rows, schema)
            writer.write_table(table, row_group_size=ROW_GROUP_ROWS)
            total_rows += table.num_rows
        writer.close()
        writer = None
        os.replace(temporary, path)
    finally:
        if writer is not None:
            writer.close()
        temporary.unlink(missing_ok=True)
    return {
        "path": str(path),
        "rows": total_rows,
        "size_bytes": path.stat().st_size,
        "sha256": dataset.sha256_path(path),
        "schema_sha256": dataset.schema_fingerprint(schema),
    }


def split_accounting(
    rows_by_capture: Mapping[str, Sequence[SplitRow]]
) -> dict[str, Any]:
    by_partition: collections.Counter[str] = collections.Counter()
    by_source: collections.Counter[str] = collections.Counter()
    by_capture: dict[str, dict[str, int]] = {}
    blocks: set[tuple[str, int]] = set()
    locked_blocks: set[tuple[str, int]] = set()
    short_only_blocks: set[tuple[str, int]] = set()
    for capture_id, rows in rows_by_capture.items():
        capture_counts: collections.Counter[str] = collections.Counter()
        block_partition: dict[int, str] = {}
        for row in rows:
            previous = block_partition.setdefault(
                row.flow.block_index, row.partition
            )
            if previous != row.partition:
                raise ValueError(
                    f"terminal split block leakage: {capture_id}/{row.flow.block_index}"
                )
            by_partition[row.partition] += 1
            capture_counts[row.partition] += 1
            by_source[row.partition_source] += 1
            key = (capture_id, row.flow.block_index)
            blocks.add(key)
            if row.partition_source in {
                "legacy_f3",
                "locked_block_inheritance",
            }:
                locked_blocks.add(key)
            else:
                short_only_blocks.add(key)
        by_capture[capture_id] = dict(capture_counts)
    if locked_blocks & short_only_blocks:
        raise ValueError("split block has conflicting allocation source")
    total = sum(by_partition.values())
    return {
        "rows": total,
        "blocks": len(blocks),
        "locked_blocks": len(locked_blocks),
        "short_only_blocks": len(short_only_blocks),
        "by_partition": dict(by_partition),
        "actual_ratios": {
            partition: by_partition[partition] / total
            for partition in PARTITIONS
        },
        "by_partition_source": dict(by_source),
        "by_capture_partition": by_capture,
    }


def validate_output_manifest(
    inputs: SplitInputs,
) -> dict[str, Any]:
    manifest_path = inputs.output_root / "manifest.json"
    manifest = dataset.load_json(manifest_path)
    record = manifest.get("flow_map", {})
    path = dataset.resolve_inside(inputs.root, str(record.get("path", "")))
    parquet_rows: int | None = None
    parquet_schema_matches = False
    if path.is_file():
        with pq.ParquetFile(path) as parquet:
            parquet_rows = parquet.metadata.num_rows
            parquet_schema_matches = parquet.schema_arrow.equals(
                split_schema(inputs.legacy_map.sha256),
                check_metadata=True,
            )
    if (
        manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_split_manifest"
        or manifest.get("status") != "complete"
        or manifest.get("seed") != SEED
        or manifest.get("time_block_seconds") != 60
        or manifest.get("ratios") != RATIOS
        or manifest.get("legacy_map", {}).get("sha256")
        != inputs.legacy_map.sha256
        or not path.is_file()
        or path.stat().st_size != record.get("size_bytes")
        or dataset.sha256_path(path) != record.get("sha256")
        or parquet_rows != record.get("rows")
        or not parquet_schema_matches
    ):
        raise ValueError("terminal split manifest mismatch")
    if (
        inputs.expected_assigned_rows is not None
        and record.get("rows") != inputs.expected_assigned_rows
    ):
        raise ValueError("terminal split row count mismatch")
    return manifest


def build_split(inputs: SplitInputs) -> tuple[dict[str, Any], bool]:
    if inputs.output_root.exists():
        return validate_output_manifest(inputs), True
    dataset.verify_database(inputs.source, "T3.3 source database")
    dataset.verify_database(inputs.assignment, "T3.3R1 assignment database")
    verify_legacy_map(inputs.legacy_map)
    rows_by_capture: dict[str, list[SplitRow]] = {}
    for capture_id in inputs.capture_ids:
        flows = read_assigned_flows(inputs, capture_id)
        legacy = read_legacy_capture(inputs.legacy_map.path, capture_id)
        rows_by_capture[capture_id] = extend_capture(flows, legacy)
    accounting = split_accounting(rows_by_capture)
    if (
        inputs.expected_assigned_rows is not None
        and accounting["rows"] != inputs.expected_assigned_rows
    ):
        raise ValueError("terminal split assigned-row accounting mismatch")
    if inputs.enforce_production_accounting and (
        accounting["by_partition_source"].get("legacy_f3", 0)
        != LEGACY_MAP_ROWS
        or accounting["rows"] != EXPECTED_ASSIGNED_ROWS
    ):
        raise ValueError("terminal split production accounting mismatch")
    staging = inputs.output_root.with_name(
        f".{inputs.output_root.name}.{uuid.uuid4().hex}.tmp"
    )
    staging.mkdir(parents=True)
    try:
        staged_map = staging / "flow-partitions.parquet"
        map_record = write_split_map(
            staged_map, rows_by_capture, inputs.legacy_map.sha256
        )
        final_map = inputs.output_root / staged_map.name
        map_record["path"] = dataset.relative(final_map, inputs.root)
        manifest = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "terminal_flow_split_manifest",
            "status": "complete",
            "generated_at_utc": dataset.utc_now(),
            "seed": SEED,
            "time_block_seconds": 60,
            "ratios": RATIOS,
            "partition_order": list(PARTITIONS),
            "legacy_map": {
                "path": dataset.relative(inputs.legacy_map.path, inputs.root),
                "rows": inputs.legacy_map.rows,
                "size_bytes": inputs.legacy_map.size_bytes,
                "sha256": inputs.legacy_map.sha256,
            },
            "flow_map": map_record,
            "accounting": accounting,
            "test_partition": {
                "status": "sealed",
                "feature_or_metric_reads_allowed": False,
            },
            "validation": {
                "legacy_f3_partitions_unchanged": True,
                "packet_count_gte_3_coverage_exact": True,
                "locked_block_short_flows_inherited": True,
                "short_only_blocks_allocated_atomically": True,
                "feature_columns_copied": False,
            },
        }
        dataset.write_json_atomic(staging / "manifest.json", manifest)
        inputs.output_root.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, inputs.output_root)
        return validate_output_manifest(inputs), False
    finally:
        if staging.exists():
            with contextlib.suppress(OSError):
                for path in sorted(staging.rglob("*"), reverse=True):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                staging.rmdir()


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    args = parser.parse_args(argv)
    try:
        inputs = production_inputs(args.project_root)
        if args.command == "build":
            manifest, skipped = build_split(inputs)
            state = "skipped" if skipped else "complete"
        else:
            manifest = validate_output_manifest(inputs)
            state = "complete"
        print(
            f"[T9.1 split] status={state} rows={manifest['flow_map']['rows']}",
            flush=True,
        )
        return 0
    except (OSError, RuntimeError, ValueError, sqlite3.Error, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
