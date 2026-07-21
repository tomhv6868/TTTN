#!/usr/bin/env python3
"""Build deterministic T3.6 known-flow and declarative LOAFO splits."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T3.6"
PYARROW_VERSION = "23.0.1"
BLOCK_NS = 60_000_000_000
ROW_GROUP_ROWS = 65_536
SOURCE_COLUMNS = [
    "capture_id",
    "flow_id",
    "flow_start_timestamp_ns",
    "assigned_class",
    "label_binary",
    "assignment_method",
]


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


def verify_runtime(contract: Mapping[str, Any]) -> None:
    execution = contract.get("execution", {})
    expected_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    ratios = contract.get("known_protocol", {}).get("ratios", {})
    if (
        os.name != "nt"
        or execution.get("host") != "windows_native"
        or execution.get("python_major_minor") != expected_python
        or execution.get("pyarrow_exact_version") != PYARROW_VERSION
        or pa.__version__ != PYARROW_VERSION
        or ratios != {"train": 70, "validation": 10, "test": 20}
        or sum(ratios.values()) != 100
        or contract.get("known_protocol", {}).get("time_block_seconds") != 60
    ):
        raise RuntimeError("T3.6 runtime or split contract mismatch")


def verify_reference(root: Path, reference: Mapping[str, Any], label: str) -> Path:
    path = resolve_inside(root, str(reference.get("path", "")))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{label} content address mismatch")
    value = load_json(path)
    for key in ("task", "status"):
        if key in reference and value.get(key) != reference[key]:
            raise ValueError(f"{label} {key} mismatch")
    return path


def verify_inputs(root: Path, contract: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    prerequisites = contract.get("prerequisites", {})
    acceptance_path = verify_reference(root, prerequisites["t3_5_acceptance"], "T3.5 acceptance")
    acceptance = load_json(acceptance_path)
    if not acceptance.get("gate", {}).get("t3_6_authorized"):
        raise ValueError("T3.5 acceptance does not authorize T3.6")
    manifest_path = verify_reference(root, prerequisites["t3_5_manifest"], "T3.5 manifest")
    verify_reference(root, prerequisites["t3_5_build"], "T3.5 build")
    verify_reference(root, prerequisites["snapshot_contract"], "T3.5 contract")
    manifest = load_json(manifest_path)
    parts = manifest.get("parts")
    if (
        manifest.get("part_count") != 20
        or manifest.get("row_count") != 3_783_154
        or not isinstance(parts, list)
        or len(parts) != 20
    ):
        raise ValueError("T3.5 manifest accounting mismatch")
    verified: list[dict[str, Any]] = []
    for record in parts:
        path = resolve_inside(root, str(record.get("path", "")))
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
        ):
            raise ValueError(f"T3.5 Parquet content address mismatch: {record.get('path')}")
        parquet = pq.ParquetFile(path)
        if parquet.metadata.num_rows != record.get("rows"):
            raise ValueError(f"T3.5 Parquet row count mismatch: {record.get('path')}")
        verified.append({**record, "resolved_path": path})
    return manifest, verified


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
    for partition, ratio in ratios.items():
        new_total = assigned_totals[partition] + (sum(block.values()) if partition == candidate else 0)
        total_target = total_flows * ratio / 100.0
        score += ((new_total - total_target) / max(total_target, 1.0)) ** 2
        for family, family_total in class_totals.items():
            new_count = assigned[partition][family] + (block[family] if partition == candidate else 0)
            target = family_total * ratio / 100.0
            score += ((new_count - target) / max(target, 1.0)) ** 2
    return score


def allocate_capture(
    capture_id: str,
    blocks: Mapping[int, collections.Counter[str]],
    ratios: Mapping[str, int],
    seed: int,
) -> dict[int, str]:
    class_totals: collections.Counter[str] = collections.Counter()
    for counts in blocks.values():
        class_totals.update(counts)
    total_flows = sum(class_totals.values())
    ordered = sorted(
        blocks,
        key=lambda block_index: (
            -max(
                blocks[block_index][family] / class_totals[family]
                for family in blocks[block_index]
            ),
            -sum(blocks[block_index].values()),
            seeded_tie(seed, capture_id, block_index),
            block_index,
        ),
    )
    assigned = {partition: collections.Counter() for partition in ratios}
    assigned_totals = {partition: 0 for partition in ratios}
    result: dict[int, str] = {}
    for block_index in ordered:
        counts = blocks[block_index]
        partition = min(
            ratios,
            key=lambda item: (
                allocation_score(
                    item, counts, assigned, assigned_totals, class_totals, total_flows, ratios
                ),
                list(ratios).index(item),
            ),
        )
        result[block_index] = partition
        assigned[partition].update(counts)
        assigned_totals[partition] += sum(counts.values())
    if set(result) != set(blocks):
        raise RuntimeError(f"incomplete block allocation: {capture_id}")
    return result


def source_parts(parts: Iterable[dict[str, Any]], checkpoint: str) -> list[dict[str, Any]]:
    selected = [record for record in parts if f"checkpoint={checkpoint}/" in record["path"]]
    return sorted(selected, key=lambda record: record["path"].split("capture_id=", 1)[1])


def read_table(path: Path, columns: Sequence[str]) -> pa.Table:
    return pq.ParquetFile(path).read(columns=list(columns))


def collect_blocks(parts: Iterable[dict[str, Any]]) -> dict[str, dict[int, collections.Counter[str]]]:
    result: dict[str, dict[int, collections.Counter[str]]] = {}
    for record in source_parts(parts, "F3"):
        table = read_table(record["resolved_path"], SOURCE_COLUMNS)
        columns = table.to_pydict()
        capture_ids = set(columns["capture_id"])
        if len(capture_ids) != 1:
            raise ValueError(f"F3 part contains multiple captures: {record['path']}")
        capture_id = capture_ids.pop()
        blocks = result.setdefault(capture_id, {})
        for timestamp, family in zip(
            columns["flow_start_timestamp_ns"], columns["assigned_class"], strict=True
        ):
            counts = blocks.setdefault(timestamp // BLOCK_NS, collections.Counter())
            counts[family] += 1
    return result


def flow_map_schema(contract_hash: str) -> pa.Schema:
    metadata = {
        b"nids.task": TASK.encode(),
        b"nids.contract_sha256": contract_hash.encode(),
        b"nids.protocol": b"campaign_time_block_stratified_v1",
        b"nids.ratios": b"70/10/20",
    }
    return pa.schema(
        [
            pa.field("capture_id", pa.string(), nullable=False),
            pa.field("flow_id", pa.uint64(), nullable=False),
            pa.field("flow_start_timestamp_ns", pa.int64(), nullable=False),
            pa.field("time_block_index", pa.int64(), nullable=False),
            pa.field("time_block_start_timestamp_ns", pa.int64(), nullable=False),
            pa.field("partition", pa.string(), nullable=False),
            pa.field("assigned_class", pa.string(), nullable=False),
            pa.field("label_binary", pa.bool_(), nullable=False),
            pa.field("assignment_method", pa.string(), nullable=False),
        ],
        metadata=metadata,
    )


def build_map_table(table: pa.Table, assignments: Mapping[int, str], schema: pa.Schema) -> pa.Table:
    source = table.to_pydict()
    block_indices = [timestamp // BLOCK_NS for timestamp in source["flow_start_timestamp_ns"]]
    values = {
        "capture_id": source["capture_id"],
        "flow_id": source["flow_id"],
        "flow_start_timestamp_ns": source["flow_start_timestamp_ns"],
        "time_block_index": block_indices,
        "time_block_start_timestamp_ns": [value * BLOCK_NS for value in block_indices],
        "partition": [assignments[value] for value in block_indices],
        "assigned_class": source["assigned_class"],
        "label_binary": source["label_binary"],
        "assignment_method": source["assignment_method"],
    }
    arrays = [pa.array(values[field.name], type=field.type) for field in schema]
    return pa.Table.from_arrays(arrays, schema=schema)


def write_flow_map(
    output: Path,
    parts: Iterable[dict[str, Any]],
    allocations: Mapping[str, Mapping[int, str]],
    schema: pa.Schema,
) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    sorting = pq.SortingColumn.from_ordering(schema, [("capture_id", "ascending"), ("flow_id", "ascending")])
    writer = pq.ParquetWriter(
        temporary,
        schema,
        version="2.6",
        compression="zstd",
        compression_level=3,
        use_dictionary=["capture_id", "partition", "assigned_class", "assignment_method"],
        write_statistics=True,
        data_page_version="1.0",
        write_batch_size=16_384,
        store_schema=True,
        use_byte_stream_split=False,
        write_page_index=False,
        write_page_checksum=False,
        sorting_columns=sorting,
    )
    rows = 0
    try:
        for record in source_parts(parts, "F3"):
            source = read_table(record["resolved_path"], SOURCE_COLUMNS)
            capture_id = source.column("capture_id")[0].as_py()
            mapped = build_map_table(source, allocations[capture_id], schema)
            writer.write_table(mapped, row_group_size=ROW_GROUP_ROWS)
            rows += mapped.num_rows
        writer.close()
        writer = None
        os.replace(temporary, output)
    finally:
        if writer is not None:
            writer.close()
        temporary.unlink(missing_ok=True)
    return rows


def load_capture_partitions(
    flow_map: Path, capture_id: str
) -> dict[int, str]:
    table = pq.read_table(
        flow_map,
        columns=["capture_id", "flow_id", "partition"],
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    )
    values = table.to_pydict()
    return dict(zip(values["flow_id"], values["partition"], strict=True))


def increment_nested(target: dict[str, Any], keys: Sequence[str]) -> None:
    node = target
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    node[keys[-1]] = node.get(keys[-1], 0) + 1


def build_accounting(
    flow_map: Path, parts: Iterable[dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, Any]]:
    known: dict[str, Any] = {
        "by_partition_and_checkpoint": {},
        "by_class_partition_and_checkpoint": {},
        "by_capture_partition_and_checkpoint": {},
    }
    family_counts: dict[str, Any] = {}
    cached_capture = ""
    partitions: dict[int, str] = {}
    for record in sorted(parts, key=lambda item: item["path"]):
        table = read_table(record["resolved_path"], ["capture_id", "flow_id", "checkpoint", "assigned_class"])
        values = table.to_pydict()
        capture_id = values["capture_id"][0]
        if capture_id != cached_capture:
            partitions = load_capture_partitions(flow_map, capture_id)
            cached_capture = capture_id
        for flow_id, checkpoint_value, family in zip(
            values["flow_id"], values["checkpoint"], values["assigned_class"], strict=True
        ):
            if flow_id not in partitions:
                raise ValueError(f"checkpoint flow missing from F3 map: {capture_id}/{flow_id}")
            partition = partitions[flow_id]
            checkpoint = f"F{checkpoint_value}"
            increment_nested(known["by_partition_and_checkpoint"], [partition, checkpoint])
            increment_nested(
                known["by_class_partition_and_checkpoint"], [family, partition, checkpoint]
            )
            increment_nested(
                known["by_capture_partition_and_checkpoint"], [capture_id, partition, checkpoint]
            )
            increment_nested(family_counts, [family, partition, checkpoint])
    return known, family_counts


def loafo_experiments(
    family_counts: Mapping[str, Any], known: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    partitions = known["by_partition_and_checkpoint"]
    families = sorted(family for family in family_counts if family != "BENIGN")
    experiments: list[dict[str, Any]] = []
    for family in families:
        counts = family_counts[family]
        expected: dict[str, dict[str, int]] = {name: {} for name in ("train", "validation", "test")}
        for checkpoint in ("F3", "F5", "F7", "F9"):
            holdout_train = counts.get("train", {}).get(checkpoint, 0)
            holdout_validation = counts.get("validation", {}).get(checkpoint, 0)
            expected["train"][checkpoint] = partitions["train"][checkpoint] - holdout_train
            expected["validation"][checkpoint] = (
                partitions["validation"][checkpoint] - holdout_validation
            )
            expected["test"][checkpoint] = (
                partitions["test"][checkpoint] + holdout_train + holdout_validation
            )
        experiments.append(
            {
                "holdout_family": family,
                "macro_loafo_eligibility": "pending_T3.7_rare_family_gate",
                "selectors": {
                    "train": "known.partition == 'train' and assigned_class != holdout_family",
                    "validation": "known.partition == 'validation' and assigned_class != holdout_family",
                    "test": "known.partition == 'test' or assigned_class == holdout_family",
                },
                "holdout_snapshot_counts_by_known_partition": counts,
                "expected_snapshot_rows": expected,
                "proof": {
                    "holdout_train_rows": 0,
                    "holdout_validation_rows": 0,
                    "all_holdout_rows_in_test": True,
                },
            }
        )
    return experiments, families


def build(
    root: Path,
    contract_path: Path,
    flow_map_override: Path | None = None,
    loafo_override: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T3.6 contract")
    verify_runtime(contract)
    manifest, parts = verify_inputs(root, contract)
    contract_hash = sha256_path(contract_path)
    flow_map = flow_map_override or resolve_inside(root, contract["outputs"]["known_flow_map"])
    loafo_path = loafo_override or resolve_inside(root, contract["outputs"]["loafo_manifest"])
    if flow_map.exists() or loafo_path.exists():
        raise FileExistsError("T3.6 output already exists; refusing to overwrite immutable artifacts")
    blocks = collect_blocks(parts)
    ratios = contract["known_protocol"]["ratios"]
    seed = contract["known_protocol"]["seed"]
    allocations = {
        capture_id: allocate_capture(capture_id, capture_blocks, ratios, seed)
        for capture_id, capture_blocks in blocks.items()
    }
    rows = write_flow_map(flow_map, parts, allocations, flow_map_schema(contract_hash))
    try:
        if rows != contract["flow_map"]["expected_rows"]:
            raise ValueError(f"unexpected flow-map row count: {rows}")
        known, family_counts = build_accounting(flow_map, parts)
        experiments, families = loafo_experiments(family_counts, known)
        unavailable = contract["expected_accounting"]["explicit_zero_snapshot_family"]
        if unavailable in family_counts or "BENIGN" not in family_counts:
            raise ValueError("unexpected Heartbleed or BENIGN family accounting")
        loafo = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "loafo_split_manifest",
            "status": "passed",
            "generated_at_utc": utc_now(),
            "contract_sha256": contract_hash,
            "source_manifest_sha256": contract["prerequisites"]["t3_5_manifest"]["sha256"],
            "known_flow_map": {
                "path": relative(flow_map, root),
                "rows": rows,
                "size_bytes": flow_map.stat().st_size,
                "sha256": sha256_path(flow_map),
            },
            "known_protocol": {
                "seed": seed,
                "time_block_seconds": 60,
                "ratios": ratios,
                "accounting": known,
            },
            "available_holdout_families": families,
            "unavailable_families": [
                {
                    "family": unavailable,
                    "status": "unavailable",
                    "reason": "zero T3.5 snapshots",
                }
            ],
            "experiments": experiments,
            "macro_loafo_eligibility": "pending_T3.7_rare_family_gate",
        }
        write_json_atomic(loafo_path, loafo)
        return loafo
    except Exception:
        flow_map.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract",
        type=Path,
        default=root_default / "config/cicids2017-split-contract.json",
    )
    args = parser.parse_args(argv)
    try:
        result = build(args.project_root, args.contract)
        print(
            f"[T3.6] status=passed flows={result['known_flow_map']['rows']} "
            f"loafo_families={len(result['experiments'])}",
            flush=True,
        )
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
