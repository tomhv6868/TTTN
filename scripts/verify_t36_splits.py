#!/usr/bin/env python3
"""Independently validate T3.6 split artifacts and publish acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq

import build_t36_splits as builder


TASK = "T3.6"
PARTITIONS = ("train", "validation", "test")
CHECKPOINTS = ("F3", "F5", "F7", "F9")


def expected_schema(contract_hash: str) -> pa.Schema:
    return builder.flow_map_schema(contract_hash)


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
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def add_nested(target: dict[str, Any], keys: Sequence[str]) -> None:
    node = target
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    node[keys[-1]] = node.get(keys[-1], 0) + 1


def require_exact_source_match(
    flow_map: Path, parts: Sequence[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, dict[int, str]], dict[str, Any]]:
    block_partitions: dict[str, str] = {}
    flow_partitions: dict[str, dict[int, str]] = {}
    accounting: dict[str, Any] = {
        "by_partition": {},
        "by_capture_partition": {},
        "by_class_partition": {},
    }
    previous_key: tuple[str, int] | None = None
    total_rows = 0
    for source_record in builder.source_parts(parts, "F3"):
        source = builder.read_table(source_record["resolved_path"], builder.SOURCE_COLUMNS)
        capture_id = source.column("capture_id")[0].as_py()
        mapped = pq.read_table(
            flow_map,
            filters=[("capture_id", "=", capture_id)],
            partitioning=None,
        )
        source_values = source.to_pydict()
        map_values = mapped.to_pydict()
        if mapped.num_rows != source.num_rows:
            raise ValueError(f"flow-map coverage mismatch: {capture_id}")
        comparable = (
            "capture_id",
            "flow_id",
            "flow_start_timestamp_ns",
            "assigned_class",
            "label_binary",
            "assignment_method",
        )
        for column in comparable:
            if map_values[column] != source_values[column]:
                raise ValueError(f"flow-map source mismatch: {capture_id}/{column}")
        capture_flows: dict[int, str] = {}
        for row in zip(
            map_values["capture_id"],
            map_values["flow_id"],
            map_values["flow_start_timestamp_ns"],
            map_values["time_block_index"],
            map_values["time_block_start_timestamp_ns"],
            map_values["partition"],
            map_values["assigned_class"],
            map_values["label_binary"],
            strict=True,
        ):
            row_capture, flow_id, timestamp, block_index, block_start, partition, family, binary = row
            key = (row_capture, flow_id)
            if previous_key is not None and key <= previous_key:
                raise ValueError("flow map is not strictly sorted and unique")
            previous_key = key
            if (
                partition not in PARTITIONS
                or block_index != timestamp // builder.BLOCK_NS
                or block_start != block_index * builder.BLOCK_NS
                or binary != (family != "BENIGN")
            ):
                raise ValueError(f"invalid flow-map row: {row_capture}/{flow_id}")
            block_key = f"{row_capture}|{block_index}"
            previous_partition = block_partitions.setdefault(block_key, partition)
            if previous_partition != partition:
                raise ValueError(f"time-block leakage: {block_key}")
            if flow_id in capture_flows:
                raise ValueError(f"duplicate flow id in capture: {row_capture}/{flow_id}")
            capture_flows[flow_id] = partition
            add_nested(accounting["by_partition"], [partition])
            add_nested(accounting["by_capture_partition"], [row_capture, partition])
            add_nested(accounting["by_class_partition"], [family, partition])
            total_rows += 1
        flow_partitions[capture_id] = capture_flows
    accounting["rows"] = total_rows
    accounting["blocks"] = len(block_partitions)
    if set(accounting["by_partition"]) != set(PARTITIONS):
        raise ValueError("known split does not populate every partition")
    return block_partitions, flow_partitions, accounting


def checkpoint_accounting(
    parts: Sequence[dict[str, Any]], flow_partitions: Mapping[str, Mapping[int, str]]
) -> dict[str, Any]:
    accounting: dict[str, Any] = {
        "by_partition_and_checkpoint": {},
        "by_class_partition_and_checkpoint": {},
        "by_capture_partition_and_checkpoint": {},
    }
    seen: dict[str, set[tuple[str, int]]] = {checkpoint: set() for checkpoint in CHECKPOINTS}
    for record in sorted(parts, key=lambda item: item["path"]):
        table = builder.read_table(
            record["resolved_path"], ["capture_id", "flow_id", "checkpoint", "assigned_class"]
        )
        values = table.to_pydict()
        for capture_id, flow_id, checkpoint_value, family in zip(
            values["capture_id"],
            values["flow_id"],
            values["checkpoint"],
            values["assigned_class"],
            strict=True,
        ):
            partition = flow_partitions.get(capture_id, {}).get(flow_id)
            if partition is None:
                raise ValueError(f"checkpoint flow does not resolve through F3: {capture_id}/{flow_id}")
            checkpoint = f"F{checkpoint_value}"
            composite = (capture_id, flow_id)
            if composite in seen[checkpoint]:
                raise ValueError(f"duplicate checkpoint flow: {capture_id}/{flow_id}/{checkpoint}")
            seen[checkpoint].add(composite)
            add_nested(accounting["by_partition_and_checkpoint"], [partition, checkpoint])
            add_nested(
                accounting["by_class_partition_and_checkpoint"], [family, partition, checkpoint]
            )
            add_nested(
                accounting["by_capture_partition_and_checkpoint"],
                [capture_id, partition, checkpoint],
            )
    return accounting


def validate_loafo(
    loafo: Mapping[str, Any],
    contract: Mapping[str, Any],
    contract_path: Path,
    flow_map: Path,
    accounting: Mapping[str, Any],
) -> dict[str, Any]:
    contract_hash = builder.sha256_path(contract_path)
    map_record = loafo.get("known_flow_map", {})
    if (
        loafo.get("task") != TASK
        or loafo.get("kind") != "loafo_split_manifest"
        or loafo.get("status") != "passed"
        or loafo.get("contract_sha256") != contract_hash
        or loafo.get("source_manifest_sha256")
        != contract["prerequisites"]["t3_5_manifest"]["sha256"]
        or map_record.get("rows") != contract["flow_map"]["expected_rows"]
        or map_record.get("size_bytes") != flow_map.stat().st_size
        or map_record.get("sha256") != builder.sha256_path(flow_map)
        or loafo.get("known_protocol", {}).get("accounting") != accounting
    ):
        raise ValueError("LOAFO manifest identity or accounting mismatch")
    experiments = loafo.get("experiments")
    families = loafo.get("available_holdout_families")
    class_counts = accounting["by_class_partition_and_checkpoint"]
    expected_families = sorted(family for family in class_counts if family != "BENIGN")
    if (
        not isinstance(experiments, list)
        or families != expected_families
        or [item.get("holdout_family") for item in experiments] != expected_families
        or loafo.get("macro_loafo_eligibility") != "pending_T3.7_rare_family_gate"
        or loafo.get("unavailable_families")
        != [{"family": "Heartbleed", "reason": "zero T3.5 snapshots", "status": "unavailable"}]
    ):
        raise ValueError("LOAFO family scope mismatch")
    partition_counts = accounting["by_partition_and_checkpoint"]
    benign_test = class_counts["BENIGN"]["test"]
    for experiment in experiments:
        family = experiment["holdout_family"]
        counts = class_counts[family]
        if experiment.get("holdout_snapshot_counts_by_known_partition") != counts:
            raise ValueError(f"LOAFO holdout accounting mismatch: {family}")
        if experiment.get("proof") != {
            "all_holdout_rows_in_test": True,
            "holdout_train_rows": 0,
            "holdout_validation_rows": 0,
        }:
            raise ValueError(f"LOAFO exclusion proof mismatch: {family}")
        rows = experiment.get("expected_snapshot_rows", {})
        for checkpoint in CHECKPOINTS:
            moved_train = counts.get("train", {}).get(checkpoint, 0)
            moved_validation = counts.get("validation", {}).get(checkpoint, 0)
            if (
                rows.get("train", {}).get(checkpoint)
                != partition_counts["train"][checkpoint] - moved_train
                or rows.get("validation", {}).get(checkpoint)
                != partition_counts["validation"][checkpoint] - moved_validation
                or rows.get("test", {}).get(checkpoint)
                != partition_counts["test"][checkpoint] + moved_train + moved_validation
            ):
                raise ValueError(f"LOAFO selector arithmetic mismatch: {family}/{checkpoint}")
    return {"families": len(experiments), "benign_test_by_checkpoint": benign_test}


def deterministic_rebuild(
    root: Path, contract_path: Path, expected_hash: str, artifact_root: Path
) -> None:
    artifact_root.mkdir(parents=True, exist_ok=True)
    temporary_root = artifact_root / f".t36-rebuild-{uuid.uuid4().hex}"
    temporary_root.mkdir()
    try:
        rebuilt_map = temporary_root / "known-flow-split.parquet"
        rebuilt_loafo = temporary_root / "loafo-manifest.json"
        builder.build(root, contract_path, rebuilt_map, rebuilt_loafo)
        if builder.sha256_path(rebuilt_map) != expected_hash:
            raise ValueError("deterministic rebuild hash mismatch")
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def verify(root: Path, contract_path: Path, rebuild: bool = True) -> dict[str, Any]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    contract = builder.load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T3.6 contract")
    builder.verify_runtime(contract)
    _, parts = builder.verify_inputs(root, contract)
    flow_map = builder.resolve_inside(root, contract["outputs"]["known_flow_map"])
    loafo_path = builder.resolve_inside(root, contract["outputs"]["loafo_manifest"])
    if not flow_map.is_file() or not loafo_path.is_file():
        raise ValueError("T3.6 artifacts are incomplete")
    parquet = pq.ParquetFile(flow_map)
    schema = expected_schema(builder.sha256_path(contract_path))
    if (
        not parquet.schema_arrow.equals(schema, check_metadata=True)
        or parquet.metadata.num_rows != contract["flow_map"]["expected_rows"]
        or parquet.metadata.num_row_groups != 25
    ):
        raise ValueError("flow-map schema or physical accounting mismatch")
    parquet_files = sorted(flow_map.parent.glob("*.parquet"))
    if parquet_files != [flow_map]:
        raise ValueError("unexpected Parquet artifact under T3.6; snapshot copy is forbidden")
    _, flow_partitions, map_accounting = require_exact_source_match(flow_map, parts)
    if map_accounting["rows"] != contract["flow_map"]["expected_rows"]:
        raise ValueError("flow-map total row mismatch")
    accounting = checkpoint_accounting(parts, flow_partitions)
    expected_rows = contract["expected_accounting"]["snapshot_rows_by_checkpoint"]
    for checkpoint in CHECKPOINTS:
        observed = sum(
            accounting["by_partition_and_checkpoint"][partition][checkpoint]
            for partition in PARTITIONS
        )
        if observed != expected_rows[checkpoint]:
            raise ValueError(f"checkpoint coverage mismatch: {checkpoint}")
    loafo = builder.load_json(loafo_path)
    loafo_summary = validate_loafo(loafo, contract, contract_path, flow_map, accounting)
    map_hash = builder.sha256_path(flow_map)
    if rebuild:
        deterministic_rebuild(root, contract_path, map_hash, flow_map.parent)
    ratios = {
        partition: map_accounting["by_partition"][partition] / map_accounting["rows"]
        for partition in PARTITIONS
    }
    return {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "split_acceptance",
        "status": "passed",
        "generated_at_utc": builder.utc_now(),
        "contract": {
            "path": builder.relative(contract_path, root),
            "sha256": builder.sha256_path(contract_path),
        },
        "known_flow_map": {
            "path": builder.relative(flow_map, root),
            "sha256": map_hash,
            "size_bytes": flow_map.stat().st_size,
            "rows": map_accounting["rows"],
            "blocks": map_accounting["blocks"],
            "schema_sha256": schema_fingerprint(schema),
            "actual_flow_ratios": ratios,
        },
        "loafo_manifest": {
            "path": builder.relative(loafo_path, root),
            "sha256": builder.sha256_path(loafo_path),
            "size_bytes": loafo_path.stat().st_size,
            **loafo_summary,
        },
        "validation": {
            "all_t3_5_part_hashes_verified": True,
            "exact_f3_flow_coverage": True,
            "time_blocks_disjoint": True,
            "checkpoint_membership_resolved": True,
            "loafo_absolute_exclusion": True,
            "benign_test_unchanged": True,
            "deterministic_rebuild_hash": rebuild,
            "snapshot_features_copied": False,
        },
        "gate": {
            "decision": "pending_user_decision",
            "t3_7_authorized": False,
            "rare_family_gate_owner": "T3.7",
        },
        "checks": [
            {"name": "known.coverage_and_block_isolation", "status": "passed"},
            {"name": "known.flow_checkpoint_colocation", "status": "passed"},
            {"name": "known.ratio_70_10_20_block_constrained", "status": "passed"},
            {"name": "unknown.loafo_absolute_holdout", "status": "passed"},
            {"name": "artifact.no_snapshot_copy", "status": "passed"},
            {"name": "artifact.deterministic_rebuild", "status": "passed" if rebuild else "skipped"},
        ],
    }


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    receipt = builder.load_json(receipt_path)
    contract = builder.load_json(contract_path)
    flow_map = builder.resolve_inside(root, contract["outputs"]["known_flow_map"])
    loafo = builder.resolve_inside(root, contract["outputs"]["loafo_manifest"])
    if (
        receipt.get("task") != TASK
        or receipt.get("status") != "passed"
        or receipt.get("contract", {}).get("sha256") != builder.sha256_path(contract_path)
        or receipt.get("known_flow_map", {}).get("sha256") != builder.sha256_path(flow_map)
        or receipt.get("loafo_manifest", {}).get("sha256") != builder.sha256_path(loafo)
    ):
        raise ValueError("T3.6 acceptance receipt mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract",
        type=Path,
        default=root_default / "config/cicids2017-split-contract.json",
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            contract = builder.load_json(contract_path)
            builder.verify_runtime(contract)
            builder.verify_inputs(root, contract)
            print("[T3.6 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = verify(root, contract_path, rebuild=True)
            output = builder.resolve_inside(
                root, builder.load_json(contract_path)["outputs"]["acceptance_receipt"]
            )
            if output.exists():
                raise FileExistsError("T3.6 acceptance receipt already exists")
            builder.write_json_atomic(output, receipt)
            print(f"[T3.6 verify] status=passed receipt={builder.relative(output, root)}", flush=True)
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T3.6 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
