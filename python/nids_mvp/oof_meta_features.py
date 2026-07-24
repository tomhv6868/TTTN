from __future__ import annotations

import argparse
import collections
import gc
import hashlib
import json
import os
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from nids_mvp import anomaly_baseline


TASK = "T4.4"
BATCH_ROWS = 65_536


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


def resolve_inside(root: Path, value: str) -> Path:
    candidate = Path(value)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def temporary_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def verify_runtime(contract: Mapping[str, Any]) -> None:
    expected = contract["execution"]
    observed = {
        "pyarrow": pa.__version__,
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
    }
    if (
        os.name != "nt"
        or expected.get("host") != "windows_native"
        or expected.get("python_major_minor") != f"{sys.version_info.major}.{sys.version_info.minor}"
        or observed != expected.get("versions")
        or expected.get("dependency_mutation_allowed") is not False
        or expected.get("model_training_allowed") is not True
        or expected.get("hooks_in_scope") is not False
    ):
        raise RuntimeError(f"T4.4 runtime contract mismatch: {observed}")


def verify_reference(root: Path, reference: Mapping[str, Any], label: str) -> Path:
    path = resolve_inside(root, str(reference.get("path", "")))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{label} content address mismatch")
    return path


def verify_inputs(
    root: Path, contract_path: Path
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, list[str]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.4 contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    manual = load_json(paths["t4_3_manual_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("t4_4_authorized")
    ):
        raise ValueError("T4.3 manual acceptance does not authorize T4.4")
    technical = load_json(paths["t4_3_technical_acceptance"])
    if technical.get("status") != "passed":
        raise ValueError("T4.3 technical acceptance is not passed")
    manifest = load_json(paths["snapshot_manifest"])
    features = manifest.get("model_feature_columns")
    parts = manifest.get("parts")
    if (
        manifest.get("status") != "passed"
        or manifest.get("row_count") != contract["prerequisites"]["snapshot_manifest"]["rows"]
        or not isinstance(features, list)
        or len(features) != contract["prerequisites"]["feature_schema"]["feature_count"]
        or not isinstance(parts, list)
        or len(parts) != contract["prerequisites"]["snapshot_manifest"]["parts"]
    ):
        raise ValueError("snapshot manifest contract mismatch")
    verified: list[dict[str, Any]] = []
    for record in parts:
        path = resolve_inside(root, str(record.get("path", "")))
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
            or pq.ParquetFile(path).metadata.num_rows != record.get("rows")
        ):
            raise ValueError(f"snapshot part content mismatch: {record.get('path')}")
        verified.append({**record, "resolved_path": path})
    flow_map = paths["known_flow_map"]
    if pq.ParquetFile(flow_map).metadata.num_rows != contract["prerequisites"]["known_flow_map"]["rows"]:
        raise ValueError("known flow-map row count mismatch")
    return contract, verified, flow_map, features


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
) -> dict[int, int]:
    class_totals: collections.Counter[str] = collections.Counter()
    for counts in blocks.values():
        class_totals.update(counts)
    total_flows = sum(class_totals.values())
    ordered = sorted(
        blocks,
        key=lambda block_index: (
            -max(blocks[block_index][family] / class_totals[family] for family in blocks[block_index]),
            -sum(blocks[block_index].values()),
            seeded_tie(seed, capture_id, block_index),
            block_index,
        ),
    )
    assigned = {partition: collections.Counter() for partition in ratios}
    assigned_totals = {partition: 0 for partition in ratios}
    result: dict[int, int] = {}
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
        result[block_index] = int(partition.removeprefix("fold_"))
        assigned[partition].update(counts)
        assigned_totals[partition] += sum(counts.values())
    if set(result) != set(blocks):
        raise RuntimeError(f"incomplete fold allocation: {capture_id}")
    return result


def capture_from_path(value: str) -> str:
    if "capture_id=" not in value:
        raise ValueError(f"snapshot path lacks capture partition: {value}")
    return value.split("capture_id=", 1)[1].split("/", 1)[0]


def capture_fold_map(
    flow_map: Path, capture_id: str, ratios: Mapping[str, int], seed: int
) -> tuple[dict[int, tuple[str, int | None]], dict[int, int]]:
    data = pq.read_table(
        flow_map,
        columns=["flow_id", "time_block_index", "partition", "assigned_class"],
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    ).to_pydict()
    blocks: dict[int, collections.Counter[str]] = {}
    for block, partition, family in zip(
        data["time_block_index"], data["partition"], data["assigned_class"], strict=True
    ):
        if partition == "train":
            blocks.setdefault(block, collections.Counter())[family] += 1
    allocation = allocate_capture(capture_id, blocks, ratios, seed)
    mapping: dict[int, tuple[str, int | None]] = {}
    for flow_id, block, partition, family in zip(
        data["flow_id"],
        data["time_block_index"],
        data["partition"],
        data["assigned_class"],
        strict=True,
    ):
        mapping[flow_id] = (family, allocation[block] if partition == "train" else None)
    if len(mapping) != len(data["flow_id"]):
        raise ValueError(f"duplicate flow-map key: {capture_id}")
    return mapping, allocation


def fold_assignment_audit(
    flow_map: Path, ratios: Mapping[str, int], seed: int
) -> dict[str, Any]:
    captures = sorted(
        set(
            pq.ParquetFile(flow_map)
            .read(columns=["capture_id"])
            .column("capture_id")
            .to_pylist()
        )
    )
    digest = hashlib.sha256()
    group_counts = collections.Counter()
    for capture_id in captures:
        _, allocation = capture_fold_map(flow_map, capture_id, ratios, seed)
        for block, fold in sorted(allocation.items()):
            digest.update(f"{capture_id}|{block}|{fold}\n".encode())
            group_counts[fold] += 1
    return {
        "captures": captures,
        "group_count": int(sum(group_counts.values())),
        "groups_by_fold": {str(fold): int(group_counts[fold]) for fold in range(5)},
        "assignment_sha256": digest.hexdigest(),
    }


def _open_matrix(path: Path, shape: tuple[int, ...], dtype: Any) -> np.memmap:
    return np.lib.format.open_memmap(path, mode="w+", dtype=dtype, shape=shape)


def checkpoint_parts(parts: Iterable[Mapping[str, Any]], checkpoint: str) -> list[Mapping[str, Any]]:
    return [record for record in parts if f"checkpoint={checkpoint}/" in record["path"]]


def materialize_checkpoint(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    features: Sequence[str],
    contract: Mapping[str, Any],
    scratch: Path,
) -> dict[str, Path]:
    expected = contract["expected_population"][checkpoint]
    rows = int(expected["rows"])
    paths = {
        "raw": scratch / f"{checkpoint}-raw.npy",
        "capture_id": scratch / f"{checkpoint}-capture-id.npy",
        "flow_id": scratch / f"{checkpoint}-flow-id.npy",
        "fold": scratch / f"{checkpoint}-fold.npy",
        "assigned_class": scratch / f"{checkpoint}-assigned-class.npy",
        "y_true": scratch / f"{checkpoint}-y-true.npy",
    }
    arrays = {
        "raw": _open_matrix(paths["raw"], (rows, len(features)), np.float64),
        "capture_id": _open_matrix(paths["capture_id"], (rows,), "<U32"),
        "flow_id": _open_matrix(paths["flow_id"], (rows,), np.uint64),
        "fold": _open_matrix(paths["fold"], (rows,), np.uint8),
        "assigned_class": _open_matrix(paths["assigned_class"], (rows,), "<U64"),
        "y_true": _open_matrix(paths["y_true"], (rows,), np.uint8),
    }
    offset = 0
    ratios = contract["folding"]["ratios"]
    seed = int(contract["folding"]["seed"])
    for record in checkpoint_parts(parts, checkpoint):
        capture_id = capture_from_path(record["path"])
        mapping, _ = capture_fold_map(flow_map, capture_id, ratios, seed)
        parquet = pq.ParquetFile(record["resolved_path"])
        columns = ["flow_id", "capture_id", "assigned_class", *features]
        for batch in parquet.iter_batches(columns=columns, batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            captures = batch.column(1).to_pylist()
            families = batch.column(2).to_pylist()
            indices: list[int] = []
            folds: list[int] = []
            for index, (flow_id, observed_capture, family) in enumerate(
                zip(flow_ids, captures, families, strict=True)
            ):
                mapped = mapping.get(flow_id)
                if observed_capture != capture_id or mapped is None or mapped[0] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[1] is not None:
                    indices.append(index)
                    folds.append(mapped[1])
            if not indices:
                continue
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(features))]
            ).astype(np.float64, copy=False)[indices]
            if np.isinf(raw).any():
                raise ValueError(f"infinite model input: {checkpoint}/{capture_id}")
            stop = offset + len(indices)
            if stop > rows:
                raise ValueError(f"train population exceeds contract: {checkpoint}")
            arrays["raw"][offset:stop] = raw
            arrays["capture_id"][offset:stop] = capture_id
            arrays["flow_id"][offset:stop] = np.asarray([flow_ids[index] for index in indices], np.uint64)
            arrays["fold"][offset:stop] = np.asarray(folds, np.uint8)
            selected_families = np.asarray([families[index] for index in indices], dtype="<U64")
            arrays["assigned_class"][offset:stop] = selected_families
            arrays["y_true"][offset:stop] = (selected_families != "BENIGN").astype(np.uint8)
            offset = stop
    for array in arrays.values():
        array.flush()
    if offset != rows:
        raise ValueError(f"train population mismatch: {checkpoint}: {offset}")
    folds = arrays["fold"]
    labels = arrays["y_true"]
    for fold in range(5):
        observed = {
            "rows": int(np.count_nonzero(folds == fold)),
            "benign": int(np.count_nonzero((folds == fold) & (labels == 0))),
            "attack": int(np.count_nonzero((folds == fold) & (labels == 1))),
        }
        expected_fold = expected["folds"][str(fold)]
        if any(observed[name] != expected_fold[name] for name in observed):
            raise ValueError(f"fold population mismatch: {checkpoint}/{fold}: {observed}")
    del arrays
    return paths


def impute(values: np.ndarray, medians: np.ndarray) -> np.ndarray:
    return np.where(np.isnan(values), medians, values)


def fit_fold_preprocessor(
    raw: np.ndarray,
    fit_indices: np.ndarray,
    features: Sequence[str],
    batch_rows: int = BATCH_ROWS,
) -> tuple[dict[str, Any], StandardScaler]:
    medians = np.empty(raw.shape[1], dtype=np.float64)
    for column in range(raw.shape[1]):
        medians[column] = np.nanmedian(np.asarray(raw[fit_indices, column], dtype=np.float64))
    if not np.isfinite(medians).all():
        raise ValueError("fold preprocessing produced non-finite median")
    scaler = StandardScaler(with_mean=True, with_std=True)
    minimum = np.full(raw.shape[1], np.inf, dtype=np.float64)
    maximum = np.full(raw.shape[1], -np.inf, dtype=np.float64)
    for start in range(0, len(fit_indices), batch_rows):
        indices = fit_indices[start : start + batch_rows]
        values = impute(np.asarray(raw[indices]), medians)
        minimum = np.minimum(minimum, np.min(values, axis=0))
        maximum = np.maximum(maximum, np.max(values, axis=0))
        scaler.partial_fit(values)
    constant_indices = np.flatnonzero(minimum == maximum)
    constant_set = set(constant_indices.tolist())
    selected_indices = [index for index in range(len(features)) if index not in constant_set]
    if not selected_indices:
        raise ValueError("fold preprocessing removed every feature")
    profile = {
        "fit_rows": int(len(fit_indices)),
        "input_features": list(features),
        "imputer": "median",
        "imputation_values": medians.tolist(),
        "constant_detection": "exact_imputed_min_equals_max",
        "dropped_constant_features": [features[index] for index in constant_indices],
        "selected_indices": selected_indices,
        "selected_features": [features[index] for index in selected_indices],
        "scaler": "standard",
        "scaler_mean": np.asarray(scaler.mean_)[selected_indices].tolist(),
        "scaler_scale": np.asarray(scaler.scale_)[selected_indices].tolist(),
        "output_dtype": "float32",
    }
    return profile, scaler


def transform_fold(
    raw: np.ndarray,
    row_indices: np.ndarray,
    profile: Mapping[str, Any],
    output_path: Path,
    batch_rows: int = BATCH_ROWS,
) -> np.memmap:
    selected = np.asarray(profile["selected_indices"], dtype=np.int64)
    output = _open_matrix(output_path, (len(row_indices), len(selected)), np.float32)
    for start in range(0, len(row_indices), batch_rows):
        stop = min(start + batch_rows, len(row_indices))
        output[start:stop] = transform_values(np.asarray(raw[row_indices[start:stop]]), profile)
    output.flush()
    if not np.isfinite(output).all():
        raise ValueError("fold transform produced non-finite output")
    return output


def transform_values(values: np.ndarray, profile: Mapping[str, Any]) -> np.ndarray:
    selected = np.asarray(profile["selected_indices"], dtype=np.int64)
    medians = np.asarray(profile["imputation_values"], dtype=np.float64)
    means = np.asarray(profile["scaler_mean"], dtype=np.float64)
    scales = np.asarray(profile["scaler_scale"], dtype=np.float64)
    transformed = impute(np.asarray(values, dtype=np.float64), medians)[:, selected]
    transformed -= means
    transformed /= scales
    result = transformed.astype(np.float32)
    if not np.isfinite(result).all():
        raise ValueError("fold transform produced non-finite output")
    return result


def derive_hbos_mask(
    matrix: np.ndarray,
    features: Sequence[str],
    sample_rows_maximum: int,
    absolute_threshold: float,
) -> tuple[list[str], dict[str, Any]]:
    count = min(sample_rows_maximum, matrix.shape[0])
    indices = np.unique(np.linspace(0, matrix.shape[0] - 1, num=count, dtype=np.int64))
    sample = np.asarray(matrix[indices], dtype=np.float64)
    with np.errstate(divide="ignore", invalid="ignore"):
        correlation = np.corrcoef(sample, rowvar=False)
    correlation = np.nan_to_num(correlation, nan=0.0, posinf=0.0, neginf=0.0)
    retained_indices: list[int] = []
    rejected: list[dict[str, Any]] = []
    for index, feature in enumerate(features):
        correlated = next(
            (
                earlier
                for earlier in retained_indices
                if abs(float(correlation[index, earlier])) >= absolute_threshold
            ),
            None,
        )
        if correlated is None:
            retained_indices.append(index)
        else:
            rejected.append(
                {
                    "feature": feature,
                    "correlated_with": features[correlated],
                    "correlation": float(correlation[index, correlated]),
                }
            )
    return [features[index] for index in retained_indices], {
        "sample_rows": int(len(indices)),
        "absolute_threshold": float(absolute_threshold),
        "retained_count": len(retained_indices),
        "rejected": rejected,
    }


def oof_schema(contract: Mapping[str, Any], contract_hash: str) -> pa.Schema:
    metadata = {
        b"nids.task": TASK.encode(),
        b"nids.artifact_id": contract["artifact"]["id"].encode(),
        b"nids.artifact_version": contract["artifact"]["version"].encode(),
        b"nids.contract_sha256": contract_hash.encode(),
        b"nids.partition": b"train",
    }
    return pa.schema(
        [
            pa.field("checkpoint", pa.string(), nullable=False),
            pa.field("capture_id", pa.string(), nullable=False),
            pa.field("flow_id", pa.uint64(), nullable=False),
            pa.field("fold", pa.uint8(), nullable=False),
            pa.field("assigned_class", pa.string(), nullable=False),
            pa.field("y_true", pa.uint8(), nullable=False),
            pa.field("hbos_raw_score", pa.float64(), nullable=False),
            pa.field("hbos_normalized_score", pa.float64(), nullable=False),
            pa.field("hbos_binary", pa.uint8(), nullable=False),
            pa.field("isolation_forest_raw_score", pa.float64(), nullable=False),
            pa.field("isolation_forest_normalized_score", pa.float64(), nullable=False),
            pa.field("isolation_forest_binary", pa.uint8(), nullable=False),
            pa.field("anomaly_count", pa.uint8(), nullable=False),
        ],
        metadata=metadata,
    )


def prediction_table(
    schema: pa.Schema,
    checkpoint: str,
    arrays: Mapping[str, np.ndarray],
    hold_indices: np.ndarray,
    scores: Mapping[str, np.ndarray],
) -> pa.Table:
    size = len(hold_indices)
    hbos_binary = np.asarray(scores["hbos_binary"], dtype=np.uint8)
    iforest_binary = np.asarray(scores["isolation_forest_binary"], dtype=np.uint8)
    values = [
        pa.array([checkpoint] * size, type=pa.string()),
        pa.array(np.asarray(arrays["capture_id"])[hold_indices], type=pa.string()),
        pa.array(np.asarray(arrays["flow_id"])[hold_indices], type=pa.uint64()),
        pa.array(np.asarray(arrays["fold"])[hold_indices], type=pa.uint8()),
        pa.array(np.asarray(arrays["assigned_class"])[hold_indices], type=pa.string()),
        pa.array(np.asarray(arrays["y_true"])[hold_indices], type=pa.uint8()),
        pa.array(scores["hbos_raw"], type=pa.float64()),
        pa.array(scores["hbos_normalized"], type=pa.float64()),
        pa.array(hbos_binary, type=pa.uint8()),
        pa.array(scores["isolation_forest_raw"], type=pa.float64()),
        pa.array(scores["isolation_forest_normalized"], type=pa.float64()),
        pa.array(iforest_binary, type=pa.uint8()),
        pa.array(hbos_binary + iforest_binary, type=pa.uint8()),
    ]
    return pa.Table.from_arrays(values, schema=schema)


def build_checkpoint(
    checkpoint: str,
    paths: Mapping[str, Path],
    features: Sequence[str],
    contract: Mapping[str, Any],
    writer: pq.ParquetWriter,
    scratch: Path,
) -> dict[str, Any]:
    arrays = {name: np.load(path, mmap_mode="r") for name, path in paths.items()}
    diagnostics: dict[str, Any] = {"folds": {}}
    aggregate = {"hbos": {"y": [], "p": []}, "isolation_forest": {"y": [], "p": []}}
    for held_fold in range(5):
        started = time.monotonic()
        fit_indices = np.flatnonzero((arrays["fold"] != held_fold) & (arrays["y_true"] == 0))
        hold_indices = np.flatnonzero(arrays["fold"] == held_fold)
        if np.intersect1d(fit_indices, hold_indices, assume_unique=True).size:
            raise ValueError(f"model-fit leakage detected: {checkpoint}/{held_fold}")
        profile, _ = fit_fold_preprocessor(arrays["raw"], fit_indices, features)
        fit_path = scratch / f"{checkpoint}-fold-{held_fold}-fit.npy"
        hold_path = scratch / f"{checkpoint}-fold-{held_fold}-hold.npy"
        x_fit = transform_fold(arrays["raw"], fit_indices, profile, fit_path)
        x_hold = transform_fold(arrays["raw"], hold_indices, profile, hold_path)
        parity_count = min(1024, len(fit_indices))
        parity_positions = np.unique(np.linspace(0, len(fit_indices) - 1, num=parity_count, dtype=np.int64))
        parity_path = scratch / f"{checkpoint}-fold-{held_fold}-parity.npy"
        parity = transform_fold(arrays["raw"], fit_indices[parity_positions], profile, parity_path)
        if not np.array_equal(np.asarray(parity), np.asarray(x_fit[parity_positions])):
            raise ValueError(f"fold preprocessing parity failed: {checkpoint}/{held_fold}")
        parity_hash = hashlib.sha256(np.asarray(parity).tobytes(order="C")).hexdigest()
        del parity
        parity_path.unlink()
        mask_config = contract["hbos"]["correlation_mask"]
        hbos_mask, mask_audit = derive_hbos_mask(
            x_fit,
            profile["selected_features"],
            int(mask_config["sample_rows_maximum"]),
            float(mask_config["absolute_threshold"]),
        )
        hbos = anomaly_baseline.fit_hbos(x_fit, profile["selected_features"], hbos_mask, contract["hbos"])
        hbos_fit_raw = anomaly_baseline.score_hbos(hbos, x_fit)
        hbos_decision = anomaly_baseline.fit_score_decision(hbos_fit_raw, contract["score_decision"])
        hbos_hold_raw = anomaly_baseline.score_hbos(hbos, x_hold)
        hbos_normalized, hbos_binary = anomaly_baseline.apply_score_decision(
            hbos_hold_raw, hbos_decision
        )
        parameters = dict(contract["isolation_forest"]["parameters"])
        parameters["random_state"] = int(contract["folding"]["seed"]) + held_fold
        isolation_forest = IsolationForest(**parameters).fit(x_fit)
        iforest_fit_raw = anomaly_baseline.score_isolation_forest(isolation_forest, x_fit)
        iforest_decision = anomaly_baseline.fit_score_decision(
            iforest_fit_raw, contract["score_decision"]
        )
        iforest_hold_raw = anomaly_baseline.score_isolation_forest(isolation_forest, x_hold)
        iforest_normalized, iforest_binary = anomaly_baseline.apply_score_decision(
            iforest_hold_raw, iforest_decision
        )
        scores = {
            "hbos_raw": hbos_hold_raw,
            "hbos_normalized": hbos_normalized,
            "hbos_binary": hbos_binary,
            "isolation_forest_raw": iforest_hold_raw,
            "isolation_forest_normalized": iforest_normalized,
            "isolation_forest_binary": iforest_binary,
        }
        writer.write_table(
            prediction_table(writer.schema, checkpoint, arrays, hold_indices, scores),
            row_group_size=int(contract["artifact"]["row_group_rows"]),
        )
        y_hold = np.asarray(arrays["y_true"])[hold_indices]
        fold_metrics = {
            "hbos": anomaly_baseline.compute_metrics(y_hold, hbos_binary),
            "isolation_forest": anomaly_baseline.compute_metrics(y_hold, iforest_binary),
        }
        for name, prediction in (("hbos", hbos_binary), ("isolation_forest", iforest_binary)):
            aggregate[name]["y"].append(np.array(y_hold, copy=True))
            aggregate[name]["p"].append(np.array(prediction, copy=True))
        diagnostics["folds"][str(held_fold)] = {
            "held_out_fold": held_fold,
            "fit_folds": [fold for fold in range(5) if fold != held_fold],
            "fit_class": "BENIGN",
            "fit_rows": int(len(fit_indices)),
            "held_rows": int(len(hold_indices)),
            "held_benign": int(np.count_nonzero(y_hold == 0)),
            "held_attack": int(np.count_nonzero(y_hold == 1)),
            "preprocessing": {
                "selected_feature_count": len(profile["selected_features"]),
                "selected_features": profile["selected_features"],
                "dropped_constant_features": profile["dropped_constant_features"],
                "parity": {
                    "status": "passed",
                    "rows": int(len(parity_positions)),
                    "output_sha256": parity_hash,
                },
            },
            "hbos": {
                "feature_count": len(hbos_mask),
                "feature_names": hbos_mask,
                "correlation_audit": mask_audit,
                "score_decision": hbos_decision,
                "metrics": fold_metrics["hbos"],
            },
            "isolation_forest": {
                "random_state": parameters["random_state"],
                "score_decision": iforest_decision,
                "metrics": fold_metrics["isolation_forest"],
            },
            "elapsed_seconds": time.monotonic() - started,
        }
        del (
            x_fit,
            x_hold,
            isolation_forest,
            hbos_fit_raw,
            hbos_hold_raw,
            hbos_normalized,
            hbos_binary,
            iforest_fit_raw,
            iforest_hold_raw,
            iforest_normalized,
            iforest_binary,
            y_hold,
        )
        fit_path.unlink()
        hold_path.unlink()
        gc.collect()
        print(
            f"[T4.4] checkpoint={checkpoint} fold={held_fold} status=scored "
            f"elapsed_seconds={time.monotonic() - started:.1f}",
            flush=True,
        )
    diagnostics["aggregate_metrics"] = {
        name: anomaly_baseline.compute_metrics(
            np.concatenate(values["y"]), np.concatenate(values["p"])
        )
        for name, values in aggregate.items()
    }
    del arrays
    return diagnostics


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, parts, flow_map, features = verify_inputs(root, contract_path)
    artifact = resolve_inside(root, contract["artifact"]["path"])
    acceptance = resolve_inside(root, contract["acceptance"]["path"])
    if artifact.exists() or acceptance.exists():
        raise FileExistsError("T4.4 artifact already exists; refusing to overwrite evidence")
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact_temp = temporary_sibling(artifact)
    acceptance_temp = temporary_sibling(acceptance)
    started = time.monotonic()
    diagnostics: dict[str, Any] = {}
    contract_hash = sha256_path(contract_path)
    schema = oof_schema(contract, contract_hash)
    scratch = root / "run_log" / f".nids-t44-{uuid.uuid4().hex}"
    scratch.mkdir(parents=False, exist_ok=False)
    try:
        with pq.ParquetWriter(
            artifact_temp,
            schema,
            compression=contract["artifact"]["compression"],
            compression_level=int(contract["artifact"]["compression_level"]),
        ) as writer:
            for checkpoint in contract["input"]["checkpoints"]:
                print(f"[T4.4] checkpoint={checkpoint} stage=materialize", flush=True)
                paths = materialize_checkpoint(
                    checkpoint, parts, flow_map, features, contract, scratch
                )
                diagnostics[checkpoint] = build_checkpoint(
                    checkpoint, paths, features, contract, writer, scratch
                )
                for path in paths.values():
                    path.unlink()
                gc.collect()
        expected_rows = sum(
            contract["expected_population"][checkpoint]["rows"]
            for checkpoint in contract["input"]["checkpoints"]
        )
        parquet = pq.ParquetFile(artifact_temp)
        try:
            if parquet.metadata.num_rows != expected_rows or parquet.schema_arrow != schema:
                raise ValueError("published OOF Parquet schema or row count mismatch")
            row_group_count = parquet.metadata.num_row_groups
        finally:
            parquet.close()
        assignment = fold_assignment_audit(
            flow_map, contract["folding"]["ratios"], int(contract["folding"]["seed"])
        )
        expected_groups = {
            fold: contract["expected_population"]["F3"]["folds"][fold]["groups"]
            for fold in map(str, range(5))
        }
        if assignment["groups_by_fold"] != expected_groups:
            raise ValueError("fold group accounting mismatch")
        source_paths = [
            root / "python/nids_mvp/oof_meta_features.py",
            root / "python/nids_mvp/anomaly_baseline.py",
            root / "tests/test_t44_oof_meta_features.py",
        ]
        receipt = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "oof_anomaly_meta_feature_acceptance_bundle",
            "status": "passed",
            "generated_at_utc": utc_now(),
            "elapsed_seconds": time.monotonic() - started,
            "contract": {"path": relative(contract_path, root), "sha256": contract_hash},
            "source_files": {relative(path, root): sha256_path(path) for path in source_paths},
            "inputs": {
                name: {"path": reference["path"], "sha256": reference["sha256"]}
                for name, reference in contract["prerequisites"].items()
            },
            "runtime": {
                "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                **contract["execution"]["versions"],
            },
            "artifact": {
                "artifact_id": contract["artifact"]["id"],
                "artifact_version": contract["artifact"]["version"],
                "path": relative(artifact, root),
                "sha256": sha256_path(artifact_temp),
                "size_bytes": artifact_temp.stat().st_size,
                "rows": expected_rows,
                "row_groups": row_group_count,
                "schema": {field.name: str(field.type) for field in schema},
            },
            "fold_assignment": assignment,
            "checkpoints": diagnostics,
            "validation": {
                "all_prerequisite_hashes_verified": True,
                "each_train_snapshot_scored_exactly_once": True,
                "same_group_one_fold": True,
                "same_flow_same_fold_all_checkpoints": True,
                "fit_rows_benign_only": True,
                "held_out_rows_excluded_from_all_model_fit": True,
                "preprocessing_fit_fold_local": True,
                "hbos_mask_fit_fold_local": True,
                "score_normalization_and_threshold_fit_fold_local": True,
                "metadata_columns_excluded_from_model_matrices": True,
                "validation_partition_excluded": True,
                "test_partition_excluded": True,
                "weighted_score_deferred_to_T4_5": True,
            },
            "gate": {"decision": "pending_user_decision", "t4_5_authorized": False},
        }
        write_json(acceptance_temp, receipt)
        os.replace(artifact_temp, artifact)
        os.replace(acceptance_temp, acceptance)
        return receipt
    finally:
        artifact_temp.unlink(missing_ok=True)
        acceptance_temp.unlink(missing_ok=True)
        gc.collect()
        if scratch.exists():
            try:
                shutil.rmtree(scratch)
            except OSError as error:
                print(f"warning: T4.4 scratch cleanup deferred: {error}", file=sys.stderr, flush=True)


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    contract, _, _, _ = verify_inputs(root, contract_path)
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T4.4 acceptance receipt")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("T4.4 contract hash mismatch")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.4 source hash mismatch: {value}")
    artifact_record = receipt.get("artifact", {})
    artifact = resolve_inside(root, artifact_record.get("path", ""))
    expected_rows = sum(
        contract["expected_population"][checkpoint]["rows"]
        for checkpoint in contract["input"]["checkpoints"]
    )
    parquet = pq.ParquetFile(artifact)
    if (
        not artifact.is_file()
        or artifact.stat().st_size != artifact_record.get("size_bytes")
        or sha256_path(artifact) != artifact_record.get("sha256")
        or parquet.metadata.num_rows != expected_rows
        or parquet.schema_arrow != oof_schema(contract, sha256_path(contract_path))
        or receipt.get("gate") != {"decision": "pending_user_decision", "t4_5_authorized": False}
    ):
        raise ValueError("T4.4 artifact validation failed")
    for checkpoint in contract["input"]["checkpoints"]:
        folds = receipt.get("checkpoints", {}).get(checkpoint, {}).get("folds", {})
        if set(folds) != set(map(str, range(5))):
            raise ValueError(f"T4.4 fold receipt incomplete: {checkpoint}")
        for fold, record in folds.items():
            expected = contract["expected_population"][checkpoint]["folds"][fold]
            if (
                record.get("held_rows") != expected["rows"]
                or record.get("held_benign") != expected["benign"]
                or record.get("held_attack") != expected["attack"]
                or record.get("preprocessing", {}).get("parity", {}).get("status") != "passed"
            ):
                raise ValueError(f"T4.4 fold receipt mismatch: {checkpoint}/{fold}")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Build leakage-safe T4.4 OOF anomaly meta-features")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path, default=root_default / "config/cicids2017-oof-contract.json"
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            verify_inputs(root, contract_path)
            print("[T4.4 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(
                f"[T4.4 OOF] status=passed rows={receipt['artifact']['rows']} folds=5",
                flush=True,
            )
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T4.4 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
