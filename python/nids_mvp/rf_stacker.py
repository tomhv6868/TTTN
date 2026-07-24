from __future__ import annotations

import argparse
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
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import sklearn
from sklearn.ensemble import RandomForestClassifier

from nids_mvp import preprocessing, rf_baseline


TASK = "T4.5"
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
        "joblib": joblib.__version__,
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
        raise RuntimeError(f"T4.5 runtime contract mismatch: {observed}")


def verify_reference(root: Path, reference: Mapping[str, Any], label: str) -> Path:
    path = resolve_inside(root, str(reference.get("path", "")))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{label} content address mismatch")
    return path


def verify_validation_identity(rf_path: Path, anomaly_path: Path, checkpoints: Sequence[str]) -> None:
    with np.load(rf_path, allow_pickle=False) as rf, np.load(anomaly_path, allow_pickle=False) as anomaly:
        for checkpoint in checkpoints:
            for field in ("capture_id", "flow_id", "y_true"):
                if not np.array_equal(rf[f"{checkpoint}__{field}"], anomaly[f"{checkpoint}__{field}"]):
                    raise ValueError(f"T4.2/T4.3 validation identity mismatch: {checkpoint}/{field}")


def verify_inputs(
    root: Path, contract_path: Path
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, list[str], dict[str, Any], dict[str, Path]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.5 contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    manual = load_json(paths["t4_4_manual_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("t4_5_authorized")
    ):
        raise ValueError("T4.4 manual acceptance does not authorize T4.5")
    t41 = load_json(paths["t4_1_technical_acceptance"])
    preprocessing_artifact = t41.get("artifact", {})
    expected_t41 = contract["prerequisites"]["t4_1_technical_acceptance"]
    if (
        t41.get("status") != "passed"
        or preprocessing_artifact.get("artifact_id") != expected_t41["artifact_id"]
        or preprocessing_artifact.get("artifact_version") != expected_t41["artifact_version"]
    ):
        raise ValueError("T4.1 preprocessing evidence mismatch")
    baseline_contract = load_json(paths["rf_baseline_contract"])
    if (
        baseline_contract.get("random_forest", {}).get("parameters")
        != contract["random_forest"]["parameters"]
        or baseline_contract.get("decision") != contract["decision"]
    ):
        raise ValueError("T4.2 comparison configuration drift")
    t42 = load_json(paths["t4_2_technical_acceptance"])
    t43 = load_json(paths["t4_3_technical_acceptance"])
    t44 = load_json(paths["t4_4_technical_acceptance"])
    if any(receipt.get("status") != "passed" for receipt in (t42, t43, t44)):
        raise ValueError("T4.2-T4.4 technical prerequisite is not passed")
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
    verified_parts: list[dict[str, Any]] = []
    for record in parts:
        path = resolve_inside(root, str(record.get("path", "")))
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
            or pq.ParquetFile(path).metadata.num_rows != record.get("rows")
        ):
            raise ValueError(f"snapshot part content mismatch: {record.get('path')}")
        verified_parts.append({**record, "resolved_path": path})
    flow_map = paths["known_flow_map"]
    if pq.ParquetFile(flow_map).metadata.num_rows != contract["prerequisites"]["known_flow_map"]["rows"]:
        raise ValueError("known flow-map row count mismatch")
    oof = pq.ParquetFile(paths["t4_4_oof_meta_features"])
    if oof.metadata.num_rows != contract["prerequisites"]["t4_4_oof_meta_features"]["rows"]:
        raise ValueError("T4.4 OOF row count mismatch")
    required_oof = {
        "checkpoint",
        "capture_id",
        "flow_id",
        "y_true",
        "hbos_normalized_score",
        "hbos_binary",
        "isolation_forest_normalized_score",
        "isolation_forest_binary",
        "anomaly_count",
    }
    if not required_oof.issubset(oof.schema_arrow.names):
        raise ValueError("T4.4 OOF schema mismatch")
    verify_validation_identity(
        paths["t4_2_validation_predictions"],
        paths["t4_3_validation_predictions"],
        contract["input"]["checkpoints"],
    )
    for checkpoint in contract["input"]["checkpoints"]:
        profile = (
            preprocessing_artifact.get("checkpoints", {})
            .get(checkpoint, {})
            .get("profiles", {})
            .get("supervised_known")
        )
        if (
            not isinstance(profile, dict)
            or len(profile.get("selected_features", []))
            != contract["original_features"]["expected_selected_feature_count"][checkpoint]
            or profile.get("dropped_constant_features")
            != contract["original_features"]["expected_dropped_features"][checkpoint]
            or profile.get("input_features") != features
            or profile.get("output_dtype") != contract["original_features"]["output_dtype"]
        ):
            raise ValueError(f"T4.1 supervised profile drift: {checkpoint}")
    return contract, verified_parts, flow_map, features, preprocessing_artifact, paths


def capture_from_path(value: str) -> str:
    if "capture_id=" not in value:
        raise ValueError(f"snapshot path lacks capture partition: {value}")
    return value.split("capture_id=", 1)[1].split("/", 1)[0]


def _open_matrix(path: Path, shape: tuple[int, ...], dtype: Any) -> np.memmap:
    return np.lib.format.open_memmap(path, mode="w+", dtype=dtype, shape=shape)


def materialize_original_checkpoint(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    input_features: Sequence[str],
    profile: Mapping[str, Any],
    contract: Mapping[str, Any],
    scratch: Path,
) -> dict[str, Path]:
    train_rows = int(contract["expected_population"]["train"][checkpoint]["rows"])
    validation_rows = int(contract["expected_population"]["validation"][checkpoint]["rows"])
    feature_count = int(contract["stacker_matrix"]["expected_feature_count"][checkpoint])
    original_count = len(profile["selected_features"])
    paths = {
        "x_train": scratch / f"{checkpoint}-x-train.npy",
        "y_train": scratch / f"{checkpoint}-y-train.npy",
        "train_capture_id": scratch / f"{checkpoint}-train-capture-id.npy",
        "train_flow_id": scratch / f"{checkpoint}-train-flow-id.npy",
        "x_validation": scratch / f"{checkpoint}-x-validation.npy",
        "y_validation": scratch / f"{checkpoint}-y-validation.npy",
        "validation_capture_id": scratch / f"{checkpoint}-validation-capture-id.npy",
        "validation_flow_id": scratch / f"{checkpoint}-validation-flow-id.npy",
    }
    arrays = {
        "x_train": _open_matrix(paths["x_train"], (train_rows, feature_count), np.float32),
        "y_train": _open_matrix(paths["y_train"], (train_rows,), np.uint8),
        "train_capture_id": _open_matrix(paths["train_capture_id"], (train_rows,), "<U64"),
        "train_flow_id": _open_matrix(paths["train_flow_id"], (train_rows,), np.uint64),
        "x_validation": _open_matrix(
            paths["x_validation"], (validation_rows, feature_count), np.float32
        ),
        "y_validation": _open_matrix(paths["y_validation"], (validation_rows,), np.uint8),
        "validation_capture_id": _open_matrix(
            paths["validation_capture_id"], (validation_rows,), "<U64"
        ),
        "validation_flow_id": _open_matrix(
            paths["validation_flow_id"], (validation_rows,), np.uint64
        ),
    }
    offsets = {"train": 0, "validation": 0}
    counts = {
        "train": {"benign": 0, "attack": 0},
        "validation": {"benign": 0, "attack": 0},
    }
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = capture_from_path(record["path"])
        mapping = rf_baseline.load_capture_map(flow_map, capture_id)
        parquet = pq.ParquetFile(record["resolved_path"])
        columns = ["flow_id", "capture_id", "assigned_class", *input_features]
        previous_flow_id: int | None = None
        for batch in parquet.iter_batches(columns=columns, batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            captures = batch.column(1).to_pylist()
            families = batch.column(2).to_pylist()
            if any(value != capture_id for value in captures):
                raise ValueError(f"capture metadata drift: {record['path']}")
            if flow_ids and previous_flow_id is not None and flow_ids[0] <= previous_flow_id:
                raise ValueError(f"snapshot flow order drift: {record['path']}")
            if any(left >= right for left, right in zip(flow_ids, flow_ids[1:])):
                raise ValueError(f"duplicate snapshot flow: {record['path']}")
            if flow_ids:
                previous_flow_id = flow_ids[-1]
            selected = {"train": [], "validation": []}
            for index, (flow_id, family) in enumerate(zip(flow_ids, families, strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] in selected:
                    selected[mapped[0]].append(index)
                elif mapped[0] != "test":
                    raise ValueError(f"unknown split partition: {mapped[0]}")
            if not selected["train"] and not selected["validation"]:
                continue
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(input_features))]
            ).astype(np.float64, copy=False)
            for partition, indices in selected.items():
                if not indices:
                    continue
                transformed = preprocessing.transform_with_artifact(raw[indices], input_features, profile)
                labels = np.fromiter(
                    (families[index] != "BENIGN" for index in indices),
                    dtype=np.uint8,
                    count=len(indices),
                )
                start = offsets[partition]
                stop = start + len(indices)
                if stop > arrays[f"x_{partition}"].shape[0]:
                    raise ValueError(f"{partition}/{checkpoint} exceeds expected rows")
                arrays[f"x_{partition}"][start:stop, :original_count] = transformed
                arrays[f"y_{partition}"][start:stop] = labels
                arrays[f"{partition}_capture_id"][start:stop] = capture_id
                arrays[f"{partition}_flow_id"][start:stop] = np.asarray(
                    [flow_ids[index] for index in indices], dtype=np.uint64
                )
                benign = int(np.count_nonzero(labels == 0))
                counts[partition]["benign"] += benign
                counts[partition]["attack"] += len(labels) - benign
                offsets[partition] = stop
    for array in arrays.values():
        array.flush()
    for partition in ("train", "validation"):
        observed = {
            "rows": offsets[partition],
            "benign": counts[partition]["benign"],
            "attack": counts[partition]["attack"],
        }
        if observed != contract["expected_population"][partition][checkpoint]:
            raise ValueError(f"{partition}/{checkpoint} population mismatch: {observed}")
    del arrays
    return paths


def build_meta_matrix(
    hbos_normalized: np.ndarray,
    isolation_forest_normalized: np.ndarray,
    hbos_binary: np.ndarray,
    isolation_forest_binary: np.ndarray,
    anomaly_count: np.ndarray | None = None,
) -> np.ndarray:
    hbos = np.asarray(hbos_normalized, dtype=np.float64)
    isolation = np.asarray(isolation_forest_normalized, dtype=np.float64)
    hbos_flag = np.asarray(hbos_binary, dtype=np.uint8)
    isolation_flag = np.asarray(isolation_forest_binary, dtype=np.uint8)
    lengths = {len(hbos), len(isolation), len(hbos_flag), len(isolation_flag)}
    if len(lengths) != 1 or not np.isfinite(hbos).all() or not np.isfinite(isolation).all():
        raise ValueError("invalid anomaly meta-feature arrays")
    if np.any(hbos_flag > 1) or np.any(isolation_flag > 1):
        raise ValueError("invalid anomaly binary feature")
    count = (hbos_flag + isolation_flag).astype(np.uint8)
    if anomaly_count is not None and not np.array_equal(count, np.asarray(anomaly_count, dtype=np.uint8)):
        raise ValueError("anomaly_count formula mismatch")
    weighted = 0.5 * hbos + 0.5 * isolation
    matrix = np.column_stack(
        (hbos, isolation, hbos_flag, isolation_flag, count, weighted)
    ).astype(np.float32)
    if matrix.dtype != np.float32 or not np.isfinite(matrix).all():
        raise ValueError("invalid stacker meta-feature matrix")
    return matrix


def keyed_reorder(
    source_capture: np.ndarray,
    source_flow: np.ndarray,
    source_y: np.ndarray,
    source_values: np.ndarray,
    target_capture: np.ndarray,
    target_flow: np.ndarray,
    target_y: np.ndarray,
) -> tuple[np.ndarray, dict[str, int]]:
    source_capture = np.asarray(source_capture)
    source_flow = np.asarray(source_flow, dtype=np.uint64)
    source_y = np.asarray(source_y, dtype=np.uint8)
    source_values = np.asarray(source_values)
    target_capture = np.asarray(target_capture)
    target_flow = np.asarray(target_flow, dtype=np.uint64)
    target_y = np.asarray(target_y, dtype=np.uint8)
    if not (
        len(source_capture) == len(source_flow) == len(source_y) == len(source_values)
        and len(target_capture) == len(target_flow) == len(target_y)
    ):
        raise ValueError("keyed join input length mismatch")
    if len(source_capture) != len(target_capture):
        raise ValueError("keyed join cardinality mismatch")
    source_captures = set(source_capture.tolist())
    target_captures = set(target_capture.tolist())
    if source_captures != target_captures:
        raise ValueError("keyed join capture mismatch")
    result = np.empty((len(target_capture), source_values.shape[1]), dtype=source_values.dtype)
    matched = 0
    for capture_id in sorted(source_captures):
        source_indices = np.flatnonzero(source_capture == capture_id)
        target_indices = np.flatnonzero(target_capture == capture_id)
        source_order = np.argsort(source_flow[source_indices], kind="stable")
        target_order = np.argsort(target_flow[target_indices], kind="stable")
        source_sorted = source_indices[source_order]
        target_sorted = target_indices[target_order]
        if (
            len(source_sorted) != len(target_sorted)
            or len(np.unique(source_flow[source_sorted])) != len(source_sorted)
            or len(np.unique(target_flow[target_sorted])) != len(target_sorted)
        ):
            raise ValueError(f"keyed join duplicate or cardinality mismatch: {capture_id}")
        if not np.array_equal(source_flow[source_sorted], target_flow[target_sorted]):
            raise ValueError(f"keyed join unmatched flow: {capture_id}")
        if not np.array_equal(source_y[source_sorted], target_y[target_sorted]):
            raise ValueError(f"keyed join label mismatch: {capture_id}")
        result[target_sorted] = source_values[source_sorted]
        matched += len(source_sorted)
    return result, {
        "source_rows": len(source_capture),
        "target_rows": len(target_capture),
        "matched_rows": matched,
        "duplicate_keys": 0,
        "unmatched_source_keys": 0,
        "unmatched_target_keys": 0,
        "label_mismatches": 0,
    }


def load_oof_checkpoint(path: Path, checkpoint: str) -> dict[str, np.ndarray]:
    columns = [
        "capture_id",
        "flow_id",
        "y_true",
        "hbos_normalized_score",
        "isolation_forest_normalized_score",
        "hbos_binary",
        "isolation_forest_binary",
        "anomaly_count",
    ]
    data = pq.read_table(
        path,
        columns=columns,
        filters=[("checkpoint", "=", checkpoint)],
        partitioning=None,
    ).to_pydict()
    return {
        "capture_id": np.asarray(data["capture_id"], dtype="<U64"),
        "flow_id": np.asarray(data["flow_id"], dtype=np.uint64),
        "y_true": np.asarray(data["y_true"], dtype=np.uint8),
        "meta": build_meta_matrix(
            data["hbos_normalized_score"],
            data["isolation_forest_normalized_score"],
            data["hbos_binary"],
            data["isolation_forest_binary"],
            data["anomaly_count"],
        ),
    }


def load_validation_meta(predictions: Mapping[str, np.ndarray], checkpoint: str) -> dict[str, np.ndarray]:
    hbos = predictions[f"{checkpoint}__hbos__normalized_score"]
    isolation = predictions[f"{checkpoint}__isolation_forest__normalized_score"]
    hbos_flag = predictions[f"{checkpoint}__hbos__y_pred"]
    isolation_flag = predictions[f"{checkpoint}__isolation_forest__y_pred"]
    return {
        "capture_id": predictions[f"{checkpoint}__capture_id"],
        "flow_id": predictions[f"{checkpoint}__flow_id"],
        "y_true": predictions[f"{checkpoint}__y_true"],
        "meta": build_meta_matrix(hbos, isolation, hbos_flag, isolation_flag),
    }


def append_joined_meta(
    matrix: np.memmap,
    original_count: int,
    target_capture: np.ndarray,
    target_flow: np.ndarray,
    target_y: np.ndarray,
    source: Mapping[str, np.ndarray],
) -> dict[str, int]:
    reordered, audit = keyed_reorder(
        source["capture_id"],
        source["flow_id"],
        source["y_true"],
        source["meta"],
        target_capture,
        target_flow,
        target_y,
    )
    matrix[:, original_count:] = reordered
    matrix.flush()
    if matrix.dtype != np.float32 or not np.isfinite(matrix).all():
        raise ValueError("stacker matrix dtype or finite-value mismatch")
    return audit


def named_feature_importance(
    model: RandomForestClassifier, feature_names: Sequence[str], meta_names: Sequence[str]
) -> dict[str, Any]:
    importance = np.asarray(model.feature_importances_, dtype=np.float64)
    if len(importance) != len(feature_names) or not np.isclose(importance.sum(), 1.0):
        raise ValueError("Random Forest feature importance accounting mismatch")
    named = [
        {"feature": feature, "importance": float(value)}
        for feature, value in zip(feature_names, importance, strict=True)
    ]
    meta_set = set(meta_names)
    return {
        "sum": float(importance.sum()),
        "all": named,
        "meta_ranked": sorted(
            (record for record in named if record["feature"] in meta_set),
            key=lambda record: (-record["importance"], record["feature"]),
        ),
    }


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, parts, flow_map, features, preprocessing_artifact, inputs = verify_inputs(
        root, contract_path
    )
    outputs = {
        name: resolve_inside(root, contract["artifacts"][name]["path"])
        for name in ("model_bundle", "validation_predictions", "acceptance")
    }
    if any(path.exists() for path in outputs.values()):
        raise FileExistsError("T4.5 artifact already exists; refusing to overwrite evidence")
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    model_temp = temporary_sibling(outputs["model_bundle"])
    prediction_temp = temporary_sibling(outputs["validation_predictions"])
    acceptance_temp = temporary_sibling(outputs["acceptance"])
    scratch = root / "run_log" / f".nids-t45-{uuid.uuid4().hex}"
    scratch.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    models: dict[str, Any] = {}
    predictions: dict[str, np.ndarray] = {}
    model_receipts: dict[str, Any] = {}
    validation_paths: dict[str, Path] = {}
    contract_hash = sha256_path(contract_path)
    try:
        baseline_acceptance = load_json(inputs["t4_2_technical_acceptance"])
        with np.load(inputs["t4_3_validation_predictions"], allow_pickle=False) as anomaly_validation:
            for checkpoint in contract["input"]["checkpoints"]:
                checkpoint_started = time.monotonic()
                print(f"[T4.5] checkpoint={checkpoint} stage=materialize_original", flush=True)
                profile = preprocessing_artifact["checkpoints"][checkpoint]["profiles"]["supervised_known"]
                paths = materialize_original_checkpoint(
                    checkpoint, parts, flow_map, features, profile, contract, scratch
                )
                x_train = np.load(paths["x_train"], mmap_mode="r+")
                y_train = np.load(paths["y_train"], mmap_mode="r")
                train_capture = np.load(paths["train_capture_id"], mmap_mode="r")
                train_flow = np.load(paths["train_flow_id"], mmap_mode="r")
                print(f"[T4.5] checkpoint={checkpoint} stage=join_oof_train", flush=True)
                oof = load_oof_checkpoint(inputs["t4_4_oof_meta_features"], checkpoint)
                train_join = append_joined_meta(
                    x_train,
                    len(profile["selected_features"]),
                    train_capture,
                    train_flow,
                    y_train,
                    oof,
                )
                del oof, train_capture, train_flow
                x_validation = np.load(paths["x_validation"], mmap_mode="r+")
                y_validation = np.load(paths["y_validation"], mmap_mode="r")
                validation_capture = np.load(paths["validation_capture_id"], mmap_mode="r")
                validation_flow = np.load(paths["validation_flow_id"], mmap_mode="r")
                validation_meta = load_validation_meta(anomaly_validation, checkpoint)
                validation_join = append_joined_meta(
                    x_validation,
                    len(profile["selected_features"]),
                    validation_capture,
                    validation_flow,
                    y_validation,
                    validation_meta,
                )
                del validation_meta
                stacker_features = [*profile["selected_features"], *contract["meta_features"]["order"]]
                if len(stacker_features) != contract["stacker_matrix"]["expected_feature_count"][checkpoint]:
                    raise ValueError(f"stacker feature count mismatch: {checkpoint}")
                print(f"[T4.5] checkpoint={checkpoint} stage=train trees=300", flush=True)
                model, probability, prediction = rf_baseline.fit_random_forest(
                    x_train,
                    y_train,
                    rf_baseline.load_validation_matrix(paths["x_validation"]),
                    contract["random_forest"]["parameters"],
                    float(contract["decision"]["threshold"]),
                )
                metrics = rf_baseline.compute_metrics(y_validation, prediction)
                baseline_metrics = baseline_acceptance["models"][checkpoint]["metrics"]
                metric_delta = {
                    name: float(metrics[name] - baseline_metrics[name])
                    for name in ("precision", "recall", "f1", "macro_f1", "mcc", "fpr")
                }
                importance = named_feature_importance(
                    model, stacker_features, contract["meta_features"]["order"]
                )
                models[checkpoint] = {
                    "model": model,
                    "preprocessing_profile": profile,
                    "original_features": profile["selected_features"],
                    "meta_features": contract["meta_features"]["order"],
                    "stacker_features": stacker_features,
                }
                predictions[f"{checkpoint}__capture_id"] = np.array(validation_capture, copy=True)
                predictions[f"{checkpoint}__flow_id"] = np.array(validation_flow, copy=True)
                predictions[f"{checkpoint}__y_true"] = np.array(y_validation, copy=True)
                predictions[f"{checkpoint}__attack_probability"] = np.array(probability, copy=True)
                predictions[f"{checkpoint}__y_pred"] = np.array(prediction, copy=True)
                model_receipts[checkpoint] = {
                    "fit_rows": int(len(y_train)),
                    "validation_rows": int(len(y_validation)),
                    "original_feature_count": len(profile["selected_features"]),
                    "meta_feature_count": len(contract["meta_features"]["order"]),
                    "stacker_feature_count": len(stacker_features),
                    "train_join": train_join,
                    "validation_join": validation_join,
                    "metrics": metrics,
                    "t4_2_baseline_metrics": baseline_metrics,
                    "stacker_minus_t4_2_delta": metric_delta,
                    "improvement_claim": "deferred_to_T4.8",
                    "feature_importance": importance,
                }
                validation_paths[checkpoint] = paths["x_validation"]
                del (
                    x_train,
                    y_train,
                    x_validation,
                    y_validation,
                    validation_capture,
                    validation_flow,
                    model,
                    probability,
                    prediction,
                )
                for name in (
                    "x_train",
                    "y_train",
                    "train_capture_id",
                    "train_flow_id",
                    "y_validation",
                    "validation_capture_id",
                    "validation_flow_id",
                ):
                    paths[name].unlink()
                gc.collect()
                print(
                    f"[T4.5] checkpoint={checkpoint} stage=trained "
                    f"elapsed_seconds={time.monotonic() - checkpoint_started:.1f}",
                    flush=True,
                )
        t43_artifacts = load_json(inputs["t4_3_technical_acceptance"])["artifacts"]
        model_bundle = {
            "schema_version": "1.0.0",
            "task": TASK,
            "artifact_id": contract["artifacts"]["model_bundle"]["id"],
            "artifact_version": contract["artifacts"]["model_bundle"]["version"],
            "preprocessing_acceptance_sha256": contract["prerequisites"]["t4_1_technical_acceptance"]["sha256"],
            "oof_meta_features_sha256": contract["prerequisites"]["t4_4_oof_meta_features"]["sha256"],
            "t4_3_anomaly_model_reference": t43_artifacts["model_bundle"],
            "labels": contract["labels"],
            "threshold": contract["decision"]["threshold"],
            "random_forest_parameters": contract["random_forest"]["parameters"],
            "meta_feature_contract": contract["meta_features"],
            "checkpoints": models,
        }
        joblib.dump(model_bundle, model_temp, compress=3)
        del model_bundle, models
        gc.collect()
        reloaded = joblib.load(model_temp)
        for checkpoint in contract["input"]["checkpoints"]:
            matrix = rf_baseline.load_validation_matrix(validation_paths[checkpoint])
            observed = rf_baseline.predict_attack_probability(
                reloaded["checkpoints"][checkpoint]["model"], matrix
            )
            expected = predictions[f"{checkpoint}__attack_probability"]
            if not np.array_equal(observed, expected):
                raise ValueError(f"model reload probability parity mismatch: {checkpoint}")
            model_receipts[checkpoint]["reload_parity"] = {
                "status": "passed",
                "comparison": "bitwise_equal_float64",
                "rows": len(expected),
                "probability_sha256": hashlib.sha256(expected.tobytes(order="C")).hexdigest(),
            }
            del matrix, observed
            validation_paths[checkpoint].unlink()
        del reloaded
        gc.collect()
        with prediction_temp.open("wb") as output:
            np.savez_compressed(output, **predictions)
            output.flush()
            os.fsync(output.fileno())
        source_paths = [
            root / "python/nids_mvp/rf_stacker.py",
            root / "tests/test_t45_rf_stacker.py",
            root / "python/nids_mvp/preprocessing.py",
            root / "python/nids_mvp/rf_baseline.py",
        ]
        receipt = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "rf_stacker_acceptance_bundle",
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
            "artifacts": {
                "model_bundle": {
                    "path": relative(outputs["model_bundle"], root),
                    "size_bytes": model_temp.stat().st_size,
                    "sha256": sha256_path(model_temp),
                },
                "validation_predictions": {
                    "path": relative(outputs["validation_predictions"], root),
                    "size_bytes": prediction_temp.stat().st_size,
                    "sha256": sha256_path(prediction_temp),
                },
            },
            "models": model_receipts,
            "validation": {
                "all_prerequisite_hashes_verified": True,
                "fit_population_exact": True,
                "validation_population_exact": True,
                "test_partition_excluded_from_transform_fit_score_and_outputs": True,
                "key_join_cardinality_exact": True,
                "duplicate_or_unmatched_key_count_zero": True,
                "train_meta_features_oof_only": True,
                "validation_meta_features_t4_3_only": True,
                "rf_baseline_probability_excluded": True,
                "feature_order_and_dtype_exact": True,
                "metadata_columns_excluded_from_model_matrix": True,
                "preprocessing_reused_without_refit": True,
                "four_independent_models": True,
                "model_reload_probability_parity": True,
                "prediction_bundle_metric_recomputation": True,
                "feature_importance_accounting": True,
                "improvement_claim_deferred_to_t4_8": True,
            },
            "gate": {"decision": "pending_user_decision", "t4_6_authorized": False},
        }
        write_json(acceptance_temp, receipt)
        os.replace(model_temp, outputs["model_bundle"])
        os.replace(prediction_temp, outputs["validation_predictions"])
        os.replace(acceptance_temp, outputs["acceptance"])
        return receipt
    finally:
        model_temp.unlink(missing_ok=True)
        prediction_temp.unlink(missing_ok=True)
        acceptance_temp.unlink(missing_ok=True)
        gc.collect()
        if scratch.exists():
            try:
                shutil.rmtree(scratch)
            except OSError as error:
                print(f"warning: T4.5 scratch cleanup deferred: {error}", file=sys.stderr, flush=True)


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    contract, _, _, _, _, inputs = verify_inputs(root, contract_path)
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T4.5 acceptance receipt")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("T4.5 contract hash mismatch")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.5 source hash mismatch: {value}")
    artifact_paths: dict[str, Path] = {}
    for name in ("model_bundle", "validation_predictions"):
        record = receipt.get("artifacts", {}).get(name, {})
        path = resolve_inside(root, str(record.get("path", "")))
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
            or relative(path, root) != contract["artifacts"][name]["path"]
        ):
            raise ValueError(f"T4.5 {name} content mismatch")
        artifact_paths[name] = path
    bundle = joblib.load(artifact_paths["model_bundle"])
    if (
        bundle.get("task") != TASK
        or bundle.get("artifact_id") != contract["artifacts"]["model_bundle"]["id"]
        or bundle.get("artifact_version") != contract["artifacts"]["model_bundle"]["version"]
        or bundle.get("random_forest_parameters") != contract["random_forest"]["parameters"]
        or bundle.get("meta_feature_contract") != contract["meta_features"]
        or list(bundle.get("checkpoints", {})) != contract["input"]["checkpoints"]
    ):
        raise ValueError("T4.5 model bundle contract mismatch")
    with np.load(artifact_paths["validation_predictions"], allow_pickle=False) as predictions, np.load(
        inputs["t4_3_validation_predictions"], allow_pickle=False
    ) as anomaly:
        for checkpoint in contract["input"]["checkpoints"]:
            capture = predictions[f"{checkpoint}__capture_id"]
            flow_id = predictions[f"{checkpoint}__flow_id"]
            y_true = predictions[f"{checkpoint}__y_true"]
            probability = predictions[f"{checkpoint}__attack_probability"]
            y_pred = predictions[f"{checkpoint}__y_pred"]
            if (
                capture.dtype.kind != "U"
                or flow_id.dtype != np.uint64
                or y_true.dtype != np.uint8
                or probability.dtype != np.float64
                or y_pred.dtype != np.uint8
                or not np.array_equal(capture, anomaly[f"{checkpoint}__capture_id"])
                or not np.array_equal(flow_id, anomaly[f"{checkpoint}__flow_id"])
                or not np.array_equal(y_true, anomaly[f"{checkpoint}__y_true"])
                or not np.array_equal(
                    y_pred, (probability >= contract["decision"]["threshold"]).astype(np.uint8)
                )
                or not np.isfinite(probability).all()
            ):
                raise ValueError(f"T4.5 validation prediction mismatch: {checkpoint}")
            if rf_baseline.compute_metrics(y_true, y_pred) != receipt["models"][checkpoint]["metrics"]:
                raise ValueError(f"T4.5 metric recomputation mismatch: {checkpoint}")
            model_record = bundle["checkpoints"][checkpoint]
            model = model_record.get("model")
            if (
                not isinstance(model, RandomForestClassifier)
                or model.classes_.tolist() != contract["labels"]["class_order"]
                or model_record.get("meta_features") != contract["meta_features"]["order"]
                or len(model_record.get("stacker_features", []))
                != contract["stacker_matrix"]["expected_feature_count"][checkpoint]
                or receipt["models"][checkpoint].get("reload_parity", {}).get("status") != "passed"
                or not np.isclose(receipt["models"][checkpoint]["feature_importance"]["sum"], 1.0)
            ):
                raise ValueError(f"T4.5 model validation failed: {checkpoint}")
    if receipt.get("gate") != {"decision": "pending_user_decision", "t4_6_authorized": False}:
        raise ValueError("T4.5 gate mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Train and validate T4.5 Random Forest stackers")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path, default=root_default / "config/cicids2017-rf-stacker-contract.json"
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            verify_inputs(root, contract_path)
            print("[T4.5 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(
                f"[T4.5 stacker] status=passed checkpoints={len(receipt['models'])} "
                f"elapsed_seconds={receipt['elapsed_seconds']:.1f}",
                flush=True,
            )
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T4.5 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
