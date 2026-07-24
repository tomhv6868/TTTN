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


TASK = "T4.6"
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
        raise RuntimeError(f"T4.6 runtime contract mismatch: {observed}")


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
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, list[str], dict[str, Any], dict[str, Path]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.6 contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    manual = load_json(paths["t4_5_manual_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("t4_6_authorized")
    ):
        raise ValueError("T4.5 manual acceptance does not authorize T4.6")
    if load_json(paths["t4_5_technical_acceptance"]).get("status") != "passed":
        raise ValueError("T4.5 technical prerequisite is not passed")
    baseline_contract = load_json(paths["rf_baseline_contract"])
    if baseline_contract.get("random_forest", {}).get("parameters") != contract["random_forest"]["parameters"]:
        raise ValueError("T4.2 Random Forest configuration drift")
    rare = load_json(paths["rare_family_audit"])
    if rare.get("status") != "passed":
        raise ValueError("T3.7 rare-family audit is not passed")
    available = [record for record in rare.get("families", []) if record.get("status") != "unavailable"]
    macro = [record["family"] for record in available if record.get("status") == "macro_eligible"]
    case_study = [record["family"] for record in available if record.get("status") == "case_study_only"]
    unavailable = [record["family"] for record in rare.get("families", []) if record.get("status") == "unavailable"]
    if (
        [record["family"] for record in available] != contract["labels"]["class_order"]
        or macro != contract["labels"]["macro_family_order"]
        or case_study != contract["labels"]["case_study_family_order"]
        or unavailable != contract["labels"]["unavailable"]
    ):
        raise ValueError("T3.7 family scope drift")
    for record in available:
        family = record["family"]
        counts = record.get("known_partition_counts", {})
        for checkpoint in contract["input"]["checkpoints"]:
            for partition in ("train", "validation"):
                observed = counts.get(partition, {}).get(checkpoint, 0)
                expected = contract["expected_population"][f"{partition}_by_family"][family][checkpoint]
                if observed != expected:
                    raise ValueError(f"T3.7 family population drift: {family}/{partition}/{checkpoint}")
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
    t41 = load_json(paths["t4_1_technical_acceptance"])
    artifact = t41.get("artifact", {})
    t41_reference = contract["prerequisites"]["t4_1_technical_acceptance"]
    if (
        t41.get("status") != "passed"
        or artifact.get("artifact_id") != t41_reference["artifact_id"]
        or artifact.get("artifact_version") != t41_reference["artifact_version"]
    ):
        raise ValueError("T4.1 preprocessing evidence mismatch")
    for checkpoint in contract["input"]["checkpoints"]:
        profile = artifact.get("checkpoints", {}).get(checkpoint, {}).get("profiles", {}).get("supervised_known")
        if (
            not isinstance(profile, dict)
            or len(profile.get("selected_features", [])) != contract["features"]["expected_selected_feature_count"][checkpoint]
            or profile.get("dropped_constant_features") != contract["features"]["expected_dropped_features"][checkpoint]
            or profile.get("input_features") != features
            or profile.get("output_dtype") != contract["features"]["matrix_dtype"]
        ):
            raise ValueError(f"T4.1 supervised profile drift: {checkpoint}")
    return contract, verified_parts, flow_map, features, artifact, paths


def capture_from_path(value: str) -> str:
    if "capture_id=" not in value:
        raise ValueError(f"snapshot path lacks capture partition: {value}")
    return value.split("capture_id=", 1)[1].split("/", 1)[0]


def _open_matrix(path: Path, shape: tuple[int, ...], dtype: Any) -> np.memmap:
    return np.lib.format.open_memmap(path, mode="w+", dtype=dtype, shape=shape)


def materialize_checkpoint(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    input_features: Sequence[str],
    profile: Mapping[str, Any],
    contract: Mapping[str, Any],
    scratch: Path,
) -> dict[str, Path]:
    train_rows = int(contract["expected_population"]["train"][checkpoint])
    validation_rows = int(contract["expected_population"]["validation"][checkpoint])
    feature_count = len(profile["selected_features"])
    class_order = contract["labels"]["class_order"]
    label_index = {family: index for index, family in enumerate(class_order)}
    paths = {
        "x_train": scratch / f"{checkpoint}-x-train.npy",
        "y_train": scratch / f"{checkpoint}-y-train.npy",
        "x_validation": scratch / f"{checkpoint}-x-validation.npy",
        "y_validation": scratch / f"{checkpoint}-y-validation.npy",
        "validation_capture_id": scratch / f"{checkpoint}-validation-capture-id.npy",
        "validation_flow_id": scratch / f"{checkpoint}-validation-flow-id.npy",
    }
    arrays = {
        "x_train": _open_matrix(paths["x_train"], (train_rows, feature_count), np.float32),
        "y_train": _open_matrix(paths["y_train"], (train_rows,), np.uint8),
        "x_validation": _open_matrix(paths["x_validation"], (validation_rows, feature_count), np.float32),
        "y_validation": _open_matrix(paths["y_validation"], (validation_rows,), np.uint8),
        "validation_capture_id": _open_matrix(paths["validation_capture_id"], (validation_rows,), "<U64"),
        "validation_flow_id": _open_matrix(paths["validation_flow_id"], (validation_rows,), np.uint64),
    }
    offsets = {"train": 0, "validation": 0}
    counts = {
        partition: {family: 0 for family in class_order}
        for partition in ("train", "validation")
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
                partition = mapped[0]
                if partition not in ("train", "validation", "test"):
                    raise ValueError(f"unknown split partition: {partition}")
                if partition in selected and family != "BENIGN":
                    if family not in label_index:
                        raise ValueError(f"attack family outside T4.6 class order: {family}")
                    selected[partition].append(index)
            if not selected["train"] and not selected["validation"]:
                continue
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(input_features))]
            ).astype(np.float64, copy=False)
            for partition, indices in selected.items():
                if not indices:
                    continue
                transformed = preprocessing.transform_with_artifact(raw[indices], input_features, profile)
                labels = np.asarray([label_index[families[index]] for index in indices], dtype=np.uint8)
                start = offsets[partition]
                stop = start + len(indices)
                if stop > arrays[f"x_{partition}"].shape[0]:
                    raise ValueError(f"{partition}/{checkpoint} exceeds expected rows")
                arrays[f"x_{partition}"][start:stop] = transformed
                arrays[f"y_{partition}"][start:stop] = labels
                if partition == "validation":
                    arrays["validation_capture_id"][start:stop] = capture_id
                    arrays["validation_flow_id"][start:stop] = np.asarray(
                        [flow_ids[index] for index in indices], dtype=np.uint64
                    )
                for index in indices:
                    counts[partition][families[index]] += 1
                offsets[partition] = stop
    for array in arrays.values():
        array.flush()
    for partition in ("train", "validation"):
        if offsets[partition] != contract["expected_population"][partition][checkpoint]:
            raise ValueError(f"{partition}/{checkpoint} population mismatch: {offsets[partition]}")
        expected_counts = {
            family: contract["expected_population"][f"{partition}_by_family"][family][checkpoint]
            for family in class_order
        }
        if counts[partition] != expected_counts:
            raise ValueError(f"{partition}/{checkpoint} family population mismatch")
    del arrays
    return paths


def validate_probability_matrix(probability: np.ndarray, rows: int, classes: int, tolerance: float) -> None:
    if (
        probability.dtype != np.float64
        or probability.shape != (rows, classes)
        or not np.isfinite(probability).all()
        or np.any((probability < 0.0) | (probability > 1.0))
        or not np.allclose(probability.sum(axis=1), 1.0, rtol=0.0, atol=tolerance)
    ):
        raise ValueError("invalid multiclass probability matrix")


def predict_probabilities(
    model: RandomForestClassifier, matrix: np.ndarray, class_order: Sequence[str], tolerance: float
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    expected_classes = list(range(len(class_order)))
    if model.classes_.tolist() != expected_classes:
        raise ValueError(f"unexpected Random Forest classes: {model.classes_.tolist()}")
    original_n_jobs = model.n_jobs
    try:
        model.set_params(n_jobs=1)
        probability = model.predict_proba(matrix).astype(np.float64, copy=False)
    finally:
        model.set_params(n_jobs=original_n_jobs)
    validate_probability_matrix(probability, len(matrix), len(class_order), tolerance)
    top_index = np.argmax(probability, axis=1).astype(np.uint8)
    labels = np.asarray(class_order, dtype="<U64")
    top_class = labels[top_index]
    confidence = probability[np.arange(len(probability)), top_index].astype(np.float64, copy=False)
    return probability, top_index, top_class, confidence


def fit_random_forest(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_validation: np.ndarray,
    parameters: Mapping[str, Any],
    class_order: Sequence[str],
    tolerance: float,
) -> tuple[RandomForestClassifier, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    model = RandomForestClassifier(**dict(parameters))
    model.fit(x_train, y_train)
    probability, top_index, top_class, confidence = predict_probabilities(
        model, x_validation, class_order, tolerance
    )
    return model, probability, top_index, top_class, confidence


def compute_metrics(
    y_true: np.ndarray,
    probability: np.ndarray,
    class_order: Sequence[str],
    macro_family_order: Sequence[str],
) -> dict[str, Any]:
    y_true = np.asarray(y_true, dtype=np.uint8)
    probability = np.asarray(probability, dtype=np.float64)
    validate_probability_matrix(probability, len(y_true), len(class_order), 1e-12)
    y_pred = np.argmax(probability, axis=1).astype(np.uint8)
    matrix = np.zeros((len(class_order), len(class_order)), dtype=np.int64)
    np.add.at(matrix, (y_true, y_pred), 1)
    records: dict[str, Any] = {}
    for index, family in enumerate(class_order):
        tp = int(matrix[index, index])
        support = int(matrix[index].sum())
        predicted = int(matrix[:, index].sum())
        fp = predicted - tp
        fn = support - tp
        precision = None if predicted == 0 else float(tp / predicted)
        recall = None if support == 0 else float(tp / support)
        if support == 0:
            f1 = None
        elif tp == 0:
            f1 = 0.0
        else:
            f1 = float(2 * tp / (2 * tp + fp + fn))
        records[family] = {
            "support": support,
            "predicted_count": predicted,
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    macro_values = [records[family]["f1"] for family in macro_family_order]
    if any(value is None for value in macro_values):
        raise ValueError("macro family lacks validation support")
    supported = [record for record in records.values() if record["support"] > 0]
    weighted_f1 = sum(record["support"] * record["f1"] for record in supported) / len(y_true)
    balanced_accuracy = sum(record["recall"] for record in supported) / len(supported)
    top_two = np.argpartition(probability, -2, axis=1)[:, -2:]
    top_two_accuracy = float(np.mean(np.any(top_two == y_true[:, None], axis=1)))
    chosen = probability[np.arange(len(y_true)), y_true]
    log_loss = float(-np.mean(np.log(np.clip(chosen, np.finfo(np.float64).eps, 1.0))))
    return {
        "macro_family_f1": float(sum(macro_values) / len(macro_values)),
        "weighted_f1_all_supported_families": float(weighted_f1),
        "balanced_accuracy_supported_families": float(balanced_accuracy),
        "top_2_accuracy": top_two_accuracy,
        "multiclass_log_loss": log_loss,
        "per_class_metrics": records,
        "confusion_matrix": matrix.tolist(),
    }


def named_feature_importance(model: RandomForestClassifier, feature_names: Sequence[str]) -> dict[str, Any]:
    importance = np.asarray(model.feature_importances_, dtype=np.float64)
    if len(importance) != len(feature_names) or not np.isclose(importance.sum(), 1.0):
        raise ValueError("Random Forest feature importance accounting mismatch")
    return {
        "sum": float(importance.sum()),
        "ranked": sorted(
            (
                {"feature": feature, "importance": float(value)}
                for feature, value in zip(feature_names, importance, strict=True)
            ),
            key=lambda record: (-record["importance"], record["feature"]),
        ),
    }


def expected_validation_identity(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    class_order: Sequence[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    capture_values: list[str] = []
    flow_values: list[int] = []
    family_values: list[str] = []
    allowed = set(class_order)
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = capture_from_path(record["path"])
        mapping = rf_baseline.load_capture_map(flow_map, capture_id)
        parquet = pq.ParquetFile(record["resolved_path"])
        for batch in parquet.iter_batches(columns=["flow_id", "assigned_class"], batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            families = batch.column(1).to_pylist()
            for flow_id, family in zip(flow_ids, families, strict=True):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] == "validation" and family != "BENIGN":
                    if family not in allowed:
                        raise ValueError(f"validation family outside T4.6 class order: {family}")
                    capture_values.append(capture_id)
                    flow_values.append(flow_id)
                    family_values.append(family)
    return (
        np.asarray(capture_values, dtype="<U64"),
        np.asarray(flow_values, dtype=np.uint64),
        np.asarray(family_values, dtype="<U64"),
    )


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, parts, flow_map, features, preprocessing_artifact, _ = verify_inputs(root, contract_path)
    outputs = {
        name: resolve_inside(root, contract["artifacts"][name]["path"])
        for name in ("model_bundle", "validation_predictions", "acceptance")
    }
    if any(path.exists() for path in outputs.values()):
        raise FileExistsError("T4.6 artifact already exists; refusing to overwrite evidence")
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    model_temp = temporary_sibling(outputs["model_bundle"])
    prediction_temp = temporary_sibling(outputs["validation_predictions"])
    acceptance_temp = temporary_sibling(outputs["acceptance"])
    scratch = root / "run_log" / f".nids-t46-{uuid.uuid4().hex}"
    scratch.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    models: dict[str, Any] = {}
    predictions: dict[str, np.ndarray] = {}
    model_receipts: dict[str, Any] = {}
    validation_paths: dict[str, Path] = {}
    contract_hash = sha256_path(contract_path)
    class_order = contract["labels"]["class_order"]
    tolerance = float(contract["confidence"]["probability_sum_absolute_tolerance"])
    try:
        for checkpoint in contract["input"]["checkpoints"]:
            checkpoint_started = time.monotonic()
            print(f"[T4.6] checkpoint={checkpoint} stage=materialize_attack_only", flush=True)
            profile = preprocessing_artifact["checkpoints"][checkpoint]["profiles"]["supervised_known"]
            paths = materialize_checkpoint(
                checkpoint, parts, flow_map, features, profile, contract, scratch
            )
            x_train = np.load(paths["x_train"], mmap_mode="r")
            y_train = np.load(paths["y_train"], mmap_mode="r")
            x_validation = rf_baseline.load_validation_matrix(paths["x_validation"])
            y_validation = np.load(paths["y_validation"], mmap_mode="r")
            validation_capture = np.load(paths["validation_capture_id"], mmap_mode="r")
            validation_flow = np.load(paths["validation_flow_id"], mmap_mode="r")
            print(f"[T4.6] checkpoint={checkpoint} stage=train trees=300 classes=13", flush=True)
            model, probability, top_index, top_class, confidence = fit_random_forest(
                x_train,
                y_train,
                x_validation,
                contract["random_forest"]["parameters"],
                class_order,
                tolerance,
            )
            metrics = compute_metrics(
                y_validation, probability, class_order, contract["labels"]["macro_family_order"]
            )
            y_true_family = np.asarray(class_order, dtype="<U64")[np.asarray(y_validation)]
            models[checkpoint] = {
                "model": model,
                "preprocessing_profile": profile,
                "features": profile["selected_features"],
                "class_order": class_order,
                "confidence_contract": contract["confidence"],
            }
            predictions[f"{checkpoint}__capture_id"] = np.array(validation_capture, copy=True)
            predictions[f"{checkpoint}__flow_id"] = np.array(validation_flow, copy=True)
            predictions[f"{checkpoint}__y_true"] = y_true_family
            predictions[f"{checkpoint}__class_probability"] = np.array(probability, copy=True)
            predictions[f"{checkpoint}__top_class_index"] = np.array(top_index, copy=True)
            predictions[f"{checkpoint}__top_class"] = np.array(top_class, copy=True)
            predictions[f"{checkpoint}__confidence"] = np.array(confidence, copy=True)
            model_receipts[checkpoint] = {
                "fit_rows": int(len(y_train)),
                "validation_rows": int(len(y_validation)),
                "class_count": len(class_order),
                "feature_count": len(profile["selected_features"]),
                "metrics": metrics,
                "feature_importance": named_feature_importance(model, profile["selected_features"]),
                "confidence_interpretation": "uncalibrated_random_forest_vote_probability",
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
                top_index,
                top_class,
                confidence,
            )
            for name in (
                "x_train",
                "y_train",
                "y_validation",
                "validation_capture_id",
                "validation_flow_id",
            ):
                paths[name].unlink()
            gc.collect()
            print(
                f"[T4.6] checkpoint={checkpoint} stage=trained "
                f"elapsed_seconds={time.monotonic() - checkpoint_started:.1f}",
                flush=True,
            )
        model_bundle = {
            "schema_version": "1.0.0",
            "task": TASK,
            "artifact_id": contract["artifacts"]["model_bundle"]["id"],
            "artifact_version": contract["artifacts"]["model_bundle"]["version"],
            "preprocessing_acceptance_sha256": contract["prerequisites"]["t4_1_technical_acceptance"]["sha256"],
            "labels": contract["labels"],
            "random_forest_parameters": contract["random_forest"]["parameters"],
            "confidence_contract": contract["confidence"],
            "checkpoints": models,
        }
        joblib.dump(model_bundle, model_temp, compress=3)
        del model_bundle, models
        gc.collect()
        reloaded = joblib.load(model_temp)
        for checkpoint in contract["input"]["checkpoints"]:
            matrix = rf_baseline.load_validation_matrix(validation_paths[checkpoint])
            observed = predict_probabilities(
                reloaded["checkpoints"][checkpoint]["model"], matrix, class_order, tolerance
            )
            expected = (
                predictions[f"{checkpoint}__class_probability"],
                predictions[f"{checkpoint}__top_class_index"],
                predictions[f"{checkpoint}__top_class"],
                predictions[f"{checkpoint}__confidence"],
            )
            if any(not np.array_equal(left, right) for left, right in zip(observed, expected, strict=True)):
                raise ValueError(f"model reload output parity mismatch: {checkpoint}")
            model_receipts[checkpoint]["reload_parity"] = {
                "status": "passed",
                "comparison": "bitwise_equal_all_multiclass_outputs",
                "rows": len(expected[0]),
                "probability_sha256": hashlib.sha256(expected[0].tobytes(order="C")).hexdigest(),
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
            root / "python/nids_mvp/known_family_rf.py",
            root / "tests/test_t46_known_family_rf.py",
            root / "python/nids_mvp/preprocessing.py",
            root / "python/nids_mvp/rf_baseline.py",
        ]
        receipt = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "known_family_rf_acceptance_bundle",
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
                "fit_population_and_per_family_counts_exact": True,
                "validation_population_and_per_family_counts_exact": True,
                "test_partition_excluded_from_transform_fit_score_and_outputs": True,
                "benign_rows_excluded_from_fit_evaluation_and_outputs": True,
                "flow_features_only": True,
                "preprocessing_reused_without_refit": True,
                "feature_order_and_dtype_exact": True,
                "metadata_columns_excluded_from_model_matrix": True,
                "four_independent_models": True,
                "all_thirteen_training_classes_present": True,
                "class_order_exact": True,
                "probability_and_confidence_contract_exact": True,
                "confidence_not_claimed_calibrated": True,
                "model_reload_output_parity": True,
                "prediction_bundle_metric_recomputation": True,
                "feature_importance_accounting": True,
                "nine_family_macro_and_four_case_study_scope_exact": True,
            },
            "gate": {"decision": "pending_user_decision", "t4_7_authorized": False},
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
                print(f"warning: T4.6 scratch cleanup deferred: {error}", file=sys.stderr, flush=True)


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    contract, parts, flow_map, _, _, _ = verify_inputs(root, contract_path)
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T4.6 acceptance receipt")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("T4.6 contract hash mismatch")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.6 source hash mismatch: {value}")
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
            raise ValueError(f"T4.6 {name} content mismatch")
        artifact_paths[name] = path
    bundle = joblib.load(artifact_paths["model_bundle"])
    class_order = contract["labels"]["class_order"]
    if (
        bundle.get("task") != TASK
        or bundle.get("artifact_id") != contract["artifacts"]["model_bundle"]["id"]
        or bundle.get("artifact_version") != contract["artifacts"]["model_bundle"]["version"]
        or bundle.get("random_forest_parameters") != contract["random_forest"]["parameters"]
        or bundle.get("labels") != contract["labels"]
        or bundle.get("confidence_contract") != contract["confidence"]
        or list(bundle.get("checkpoints", {})) != contract["input"]["checkpoints"]
    ):
        raise ValueError("T4.6 model bundle contract mismatch")
    tolerance = float(contract["confidence"]["probability_sum_absolute_tolerance"])
    with np.load(artifact_paths["validation_predictions"], allow_pickle=False) as predictions:
        for checkpoint in contract["input"]["checkpoints"]:
            capture = predictions[f"{checkpoint}__capture_id"]
            flow_id = predictions[f"{checkpoint}__flow_id"]
            y_true = predictions[f"{checkpoint}__y_true"]
            probability = predictions[f"{checkpoint}__class_probability"]
            top_index = predictions[f"{checkpoint}__top_class_index"]
            top_class = predictions[f"{checkpoint}__top_class"]
            confidence = predictions[f"{checkpoint}__confidence"]
            expected_capture, expected_flow, expected_y = expected_validation_identity(
                checkpoint, parts, flow_map, class_order
            )
            validate_probability_matrix(probability, len(y_true), len(class_order), tolerance)
            observed_top = np.argmax(probability, axis=1).astype(np.uint8)
            encoded_y = np.asarray([class_order.index(value) for value in y_true], dtype=np.uint8)
            if (
                capture.dtype.kind != "U"
                or flow_id.dtype != np.uint64
                or y_true.dtype.kind != "U"
                or top_index.dtype != np.uint8
                or top_class.dtype.kind != "U"
                or confidence.dtype != np.float64
                or not np.array_equal(capture, expected_capture)
                or not np.array_equal(flow_id, expected_flow)
                or not np.array_equal(y_true, expected_y)
                or not np.array_equal(top_index, observed_top)
                or not np.array_equal(top_class, np.asarray(class_order, dtype="<U64")[observed_top])
                or not np.array_equal(confidence, probability[np.arange(len(probability)), observed_top])
            ):
                raise ValueError(f"T4.6 validation prediction mismatch: {checkpoint}")
            metrics = compute_metrics(
                encoded_y, probability, class_order, contract["labels"]["macro_family_order"]
            )
            if metrics != receipt["models"][checkpoint]["metrics"]:
                raise ValueError(f"T4.6 metric recomputation mismatch: {checkpoint}")
            model_record = bundle["checkpoints"][checkpoint]
            model = model_record.get("model")
            if (
                not isinstance(model, RandomForestClassifier)
                or model.classes_.tolist() != list(range(len(class_order)))
                or model_record.get("class_order") != class_order
                or len(model_record.get("features", [])) != contract["features"]["expected_selected_feature_count"][checkpoint]
                or receipt["models"][checkpoint].get("reload_parity", {}).get("status") != "passed"
                or not np.isclose(receipt["models"][checkpoint]["feature_importance"]["sum"], 1.0)
            ):
                raise ValueError(f"T4.6 model validation failed: {checkpoint}")
    if receipt.get("gate") != {"decision": "pending_user_decision", "t4_7_authorized": False}:
        raise ValueError("T4.6 gate mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Train and validate T4.6 known-family RF models")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path, default=root_default / "config/cicids2017-known-family-contract.json"
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            verify_inputs(root, contract_path)
            print("[T4.6 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(
                f"[T4.6 known-family] status=passed checkpoints={len(receipt['models'])} "
                f"elapsed_seconds={receipt['elapsed_seconds']:.1f}",
                flush=True,
            )
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T4.6 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
