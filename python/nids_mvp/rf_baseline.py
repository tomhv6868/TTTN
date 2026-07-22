from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import sys
import tempfile
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
from sklearn.metrics import confusion_matrix, f1_score, matthews_corrcoef, precision_score, recall_score

from nids_mvp import preprocessing


TASK = "T4.2"
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
        raise RuntimeError(f"T4.2 runtime contract mismatch: {observed}")


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
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, list[str], dict[str, Any]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.2 contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    manual = load_json(paths["t4_1_manual_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("t4_2_authorized")
    ):
        raise ValueError("T4.1 manual acceptance does not authorize T4.2")
    t41 = load_json(paths["t4_1_technical_acceptance"])
    artifact = t41.get("artifact", {})
    expected_t41 = contract["prerequisites"]["t4_1_technical_acceptance"]
    if (
        t41.get("status") != "passed"
        or artifact.get("artifact_id") != expected_t41["artifact_id"]
        or artifact.get("artifact_version") != expected_t41["artifact_version"]
    ):
        raise ValueError("T4.1 preprocessing acceptance mismatch")
    manifest = load_json(paths["snapshot_manifest"])
    features = manifest.get("model_feature_columns")
    if (
        manifest.get("status") != "passed"
        or manifest.get("row_count") != contract["prerequisites"]["snapshot_manifest"]["rows"]
        or not isinstance(features, list)
        or features != artifact.get("input_features")
    ):
        raise ValueError("T3.5/T4.1 feature allowlist mismatch")
    flow_map = paths["known_flow_map"]
    if pq.ParquetFile(flow_map).metadata.num_rows != contract["prerequisites"]["known_flow_map"]["rows"]:
        raise ValueError("T3.6 flow-map row count mismatch")
    parts = manifest.get("parts")
    if not isinstance(parts, list) or len(parts) != contract["prerequisites"]["snapshot_manifest"]["parts"]:
        raise ValueError("T3.5 part count mismatch")
    verified: list[dict[str, Any]] = []
    for record in parts:
        path = resolve_inside(root, str(record.get("path", "")))
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
            or pq.ParquetFile(path).metadata.num_rows != record.get("rows")
        ):
            raise ValueError(f"T3.5 part content mismatch: {record.get('path')}")
        verified.append({**record, "resolved_path": path})
    for checkpoint in contract["input"]["checkpoints"]:
        profile = artifact.get("checkpoints", {}).get(checkpoint, {}).get("profiles", {}).get("supervised_known")
        if not isinstance(profile, dict):
            raise ValueError(f"missing T4.1 supervised profile: {checkpoint}")
        if (
            len(profile.get("selected_features", []))
            != contract["preprocessing"]["expected_selected_feature_count"][checkpoint]
            or profile.get("dropped_constant_features")
            != contract["preprocessing"]["expected_dropped_features"][checkpoint]
            or profile.get("input_features") != features
            or profile.get("output_dtype") != contract["preprocessing"]["model_input_dtype"]
        ):
            raise ValueError(f"T4.1 supervised profile drift: {checkpoint}")
    return contract, verified, flow_map, features, artifact


def capture_from_path(value: str) -> str:
    if "capture_id=" not in value:
        raise ValueError(f"snapshot path lacks capture partition: {value}")
    return value.split("capture_id=", 1)[1].split("/", 1)[0]


def load_capture_map(flow_map: Path, capture_id: str) -> dict[int, tuple[str, str]]:
    table = pq.read_table(
        flow_map,
        columns=["flow_id", "partition", "assigned_class"],
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    ).to_pydict()
    result = dict(
        zip(table["flow_id"], zip(table["partition"], table["assigned_class"], strict=True), strict=True)
    )
    if len(result) != len(table["flow_id"]):
        raise ValueError(f"duplicate flow-map key for capture {capture_id}")
    return result


def _open_matrix(path: Path, rows: int, columns: int, dtype: Any) -> np.memmap:
    return np.lib.format.open_memmap(path, mode="w+", dtype=dtype, shape=(rows, columns))


def load_validation_matrix(path: Path) -> np.ndarray:
    matrix = np.load(path, allow_pickle=False)
    if isinstance(matrix, np.memmap):
        raise ValueError("validation matrix must be loaded eagerly")
    return matrix


def materialize_checkpoint(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    input_features: Sequence[str],
    profile: Mapping[str, Any],
    expected: Mapping[str, Mapping[str, int]],
    scratch: Path,
) -> dict[str, Path]:
    selected_count = len(profile["selected_features"])
    train_rows = int(expected["train"][checkpoint]["rows"])
    validation_rows = int(expected["validation"][checkpoint]["rows"])
    paths = {
        "x_train": scratch / f"{checkpoint}-x-train.npy",
        "y_train": scratch / f"{checkpoint}-y-train.npy",
        "x_validation": scratch / f"{checkpoint}-x-validation.npy",
        "y_validation": scratch / f"{checkpoint}-y-validation.npy",
        "validation_flow_id": scratch / f"{checkpoint}-validation-flow-id.npy",
        "validation_capture_id": scratch / f"{checkpoint}-validation-capture-id.npy",
    }
    arrays = {
        "x_train": _open_matrix(paths["x_train"], train_rows, selected_count, np.float32),
        "y_train": np.lib.format.open_memmap(paths["y_train"], mode="w+", dtype=np.uint8, shape=(train_rows,)),
        "x_validation": _open_matrix(
            paths["x_validation"], validation_rows, selected_count, np.float32
        ),
        "y_validation": np.lib.format.open_memmap(
            paths["y_validation"], mode="w+", dtype=np.uint8, shape=(validation_rows,)
        ),
        "validation_flow_id": np.lib.format.open_memmap(
            paths["validation_flow_id"], mode="w+", dtype=np.uint64, shape=(validation_rows,)
        ),
        "validation_capture_id": np.lib.format.open_memmap(
            paths["validation_capture_id"], mode="w+", dtype="<U64", shape=(validation_rows,)
        ),
    }
    offsets = {"train": 0, "validation": 0}
    class_counts = {
        "train": {"benign": 0, "attack": 0},
        "validation": {"benign": 0, "attack": 0},
    }
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = capture_from_path(record["path"])
        mapping = load_capture_map(flow_map, capture_id)
        parquet = pq.ParquetFile(record["resolved_path"])
        columns = ["flow_id", "capture_id", "assigned_class", *input_features]
        previous_flow_id: int | None = None
        for batch in parquet.iter_batches(columns=columns, batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            captures = batch.column(1).to_pylist()
            families = batch.column(2).to_pylist()
            if any(value != capture_id for value in captures):
                raise ValueError(f"capture metadata drift in {record['path']}")
            if flow_ids and previous_flow_id is not None and flow_ids[0] <= previous_flow_id:
                raise ValueError(f"snapshot flow order drift in {record['path']}")
            if any(left >= right for left, right in zip(flow_ids, flow_ids[1:])):
                raise ValueError(f"duplicate snapshot flow in {record['path']}")
            if flow_ids:
                previous_flow_id = flow_ids[-1]
            partition_indices = {"train": [], "validation": []}
            for index, (flow_id, family) in enumerate(zip(flow_ids, families, strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] in partition_indices:
                    partition_indices[mapped[0]].append(index)
                elif mapped[0] != "test":
                    raise ValueError(f"unknown split partition: {mapped[0]}")
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(input_features))]
            ).astype(np.float64, copy=False)
            for partition, indices in partition_indices.items():
                if not indices:
                    continue
                selected_rows = raw[indices]
                transformed = preprocessing.transform_with_artifact(selected_rows, input_features, profile)
                labels = np.fromiter(
                    (families[index] != "BENIGN" for index in indices), dtype=np.uint8, count=len(indices)
                )
                start = offsets[partition]
                stop = start + len(indices)
                target_x = arrays["x_train"] if partition == "train" else arrays["x_validation"]
                target_y = arrays["y_train"] if partition == "train" else arrays["y_validation"]
                if stop > target_x.shape[0]:
                    raise ValueError(f"{partition}/{checkpoint} exceeds expected rows")
                target_x[start:stop] = transformed
                target_y[start:stop] = labels
                if partition == "validation":
                    arrays["validation_flow_id"][start:stop] = np.asarray(
                        [flow_ids[index] for index in indices], dtype=np.uint64
                    )
                    arrays["validation_capture_id"][start:stop] = capture_id
                benign = int(np.count_nonzero(labels == 0))
                class_counts[partition]["benign"] += benign
                class_counts[partition]["attack"] += len(labels) - benign
                offsets[partition] = stop
    for value in arrays.values():
        value.flush()
    for partition in ("train", "validation"):
        observed = {
            "rows": offsets[partition],
            "benign": class_counts[partition]["benign"],
            "attack": class_counts[partition]["attack"],
        }
        if observed != dict(expected[partition][checkpoint]):
            raise ValueError(f"{partition}/{checkpoint} population mismatch: {observed}")
    del arrays
    return paths


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=[0, 1], average="macro", zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "fpr": float(fp / (fp + tn)),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def predict_attack_probability(model: RandomForestClassifier, matrix: np.ndarray) -> np.ndarray:
    original_n_jobs = model.n_jobs
    try:
        model.set_params(n_jobs=1)
        probability = model.predict_proba(matrix)[:, 1].astype(np.float64, copy=False)
    finally:
        model.set_params(n_jobs=original_n_jobs)
    if not np.isfinite(probability).all() or np.any((probability < 0.0) | (probability > 1.0)):
        raise ValueError("Random Forest produced invalid validation probability")
    return probability


def fit_random_forest(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_validation: np.ndarray,
    parameters: Mapping[str, Any],
    threshold: float,
) -> tuple[RandomForestClassifier, np.ndarray, np.ndarray]:
    model = RandomForestClassifier(**dict(parameters))
    model.fit(x_train, y_train)
    if model.classes_.tolist() != [0, 1]:
        raise ValueError(f"unexpected Random Forest classes: {model.classes_.tolist()}")
    probability = predict_attack_probability(model, x_validation)
    prediction = (probability >= threshold).astype(np.uint8)
    return model, probability, prediction


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def temporary_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")


def expected_validation_identity(
    checkpoint: str, parts: Sequence[Mapping[str, Any]], flow_map: Path
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    capture_values: list[str] = []
    flow_values: list[int] = []
    label_values: list[int] = []
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = capture_from_path(record["path"])
        mapping = load_capture_map(flow_map, capture_id)
        parquet = pq.ParquetFile(record["resolved_path"])
        for batch in parquet.iter_batches(columns=["flow_id", "assigned_class"], batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            families = batch.column(1).to_pylist()
            for flow_id, family in zip(flow_ids, families, strict=True):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] == "validation":
                    capture_values.append(capture_id)
                    flow_values.append(flow_id)
                    label_values.append(family != "BENIGN")
    return (
        np.asarray(capture_values, dtype="<U64"),
        np.asarray(flow_values, dtype=np.uint64),
        np.asarray(label_values, dtype=np.uint8),
    )


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, parts, flow_map, features, preprocessing_artifact = verify_inputs(root, contract_path)
    outputs = {
        name: resolve_inside(root, contract["artifacts"][name]["path"])
        for name in ("model_bundle", "validation_predictions", "acceptance")
    }
    if any(path.exists() for path in outputs.values()):
        raise FileExistsError("T4.2 artifact already exists; refusing to overwrite evidence")
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    models: dict[str, Any] = {}
    predictions: dict[str, np.ndarray] = {}
    metrics: dict[str, Any] = {}
    parity: dict[str, Any] = {}
    scratch_parent = root / "run_log"
    with tempfile.TemporaryDirectory(prefix="nids-t42-", dir=scratch_parent) as temporary:
        scratch = Path(temporary)
        validation_paths: dict[str, Path] = {}
        for checkpoint in contract["input"]["checkpoints"]:
            checkpoint_started = time.monotonic()
            print(f"[T4.2] checkpoint={checkpoint} stage=materialize", flush=True)
            profile = preprocessing_artifact["checkpoints"][checkpoint]["profiles"]["supervised_known"]
            paths = materialize_checkpoint(
                checkpoint,
                parts,
                flow_map,
                features,
                profile,
                contract["expected_population"],
                scratch,
            )
            x_train = np.load(paths["x_train"], mmap_mode="r")
            y_train = np.load(paths["y_train"], mmap_mode="r")
            x_validation = load_validation_matrix(paths["x_validation"])
            y_validation = np.load(paths["y_validation"], mmap_mode="r")
            print(f"[T4.2] checkpoint={checkpoint} stage=train trees=300", flush=True)
            model, probability, prediction = fit_random_forest(
                x_train,
                y_train,
                x_validation,
                contract["random_forest"]["parameters"],
                float(contract["decision"]["threshold"]),
            )
            metrics[checkpoint] = compute_metrics(y_validation, prediction)
            models[checkpoint] = {
                "model": model,
                "selected_features": profile["selected_features"],
                "preprocessing_profile": profile,
            }
            predictions[f"{checkpoint}__capture_id"] = np.array(
                np.load(paths["validation_capture_id"], mmap_mode="r"), copy=True
            )
            predictions[f"{checkpoint}__flow_id"] = np.array(
                np.load(paths["validation_flow_id"], mmap_mode="r"), copy=True
            )
            predictions[f"{checkpoint}__y_true"] = np.array(y_validation, copy=True)
            predictions[f"{checkpoint}__attack_probability"] = np.array(probability, copy=True)
            predictions[f"{checkpoint}__y_pred"] = np.array(prediction, copy=True)
            validation_paths[checkpoint] = paths["x_validation"]
            del x_train, y_train, x_validation, y_validation, model, probability, prediction
            for name in ("x_train", "y_train", "y_validation", "validation_flow_id", "validation_capture_id"):
                paths[name].unlink()
            gc.collect()
            print(
                f"[T4.2] checkpoint={checkpoint} stage=trained elapsed_seconds={time.monotonic() - checkpoint_started:.1f}",
                flush=True,
            )
        model_bundle = {
            "schema_version": "1.0.0",
            "task": TASK,
            "artifact_id": contract["artifacts"]["model_bundle"]["id"],
            "artifact_version": contract["artifacts"]["model_bundle"]["version"],
            "feature_schema_id": contract["prerequisites"]["feature_schema"]["schema_id"],
            "preprocessing_acceptance_sha256": contract["prerequisites"]["t4_1_technical_acceptance"]["sha256"],
            "labels": contract["labels"],
            "threshold": contract["decision"]["threshold"],
            "random_forest_parameters": contract["random_forest"]["parameters"],
            "checkpoints": models,
        }
        model_temp = temporary_sibling(outputs["model_bundle"])
        prediction_temp = temporary_sibling(outputs["validation_predictions"])
        acceptance_temp = temporary_sibling(outputs["acceptance"])
        try:
            joblib.dump(model_bundle, model_temp, compress=3)
            del model_bundle, models
            gc.collect()
            reloaded = joblib.load(model_temp)
            for checkpoint in contract["input"]["checkpoints"]:
                x_validation = load_validation_matrix(validation_paths[checkpoint])
                reloaded_probability = predict_attack_probability(
                    reloaded["checkpoints"][checkpoint]["model"], x_validation
                )
                expected_probability = predictions[f"{checkpoint}__attack_probability"]
                if not np.array_equal(reloaded_probability, expected_probability):
                    raise ValueError(f"model reload probability parity mismatch: {checkpoint}")
                parity[checkpoint] = {
                    "status": "passed",
                    "comparison": "bitwise_equal_float64",
                    "rows": int(len(expected_probability)),
                    "probability_sha256": hashlib.sha256(
                        expected_probability.tobytes(order="C")
                    ).hexdigest(),
                }
                del x_validation, reloaded_probability
            del reloaded
            gc.collect()
            with prediction_temp.open("wb") as output:
                np.savez_compressed(output, **predictions)
                output.flush()
                os.fsync(output.fileno())
            sources = [
                root / "config/agent/current-task.json",
                contract_path,
                root / "python/nids_mvp/rf_baseline.py",
                root / "tests/test_t42_rf_baseline.py",
            ]
            receipt = {
                "schema_version": "1.0.0",
                "task": TASK,
                "kind": "rf_baseline_acceptance_bundle",
                "status": "passed",
                "generated_at_utc": utc_now(),
                "elapsed_seconds": time.monotonic() - started,
                "contract": {"path": relative(contract_path, root), "sha256": sha256_path(contract_path)},
                "source_files": {relative(path, root): sha256_path(path) for path in sources},
                "inputs": {
                    "snapshot_manifest_sha256": contract["prerequisites"]["snapshot_manifest"]["sha256"],
                    "known_flow_map_sha256": contract["prerequisites"]["known_flow_map"]["sha256"],
                    "preprocessing_acceptance_sha256": contract["prerequisites"]["t4_1_technical_acceptance"]["sha256"],
                    "t4_1_manual_acceptance_sha256": contract["prerequisites"]["t4_1_manual_acceptance"]["sha256"],
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
                "models": {
                    checkpoint: {
                        "fit_rows": contract["expected_population"]["train"][checkpoint]["rows"],
                        "validation_rows": contract["expected_population"]["validation"][checkpoint]["rows"],
                        "selected_feature_count": contract["preprocessing"]["expected_selected_feature_count"][checkpoint],
                        "metrics": metrics[checkpoint],
                        "reload_parity": parity[checkpoint],
                    }
                    for checkpoint in contract["input"]["checkpoints"]
                },
                "validation": {
                    "all_prerequisite_hashes_verified": True,
                    "fit_population_exact": True,
                    "validation_population_exact": True,
                    "test_partition_excluded_from_transform_fit_score_and_outputs": True,
                    "feature_order_exact": True,
                    "metadata_columns_excluded_from_model_matrix": True,
                    "preprocessing_reused_without_refit": True,
                    "four_independent_models": True,
                    "model_reload_probability_parity": True,
                    "prediction_bundle_metric_recomputation": True,
                },
                "gate": {"decision": "pending_user_decision", "t4_3_authorized": False},
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


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    contract, parts, flow_map, _, _ = verify_inputs(root, contract_path)
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T4.2 acceptance bundle")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("T4.2 contract hash mismatch")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.2 source hash mismatch: {value}")
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
            raise ValueError(f"T4.2 {name} content mismatch")
        artifact_paths[name] = path
    bundle = joblib.load(artifact_paths["model_bundle"])
    if (
        bundle.get("task") != TASK
        or bundle.get("artifact_id") != contract["artifacts"]["model_bundle"]["id"]
        or bundle.get("artifact_version") != contract["artifacts"]["model_bundle"]["version"]
        or list(bundle.get("checkpoints", {})) != contract["input"]["checkpoints"]
        or bundle.get("random_forest_parameters") != contract["random_forest"]["parameters"]
    ):
        raise ValueError("T4.2 model bundle contract mismatch")
    with np.load(artifact_paths["validation_predictions"], allow_pickle=False) as predictions:
        for checkpoint in contract["input"]["checkpoints"]:
            capture = predictions[f"{checkpoint}__capture_id"]
            flow_id = predictions[f"{checkpoint}__flow_id"]
            y_true = predictions[f"{checkpoint}__y_true"]
            probability = predictions[f"{checkpoint}__attack_probability"]
            y_pred = predictions[f"{checkpoint}__y_pred"]
            expected_capture, expected_flow, expected_y = expected_validation_identity(
                checkpoint, parts, flow_map
            )
            if (
                capture.dtype.kind != "U"
                or flow_id.dtype != np.uint64
                or y_true.dtype != np.uint8
                or probability.dtype != np.float64
                or y_pred.dtype != np.uint8
                or not np.array_equal(capture, expected_capture)
                or not np.array_equal(flow_id, expected_flow)
                or not np.array_equal(y_true, expected_y)
                or not np.array_equal(
                    y_pred, (probability >= contract["decision"]["threshold"]).astype(np.uint8)
                )
                or not np.isfinite(probability).all()
            ):
                raise ValueError(f"T4.2 validation prediction mismatch: {checkpoint}")
            observed_metrics = compute_metrics(y_true, y_pred)
            if observed_metrics != receipt["models"][checkpoint]["metrics"]:
                raise ValueError(f"T4.2 metric recomputation mismatch: {checkpoint}")
            model_record = bundle["checkpoints"][checkpoint]
            model = model_record.get("model")
            if (
                not isinstance(model, RandomForestClassifier)
                or model.classes_.tolist() != contract["labels"]["class_order"]
                or model_record.get("selected_features")
                != model_record.get("preprocessing_profile", {}).get("selected_features")
                or receipt["models"][checkpoint].get("reload_parity", {}).get("status") != "passed"
            ):
                raise ValueError(f"T4.2 model validation failed: {checkpoint}")
    if receipt.get("gate") != {"decision": "pending_user_decision", "t4_3_authorized": False}:
        raise ValueError("T4.2 gate mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Train and validate T4.2 Random Forest baselines")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path, default=root_default / "config/cicids2017-rf-baseline-contract.json"
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            verify_inputs(root, contract_path)
            print("[T4.2 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(
                f"[T4.2 baseline] status=passed checkpoints={len(receipt['models'])} elapsed_seconds={receipt['elapsed_seconds']:.1f}",
                flush=True,
            )
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T4.2 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
