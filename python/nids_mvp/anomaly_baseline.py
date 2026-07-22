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
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, matthews_corrcoef, precision_score, recall_score

from nids_mvp import preprocessing


TASK = "T4.3"
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


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def temporary_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")


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
        raise RuntimeError(f"T4.3 runtime contract mismatch: {observed}")


def verify_reference(root: Path, reference: Mapping[str, Any], label: str) -> Path:
    path = resolve_inside(root, str(reference.get("path", "")))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{label} content address mismatch")
    return path


def derive_hbos_mask(eda_checkpoint: Mapping[str, Any]) -> list[str]:
    pairs: set[tuple[str, str]] = set()
    for pair in eda_checkpoint["correlation_audit"]["pairs"]:
        pairs.add((pair["left"], pair["right"]))
        pairs.add((pair["right"], pair["left"]))
    retained: list[str] = []
    for statistic in eda_checkpoint["feature_statistics"]:
        feature = statistic["feature"]
        if not any((feature, earlier) in pairs for earlier in retained):
            retained.append(feature)
    return retained


def verify_inputs(
    root: Path, contract_path: Path
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, list[str], dict[str, Any]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.3 model contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    manual = load_json(paths["t4_3_eda_manual_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("model_contract_authorized")
    ):
        raise ValueError("T4.3 EDA acceptance does not authorize model implementation")
    eda = load_json(paths["t4_3_eda"])
    expected_eda = contract["prerequisites"]["t4_3_eda"]
    if (
        eda.get("status") != "passed"
        or eda.get("artifact_id") != expected_eda["artifact_id"]
        or eda.get("artifact_version") != expected_eda["artifact_version"]
    ):
        raise ValueError("T4.3 EDA evidence mismatch")
    preprocessing_acceptance = load_json(paths["t4_1_technical_acceptance"])
    artifact = preprocessing_acceptance.get("artifact", {})
    expected_t41 = contract["prerequisites"]["t4_1_technical_acceptance"]
    if (
        preprocessing_acceptance.get("status") != "passed"
        or artifact.get("artifact_id") != expected_t41["artifact_id"]
        or artifact.get("artifact_version") != expected_t41["artifact_version"]
    ):
        raise ValueError("T4.1 preprocessing acceptance mismatch")
    manifest = load_json(paths["snapshot_manifest"])
    input_features = manifest.get("model_feature_columns")
    if (
        manifest.get("status") != "passed"
        or manifest.get("row_count") != contract["prerequisites"]["snapshot_manifest"]["rows"]
        or not isinstance(input_features, list)
        or input_features != artifact.get("input_features")
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
        profile = artifact.get("checkpoints", {}).get(checkpoint, {}).get("profiles", {}).get("anomaly_benign")
        if not isinstance(profile, dict):
            raise ValueError(f"missing T4.1 anomaly profile: {checkpoint}")
        if (
            profile.get("fit_population_rows") != contract["expected_population"]["fit_benign_train"][checkpoint]
            or len(profile.get("selected_features", []))
            != contract["preprocessing"]["expected_selected_feature_count"][checkpoint]
            or profile.get("dropped_constant_features")
            != contract["preprocessing"]["expected_dropped_features"][checkpoint]
            or profile.get("input_features") != input_features
            or profile.get("output_dtype") != contract["preprocessing"]["model_input_dtype"]
        ):
            raise ValueError(f"T4.1 anomaly profile drift: {checkpoint}")
        mask = contract["hbos"]["feature_masks"][checkpoint]
        if (
            mask != derive_hbos_mask(eda["checkpoints"][checkpoint])
            or len(mask) != contract["hbos"]["expected_feature_counts"][checkpoint]
            or [feature for feature in profile["selected_features"] if feature in set(mask)] != mask
        ):
            raise ValueError(f"T4.3 HBOS mask drift: {checkpoint}")
    return contract, verified, flow_map, input_features, artifact


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


def materialize_checkpoint(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    input_features: Sequence[str],
    profile: Mapping[str, Any],
    expected_fit_rows: int,
    expected_validation: Mapping[str, int],
    scratch: Path,
) -> dict[str, Path]:
    selected_count = len(profile["selected_features"])
    validation_rows = int(expected_validation["rows"])
    paths = {
        "x_train": scratch / f"{checkpoint}-x-benign-train.npy",
        "x_validation": scratch / f"{checkpoint}-x-validation.npy",
        "y_validation": scratch / f"{checkpoint}-y-validation.npy",
        "validation_flow_id": scratch / f"{checkpoint}-validation-flow-id.npy",
        "validation_capture_id": scratch / f"{checkpoint}-validation-capture-id.npy",
    }
    arrays = {
        "x_train": _open_matrix(paths["x_train"], expected_fit_rows, selected_count, np.float32),
        "x_validation": _open_matrix(paths["x_validation"], validation_rows, selected_count, np.float32),
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
    validation_counts = {"benign": 0, "attack": 0}
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
            train_indices: list[int] = []
            validation_indices: list[int] = []
            for index, (flow_id, family) in enumerate(zip(flow_ids, families, strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] not in {"train", "validation", "test"}:
                    raise ValueError(f"unknown split partition: {mapped[0]}")
                if mapped[0] == "train" and family == "BENIGN":
                    train_indices.append(index)
                elif mapped[0] == "validation":
                    validation_indices.append(index)
            if not train_indices and not validation_indices:
                continue
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(input_features))]
            ).astype(np.float64, copy=False)
            if train_indices:
                transformed = preprocessing.transform_with_artifact(raw[train_indices], input_features, profile)
                start = offsets["train"]
                stop = start + len(transformed)
                if stop > arrays["x_train"].shape[0]:
                    raise ValueError(f"benign train/{checkpoint} exceeds expected rows")
                arrays["x_train"][start:stop] = transformed
                offsets["train"] = stop
            if validation_indices:
                transformed = preprocessing.transform_with_artifact(raw[validation_indices], input_features, profile)
                labels = np.fromiter(
                    (families[index] != "BENIGN" for index in validation_indices),
                    dtype=np.uint8,
                    count=len(validation_indices),
                )
                start = offsets["validation"]
                stop = start + len(transformed)
                if stop > arrays["x_validation"].shape[0]:
                    raise ValueError(f"validation/{checkpoint} exceeds expected rows")
                arrays["x_validation"][start:stop] = transformed
                arrays["y_validation"][start:stop] = labels
                arrays["validation_flow_id"][start:stop] = np.asarray(
                    [flow_ids[index] for index in validation_indices], dtype=np.uint64
                )
                arrays["validation_capture_id"][start:stop] = capture_id
                benign = int(np.count_nonzero(labels == 0))
                validation_counts["benign"] += benign
                validation_counts["attack"] += len(labels) - benign
                offsets["validation"] = stop
    for value in arrays.values():
        value.flush()
    if offsets["train"] != expected_fit_rows:
        raise ValueError(f"benign train/{checkpoint} population mismatch: {offsets['train']}")
    observed_validation = {
        "rows": offsets["validation"],
        "benign": validation_counts["benign"],
        "attack": validation_counts["attack"],
    }
    if observed_validation != dict(expected_validation):
        raise ValueError(f"validation/{checkpoint} population mismatch: {observed_validation}")
    del arrays
    return paths


def _hbos_bin_indices(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    indices = np.empty(len(values), dtype=np.int64)
    below = values < edges[0]
    above = values > edges[-1]
    inside = ~(below | above)
    indices[below] = 0
    indices[above] = len(edges)
    interior = np.searchsorted(edges, values[inside], side="right") - 1
    indices[inside] = 1 + np.clip(interior, 0, len(edges) - 2)
    return indices


def fit_hbos(
    matrix: np.ndarray,
    selected_features: Sequence[str],
    feature_mask: Sequence[str],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    feature_indices = [selected_features.index(feature) for feature in feature_mask]
    binning = config["binning"]
    interior_bins = int(binning["interior_bin_count"])
    total_bins = int(binning["total_bin_count"])
    edges_by_feature: list[np.ndarray] = []
    probabilities_by_feature: list[np.ndarray] = []
    counts_by_feature: list[np.ndarray] = []
    for feature, feature_index in zip(feature_mask, feature_indices, strict=True):
        values = np.asarray(matrix[:, feature_index])
        lower, upper = np.quantile(
            values,
            [binning["lower_quantile"], binning["upper_quantile"]],
            method=binning["quantile_method"],
        )
        if lower == upper:
            lower, upper = np.min(values), np.max(values)
        if not np.isfinite(lower) or not np.isfinite(upper) or lower >= upper:
            raise ValueError(f"invalid HBOS range: {feature}")
        edges = np.linspace(lower, upper, interior_bins + 1, dtype=np.float64)
        indices = _hbos_bin_indices(values, edges)
        counts = np.bincount(indices, minlength=total_bins).astype(np.int64)
        probabilities = (counts.astype(np.float64) + 1.0) / (len(values) + total_bins)
        if counts.sum() != len(values) or not np.isclose(probabilities.sum(), 1.0):
            raise ValueError(f"invalid HBOS bin mass: {feature}")
        edges_by_feature.append(edges)
        counts_by_feature.append(counts)
        probabilities_by_feature.append(probabilities)
    return {
        "feature_names": list(feature_mask),
        "feature_indices": feature_indices,
        "fit_rows": int(matrix.shape[0]),
        "interior_bin_count": interior_bins,
        "total_bin_count": total_bins,
        "edges": edges_by_feature,
        "counts": counts_by_feature,
        "probabilities": probabilities_by_feature,
    }


def score_hbos(model: Mapping[str, Any], matrix: np.ndarray) -> np.ndarray:
    scores = np.zeros(matrix.shape[0], dtype=np.float64)
    for feature_index, edges, probabilities in zip(
        model["feature_indices"], model["edges"], model["probabilities"], strict=True
    ):
        bins = _hbos_bin_indices(np.asarray(matrix[:, feature_index]), np.asarray(edges))
        scores -= np.log(np.asarray(probabilities, dtype=np.float64)[bins])
    scores /= len(model["feature_indices"])
    if not np.isfinite(scores).all():
        raise ValueError("HBOS produced non-finite scores")
    return scores


def score_isolation_forest(
    model: IsolationForest, matrix: np.ndarray, batch_rows: int = BATCH_ROWS
) -> np.ndarray:
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    for start in range(0, matrix.shape[0], batch_rows):
        stop = min(start + batch_rows, matrix.shape[0])
        scores[start:stop] = -model.score_samples(matrix[start:stop])
    if not np.isfinite(scores).all():
        raise ValueError("Isolation Forest produced non-finite scores")
    return scores


def fit_score_decision(raw_score: np.ndarray, config: Mapping[str, Any]) -> dict[str, Any]:
    mean = float(np.mean(raw_score, dtype=np.float64))
    standard_deviation = float(np.std(raw_score, dtype=np.float64, ddof=0))
    if not np.isfinite(mean) or not np.isfinite(standard_deviation) or standard_deviation == 0.0:
        raise ValueError("invalid benign-train score normalization")
    normalized = (raw_score - mean) / standard_deviation
    threshold = float(
        np.quantile(
            normalized,
            float(config["threshold_quantile"]),
            method=config["threshold_quantile_method"],
        )
    )
    prediction = (normalized >= threshold).astype(np.uint8)
    return {
        "mean": mean,
        "standard_deviation": standard_deviation,
        "threshold": threshold,
        "threshold_quantile": float(config["threshold_quantile"]),
        "threshold_quantile_method": config["threshold_quantile_method"],
        "empirical_benign_train_fpr": float(np.mean(prediction, dtype=np.float64)),
    }


def apply_score_decision(
    raw_score: np.ndarray, decision: Mapping[str, Any]
) -> tuple[np.ndarray, np.ndarray]:
    normalized = (raw_score - decision["mean"]) / decision["standard_deviation"]
    prediction = (normalized >= decision["threshold"]).astype(np.uint8)
    if not np.isfinite(normalized).all():
        raise ValueError("score normalization produced non-finite values")
    return normalized.astype(np.float64, copy=False), prediction


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
    contract, parts, flow_map, input_features, preprocessing_artifact = verify_inputs(root, contract_path)
    outputs = {
        name: resolve_inside(root, contract["artifacts"][name]["path"])
        for name in ("model_bundle", "validation_predictions", "acceptance")
    }
    if any(path.exists() for path in outputs.values()):
        raise FileExistsError("T4.3 artifact already exists; refusing to overwrite evidence")
    for path in outputs.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    models: dict[str, Any] = {}
    predictions: dict[str, np.ndarray] = {}
    metrics: dict[str, dict[str, Any]] = {}
    diagnostics: dict[str, dict[str, Any]] = {}
    parity: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="nids-t43-model-", dir=root / "run_log") as temporary:
        scratch = Path(temporary)
        validation_paths: dict[str, Path] = {}
        for checkpoint in contract["input"]["checkpoints"]:
            checkpoint_started = time.monotonic()
            print(f"[T4.3] checkpoint={checkpoint} stage=materialize", flush=True)
            profile = preprocessing_artifact["checkpoints"][checkpoint]["profiles"]["anomaly_benign"]
            paths = materialize_checkpoint(
                checkpoint,
                parts,
                flow_map,
                input_features,
                profile,
                int(contract["expected_population"]["fit_benign_train"][checkpoint]),
                contract["expected_population"]["validation"][checkpoint],
                scratch,
            )
            x_train = np.load(paths["x_train"], mmap_mode="r")
            x_validation = np.load(paths["x_validation"], mmap_mode="r")
            y_validation = np.load(paths["y_validation"], mmap_mode="r")
            print(f"[T4.3] checkpoint={checkpoint} stage=fit_hbos", flush=True)
            hbos = fit_hbos(
                x_train,
                profile["selected_features"],
                contract["hbos"]["feature_masks"][checkpoint],
                contract["hbos"],
            )
            hbos_train_raw = score_hbos(hbos, x_train)
            hbos_decision = fit_score_decision(hbos_train_raw, contract["score_normalization_and_decision"])
            hbos["decision"] = hbos_decision
            hbos_validation_raw = score_hbos(hbos, x_validation)
            hbos_validation_normalized, hbos_prediction = apply_score_decision(
                hbos_validation_raw, hbos_decision
            )
            print(f"[T4.3] checkpoint={checkpoint} stage=fit_isolation_forest", flush=True)
            isolation_forest = IsolationForest(**contract["isolation_forest"]["parameters"])
            isolation_forest.fit(x_train)
            iforest_train_raw = score_isolation_forest(isolation_forest, x_train)
            iforest_decision = fit_score_decision(
                iforest_train_raw, contract["score_normalization_and_decision"]
            )
            iforest_validation_raw = score_isolation_forest(isolation_forest, x_validation)
            iforest_validation_normalized, iforest_prediction = apply_score_decision(
                iforest_validation_raw, iforest_decision
            )
            models[checkpoint] = {
                "preprocessing_profile": profile,
                "hbos": hbos,
                "isolation_forest": {
                    "feature_names": profile["selected_features"],
                    "estimator": isolation_forest,
                    "decision": iforest_decision,
                },
            }
            predictions[f"{checkpoint}__capture_id"] = np.array(
                np.load(paths["validation_capture_id"], mmap_mode="r"), copy=True
            )
            predictions[f"{checkpoint}__flow_id"] = np.array(
                np.load(paths["validation_flow_id"], mmap_mode="r"), copy=True
            )
            predictions[f"{checkpoint}__y_true"] = np.array(y_validation, copy=True)
            for model_name, raw, normalized, prediction in (
                ("hbos", hbos_validation_raw, hbos_validation_normalized, hbos_prediction),
                ("isolation_forest", iforest_validation_raw, iforest_validation_normalized, iforest_prediction),
            ):
                predictions[f"{checkpoint}__{model_name}__raw_score"] = np.asarray(raw, dtype=np.float64)
                predictions[f"{checkpoint}__{model_name}__normalized_score"] = np.asarray(
                    normalized, dtype=np.float64
                )
                predictions[f"{checkpoint}__{model_name}__y_pred"] = np.asarray(prediction, dtype=np.uint8)
            metrics[checkpoint] = {
                "hbos": compute_metrics(y_validation, hbos_prediction),
                "isolation_forest": compute_metrics(y_validation, iforest_prediction),
            }
            diagnostics[checkpoint] = {
                "hbos": {**hbos_decision, "feature_count": len(hbos["feature_names"])},
                "isolation_forest": {
                    **iforest_decision,
                    "feature_count": len(profile["selected_features"]),
                },
            }
            validation_paths[checkpoint] = paths["x_validation"]
            del (
                x_train,
                x_validation,
                y_validation,
                hbos_train_raw,
                hbos_validation_raw,
                hbos_validation_normalized,
                hbos_prediction,
                iforest_train_raw,
                iforest_validation_raw,
                iforest_validation_normalized,
                iforest_prediction,
                isolation_forest,
            )
            for name in ("x_train", "y_validation", "validation_flow_id", "validation_capture_id"):
                paths[name].unlink()
            gc.collect()
            print(
                f"[T4.3] checkpoint={checkpoint} stage=trained "
                f"elapsed_seconds={time.monotonic() - checkpoint_started:.1f}",
                flush=True,
            )
        model_bundle = {
            "schema_version": "1.0.0",
            "task": TASK,
            "artifact_id": contract["artifacts"]["model_bundle"]["id"],
            "artifact_version": contract["artifacts"]["model_bundle"]["version"],
            "feature_schema_id": contract["prerequisites"]["feature_schema"]["schema_id"],
            "preprocessing_acceptance_sha256": contract["prerequisites"]["t4_1_technical_acceptance"]["sha256"],
            "eda_sha256": contract["prerequisites"]["t4_3_eda"]["sha256"],
            "isolation_forest_parameters": contract["isolation_forest"]["parameters"],
            "score_decision_contract": contract["score_normalization_and_decision"],
            "checkpoints": models,
        }
        model_temp = temporary_sibling(outputs["model_bundle"])
        prediction_temp = temporary_sibling(outputs["validation_predictions"])
        acceptance_temp = temporary_sibling(outputs["acceptance"])
        try:
            print("[T4.3] stage=serialize_model", flush=True)
            joblib.dump(model_bundle, model_temp, compress=3)
            del model_bundle, models
            gc.collect()
            reloaded = joblib.load(model_temp)
            for checkpoint in contract["input"]["checkpoints"]:
                x_validation = np.load(validation_paths[checkpoint], mmap_mode="r")
                parity[checkpoint] = {}
                model_record = reloaded["checkpoints"][checkpoint]
                for model_name in ("hbos", "isolation_forest"):
                    if model_name == "hbos":
                        raw = score_hbos(model_record["hbos"], x_validation)
                    else:
                        raw = score_isolation_forest(
                            model_record["isolation_forest"]["estimator"], x_validation
                        )
                    decision = model_record[model_name]["decision"]
                    normalized, prediction = apply_score_decision(raw, decision)
                    expected_raw = predictions[f"{checkpoint}__{model_name}__raw_score"]
                    expected_normalized = predictions[f"{checkpoint}__{model_name}__normalized_score"]
                    expected_prediction = predictions[f"{checkpoint}__{model_name}__y_pred"]
                    if (
                        not np.array_equal(raw, expected_raw)
                        or not np.array_equal(normalized, expected_normalized)
                        or not np.array_equal(prediction, expected_prediction)
                    ):
                        raise ValueError(f"model reload parity mismatch: {checkpoint}/{model_name}")
                    parity[checkpoint][model_name] = {
                        "status": "passed",
                        "comparison": "bitwise_equal_float64_and_uint8",
                        "rows": int(len(raw)),
                        "raw_score_sha256": hashlib.sha256(raw.tobytes(order="C")).hexdigest(),
                        "normalized_score_sha256": hashlib.sha256(
                            normalized.tobytes(order="C")
                        ).hexdigest(),
                        "prediction_sha256": hashlib.sha256(
                            prediction.tobytes(order="C")
                        ).hexdigest(),
                    }
                del x_validation
            del reloaded
            gc.collect()
            with prediction_temp.open("wb") as output:
                np.savez_compressed(output, **predictions)
                output.flush()
                os.fsync(output.fileno())
            sources = [
                root / "config/agent/current-task.json",
                contract_path,
                root / "python/nids_mvp/anomaly_baseline.py",
                root / "tests/test_t43_anomaly_baseline.py",
            ]
            receipt = {
                "schema_version": "1.0.0",
                "task": TASK,
                "kind": "anomaly_baseline_acceptance_bundle",
                "status": "passed",
                "generated_at_utc": utc_now(),
                "elapsed_seconds": time.monotonic() - started,
                "contract": {"path": relative(contract_path, root), "sha256": sha256_path(contract_path)},
                "source_files": {relative(path, root): sha256_path(path) for path in sources},
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
                "models": {
                    checkpoint: {
                        model_name: {
                            "fit_rows": contract["expected_population"]["fit_benign_train"][checkpoint],
                            "validation_rows": contract["expected_population"]["validation"][checkpoint]["rows"],
                            "feature_count": diagnostics[checkpoint][model_name]["feature_count"],
                            "train_score_mean": diagnostics[checkpoint][model_name]["mean"],
                            "train_score_standard_deviation": diagnostics[checkpoint][model_name][
                                "standard_deviation"
                            ],
                            "normalized_threshold": diagnostics[checkpoint][model_name]["threshold"],
                            "empirical_benign_train_fpr": diagnostics[checkpoint][model_name][
                                "empirical_benign_train_fpr"
                            ],
                            "metrics": metrics[checkpoint][model_name],
                            "reload_parity": parity[checkpoint][model_name],
                        }
                        for model_name in ("hbos", "isolation_forest")
                    }
                    for checkpoint in contract["input"]["checkpoints"]
                },
                "validation": {
                    "all_prerequisite_hashes_verified": True,
                    "exact_benign_train_fit_population": True,
                    "validation_population_exact": True,
                    "test_partition_excluded_from_transform_score_and_outputs": True,
                    "attack_train_excluded_from_model_fit": True,
                    "feature_order_exact": True,
                    "metadata_columns_excluded_from_model_matrices": True,
                    "preprocessing_reused_without_refit": True,
                    "four_independent_hbos_models": True,
                    "four_independent_isolation_forest_models": True,
                    "model_reload_score_and_binary_parity": True,
                    "prediction_bundle_metric_recomputation": True,
                },
                "gate": {"decision": "pending_user_decision", "t4_4_authorized": False},
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


def validate_receipt(root: Path, contract_path: Path) -> None:
    contract, parts, flow_map, _, _ = verify_inputs(root, contract_path)
    receipt_path = resolve_inside(root, contract["artifacts"]["acceptance"]["path"])
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T4.3 acceptance bundle")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("T4.3 contract hash mismatch")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.3 source hash mismatch: {value}")
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
            raise ValueError(f"T4.3 {name} content mismatch")
        artifact_paths[name] = path
    bundle = joblib.load(artifact_paths["model_bundle"])
    if (
        bundle.get("task") != TASK
        or bundle.get("artifact_id") != contract["artifacts"]["model_bundle"]["id"]
        or bundle.get("artifact_version") != contract["artifacts"]["model_bundle"]["version"]
        or list(bundle.get("checkpoints", {})) != contract["input"]["checkpoints"]
        or bundle.get("isolation_forest_parameters") != contract["isolation_forest"]["parameters"]
    ):
        raise ValueError("T4.3 model bundle contract mismatch")
    expected_keys: set[str] = set()
    for checkpoint in contract["input"]["checkpoints"]:
        expected_keys.update(
            {
                f"{checkpoint}__capture_id",
                f"{checkpoint}__flow_id",
                f"{checkpoint}__y_true",
            }
        )
        for model_name in ("hbos", "isolation_forest"):
            expected_keys.update(
                {
                    f"{checkpoint}__{model_name}__raw_score",
                    f"{checkpoint}__{model_name}__normalized_score",
                    f"{checkpoint}__{model_name}__y_pred",
                }
            )
    with np.load(artifact_paths["validation_predictions"], allow_pickle=False) as predictions:
        if set(predictions.files) != expected_keys:
            raise ValueError("T4.3 validation prediction key mismatch")
        for checkpoint in contract["input"]["checkpoints"]:
            capture = predictions[f"{checkpoint}__capture_id"]
            flow_id = predictions[f"{checkpoint}__flow_id"]
            y_true = predictions[f"{checkpoint}__y_true"]
            expected_capture, expected_flow, expected_y = expected_validation_identity(
                checkpoint, parts, flow_map
            )
            if (
                capture.dtype.kind != "U"
                or flow_id.dtype != np.uint64
                or y_true.dtype != np.uint8
                or not np.array_equal(capture, expected_capture)
                or not np.array_equal(flow_id, expected_flow)
                or not np.array_equal(y_true, expected_y)
            ):
                raise ValueError(f"T4.3 validation identity mismatch: {checkpoint}")
            model_record = bundle["checkpoints"][checkpoint]
            if (
                model_record["hbos"]["feature_names"] != contract["hbos"]["feature_masks"][checkpoint]
                or not isinstance(model_record["isolation_forest"]["estimator"], IsolationForest)
                or model_record["isolation_forest"]["feature_names"]
                != model_record["preprocessing_profile"]["selected_features"]
            ):
                raise ValueError(f"T4.3 model validation failed: {checkpoint}")
            for model_name in ("hbos", "isolation_forest"):
                raw = predictions[f"{checkpoint}__{model_name}__raw_score"]
                normalized = predictions[f"{checkpoint}__{model_name}__normalized_score"]
                prediction = predictions[f"{checkpoint}__{model_name}__y_pred"]
                decision = model_record[model_name]["decision"]
                recomputed_normalized, recomputed_prediction = apply_score_decision(raw, decision)
                if (
                    raw.dtype != np.float64
                    or normalized.dtype != np.float64
                    or prediction.dtype != np.uint8
                    or not np.isfinite(raw).all()
                    or not np.array_equal(normalized, recomputed_normalized)
                    or not np.array_equal(prediction, recomputed_prediction)
                ):
                    raise ValueError(f"T4.3 prediction mismatch: {checkpoint}/{model_name}")
                observed_metrics = compute_metrics(y_true, prediction)
                record = receipt["models"][checkpoint][model_name]
                if (
                    observed_metrics != record["metrics"]
                    or record.get("reload_parity", {}).get("status") != "passed"
                    or not 0.0 <= record.get("empirical_benign_train_fpr", -1.0) <= 1.0
                ):
                    raise ValueError(f"T4.3 metric/parity mismatch: {checkpoint}/{model_name}")
    if receipt.get("gate") != {"decision": "pending_user_decision", "t4_4_authorized": False}:
        raise ValueError("T4.3 gate mismatch")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Train and validate T4.3 anomaly baselines")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path("config/cicids2017-anomaly-baseline-contract.json"),
    )
    args = parser.parse_args(argv)
    root = args.project_root.resolve()
    contract_path = resolve_inside(root, str(args.contract))
    if args.command == "check":
        verify_inputs(root, contract_path)
        print("T4.3 anomaly baseline input check passed")
    elif args.command == "run":
        publish(root, contract_path)
        print("T4.3 anomaly baseline artifacts published")
    else:
        validate_receipt(root, contract_path)
        print("T4.3 anomaly baseline validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
