from __future__ import annotations

import argparse
import hashlib
import json
import os
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

from nids_mvp import known_family_rf, preprocessing, rf_baseline, rf_stacker


TASK = "T4.7"
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
        or expected.get("hooks_in_scope") is not False
    ):
        raise RuntimeError(f"T4.7 runtime contract mismatch: {observed}")


def verify_inputs(root: Path, contract_path: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.7 contract")
    verify_runtime(contract)
    paths: dict[str, Path] = {}
    for name, reference in contract["prerequisites"].items():
        path = resolve_inside(root, reference["path"])
        if (
            not path.is_file()
            or path.stat().st_size != reference["size_bytes"]
            or sha256_path(path) != reference["sha256"]
        ):
            raise ValueError(f"{name} content address mismatch")
        paths[name] = path
    manual = load_json(paths["t4_6_user_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("t4_7_authorized")
    ):
        raise ValueError("T4.6 manual acceptance does not authorize T4.7")
    return contract, paths


def _verified_parts(root: Path, manifest_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    manifest = load_json(manifest_path)
    features = manifest.get("model_feature_columns")
    records = manifest.get("parts")
    if manifest.get("status") != "passed" or not isinstance(features, list) or not isinstance(records, list):
        raise ValueError("invalid snapshot manifest")
    parts = []
    for record in records:
        path = resolve_inside(root, record["path"])
        if (
            not path.is_file()
            or path.stat().st_size != record["size_bytes"]
            or sha256_path(path) != record["sha256"]
            or pq.ParquetFile(path).metadata.num_rows != record["rows"]
        ):
            raise ValueError(f"snapshot part mismatch: {record['path']}")
        parts.append({**record, "resolved_path": path})
    return parts, features


def materialize_validation(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    input_features: Sequence[str],
    profile: Mapping[str, Any],
) -> dict[str, np.ndarray]:
    matrices: list[np.ndarray] = []
    capture_values: list[str] = []
    flow_values: list[int] = []
    family_values: list[str] = []
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = rf_baseline.capture_from_path(record["path"])
        mapping = rf_baseline.load_capture_map(flow_map, capture_id)
        parquet = pq.ParquetFile(record["resolved_path"])
        columns = ["flow_id", "capture_id", "assigned_class", *input_features]
        for batch in parquet.iter_batches(columns=columns, batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            captures = batch.column(1).to_pylist()
            families = batch.column(2).to_pylist()
            if any(value != capture_id for value in captures):
                raise ValueError(f"capture metadata drift: {record['path']}")
            indices = []
            for index, (flow_id, family) in enumerate(zip(flow_ids, families, strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] == "validation":
                    indices.append(index)
                elif mapped[0] not in {"train", "test"}:
                    raise ValueError(f"unknown partition: {mapped[0]}")
            if not indices:
                continue
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(input_features))]
            ).astype(np.float64, copy=False)
            matrices.append(preprocessing.transform_with_artifact(raw[indices], input_features, profile))
            capture_values.extend(capture_id for _ in indices)
            flow_values.extend(flow_ids[index] for index in indices)
            family_values.extend(families[index] for index in indices)
    matrix = np.concatenate(matrices, axis=0)
    result = {
        "matrix": matrix,
        "capture_id": np.asarray(capture_values, dtype="<U64"),
        "flow_id": np.asarray(flow_values, dtype=np.uint64),
        "family": np.asarray(family_values, dtype="<U64"),
    }
    if matrix.dtype != np.float32 or not np.isfinite(matrix).all():
        raise ValueError(f"invalid validation matrix: {checkpoint}")
    return result


def cumulative_probabilities(
    model: RandomForestClassifier, matrix: np.ndarray, candidates: Sequence[int]
) -> dict[int, np.ndarray]:
    ordered = sorted(set(int(value) for value in candidates))
    if not ordered or ordered[0] <= 0 or ordered[-1] != len(model.estimators_):
        raise ValueError("candidate tree counts must end at the full accepted forest")
    probability_sum = np.zeros((len(matrix), len(model.classes_)), dtype=np.float64)
    result: dict[int, np.ndarray] = {}
    candidate_set = set(ordered)
    for index, estimator in enumerate(model.estimators_, start=1):
        probability_sum += estimator.predict_proba(matrix, check_input=False)
        if index in candidate_set:
            result[index] = probability_sum / index
    return result


def binary_log_loss(y_true: np.ndarray, probability: np.ndarray) -> float:
    clipped = np.clip(probability, np.finfo(np.float64).eps, 1.0 - np.finfo(np.float64).eps)
    return float(-np.mean(y_true * np.log(clipped) + (1 - y_true) * np.log1p(-clipped)))


def binary_curve(
    model: RandomForestClassifier,
    matrix: np.ndarray,
    y_true: np.ndarray,
    candidates: Sequence[int],
    accepted_probability: np.ndarray,
) -> dict[str, Any]:
    started = time.monotonic()
    cumulative = cumulative_probabilities(model, matrix, candidates)
    if not np.allclose(cumulative[max(candidates)][:, 1], accepted_probability, rtol=0.0, atol=1e-12):
        raise ValueError("accepted 300-tree binary probability parity failed")
    points = {}
    for count, probability in cumulative.items():
        attack_probability = probability[:, 1]
        prediction = (attack_probability >= 0.5).astype(np.uint8)
        points[str(count)] = {
            "metrics": rf_baseline.compute_metrics(y_true, prediction),
            "validation_log_loss": binary_log_loss(y_true, attack_probability),
        }
    return {"elapsed_seconds": time.monotonic() - started, "points": points}


def multiclass_curve(
    model: RandomForestClassifier,
    matrix: np.ndarray,
    y_true: np.ndarray,
    candidates: Sequence[int],
    accepted_probability: np.ndarray,
    class_order: Sequence[str],
    macro_order: Sequence[str],
) -> dict[str, Any]:
    started = time.monotonic()
    cumulative = cumulative_probabilities(model, matrix, candidates)
    if not np.allclose(cumulative[max(candidates)], accepted_probability, rtol=0.0, atol=1e-12):
        raise ValueError("accepted 300-tree multiclass probability parity failed")
    points = {}
    for count, probability in cumulative.items():
        metrics = known_family_rf.compute_metrics(y_true, probability, class_order, macro_order)
        points[str(count)] = {
            "metrics": metrics,
            "validation_log_loss": metrics["multiclass_log_loss"],
        }
    return {"elapsed_seconds": time.monotonic() - started, "points": points}


def select_tree_count(results: Mapping[str, Any], benchmark: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
    reference = str(benchmark["reference_tree_count"])
    binary_gate = benchmark["binary_gates"]
    multiclass_gate = benchmark["multiclass_gates"]
    decisions: dict[str, Any] = {}
    selected = int(reference)
    for candidate in benchmark["candidate_tree_counts"]:
        key = str(candidate)
        failures = []
        for role in ("flow_rf", "rf_stacker"):
            for checkpoint, record in results[role].items():
                metrics = record["points"][key]["metrics"]
                baseline = record["points"][reference]["metrics"]
                if baseline["macro_f1"] - metrics["macro_f1"] > binary_gate["macro_f1_max_drop"]:
                    failures.append(f"{role}/{checkpoint}/macro_f1")
                if baseline["recall"] - metrics["recall"] > binary_gate["attack_recall_max_drop"]:
                    failures.append(f"{role}/{checkpoint}/recall")
                if metrics["fpr"] - baseline["fpr"] > binary_gate["benign_fpr_max_increase"]:
                    failures.append(f"{role}/{checkpoint}/fpr")
        for checkpoint, record in results["known_family_rf"].items():
            metrics = record["points"][key]["metrics"]
            baseline = record["points"][reference]["metrics"]
            if baseline["macro_family_f1"] - metrics["macro_family_f1"] > multiclass_gate["macro_family_f1_max_drop"]:
                failures.append(f"known_family_rf/{checkpoint}/macro_family_f1")
            if baseline["balanced_accuracy_supported_families"] - metrics["balanced_accuracy_supported_families"] > multiclass_gate["balanced_accuracy_max_drop"]:
                failures.append(f"known_family_rf/{checkpoint}/balanced_accuracy")
        decisions[key] = {"passed": not failures, "failures": failures}
        if not failures and selected == int(reference):
            selected = candidate
    return selected, decisions


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, paths = verify_inputs(root, contract_path)
    output = resolve_inside(root, contract["optimization_benchmark"]["artifact"]["path"])
    if output.exists():
        raise FileExistsError("tree convergence benchmark already exists; refusing to overwrite evidence")
    output.parent.mkdir(parents=True, exist_ok=True)
    parts, input_features = _verified_parts(root, paths["snapshot_manifest"])
    bundles = {
        "flow_rf": joblib.load(paths["t4_2_model"]),
        "rf_stacker": joblib.load(paths["t4_5_model"]),
        "known_family_rf": joblib.load(paths["t4_6_model"]),
    }
    candidates = contract["optimization_benchmark"]["candidate_tree_counts"]
    results: dict[str, dict[str, Any]] = {name: {} for name in bundles}
    started = time.monotonic()
    with (
        np.load(paths["t4_2_validation_predictions"], allow_pickle=False) as baseline_predictions,
        np.load(paths["t4_3_validation_predictions"], allow_pickle=False) as anomaly_predictions,
        np.load(paths["t4_5_validation_predictions"], allow_pickle=False) as stacker_predictions,
        np.load(paths["t4_6_validation_predictions"], allow_pickle=False) as family_predictions,
    ):
        for checkpoint in contract["checkpoints"]:
            print(f"[T4.7] checkpoint={checkpoint} stage=materialize_validation", flush=True)
            profile = bundles["flow_rf"]["checkpoints"][checkpoint]["preprocessing_profile"]
            validation = materialize_validation(
                checkpoint, parts, paths["known_flow_map"], input_features, profile
            )
            y_binary = (validation["family"] != "BENIGN").astype(np.uint8)
            for field, observed in (
                ("capture_id", validation["capture_id"]),
                ("flow_id", validation["flow_id"]),
                ("y_true", y_binary),
            ):
                if not np.array_equal(observed, baseline_predictions[f"{checkpoint}__{field}"]):
                    raise ValueError(f"accepted validation identity mismatch: {checkpoint}/{field}")
            print(f"[T4.7] checkpoint={checkpoint} role=flow_rf stage=cumulative_vote", flush=True)
            results["flow_rf"][checkpoint] = binary_curve(
                bundles["flow_rf"]["checkpoints"][checkpoint]["model"],
                validation["matrix"],
                y_binary,
                candidates,
                baseline_predictions[f"{checkpoint}__attack_probability"],
            )
            meta = rf_stacker.load_validation_meta(anomaly_predictions, checkpoint)
            reordered, join = rf_stacker.keyed_reorder(
                meta["capture_id"], meta["flow_id"], meta["y_true"], meta["meta"],
                validation["capture_id"], validation["flow_id"], y_binary,
            )
            stacker_matrix = np.column_stack((validation["matrix"], reordered)).astype(np.float32)
            print(f"[T4.7] checkpoint={checkpoint} role=rf_stacker stage=cumulative_vote", flush=True)
            results["rf_stacker"][checkpoint] = binary_curve(
                bundles["rf_stacker"]["checkpoints"][checkpoint]["model"],
                stacker_matrix,
                y_binary,
                candidates,
                stacker_predictions[f"{checkpoint}__attack_probability"],
            )
            results["rf_stacker"][checkpoint]["validation_join"] = join
            attack_mask = y_binary == 1
            class_order = bundles["known_family_rf"]["labels"]["class_order"]
            label_index = {family: index for index, family in enumerate(class_order)}
            expected_family = family_predictions[f"{checkpoint}__y_true"]
            observed_family = validation["family"][attack_mask]
            if not np.array_equal(observed_family, expected_family):
                raise ValueError(f"accepted family labels mismatch: {checkpoint}/y_true")
            y_family = np.asarray([label_index[value] for value in expected_family], dtype=np.uint8)
            for field, observed in (
                ("capture_id", validation["capture_id"][attack_mask]),
                ("flow_id", validation["flow_id"][attack_mask]),
                ("y_true", expected_family),
            ):
                if not np.array_equal(observed, family_predictions[f"{checkpoint}__{field}"]):
                    raise ValueError(f"accepted family identity mismatch: {checkpoint}/{field}")
            print(f"[T4.7] checkpoint={checkpoint} role=known_family_rf stage=cumulative_vote", flush=True)
            results["known_family_rf"][checkpoint] = multiclass_curve(
                bundles["known_family_rf"]["checkpoints"][checkpoint]["model"],
                validation["matrix"][attack_mask],
                y_family,
                candidates,
                family_predictions[f"{checkpoint}__class_probability"],
                class_order,
                contract["family_scope"]["macro_aggregate"],
            )
    selected, decisions = select_tree_count(results, contract["optimization_benchmark"])
    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "stage": "optimization_benchmark",
        "status": "passed",
        "created_at_utc": utc_now(),
        "contract": {"path": contract_path.relative_to(root).as_posix(), "sha256": sha256_path(contract_path)},
        "source": {"path": "python/nids_mvp/tree_convergence.py", "sha256": sha256_path(Path(__file__))},
        "selection": {
            "selected_tree_count": selected,
            "reference_tree_count": contract["optimization_benchmark"]["reference_tree_count"],
            "estimated_training_fraction": selected / contract["optimization_benchmark"]["reference_tree_count"],
            "candidate_decisions": decisions,
        },
        "results": results,
        "elapsed_seconds": time.monotonic() - started,
        "validation": {
            "known_validation_only": True,
            "test_partition_loaded_or_scored": False,
            "accepted_300_tree_probability_parity": True,
            "all_prerequisite_hashes_verified": True,
            "hooks_read_or_run": False,
            "dependency_or_environment_mutation": False,
        },
    }
    write_json(output, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the T4.7 validation-only RF convergence benchmark")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--contract", default="config/cicids2017-loafo-contract.json")
    args = parser.parse_args()
    root = args.root.resolve()
    receipt = publish(root, resolve_inside(root, args.contract))
    print(json.dumps({"status": receipt["status"], "selection": receipt["selection"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
