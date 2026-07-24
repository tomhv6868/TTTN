from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import psutil
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from nids_mvp import anomaly_baseline, preprocessing, rf_baseline, rf_stacker


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


def merge_execution_contract(
    base: Mapping[str, Any], decision: Mapping[str, Any], contract: Mapping[str, Any]
) -> dict[str, Any]:
    override = contract["random_forest"]
    if (
        contract.get("task") != TASK
        or base.get("task") != TASK
        or decision.get("task") != TASK
        or decision.get("status") != "passed"
        or decision.get("decision") != "accepted"
        or decision.get("execution", {}).get("backend") != override.get("implementation")
        or decision.get("execution", {}).get("n_estimators") != override.get("final_tree_count")
        or decision.get("execution", {}).get("n_jobs") != override.get("n_jobs")
        or decision.get("evidence_policy", {}).get("overwrite_existing_evidence") is not False
        or decision.get("evidence_policy", {}).get("test_labels_allowed_for_fit_or_selection") is not False
        or decision.get("evidence_policy", {}).get("hooks_allowed") is not False
    ):
        raise ValueError("invalid T4.7 derived execution decision")
    merged = dict(base)
    merged["random_forest"] = {**base["random_forest"], **override}
    merged["execution_variant"] = contract["execution_variant"]
    merged["validation_override"] = contract["validation_override"]
    return merged


def load_execution_contract(root: Path, contract_path: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    contract = load_json(contract_path)
    if contract.get("contract_kind") != "derived_execution_override":
        return contract, {}
    references: dict[str, Path] = {}
    for name in ("base_contract", "user_decision"):
        reference = contract[name]
        path = resolve_inside(root, reference["path"])
        if (
            not path.is_file()
            or path.stat().st_size != reference["size_bytes"]
            or sha256_path(path) != reference["sha256"]
        ):
            raise ValueError(f"{name} content address mismatch")
        references[name] = path
    merged = merge_execution_contract(
        load_json(references["base_contract"]),
        load_json(references["user_decision"]),
        contract,
    )
    return merged, references


def resolve_inside(root: Path, value: str) -> Path:
    candidate = Path(value)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def verified_inputs(root: Path, contract_path: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    contract, paths = load_execution_contract(root, contract_path)
    if contract.get("task") != TASK or contract["validation"].get("hooks_excluded") is not True:
        raise ValueError("invalid T4.7 contract")
    for name, reference in contract["prerequisites"].items():
        path = resolve_inside(root, reference["path"])
        if (
            not path.is_file()
            or path.stat().st_size != reference["size_bytes"]
            or sha256_path(path) != reference["sha256"]
        ):
            raise ValueError(f"{name} content address mismatch")
        paths[name] = path
    benchmark_path = resolve_inside(root, contract["optimization_benchmark"]["artifact"]["path"])
    benchmark = load_json(benchmark_path)
    if (
        benchmark.get("status") != "passed"
        or benchmark.get("selection", {}).get("selected_tree_count") not in contract["optimization_benchmark"]["candidate_tree_counts"]
        or benchmark.get("validation", {}).get("test_partition_loaded_or_scored") is not False
    ):
        raise ValueError("invalid tree convergence benchmark")
    paths["tree_benchmark"] = benchmark_path
    return contract, paths


def verified_parts(root: Path, manifest_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    manifest = load_json(manifest_path)
    parts = []
    for record in manifest["parts"]:
        path = resolve_inside(root, record["path"])
        if (
            not path.is_file()
            or path.stat().st_size != record["size_bytes"]
            or sha256_path(path) != record["sha256"]
            or pq.ParquetFile(path).metadata.num_rows != record["rows"]
        ):
            raise ValueError(f"snapshot part mismatch: {record['path']}")
        parts.append({**record, "resolved_path": path})
    return parts, list(manifest["model_feature_columns"])


def load_capture_map(path: Path, capture_id: str) -> dict[int, tuple[str, str, int]]:
    table = pq.read_table(
        path,
        columns=["flow_id", "partition", "assigned_class", "time_block_index"],
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    ).to_pydict()
    result = {
        int(flow_id): (partition, family, int(block))
        for flow_id, partition, family, block in zip(
            table["flow_id"], table["partition"], table["assigned_class"], table["time_block_index"], strict=True
        )
    }
    if len(result) != len(table["flow_id"]):
        raise ValueError(f"duplicate flow-map key: {capture_id}")
    return result


def materialize_checkpoint(
    checkpoint: str,
    holdout: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    features: Sequence[str],
    expected: Mapping[str, Any],
) -> dict[str, np.ndarray]:
    raw = {"train": [], "eval": []}
    meta: dict[str, dict[str, list[Any]]] = {
        population: {name: [] for name in ("capture_id", "flow_id", "family", "partition", "time_block_index")}
        for population in ("train", "eval")
    }
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = rf_baseline.capture_from_path(record["path"])
        mapping = load_capture_map(flow_map, capture_id)
        columns = ["flow_id", "capture_id", "assigned_class", *features]
        for batch in pq.ParquetFile(record["resolved_path"]).iter_batches(columns=columns, batch_size=BATCH_ROWS):
            flow_ids = batch.column(0).to_pylist()
            captures = batch.column(1).to_pylist()
            families = batch.column(2).to_pylist()
            if any(value != capture_id for value in captures):
                raise ValueError(f"capture metadata drift: {record['path']}")
            rows = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(features))]
            ).astype(np.float64, copy=False)
            if np.isinf(rows).any():
                raise ValueError(f"infinite snapshot feature: {record['path']}")
            selected = {"train": [], "eval": []}
            selected_records = {"train": [], "eval": []}
            for index, (flow_id, family) in enumerate(zip(flow_ids, families, strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                partition, _, time_block = mapped
                population = None
                if partition == "train" and family != holdout:
                    population = "train"
                if partition == "test" or family == holdout:
                    population = "eval"
                if population is not None:
                    selected[population].append(index)
                    selected_records[population].append((flow_id, family, partition, time_block))
            for population in ("train", "eval"):
                indices = selected[population]
                if not indices:
                    continue
                raw[population].append(rows[indices])
                records = selected_records[population]
                meta[population]["capture_id"].extend(capture_id for _ in records)
                meta[population]["flow_id"].extend(value[0] for value in records)
                meta[population]["family"].extend(value[1] for value in records)
                meta[population]["partition"].extend(value[2] for value in records)
                meta[population]["time_block_index"].extend(value[3] for value in records)
    result: dict[str, np.ndarray] = {}
    for population in ("train", "eval"):
        result[f"x_{population}_raw"] = np.concatenate(raw[population], axis=0)
        result[f"{population}_capture_id"] = np.asarray(meta[population]["capture_id"], dtype="<U64")
        result[f"{population}_flow_id"] = np.asarray(meta[population]["flow_id"], dtype=np.uint64)
        result[f"{population}_family"] = np.asarray(meta[population]["family"], dtype="<U64")
        result[f"{population}_partition"] = np.asarray(meta[population]["partition"], dtype="<U16")
        result[f"{population}_time_block_index"] = np.asarray(meta[population]["time_block_index"], dtype=np.int64)
    if len(result["train_family"]) != expected["train"][checkpoint]:
        raise ValueError(f"LOAFO train population mismatch: {holdout}/{checkpoint}")
    if len(result["eval_family"]) != expected["test"][checkpoint]:
        raise ValueError(f"LOAFO evaluation population mismatch: {holdout}/{checkpoint}")
    valid_eval = (result["eval_partition"] == "test") | (result["eval_family"] == holdout)
    if np.any(result["train_family"] == holdout) or not np.all(valid_eval):
        raise ValueError(f"LOAFO selector invariant failed: {holdout}/{checkpoint}")
    return result


def fit_supervised_profile(matrix: np.ndarray, checkpoint: str, features: Sequence[str]) -> dict[str, Any]:
    imputer = SimpleImputer(strategy="median", keep_empty_features=True).fit(matrix)
    imputed = imputer.transform(matrix)
    scaler = StandardScaler(with_mean=True, with_std=True).fit(imputed)
    constants = np.flatnonzero(np.asarray(scaler.var_) == 0.0)
    constant_set = set(constants.tolist())
    selected = [index for index in range(len(features)) if index not in constant_set]
    profile = {
        "checkpoint": checkpoint,
        "profile": "supervised_known_loafo",
        "fit_population_rows": int(len(matrix)),
        "input_features": list(features),
        "input_dtype": "float64",
        "imputer": "median",
        "imputation_values": np.asarray(imputer.statistics_, dtype=np.float64).tolist(),
        "dropped_constant_features": [features[index] for index in constants],
        "selected_indices": selected,
        "selected_features": [features[index] for index in selected],
        "scaler": "standard",
        "scaler_mean": np.asarray(scaler.mean_, dtype=np.float64)[selected].tolist(),
        "scaler_scale": np.asarray(scaler.scale_, dtype=np.float64)[selected].tolist(),
        "output_dtype": "float32",
    }
    reference = scaler.transform(imputed[: min(257, len(imputed))])[:, selected].astype(np.float32)
    serving = preprocessing.transform_with_artifact(matrix[: len(reference)], features, profile)
    if not np.array_equal(reference, serving):
        raise ValueError(f"LOAFO train-serving parity failed: {checkpoint}")
    profile["parity"] = {
        "rows": len(reference),
        "status": "passed",
        "output_sha256": hashlib.sha256(serving.tobytes(order="C")).hexdigest(),
    }
    return profile


def subset_oof(source: Mapping[str, np.ndarray], capture: np.ndarray, flow: np.ndarray, y: np.ndarray) -> np.ndarray:
    result = np.empty((len(flow), source["meta"].shape[1]), dtype=np.float32)
    matched = 0
    for capture_id in np.unique(capture):
        source_indices = np.flatnonzero(source["capture_id"] == capture_id)
        target_indices = np.flatnonzero(capture == capture_id)
        order = np.argsort(source["flow_id"][source_indices], kind="stable")
        sorted_source = source_indices[order]
        positions = np.searchsorted(source["flow_id"][sorted_source], flow[target_indices])
        if np.any(positions >= len(sorted_source)):
            raise ValueError(f"OOF target outside source: {capture_id}")
        chosen = sorted_source[positions]
        if not np.array_equal(source["flow_id"][chosen], flow[target_indices]) or not np.array_equal(source["y_true"][chosen], y[target_indices]):
            raise ValueError(f"OOF keyed join mismatch: {capture_id}")
        result[target_indices] = source["meta"][chosen]
        matched += len(target_indices)
    if matched != len(flow) or not np.isfinite(result).all():
        raise ValueError("OOF subset join cardinality mismatch")
    return result


def binary_role_metrics(family: np.ndarray, holdout: str, prediction: np.ndarray) -> dict[str, Any]:
    roles = {
        "benign": family == "BENIGN",
        "known_attack": (family != "BENIGN") & (family != holdout),
        "unknown_holdout": family == holdout,
    }
    result = {}
    for role, mask in roles.items():
        result[role] = {
            "rows": int(np.count_nonzero(mask)),
            "positive_rate": None if not np.any(mask) else float(np.mean(prediction[mask])),
        }
    result["benign_fpr"] = result["benign"]["positive_rate"]
    result["known_attack_recall"] = result["known_attack"]["positive_rate"]
    result["unknown_holdout_recall"] = result["unknown_holdout"]["positive_rate"]
    return result


def rf_parameters(bundle: Mapping[str, Any], tree_count: int) -> dict[str, Any]:
    parameters = dict(bundle["random_forest_parameters"])
    parameters["n_estimators"] = tree_count
    return parameters


def train_family(root: Path, contract_path: Path, holdout: str) -> dict[str, Any]:
    contract, paths = verified_inputs(root, contract_path)
    if holdout not in contract["family_scope"]["execute_in_order"]:
        raise ValueError(f"family outside T4.7 execution scope: {holdout}")
    slug = holdout.lower().replace(" ", "-").replace("–", "-")
    output_root = resolve_inside(
        root, contract.get("execution_variant", {}).get("output_root", "run_log/t4.7")
    )
    output_dir = output_root / slug
    prediction_path = output_dir / "predictions.parquet"
    receipt_path = output_dir / "receipt.json"
    if prediction_path.exists() or receipt_path.exists():
        raise FileExistsError(f"LOAFO family evidence already exists: {holdout}")
    output_dir.mkdir(parents=True, exist_ok=True)
    parts, features = verified_parts(root, paths["snapshot_manifest"])
    loafo_manifest = load_json(paths["loafo_manifest"])
    experiment = next(value for value in loafo_manifest["experiments"] if value["holdout_family"] == holdout)
    benchmark = load_json(paths["tree_benchmark"])
    tree_count = int(
        contract["random_forest"].get(
            "final_tree_count", benchmark["selection"]["selected_tree_count"]
        )
    )
    if (
        tree_count not in contract["optimization_benchmark"]["candidate_tree_counts"]
        or contract["random_forest"].get("n_jobs", -1) != -1
    ):
        raise ValueError("invalid T4.7 Random Forest execution override")
    baseline_bundle = joblib.load(paths["t4_2_model"])
    anomaly_bundle = joblib.load(paths["t4_3_model"])
    stacker_bundle = joblib.load(paths["t4_5_model"])
    family_bundle = joblib.load(paths["t4_6_model"])
    class_order = [value for value in family_bundle["labels"]["class_order"] if value != holdout]
    class_index = {value: index for index, value in enumerate(class_order)}
    started = time.monotonic()
    process = psutil.Process()
    peak_rss = process.memory_info().rss
    checkpoint_receipts: dict[str, Any] = {}
    writer: pq.ParquetWriter | None = None
    with tempfile.TemporaryDirectory(prefix=f"nids-t47-{slug}-", dir=root / "run_log") as temporary:
        scratch = Path(temporary)
        prediction_temp = scratch / "predictions.parquet"
        for checkpoint in contract["checkpoints"]:
            checkpoint_started = time.monotonic()
            print(f"[T4.7] family={holdout} checkpoint={checkpoint} stage=materialize", flush=True)
            data = materialize_checkpoint(
                checkpoint, holdout, parts, paths["known_flow_map"], features, experiment["expected_snapshot_rows"]
            )
            peak_rss = max(peak_rss, process.memory_info().rss)
            profile = fit_supervised_profile(data["x_train_raw"], checkpoint, features)
            x_train = preprocessing.transform_with_artifact(data["x_train_raw"], features, profile)
            x_eval = preprocessing.transform_with_artifact(data["x_eval_raw"], features, profile)
            y_train = (data["train_family"] != "BENIGN").astype(np.uint8)
            y_eval = (data["eval_family"] != "BENIGN").astype(np.uint8)
            parameters = rf_parameters(baseline_bundle, tree_count)
            print(f"[T4.7] family={holdout} checkpoint={checkpoint} stage=train_flow_rf", flush=True)
            flow_model = RandomForestClassifier(**parameters).fit(x_train, y_train)
            flow_probability = rf_baseline.predict_attack_probability(flow_model, x_eval)
            flow_prediction = (flow_probability >= baseline_bundle["threshold"]).astype(np.uint8)
            anomaly_profile = anomaly_bundle["checkpoints"][checkpoint]["preprocessing_profile"]
            x_eval_anomaly = preprocessing.transform_with_artifact(data["x_eval_raw"], features, anomaly_profile)
            anomaly_checkpoint = anomaly_bundle["checkpoints"][checkpoint]
            hbos_raw = anomaly_baseline.score_hbos(anomaly_checkpoint["hbos"], x_eval_anomaly)
            hbos_score, hbos_prediction = anomaly_baseline.apply_score_decision(hbos_raw, anomaly_checkpoint["hbos"]["decision"])
            isolation_raw = anomaly_baseline.score_isolation_forest(anomaly_checkpoint["isolation_forest"]["estimator"], x_eval_anomaly)
            isolation_score, isolation_prediction = anomaly_baseline.apply_score_decision(
                isolation_raw, anomaly_checkpoint["isolation_forest"]["decision"]
            )
            eval_meta = rf_stacker.build_meta_matrix(hbos_score, isolation_score, hbos_prediction, isolation_prediction)
            oof = rf_stacker.load_oof_checkpoint(paths["t4_4_oof_meta_features"], checkpoint)
            train_meta = subset_oof(oof, data["train_capture_id"], data["train_flow_id"], y_train)
            x_train_stacker = np.column_stack((x_train, train_meta)).astype(np.float32)
            x_eval_stacker = np.column_stack((x_eval, eval_meta)).astype(np.float32)
            print(f"[T4.7] family={holdout} checkpoint={checkpoint} stage=train_stacker", flush=True)
            stacker_model = RandomForestClassifier(**rf_parameters(stacker_bundle, tree_count)).fit(x_train_stacker, y_train)
            stacker_probability = rf_baseline.predict_attack_probability(stacker_model, x_eval_stacker)
            stacker_prediction = (stacker_probability >= stacker_bundle["threshold"]).astype(np.uint8)
            attack_train = y_train == 1
            family_y_train = np.asarray([class_index[value] for value in data["train_family"][attack_train]], dtype=np.uint8)
            print(f"[T4.7] family={holdout} checkpoint={checkpoint} stage=train_known_family", flush=True)
            known_model = RandomForestClassifier(**rf_parameters(family_bundle, tree_count)).fit(x_train[attack_train], family_y_train)
            if known_model.classes_.tolist() != list(range(len(class_order))):
                raise ValueError(f"known-family class coverage mismatch: {holdout}/{checkpoint}")
            attack_eval = y_eval == 1
            known_probability = known_model.predict_proba(x_eval[attack_eval])
            order = np.argsort(known_probability, axis=1, kind="stable")
            top = order[:, -1]
            second = order[:, -2]
            top_class = np.full(len(y_eval), "", dtype="<U64")
            second_class = np.full(len(y_eval), "", dtype="<U64")
            top_probability = np.full(len(y_eval), np.nan, dtype=np.float64)
            second_probability = np.full(len(y_eval), np.nan, dtype=np.float64)
            labels = np.asarray(class_order, dtype="<U64")
            top_class[attack_eval] = labels[top]
            second_class[attack_eval] = labels[second]
            top_probability[attack_eval] = known_probability[np.arange(len(top)), top]
            second_probability[attack_eval] = known_probability[np.arange(len(second)), second]
            model_path = scratch / f"{checkpoint}-models.joblib"
            joblib.dump({"flow": flow_model, "stacker": stacker_model, "known": known_model}, model_path)
            reloaded = joblib.load(model_path)
            parity_rows = min(257, len(x_eval))
            reload_parity = {
                "flow": bool(np.allclose(flow_model.predict_proba(x_eval[:parity_rows]), reloaded["flow"].predict_proba(x_eval[:parity_rows]), rtol=0.0, atol=1e-15)),
                "stacker": bool(np.allclose(stacker_model.predict_proba(x_eval_stacker[:parity_rows]), reloaded["stacker"].predict_proba(x_eval_stacker[:parity_rows]), rtol=0.0, atol=1e-15)),
                "known": bool(np.allclose(known_model.predict_proba(x_eval[attack_eval][:parity_rows]), reloaded["known"].predict_proba(x_eval[attack_eval][:parity_rows]), rtol=0.0, atol=1e-15)),
            }
            if not all(reload_parity.values()):
                raise ValueError(f"temporary model reload parity failed: {holdout}/{checkpoint}")
            model_path.unlink()
            role = np.where(data["eval_family"] == holdout, "unknown_holdout", np.where(y_eval == 1, "known_attack", "benign"))
            table = pa.table({
                "checkpoint": np.full(len(y_eval), checkpoint),
                "capture_id": data["eval_capture_id"],
                "flow_id": data["eval_flow_id"],
                "time_block_index": data["eval_time_block_index"],
                "assigned_class": data["eval_family"],
                "source_partition": data["eval_partition"],
                "evaluation_role": role,
                "y_binary": y_eval,
                "flow_rf_probability": flow_probability,
                "flow_rf_prediction": flow_prediction,
                "hbos_normalized_score": hbos_score,
                "hbos_prediction": hbos_prediction,
                "isolation_forest_normalized_score": isolation_score,
                "isolation_forest_prediction": isolation_prediction,
                "anomaly_count": (hbos_prediction + isolation_prediction).astype(np.uint8),
                "anomaly_weighted_score": (0.5 * hbos_score + 0.5 * isolation_score),
                "stacker_probability": stacker_probability,
                "stacker_prediction": stacker_prediction,
                "known_top_class": top_class,
                "known_top_probability": top_probability,
                "known_second_class": second_class,
                "known_second_probability": second_probability,
            })
            if writer is None:
                writer = pq.ParquetWriter(prediction_temp, table.schema, compression="zstd")
            writer.write_table(table)
            known_mask = (data["eval_family"] != "BENIGN") & (data["eval_family"] != holdout)
            holdout_mask = data["eval_family"] == holdout
            known_top2 = (top_class[known_mask] == data["eval_family"][known_mask]) | (second_class[known_mask] == data["eval_family"][known_mask])
            checkpoint_receipts[checkpoint] = {
                "population": {
                    "train_rows": len(y_train),
                    "train_benign": int(np.count_nonzero(y_train == 0)),
                    "train_known_attack": int(np.count_nonzero(y_train == 1)),
                    "evaluation_rows": len(y_eval),
                    "evaluation_benign": int(np.count_nonzero(y_eval == 0)),
                    "evaluation_known_attack": int(np.count_nonzero(known_mask)),
                    "evaluation_unknown_holdout": int(np.count_nonzero(holdout_mask)),
                },
                "preprocessing": {
                    "fit_rows": profile["fit_population_rows"],
                    "selected_features": profile["selected_features"],
                    "dropped_constant_features": profile["dropped_constant_features"],
                    "parity": profile["parity"],
                },
                "metrics": {
                    "flow_rf": binary_role_metrics(data["eval_family"], holdout, flow_prediction),
                    "hbos": binary_role_metrics(data["eval_family"], holdout, hbos_prediction),
                    "isolation_forest": binary_role_metrics(data["eval_family"], holdout, isolation_prediction),
                    "rf_stacker": binary_role_metrics(data["eval_family"], holdout, stacker_prediction),
                    "known_family": {
                        "known_rows": int(np.count_nonzero(known_mask)),
                        "known_accuracy": float(np.mean(top_class[known_mask] == data["eval_family"][known_mask])),
                        "known_top_2_accuracy": float(np.mean(known_top2)),
                        "holdout_rows": int(np.count_nonzero(holdout_mask)),
                        "holdout_mean_top_confidence": float(np.mean(top_probability[holdout_mask])),
                    },
                },
                "feature_importance": {
                    "flow_rf": rf_stacker.named_feature_importance(flow_model, profile["selected_features"], [])["all"],
                    "rf_stacker": rf_stacker.named_feature_importance(
                        stacker_model, [*profile["selected_features"], *stacker_bundle["meta_feature_contract"]["order"]], stacker_bundle["meta_feature_contract"]["order"]
                    )["all"],
                },
                "reload_parity": reload_parity,
                "reload_parity_absolute_tolerance": 1e-15,
                "leakage_audit": {
                    "holdout_supervised_fit_rows": int(np.count_nonzero(data["train_family"] == holdout)),
                    "anomaly_models_refit": False,
                    "oof_train_meta_only": True,
                    "test_used_for_selection_or_fit": False,
                },
                "elapsed_seconds": time.monotonic() - checkpoint_started,
            }
            peak_rss = max(peak_rss, process.memory_info().rss)
            del data, x_train, x_eval, x_eval_anomaly, x_train_stacker, x_eval_stacker, oof
        if writer is not None:
            writer.close()
        os.replace(prediction_temp, prediction_path)
    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "stage": "loafo_family",
        "status": "passed",
        "holdout_family": holdout,
        "tree_count": tree_count,
        "execution_variant": contract.get(
            "execution_variant",
            {"id": "rf50-accelerated", "role": "accelerated_ablation", "output_root": "run_log/t4.7"},
        ),
        "contract": {"path": contract_path.relative_to(root).as_posix(), "sha256": sha256_path(contract_path)},
        "user_decision": None if "user_decision" not in paths else {
            "path": paths["user_decision"].relative_to(root).as_posix(),
            "sha256": sha256_path(paths["user_decision"]),
        },
        "tree_benchmark": {"path": paths["tree_benchmark"].relative_to(root).as_posix(), "sha256": sha256_path(paths["tree_benchmark"])},
        "prediction_artifact": {
            "path": prediction_path.relative_to(root).as_posix(),
            "size_bytes": prediction_path.stat().st_size,
            "sha256": sha256_path(prediction_path),
            "rows": pq.ParquetFile(prediction_path).metadata.num_rows,
        },
        "checkpoints": checkpoint_receipts,
        "resource_usage": {
            "elapsed_seconds": time.monotonic() - started,
            "peak_process_rss_bytes": peak_rss,
            "gpu_training_used": False,
        },
        "validation": {
            "holdout_absent_from_supervised_fit": all(value["leakage_audit"]["holdout_supervised_fit_rows"] == 0 for value in checkpoint_receipts.values()),
            "anomaly_models_benign_only_reused_without_refit": True,
            "test_labels_used_for_selection_or_fit": False,
            "temporary_models_retained": False,
            "all_reload_parity_passed": all(all(value["reload_parity"].values()) for value in checkpoint_receipts.values()),
            "hooks_read_or_run": False,
        },
    }
    with receipt_path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(receipt, output, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one restartable T4.7 LOAFO family stage")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--contract", default="config/cicids2017-loafo-contract.json")
    parser.add_argument("--family", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    receipt = train_family(root, resolve_inside(root, args.contract), args.family)
    print(json.dumps({"status": receipt["status"], "family": receipt["holdout_family"], "resource_usage": receipt["resource_usage"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
