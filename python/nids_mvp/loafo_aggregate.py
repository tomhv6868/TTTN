from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve

from nids_mvp import loafo


TASK = "T4.7"
BOOTSTRAP_SAMPLES = 10_000
BOOTSTRAP_SEED = 1729
CURVE_POINTS = 201
HISTOGRAM_BINS = 20
ACCEPTANCE_NAME = "acceptance.json"
REPORT_NAME = "report.vi.html"
CHECKPOINTS = ("F3", "F5", "F7", "F9")
ROLE_NAMES = ("benign", "known_attack", "unknown_holdout")
MODEL_SPECS = {
    "flow_rf": ("flow_rf_probability", "flow_rf_prediction", "Flow RF"),
    "hbos": ("hbos_normalized_score", "hbos_prediction", "HBOS"),
    "isolation_forest": (
        "isolation_forest_normalized_score",
        "isolation_forest_prediction",
        "Isolation Forest",
    ),
    "rf_stacker": ("stacker_probability", "stacker_prediction", "RF Stacker"),
}
EXPECTED_SCHEMA = pa.schema(
    [
        ("checkpoint", pa.string()),
        ("capture_id", pa.string()),
        ("flow_id", pa.uint64()),
        ("time_block_index", pa.int64()),
        ("assigned_class", pa.string()),
        ("source_partition", pa.string()),
        ("evaluation_role", pa.string()),
        ("y_binary", pa.uint8()),
        ("flow_rf_probability", pa.float64()),
        ("flow_rf_prediction", pa.uint8()),
        ("hbos_normalized_score", pa.float64()),
        ("hbos_prediction", pa.uint8()),
        ("isolation_forest_normalized_score", pa.float64()),
        ("isolation_forest_prediction", pa.uint8()),
        ("anomaly_count", pa.uint8()),
        ("anomaly_weighted_score", pa.float64()),
        ("stacker_probability", pa.float64()),
        ("stacker_prediction", pa.uint8()),
        ("known_top_class", pa.string()),
        ("known_top_probability", pa.float64()),
        ("known_second_class", pa.string()),
        ("known_second_probability", pa.float64()),
    ]
)
SCAN_COLUMNS = [
    "checkpoint",
    "assigned_class",
    "evaluation_role",
    "y_binary",
    "flow_rf_probability",
    "flow_rf_prediction",
    "hbos_normalized_score",
    "hbos_prediction",
    "isolation_forest_normalized_score",
    "isolation_forest_prediction",
    "stacker_probability",
    "stacker_prediction",
    "known_top_class",
    "known_top_probability",
    "known_second_class",
    "known_second_probability",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def family_slug(family: str) -> str:
    return family.lower().replace(" ", "-").replace("–", "-")


def _array(table: pa.Table, name: str) -> np.ndarray:
    column = table[name].combine_chunks()
    if pa.types.is_string(column.type):
        return np.asarray(column.to_pylist(), dtype=object)
    return column.to_numpy(zero_copy_only=False)


def _safe_rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        raise ValueError("metric denominator is zero")
    return float(numerator / denominator)


def bootstrap_mean(
    values: Sequence[float],
    samples: int = BOOTSTRAP_SAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, Any]:
    data = np.asarray(values, dtype=np.float64)
    if data.ndim != 1 or len(data) == 0 or not np.isfinite(data).all():
        raise ValueError("bootstrap values must be a non-empty finite vector")
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(data), size=(samples, len(data)))
    estimates = data[indices].mean(axis=1)
    low, high = np.quantile(estimates, [0.025, 0.975])
    return {
        "mean": float(data.mean()),
        "ci95_low": float(low),
        "ci95_high": float(high),
        "family_units": int(len(data)),
        "bootstrap_samples": int(samples),
        "bootstrap_seed": int(seed),
    }


def binary_novel_metrics(
    roles: np.ndarray,
    prediction: np.ndarray,
) -> dict[str, Any]:
    selected = (roles == "benign") | (roles == "unknown_holdout")
    y_true = roles[selected] == "unknown_holdout"
    y_pred = prediction[selected].astype(bool)
    if not np.any(y_true) or np.all(y_true):
        raise ValueError("novel detection requires benign and unknown rows")
    tn = int(np.count_nonzero(~y_true & ~y_pred))
    fp = int(np.count_nonzero(~y_true & y_pred))
    fn = int(np.count_nonzero(y_true & ~y_pred))
    tp = int(np.count_nonzero(y_true & y_pred))
    precision = _safe_rate(tp, tp + fp) if tp + fp else 0.0
    recall = _safe_rate(tp, tp + fn)
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "rows": int(len(y_true)),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": _safe_rate(fp, fp + tn),
    }


def _curve_summary(
    roles: np.ndarray,
    score: np.ndarray,
) -> dict[str, Any]:
    selected = (roles == "benign") | (roles == "unknown_holdout")
    y_true = (roles[selected] == "unknown_holdout").astype(np.uint8)
    selected_score = score[selected].astype(np.float64, copy=False)
    if not np.isfinite(selected_score).all():
        raise ValueError("non-finite detection score")
    fpr, tpr, _ = roc_curve(y_true, selected_score)
    precision, recall, _ = precision_recall_curve(y_true, selected_score)
    roc_grid = np.linspace(0.0, 1.0, CURVE_POINTS)
    recall_grid = np.linspace(0.0, 1.0, CURVE_POINTS)
    roc_values = np.interp(roc_grid, fpr, tpr)
    pr_values = np.interp(recall_grid, recall[::-1], precision[::-1])
    return {
        "roc_auc": float(roc_auc_score(y_true, selected_score)),
        "average_precision": float(average_precision_score(y_true, selected_score)),
        "roc_tpr": roc_values.tolist(),
        "pr_precision": pr_values.tolist(),
    }


def _histogram(values: np.ndarray) -> list[int]:
    clipped = np.clip(values.astype(np.float64, copy=False), 0.0, 1.0)
    counts, _ = np.histogram(clipped, bins=HISTOGRAM_BINS, range=(0.0, 1.0))
    return counts.astype(int).tolist()


def _assert_close(observed: float, expected: float, label: str) -> None:
    if not math.isclose(observed, expected, rel_tol=1e-12, abs_tol=1e-15):
        raise ValueError(f"metric mismatch: {label}")


def _validate_known_outputs(
    roles: np.ndarray,
    top_class: np.ndarray,
    second_class: np.ndarray,
    top_probability: np.ndarray,
    second_probability: np.ndarray,
    checkpoint: str,
) -> None:
    benign = roles == "benign"
    attack = ~benign
    if (
        np.any(top_class[benign] != "")
        or np.any(second_class[benign] != "")
        or not np.isnan(top_probability[benign]).all()
        or not np.isnan(second_probability[benign]).all()
        or np.any(top_class[attack] == "")
        or np.any(second_class[attack] == "")
    ):
        raise ValueError(f"invalid known-family applicability: {checkpoint}")
    attack_top = top_probability[attack]
    attack_second = second_probability[attack]
    if (
        not np.isfinite(attack_top).all()
        or not np.isfinite(attack_second).all()
        or np.any(attack_top < 0.0)
        or np.any(attack_top > 1.0)
        or np.any(attack_second < 0.0)
        or np.any(attack_second > 1.0)
        or np.any(attack_top < attack_second)
    ):
        raise ValueError(f"invalid known-family probability: {checkpoint}")


def summarize_checkpoint(
    table: pa.Table,
    checkpoint: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    roles = _array(table, "evaluation_role")
    assigned = _array(table, "assigned_class")
    y_binary = _array(table, "y_binary")
    observed_roles = set(roles.tolist())
    if observed_roles != set(ROLE_NAMES):
        raise ValueError(f"evaluation role mismatch: {checkpoint}")
    expected_y = (roles != "benign").astype(np.uint8)
    if not np.array_equal(y_binary, expected_y):
        raise ValueError(f"binary labels do not match roles: {checkpoint}")
    populations = {
        role: int(np.count_nonzero(roles == role))
        for role in ROLE_NAMES
    }
    expected_population = receipt["population"]
    population_fields = {
        "benign": "evaluation_benign",
        "known_attack": "evaluation_known_attack",
        "unknown_holdout": "evaluation_unknown_holdout",
    }
    for role, field in population_fields.items():
        if populations[role] != expected_population[field]:
            raise ValueError(f"population mismatch: {checkpoint}/{role}")
    if len(table) != expected_population["evaluation_rows"]:
        raise ValueError(f"evaluation row mismatch: {checkpoint}")

    model_summaries: dict[str, Any] = {}
    for model, (score_column, prediction_column, _) in MODEL_SPECS.items():
        score = _array(table, score_column)
        prediction = _array(table, prediction_column)
        if (
            prediction.dtype != np.uint8
            or not np.isfinite(score).all()
            or not np.isin(prediction, [0, 1]).all()
        ):
            raise ValueError(f"invalid model output: {checkpoint}/{model}")
        operating: dict[str, Any] = {}
        for role in ROLE_NAMES:
            mask = roles == role
            positive_rate = float(prediction[mask].mean())
            expected = receipt["metrics"][model][role]
            if int(np.count_nonzero(mask)) != expected["rows"]:
                raise ValueError(f"role row mismatch: {checkpoint}/{model}/{role}")
            _assert_close(
                positive_rate,
                expected["positive_rate"],
                f"{checkpoint}/{model}/{role}",
            )
            operating[role] = {
                "rows": int(np.count_nonzero(mask)),
                "positive_rate": positive_rate,
            }
        novel = binary_novel_metrics(roles, prediction)
        curves = _curve_summary(roles, score)
        model_summaries[model] = {
            "operating": operating,
            "novel_detection": novel,
            **curves,
            "score_histogram": {
                role: _histogram(score[roles == role])
                for role in ROLE_NAMES
            },
        }

    top_class = _array(table, "known_top_class")
    second_class = _array(table, "known_second_class")
    top_probability = _array(table, "known_top_probability")
    second_probability = _array(table, "known_second_probability")
    _validate_known_outputs(
        roles,
        top_class,
        second_class,
        top_probability,
        second_probability,
        checkpoint,
    )
    known = roles == "known_attack"
    unknown = roles == "unknown_holdout"
    known_accuracy = float(np.mean(top_class[known] == assigned[known]))
    known_top2 = float(
        np.mean((top_class[known] == assigned[known]) | (second_class[known] == assigned[known]))
    )
    holdout_confidence = float(np.mean(top_probability[unknown]))
    expected_known = receipt["metrics"]["known_family"]
    for observed, key in (
        (known_accuracy, "known_accuracy"),
        (known_top2, "known_top_2_accuracy"),
        (holdout_confidence, "holdout_mean_top_confidence"),
    ):
        _assert_close(observed, expected_known[key], f"{checkpoint}/known_family/{key}")
    if (
        int(np.count_nonzero(known)) != expected_known["known_rows"]
        or int(np.count_nonzero(unknown)) != expected_known["holdout_rows"]
    ):
        raise ValueError(f"known-family population mismatch: {checkpoint}")
    return {
        "population": populations,
        "models": model_summaries,
        "known_family": {
            "known_rows": int(np.count_nonzero(known)),
            "holdout_rows": int(np.count_nonzero(unknown)),
            "known_accuracy": known_accuracy,
            "known_top_2_accuracy": known_top2,
            "holdout_mean_top_confidence": holdout_confidence,
            "confidence_histogram": {
                "known_attack": _histogram(top_probability[known]),
                "unknown_holdout": _histogram(top_probability[unknown]),
            },
        },
    }


def summarize_predictions(
    prediction_path: Path,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    parquet = pq.ParquetFile(prediction_path)
    if not parquet.schema_arrow.equals(EXPECTED_SCHEMA, check_metadata=False):
        raise ValueError(f"prediction schema mismatch: {prediction_path}")
    if parquet.num_row_groups != len(CHECKPOINTS):
        raise ValueError(f"prediction row-group count mismatch: {prediction_path}")
    checkpoints: dict[str, Any] = {}
    for row_group in range(parquet.num_row_groups):
        table = parquet.read_row_group(row_group, columns=SCAN_COLUMNS)
        checkpoint_values = set(_array(table, "checkpoint").tolist())
        if len(checkpoint_values) != 1:
            raise ValueError(f"mixed checkpoint row group: {prediction_path}/{row_group}")
        checkpoint = checkpoint_values.pop()
        if checkpoint not in CHECKPOINTS or checkpoint in checkpoints:
            raise ValueError(f"invalid checkpoint row group: {prediction_path}/{checkpoint}")
        checkpoints[checkpoint] = summarize_checkpoint(
            table,
            checkpoint,
            receipt["checkpoints"][checkpoint],
        )
    if tuple(checkpoints) != CHECKPOINTS:
        raise ValueError(f"checkpoint order mismatch: {prediction_path}")
    return {
        "rows": int(parquet.metadata.num_rows),
        "checkpoints": checkpoints,
    }


def _validation_passed(receipt: Mapping[str, Any]) -> bool:
    validation = receipt.get("validation", {})
    return bool(
        validation.get("holdout_absent_from_supervised_fit")
        and validation.get("anomaly_models_benign_only_reused_without_refit")
        and validation.get("all_reload_parity_passed")
        and validation.get("test_labels_used_for_selection_or_fit") is False
        and validation.get("hooks_read_or_run") is False
        and all(
            checkpoint["leakage_audit"]["holdout_supervised_fit_rows"] == 0
            and checkpoint["leakage_audit"]["test_used_for_selection_or_fit"] is False
            and checkpoint["leakage_audit"]["anomaly_models_refit"] is False
            and all(checkpoint["reload_parity"].values())
            for checkpoint in receipt.get("checkpoints", {}).values()
        )
    )


def verify_family(
    root: Path,
    contract_path: Path,
    contract: Mapping[str, Any],
    paths: Mapping[str, Path],
    family: str,
) -> dict[str, Any]:
    slug = family_slug(family)
    output_root = loafo.resolve_inside(root, contract["execution_variant"]["output_root"])
    family_root = output_root / slug
    receipt_path = family_root / "receipt.json"
    prediction_path = family_root / "predictions.parquet"
    if not receipt_path.is_file() or not prediction_path.is_file():
        raise ValueError(f"missing RF300 family evidence: {family}")
    receipt = loafo.load_json(receipt_path)
    expected_contract_hash = loafo.sha256_path(contract_path)
    expected_decision_hash = loafo.sha256_path(paths["user_decision"])
    expected_benchmark_hash = loafo.sha256_path(paths["tree_benchmark"])
    prediction_record = receipt.get("prediction_artifact", {})
    if (
        receipt.get("task") != TASK
        or receipt.get("status") != "passed"
        or receipt.get("holdout_family") != family
        or receipt.get("tree_count") != 300
        or receipt.get("execution_variant", {}).get("id") != "rf300-primary"
        or receipt.get("execution_variant", {}).get("role") != "primary_final"
        or receipt.get("contract", {}).get("sha256") != expected_contract_hash
        or receipt.get("user_decision", {}).get("sha256") != expected_decision_hash
        or receipt.get("tree_benchmark", {}).get("sha256") != expected_benchmark_hash
        or tuple(receipt.get("checkpoints", {})) != CHECKPOINTS
        or not _validation_passed(receipt)
    ):
        raise ValueError(f"invalid RF300 family receipt: {family}")
    if (
        prediction_record.get("path") != prediction_path.relative_to(root).as_posix()
        or prediction_record.get("size_bytes") != prediction_path.stat().st_size
        or prediction_record.get("sha256") != loafo.sha256_path(prediction_path)
        or prediction_record.get("rows") != pq.ParquetFile(prediction_path).metadata.num_rows
    ):
        raise ValueError(f"RF300 prediction content mismatch: {family}")
    prediction_summary = summarize_predictions(prediction_path, receipt)
    if prediction_summary["rows"] != prediction_record["rows"]:
        raise ValueError(f"RF300 prediction row mismatch: {family}")

    prior_root = loafo.resolve_inside(
        root,
        contract["execution_variant"]["prior_variant"]["output_root"],
    )
    prior_receipt_path = prior_root / slug / "receipt.json"
    if not prior_receipt_path.is_file():
        raise ValueError(f"missing preserved RF50 receipt: {family}")
    prior_receipt = loafo.load_json(prior_receipt_path)
    if (
        prior_receipt.get("status") != "passed"
        or prior_receipt.get("holdout_family") != family
        or prior_receipt.get("tree_count") != 50
        or prior_receipt.get("contract", {}).get("sha256") != loafo.sha256_path(paths["base_contract"])
        or not _validation_passed(prior_receipt)
    ):
        raise ValueError(f"invalid preserved RF50 receipt: {family}")
    return {
        "family": family,
        "receipt": receipt,
        "prediction": prediction_summary,
        "evidence": {
            "rf300_receipt": {
                "path": receipt_path.relative_to(root).as_posix(),
                "size_bytes": receipt_path.stat().st_size,
                "sha256": loafo.sha256_path(receipt_path),
            },
            "rf300_predictions": {
                "path": prediction_path.relative_to(root).as_posix(),
                "size_bytes": prediction_path.stat().st_size,
                "sha256": prediction_record["sha256"],
                "rows": prediction_record["rows"],
            },
            "rf50_receipt": {
                "path": prior_receipt_path.relative_to(root).as_posix(),
                "size_bytes": prior_receipt_path.stat().st_size,
                "sha256": loafo.sha256_path(prior_receipt_path),
            },
        },
        "rf50_receipt": prior_receipt,
    }


def _normalized_histogram(counts: Sequence[int]) -> np.ndarray:
    values = np.asarray(counts, dtype=np.float64)
    if values.sum() == 0:
        raise ValueError("empty histogram")
    return values / values.sum()


def _mean_histograms(histograms: Sequence[Sequence[int]]) -> list[float]:
    return np.mean([_normalized_histogram(value) for value in histograms], axis=0).tolist()


def _aggregate_feature_importance(
    families: Sequence[Mapping[str, Any]],
    checkpoint: str,
    model: str,
) -> list[dict[str, Any]]:
    by_family: list[dict[str, float]] = []
    features: set[str] = set()
    for family in families:
        values = {
            record["feature"]: float(record["importance"])
            for record in family["receipt"]["checkpoints"][checkpoint]["feature_importance"][model]
        }
        by_family.append(values)
        features.update(values)
    aggregate = [
        {
            "feature": feature,
            "mean_importance": float(np.mean([values.get(feature, 0.0) for values in by_family])),
        }
        for feature in features
    ]
    return sorted(aggregate, key=lambda value: (-value["mean_importance"], value["feature"]))


def _public_family_result(
    family: Mapping[str, Any],
    scope: str,
) -> dict[str, Any]:
    checkpoints: dict[str, Any] = {}
    for checkpoint in CHECKPOINTS:
        prediction = family["prediction"]["checkpoints"][checkpoint]
        checkpoints[checkpoint] = {
            "population": prediction["population"],
            "models": {
                model: {
                    "unknown_holdout_recall": values["operating"]["unknown_holdout"]["positive_rate"],
                    "known_attack_recall": values["operating"]["known_attack"]["positive_rate"],
                    "benign_fpr": values["operating"]["benign"]["positive_rate"],
                    "novel_detection": values["novel_detection"],
                    "roc_auc": values["roc_auc"],
                    "average_precision": values["average_precision"],
                }
                for model, values in prediction["models"].items()
            },
            "known_family": {
                key: value
                for key, value in prediction["known_family"].items()
                if key != "confidence_histogram"
            },
        }
    receipt = family["receipt"]
    return {
        "scope": scope,
        "prediction_rows": family["prediction"]["rows"],
        "elapsed_seconds": receipt["resource_usage"]["elapsed_seconds"],
        "peak_process_rss_bytes": receipt["resource_usage"]["peak_process_rss_bytes"],
        "gpu_training_used": receipt["resource_usage"]["gpu_training_used"],
        "checkpoints": checkpoints,
    }


def aggregate_macro(
    families: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if len(families) != 9:
        raise ValueError("T4.7 macro aggregate requires exactly nine families")
    result: dict[str, Any] = {"family_count": len(families), "checkpoints": {}}
    for checkpoint in CHECKPOINTS:
        checkpoint_result: dict[str, Any] = {"models": {}}
        for model in MODEL_SPECS:
            values = [
                family["prediction"]["checkpoints"][checkpoint]["models"][model]
                for family in families
            ]
            metric_vectors = {
                "unknown_holdout_recall": [
                    value["operating"]["unknown_holdout"]["positive_rate"] for value in values
                ],
                "known_attack_recall": [
                    value["operating"]["known_attack"]["positive_rate"] for value in values
                ],
                "benign_fpr": [
                    value["operating"]["benign"]["positive_rate"] for value in values
                ],
                "novel_f1": [value["novel_detection"]["f1"] for value in values],
                "roc_auc": [value["roc_auc"] for value in values],
                "average_precision": [value["average_precision"] for value in values],
            }
            confusion = np.sum(
                [value["novel_detection"]["confusion_matrix"] for value in values],
                axis=0,
                dtype=np.int64,
            )
            checkpoint_result["models"][model] = {
                "metrics": {
                    metric: bootstrap_mean(vector)
                    for metric, vector in metric_vectors.items()
                },
                "pooled_experiment_confusion_matrix": confusion.tolist(),
                "roc_curve": {
                    "fpr_grid": np.linspace(0.0, 1.0, CURVE_POINTS).tolist(),
                    "mean_tpr": np.mean([value["roc_tpr"] for value in values], axis=0).tolist(),
                },
                "pr_curve": {
                    "recall_grid": np.linspace(0.0, 1.0, CURVE_POINTS).tolist(),
                    "mean_precision": np.mean(
                        [value["pr_precision"] for value in values],
                        axis=0,
                    ).tolist(),
                },
                "score_histogram": {
                    role: _mean_histograms(
                        [value["score_histogram"][role] for value in values]
                    )
                    for role in ROLE_NAMES
                },
            }
        checkpoint_result["known_family_confidence_histogram"] = {
            role: _mean_histograms(
                [
                    family["prediction"]["checkpoints"][checkpoint]["known_family"][
                        "confidence_histogram"
                    ][role]
                    for family in families
                ]
            )
            for role in ("known_attack", "unknown_holdout")
        }
        checkpoint_result["feature_importance"] = {
            model: _aggregate_feature_importance(families, checkpoint, model)
            for model in ("flow_rf", "rf_stacker")
        }
        result["checkpoints"][checkpoint] = checkpoint_result
    return result


def compare_rf50_rf300(
    families: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {"checkpoints": {}}
    for checkpoint in CHECKPOINTS:
        result["checkpoints"][checkpoint] = {}
        for model in ("flow_rf", "rf_stacker"):
            rf50 = np.asarray(
                [
                    family["rf50_receipt"]["checkpoints"][checkpoint]["metrics"][model][
                        "unknown_holdout_recall"
                    ]
                    for family in families
                ],
                dtype=np.float64,
            )
            rf300 = np.asarray(
                [
                    family["prediction"]["checkpoints"][checkpoint]["models"][model][
                        "operating"
                    ]["unknown_holdout"]["positive_rate"]
                    for family in families
                ],
                dtype=np.float64,
            )
            result["checkpoints"][checkpoint][model] = {
                "rf50_macro_mean": float(rf50.mean()),
                "rf300_macro_mean": float(rf300.mean()),
                "paired_delta_rf300_minus_rf50": bootstrap_mean(rf300 - rf50),
                "per_family": [
                    {
                        "family": family["family"],
                        "rf50": float(left),
                        "rf300": float(right),
                        "delta": float(right - left),
                    }
                    for family, left, right in zip(families, rf50, rf300, strict=True)
                ],
            }
    return result


def build_analysis(
    root: Path,
    contract_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract, paths = loafo.verified_inputs(root, contract_path)
    if (
        contract.get("execution_variant", {}).get("id") != "rf300-primary"
        or contract.get("random_forest", {}).get("final_tree_count") != 300
        or contract["family_scope"].get("macro_aggregate") is None
    ):
        raise ValueError("aggregate requires the RF300 primary execution contract")
    expected = contract["family_scope"]["execute_in_order"]
    macro_order = contract["family_scope"]["macro_aggregate"]
    case_order = contract["family_scope"]["case_study_only"]
    if (
        len(expected) != 13
        or len(macro_order) != 9
        or len(case_order) != 4
        or expected != [*macro_order, *case_order]
    ):
        raise ValueError("invalid T4.7 family scope")
    families = [
        verify_family(root, contract_path, contract, paths, family)
        for family in expected
    ]
    by_name = {family["family"]: family for family in families}
    macro_families = [by_name[name] for name in macro_order]
    benchmark = loafo.load_json(paths["tree_benchmark"])
    analysis = {
        "policy": {
            "macro_unit": "holdout_family",
            "macro_weighting": "equal_weight_per_family",
            "macro_family_order": macro_order,
            "case_study_family_order": case_order,
            "case_studies_excluded_from_macro": True,
            "confidence_interval": {
                "method": "percentile_bootstrap_over_family_units",
                "level": 0.95,
                "samples": BOOTSTRAP_SAMPLES,
                "seed": BOOTSTRAP_SEED,
            },
            "roc_pr": "per-family novel-vs-benign curves interpolated then macro-averaged",
            "loss": "known-validation log-loss by tree count; Random Forest has no epoch training loss",
            "improvement_claim_deferred_to_t4_8": True,
        },
        "input_evidence": {
            family["family"]: family["evidence"]
            for family in families
        },
        "per_family": {
            family["family"]: _public_family_result(
                family,
                "macro" if family["family"] in macro_order else "case_study_only",
            )
            for family in families
        },
        "macro_aggregate": aggregate_macro(macro_families),
        "rf50_comparison": compare_rf50_rf300(macro_families),
        "resource_usage": {
            "receipt_wall_seconds": float(
                sum(family["receipt"]["resource_usage"]["elapsed_seconds"] for family in families)
            ),
            "max_peak_process_rss_bytes": int(
                max(
                    family["receipt"]["resource_usage"]["peak_process_rss_bytes"]
                    for family in families
                )
            ),
            "gpu_trained_family_count": int(
                sum(
                    bool(family["receipt"]["resource_usage"]["gpu_training_used"])
                    for family in families
                )
            ),
            "gpu_utilization_telemetry_collected": False,
        },
        "totals": {
            "families": len(families),
            "macro_families": len(macro_order),
            "case_studies": len(case_order),
            "prediction_rows": int(sum(family["prediction"]["rows"] for family in families)),
        },
    }
    return analysis, benchmark


def _fmt(value: float, digits: int = 4) -> str:
    return f"{value:.{digits}f}"


def _line_svg(
    x: Sequence[float],
    series: Mapping[str, Sequence[float]],
    title: str,
    y_min: float | None = None,
    y_max: float | None = None,
) -> str:
    width, height = 700, 320
    left, right, top, bottom = 58, 18, 42, 42
    plot_w, plot_h = width - left - right, height - top - bottom
    x_values = np.asarray(x, dtype=np.float64)
    all_y = np.concatenate([np.asarray(value, dtype=np.float64) for value in series.values()])
    low = float(all_y.min()) if y_min is None else y_min
    high = float(all_y.max()) if y_max is None else y_max
    if math.isclose(low, high):
        low, high = low - 0.05, high + 0.05
    pad = (high - low) * 0.05
    if y_min is None:
        low -= pad
    if y_max is None:
        high += pad
    x_low, x_high = float(x_values.min()), float(x_values.max())
    colors = ("#2563eb", "#dc2626", "#059669", "#7c3aed", "#d97706")
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="{left}" y="24" class="chart-title">{html.escape(title)}</text>',
    ]
    for tick in range(6):
        fraction = tick / 5
        y_pos = top + plot_h * (1.0 - fraction)
        value = low + (high - low) * fraction
        parts.append(
            f'<line x1="{left}" y1="{y_pos:.1f}" x2="{left + plot_w}" y2="{y_pos:.1f}" class="grid"/>'
        )
        parts.append(
            f'<text x="{left - 8}" y="{y_pos + 4:.1f}" text-anchor="end" class="axis">{value:.3f}</text>'
        )
    for tick in range(6):
        fraction = tick / 5
        x_pos = left + plot_w * fraction
        value = x_low + (x_high - x_low) * fraction
        parts.append(
            f'<text x="{x_pos:.1f}" y="{height - 14}" text-anchor="middle" class="axis">{value:.2f}</text>'
        )
    for index, (label, values) in enumerate(series.items()):
        y_values = np.asarray(values, dtype=np.float64)
        points = []
        for x_value, y_value in zip(x_values, y_values, strict=True):
            x_pos = left + plot_w * (x_value - x_low) / (x_high - x_low)
            y_pos = top + plot_h * (high - y_value) / (high - low)
            points.append(f"{x_pos:.2f},{y_pos:.2f}")
        color = colors[index % len(colors)]
        parts.append(
            f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}" stroke-width="2.4"/>'
        )
        legend_x = left + (index % 3) * 190
        legend_y = height - 2 + (index // 3) * 16
        parts.append(
            f'<text x="{legend_x}" y="{legend_y}" fill="{color}" class="legend">{html.escape(label)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _bar_svg(labels: Sequence[str], values: Sequence[float], title: str) -> str:
    width = 700
    row_height = 24
    height = 52 + row_height * len(labels)
    left, right = 210, 70
    plot_w = width - left - right
    maximum = max(values) if values else 1.0
    if maximum <= 0.0:
        maximum = 1.0
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="12" y="24" class="chart-title">{html.escape(title)}</text>',
    ]
    for index, (label, value) in enumerate(zip(labels, values, strict=True)):
        y = 40 + index * row_height
        bar_width = plot_w * value / maximum
        parts.extend(
            [
                f'<text x="{left - 8}" y="{y + 13}" text-anchor="end" class="axis">{html.escape(label)}</text>',
                f'<rect x="{left}" y="{y}" width="{bar_width:.2f}" height="16" rx="3" fill="#2563eb"/>',
                f'<text x="{left + bar_width + 6:.2f}" y="{y + 13}" class="axis">{value:.4f}</text>',
            ]
        )
    parts.append("</svg>")
    return "".join(parts)


def _heatmap_svg(
    rows: Sequence[str],
    columns: Sequence[str],
    values: Sequence[Sequence[float]],
    title: str,
) -> str:
    cell_w, cell_h = 92, 30
    left, top = 190, 54
    width = left + cell_w * len(columns) + 20
    height = top + cell_h * len(rows) + 24
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        f'<text x="12" y="24" class="chart-title">{html.escape(title)}</text>',
    ]
    for column, label in enumerate(columns):
        parts.append(
            f'<text x="{left + column * cell_w + cell_w / 2}" y="{top - 12}" text-anchor="middle" class="axis">{html.escape(label)}</text>'
        )
    for row, label in enumerate(rows):
        y = top + row * cell_h
        parts.append(
            f'<text x="{left - 8}" y="{y + 20}" text-anchor="end" class="axis">{html.escape(label)}</text>'
        )
        for column, value in enumerate(values[row]):
            bounded = max(0.0, min(1.0, value))
            red = int(242 - 190 * bounded)
            green = int(248 - 90 * bounded)
            blue = int(255 - 50 * bounded)
            x = left + column * cell_w
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_w - 2}" height="{cell_h - 2}" fill="rgb({red},{green},{blue})"/>'
            )
            parts.append(
                f'<text x="{x + (cell_w - 2) / 2}" y="{y + 19}" text-anchor="middle" class="cell">{value:.3f}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def _confusion_html(matrix: Sequence[Sequence[int]], title: str) -> str:
    return (
        '<div class="matrix-card">'
        f"<h4>{html.escape(title)}</h4>"
        '<table class="matrix"><tr><th></th><th>Dự đoán 0</th><th>Dự đoán 1</th></tr>'
        f"<tr><th>Thật 0</th><td>{matrix[0][0]:,}</td><td>{matrix[0][1]:,}</td></tr>"
        f"<tr><th>Thật 1</th><td>{matrix[1][0]:,}</td><td>{matrix[1][1]:,}</td></tr></table></div>"
    )


def _report_styles() -> str:
    return """
body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;background:#f6f8fb;color:#172033}
main{max-width:1480px;margin:auto;padding:28px}.hero{background:#111827;color:white;padding:28px;border-radius:18px}
h1,h2,h3,h4{margin-top:0}h2{margin-top:34px;border-bottom:2px solid #dbe3ef;padding-bottom:8px}
.cards,.charts,.matrix-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:14px}
.card,.chart,.matrix-card{background:white;border:1px solid #dbe3ef;border-radius:12px;padding:16px;overflow:auto}
.metric{font-size:28px;font-weight:700;color:#2563eb}.muted{color:#667085}.warning{background:#fff7ed;border-left:5px solid #f97316;padding:14px}
table{border-collapse:collapse;width:100%;background:white}th,td{border:1px solid #dbe3ef;padding:7px;text-align:right}
th:first-child,td:first-child{text-align:left}th{background:#eef3f9}.matrix td{text-align:center;font-size:17px;font-weight:650}
svg{width:100%;height:auto}.grid{stroke:#dbe3ef;stroke-width:1}.axis{font-size:11px;fill:#536176}
.chart-title{font-size:15px;font-weight:700;fill:#172033}.legend{font-size:11px;font-weight:650}.cell{font-size:11px;font-weight:700;fill:#111827}
code{background:#e9eef5;padding:2px 5px;border-radius:4px}.good{color:#047857}.bad{color:#b42318}
"""


def render_report(
    analysis: Mapping[str, Any],
    benchmark: Mapping[str, Any],
) -> bytes:
    macro = analysis["macro_aggregate"]
    policy = analysis["policy"]
    family_order = policy["macro_family_order"]
    case_order = policy["case_study_family_order"]
    parts = [
        "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>T4.7 — Báo cáo LOAFO RF300</title><style>",
        _report_styles(),
        "</style></head><body><main>",
        '<section class="hero"><h1>T4.7 — LOAFO RF300</h1>',
        "<p>Báo cáo kỹ thuật tự chứa cho 13 thí nghiệm leave-one-attack-family-out, "
        "với Random Forest 300 cây là nhánh primary-final và RF50 được giữ làm accelerated ablation.</p></section>",
        "<h2>Tổng quan bằng chứng</h2><div class=\"cards\">",
        f'<div class="card"><div class="metric">{analysis["totals"]["families"]}/13</div><div>Family hoàn tất</div></div>',
        f'<div class="card"><div class="metric">{analysis["totals"]["prediction_rows"]:,}</div><div>Dòng prediction</div></div>',
        f'<div class="card"><div class="metric">{analysis["resource_usage"]["max_peak_process_rss_bytes"]/2**30:.2f} GiB</div><div>Peak RSS lớn nhất</div></div>',
        f'<div class="card"><div class="metric">{analysis["resource_usage"]["gpu_trained_family_count"]}</div><div>Family dùng GPU</div></div>',
        "</div>",
        '<p class="warning"><strong>Ranh giới diễn giải:</strong> macro dùng chín family với trọng số bằng nhau. '
        "Bốn family hiếm chỉ là case study. CI bootstrap 95% là mô tả độ biến thiên giữa family; "
        "mọi tuyên bố cải thiện được hoãn sang T4.8.</p>",
        "<h3>Phạm vi macro</h3><p>",
        html.escape(", ".join(family_order)),
        "</p><h3>Case study tách riêng</h3><p>",
        html.escape(", ".join(case_order)),
        "</p>",
        "<h2>RF300 so với RF50</h2>",
        "<table><tr><th>Checkpoint</th><th>Model</th><th>RF50 macro recall</th>"
        "<th>RF300 macro recall</th><th>Delta</th><th>CI95 delta</th></tr>",
    ]
    for checkpoint in CHECKPOINTS:
        for model in ("flow_rf", "rf_stacker"):
            value = analysis["rf50_comparison"]["checkpoints"][checkpoint][model]
            delta = value["paired_delta_rf300_minus_rf50"]
            parts.append(
                "<tr>"
                f"<td>{checkpoint}</td><td>{MODEL_SPECS[model][2]}</td>"
                f"<td>{_fmt(value['rf50_macro_mean'])}</td>"
                f"<td>{_fmt(value['rf300_macro_mean'])}</td>"
                f"<td>{_fmt(delta['mean'])}</td>"
                f"<td>[{_fmt(delta['ci95_low'])}, {_fmt(delta['ci95_high'])}]</td></tr>"
            )
    parts.append("</table>")

    parts.extend(
        [
            "<h2>Macro metric trên chín family</h2>",
            "<table><tr><th>Checkpoint</th><th>Model</th><th>Unknown recall (CI95)</th>"
            "<th>Benign FPR (CI95)</th><th>Novel F1 (CI95)</th><th>ROC AUC</th><th>AP</th></tr>",
        ]
    )
    for checkpoint in CHECKPOINTS:
        for model in MODEL_SPECS:
            metrics = macro["checkpoints"][checkpoint]["models"][model]["metrics"]
            parts.append(
                "<tr>"
                f"<td>{checkpoint}</td><td>{MODEL_SPECS[model][2]}</td>"
                f"<td>{_fmt(metrics['unknown_holdout_recall']['mean'])} "
                f"[{_fmt(metrics['unknown_holdout_recall']['ci95_low'])}, {_fmt(metrics['unknown_holdout_recall']['ci95_high'])}]</td>"
                f"<td>{_fmt(metrics['benign_fpr']['mean'])} "
                f"[{_fmt(metrics['benign_fpr']['ci95_low'])}, {_fmt(metrics['benign_fpr']['ci95_high'])}]</td>"
                f"<td>{_fmt(metrics['novel_f1']['mean'])} "
                f"[{_fmt(metrics['novel_f1']['ci95_low'])}, {_fmt(metrics['novel_f1']['ci95_high'])}]</td>"
                f"<td>{_fmt(metrics['roc_auc']['mean'])}</td>"
                f"<td>{_fmt(metrics['average_precision']['mean'])}</td></tr>"
            )
    parts.append("</table>")

    parts.append("<h2>Validation log-loss theo số cây</h2>")
    parts.append(
        "<p>Random Forest không có epoch training loss. Các đồ thị dưới đây là validation log-loss "
        "trên known validation từ benchmark hội tụ, không phải loss trên test LOAFO.</p><div class=\"charts\">"
    )
    tree_counts = sorted(
        int(value)
        for value in next(iter(benchmark["results"]["flow_rf"].values()))["points"]
    )
    for role, checkpoints in benchmark["results"].items():
        series = {
            checkpoint: [
                checkpoints[checkpoint]["points"][str(count)]["validation_log_loss"]
                for count in tree_counts
            ]
            for checkpoint in CHECKPOINTS
        }
        parts.append(
            f'<div class="chart">{_line_svg(tree_counts, series, f"{role} — validation log-loss")}</div>'
        )
    parts.append("</div>")

    parts.append("<h2>ROC và Precision–Recall macro</h2><div class=\"charts\">")
    for checkpoint in CHECKPOINTS:
        models = macro["checkpoints"][checkpoint]["models"]
        parts.append(
            f'<div class="chart">{_line_svg(models["flow_rf"]["roc_curve"]["fpr_grid"], {MODEL_SPECS[m][2]: models[m]["roc_curve"]["mean_tpr"] for m in MODEL_SPECS}, f"{checkpoint} — ROC macro", 0.0, 1.0)}</div>'
        )
        parts.append(
            f'<div class="chart">{_line_svg(models["flow_rf"]["pr_curve"]["recall_grid"], {MODEL_SPECS[m][2]: models[m]["pr_curve"]["mean_precision"] for m in MODEL_SPECS}, f"{checkpoint} — PR macro", 0.0, 1.0)}</div>'
        )
    parts.append("</div>")

    parts.append("<h2>Confusion matrix novel-vs-benign</h2>")
    parts.append(
        "<p>Đây là pooled experiment-observation counts qua chín LOAFO run; benign rows xuất hiện trong "
        "mỗi run. Macro metric phía trên vẫn bình quân theo family và không bị family lớn lấn át.</p>"
    )
    for checkpoint in CHECKPOINTS:
        parts.append(f"<h3>{checkpoint}</h3><div class=\"matrix-grid\">")
        for model in MODEL_SPECS:
            matrix = macro["checkpoints"][checkpoint]["models"][model][
                "pooled_experiment_confusion_matrix"
            ]
            parts.append(_confusion_html(matrix, MODEL_SPECS[model][2]))
        parts.append("</div>")

    for metric, title in (
        ("unknown_holdout_recall", "Unknown recall"),
        ("benign_fpr", "Benign FPR"),
    ):
        parts.append(f"<h2>Heatmap {title}</h2><div class=\"charts\">")
        for model in MODEL_SPECS:
            values = [
                [
                    analysis["per_family"][family]["checkpoints"][checkpoint]["models"][model][
                        metric
                    ]
                    for checkpoint in CHECKPOINTS
                ]
                for family in family_order
            ]
            parts.append(
                f'<div class="chart">{_heatmap_svg(family_order, CHECKPOINTS, values, f"{MODEL_SPECS[model][2]} — {title}")}</div>'
            )
        parts.append("</div>")

    parts.append("<h2>Feature importance macro</h2><div class=\"charts\">")
    for checkpoint in CHECKPOINTS:
        for model in ("flow_rf", "rf_stacker"):
            top = macro["checkpoints"][checkpoint]["feature_importance"][model][:10]
            parts.append(
                f'<div class="chart">{_bar_svg([x["feature"] for x in top], [x["mean_importance"] for x in top], f"{checkpoint} — {MODEL_SPECS[model][2]} top 10")}</div>'
            )
    parts.append("</div>")

    histogram_x = [(index + 0.5) / HISTOGRAM_BINS for index in range(HISTOGRAM_BINS)]
    parts.append("<h2>Phân phối confidence/score</h2><div class=\"charts\">")
    for checkpoint in CHECKPOINTS:
        known_hist = macro["checkpoints"][checkpoint]["known_family_confidence_histogram"]
        stacker_hist = macro["checkpoints"][checkpoint]["models"]["rf_stacker"][
            "score_histogram"
        ]
        parts.append(
            f'<div class="chart">{_line_svg(histogram_x, {"Known attack": known_hist["known_attack"], "Unknown holdout": known_hist["unknown_holdout"]}, f"{checkpoint} — known-family top confidence", 0.0, None)}</div>'
        )
        parts.append(
            f'<div class="chart">{_line_svg(histogram_x, {"Benign": stacker_hist["benign"], "Unknown holdout": stacker_hist["unknown_holdout"]}, f"{checkpoint} — stacker score distribution", 0.0, None)}</div>'
        )
    parts.append("</div>")

    elapsed = [
        analysis["per_family"][family]["elapsed_seconds"] / 60.0
        for family in [*family_order, *case_order]
    ]
    ram = [
        analysis["per_family"][family]["peak_process_rss_bytes"] / 2**30
        for family in [*family_order, *case_order]
    ]
    parts.extend(
        [
            "<h2>Tài nguyên</h2><div class=\"charts\">",
            f'<div class="chart">{_bar_svg([*family_order, *case_order], elapsed, "Wall time receipt (phút)")}</div>',
            f'<div class="chart">{_bar_svg([*family_order, *case_order], ram, "Peak process RSS (GiB)")}</div>',
            "</div>",
            '<p class="warning">Wall time là elapsed wall-clock của receipt; thời gian host suspend không thể '
            "tách khỏi số liệu này. GPU không được dùng để train ở cả 13 family. Telemetry phần trăm GPU "
            "không được thu thập, vì vậy báo cáo không suy diễn utilization.</p>",
            "<h2>Bốn case study</h2>",
            "<table><tr><th>Family</th><th>Checkpoint</th><th>Model</th><th>Unknown rows</th>"
            "<th>Unknown recall</th><th>Benign FPR</th></tr>",
        ]
    )
    for family in case_order:
        record = analysis["per_family"][family]
        for checkpoint in CHECKPOINTS:
            for model in ("flow_rf", "rf_stacker"):
                values = record["checkpoints"][checkpoint]
                parts.append(
                    "<tr>"
                    f"<td>{html.escape(family)}</td><td>{checkpoint}</td>"
                    f"<td>{MODEL_SPECS[model][2]}</td>"
                    f"<td>{values['population']['unknown_holdout']}</td>"
                    f"<td>{_fmt(values['models'][model]['unknown_holdout_recall'])}</td>"
                    f"<td>{_fmt(values['models'][model]['benign_fpr'])}</td></tr>"
                )
    parts.extend(
        [
            "</table>",
            "<h2>Kết luận kỹ thuật T4.7</h2>",
            "<p class=\"good\"><strong>Đạt technical gate:</strong> 13 family có evidence content-addressed; "
            "holdout không tham gia supervised fit; anomaly model vẫn benign-only; test label không tham gia "
            "fit, threshold hoặc selection; reload parity đạt.</p>",
            "<p>Không có tuyên bố rằng stacker cải thiện baseline tại đây. So sánh trực tiếp metric và "
            "confidence interval để quyết định cải thiện thuộc T4.8.</p>",
            "</main></body></html>",
        ]
    )
    return "".join(parts).encode("utf-8")


def _write_temp(path: Path, content: bytes) -> Path:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def build_receipt(
    root: Path,
    contract_path: Path,
    analysis: Mapping[str, Any],
    report_path: Path,
    report_bytes: bytes,
    elapsed_seconds: float,
) -> dict[str, Any]:
    source_paths = [
        root / "python/nids_mvp/loafo_aggregate.py",
        root / "tests/test_t47_loafo_aggregate.py",
        root / "python/nids_mvp/loafo.py",
    ]
    return {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "loafo_rf300_aggregate_acceptance",
        "status": "passed",
        "generated_at_utc": utc_now(),
        "elapsed_seconds": elapsed_seconds,
        "contract": {
            "path": contract_path.relative_to(root).as_posix(),
            "size_bytes": contract_path.stat().st_size,
            "sha256": loafo.sha256_path(contract_path),
        },
        "source_files": {
            path.relative_to(root).as_posix(): loafo.sha256_path(path)
            for path in source_paths
        },
        "analysis": analysis,
        "artifacts": {
            "report": {
                "path": report_path.relative_to(root).as_posix(),
                "size_bytes": len(report_bytes),
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
                "format": "self_contained_html_utf8",
            }
        },
        "validation": {
            "thirteen_family_scope_exact": True,
            "nine_family_macro_scope_exact": True,
            "four_case_studies_excluded_from_macro": True,
            "all_prediction_hashes_and_rows_verified": True,
            "all_family_receipts_verified": True,
            "all_metrics_recomputed_from_predictions": True,
            "equal_family_macro_weighting": True,
            "bootstrap_family_unit_exact": True,
            "rf50_accelerated_ablation_preserved": True,
            "rf300_primary_final": True,
            "holdout_absent_from_supervised_fit": True,
            "anomaly_models_benign_only_without_refit": True,
            "test_labels_excluded_from_fit_threshold_and_selection": True,
            "all_reload_parity_passed": True,
            "hooks_read_or_run": False,
            "dependency_or_environment_mutation": False,
            "report_contains_required_diagnostics": True,
            "improvement_claim_deferred_to_t4_8": True,
        },
        "gate": {
            "decision": "pending_user_decision",
            "t4_8_authorized": False,
        },
    }


def run_aggregate(root: Path, contract_path: Path) -> dict[str, Any]:
    started = time.monotonic()
    contract, _ = loafo.load_execution_contract(root, contract_path)
    output_root = loafo.resolve_inside(root, contract["execution_variant"]["output_root"])
    output_root.mkdir(parents=True, exist_ok=True)
    acceptance_path = output_root / ACCEPTANCE_NAME
    report_path = output_root / REPORT_NAME
    if acceptance_path.exists() or report_path.exists():
        raise FileExistsError("T4.7 aggregate evidence already exists")
    analysis, benchmark = build_analysis(root, contract_path)
    report_bytes = render_report(analysis, benchmark)
    receipt = build_receipt(
        root,
        contract_path,
        analysis,
        report_path,
        report_bytes,
        time.monotonic() - started,
    )
    receipt_bytes = (
        json.dumps(
            receipt,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    report_temp = _write_temp(report_path, report_bytes)
    receipt_temp = _write_temp(acceptance_path, receipt_bytes)
    report_published = False
    try:
        os.replace(report_temp, report_path)
        report_published = True
        os.replace(receipt_temp, acceptance_path)
    except BaseException:
        if report_published and not acceptance_path.exists():
            report_path.unlink(missing_ok=True)
        raise
    finally:
        report_temp.unlink(missing_ok=True)
        receipt_temp.unlink(missing_ok=True)
    return receipt


def validate_receipt(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, _ = loafo.load_execution_contract(root, contract_path)
    output_root = loafo.resolve_inside(root, contract["execution_variant"]["output_root"])
    acceptance_path = output_root / ACCEPTANCE_NAME
    report_path = output_root / REPORT_NAME
    receipt = loafo.load_json(acceptance_path)
    if (
        receipt.get("task") != TASK
        or receipt.get("kind") != "loafo_rf300_aggregate_acceptance"
        or receipt.get("status") != "passed"
        or receipt.get("contract", {}).get("sha256") != loafo.sha256_path(contract_path)
        or receipt.get("gate")
        != {"decision": "pending_user_decision", "t4_8_authorized": False}
    ):
        raise ValueError("invalid T4.7 aggregate acceptance")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = loafo.resolve_inside(root, value)
        if not path.is_file() or loafo.sha256_path(path) != expected_hash:
            raise ValueError(f"T4.7 aggregate source mismatch: {value}")
    analysis, benchmark = build_analysis(root, contract_path)
    if analysis != receipt.get("analysis"):
        raise ValueError("T4.7 aggregate analysis mismatch")
    expected_report = render_report(analysis, benchmark)
    artifact = receipt.get("artifacts", {}).get("report", {})
    if (
        artifact.get("path") != report_path.relative_to(root).as_posix()
        or not report_path.is_file()
        or artifact.get("size_bytes") != report_path.stat().st_size
        or artifact.get("sha256") != loafo.sha256_path(report_path)
        or report_path.read_bytes() != expected_report
    ):
        raise ValueError("T4.7 report content mismatch")
    required = receipt.get("validation", {})
    if not required or not all(value is True or value is False for value in required.values()):
        raise ValueError("invalid T4.7 validation record")
    if required.get("hooks_read_or_run") is not False:
        raise ValueError("hook evidence is forbidden")
    if required.get("dependency_or_environment_mutation") is not False:
        raise ValueError("unexpected environment mutation")
    if not all(
        value
        for key, value in required.items()
        if key not in {"hooks_read_or_run", "dependency_or_environment_mutation"}
    ):
        raise ValueError("T4.7 validation gate failed")
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate and report T4.7 RF300 LOAFO evidence")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--contract",
        default="config/cicids2017-loafo-rf300-contract.json",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    contract_path = loafo.resolve_inside(root, args.contract)
    if args.command == "check":
        analysis, _ = build_analysis(root, contract_path)
        result = {
            "status": "passed",
            "families": analysis["totals"]["families"],
            "prediction_rows": analysis["totals"]["prediction_rows"],
        }
    elif args.command == "run":
        receipt = run_aggregate(root, contract_path)
        result = {
            "status": receipt["status"],
            "report": receipt["artifacts"]["report"],
            "gate": receipt["gate"],
        }
    else:
        receipt = validate_receipt(root, contract_path)
        result = {
            "status": receipt["status"],
            "families": receipt["analysis"]["totals"]["families"],
            "report": receipt["artifacts"]["report"],
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
