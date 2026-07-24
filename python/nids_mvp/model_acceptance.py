from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import tempfile
import time
from collections import defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T4.8"
KIND = "model_acceptance_bundle"
CHECKPOINTS = ("F3", "F5", "F7", "F9")
BASELINES = ("flow_rf", "hbos", "isolation_forest")
MODELS = (*BASELINES, "rf_stacker")
LOAFO_METRICS = (
    "novel_f1",
    "unknown_holdout_recall",
    "benign_fpr",
    "roc_auc",
    "average_precision",
)
KNOWN_METRICS = ("f1", "recall", "fpr")
MODEL_LABELS = {
    "flow_rf": "Flow RF",
    "hbos": "HBOS",
    "isolation_forest": "Isolation Forest",
    "rf_stacker": "RF Stacker",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def resolve_inside(root: Path, value: str | Path) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"path escapes workspace: {value}") from error
    return resolved


def _validate_contract_semantics(contract: Mapping[str, Any]) -> None:
    baseline = contract.get("baseline_interpretation", {})
    comparisons = contract.get("comparisons", {})
    primary = contract.get("primary_endpoint", {})
    primary_ci = primary.get("confidence_interval", {})
    known = contract.get("known_validation", {})
    known_bootstrap = known.get("bootstrap", {})
    execution = contract.get("execution", {})
    authorization = contract.get("authorization", {})
    multiplicity = contract.get("multiplicity", {})
    if (
        contract.get("task") != TASK
        or contract.get("schema_version") != "1.0.0"
        or authorization.get("decision") != "accepted"
        or authorization.get("implementation_authorized") is not True
        or authorization.get("model_training_allowed") is not False
        or authorization.get("threshold_change_allowed") is not False
        or execution.get("host") != "windows_native"
        or execution.get("dependency_mutation_allowed") is not False
        or execution.get("model_training_allowed") is not False
        or execution.get("threshold_change_allowed") is not False
        or execution.get("test_partition_selection_allowed") is not False
        or execution.get("hooks_in_scope") is not False
        or baseline.get("baseline_a", {}).get("id") != "flow_rf"
        or baseline.get("baseline_b", {}).get("independent_models")
        != ["hbos", "isolation_forest"]
        or baseline.get("baseline_b", {}).get("evaluate_independently") is not True
        or baseline.get("anomaly_ensemble_baseline_defined") is not False
        or baseline.get("new_or_majority_vote_or_weighted_threshold_allowed") is not False
        or comparisons.get("candidate") != "rf_stacker"
        or comparisons.get("primary_confirmatory") != "flow_rf"
        or comparisons.get("secondary_descriptive") != ["hbos", "isolation_forest"]
        or comparisons.get(
            "select_baseline_checkpoint_metric_or_threshold_from_loafo_outcomes_allowed"
        )
        is not False
        or tuple(contract.get("checkpoints", ())) != CHECKPOINTS
        or primary.get("name") != "global_paired_novel_f1_delta"
        or primary.get("family_weighting") != "equal"
        or primary.get("checkpoint_weighting_within_family") != "equal"
        or primary_ci.get("method") != "paired percentile bootstrap"
        or primary_ci.get("samples") != 10_000
        or primary_ci.get("seed") != 1729
        or primary_ci.get("resampling_unit") != "holdout_family"
        or primary_ci.get("keep_all_checkpoints_of_family_together") is not True
        or known.get("dependency_unit") != ["capture_id", "time_block_index"]
        or known.get("stratum") != "capture_id"
        or known_bootstrap.get("method")
        != "paired stratified cluster percentile bootstrap"
        or known_bootstrap.get("samples") != 10_000
        or known_bootstrap.get("seed") != 1729
        or known_bootstrap.get("resample_time_blocks_with_replacement_within_capture")
        is not True
        or known.get("independent_flow_bootstrap_allowed") is not False
        or multiplicity.get("formal_claim_count") != 1
        or multiplicity.get("checkpoint_claims") is not False
        or multiplicity.get("secondary_baseline_claims") is not False
        or multiplicity.get("family_wise_correction_required") is not False
    ):
        raise ValueError("T4.8 contract semantics do not match the accepted design")
    families = contract.get("family_scope", {})
    if (
        len(families.get("macro_aggregate", ())) != 9
        or len(families.get("case_study_only", ())) != 4
        or families.get("unavailable") != ["Heartbleed"]
        or families.get("case_studies_in_inferential_claim_allowed") is not False
    ):
        raise ValueError("T4.8 family scope mismatch")


def verified_contract(
    root: Path,
    contract_path: Path,
) -> tuple[dict[str, Any], dict[str, Path], dict[str, dict[str, Any]]]:
    contract = load_json(contract_path)
    _validate_contract_semantics(contract)
    paths: dict[str, Path] = {}
    records: dict[str, dict[str, Any]] = {}
    for name, expected in contract.get("prerequisites", {}).items():
        path = resolve_inside(root, expected["path"])
        if not path.is_file():
            raise FileNotFoundError(f"missing prerequisite: {name}")
        actual = {
            "path": path.relative_to(root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_path(path),
        }
        if (
            actual["size_bytes"] != expected["size_bytes"]
            or actual["sha256"] != expected["sha256"]
        ):
            raise ValueError(f"prerequisite content mismatch: {name}")
        paths[name] = path
        records[name] = actual
    if np.__version__ != contract["execution"]["versions"]["numpy"]:
        raise ValueError("NumPy version mismatch")
    if pa.__version__ != contract["execution"]["versions"]["pyarrow"]:
        raise ValueError("PyArrow version mismatch")
    manual = load_json(paths["t4_7_manual_acceptance"])
    if (
        manual.get("task") != "T4.7"
        or manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or manual.get("gate", {}).get("t4_8_authorized") is not True
        or manual.get("technical_acceptance", {}).get("sha256")
        != records["t4_7_acceptance"]["sha256"]
    ):
        raise ValueError("T4.7 manual acceptance mismatch")
    return contract, paths, records


def _interval(
    estimates: np.ndarray,
    level: float,
) -> tuple[float, float]:
    if estimates.ndim != 1 or not np.isfinite(estimates).all():
        raise ValueError("bootstrap estimates must be a finite vector")
    tail = (1.0 - level) / 2.0
    low, high = np.quantile(
        estimates,
        [tail, 1.0 - tail],
        method="linear",
    )
    return float(low), float(high)


def paired_family_bootstrap(
    deltas: np.ndarray | Sequence[Sequence[float]],
    samples: int,
    seed: int,
    level: float = 0.95,
) -> dict[str, Any]:
    values = np.asarray(deltas, dtype=np.float64)
    if (
        values.ndim != 2
        or values.shape[0] == 0
        or values.shape[1] == 0
        or samples <= 0
        or not np.isfinite(values).all()
    ):
        raise ValueError("family bootstrap requires a non-empty finite matrix")
    family_means = values.mean(axis=1)
    rng = np.random.default_rng(seed)
    indices = rng.integers(
        0,
        family_means.shape[0],
        size=(samples, family_means.shape[0]),
    )
    estimates = family_means[indices].mean(axis=1)
    low, high = _interval(estimates, level)
    return {
        "delta": float(family_means.mean()),
        "ci95_low": low,
        "ci95_high": high,
        "family_units": int(values.shape[0]),
        "checkpoints_per_family": int(values.shape[1]),
        "bootstrap_samples": int(samples),
        "bootstrap_seed": int(seed),
        "confidence_level": float(level),
    }


def _loafo_metric(model: Mapping[str, Any], name: str) -> float:
    if name == "novel_f1":
        value = model["novel_detection"]["f1"]
    else:
        value = model[name]
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite LOAFO metric: {name}")
    return result


def _validate_t4_7(
    acceptance: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    analysis = acceptance.get("analysis", {})
    policy = analysis.get("policy", {})
    validation = acceptance.get("validation", {})
    expected_true = (
        "all_family_receipts_verified",
        "all_metrics_recomputed_from_predictions",
        "all_prediction_hashes_and_rows_verified",
        "all_reload_parity_passed",
        "anomaly_models_benign_only_without_refit",
        "equal_family_macro_weighting",
        "holdout_absent_from_supervised_fit",
        "rf300_primary_final",
        "test_labels_excluded_from_fit_threshold_and_selection",
    )
    if (
        acceptance.get("task") != "T4.7"
        or acceptance.get("status") != "passed"
        or acceptance.get("kind") != "loafo_rf300_aggregate_acceptance"
        or analysis.get("totals", {}).get("families") != 13
        or analysis.get("totals", {}).get("macro_families") != 9
        or analysis.get("totals", {}).get("case_studies") != 4
        or policy.get("macro_family_order")
        != contract["family_scope"]["macro_aggregate"]
        or policy.get("case_study_family_order")
        != contract["family_scope"]["case_study_only"]
        or validation.get("hooks_read_or_run") is not False
        or validation.get("dependency_or_environment_mutation") is not False
        or not all(validation.get(name) is True for name in expected_true)
    ):
        raise ValueError("accepted T4.7 aggregate is incompatible with T4.8")
    expected_families = [
        *contract["family_scope"]["macro_aggregate"],
        *contract["family_scope"]["case_study_only"],
    ]
    observed_families = analysis.get("per_family", {})
    if (
        len(observed_families) != len(expected_families)
        or set(observed_families) != set(expected_families)
    ):
        raise ValueError("T4.7 per-family scope mismatch")


def loafo_analysis(
    contract: Mapping[str, Any],
    acceptance: Mapping[str, Any],
) -> dict[str, Any]:
    _validate_t4_7(acceptance, contract)
    macro_families = contract["family_scope"]["macro_aggregate"]
    case_families = contract["family_scope"]["case_study_only"]
    per_family = acceptance["analysis"]["per_family"]
    primary_ci = contract["primary_endpoint"]["confidence_interval"]
    samples = int(primary_ci["samples"])
    seed = int(primary_ci["seed"])
    level = float(primary_ci["level"])
    matrices: dict[str, dict[str, np.ndarray]] = {}
    for metric in LOAFO_METRICS:
        matrices[metric] = {}
        for model in MODELS:
            matrices[metric][model] = np.asarray(
                [
                    [
                        _loafo_metric(
                            per_family[family]["checkpoints"][checkpoint]["models"][model],
                            metric,
                        )
                        for checkpoint in CHECKPOINTS
                    ]
                    for family in macro_families
                ],
                dtype=np.float64,
            )
    comparisons: dict[str, Any] = {}
    checkpoint_results: dict[str, Any] = {checkpoint: {} for checkpoint in CHECKPOINTS}
    for baseline in BASELINES:
        novel_delta = matrices["novel_f1"]["rf_stacker"] - matrices["novel_f1"][baseline]
        primary_result = paired_family_bootstrap(
            novel_delta,
            samples,
            seed,
            level,
        )
        primary_result["per_family_mean_delta"] = {
            family: float(value)
            for family, value in zip(
                macro_families,
                novel_delta.mean(axis=1),
                strict=True,
            )
        }
        comparisons[baseline] = {
            "role": "primary_confirmatory"
            if baseline == contract["comparisons"]["primary_confirmatory"]
            else "secondary_descriptive",
            "global_novel_f1": primary_result,
        }
        for checkpoint_index, checkpoint in enumerate(CHECKPOINTS):
            metric_results: dict[str, Any] = {}
            for metric in LOAFO_METRICS:
                delta = (
                    matrices[metric]["rf_stacker"][:, checkpoint_index]
                    - matrices[metric][baseline][:, checkpoint_index]
                )
                result = paired_family_bootstrap(
                    delta.reshape(-1, 1),
                    samples,
                    seed,
                    level,
                )
                result["inferential_claim_allowed"] = False
                metric_results[metric] = result
            checkpoint_results[checkpoint][baseline] = metric_results
    case_studies: dict[str, Any] = {}
    for family in case_families:
        case_studies[family] = {
            checkpoint: {
                model: {
                    metric: _loafo_metric(
                        per_family[family]["checkpoints"][checkpoint]["models"][model],
                        metric,
                    )
                    for metric in LOAFO_METRICS
                }
                for model in MODELS
            }
            for checkpoint in CHECKPOINTS
        }
    return {
        "policy": {
            "primary_estimand": contract["primary_endpoint"]["estimand"],
            "macro_family_order": macro_families,
            "case_study_family_order": case_families,
            "case_studies_excluded_from_inference": True,
            "checkpoint_claims_allowed": False,
            "secondary_baseline_claims_allowed": False,
        },
        "comparisons": comparisons,
        "per_checkpoint_descriptive": checkpoint_results,
        "case_studies": case_studies,
    }


def _expected_npz_keys(kind: str) -> set[str]:
    keys: set[str] = set()
    for checkpoint in CHECKPOINTS:
        prefix = f"{checkpoint}__"
        keys.update(
            {
                f"{prefix}capture_id",
                f"{prefix}flow_id",
                f"{prefix}y_true",
            }
        )
        if kind in {"flow_rf", "rf_stacker"}:
            keys.update(
                {
                    f"{prefix}attack_probability",
                    f"{prefix}y_pred",
                }
            )
        else:
            for model in ("hbos", "isolation_forest"):
                keys.update(
                    {
                        f"{prefix}{model}__raw_score",
                        f"{prefix}{model}__normalized_score",
                        f"{prefix}{model}__y_pred",
                    }
                )
    return keys


def _validate_npz_schema(
    data: Any,
    kind: str,
    expected_rows: Mapping[str, int],
) -> None:
    if set(data.files) != _expected_npz_keys(kind):
        raise ValueError(f"validation prediction key mismatch: {kind}")
    for checkpoint in CHECKPOINTS:
        prefix = f"{checkpoint}__"
        rows = int(expected_rows[checkpoint])
        capture_id = data[f"{prefix}capture_id"]
        flow_id = data[f"{prefix}flow_id"]
        y_true = data[f"{prefix}y_true"]
        if (
            capture_id.shape != (rows,)
            or capture_id.dtype.kind != "U"
            or flow_id.shape != (rows,)
            or flow_id.dtype != np.uint64
            or y_true.shape != (rows,)
            or y_true.dtype != np.uint8
            or not np.isin(y_true, [0, 1]).all()
        ):
            raise ValueError(f"validation prediction identity mismatch: {kind}/{checkpoint}")
        if kind in {"flow_rf", "rf_stacker"}:
            probability = data[f"{prefix}attack_probability"]
            prediction = data[f"{prefix}y_pred"]
            if (
                probability.shape != (rows,)
                or probability.dtype != np.float64
                or not np.isfinite(probability).all()
                or np.any(probability < 0.0)
                or np.any(probability > 1.0)
                or prediction.shape != (rows,)
                or prediction.dtype != np.uint8
                or not np.isin(prediction, [0, 1]).all()
            ):
                raise ValueError(f"validation model output mismatch: {kind}/{checkpoint}")
        else:
            for model in ("hbos", "isolation_forest"):
                raw = data[f"{prefix}{model}__raw_score"]
                normalized = data[f"{prefix}{model}__normalized_score"]
                prediction = data[f"{prefix}{model}__y_pred"]
                if (
                    raw.shape != (rows,)
                    or raw.dtype != np.float64
                    or not np.isfinite(raw).all()
                    or normalized.shape != (rows,)
                    or normalized.dtype != np.float64
                    or not np.isfinite(normalized).all()
                    or prediction.shape != (rows,)
                    or prediction.dtype != np.uint8
                    or not np.isin(prediction, [0, 1]).all()
                ):
                    raise ValueError(
                        f"validation anomaly output mismatch: {model}/{checkpoint}"
                    )


def join_prediction_groups(
    capture_id: np.ndarray,
    flow_id: np.ndarray,
    y_true: np.ndarray,
    split_lookup: Mapping[tuple[str, int], tuple[tuple[str, int], int]],
    group_index: Mapping[tuple[str, int], int],
) -> tuple[np.ndarray, dict[str, int]]:
    keys = list(zip(capture_id.tolist(), flow_id.tolist(), strict=True))
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate validation prediction key")
    joined = [split_lookup.get((str(capture), int(flow))) for capture, flow in keys]
    if any(value is None for value in joined):
        raise ValueError("validation prediction key is absent from known split")
    values = [value for value in joined if value is not None]
    joined_labels = np.asarray([value[1] for value in values], dtype=np.uint8)
    if not np.array_equal(joined_labels, y_true):
        raise ValueError("validation prediction label mismatch")
    row_groups = np.asarray(
        [group_index[value[0]] for value in values],
        dtype=np.int64,
    )
    return row_groups, {
        "rows": int(len(keys)),
        "duplicate_keys": 0,
        "unmatched_keys": 0,
        "label_mismatches": 0,
        "compound_groups": int(len(np.unique(row_groups))),
    }


def stratified_cluster_draws(
    groups: Sequence[tuple[str, int]],
    samples: int,
    seed: int,
) -> dict[str, np.ndarray]:
    if not groups or samples <= 0:
        raise ValueError("cluster bootstrap requires groups and samples")
    by_capture: dict[str, list[int]] = defaultdict(list)
    for index, (capture_id, _) in enumerate(groups):
        by_capture[capture_id].append(index)
    rng = np.random.default_rng(seed)
    draws: dict[str, np.ndarray] = {}
    for capture_id in sorted(by_capture):
        indices = np.asarray(by_capture[capture_id], dtype=np.int64)
        draws[capture_id] = indices[
            rng.integers(
                0,
                len(indices),
                size=(samples, len(indices)),
            )
        ]
    return draws


def _confusion_metric(confusion: np.ndarray, name: str) -> np.ndarray:
    values = np.asarray(confusion)
    if values.shape[-1] != 4 or np.any(values < 0):
        raise ValueError("confusion counts must end with TN, FP, FN, TP")
    tn, fp, fn, tp = (values[..., index].astype(np.float64) for index in range(4))
    if name == "f1":
        numerator = 2.0 * tp
        denominator = 2.0 * tp + fp + fn
    elif name == "recall":
        numerator = tp
        denominator = tp + fn
    elif name == "fpr":
        numerator = fp
        denominator = fp + tn
    else:
        raise KeyError(name)
    if np.any(denominator == 0.0):
        raise ValueError(f"zero denominator for {name}")
    return numerator / denominator


def confusion_metrics(confusion: Sequence[int] | np.ndarray) -> dict[str, float]:
    values = np.asarray(confusion, dtype=np.int64)
    if values.shape != (4,):
        raise ValueError("point confusion must contain TN, FP, FN, TP")
    return {
        name: float(_confusion_metric(values, name))
        for name in KNOWN_METRICS
    }


def _bootstrap_confusion(
    group_confusion: np.ndarray,
    draws: Mapping[str, np.ndarray],
) -> np.ndarray:
    values = np.asarray(group_confusion, dtype=np.int64)
    if values.ndim != 2 or values.shape[1] != 4:
        raise ValueError("group confusion must have shape (groups, 4)")
    sample_counts = {draw.shape[0] for draw in draws.values()}
    if len(sample_counts) != 1:
        raise ValueError("cluster bootstrap draw count mismatch")
    result = np.zeros((sample_counts.pop(), 4), dtype=np.int64)
    for capture_id in sorted(draws):
        result += values[draws[capture_id]].sum(axis=1)
    return result


def cluster_metric_comparison(
    candidate_group_confusion: np.ndarray,
    baseline_group_confusion: np.ndarray,
    draws: Mapping[str, np.ndarray],
    level: float = 0.95,
) -> dict[str, Any]:
    candidate = np.asarray(candidate_group_confusion, dtype=np.int64)
    baseline = np.asarray(baseline_group_confusion, dtype=np.int64)
    if candidate.shape != baseline.shape:
        raise ValueError("paired group confusion shape mismatch")
    candidate_point = confusion_metrics(candidate.sum(axis=0))
    baseline_point = confusion_metrics(baseline.sum(axis=0))
    candidate_bootstrap = _bootstrap_confusion(candidate, draws)
    baseline_bootstrap = _bootstrap_confusion(baseline, draws)
    result: dict[str, Any] = {}
    for name in KNOWN_METRICS:
        estimates = _confusion_metric(candidate_bootstrap, name) - _confusion_metric(
            baseline_bootstrap,
            name,
        )
        low, high = _interval(estimates, level)
        result[name] = {
            "candidate": candidate_point[name],
            "baseline": baseline_point[name],
            "delta": candidate_point[name] - baseline_point[name],
            "ci95_low": low,
            "ci95_high": high,
            "inferential_claim_allowed": False,
        }
    return result


def _split_lookup(
    path: Path,
    expected_rows: int,
) -> tuple[
    dict[tuple[str, int], tuple[tuple[str, int], int]],
    list[tuple[str, int]],
]:
    parquet = pq.ParquetFile(path)
    if parquet.metadata.num_rows != expected_rows:
        raise ValueError("known split row count mismatch")
    required = {
        "capture_id",
        "flow_id",
        "time_block_index",
        "partition",
        "label_binary",
    }
    if not required.issubset(parquet.schema_arrow.names):
        raise ValueError("known split schema mismatch")
    table = pq.read_table(
        path,
        columns=sorted(required),
        filters=[("partition", "=", "validation")],
    )
    if any(table[name].null_count != 0 for name in table.column_names):
        raise ValueError("known split contains null validation metadata")
    captures = table["capture_id"].combine_chunks().to_pylist()
    flow_ids = table["flow_id"].combine_chunks().to_numpy(zero_copy_only=False)
    blocks = table["time_block_index"].combine_chunks().to_numpy(zero_copy_only=False)
    labels = (
        table["label_binary"]
        .combine_chunks()
        .to_numpy(zero_copy_only=False)
        .astype(np.uint8)
    )
    lookup: dict[tuple[str, int], tuple[tuple[str, int], int]] = {}
    for capture_id, flow_id, block, label in zip(
        captures,
        flow_ids,
        blocks,
        labels,
        strict=True,
    ):
        key = (str(capture_id), int(flow_id))
        if key in lookup:
            raise ValueError("duplicate known split flow key")
        lookup[key] = ((str(capture_id), int(block)), int(label))
    return lookup, sorted({value[0] for value in lookup.values()})


def known_validation_analysis(
    contract: Mapping[str, Any],
    paths: Mapping[str, Path],
) -> dict[str, Any]:
    known = contract["known_validation"]
    lookup, groups = _split_lookup(
        paths["known_flow_map"],
        int(contract["prerequisites"]["known_flow_map"]["rows"]),
    )
    if len(groups) != int(known["expected_compound_group_count"]):
        raise ValueError("known validation compound group count mismatch")
    group_index = {group: index for index, group in enumerate(groups)}
    bootstrap = known["bootstrap"]
    draws = stratified_cluster_draws(
        groups,
        int(bootstrap["samples"]),
        int(bootstrap["seed"]),
    )
    path_by_kind = {
        "flow_rf": paths["t4_2_validation_predictions"],
        "anomaly": paths["t4_3_validation_predictions"],
        "rf_stacker": paths["t4_5_validation_predictions"],
    }
    with ExitStack() as stack:
        data = {
            kind: stack.enter_context(np.load(path, allow_pickle=False))
            for kind, path in path_by_kind.items()
        }
        for kind, values in data.items():
            _validate_npz_schema(values, kind, known["expected_rows"])
        checkpoint_results: dict[str, Any] = {}
        for checkpoint in CHECKPOINTS:
            prefix = f"{checkpoint}__"
            reference_capture = data["flow_rf"][f"{prefix}capture_id"]
            reference_flow = data["flow_rf"][f"{prefix}flow_id"]
            reference_y = data["flow_rf"][f"{prefix}y_true"]
            for kind in ("anomaly", "rf_stacker"):
                if (
                    not np.array_equal(
                        reference_capture,
                        data[kind][f"{prefix}capture_id"],
                    )
                    or not np.array_equal(reference_flow, data[kind][f"{prefix}flow_id"])
                    or not np.array_equal(reference_y, data[kind][f"{prefix}y_true"])
                ):
                    raise ValueError(
                        f"validation prediction identity differs: {checkpoint}/{kind}"
                    )
            row_groups, alignment = join_prediction_groups(
                reference_capture,
                reference_flow,
                reference_y,
                lookup,
                group_index,
            )
            if alignment["rows"] != int(known["expected_rows"][checkpoint]):
                raise ValueError(f"known validation row count mismatch: {checkpoint}")
            if alignment["compound_groups"] != len(groups):
                raise ValueError(f"known validation group coverage mismatch: {checkpoint}")
            predictions = {
                "flow_rf": data["flow_rf"][f"{prefix}y_pred"],
                "hbos": data["anomaly"][f"{prefix}hbos__y_pred"],
                "isolation_forest": data["anomaly"][
                    f"{prefix}isolation_forest__y_pred"
                ],
                "rf_stacker": data["rf_stacker"][f"{prefix}y_pred"],
            }
            group_confusion: dict[str, np.ndarray] = {}
            for model, prediction in predictions.items():
                confusion = np.zeros((len(groups), 4), dtype=np.int64)
                np.add.at(
                    confusion,
                    (row_groups, 2 * reference_y + prediction),
                    1,
                )
                group_confusion[model] = confusion
            comparisons = {
                baseline: cluster_metric_comparison(
                    group_confusion["rf_stacker"],
                    group_confusion[baseline],
                    draws,
                    float(bootstrap["level"]),
                )
                for baseline in BASELINES
            }
            checkpoint_results[checkpoint] = {
                "alignment": alignment,
                "population": {
                    "rows": int(len(reference_y)),
                    "benign": int(np.count_nonzero(reference_y == 0)),
                    "attack": int(np.count_nonzero(reference_y == 1)),
                    "compound_groups": len(groups),
                },
                "comparisons": comparisons,
            }
    return {
        "policy": {
            "join_key": known["join_key"],
            "dependency_unit": known["dependency_unit"],
            "stratum": known["stratum"],
            "bootstrap_method": bootstrap["method"],
            "bootstrap_samples": int(bootstrap["samples"]),
            "bootstrap_seed": int(bootstrap["seed"]),
            "independent_flow_bootstrap_allowed": False,
            "confidence_intervals_are_secondary_descriptive": True,
        },
        "validation_split_rows": len(lookup),
        "compound_groups": len(groups),
        "groups_by_capture": {
            capture_id: int(sum(group[0] == capture_id for group in groups))
            for capture_id in sorted({group[0] for group in groups})
        },
        "checkpoints": checkpoint_results,
    }


def decide_model(
    contract: Mapping[str, Any],
    primary: Mapping[str, Any],
    known_checkpoints: Mapping[str, Any],
) -> dict[str, Any]:
    threshold = float(
        contract["claim_and_selection"]["improvement_claim"][
            "primary_ci_lower_bound_must_be_strictly_greater_than"
        ]
    )
    recall_minimum = float(contract["safeguards"]["known_recall"]["minimum_delta"])
    fpr_maximum = float(contract["safeguards"]["benign_fpr"]["maximum_delta"])
    primary_passed = float(primary["ci95_low"]) > threshold
    safeguard_results: dict[str, Any] = {}
    for checkpoint in CHECKPOINTS:
        metrics = known_checkpoints[checkpoint]["comparisons"]["flow_rf"]
        recall_delta = float(metrics["recall"]["delta"])
        fpr_delta = float(metrics["fpr"]["delta"])
        recall_passed = recall_delta >= recall_minimum
        fpr_passed = fpr_delta <= fpr_maximum
        safeguard_results[checkpoint] = {
            "known_recall_delta": recall_delta,
            "known_recall_minimum": recall_minimum,
            "known_recall_passed": recall_passed,
            "benign_fpr_delta": fpr_delta,
            "benign_fpr_maximum": fpr_maximum,
            "benign_fpr_passed": fpr_passed,
            "passed": recall_passed and fpr_passed,
        }
    safeguards_passed = all(
        value["passed"] for value in safeguard_results.values()
    )
    claim_supported = primary_passed and safeguards_passed
    selection_key = "on_pass" if claim_supported else "on_fail"
    selection = dict(contract["claim_and_selection"][selection_key])
    reasons: list[str] = []
    if not primary_passed:
        reasons.append("primary_ci_lower_bound_not_above_zero")
    if not safeguards_passed:
        reasons.append("known_validation_safeguard_failed")
    if claim_supported:
        reasons.append("primary_and_safeguards_passed")
    return {
        "primary_confirmatory_comparison": "rf_stacker minus flow_rf",
        "primary_ci_lower_bound_threshold": threshold,
        "primary_passed": primary_passed,
        "safeguards": safeguard_results,
        "all_safeguards_passed": safeguards_passed,
        "stacker_improvement_claim_supported": claim_supported,
        "selection": selection,
        "reason_codes": reasons,
        "t5_1_authorized": False,
        "manual_acceptance_required": True,
    }


def build_analysis(
    contract: Mapping[str, Any],
    paths: Mapping[str, Path],
) -> dict[str, Any]:
    t4_7 = load_json(paths["t4_7_acceptance"])
    loafo = loafo_analysis(contract, t4_7)
    known = known_validation_analysis(contract, paths)
    primary = loafo["comparisons"]["flow_rf"]["global_novel_f1"]
    decision = decide_model(contract, primary, known["checkpoints"])
    return {
        "baseline_interpretation": {
            "flow_rf": "primary classifier baseline",
            "hbos": "independent anomaly baseline",
            "isolation_forest": "independent anomaly baseline",
            "anomaly_ensemble_created": False,
        },
        "loafo": loafo,
        "known_validation": known,
        "multiplicity": dict(contract["multiplicity"]),
        "decision": decision,
    }


def _fmt(value: float, digits: int = 6) -> str:
    return f"{value:.{digits}f}"


def render_report(analysis: Mapping[str, Any]) -> bytes:
    comparisons = analysis["loafo"]["comparisons"]
    decision = analysis["decision"]
    selected = decision["selection"]["phase_5_binary_classifier"]
    parts = [
        '<!doctype html><html lang="vi"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>T4.8 — Nghiệm thu mô hình</title><style>",
        "body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fb;color:#172033}"
        "main{max-width:1180px;margin:auto;padding:28px}"
        "header{background:#111827;color:white;border-radius:16px;padding:24px}"
        "section{background:white;border:1px solid #dbe3ef;border-radius:12px;padding:18px;margin-top:18px}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #dbe3ef;padding:8px;text-align:right}"
        "th:first-child,td:first-child{text-align:left}th{background:#eef3f9}"
        ".pass{color:#047857}.fail{color:#b42318}.note{background:#fff7ed;border-left:5px solid #f97316;padding:12px}",
        "</style></head><body><main><header><h1>T4.8 — Model acceptance</h1>",
        "<p>So sánh ghép cặp đã khóa trước giữa RF Stacker và các baseline đã nghiệm thu.</p></header>",
        "<section><h2>Primary endpoint LOAFO</h2>",
        "<table><tr><th>So sánh</th><th>Delta novel-F1</th><th>CI95</th><th>Vai trò</th></tr>",
    ]
    for baseline in BASELINES:
        result = comparisons[baseline]["global_novel_f1"]
        parts.append(
            "<tr>"
            f"<td>RF Stacker − {MODEL_LABELS[baseline]}</td>"
            f"<td>{_fmt(result['delta'])}</td>"
            f"<td>[{_fmt(result['ci95_low'])}, {_fmt(result['ci95_high'])}]</td>"
            f"<td>{html.escape(comparisons[baseline]['role'])}</td></tr>"
        )
    parts.extend(
        [
            "</table>",
            '<p class="note">Primary claim duy nhất là RF Stacker − Flow RF. HBOS và Isolation Forest '
            "được báo cáo độc lập như secondary baseline; không tạo anomaly ensemble mới.</p></section>",
            "<section><h2>Safeguard trên known validation</h2>",
            "<table><tr><th>Checkpoint</th><th>Recall delta</th><th>Ngưỡng</th>"
            "<th>FPR delta</th><th>Trần</th><th>Kết quả</th></tr>",
        ]
    )
    for checkpoint in CHECKPOINTS:
        safeguard = decision["safeguards"][checkpoint]
        status = "Đạt" if safeguard["passed"] else "Không đạt"
        css = "pass" if safeguard["passed"] else "fail"
        parts.append(
            "<tr>"
            f"<td>{checkpoint}</td>"
            f"<td>{_fmt(safeguard['known_recall_delta'])}</td>"
            f"<td>≥ {_fmt(safeguard['known_recall_minimum'])}</td>"
            f"<td>{_fmt(safeguard['benign_fpr_delta'])}</td>"
            f"<td>≤ {_fmt(safeguard['benign_fpr_maximum'])}</td>"
            f'<td class="{css}">{status}</td></tr>'
        )
    claim_text = (
        "Có đủ bằng chứng để tuyên bố Stacker cải thiện."
        if decision["stacker_improvement_claim_supported"]
        else "Không có đủ bằng chứng để tuyên bố Stacker cải thiện Flow RF."
    )
    parts.extend(
        [
            "</table></section>",
            "<section><h2>Quyết định</h2>",
            f"<p><strong>{html.escape(claim_text)}</strong></p>",
            f"<p>Binary classifier đề xuất cho Phase 5: <strong>{html.escape(selected)}</strong>.</p>",
            "<p>HBOS và Isolation Forest được giữ cho fusion ở T6; "
            "Stacker được giữ làm ablation nếu primary gate không đạt.</p>",
            "<p>T5.1 vẫn chưa được mở cho tới khi có nghiệm thu thủ công T4.8.</p></section>",
            "<section><h2>Ranh giới thống kê</h2>",
            "<p>Bootstrap LOAFO resample chín family và giữ F3/F5/F7/F9 của cùng family bên nhau. "
            "Known validation resample nguyên time block trong từng capture; không bootstrap từng flow.</p>",
            "<p>CI theo checkpoint và hai anomaly baseline chỉ mang tính mô tả. "
            "Bốn case study không tham gia claim và không có phép chọn model, metric hoặc threshold từ test labels.</p>",
            "</section></main></body></html>",
        ]
    )
    report = "".join(parts)
    if "http://" in report or "https://" in report or "<script" in report.lower():
        raise ValueError("report must be self-contained")
    return report.encode("utf-8")


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
    prerequisite_records: Mapping[str, Any],
    analysis: Mapping[str, Any],
    report_path: Path,
    report_bytes: bytes,
    elapsed_seconds: float,
) -> dict[str, Any]:
    source_paths = [
        root / "python/nids_mvp/model_acceptance.py",
        root / "tests/test_t48_model_acceptance.py",
    ]
    validation = {
        "all_prerequisite_hashes_verified": True,
        "t4_7_manual_acceptance_verified": True,
        "separate_baseline_interpretation_exact": True,
        "no_new_anomaly_ensemble": True,
        "primary_family_and_checkpoint_scope_exact": True,
        "case_studies_excluded_from_inference": True,
        "known_prediction_identity_and_labels_exact": True,
        "known_split_join_cardinality_exact": True,
        "paired_family_bootstrap_exact": True,
        "paired_group_bootstrap_exact": True,
        "safeguards_applied_to_every_checkpoint": True,
        "no_model_fit_or_threshold_change": True,
        "test_labels_not_used_for_selection": True,
        "hooks_read_or_run": False,
        "dependency_or_environment_mutation": False,
        "report_self_contained": True,
        "atomic_first_publish": True,
    }
    return {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": KIND,
        "status": "passed",
        "generated_at_utc": utc_now(),
        "elapsed_seconds": float(elapsed_seconds),
        "contract": {
            "path": contract_path.relative_to(root).as_posix(),
            "size_bytes": contract_path.stat().st_size,
            "sha256": sha256_path(contract_path),
        },
        "runtime": {
            "python": os.sys.version.split()[0],
            "numpy": np.__version__,
            "pyarrow": pa.__version__,
        },
        "source_files": {
            path.relative_to(root).as_posix(): sha256_path(path)
            for path in source_paths
        },
        "input_evidence": dict(prerequisite_records),
        "analysis": analysis,
        "artifacts": {
            "report": {
                "path": report_path.relative_to(root).as_posix(),
                "size_bytes": len(report_bytes),
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
                "format": "self_contained_html_utf8",
            }
        },
        "validation": validation,
        "gate": {
            "decision": "pending_user_decision",
            "recommended_binary_classifier": analysis["decision"]["selection"][
                "phase_5_binary_classifier"
            ],
            "stacker_improvement_claim_supported": analysis["decision"][
                "stacker_improvement_claim_supported"
            ],
            "t5_1_authorized": False,
        },
    }


def run_acceptance(root: Path, contract_path: Path) -> dict[str, Any]:
    started = time.monotonic()
    contract, paths, prerequisite_records = verified_contract(root, contract_path)
    acceptance_path = resolve_inside(root, contract["artifacts"]["acceptance"]["path"])
    report_path = resolve_inside(root, contract["artifacts"]["report"]["path"])
    if acceptance_path.exists() or report_path.exists():
        raise FileExistsError("T4.8 evidence already exists")
    acceptance_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    analysis = build_analysis(contract, paths)
    report_bytes = render_report(analysis)
    receipt = build_receipt(
        root,
        contract_path,
        prerequisite_records,
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
    contract, paths, prerequisite_records = verified_contract(root, contract_path)
    acceptance_path = resolve_inside(root, contract["artifacts"]["acceptance"]["path"])
    report_path = resolve_inside(root, contract["artifacts"]["report"]["path"])
    receipt = load_json(acceptance_path)
    if (
        receipt.get("task") != TASK
        or receipt.get("kind") != KIND
        or receipt.get("status") != "passed"
        or receipt.get("contract", {}).get("sha256") != sha256_path(contract_path)
        or receipt.get("input_evidence") != prerequisite_records
        or receipt.get("gate", {}).get("decision") != "pending_user_decision"
        or receipt.get("gate", {}).get("t5_1_authorized") is not False
    ):
        raise ValueError("invalid T4.8 acceptance receipt")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.8 source mismatch: {value}")
    analysis = build_analysis(contract, paths)
    if receipt.get("analysis") != analysis:
        raise ValueError("T4.8 analysis mismatch")
    expected_report = render_report(analysis)
    artifact = receipt.get("artifacts", {}).get("report", {})
    if (
        artifact.get("path") != report_path.relative_to(root).as_posix()
        or not report_path.is_file()
        or artifact.get("size_bytes") != report_path.stat().st_size
        or artifact.get("sha256") != sha256_path(report_path)
        or report_path.read_bytes() != expected_report
    ):
        raise ValueError("T4.8 report mismatch")
    required = receipt.get("validation", {})
    if (
        not required
        or required.get("hooks_read_or_run") is not False
        or required.get("dependency_or_environment_mutation") is not False
        or not all(
            value is True
            for key, value in required.items()
            if key not in {"hooks_read_or_run", "dependency_or_environment_mutation"}
        )
    ):
        raise ValueError("T4.8 validation gate failed")
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the locked T4.8 model acceptance")
    parser.add_argument("command", choices=("run", "validate"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--contract",
        default="config/cicids2017-model-acceptance-contract.json",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    contract_path = resolve_inside(root, args.contract)
    if args.command == "run":
        receipt = run_acceptance(root, contract_path)
    else:
        receipt = validate_receipt(root, contract_path)
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "recommended_binary_classifier": receipt["gate"][
                    "recommended_binary_classifier"
                ],
                "stacker_improvement_claim_supported": receipt["gate"][
                    "stacker_improvement_claim_supported"
                ],
                "t5_1_authorized": receipt["gate"]["t5_1_authorized"],
                "report": receipt["artifacts"]["report"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
