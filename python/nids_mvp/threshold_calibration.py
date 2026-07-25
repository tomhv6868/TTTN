from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

DEPENDENCY_ERROR: ModuleNotFoundError | None = None
try:
    import numpy as np
    import pyarrow as pa
    import pyarrow.parquet as pq
except ModuleNotFoundError as error:
    DEPENDENCY_ERROR = error
    np = None
    pa = None
    pq = None


TASK = "T6.1"
CHECKPOINTS = ("F3", "F5", "F7", "F9")
FPR_CAP = 0.01
FLOW_RF_THRESHOLD = 0.5
GRID_MAX_INDIVIDUAL_FPR = 0.02
GRID_POINTS = 201
PREDICTION_COLUMNS = (
    "flow_rf_probability",
    "hbos_normalized_score",
    "isolation_forest_normalized_score",
)


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
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return path


def verify_artifact(root: Path, record: Mapping[str, Any], context: str) -> Path:
    path = resolve_inside(root, str(record.get("path", "")))
    if (
        not path.is_file()
        or path.stat().st_size != record.get("size_bytes")
        or sha256_path(path) != record.get("sha256")
    ):
        raise ValueError(f"{context} content mismatch: {path}")
    return path


def candidate_thresholds(
    benign_scores: np.ndarray,
    maximum_individual_fpr: float = GRID_MAX_INDIVIDUAL_FPR,
    points: int = GRID_POINTS,
) -> np.ndarray:
    values = np.asarray(benign_scores, dtype=np.float64)
    if (
        values.ndim != 1
        or values.size == 0
        or not np.isfinite(values).all()
        or not 0.0 < maximum_individual_fpr < 1.0
        or points < 2
    ):
        raise ValueError("invalid benign calibration scores or grid")
    rates = np.linspace(0.0, maximum_individual_fpr, points)
    thresholds = [float(np.nextafter(np.max(values), np.inf))]
    thresholds.extend(
        float(np.quantile(values, 1.0 - rate, method="higher"))
        for rate in rates[1:]
    )
    return np.unique(np.asarray(thresholds, dtype=np.float64))


def threshold_count_matrix(
    hbos_scores: np.ndarray,
    isolation_scores: np.ndarray,
    hbos_thresholds: np.ndarray,
    isolation_thresholds: np.ndarray,
    *,
    both_exceeded: bool,
) -> np.ndarray:
    hbos = np.asarray(hbos_scores, dtype=np.float64)
    isolation = np.asarray(isolation_scores, dtype=np.float64)
    if (
        hbos.ndim != 1
        or isolation.ndim != 1
        or hbos.shape != isolation.shape
        or not np.isfinite(hbos).all()
        or not np.isfinite(isolation).all()
    ):
        raise ValueError("invalid paired anomaly scores")
    hbos_index = np.searchsorted(hbos_thresholds, hbos, side="right")
    isolation_index = np.searchsorted(
        isolation_thresholds,
        isolation,
        side="right",
    )
    histogram = np.zeros(
        (len(hbos_thresholds) + 1, len(isolation_thresholds) + 1),
        dtype=np.int64,
    )
    np.add.at(histogram, (hbos_index, isolation_index), 1)
    if both_exceeded:
        reverse = histogram[::-1, ::-1].cumsum(0).cumsum(1)[::-1, ::-1]
        return reverse[1:, 1:]
    return histogram.cumsum(0).cumsum(1)[:-1, :-1]


def validate_score_arrays(
    flow_probability: np.ndarray,
    hbos_score: np.ndarray,
    isolation_score: np.ndarray,
    y_true: np.ndarray,
) -> None:
    arrays = (
        np.asarray(flow_probability),
        np.asarray(hbos_score),
        np.asarray(isolation_score),
        np.asarray(y_true),
    )
    if any(value.ndim != 1 for value in arrays):
        raise ValueError("calibration arrays must be one-dimensional")
    if len({value.shape for value in arrays}) != 1 or arrays[0].size == 0:
        raise ValueError("calibration array shapes differ")
    if (
        not np.isfinite(arrays[0]).all()
        or not np.isfinite(arrays[1]).all()
        or not np.isfinite(arrays[2]).all()
        or not np.isin(arrays[3], (0, 1)).all()
        or not np.any(arrays[3] == 0)
        or not np.any(arrays[3] == 1)
    ):
        raise ValueError("invalid calibration score or label values")


def calibrate_checkpoint(
    flow_probability: np.ndarray,
    hbos_score: np.ndarray,
    isolation_score: np.ndarray,
    y_true: np.ndarray,
    unknown_scores: Mapping[str, tuple[np.ndarray, np.ndarray, np.ndarray]],
    confirmatory_families: Sequence[str],
    *,
    fpr_cap: float = FPR_CAP,
    flow_threshold: float = FLOW_RF_THRESHOLD,
    maximum_individual_fpr: float = GRID_MAX_INDIVIDUAL_FPR,
    grid_points: int = GRID_POINTS,
) -> dict[str, Any]:
    validate_score_arrays(
        flow_probability,
        hbos_score,
        isolation_score,
        y_true,
    )
    if not 0.0 < fpr_cap < 1.0 or not 0.0 <= flow_threshold <= 1.0:
        raise ValueError("invalid calibration policy")
    flow = np.asarray(flow_probability, dtype=np.float64)
    hbos = np.asarray(hbos_score, dtype=np.float64)
    isolation = np.asarray(isolation_score, dtype=np.float64)
    labels = np.asarray(y_true, dtype=np.uint8)
    benign = labels == 0
    known = labels == 1
    hbos_thresholds = candidate_thresholds(
        hbos[benign],
        maximum_individual_fpr,
        grid_points,
    )
    isolation_thresholds = candidate_thresholds(
        isolation[benign],
        maximum_individual_fpr,
        grid_points,
    )

    benign_flow_attack = benign & (flow >= flow_threshold)
    benign_non_flow = benign & ~benign_flow_attack
    benign_below_both = threshold_count_matrix(
        hbos[benign_non_flow],
        isolation[benign_non_flow],
        hbos_thresholds,
        isolation_thresholds,
        both_exceeded=False,
    )
    benign_alerts = (
        int(np.count_nonzero(benign_flow_attack))
        + int(np.count_nonzero(benign_non_flow))
        - benign_below_both
    )
    fusion_fpr = benign_alerts.astype(np.float64) / int(np.count_nonzero(benign))

    known_flow_attack = known & (flow >= flow_threshold)
    known_non_flow = known & ~known_flow_attack
    known_below_both = threshold_count_matrix(
        hbos[known_non_flow],
        isolation[known_non_flow],
        hbos_thresholds,
        isolation_thresholds,
        both_exceeded=False,
    )
    known_alerts = (
        int(np.count_nonzero(known_flow_attack))
        + int(np.count_nonzero(known_non_flow))
        - known_below_both
    )
    known_recall = known_alerts.astype(np.float64) / int(np.count_nonzero(known))

    expected_families = tuple(confirmatory_families)
    if not expected_families or any(
        family not in unknown_scores for family in expected_families
    ):
        raise ValueError("confirmatory LOAFO family scores are incomplete")
    macro_unknown_candidate = np.zeros_like(fusion_fpr, dtype=np.float64)
    case_study_rates: dict[str, np.ndarray] = {}
    for family, family_scores in unknown_scores.items():
        family_flow, family_hbos, family_isolation = (
            np.asarray(value, dtype=np.float64) for value in family_scores
        )
        if (
            family_flow.ndim != 1
            or family_flow.size == 0
            or family_flow.shape != family_hbos.shape
            or family_flow.shape != family_isolation.shape
            or not np.isfinite(family_flow).all()
            or not np.isfinite(family_hbos).all()
            or not np.isfinite(family_isolation).all()
        ):
            raise ValueError(f"invalid LOAFO scores: {family}")
        anomaly_eligible = family_flow < flow_threshold
        both = threshold_count_matrix(
            family_hbos[anomaly_eligible],
            family_isolation[anomaly_eligible],
            hbos_thresholds,
            isolation_thresholds,
            both_exceeded=True,
        ).astype(np.float64) / family_flow.size
        if family in expected_families:
            macro_unknown_candidate += both / len(expected_families)
        else:
            case_study_rates[family] = both

    feasible = fusion_fpr <= fpr_cap
    if not np.any(feasible):
        raise ValueError("no threshold pair satisfies the FPR cap")
    feasible_unknown = np.where(feasible, macro_unknown_candidate, -1.0)
    best_unknown = float(np.max(feasible_unknown))
    candidates = np.argwhere(
        np.isclose(feasible_unknown, best_unknown, rtol=0.0, atol=1e-15)
    )
    selected = max(
        candidates,
        key=lambda index: (
            known_recall[tuple(index)],
            -fusion_fpr[tuple(index)],
        ),
    )
    hbos_index, isolation_index = (int(value) for value in selected)
    current_flow = flow >= flow_threshold
    baseline_known_recall = float(np.mean(current_flow[known], dtype=np.float64))
    result = {
        "flow_rf_threshold": float(flow_threshold),
        "hbos_normalized_threshold": float(hbos_thresholds[hbos_index]),
        "isolation_forest_normalized_threshold": float(
            isolation_thresholds[isolation_index]
        ),
        "validation": {
            "benign_rows": int(np.count_nonzero(benign)),
            "known_attack_rows": int(np.count_nonzero(known)),
            "fusion_fpr": float(fusion_fpr[hbos_index, isolation_index]),
            "false_alerts_per_100k_benign_flows": float(
                fusion_fpr[hbos_index, isolation_index] * 100_000.0
            ),
            "known_recall": float(known_recall[hbos_index, isolation_index]),
            "flow_rf_baseline_known_recall": baseline_known_recall,
        },
        "loafo": {
            "confirmatory_family_count": len(expected_families),
            "macro_unknown_candidate_recall": float(
                macro_unknown_candidate[hbos_index, isolation_index]
            ),
            "case_study_unknown_candidate_recall": {
                family: float(values[hbos_index, isolation_index])
                for family, values in sorted(case_study_rates.items())
            },
        },
        "search": {
            "maximum_individual_anomaly_fpr": float(maximum_individual_fpr),
            "grid_points_per_anomaly_model": int(grid_points),
            "feasible_pairs": int(np.count_nonzero(feasible)),
            "candidate_pairs": int(fusion_fpr.size),
        },
    }
    if result["validation"]["known_recall"] < baseline_known_recall:
        raise ValueError("calibration reduced known recall")
    return result


def read_unknown_scores(
    path: Path,
    checkpoint: str,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    table = pq.read_table(
        path,
        columns=list(PREDICTION_COLUMNS),
        filters=[
            ("checkpoint", "=", checkpoint),
            ("evaluation_role", "=", "unknown_holdout"),
        ],
    )
    if table.num_rows == 0:
        raise ValueError(f"empty LOAFO holdout population: {path}/{checkpoint}")
    return tuple(
        column.to_numpy(zero_copy_only=False) for column in table.columns
    )


def build_threshold_artifact(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    t42_path = root / "run_log/t4.2/acceptance.json"
    t43_path = root / "run_log/t4.3/acceptance.json"
    t47_path = root / "run_log/t4.7-rf300/acceptance.json"
    scope_path = root / "config/cicids2017-model-acceptance-contract.json"
    t42 = load_json(t42_path)
    t43 = load_json(t43_path)
    t47 = load_json(t47_path)
    scope = load_json(scope_path)
    if any(value.get("status") != "passed" for value in (t42, t43, t47)):
        raise ValueError("T6.1 prerequisite acceptance is not passed")
    rf_path = verify_artifact(
        root,
        t42["artifacts"]["validation_predictions"],
        "T4.2 validation predictions",
    )
    anomaly_path = verify_artifact(
        root,
        t43["artifacts"]["validation_predictions"],
        "T4.3 validation predictions",
    )
    confirmatory_names = tuple(scope["family_scope"]["macro_aggregate"])
    case_study_names = {"PortScan"}
    required_names = set(confirmatory_names) | case_study_names
    family_artifacts: dict[str, dict[str, Any]] = {}
    family_paths: dict[str, Path] = {}
    for directory in sorted((root / "run_log/t4.7-rf300").iterdir()):
        receipt_path = directory / "receipt.json"
        if not receipt_path.is_file():
            continue
        receipt = load_json(receipt_path)
        family = str(receipt.get("holdout_family", ""))
        if family not in required_names:
            continue
        if receipt.get("status") != "passed" or receipt.get("task") != "T4.7":
            raise ValueError(f"invalid T4.7 family receipt: {family}")
        prediction = verify_artifact(
            root,
            receipt["prediction_artifact"],
            f"T4.7 prediction {family}",
        )
        family_paths[family] = prediction
        family_artifacts[family] = {
            "receipt_sha256": sha256_path(receipt_path),
            "prediction_sha256": sha256_path(prediction),
            "prediction_rows": int(receipt["prediction_artifact"]["rows"]),
        }
    if set(family_paths) != required_names:
        missing = sorted(required_names - set(family_paths))
        raise ValueError(f"missing T4.7 family evidence: {missing}")

    with np.load(rf_path, allow_pickle=False) as rf, np.load(
        anomaly_path,
        allow_pickle=False,
    ) as anomaly:
        checkpoint_results: dict[str, Any] = {}
        for checkpoint in CHECKPOINTS:
            identities = ("capture_id", "flow_id", "y_true")
            if any(
                not np.array_equal(
                    rf[f"{checkpoint}__{name}"],
                    anomaly[f"{checkpoint}__{name}"],
                )
                for name in identities
            ):
                raise ValueError(
                    f"T4.2/T4.3 validation identity mismatch: {checkpoint}"
                )
            unknown = {
                family: read_unknown_scores(path, checkpoint)
                for family, path in family_paths.items()
            }
            selected = calibrate_checkpoint(
                rf[f"{checkpoint}__attack_probability"],
                anomaly[f"{checkpoint}__hbos__normalized_score"],
                anomaly[
                    f"{checkpoint}__isolation_forest__normalized_score"
                ],
                rf[f"{checkpoint}__y_true"],
                unknown,
                confirmatory_names,
            )
            selected["prior_provisional_thresholds"] = {
                "hbos_normalized_threshold": float(
                    t43["models"][checkpoint]["hbos"]["normalized_threshold"]
                ),
                "isolation_forest_normalized_threshold": float(
                    t43["models"][checkpoint]["isolation_forest"][
                        "normalized_threshold"
                    ]
                ),
            }
            checkpoint_results[checkpoint] = selected

    artifact = {
        "schema_version": "1.0.0",
        "task": TASK,
        "status": "accepted",
        "kind": "fusion_thresholds",
        "policy": {
            "benign_validation_fpr_cap": FPR_CAP,
            "flow_rf_threshold": FLOW_RF_THRESHOLD,
            "flow_rf_threshold_locked": True,
            "comparison": "score >= threshold",
            "primary_objective": "macro LOAFO unknown_candidate recall",
            "tie_breakers": [
                "known validation recall",
                "lower benign validation FPR",
            ],
        },
        "checkpoints": checkpoint_results,
        "limitations": {
            "alerts_per_hour": (
                "not estimated because accepted prediction artifacts do not "
                "contain a traffic-duration denominator"
            ),
            "portscan": "case study only; not used to select thresholds",
            "runtime_activation": "deferred to T6.2 decision-engine integration",
        },
    }
    sources = {
        "t4.2_acceptance": sha256_path(t42_path),
        "t4.2_validation_predictions": sha256_path(rf_path),
        "t4.3_acceptance": sha256_path(t43_path),
        "t4.3_validation_predictions": sha256_path(anomaly_path),
        "t4.7_acceptance": sha256_path(t47_path),
        "family_scope_contract": sha256_path(scope_path),
        "loafo_families": family_artifacts,
    }
    return artifact, sources


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def write_exclusive(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        with path.open("xb") as output:
            output.write(temporary_path.read_bytes())
            output.flush()
            os.fsync(output.fileno())
    finally:
        temporary_path.unlink(missing_ok=True)


def run(root: Path, output_dir: Path) -> dict[str, Any]:
    threshold_path = output_dir / "thresholds.json"
    acceptance_path = output_dir / "acceptance.json"
    if threshold_path.exists() or acceptance_path.exists():
        raise FileExistsError("T6.1 output already exists")
    artifact, sources = build_threshold_artifact(root)
    write_exclusive(threshold_path, canonical_json(artifact))
    try:
        receipt = {
            "schema_version": "1.0.0",
            "task": TASK,
            "status": "passed",
            "kind": "threshold_calibration_acceptance",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "artifact": {
                "path": threshold_path.relative_to(root).as_posix(),
                "size_bytes": threshold_path.stat().st_size,
                "sha256": sha256_path(threshold_path),
            },
            "sources": sources,
            "acceptance": {
                "fpr_cap_exact": all(
                    value["validation"]["fusion_fpr"] <= FPR_CAP
                    for value in artifact["checkpoints"].values()
                ),
                "flow_rf_threshold_unchanged": all(
                    value["flow_rf_threshold"] == FLOW_RF_THRESHOLD
                    for value in artifact["checkpoints"].values()
                ),
                "known_recall_not_reduced": all(
                    value["validation"]["known_recall"]
                    >= value["validation"]["flow_rf_baseline_known_recall"]
                    for value in artifact["checkpoints"].values()
                ),
                "confirmatory_loafo_family_count": artifact["checkpoints"][
                    "F3"
                ]["loafo"]["confirmatory_family_count"],
                "model_training_performed": False,
                "test_partition_used": False,
                "runtime_activation_deferred_to": "T6.2",
            },
            "runtime": {
                "python": sys.version.split()[0],
                "numpy": np.__version__,
                "pyarrow": pa.__version__,
            },
        }
        if not all(
            (
                receipt["acceptance"]["fpr_cap_exact"],
                receipt["acceptance"]["flow_rf_threshold_unchanged"],
                receipt["acceptance"]["known_recall_not_reduced"],
            )
        ):
            raise ValueError("T6.1 acceptance invariant failed")
        write_exclusive(acceptance_path, canonical_json(receipt))
        return receipt
    except BaseException:
        threshold_path.unlink(missing_ok=True)
        raise


def validate(root: Path, output_dir: Path) -> dict[str, Any]:
    threshold_path = output_dir / "thresholds.json"
    acceptance_path = output_dir / "acceptance.json"
    artifact = load_json(threshold_path)
    receipt = load_json(acceptance_path)
    expected, sources = build_threshold_artifact(root)
    if artifact != expected:
        raise ValueError("T6.1 threshold artifact differs from recomputation")
    if (
        receipt.get("task") != TASK
        or receipt.get("status") != "passed"
        or receipt.get("sources") != sources
        or receipt.get("artifact", {}).get("sha256")
        != sha256_path(threshold_path)
        or receipt.get("artifact", {}).get("size_bytes")
        != threshold_path.stat().st_size
    ):
        raise ValueError("T6.1 acceptance receipt mismatch")
    return receipt


def write_failed_attempt(output_dir: Path, error: BaseException) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = output_dir / f"failed-attempt-{stamp}.json"
    value = {
        "schema_version": "1.0.0",
        "task": TASK,
        "status": "failed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "error_type": type(error).__name__,
        "error": str(error),
    }
    write_exclusive(path, canonical_json(value))
    return path


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Calibrate accepted Phase 6 fusion thresholds"
    )
    parser.add_argument("command", choices=("run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    root = args.project_root.resolve()
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir is not None
        else root / "run_log/t6.1"
    )
    try:
        if DEPENDENCY_ERROR is not None:
            raise RuntimeError(
                f"locked calibration dependencies unavailable: {DEPENDENCY_ERROR}"
            )
        receipt = (
            run(root, output_dir)
            if args.command == "run"
            else validate(root, output_dir)
        )
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        failed = write_failed_attempt(output_dir, error)
        print(f"failed_attempt_receipt: {failed}", file=sys.stderr)
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
