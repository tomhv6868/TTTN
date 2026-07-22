from __future__ import annotations

import argparse
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


def write_text(path: Path, value: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(value)
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
        or expected.get("model_training_allowed") is not False
        or expected.get("hooks_in_scope") is not False
    ):
        raise RuntimeError(f"T4.3 EDA runtime contract mismatch: {observed}")


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
    if contract.get("task") != TASK or contract.get("phase") != "eda":
        raise ValueError("invalid T4.3 EDA contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    manual = load_json(paths["t4_2_manual_acceptance"])
    if (
        manual.get("status") != "passed"
        or manual.get("decision") != "accepted"
        or not manual.get("gate", {}).get("t4_3_authorized")
    ):
        raise ValueError("T4.2 manual acceptance does not authorize T4.3")
    technical = load_json(paths["t4_2_technical_acceptance"])
    if technical.get("status") != "passed":
        raise ValueError("T4.2 technical acceptance mismatch")
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
        profile = artifact.get("checkpoints", {}).get(checkpoint, {}).get("profiles", {}).get("anomaly_benign")
        expected = contract["expected_population"][checkpoint]
        if not isinstance(profile, dict):
            raise ValueError(f"missing T4.1 anomaly profile: {checkpoint}")
        if (
            profile.get("fit_population_rows") != expected["rows"]
            or len(profile.get("selected_features", [])) != expected["selected_feature_count"]
            or profile.get("dropped_constant_features") != expected["dropped_features"]
            or profile.get("input_features") != features
            or profile.get("output_dtype") != "float32"
        ):
            raise ValueError(f"T4.1 anomaly profile drift: {checkpoint}")
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


def materialize_benign_train(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    input_features: Sequence[str],
    profile: Mapping[str, Any],
    expected_rows: int,
    scratch: Path,
) -> tuple[Path, dict[str, dict[str, int]]]:
    output_path = scratch / f"{checkpoint}-benign-train.npy"
    selected_features = list(profile["selected_features"])
    matrix = np.lib.format.open_memmap(
        output_path,
        mode="w+",
        dtype=np.float32,
        shape=(expected_rows, len(selected_features)),
    )
    raw_counts = {
        feature: {"nan_count": 0, "positive_infinity_count": 0, "negative_infinity_count": 0}
        for feature in input_features
    }
    offset = 0
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
            benign_indices: list[int] = []
            for index, (flow_id, family) in enumerate(zip(flow_ids, families, strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] not in {"train", "validation", "test"}:
                    raise ValueError(f"unknown split partition: {mapped[0]}")
                if mapped[0] == "train" and family == "BENIGN":
                    benign_indices.append(index)
            if not benign_indices:
                continue
            raw = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(input_features))]
            ).astype(np.float64, copy=False)[benign_indices]
            for feature_index, feature in enumerate(input_features):
                values = raw[:, feature_index]
                raw_counts[feature]["nan_count"] += int(np.count_nonzero(np.isnan(values)))
                raw_counts[feature]["positive_infinity_count"] += int(np.count_nonzero(np.isposinf(values)))
                raw_counts[feature]["negative_infinity_count"] += int(np.count_nonzero(np.isneginf(values)))
            transformed = preprocessing.transform_with_artifact(raw, input_features, profile)
            stop = offset + len(transformed)
            if stop > expected_rows:
                raise ValueError(f"benign train/{checkpoint} exceeds expected rows")
            matrix[offset:stop] = transformed
            offset = stop
    matrix.flush()
    if offset != expected_rows:
        raise ValueError(f"benign train/{checkpoint} population mismatch: {offset}")
    del matrix
    return output_path, raw_counts


def deterministic_indices(rows: int, maximum: int) -> np.ndarray:
    count = min(rows, maximum)
    return np.unique(np.linspace(0, rows - 1, num=count, dtype=np.int64))


def hbos_diagnostics(
    matrix: np.ndarray,
    features: Sequence[str],
    candidate_bins: Sequence[int],
) -> dict[str, list[dict[str, Any]]]:
    largest = max(candidate_bins)
    if any(largest % candidate != 0 for candidate in candidate_bins):
        raise ValueError("HBOS candidate bins must divide the largest candidate")
    probabilities = np.linspace(0.0, 1.0, largest + 1)
    largest_edges = np.quantile(matrix, probabilities, axis=0, method="linear")
    result: dict[str, list[dict[str, Any]]] = {str(value): [] for value in candidate_bins}
    for feature_index, feature in enumerate(features):
        column = np.asarray(matrix[:, feature_index])
        for requested in candidate_bins:
            stride = largest // requested
            edges = np.unique(largest_edges[::stride, feature_index])
            effective = len(edges) - 1
            if effective < 1:
                raise ValueError(f"quantile edges collapsed completely: {feature}")
            counts, _ = np.histogram(column, bins=edges)
            masses = counts.astype(np.float64) / len(column)
            result[str(requested)].append(
                {
                    "feature": feature,
                    "requested_bin_count": int(requested),
                    "effective_bin_count": int(effective),
                    "collapsed_edge_count": int(requested - effective),
                    "minimum_bin_mass": float(masses.min()),
                    "maximum_bin_mass": float(masses.max()),
                }
            )
    return result


def analyze_matrix(
    matrix_path: Path,
    features: Sequence[str],
    quantile_probabilities: Sequence[float],
    sample_maximum: int,
    correlation_threshold: float,
    candidate_bins: Sequence[int],
) -> dict[str, Any]:
    matrix = np.load(matrix_path, mmap_mode="r")
    if matrix.ndim != 2 or matrix.shape[1] != len(features):
        raise ValueError("materialized EDA matrix shape mismatch")
    if not np.isfinite(matrix).all():
        raise ValueError("transformed benign-train matrix contains non-finite values")
    quantiles = np.quantile(matrix, quantile_probabilities, axis=0, method="linear")
    means = np.mean(matrix, axis=0, dtype=np.float64)
    standard_deviations = np.std(matrix, axis=0, dtype=np.float64)
    minimums = np.min(matrix, axis=0)
    maximums = np.max(matrix, axis=0)
    indices = deterministic_indices(matrix.shape[0], sample_maximum)
    sample = np.asarray(matrix[indices], dtype=np.float64)
    unique_counts = [int(np.unique(sample[:, index]).size) for index in range(sample.shape[1])]
    sample_standard_deviations = np.std(sample, axis=0, dtype=np.float64)
    sample_constant_indices = np.flatnonzero(sample_standard_deviations == 0.0)
    correlation = np.corrcoef(sample, rowvar=False)
    pairs: list[dict[str, Any]] = []
    for left in range(len(features)):
        for right in range(left + 1, len(features)):
            value = float(correlation[left, right])
            if np.isfinite(value) and abs(value) >= correlation_threshold:
                pairs.append(
                    {
                        "left": features[left],
                        "right": features[right],
                        "pearson": value,
                        "absolute_pearson": abs(value),
                    }
                )
    pairs.sort(key=lambda item: (-item["absolute_pearson"], item["left"], item["right"]))
    feature_statistics = []
    for index, feature in enumerate(features):
        feature_statistics.append(
            {
                "feature": feature,
                "count": int(matrix.shape[0]),
                "finite_count": int(matrix.shape[0]),
                "mean": float(means[index]),
                "standard_deviation": float(standard_deviations[index]),
                "minimum": float(minimums[index]),
                "maximum": float(maximums[index]),
                "quantiles": {
                    f"{probability:g}": float(quantiles[position, index])
                    for position, probability in enumerate(quantile_probabilities)
                },
                "sample_unique_count": unique_counts[index],
            }
        )
    diagnostics = hbos_diagnostics(matrix, features, candidate_bins)
    return {
        "rows": int(matrix.shape[0]),
        "selected_feature_count": len(features),
        "sample": {
            "row_count": int(len(indices)),
            "selection": "sorted unique numpy.linspace indices over the materialized benign-train row order",
            "sample_constant_features": [features[index] for index in sample_constant_indices],
        },
        "feature_statistics": feature_statistics,
        "correlation_audit": {
            "method": "pearson",
            "absolute_report_threshold": correlation_threshold,
            "reported_pair_count": len(pairs),
            "pairs": pairs,
            "feature_pruning_performed": False,
        },
        "hbos_candidate_diagnostics": {
            "edge_strategy": "feature-wise empirical quantiles with duplicate edges collapsed",
            "population": "all benign train rows",
            "candidates": diagnostics,
            "winner_selected": False,
        },
    }


def render_report(receipt: Mapping[str, Any], json_sha256: str) -> str:
    lines = [
        "# T4.3 — EDA cho anomaly baseline",
        "",
        "EDA này chỉ dùng các flow `BENIGN` thuộc train và tái sử dụng profile `anomaly_benign` của T4.1. "
        "Không có model, feature mask, số bins hoặc threshold cuối cùng nào được chọn trong bước này.",
        "",
        f"- SHA-256 của `run_log/t4.3/eda.json`: `{json_sha256}`",
        f"- Trạng thái: `{receipt['status']}`",
        "- Validation, test và attack-train đóng góp vào thống kê: `không`",
        "",
        "## Phạm vi dữ liệu",
        "",
        "| Checkpoint | Benign train | Feature sau T4.1 | Mẫu correlation | Cặp |NaN raw| |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for checkpoint, result in receipt["checkpoints"].items():
        raw_nan = sum(value["nan_count"] for value in result["raw_feature_checks"].values())
        lines.append(
            f"| {checkpoint} | {result['rows']:,} | {result['selected_feature_count']} | "
            f"{result['sample']['row_count']:,} | {result['correlation_audit']['reported_pair_count']} | {raw_nan:,} |"
        )
    lines.extend(
        [
            "",
            "## Tương quan cao",
            "",
            "Các bảng dưới đây chỉ nêu bằng chứng `|Pearson| >= 0.98`; chúng không tự động loại feature.",
            "",
        ]
    )
    for checkpoint, result in receipt["checkpoints"].items():
        lines.extend([f"### {checkpoint}", "", "| Feature A | Feature B | Pearson |", "|---|---|---:|"])
        pairs = result["correlation_audit"]["pairs"][:20]
        if pairs:
            for pair in pairs:
                lines.append(f"| `{pair['left']}` | `{pair['right']}` | {pair['pearson']:.6f} |")
        else:
            lines.append("| _Không có_ | _Không có_ | — |")
        lines.append("")
    lines.extend(
        [
            "## Độ nhạy candidate bins của HBOS",
            "",
            "`effective < requested` nghĩa là quantile edges bị gộp do feature có nhiều giá trị trùng. "
            "Bảng chỉ tổng hợp số feature bị collapse; chưa chọn candidate thắng.",
            "",
            "| Checkpoint | Requested bins | Feature bị collapse | Effective bins nhỏ nhất |",
            "|---|---:|---:|---:|",
        ]
    )
    for checkpoint, result in receipt["checkpoints"].items():
        candidates = result["hbos_candidate_diagnostics"]["candidates"]
        for requested, features in candidates.items():
            collapsed = sum(item["collapsed_edge_count"] > 0 for item in features)
            minimum = min(item["effective_bin_count"] for item in features)
            lines.append(f"| {checkpoint} | {requested} | {collapsed} | {minimum} |")
    lines.extend(
        [
            "",
            "## Cổng quyết định",
            "",
            "Cần người dùng xem evidence machine-readable trước khi khóa feature mask HBOS, số bins, "
            "tham số Isolation Forest, chuẩn hóa score và binary threshold trong model contract T4.3.",
            "",
        ]
    )
    return "\n".join(lines)


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, parts, flow_map, input_features, artifact = verify_inputs(root, contract_path)
    json_path = resolve_inside(root, contract["artifacts"]["machine_readable_eda"]["path"])
    report_path = resolve_inside(root, contract["artifacts"]["human_readable_report"]["path"])
    if json_path.exists() or report_path.exists():
        raise FileExistsError("T4.3 EDA artifact already exists; refusing to overwrite evidence")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="nids-t43-eda-", dir=root / "run_log") as temporary:
        scratch = Path(temporary)
        for checkpoint in contract["input"]["checkpoints"]:
            checkpoint_started = time.monotonic()
            print(f"[T4.3 EDA] checkpoint={checkpoint} stage=materialize", flush=True)
            profile = artifact["checkpoints"][checkpoint]["profiles"]["anomaly_benign"]
            expected = contract["expected_population"][checkpoint]
            matrix_path, raw_counts = materialize_benign_train(
                checkpoint,
                parts,
                flow_map,
                input_features,
                profile,
                int(expected["rows"]),
                scratch,
            )
            print(f"[T4.3 EDA] checkpoint={checkpoint} stage=analyze", flush=True)
            result = analyze_matrix(
                matrix_path,
                profile["selected_features"],
                contract["eda"]["transformed_feature_statistics"]["quantile_probabilities"],
                int(contract["eda"]["deterministic_sample"]["maximum_rows_per_checkpoint"]),
                float(contract["eda"]["correlation_audit"]["absolute_pearson_report_threshold"]),
                contract["eda"]["hbos_candidate_diagnostics"]["candidate_bin_counts"],
            )
            result["raw_feature_checks"] = raw_counts
            result["dropped_constant_features"] = profile["dropped_constant_features"]
            result["elapsed_seconds"] = time.monotonic() - checkpoint_started
            results[checkpoint] = result
            matrix_path.unlink()
            print(
                f"[T4.3 EDA] checkpoint={checkpoint} stage=complete "
                f"elapsed_seconds={result['elapsed_seconds']:.1f}",
                flush=True,
            )
    sources = [
        root / "config/agent/current-task.json",
        contract_path,
        root / "python/nids_mvp/anomaly_eda.py",
        root / "tests/test_t43_anomaly_eda.py",
    ]
    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "phase": "eda",
        "kind": "anomaly_eda_evidence",
        "status": "passed",
        "artifact_id": contract["artifacts"]["machine_readable_eda"]["id"],
        "artifact_version": contract["artifacts"]["machine_readable_eda"]["version"],
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
        "checkpoints": results,
        "validation": {
            "all_prerequisite_hashes_verified": True,
            "exact_benign_train_population": True,
            "preprocessing_reused_without_refit": True,
            "feature_order_exact": True,
            "validation_rows_excluded_from_statistics": True,
            "test_rows_excluded_from_statistics": True,
            "attack_train_rows_excluded_from_statistics": True,
            "raw_flow_rows_not_emitted": True,
            "final_model_fit": False,
            "feature_mask_selected": False,
            "hbos_bin_count_selected": False,
            "isolation_forest_parameters_selected": False,
            "decision_threshold_selected": False,
        },
        "gate": {
            "decision": "pending_user_review",
            "model_contract_authorized": False,
        },
    }
    json_temp = temporary_sibling(json_path)
    report_temp = temporary_sibling(report_path)
    try:
        write_json(json_temp, receipt)
        json_sha256 = sha256_path(json_temp)
        write_text(report_temp, render_report(receipt, json_sha256))
        os.replace(report_temp, report_path)
        os.replace(json_temp, json_path)
    finally:
        json_temp.unlink(missing_ok=True)
        report_temp.unlink(missing_ok=True)
    return receipt


def validate_receipt(root: Path, contract_path: Path) -> None:
    contract, _, _, _, artifact = verify_inputs(root, contract_path)
    json_path = resolve_inside(root, contract["artifacts"]["machine_readable_eda"]["path"])
    report_path = resolve_inside(root, contract["artifacts"]["human_readable_report"]["path"])
    receipt = load_json(json_path)
    if (
        receipt.get("task") != TASK
        or receipt.get("phase") != "eda"
        or receipt.get("status") != "passed"
        or receipt.get("artifact_id") != contract["artifacts"]["machine_readable_eda"]["id"]
        or receipt.get("artifact_version") != contract["artifacts"]["machine_readable_eda"]["version"]
    ):
        raise ValueError("invalid T4.3 EDA artifact")
    expected_sources = [
        root / "config/agent/current-task.json",
        contract_path,
        root / "python/nids_mvp/anomaly_eda.py",
        root / "tests/test_t43_anomaly_eda.py",
    ]
    observed_sources = receipt.get("source_files", {})
    for path in expected_sources:
        if observed_sources.get(relative(path, root)) != sha256_path(path):
            raise ValueError(f"T4.3 EDA source hash mismatch: {path}")
    validation = receipt.get("validation", {})
    required_true = [
        "all_prerequisite_hashes_verified",
        "exact_benign_train_population",
        "preprocessing_reused_without_refit",
        "feature_order_exact",
        "validation_rows_excluded_from_statistics",
        "test_rows_excluded_from_statistics",
        "attack_train_rows_excluded_from_statistics",
        "raw_flow_rows_not_emitted",
    ]
    required_false = [
        "final_model_fit",
        "feature_mask_selected",
        "hbos_bin_count_selected",
        "isolation_forest_parameters_selected",
        "decision_threshold_selected",
    ]
    if not all(validation.get(name) is True for name in required_true):
        raise ValueError("T4.3 EDA positive scope gate mismatch")
    if not all(validation.get(name) is False for name in required_false):
        raise ValueError("T4.3 EDA negative scope gate mismatch")
    for checkpoint in contract["input"]["checkpoints"]:
        result = receipt.get("checkpoints", {}).get(checkpoint, {})
        expected = contract["expected_population"][checkpoint]
        profile = artifact["checkpoints"][checkpoint]["profiles"]["anomaly_benign"]
        if (
            result.get("rows") != expected["rows"]
            or result.get("selected_feature_count") != expected["selected_feature_count"]
            or result.get("dropped_constant_features") != expected["dropped_features"]
            or [item.get("feature") for item in result.get("feature_statistics", [])]
            != profile["selected_features"]
            or result.get("correlation_audit", {}).get("feature_pruning_performed") is not False
            or result.get("hbos_candidate_diagnostics", {}).get("winner_selected") is not False
        ):
            raise ValueError(f"T4.3 EDA checkpoint mismatch: {checkpoint}")
        for item in result["feature_statistics"]:
            if item["count"] != expected["rows"] or item["finite_count"] != expected["rows"]:
                raise ValueError(f"T4.3 EDA feature count mismatch: {checkpoint}/{item['feature']}")
        for requested in contract["eda"]["hbos_candidate_diagnostics"]["candidate_bin_counts"]:
            diagnostics = result["hbos_candidate_diagnostics"]["candidates"].get(str(requested), [])
            if len(diagnostics) != expected["selected_feature_count"]:
                raise ValueError(f"T4.3 EDA HBOS diagnostics mismatch: {checkpoint}/{requested}")
    report = report_path.read_text(encoding="utf-8")
    if sha256_path(json_path) not in report or "pending_user_review" in report:
        raise ValueError("T4.3 EDA report does not bind the machine-readable artifact")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Generate and validate T4.3 benign-train anomaly EDA")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path("config/cicids2017-anomaly-eda-contract.json"),
    )
    args = parser.parse_args(argv)
    root = args.project_root.resolve()
    contract_path = resolve_inside(root, str(args.contract))
    if args.command == "check":
        verify_inputs(root, contract_path)
        print("T4.3 EDA input check passed")
    elif args.command == "run":
        publish(root, contract_path)
        print("T4.3 EDA artifacts published")
    else:
        validate_receipt(root, contract_path)
        print("T4.3 EDA validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
