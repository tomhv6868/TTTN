from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
from bisect import bisect_right
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

DEPENDENCY_ERROR: ModuleNotFoundError | None = None
try:
    import joblib
    import numpy as np
    import sklearn
except ModuleNotFoundError as error:
    DEPENDENCY_ERROR = error
    joblib = None
    np = None
    sklearn = None


CHECKPOINTS = ("F3", "F5", "F7", "F9")
REFERENCE_ABSOLUTE_TOLERANCE = 1e-5
NATIVE_RECORD_PREFIX = "T53_PARITY_JSON "


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


def verify_reference(
    root: Path,
    record: Mapping[str, Any],
    context: str,
) -> Path:
    path = (root / str(record.get("path", ""))).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{context} path escapes project root") from error
    if (
        not path.is_file()
        or path.stat().st_size != record.get("size_bytes")
        or sha256_path(path) != record.get("sha256")
    ):
        raise ValueError(f"{context} content mismatch: {path}")
    return path


def transform(profile: Mapping[str, Any], raw: np.ndarray) -> np.ndarray:
    values = raw.copy()
    imputation = np.asarray(profile["imputation_values"], dtype=np.float64)
    missing = np.isnan(values)
    values[missing] = imputation[missing]
    selected = values[np.asarray(profile["selected_indices"], dtype=np.int64)]
    mean = np.asarray(profile["scaler_mean"], dtype=np.float64)
    scale = np.asarray(profile["scaler_scale"], dtype=np.float64)
    transformed = ((selected - mean) / scale).astype(np.float32)
    if not np.isfinite(transformed).all():
        raise ValueError("reference preprocessing produced non-finite values")
    return transformed.reshape(1, -1)


def hbos_score(state: Mapping[str, Any], features: np.ndarray) -> float:
    score = 0.0
    records = zip(
        state["feature_indices"],
        state["edges"],
        state["probabilities"],
        strict=True,
    )
    for feature_index, edges, probabilities in records:
        value = float(features[0, feature_index])
        if value < edges[0]:
            bin_index = 0
        elif value > edges[-1]:
            bin_index = len(edges)
        else:
            interior = max(
                0,
                min(bisect_right(edges, value) - 1, len(edges) - 2),
            )
            bin_index = 1 + interior
        score -= math.log(probabilities[bin_index])
    return score / len(state["feature_indices"])


def normalized(raw: float, decision: Mapping[str, Any]) -> float:
    return (raw - decision["mean"]) / decision["standard_deviation"]


def parity_inputs() -> dict[str, np.ndarray]:
    indices = np.arange(1, 55, dtype=np.float64)
    missing = indices.copy()
    missing[::7] = np.nan
    return {
        "ascending": indices,
        "zeros": np.zeros(54, dtype=np.float64),
        "negative": -indices,
        "alternating": np.where(
            np.arange(54) % 2 == 0,
            -0.5 * indices,
            1.5 * indices,
        ),
        "wide": (np.arange(54, dtype=np.float64) - 27.0) * 1000.0,
        "missing": missing,
    }


def score_case(
    raw: np.ndarray,
    profiles: Mapping[str, Any],
    flow_model: Any,
    known_model: Any,
    anomaly_record: Mapping[str, Any],
    isolation_forest: Any,
) -> dict[str, Any]:
    supervised = transform(profiles["supervised_known"], raw)
    anomaly_features = transform(profiles["anomaly_benign"], raw)
    flow_probability = float(flow_model.predict_proba(supervised)[0, 1])
    known_probabilities = known_model.predict_proba(supervised)[0]
    hbos_raw = hbos_score(anomaly_record["hbos"], anomaly_features)
    hbos_decision = anomaly_record["hbos"]["decision"]
    hbos_normalized = normalized(hbos_raw, hbos_decision)
    isolation_raw = -float(isolation_forest.score_samples(anomaly_features)[0])
    isolation_decision = anomaly_record["isolation_forest"]["decision"]
    isolation_normalized = normalized(isolation_raw, isolation_decision)
    return {
        "flow_attack_probability": flow_probability,
        "flow_attack": flow_probability >= 0.5,
        "known_family_probabilities": [
            float(value) for value in known_probabilities
        ],
        "known_family_index": int(np.argmax(known_probabilities)),
        "hbos_raw": hbos_raw,
        "hbos_normalized": hbos_normalized,
        "hbos_threshold_exceeded": (
            hbos_normalized >= hbos_decision["threshold"]
        ),
        "isolation_forest_raw": isolation_raw,
        "isolation_forest_normalized": isolation_normalized,
        "isolation_forest_threshold_exceeded": (
            isolation_normalized >= isolation_decision["threshold"]
        ),
    }


def build_reference(root: Path, checkpoint: str) -> dict[str, Any]:
    contract = load_json(root / "config/cicids2017-artifact-bundle-contract.json")
    prerequisites = contract["prerequisites"]
    selected = {
        name: verify_reference(root, prerequisites[name], name)
        for name in (
            "preprocessing_acceptance",
            "flow_rf_artifact",
            "anomaly_artifact",
            "known_family_artifact",
        )
    }
    preprocessing = load_json(selected["preprocessing_acceptance"])
    flow = joblib.load(selected["flow_rf_artifact"])
    anomaly = joblib.load(selected["anomaly_artifact"])
    known = joblib.load(selected["known_family_artifact"])

    profiles = preprocessing["artifact"]["checkpoints"][checkpoint]["profiles"]
    flow_model = flow["checkpoints"][checkpoint]["model"]
    known_model = known["checkpoints"][checkpoint]["model"]
    anomaly_record = anomaly["checkpoints"][checkpoint]
    isolation_forest = anomaly_record["isolation_forest"]["estimator"]
    flow_model.n_jobs = 1
    known_model.n_jobs = 1
    isolation_forest.n_jobs = 1

    return {
        "schema_version": "1.0.0",
        "kind": "python_cpp_parity_matrix_reference",
        "checkpoint": checkpoint,
        "absolute_tolerance": REFERENCE_ABSOLUTE_TOLERANCE,
        "input": {
            "feature_schema_id": "nids.flow_features.v1",
            "feature_count": 54,
            "case_ids": list(parity_inputs()),
        },
        "python_runtime": {
            "joblib": joblib.__version__,
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "prerequisite_sha256": {
            name: sha256_path(path) for name, path in selected.items()
        },
        "cases": {
            case_id: score_case(
                raw,
                profiles,
                flow_model,
                known_model,
                anomaly_record,
                isolation_forest,
            )
            for case_id, raw in parity_inputs().items()
        },
    }


def parse_native_records(output: str, checkpoint: str) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for line in output.splitlines():
        if not line.startswith(NATIVE_RECORD_PREFIX):
            continue
        record = json.loads(line[len(NATIVE_RECORD_PREFIX) :])
        if record.get("checkpoint") != checkpoint:
            raise ValueError(
                f"native checkpoint mismatch: expected {checkpoint}, "
                f"observed {record.get('checkpoint')}"
            )
        case_id = record.get("case_id")
        if not isinstance(case_id, str) or case_id in records:
            raise ValueError(f"invalid or duplicate native case id: {case_id}")
        scores = record.get("scores")
        if not isinstance(scores, dict):
            raise ValueError(f"native scores missing for case: {case_id}")
        records[case_id] = scores
    if not records:
        raise ValueError("native parity test emitted no matrix records")
    return records


def compare_scores(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
    tolerance: float = REFERENCE_ABSOLUTE_TOLERANCE,
) -> float:
    exact_fields = (
        "flow_attack",
        "known_family_index",
        "hbos_threshold_exceeded",
        "isolation_forest_threshold_exceeded",
    )
    for field in exact_fields:
        if observed.get(field) != expected.get(field):
            raise ValueError(
                f"native parity exact mismatch for {field}: "
                f"observed={observed.get(field)}, expected={expected.get(field)}"
            )
    numeric_fields = (
        "flow_attack_probability",
        "hbos_raw",
        "hbos_normalized",
        "isolation_forest_raw",
        "isolation_forest_normalized",
    )
    differences = []
    for field in numeric_fields:
        difference = abs(float(observed[field]) - float(expected[field]))
        differences.append(difference)
        if not math.isfinite(difference) or difference > tolerance:
            raise ValueError(
                f"native parity numeric mismatch for {field}: "
                f"observed={observed[field]}, expected={expected[field]}, "
                f"difference={difference}, tolerance={tolerance}"
            )
    expected_probabilities = expected["known_family_probabilities"]
    observed_probabilities = observed.get("known_family_probabilities")
    if (
        not isinstance(observed_probabilities, list)
        or len(observed_probabilities) != len(expected_probabilities)
    ):
        raise ValueError("native known-family probability shape mismatch")
    for index, (observed_value, expected_value) in enumerate(
        zip(observed_probabilities, expected_probabilities, strict=True)
    ):
        difference = abs(float(observed_value) - float(expected_value))
        differences.append(difference)
        if not math.isfinite(difference) or difference > tolerance:
            raise ValueError(
                "native known-family probability mismatch at "
                f"index {index}: observed={observed_value}, "
                f"expected={expected_value}, difference={difference}, "
                f"tolerance={tolerance}"
            )
    return max(differences, default=0.0)


def run_native_matrix(
    native_test: Path,
    staged_root: Path,
    reference: Mapping[str, Any],
) -> dict[str, Any]:
    checkpoint = str(reference["checkpoint"])
    bundle = (staged_root / checkpoint).resolve()
    if not bundle.is_dir():
        raise ValueError(f"staged bundle is missing: {bundle}")
    completed = subprocess.run(
        [str(native_test), str(bundle), "--emit-matrix"],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"native parity test failed for {checkpoint}: "
            f"return_code={completed.returncode}, "
            f"stderr={completed.stderr.strip()}"
        )
    observed = parse_native_records(completed.stdout, checkpoint)
    expected_cases = reference["cases"]
    if set(observed) != set(expected_cases):
        raise ValueError(
            f"native parity case set mismatch for {checkpoint}: "
            f"observed={sorted(observed)}, expected={sorted(expected_cases)}"
        )
    maximum_error = max(
        compare_scores(expected_cases[case_id], observed[case_id])
        for case_id in expected_cases
    )
    return {
        "status": "passed",
        "bundle_manifest_sha256": sha256_path(bundle / "manifest.json"),
        "cases_compared": len(expected_cases),
        "maximum_absolute_error": maximum_error,
        "exact_fields_equal": True,
    }


def write_receipt(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite parity receipt: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as output:
        temporary = Path(output.name)
        json.dump(
            document,
            output,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_failed_attempt(directory: Path, error: Exception) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc)
    path = directory / (
        "failed-attempt-"
        + timestamp.strftime("%Y%m%dT%H%M%S.%fZ")
        + ".json"
    )
    with path.open("x", encoding="utf-8") as output:
        json.dump(
            {
                "schema_version": "1.0.0",
                "kind": "t5.3-python-cpp-parity-attempt",
                "status": "failed",
                "generated_at_utc": timestamp.isoformat(),
                "python_executable": sys.executable,
                "python_version": sys.version.split()[0],
                "error_type": type(error).__name__,
                "error": str(error),
            },
            output,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        output.write("\n")
    return path


def run_acceptance(
    root: Path,
    native_test: Path,
    staged_root: Path,
    checkpoints: Sequence[str],
) -> dict[str, Any]:
    if not native_test.is_file():
        raise ValueError(f"native parity test does not exist: {native_test}")
    results: dict[str, Any] = {}
    prerequisite_sha256: dict[str, str] | None = None
    python_runtime: dict[str, str] | None = None
    for checkpoint in checkpoints:
        reference = build_reference(root, checkpoint)
        results[checkpoint] = run_native_matrix(
            native_test,
            staged_root,
            reference,
        )
        prerequisite_sha256 = reference["prerequisite_sha256"]
        python_runtime = reference["python_runtime"]
    return {
        "schema_version": "1.0.0",
        "kind": "t5.3-python-cpp-parity-acceptance",
        "status": "passed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "absolute_tolerance": REFERENCE_ABSOLUTE_TOLERANCE,
        "native_test": {
            "path": str(native_test),
            "sha256": sha256_path(native_test),
        },
        "python_runtime": python_runtime,
        "prerequisite_sha256": prerequisite_sha256,
        "checkpoints": results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Emit a bounded Python reference for native model parity"
    )
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--checkpoint",
        choices=(*CHECKPOINTS, "ALL"),
        default="F9",
    )
    parser.add_argument("--native-test", type=Path)
    parser.add_argument("--staged-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if DEPENDENCY_ERROR is not None:
            raise RuntimeError(
                "locked Python model dependencies are unavailable: "
                f"{DEPENDENCY_ERROR}"
            )
        root = args.project_root.resolve()
        checkpoints = (
            CHECKPOINTS if args.checkpoint == "ALL" else (args.checkpoint,)
        )
        if args.native_test is None:
            if args.staged_root is not None or args.output is not None:
                raise ValueError(
                    "--staged-root/--output require --native-test"
                )
            references = [
                build_reference(root, checkpoint) for checkpoint in checkpoints
            ]
            reference: Any = (
                references[0] if len(references) == 1 else references
            )
        else:
            if args.staged_root is None or args.output is None:
                raise ValueError(
                    "--native-test requires --staged-root and --output"
                )
            reference = run_acceptance(
                root,
                args.native_test.resolve(),
                args.staged_root.resolve(),
                checkpoints,
            )
            write_receipt(args.output.resolve(), reference)
        print(
            json.dumps(
                reference,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            ),
            flush=True,
        )
        return 0
    except (
        json.JSONDecodeError,
        KeyError,
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as error:
        if args.output is not None:
            failed = write_failed_attempt(
                args.output.resolve().parent,
                error,
            )
            print(f"failed_attempt_receipt: {failed}", file=sys.stderr)
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
