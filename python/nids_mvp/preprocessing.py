from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import sklearn
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler


TASK = "T4.1"
PROFILES = ("supervised_known", "anomaly_benign")
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
        or expected.get("python_major_minor")
        != f"{sys.version_info.major}.{sys.version_info.minor}"
        or observed != expected.get("versions")
        or expected.get("dependency_mutation_allowed") is not False
        or expected.get("hooks_in_scope") is not False
    ):
        raise RuntimeError(f"T4.1 runtime contract mismatch: {observed}")


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
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], Path, list[str]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T4.1 contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, reference, name)
        for name, reference in contract["prerequisites"].items()
    }
    user = load_json(paths["t3_7_manual_acceptance"])
    if (
        user.get("status") != "passed"
        or user.get("decision") != "accepted"
        or not user.get("gate", {}).get("t4_1_authorized")
    ):
        raise ValueError("T3.7 manual acceptance does not authorize T4.1")
    technical = load_json(paths["t3_7_technical_acceptance"])
    if technical.get("status") != "passed":
        raise ValueError("T3.7 technical acceptance is not passed")
    manifest = load_json(paths["snapshot_manifest"])
    feature_schema = load_json(paths["feature_schema"])
    features = manifest.get("model_feature_columns")
    schema_features = [item["name"] for item in feature_schema.get("features", [])]
    if (
        manifest.get("status") != "passed"
        or manifest.get("row_count") != contract["prerequisites"]["snapshot_manifest"]["rows"]
        or not isinstance(features, list)
        or features != schema_features
        or len(features) != contract["prerequisites"]["feature_schema"]["feature_count"]
    ):
        raise ValueError("T3.5 feature allowlist or manifest mismatch")
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
    return contract, manifest, verified, flow_map, features


def capture_from_path(value: str) -> str:
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


def materialize_training_matrices(
    checkpoint: str,
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    features: Sequence[str],
    expected_rows: Mapping[str, Mapping[str, int]],
    scratch: Path,
) -> dict[str, Path]:
    paths = {profile: scratch / f"{checkpoint}-{profile}.npy" for profile in PROFILES}
    matrices = {
        profile: np.lib.format.open_memmap(
            paths[profile], mode="w+", dtype=np.float64, shape=(expected_rows[profile][checkpoint], len(features))
        )
        for profile in PROFILES
    }
    offsets = {profile: 0 for profile in PROFILES}
    for record in parts:
        if f"checkpoint={checkpoint}/" not in record["path"]:
            continue
        capture_id = capture_from_path(record["path"])
        mapping = load_capture_map(flow_map, capture_id)
        parquet = pq.ParquetFile(record["resolved_path"])
        columns = ["flow_id", "capture_id", "assigned_class", *features]
        previous_flow_id: int | None = None
        for batch in parquet.iter_batches(columns=columns, batch_size=BATCH_ROWS):
            data = {
                "flow_id": batch.column(0).to_pylist(),
                "capture_id": batch.column(1).to_pylist(),
                "assigned_class": batch.column(2).to_pylist(),
            }
            flow_ids = data["flow_id"]
            if any(value != capture_id for value in data["capture_id"]):
                raise ValueError(f"capture metadata drift in {record['path']}")
            if flow_ids and previous_flow_id is not None and flow_ids[0] <= previous_flow_id:
                raise ValueError(f"snapshot flow order drift in {record['path']}")
            if any(left >= right for left, right in zip(flow_ids, flow_ids[1:])):
                raise ValueError(f"duplicate snapshot flow in {record['path']}")
            if flow_ids:
                previous_flow_id = flow_ids[-1]
            rows = np.column_stack(
                [batch.column(index + 3).to_numpy(zero_copy_only=False) for index in range(len(features))]
            ).astype(np.float64, copy=False)
            if np.isinf(rows).any():
                raise ValueError(f"infinite training feature in {record['path']}")
            supervised: list[int] = []
            benign: list[int] = []
            for index, (flow_id, family) in enumerate(zip(flow_ids, data["assigned_class"], strict=True)):
                mapped = mapping.get(flow_id)
                if mapped is None or mapped[1] != family:
                    raise ValueError(f"snapshot/flow-map drift: {capture_id}/{flow_id}")
                if mapped[0] == "train":
                    supervised.append(index)
                    if family == "BENIGN":
                        benign.append(index)
            for profile, indices in (("supervised_known", supervised), ("anomaly_benign", benign)):
                start, stop = offsets[profile], offsets[profile] + len(indices)
                if stop > matrices[profile].shape[0]:
                    raise ValueError(f"{profile}/{checkpoint} exceeds expected rows")
                if indices:
                    matrices[profile][start:stop] = rows[indices]
                offsets[profile] = stop
    for profile, matrix in matrices.items():
        matrix.flush()
        if offsets[profile] != matrix.shape[0]:
            raise ValueError(f"{profile}/{checkpoint} row count mismatch: {offsets[profile]}")
    return paths


def transform_with_artifact(
    values: np.ndarray, input_features: Sequence[str], profile: Mapping[str, Any]
) -> np.ndarray:
    if list(input_features) != profile.get("input_features"):
        raise ValueError("serving feature order or schema mismatch")
    matrix = np.asarray(values, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != len(input_features):
        raise ValueError("serving matrix shape mismatch")
    if np.isinf(matrix).any():
        raise ValueError("serving input contains infinity")
    medians = np.asarray(profile["imputation_values"], dtype=np.float64)
    imputed = np.where(np.isnan(matrix), medians, matrix)
    indices = np.asarray(profile["selected_indices"], dtype=np.int64)
    selected = imputed[:, indices].copy()
    selected -= np.asarray(profile["scaler_mean"], dtype=np.float64)
    selected /= np.asarray(profile["scaler_scale"], dtype=np.float64)
    result = selected.astype(np.float32)
    if not np.isfinite(result).all():
        raise ValueError("serving transform produced non-finite output")
    return result


def fit_profile(
    matrix_path: Path,
    checkpoint: str,
    profile_name: str,
    features: Sequence[str],
    expected_constants: Sequence[str],
    sample_rows: int,
    scratch: Path,
) -> dict[str, Any]:
    matrix = np.load(matrix_path, mmap_mode="r")
    imputer = SimpleImputer(strategy="median", keep_empty_features=True).fit(matrix)
    medians = np.asarray(imputer.statistics_, dtype=np.float64)
    if not np.isfinite(medians).all():
        raise ValueError(f"non-finite imputation statistic: {profile_name}/{checkpoint}")
    imputed_path = scratch / f"{checkpoint}-{profile_name}-imputed.npy"
    imputed = np.lib.format.open_memmap(imputed_path, mode="w+", dtype=np.float64, shape=matrix.shape)
    for start in range(0, matrix.shape[0], BATCH_ROWS):
        stop = min(start + BATCH_ROWS, matrix.shape[0])
        imputed[start:stop] = imputer.transform(matrix[start:stop])
    imputed.flush()
    scaler = StandardScaler(with_mean=True, with_std=True).fit(imputed)
    constant_indices = np.flatnonzero(np.asarray(scaler.var_) == 0.0)
    constants = [features[index] for index in constant_indices]
    if constants != list(expected_constants):
        raise ValueError(f"constant-feature drift: {profile_name}/{checkpoint}: {constants}")
    selected_indices = [index for index in range(len(features)) if index not in set(constant_indices.tolist())]
    count = min(sample_rows, matrix.shape[0])
    parity_indices = np.unique(np.linspace(0, matrix.shape[0] - 1, num=count, dtype=np.int64))
    train_output = scaler.transform(imputed[parity_indices])[:, selected_indices].astype(np.float32)
    artifact = {
        "checkpoint": checkpoint,
        "profile": profile_name,
        "fit_population_rows": int(matrix.shape[0]),
        "input_features": list(features),
        "input_dtype": "float64",
        "imputer": "median",
        "imputation_values": medians.tolist(),
        "dropped_constant_features": constants,
        "selected_indices": selected_indices,
        "selected_features": [features[index] for index in selected_indices],
        "scaler": "standard",
        "scaler_mean": np.asarray(scaler.mean_)[selected_indices].tolist(),
        "scaler_scale": np.asarray(scaler.scale_)[selected_indices].tolist(),
        "output_dtype": "float32",
    }
    serving_output = transform_with_artifact(matrix[parity_indices], features, artifact)
    if not np.array_equal(train_output, serving_output):
        raise ValueError(f"train-serving parity mismatch: {profile_name}/{checkpoint}")
    artifact["parity"] = {
        "rows": int(len(parity_indices)),
        "comparison": "bitwise_equal_float32",
        "status": "passed",
        "output_sha256": hashlib.sha256(serving_output.tobytes(order="C")).hexdigest(),
    }
    del imputed
    imputed_path.unlink()
    return artifact


def build_artifact(
    contract: Mapping[str, Any],
    parts: Sequence[Mapping[str, Any]],
    flow_map: Path,
    features: list[str],
    scratch_parent: Path,
) -> dict[str, Any]:
    checkpoints: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="nids-t41-", dir=scratch_parent) as temporary:
        scratch = Path(temporary)
        for checkpoint in contract["input"]["checkpoints"]:
            paths = materialize_training_matrices(
                checkpoint, parts, flow_map, features, contract["expected_rows"], scratch
            )
            profiles = {
                profile: fit_profile(
                    paths[profile],
                    checkpoint,
                    profile,
                    features,
                    contract["expected_constant_features"][profile][checkpoint],
                    contract["parity"]["sample_rows_per_profile_checkpoint"],
                    scratch,
                )
                for profile in PROFILES
            }
            checkpoints[checkpoint] = {"profiles": profiles}
            for path in paths.values():
                path.unlink()
    return {
        "artifact_id": contract["artifact"]["id"],
        "artifact_version": contract["artifact"]["version"],
        "feature_schema_id": contract["prerequisites"]["feature_schema"]["schema_id"],
        "input_features": features,
        "profiles": list(PROFILES),
        "checkpoints": checkpoints,
        "loafo_policy": contract["loafo"],
    }


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    contract, manifest, parts, flow_map, features = verify_inputs(root, contract_path)
    output = resolve_inside(root, contract["artifact"]["output"])
    if output.exists():
        raise FileExistsError("T4.1 acceptance bundle already exists; refusing to overwrite evidence")
    artifact = build_artifact(contract, parts, flow_map, features, root / "run_log")
    sources = [
        root / "config/agent/current-task.json",
        contract_path,
        root / "python/nids_mvp/preprocessing.py",
        root / "tests/test_t41_preprocessing.py",
    ]
    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "preprocessing_acceptance_bundle",
        "status": "passed",
        "generated_at_utc": utc_now(),
        "contract": {"path": relative(contract_path, root), "sha256": sha256_path(contract_path)},
        "source_files": {relative(path, root): sha256_path(path) for path in sources},
        "inputs": {
            "snapshot_manifest_sha256": sha256_path(resolve_inside(root, contract["prerequisites"]["snapshot_manifest"]["path"])),
            "known_flow_map_sha256": sha256_path(flow_map),
            "t3_7_manual_acceptance_sha256": sha256_path(resolve_inside(root, contract["prerequisites"]["t3_7_manual_acceptance"]["path"])),
        },
        "runtime": {
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            **contract["execution"]["versions"],
        },
        "artifact": artifact,
        "validation": {
            "all_t3_5_part_hashes_verified": True,
            "flow_map_hash_verified": True,
            "fit_partition_train_only": True,
            "anomaly_profile_benign_only": True,
            "feature_allowlist_exact": True,
            "constant_masks_exact": True,
            "train_serving_parity_all_profiles": True,
        },
        "gate": {"decision": "pending_user_decision", "t4_2_authorized": False},
    }
    write_json_atomic(output, receipt)
    return receipt


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    contract, _, _, _, features = verify_inputs(root, contract_path)
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T4.1 acceptance bundle")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("T4.1 contract hash mismatch")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T4.1 source hash mismatch: {value}")
    artifact = receipt.get("artifact", {})
    if (
        artifact.get("artifact_id") != contract["artifact"]["id"]
        or artifact.get("artifact_version") != contract["artifact"]["version"]
        or artifact.get("input_features") != features
        or list(artifact.get("checkpoints", {})) != contract["input"]["checkpoints"]
        or receipt.get("gate") != {"decision": "pending_user_decision", "t4_2_authorized": False}
    ):
        raise ValueError("T4.1 artifact contract mismatch")
    for checkpoint in contract["input"]["checkpoints"]:
        profiles = artifact["checkpoints"][checkpoint].get("profiles", {})
        if set(profiles) != set(PROFILES):
            raise ValueError(f"T4.1 profile set mismatch: {checkpoint}")
        for profile_name in PROFILES:
            profile = profiles[profile_name]
            if (
                profile.get("fit_population_rows") != contract["expected_rows"][profile_name][checkpoint]
                or profile.get("dropped_constant_features")
                != contract["expected_constant_features"][profile_name][checkpoint]
                or profile.get("parity", {}).get("status") != "passed"
            ):
                raise ValueError(f"T4.1 profile validation failed: {profile_name}/{checkpoint}")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Fit and validate T4.1 preprocessing artifacts")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract", type=Path, default=root_default / "config/cicids2017-preprocessing-contract.json"
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            verify_inputs(root, contract_path)
            print("[T4.1 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(
                f"[T4.1 preprocessing] status=passed checkpoints={len(receipt['artifact']['checkpoints'])} profiles=2",
                flush=True,
            )
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T4.1 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
