"""Train and lock the T9.1 demo-critical terminal-flow model."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.metadata
import json
import os
import shutil
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import lightgbm
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import sklearn
from lightgbm import LGBMClassifier
from lightgbm.basic import LightGBMError

from nids_mvp import full_flow_dataset as dataset


TASK = "T9.1"
CLASS_ORDER = (
    "Benign",
    "FTP-Bruteforce",
    "SSH-Bruteforce",
    "PortScan",
    "DoS",
    "Other",
)
TARGET_FAMILIES = ("FTP-Bruteforce", "PortScan")
PROFILE_LENGTHS = {"A": 54, "B": 61, "C": 64, "D": 66, "E": 70}
REQUIREMENTS_SHA256 = "0afc07c900ba8ab7862654fea570977fb30de6580b2cd5a963609e1930c3f0a5"
BATCH_ROWS = 65_536
PRODUCTION_PARAMETERS: dict[str, Any] = {
    "boosting_type": "gbdt",
    "objective": "multiclass",
    "num_leaves": 31,
    "max_depth": -1,
    "learning_rate": 0.05,
    "n_estimators": 300,
    "subsample_for_bin": 200_000,
    "class_weight": "balanced",
    "min_split_gain": 0.0,
    "min_child_weight": 0.001,
    "min_child_samples": 20,
    "subsample": 1.0,
    "subsample_freq": 0,
    "colsample_bytree": 1.0,
    "reg_alpha": 0.0,
    "reg_lambda": 0.0,
    "random_state": 3607,
    "n_jobs": 8,
    "importance_type": "split",
    "deterministic": True,
    "force_col_wise": True,
    "verbosity": -1,
}


@dataclass(frozen=True)
class TrainingPolicy:
    parameters: Mapping[str, Any]
    maximum_benign_fpr: float = 0.01
    target_minimum_precision: float = 0.90
    target_minimum_recall: float = 0.90
    attack_recall_max_drop: float = 0.002
    macro_f1_max_drop: float = 0.01
    target_f1_max_drop: float = 0.01
    macro_minimum_support: int = 100


PRODUCTION_POLICY = TrainingPolicy(parameters=PRODUCTION_PARAMETERS)


@dataclass(frozen=True)
class ModelInputs:
    root: Path
    dataset_manifest_path: Path
    feature_schema_path: Path
    requirements_path: Path
    output_root: Path
    enforce_runtime: bool = True


@dataclass(frozen=True)
class FeatureProfile:
    profile_id: str
    name: str
    feature_names: tuple[str, ...]

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)


@dataclass(frozen=True)
class VerifiedPart:
    path: Path
    relative_path: str
    partition: str
    rows: int
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class VerifiedInputs:
    inputs: ModelInputs
    dataset_manifest_sha256: str
    feature_schema_sha256: str
    requirements_sha256: str
    split_map_sha256: str
    feature_names: tuple[str, ...]
    profiles: tuple[FeatureProfile, ...]
    train_parts: tuple[VerifiedPart, ...]
    validation_parts: tuple[VerifiedPart, ...]
    sealed_test_paths: tuple[str, ...]
    train_rows: int
    validation_rows: int


@dataclass(frozen=True)
class MatrixPaths:
    x_train: Path
    y_train: Path
    x_validation: Path
    y_validation: Path
    validation_capture_id: Path
    validation_flow_id: Path
    family_counts: Mapping[str, Mapping[str, int]]


def production_inputs(root: Path) -> ModelInputs:
    root = root.resolve()
    return ModelInputs(
        root=root,
        dataset_manifest_path=root / "run_log/full-flow-v1/dataset/manifest.json",
        feature_schema_path=root / "config/terminal-flow-feature-schema-v1.json",
        requirements_path=root / "config/full-flow-reproducibility-requirements.txt",
        output_root=root / "run_log/full-flow-v1/model",
        enforce_runtime=True,
    )


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            json.dump(
                value,
                output,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def requirement_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parts = value.split("==")
        if len(parts) != 2 or not all(parts):
            raise ValueError(f"unsupported requirement pin: {value}")
        name, version = parts
        normalized = name.lower().replace("_", "-")
        if normalized in pins:
            raise ValueError(f"duplicate requirement pin: {name}")
        pins[normalized] = version
    return pins


def runtime_versions(requirements_path: Path) -> dict[str, Any]:
    packages = {
        name: importlib.metadata.version(name)
        for name in requirement_pins(requirements_path)
    }
    return {
        "python": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "lightgbm": lightgbm.__version__,
        "numpy": np.__version__,
        "pyarrow": pa.__version__,
        "scikit_learn": sklearn.__version__,
        "joblib": joblib.__version__,
        "packages": packages,
    }


def verify_runtime(inputs: ModelInputs) -> None:
    expected_python = inputs.root / ".venv-full-flow-v1/Scripts/python.exe"
    pins = requirement_pins(inputs.requirements_path)
    observed = runtime_versions(inputs.requirements_path)
    mismatches = {
        name: {"expected": version, "observed": observed["packages"].get(name)}
        for name, version in pins.items()
        if observed["packages"].get(name) != version
    }
    if (
        os.name != "nt"
        or sys.version_info[:2] != (3, 13)
        or not expected_python.is_file()
        or Path(sys.executable).resolve() != expected_python.resolve()
        or mismatches
    ):
        raise RuntimeError(
            "T9.1 training runtime mismatch: "
            f"python={sys.executable} versions={mismatches}"
        )


def profiles_from_schema(
    feature_names: Sequence[str], records: Sequence[Mapping[str, Any]]
) -> tuple[FeatureProfile, ...]:
    profiles: list[FeatureProfile] = []
    for record in records:
        profile_id = str(record.get("id", ""))
        length = int(record.get("length", -1))
        if (
            PROFILE_LENGTHS.get(profile_id) != length
            or record.get("start_index") != 0
            or record.get("end_index") != length - 1
            or not isinstance(record.get("name"), str)
        ):
            raise ValueError(f"terminal profile contract mismatch: {profile_id}")
        profiles.append(
            FeatureProfile(
                profile_id=profile_id,
                name=str(record["name"]),
                feature_names=tuple(feature_names[:length]),
            )
        )
    if tuple(item.profile_id for item in profiles) != tuple(PROFILE_LENGTHS):
        raise ValueError("terminal profile ordering mismatch")
    return tuple(profiles)


def capture_from_path(value: str) -> str:
    marker = "capture_id="
    if marker not in value:
        raise ValueError(f"dataset part lacks capture partition: {value}")
    return value.split(marker, 1)[1].split("/", 1)[0]


def verify_part(
    inputs: ModelInputs,
    record: Mapping[str, Any],
    partition: str,
    expected_schema: pa.Schema,
) -> VerifiedPart:
    value = record.get("path")
    if not isinstance(value, str):
        raise ValueError("dataset part path must be a string")
    path = dataset.resolve_inside(inputs.root, value)
    rows = record.get("rows")
    size_bytes = record.get("size_bytes")
    content_hash = record.get("sha256")
    if (
        record.get("kind") != "assigned"
        or record.get("partition") != partition
        or not isinstance(rows, int)
        or rows < 1
        or not isinstance(size_bytes, int)
        or size_bytes < 1
        or not is_sha256(content_hash)
        or not path.is_file()
        or path.stat().st_size != size_bytes
        or sha256_path(path) != content_hash
        or record.get("schema_sha256") != dataset.schema_fingerprint(expected_schema)
    ):
        raise ValueError(f"invalid {partition} dataset part: {value}")
    with pq.ParquetFile(path) as parquet:
        if (
            parquet.metadata.num_rows != rows
            or not parquet.schema_arrow.equals(expected_schema, check_metadata=True)
        ):
            raise ValueError(f"{partition} dataset part schema mismatch: {value}")
    capture_from_path(value)
    return VerifiedPart(
        path=path,
        relative_path=value,
        partition=partition,
        rows=rows,
        size_bytes=size_bytes,
        sha256=str(content_hash),
    )


def verify_inputs(inputs: ModelInputs) -> VerifiedInputs:
    if not inputs.dataset_manifest_path.is_file():
        raise ValueError(
            "terminal dataset manifest missing; build all terminal shards and dataset first"
        )
    if (
        not inputs.requirements_path.is_file()
        or sha256_path(inputs.requirements_path) != REQUIREMENTS_SHA256
    ):
        raise ValueError("full-flow requirements content address mismatch")
    if inputs.enforce_runtime:
        verify_runtime(inputs)
    feature_names, profile_records = dataset.load_feature_schema(
        inputs.feature_schema_path, dataset.FEATURE_SCHEMA_SHA256
    )
    profiles = profiles_from_schema(feature_names, profile_records)
    manifest = load_json(inputs.dataset_manifest_path)
    feature_record = manifest.get("feature_schema", {})
    split_record = manifest.get("split_map", {})
    split_hash = split_record.get("sha256")
    training_paths = manifest.get("training_parts")
    validation_paths = manifest.get("validation_parts")
    test_record = manifest.get("test_partition", {})
    sealed_test_paths = test_record.get("parts")
    part_records = manifest.get("parts")
    if (
        manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_dataset_manifest"
        or manifest.get("status") != "complete"
        or feature_record.get("schema_id") != dataset.FEATURE_SCHEMA_ID
        or feature_record.get("sha256") != dataset.FEATURE_SCHEMA_SHA256
        or feature_record.get("feature_count") != dataset.FEATURE_COUNT
        or manifest.get("model_feature_columns") != feature_names
        or not is_sha256(split_hash)
        or not isinstance(training_paths, list)
        or not isinstance(validation_paths, list)
        or test_record.get("status") != "sealed"
        or not isinstance(sealed_test_paths, list)
        or not isinstance(part_records, list)
    ):
        raise ValueError("terminal dataset manifest contract mismatch")
    expected_schema = dataset.arrow_schema(
        feature_names,
        dataset.FEATURE_SCHEMA_SHA256,
        str(split_hash),
        profile_records,
    )
    if manifest.get("schema_sha256") != dataset.schema_fingerprint(expected_schema):
        raise ValueError("terminal dataset schema fingerprint mismatch")
    if any(not isinstance(record, Mapping) for record in part_records):
        raise ValueError("terminal dataset part record must be an object")
    all_path_values = [record.get("path") for record in part_records]
    if (
        any(not isinstance(value, str) for value in all_path_values)
        or len(set(all_path_values)) != len(all_path_values)
    ):
        raise ValueError("terminal dataset part inventory mismatch")
    by_path = {
        str(record["path"]): record
        for record in part_records
        if isinstance(record, Mapping)
    }
    train_set = set(training_paths)
    validation_set = set(validation_paths)
    test_set = set(sealed_test_paths)
    if (
        not training_paths
        or not validation_paths
        or any(not isinstance(value, str) for value in training_paths)
        or any(not isinstance(value, str) for value in validation_paths)
        or any(not isinstance(value, str) for value in sealed_test_paths)
        or len(train_set) != len(training_paths)
        or len(validation_set) != len(validation_paths)
        or len(test_set) != len(sealed_test_paths)
        or train_set & validation_set
        or train_set & test_set
        or validation_set & test_set
    ):
        raise ValueError("terminal train/validation/test inventory overlaps")
    for value in sealed_test_paths:
        record = by_path.get(value)
        if record is None or record.get("kind") != "assigned" or record.get("partition") != "test":
            raise ValueError("sealed test inventory mismatch")
    expected_train = {
        value
        for value, record in by_path.items()
        if record.get("kind") == "assigned" and record.get("partition") == "train"
    }
    expected_validation = {
        value
        for value, record in by_path.items()
        if record.get("kind") == "assigned"
        and record.get("partition") == "validation"
    }
    expected_test = {
        value
        for value, record in by_path.items()
        if record.get("kind") == "assigned" and record.get("partition") == "test"
    }
    if (
        train_set != expected_train
        or validation_set != expected_validation
        or test_set != expected_test
    ):
        raise ValueError("terminal allowed-part inventory mismatch")
    if inputs.enforce_runtime and (
        manifest.get("rows") != dataset.EXPECTED_TOTAL_ROWS
        or manifest.get("assigned_rows") != dataset.EXPECTED_ASSIGNED_ROWS
        or manifest.get("quarantine_rows") != dataset.EXPECTED_QUARANTINE_ROWS
        or manifest.get("family_counts") != dataset.EXPECTED_FAMILY_COUNTS
        or manifest.get("quarantine_counts") != dataset.EXPECTED_QUARANTINE_COUNTS
    ):
        raise ValueError("terminal dataset production accounting mismatch")
    train_parts = tuple(
        verify_part(inputs, by_path[value], "train", expected_schema)
        for value in training_paths
    )
    validation_parts = tuple(
        verify_part(inputs, by_path[value], "validation", expected_schema)
        for value in validation_paths
    )
    return VerifiedInputs(
        inputs=inputs,
        dataset_manifest_sha256=sha256_path(inputs.dataset_manifest_path),
        feature_schema_sha256=dataset.FEATURE_SCHEMA_SHA256,
        requirements_sha256=REQUIREMENTS_SHA256,
        split_map_sha256=str(split_hash),
        feature_names=tuple(feature_names),
        profiles=profiles,
        train_parts=train_parts,
        validation_parts=validation_parts,
        sealed_test_paths=tuple(sealed_test_paths),
        train_rows=sum(item.rows for item in train_parts),
        validation_rows=sum(item.rows for item in validation_parts),
    )


def open_memmap(path: Path, shape: tuple[int, ...], dtype: Any) -> np.memmap:
    return np.lib.format.open_memmap(path, mode="w+", dtype=dtype, shape=shape)


def close_memmap(value: np.ndarray) -> None:
    mapping = getattr(value, "_mmap", None)
    if mapping is not None:
        mapping.close()


def populate_matrices(
    verified: VerifiedInputs, arrays: Mapping[str, np.memmap]
) -> dict[str, dict[str, int]]:
    offsets = {"train": 0, "validation": 0}
    counts = {
        partition: Counter({family: 0 for family in CLASS_ORDER})
        for partition in offsets
    }
    metadata_indices = {
        name: index for index, (name, _, _) in enumerate(dataset.METADATA_FIELDS)
    }
    required_metadata_indices = tuple(
        metadata_indices[name]
        for name in (
            "flow_id",
            "capture_id",
            "partition",
            "label_status",
            "label_family",
            "label_binary",
        )
    )
    feature_start = len(dataset.METADATA_FIELDS)
    feature_indices = tuple(
        range(feature_start, feature_start + len(verified.feature_names))
    )
    selected_indices = (*required_metadata_indices, *feature_indices)
    label_index = {family: index for index, family in enumerate(CLASS_ORDER)}
    for part in (*verified.train_parts, *verified.validation_parts):
        capture_id = capture_from_path(part.relative_path)
        previous_flow_id: int | None = None
        with pq.ParquetFile(part.path) as parquet:
            for batch in parquet.iter_batches(batch_size=BATCH_ROWS):
                if any(
                    batch.column(index).null_count
                    for index in selected_indices
                ):
                    raise ValueError(f"null model input in {part.relative_path}")
                flow_ids = batch.column(metadata_indices["flow_id"]).to_pylist()
                captures = batch.column(metadata_indices["capture_id"]).to_pylist()
                partitions = batch.column(metadata_indices["partition"]).to_pylist()
                statuses = batch.column(metadata_indices["label_status"]).to_pylist()
                families = batch.column(metadata_indices["label_family"]).to_pylist()
                binaries = batch.column(metadata_indices["label_binary"]).to_pylist()
                if (
                    any(value != capture_id for value in captures)
                    or any(value != part.partition for value in partitions)
                    or any(value != "assigned" for value in statuses)
                    or any(family not in label_index for family in families)
                    or any(
                        binary != (family != "Benign")
                        for family, binary in zip(families, binaries, strict=True)
                    )
                    or flow_ids
                    and previous_flow_id is not None
                    and flow_ids[0] <= previous_flow_id
                    or any(
                        left >= right for left, right in zip(flow_ids, flow_ids[1:])
                    )
                ):
                    raise ValueError(
                        f"terminal model metadata drift: {part.relative_path}"
                    )
                if flow_ids:
                    previous_flow_id = int(flow_ids[-1])
                raw = np.column_stack(
                    [
                        batch.column(index).to_numpy(zero_copy_only=False)
                        for index in feature_indices
                    ]
                ).astype(np.float64, copy=False)
                if not np.isfinite(raw).all():
                    raise ValueError(
                        f"non-finite terminal model input: {part.relative_path}"
                    )
                with np.errstate(over="ignore", invalid="ignore"):
                    matrix = raw.astype(np.float32)
                if not np.isfinite(matrix).all():
                    raise ValueError(
                        f"terminal model input exceeds float32: {part.relative_path}"
                    )
                labels = np.asarray(
                    [label_index[family] for family in families], dtype=np.uint8
                )
                start = offsets[part.partition]
                stop = start + len(labels)
                target_x = arrays[f"x_{part.partition}"]
                target_y = arrays[f"y_{part.partition}"]
                if stop > target_x.shape[0]:
                    raise ValueError(f"{part.partition} exceeds manifest row count")
                target_x[start:stop] = matrix
                target_y[start:stop] = labels
                if part.partition == "validation":
                    arrays["validation_capture_id"][start:stop] = capture_id
                    arrays["validation_flow_id"][start:stop] = np.asarray(
                        flow_ids, dtype=np.uint64
                    )
                counts[part.partition].update(families)
                offsets[part.partition] = stop
    for value in arrays.values():
        value.flush()
    for partition, expected_rows in (
        ("train", verified.train_rows),
        ("validation", verified.validation_rows),
    ):
        if offsets[partition] != expected_rows:
            raise ValueError(f"{partition} model population mismatch")
    if any(counts["train"][family] < 1 for family in CLASS_ORDER):
        raise ValueError("training partition does not cover all six classes")
    if counts["validation"]["Benign"] < 1 or any(
        counts["validation"][family] < 1 for family in TARGET_FAMILIES
    ):
        raise ValueError("validation partition lacks a required gate family")
    return {
        partition: dict(sorted(partition_counts.items()))
        for partition, partition_counts in counts.items()
    }


def materialize_train_validation(
    verified: VerifiedInputs, scratch: Path
) -> MatrixPaths:
    scratch.mkdir(parents=True, exist_ok=False)
    paths = MatrixPaths(
        x_train=scratch / "x-train.npy",
        y_train=scratch / "y-train.npy",
        x_validation=scratch / "x-validation.npy",
        y_validation=scratch / "y-validation.npy",
        validation_capture_id=scratch / "validation-capture-id.npy",
        validation_flow_id=scratch / "validation-flow-id.npy",
        family_counts={},
    )
    arrays: dict[str, np.memmap] = {}
    try:
        arrays.update(
            {
                "x_train": open_memmap(
                    paths.x_train,
                    (verified.train_rows, len(verified.feature_names)),
                    np.float32,
                ),
                "y_train": open_memmap(
                    paths.y_train, (verified.train_rows,), np.uint8
                ),
                "x_validation": open_memmap(
                    paths.x_validation,
                    (verified.validation_rows, len(verified.feature_names)),
                    np.float32,
                ),
                "y_validation": open_memmap(
                    paths.y_validation, (verified.validation_rows,), np.uint8
                ),
                "validation_capture_id": open_memmap(
                    paths.validation_capture_id,
                    (verified.validation_rows,),
                    "<U64",
                ),
                "validation_flow_id": open_memmap(
                    paths.validation_flow_id,
                    (verified.validation_rows,),
                    np.uint64,
                ),
            }
        )
        family_counts = populate_matrices(verified, arrays)
        for value in arrays.values():
            value.flush()
    finally:
        for value in arrays.values():
            close_memmap(value)
        arrays.clear()
    return MatrixPaths(
        x_train=paths.x_train,
        y_train=paths.y_train,
        x_validation=paths.x_validation,
        y_validation=paths.y_validation,
        validation_capture_id=paths.validation_capture_id,
        validation_flow_id=paths.validation_flow_id,
        family_counts=family_counts,
    )


def validate_probability_matrix(probability: np.ndarray, rows: int) -> None:
    if (
        probability.dtype != np.float64
        or probability.shape != (rows, len(CLASS_ORDER))
        or not np.isfinite(probability).all()
        or np.any((probability < 0.0) | (probability > 1.0))
        or not np.allclose(probability.sum(axis=1), 1.0, rtol=0.0, atol=1e-6)
    ):
        raise ValueError("invalid terminal multiclass probability matrix")


def predict_probabilities(model: LGBMClassifier, matrix: np.ndarray) -> np.ndarray:
    if model.classes_.tolist() != list(range(len(CLASS_ORDER))):
        raise ValueError(f"unexpected LightGBM classes: {model.classes_.tolist()}")
    probability = np.asarray(model.predict_proba(matrix), dtype=np.float64)
    validate_probability_matrix(probability, len(matrix))
    return probability


def fit_profile(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_validation: np.ndarray,
    feature_names: Sequence[str],
    parameters: Mapping[str, Any],
) -> tuple[LGBMClassifier, np.ndarray]:
    if x_train.dtype != np.float32 or x_validation.dtype != np.float32:
        raise ValueError("LightGBM matrices must be float32")
    if x_train.shape[1] != len(feature_names) or x_validation.shape[1] != len(
        feature_names
    ):
        raise ValueError("LightGBM feature dimension mismatch")
    model = LGBMClassifier(**dict(parameters))
    model.fit(x_train, y_train, feature_name=list(feature_names))
    if model.feature_name_ != list(feature_names):
        raise ValueError("LightGBM feature name ordering mismatch")
    return model, predict_probabilities(model, x_validation)


def confusion_metrics(
    matrix: np.ndarray, macro_minimum_support: int
) -> dict[str, Any]:
    if matrix.shape != (len(CLASS_ORDER), len(CLASS_ORDER)) or np.any(matrix < 0):
        raise ValueError("invalid terminal confusion matrix")
    per_class: dict[str, Any] = {}
    for index, family in enumerate(CLASS_ORDER):
        support = int(matrix[index].sum())
        predicted = int(matrix[:, index].sum())
        true_positive = int(matrix[index, index])
        false_positive = predicted - true_positive
        false_negative = support - true_positive
        precision = 0.0 if predicted == 0 else true_positive / predicted
        recall = 0.0 if support == 0 else true_positive / support
        f1 = (
            0.0
            if 2 * true_positive + false_positive + false_negative == 0
            else 2
            * true_positive
            / (2 * true_positive + false_positive + false_negative)
        )
        per_class[family] = {
            "support": support,
            "predicted_count": predicted,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        }
    benign_support = int(matrix[0].sum())
    attack_support = int(matrix[1:].sum())
    predicted_attack = int(matrix[:, 1:].sum())
    true_attack_detected = int(matrix[1:, 1:].sum())
    false_attack = int(matrix[0, 1:].sum())
    eligible_macro = [
        family
        for family in CLASS_ORDER
        if per_class[family]["support"] >= macro_minimum_support
    ]
    if not eligible_macro or benign_support == 0 or attack_support == 0:
        raise ValueError("validation population cannot support selection metrics")
    return {
        "attack_precision": (
            0.0 if predicted_attack == 0 else true_attack_detected / predicted_attack
        ),
        "attack_recall": true_attack_detected / attack_support,
        "benign_fpr": false_attack / benign_support,
        "macro_f1": float(
            sum(per_class[family]["f1"] for family in eligible_macro)
            / len(eligible_macro)
        ),
        "macro_families": eligible_macro,
        "minimum_target_f1": float(
            min(per_class[family]["f1"] for family in TARGET_FAMILIES)
        ),
        "per_class": per_class,
        "confusion_matrix": matrix.tolist(),
    }


def select_threshold(
    y_true: np.ndarray,
    probability: np.ndarray,
    policy: TrainingPolicy,
) -> dict[str, Any]:
    labels = np.asarray(y_true, dtype=np.uint8)
    validate_probability_matrix(probability, len(labels))
    if (
        labels.ndim != 1
        or np.any(labels >= len(CLASS_ORDER))
        or policy.maximum_benign_fpr < 0.0
        or policy.maximum_benign_fpr > 1.0
    ):
        raise ValueError("invalid validation labels or threshold policy")
    attack_score = 1.0 - probability[:, 0]
    attack_family = np.argmax(probability[:, 1:], axis=1).astype(np.int64) + 1
    order = np.argsort(-attack_score, kind="stable")
    matrix = np.zeros((len(CLASS_ORDER), len(CLASS_ORDER)), dtype=np.int64)
    matrix[:, 0] = np.bincount(labels, minlength=len(CLASS_ORDER))
    maximum_score = float(np.max(attack_score))
    initial_threshold = float(np.nextafter(maximum_score, np.inf))
    best_metrics = confusion_metrics(matrix, policy.macro_minimum_support)
    best_threshold = initial_threshold
    best_rank = (
        best_metrics["minimum_target_f1"],
        best_metrics["macro_f1"],
        best_metrics["attack_recall"],
        -best_metrics["benign_fpr"],
        best_threshold,
    )
    candidate_count = 1
    position = 0
    while position < len(order):
        score = attack_score[order[position]]
        stop = position + 1
        while stop < len(order) and attack_score[order[stop]] == score:
            stop += 1
        indices = order[position:stop]
        truths = labels[indices].astype(np.int64, copy=False)
        predictions = attack_family[indices]
        np.add.at(matrix, (truths, np.zeros_like(truths)), -1)
        np.add.at(matrix, (truths, predictions), 1)
        metrics = confusion_metrics(matrix, policy.macro_minimum_support)
        if metrics["benign_fpr"] > policy.maximum_benign_fpr + 1e-15:
            break
        threshold = float(score)
        candidate_count += 1
        rank = (
            metrics["minimum_target_f1"],
            metrics["macro_f1"],
            metrics["attack_recall"],
            -metrics["benign_fpr"],
            threshold,
        )
        if rank > best_rank:
            best_rank = rank
            best_threshold = threshold
            best_metrics = metrics
        position = stop
    return {
        "threshold": best_threshold,
        "candidate_count": candidate_count,
        "objective_order": [
            "minimum_target_f1_desc",
            "macro_f1_desc",
            "attack_recall_desc",
            "benign_fpr_asc",
            "threshold_desc",
        ],
        "metrics": best_metrics,
    }


def select_profile(
    profile_results: Sequence[Mapping[str, Any]], policy: TrainingPolicy
) -> dict[str, Any]:
    if [record.get("profile_id") for record in profile_results] != list(
        PROFILE_LENGTHS
    ):
        raise ValueError("profile selection requires ordered A-E results")
    metrics = [record["threshold_selection"]["metrics"] for record in profile_results]
    best_attack_recall = max(float(value["attack_recall"]) for value in metrics)
    best_macro_f1 = max(float(value["macro_f1"]) for value in metrics)
    best_target_f1 = max(float(value["minimum_target_f1"]) for value in metrics)
    decisions: list[dict[str, Any]] = []
    eligible_ids: list[str] = []
    for record, value in zip(profile_results, metrics, strict=True):
        reasons: list[str] = []
        for family in TARGET_FAMILIES:
            family_metrics = value["per_class"][family]
            if family_metrics["precision"] < policy.target_minimum_precision:
                reasons.append(f"{family}:precision")
            if family_metrics["recall"] < policy.target_minimum_recall:
                reasons.append(f"{family}:recall")
        if value["attack_recall"] < best_attack_recall - policy.attack_recall_max_drop:
            reasons.append("attack_recall_drop")
        if value["macro_f1"] < best_macro_f1 - policy.macro_f1_max_drop:
            reasons.append("macro_f1_drop")
        if value["minimum_target_f1"] < best_target_f1 - policy.target_f1_max_drop:
            reasons.append("target_f1_drop")
        profile_id = str(record["profile_id"])
        if not reasons:
            eligible_ids.append(profile_id)
        decisions.append(
            {
                "profile_id": profile_id,
                "feature_count": int(record["feature_count"]),
                "eligible": not reasons,
                "rejection_reasons": reasons,
            }
        )
    if not eligible_ids:
        raise ValueError("no validation-eligible terminal feature profile")
    selected = min(eligible_ids, key=lambda value: (PROFILE_LENGTHS[value], value))
    selected_result = next(
        record for record in profile_results if record["profile_id"] == selected
    )
    return {
        "selected_profile": selected,
        "selected_feature_count": PROFILE_LENGTHS[selected],
        "selected_feature_indices": list(range(PROFILE_LENGTHS[selected])),
        "selected_threshold": selected_result["threshold_selection"]["threshold"],
        "best_validation_metrics": {
            "attack_recall": best_attack_recall,
            "macro_f1": best_macro_f1,
            "minimum_target_f1": best_target_f1,
        },
        "decisions": decisions,
    }


def probability_sha256(probability: np.ndarray) -> str:
    contiguous = np.ascontiguousarray(probability, dtype=np.float64)
    return hashlib.sha256(contiguous.tobytes(order="C")).hexdigest()


def policy_record(policy: TrainingPolicy) -> dict[str, Any]:
    return {
        "parameters": dict(policy.parameters),
        "maximum_benign_fpr": policy.maximum_benign_fpr,
        "target_minimum_precision": policy.target_minimum_precision,
        "target_minimum_recall": policy.target_minimum_recall,
        "attack_recall_max_drop": policy.attack_recall_max_drop,
        "macro_f1_max_drop": policy.macro_f1_max_drop,
        "target_f1_max_drop": policy.target_f1_max_drop,
        "macro_minimum_support": policy.macro_minimum_support,
    }


def source_files() -> dict[str, str]:
    return {
        "python/nids_mvp/full_flow_model.py": sha256_path(Path(__file__).resolve())
    }


def artifact_record(path: Path, final_path: Path, root: Path) -> dict[str, Any]:
    return {
        "path": relative(final_path, root),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_path(path),
    }


def train_model(
    inputs: ModelInputs, policy: TrainingPolicy = PRODUCTION_POLICY
) -> tuple[dict[str, Any], bool]:
    if inputs.output_root.exists():
        return validate_model(inputs, policy), True
    verified = verify_inputs(inputs)
    parent = inputs.output_root.parent
    parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    work = parent / f".model-work-{token}"
    staging = parent / f".model-{token}.tmp"
    work.mkdir()
    staging.mkdir()
    started = time.monotonic()
    open_mappings: list[np.ndarray] = []

    def load_memmap(path: Path) -> np.ndarray:
        value = np.load(path, mmap_mode="r", allow_pickle=False)
        open_mappings.append(value)
        return value

    try:
        matrices = materialize_train_validation(verified, work / "matrices")
        x_train = load_memmap(matrices.x_train)
        y_train = load_memmap(matrices.y_train)
        x_validation = load_memmap(matrices.x_validation)
        y_validation = load_memmap(matrices.y_validation)
        probability_paths: dict[str, Path] = {}
        candidate_paths: dict[str, Path] = {}
        profile_results: list[dict[str, Any]] = []
        for profile in verified.profiles:
            profile_started = time.monotonic()
            print(
                f"[T9.1 model] profile={profile.profile_id} stage=train "
                f"features={profile.feature_count}",
                flush=True,
            )
            model, probability = fit_profile(
                x_train[:, : profile.feature_count],
                y_train,
                x_validation[:, : profile.feature_count],
                profile.feature_names,
                policy.parameters,
            )
            threshold_selection = select_threshold(
                y_validation, probability, policy
            )
            probability_path = work / f"profile-{profile.profile_id}-probability.npy"
            np.save(probability_path, probability, allow_pickle=False)
            probability_paths[profile.profile_id] = probability_path
            candidate_path = work / f"profile-{profile.profile_id}-model.joblib"
            candidate_bundle = {
                "schema_version": "1.0.0",
                "task": TASK,
                "kind": "terminal_flow_lightgbm_candidate",
                "profile_id": profile.profile_id,
                "feature_names": list(profile.feature_names),
                "class_order": list(CLASS_ORDER),
                "threshold": threshold_selection["threshold"],
                "preprocessing": {
                    "operation": "finite_float64_to_float32_cast",
                    "imputation": None,
                    "scaler": None,
                    "categorical_encoding": None,
                },
                "parameters": dict(policy.parameters),
                "model": model,
            }
            joblib.dump(candidate_bundle, candidate_path, compress=3)
            reloaded = joblib.load(candidate_path)
            reloaded_probability = predict_probabilities(
                reloaded["model"], x_validation[:, : profile.feature_count]
            )
            if not np.array_equal(reloaded_probability, probability):
                raise ValueError(
                    f"LightGBM reload probability parity mismatch: {profile.profile_id}"
                )
            candidate_paths[profile.profile_id] = candidate_path
            profile_results.append(
                {
                    "profile_id": profile.profile_id,
                    "profile_name": profile.name,
                    "feature_count": profile.feature_count,
                    "feature_names": list(profile.feature_names),
                    "fit_seconds": time.monotonic() - profile_started,
                    "probability_sha256": probability_sha256(probability),
                    "reload_probability_parity": "bitwise_equal_float64",
                    "threshold_selection": threshold_selection,
                }
            )
            del model, reloaded, probability, reloaded_probability
            gc.collect()
        selection = select_profile(profile_results, policy)
        selected_id = selection["selected_profile"]
        model_path = staging / "selected-model.joblib"
        shutil.copyfile(candidate_paths[selected_id], model_path)
        with model_path.open("rb+") as output:
            output.flush()
            os.fsync(output.fileno())
        predictions_path = staging / "validation-predictions.npz"
        prediction_values: dict[str, np.ndarray] = {
            "validation_capture_id": load_memmap(
                matrices.validation_capture_id
            ),
            "validation_flow_id": load_memmap(matrices.validation_flow_id),
            "y_true": y_validation,
        }
        for profile_id in PROFILE_LENGTHS:
            prediction_values[f"profile_{profile_id}_probability"] = load_memmap(
                probability_paths[profile_id]
            )
        with predictions_path.open("wb") as output:
            np.savez_compressed(output, **prediction_values)
            output.flush()
            os.fsync(output.fileno())
        final_model_path = inputs.output_root / model_path.name
        final_predictions_path = inputs.output_root / predictions_path.name
        manifest = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "terminal_flow_validation_selection",
            "status": "locked",
            "scope": "demo_critical_path",
            "generated_at_utc": utc_now(),
            "elapsed_seconds": time.monotonic() - started,
            "source_files": source_files(),
            "runtime": runtime_versions(inputs.requirements_path),
            "inputs": {
                "dataset_manifest": {
                    "path": relative(inputs.dataset_manifest_path, inputs.root),
                    "sha256": verified.dataset_manifest_sha256,
                },
                "feature_schema": {
                    "path": relative(inputs.feature_schema_path, inputs.root),
                    "schema_id": dataset.FEATURE_SCHEMA_ID,
                    "sha256": verified.feature_schema_sha256,
                },
                "requirements": {
                    "path": relative(inputs.requirements_path, inputs.root),
                    "sha256": verified.requirements_sha256,
                },
                "split_map_sha256": verified.split_map_sha256,
                "allowed_parts": [
                    {
                        "path": part.relative_path,
                        "partition": part.partition,
                        "rows": part.rows,
                        "size_bytes": part.size_bytes,
                        "sha256": part.sha256,
                    }
                    for part in (*verified.train_parts, *verified.validation_parts)
                ],
            },
            "labels": {
                "class_order": list(CLASS_ORDER),
                "benign_index": 0,
                "target_families": list(TARGET_FAMILIES),
                "attack_score": "1 - P(Benign)",
                "attack_family": "argmax P(class) over indices 1..5",
                "decision_rule": (
                    "attack_score >= selected_threshold selects the highest-"
                    "probability attack class; otherwise Benign"
                ),
            },
            "preprocessing": {
                "operation": "finite_float64_to_float32_cast",
                "input_dtype": "float64",
                "model_dtype": "float32",
                "imputation": None,
                "scaler": None,
                "categorical_encoding": None,
            },
            "policy": policy_record(policy),
            "population": {
                "train_rows": verified.train_rows,
                "validation_rows": verified.validation_rows,
                "family_counts": matrices.family_counts,
            },
            "profiles": profile_results,
            "selection": selection,
            "artifacts": {
                "selected_model": artifact_record(
                    model_path, final_model_path, inputs.root
                ),
                "validation_predictions": artifact_record(
                    predictions_path, final_predictions_path, inputs.root
                ),
            },
            "test_partition": {
                "status": "sealed",
                "feature_reads": 0,
                "metric_reads": 0,
                "path_resolution_or_hash_reads": 0,
            },
            "validation": {
                "train_only_fit": True,
                "validation_only_threshold_and_profile_selection": True,
                "metadata_excluded_from_model_matrix": True,
                "ordered_feature_prefixes_exact": True,
                "candidate_reload_probability_parity": True,
            },
            "deferred_for_demo": [
                "separate binary and family heads",
                "HistGradientBoosting and SGD benchmark",
                "nine algorithm-pair comparison",
                "sealed test evaluation",
                "extended performance benchmarking",
            ],
        }
        write_json_atomic(staging / "manifest.json", manifest)
        os.replace(staging, inputs.output_root)
        return manifest, False
    finally:
        for value in reversed(open_mappings):
            close_memmap(value)
        open_mappings.clear()
        gc.collect()
        if work.exists():
            shutil.rmtree(work)
        if staging.exists():
            shutil.rmtree(staging)


def validate_artifact(
    inputs: ModelInputs, record: Mapping[str, Any], expected_name: str
) -> Path:
    path = dataset.resolve_inside(inputs.root, str(record.get("path", "")))
    expected_path = inputs.output_root / expected_name
    if (
        path != expected_path.resolve()
        or not path.is_file()
        or path.stat().st_size != record.get("size_bytes")
        or sha256_path(path) != record.get("sha256")
    ):
        raise ValueError(f"terminal model artifact mismatch: {expected_name}")
    return path


def validate_model(
    inputs: ModelInputs, policy: TrainingPolicy = PRODUCTION_POLICY
) -> dict[str, Any]:
    verified = verify_inputs(inputs)
    manifest_path = inputs.output_root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("terminal model manifest missing")
    manifest = load_json(manifest_path)
    if (
        manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_validation_selection"
        or manifest.get("status") != "locked"
        or manifest.get("scope") != "demo_critical_path"
        or manifest.get("source_files") != source_files()
        or manifest.get("policy") != policy_record(policy)
        or manifest.get("labels", {}).get("class_order") != list(CLASS_ORDER)
        or manifest.get("inputs", {}).get("dataset_manifest", {}).get("sha256")
        != verified.dataset_manifest_sha256
        or manifest.get("inputs", {}).get("feature_schema", {}).get("sha256")
        != verified.feature_schema_sha256
        or manifest.get("inputs", {}).get("requirements", {}).get("sha256")
        != verified.requirements_sha256
        or manifest.get("inputs", {}).get("split_map_sha256")
        != verified.split_map_sha256
        or manifest.get("population", {}).get("train_rows") != verified.train_rows
        or manifest.get("population", {}).get("validation_rows")
        != verified.validation_rows
        or manifest.get("test_partition")
        != {
            "status": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_resolution_or_hash_reads": 0,
        }
    ):
        raise ValueError("terminal model manifest contract mismatch")
    allowed_parts = manifest.get("inputs", {}).get("allowed_parts")
    expected_parts = [
        {
            "path": part.relative_path,
            "partition": part.partition,
            "rows": part.rows,
            "size_bytes": part.size_bytes,
            "sha256": part.sha256,
        }
        for part in (*verified.train_parts, *verified.validation_parts)
    ]
    if allowed_parts != expected_parts:
        raise ValueError("terminal model allowed-part drift")
    artifacts = manifest.get("artifacts", {})
    model_path = validate_artifact(
        inputs, artifacts.get("selected_model", {}), "selected-model.joblib"
    )
    predictions_path = validate_artifact(
        inputs,
        artifacts.get("validation_predictions", {}),
        "validation-predictions.npz",
    )
    stored_profiles = manifest.get("profiles")
    if (
        not isinstance(stored_profiles, list)
        or [record.get("profile_id") for record in stored_profiles]
        != list(PROFILE_LENGTHS)
    ):
        raise ValueError("terminal model profile inventory mismatch")
    recomputed_results: list[dict[str, Any]] = []
    with np.load(predictions_path, allow_pickle=False) as predictions:
        capture_id = predictions["validation_capture_id"]
        flow_id = predictions["validation_flow_id"]
        y_true = predictions["y_true"]
        if (
            capture_id.dtype.kind != "U"
            or capture_id.shape != (verified.validation_rows,)
            or flow_id.dtype != np.uint64
            or flow_id.shape != (verified.validation_rows,)
            or y_true.dtype != np.uint8
            or y_true.shape != (verified.validation_rows,)
        ):
            raise ValueError("terminal validation identity artifact mismatch")
        for stored, profile in zip(stored_profiles, verified.profiles, strict=True):
            probability = predictions[f"profile_{profile.profile_id}_probability"]
            validate_probability_matrix(probability, verified.validation_rows)
            recomputed = select_threshold(y_true, probability, policy)
            if (
                stored.get("feature_count") != profile.feature_count
                or stored.get("feature_names") != list(profile.feature_names)
                or stored.get("probability_sha256") != probability_sha256(probability)
                or stored.get("threshold_selection") != recomputed
                or stored.get("reload_probability_parity")
                != "bitwise_equal_float64"
            ):
                raise ValueError(
                    f"terminal validation selection drift: {profile.profile_id}"
                )
            recomputed_results.append(
                {
                    "profile_id": profile.profile_id,
                    "feature_count": profile.feature_count,
                    "threshold_selection": recomputed,
                }
            )
    selection = select_profile(recomputed_results, policy)
    if manifest.get("selection") != selection:
        raise ValueError("terminal feature profile selection drift")
    bundle = joblib.load(model_path)
    selected_id = selection["selected_profile"]
    selected_profile = verified.profiles[list(PROFILE_LENGTHS).index(selected_id)]
    model = bundle.get("model")
    if (
        bundle.get("task") != TASK
        or bundle.get("kind") != "terminal_flow_lightgbm_candidate"
        or bundle.get("profile_id") != selected_id
        or bundle.get("feature_names") != list(selected_profile.feature_names)
        or bundle.get("class_order") != list(CLASS_ORDER)
        or bundle.get("parameters") != dict(policy.parameters)
        or bundle.get("preprocessing")
        != {
            "operation": "finite_float64_to_float32_cast",
            "imputation": None,
            "scaler": None,
            "categorical_encoding": None,
        }
        or not isinstance(model, LGBMClassifier)
        or model.classes_.tolist() != list(range(len(CLASS_ORDER)))
        or model.feature_name_ != list(selected_profile.feature_names)
    ):
        raise ValueError("selected terminal LightGBM model mismatch")
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    args = parser.parse_args(argv)
    try:
        inputs = production_inputs(args.project_root)
        if args.command == "check":
            verified = verify_inputs(inputs)
            print(
                f"[T9.1 model check] status=passed train_rows={verified.train_rows} "
                f"validation_rows={verified.validation_rows} test=sealed",
                flush=True,
            )
        elif args.command == "run":
            manifest, skipped = train_model(inputs)
            print(
                f"[T9.1 model] status={'skipped' if skipped else 'locked'} "
                f"profile={manifest['selection']['selected_profile']} test=sealed",
                flush=True,
            )
        else:
            manifest = validate_model(inputs)
            print(
                f"[T9.1 model validate] status=passed "
                f"profile={manifest['selection']['selected_profile']} test=sealed",
                flush=True,
            )
        return 0
    except (
        FileNotFoundError,
        ImportError,
        LightGBMError,
        OSError,
        RuntimeError,
        ValueError,
        pa.ArrowException,
    ) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
