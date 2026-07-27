from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
import os
import shutil
import sys
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import lightgbm
import numpy as np
import onnx
import onnxmltools
from lightgbm import LGBMClassifier
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType

from nids_mvp import full_flow_dataset as dataset
from nids_mvp import full_flow_model as model_stage


TASK = "T9.1"
BUNDLE_SCHEMA_ID = "nids.terminal_flow_bundle.v1"
BUNDLE_SCHEMA_VERSION = "1.0.0"
ARTIFACT_ID = "nids.terminal_flow_bundle.v1"
ARTIFACT_VERSION = "1.0.0"
GRAPH_NAME = "nids_t91_terminal_multiclass"
MODEL_MEMBER = "models/terminal_multiclass.onnx"
MEMBER_ORDER = (
    "feature_schema.json",
    "preprocessing.json",
    "thresholds.json",
    MODEL_MEMBER,
    "manifest.json",
)
JSON_MEMBERS = frozenset(MEMBER_ORDER) - {MODEL_MEMBER}
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_COMPRESSION_LEVEL = 9
ZIP_CREATE_SYSTEM = 0
ZIP_EXTERNAL_ATTRIBUTES = 0o600 << 16
TARGET_OPSET = 15
EXPECTED_OPSETS = {"ai.onnx": 9, "ai.onnx.ml": 1}
EXPECTED_CONVERTER_VERSIONS = {
    "lightgbm": "4.6.0",
    "onnx": "1.20.1",
    "onnxmltools": "1.16.0",
}
SEALED_TEST_RECORD = {
    "status": "sealed",
    "feature_reads": 0,
    "metric_reads": 0,
    "path_resolution_or_hash_reads": 0,
}
PREPROCESSING = {
    "operation": "finite_float64_to_float32_cast",
    "input_dtype": "float64",
    "model_dtype": "float32",
    "imputation": None,
    "scaler": None,
    "categorical_encoding": None,
}
PYTHON_CPP_PARITY_CONTRACT = {
    "claimed": False,
    "deferred_to": "phase7",
    "required_before_live": True,
}


@dataclass(frozen=True)
class BundleInputs:
    root: Path
    model_manifest_path: Path
    feature_schema_path: Path
    selected_model_path: Path
    validation_predictions_path: Path
    bundle_path: Path
    staging_path: Path
    enforce_runtime: bool = True


@dataclass(frozen=True)
class VerifiedInputs:
    inputs: BundleInputs
    model_manifest: dict[str, Any]
    model_manifest_sha256: str
    feature_schema: dict[str, Any]
    feature_schema_sha256: str
    selected_artifact: dict[str, Any]
    estimator: LGBMClassifier
    selected_profile: str
    selected_feature_indices: tuple[int, ...]
    selected_feature_names: tuple[str, ...]
    class_order: tuple[str, ...]
    threshold: float
    validation_parts: tuple[dict[str, Any], ...]
    validation_rows: int


@dataclass(frozen=True)
class ArchiveValidation:
    manifest: dict[str, Any]
    manifest_sha256: str
    archive_sha256: str
    model_blob: bytes
    members: Mapping[str, bytes]


def production_inputs(root: Path) -> BundleInputs:
    root = root.resolve()
    model_root = root / "run_log/full-flow-v1/model"
    return BundleInputs(
        root=root,
        model_manifest_path=model_root / "manifest.json",
        feature_schema_path=root / "config/terminal-flow-feature-schema-v1.json",
        selected_model_path=model_root / "selected-model.joblib",
        validation_predictions_path=model_root / "validation-predictions.npz",
        bundle_path=model_root / "terminal-flow.bundle.zip",
        staging_path=model_root / "terminal-flow.bundle",
        enforce_runtime=True,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def resolve_inside(root: Path, value: str) -> Path:
    candidate = Path(value)
    path = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return path


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def verify_artifact(
    root: Path,
    expected_path: Path,
    record: Mapping[str, Any],
    context: str,
) -> Path:
    path = resolve_inside(root, str(record.get("path", "")))
    if (
        path != expected_path.resolve()
        or not path.is_file()
        or not isinstance(record.get("size_bytes"), int)
        or path.stat().st_size != record.get("size_bytes")
        or not is_sha256(record.get("sha256"))
        or sha256_path(path) != record.get("sha256")
    ):
        raise ValueError(f"terminal {context} artifact mismatch")
    return path


def schema_feature_names(schema: Mapping[str, Any]) -> tuple[str, ...]:
    records = schema.get("features")
    vector = schema.get("feature_vector", {})
    profiles = schema.get("feature_profiles")
    if (
        schema.get("schema_id") != dataset.FEATURE_SCHEMA_ID
        or vector.get("length") != dataset.FEATURE_COUNT
        or vector.get("encoded_type") != "float64"
        or vector.get("finite_only") is not True
        or not isinstance(records, list)
        or len(records) != dataset.FEATURE_COUNT
        or not isinstance(profiles, list)
        or len(profiles) != len(model_stage.PROFILE_LENGTHS)
    ):
        raise ValueError("terminal feature schema inventory mismatch")
    names: list[str] = []
    for index, record in enumerate(records):
        if (
            not isinstance(record, Mapping)
            or record.get("index") != index
            or not isinstance(record.get("name"), str)
        ):
            raise ValueError("terminal feature schema ordering mismatch")
        names.append(str(record["name"]))
    if len(set(names)) != len(names):
        raise ValueError("terminal feature schema has duplicate names")
    for record, (profile_id, length) in zip(
        profiles, model_stage.PROFILE_LENGTHS.items(), strict=True
    ):
        if (
            not isinstance(record, Mapping)
            or record.get("id") != profile_id
            or not isinstance(record.get("name"), str)
            or record.get("start_index") != 0
            or record.get("end_index") != length - 1
            or record.get("length") != length
        ):
            raise ValueError("terminal feature profile schema mismatch")
    return tuple(names)


def bundle_preprocessing_contract(
    input_feature_names: Sequence[str],
    feature_schema_sha256: str,
    selected_profile: str,
    selected_indices: Sequence[int],
    selected_names: Sequence[str],
) -> dict[str, Any]:
    indices = list(selected_indices)
    names = list(selected_names)
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "feature_schema_id": dataset.FEATURE_SCHEMA_ID,
        "feature_schema_source_sha256": feature_schema_sha256,
        "input": {
            "dtype": "float64",
            "feature_count": dataset.FEATURE_COUNT,
            "feature_names": list(input_feature_names),
            "finite_required": True,
            "ordering": "ascending_feature_index",
        },
        "selection": {
            "operation": "select_indices",
            "profile_id": selected_profile,
            "profile_kind": "prefix",
            "feature_count": len(indices),
            "feature_indices": indices,
            "feature_names": names,
        },
        "output": {
            "dtype": "float32",
            "feature_count": len(indices),
            "feature_names": names,
            "finite_required": True,
            "float32_overflow": "fail_fast",
        },
        "steps": [
            {
                "operation": "require_finite",
                "dtype": "float64",
                "feature_count": dataset.FEATURE_COUNT,
            },
            {"operation": "select_indices", "indices": indices},
            {
                "operation": "cast",
                "from_dtype": "float64",
                "to_dtype": "float32",
                "overflow": "fail_fast",
            },
            {
                "operation": "require_finite",
                "dtype": "float32",
                "feature_count": len(indices),
            },
        ],
        "imputation": None,
        "scaler": None,
        "categorical_encoding": None,
    }


def threshold_contract(
    class_order: Sequence[str], threshold: float
) -> dict[str, Any]:
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "class_order": list(class_order),
        "selected_threshold": threshold,
        "decision": {
            "probability_tensor": "probabilities",
            "benign_class_index": 0,
            "attack_score": {
                "operation": "one_minus_probability",
                "probability_index": 0,
                "formula": "1.0 - probabilities[0]",
            },
            "gate": {"comparator": ">=", "threshold": threshold},
            "attack_class": {
                "operation": "argmax",
                "indices": list(range(1, len(class_order))),
                "tie_break": "lowest_class_index",
            },
            "benign_result_index": 0,
        },
    }


def verify_runtime(inputs: BundleInputs, manifest: Mapping[str, Any]) -> None:
    model_inputs = model_stage.production_inputs(inputs.root)
    model_stage.verify_runtime(model_inputs)
    observed = {
        "lightgbm": lightgbm.__version__,
        "onnx": onnx.__version__,
        "onnxmltools": onnxmltools.__version__,
    }
    model_packages = manifest.get("runtime", {}).get("packages", {})
    if observed != EXPECTED_CONVERTER_VERSIONS or any(
        model_packages.get(name) != version
        for name, version in EXPECTED_CONVERTER_VERSIONS.items()
    ):
        raise RuntimeError(
            "T9.1 ONNX converter runtime mismatch: "
            f"expected={EXPECTED_CONVERTER_VERSIONS}, observed={observed}"
        )


def verify_inputs(inputs: BundleInputs) -> VerifiedInputs:
    root = inputs.root.resolve()
    if not inputs.model_manifest_path.is_file() or not inputs.feature_schema_path.is_file():
        raise ValueError("terminal model selection or feature schema is missing")
    manifest = load_json(inputs.model_manifest_path)
    if inputs.enforce_runtime:
        verify_runtime(inputs, manifest)
    labels = manifest.get("labels", {})
    selection = manifest.get("selection", {})
    artifacts = manifest.get("artifacts", {})
    profile_id = selection.get("selected_profile")
    feature_count = selection.get("selected_feature_count")
    feature_indices = selection.get("selected_feature_indices")
    threshold = selection.get("selected_threshold")
    if (
        manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_validation_selection"
        or manifest.get("status") != "locked"
        or manifest.get("scope") != "demo_critical_path"
        or labels.get("class_order") != list(model_stage.CLASS_ORDER)
        or labels.get("benign_index") != 0
        or manifest.get("preprocessing") != PREPROCESSING
        or manifest.get("test_partition") != SEALED_TEST_RECORD
        or profile_id not in model_stage.PROFILE_LENGTHS
        or feature_count != model_stage.PROFILE_LENGTHS.get(profile_id)
        or feature_indices != list(range(int(feature_count or 0)))
        or not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or not math.isfinite(float(threshold))
        or not 0.0 <= float(threshold) <= 1.0
    ):
        raise ValueError("terminal model selection contract mismatch")
    if inputs.enforce_runtime and (
        manifest.get("source_files") != model_stage.source_files()
        or manifest.get("policy") != model_stage.policy_record(
            model_stage.PRODUCTION_POLICY
        )
    ):
        raise ValueError("terminal model implementation lock mismatch")
    schema = load_json(inputs.feature_schema_path)
    schema_hash = sha256_path(inputs.feature_schema_path)
    schema_record = manifest.get("inputs", {}).get("feature_schema", {})
    if (
        schema.get("schema_id") != dataset.FEATURE_SCHEMA_ID
        or schema_record.get("schema_id") != dataset.FEATURE_SCHEMA_ID
        or schema_record.get("sha256") != schema_hash
        or resolve_inside(root, str(schema_record.get("path", "")))
        != inputs.feature_schema_path.resolve()
        or inputs.enforce_runtime
        and schema_hash != dataset.FEATURE_SCHEMA_SHA256
    ):
        raise ValueError("terminal feature schema content address mismatch")
    all_feature_names = schema_feature_names(schema)
    selected_names = all_feature_names[: int(feature_count)]
    profiles = manifest.get("profiles")
    selected_profile_record = next(
        (
            record
            for record in profiles
            if isinstance(record, Mapping) and record.get("profile_id") == profile_id
        ),
        None,
    ) if isinstance(profiles, list) else None
    if (
        not isinstance(selected_profile_record, Mapping)
        or selected_profile_record.get("feature_count") != feature_count
        or selected_profile_record.get("feature_names") != list(selected_names)
    ):
        raise ValueError("terminal selected feature profile mismatch")
    model_path = verify_artifact(
        root,
        inputs.selected_model_path,
        artifacts.get("selected_model", {}),
        "selected model",
    )
    verify_artifact(
        root,
        inputs.validation_predictions_path,
        artifacts.get("validation_predictions", {}),
        "validation predictions",
    )
    selected_artifact = joblib.load(model_path)
    estimator = selected_artifact.get("model")
    candidate_preprocessing = {
        key: PREPROCESSING[key]
        for key in ("operation", "imputation", "scaler", "categorical_encoding")
    }
    if (
        selected_artifact.get("task") != TASK
        or selected_artifact.get("kind") != "terminal_flow_lightgbm_candidate"
        or selected_artifact.get("profile_id") != profile_id
        or selected_artifact.get("feature_names") != list(selected_names)
        or selected_artifact.get("class_order") != list(model_stage.CLASS_ORDER)
        or selected_artifact.get("threshold") != float(threshold)
        or selected_artifact.get("preprocessing") != candidate_preprocessing
        or not isinstance(estimator, LGBMClassifier)
        or estimator.classes_.tolist() != list(range(len(model_stage.CLASS_ORDER)))
        or estimator.n_features_in_ != feature_count
        or estimator.feature_name_ != list(selected_names)
    ):
        raise ValueError("terminal selected LightGBM artifact mismatch")
    allowed_parts = manifest.get("inputs", {}).get("allowed_parts")
    if not isinstance(allowed_parts, list) or any(
        not isinstance(record, Mapping)
        or record.get("partition") not in {"train", "validation"}
        for record in allowed_parts
    ):
        raise ValueError("terminal allowed-part manifest mismatch")
    validation_parts = tuple(
        dict(record) for record in allowed_parts if record.get("partition") == "validation"
    )
    validation_rows = manifest.get("population", {}).get("validation_rows")
    if (
        not validation_parts
        or not isinstance(validation_rows, int)
        or validation_rows < 1
        or sum(int(record.get("rows", -1)) for record in validation_parts)
        != validation_rows
    ):
        raise ValueError("terminal validation inventory mismatch")
    return VerifiedInputs(
        inputs=inputs,
        model_manifest=manifest,
        model_manifest_sha256=sha256_path(inputs.model_manifest_path),
        feature_schema=schema,
        feature_schema_sha256=schema_hash,
        selected_artifact=selected_artifact,
        estimator=estimator,
        selected_profile=str(profile_id),
        selected_feature_indices=tuple(feature_indices),
        selected_feature_names=selected_names,
        class_order=tuple(model_stage.CLASS_ORDER),
        threshold=float(threshold),
        validation_parts=validation_parts,
        validation_rows=validation_rows,
    )


def serialized_nodes(model: onnx.ModelProto) -> tuple[bytes, ...]:
    return tuple(node.SerializeToString(deterministic=True) for node in model.graph.node)


def serialized_initializers(model: onnx.ModelProto) -> tuple[bytes, ...]:
    return tuple(
        value.SerializeToString(deterministic=True)
        for value in model.graph.initializer
    )


def tensor_shape(value: onnx.ValueInfoProto) -> list[int]:
    result: list[int] = []
    for dimension in value.type.tensor_type.shape.dim:
        result.append(int(dimension.dim_value) if dimension.HasField("dim_value") else -1)
    return result


def repair_label_batch_shape(model: onnx.ModelProto) -> None:
    nodes_before = serialized_nodes(model)
    initializers_before = serialized_initializers(model)
    outputs = {value.name: value for value in model.graph.output}
    label = outputs.get("label")
    if label is None:
        raise ValueError("terminal ONNX model is missing label output")
    dimensions = label.type.tensor_type.shape.dim
    if len(dimensions) != 1:
        raise ValueError(f"unexpected terminal ONNX label rank: {len(dimensions)}")
    dimension = dimensions[0]
    if dimension.HasField("dim_value") and dimension.dim_value != 1:
        raise ValueError(
            f"unexpected terminal ONNX label dimension: {dimension.dim_value}"
        )
    if dimension.dim_param not in ("", "N"):
        raise ValueError(
            f"unexpected terminal ONNX label symbol: {dimension.dim_param}"
        )
    dimension.dim_param = "N"
    if tensor_shape(label) != [-1]:
        raise ValueError("terminal ONNX label shape repair failed")
    if serialized_nodes(model) != nodes_before:
        raise ValueError("terminal ONNX label repair changed graph nodes")
    if serialized_initializers(model) != initializers_before:
        raise ValueError("terminal ONNX label repair changed initializers")


def conversion_estimator(estimator: LGBMClassifier) -> tuple[LGBMClassifier, np.ndarray, str]:
    original_classes = np.asarray(estimator.classes_).copy()
    expected_classes = np.arange(len(model_stage.CLASS_ORDER), dtype=np.int64)
    if original_classes.tolist() != expected_classes.tolist():
        raise ValueError(f"unexpected LightGBM classes: {original_classes.tolist()}")
    booster_text = estimator.booster_.model_to_string()
    converted = copy.deepcopy(estimator)
    converted._classes = expected_classes.copy()
    if (
        np.asarray(converted.classes_).dtype != np.dtype(np.int64)
        or converted.classes_.tolist() != expected_classes.tolist()
        or converted.booster_.model_to_string() != booster_text
    ):
        raise ValueError("LightGBM conversion copy normalization changed the model")
    return converted, original_classes, booster_text


def convert_estimator(estimator: LGBMClassifier, feature_count: int) -> bytes:
    converted, original_classes, booster_text = conversion_estimator(estimator)
    model = convert_lightgbm(
        converted,
        name=GRAPH_NAME,
        initial_types=[("input", FloatTensorType([None, feature_count]))],
        target_opset=TARGET_OPSET,
        zipmap=False,
    )
    if (
        not np.array_equal(np.asarray(estimator.classes_), original_classes)
        or estimator.booster_.model_to_string() != booster_text
        or converted.booster_.model_to_string() != booster_text
    ):
        raise ValueError("ONNX conversion mutated the selected LightGBM artifact")
    model.graph.name = GRAPH_NAME
    repair_label_batch_shape(model)
    onnx.checker.check_model(model)
    metadata = onnx_metadata(model)
    expected_metadata = {
        "graph_name": GRAPH_NAME,
        "input": {"name": "input", "dtype": "float", "shape": [-1, feature_count]},
        "outputs": [
            {"name": "label", "dtype": "int64", "shape": [-1]},
            {
                "name": "probabilities",
                "dtype": "float",
                "shape": [-1, len(model_stage.CLASS_ORDER)],
            },
        ],
        "opset_imports": EXPECTED_OPSETS,
    }
    if metadata != expected_metadata:
        raise ValueError(
            "terminal ONNX metadata mismatch: "
            f"expected={expected_metadata}, observed={metadata}"
        )
    if any(node.op_type == "ZipMap" for node in model.graph.node):
        raise ValueError("terminal ONNX unexpectedly contains ZipMap")
    return model.SerializeToString(deterministic=True)


def export_repeat_checked(estimator: LGBMClassifier, feature_count: int) -> bytes:
    first = convert_estimator(estimator, feature_count)
    second = convert_estimator(estimator, feature_count)
    if first != second:
        raise ValueError("nondeterministic terminal LightGBM ONNX export")
    return first


def onnx_metadata(model_or_blob: onnx.ModelProto | bytes) -> dict[str, Any]:
    model = (
        onnx.load_model_from_string(model_or_blob)
        if isinstance(model_or_blob, bytes)
        else model_or_blob
    )
    onnx.checker.check_model(model)
    tensor_names = onnx.TensorProto.DataType

    def value_record(value: onnx.ValueInfoProto) -> dict[str, Any]:
        return {
            "name": value.name,
            "dtype": tensor_names.Name(value.type.tensor_type.elem_type).lower(),
            "shape": tensor_shape(value),
        }

    if len(model.graph.input) != 1:
        raise ValueError("terminal ONNX must expose exactly one input")
    return {
        "graph_name": model.graph.name,
        "input": value_record(model.graph.input[0]),
        "outputs": [value_record(value) for value in model.graph.output],
        "opset_imports": {
            item.domain or "ai.onnx": int(item.version)
            for item in model.opset_import
        },
    }


def member_record(name: str, value: bytes) -> dict[str, Any]:
    return {"path": name, "size_bytes": len(value), "sha256": sha256_bytes(value)}


def build_members(verified: VerifiedInputs, model_blob: bytes) -> dict[str, bytes]:
    all_feature_names = schema_feature_names(verified.feature_schema)
    preprocessing = bundle_preprocessing_contract(
        all_feature_names,
        verified.feature_schema_sha256,
        verified.selected_profile,
        verified.selected_feature_indices,
        verified.selected_feature_names,
    )
    thresholds = threshold_contract(verified.class_order, verified.threshold)
    members = {
        "feature_schema.json": canonical_json(verified.feature_schema),
        "preprocessing.json": canonical_json(preprocessing),
        "thresholds.json": canonical_json(thresholds),
        MODEL_MEMBER: model_blob,
    }
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "task": TASK,
        "kind": "terminal_flow_native_bundle_manifest",
        "status": "locked",
        "artifact_id": ARTIFACT_ID,
        "artifact_version": ARTIFACT_VERSION,
        "bundle_schema_id": BUNDLE_SCHEMA_ID,
        "feature_schema_id": dataset.FEATURE_SCHEMA_ID,
        "feature_schema_source_sha256": verified.feature_schema_sha256,
        "model_selection": {
            "manifest_path": relative(
                verified.inputs.model_manifest_path, verified.inputs.root
            ),
            "manifest_sha256": verified.model_manifest_sha256,
            "selected_model_sha256": verified.model_manifest["artifacts"][
                "selected_model"
            ]["sha256"],
            "validation_predictions_sha256": verified.model_manifest["artifacts"][
                "validation_predictions"
            ]["sha256"],
        },
        "selected_profile": verified.selected_profile,
        "selected_feature_count": len(verified.selected_feature_indices),
        "selected_feature_indices": list(verified.selected_feature_indices),
        "selected_feature_names": list(verified.selected_feature_names),
        "class_order": list(verified.class_order),
        "benign_index": 0,
        "selected_threshold": verified.threshold,
        "members": [member_record(name, members[name]) for name in MEMBER_ORDER[:-1]],
        "model": onnx_metadata(model_blob),
        "converter": {
            **EXPECTED_CONVERTER_VERSIONS,
            "requested_target_opset": TARGET_OPSET,
            "zipmap": False,
            "serialization": "protobuf_deterministic",
        },
        "test_partition": SEALED_TEST_RECORD,
        "parity": {
            "python_ort": {
                "claimed": False,
                "external_evidence": "onnx-parity.json",
                "required_before_native": True,
            },
            "python_cpp_numeric_parity": dict(PYTHON_CPP_PARITY_CONTRACT),
        },
    }
    members["manifest.json"] = canonical_json(manifest)
    return members


def archive_bytes(members: Mapping[str, bytes]) -> bytes:
    if set(members) != set(MEMBER_ORDER):
        raise ValueError("terminal bundle member inventory mismatch")
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=ZIP_COMPRESSION_LEVEL,
    ) as archive:
        for name in MEMBER_ORDER:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = ZIP_CREATE_SYSTEM
            info.external_attr = ZIP_EXTERNAL_ATTRIBUTES
            info.extra = b""
            info.comment = b""
            archive.writestr(
                info,
                members[name],
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=ZIP_COMPRESSION_LEVEL,
            )
    return output.getvalue()


def validate_archive(
    blob: bytes,
    expected_manifest_sha256: str | None = None,
    expected: VerifiedInputs | None = None,
) -> ArchiveValidation:
    with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
        infos = archive.infolist()
        if tuple(info.filename for info in infos) != MEMBER_ORDER:
            raise ValueError("terminal bundle member order or uniqueness mismatch")
        if archive.testzip() is not None:
            raise ValueError("terminal bundle CRC failure")
        for info in infos:
            if (
                info.date_time != ZIP_TIMESTAMP
                or info.compress_type != zipfile.ZIP_DEFLATED
                or info.create_system != ZIP_CREATE_SYSTEM
                or info.external_attr != ZIP_EXTERNAL_ATTRIBUTES
                or info.extra != b""
                or info.comment != b""
            ):
                raise ValueError(f"terminal bundle metadata mismatch: {info.filename}")
        members = {info.filename: archive.read(info) for info in infos}
    for name in JSON_MEMBERS:
        try:
            value = json.loads(members[name].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid terminal JSON member: {name}") from error
        if canonical_json(value) != members[name]:
            raise ValueError(f"non-canonical terminal JSON member: {name}")
    manifest = json.loads(members["manifest.json"])
    manifest_hash = sha256_bytes(members["manifest.json"])
    if expected_manifest_sha256 is not None and manifest_hash != expected_manifest_sha256:
        raise ValueError("terminal bundle manifest trust hash mismatch")
    model_metadata = onnx_metadata(members[MODEL_MEMBER])
    expected_records = [member_record(name, members[name]) for name in MEMBER_ORDER[:-1]]
    feature_schema = json.loads(members["feature_schema.json"])
    preprocessing = json.loads(members["preprocessing.json"])
    thresholds = json.loads(members["thresholds.json"])
    if not all(
        isinstance(value, Mapping)
        for value in (manifest, feature_schema, preprocessing, thresholds)
    ):
        raise ValueError("terminal bundle JSON members must be objects")
    all_feature_names = schema_feature_names(feature_schema)
    profile_id = manifest.get("selected_profile")
    feature_count = manifest.get("selected_feature_count")
    feature_indices = manifest.get("selected_feature_indices")
    feature_names = manifest.get("selected_feature_names")
    threshold = manifest.get("selected_threshold")
    source_schema_hash = manifest.get("feature_schema_source_sha256")
    expected_feature_count = (
        model_stage.PROFILE_LENGTHS.get(profile_id)
        if isinstance(profile_id, str)
        else None
    )
    if (
        expected_feature_count is None
        or feature_count != expected_feature_count
        or feature_indices != list(range(expected_feature_count))
        or feature_names != list(all_feature_names[:expected_feature_count])
        or not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or not math.isfinite(float(threshold))
        or not 0.0 <= float(threshold) <= 1.0
        or not is_sha256(source_schema_hash)
    ):
        raise ValueError("terminal bundle selected feature contract mismatch")
    expected_preprocessing = bundle_preprocessing_contract(
        all_feature_names,
        str(source_schema_hash),
        str(profile_id),
        feature_indices,
        feature_names,
    )
    expected_thresholds = threshold_contract(
        model_stage.CLASS_ORDER, float(threshold)
    )
    expected_model_metadata = {
        "graph_name": GRAPH_NAME,
        "input": {
            "name": "input",
            "dtype": "float",
            "shape": [-1, expected_feature_count],
        },
        "outputs": [
            {"name": "label", "dtype": "int64", "shape": [-1]},
            {
                "name": "probabilities",
                "dtype": "float",
                "shape": [-1, len(model_stage.CLASS_ORDER)],
            },
        ],
        "opset_imports": EXPECTED_OPSETS,
    }
    expected_converter = {
        **EXPECTED_CONVERTER_VERSIONS,
        "requested_target_opset": TARGET_OPSET,
        "zipmap": False,
        "serialization": "protobuf_deterministic",
    }
    expected_parity = {
        "python_ort": {
            "claimed": False,
            "external_evidence": "onnx-parity.json",
            "required_before_native": True,
        },
        "python_cpp_numeric_parity": PYTHON_CPP_PARITY_CONTRACT,
    }
    model_selection = manifest.get("model_selection")
    if (
        set(manifest)
        != {
            "schema_version",
            "task",
            "kind",
            "status",
            "artifact_id",
            "artifact_version",
            "bundle_schema_id",
            "feature_schema_id",
            "feature_schema_source_sha256",
            "model_selection",
            "selected_profile",
            "selected_feature_count",
            "selected_feature_indices",
            "selected_feature_names",
            "class_order",
            "benign_index",
            "selected_threshold",
            "members",
            "model",
            "converter",
            "test_partition",
            "parity",
        }
        or manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION
        or manifest.get("task") != TASK
        or manifest.get("kind") != "terminal_flow_native_bundle_manifest"
        or manifest.get("status") != "locked"
        or manifest.get("artifact_id") != ARTIFACT_ID
        or manifest.get("artifact_version") != ARTIFACT_VERSION
        or manifest.get("bundle_schema_id") != BUNDLE_SCHEMA_ID
        or manifest.get("feature_schema_id") != dataset.FEATURE_SCHEMA_ID
        or manifest.get("members") != expected_records
        or manifest.get("model") != expected_model_metadata
        or model_metadata != expected_model_metadata
        or manifest.get("converter") != expected_converter
        or manifest.get("class_order") != list(model_stage.CLASS_ORDER)
        or manifest.get("benign_index") != 0
        or manifest.get("test_partition") != SEALED_TEST_RECORD
        or manifest.get("parity") != expected_parity
        or preprocessing != expected_preprocessing
        or thresholds != expected_thresholds
        or not isinstance(model_selection, Mapping)
        or set(model_selection)
        != {
            "manifest_path",
            "manifest_sha256",
            "selected_model_sha256",
            "validation_predictions_sha256",
        }
        or not isinstance(model_selection.get("manifest_path"), str)
        or not model_selection.get("manifest_path")
        or not is_sha256(model_selection.get("manifest_sha256"))
        or not is_sha256(model_selection.get("selected_model_sha256"))
        or not is_sha256(model_selection.get("validation_predictions_sha256"))
    ):
        raise ValueError("terminal bundle manifest or member contract mismatch")
    if expected is not None and (
        feature_schema != expected.feature_schema
        or manifest.get("model_selection", {}).get("manifest_sha256")
        != expected.model_manifest_sha256
        or manifest.get("model_selection", {}).get("selected_model_sha256")
        != expected.model_manifest["artifacts"]["selected_model"]["sha256"]
        or manifest.get("model_selection", {}).get("validation_predictions_sha256")
        != expected.model_manifest["artifacts"]["validation_predictions"]["sha256"]
        or manifest.get("feature_schema_source_sha256")
        != expected.feature_schema_sha256
        or manifest.get("selected_profile") != expected.selected_profile
        or manifest.get("selected_feature_indices")
        != list(expected.selected_feature_indices)
        or manifest.get("selected_feature_names")
        != list(expected.selected_feature_names)
        or manifest.get("selected_threshold") != expected.threshold
    ):
        raise ValueError("terminal bundle source lock mismatch")
    return ArchiveValidation(
        manifest=manifest,
        manifest_sha256=manifest_hash,
        archive_sha256=sha256_bytes(blob),
        model_blob=members[MODEL_MEMBER],
        members=members,
    )


def build_bundle(inputs: BundleInputs) -> tuple[bytes, VerifiedInputs, ArchiveValidation]:
    verified = verify_inputs(inputs)
    model_blob = export_repeat_checked(
        verified.estimator, len(verified.selected_feature_indices)
    )
    members = build_members(verified, model_blob)
    first = archive_bytes(members)
    second = archive_bytes(members)
    if first != second:
        raise ValueError("nondeterministic terminal bundle archive")
    validation = validate_archive(first, expected=verified)
    return first, verified, validation


def write_bytes_atomic(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_staging(
    staging_path: Path, archive: ArchiveValidation
) -> None:
    if not staging_path.is_dir() or staging_path.is_symlink():
        raise ValueError("terminal bundle staging directory is missing")
    observed: dict[str, Path] = {}
    observed_directories: set[str] = set()
    for path in staging_path.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"terminal bundle staging contains symlink: {path.name}")
        if path.is_file():
            name = path.relative_to(staging_path).as_posix()
            if name in observed:
                raise ValueError(f"duplicate terminal staged member: {name}")
            observed[name] = path
        elif path.is_dir():
            observed_directories.add(path.relative_to(staging_path).as_posix())
        else:
            raise ValueError(f"invalid terminal bundle staging entry: {path.name}")
    if observed_directories != {"models"}:
        raise ValueError("terminal bundle staging directory inventory mismatch")
    if set(observed) != set(MEMBER_ORDER):
        raise ValueError("terminal bundle staging member inventory mismatch")
    for name in MEMBER_ORDER:
        if observed[name].read_bytes() != archive.members[name]:
            raise ValueError(f"terminal staged member differs from archive: {name}")
    manifest_hash = sha256_path(observed["manifest.json"])
    if manifest_hash != archive.manifest_sha256:
        raise ValueError("terminal staged manifest trust hash mismatch")


def write_staging_atomic(
    staging_path: Path,
    archive: ArchiveValidation,
) -> None:
    staging_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = staging_path.with_name(
        f".{staging_path.name}.{uuid.uuid4().hex}.tmp"
    )
    try:
        temporary.mkdir()
        for name in MEMBER_ORDER:
            target = temporary.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(archive.members[name])
                output.flush()
                os.fsync(output.fileno())
        validate_staging(temporary, archive)
        os.replace(temporary, staging_path)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def publish(inputs: BundleInputs) -> tuple[ArchiveValidation, bool]:
    blob, verified, validation = build_bundle(inputs)
    archive_existed = inputs.bundle_path.exists()
    staging_existed = inputs.staging_path.exists()
    if inputs.bundle_path.exists():
        existing = inputs.bundle_path.read_bytes()
        existing_validation = validate_archive(existing, expected=verified)
        if existing != blob:
            raise ValueError("existing terminal bundle differs from deterministic rebuild")
        validation = existing_validation
    else:
        write_bytes_atomic(inputs.bundle_path, blob)
    published = validate_archive(inputs.bundle_path.read_bytes(), expected=verified)
    if published.archive_sha256 != validation.archive_sha256:
        raise ValueError("published terminal bundle hash mismatch")
    if inputs.staging_path.exists():
        validate_staging(inputs.staging_path, published)
    else:
        write_staging_atomic(inputs.staging_path, published)
    validate_staging(inputs.staging_path, published)
    return published, archive_existed and staging_existed


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Build the T9.1 terminal ONNX bundle")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args(argv)
    try:
        inputs = production_inputs(args.project_root)
        if args.command == "check":
            blob, verified, validation = build_bundle(inputs)
            print(
                "[T9.1 bundle check] status=passed "
                f"profile={verified.selected_profile} bytes={len(blob)} "
                f"manifest_sha256={validation.manifest_sha256}",
                flush=True,
            )
        elif args.command == "run":
            validation, skipped = publish(inputs)
            print(
                f"[T9.1 bundle run] status={'skipped' if skipped else 'passed'} "
                f"archive_sha256={validation.archive_sha256} "
                f"manifest_sha256={validation.manifest_sha256}",
                flush=True,
            )
        else:
            path = args.input.resolve() if args.input else inputs.bundle_path
            validation = validate_archive(
                path.read_bytes(), expected_manifest_sha256=args.manifest_sha256
            )
            if args.input is None:
                validate_staging(inputs.staging_path, validation)
            print(
                "[T9.1 bundle validate] status=passed "
                f"archive_sha256={validation.archive_sha256} "
                f"manifest_sha256={validation.manifest_sha256}",
                flush=True,
            )
        return 0
    except (
        FileNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
