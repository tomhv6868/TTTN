from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import onnx
import sklearn
import skl2onnx
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType


TASK = "T5.1"
JSON_MEMBERS = {
    "feature_schema.json",
    "preprocessing.json",
    "hbos.json",
    "thresholds.json",
    "manifest.json",
}
MODEL_MEMBERS = {
    "flow_rf": "models/flow_rf.onnx",
    "isolation_forest": "models/isolation_forest.onnx",
    "known_family_rf": "models/known_family_rf.onnx",
}


@dataclass(frozen=True)
class Inputs:
    contract: dict[str, Any]
    feature_schema: dict[str, Any]
    preprocessing: dict[str, Any]
    flow_rf: dict[str, Any]
    anomaly: dict[str, Any]
    known_family: dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if isinstance(value, np.ndarray):
        return jsonable(value.tolist())
    if isinstance(value, np.generic):
        return value.item()
    return value


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            jsonable(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


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


def verify_reference(root: Path, name: str, record: Mapping[str, Any]) -> Path:
    path = resolve_inside(root, str(record.get("path", "")))
    if not path.is_file():
        raise ValueError(f"missing T5.1 prerequisite: {name}")
    if path.stat().st_size != record.get("size_bytes") or sha256_path(path) != record.get("sha256"):
        raise ValueError(f"T5.1 prerequisite content mismatch: {name}")
    return path


def verify_runtime(contract: Mapping[str, Any]) -> None:
    expected = contract["execution"]["versions"]
    observed = {
        "joblib": joblib.__version__,
        "numpy": np.__version__,
        "onnx": onnx.__version__,
        "scikit_learn": sklearn.__version__,
        "skl2onnx": skl2onnx.__version__,
    }
    if observed != expected:
        raise ValueError(f"T5.1 exporter runtime mismatch: expected={expected}, observed={observed}")
    python = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if python != contract["execution"]["python"]:
        raise ValueError(f"T5.1 Python mismatch: expected={contract['execution']['python']}, observed={python}")


def verify_inputs(root: Path, contract_path: Path) -> Inputs:
    contract = load_json(contract_path)
    checkpoints = contract.get("artifact", {}).get("checkpoints")
    if (
        contract.get("task") != TASK
        or checkpoints != ["F3", "F5", "F7", "F9"]
        or contract.get("design_approval", {}).get("decision") != "accepted"
        or contract["design_approval"].get("production_models")
        != ["flow_rf", "known_family_rf", "hbos", "isolation_forest"]
    ):
        raise ValueError("invalid T5.1 artifact bundle contract")
    verify_runtime(contract)
    paths = {
        name: verify_reference(root, name, record)
        for name, record in contract["prerequisites"].items()
    }
    feature_schema = load_json(paths["feature_schema"])
    preprocessing = load_json(paths["preprocessing_acceptance"])
    model_acceptance = load_json(paths["model_acceptance"])
    manual_acceptance = load_json(paths["model_manual_acceptance"])
    dependencies = load_json(paths["export_dependencies"])
    for name in ("preprocessing_acceptance", "flow_rf_acceptance", "anomaly_acceptance", "known_family_acceptance"):
        if load_json(paths[name]).get("status") != "passed":
            raise ValueError(f"prerequisite acceptance is not passed: {name}")
    if (
        model_acceptance.get("status") != "passed"
        or model_acceptance.get("gate", {}).get("recommended_binary_classifier") != "flow_rf"
        or manual_acceptance.get("status") != "passed"
        or manual_acceptance.get("decision") != "accepted"
        or manual_acceptance.get("selection", {}).get("phase_5_binary_classifier") != "flow_rf"
        or not manual_acceptance.get("gate", {}).get("t5_1_authorized")
        or dependencies.get("status") != "passed"
    ):
        raise ValueError("T4.8 selection or T5.1 dependency authorization mismatch")
    flow_rf = joblib.load(paths["flow_rf_artifact"])
    anomaly = joblib.load(paths["anomaly_artifact"])
    known_family = joblib.load(paths["known_family_artifact"])
    raw_names = [record["name"] for record in feature_schema.get("features", [])]
    artifact = preprocessing.get("artifact", {})
    if (
        feature_schema.get("schema_id") != "nids.flow_features.v1"
        or feature_schema.get("feature_vector", {}).get("length") != 54
        or len(raw_names) != 54
        or artifact.get("input_features") != raw_names
        or list(flow_rf.get("checkpoints", {})) != checkpoints
        or list(anomaly.get("checkpoints", {})) != checkpoints
        or list(known_family.get("checkpoints", {})) != checkpoints
        or flow_rf.get("threshold") != 0.5
        or len(known_family.get("labels", {}).get("class_order", [])) != 13
    ):
        raise ValueError("T5.1 accepted artifact identity mismatch")
    required_hbos = set(contract["hbos"]["required_fields"])
    for checkpoint in checkpoints:
        accepted_profiles = artifact["checkpoints"][checkpoint]["profiles"]
        flow_record = flow_rf["checkpoints"][checkpoint]
        anomaly_record = anomaly["checkpoints"][checkpoint]
        known_record = known_family["checkpoints"][checkpoint]
        supervised = accepted_profiles["supervised_known"]
        anomaly_profile = accepted_profiles["anomaly_benign"]
        flow_model = flow_record.get("model")
        known_model = known_record.get("model")
        iforest = anomaly_record.get("isolation_forest", {}).get("estimator")
        if (
            flow_record.get("preprocessing_profile") != supervised
            or known_record.get("preprocessing_profile") != supervised
            or anomaly_record.get("preprocessing_profile") != anomaly_profile
            or flow_record.get("selected_features") != supervised["selected_features"]
            or known_record.get("features") != supervised["selected_features"]
            or not isinstance(flow_model, RandomForestClassifier)
            or not isinstance(known_model, RandomForestClassifier)
            or not isinstance(iforest, IsolationForest)
            or len(flow_model.estimators_) != 300
            or len(known_model.estimators_) != 300
            or len(iforest.estimators_) != 300
            or flow_model.classes_.tolist() != [0, 1]
            or known_model.classes_.tolist() != list(range(13))
            or flow_model.n_features_in_ != len(supervised["selected_features"])
            or known_model.n_features_in_ != len(supervised["selected_features"])
            or iforest.n_features_in_ != len(anomaly_profile["selected_features"])
        ):
            raise ValueError(f"T5.1 model or preprocessing mismatch: {checkpoint}")
        hbos = anomaly_record.get("hbos", {})
        indices = hbos.get("feature_indices", [])
        if (
            set(hbos) != required_hbos
            or hbos.get("feature_names") != [anomaly_profile["selected_features"][index] for index in indices]
            or hbos.get("total_bin_count") != 18
            or hbos.get("interior_bin_count") != 16
            or anomaly_record["isolation_forest"].get("feature_names")
            != anomaly_profile["selected_features"]
        ):
            raise ValueError(f"T5.1 anomaly state mismatch: {checkpoint}")
        for model_name in ("hbos", "isolation_forest"):
            decision = anomaly_record[model_name]["decision"]
            numeric = [
                decision[name]
                for name in (
                    "mean",
                    "standard_deviation",
                    "threshold",
                    "threshold_quantile",
                    "empirical_benign_train_fpr",
                )
            ]
            if not np.isfinite(numeric).all() or decision["standard_deviation"] <= 0:
                raise ValueError(f"T5.1 invalid anomaly decision: {checkpoint}/{model_name}")
    return Inputs(contract, feature_schema, preprocessing, flow_rf, anomaly, known_family)


def repair_iforest_score_samples_shape(model: onnx.ModelProto) -> None:
    nodes_before = [node.SerializeToString(deterministic=True) for node in model.graph.node]
    initializers_before = [value.SerializeToString(deterministic=True) for value in model.graph.initializer]
    outputs = {value.name: value for value in model.graph.output}
    output = outputs.get("score_samples")
    if output is None:
        raise ValueError("Isolation Forest ONNX is missing score_samples output")
    shape = output.type.tensor_type.shape
    if len(shape.dim) == 0:
        shape.dim.add().dim_param = "N"
        shape.dim.add().dim_value = 1
    elif len(shape.dim) != 2 or shape.dim[1].dim_value != 1:
        raise ValueError("unexpected Isolation Forest score_samples shape")
    if nodes_before != [node.SerializeToString(deterministic=True) for node in model.graph.node]:
        raise ValueError("Isolation Forest metadata repair changed graph nodes")
    if initializers_before != [
        value.SerializeToString(deterministic=True) for value in model.graph.initializer
    ]:
        raise ValueError("Isolation Forest metadata repair changed initializers")


def convert_estimator(estimator: Any, feature_count: int, model_name: str) -> bytes:
    options = (
        {id(estimator): {"score_samples": True}}
        if model_name == "isolation_forest"
        else {id(estimator): {"zipmap": False}}
    )
    original_n_jobs = getattr(estimator, "n_jobs", None)
    if original_n_jobs is not None:
        estimator.n_jobs = 1
    try:
        model = convert_sklearn(
            estimator,
            initial_types=[("input", FloatTensorType([None, feature_count]))],
            options=options,
            target_opset={"": 15, "ai.onnx.ml": 2},
        )
    finally:
        if original_n_jobs is not None:
            estimator.n_jobs = original_n_jobs
    model.graph.name = f"nids_t51_{model_name}"
    if model_name == "isolation_forest":
        repair_iforest_score_samples_shape(model)
    onnx.checker.check_model(model)
    expected_outputs = (
        ["label", "scores", "score_samples"]
        if model_name == "isolation_forest"
        else ["label", "probabilities"]
    )
    if [value.name for value in model.graph.output] != expected_outputs:
        raise ValueError(f"unexpected ONNX outputs for {model_name}")
    return model.SerializeToString(deterministic=True)


def export_repeat_checked(estimator: Any, feature_count: int, model_name: str) -> bytes:
    first = convert_estimator(estimator, feature_count, model_name)
    second = convert_estimator(estimator, feature_count, model_name)
    if first != second:
        raise ValueError(f"nondeterministic ONNX export: {model_name}")
    return first


def tensor_shape(value: onnx.ValueInfoProto) -> list[Any]:
    dimensions: list[Any] = []
    for dimension in value.type.tensor_type.shape.dim:
        if dimension.HasField("dim_value"):
            dimensions.append(int(dimension.dim_value))
        elif dimension.dim_param:
            dimensions.append(dimension.dim_param)
        else:
            dimensions.append(None)
    return dimensions


def onnx_metadata(blob: bytes, class_order: Sequence[Any] | None) -> dict[str, Any]:
    model = onnx.load_model_from_string(blob)
    onnx.checker.check_model(model)
    tensor_type = onnx.TensorProto.DataType
    model_input = model.graph.input[0]
    return {
        "input_name": model_input.name,
        "input_dtype": tensor_type.Name(model_input.type.tensor_type.elem_type).lower(),
        "input_shape": tensor_shape(model_input),
        "output_names": [value.name for value in model.graph.output],
        "output_shapes": {value.name: tensor_shape(value) for value in model.graph.output},
        "class_order": list(class_order) if class_order is not None else None,
        "opset_imports": [
            {"domain": item.domain or "ai.onnx", "version": item.version}
            for item in model.opset_import
        ],
    }


def checkpoint_members(inputs: Inputs, contract_path: Path, checkpoint: str) -> dict[str, bytes]:
    profiles = inputs.preprocessing["artifact"]["checkpoints"][checkpoint]["profiles"]
    anomaly_record = inputs.anomaly["checkpoints"][checkpoint]
    flow_record = inputs.flow_rf["checkpoints"][checkpoint]
    known_record = inputs.known_family["checkpoints"][checkpoint]
    model_blobs = {
        "flow_rf": export_repeat_checked(
            flow_record["model"], len(profiles["supervised_known"]["selected_features"]), "flow_rf"
        ),
        "isolation_forest": export_repeat_checked(
            anomaly_record["isolation_forest"]["estimator"],
            len(profiles["anomaly_benign"]["selected_features"]),
            "isolation_forest",
        ),
        "known_family_rf": export_repeat_checked(
            known_record["model"],
            len(profiles["supervised_known"]["selected_features"]),
            "known_family_rf",
        ),
    }
    members = {
        "feature_schema.json": canonical_json(inputs.feature_schema),
        "preprocessing.json": canonical_json(
            {
                "schema_version": "1.0.0",
                "checkpoint": checkpoint,
                "input_features": inputs.preprocessing["artifact"]["input_features"],
                "profiles": profiles,
            }
        ),
        "hbos.json": canonical_json(
            {
                "schema_version": "1.0.0",
                "checkpoint": checkpoint,
                "state": anomaly_record["hbos"],
                "score_decision_contract": inputs.anomaly["score_decision_contract"],
            }
        ),
        "thresholds.json": canonical_json(
            {
                "schema_version": "1.0.0",
                "checkpoint": checkpoint,
                "flow_rf": {
                    "threshold": inputs.flow_rf["threshold"],
                    "status": "accepted T4.2 operating point",
                    "binary_rule": "attack_probability >= threshold",
                },
                "hbos": {
                    **anomaly_record["hbos"]["decision"],
                    "status": "provisional",
                    "final_threshold_task": "T6.1",
                },
                "isolation_forest": {
                    **anomaly_record["isolation_forest"]["decision"],
                    "status": "provisional",
                    "final_threshold_task": "T6.1",
                    "raw_anomaly_score_formula": "-score_samples",
                },
                "recalibration_performed": False,
            }
        ),
        **{MODEL_MEMBERS[name]: blob for name, blob in model_blobs.items()},
    }
    contract_hash = sha256_path(contract_path)
    payload_order = inputs.contract["archive"]["member_order"][:-1]
    manifest = {
        "schema_version": "1.0.0",
        "artifact_id": inputs.contract["artifact"]["id"],
        "artifact_version": inputs.contract["artifact"]["version"],
        "checkpoint": checkpoint,
        "feature_schema_id": inputs.feature_schema["schema_id"],
        "contract_sha256": contract_hash,
        "prerequisite_sha256": {
            name: record["sha256"] for name, record in inputs.contract["prerequisites"].items()
        },
        "members": [
            {"path": name, "size_bytes": len(members[name]), "sha256": sha256_bytes(members[name])}
            for name in payload_order
        ],
        "models": {
            "flow_rf": onnx_metadata(model_blobs["flow_rf"], [0, 1]),
            "isolation_forest": onnx_metadata(model_blobs["isolation_forest"], None),
            "known_family_rf": onnx_metadata(
                model_blobs["known_family_rf"], inputs.known_family["labels"]["class_order"]
            ),
        },
        "threshold_recalibration_performed": False,
        "python_cpp_numeric_parity": {"claimed": False, "deferred_to": "T5.3"},
    }
    members["manifest.json"] = canonical_json(manifest)
    return members


def archive_bytes(members: Mapping[str, bytes], contract: Mapping[str, Any]) -> bytes:
    output = io.BytesIO()
    archive = contract["archive"]
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=archive["compression_level"]
    ) as bundle:
        for name in archive["member_order"]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = archive["create_system"]
            info.external_attr = archive["external_attributes"]
            bundle.writestr(info, members[name], compresslevel=archive["compression_level"])
    return output.getvalue()


def validate_archive(blob: bytes, contract: Mapping[str, Any], checkpoint: str) -> dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(blob), "r") as bundle:
        infos = bundle.infolist()
        if [info.filename for info in infos] != contract["archive"]["member_order"]:
            raise ValueError(f"archive member order mismatch: {checkpoint}")
        if bundle.testzip() is not None:
            raise ValueError(f"archive CRC failure: {checkpoint}")
        for info in infos:
            if (
                info.date_time != (1980, 1, 1, 0, 0, 0)
                or info.compress_type != zipfile.ZIP_DEFLATED
                or info.create_system != contract["archive"]["create_system"]
                or info.external_attr != contract["archive"]["external_attributes"]
            ):
                raise ValueError(f"archive metadata mismatch: {checkpoint}/{info.filename}")
        values = {info.filename: bundle.read(info.filename) for info in infos}
    for name in JSON_MEMBERS:
        if canonical_json(json.loads(values[name].decode("utf-8"))) != values[name]:
            raise ValueError(f"non-canonical JSON member: {checkpoint}/{name}")
    for name in MODEL_MEMBERS.values():
        onnx.checker.check_model(onnx.load_model_from_string(values[name]))
    manifest = json.loads(values["manifest.json"])
    expected_records = [
        {"path": name, "size_bytes": len(values[name]), "sha256": sha256_bytes(values[name])}
        for name in contract["archive"]["member_order"][:-1]
    ]
    if (
        manifest.get("checkpoint") != checkpoint
        or manifest.get("artifact_id") != contract["artifact"]["id"]
        or manifest.get("members") != expected_records
        or set(manifest.get("models", {})) != set(MODEL_MEMBERS)
        or any("stacker" in name.lower() for name in values)
    ):
        raise ValueError(f"archive manifest mismatch: {checkpoint}")
    return manifest


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    inputs = verify_inputs(root, contract_path)
    outputs = {
        checkpoint: resolve_inside(root, path)
        for checkpoint, path in inputs.contract["artifact"]["outputs"].items()
    }
    acceptance_path = resolve_inside(root, inputs.contract["artifact"]["acceptance"])
    if acceptance_path.exists() or any(path.exists() for path in outputs.values()):
        raise FileExistsError("T5.1 artifact already exists; refusing to overwrite evidence")
    temporary: dict[str, Path] = {}
    records: dict[str, Any] = {}
    try:
        for checkpoint, output_path in outputs.items():
            members = checkpoint_members(inputs, contract_path, checkpoint)
            first = archive_bytes(members, inputs.contract)
            second = archive_bytes(members, inputs.contract)
            if first != second:
                raise ValueError(f"nondeterministic archive build: {checkpoint}")
            manifest = validate_archive(first, inputs.contract, checkpoint)
            temp = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex}.tmp")
            write_bytes(temp, first)
            temporary[checkpoint] = temp
            records[checkpoint] = {
                "path": relative(output_path, root),
                "size_bytes": len(first),
                "sha256": sha256_bytes(first),
                "manifest_sha256": sha256_bytes(canonical_json(manifest)),
            }
        source_paths = [
            contract_path,
            root / "python/nids_mvp/artifact_bundle.py",
            root / "tests/test_t51_artifact_bundle.py",
            root / "run_log/t5.1/dependency-receipt.json",
        ]
        receipt = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "native_inference_artifact_bundle_acceptance",
            "status": "passed",
            "generated_at_utc": utc_now(),
            "contract": {"path": relative(contract_path, root), "sha256": sha256_path(contract_path)},
            "source_files": {relative(path, root): sha256_path(path) for path in source_paths},
            "artifacts": records,
            "validation": inputs.contract["acceptance"],
            "gate": {"decision": "pending_user_decision", "t5_2_authorized": False},
        }
        acceptance_temp = acceptance_path.with_name(
            f".{acceptance_path.name}.{uuid.uuid4().hex}.tmp"
        )
        write_bytes(acceptance_temp, canonical_json(receipt))
        for checkpoint, output_path in outputs.items():
            os.replace(temporary.pop(checkpoint), output_path)
        os.replace(acceptance_temp, acceptance_path)
        return receipt
    finally:
        for path in temporary.values():
            path.unlink(missing_ok=True)


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    inputs = verify_inputs(root, contract_path)
    receipt = load_json(receipt_path)
    if (
        receipt.get("task") != TASK
        or receipt.get("status") != "passed"
        or receipt.get("contract", {}).get("sha256") != sha256_path(contract_path)
    ):
        raise ValueError("invalid T5.1 acceptance receipt")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T5.1 source hash mismatch: {value}")
    for checkpoint, output in inputs.contract["artifact"]["outputs"].items():
        record = receipt.get("artifacts", {}).get(checkpoint, {})
        path = resolve_inside(root, output)
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
        ):
            raise ValueError(f"T5.1 bundle content mismatch: {checkpoint}")
        validate_archive(path.read_bytes(), inputs.contract, checkpoint)
    if receipt.get("gate") != {"decision": "pending_user_decision", "t5_2_authorized": False}:
        raise ValueError("T5.1 gate mismatch")


def check_exporter(inputs: Inputs) -> None:
    checkpoint = inputs.contract["artifact"]["checkpoints"][0]
    profile = inputs.preprocessing["artifact"]["checkpoints"][checkpoint]["profiles"]
    probes = (
        (
            inputs.flow_rf["checkpoints"][checkpoint]["model"],
            len(profile["supervised_known"]["selected_features"]),
            "flow_rf",
        ),
        (
            inputs.anomaly["checkpoints"][checkpoint]["isolation_forest"]["estimator"],
            len(profile["anomaly_benign"]["selected_features"]),
            "isolation_forest",
        ),
        (
            inputs.known_family["checkpoints"][checkpoint]["model"],
            len(profile["supervised_known"]["selected_features"]),
            "known_family_rf",
        ),
    )
    for estimator, feature_count, model_name in probes:
        convert_estimator(estimator, feature_count, model_name)


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Build and validate T5.1 native inference bundles")
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract",
        type=Path,
        default=root_default / "config/cicids2017-artifact-bundle-contract.json",
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            inputs = verify_inputs(root, contract_path)
            check_exporter(inputs)
            print("[T5.1 check] status=passed checkpoints=4 converter_probe=F3", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(f"[T5.1 run] status=passed bundles={len(receipt['artifacts'])}", flush=True)
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T5.1 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
