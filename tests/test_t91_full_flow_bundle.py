from __future__ import annotations

import json
import shutil
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import joblib
import numpy as np
import onnx
from lightgbm import LGBMClassifier
from onnx import TensorProto, helper, numpy_helper
from onnxmltools import convert_lightgbm

from nids_mvp import full_flow_bundle as bundle
from nids_mvp import full_flow_dataset as dataset
from nids_mvp import full_flow_model as model


@contextmanager
def temporary_root():
    path = Path(__file__).resolve().parents[1] / (
        f".t91-full-flow-bundle-test-{uuid.uuid4().hex}"
    )
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def archive_with_json_value(
    validation: bundle.ArchiveValidation,
    member: str,
    path: tuple[str | int, ...],
    value: object,
) -> bytes:
    members = dict(validation.members)
    documents = {
        name: json.loads(members[name]) for name in bundle.JSON_MEMBERS
    }
    target = documents[member]
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    if member != "manifest.json":
        members[member] = bundle.canonical_json(documents[member])
    manifest = documents["manifest.json"]
    manifest["members"] = [
        bundle.member_record(name, members[name])
        for name in bundle.MEMBER_ORDER[:-1]
    ]
    members["manifest.json"] = bundle.canonical_json(manifest)
    return bundle.archive_bytes(members)


def estimator_fixture() -> tuple[LGBMClassifier, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(3607)
    labels = np.repeat(np.arange(len(model.CLASS_ORDER), dtype=np.uint8), 18)
    matrix = rng.normal(0.0, 0.03, size=(len(labels), 54)).astype(np.float32)
    for index in range(len(model.CLASS_ORDER)):
        rows = labels == index
        matrix[rows, index] += 8.0
        matrix[rows, 6] = float(index)
    feature_names = [f"feature_{index:02d}" for index in range(54)]
    estimator = LGBMClassifier(
        objective="multiclass",
        num_class=len(model.CLASS_ORDER),
        n_estimators=12,
        learning_rate=0.2,
        num_leaves=15,
        min_child_samples=1,
        min_data_in_bin=1,
        random_state=3607,
        n_jobs=1,
        deterministic=True,
        force_col_wise=True,
        verbosity=-1,
    )
    estimator.fit(matrix, labels, feature_name=feature_names)
    estimator._classes = np.arange(len(model.CLASS_ORDER), dtype=np.uint8)
    return estimator, matrix, labels


def create_inputs(root: Path) -> tuple[bundle.BundleInputs, LGBMClassifier]:
    model_root = root / "model"
    schema_path = root / "config/terminal-flow-feature-schema-v1.json"
    model_path = model_root / "selected-model.joblib"
    predictions_path = model_root / "validation-predictions.npz"
    manifest_path = model_root / "manifest.json"
    feature_names = [f"feature_{index:02d}" for index in range(70)]
    schema = {
        "schema_id": dataset.FEATURE_SCHEMA_ID,
        "schema_version": "1.0.0",
        "feature_vector": {
            "length": 70,
            "encoded_type": "float64",
            "finite_only": True,
        },
        "feature_profiles": [
            {
                "id": profile,
                "name": f"profile_{profile}",
                "start_index": 0,
                "end_index": length - 1,
                "length": length,
            }
            for profile, length in model.PROFILE_LENGTHS.items()
        ],
        "features": [
            {"index": index, "name": name, "logical_type": "float64"}
            for index, name in enumerate(feature_names)
        ],
    }
    write_json(schema_path, schema)
    estimator, matrix, labels = estimator_fixture()
    threshold = 0.5
    selected = {
        "schema_version": "1.0.0",
        "task": bundle.TASK,
        "kind": "terminal_flow_lightgbm_candidate",
        "profile_id": "A",
        "feature_names": feature_names[:54],
        "class_order": list(model.CLASS_ORDER),
        "threshold": threshold,
        "preprocessing": {
            "operation": bundle.PREPROCESSING["operation"],
            "imputation": None,
            "scaler": None,
            "categorical_encoding": None,
        },
        "parameters": {},
        "model": estimator,
    }
    model_root.mkdir(parents=True)
    joblib.dump(selected, model_path, compress=3)
    probability = np.asarray(estimator.booster_.predict(matrix[:6]), dtype=np.float64)
    prediction_values = {
        "validation_capture_id": np.asarray(["fixture"] * 6, dtype="<U64"),
        "validation_flow_id": np.arange(1, 7, dtype=np.uint64),
        "y_true": labels[:6],
        **{
            f"profile_{profile}_probability": probability
            for profile in model.PROFILE_LENGTHS
        },
    }
    np.savez_compressed(predictions_path, **prediction_values)
    model_record = {
        "path": model_path.relative_to(root).as_posix(),
        "size_bytes": model_path.stat().st_size,
        "sha256": bundle.sha256_path(model_path),
    }
    prediction_record = {
        "path": predictions_path.relative_to(root).as_posix(),
        "size_bytes": predictions_path.stat().st_size,
        "sha256": bundle.sha256_path(predictions_path),
    }
    schema_hash = bundle.sha256_path(schema_path)
    manifest = {
        "schema_version": "1.0.0",
        "task": bundle.TASK,
        "kind": "terminal_flow_validation_selection",
        "status": "locked",
        "scope": "demo_critical_path",
        "labels": {
            "class_order": list(model.CLASS_ORDER),
            "benign_index": 0,
        },
        "preprocessing": dict(bundle.PREPROCESSING),
        "selection": {
            "selected_profile": "A",
            "selected_feature_count": 54,
            "selected_feature_indices": list(range(54)),
            "selected_threshold": threshold,
        },
        "profiles": [
            {
                "profile_id": "A",
                "feature_count": 54,
                "feature_names": feature_names[:54],
            }
        ],
        "inputs": {
            "feature_schema": {
                "path": schema_path.relative_to(root).as_posix(),
                "schema_id": dataset.FEATURE_SCHEMA_ID,
                "sha256": schema_hash,
            },
            "allowed_parts": [
                {
                    "path": (
                        "dataset/capture_id=fixture/assigned/"
                        "partition=validation/part-00000.parquet"
                    ),
                    "partition": "validation",
                    "rows": 6,
                    "size_bytes": 1,
                    "sha256": "0" * 64,
                }
            ],
        },
        "population": {"validation_rows": 6},
        "artifacts": {
            "selected_model": model_record,
            "validation_predictions": prediction_record,
        },
        "test_partition": dict(bundle.SEALED_TEST_RECORD),
    }
    write_json(manifest_path, manifest)
    return (
        bundle.BundleInputs(
            root=root,
            model_manifest_path=manifest_path,
            feature_schema_path=schema_path,
            selected_model_path=model_path,
            validation_predictions_path=predictions_path,
            bundle_path=model_root / "terminal-flow.bundle.zip",
            staging_path=model_root / "terminal-flow.bundle",
            enforce_runtime=False,
        ),
        estimator,
    )


def label_shape_fixture() -> onnx.ModelProto:
    model_input = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, 54])
    label = helper.make_tensor_value_info("label", TensorProto.INT64, [1])
    probabilities = helper.make_tensor_value_info(
        "probabilities", TensorProto.FLOAT, [None, len(model.CLASS_ORDER)]
    )
    value = numpy_helper.from_array(np.asarray([0], dtype=np.int64), name="constant")
    graph = helper.make_graph(
        [helper.make_node("Constant", [], ["label"], value=value)],
        bundle.GRAPH_NAME,
        [model_input],
        [label, probabilities],
    )
    return helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])


class FullFlowBundleTests(unittest.TestCase):
    def test_canonical_json_is_stable_and_rejects_non_finite(self) -> None:
        self.assertEqual(bundle.canonical_json({"z": 2, "a": 1}), b'{"a":1,"z":2}\n')
        with self.assertRaisesRegex(ValueError, "Out of range float"):
            bundle.canonical_json({"bad": float("nan")})

    def test_label_shape_repair_changes_only_metadata(self) -> None:
        onnx_model = label_shape_fixture()
        nodes = bundle.serialized_nodes(onnx_model)
        initializers = bundle.serialized_initializers(onnx_model)

        bundle.repair_label_batch_shape(onnx_model)

        label = {value.name: value for value in onnx_model.graph.output}["label"]
        self.assertEqual(bundle.tensor_shape(label), [-1])
        self.assertEqual(bundle.serialized_nodes(onnx_model), nodes)
        self.assertEqual(bundle.serialized_initializers(onnx_model), initializers)

    def test_uint8_classes_are_normalized_only_on_conversion_copy(self) -> None:
        estimator, _, _ = estimator_fixture()
        original_classes = estimator.classes_.copy()
        original_booster = estimator.booster_.model_to_string()
        with mock.patch.object(
            bundle, "convert_lightgbm", wraps=convert_lightgbm
        ) as converter:
            blob = bundle.convert_estimator(estimator, 54)

        converted_estimator = converter.call_args.args[0]
        self.assertEqual(converted_estimator.classes_.dtype, np.dtype(np.int64))
        self.assertEqual(converter.call_args.kwargs["target_opset"], 15)
        self.assertFalse(converter.call_args.kwargs["zipmap"])
        self.assertEqual(estimator.classes_.dtype, np.dtype(np.uint8))
        self.assertTrue(np.array_equal(estimator.classes_, original_classes))
        self.assertEqual(estimator.booster_.model_to_string(), original_booster)
        self.assertEqual(bundle.onnx_metadata(blob)["opset_imports"], bundle.EXPECTED_OPSETS)

    def test_repeat_export_is_byte_identical(self) -> None:
        estimator, _, _ = estimator_fixture()
        first = bundle.export_repeat_checked(estimator, 54)
        second = bundle.export_repeat_checked(estimator, 54)
        self.assertEqual(first, second)
        metadata = bundle.onnx_metadata(first)
        self.assertEqual(metadata["graph_name"], bundle.GRAPH_NAME)
        self.assertEqual(metadata["input"]["shape"], [-1, 54])
        self.assertEqual(metadata["outputs"][0]["shape"], [-1])
        self.assertEqual(metadata["outputs"][1]["shape"], [-1, 6])

    def test_publish_is_deterministic_resumable_and_stages_exact_members(self) -> None:
        with temporary_root() as root:
            inputs, _ = create_inputs(root)
            first, skipped = bundle.publish(inputs)
            self.assertFalse(skipped)
            bundle.validate_staging(inputs.staging_path, first)
            self.assertEqual(
                {
                    path.relative_to(inputs.staging_path).as_posix()
                    for path in inputs.staging_path.rglob("*")
                    if path.is_file()
                },
                set(bundle.MEMBER_ORDER),
            )
            archive_bytes = inputs.bundle_path.read_bytes()
            manifest = first.manifest
            preprocessing = json.loads(first.members["preprocessing.json"])
            thresholds = json.loads(first.members["thresholds.json"])
            all_feature_names = [f"feature_{index:02d}" for index in range(70)]
            self.assertEqual(manifest["artifact_id"], "nids.terminal_flow_bundle.v1")
            self.assertEqual(manifest["artifact_version"], "1.0.0")
            self.assertEqual(preprocessing["input"]["feature_count"], 70)
            self.assertEqual(preprocessing["input"]["feature_names"], all_feature_names)
            self.assertTrue(preprocessing["input"]["finite_required"])
            self.assertEqual(preprocessing["input"]["dtype"], "float64")
            self.assertEqual(preprocessing["selection"]["profile_kind"], "prefix")
            self.assertEqual(preprocessing["selection"]["feature_count"], 54)
            self.assertEqual(
                preprocessing["selection"]["feature_indices"], list(range(54))
            )
            self.assertEqual(
                preprocessing["selection"]["feature_names"], all_feature_names[:54]
            )
            self.assertEqual(preprocessing["output"]["dtype"], "float32")
            self.assertEqual(
                [step["operation"] for step in preprocessing["steps"]],
                ["require_finite", "select_indices", "cast", "require_finite"],
            )
            self.assertEqual(
                thresholds["decision"]["attack_score"]["formula"],
                "1.0 - probabilities[0]",
            )
            self.assertEqual(thresholds["decision"]["gate"]["comparator"], ">=")
            self.assertEqual(thresholds["decision"]["benign_class_index"], 0)
            self.assertEqual(
                thresholds["decision"]["attack_class"]["indices"],
                [1, 2, 3, 4, 5],
            )
            self.assertEqual(
                manifest["parity"]["python_cpp_numeric_parity"],
                {
                    "claimed": False,
                    "deferred_to": "phase7",
                    "required_before_live": True,
                },
            )

            second, skipped = bundle.publish(inputs)

            self.assertTrue(skipped)
            self.assertEqual(second.archive_sha256, first.archive_sha256)
            self.assertEqual(inputs.bundle_path.read_bytes(), archive_bytes)
            self.assertEqual(
                bundle.sha256_path(inputs.staging_path / "manifest.json"),
                first.manifest_sha256,
            )

    def test_archive_validator_rejects_semantic_contract_drift(self) -> None:
        with temporary_root() as root:
            inputs, _ = create_inputs(root)
            validation, _ = bundle.publish(inputs)
            mutations = (
                ("feature_schema.json", ("feature_vector", "length"), 69),
                ("feature_schema.json", ("features", 0, "index"), 1),
                ("preprocessing.json", ("output", "dtype"), "float64"),
                ("manifest.json", ("selected_feature_count",), 53),
                ("thresholds.json", ("decision", "gate", "comparator"), ">"),
                ("thresholds.json", ("class_order",), list(reversed(model.CLASS_ORDER))),
                ("manifest.json", ("artifact_id",), "wrong"),
                ("manifest.json", ("artifact_version",), "wrong"),
            )
            for member, path, value in mutations:
                with self.subTest(member=member, path=path):
                    tampered = archive_with_json_value(
                        validation, member, path, value
                    )
                    with self.assertRaises(ValueError):
                        bundle.validate_archive(tampered)

    def test_staging_tamper_and_manifest_trust_hash_are_rejected(self) -> None:
        with temporary_root() as root:
            inputs, _ = create_inputs(root)
            validation, _ = bundle.publish(inputs)
            with self.assertRaisesRegex(ValueError, "trust hash"):
                bundle.validate_archive(
                    inputs.bundle_path.read_bytes(), expected_manifest_sha256="0" * 64
                )
            unexpected_directory = inputs.staging_path / "unexpected"
            unexpected_directory.mkdir()
            with self.assertRaisesRegex(ValueError, "directory inventory"):
                bundle.validate_staging(inputs.staging_path, validation)
            unexpected_directory.rmdir()
            staged_model = inputs.staging_path.joinpath(*bundle.MODEL_MEMBER.split("/"))
            staged_model.write_bytes(staged_model.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "differs from archive"):
                bundle.validate_staging(inputs.staging_path, validation)


if __name__ == "__main__":
    unittest.main()
