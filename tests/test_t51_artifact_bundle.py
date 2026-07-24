from __future__ import annotations

import io
import json
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

from nids_mvp import artifact_bundle


def classifier_model(class_count: int = 2) -> onnx.ModelProto:
    model_input = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, class_count])
    label = helper.make_tensor_value_info("label", TensorProto.INT64, [None])
    probabilities = helper.make_tensor_value_info(
        "probabilities", TensorProto.FLOAT, [None, class_count]
    )
    label_value = numpy_helper.from_array(np.asarray([0], dtype=np.int64), name="label_value")
    graph = helper.make_graph(
        [
            helper.make_node("Constant", [], ["label"], value=label_value),
            helper.make_node("Identity", ["input"], ["probabilities"]),
        ],
        "classifier",
        [model_input],
        [label, probabilities],
    )
    return helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])


def isolation_forest_model(missing_score_samples_shape: bool = False) -> onnx.ModelProto:
    model_input = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, 1])
    label = helper.make_tensor_value_info("label", TensorProto.INT64, [None, 1])
    scores = helper.make_tensor_value_info("scores", TensorProto.FLOAT, [None, 1])
    score_shape = None if missing_score_samples_shape else [None, 1]
    score_samples = helper.make_tensor_value_info(
        "score_samples", TensorProto.FLOAT, score_shape
    )
    label_value = numpy_helper.from_array(np.asarray([[1]], dtype=np.int64), name="label_value")
    graph = helper.make_graph(
        [
            helper.make_node("Constant", [], ["label"], value=label_value),
            helper.make_node("Identity", ["input"], ["scores"]),
            helper.make_node("Identity", ["input"], ["score_samples"]),
        ],
        "isolation_forest",
        [model_input],
        [label, scores, score_samples],
    )
    return helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])


def archive_contract() -> dict:
    return {
        "artifact": {"id": "test.bundle"},
        "archive": {
            "member_order": [
                "feature_schema.json",
                "preprocessing.json",
                "hbos.json",
                "thresholds.json",
                "models/flow_rf.onnx",
                "models/isolation_forest.onnx",
                "models/known_family_rf.onnx",
                "manifest.json",
            ],
            "compression_level": 9,
            "create_system": 0,
            "external_attributes": 25165824,
        },
    }


def archive_members(contract: dict) -> dict[str, bytes]:
    classifier = classifier_model().SerializeToString(deterministic=True)
    isolation = isolation_forest_model().SerializeToString(deterministic=True)
    members = {
        "feature_schema.json": artifact_bundle.canonical_json({"features": []}),
        "preprocessing.json": artifact_bundle.canonical_json({"profiles": {}}),
        "hbos.json": artifact_bundle.canonical_json({"state": {}}),
        "thresholds.json": artifact_bundle.canonical_json({"recalibration_performed": False}),
        "models/flow_rf.onnx": classifier,
        "models/isolation_forest.onnx": isolation,
        "models/known_family_rf.onnx": classifier,
    }
    manifest = {
        "artifact_id": contract["artifact"]["id"],
        "checkpoint": "F3",
        "members": [
            {
                "path": name,
                "size_bytes": len(members[name]),
                "sha256": artifact_bundle.sha256_bytes(members[name]),
            }
            for name in contract["archive"]["member_order"][:-1]
        ],
        "models": {
            "flow_rf": {},
            "isolation_forest": {},
            "known_family_rf": {},
        },
    }
    members["manifest.json"] = artifact_bundle.canonical_json(manifest)
    return members


class ArtifactBundleTests(unittest.TestCase):
    def test_canonical_json_normalizes_numpy_and_rejects_non_finite(self) -> None:
        value = {"z": np.asarray([2, 1], dtype=np.int64), "a": np.float64(0.25)}
        self.assertEqual(artifact_bundle.canonical_json(value), b'{"a":0.25,"z":[2,1]}\n')
        with self.assertRaisesRegex(ValueError, "Out of range float"):
            artifact_bundle.canonical_json({"bad": float("nan")})

    def test_iforest_shape_repair_changes_only_output_metadata(self) -> None:
        model = isolation_forest_model(missing_score_samples_shape=True)
        nodes = [node.SerializeToString(deterministic=True) for node in model.graph.node]
        initializers = [
            value.SerializeToString(deterministic=True) for value in model.graph.initializer
        ]
        artifact_bundle.repair_iforest_score_samples_shape(model)
        output = {value.name: value for value in model.graph.output}["score_samples"]
        self.assertEqual(artifact_bundle.tensor_shape(output), ["N", 1])
        self.assertEqual(
            nodes, [node.SerializeToString(deterministic=True) for node in model.graph.node]
        )
        self.assertEqual(
            initializers,
            [value.SerializeToString(deterministic=True) for value in model.graph.initializer],
        )
        onnx.checker.check_model(model)

    def test_convert_estimator_locks_options_opsets_and_output_shape(self) -> None:
        estimator = mock.Mock()
        estimator.n_jobs = -1
        converted = isolation_forest_model(missing_score_samples_shape=True)
        observed_n_jobs = []

        def convert(*args, **kwargs):
            observed_n_jobs.append(args[0].n_jobs)
            return converted

        with mock.patch.object(
            artifact_bundle, "convert_sklearn", side_effect=convert
        ) as converter:
            blob = artifact_bundle.convert_estimator(estimator, 7, "isolation_forest")
        call = converter.call_args
        self.assertEqual(observed_n_jobs, [1])
        self.assertEqual(estimator.n_jobs, -1)
        self.assertEqual(call.kwargs["options"], {id(estimator): {"score_samples": True}})
        self.assertEqual(call.kwargs["target_opset"], {"": 15, "ai.onnx.ml": 2})
        self.assertEqual(call.kwargs["initial_types"][0][0], "input")
        model = onnx.load_model_from_string(blob)
        self.assertEqual(model.graph.name, "nids_t51_isolation_forest")
        self.assertEqual(
            artifact_bundle.tensor_shape(
                {value.name: value for value in model.graph.output}["score_samples"]
            ),
            ["N", 1],
        )

    def test_random_converter_graph_names_are_canonicalized(self) -> None:
        first = classifier_model()
        first.graph.name = "15b73f90f7e341089b347a4ad82477fd"
        second = classifier_model()
        second.graph.name = "497548d583ab4207bd085c4371e0195a"
        estimator = mock.Mock()
        estimator.n_jobs = -1
        with mock.patch.object(
            artifact_bundle, "convert_sklearn", side_effect=[first, second]
        ):
            blob = artifact_bundle.export_repeat_checked(estimator, 2, "flow_rf")
        model = onnx.load_model_from_string(blob)
        self.assertEqual(model.graph.name, "nids_t51_flow_rf")

    def test_repeat_checked_export_rejects_nondeterminism(self) -> None:
        with mock.patch.object(
            artifact_bundle, "convert_estimator", side_effect=[b"first", b"second"]
        ):
            with self.assertRaisesRegex(ValueError, "nondeterministic ONNX export"):
                artifact_bundle.export_repeat_checked(object(), 1, "flow_rf")

    def test_archive_is_byte_deterministic_and_validated(self) -> None:
        contract = archive_contract()
        members = archive_members(contract)
        first = artifact_bundle.archive_bytes(members, contract)
        second = artifact_bundle.archive_bytes(members, contract)
        self.assertEqual(first, second)
        manifest = artifact_bundle.validate_archive(first, contract, "F3")
        self.assertEqual(manifest["checkpoint"], "F3")
        with zipfile.ZipFile(io.BytesIO(first)) as bundle:
            self.assertEqual(
                [value.filename for value in bundle.infolist()],
                contract["archive"]["member_order"],
            )

    def test_archive_rejects_noncanonical_json(self) -> None:
        contract = archive_contract()
        members = archive_members(contract)
        members["thresholds.json"] = b'{ "recalibration_performed": false }\n'
        manifest = json.loads(members["manifest.json"])
        for record in manifest["members"]:
            if record["path"] == "thresholds.json":
                record["size_bytes"] = len(members["thresholds.json"])
                record["sha256"] = artifact_bundle.sha256_bytes(members["thresholds.json"])
        members["manifest.json"] = artifact_bundle.canonical_json(manifest)
        blob = artifact_bundle.archive_bytes(members, contract)
        with self.assertRaisesRegex(ValueError, "non-canonical JSON member"):
            artifact_bundle.validate_archive(blob, contract, "F3")

    def test_resolve_inside_rejects_escape(self) -> None:
        root = Path.cwd().resolve()
        with self.assertRaisesRegex(ValueError, "path escapes project root"):
            artifact_bundle.resolve_inside(root, str(root.parent / "outside.json"))

    def test_workspace_contract_locks_approved_scope(self) -> None:
        root = Path(__file__).resolve().parents[1]
        contract = artifact_bundle.load_json(
            root / "config/cicids2017-artifact-bundle-contract.json"
        )
        self.assertEqual(
            contract["design_approval"]["production_models"],
            ["flow_rf", "known_family_rf", "hbos", "isolation_forest"],
        )
        self.assertEqual(
            contract["design_approval"]["excluded_from_production_bundle"],
            {"rf_stacker": "retained as T4.5 ablation only"},
        )
        self.assertFalse(contract["thresholds"]["recalibration_allowed"])
        self.assertEqual(contract["acceptance"]["python_cpp_numeric_parity_deferred_to"], "T5.3")


if __name__ == "__main__":
    unittest.main()
