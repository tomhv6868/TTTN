from __future__ import annotations

import json
import unittest
from unittest import mock

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

import test_t91_full_flow_bundle as bundle_fixture
from nids_mvp import full_flow_bundle as bundle
from nids_mvp import full_flow_dataset as dataset
from nids_mvp import full_flow_model as model
from nids_mvp import full_flow_parity as parity


def metadata_values(labels: np.ndarray) -> dict[str, list | np.ndarray]:
    rows = len(labels)
    families = [model.CLASS_ORDER[int(index)] for index in labels]
    return {
        "flow_id": np.arange(1, rows + 1, dtype=np.uint64),
        "capture_id": ["fixture"] * rows,
        "export_ordinal": np.arange(1, rows + 1, dtype=np.uint64),
        "flow_generation": np.ones(rows, dtype=np.uint64),
        "protocol": np.full(rows, 6, dtype=np.uint8),
        "low_ip": np.full(rows, 0x0A000001, dtype=np.uint32),
        "low_port": np.full(rows, 12345, dtype=np.uint16),
        "high_ip": np.full(rows, 0x0A000002, dtype=np.uint32),
        "high_port": np.full(rows, 80, dtype=np.uint16),
        "forward_source_ip": np.full(rows, 0x0A000001, dtype=np.uint32),
        "forward_source_port": np.full(rows, 12345, dtype=np.uint16),
        "clock_domain": ["unix_epoch"] * rows,
        "creation_timestamp_ns": np.arange(rows, dtype=np.int64),
        "last_capture_timestamp_ns": np.arange(rows, dtype=np.int64) + 1,
        "last_event_timestamp_ns": np.arange(rows, dtype=np.int64) + 1,
        "packet_count": np.full(rows, 2, dtype=np.uint64),
        "forward_packet_count": np.ones(rows, dtype=np.uint64),
        "reverse_packet_count": np.ones(rows, dtype=np.uint64),
        "paired_f9": np.zeros(rows, dtype=np.bool_),
        "close_reason": ["tcp_reset"] * rows,
        "label_status": ["assigned"] * rows,
        "assigned_class": families,
        "label_family": families,
        "label_binary": labels != 0,
        "assignment_method": ["fixture"] * rows,
        "quarantine_reason": [None] * rows,
        "partition": ["validation"] * rows,
    }


def write_validation_parquet(
    path, feature_names: list[str], matrix: np.ndarray, labels: np.ndarray
) -> None:
    values = metadata_values(labels)
    fields = [
        pa.field(name, arrow_type, nullable=nullable)
        for name, arrow_type, nullable in dataset.METADATA_FIELDS
    ]
    arrays = [
        pa.array(values[name], type=arrow_type)
        for name, arrow_type, _ in dataset.METADATA_FIELDS
    ]
    for index, name in enumerate(feature_names):
        fields.append(pa.field(name, pa.float64(), nullable=False))
        arrays.append(pa.array(matrix[:, index], type=pa.float64()))
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.Table.from_arrays(arrays, schema=pa.schema(fields)),
        path,
        compression="zstd",
        use_dictionary=False,
        write_statistics=True,
    )


def create_parity_inputs(root):
    bundle_inputs, estimator = bundle_fixture.create_inputs(root)
    _, selected_matrix, labels = bundle_fixture.estimator_fixture()
    matrix = np.zeros((len(labels), 70), dtype=np.float64)
    matrix[:, :54] = selected_matrix.astype(np.float64)
    feature_names = [f"feature_{index:02d}" for index in range(70)]
    part_path = (
        root
        / "dataset/capture_id=fixture/assigned/partition=validation/part-00000.parquet"
    )
    write_validation_parquet(part_path, feature_names, matrix, labels)
    probabilities = parity.python_probabilities(
        estimator, selected_matrix.astype(np.float32, copy=False)
    )
    decisions = parity.final_decisions(probabilities, 0.5)
    if set(decisions.tolist()) != set(range(len(model.CLASS_ORDER))):
        raise AssertionError("fixture model does not cover every final class")
    prediction_values = {
        "validation_capture_id": np.asarray(["fixture"] * len(labels), dtype="<U64"),
        "validation_flow_id": np.arange(1, len(labels) + 1, dtype=np.uint64),
        "y_true": labels,
        **{
            f"profile_{profile}_probability": probabilities
            for profile in model.PROFILE_LENGTHS
        },
    }
    np.savez_compressed(bundle_inputs.validation_predictions_path, **prediction_values)
    manifest = bundle.load_json(bundle_inputs.model_manifest_path)
    relative_part = part_path.relative_to(root).as_posix()
    manifest["inputs"]["allowed_parts"] = [
        {
            "path": relative_part,
            "partition": "validation",
            "rows": len(labels),
            "size_bytes": part_path.stat().st_size,
            "sha256": bundle.sha256_path(part_path),
        }
    ]
    manifest["population"]["validation_rows"] = len(labels)
    predictions = manifest["artifacts"]["validation_predictions"]
    predictions["size_bytes"] = bundle_inputs.validation_predictions_path.stat().st_size
    predictions["sha256"] = bundle.sha256_path(
        bundle_inputs.validation_predictions_path
    )
    bundle_fixture.write_json(bundle_inputs.model_manifest_path, manifest)
    bundle.publish(bundle_inputs)
    return parity.ParityInputs(
        root=root,
        bundle_inputs=bundle_inputs,
        evidence_path=bundle_inputs.bundle_path.parent / "onnx-parity.json",
        native_reference_path=(
            bundle_inputs.bundle_path.parent / "native-parity-reference.json"
        ),
    )


class FullFlowParityTests(unittest.TestCase):
    def test_final_decision_uses_threshold_then_attack_argmax(self) -> None:
        probability = np.asarray(
            [
                [0.8, 0.01, 0.01, 0.02, 0.15, 0.01],
                [0.4, 0.1, 0.2, 0.05, 0.15, 0.1],
                [0.5, 0.1, 0.1, 0.25, 0.025, 0.025],
            ],
            dtype=np.float64,
        )
        self.assertEqual(
            parity.final_decisions(probability, 0.5).tolist(),
            [0, 2, 3],
        )

    def test_full_validation_python_ort_parity_and_native_reference(self) -> None:
        with bundle_fixture.temporary_root() as root:
            inputs = create_parity_inputs(root)
            original_resolve = bundle.resolve_inside

            def reject_test_path(project_root, value):
                self.assertNotIn("partition=test", str(value))
                return original_resolve(project_root, value)

            with mock.patch.object(
                bundle, "resolve_inside", side_effect=reject_test_path
            ):
                evidence, reference = parity.run_parity(inputs)

            self.assertEqual(evidence["status"], "python_ort_passed_native_pending")
            self.assertEqual(evidence["validation"]["rows"], 108)
            self.assertLessEqual(
                evidence["validation"]["maximum_absolute_probability_error"],
                parity.ABSOLUTE_TOLERANCE,
            )
            self.assertTrue(evidence["validation"]["model_labels_exact"])
            self.assertTrue(
                evidence["validation"]["thresholded_final_decisions_exact"]
            )
            self.assertEqual(reference["status"], "python_ort_passed_native_pending")
            self.assertEqual(
                reference["input_encoding"],
                {
                    "numeric_dtype": "float32",
                    "bit_pattern_dtype": "uint32",
                    "bit_pattern_format": "IEEE 754 binary32",
                },
            )
            self.assertEqual(len(reference["cases"]), 14)
            for case in reference["cases"]:
                values = np.asarray(case["input"], dtype="<f4")
                expected_bits = [int(value) for value in values.view("<u4")]
                self.assertEqual(len(expected_bits), 54)
                self.assertEqual(
                    case["input_float32_uint32_bits"], expected_bits
                )
            self.assertEqual(
                {case["case_id"] for case in reference["cases"][-2:]},
                {"threshold-below", "threshold-above"},
            )
            self.assertEqual(evidence["test_partition"], bundle.SEALED_TEST_RECORD)

    def test_publish_is_canonical_resumable_and_keeps_native_pending(self) -> None:
        with bundle_fixture.temporary_root() as root:
            inputs = create_parity_inputs(root)
            first, skipped = parity.publish(inputs)
            self.assertFalse(skipped)
            self.assertEqual(first["native_parity"]["status"], "pending")
            self.assertEqual(
                bundle.canonical_json(json.loads(inputs.evidence_path.read_text("utf-8"))),
                inputs.evidence_path.read_bytes(),
            )

            second, skipped = parity.publish(inputs)

            self.assertTrue(skipped)
            self.assertEqual(second, first)
            self.assertEqual(parity.validate_outputs(inputs), first)

    def test_validation_part_hash_drift_is_fatal(self) -> None:
        with bundle_fixture.temporary_root() as root:
            inputs = create_parity_inputs(root)
            verified = bundle.verify_inputs(inputs.bundle_inputs)
            record = dict(verified.validation_parts[0])
            record["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "invalid terminal validation part"):
                parity.validation_part(verified, record)

    def test_evidence_cannot_claim_native_passed(self) -> None:
        with bundle_fixture.temporary_root() as root:
            inputs = create_parity_inputs(root)
            parity.publish(inputs)
            evidence = json.loads(inputs.evidence_path.read_text("utf-8"))
            evidence["status"] = "passed"
            inputs.evidence_path.write_bytes(bundle.canonical_json(evidence))
            with self.assertRaisesRegex(ValueError, "evidence contract"):
                parity.validate_outputs(inputs)

    def test_canonical_evidence_metric_runtime_and_source_tamper_is_fatal(self) -> None:
        with bundle_fixture.temporary_root() as root:
            inputs = create_parity_inputs(root)
            parity.publish(inputs)
            evidence_bytes = inputs.evidence_path.read_bytes()
            mutations = (
                ("validation", "maximum_absolute_probability_error", 2e-5),
                ("validation", "rows", 107),
                ("validation", "model_labels_exact", False),
                ("runtime", "execution_providers", ["CUDAExecutionProvider"]),
                ("bundle", "path", "wrong/terminal-flow.bundle.zip"),
                ("model", "selected_profile", "E"),
            )
            for section, field, value in mutations:
                with self.subTest(section=section, field=field):
                    evidence = json.loads(evidence_bytes)
                    evidence[section][field] = value
                    inputs.evidence_path.write_bytes(bundle.canonical_json(evidence))
                    with self.assertRaisesRegex(ValueError, "contract"):
                        parity.validate_outputs(inputs)

    def test_native_reference_float32_bit_tamper_is_fatal(self) -> None:
        with bundle_fixture.temporary_root() as root:
            inputs = create_parity_inputs(root)
            parity.publish(inputs)
            reference = json.loads(inputs.native_reference_path.read_text("utf-8"))
            reference["cases"][0]["input_float32_uint32_bits"][0] ^= 1
            reference_bytes = bundle.canonical_json(reference)
            inputs.native_reference_path.write_bytes(reference_bytes)
            evidence = json.loads(inputs.evidence_path.read_text("utf-8"))
            evidence["native_parity"]["reference_sha256"] = bundle.sha256_bytes(
                reference_bytes
            )
            inputs.evidence_path.write_bytes(bundle.canonical_json(evidence))

            with self.assertRaisesRegex(ValueError, "bit pattern"):
                parity.validate_outputs(inputs)


if __name__ == "__main__":
    unittest.main()
