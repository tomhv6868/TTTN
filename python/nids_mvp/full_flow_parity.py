from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

import numpy as np
import onnxruntime as ort
import pyarrow.parquet as pq

from nids_mvp import full_flow_bundle as bundle_stage
from nids_mvp import full_flow_dataset as dataset
from nids_mvp import full_flow_model as model_stage


TASK = "T9.1"
ABSOLUTE_TOLERANCE = 1e-5
BATCH_ROWS = 65_536
EXPECTED_PYTHON_ORT_VERSION = "1.27.0"


@dataclass(frozen=True)
class ParityInputs:
    root: Path
    bundle_inputs: bundle_stage.BundleInputs
    evidence_path: Path
    native_reference_path: Path


@dataclass(frozen=True)
class ValidationBatch:
    matrix: np.ndarray
    labels: np.ndarray
    capture_ids: np.ndarray
    flow_ids: np.ndarray


def production_inputs(root: Path) -> ParityInputs:
    root = root.resolve()
    model_root = root / "run_log/full-flow-v1/model"
    return ParityInputs(
        root=root,
        bundle_inputs=bundle_stage.production_inputs(root),
        evidence_path=model_root / "onnx-parity.json",
        native_reference_path=model_root / "native-parity-reference.json",
    )


def parity_bundle_record(
    inputs: ParityInputs,
    archive: bundle_stage.ArchiveValidation,
) -> dict[str, Any]:
    return {
        "path": bundle_stage.relative(
            inputs.bundle_inputs.bundle_path, inputs.root
        ),
        "staging_path": bundle_stage.relative(
            inputs.bundle_inputs.staging_path, inputs.root
        ),
        "archive_sha256": archive.archive_sha256,
        "manifest_sha256": archive.manifest_sha256,
        "model_member": bundle_stage.MODEL_MEMBER,
        "model_sha256": bundle_stage.sha256_bytes(archive.model_blob),
    }


def parity_model_record(
    verified: bundle_stage.VerifiedInputs,
) -> dict[str, Any]:
    return {
        "selection_manifest_sha256": verified.model_manifest_sha256,
        "selected_profile": verified.selected_profile,
        "selected_feature_indices": list(verified.selected_feature_indices),
        "selected_feature_names": list(verified.selected_feature_names),
        "class_order": list(verified.class_order),
        "selected_threshold": verified.threshold,
    }


def validation_batch_count(verified: bundle_stage.VerifiedInputs) -> int:
    result = 0
    for record in verified.validation_parts:
        rows = record.get("rows")
        if not isinstance(rows, int) or isinstance(rows, bool) or rows < 1:
            raise ValueError("terminal validation part row count mismatch")
        result += (rows + BATCH_ROWS - 1) // BATCH_ROWS
    return result


def native_parity_record(inputs: ParityInputs, reference_bytes: bytes) -> dict[str, Any]:
    return {
        "status": "pending",
        "reference_path": bundle_stage.relative(
            inputs.native_reference_path, inputs.root
        ),
        "reference_sha256": bundle_stage.sha256_bytes(reference_bytes),
        "required_before_live": True,
    }


def class_id(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def final_decisions(probability: np.ndarray, threshold: float) -> np.ndarray:
    if (
        probability.ndim != 2
        or probability.shape[1] != len(model_stage.CLASS_ORDER)
        or not np.isfinite(probability).all()
    ):
        raise ValueError("invalid terminal probability matrix for decision")
    attack_score = 1.0 - probability[:, 0]
    attack_family = 1 + np.argmax(probability[:, 1:], axis=1)
    return np.where(attack_score >= threshold, attack_family, 0).astype(
        np.int64, copy=False
    )


def python_probabilities(
    estimator: Any, matrix: np.ndarray
) -> np.ndarray:
    if matrix.dtype != np.float32 or matrix.ndim != 2:
        raise ValueError("terminal parity matrix must be two-dimensional float32")
    if estimator.classes_.tolist() != list(range(len(model_stage.CLASS_ORDER))):
        raise ValueError("terminal parity LightGBM class order mismatch")
    probability = np.asarray(estimator.booster_.predict(matrix), dtype=np.float64)
    model_stage.validate_probability_matrix(probability, len(matrix))
    return probability


def validation_part(
    verified: bundle_stage.VerifiedInputs,
    record: Mapping[str, Any],
) -> tuple[Path, str]:
    value = record.get("path")
    if not isinstance(value, str):
        raise ValueError("validation part path must be a string")
    path = bundle_stage.resolve_inside(verified.inputs.root, value)
    rows = record.get("rows")
    size_bytes = record.get("size_bytes")
    content_hash = record.get("sha256")
    if (
        record.get("partition") != "validation"
        or not isinstance(rows, int)
        or rows < 1
        or not isinstance(size_bytes, int)
        or size_bytes < 1
        or not bundle_stage.is_sha256(content_hash)
        or not path.is_file()
        or path.stat().st_size != size_bytes
        or bundle_stage.sha256_path(path) != content_hash
    ):
        raise ValueError(f"invalid terminal validation part: {value}")
    capture_id = model_stage.capture_from_path(value)
    metadata_names = [name for name, _, _ in dataset.METADATA_FIELDS]
    feature_names = bundle_stage.schema_feature_names(verified.feature_schema)
    with pq.ParquetFile(path) as parquet:
        if (
            parquet.metadata.num_rows != rows
            or parquet.schema_arrow.names != [*metadata_names, *feature_names]
        ):
            raise ValueError(f"terminal validation Parquet contract mismatch: {value}")
    return path, capture_id


def iter_validation_batches(
    verified: bundle_stage.VerifiedInputs,
) -> Iterator[ValidationBatch]:
    metadata_indices = {
        name: index for index, (name, _, _) in enumerate(dataset.METADATA_FIELDS)
    }
    required_metadata = (
        "flow_id",
        "capture_id",
        "partition",
        "label_status",
        "label_family",
        "label_binary",
    )
    feature_start = len(dataset.METADATA_FIELDS)
    feature_indices = tuple(
        feature_start + index for index in verified.selected_feature_indices
    )
    selected_columns = (
        *(metadata_indices[name] for name in required_metadata),
        *feature_indices,
    )
    label_index = {
        family: index for index, family in enumerate(model_stage.CLASS_ORDER)
    }
    for record in verified.validation_parts:
        path, capture_id = validation_part(verified, record)
        previous_flow_id: int | None = None
        with pq.ParquetFile(path) as parquet:
            for batch in parquet.iter_batches(batch_size=BATCH_ROWS):
                if any(batch.column(index).null_count for index in selected_columns):
                    raise ValueError(f"null terminal validation input: {record['path']}")
                flow_ids = batch.column(metadata_indices["flow_id"]).to_pylist()
                captures = batch.column(metadata_indices["capture_id"]).to_pylist()
                partitions = batch.column(metadata_indices["partition"]).to_pylist()
                statuses = batch.column(metadata_indices["label_status"]).to_pylist()
                families = batch.column(metadata_indices["label_family"]).to_pylist()
                binaries = batch.column(metadata_indices["label_binary"]).to_pylist()
                if (
                    any(value != capture_id for value in captures)
                    or any(value != "validation" for value in partitions)
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
                    raise ValueError(f"terminal validation metadata drift: {record['path']}")
                if flow_ids:
                    previous_flow_id = int(flow_ids[-1])
                raw = np.column_stack(
                    [
                        batch.column(index).to_numpy(zero_copy_only=False)
                        for index in feature_indices
                    ]
                ).astype(np.float64, copy=False)
                if not np.isfinite(raw).all():
                    raise ValueError(f"non-finite validation input: {record['path']}")
                with np.errstate(over="ignore", invalid="ignore"):
                    matrix = raw.astype(np.float32)
                if not np.isfinite(matrix).all():
                    raise ValueError(
                        f"validation input exceeds float32: {record['path']}"
                    )
                yield ValidationBatch(
                    matrix=matrix,
                    labels=np.asarray(
                        [label_index[family] for family in families], dtype=np.uint8
                    ),
                    capture_ids=np.asarray(captures, dtype="<U64"),
                    flow_ids=np.asarray(flow_ids, dtype=np.uint64),
                )


def native_case(
    case_id_value: str,
    row_index: int,
    matrix: np.ndarray,
    labels: np.ndarray,
    capture_ids: np.ndarray,
    flow_ids: np.ndarray,
    probabilities: np.ndarray,
    model_labels: np.ndarray,
    decisions: np.ndarray,
    threshold: float,
    class_order: Sequence[str],
) -> dict[str, Any]:
    probability = probabilities[row_index]
    input_values = np.asarray(matrix[row_index], dtype="<f4")
    true_index = int(labels[row_index])
    model_index = int(model_labels[row_index])
    decision_index = int(decisions[row_index])
    return {
        "case_id": case_id_value,
        "capture_id": str(capture_ids[row_index]),
        "flow_id": int(flow_ids[row_index]),
        "true_class_index": true_index,
        "true_class": class_order[true_index],
        "input": [float(value) for value in input_values],
        "input_float32_uint32_bits": [
            int(value) for value in input_values.view("<u4")
        ],
        "expected": {
            "probabilities": [float(value) for value in probability],
            "model_label_index": model_index,
            "model_label": class_order[model_index],
            "attack_score": float(1.0 - probability[0]),
            "selected_threshold": threshold,
            "decision_index": decision_index,
            "decision": class_order[decision_index],
        },
    }


class ReferenceCollector:
    def __init__(self, class_order: Sequence[str], threshold: float) -> None:
        self.class_order = tuple(class_order)
        self.threshold = threshold
        self.true_cases: dict[int, dict[str, Any]] = {}
        self.decision_cases: dict[int, dict[str, Any]] = {}
        self.boundary_cases: dict[str, tuple[float, int, dict[str, Any]]] = {}

    def update(
        self,
        ordinal: int,
        batch: ValidationBatch,
        probabilities: np.ndarray,
        model_labels: np.ndarray,
        decisions: np.ndarray,
    ) -> None:
        for index, name in enumerate(self.class_order):
            true_matches = np.flatnonzero(batch.labels == index)
            if index not in self.true_cases and len(true_matches):
                row = int(true_matches[0])
                self.true_cases[index] = native_case(
                    f"true-{class_id(name)}",
                    row,
                    batch.matrix,
                    batch.labels,
                    batch.capture_ids,
                    batch.flow_ids,
                    probabilities,
                    model_labels,
                    decisions,
                    self.threshold,
                    self.class_order,
                )
            decision_matches = np.flatnonzero(decisions == index)
            if index not in self.decision_cases and len(decision_matches):
                row = int(decision_matches[0])
                self.decision_cases[index] = native_case(
                    f"decision-{class_id(name)}",
                    row,
                    batch.matrix,
                    batch.labels,
                    batch.capture_ids,
                    batch.flow_ids,
                    probabilities,
                    model_labels,
                    decisions,
                    self.threshold,
                    self.class_order,
                )
        scores = 1.0 - probabilities[:, 0]
        for side, mask in (
            ("below", scores < self.threshold),
            ("above", scores >= self.threshold),
        ):
            matches = np.flatnonzero(mask)
            if not len(matches):
                continue
            distances = np.abs(scores[matches] - self.threshold)
            local = int(matches[int(np.argmin(distances))])
            distance = float(abs(scores[local] - self.threshold))
            global_ordinal = ordinal + local
            candidate = native_case(
                f"threshold-{side}",
                local,
                batch.matrix,
                batch.labels,
                batch.capture_ids,
                batch.flow_ids,
                probabilities,
                model_labels,
                decisions,
                self.threshold,
                self.class_order,
            )
            previous = self.boundary_cases.get(side)
            if previous is None or (distance, global_ordinal) < previous[:2]:
                self.boundary_cases[side] = (distance, global_ordinal, candidate)

    def cases(self) -> list[dict[str, Any]]:
        expected = set(range(len(self.class_order)))
        if set(self.true_cases) != expected or set(self.decision_cases) != expected:
            raise ValueError("native reference does not cover every terminal class")
        if set(self.boundary_cases) != {"below", "above"}:
            raise ValueError("native reference lacks both threshold boundary sides")
        return [
            *(self.true_cases[index] for index in range(len(self.class_order))),
            *(self.decision_cases[index] for index in range(len(self.class_order))),
            self.boundary_cases["below"][2],
            self.boundary_cases["above"][2],
        ]


def verify_prediction_archive(
    verified: bundle_stage.VerifiedInputs,
) -> tuple[np.lib.npyio.NpzFile, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    predictions = np.load(
        verified.inputs.validation_predictions_path, allow_pickle=False
    )
    expected_keys = {
        "validation_capture_id",
        "validation_flow_id",
        "y_true",
        *(f"profile_{profile}_probability" for profile in model_stage.PROFILE_LENGTHS),
    }
    if set(predictions.files) != expected_keys:
        predictions.close()
        raise ValueError("terminal validation prediction inventory mismatch")
    capture_ids = predictions["validation_capture_id"]
    flow_ids = predictions["validation_flow_id"]
    labels = predictions["y_true"]
    probabilities = predictions[f"profile_{verified.selected_profile}_probability"]
    if (
        capture_ids.dtype.kind != "U"
        or capture_ids.shape != (verified.validation_rows,)
        or flow_ids.dtype != np.uint64
        or flow_ids.shape != (verified.validation_rows,)
        or labels.dtype != np.uint8
        or labels.shape != (verified.validation_rows,)
    ):
        predictions.close()
        raise ValueError("terminal validation prediction metadata mismatch")
    model_stage.validate_probability_matrix(probabilities, verified.validation_rows)
    return predictions, capture_ids, flow_ids, labels, probabilities


def run_parity(inputs: ParityInputs) -> tuple[dict[str, Any], dict[str, Any]]:
    verified = bundle_stage.verify_inputs(inputs.bundle_inputs)
    archive = bundle_stage.validate_archive(
        inputs.bundle_inputs.bundle_path.read_bytes(), expected=verified
    )
    bundle_stage.validate_staging(inputs.bundle_inputs.staging_path, archive)
    if ort.__version__ != EXPECTED_PYTHON_ORT_VERSION:
        raise RuntimeError(
            "T9.1 Python ONNX Runtime mismatch: "
            f"expected={EXPECTED_PYTHON_ORT_VERSION}, observed={ort.__version__}"
        )
    session = ort.InferenceSession(
        archive.model_blob, providers=["CPUExecutionProvider"]
    )
    providers = session.get_providers()
    if providers != ["CPUExecutionProvider"]:
        raise ValueError(f"unexpected terminal parity providers: {providers}")
    predictions, saved_capture_ids, saved_flow_ids, saved_labels, saved_probability = (
        verify_prediction_archive(verified)
    )
    rows = 0
    batch_count = 0
    maximum_error = 0.0
    collector = ReferenceCollector(verified.class_order, verified.threshold)
    try:
        for batch in iter_validation_batches(verified):
            start = rows
            stop = start + len(batch.labels)
            if stop > verified.validation_rows:
                raise ValueError("terminal validation parity row overflow")
            if (
                not np.array_equal(saved_capture_ids[start:stop], batch.capture_ids)
                or not np.array_equal(saved_flow_ids[start:stop], batch.flow_ids)
                or not np.array_equal(saved_labels[start:stop], batch.labels)
            ):
                raise ValueError("terminal validation parity row identity drift")
            python_probability = python_probabilities(
                verified.estimator, batch.matrix
            )
            if not np.array_equal(
                saved_probability[start:stop], python_probability
            ):
                raise ValueError("terminal saved Python probability drift")
            ort_label, ort_probability = session.run(
                ["label", "probabilities"], {"input": batch.matrix}
            )
            ort_label = np.asarray(ort_label)
            ort_probability = np.asarray(ort_probability)
            if (
                ort_label.dtype != np.int64
                or ort_label.shape != (len(batch.labels),)
                or ort_probability.dtype != np.float32
                or ort_probability.shape
                != (len(batch.labels), len(verified.class_order))
                or not np.isfinite(ort_probability).all()
            ):
                raise ValueError("terminal ORT output contract mismatch")
            difference = np.abs(
                python_probability - ort_probability.astype(np.float64)
            )
            batch_error = float(np.max(difference, initial=0.0))
            if not math.isfinite(batch_error) or batch_error > ABSOLUTE_TOLERANCE:
                raise ValueError(
                    "terminal Python/ORT probability mismatch: "
                    f"maximum={batch_error}, tolerance={ABSOLUTE_TOLERANCE}"
                )
            python_label = np.argmax(python_probability, axis=1).astype(np.int64)
            if not np.array_equal(ort_label, python_label):
                raise ValueError("terminal Python/ORT model label mismatch")
            python_decision = final_decisions(
                python_probability, verified.threshold
            )
            ort_decision = final_decisions(
                ort_probability.astype(np.float64), verified.threshold
            )
            if not np.array_equal(ort_decision, python_decision):
                raise ValueError("terminal Python/ORT final decision mismatch")
            collector.update(
                rows,
                batch,
                python_probability,
                python_label,
                python_decision,
            )
            maximum_error = max(maximum_error, batch_error)
            rows = stop
            batch_count += 1
    finally:
        predictions.close()
    if rows != verified.validation_rows:
        raise ValueError(
            "terminal validation parity row count mismatch: "
            f"expected={verified.validation_rows}, observed={rows}"
        )
    expected_batches = validation_batch_count(verified)
    if batch_count != expected_batches:
        raise ValueError(
            "terminal validation parity batch count mismatch: "
            f"expected={expected_batches}, observed={batch_count}"
        )
    bundle_record = parity_bundle_record(inputs, archive)
    model_record = parity_model_record(verified)
    native_reference = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "terminal_flow_native_parity_reference",
        "status": "python_ort_passed_native_pending",
        "absolute_tolerance": ABSOLUTE_TOLERANCE,
        "input_encoding": {
            "numeric_dtype": "float32",
            "bit_pattern_dtype": "uint32",
            "bit_pattern_format": "IEEE 754 binary32",
        },
        "bundle": bundle_record,
        "model": model_record,
        "cases": collector.cases(),
        "test_partition": bundle_stage.SEALED_TEST_RECORD,
    }
    reference_bytes = bundle_stage.canonical_json(native_reference)
    evidence = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "terminal_flow_python_ort_parity",
        "status": "python_ort_passed_native_pending",
        "bundle": native_reference["bundle"],
        "model": native_reference["model"],
        "validation": {
            "partition": "validation",
            "rows": rows,
            "parts": len(verified.validation_parts),
            "batches": batch_count,
            "saved_python_probability_parity": "bitwise_equal_float64",
            "maximum_absolute_probability_error": maximum_error,
            "absolute_tolerance": ABSOLUTE_TOLERANCE,
            "model_labels_exact": True,
            "thresholded_final_decisions_exact": True,
        },
        "runtime": {
            "onnxruntime": ort.__version__,
            "execution_providers": providers,
        },
        "native_parity": native_parity_record(inputs, reference_bytes),
        "test_partition": bundle_stage.SEALED_TEST_RECORD,
    }
    return evidence, native_reference


def write_atomic(path: Path, value: bytes) -> None:
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


def validate_native_reference(
    reference: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    model = reference.get("model")
    cases = reference.get("cases")
    if not isinstance(model, Mapping) or not isinstance(cases, list):
        raise ValueError("terminal native reference inventory mismatch")
    class_order = model.get("class_order")
    feature_indices = model.get("selected_feature_indices")
    feature_names = model.get("selected_feature_names")
    threshold = model.get("selected_threshold")
    expected_case_ids = [
        *(f"true-{class_id(name)}" for name in model_stage.CLASS_ORDER),
        *(f"decision-{class_id(name)}" for name in model_stage.CLASS_ORDER),
        "threshold-below",
        "threshold-above",
    ]
    if (
        reference.get("schema_version") != "1.0.0"
        or reference.get("task") != TASK
        or reference.get("absolute_tolerance") != ABSOLUTE_TOLERANCE
        or reference.get("input_encoding")
        != {
            "numeric_dtype": "float32",
            "bit_pattern_dtype": "uint32",
            "bit_pattern_format": "IEEE 754 binary32",
        }
        or class_order != list(model_stage.CLASS_ORDER)
        or feature_indices != manifest.get("selected_feature_indices")
        or feature_names != manifest.get("selected_feature_names")
        or model.get("selected_profile") != manifest.get("selected_profile")
        or model.get("selection_manifest_sha256")
        != manifest.get("model_selection", {}).get("manifest_sha256")
        or threshold != manifest.get("selected_threshold")
        or not isinstance(feature_indices, list)
        or not isinstance(feature_names, list)
        or len(feature_indices) != len(feature_names)
        or [case.get("case_id") if isinstance(case, Mapping) else None for case in cases]
        != expected_case_ids
    ):
        raise ValueError("terminal native reference model contract mismatch")
    feature_count = len(feature_indices)
    for ordinal, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise ValueError("terminal native reference case must be an object")
        values = case.get("input")
        bits = case.get("input_float32_uint32_bits")
        expected = case.get("expected")
        true_index = case.get("true_class_index")
        if (
            not isinstance(values, list)
            or len(values) != feature_count
            or any(
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                for value in values
            )
            or not isinstance(bits, list)
            or len(bits) != feature_count
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 0xFFFFFFFF
                for value in bits
            )
            or not isinstance(expected, Mapping)
            or not isinstance(case.get("capture_id"), str)
            or not case.get("capture_id")
            or not isinstance(case.get("flow_id"), int)
            or isinstance(case.get("flow_id"), bool)
            or case.get("flow_id") < 0
            or not isinstance(true_index, int)
            or isinstance(true_index, bool)
            or not 0 <= true_index < len(class_order)
            or case.get("true_class") != class_order[true_index]
        ):
            raise ValueError("terminal native reference case contract mismatch")
        with np.errstate(over="ignore", invalid="ignore"):
            input_values = np.asarray(values, dtype="<f4")
        observed_bits = [int(value) for value in input_values.view("<u4")]
        if not np.isfinite(input_values).all() or bits != observed_bits:
            raise ValueError("terminal native reference float32 bit pattern mismatch")
        probabilities = expected.get("probabilities")
        model_index = expected.get("model_label_index")
        decision_index = expected.get("decision_index")
        if (
            not isinstance(probabilities, list)
            or len(probabilities) != len(class_order)
            or any(
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                for value in probabilities
            )
            or not isinstance(model_index, int)
            or isinstance(model_index, bool)
            or not 0 <= model_index < len(class_order)
            or not isinstance(decision_index, int)
            or isinstance(decision_index, bool)
            or not 0 <= decision_index < len(class_order)
        ):
            raise ValueError("terminal native reference expected output mismatch")
        probability = np.asarray(probabilities, dtype=np.float64)
        calculated_model_index = int(np.argmax(probability))
        calculated_attack_score = float(1.0 - probability[0])
        calculated_decision_index = (
            1 + int(np.argmax(probability[1:]))
            if calculated_attack_score >= float(threshold)
            else 0
        )
        if (
            not np.all((probability >= 0.0) & (probability <= 1.0))
            or abs(float(probability.sum()) - 1.0) > ABSOLUTE_TOLERANCE
            or expected.get("model_label") != class_order[model_index]
            or expected.get("decision") != class_order[decision_index]
            or expected.get("selected_threshold") != threshold
            or expected.get("attack_score") != calculated_attack_score
            or model_index != calculated_model_index
            or decision_index != calculated_decision_index
            or ordinal < len(class_order)
            and true_index != ordinal
            or len(class_order) <= ordinal < 2 * len(class_order)
            and decision_index != ordinal - len(class_order)
            or ordinal == len(cases) - 2
            and not calculated_attack_score < float(threshold)
            or ordinal == len(cases) - 1
            and not calculated_attack_score >= float(threshold)
        ):
            raise ValueError("terminal native reference decision contract mismatch")


def validate_outputs(inputs: ParityInputs) -> dict[str, Any]:
    evidence_bytes = inputs.evidence_path.read_bytes()
    reference_bytes = inputs.native_reference_path.read_bytes()
    evidence = json.loads(evidence_bytes.decode("utf-8"))
    reference = json.loads(reference_bytes.decode("utf-8"))
    if (
        not isinstance(evidence, Mapping)
        or not isinstance(reference, Mapping)
        or bundle_stage.canonical_json(evidence) != evidence_bytes
        or bundle_stage.canonical_json(reference) != reference_bytes
    ):
        raise ValueError("non-canonical terminal parity evidence")
    verified = bundle_stage.verify_inputs(inputs.bundle_inputs)
    archive = bundle_stage.validate_archive(
        inputs.bundle_inputs.bundle_path.read_bytes(), expected=verified
    )
    bundle_stage.validate_staging(inputs.bundle_inputs.staging_path, archive)
    expected_bundle = parity_bundle_record(inputs, archive)
    expected_model = parity_model_record(verified)
    expected_native_parity = native_parity_record(inputs, reference_bytes)
    validation = evidence.get("validation")
    runtime = evidence.get("runtime")
    maximum_error = (
        validation.get("maximum_absolute_probability_error")
        if isinstance(validation, Mapping)
        else None
    )
    if (
        not isinstance(maximum_error, (int, float))
        or isinstance(maximum_error, bool)
        or not math.isfinite(float(maximum_error))
        or not 0.0 <= float(maximum_error) <= ABSOLUTE_TOLERANCE
    ):
        raise ValueError("terminal parity maximum error contract mismatch")
    expected_validation = {
        "partition": "validation",
        "rows": verified.validation_rows,
        "parts": len(verified.validation_parts),
        "batches": validation_batch_count(verified),
        "saved_python_probability_parity": "bitwise_equal_float64",
        "maximum_absolute_probability_error": maximum_error,
        "absolute_tolerance": ABSOLUTE_TOLERANCE,
        "model_labels_exact": True,
        "thresholded_final_decisions_exact": True,
    }
    if (
        set(evidence)
        != {
            "schema_version",
            "task",
            "kind",
            "status",
            "bundle",
            "model",
            "validation",
            "runtime",
            "native_parity",
            "test_partition",
        }
        or evidence.get("schema_version") != "1.0.0"
        or evidence.get("task") != TASK
        or evidence.get("kind") != "terminal_flow_python_ort_parity"
        or evidence.get("status") != "python_ort_passed_native_pending"
        or evidence.get("bundle") != expected_bundle
        or evidence.get("model") != expected_model
        or validation != expected_validation
        or runtime
        != {
            "onnxruntime": EXPECTED_PYTHON_ORT_VERSION,
            "execution_providers": ["CPUExecutionProvider"],
        }
        or evidence.get("native_parity") != expected_native_parity
        or evidence.get("test_partition") != bundle_stage.SEALED_TEST_RECORD
        or set(reference)
        != {
            "schema_version",
            "task",
            "kind",
            "status",
            "absolute_tolerance",
            "input_encoding",
            "bundle",
            "model",
            "cases",
            "test_partition",
        }
        or reference.get("schema_version") != "1.0.0"
        or reference.get("task") != TASK
        or reference.get("kind") != "terminal_flow_native_parity_reference"
        or reference.get("status") != "python_ort_passed_native_pending"
        or reference.get("absolute_tolerance") != ABSOLUTE_TOLERANCE
        or reference.get("bundle") != expected_bundle
        or reference.get("model") != expected_model
        or reference.get("test_partition") != bundle_stage.SEALED_TEST_RECORD
        or not isinstance(reference.get("cases"), list)
        or len(reference["cases"]) != 14
    ):
        raise ValueError("terminal parity evidence contract mismatch")
    validate_native_reference(reference, archive.manifest)
    return evidence


def publish(inputs: ParityInputs) -> tuple[dict[str, Any], bool]:
    evidence, reference = run_parity(inputs)
    values = {
        inputs.native_reference_path: bundle_stage.canonical_json(reference),
        inputs.evidence_path: bundle_stage.canonical_json(evidence),
    }
    existing = [path.exists() for path in values]
    for path, value in values.items():
        if path.exists() and path.read_bytes() != value:
            raise ValueError(f"existing terminal parity output differs: {path.name}")
    for path, value in values.items():
        if not path.exists():
            write_atomic(path, value)
    validated = validate_outputs(inputs)
    return validated, all(existing)


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Run T9.1 Python versus ONNX Runtime validation parity"
    )
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    args = parser.parse_args(argv)
    try:
        inputs = production_inputs(args.project_root)
        if args.command == "check":
            verified = bundle_stage.verify_inputs(inputs.bundle_inputs)
            archive = bundle_stage.validate_archive(
                inputs.bundle_inputs.bundle_path.read_bytes(), expected=verified
            )
            bundle_stage.validate_staging(inputs.bundle_inputs.staging_path, archive)
            session = ort.InferenceSession(
                archive.model_blob, providers=["CPUExecutionProvider"]
            )
            if session.get_providers() != ["CPUExecutionProvider"]:
                raise ValueError("terminal parity CPU provider preflight failed")
            print(
                "[T9.1 parity check] status=passed partition=validation "
                f"rows={verified.validation_rows} test=sealed",
                flush=True,
            )
        elif args.command == "run":
            evidence, skipped = publish(inputs)
            print(
                f"[T9.1 parity run] status={'skipped' if skipped else evidence['status']} "
                f"rows={evidence['validation']['rows']} test=sealed",
                flush=True,
            )
        else:
            evidence = validate_outputs(inputs)
            print(
                "[T9.1 parity validate] "
                f"status={evidence['status']} rows={evidence['validation']['rows']} "
                "test=sealed",
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
