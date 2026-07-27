from __future__ import annotations

import contextlib
import json
import shutil
import sys
import unittest
import uuid
from collections.abc import Iterator
from pathlib import Path

import joblib
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from nids_mvp import full_flow_dataset as dataset
from nids_mvp import full_flow_model as model


CAPTURE_ID = "synthetic-working-hours"
ASSIGNED_CLASS = {
    "Benign": "BENIGN",
    "FTP-Bruteforce": "FTP-Patator",
    "SSH-Bruteforce": "SSH-Patator",
    "PortScan": "PortScan",
    "DoS": "DDoS",
    "Other": "Bot",
}


@contextlib.contextmanager
def temporary_root() -> Iterator[Path]:
    path = ROOT / f".t91-full-flow-model-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")


def small_policy() -> model.TrainingPolicy:
    parameters = dict(model.PRODUCTION_PARAMETERS)
    parameters.update(
        {
            "num_leaves": 7,
            "learning_rate": 0.2,
            "n_estimators": 30,
            "subsample_for_bin": 100,
            "min_child_samples": 2,
            "n_jobs": 1,
        }
    )
    return model.TrainingPolicy(
        parameters=parameters,
        maximum_benign_fpr=0.01,
        target_minimum_precision=0.90,
        target_minimum_recall=0.90,
        attack_recall_max_drop=0.002,
        macro_f1_max_drop=0.01,
        target_f1_max_drop=0.01,
        macro_minimum_support=1,
    )


def fixture_rows(
    partition: str, samples_per_class: int, first_flow_id: int
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    flow_id = first_flow_id
    for class_index, family in enumerate(model.CLASS_ORDER):
        for sample in range(samples_per_class):
            base = float(class_index * 100 + sample)
            features = [base + index / 10_000.0 for index in range(70)]
            rows.append(
                {
                    "flow_id": flow_id,
                    "capture_id": CAPTURE_ID,
                    "export_ordinal": flow_id,
                    "flow_generation": 1,
                    "protocol": 6,
                    "low_ip": 0x0A000001,
                    "low_port": 10_000 + class_index,
                    "high_ip": 0x0A000002,
                    "high_port": 20_000 + class_index,
                    "forward_source_ip": 0x0A000001,
                    "forward_source_port": 10_000 + class_index,
                    "clock_domain": "unix_epoch",
                    "creation_timestamp_ns": flow_id * 1_000,
                    "last_capture_timestamp_ns": flow_id * 1_000 + 100,
                    "last_event_timestamp_ns": flow_id * 1_000 + 100,
                    "packet_count": 2,
                    "forward_packet_count": 1,
                    "reverse_packet_count": 1,
                    "paired_f9": False,
                    "close_reason": "tcp_reset",
                    "label_status": "assigned",
                    "assigned_class": ASSIGNED_CLASS[family],
                    "label_family": family,
                    "label_binary": family != "Benign",
                    "assignment_method": "mutual_unique",
                    "quarantine_reason": None,
                    "partition": partition,
                    "features": features,
                }
            )
            flow_id += 1
    return rows


def rows_to_table(
    rows: list[dict[str, object]], schema: pa.Schema
) -> pa.Table:
    arrays: list[pa.Array] = []
    feature_names = schema.names[len(dataset.METADATA_FIELDS) :]
    for field in schema:
        if field.name in feature_names:
            feature_index = feature_names.index(field.name)
            values = [row["features"][feature_index] for row in rows]
        else:
            values = [row[field.name] for row in rows]
        arrays.append(pa.array(values, type=field.type))
    return pa.Table.from_arrays(arrays, schema=schema)


def part_record(root: Path, path: Path, partition: str, rows: int) -> dict:
    return {
        "kind": "assigned",
        "partition": partition,
        "path": path.relative_to(root).as_posix(),
        "rows": rows,
        "size_bytes": path.stat().st_size,
        "sha256": model.sha256_path(path),
        "schema_sha256": None,
    }


def create_inputs(root: Path) -> tuple[model.ModelInputs, dict[str, Path]]:
    config = root / "config"
    config.mkdir()
    schema_path = config / "terminal-flow-feature-schema-v1.json"
    requirements_path = config / "full-flow-reproducibility-requirements.txt"
    shutil.copyfile(ROOT / "config/terminal-flow-feature-schema-v1.json", schema_path)
    shutil.copyfile(
        ROOT / "config/full-flow-reproducibility-requirements.txt",
        requirements_path,
    )
    feature_names, profiles = dataset.load_feature_schema(
        schema_path, dataset.FEATURE_SCHEMA_SHA256
    )
    split_hash = "d" * 64
    schema = dataset.arrow_schema(
        feature_names,
        dataset.FEATURE_SCHEMA_SHA256,
        split_hash,
        profiles,
    )
    part_paths: dict[str, Path] = {}
    records: list[dict] = []
    specifications = (
        ("train", 12, 1),
        ("validation", 3, 10_001),
    )
    for partition, samples, first_flow_id in specifications:
        path = (
            root
            / "dataset"
            / f"capture_id={CAPTURE_ID}"
            / "assigned"
            / f"partition={partition}"
            / "part-00000.parquet"
        )
        path.parent.mkdir(parents=True)
        rows = fixture_rows(partition, samples, first_flow_id)
        pq.write_table(rows_to_table(rows, schema), path)
        record = part_record(root, path, partition, len(rows))
        record["schema_sha256"] = dataset.schema_fingerprint(schema)
        records.append(record)
        part_paths[partition] = path
    test_path = (
        root
        / "dataset"
        / f"capture_id={CAPTURE_ID}"
        / "assigned"
        / "partition=test"
        / "part-00000.parquet"
    )
    test_record = {
        "kind": "assigned",
        "partition": "test",
        "path": test_path.relative_to(root).as_posix(),
        "rows": 18,
        "size_bytes": 123,
        "sha256": "f" * 64,
        "schema_sha256": dataset.schema_fingerprint(schema),
    }
    records.append(test_record)
    manifest_path = root / "dataset/manifest.json"
    write_json(
        manifest_path,
        {
            "schema_version": "1.0.0",
            "task": model.TASK,
            "kind": "terminal_flow_dataset_manifest",
            "status": "complete",
            "feature_schema": {
                "path": schema_path.relative_to(root).as_posix(),
                "schema_id": dataset.FEATURE_SCHEMA_ID,
                "sha256": dataset.FEATURE_SCHEMA_SHA256,
                "feature_count": dataset.FEATURE_COUNT,
            },
            "split_map": {"path": "split/flow-partitions.parquet", "sha256": split_hash},
            "schema_sha256": dataset.schema_fingerprint(schema),
            "model_feature_columns": feature_names,
            "training_parts": [records[0]["path"]],
            "validation_parts": [records[1]["path"]],
            "test_partition": {
                "status": "sealed",
                "policy": "fixture test path must remain unopened",
                "parts": [test_record["path"]],
            },
            "parts": records,
        },
    )
    part_paths["test"] = test_path
    return (
        model.ModelInputs(
            root=root,
            dataset_manifest_path=manifest_path,
            feature_schema_path=schema_path,
            requirements_path=requirements_path,
            output_root=root / "model",
            enforce_runtime=False,
        ),
        part_paths,
    )


def update_part_record(inputs: model.ModelInputs, path: Path) -> None:
    manifest = model.load_json(inputs.dataset_manifest_path)
    relative_path = path.relative_to(inputs.root).as_posix()
    for record in manifest["parts"]:
        if record["path"] == relative_path:
            record["size_bytes"] = path.stat().st_size
            record["sha256"] = model.sha256_path(path)
            break
    write_json(inputs.dataset_manifest_path, manifest)


def mutate_column(
    inputs: model.ModelInputs,
    path: Path,
    column: str,
    mutate,
) -> None:
    with pq.ParquetFile(path) as parquet:
        table = parquet.read()
    index = table.schema.get_field_index(column)
    values = table.column(index).to_pylist()
    values[0] = mutate(values[0])
    field = table.schema.field(index)
    replacement = pa.array(values, type=field.type)
    if replacement.null_count:
        field = pa.field(
            field.name,
            field.type,
            nullable=True,
            metadata=field.metadata,
        )
    table = table.set_column(index, field, replacement)
    pq.write_table(table, path)
    update_part_record(inputs, path)


def probability_row(benign: float, predicted_class: int) -> list[float]:
    values = [0.0] * len(model.CLASS_ORDER)
    values[0] = benign
    values[predicted_class] = 1.0 - benign
    return values


def profile_result(
    profile_id: str,
    precision: float,
    recall: float,
    attack_recall: float,
    macro_f1: float,
    target_f1: float,
    threshold: float,
) -> dict:
    per_class = {
        family: {"precision": 1.0, "recall": 1.0, "f1": 1.0}
        for family in model.CLASS_ORDER
    }
    for family in model.TARGET_FAMILIES:
        per_class[family] = {
            "precision": precision,
            "recall": recall,
            "f1": target_f1,
        }
    return {
        "profile_id": profile_id,
        "feature_count": model.PROFILE_LENGTHS[profile_id],
        "threshold_selection": {
            "threshold": threshold,
            "metrics": {
                "attack_recall": attack_recall,
                "macro_f1": macro_f1,
                "minimum_target_f1": target_f1,
                "per_class": per_class,
            },
        },
    }


class FullFlowModelTest(unittest.TestCase):
    def test_materialization_is_train_validation_only_and_exact_prefix(self) -> None:
        with temporary_root() as root:
            inputs, paths = create_inputs(root)
            self.assertFalse(paths["test"].exists())

            verified = model.verify_inputs(inputs)
            matrices = model.materialize_train_validation(
                verified, root / "matrix-work"
            )
            x_train = np.array(np.load(matrices.x_train, mmap_mode="r"))
            y_train = np.array(np.load(matrices.y_train, mmap_mode="r"))
            x_validation = np.array(
                np.load(matrices.x_validation, mmap_mode="r")
            )

            self.assertEqual(x_train.shape, (72, 70))
            self.assertEqual(x_validation.shape, (18, 70))
            self.assertEqual(
                y_train.tolist(),
                [index for index in range(6) for _ in range(12)],
            )
            self.assertEqual(
                verified.profiles[0].feature_names,
                verified.feature_names[:54],
            )
            self.assertEqual(
                verified.profiles[-1].feature_names,
                verified.feature_names,
            )
            self.assertTrue(np.isfinite(x_train).all())
            self.assertFalse(paths["test"].exists())

    def test_materialization_rejects_partition_and_label_drift(self) -> None:
        cases = (
            ("partition", lambda _: "test", "metadata drift"),
            ("label_binary", lambda value: not value, "metadata drift"),
        )
        for column, mutation, message in cases:
            with self.subTest(column=column), temporary_root() as root:
                inputs, paths = create_inputs(root)
                mutate_column(inputs, paths["validation"], column, mutation)
                verified = model.verify_inputs(inputs)
                with self.assertRaisesRegex(ValueError, message):
                    model.materialize_train_validation(verified, root / "work")

    def test_materialization_rejects_null_nonfinite_and_float32_overflow(self) -> None:
        cases = (
            (lambda _: None, "null model input"),
            (lambda _: float("inf"), "non-finite"),
            (lambda _: 1e300, "exceeds float32"),
        )
        for mutation, message in cases:
            with self.subTest(message=message), temporary_root() as root:
                inputs, paths = create_inputs(root)
                verified = model.verify_inputs(inputs)
                mutate_column(inputs, paths["validation"], "flow_age_us", mutation)
                with self.assertRaisesRegex(ValueError, message):
                    model.materialize_train_validation(verified, root / "work")

    def test_probability_validation_and_lightgbm_fit_are_deterministic(self) -> None:
        policy = small_policy()
        rows_per_class = 12
        x_train = np.asarray(
            [
                [class_index * 100.0 + sample, float(class_index)]
                for class_index in range(6)
                for sample in range(rows_per_class)
            ],
            dtype=np.float32,
        )
        y_train = np.asarray(
            [class_index for class_index in range(6) for _ in range(rows_per_class)],
            dtype=np.uint8,
        )
        x_validation = x_train[::3].copy()
        first = model.fit_profile(
            x_train, y_train, x_validation, ("a", "b"), policy.parameters
        )
        second = model.fit_profile(
            x_train, y_train, x_validation, ("a", "b"), policy.parameters
        )
        np.testing.assert_array_equal(first[1], second[1])
        self.assertEqual(first[0].classes_.tolist(), list(range(6)))
        self.assertEqual(first[0].feature_name_, ["a", "b"])

        invalid = first[1].copy()
        invalid[0, 0] = np.nan
        with self.assertRaisesRegex(ValueError, "invalid terminal multiclass"):
            model.validate_probability_matrix(invalid, len(invalid))

    def test_threshold_sweep_is_fpr_bounded_and_deterministic(self) -> None:
        y_true: list[int] = [0] * 100
        probability: list[list[float]] = [probability_row(0.99, 1) for _ in range(99)]
        probability.append(probability_row(0.15, 1))
        for class_index, benign_score in ((1, 0.10), (2, 0.20), (3, 0.15), (4, 0.25), (5, 0.30)):
            y_true.extend([class_index] * 4)
            probability.extend([probability_row(benign_score, class_index) for _ in range(4)])
        labels = np.asarray(y_true, dtype=np.uint8)
        probabilities = np.asarray(probability, dtype=np.float64)
        policy = small_policy()

        first = model.select_threshold(labels, probabilities, policy)
        second = model.select_threshold(labels, probabilities, policy)

        self.assertEqual(first, second)
        self.assertLessEqual(first["metrics"]["benign_fpr"], 0.01)
        self.assertEqual(first["metrics"]["per_class"]["FTP-Bruteforce"]["recall"], 1.0)
        self.assertEqual(first["metrics"]["per_class"]["PortScan"]["recall"], 1.0)
        self.assertEqual(first["objective_order"][-1], "threshold_desc")

    def test_profile_selection_chooses_smallest_eligible_and_can_fail_closed(self) -> None:
        policy = small_policy()
        results = [
            profile_result("A", 0.95, 0.95, 0.97, 0.97, 0.95, 0.50),
            profile_result("B", 0.96, 0.96, 0.989, 0.985, 0.985, 0.42),
            profile_result("C", 0.97, 0.97, 0.989, 0.986, 0.986, 0.41),
            profile_result("D", 0.98, 0.98, 0.990, 0.989, 0.989, 0.40),
            profile_result("E", 0.99, 0.99, 0.990, 0.990, 0.990, 0.39),
        ]
        selection = model.select_profile(results, policy)
        self.assertEqual(selection["selected_profile"], "B")
        self.assertEqual(selection["selected_feature_indices"], list(range(61)))
        self.assertEqual(selection["selected_threshold"], 0.42)

        failing = [
            profile_result(profile_id, 0.5, 0.5, 0.99, 0.99, 0.5, 0.5)
            for profile_id in model.PROFILE_LENGTHS
        ]
        with self.assertRaisesRegex(ValueError, "no validation-eligible"):
            model.select_profile(failing, policy)

    def test_training_publish_is_atomic_resumable_and_test_sealed(self) -> None:
        with temporary_root() as root:
            inputs, paths = create_inputs(root)
            policy = small_policy()

            manifest, skipped = model.train_model(inputs, policy)

            self.assertFalse(skipped)
            self.assertEqual(manifest["status"], "locked")
            self.assertEqual(manifest["selection"]["selected_profile"], "A")
            self.assertEqual(
                manifest["preprocessing"]["operation"],
                "finite_float64_to_float32_cast",
            )
            self.assertEqual(
                manifest["test_partition"],
                {
                    "status": "sealed",
                    "feature_reads": 0,
                    "metric_reads": 0,
                    "path_resolution_or_hash_reads": 0,
                },
            )
            self.assertEqual(
                {path.name for path in inputs.output_root.iterdir()},
                {"manifest.json", "selected-model.joblib", "validation-predictions.npz"},
            )
            self.assertFalse(paths["test"].exists())
            bundle = joblib.load(inputs.output_root / "selected-model.joblib")
            self.assertEqual(bundle["class_order"], list(model.CLASS_ORDER))
            self.assertEqual(bundle["profile_id"], "A")

            self.assertEqual(model.validate_model(inputs, policy), manifest)
            resumed, skipped = model.train_model(inputs, policy)
            self.assertTrue(skipped)
            self.assertEqual(resumed, manifest)
            self.assertFalse(paths["test"].exists())
            self.assertFalse(list(root.glob(".model-*")))


if __name__ == "__main__":
    unittest.main()
