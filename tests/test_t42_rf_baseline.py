from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from nids_mvp import rf_baseline


ROOT = Path(__file__).resolve().parents[1]


def fixture_profile() -> dict:
    return {
        "input_features": ["a", "constant", "c"],
        "selected_features": ["a", "c"],
        "imputation_values": [2.0, 5.0, 11.0],
        "selected_indices": [0, 2],
        "scaler_mean": [2.0, 11.0],
        "scaler_scale": [1.0, 2.0],
    }


class T42RandomForestBaselineTests(unittest.TestCase):
    def test_contract_locks_binary_validation_only_baseline(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-rf-baseline-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["input"]["fit_partition"], "train")
        self.assertEqual(contract["input"]["evaluation_partition"], "validation")
        self.assertEqual(contract["input"]["sealed_partition"], "test")
        self.assertEqual(contract["labels"]["positive"]["value"], 1)
        self.assertEqual(contract["decision"]["threshold"], 0.5)
        self.assertFalse(contract["random_forest"]["hyperparameter_search_allowed"])
        self.assertEqual(contract["random_forest"]["parameters"]["n_estimators"], 300)
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_compute_metrics_uses_attack_positive_and_locked_confusion_layout(self):
        y_true = np.array([0, 0, 0, 1, 1, 1], dtype=np.uint8)
        y_pred = np.array([0, 1, 0, 1, 0, 1], dtype=np.uint8)
        metrics = rf_baseline.compute_metrics(y_true, y_pred)
        self.assertEqual(metrics["confusion_matrix"], [[2, 1], [1, 2]])
        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertAlmostEqual(metrics["recall"], 2 / 3)
        self.assertAlmostEqual(metrics["f1"], 2 / 3)
        self.assertAlmostEqual(metrics["macro_f1"], 2 / 3)
        self.assertAlmostEqual(metrics["fpr"], 1 / 3)

    def test_materialization_reuses_preprocessing_and_excludes_test(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flow_map = root / "known-flow-split.parquet"
            pq.write_table(
                pa.table(
                    {
                        "capture_id": ["fixture"] * 4,
                        "flow_id": pa.array([1, 2, 3, 4], type=pa.uint64()),
                        "partition": ["train", "train", "validation", "test"],
                        "assigned_class": ["BENIGN", "Attack", "Attack", "BENIGN"],
                    }
                ),
                flow_map,
            )
            part = root / "checkpoint=F3" / "capture_id=fixture" / "part.parquet"
            part.parent.mkdir(parents=True)
            pq.write_table(
                pa.table(
                    {
                        "flow_id": pa.array([1, 2, 3, 4], type=pa.uint64()),
                        "capture_id": ["fixture"] * 4,
                        "assigned_class": ["BENIGN", "Attack", "Attack", "BENIGN"],
                        "a": pa.array([1.0, 3.0, 2.0, 100.0], type=pa.float64()),
                        "constant": pa.array([5.0] * 4, type=pa.float64()),
                        "c": pa.array([9.0, 15.0, 13.0, 100.0], type=pa.float64()),
                    }
                ),
                part,
            )
            expected = {
                "train": {"F3": {"rows": 2, "benign": 1, "attack": 1}},
                "validation": {"F3": {"rows": 1, "benign": 0, "attack": 1}},
            }
            paths = rf_baseline.materialize_checkpoint(
                "F3",
                [{"path": "checkpoint=F3/capture_id=fixture/part.parquet", "resolved_path": part}],
                flow_map,
                ["a", "constant", "c"],
                fixture_profile(),
                expected,
                root,
            )
            np.testing.assert_array_equal(np.load(paths["x_train"]), [[-1.0, -1.0], [1.0, 2.0]])
            np.testing.assert_array_equal(np.load(paths["y_train"]), [0, 1])
            np.testing.assert_array_equal(np.load(paths["x_validation"]), [[0.0, 1.0]])
            np.testing.assert_array_equal(np.load(paths["validation_flow_id"]), [3])

    def test_materialization_rejects_snapshot_flow_map_label_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flow_map = root / "known-flow-split.parquet"
            pq.write_table(
                pa.table(
                    {
                        "capture_id": ["fixture"],
                        "flow_id": pa.array([1], type=pa.uint64()),
                        "partition": ["train"],
                        "assigned_class": ["BENIGN"],
                    }
                ),
                flow_map,
            )
            part = root / "checkpoint=F3" / "capture_id=fixture" / "part.parquet"
            part.parent.mkdir(parents=True)
            pq.write_table(
                pa.table(
                    {
                        "flow_id": pa.array([1], type=pa.uint64()),
                        "capture_id": ["fixture"],
                        "assigned_class": ["Attack"],
                        "a": pa.array([1.0], type=pa.float64()),
                        "constant": pa.array([5.0], type=pa.float64()),
                        "c": pa.array([9.0], type=pa.float64()),
                    }
                ),
                part,
            )
            expected = {
                "train": {"F3": {"rows": 1, "benign": 1, "attack": 0}},
                "validation": {"F3": {"rows": 1, "benign": 1, "attack": 0}},
            }
            with self.assertRaisesRegex(ValueError, "snapshot/flow-map drift"):
                rf_baseline.materialize_checkpoint(
                    "F3",
                    [{"path": "checkpoint=F3/capture_id=fixture/part.parquet", "resolved_path": part}],
                    flow_map,
                    ["a", "constant", "c"],
                    fixture_profile(),
                    expected,
                    root,
                )

    def test_random_forest_probability_and_threshold_are_deterministic(self):
        x_train = np.array([[0.0], [0.1], [0.2], [0.8], [0.9], [1.0]], dtype=np.float32)
        y_train = np.array([0, 0, 0, 1, 1, 1], dtype=np.uint8)
        x_validation = np.array([[0.15], [0.85]], dtype=np.float32)
        parameters = {
            "n_estimators": 20,
            "criterion": "gini",
            "max_depth": None,
            "min_samples_split": 2,
            "min_samples_leaf": 1,
            "max_features": "sqrt",
            "bootstrap": True,
            "class_weight": "balanced_subsample",
            "random_state": 4202,
            "n_jobs": -1,
            "oob_score": False,
            "warm_start": False,
            "ccp_alpha": 0.0,
            "max_samples": None,
        }
        first = rf_baseline.fit_random_forest(
            x_train, y_train, x_validation, parameters, 0.5
        )
        second = rf_baseline.fit_random_forest(
            x_train, y_train, x_validation, parameters, 0.5
        )
        self.assertEqual(first[0].n_jobs, -1)
        np.testing.assert_array_equal(first[1], second[1])
        np.testing.assert_array_equal(first[2], (first[1] >= 0.5).astype(np.uint8))
        np.testing.assert_array_equal(
            first[1], rf_baseline.predict_attack_probability(first[0], x_validation)
        )
        self.assertEqual(first[0].n_jobs, -1)

    def test_validation_matrix_is_eager_and_does_not_hold_file_handle(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "validation.npy"
            np.save(path, np.array([[1.0, 2.0]], dtype=np.float32))
            matrix = rf_baseline.load_validation_matrix(path)
            self.assertNotIsInstance(matrix, np.memmap)
            path.unlink()
            np.testing.assert_array_equal(matrix, [[1.0, 2.0]])


if __name__ == "__main__":
    unittest.main()
