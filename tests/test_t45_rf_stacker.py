from __future__ import annotations

import json
import unittest
from pathlib import Path

import numpy as np

from nids_mvp import rf_baseline, rf_stacker


ROOT = Path(__file__).resolve().parents[1]


class T45RandomForestStackerTests(unittest.TestCase):
    def test_contract_locks_approved_stacker_design(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-rf-stacker-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            contract["meta_features"]["order"],
            [
                "hbos_normalized_score",
                "isolation_forest_normalized_score",
                "hbos_binary",
                "isolation_forest_binary",
                "anomaly_count",
                "weighted_score",
            ],
        )
        self.assertFalse(contract["meta_features"]["raw_scores_allowed"])
        self.assertEqual(contract["meta_features"]["final_matrix_dtype"], "float32")
        self.assertFalse(contract["input"]["join_by_row_position_allowed"])
        self.assertFalse(contract["input"]["rf_baseline_probability_as_feature_allowed"])
        self.assertEqual(contract["random_forest"]["parameters"]["random_state"], 4202)
        self.assertEqual(contract["decision"]["threshold"], 0.5)
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_meta_matrix_uses_normalized_scores_fixed_weights_and_float32(self):
        observed = rf_stacker.build_meta_matrix(
            np.asarray([2.0, -1.0]),
            np.asarray([4.0, 3.0]),
            np.asarray([1, 0], dtype=np.uint8),
            np.asarray([0, 1], dtype=np.uint8),
            np.asarray([1, 1], dtype=np.uint8),
        )
        expected = np.asarray(
            [[2.0, 4.0, 1.0, 0.0, 1.0, 3.0], [-1.0, 3.0, 0.0, 1.0, 1.0, 1.0]],
            dtype=np.float32,
        )
        self.assertEqual(observed.dtype, np.float32)
        np.testing.assert_array_equal(observed, expected)

    def test_meta_matrix_rejects_anomaly_count_drift(self):
        with self.assertRaisesRegex(ValueError, "anomaly_count formula mismatch"):
            rf_stacker.build_meta_matrix(
                np.asarray([0.0]),
                np.asarray([0.0]),
                np.asarray([1], dtype=np.uint8),
                np.asarray([1], dtype=np.uint8),
                np.asarray([1], dtype=np.uint8),
            )

    def test_keyed_reorder_does_not_depend_on_row_position(self):
        source_capture = np.asarray(["b", "a", "a"], dtype="<U1")
        source_flow = np.asarray([3, 2, 1], dtype=np.uint64)
        source_y = np.asarray([1, 0, 1], dtype=np.uint8)
        values = np.asarray([[30.0], [20.0], [10.0]], dtype=np.float32)
        target_capture = np.asarray(["a", "b", "a"], dtype="<U1")
        target_flow = np.asarray([1, 3, 2], dtype=np.uint64)
        target_y = np.asarray([1, 1, 0], dtype=np.uint8)
        reordered, audit = rf_stacker.keyed_reorder(
            source_capture,
            source_flow,
            source_y,
            values,
            target_capture,
            target_flow,
            target_y,
        )
        np.testing.assert_array_equal(reordered[:, 0], [10.0, 30.0, 20.0])
        self.assertEqual(audit["matched_rows"], 3)
        self.assertEqual(audit["duplicate_keys"], 0)

    def test_keyed_reorder_rejects_duplicate_and_label_drift(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            rf_stacker.keyed_reorder(
                np.asarray(["a", "a"]),
                np.asarray([1, 1], dtype=np.uint64),
                np.asarray([0, 0], dtype=np.uint8),
                np.asarray([[1.0], [2.0]], dtype=np.float32),
                np.asarray(["a", "a"]),
                np.asarray([1, 2], dtype=np.uint64),
                np.asarray([0, 0], dtype=np.uint8),
            )
        with self.assertRaisesRegex(ValueError, "label mismatch"):
            rf_stacker.keyed_reorder(
                np.asarray(["a"]),
                np.asarray([1], dtype=np.uint64),
                np.asarray([0], dtype=np.uint8),
                np.asarray([[1.0]], dtype=np.float32),
                np.asarray(["a"]),
                np.asarray([1], dtype=np.uint64),
                np.asarray([1], dtype=np.uint8),
            )

    def test_random_forest_probability_is_deterministic(self):
        x_train = np.asarray(
            [[0.0, 0.0], [0.1, 0.0], [0.2, 0.0], [0.8, 1.0], [0.9, 1.0], [1.0, 1.0]],
            dtype=np.float32,
        )
        y_train = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.uint8)
        x_validation = np.asarray([[0.15, 0.0], [0.85, 1.0]], dtype=np.float32)
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
            "n_jobs": 1,
            "oob_score": False,
            "warm_start": False,
            "ccp_alpha": 0.0,
            "max_samples": None,
        }
        first = rf_baseline.fit_random_forest(x_train, y_train, x_validation, parameters, 0.5)
        second = rf_baseline.fit_random_forest(x_train, y_train, x_validation, parameters, 0.5)
        np.testing.assert_array_equal(first[1], second[1])
        np.testing.assert_array_equal(first[2], (first[1] >= 0.5).astype(np.uint8))


if __name__ == "__main__":
    unittest.main()
