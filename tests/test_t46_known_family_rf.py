from __future__ import annotations

import json
import unittest
from pathlib import Path

import numpy as np

from nids_mvp import known_family_rf


ROOT = Path(__file__).resolve().parents[1]


class T46KnownFamilyRandomForestTests(unittest.TestCase):
    def test_contract_locks_approved_design(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-known-family-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(contract["labels"]["class_order"]), 13)
        self.assertEqual(len(contract["labels"]["macro_family_order"]), 9)
        self.assertEqual(len(contract["labels"]["case_study_family_order"]), 4)
        self.assertNotIn("BENIGN", contract["labels"]["class_order"])
        self.assertEqual(contract["labels"]["unavailable"], ["Heartbleed"])
        self.assertFalse(contract["input"]["stacker_or_anomaly_features_allowed"])
        self.assertEqual(contract["features"]["preprocessing_profile"], "supervised_known")
        self.assertEqual(contract["random_forest"]["parameters"]["class_weight"], "balanced_subsample")
        self.assertEqual(contract["confidence"]["calibration"], "none")
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_probability_contract_uses_first_argmax_and_max_confidence(self):
        class DummyModel:
            classes_ = np.asarray([0, 1, 2])
            n_jobs = 1

            def set_params(self, **values):
                self.n_jobs = values["n_jobs"]

            def predict_proba(self, matrix):
                return np.asarray([[0.4, 0.4, 0.2], [0.1, 0.2, 0.7]], dtype=np.float64)

        probability, top_index, top_class, confidence = known_family_rf.predict_probabilities(
            DummyModel(), np.zeros((2, 1), dtype=np.float32), ["a", "b", "c"], 1e-12
        )
        np.testing.assert_array_equal(top_index, np.asarray([0, 2], dtype=np.uint8))
        np.testing.assert_array_equal(top_class, np.asarray(["a", "c"]))
        np.testing.assert_array_equal(confidence, np.asarray([0.4, 0.7]))
        self.assertEqual(probability.dtype, np.float64)

    def test_probability_validator_rejects_shape_range_and_sum_drift(self):
        with self.assertRaisesRegex(ValueError, "invalid multiclass probability"):
            known_family_rf.validate_probability_matrix(
                np.asarray([[0.5, 0.4]], dtype=np.float64), 1, 2, 1e-12
            )
        with self.assertRaisesRegex(ValueError, "invalid multiclass probability"):
            known_family_rf.validate_probability_matrix(
                np.asarray([[1.1, -0.1]], dtype=np.float64), 1, 2, 1e-12
            )

    def test_metrics_keep_zero_support_undefined_and_exclude_it_from_balanced_accuracy(self):
        probability = np.asarray(
            [
                [0.8, 0.1, 0.1],
                [0.2, 0.7, 0.1],
                [0.6, 0.3, 0.1],
            ],
            dtype=np.float64,
        )
        observed = known_family_rf.compute_metrics(
            np.asarray([0, 1, 1], dtype=np.uint8), probability, ["a", "b", "c"], ["a", "b"]
        )
        self.assertIsNone(observed["per_class_metrics"]["c"]["recall"])
        self.assertIsNone(observed["per_class_metrics"]["c"]["f1"])
        self.assertAlmostEqual(observed["balanced_accuracy_supported_families"], 0.75)
        self.assertAlmostEqual(observed["macro_family_f1"], 2 / 3)
        self.assertEqual(observed["confusion_matrix"], [[1, 0, 0], [1, 1, 0], [0, 0, 0]])

    def test_metrics_reject_macro_family_without_validation_support(self):
        with self.assertRaisesRegex(ValueError, "macro family lacks validation support"):
            known_family_rf.compute_metrics(
                np.asarray([0], dtype=np.uint8),
                np.asarray([[0.8, 0.2]], dtype=np.float64),
                ["a", "b"],
                ["a", "b"],
            )

    def test_multiclass_random_forest_is_deterministic_with_locked_seed(self):
        class_order = ["a", "b", "c"]
        x_train = np.asarray(
            [[0.0], [0.1], [0.2], [0.4], [0.5], [0.6], [0.8], [0.9], [1.0]],
            dtype=np.float32,
        )
        y_train = np.asarray([0, 0, 0, 1, 1, 1, 2, 2, 2], dtype=np.uint8)
        x_validation = np.asarray([[0.15], [0.55], [0.95]], dtype=np.float32)
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
        first = known_family_rf.fit_random_forest(
            x_train, y_train, x_validation, parameters, class_order, 1e-12
        )
        second = known_family_rf.fit_random_forest(
            x_train, y_train, x_validation, parameters, class_order, 1e-12
        )
        for left, right in zip(first[1:], second[1:], strict=True):
            np.testing.assert_array_equal(left, right)


if __name__ == "__main__":
    unittest.main()
