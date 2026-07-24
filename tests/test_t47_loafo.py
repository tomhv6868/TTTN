import unittest

import numpy as np

from nids_mvp.loafo import (
    binary_role_metrics,
    fit_supervised_profile,
    merge_execution_contract,
    subset_oof,
)
from nids_mvp.preprocessing import transform_with_artifact


class LoafoTests(unittest.TestCase):
    def test_derived_contract_requires_content_addressed_user_decision(self):
        base = {
            "task": "T4.7",
            "random_forest": {"implementation": "sklearn.ensemble.RandomForestClassifier"},
        }
        decision = {
            "task": "T4.7",
            "status": "passed",
            "decision": "accepted",
            "execution": {
                "backend": "sklearn.ensemble.RandomForestClassifier",
                "n_estimators": 300,
                "n_jobs": -1,
            },
            "evidence_policy": {
                "overwrite_existing_evidence": False,
                "test_labels_allowed_for_fit_or_selection": False,
                "hooks_allowed": False,
            },
        }
        derived = {
            "task": "T4.7",
            "execution_variant": {"id": "rf300-primary", "output_root": "run_log/t4.7-rf300"},
            "random_forest": {
                    "implementation": "sklearn.ensemble.RandomForestClassifier",
                    "final_tree_count": 300,
                    "n_jobs": -1,
            },
            "validation_override": {"rf300_is_primary_final": True},
        }
        contract = merge_execution_contract(base, decision, derived)
        self.assertEqual(contract["random_forest"]["final_tree_count"], 300)
        self.assertEqual(contract["execution_variant"]["id"], "rf300-primary")

    def test_profile_is_train_serving_exact_and_drops_constant(self):
        matrix = np.asarray([[1.0, 7.0, np.nan], [3.0, 7.0, 5.0], [5.0, 7.0, 9.0]])
        profile = fit_supervised_profile(matrix, "F3", ["a", "constant", "nullable"])
        self.assertEqual(profile["dropped_constant_features"], ["constant"])
        self.assertEqual(profile["parity"]["status"], "passed")
        transformed = transform_with_artifact(matrix, profile["input_features"], profile)
        self.assertEqual(transformed.dtype, np.float32)
        self.assertTrue(np.isfinite(transformed).all())

    def test_oof_subset_is_keyed_not_positional(self):
        source = {
            "capture_id": np.asarray(["a", "a", "b"]),
            "flow_id": np.asarray([2, 1, 3], dtype=np.uint64),
            "y_true": np.asarray([1, 0, 1], dtype=np.uint8),
            "meta": np.asarray([[20.0], [10.0], [30.0]], dtype=np.float32),
        }
        result = subset_oof(
            source,
            np.asarray(["b", "a"]),
            np.asarray([3, 1], dtype=np.uint64),
            np.asarray([1, 0], dtype=np.uint8),
        )
        np.testing.assert_array_equal(result[:, 0], np.asarray([30.0, 10.0], dtype=np.float32))

    def test_role_metrics_separate_unknown_from_known(self):
        metrics = binary_role_metrics(
            np.asarray(["BENIGN", "Known", "Holdout", "Holdout"]),
            "Holdout",
            np.asarray([0, 1, 0, 1], dtype=np.uint8),
        )
        self.assertEqual(metrics["benign_fpr"], 0.0)
        self.assertEqual(metrics["known_attack_recall"], 1.0)
        self.assertEqual(metrics["unknown_holdout_recall"], 0.5)


if __name__ == "__main__":
    unittest.main()
