from __future__ import annotations

import collections
import json
import unittest
from pathlib import Path

import numpy as np

from nids_mvp import oof_meta_features


ROOT = Path(__file__).resolve().parents[1]


class T44OofMetaFeatureTests(unittest.TestCase):
    def test_contract_locks_group_aware_benign_only_oof_protocol(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-oof-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["folding"]["fold_count"], 5)
        self.assertEqual(contract["folding"]["group_key"], ["capture_id", "time_block_index"])
        self.assertEqual(contract["folding"]["seed"], 4404)
        self.assertTrue(contract["folding"]["same_assignment_all_checkpoints"])
        self.assertEqual(contract["input"]["partition"], "train")
        self.assertEqual(contract["input"]["fit_class"], "BENIGN")
        self.assertFalse(contract["input"]["validation_rows_allowed"])
        self.assertFalse(contract["input"]["test_rows_allowed"])
        self.assertEqual(contract["hbos"]["correlation_mask"]["sample_rows_maximum"], 100000)
        self.assertEqual(contract["hbos"]["correlation_mask"]["absolute_threshold"], 0.98)
        self.assertEqual(contract["isolation_forest"]["random_state_formula"], "4404 + held_out_fold")
        self.assertFalse(contract["artifact"]["weighted_score_in_scope"])
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_allocator_is_deterministic_and_never_splits_a_group(self):
        blocks = {
            index: collections.Counter({"BENIGN": 10 + index, "Attack": index % 3})
            for index in range(25)
        }
        ratios = {f"fold_{index}": 20 for index in range(5)}
        first = oof_meta_features.allocate_capture("capture", blocks, ratios, 4404)
        second = oof_meta_features.allocate_capture("capture", blocks, ratios, 4404)
        self.assertEqual(first, second)
        self.assertEqual(set(first), set(blocks))
        self.assertEqual(set(first.values()), set(range(5)))
        self.assertTrue(all(isinstance(first[group], int) for group in blocks))

    def test_fold_preprocessor_is_independent_of_held_out_values(self):
        fit = np.asarray(
            [[1.0, 5.0, np.nan], [2.0, 5.0, 10.0], [3.0, 5.0, 12.0], [4.0, 5.0, 14.0]],
            dtype=np.float64,
        )
        raw_a = np.vstack([fit, [[100.0, 999.0, 1000.0]]])
        raw_b = np.vstack([fit, [[-1000.0, -999.0, -1000.0]]])
        indices = np.arange(4, dtype=np.int64)
        profile_a, _ = oof_meta_features.fit_fold_preprocessor(raw_a, indices, ["a", "constant", "c"], 2)
        profile_b, _ = oof_meta_features.fit_fold_preprocessor(raw_b, indices, ["a", "constant", "c"], 2)
        self.assertEqual(profile_a, profile_b)
        self.assertEqual(profile_a["constant_detection"], "exact_imputed_min_equals_max")
        self.assertEqual(profile_a["dropped_constant_features"], ["constant"])
        self.assertEqual(profile_a["imputation_values"], [2.5, 5.0, 12.0])

    def test_transform_is_float32_finite_and_has_train_serving_parity(self):
        raw = np.asarray(
            [[1.0, 5.0, np.nan], [2.0, 5.0, 10.0], [3.0, 5.0, 12.0], [4.0, 5.0, 14.0]],
            dtype=np.float64,
        )
        indices = np.arange(4, dtype=np.int64)
        profile, _ = oof_meta_features.fit_fold_preprocessor(raw, indices, ["a", "constant", "c"], 2)
        first = oof_meta_features.transform_values(raw, profile)
        second = oof_meta_features.transform_values(raw.copy(), profile)
        self.assertEqual(first.dtype, np.float32)
        self.assertTrue(np.isfinite(first).all())
        np.testing.assert_array_equal(first, second)

    def test_hbos_mask_uses_greedy_schema_order(self):
        axis = np.linspace(-2.0, 2.0, 100, dtype=np.float32)
        matrix = np.column_stack([axis, axis * 2.0, axis**2, -axis])
        retained, audit = oof_meta_features.derive_hbos_mask(
            matrix, ["first", "duplicate", "curve", "inverse"], 100, 0.98
        )
        self.assertEqual(retained, ["first", "curve"])
        self.assertEqual([item["feature"] for item in audit["rejected"]], ["duplicate", "inverse"])

    def test_oof_schema_contains_only_identifiers_labels_and_approved_meta_features(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-oof-contract.json").read_text(encoding="utf-8")
        )
        schema = oof_meta_features.oof_schema(contract, "0" * 64)
        self.assertEqual(
            schema.names,
            [
                "checkpoint",
                "capture_id",
                "flow_id",
                "fold",
                "assigned_class",
                "y_true",
                "hbos_raw_score",
                "hbos_normalized_score",
                "hbos_binary",
                "isolation_forest_raw_score",
                "isolation_forest_normalized_score",
                "isolation_forest_binary",
                "anomaly_count",
            ],
        )
        self.assertNotIn("weighted_score", schema.names)


if __name__ == "__main__":
    unittest.main()
