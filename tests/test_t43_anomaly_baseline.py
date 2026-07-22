from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.ensemble import IsolationForest

from nids_mvp import anomaly_baseline


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


class T43AnomalyBaselineTests(unittest.TestCase):
    def test_contract_locks_two_benign_trained_validation_baselines(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-anomaly-baseline-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["input"]["fit_partition"], "train")
        self.assertEqual(contract["input"]["fit_class"], "BENIGN")
        self.assertEqual(contract["input"]["evaluation_partition"], "validation")
        self.assertEqual(contract["input"]["sealed_partition"], "test")
        self.assertEqual(contract["hbos"]["binning"]["interior_bin_count"], 16)
        self.assertEqual(contract["hbos"]["binning"]["total_bin_count"], 18)
        self.assertEqual(contract["isolation_forest"]["parameters"]["n_estimators"], 300)
        self.assertEqual(contract["isolation_forest"]["parameters"]["max_samples"], 4096)
        self.assertEqual(contract["score_normalization_and_decision"]["threshold_quantile"], 0.99)
        self.assertFalse(contract["score_normalization_and_decision"]["validation_threshold_tuning_allowed"])
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_hbos_bin_boundaries_include_both_interior_endpoints(self):
        edges = np.asarray([0.0, 1.0, 2.0])
        values = np.asarray([-1.0, 0.0, 0.5, 1.0, 2.0, 3.0])
        np.testing.assert_array_equal(
            anomaly_baseline._hbos_bin_indices(values, edges),
            [0, 1, 1, 2, 2, 3],
        )

    def test_hbos_fit_uses_laplace_mass_and_named_feature_mask(self):
        matrix = np.asarray(
            [
                [-2.0, 100.0, 0.0],
                [-1.0, 200.0, 0.5],
                [0.0, 300.0, 1.0],
                [1.0, 400.0, 1.5],
                [2.0, 500.0, 2.0],
            ],
            dtype=np.float32,
        )
        config = {
            "binning": {
                "interior_bin_count": 2,
                "total_bin_count": 4,
                "lower_quantile": 0.0,
                "upper_quantile": 1.0,
                "quantile_method": "linear",
            }
        }
        model = anomaly_baseline.fit_hbos(matrix, ["a", "ignored", "c"], ["a", "c"], config)
        self.assertEqual(model["feature_indices"], [0, 2])
        self.assertEqual(model["feature_names"], ["a", "c"])
        for counts, probabilities in zip(model["counts"], model["probabilities"], strict=True):
            np.testing.assert_allclose(probabilities, (counts + 1.0) / 9.0)
            self.assertAlmostEqual(float(probabilities.sum()), 1.0)
        self.assertTrue(np.isfinite(anomaly_baseline.score_hbos(model, matrix)).all())

    def test_score_decision_uses_population_zscore_higher_quantile_and_reports_ties(self):
        raw = np.asarray([0.0, 0.0, 0.0, 1.0], dtype=np.float64)
        config = {"threshold_quantile": 0.99, "threshold_quantile_method": "higher"}
        decision = anomaly_baseline.fit_score_decision(raw, config)
        normalized, prediction = anomaly_baseline.apply_score_decision(raw, decision)
        self.assertAlmostEqual(float(np.mean(normalized)), 0.0)
        self.assertAlmostEqual(float(np.std(normalized, ddof=0)), 1.0)
        np.testing.assert_array_equal(prediction, [0, 0, 0, 1])
        self.assertEqual(decision["threshold"], normalized[-1])
        self.assertEqual(decision["empirical_benign_train_fpr"], 0.25)

    def test_isolation_forest_score_orientation_is_anomaly_higher(self):
        matrix = np.arange(40, dtype=np.float32).reshape(20, 2)
        model = IsolationForest(n_estimators=5, max_samples=8, random_state=3).fit(matrix)
        observed = anomaly_baseline.score_isolation_forest(model, matrix, batch_rows=7)
        np.testing.assert_array_equal(observed, -model.score_samples(matrix))

    def test_metrics_use_attack_positive_and_locked_confusion_layout(self):
        y_true = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.uint8)
        y_pred = np.asarray([0, 1, 0, 1, 0, 1], dtype=np.uint8)
        metrics = anomaly_baseline.compute_metrics(y_true, y_pred)
        self.assertEqual(metrics["confusion_matrix"], [[2, 1], [1, 2]])
        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertAlmostEqual(metrics["recall"], 2 / 3)
        self.assertAlmostEqual(metrics["fpr"], 1 / 3)

    def test_materialization_fits_only_benign_train_and_emits_all_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flow_map = root / "known-flow-split.parquet"
            pq.write_table(
                pa.table(
                    {
                        "capture_id": ["fixture"] * 5,
                        "flow_id": pa.array([1, 2, 3, 4, 5], type=pa.uint64()),
                        "partition": ["train", "train", "validation", "validation", "test"],
                        "assigned_class": ["BENIGN", "Attack", "BENIGN", "Attack", "BENIGN"],
                    }
                ),
                flow_map,
            )
            part = root / "checkpoint=F3" / "capture_id=fixture" / "part.parquet"
            part.parent.mkdir(parents=True)
            pq.write_table(
                pa.table(
                    {
                        "flow_id": pa.array([1, 2, 3, 4, 5], type=pa.uint64()),
                        "capture_id": ["fixture"] * 5,
                        "assigned_class": ["BENIGN", "Attack", "BENIGN", "Attack", "BENIGN"],
                        "a": pa.array([1.0, 50.0, 2.0, 3.0, 100.0], type=pa.float64()),
                        "constant": pa.array([5.0] * 5, type=pa.float64()),
                        "c": pa.array([9.0, 50.0, 13.0, 15.0, 100.0], type=pa.float64()),
                    }
                ),
                part,
            )
            paths = anomaly_baseline.materialize_checkpoint(
                "F3",
                [{"path": part.relative_to(root).as_posix(), "resolved_path": part}],
                flow_map,
                ["a", "constant", "c"],
                fixture_profile(),
                1,
                {"rows": 2, "benign": 1, "attack": 1},
                root,
            )
            np.testing.assert_array_equal(np.load(paths["x_train"]), [[-1.0, -1.0]])
            np.testing.assert_array_equal(np.load(paths["x_validation"]), [[0.0, 1.0], [1.0, 2.0]])
            np.testing.assert_array_equal(np.load(paths["y_validation"]), [0, 1])
            np.testing.assert_array_equal(np.load(paths["validation_flow_id"]), [3, 4])


if __name__ == "__main__":
    unittest.main()
