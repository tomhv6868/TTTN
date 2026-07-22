from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from nids_mvp import anomaly_eda


ROOT = Path(__file__).resolve().parents[1]


class T43AnomalyEdaTests(unittest.TestCase):
    def test_contract_locks_benign_train_only_without_model_decisions(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-anomaly-eda-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["input"]["partition"], "train")
        self.assertEqual(contract["input"]["assigned_class"], "BENIGN")
        self.assertEqual(contract["input"]["preprocessing_profile"], "anomaly_benign")
        self.assertFalse(contract["input"]["attack_train_rows_allowed"])
        self.assertFalse(contract["input"]["validation_rows_allowed"])
        self.assertFalse(contract["input"]["test_rows_allowed"])
        self.assertFalse(contract["execution"]["model_training_allowed"])
        self.assertFalse(contract["eda"]["correlation_audit"]["feature_pruning_allowed"])
        self.assertFalse(contract["eda"]["hbos_candidate_diagnostics"]["winner_selection_allowed"])
        self.assertFalse(contract["eda"]["decision_threshold_selection_allowed"])
        self.assertEqual(
            contract["eda"]["hbos_candidate_diagnostics"]["candidate_bin_counts"],
            [16, 32, 64],
        )

    def test_materialization_excludes_attack_train_validation_and_test(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "run_log") as temporary:
            root = Path(temporary)
            flow_map = root / "known-flow-split.parquet"
            pq.write_table(
                pa.table(
                    {
                        "capture_id": ["fixture"] * 4,
                        "flow_id": pa.array([1, 2, 3, 4], type=pa.uint64()),
                        "partition": ["train", "train", "validation", "test"],
                        "assigned_class": ["BENIGN", "Attack", "BENIGN", "BENIGN"],
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
                        "assigned_class": ["BENIGN", "Attack", "BENIGN", "BENIGN"],
                        "a": pa.array([1.0, 2.0, 100.0, 200.0], type=pa.float64()),
                        "b": pa.array([np.nan, 3.0, 100.0, 200.0], type=pa.float64()),
                    }
                ),
                part,
            )
            profile = {
                "input_features": ["a", "b"],
                "selected_features": ["a", "b"],
                "selected_indices": [0, 1],
                "imputation_values": [0.0, 5.0],
                "scaler_mean": [0.0, 0.0],
                "scaler_scale": [1.0, 1.0],
            }
            matrix_path, raw_counts = anomaly_eda.materialize_benign_train(
                "F3",
                [{"path": part.relative_to(root).as_posix(), "resolved_path": part}],
                flow_map,
                ["a", "b"],
                profile,
                1,
                root,
            )
            np.testing.assert_array_equal(np.load(matrix_path), [[1.0, 5.0]])
            self.assertEqual(raw_counts["b"]["nan_count"], 1)
            self.assertEqual(raw_counts["a"]["nan_count"], 0)

    def test_analysis_reports_correlations_and_all_hbos_candidates_without_selecting(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "run_log") as temporary:
            matrix_path = Path(temporary) / "matrix.npy"
            first = np.linspace(-2.0, 2.0, 200, dtype=np.float32)
            matrix = np.column_stack((first, first * 2.0, np.sin(first))).astype(np.float32)
            np.save(matrix_path, matrix, allow_pickle=False)
            result = anomaly_eda.analyze_matrix(
                matrix_path,
                ["first", "duplicate", "curved"],
                [0.0, 0.5, 1.0],
                100,
                0.98,
                [2, 4],
            )
            self.assertEqual(result["rows"], 200)
            self.assertEqual(result["sample"]["row_count"], 100)
            self.assertEqual(result["correlation_audit"]["pairs"][0]["left"], "first")
            self.assertEqual(result["correlation_audit"]["pairs"][0]["right"], "duplicate")
            self.assertFalse(result["correlation_audit"]["feature_pruning_performed"])
            self.assertEqual(set(result["hbos_candidate_diagnostics"]["candidates"]), {"2", "4"})
            self.assertFalse(result["hbos_candidate_diagnostics"]["winner_selected"])

    def test_quantile_diagnostics_collapse_duplicate_edges(self):
        matrix = np.asarray([[0.0], [0.0], [0.0], [0.0], [0.0], [0.0], [1.0], [2.0]])
        result = anomaly_eda.hbos_diagnostics(matrix, ["discrete"], [2, 4])
        four_bins = result["4"][0]
        self.assertLess(four_bins["effective_bin_count"], four_bins["requested_bin_count"])
        self.assertGreater(four_bins["collapsed_edge_count"], 0)
        self.assertFalse("winner" in four_bins)

    def test_report_binds_json_hash_and_marks_decisions_as_pending(self):
        receipt = {
            "status": "passed",
            "checkpoints": {
                "F3": {
                    "rows": 2,
                    "selected_feature_count": 1,
                    "sample": {"row_count": 2},
                    "raw_feature_checks": {
                        "a": {
                            "nan_count": 0,
                            "positive_infinity_count": 0,
                            "negative_infinity_count": 0,
                        }
                    },
                    "correlation_audit": {"reported_pair_count": 0, "pairs": []},
                    "hbos_candidate_diagnostics": {
                        "candidates": {
                            "2": [
                                {
                                    "effective_bin_count": 2,
                                    "collapsed_edge_count": 0,
                                }
                            ]
                        }
                    },
                }
            },
        }
        report = anomaly_eda.render_report(receipt, "abc123")
        self.assertIn("abc123", report)
        self.assertIn("chưa chọn candidate thắng", report)
        self.assertIn("Cổng quyết định", report)


if __name__ == "__main__":
    unittest.main()
