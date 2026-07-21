from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from nids_mvp import preprocessing


ROOT = Path(__file__).resolve().parents[1]


def serving_profile() -> dict:
    return {
        "input_features": ["a", "constant", "c"],
        "imputation_values": [2.0, 5.0, 11.0],
        "selected_indices": [0, 2],
        "scaler_mean": [2.0, 11.0],
        "scaler_scale": [1.0, 2.0],
    }


class T41PreprocessingTests(unittest.TestCase):
    def test_contract_locks_confirmed_preprocessing_and_profiles(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-preprocessing-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["preprocessing"]["imputer"]["strategy"], "median")
        self.assertEqual(contract["preprocessing"]["scaler"]["algorithm"], "sklearn.preprocessing.StandardScaler")
        self.assertEqual(contract["preprocessing"]["output_dtype"], "float32")
        self.assertEqual(set(contract["profiles"]), set(preprocessing.PROFILES))
        self.assertFalse(contract["profiles"]["supervised_known"]["loafo_reuse_allowed"])
        self.assertTrue(contract["loafo"]["supervised_preprocessing_refit_per_holdout_required"])
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_serving_transform_imputes_nan_scales_and_casts_float32(self):
        values = np.array([[1.0, 5.0, np.nan], [3.0, 5.0, 15.0]], dtype=np.float64)
        result = preprocessing.transform_with_artifact(
            values, ["a", "constant", "c"], serving_profile()
        )
        expected = np.array([[-1.0, 0.0], [1.0, 2.0]], dtype=np.float32)
        self.assertEqual(result.dtype, np.float32)
        np.testing.assert_array_equal(result, expected)

    def test_serving_transform_rejects_infinity_and_feature_order_drift(self):
        with self.assertRaisesRegex(ValueError, "infinity"):
            preprocessing.transform_with_artifact(
                np.array([[1.0, 5.0, np.inf]]), ["a", "constant", "c"], serving_profile()
            )
        with self.assertRaisesRegex(ValueError, "order or schema"):
            preprocessing.transform_with_artifact(
                np.array([[1.0, 5.0, 3.0]]), ["c", "constant", "a"], serving_profile()
            )

    def test_fit_profile_drops_only_constant_and_proves_bitwise_parity(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "run_log") as temporary:
            scratch = Path(temporary)
            path = scratch / "matrix.npy"
            matrix = np.lib.format.open_memmap(path, mode="w+", dtype=np.float64, shape=(5, 3))
            matrix[:] = [
                [1.0, 5.0, 9.0],
                [2.0, 5.0, np.nan],
                [3.0, 5.0, 11.0],
                [4.0, 5.0, 13.0],
                [5.0, 5.0, 15.0],
            ]
            matrix.flush()
            artifact = preprocessing.fit_profile(
                path, "F3", "supervised_known", ["a", "constant", "c"], ["constant"], 5, scratch
            )
            del matrix
            self.assertEqual(artifact["dropped_constant_features"], ["constant"])
            self.assertEqual(artifact["selected_features"], ["a", "c"])
            self.assertEqual(artifact["imputation_values"], [3.0, 5.0, 12.0])
            self.assertEqual(artifact["parity"]["status"], "passed")
            self.assertEqual(artifact["parity"]["comparison"], "bitwise_equal_float32")

    def test_materialization_uses_only_train_and_benign_profile_is_stricter(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "run_log") as temporary:
            root = Path(temporary)
            capture = "fixture"
            flow_map = root / "known-flow-split.parquet"
            pq.write_table(
                pa.table(
                    {
                        "capture_id": [capture] * 4,
                        "flow_id": pa.array([1, 2, 3, 4], type=pa.uint64()),
                        "partition": ["train", "train", "validation", "test"],
                        "assigned_class": ["BENIGN", "Attack", "BENIGN", "Attack"],
                    }
                ),
                flow_map,
            )
            part = root / "checkpoint=F3" / f"capture_id={capture}" / "part.parquet"
            part.parent.mkdir(parents=True)
            pq.write_table(
                pa.table(
                    {
                        "flow_id": pa.array([1, 2, 3, 4], type=pa.uint64()),
                        "capture_id": [capture] * 4,
                        "assigned_class": ["BENIGN", "Attack", "BENIGN", "Attack"],
                        "a": pa.array([10.0, 20.0, 30.0, 40.0], type=pa.float64()),
                        "b": pa.array([1.0, 2.0, 3.0, 4.0], type=pa.float64()),
                    }
                ),
                part,
            )
            paths = preprocessing.materialize_training_matrices(
                "F3",
                [{"path": f"checkpoint=F3/capture_id={capture}/part.parquet", "resolved_path": part}],
                flow_map,
                ["a", "b"],
                {"supervised_known": {"F3": 2}, "anomaly_benign": {"F3": 1}},
                root,
            )
            np.testing.assert_array_equal(np.load(paths["supervised_known"]), [[10.0, 1.0], [20.0, 2.0]])
            np.testing.assert_array_equal(np.load(paths["anomaly_benign"]), [[10.0, 1.0]])

    def test_materialization_rejects_snapshot_flow_map_label_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "run_log") as temporary:
            root = Path(temporary)
            flow_map = root / "flow-map.parquet"
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
                    }
                ),
                part,
            )
            with self.assertRaisesRegex(ValueError, "snapshot/flow-map drift"):
                preprocessing.materialize_training_matrices(
                    "F3",
                    [{"path": "checkpoint=F3/capture_id=fixture/part.parquet", "resolved_path": part}],
                    flow_map,
                    ["a"],
                    {"supervised_known": {"F3": 1}, "anomaly_benign": {"F3": 0}},
                    root,
                )


if __name__ == "__main__":
    unittest.main()
