from __future__ import annotations

import unittest

import numpy as np

from nids_mvp import threshold_calibration


class ThresholdCalibrationTest(unittest.TestCase):
    def test_candidate_thresholds_are_finite_unique_and_ordered(self) -> None:
        values = np.linspace(-2.0, 3.0, 1001)

        thresholds = threshold_calibration.candidate_thresholds(
            values,
            maximum_individual_fpr=0.1,
            points=21,
        )

        self.assertTrue(np.isfinite(thresholds).all())
        self.assertTrue(np.all(thresholds[1:] > thresholds[:-1]))
        self.assertGreater(thresholds[-1], values.max())

    def test_calibration_keeps_flow_threshold_and_respects_fpr_cap(self) -> None:
        flow = np.array(
            [0.1] * 10 + [0.9, 0.8, 0.7, 0.6],
            dtype=np.float64,
        )
        hbos = np.array(
            [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 4.0, 5.0]
            + [0.0] * 4,
            dtype=np.float64,
        )
        isolation = np.array(
            [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 5.0, 4.0]
            + [0.0] * 4,
            dtype=np.float64,
        )
        labels = np.array([0] * 10 + [1] * 4, dtype=np.uint8)
        family_scores = (
            np.array([0.1, 0.2, 0.3], dtype=np.float64),
            np.array([10.0, 9.0, 8.0], dtype=np.float64),
            np.array([10.0, 9.0, 8.0], dtype=np.float64),
        )

        result = threshold_calibration.calibrate_checkpoint(
            flow,
            hbos,
            isolation,
            labels,
            {"Family A": family_scores, "PortScan": family_scores},
            ("Family A",),
            fpr_cap=0.2,
            maximum_individual_fpr=0.4,
            grid_points=9,
        )

        self.assertEqual(0.5, result["flow_rf_threshold"])
        self.assertLessEqual(result["validation"]["fusion_fpr"], 0.2)
        self.assertEqual(1.0, result["validation"]["known_recall"])
        self.assertEqual(
            1.0,
            result["loafo"]["macro_unknown_candidate_recall"],
        )
        self.assertEqual(
            1.0,
            result["loafo"]["case_study_unknown_candidate_recall"][
                "PortScan"
            ],
        )

    def test_calibration_rejects_missing_confirmatory_family(self) -> None:
        values = np.array([0.0, 0.1, 0.8, 0.9], dtype=np.float64)
        labels = np.array([0, 0, 1, 1], dtype=np.uint8)

        with self.assertRaisesRegex(ValueError, "incomplete"):
            threshold_calibration.calibrate_checkpoint(
                values,
                values,
                values,
                labels,
                {},
                ("Family A",),
                fpr_cap=0.5,
                maximum_individual_fpr=0.5,
                grid_points=3,
            )


if __name__ == "__main__":
    unittest.main()
