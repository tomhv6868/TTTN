from __future__ import annotations

import unittest

from nids_mvp import model_parity


class ModelParityTest(unittest.TestCase):
    def test_input_matrix_covers_finite_ranges_and_imputation(self) -> None:
        cases = model_parity.parity_inputs()

        self.assertEqual(
            {
                "ascending",
                "zeros",
                "negative",
                "alternating",
                "wide",
                "missing",
            },
            set(cases),
        )
        self.assertTrue(all(values.shape == (54,) for values in cases.values()))
        self.assertEqual(8, int(sum(cases["missing"] != cases["missing"])))

    def test_compare_scores_accepts_values_within_tolerance(self) -> None:
        expected = {
            "flow_attack_probability": 0.5,
            "flow_attack": True,
            "known_family_probabilities": [0.25, 0.75],
            "known_family_index": 1,
            "hbos_raw": 1.0,
            "hbos_normalized": 2.0,
            "hbos_threshold_exceeded": True,
            "isolation_forest_raw": 3.0,
            "isolation_forest_normalized": 4.0,
            "isolation_forest_threshold_exceeded": False,
        }
        observed = dict(expected)
        observed["flow_attack_probability"] = 0.500001
        observed["known_family_probabilities"] = [0.250001, 0.749999]

        maximum = model_parity.compare_scores(expected, observed)

        self.assertLessEqual(maximum, model_parity.REFERENCE_ABSOLUTE_TOLERANCE)

    def test_compare_scores_rejects_exact_field_drift(self) -> None:
        expected = {
            "flow_attack_probability": 0.5,
            "flow_attack": True,
            "known_family_probabilities": [0.25, 0.75],
            "known_family_index": 1,
            "hbos_raw": 1.0,
            "hbos_normalized": 2.0,
            "hbos_threshold_exceeded": True,
            "isolation_forest_raw": 3.0,
            "isolation_forest_normalized": 4.0,
            "isolation_forest_threshold_exceeded": False,
        }
        observed = dict(expected)
        observed["flow_attack"] = False

        with self.assertRaisesRegex(ValueError, "flow_attack"):
            model_parity.compare_scores(expected, observed)


if __name__ == "__main__":
    unittest.main()
