import unittest

import numpy as np

from nids_mvp.loafo_aggregate import (
    BOOTSTRAP_SAMPLES,
    MODEL_SPECS,
    _heatmap_svg,
    _line_svg,
    _validate_known_outputs,
    aggregate_macro,
    binary_novel_metrics,
    bootstrap_mean,
)


def family_result(offset: float = 0.0):
    checkpoints = {}
    for checkpoint in ("F3", "F5", "F7", "F9"):
        models = {}
        for model in MODEL_SPECS:
            models[model] = {
                "operating": {
                    "benign": {"positive_rate": 0.1 + offset},
                    "known_attack": {"positive_rate": 0.8 + offset},
                    "unknown_holdout": {"positive_rate": 0.6 + offset},
                },
                "novel_detection": {
                    "f1": 0.5 + offset,
                    "confusion_matrix": [[8, 2], [4, 6]],
                },
                "roc_auc": 0.7 + offset,
                "average_precision": 0.65 + offset,
                "roc_tpr": np.linspace(0.0, 1.0, 201).tolist(),
                "pr_precision": np.linspace(1.0, 0.0, 201).tolist(),
                "score_histogram": {
                    "benign": [1] * 20,
                    "known_attack": [2] * 20,
                    "unknown_holdout": [3] * 20,
                },
            }
        checkpoints[checkpoint] = {
            "models": models,
            "known_family": {
                "confidence_histogram": {
                    "known_attack": [2] * 20,
                    "unknown_holdout": [1] * 20,
                }
            },
        }
    importance = {
        checkpoint: {
            "feature_importance": {
                "flow_rf": [{"feature": "a", "importance": 1.0}],
                "rf_stacker": [{"feature": "a", "importance": 0.8}],
            }
        }
        for checkpoint in ("F3", "F5", "F7", "F9")
    }
    return {
        "prediction": {"checkpoints": checkpoints},
        "receipt": {"checkpoints": importance},
    }


class LoafoAggregateTests(unittest.TestCase):
    def test_bootstrap_is_deterministic_and_uses_family_units(self):
        first = bootstrap_mean([0.2, 0.4, 0.6])
        second = bootstrap_mean([0.2, 0.4, 0.6])
        self.assertEqual(first, second)
        self.assertEqual(first["family_units"], 3)
        self.assertEqual(first["bootstrap_samples"], BOOTSTRAP_SAMPLES)
        self.assertAlmostEqual(first["mean"], 0.4)

    def test_novel_metrics_exclude_known_attacks(self):
        roles = np.asarray(
            ["benign", "benign", "unknown_holdout", "unknown_holdout", "known_attack"]
        )
        prediction = np.asarray([0, 1, 0, 1, 0], dtype=np.uint8)
        metrics = binary_novel_metrics(roles, prediction)
        self.assertEqual(metrics["rows"], 4)
        self.assertEqual(metrics["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertAlmostEqual(metrics["f1"], 0.5)

    def test_known_outputs_use_nan_only_for_benign_rows(self):
        roles = np.asarray(["benign", "known_attack", "unknown_holdout"])
        top_class = np.asarray(["", "Bot", "DDoS"])
        second_class = np.asarray(["", "DDoS", "Bot"])
        top_probability = np.asarray([np.nan, 0.8, 0.7])
        second_probability = np.asarray([np.nan, 0.2, 0.3])
        _validate_known_outputs(
            roles,
            top_class,
            second_class,
            top_probability,
            second_probability,
            "F3",
        )
        top_probability[1] = np.nan
        with self.assertRaisesRegex(ValueError, "known-family probability"):
            _validate_known_outputs(
                roles,
                top_class,
                second_class,
                top_probability,
                second_probability,
                "F3",
            )

    def test_macro_aggregate_requires_nine_equal_family_units(self):
        families = [family_result(index / 100.0) for index in range(9)]
        aggregate = aggregate_macro(families)
        metric = aggregate["checkpoints"]["F3"]["models"]["flow_rf"]["metrics"][
            "unknown_holdout_recall"
        ]
        self.assertEqual(metric["family_units"], 9)
        self.assertAlmostEqual(metric["mean"], 0.64)
        self.assertEqual(
            aggregate["checkpoints"]["F3"]["models"]["flow_rf"][
                "pooled_experiment_confusion_matrix"
            ],
            [[72, 18], [36, 54]],
        )

    def test_macro_aggregate_rejects_case_study_inclusion(self):
        with self.assertRaisesRegex(ValueError, "exactly nine"):
            aggregate_macro([family_result()] * 10)

    def test_svg_helpers_are_self_contained(self):
        line = _line_svg([0.0, 1.0], {"A": [0.0, 1.0]}, "ROC")
        heatmap = _heatmap_svg(["Family"], ["F3"], [[0.5]], "Recall")
        self.assertIn("<svg", line)
        self.assertIn("ROC", line)
        self.assertIn("<svg", heatmap)
        self.assertNotIn("http://", line + heatmap)
        self.assertNotIn("https://", line + heatmap)


if __name__ == "__main__":
    unittest.main()
