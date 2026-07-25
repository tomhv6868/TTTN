import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/build_t81_t82_demo_acceptance.py"


def load_module():
    spec = importlib.util.spec_from_file_location("t81_t82_acceptance", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


t8 = load_module()


def metric(mean):
    return {
        "mean": mean,
        "ci95_low": max(0.0, mean - 0.1),
        "ci95_high": min(1.0, mean + 0.1),
        "family_units": 9,
    }


def model(value):
    return {
        "metrics": {
            "known_attack_recall": metric(value),
            "unknown_holdout_recall": metric(value / 2),
            "benign_fpr": metric(value / 100),
            "novel_f1": metric(value / 3),
        }
    }


class DemoAcceptanceTests(unittest.TestCase):
    def test_detection_study_preserves_three_configuration_groups(self):
        models = {
            "flow_rf": model(0.9),
            "hbos": model(0.1),
            "isolation_forest": model(0.2),
            "rf_stacker": model(0.8),
        }
        acceptance = {
            "analysis": {
                "macro_aggregate": {
                    "checkpoints": {
                        checkpoint: {"models": models}
                        for checkpoint in t8.CHECKPOINTS
                    }
                }
            }
        }
        result = t8.build_detection_study(acceptance)
        self.assertEqual(t8.CHECKPOINTS, tuple(result))
        self.assertEqual(
            ("flow_rf", "anomaly_only", "rf_stacker"),
            tuple(result["F9"]),
        )
        self.assertEqual(
            "independent_benign_only_baselines_no_ensemble",
            result["F9"]["anomaly_only"]["interpretation"],
        )

    def test_metric_summary_rejects_wrong_family_unit(self):
        invalid = model(0.5)
        invalid["metrics"]["known_attack_recall"]["family_units"] = 8
        with self.assertRaisesRegex(ValueError, "family unit count"):
            t8.model_summary(invalid)

    def test_receipt_validation_rejects_fabricated_alert_rate(self):
        receipt = {
            "task": t8.TASK,
            "status": "accepted_for_demo",
            "scope": {"model_training_performed": False},
            "detection_study": {
                "alerts_per_hour": {"value": 12.0},
                "checkpoints": {checkpoint: {} for checkpoint in t8.CHECKPOINTS},
            },
            "model_selection": {
                "selected_binary_classifier": "flow_rf",
                "stacker_improvement_claim_supported": False,
            },
        }
        with self.assertRaisesRegex(ValueError, "must not be fabricated"):
            t8.validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
