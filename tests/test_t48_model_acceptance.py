import json
import unittest
from pathlib import Path

import numpy as np

from nids_mvp.model_acceptance import (
    CHECKPOINTS,
    _validate_contract_semantics,
    cluster_metric_comparison,
    confusion_metrics,
    decide_model,
    join_prediction_groups,
    loafo_analysis,
    paired_family_bootstrap,
    render_report,
    stratified_cluster_draws,
)


ROOT = Path(__file__).resolve().parents[1]


def decision_contract():
    return {
        "claim_and_selection": {
            "improvement_claim": {
                "primary_ci_lower_bound_must_be_strictly_greater_than": 0.0,
            },
            "on_pass": {
                "phase_5_binary_classifier": "rf_stacker",
                "hbos_and_isolation_forest": "retain_for_phase_6_fusion",
                "flow_rf": "retain_as_baseline",
            },
            "on_fail": {
                "phase_5_binary_classifier": "flow_rf",
                "hbos_and_isolation_forest": "retain_for_phase_6_fusion",
                "rf_stacker": "retain_as_ablation",
            },
        },
        "safeguards": {
            "known_recall": {"minimum_delta": -0.002},
            "benign_fpr": {"maximum_delta": 0.0005},
        },
    }


def known_checkpoints(recall_delta=0.0, fpr_delta=0.0):
    return {
        checkpoint: {
            "comparisons": {
                "flow_rf": {
                    "recall": {"delta": recall_delta},
                    "fpr": {"delta": fpr_delta},
                }
            }
        }
        for checkpoint in CHECKPOINTS
    }


def synthetic_loafo_inputs():
    macro = [f"Family {index}" for index in range(9)]
    cases = [f"Case {index}" for index in range(4)]
    contract = {
        "family_scope": {
            "macro_aggregate": macro,
            "case_study_only": cases,
        },
        "comparisons": {"primary_confirmatory": "flow_rf"},
        "primary_endpoint": {
            "estimand": "synthetic equal-family checkpoint mean",
            "confidence_interval": {
                "samples": 1000,
                "seed": 1729,
                "level": 0.95,
            }
        },
    }
    per_family = {}
    for family_index, family in enumerate([*macro, *cases]):
        checkpoints = {}
        for checkpoint_index, checkpoint in enumerate(CHECKPOINTS):
            models = {}
            for model_index, model in enumerate(
                ("flow_rf", "hbos", "isolation_forest", "rf_stacker")
            ):
                value = 0.1 + family_index / 100.0 + checkpoint_index / 1000.0
                value += model_index / 10000.0
                models[model] = {
                    "unknown_holdout_recall": value,
                    "known_attack_recall": value,
                    "benign_fpr": value / 10.0,
                    "novel_detection": {"f1": value},
                    "roc_auc": value,
                    "average_precision": value,
                }
            checkpoints[checkpoint] = {"models": models}
        per_family[family] = {"checkpoints": checkpoints}
    acceptance = {
        "task": "T4.7",
        "kind": "loafo_rf300_aggregate_acceptance",
        "status": "passed",
        "analysis": {
            "totals": {
                "families": 13,
                "macro_families": 9,
                "case_studies": 4,
            },
            "policy": {
                "macro_family_order": macro,
                "case_study_family_order": cases,
            },
            "per_family": dict(sorted(per_family.items())),
        },
        "validation": {
            "all_family_receipts_verified": True,
            "all_metrics_recomputed_from_predictions": True,
            "all_prediction_hashes_and_rows_verified": True,
            "all_reload_parity_passed": True,
            "anomaly_models_benign_only_without_refit": True,
            "equal_family_macro_weighting": True,
            "holdout_absent_from_supervised_fit": True,
            "rf300_primary_final": True,
            "test_labels_excluded_from_fit_threshold_and_selection": True,
            "hooks_read_or_run": False,
            "dependency_or_environment_mutation": False,
        },
    }
    return contract, acceptance


class ModelAcceptanceTests(unittest.TestCase):
    def test_locked_contract_keeps_anomaly_baselines_independent(self):
        contract = json.loads(
            (
                ROOT / "config/cicids2017-model-acceptance-contract.json"
            ).read_text(encoding="utf-8")
        )
        _validate_contract_semantics(contract)
        baseline = contract["baseline_interpretation"]
        self.assertFalse(baseline["anomaly_ensemble_baseline_defined"])
        self.assertFalse(
            baseline["new_or_majority_vote_or_weighted_threshold_allowed"]
        )
        self.assertEqual(
            baseline["baseline_b"]["independent_models"],
            ["hbos", "isolation_forest"],
        )

    def test_family_bootstrap_is_deterministic_and_keeps_checkpoint_vector(self):
        deltas = np.asarray(
            [
                [0.1, 0.2, 0.3, 0.4],
                [-0.4, -0.3, -0.2, -0.1],
            ]
        )
        first = paired_family_bootstrap(deltas, samples=1000, seed=1729)
        second = paired_family_bootstrap(deltas, samples=1000, seed=1729)
        self.assertEqual(first, second)
        self.assertEqual(first["family_units"], 2)
        self.assertEqual(first["checkpoints_per_family"], 4)
        self.assertAlmostEqual(first["delta"], 0.0)
        with self.assertRaisesRegex(ValueError, "matrix"):
            paired_family_bootstrap(deltas.ravel(), samples=1000, seed=1729)

    def test_loafo_analysis_accepts_serialized_family_key_order(self):
        contract, acceptance = synthetic_loafo_inputs()
        result = loafo_analysis(contract, acceptance)
        self.assertEqual(
            result["comparisons"]["flow_rf"]["role"],
            "primary_confirmatory",
        )
        self.assertEqual(
            result["comparisons"]["hbos"]["role"],
            "secondary_descriptive",
        )
        self.assertTrue(result["policy"]["case_studies_excluded_from_inference"])

    def test_join_prediction_groups_rejects_identity_drift(self):
        lookup = {
            ("capture", 1): (("capture", 10), 0),
            ("capture", 2): (("capture", 10), 1),
        }
        groups = {("capture", 10): 0}
        row_groups, audit = join_prediction_groups(
            np.asarray(["capture", "capture"]),
            np.asarray([1, 2], dtype=np.uint64),
            np.asarray([0, 1], dtype=np.uint8),
            lookup,
            groups,
        )
        self.assertTrue(np.array_equal(row_groups, np.asarray([0, 0])))
        self.assertEqual(audit["compound_groups"], 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            join_prediction_groups(
                np.asarray(["capture", "capture"]),
                np.asarray([1, 1], dtype=np.uint64),
                np.asarray([0, 0], dtype=np.uint8),
                lookup,
                groups,
            )
        with self.assertRaisesRegex(ValueError, "absent"):
            join_prediction_groups(
                np.asarray(["capture"]),
                np.asarray([3], dtype=np.uint64),
                np.asarray([0], dtype=np.uint8),
                lookup,
                groups,
            )
        with self.assertRaisesRegex(ValueError, "label"):
            join_prediction_groups(
                np.asarray(["capture"]),
                np.asarray([2], dtype=np.uint64),
                np.asarray([0], dtype=np.uint8),
                lookup,
                groups,
            )

    def test_cluster_bootstrap_is_paired_and_stratified(self):
        groups = [
            ("capture-a", 1),
            ("capture-a", 2),
            ("capture-b", 1),
        ]
        draws = stratified_cluster_draws(groups, samples=1000, seed=1729)
        self.assertEqual(set(draws), {"capture-a", "capture-b"})
        self.assertEqual(draws["capture-a"].shape, (1000, 2))
        self.assertEqual(draws["capture-b"].shape, (1000, 1))
        baseline = np.asarray(
            [
                [90, 10, 20, 80],
                [80, 20, 30, 70],
                [95, 5, 10, 90],
            ],
            dtype=np.int64,
        )
        candidate = np.asarray(
            [
                [91, 9, 15, 85],
                [81, 19, 25, 75],
                [96, 4, 5, 95],
            ],
            dtype=np.int64,
        )
        first = cluster_metric_comparison(candidate, baseline, draws)
        second = cluster_metric_comparison(candidate, baseline, draws)
        self.assertEqual(first, second)
        self.assertGreater(first["recall"]["delta"], 0.0)
        self.assertLess(first["fpr"]["delta"], 0.0)
        self.assertFalse(first["f1"]["inferential_claim_allowed"])

    def test_confusion_metrics_use_locked_binary_formulas(self):
        metrics = confusion_metrics([90, 10, 20, 80])
        self.assertAlmostEqual(metrics["recall"], 0.8)
        self.assertAlmostEqual(metrics["fpr"], 0.1)
        self.assertAlmostEqual(metrics["f1"], 160 / 190)

    def test_decision_falls_back_when_primary_interval_contains_zero(self):
        result = decide_model(
            decision_contract(),
            {"ci95_low": -0.01},
            known_checkpoints(),
        )
        self.assertFalse(result["stacker_improvement_claim_supported"])
        self.assertTrue(result["all_safeguards_passed"])
        self.assertEqual(
            result["selection"]["phase_5_binary_classifier"],
            "flow_rf",
        )
        self.assertFalse(result["t5_1_authorized"])

    def test_decision_requires_every_checkpoint_safeguard(self):
        known = known_checkpoints()
        known["F7"]["comparisons"]["flow_rf"]["recall"]["delta"] = -0.0021
        result = decide_model(
            decision_contract(),
            {"ci95_low": 0.01},
            known,
        )
        self.assertTrue(result["primary_passed"])
        self.assertFalse(result["all_safeguards_passed"])
        self.assertEqual(
            result["selection"]["phase_5_binary_classifier"],
            "flow_rf",
        )

    def test_decision_selects_stacker_only_when_all_gates_pass(self):
        result = decide_model(
            decision_contract(),
            {"ci95_low": 0.01},
            known_checkpoints(recall_delta=-0.002, fpr_delta=0.0005),
        )
        self.assertTrue(result["stacker_improvement_claim_supported"])
        self.assertEqual(
            result["selection"]["phase_5_binary_classifier"],
            "rf_stacker",
        )
        self.assertFalse(result["t5_1_authorized"])

    def test_report_is_self_contained_and_states_fallback(self):
        contract = decision_contract()
        primary = {
            "delta": -0.02,
            "ci95_low": -0.05,
            "ci95_high": 0.001,
        }
        known = known_checkpoints()
        decision = decide_model(contract, primary, known)
        analysis = {
            "loafo": {
                "comparisons": {
                    baseline: {
                        "role": "primary_confirmatory"
                        if baseline == "flow_rf"
                        else "secondary_descriptive",
                        "global_novel_f1": primary,
                    }
                    for baseline in ("flow_rf", "hbos", "isolation_forest")
                }
            },
            "decision": decision,
        }
        report = render_report(analysis).decode("utf-8")
        self.assertIn("flow_rf", report)
        self.assertIn("Không có đủ bằng chứng", report)
        self.assertNotIn("http://", report)
        self.assertNotIn("https://", report)
        self.assertNotIn("<script", report.lower())


if __name__ == "__main__":
    unittest.main()
