import unittest

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from nids_mvp.tree_convergence import cumulative_probabilities, select_tree_count


class TreeConvergenceTests(unittest.TestCase):
    def test_cumulative_probabilities_and_parity(self):
        x = np.asarray([[0.0], [1.0], [0.1], [0.9]], dtype=np.float32)
        y = np.asarray([0, 1, 0, 1], dtype=np.uint8)
        model = RandomForestClassifier(n_estimators=5, random_state=7, n_jobs=1)
        model.fit(x, y)
        curves = cumulative_probabilities(model, x, [1, 3, 5])
        self.assertEqual(set(curves), {1, 3, 5})
        np.testing.assert_allclose(curves[5], model.predict_proba(x), rtol=0.0, atol=1e-12)

    def test_selection_uses_smallest_passing_candidate(self):
        point = lambda f1, recall, fpr: {"metrics": {"macro_f1": f1, "recall": recall, "fpr": fpr}}
        multi = lambda f1, bal: {"metrics": {"macro_family_f1": f1, "balanced_accuracy_supported_families": bal}}
        results = {
            "flow_rf": {"F3": {"points": {"50": point(.9, .9, .01), "300": point(.9, .9, .01)}}},
            "rf_stacker": {"F3": {"points": {"50": point(.9, .9, .01), "300": point(.9, .9, .01)}}},
            "known_family_rf": {"F3": {"points": {"50": multi(.9, .8), "300": multi(.9, .8)}}},
        }
        benchmark = {
            "reference_tree_count": 300,
            "candidate_tree_counts": [50, 300],
            "binary_gates": {"macro_f1_max_drop": .002, "attack_recall_max_drop": .002, "benign_fpr_max_increase": .0005},
            "multiclass_gates": {"macro_family_f1_max_drop": .002, "balanced_accuracy_max_drop": .002},
        }
        selected, decisions = select_tree_count(results, benchmark)
        self.assertEqual(selected, 50)
        self.assertTrue(decisions["50"]["passed"])


if __name__ == "__main__":
    unittest.main()
