from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "score_terminal_flows_onnx", ROOT / "scripts" / "score_terminal_flows_onnx.py"
)
assert SPEC and SPEC.loader
SCORER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCORER)


class TerminalOfflineScorerTest(unittest.TestCase):
    def test_gate_can_override_attack_raw_argmax_to_benign(self):
        scored = SCORER.decide(
            [0.4, 0.1, 0.1, 0.3, 0.05, 0.05],
            ["Benign", "FTP", "SSH", "PortScan", "DoS", "Other"],
            0,
            0.998,
        )
        self.assertEqual("Benign", scored["raw_argmax"])
        self.assertEqual("PortScan", scored["top_attack_candidate"])
        self.assertEqual("Benign", scored["decision"])
        self.assertFalse(scored["gate_passed"])

    def test_passing_gate_selects_top_attack_class(self):
        scored = SCORER.decide(
            [0.001, 0.001, 0.002, 0.8, 0.15, 0.046],
            ["Benign", "FTP", "SSH", "PortScan", "DoS", "Other"],
            0,
            0.998,
        )
        self.assertEqual("PortScan", scored["decision"])
        self.assertTrue(scored["gate_passed"])

    def test_percentiles_are_interpolated(self):
        observed = SCORER.distribution([1.0, 2.0, 3.0, 4.0])
        self.assertEqual(2.5, observed["median"])
        self.assertEqual(1.75, observed["p25"])

    def test_batches_do_not_drop_the_final_partial_batch(self):
        observed = list(SCORER.batches(iter(range(5)), 2))
        self.assertEqual([[0, 1], [2, 3], [4]], observed)

    def test_locked_repo_bundle_passes_checksum_validation(self):
        observed = SCORER.verify_bundle(
            ROOT / "run_log" / "full-flow-v1" / "model" / "terminal-flow.bundle"
        )
        self.assertEqual("A", observed["manifest"]["selected_profile"])
        self.assertEqual(54, len(observed["selected_indices"]))
        self.assertEqual(0.9984837643022101, observed["threshold"])


if __name__ == "__main__":
    unittest.main()
