import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_terminal_offline_limitations",
    ROOT / "scripts/build_terminal_offline_limitations.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class TerminalOfflineLimitationsTests(unittest.TestCase):
    def test_build_uses_locked_evidence(self):
        document = MODULE.build()
        contract = document["model_contract"]
        self.assertEqual(contract["selected_threshold"], 0.9984837643022101)
        self.assertEqual(contract["training_family_counts"]["Other"], 576)
        self.assertEqual(contract["target_families"], ["FTP-Bruteforce", "PortScan"])
        self.assertEqual(len(document["offline_rows"]), 14)
        self.assertEqual(len(document["supporting_sources"]), 18)

    def test_gate_examples_match_offline_summaries(self):
        document = MODULE.build()
        causes = {cause["id"]: cause for cause in document["causes"]}
        examples = causes["high_binary_attack_gate"]["examples"]
        self.assertEqual(examples["portscan_raw_argmax_portscan"], 84217)
        self.assertEqual(examples["portscan_final_portscan"], 82414)
        self.assertEqual(examples["ddos_top_attack_candidate_dos"], 15763)
        self.assertEqual(examples["ddos_final_dos"], 10725)
        self.assertEqual(causes["unproven_feature_level_cause"]["status"], "not_established")

    def test_markdown_preserves_interpretation_limits(self):
        text = MODULE.markdown(MODULE.build())
        self.assertIn("không cùng đơn vị", text)
        self.assertIn("chưa chứng minh một feature cụ thể", text)
        self.assertIn("test vẫn sealed", text)


if __name__ == "__main__":
    unittest.main()
