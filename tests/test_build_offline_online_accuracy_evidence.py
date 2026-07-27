import json
import unittest
from pathlib import Path

from scripts.build_offline_online_accuracy_evidence import build, render_markdown


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_JSON = ROOT / "run_log/full-flow-v1/thesis-evidence/offline-online-accuracy-20260809.json"
EVIDENCE_MD = ROOT / "run_log/full-flow-v1/thesis-evidence/offline-online-accuracy-20260809.md"


class OfflineOnlineAccuracyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = build()

    def test_accuracy_comes_from_the_offline_side_and_reports_both_rates(self):
        accuracy = self.evidence["terminal_v1"]["offline_accuracy"]
        micro = accuracy["micro_by_flow"]
        self.assertEqual(micro["correct"], 176383)
        self.assertEqual(micro["total"], 184571)
        self.assertAlmostEqual(micro["rate"], 176383 / 184571)
        self.assertEqual(accuracy["macro_by_family"]["families"], 13)
        self.assertLess(accuracy["macro_by_family"]["rate"], micro["rate"])

    def test_lossless_cases_reproduce_the_offline_result(self):
        cost = self.evidence["terminal_v1"]["cost_of_running_live"]
        self.assertTrue(cost["lossless_cases"])
        self.assertLess(cost["lossless_max_abs_delta_points"], 1.0)
        for row in cost["lossless_cases"]:
            self.assertAlmostEqual(
                row["offline_correct_rate"], row["live_expected_label_share"], places=2
            )

    def test_lossy_cases_are_ordered_by_loss_and_all_drop(self):
        lossy = self.evidence["terminal_v1"]["cost_of_running_live"]["lossy_cases"]
        self.assertTrue(lossy)
        rates = [row["live_imissed_rate"] for row in lossy]
        self.assertEqual(rates, sorted(rates, reverse=True))
        for row in lossy:
            self.assertLess(row["delta_points"], 0.0)

    def test_zero_inference_cases_are_marked_scope_mismatch_not_model_miss(self):
        excluded = self.evidence["terminal_v1"]["excluded_from_live_comparison"]
        self.assertEqual({row["case"] for row in excluded}, {"bot", "infiltration"})
        for row in excluded:
            self.assertIn("scope mismatch", row["reason"])

    def test_f9_family_window_has_no_offline_counterpart(self):
        family = self.evidence["f9"]["live_family_window"]
        self.assertIsNone(family["offline_counterpart"])
        self.assertIn("cannot", family["caveat"])
        self.assertEqual(family["total_alerts"], 10650)

    def test_f9_agreement_is_not_reported_as_correctness(self):
        head = self.evidence["f9"]["head_to_head"]
        self.assertEqual(head["comparable"], 10)
        self.assertEqual(head["agree"], 9)
        self.assertGreater(head["agree_wrong"], 0)
        self.assertIn("not that the answer is correct", head["caveat"])

    def test_every_supporting_source_is_hashed_and_test_partition_sealed(self):
        for source in self.evidence["supporting_sources"]:
            self.assertEqual(len(source["sha256"]), 64)
            self.assertTrue((ROOT / source["path"]).exists())
        partition = self.evidence["test_partition"]
        self.assertEqual(partition["state"], "sealed")
        self.assertEqual(partition["feature_reads"], 0)

    def test_published_files_match_a_fresh_build(self):
        published = json.loads(EVIDENCE_JSON.read_text(encoding="utf-8"))
        fresh = dict(self.evidence)
        published.pop("generated_at_utc")
        fresh.pop("generated_at_utc")
        self.assertEqual(published, fresh)
        self.assertIn("PortScan", EVIDENCE_MD.read_text(encoding="utf-8"))

    def test_markdown_is_vietnamese_and_states_the_key_limits(self):
        markdown = render_markdown(self.evidence)
        for required in (
            "không áp dụng",
            "tỷ lệ live không phải độ chính xác của model",
            "không có nghĩa là đáp án đúng",
            "sealed",
        ):
            self.assertIn(required, markdown)


if __name__ == "__main__":
    unittest.main()
