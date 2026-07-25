import json
import unittest
from pathlib import Path

from scripts.measure_detection_latency import build, percentiles, render_markdown


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_JSON = ROOT / "run_log/full-flow-v1/thesis-evidence/detection-latency-20260809.json"


class PercentileTests(unittest.TestCase):
    def test_empty_input_reports_zero_samples_not_a_fake_zero_latency(self):
        self.assertEqual(percentiles([]), {"samples": 0})

    def test_nearest_rank_percentiles_are_actual_observations(self):
        stats = percentiles(list(range(1, 101)))
        self.assertEqual(stats["samples"], 100)
        self.assertEqual(stats["min_ns"], 1)
        self.assertEqual(stats["max_ns"], 100)
        for key in ("p50_ns", "p95_ns", "p99_ns"):
            self.assertIn(stats[key], range(1, 101))
        self.assertLessEqual(stats["p50_ns"], stats["p95_ns"])
        self.assertLessEqual(stats["p95_ns"], stats["p99_ns"])

    def test_single_sample_collapses_every_percentile(self):
        stats = percentiles([7])
        self.assertEqual({stats["p50_ns"], stats["p95_ns"], stats["p99_ns"], stats["max_ns"]}, {7})


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = build()

    def test_f9_capture_to_inference_is_measured_from_real_alerts(self):
        stats = self.evidence["f9"]["capture_to_inference_ns"]["overall"]
        self.assertEqual(stats["samples"], 10665)
        self.assertGreater(stats["min_ns"], 0)
        self.assertLessEqual(stats["p50_ns"], stats["p95_ns"])
        self.assertLessEqual(stats["p99_ns"], stats["max_ns"])

    def test_benchmark_run_supplies_inference_and_alert_latency(self):
        bench = self.evidence["f9"]["benchmark_runs"]
        self.assertTrue(bench["available"])
        usable = [r for r in bench["runs"] if r["latency_ns"]["inference"]["observations"]]
        self.assertTrue(usable)
        run = usable[0]
        for key in ("parse", "pipeline", "inference", "alert"):
            block = run["latency_ns"][key]
            self.assertLessEqual(block["p50"], block["p95"])
            self.assertLessEqual(block["p95"], block["p99"])
            self.assertLessEqual(block["p99"], block["max"])

    def test_inference_bucket_is_documented_as_more_than_the_model_call(self):
        semantics = self.evidence["f9"]["benchmark_runs"]["semantics"]
        self.assertIn("NOT the model call alone", semantics["inference"])
        self.assertIn("feature encoding", semantics["inference"])

    def test_failed_benchmark_attempts_are_kept_and_marked_by_zero_observations(self):
        runs = self.evidence["f9"]["benchmark_runs"]["runs"]
        self.assertGreater(len(runs), 1, "phai giu ca cac lan chay hong")
        empty = [r for r in runs if not r["latency_ns"]["inference"]["observations"]]
        self.assertTrue(empty, "lan chay khong ra inference phai duoc giu lai")

    def test_packet_loss_is_recorded_next_to_the_latency_numbers(self):
        usable = [
            r for r in self.evidence["f9"]["benchmark_runs"]["runs"]
            if r["latency_ns"]["inference"]["observations"]
        ]
        for run in usable:
            self.assertIsNotNone(run["imissed_rate"])
            self.assertGreaterEqual(run["imissed_rate"], 0.0)

    def test_terminal_is_now_instrumented_and_measured_without_packet_loss(self):
        terminal = self.evidence["terminal_v1"]
        self.assertTrue(terminal["instrumented"])
        usable = [
            r for r in terminal["benchmark_runs"]["runs"]
            if r["latency_ns"]["inference"]["observations"]
        ]
        self.assertTrue(usable)
        run = usable[0]
        self.assertEqual(run["port_imissed"], 0, "phep do sach thi imissed phai bang 0")
        for key in ("inference", "alert"):
            block = run["latency_ns"][key]
            self.assertGreater(block["observations"], 0)
            self.assertLessEqual(block["p50"], block["p95"])
            self.assertLessEqual(block["p95"], block["p99"])
            self.assertLessEqual(block["p99"], block["max"])

    def test_terminal_scopes_are_declared_in_the_payload_itself(self):
        run = [
            r for r in self.evidence["terminal_v1"]["benchmark_runs"]["runs"]
            if r["latency_ns"]["inference"]["observations"]
        ][0]
        self.assertEqual(
            run["latency_ns"]["inference_scope"], "model_call_only_features_already_built"
        )
        self.assertEqual(
            run["latency_ns"]["alert_scope"], "last_capture_timestamp_ns_until_alert_written"
        )

    def test_the_two_sensors_are_never_presented_as_one_column(self):
        gaps = self.evidence["measurement_gaps"]
        self.assertTrue(any("Never put them in one column" in gap for gap in gaps))
        semantics = self.evidence["terminal_v1"]["benchmark_runs"]["semantics"]
        self.assertIn("not comparable", semantics["inference"])
        self.assertIn("wait for the flow to close", semantics["alert"])

    def test_sources_are_hashed_and_test_partition_sealed(self):
        self.assertTrue(self.evidence["supporting_sources"])
        for source in self.evidence["supporting_sources"]:
            self.assertEqual(len(source["sha256"]), 64)
            self.assertTrue((ROOT / source["path"]).exists())
        self.assertEqual(self.evidence["test_partition"]["state"], "sealed")

    def test_published_json_matches_a_fresh_build(self):
        published = json.loads(EVIDENCE_JSON.read_text(encoding="utf-8"))
        fresh = dict(self.evidence)
        published.pop("generated_at_utc")
        fresh.pop("generated_at_utc")
        self.assertEqual(published, fresh)

    def test_markdown_separates_the_three_quantities(self):
        markdown = render_markdown(self.evidence)
        self.assertIn("chặn dưới", markdown)
        self.assertIn("KHÔNG phải riêng lời gọi model", markdown)
        self.assertIn("tải bão hòa", markdown)
        self.assertIn("ĐÚNG là lời gọi model", markdown)
        self.assertIn("Không bao giờ xếp chung một cột", markdown)


if __name__ == "__main__":
    unittest.main()
