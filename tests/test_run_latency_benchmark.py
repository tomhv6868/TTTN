import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.run_latency_benchmark import (
    build_contract,
    human_ns,
    print_report,
    read_summary,
)


ROOT = Path(__file__).resolve().parents[1]


class HumanReadableTests(unittest.TestCase):
    def test_units_switch_at_the_right_thresholds(self):
        self.assertEqual(human_ns(999), "999 ns")
        self.assertEqual(human_ns(1_000), "1.00 us")
        self.assertEqual(human_ns(1_500_000), "1.50 ms")
        self.assertEqual(human_ns(2_000_000_000), "2.00 s")


class ContractTests(unittest.TestCase):
    def test_contract_requests_benchmark_metrics(self):
        contract = build_contract("ftp-patator", "t91-latency-ftp-patator-test")
        self.assertIs(contract["benchmark_metrics"], True)

    def test_contract_keeps_the_shape_the_sensor_wrapper_validates(self):
        contract = build_contract("ftp-patator", "t91-latency-ftp-patator-test")
        self.assertEqual(contract["schema_version"], "2.0.0")
        self.assertEqual(contract["task"], "T9.1")
        self.assertEqual(contract["kind"], "terminal_live_run_contract")
        # The wrapper rejects a signal_only lifecycle with any other key set.
        self.assertEqual(
            set(contract["lifecycle"]),
            {"mode", "lease_timeout_seconds", "shutdown_grace_ms"},
        )
        self.assertEqual(set(contract["bounds"]), {"ready_timeout_seconds"})
        self.assertEqual(contract["output"], {"mode": "alerts_only"})
        self.assertIsNone(contract["topology"]["source_ip"])
        self.assertEqual(contract["topology"]["scope_mode"], "target_ip")

    def test_run_id_lands_in_a_dedicated_artifact_root(self):
        contract = build_contract("ftp-patator", "t91-latency-ftp-patator-test")
        self.assertEqual(contract["artifact_root"], "run_log/full-flow-v1/latency-live")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _write(self, records: list[dict]) -> Path:
        path = self.dir / "sensor.jsonl"
        path.write_text(
            "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
        )
        return path

    def test_summary_is_found_among_other_events(self):
        path = self._write(
            [
                {"event_type": "nids_terminal_live_ready"},
                {"event_type": "nids_terminal_flow_alert"},
                {"event_type": "nids_terminal_live_summary", "status": "passed"},
            ]
        )
        summary = read_summary(path)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["status"], "passed")

    def test_missing_latency_block_is_reported_as_a_failure_not_zeros(self):
        summary = {"status": "passed", "inferences": 5, "alerts": 3, "port_stats": {}}
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            ok = print_report(summary, ROOT / "fake.jsonl")
        self.assertFalse(ok)
        self.assertIn("KHONG CO KHOI latency_ns", buffer.getvalue())

    def test_report_prints_both_scopes_so_the_reader_cannot_conflate_sensors(self):
        summary = {
            "status": "passed",
            "inferences": 435,
            "alerts": 328,
            "port_stats": {"ipackets": 5833, "imissed": 0},
            "latency_ns": {
                "inference": {"observations": 435, "p50": 452029, "p95": 639331,
                              "p99": 900432, "max": 8468722},
                "alert": {"observations": 328, "p50": 1366438, "p95": 2089019,
                          "p99": 7476628, "max": 74657461367},
                "inference_scope": "model_call_only_features_already_built",
                "alert_scope": "last_capture_timestamp_ns_until_alert_written",
            },
        }
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            ok = print_report(summary, ROOT / "fake.jsonl")
        text = buffer.getvalue()
        self.assertTrue(ok)
        self.assertIn("model_call_only_features_already_built", text)
        self.assertIn("KHONG so truc tiep", text)
        self.assertIn("Mat 0 packet", text)

    def test_packet_loss_triggers_an_overload_warning(self):
        summary = {
            "status": "passed",
            "inferences": 10,
            "alerts": 5,
            "port_stats": {"ipackets": 1000, "imissed": 400},
            "latency_ns": {
                "inference": {"observations": 10, "p50": 1, "p95": 2, "p99": 3, "max": 4},
                "alert": {"observations": 5, "p50": 1, "p95": 2, "p99": 3, "max": 4},
                "inference_scope": "x",
                "alert_scope": "y",
            },
        }
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            print_report(summary, ROOT / "fake.jsonl")
        self.assertIn("qua tai", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
