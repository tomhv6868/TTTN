import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/build_t74_t76_speedrun_acceptance.py"


def load_module():
    spec = importlib.util.spec_from_file_location("t74_t76_acceptance", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acceptance = load_module()


class SpeedRunAcceptanceTests(unittest.TestCase):
    def test_cpu_percent_uses_active_runtime(self):
        summary = {
            "active_duration_ns": 10_000_000_000,
            "process_resource": {
                "available": True,
                "user_cpu_us": 4_000_000,
                "system_cpu_us": 1_000_000,
            },
        }
        self.assertEqual(50.0, acceptance.cpu_percent(summary))

    def test_validation_rejects_fabricated_queue_pressure(self):
        receipt = {
            "task": acceptance.TASK,
            "status": "accepted_for_speed_run_demo",
            "scope": {"formal_phase_7_acceptance": False},
            "t7_4_capacity": {
                "baseline": {"maximum_precisely_located": False}
            },
            "t7_5_system_benchmark": {
                "alert_queue": {"pressure_available": True}
            },
            "t7_6_stability": {
                "status": "passed",
                "rollback_status": "passed",
                "port_imissed": 0,
                "port_rx_nombuf": 0,
            },
        }
        with self.assertRaisesRegex(ValueError, "pressure was fabricated"):
            acceptance.validate_receipt(receipt)

    def test_latency_is_converted_from_nanoseconds_to_milliseconds(self):
        summary = {
            "latency_ns": {
                "inference": {
                    "p50": 1_000_000,
                    "p95": 2_000_000,
                    "p99": 3_000_000,
                    "max": 4_000_000,
                }
            }
        }
        self.assertEqual(
            {"p50": 1.0, "p95": 2.0, "p99": 3.0, "max": 4.0},
            acceptance.latency_ms(summary, "inference"),
        )


if __name__ == "__main__":
    unittest.main()
