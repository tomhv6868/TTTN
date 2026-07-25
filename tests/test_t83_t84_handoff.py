import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/build_t83_t84_handoff.py"


def load_module():
    spec = importlib.util.spec_from_file_location("t83_t84_handoff", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


t8 = load_module()


def valid_receipt():
    return {
        "task": t8.TASK,
        "status": "accepted_for_demo",
        "reproducibility": {
            "benchmark": {
                "status": "accepted_for_speed_run_demo",
                "receipt_sha256": t8.T74_T76_SHA256,
                "formal_phase_7_acceptance": False,
            }
        },
    }


def valid_report():
    return (
        "unknown_candidate không đồng nghĩa với zero-day thực tế; "
        "PortScan recall 0%; VMware không phải bằng chứng hiệu năng production; "
        "[5.000, 10.000) pps; 195,832 flows/s; "
        "0,079/0,516/0,858 microsecond; 4,771/6,358/8,317 ms; "
        "4,514/6,021/7,026 ms; synthetic multi-flow TCP F9 không phải "
        "production traffic mix; 408 packet; 202 parser errors; "
        "identity-level delivery; T6.5 async queue; 703,99 alerts/hour; "
        "detection study T8.1"
    )


class HandoffTests(unittest.TestCase):
    def test_command_registry_does_not_invent_benchmark(self):
        registry = t8.commands()
        benchmark = registry["benchmark"]
        self.assertEqual("accepted_for_speed_run_demo", benchmark["status"])
        self.assertEqual(t8.T74_T76_SHA256, benchmark["receipt_sha256"])
        self.assertFalse(benchmark["formal_phase_7_acceptance"])
        self.assertIsNone(benchmark["rerun_command"])
        self.assertIn(
            "python scripts/build_t74_t76_speedrun_acceptance.py validate",
            benchmark["validation_commands"],
        )
        self.assertIn("nids_demo_replay", registry["offline_replay_ubuntu"][-1])

    def test_acceptance_requires_speed_run_scope_and_disclaimers(self):
        receipt = valid_receipt()
        report = valid_report()
        t8.validate_acceptance(receipt, report)
        overstated = copy.deepcopy(receipt)
        overstated["reproducibility"]["benchmark"]["formal_phase_7_acceptance"] = True
        with self.assertRaisesRegex(ValueError, "formal Phase 7"):
            t8.validate_acceptance(overstated, report)
        with self.assertRaisesRegex(ValueError, "delivery limit"):
            t8.validate_acceptance(receipt, report.replace("identity-level delivery", "delivery"))

    def test_speed_run_receipt_contract_is_locked(self):
        receipt = t8.load_json(ROOT / t8.T74_T76_RECEIPT)
        t8.validate_speed_run_receipt(receipt)
        drifted = copy.deepcopy(receipt)
        drifted["t7_4_capacity"]["baseline"]["maximum_precisely_located"] = True
        with self.assertRaisesRegex(ValueError, "maximum_precisely_located"):
            t8.validate_speed_run_receipt(drifted)

    def test_vi_number_uses_report_separators(self):
        self.assertEqual("1.800.000", t8.vi_number(1_800_000))
        self.assertEqual("999,982", t8.vi_number(999.982152981855, 3))

    def test_workspace_command_targets_exist(self):
        missing = [path for path in t8.COMMAND_TARGETS if not (ROOT / path).is_file()]
        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
