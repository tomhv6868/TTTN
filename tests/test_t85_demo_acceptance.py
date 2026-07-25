import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/build_t85_demo_acceptance.py"


def load_module():
    spec = importlib.util.spec_from_file_location("t85_demo_acceptance", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acceptance = load_module()


def base_receipt():
    return {
        "schema_version": "1.0.0",
        "task": "T8.5",
        "kind": "demo_critical_path_acceptance",
        "status": "passed",
        "scope": {"formal_phase_8_acceptance": False},
        "result": {
            "summary_status": "passed",
            "ubuntu_rollback_status": "passed",
            "kali_rollback_status": "passed",
        },
        "preserved_live_evidence": {"value": 1},
    }


class DemoAcceptanceTests(unittest.TestCase):
    def test_refresh_locks_segment_order_and_preserves_live_evidence(self):
        receipt = acceptance.refresh_receipt(
            base_receipt(),
            ROOT,
            "2026-07-26T00:00:00+00:00",
        )

        self.assertEqual(
            receipt["preserved_live_evidence"],
            {"value": 1},
        )
        workflow = receipt["segmented_full_replay_workflow"]
        self.assertEqual(workflow["status"], "ready_for_new_evidence")
        self.assertFalse(workflow["execution_completed"])
        self.assertTrue(workflow["topspeed_retained"])
        self.assertFalse(workflow["source_pcap_delta_time_preserved"])
        self.assertEqual(
            [segment["id"] for segment in workflow["ordered_segments"]],
            ["monday", "tuesday", "wednesday", "thursday", "friday"],
        )
        historical = receipt["supplemental_handoff_evidence"][
            "historical_combined_full_replay_audit"
        ]
        self.assertEqual(historical["status"], "failed")
        self.assertEqual(historical["chronology_status"], "not_verifiable")

    def test_validation_rejects_promoting_historical_chronology(self):
        receipt = acceptance.refresh_receipt(
            base_receipt(),
            ROOT,
            "2026-07-26T00:00:00+00:00",
        )
        drifted = copy.deepcopy(receipt)
        drifted["supplemental_handoff_evidence"][
            "historical_combined_full_replay_audit"
        ]["chronology_status"] = "passed"

        with self.assertRaisesRegex(ValueError, "chronology_status"):
            acceptance.validate_receipt(drifted, ROOT)

    def test_validation_rejects_topspeed_delta_time_claim(self):
        receipt = acceptance.refresh_receipt(
            base_receipt(),
            ROOT,
            "2026-07-26T00:00:00+00:00",
        )
        drifted = copy.deepcopy(receipt)
        drifted["segmented_full_replay_workflow"][
            "source_pcap_delta_time_preserved"
        ] = True

        with self.assertRaisesRegex(ValueError, "source_pcap_delta_time_preserved"):
            acceptance.validate_receipt(drifted, ROOT)

    def test_validation_rejects_workflow_file_hash_drift(self):
        receipt = acceptance.refresh_receipt(
            base_receipt(),
            ROOT,
            "2026-07-26T00:00:00+00:00",
        )
        drifted = copy.deepcopy(receipt)
        drifted["segmented_full_replay_workflow"]["workflow_files"][
            "streaming_auditor"
        ]["sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "streaming_auditor"):
            acceptance.validate_receipt(drifted, ROOT)

    def test_current_task_reference_is_content_addressed(self):
        current_task = acceptance.load_json(
            ROOT / "config/agent/current-task.json"
        )
        acceptance.validate_current_task(current_task, ROOT)

        drifted = copy.deepcopy(current_task)
        drifted["demo_acceptance"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "reference drifted: sha256"):
            acceptance.validate_current_task(drifted, ROOT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
