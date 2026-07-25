from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import t85_demo_scenario as scenario


class T85DemoScenarioTests(unittest.TestCase):
    def test_manifest_locks_taxonomy_and_claim_boundary(self) -> None:
        config = scenario.load_json(scenario.DEFAULT_CONFIG)
        executable = [case for case in config["cases"] if case["tier"] != "presentation_only"]
        modeled = [case for case in executable if case["model_available"]]
        unavailable = [case for case in executable if not case["model_available"]]

        self.assertEqual(len(executable), 14)
        self.assertEqual(len(modeled), 13)
        self.assertEqual([case["label"] for case in unavailable], ["Heartbleed"])
        self.assertEqual(config["taxonomy"]["source_attack_label_count"], 14)
        self.assertFalse(config["formal_acceptance"])
        self.assertEqual(config["artifact_root"], "run_log/t8.5/scenarios")

    def test_run_id_cannot_escape_scenario_root(self) -> None:
        config = scenario.load_json(scenario.DEFAULT_CONFIG)
        for value in ("../outside", "UPPER", "a", "contains space"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scenario.scenario_root(config, value)

    def test_init_is_exclusive_and_writes_diagnostic_evidence(self) -> None:
        root = ROOT / "run_log/t8.5/scenarios/demo-test"
        written: list[tuple[Path, dict[str, object]]] = []
        with (
            patch.object(scenario, "scenario_root", return_value=root),
            patch.object(Path, "mkdir") as mkdir,
            patch.object(
                scenario,
                "write_new_json",
                side_effect=lambda path, value: written.append((path, value)),
            ),
        ):
            observed = scenario.init_run(scenario.DEFAULT_CONFIG, "demo-test")
        receipt = written[0][1]
        self.assertEqual(observed, root)
        self.assertEqual(receipt["kind"], "diagnostic_demo_evidence")
        self.assertFalse(receipt["formal_acceptance"])
        self.assertFalse(receipt["roadmap_mutated"])
        self.assertEqual(mkdir.call_count, 5)

        with (
            patch.object(scenario, "scenario_root", return_value=root),
            patch.object(Path, "mkdir", side_effect=FileExistsError),
            self.assertRaises(FileExistsError),
        ):
            scenario.init_run(scenario.DEFAULT_CONFIG, "demo-test")

    def test_record_tool_never_claims_dataset_equivalence(self) -> None:
        config = scenario.load_json(scenario.DEFAULT_CONFIG)
        scenario_document = {"cases": config["cases"]}
        root = ROOT / "run_log/t8.5/scenarios/tool-test"
        written: list[tuple[Path, dict[str, object]]] = []
        completed = subprocess.CompletedProcess(["nmap"], 0, "ok", "")
        with (
            patch.object(scenario, "load_json", side_effect=[config, scenario_document]),
            patch.object(scenario, "scenario_root", return_value=root),
            patch.object(scenario.subprocess, "run", return_value=completed),
            patch.object(
                scenario,
                "write_new_json",
                side_effect=lambda path, value: written.append((path, value)),
            ),
        ):
            path = scenario.record_tool(
                scenario.DEFAULT_CONFIG, "tool-test", "portscan", ["nmap", "target"]
            )
        receipt = written[0][1]
        self.assertEqual(path, root / "kali/tools/portscan.json")
        self.assertEqual(receipt["status"], "observed")
        self.assertFalse(receipt["dataset_equivalence_claimed"])
        self.assertFalse(receipt["formal_acceptance"])

    def test_resource_config_uses_scenario_root_and_locked_resource_builder(self) -> None:
        root = ROOT / "run_log/t8.5/scenarios/resource-test"
        resource = {"schema_version": "1.0.0", "task": "T0.3"}
        written: list[tuple[Path, dict[str, object]]] = []
        with (
            patch.object(scenario, "scenario_root", return_value=root),
            patch.object(Path, "is_file", return_value=True),
            patch("kali_passive_traffic.load_and_validate_config", return_value={}),
            patch("dpdk_passive_probe.build_resource_config", return_value=resource),
            patch.object(
                scenario,
                "write_new_json",
                side_effect=lambda path, value: written.append((path, value)),
            ),
        ):
            path = scenario.build_resource_config(
                scenario.DEFAULT_CONFIG, "resource-test", "full-replay"
            )
        self.assertEqual(path, root / "ubuntu/full-replay/resource-config.json")
        self.assertEqual(written, [(path, resource)])


if __name__ == "__main__":
    unittest.main()
