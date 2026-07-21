from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "run_log" / "t3.7" / "test-work"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit = load_script(
    "audit_t37_rare_families_test",
    ROOT / "scripts" / "audit_t37_rare_families.py",
)


def gate_contract() -> dict:
    return {
        "eligibility": {
            "minimum_distinct_flows_at_f9": 100,
            "statistical_rationale": {"z": 1.959963984540054},
        },
        "provenance": {
            "consensus_dependency_warning": {"threshold": 0.5},
        },
    }


def synthetic_distributions(f9_a: int = 100, f9_b: int = 99) -> dict:
    counts = {
        "BENIGN": {checkpoint: 1000 for checkpoint in audit.CHECKPOINTS},
        "Attack A": {"F3": 120, "F5": 110, "F7": 105, "F9": f9_a},
        "Attack B": {"F3": 120, "F5": 110, "F7": 105, "F9": f9_b},
    }
    methods = {}
    partitions = {}
    captures = {}
    for family, family_counts in counts.items():
        methods[family] = {
            "mutual_unique": {key: value // 4 for key, value in family_counts.items()},
            "class_consensus": {
                key: value - value // 4 for key, value in family_counts.items()
            },
        }
        partitions[family] = {
            "train": {key: value // 2 for key, value in family_counts.items()},
            "validation": {key: value // 10 for key, value in family_counts.items()},
            "test": {
                key: value - value // 2 - value // 10 for key, value in family_counts.items()
            },
        }
        captures[family] = {"fixture": family_counts.copy()}
    return {
        "family_and_checkpoint": counts,
        "family_assignment_method_and_checkpoint": methods,
        "family_partition_and_checkpoint": partitions,
        "family_capture_and_checkpoint": captures,
    }


class ParquetFixture:
    capture_id = "fixture-capture"

    def __init__(self) -> None:
        self.root = TEST_ROOT / uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.flow_map = self.root / "known-flow-split.parquet"
        pq.write_table(
            pa.table(
                {
                    "capture_id": [self.capture_id, self.capture_id],
                    "flow_id": pa.array([1, 2], type=pa.uint64()),
                    "partition": ["train", "test"],
                    "assigned_class": ["BENIGN", "Attack A"],
                    "assignment_method": ["mutual_unique", "class_consensus"],
                }
            ),
            self.flow_map,
        )
        self.parts = [self._part("F3", 3, [1, 2]), self._part("F5", 5, [2])]

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _part(self, checkpoint: str, value: int, flow_ids: list[int]) -> dict:
        path = (
            self.root
            / f"checkpoint={checkpoint}"
            / f"capture_id={self.capture_id}"
            / "part-00000.parquet"
        )
        path.parent.mkdir(parents=True)
        families = ["BENIGN" if flow_id == 1 else "Attack A" for flow_id in flow_ids]
        methods = ["mutual_unique" if flow_id == 1 else "class_consensus" for flow_id in flow_ids]
        pq.write_table(
            pa.table(
                {
                    "flow_id": pa.array(flow_ids, type=pa.uint64()),
                    "capture_id": [self.capture_id] * len(flow_ids),
                    "checkpoint": pa.array([value] * len(flow_ids), type=pa.uint8()),
                    "assigned_class": families,
                    "label_binary": [family != "BENIGN" for family in families],
                    "assignment_method": methods,
                }
            ),
            path,
        )
        return {
            "path": path.relative_to(self.root).as_posix(),
            "resolved_path": path,
        }


class T37RareFamilyTests(unittest.TestCase):
    def test_contract_locks_confirmed_gate(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-rare-family-contract.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(contract["eligibility"]["minimum_distinct_flows_at_f9"], 100)
        self.assertEqual(
            contract["eligibility"]["macro_family_scope"],
            "one_common_list_for_F3_F5_F7_F9",
        )
        self.assertEqual(
            contract["provenance"]["eligible_assignment_methods"],
            ["mutual_unique", "class_consensus"],
        )
        self.assertFalse(contract["execution"]["hooks_in_scope"])

    def test_wilson_threshold_has_confirmed_precision(self):
        at_threshold = audit.wilson_worst_case_half_width(100, 1.959963984540054)
        below_threshold = audit.wilson_worst_case_half_width(90, 1.959963984540054)
        self.assertIsNotNone(at_threshold)
        self.assertLess(at_threshold, 0.10)
        self.assertGreater(below_threshold, 0.10)
        self.assertIsNone(audit.wilson_worst_case_half_width(0, 1.959963984540054))

    def test_gate_uses_f9_boundary_and_one_common_scope(self):
        records, gate = audit.family_gate(synthetic_distributions(), gate_contract())
        self.assertEqual(gate["macro_eligible"], ["Attack A"])
        self.assertEqual(gate["case_study_only"], ["Attack B"])
        self.assertEqual(gate["unavailable"], ["Heartbleed"])
        by_family = {record["family"]: record for record in records}
        self.assertEqual(by_family["Attack A"]["eligibility_count"], 100)
        self.assertTrue(by_family["Attack A"]["provenance_warning"])
        self.assertEqual(by_family["Attack B"]["status"], "case_study_only")

    def test_consensus_share_is_warning_only(self):
        records, gate = audit.family_gate(synthetic_distributions(), gate_contract())
        attack_a = next(record for record in records if record["family"] == "Attack A")
        self.assertGreater(attack_a["class_consensus_share_at_f9"], 0.5)
        self.assertTrue(attack_a["provenance_warning"])
        self.assertIn("Attack A", gate["macro_eligible"])

    def test_streaming_scan_reconciles_flow_map_and_counts_distinct_rows(self):
        fixture = ParquetFixture()
        try:
            distributions = audit.scan_distributions(fixture.parts, fixture.flow_map)
            self.assertEqual(distributions["checkpoint"], {"F3": 2, "F5": 1})
            self.assertEqual(
                distributions["family_and_checkpoint"]["Attack A"],
                {"F3": 1, "F5": 1},
            )
            self.assertEqual(
                distributions["family_partition_and_checkpoint"]["Attack A"]["test"],
                {"F3": 1, "F5": 1},
            )
            self.assertEqual(
                distributions["family_assignment_method_and_checkpoint"]["Attack A"][
                    "class_consensus"
                ],
                {"F3": 1, "F5": 1},
            )
        finally:
            fixture.close()

    def test_streaming_scan_rejects_duplicate_checkpoint_flow(self):
        fixture = ParquetFixture()
        try:
            bad = fixture._part("F7", 7, [2, 2])
            with self.assertRaisesRegex(ValueError, "non-unique or unsorted"):
                audit.scan_distributions([bad], fixture.flow_map)
        finally:
            fixture.close()

    def test_loafo_reconciliation_rejects_partition_drift(self):
        distributions = synthetic_distributions()
        _, gate = audit.family_gate(distributions, gate_contract())
        available = ["Attack A", "Attack B"]
        loafo = {
            "available_holdout_families": available,
            "experiments": [
                {
                    "holdout_family": family,
                    "holdout_snapshot_counts_by_known_partition": copy.deepcopy(
                        distributions["family_partition_and_checkpoint"][family]
                    ),
                }
                for family in available
            ],
            "unavailable_families": [{"family": "Heartbleed"}],
        }
        audit.reconcile_loafo(loafo, distributions, gate)
        loafo["experiments"][0]["holdout_snapshot_counts_by_known_partition"]["train"][
            "F9"
        ] += 1
        with self.assertRaisesRegex(ValueError, "accounting drift"):
            audit.reconcile_loafo(loafo, distributions, gate)

    def test_report_is_rendered_from_gate_records(self):
        records, gate = audit.family_gate(synthetic_distributions(), gate_contract())
        report = audit.render_report({"families": records, "gate": gate})
        self.assertIn("| Attack A |", report)
        self.assertIn("Đủ mẫu macro LOAFO", report)
        self.assertIn("T4.1 chưa được mở", report)
        self.assertIn("không chạy hook", report)


if __name__ == "__main__":
    unittest.main()
