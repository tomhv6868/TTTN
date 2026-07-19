from __future__ import annotations

import argparse
import contextlib
import copy
import importlib.util
import json
import shutil
import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


T33_TESTS = load_script(
    "test_t33r1_fixture_for_t34r1",
    ROOT / "tests" / "test_t33r1_class_consensus.py",
)
AUDITOR = load_script(
    "audit_t34r1_class_consensus",
    ROOT / "scripts" / "audit_t34r1_class_consensus.py",
)


class RevisedAuditFixture:
    def __init__(self) -> None:
        self.consensus = T33_TESTS.ConsensusFixture()
        self.root = self.consensus.root
        self.source = self.consensus.source
        self.derived = self.consensus.database_output
        self.build = self.consensus.build_output
        self.acceptance = self.consensus.acceptance_output
        self.contract = self.root / "config/cicids2017-class-consensus-audit-contract.json"
        self.output = self.root / "run_log/t3.4r1/audit.json"
        self.report = self.root / "docs/dataset/cicids2017-class-consensus-audit.vi.md"
        (self.root / "run_log/t3.4r1").mkdir(parents=True)
        self.report.parent.mkdir(parents=True)
        shutil.copy2(
            ROOT / "scripts" / "audit_t34r1_class_consensus.py",
            self.root / "scripts" / "audit_t34r1_class_consensus.py",
        )
        self._add_audit_columns()
        self.consensus._write_evidence_and_contract()
        self.consensus.build()
        self.consensus.assert_success(T33_TESTS.BUILDER.validate(self.consensus.validate_args()))
        self._write_contract()

    def close(self) -> None:
        self.consensus.close()

    @staticmethod
    def write_json(path: Path, document: dict) -> None:
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _add_audit_columns(self) -> None:
        with contextlib.closing(sqlite3.connect(self.source)) as connection:
            connection.executescript("""
                ALTER TABLE flow ADD COLUMN forward_source_ip INTEGER;
                ALTER TABLE flow ADD COLUMN forward_source_port INTEGER;
                ALTER TABLE flow ADD COLUMN creation_timestamp_ns INTEGER;
                ALTER TABLE flow ADD COLUMN last_event_timestamp_ns INTEGER;
                ALTER TABLE flow ADD COLUMN packet_count INTEGER;
                ALTER TABLE flow ADD COLUMN forward_packet_count INTEGER;
                ALTER TABLE flow ADD COLUMN reverse_packet_count INTEGER;
                ALTER TABLE label_row ADD COLUMN source_ip INTEGER;
                ALTER TABLE label_row ADD COLUMN source_port INTEGER;
                ALTER TABLE label_row ADD COLUMN duration_us INTEGER;
                ALTER TABLE label_row ADD COLUMN forward_packet_count INTEGER;
                ALTER TABLE label_row ADD COLUMN backward_packet_count INTEGER;
                UPDATE flow SET
                  forward_source_ip=100+flow_id,
                  forward_source_port=1000+flow_id,
                  creation_timestamp_ns=0,
                  last_event_timestamp_ns=1000000,
                  packet_count=3,
                  forward_packet_count=2,
                  reverse_packet_count=1;
                UPDATE label_row SET
                  source_ip=100+CASE
                    WHEN label_id IN (2,3) THEN 2
                    WHEN label_id IN (4,5) THEN 3
                    WHEN label_id=6 THEN 4
                    WHEN label_id=7 THEN 6
                    WHEN label_id IN (8,9) THEN 8
                    ELSE 1 END,
                  source_port=1000+CASE
                    WHEN label_id IN (2,3) THEN 2
                    WHEN label_id IN (4,5) THEN 3
                    WHEN label_id=6 THEN 4
                    WHEN label_id=7 THEN 6
                    WHEN label_id IN (8,9) THEN 8
                    ELSE 1 END,
                  duration_us=1000,
                  forward_packet_count=2,
                  backward_packet_count=1;
            """)
            connection.commit()

    def _database_reference(
        self, path: Path, relative: str, application_id: int, user_version: int
    ) -> dict:
        return {
            "path": relative,
            "size_bytes": path.stat().st_size,
            "sha256": AUDITOR.sha256_path(path),
            "application_id": application_id,
            "user_version": user_version,
            "access": "read_only_immutable",
        }

    def _write_contract(self) -> None:
        contract = copy.deepcopy(AUDITOR.load_json(
            ROOT / "config/cicids2017-class-consensus-audit-contract.json"
        ))
        contract["prerequisite"] = {
            "acceptance": {
                "path": "run_log/t3.3r1/acceptance.json",
                "sha256": AUDITOR.sha256_path(self.acceptance),
                "task": "T3.3R1",
                "status": "passed",
            },
            "build": {
                "path": "run_log/t3.3r1/build.json",
                "sha256": AUDITOR.sha256_path(self.build),
                "task": "T3.3R1",
                "status": "passed",
            },
            "derived_database": self._database_reference(
                self.derived,
                "run_log/t3.3r1/class-consensus.sqlite3",
                T33_TESTS.BUILDER.APPLICATION_ID,
                T33_TESTS.BUILDER.USER_VERSION,
            ),
            "source_database": self._database_reference(
                self.source,
                "run_log/t3.3/label-join.sqlite3",
                1313424467,
                304,
            ),
        }
        self.write_json(self.contract, contract)

    def args(self, command: str) -> argparse.Namespace:
        return argparse.Namespace(
            command=command,
            project_root=self.root,
            contract=self.contract,
            input=self.output,
            output=self.output,
            report=self.report,
        )

    def compute(self) -> dict:
        contract, inputs = AUDITOR.validate_inputs(self.root, self.contract)
        return AUDITOR.execute_audit(contract, inputs)

    def readdress_prerequisites(self) -> None:
        derived_reference = self._database_reference(
            self.derived,
            "run_log/t3.3r1/class-consensus.sqlite3",
            T33_TESTS.BUILDER.APPLICATION_ID,
            T33_TESTS.BUILDER.USER_VERSION,
        )
        build = AUDITOR.load_json(self.build)
        build["derived_database"] = copy.deepcopy(derived_reference)
        self.write_json(self.build, build)
        acceptance = AUDITOR.load_json(self.acceptance)
        acceptance["derived_database"] = copy.deepcopy(derived_reference)
        acceptance["build"]["sha256"] = AUDITOR.sha256_path(self.build)
        self.write_json(self.acceptance, acceptance)
        contract = AUDITOR.load_json(self.contract)
        contract["prerequisite"]["derived_database"] = derived_reference
        contract["prerequisite"]["build"]["sha256"] = AUDITOR.sha256_path(self.build)
        contract["prerequisite"]["acceptance"]["sha256"] = AUDITOR.sha256_path(
            self.acceptance
        )
        self.write_json(self.contract, contract)


class RevisedClassConsensusAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RevisedAuditFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_reports_overall_capture_method_and_capture_class_metrics(self) -> None:
        audit = self.fixture.compute()

        self.assertEqual({
            "source_flows": 8,
            "assigned_flows": 5,
            "quarantined_flows": 3,
            "assignment_rate": 0.625,
            "quarantine_rate": 0.375,
        }, audit["assignment"]["overall"])
        self.assertEqual([
            {"assignment_method": "class_consensus", "assigned_flows": 3,
             "assigned_share": 0.6},
            {"assignment_method": "mutual_unique", "assigned_flows": 2,
             "assigned_share": 0.4},
        ], audit["assignment"]["by_method"])
        self.assertEqual([
            {"capture_id": "capture-a", "source_flows": 5, "assigned_flows": 2,
             "quarantined_flows": 3, "mutual_unique": 1, "class_consensus": 1,
             "assignment_rate": 0.4},
            {"capture_id": "capture-b", "source_flows": 3, "assigned_flows": 3,
             "quarantined_flows": 0, "mutual_unique": 1, "class_consensus": 2,
             "assignment_rate": 1.0},
        ], audit["assignment"]["by_capture"])
        self.assertEqual([
            {"capture_id": "capture-a", "label": "BENIGN",
             "assignment_method": "mutual_unique", "assigned_flows": 1},
            {"capture_id": "capture-a", "label": "DoS Hulk",
             "assignment_method": "class_consensus", "assigned_flows": 1},
            {"capture_id": "capture-b", "label": "BENIGN",
             "assignment_method": "mutual_unique", "assigned_flows": 1},
            {"capture_id": "capture-b", "label": "PortScan",
             "assignment_method": "class_consensus", "assigned_flows": 2},
        ], audit["classes"]["by_capture_class_and_method"])

    def test_reports_all_classes_representation_and_non_parity(self) -> None:
        audit = self.fixture.compute()
        classes = {row["label"]: row for row in audit["classes"]["by_class"]}

        expected = {
            "BENIGN": (2, 1, 2, 1.0, 2, 2, 0, 0),
            "Bot": (2, 1, 0, 0.0, 0, 0, 0, -2),
            "DDoS": (1, 0, 0, 0.0, 0, 0, 0, -1),
            "DoS Hulk": (2, 0, 2, 1.0, 1, 0, 1, -1),
            "Heartbleed": (0, 1, 0, None, 0, 0, 0, 0),
            "PortScan": (1, 0, 1, 1.0, 2, 0, 2, 1),
            "Web Attack": (1, 0, 0, 0.0, 0, 0, 0, -1),
        }
        for label, values in expected.items():
            row = classes[label]
            self.assertEqual(values, (
                row["source_label_rows"], row["source_quarantined_label_rows"],
                row["represented_source_label_rows"],
                row["source_label_row_representation_rate"], row["assigned_flows"],
                row["mutual_unique"], row["class_consensus"],
                row["assigned_flow_minus_source_label_rows"],
            ))
        comparison = audit["flow_count_vs_source_label_rows"]
        self.assertEqual((5, 9, -4), (
            comparison["assigned_flows"], comparison["source_label_rows"],
            comparison["delta"],
        ))
        self.assertEqual("diagnostic_non_parity_only", comparison["interpretation"])
        self.assertIn("different units", comparison["notice"])

    def test_reports_candidate_degrees_full_graph_fanout_and_quarantine(self) -> None:
        audit = self.fixture.compute()

        self.assertEqual([
            {"assignment_method": "class_consensus", "label": "DoS Hulk",
             "bucket": "2", "assigned_flows": 1},
            {"assignment_method": "class_consensus", "label": "PortScan",
             "bucket": "1", "assigned_flows": 2},
            {"assignment_method": "mutual_unique", "label": "BENIGN",
             "bucket": "1", "assigned_flows": 2},
        ], audit["candidate_count_distribution"])
        fanout = audit["source_label_fanout"]
        self.assertEqual((7, 1, 2), (
            fanout["eligible_source_labels"],
            fanout["minimum_eligible_flows_per_source_label"],
            fanout["maximum_eligible_flows_per_source_label"],
        ))
        self.assertAlmostEqual(8 / 7, fanout["mean_eligible_flows_per_source_label"])
        self.assertEqual([
            {"bucket": "1", "source_label_count": 6},
            {"bucket": "2", "source_label_count": 1},
        ], fanout["fanout_buckets"])
        self.assertEqual([
            {"reason": "audit_conflict", "count": 1},
            {"reason": "mixed_candidate_classes", "count": 1},
            {"reason": "no_eligible_candidate", "count": 1},
        ], audit["quarantine"]["flow_by_reason"])
        self.assertEqual([
            {"reason": "invalid_flow_duration", "count": 2},
            {"reason": "unsupported_protocol", "count": 1},
        ], audit["quarantine"]["source_label_by_reason"])

    def test_examples_are_bounded_and_private(self) -> None:
        audit = self.fixture.compute()
        contract = AUDITOR.load_json(self.fixture.contract)
        limit = contract["audit"]["examples"]["maximum_per_category"]
        forbidden = {
            "source_ip", "destination_ip", "dest_ip", "forward_source_ip",
            "source_port", "destination_port", "dest_port", "forward_source_port",
            "payload", "raw_packet_bytes",
        }

        for category, rows in audit["examples"].items():
            self.assertLessEqual(len(rows), limit, category)
            for row in rows:
                self.assertTrue(forbidden.isdisjoint(row), (category, row))
        self.assertEqual(2, audit["examples"]["highest_source_label_fanout"][0][
            "eligible_flow_count"
        ])

    def test_run_and_validate_preserve_databases_and_keep_gate_pending(self) -> None:
        source_before = AUDITOR.sha256_path(self.fixture.source)
        derived_before = AUDITOR.sha256_path(self.fixture.derived)

        self.assertEqual(0, AUDITOR.run(self.fixture.args("run")))
        self.assertEqual(0, AUDITOR.validate(self.fixture.args("validate")))
        receipt = AUDITOR.load_json(self.fixture.output)
        self.assertEqual(AUDITOR.gate_document(), receipt["gate"])
        self.assertEqual("pending_user_decision", receipt["gate"]["status"])
        self.assertIsNone(receipt["gate"]["decision"])
        self.assertIsNone(receipt["gate"]["approved_family_scope"])
        self.assertTrue(all(value is None for value in receipt["gate"]["thresholds"].values()))
        self.assertFalse(receipt["gate"]["t3_5_authorized"])
        self.assertEqual(source_before, AUDITOR.sha256_path(self.fixture.source))
        self.assertEqual(derived_before, AUDITOR.sha256_path(self.fixture.derived))
        for database in (self.fixture.source, self.fixture.derived):
            self.assertFalse(Path(str(database) + "-wal").exists())
            self.assertFalse(Path(str(database) + "-shm").exists())
        report = self.fixture.report.read_text(encoding="utf-8")
        self.assertNotIn("source_ip", report)
        self.assertNotIn("payload", report.casefold())

    def test_independent_recomputation_rejects_projection_drift_after_readdressing(self) -> None:
        with contextlib.closing(sqlite3.connect(self.fixture.derived)) as connection:
            connection.execute(
                "UPDATE flow_assignment SET assigned_class='Bot' WHERE flow_id=2"
            )
            connection.execute(
                "UPDATE assignment_candidate SET candidate_class='Bot' WHERE flow_id=2"
            )
            connection.commit()
        self.fixture.readdress_prerequisites()

        with self.assertRaisesRegex(ValueError, "derived projection"):
            self.fixture.compute()

    def test_independent_recomputation_rejects_provenance_drift_after_readdressing(self) -> None:
        with contextlib.closing(sqlite3.connect(self.fixture.derived)) as connection:
            connection.execute(
                "UPDATE assignment_candidate SET eligible_variant_count=1 "
                "WHERE flow_id=2 AND label_id=2"
            )
            connection.commit()
        self.fixture.readdress_prerequisites()

        with self.assertRaisesRegex(ValueError, "derived projection"):
            self.fixture.compute()

    def test_validator_rejects_audit_receipt_drift(self) -> None:
        self.assertEqual(0, AUDITOR.run(self.fixture.args("run")))
        receipt = AUDITOR.load_json(self.fixture.output)
        receipt["audit"]["assignment"]["overall"]["assigned_flows"] = 99
        self.fixture.write_json(self.fixture.output, receipt)

        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            AUDITOR.validate(self.fixture.args("validate"))


if __name__ == "__main__":
    unittest.main()
