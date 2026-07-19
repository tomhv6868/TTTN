from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import shutil
import sqlite3
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audit_t34_label_join", ROOT / "scripts/audit_t34_label_join.py")
assert SPEC is not None and SPEC.loader is not None
AUDITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDITOR)


class AuditFixture:
    def __init__(self) -> None:
        test_root = ROOT / "run_log/t3.4/test-work"
        test_root.mkdir(parents=True, exist_ok=True)
        self.root = test_root / f"fixture-{uuid.uuid4().hex}"
        self.root.mkdir()
        for directory in ("config", "scripts", "run_log/t1.2", "run_log/t3.3", "run_log/t3.4", "docs/dataset"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "scripts/audit_t34_label_join.py", self.root / "scripts/audit_t34_label_join.py")
        self.database = self.root / "run_log/t3.3/label-join.sqlite3"
        self.acceptance = self.root / "run_log/t3.3/acceptance.json"
        self.build = self.root / "run_log/t3.3/build.json"
        self.survey = self.root / "run_log/t1.2/flow-survey.json"
        self.contract = self.root / "config/cicids2017-label-audit-contract.json"
        self.output = self.root / "run_log/t3.4/audit.json"
        self.report = self.root / "docs/dataset/cicids2017-label-audit.vi.md"
        self.create_database()
        self.write_evidence()

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write_json(self, path: Path, document: dict) -> None:
        path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def create_database(self) -> None:
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            connection.executescript("""
                PRAGMA application_id=1313424467;
                PRAGMA user_version=304;
                CREATE TABLE candidate_edge(
                  flow_id INTEGER,label_id INTEGER,variant TEXT,required_tolerance_ns INTEGER,
                  schedule_conflict INTEGER,role_conflict INTEGER,
                  PRIMARY KEY(flow_id,label_id,variant)
                );
                CREATE TABLE flow(
                  flow_id INTEGER PRIMARY KEY,capture_id TEXT,forward_source_ip INTEGER,
                  forward_source_port INTEGER,creation_timestamp_ns INTEGER,
                  last_event_timestamp_ns INTEGER,packet_count INTEGER,
                  forward_packet_count INTEGER,reverse_packet_count INTEGER,close_reason TEXT
                );
                CREATE TABLE label_row(
                  label_id INTEGER PRIMARY KEY,capture_id TEXT,source_ip INTEGER,source_port INTEGER,
                  duration_us INTEGER,forward_packet_count INTEGER,backward_packet_count INTEGER,label TEXT
                );
                CREATE TABLE exporter_summary(
                  capture_id TEXT PRIMARY KEY,records_read INTEGER,packets_parsed INTEGER,
                  parser_errors INTEGER,packets_accepted INTEGER,ingest_errors INTEGER,
                  exported_flows INTEGER,flows_closed INTEGER
                );
                CREATE TABLE sweep_summary(
                  tolerance_seconds INTEGER PRIMARY KEY,raw_edge_count INTEGER,eligible_edge_count INTEGER,
                  matched_count INTEGER,flow_total INTEGER,flow_unmatched INTEGER,flow_ambiguous INTEGER,
                  flow_audit_conflict INTEGER,label_total INTEGER,label_unmatched INTEGER,
                  label_ambiguous INTEGER,label_audit_conflict INTEGER
                );
            """)
            flows = [
                (flow_id, "capture-a", 100 + flow_id, 1000 + flow_id, 0, 1_000_000,
                 3, 2, 1, "end_of_input")
                for flow_id in range(1, 8)
            ]
            connection.executemany("INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?)", flows)
            labels = [
                (1, "capture-a", 101, 1001, 1000, 2, 1, "BENIGN"),
                (2, "capture-a", 102, 1002, 1000, 2, 1, "DoS Hulk"),
                (3, "capture-a", 102, 1002, 1000, 2, 1, "DoS Hulk"),
                (4, "capture-a", 103, 1003, 1000, 2, 1, "Bot"),
                (5, "capture-a", 105, 1005, 1000, 2, 1, "PortScan"),
                (6, "capture-a", 106, 1006, 1000, 2, 1, "DDoS"),
                (7, "capture-a", 104, 1004, 1000, 2, 1, "Web Attack"),
            ]
            connection.executemany("INSERT INTO label_row VALUES(?,?,?,?,?,?,?,?)", labels)
            edges = [
                (1, 1, "base", 0, 0, 0),
                (2, 2, "base", 0, 0, 0), (2, 3, "base", 0, 0, 0),
                (3, 4, "base", 0, 1, 0),
                (5, 5, "base", 0, 0, 0),
                (6, 6, "base", 0, 0, 0), (7, 6, "base", 0, 0, 0),
                (4, 7, "base", 1_000_000_000, 0, 0),
                (1, 2, "base", 5_000_000_000, 0, 0),
            ]
            connection.executemany("INSERT INTO candidate_edge VALUES(?,?,?,?,?,?)", edges)
            sweeps = [
                (0, 7, 6, 2, 7, 1, 3, 1, 7, 1, 3, 1),
                (1, 8, 7, 3, 7, 0, 3, 1, 7, 0, 3, 1),
                (5, 9, 8, 2, 7, 0, 4, 1, 7, 0, 4, 1),
            ]
            connection.executemany("INSERT INTO sweep_summary VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", sweeps)
            connection.execute("INSERT INTO exporter_summary VALUES(?,?,?,?,?,?,?,?)",
                               ("capture-a", 21, 21, 0, 21, 0, 7, 7))
            connection.commit()

    def write_evidence(self) -> None:
        database_hash = AUDITOR.sha256_path(self.database)
        database_ref = {
            "path": "run_log/t3.3/label-join.sqlite3", "size_bytes": self.database.stat().st_size,
            "sha256": database_hash, "application_id": 1313424467, "user_version": 304
        }
        self.write_json(self.acceptance, {
            "schema_version": "1.0.0", "task": "T3.3", "kind": "label_join_acceptance",
            "status": "passed", "sqlite": {"sha256": database_hash}
        })
        self.write_json(self.build, {
            "schema_version": "1.0.0", "task": "T3.3", "kind": "label_join_build",
            "status": "passed", "sqlite": {"sha256": database_hash}
        })
        self.write_json(self.survey, {
            "schema_version": "1.0.0", "task": "T1.2", "kind": "flow_survey", "status": "passed",
            "totals": {"idle_timeout_profiles": {"60": {
                "session_count": 7,
                "completion_reasons": {"end_of_file": 7, "fin_handshake": 0,
                                       "idle_timeout": 0, "rst": 0, "tuple_reuse": 0}
            }}}
        })
        self.write_json(self.contract, {
            "schema_version": "1.0.0", "task": "T3.4", "dataset": "fixture",
            "prerequisite": {
                "acceptance": {"path": "run_log/t3.3/acceptance.json",
                               "sha256": AUDITOR.sha256_path(self.acceptance), "task": "T3.3", "status": "passed"},
                "build": {"path": "run_log/t3.3/build.json", "sha256": AUDITOR.sha256_path(self.build),
                          "task": "T3.3", "status": "passed"},
                "database": database_ref,
            },
            "comparison_evidence": {"t1_2_flow_survey": {
                "path": "run_log/t1.2/flow-survey.json", "sha256": AUDITOR.sha256_path(self.survey),
                "task": "T1.2", "status": "passed", "idle_timeout_profile_seconds": 60
            }},
            "audit": {
                "database_access": "read_only_immutable", "tolerance_seconds": [0, 1, 5],
                "source_mutation_allowed": False, "automatic_relabeling_allowed": False,
                "automatic_flow_boundary_changes_allowed": False,
                "matched_pair_agreement": {"duration_delta_buckets_microseconds": [1000, 1_000_000, 60_000_000],
                                           "packet_count_delta_buckets": [0, 1, 10]},
                "examples": {"maximum_per_category": 2},
            },
            "gate": {"initial_status": "pending_user_decision"},
            "outputs": {"audit_receipt": "run_log/t3.4/audit.json",
                        "report": "docs/dataset/cicids2017-label-audit.vi.md"},
        })

    def args(self, command: str) -> argparse.Namespace:
        return argparse.Namespace(
            command=command, project_root=self.root, contract=self.contract,
            input=self.output, output=self.output, report=self.report
        )


class LabelAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = AuditFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def compute(self) -> dict:
        contract, inputs = AUDITOR.validate_inputs(self.fixture.root, self.fixture.contract)
        with contextlib.closing(AUDITOR.open_database(inputs["database"])) as connection:
            AUDITOR.validate_database(connection, contract["prerequisite"]["database"])
            return AUDITOR.compute_audit(connection, contract, inputs)

    def test_recomputes_non_monotonic_sweep_and_recommends_best_tolerance(self) -> None:
        audit = self.compute()
        observed = [(row["tolerance_seconds"], row["matched_count"], row["flow_unmatched"],
                     row["flow_ambiguous"], row["flow_audit_conflict"]) for row in audit["sweeps"]]
        self.assertEqual([(0, 2, 1, 3, 1), (1, 3, 0, 3, 1), (5, 2, 0, 4, 1)], observed)
        self.assertEqual(1, audit["recommended_tolerance_seconds"])
        self.assertTrue(all(row["stored_summary_consistent"] for row in audit["sweeps"]))

    def test_reports_zero_match_classes_and_fail_closed_ambiguity(self) -> None:
        audit = self.compute()
        rows = audit["label_status_by_capture_and_class_at_recommended_tolerance"]
        classes = {row["label"]: row for row in rows}
        self.assertEqual(0, classes["DoS Hulk"]["matched"])
        self.assertEqual(2, classes["DoS Hulk"]["ambiguous"])
        self.assertIn("DoS Hulk", audit["zero_match_attack_families_at_recommended_tolerance"])
        purity = audit["ambiguity_candidate_class_purity_at_recommended_tolerance"]
        self.assertEqual(3, purity["candidate_class_homogeneous_flow_count"])
        self.assertIn("not an assigned label", purity["notice"])

    def test_run_and_validate_preserve_database_and_pending_gate(self) -> None:
        before = AUDITOR.sha256_path(self.fixture.database)
        self.assertEqual(0, AUDITOR.run(self.fixture.args("run")))
        self.assertEqual(before, AUDITOR.sha256_path(self.fixture.database))
        self.assertFalse(Path(str(self.fixture.database) + "-wal").exists())
        self.assertFalse(Path(str(self.fixture.database) + "-shm").exists())
        receipt = AUDITOR.load_json(self.fixture.output)
        self.assertEqual("pending_user_decision", receipt["gate"]["status"])
        self.assertIsNone(receipt["gate"]["selected_tolerance_seconds"])
        self.assertEqual(0, AUDITOR.validate(self.fixture.args("validate")))
        report = self.fixture.report.read_text(encoding="utf-8")
        self.assertNotIn("source_ip", report)
        self.assertNotIn("payload", report.casefold())

    def test_stored_sweep_drift_is_rejected_after_content_is_readdressed(self) -> None:
        with contextlib.closing(sqlite3.connect(self.fixture.database)) as connection:
            connection.execute("UPDATE sweep_summary SET matched_count=99 WHERE tolerance_seconds=0")
            connection.commit()
        self.fixture.write_evidence()
        with self.assertRaisesRegex(ValueError, "sweep_summary"):
            self.compute()

    def test_tampered_audit_receipt_is_rejected(self) -> None:
        AUDITOR.run(self.fixture.args("run"))
        receipt = AUDITOR.load_json(self.fixture.output)
        receipt["audit"]["recommended_tolerance_seconds"] = 60
        self.fixture.write_json(self.fixture.output, receipt)
        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            AUDITOR.validate(self.fixture.args("validate"))

    def test_missing_database_column_fails_before_artifact_write(self) -> None:
        with contextlib.closing(sqlite3.connect(self.fixture.database)) as connection:
            connection.execute("ALTER TABLE exporter_summary RENAME COLUMN ingest_errors TO hidden_errors")
            connection.commit()
        self.fixture.write_evidence()
        contract, inputs = AUDITOR.validate_inputs(self.fixture.root, self.fixture.contract)
        with contextlib.closing(AUDITOR.open_database(inputs["database"])) as connection:
            with self.assertRaisesRegex(ValueError, "missing columns"):
                AUDITOR.validate_database(connection, contract["prerequisite"]["database"])
        self.assertFalse(self.fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
