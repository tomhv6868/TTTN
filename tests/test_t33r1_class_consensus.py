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
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST_WORK = ROOT / "run_log" / "t3.3r1" / "test-work"
TEST_WORK.mkdir(parents=True, exist_ok=True)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BUILDER = load_script(
    "build_t33r1_class_consensus",
    ROOT / "scripts" / "build_t33r1_class_consensus.py",
)


class ConsensusFixture:
    def __init__(self) -> None:
        self.base = TEST_WORK / f"fixture-{uuid.uuid4().hex}"
        self.root = self.base / "project"
        for directory in (
            "config",
            "scripts",
            "run_log/t3.3",
            "run_log/t3.4",
            "run_log/t3.3r1",
        ):
            (self.root / directory).mkdir(parents=True, exist_ok=True)

        shutil.copy2(
            ROOT / "scripts" / "build_t33r1_class_consensus.py",
            self.root / "scripts" / "build_t33r1_class_consensus.py",
        )
        self.source = self.root / "run_log/t3.3/label-join.sqlite3"
        self.contract_path = self.root / "config/cicids2017-class-consensus-contract.json"
        self.database_output = self.root / "run_log/t3.3r1/class-consensus.sqlite3"
        self.build_output = self.root / "run_log/t3.3r1/build.json"
        self.acceptance_output = self.root / "run_log/t3.3r1/acceptance.json"
        self._create_source()
        self._write_evidence_and_contract()

    def close(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)

    def write_json(self, path: Path, document: dict) -> None:
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _create_source(self) -> None:
        with contextlib.closing(sqlite3.connect(self.source)) as connection:
            connection.executescript("""
                PRAGMA application_id=1313424467;
                PRAGMA user_version=304;
                CREATE TABLE flow(flow_id INTEGER PRIMARY KEY,capture_id TEXT NOT NULL);
                CREATE TABLE label_row(label_id INTEGER PRIMARY KEY,label TEXT NOT NULL);
                CREATE TABLE candidate_edge(
                  flow_id INTEGER NOT NULL,label_id INTEGER NOT NULL,variant TEXT NOT NULL,
                  required_tolerance_ns INTEGER NOT NULL,schedule_conflict INTEGER NOT NULL,
                  role_conflict INTEGER NOT NULL
                );
                CREATE TABLE quarantined_label_row(label TEXT NOT NULL,reason TEXT NOT NULL);
            """)
            connection.executemany(
                "INSERT INTO flow VALUES(?,?)",
                [(flow_id, "capture-a" if flow_id <= 5 else "capture-b") for flow_id in range(1, 9)],
            )
            connection.executemany(
                "INSERT INTO label_row VALUES(?,?)",
                [
                    (1, "BENIGN"),
                    (2, "DoS Hulk"),
                    (3, "DoS Hulk"),
                    (4, "Bot"),
                    (5, "DDoS"),
                    (6, "Web Attack"),
                    (7, "PortScan"),
                    (8, "BENIGN"),
                    (9, "Bot"),
                ],
            )
            connection.executemany(
                "INSERT INTO candidate_edge VALUES(?,?,?,?,?,?)",
                [
                    (1, 1, "base", 0, 0, 0),
                    (2, 2, "base", 0, 0, 0),
                    (2, 2, "plus_12h", 0, 0, 0),
                    (2, 3, "base", 0, 0, 0),
                    (3, 4, "base", 0, 0, 0),
                    (3, 5, "base", 0, 0, 0),
                    (4, 6, "base", 0, 1, 0),
                    (6, 7, "base", 0, 0, 0),
                    (7, 7, "base", 0, 0, 0),
                    (8, 8, "base", 0, 0, 0),
                    (8, 9, "base", 0, 0, 1),
                ],
            )
            connection.executemany(
                "INSERT INTO quarantined_label_row VALUES(?,?)",
                [
                    ("BENIGN", "unsupported_protocol"),
                    ("Bot", "invalid_flow_duration"),
                    ("Heartbleed", "invalid_flow_duration"),
                ],
            )
            connection.commit()

    def _write_evidence_and_contract(self) -> None:
        source_hash = BUILDER.sha256_path(self.source)
        t33_path = self.root / "run_log/t3.3/acceptance.json"
        t34_path = self.root / "run_log/t3.4/acceptance.json"
        audit_path = self.root / "run_log/t3.4/audit.json"
        self.write_json(
            t33_path,
            {"task": "T3.3", "status": "passed", "sqlite": {"sha256": source_hash}},
        )
        self.write_json(
            t34_path,
            {
                "task": "T3.4",
                "status": "passed",
                "gate": {"decision": "rejected", "t3_5_authorized": False},
                "user_approval": {"selected_tolerance_seconds": 0},
            },
        )
        self.write_json(
            audit_path,
            {"task": "T3.4", "status": "passed", "gate": {"status": "pending_user_decision"}},
        )

        contract = copy.deepcopy(
            BUILDER.load_json(ROOT / "config/cicids2017-class-consensus-contract.json")
        )
        contract["prerequisites"] = {
            "t3_3_acceptance": {
                "path": "run_log/t3.3/acceptance.json",
                "sha256": BUILDER.sha256_path(t33_path),
                "task": "T3.3",
                "status": "passed",
            },
            "t3_3_database": {
                "path": "run_log/t3.3/label-join.sqlite3",
                "size_bytes": self.source.stat().st_size,
                "sha256": source_hash,
                "application_id": 1313424467,
                "user_version": 304,
                "access": "read_only_immutable",
            },
            "t3_4_acceptance": {
                "path": "run_log/t3.4/acceptance.json",
                "sha256": BUILDER.sha256_path(t34_path),
                "task": "T3.4",
                "status": "passed",
            },
            "t3_4_audit": {
                "path": "run_log/t3.4/audit.json",
                "sha256": BUILDER.sha256_path(audit_path),
                "task": "T3.4",
                "status": "passed",
            },
        }
        self.write_json(self.contract_path, contract)

    def run_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            command="run",
            project_root=self.root,
            contract=self.contract_path,
            database_output=self.database_output,
            build_output=self.build_output,
        )

    def validate_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            command="validate",
            project_root=self.root,
            contract=self.contract_path,
            build_input=self.build_output,
            acceptance_output=self.acceptance_output,
        )

    def build(self) -> dict:
        self.assert_success(BUILDER.run(self.run_args()))
        return BUILDER.load_json(self.build_output)

    @staticmethod
    def assert_success(return_code: int) -> None:
        if return_code != 0:
            raise AssertionError(f"builder returned {return_code}")


class ClassConsensusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ConsensusFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def rows(self, table: str, columns: str) -> list[tuple]:
        with contextlib.closing(sqlite3.connect(self.fixture.database_output)) as connection:
            return connection.execute(
                f"SELECT {columns} FROM {table} ORDER BY flow_id"
            ).fetchall()

    def test_assignments_preserve_method_and_candidate_provenance(self) -> None:
        self.fixture.build()

        assignments = self.rows(
            "flow_assignment",
            "flow_id,assigned_class,assignment_method,eligible_candidate_count,"
            "distinct_eligible_candidate_class_count,eligible_candidate_label_ids_json,"
            "mutual_unique_label_id",
        )
        candidates = self.rows(
            "assignment_candidate",
            "flow_id,label_id,candidate_class,eligible_variant_count,minimum_required_tolerance_ns",
        )

        self.assertEqual(
            [
                (1, "BENIGN", "mutual_unique", 1, 1, "[1]", 1),
                (2, "DoS Hulk", "class_consensus", 2, 1, "[2,3]", None),
                (6, "PortScan", "class_consensus", 1, 1, "[7]", None),
                (7, "PortScan", "class_consensus", 1, 1, "[7]", None),
                (8, "BENIGN", "mutual_unique", 1, 1, "[8]", 8),
            ],
            assignments,
        )
        self.assertEqual(
            [
                (1, 1, "BENIGN", 1, 0),
                (2, 2, "DoS Hulk", 2, 0),
                (2, 3, "DoS Hulk", 1, 0),
                (6, 7, "PortScan", 1, 0),
                (7, 7, "PortScan", 1, 0),
                (8, 8, "BENIGN", 1, 0),
            ],
            candidates,
        )

    def test_mixed_raw_only_and_missing_candidates_are_quarantined(self) -> None:
        self.fixture.build()

        self.assertEqual(
            [
                (3, "mixed_candidate_classes", 2, 2, 2),
                (4, "audit_conflict", 1, 0, 0),
                (5, "no_eligible_candidate", 0, 0, 0),
            ],
            self.rows(
                "quarantine",
                "flow_id,reason,raw_candidate_count,eligible_candidate_count,"
                "distinct_eligible_candidate_class_count",
            ),
        )

    def test_receipt_aggregates_all_observed_classes_including_zero_assignments(self) -> None:
        receipt = self.fixture.build()

        self.assertEqual(
            {
                "source_flows": 8,
                "assigned": 5,
                "mutual_unique": 2,
                "class_consensus": 3,
                "quarantined": 3,
            },
            receipt["summary"]["totals"],
        )
        by_class = {row["label"]: row for row in receipt["summary"]["by_class"]}
        self.assertEqual((2, 2, 0), tuple(by_class["BENIGN"][key] for key in (
            "assigned_flows", "mutual_unique", "class_consensus"
        )))
        self.assertEqual((1, 0, 1), tuple(by_class["DoS Hulk"][key] for key in (
            "assigned_flows", "mutual_unique", "class_consensus"
        )))
        self.assertEqual((2, 0, 2), tuple(by_class["PortScan"][key] for key in (
            "assigned_flows", "mutual_unique", "class_consensus"
        )))
        self.assertEqual(0, by_class["Bot"]["assigned_flows"])
        self.assertEqual(0, by_class["DDoS"]["assigned_flows"])
        self.assertEqual(0, by_class["Web Attack"]["assigned_flows"])
        self.assertEqual(0, by_class["Heartbleed"]["source_label_rows"])
        self.assertEqual(1, by_class["Heartbleed"]["source_quarantined_label_rows"])
        self.assertEqual(0, by_class["Heartbleed"]["assigned_flows"])

    def test_run_and_independent_validation_leave_source_immutable(self) -> None:
        before = BUILDER.sha256_path(self.fixture.source)
        receipt = self.fixture.build()

        self.assertEqual(before, BUILDER.sha256_path(self.fixture.source))
        self.assertEqual(before, receipt["source_database"]["sha256_after"])
        self.assertFalse(Path(str(self.fixture.source) + "-wal").exists())
        self.assertFalse(Path(str(self.fixture.source) + "-shm").exists())
        self.assertFalse(Path(str(self.fixture.database_output) + "-wal").exists())
        self.assertFalse(Path(str(self.fixture.database_output) + "-shm").exists())
        self.assertEqual(0, BUILDER.validate(self.fixture.validate_args()))
        self.assertEqual(before, BUILDER.sha256_path(self.fixture.source))
        acceptance = BUILDER.load_json(self.fixture.acceptance_output)
        self.assertTrue(acceptance["independent_recomputation"])
        self.assertFalse(acceptance["gate"]["t3_5_authorized"])

    def test_validator_detects_projection_drift_after_database_is_readdressed(self) -> None:
        receipt = self.fixture.build()
        with contextlib.closing(sqlite3.connect(self.fixture.database_output)) as connection:
            connection.execute(
                "UPDATE flow_assignment SET assigned_class='Bot' WHERE flow_id=2"
            )
            connection.commit()
        receipt["derived_database"]["size_bytes"] = self.fixture.database_output.stat().st_size
        receipt["derived_database"]["sha256"] = BUILDER.sha256_path(
            self.fixture.database_output
        )
        self.fixture.write_json(self.fixture.build_output, receipt)

        with self.assertRaisesRegex(ValueError, "independent recomputation"):
            BUILDER.validate(self.fixture.validate_args())

    def test_validator_detects_receipt_summary_tamper(self) -> None:
        receipt = self.fixture.build()
        receipt["summary"]["totals"]["assigned"] = 99
        self.fixture.write_json(self.fixture.build_output, receipt)

        with self.assertRaisesRegex(ValueError, "receipt summary mismatch"):
            BUILDER.validate(self.fixture.validate_args())

    def test_validator_detects_metadata_drift_after_database_is_readdressed(self) -> None:
        receipt = self.fixture.build()
        with contextlib.closing(sqlite3.connect(self.fixture.database_output)) as connection:
            connection.execute(
                "UPDATE build_metadata SET value='1' WHERE key='selected_tolerance_seconds'"
            )
            connection.commit()
        receipt["derived_database"]["size_bytes"] = self.fixture.database_output.stat().st_size
        receipt["derived_database"]["sha256"] = BUILDER.sha256_path(
            self.fixture.database_output
        )
        self.fixture.write_json(self.fixture.build_output, receipt)

        with self.assertRaisesRegex(ValueError, "build_metadata mismatch"):
            BUILDER.validate(self.fixture.validate_args())


if __name__ == "__main__":
    unittest.main()
