from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import sqlite3
import struct
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TEST_WORK = ROOT / "run_log" / "t3.5" / "test-work"
TEST_WORK.mkdir(parents=True, exist_ok=True)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


shards = load_script(
    "build_t35_snapshot_shard_test",
    ROOT / "scripts" / "build_t35_snapshot_shard.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FakeProcess:
    def __init__(self, lines: list[str], return_code: int = 0) -> None:
        self.stdout = io.StringIO("".join(lines))
        self.return_code = return_code
        self.terminated = False

    def wait(self, timeout=None):
        return self.return_code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


class FakePopenFactory:
    def __init__(self, lines: list[str], return_code: int = 0) -> None:
        self.lines = lines
        self.return_code = return_code
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        return FakeProcess(self.lines, self.return_code)


def encoded(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"), allow_nan=True) + "\n"


def identity(generation: int) -> dict:
    low = f"10.0.0.{generation * 2 - 1}"
    high = f"10.0.0.{generation * 2}"
    return {
        "protocol": "tcp",
        "low_ip": low,
        "low_port": 1000 + generation,
        "high_ip": high,
        "high_port": 80,
        "forward_source_ip": low,
        "forward_source_port": 1000 + generation,
    }


def snapshot(capture_id: str, generation: int, checkpoint: str) -> dict:
    packet_count = shards.CHECKPOINTS[checkpoint]
    features = [float(index) for index in range(shards.FEATURE_COUNT)]
    features[1] = float(packet_count)
    return {
        "schema_version": 1,
        "task": "T3.5",
        "kind": "snapshot",
        "capture_id": capture_id,
        **identity(generation),
        "generation": generation,
        "clock_domain": "unix_epoch",
        "checkpoint": checkpoint,
        "packet_count": packet_count,
        "checkpoint_timestamp_ns": 1_000 + packet_count,
        "features": features,
    }


def flow(capture_id: str, generation: int, ordinal: int, packet_count: int) -> dict:
    return {
        "schema_version": 1,
        "task": "T3.5",
        "kind": "flow",
        "capture_id": capture_id,
        "export_ordinal": ordinal,
        **identity(generation),
        "generation": generation,
        "clock_domain": "unix_epoch",
        "creation_timestamp_ns": 1_000,
        "last_capture_timestamp_ns": 2_000,
        "last_event_timestamp_ns": 2_000,
        "packet_count": packet_count,
        "forward_packet_count": packet_count,
        "reverse_packet_count": 0,
        "close_reason": "end_of_input",
    }


def summary(
    capture_id: str,
    pcap: Path,
    flows: int = 2,
    snapshots: int = 4,
    exclusions: int = 2,
) -> dict:
    packets = 11
    return {
        "schema_version": 1,
        "task": "T3.5",
        "kind": "summary",
        "status": "passed",
        "input": str(pcap),
        "capture_id": capture_id,
        "pcap": {
            "records_read": packets + exclusions,
            "packets_parsed": packets,
            "parser_errors": exclusions,
            "captured_bytes": 100,
            "wire_bytes": 100,
        },
        "flows": {
            "packets_accepted": packets,
            "flow_generations_created": flows,
            "flows_closed": flows,
        },
        "exported_flows": flows,
        "exported_checkpoints": snapshots,
        "parser_errors": exclusions,
        "ingest_errors": 0,
    }


class Fixture:
    def __init__(self) -> None:
        self.base = TEST_WORK / f"snapshot-shard-{uuid.uuid4().hex}"
        self.root = self.base / "project"
        self.scratch = self.base / "scratch"
        (self.root / "config").mkdir(parents=True)
        self.scratch.mkdir(parents=True)
        self.contract_path = self.root / "config" / "cicids2017-snapshot-contract.json"
        self.contract = copy.deepcopy(
            shards.load_json(ROOT / "config" / "cicids2017-snapshot-contract.json")
        )
        self.capture = self.contract["captures"][0]
        self.capture_id = self.capture["id"]
        self.pcap = self.root / self.capture["pcap"]["path"]
        self.pcap.parent.mkdir(parents=True)
        self.pcap.write_bytes(b"fixture pcap")
        self.capture["pcap"]["size_bytes"] = self.pcap.stat().st_size
        self.capture["pcap"]["sha256"] = digest(self.pcap)
        self.label_contract_path = self.root / "config" / "label-contract.json"
        self.label_contract = {
            "task": "T3.3",
            "exporter": {
                "parser_exclusion_policy": {
                    "expected_by_capture": {self.capture_id: {"total": 2}}
                }
            },
        }
        self.label_contract_path.write_text(
            json.dumps(self.label_contract) + "\n", encoding="utf-8"
        )
        self.contract["prerequisites"]["label_join_contract"] = {
            "path": "config/label-contract.json",
            "sha256": digest(self.label_contract_path),
        }
        self.contract["replay"]["staging"]["directory"] = (
            "run_log/t3.5/checkpoints/snapshot-shards"
        )
        self.contract_path.write_text(
            json.dumps(self.contract, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self.exporter = self.base / "fake_exporter"
        self.exporter.write_bytes(b"fixture exporter")
        self.output = shards.output_directory(
            self.root, self.contract, self.capture_id
        )

    def close(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)

    def valid_records(self) -> list[str]:
        records = [
            encoded(snapshot(self.capture_id, 2, checkpoint))
            for checkpoint in shards.CHECKPOINT_ORDER
        ]
        records.extend(
            [
                encoded(flow(self.capture_id, 1, 1, 2)),
                encoded(flow(self.capture_id, 2, 2, 9)),
                encoded(summary(self.capture_id, self.pcap)),
            ]
        )
        return records

    def build(self, lines: list[str] | None = None, return_code: int = 0):
        factory = FakePopenFactory(lines or self.valid_records(), return_code)
        with (
            mock.patch.object(shards, "require_production_host"),
            mock.patch.object(shards, "require_local_scratch"),
        ):
            result = shards.build_capture(
                self.root,
                self.contract_path,
                self.capture_id,
                self.exporter,
                self.scratch,
                self.output,
                factory,
            )
        return result, factory


class SnapshotShardTests(unittest.TestCase):
    def test_valid_schedule_and_short_flow_publish_resumable_private_shard(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)

        (receipt, skipped), factory = fixture.build()

        self.assertFalse(skipped)
        self.assertEqual(2, receipt["summary"]["exported_flows"])
        self.assertEqual(
            {"F3": 1, "F5": 1, "F7": 1, "F9": 1},
            receipt["snapshots_by_checkpoint"],
        )
        database = fixture.output / shards.DATABASE_NAME
        self.assertFalse(database.with_name(database.name + "-wal").exists())
        self.assertFalse(database.with_name(database.name + "-shm").exists())
        with contextlib.closing(sqlite3.connect(database)) as connection:
            self.assertEqual("delete", connection.execute("PRAGMA journal_mode").fetchone()[0])
            self.assertEqual(
                [(1, 2), (2, 9)],
                connection.execute(
                    "SELECT generation,packet_count FROM flow ORDER BY generation"
                ).fetchall(),
            )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM snapshot WHERE generation=1"
                ).fetchone()[0],
            )
            schema_text = " ".join(
                row[0]
                for row in connection.execute(
                    "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
                )
            ).lower()
            self.assertNotIn("payload", schema_text)
            self.assertNotIn("raw_packet", schema_text)
        validated = shards.validate_checkpoint(
            fixture.root,
            fixture.contract_path,
            fixture.capture_id,
            fixture.exporter,
            fixture.output,
        )
        self.assertEqual(receipt, validated)

        with (
            mock.patch.object(shards, "require_production_host"),
            mock.patch.object(shards, "require_local_scratch"),
        ):
            resumed, skipped = shards.build_capture(
                fixture.root,
                fixture.contract_path,
                fixture.capture_id,
                fixture.exporter,
                fixture.scratch,
                fixture.output,
                factory,
            )
        self.assertTrue(skipped)
        self.assertEqual(receipt, resumed)
        self.assertEqual(1, factory.calls)

    def test_strict_json_rejects_malformed_duplicate_key_and_extra_payload(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        valid = snapshot(fixture.capture_id, 2, "F3")
        cases = {
            "invalid exporter JSON": "{not-json}\n",
            "duplicate JSON key": encoded(valid).rstrip("\n")[:-1]
            + ',"kind":"snapshot"}\n',
            "fields mismatch": encoded({**valid, "payload": "forbidden"}),
        }
        for message, first_line in cases.items():
            with self.subTest(message=message):
                lines = [first_line, *fixture.valid_records()[1:]]
                with self.assertRaisesRegex((ValueError, sqlite3.Error), message):
                    fixture.build(lines)
                self.assertFalse(fixture.output.exists())

    def test_duplicate_checkpoint_and_nonfinite_feature_are_fatal(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        duplicate = fixture.valid_records()
        duplicate.insert(1, duplicate[0])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "UNIQUE"):
            fixture.build(duplicate)
        self.assertFalse(fixture.output.exists())

        invalid = snapshot(fixture.capture_id, 2, "F3")
        invalid["features"][2] = float("nan")
        lines = [encoded(invalid), *fixture.valid_records()[1:]]
        with self.assertRaisesRegex(ValueError, "non-finite"):
            fixture.build(lines)
        self.assertFalse(fixture.output.exists())

    def test_wrong_snapshot_identity_is_rejected_after_stream(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        wrong = snapshot(fixture.capture_id, 2, "F3")
        wrong["high_ip"] = "10.0.0.99"
        lines = [encoded(wrong), *fixture.valid_records()[1:]]

        with self.assertRaisesRegex(ValueError, "identity, schedule, or completeness"):
            fixture.build(lines)

        self.assertFalse(fixture.output.exists())

    def test_missing_checkpoint_is_not_synthesized(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        lines = fixture.valid_records()
        del lines[2]
        changed_summary = summary(fixture.capture_id, fixture.pcap, snapshots=3)
        lines[-1] = encoded(changed_summary)

        with self.assertRaisesRegex(ValueError, "identity, schedule, or completeness"):
            fixture.build(lines)

    def test_bad_or_nonfinal_summary_is_fatal(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        bad = summary(fixture.capture_id, fixture.pcap)
        bad["status"] = "failed"
        cases = [
            [*fixture.valid_records()[:-1], encoded(bad)],
            [*fixture.valid_records(), encoded(flow(fixture.capture_id, 3, 3, 1))],
        ]
        for lines in cases:
            with self.subTest(lines=len(lines)):
                with self.assertRaisesRegex(ValueError, "summary"):
                    fixture.build(lines)
                self.assertFalse(fixture.output.exists())

    def test_nested_summary_drift_and_sqlite_integer_overflow_are_rejected_cleanly(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        nested_drift = summary(fixture.capture_id, fixture.pcap)
        nested_drift["pcap"]["parser_errors"] = 1
        nested_drift["pcap"]["records_read"] = 12
        lines = [*fixture.valid_records()[:-1], encoded(nested_drift)]
        with self.assertRaisesRegex(ValueError, "packet accounting mismatch"):
            fixture.build(lines)

        overflow = flow(fixture.capture_id, 1, 1, 2)
        overflow["generation"] = 1 << 63
        lines = [*fixture.valid_records()[:4], encoded(overflow), *fixture.valid_records()[5:]]
        with self.assertRaisesRegex(ValueError, "generation must be an integer"):
            fixture.build(lines)

    def test_nonzero_exporter_exit_does_not_publish(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)

        with self.assertRaisesRegex(ValueError, "exporter failed rc=7"):
            fixture.build(return_code=7)

        self.assertFalse(fixture.output.exists())

    def test_receipt_and_readdressed_database_tamper_are_detected(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.build()
        receipt_path = fixture.output / shards.RECEIPT_NAME
        receipt = shards.load_json(receipt_path)
        receipt["snapshots_by_checkpoint"]["F3"] = 2
        receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "metric mismatch"):
            shards.validate_checkpoint(
                fixture.root,
                fixture.contract_path,
                fixture.capture_id,
                fixture.exporter,
                fixture.output,
            )

        receipt["snapshots_by_checkpoint"]["F3"] = 1
        database = fixture.output / shards.DATABASE_NAME
        with contextlib.closing(sqlite3.connect(database)) as connection:
            blob = connection.execute(
                "SELECT features FROM snapshot WHERE generation=2 AND checkpoint='F3'"
            ).fetchone()[0]
            values = list(struct.unpack("<54d", blob))
            values[1] = 99.0
            connection.execute(
                "UPDATE snapshot SET features=? WHERE generation=2 AND checkpoint='F3'",
                (struct.pack("<54d", *values),),
            )
            connection.commit()
        receipt["sqlite"]["sha256"] = digest(database)
        receipt["sqlite"]["size_bytes"] = database.stat().st_size
        receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "feature packet_count mismatch"):
            shards.validate_checkpoint(
                fixture.root,
                fixture.contract_path,
                fixture.capture_id,
                fixture.exporter,
                fixture.output,
            )

    def test_production_host_guard_cannot_be_disabled_by_cli(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        with mock.patch.object(shards.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(RuntimeError, "Ubuntu 24.04 VMware"):
                shards.build_capture(
                    fixture.root,
                    fixture.contract_path,
                    fixture.capture_id,
                    fixture.exporter,
                    fixture.scratch,
                    fixture.output,
                    FakePopenFactory(fixture.valid_records()),
                )


if __name__ == "__main__":
    unittest.main()
