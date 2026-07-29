from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import ipaddress
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
TEST_WORK = ROOT / "run_log" / "full-flow-v1" / "test-work"
TEST_WORK.mkdir(parents=True, exist_ok=True)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


shards = load_script(
    "build_t91_terminal_shard_test",
    ROOT / "scripts" / "build_t91_terminal_shard.py",
)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def encoded(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"), allow_nan=True) + "\n"


def ipv4(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


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


class Fixture:
    capture_id = "fixture-capture"

    def __init__(self) -> None:
        self.base = TEST_WORK / f"terminal-shard-{uuid.uuid4().hex}"
        self.base.mkdir(parents=True)
        self.root = self.base / "project"
        self.scratch = self.base / "scratch"
        self.root.mkdir()
        self.scratch.mkdir()
        self.schema = self.root / "config" / "terminal-flow-feature-schema-v1.json"
        self.schema.parent.mkdir()
        shutil.copyfile(
            ROOT / "config" / "terminal-flow-feature-schema-v1.json",
            self.schema,
        )
        self.pcap = self.root / "pcap" / "fixture.pcap"
        self.pcap.parent.mkdir()
        self.pcap.write_bytes(b"tiny deterministic pcap fixture")
        self.exporter = self.base / "fake-terminal-exporter"
        self.exporter.write_bytes(b"fake executable identity")
        self.source_database = self.root / "run_log" / "t3.3" / "label-join.sqlite3"
        self.source_database.parent.mkdir(parents=True)
        self.source_rows = [
            (
                101,
                self.capture_id,
                1,
                6,
                ipv4("10.0.0.1"),
                12_345,
                ipv4("10.0.0.2"),
                80,
                ipv4("10.0.0.1"),
                12_345,
                2,
                1_000,
                900,
                2_000,
                2,
                1,
                1,
                "end_of_input",
            ),
            (
                102,
                self.capture_id,
                2,
                17,
                ipv4("10.0.0.3"),
                53,
                ipv4("10.0.0.4"),
                53_000,
                ipv4("10.0.0.4"),
                53_000,
                1,
                3_000,
                3_000,
                3_000,
                1,
                1,
                0,
                "end_of_input",
            ),
        ]
        self._create_source_database()
        self.output = shards.output_directory(self.root, self.capture_id)

    def close(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)

    def _create_source_database(self) -> None:
        with contextlib.closing(sqlite3.connect(self.source_database)) as connection:
            connection.execute(
                f"PRAGMA application_id={shards.SOURCE_APPLICATION_ID}"
            )
            connection.execute(f"PRAGMA user_version={shards.SOURCE_USER_VERSION}")
            connection.executescript(
                """
                CREATE TABLE input_file(
                    input_id INTEGER PRIMARY KEY,
                    capture_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL
                ) STRICT;
                CREATE TABLE flow(
                    flow_id INTEGER PRIMARY KEY,
                    capture_id TEXT NOT NULL,
                    export_ordinal INTEGER NOT NULL,
                    protocol INTEGER NOT NULL,
                    low_ip INTEGER NOT NULL,
                    low_port INTEGER NOT NULL,
                    high_ip INTEGER NOT NULL,
                    high_port INTEGER NOT NULL,
                    forward_source_ip INTEGER NOT NULL,
                    forward_source_port INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    creation_timestamp_ns INTEGER NOT NULL,
                    last_capture_timestamp_ns INTEGER NOT NULL,
                    last_event_timestamp_ns INTEGER NOT NULL,
                    packet_count INTEGER NOT NULL,
                    forward_packet_count INTEGER NOT NULL,
                    reverse_packet_count INTEGER NOT NULL,
                    close_reason TEXT NOT NULL,
                    UNIQUE(capture_id,export_ordinal)
                ) STRICT;
                CREATE TABLE exporter_summary(
                    capture_id TEXT PRIMARY KEY,
                    records_read INTEGER NOT NULL,
                    packets_parsed INTEGER NOT NULL,
                    parser_errors INTEGER NOT NULL,
                    packets_accepted INTEGER NOT NULL,
                    ingest_errors INTEGER NOT NULL,
                    exported_flows INTEGER NOT NULL,
                    flows_closed INTEGER NOT NULL
                ) STRICT;
                """
            )
            connection.execute(
                "INSERT INTO input_file VALUES(1,?,?,?,?,?)",
                (
                    self.capture_id,
                    "pcap",
                    self.pcap.relative_to(self.root).as_posix(),
                    self.pcap.stat().st_size,
                    digest(self.pcap),
                ),
            )
            connection.executemany(
                "INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                self.source_rows,
            )
            connection.execute(
                "INSERT INTO exporter_summary VALUES(?,?,?,?,?,?,?,?)",
                (self.capture_id, 4, 3, 1, 3, 0, 2, 2),
            )
            connection.commit()
            connection.execute("PRAGMA journal_mode=DELETE")

    @staticmethod
    def feature_vector(
        protocol: int,
        packet_count: int,
        forward_count: int,
        reverse_count: int,
        source_port: int,
        destination_port: int,
    ) -> list[float]:
        values = [0.0] * shards.FEATURE_COUNT
        values[1] = float(packet_count)
        values[2] = float(forward_count)
        values[3] = float(reverse_count)
        values[54] = float(protocol)
        values[61] = 1.0
        values[62] = 1.0
        values[63] = 1.0
        values[64] = float(source_port)
        values[65] = float(destination_port)
        values[68 if protocol == 6 else 69] = 1.0
        return values

    def terminal_flow(self, source_row: tuple) -> dict:
        (
            _flow_id,
            capture_id,
            ordinal,
            protocol,
            low_ip,
            low_port,
            high_ip,
            high_port,
            forward_ip,
            forward_port,
            generation,
            creation,
            last_capture,
            last_event,
            packet_count,
            forward_count,
            reverse_count,
            close_reason,
        ) = source_row
        forward_is_low = (forward_ip, forward_port) == (low_ip, low_port)
        destination_port = high_port if forward_is_low else low_port
        return {
            "schema_version": 1,
            "task": "T9.1",
            "kind": "terminal_flow",
            "feature_schema_id": shards.FEATURE_SCHEMA_ID,
            "feature_count": shards.FEATURE_COUNT,
            "capture_id": capture_id,
            "export_ordinal": ordinal,
            "protocol": "tcp" if protocol == 6 else "udp",
            "low_ip": str(ipaddress.IPv4Address(low_ip)),
            "low_port": low_port,
            "high_ip": str(ipaddress.IPv4Address(high_ip)),
            "high_port": high_port,
            "forward_source_ip": str(ipaddress.IPv4Address(forward_ip)),
            "forward_source_port": forward_port,
            "generation": generation,
            "clock_domain": "unix_epoch",
            "creation_timestamp_ns": creation,
            "last_capture_timestamp_ns": last_capture,
            "last_event_timestamp_ns": last_event,
            "packet_count": packet_count,
            "forward_packet_count": forward_count,
            "reverse_packet_count": reverse_count,
            "close_reason": close_reason,
            "features": self.feature_vector(
                protocol,
                packet_count,
                forward_count,
                reverse_count,
                forward_port,
                destination_port,
            ),
        }

    def summary(self) -> dict:
        close_reasons = {reason: 0 for reason in shards.CLOSE_REASONS}
        close_reasons["end_of_input"] = 2
        return {
            "schema_version": 1,
            "task": "T9.1",
            "kind": "summary",
            "status": "passed",
            "feature_schema_id": shards.FEATURE_SCHEMA_ID,
            "feature_count": shards.FEATURE_COUNT,
            "input": str(self.pcap),
            "capture_id": self.capture_id,
            "pcap": {
                "records_read": 4,
                "packets_parsed": 3,
                "parser_errors": 1,
                "captured_bytes": 300,
                "wire_bytes": 400,
            },
            "flows": {
                "packets_accepted": 3,
                "packets_rejected_clock_domain": 0,
                "packets_rejected_timestamp_overflow": 0,
                "packets_rejected_feature_update": 0,
                "packets_rejected_resource_exhausted": 0,
                "flow_generations_created": 2,
                "flows_closed": 2,
                "active_flow_count": 0,
                "peak_active_flow_count": 2,
                "fixed_memory_bytes": 100,
                "current_allocator_bytes": 0,
                "peak_allocator_bytes": 20,
                "current_memory_bytes": 100,
                "peak_memory_bytes": 120,
                "memory_budget_bytes": 1_000,
                "close_reason_count": close_reasons,
            },
            "exported_flows": 2,
            "parser_errors": 1,
            "ingest_errors": 0,
            "terminal_feature_errors": 0,
        }

    def valid_records(self) -> list[str]:
        return [
            encoded(self.terminal_flow(self.source_rows[0])),
            encoded(self.terminal_flow(self.source_rows[1])),
            encoded(self.summary()),
        ]

    def options(self) -> dict:
        return {
            "source_database": self.source_database,
            "feature_schema": self.schema,
            "expected_source_database_sha256": digest(self.source_database),
            "expected_source_database_size": self.source_database.stat().st_size,
            "expected_feature_schema_sha256": digest(self.schema),
        }

    def build(
        self,
        lines: list[str] | None = None,
        return_code: int = 0,
        factory: FakePopenFactory | None = None,
    ):
        factory = factory or FakePopenFactory(
            self.valid_records() if lines is None else lines,
            return_code,
        )
        with (
            mock.patch.object(shards, "require_production_host"),
            mock.patch.object(shards, "require_local_scratch"),
        ):
            result = shards.build_capture(
                self.root,
                self.capture_id,
                self.exporter,
                self.scratch,
                popen_factory=factory,
                **self.options(),
            )
        return result, factory

    def validate(self):
        return shards.validate_checkpoint(
            self.root,
            self.capture_id,
            self.exporter,
            **self.options(),
        )


class TerminalShardTests(unittest.TestCase):
    def test_valid_build_maps_oracle_flow_ids_and_resumes_after_full_validation(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        factory = FakePopenFactory(fixture.valid_records())

        (manifest, skipped), _ = fixture.build(factory=factory)

        self.assertFalse(skipped)
        self.assertEqual(2, manifest["database"]["rows"])
        self.assertEqual(
            "capture_id_export_ordinal_then_exact_close_record",
            manifest["oracle_reconciliation"]["key"],
        )
        database = fixture.output / shards.DATABASE_NAME
        self.assertFalse(database.with_name(database.name + "-wal").exists())
        self.assertFalse(database.with_name(database.name + "-shm").exists())
        with contextlib.closing(sqlite3.connect(database)) as connection:
            self.assertEqual(
                "delete",
                connection.execute("PRAGMA journal_mode").fetchone()[0],
            )
            self.assertEqual(
                [(101, 1, 2), (102, 2, 1)],
                connection.execute(
                    "SELECT flow_id,export_ordinal,generation "
                    "FROM terminal_flow ORDER BY export_ordinal"
                ).fetchall(),
            )
            blob = connection.execute(
                "SELECT features FROM terminal_flow WHERE flow_id=101"
            ).fetchone()[0]
            self.assertEqual(shards.FEATURE_BLOB_SIZE, len(blob))
            self.assertEqual(2.0, struct.unpack("<70d", blob)[1])
        self.assertEqual(manifest, fixture.validate())

        (resumed, skipped), _ = fixture.build(factory=factory)

        self.assertTrue(skipped)
        self.assertEqual(manifest, resumed)
        self.assertEqual(1, factory.calls)

    def test_strict_json_feature_oracle_and_summary_failures_never_publish(self):
        cases = []

        fixture = Fixture()
        flow = fixture.terminal_flow(fixture.source_rows[0])
        flow["features"][4] = float("nan")
        cases.append((fixture, [encoded(flow), *fixture.valid_records()[1:]], "non-finite"))

        fixture = Fixture()
        flow = fixture.terminal_flow(fixture.source_rows[0])
        flow["high_port"] = 81
        flow["features"][65] = 81.0
        cases.append((fixture, [encoded(flow), *fixture.valid_records()[1:]], "oracle close record mismatch"))

        fixture = Fixture()
        summary = fixture.summary()
        summary["failure"] = "sink"
        cases.append((fixture, [*fixture.valid_records()[:-1], encoded(summary)], "fields mismatch"))

        fixture = Fixture()
        failed = fixture.summary()
        failed["status"] = "failed"
        failed["failure"] = "terminal_feature"
        failed["failure_record_number"] = 3
        cases.append((fixture, [*fixture.valid_records()[:-1], encoded(failed)], "reported failed summary"))

        fixture = Fixture()
        records = fixture.valid_records()
        records.append(encoded(fixture.terminal_flow(fixture.source_rows[0])))
        cases.append((fixture, records, "after summary"))

        for fixture, records, message in cases:
            with self.subTest(message=message):
                self.addCleanup(fixture.close)
                with self.assertRaisesRegex(
                    (ValueError, sqlite3.Error),
                    message,
                ):
                    fixture.build(records)
                self.assertFalse(fixture.output.exists())

    def test_missing_oracle_row_and_nonzero_exporter_exit_do_not_publish(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        records = [
            encoded(fixture.terminal_flow(fixture.source_rows[0])),
            encoded(fixture.summary()),
        ]
        with self.assertRaisesRegex(ValueError, "omitted rows"):
            fixture.build(records)
        self.assertFalse(fixture.output.exists())

        fixture = Fixture()
        self.addCleanup(fixture.close)
        with self.assertRaisesRegex(ValueError, "exporter failed rc=7"):
            fixture.build(return_code=7)
        self.assertFalse(fixture.output.exists())

    def test_manifest_and_semantic_database_tamper_are_detected(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.build()
        manifest_path = fixture.output / shards.MANIFEST_NAME
        manifest = shards.load_json(manifest_path)
        manifest["database"]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest database mismatch"):
            fixture.validate()

        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.build()
        database = fixture.output / shards.DATABASE_NAME
        with contextlib.closing(sqlite3.connect(database)) as connection:
            blob = connection.execute(
                "SELECT features FROM terminal_flow WHERE flow_id=101"
            ).fetchone()[0]
            values = list(struct.unpack("<70d", blob))
            values[1] = 99.0
            connection.execute(
                "UPDATE terminal_flow SET features=? WHERE flow_id=101",
                (struct.pack("<70d", *values),),
            )
            connection.commit()
        manifest_path = fixture.output / shards.MANIFEST_NAME
        manifest = shards.load_json(manifest_path)
        manifest["database"]["sha256"] = digest(database)
        manifest["database"]["size_bytes"] = database.stat().st_size
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "feature BLOB mismatch"):
            fixture.validate()

    def test_production_host_guard_cannot_be_disabled_by_cli(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        with mock.patch.object(shards.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(RuntimeError, "Ubuntu 24.04 VMware"):
                shards.build_capture(
                    fixture.root,
                    fixture.capture_id,
                    fixture.exporter,
                    fixture.scratch,
                    popen_factory=FakePopenFactory(fixture.valid_records()),
                    **fixture.options(),
                )
        self.assertFalse(fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
