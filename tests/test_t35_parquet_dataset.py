from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import shutil
import sqlite3
import struct
import sys
import unittest
import uuid
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "run_log" / "t3.5" / "parquet-test-work"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


package = load_script("package_t35_parquet_test", ROOT / "scripts/package_t35_parquet.py")
verify = load_script(
    "verify_t35_snapshot_dataset_test",
    ROOT / "scripts/verify_t35_snapshot_dataset.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class Fixture:
    capture_id = "fixture-capture"

    def __init__(self) -> None:
        self.root = TEST_ROOT / uuid.uuid4().hex
        (self.root / "config").mkdir(parents=True)
        self.feature_schema = self.root / "config" / "flow-feature-schema-v1.json"
        shutil.copyfile(ROOT / "config" / "flow-feature-schema-v1.json", self.feature_schema)
        self.source = self.root / "source.sqlite3"
        self.assignment = self.root / "assignment.sqlite3"
        self._create_source()
        self._create_assignment()
        self.contract_path = self.root / "config" / "snapshot-contract.json"
        self.contract = self._contract()
        write_json(self.contract_path, self.contract)
        self.shard_dir = self.root / "shards" / self.capture_id
        self.shard_dir.mkdir(parents=True)
        self.shard = self.shard_dir / "snapshot-shard.sqlite3"
        self._create_shard()
        self._write_shard_receipt()

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _create_source(self) -> None:
        connection = sqlite3.connect(self.source)
        connection.execute("PRAGMA application_id=101")
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            """
            CREATE TABLE flow(
              flow_id INTEGER PRIMARY KEY,capture_id TEXT,export_ordinal INTEGER,
              protocol INTEGER,low_ip INTEGER,low_port INTEGER,high_ip INTEGER,high_port INTEGER,
              forward_source_ip INTEGER,forward_source_port INTEGER,generation INTEGER,
              creation_timestamp_ns INTEGER,last_capture_timestamp_ns INTEGER,
              last_event_timestamp_ns INTEGER,packet_count INTEGER,
              forward_packet_count INTEGER,reverse_packet_count INTEGER,close_reason TEXT
            ) STRICT
            """
        )
        rows = [
            (1, self.capture_id, 1, 6, 0x0A000001, 1001, 0x0A000002, 80,
             0x0A000001, 1001, 1, 1000, 2000, 2000, 9, 9, 0, "end_of_input"),
            (2, self.capture_id, 2, 6, 0x0A000003, 1002, 0x0A000004, 80,
             0x0A000003, 1002, 2, 1100, 1500, 1500, 2, 2, 0, "end_of_input"),
        ]
        connection.executemany("INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        connection.commit()
        connection.close()

    def _create_assignment(self) -> None:
        connection = sqlite3.connect(self.assignment)
        connection.execute("PRAGMA application_id=102")
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "CREATE TABLE flow_assignment(flow_id INTEGER PRIMARY KEY,capture_id TEXT,assigned_class TEXT,assignment_method TEXT) STRICT"
        )
        connection.executemany(
            "INSERT INTO flow_assignment VALUES(?,?,?,?)",
            [
                (1, self.capture_id, "BENIGN", "mutual_unique"),
                (2, self.capture_id, "DDoS", "class_consensus"),
            ],
        )
        connection.commit()
        connection.close()

    def _reference(self, path: Path, application_id: int) -> dict:
        return {
            "path": path.relative_to(self.root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": digest(path),
            "application_id": application_id,
            "user_version": 1,
        }

    def _contract(self) -> dict:
        by_checkpoint = {name: 1 for name in package.CHECKPOINTS}
        zeros = {name: 0 for name in package.CHECKPOINTS}
        return {
            "schema_version": "1.0.0",
            "task": "T3.5",
            "captures": [{"id": self.capture_id, "pcap": {"path": "fixture.pcap"}}],
            "prerequisites": {
                "source_database": self._reference(self.source, 101),
                "assignment_database": self._reference(self.assignment, 102),
                "feature_schema": {
                    "path": "config/flow-feature-schema-v1.json",
                    "sha256": digest(self.feature_schema),
                    "schema_id": "nids.flow_features.v1",
                    "schema_version": "1.0.0",
                },
            },
            "execution_pipeline": {
                "parquet_runtime": {
                    "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
                    "pyarrow_exact_version": pa.__version__,
                }
            },
            "replay": {"staging": {
                "directory": "shards", "database_name": "snapshot-shard.sqlite3",
                "receipt_name": "receipt.json", "application_id": 103, "user_version": 1,
            }},
            "parquet": {
                "root": "dataset", "parts": 4,
                "capture_commit_receipt": "dataset/capture-receipts/{capture_id}.json",
                "writer_batch_rows": 16384, "row_group_rows": 65536,
                "compression": "zstd", "compression_level": 3,
            },
            "expected_accounting": {
                "assigned_flows": 2, "assigned_flows_below_f3": 1,
                "assigned_final_packet_count": {"2": 1},
                "by_checkpoint": by_checkpoint,
                "by_capture_and_checkpoint": {self.capture_id: by_checkpoint},
                "by_method_and_checkpoint": {
                    "mutual_unique": by_checkpoint, "class_consensus": zeros,
                },
                "required_warning_metrics": {"PortScan": {"assigned": 0, **zeros}},
                "explicit_zero_snapshot_class": "Heartbleed",
            },
            "outputs": {
                "manifest": "manifest.json", "build_receipt": "build.json",
            },
        }

    @staticmethod
    def feature_blob(checkpoint: int) -> bytes:
        values = [float(index) / 10.0 for index in range(54)]
        values[1] = float(checkpoint)
        values[10] = -0.0
        return struct.pack("<54d", *values)

    def _create_shard(self) -> None:
        connection = sqlite3.connect(self.shard)
        connection.execute("PRAGMA application_id=103")
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            """
            CREATE TABLE flow(
              export_ordinal INTEGER PRIMARY KEY,generation INTEGER UNIQUE,capture_id TEXT,
              protocol TEXT,low_ip TEXT,low_port INTEGER,high_ip TEXT,high_port INTEGER,
              forward_source_ip TEXT,forward_source_port INTEGER,clock_domain TEXT,
              creation_timestamp_ns INTEGER,last_capture_timestamp_ns INTEGER,
              last_event_timestamp_ns INTEGER,packet_count INTEGER,
              forward_packet_count INTEGER,reverse_packet_count INTEGER,close_reason TEXT
            ) STRICT
            """
        )
        connection.execute(
            """
            CREATE TABLE snapshot(
              generation INTEGER,checkpoint TEXT,capture_id TEXT,protocol TEXT,low_ip TEXT,
              low_port INTEGER,high_ip TEXT,high_port INTEGER,forward_source_ip TEXT,
              forward_source_port INTEGER,clock_domain TEXT,packet_count INTEGER,
              checkpoint_timestamp_ns INTEGER,features BLOB,
              PRIMARY KEY(generation,checkpoint)
            ) STRICT
            """
        )
        flow_rows = [
            (1, 1, self.capture_id, "tcp", "10.0.0.1", 1001, "10.0.0.2", 80,
             "10.0.0.1", 1001, "unix_epoch", 1000, 2000, 2000, 9, 9, 0, "end_of_input"),
            (2, 2, self.capture_id, "tcp", "10.0.0.3", 1002, "10.0.0.4", 80,
             "10.0.0.3", 1002, "unix_epoch", 1100, 1500, 1500, 2, 2, 0, "end_of_input"),
        ]
        connection.executemany("INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", flow_rows)
        for name, checkpoint in package.CHECKPOINTS.items():
            connection.execute(
                "INSERT INTO snapshot VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (1, name, self.capture_id, "tcp", "10.0.0.1", 1001, "10.0.0.2", 80,
                 "10.0.0.1", 1001, "unix_epoch", checkpoint, 1000 + checkpoint,
                 self.feature_blob(checkpoint)),
            )
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.commit()
        connection.close()

    def _write_shard_receipt(self) -> None:
        write_json(self.shard_dir / "receipt.json", {
            "task": "T3.5", "status": "passed", "capture_id": self.capture_id,
            "task_contract": {"sha256": digest(self.contract_path)},
            "sqlite": {
                "size_bytes": self.shard.stat().st_size, "sha256": digest(self.shard),
                "journal_mode": "delete",
            },
        })

    def package(self):
        return package.run(self.root, self.contract_path)

    def verify(self, write_outputs: bool = False):
        return verify.verify(self.root, self.contract_path, write_outputs)


class ParquetDatasetTests(unittest.TestCase):
    def test_package_verify_resume_and_privacy_schema(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)

        receipts = fixture.package()
        manifest = fixture.verify(write_outputs=True)

        self.assertEqual(4, manifest["part_count"])
        self.assertEqual(4, manifest["row_count"])
        self.assertTrue((fixture.root / "manifest.json").is_file())
        self.assertTrue((fixture.root / "build.json").is_file())
        part = package.output_part(
            fixture.root, fixture.contract, fixture.capture_id, "F3"
        )
        table = pq.ParquetFile(part).read()
        self.assertEqual(62, table.num_columns)
        self.assertEqual(pa.uint64(), table.schema.field("flow_id").type)
        self.assertEqual(pa.uint8(), table.schema.field("checkpoint").type)
        self.assertEqual(pa.float64(), table.schema.field("packet_count").type)
        forbidden = {
            "generation", "export_ordinal", "protocol", "low_ip", "low_port",
            "high_ip", "high_port", "forward_source_ip", "forward_source_port", "payload",
        }
        self.assertFalse(forbidden & set(table.column_names))
        resumed = fixture.package()
        self.assertEqual(receipts, resumed)

    def test_close_record_drift_blocks_publication(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        with contextlib.closing(sqlite3.connect(fixture.shard)) as connection:
            connection.execute("UPDATE flow SET packet_count=8 WHERE generation=1")
            connection.commit()
        fixture._write_shard_receipt()

        with self.assertRaisesRegex(ValueError, "close-record reconciliation failed"):
            fixture.package()

        self.assertFalse((fixture.root / "dataset" / "capture-receipts").exists())

    def test_bitwise_feature_drift_is_detected_even_when_part_is_readdressed(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.package()
        part = package.output_part(fixture.root, fixture.contract, fixture.capture_id, "F3")
        table = pq.ParquetFile(part).read()
        index = table.schema.get_field_index("packet_length_std")
        columns = list(table.columns)
        columns[index] = pa.array([0.0], type=pa.float64())
        changed = pa.Table.from_arrays(columns, schema=table.schema)
        sorting = pq.SortingColumn.from_ordering(table.schema, [("flow_id", "ascending")])
        pq.write_table(
            changed, part, version="2.6", compression="zstd", compression_level=3,
            use_dictionary=["capture_id", "assigned_class", "assignment_method"],
            write_statistics=True, data_page_version="1.0", write_batch_size=16384,
            sorting_columns=sorting,
        )
        receipt_path = package.capture_receipt_path(
            fixture.root, fixture.contract, fixture.capture_id
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        record = next(item for item in receipt["parts"] if item["checkpoint"] == "F3")
        record["size_bytes"] = part.stat().st_size
        record["sha256"] = digest(part)
        write_json(receipt_path, receipt)

        with self.assertRaisesRegex(ValueError, "feature bit mismatch"):
            fixture.verify()

    def test_extra_parquet_part_is_rejected(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.package()
        extra = fixture.root / "dataset" / "unexpected.parquet"
        shutil.copyfile(
            package.output_part(fixture.root, fixture.contract, fixture.capture_id, "F3"),
            extra,
        )

        with self.assertRaisesRegex(ValueError, "part set mismatch"):
            fixture.verify()


if __name__ == "__main__":
    unittest.main()
