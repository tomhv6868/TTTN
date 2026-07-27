from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import struct
import sys
import unittest
import uuid
from collections.abc import Iterator
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from nids_mvp import full_flow_dataset as dataset


CAPTURE_ID = "synthetic-working-hours"
SOURCE_APPLICATION_ID = 0x12340001
ASSIGNMENT_APPLICATION_ID = 0x12340002
SOURCE_USER_VERSION = 7
ASSIGNMENT_USER_VERSION = 8


@contextlib.contextmanager
def temporary_root() -> Iterator[Path]:
    path = ROOT / f".t91-full-flow-dataset-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def configure_database(
    connection: sqlite3.Connection, application_id: int, user_version: int
) -> None:
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute(f"PRAGMA application_id={application_id}")
    connection.execute(f"PRAGMA user_version={user_version}")


def database_reference(
    path: Path, application_id: int, user_version: int
) -> dataset.DatabaseReference:
    return dataset.DatabaseReference(
        path=path,
        size_bytes=path.stat().st_size,
        sha256=dataset.sha256_path(path),
        application_id=application_id,
        user_version=user_version,
    )


def source_rows() -> list[tuple[object, ...]]:
    rows: list[tuple[object, ...]] = []
    packet_counts = (3, 2, 9, 9)
    forward_counts = (2, 1, 5, 6)
    protocols = (6, 6, 17, 6)
    for ordinal, (packet_count, forward_count, protocol) in enumerate(
        zip(packet_counts, forward_counts, protocols, strict=True), start=1
    ):
        timestamp = ordinal * 60_000_000_000
        rows.append(
            (
                ordinal,
                CAPTURE_ID,
                ordinal,
                protocol,
                0x0A000001,
                10_000 + ordinal,
                0x0A000002,
                80,
                0x0A000001,
                10_000 + ordinal,
                1,
                timestamp,
                timestamp + 10,
                timestamp + 20,
                packet_count,
                forward_count,
                packet_count - forward_count,
                "end_of_input",
            )
        )
    return rows


def create_source_database(path: Path) -> dataset.DatabaseReference:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        configure_database(
            connection, SOURCE_APPLICATION_ID, SOURCE_USER_VERSION
        )
        connection.execute(
            """
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
                close_reason TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            source_rows(),
        )
        connection.commit()
    return database_reference(
        path, SOURCE_APPLICATION_ID, SOURCE_USER_VERSION
    )


def create_assignment_database(
    path: Path, duplicate_assignment: bool
) -> dataset.DatabaseReference:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        configure_database(
            connection, ASSIGNMENT_APPLICATION_ID, ASSIGNMENT_USER_VERSION
        )
        connection.execute(
            """
            CREATE TABLE flow_assignment(
                flow_id INTEGER PRIMARY KEY,
                capture_id TEXT NOT NULL,
                assigned_class TEXT NOT NULL,
                assignment_method TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE quarantine(
                flow_id INTEGER PRIMARY KEY,
                capture_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )
        assignments = [
            (1, CAPTURE_ID, "BENIGN", "mutual_unique"),
            (2, CAPTURE_ID, "FTP-Patator", "class_consensus"),
            (3, CAPTURE_ID, "PortScan", "mutual_unique"),
        ]
        if duplicate_assignment:
            assignments.append(
                (4, CAPTURE_ID, "BENIGN", "mutual_unique")
            )
        connection.executemany(
            "INSERT INTO flow_assignment VALUES(?,?,?,?)", assignments
        )
        connection.execute(
            "INSERT INTO quarantine VALUES(?,?,?)",
            (4, CAPTURE_ID, "no_eligible_candidate"),
        )
        connection.commit()
    return database_reference(
        path, ASSIGNMENT_APPLICATION_ID, ASSIGNMENT_USER_VERSION
    )


def create_feature_schema(path: Path) -> str:
    profiles = [
        {"id": "A", "start_index": 0, "end_index": 53, "length": 54},
        {"id": "B", "start_index": 0, "end_index": 60, "length": 61},
        {"id": "C", "start_index": 0, "end_index": 63, "length": 64},
        {"id": "D", "start_index": 0, "end_index": 65, "length": 66},
        {"id": "E", "start_index": 0, "end_index": 69, "length": 70},
    ]
    write_json(
        path,
        {
            "schema_id": dataset.FEATURE_SCHEMA_ID,
            "feature_vector": {
                "length": dataset.FEATURE_COUNT,
                "encoded_type": "float64",
                "finite_only": True,
            },
            "features": [
                {"index": index, "name": f"feature_{index:02d}"}
                for index in range(dataset.FEATURE_COUNT)
            ],
            "feature_profiles": profiles,
        },
    )
    return dataset.sha256_path(path)


def create_split_map(root: Path) -> tuple[Path, str, Path]:
    path = root / "inputs/flow-partitions.parquet"
    path.parent.mkdir(parents=True, exist_ok=True)
    schema = pa.schema(
        [
            pa.field("capture_id", pa.string(), nullable=False),
            pa.field("flow_id", pa.uint64(), nullable=False),
            pa.field("partition", pa.string(), nullable=False),
            pa.field("partition_source", pa.string(), nullable=False),
        ]
    )
    table = pa.Table.from_arrays(
        [
            pa.array([CAPTURE_ID] * 3, type=pa.string()),
            pa.array([1, 2, 3], type=pa.uint64()),
            pa.array(["train", "validation", "test"], type=pa.string()),
            pa.array(
                ["legacy_f3", "locked_block_inheritance", "legacy_f3"],
                type=pa.string(),
            ),
        ],
        schema=schema,
    )
    pq.write_table(table, path)
    manifest_path = root / "inputs/split-manifest.json"
    write_json(
        manifest_path,
        {
            "task": dataset.TASK,
            "kind": "terminal_flow_split_manifest",
            "status": "complete",
        },
    )
    return path, dataset.sha256_path(path), manifest_path


def feature_blob(row: tuple[object, ...]) -> bytes:
    values = [0.0] * dataset.FEATURE_COUNT
    values[1] = float(row[14])
    values[2] = float(row[15])
    values[3] = float(row[16])
    values[54] = float(row[3])
    values[64] = float(row[9])
    values[65] = float(row[7])
    values[66] = 1.0
    return struct.pack("<70d", *values)


def create_terminal_shard(
    root: Path,
    source: dataset.DatabaseReference,
    feature_schema_path: Path,
    feature_schema_sha256: str,
) -> tuple[Path, Path]:
    directory = root / "terminal-shards" / CAPTURE_ID
    directory.mkdir(parents=True, exist_ok=True)
    database_path = directory / "terminal-flow-shard.sqlite3"
    with contextlib.closing(sqlite3.connect(database_path)) as connection:
        configure_database(
            connection,
            dataset.TERMINAL_SHARD_APPLICATION_ID,
            dataset.TERMINAL_SHARD_USER_VERSION,
        )
        connection.execute(
            """
            CREATE TABLE terminal_flow(
                flow_id INTEGER,
                export_ordinal INTEGER,
                generation INTEGER,
                capture_id TEXT,
                protocol INTEGER,
                low_ip INTEGER,
                low_port INTEGER,
                high_ip INTEGER,
                high_port INTEGER,
                forward_source_ip INTEGER,
                forward_source_port INTEGER,
                clock_domain TEXT,
                creation_timestamp_ns INTEGER,
                last_capture_timestamp_ns INTEGER,
                last_event_timestamp_ns INTEGER,
                packet_count INTEGER,
                forward_packet_count INTEGER,
                reverse_packet_count INTEGER,
                close_reason TEXT,
                features BLOB
            )
            """
        )
        terminal_rows = []
        for row in source_rows():
            terminal_rows.append(
                (
                    row[0],
                    row[2],
                    row[10],
                    row[1],
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    row[8],
                    row[9],
                    "unix_epoch",
                    row[11],
                    row[12],
                    row[13],
                    row[14],
                    row[15],
                    row[16],
                    row[17],
                    feature_blob(row),
                )
            )
        connection.executemany(
            "INSERT INTO terminal_flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            terminal_rows,
        )
        connection.commit()
    manifest_path = directory / "manifest.json"
    write_shard_manifest(
        root,
        database_path,
        manifest_path,
        source,
        feature_schema_path,
        feature_schema_sha256,
    )
    return database_path, manifest_path


def write_shard_manifest(
    root: Path,
    database_path: Path,
    manifest_path: Path,
    source: dataset.DatabaseReference,
    feature_schema_path: Path,
    feature_schema_sha256: str,
) -> None:
    rows = len(source_rows())
    write_json(
        manifest_path,
        {
            "schema_version": "1.0.0",
            "task": dataset.TASK,
            "kind": "terminal_flow_shard_manifest",
            "status": "passed",
            "capture_id": CAPTURE_ID,
            "producer": {"sha256": "a" * 64},
            "exporter": {"sha256": "b" * 64},
            "feature_schema": {
                "path": feature_schema_path.relative_to(root).as_posix(),
                "sha256": feature_schema_sha256,
                "schema_id": dataset.FEATURE_SCHEMA_ID,
                "feature_count": dataset.FEATURE_COUNT,
            },
            "source_database": {
                "path": source.path.relative_to(root).as_posix(),
                "size_bytes": source.size_bytes,
                "sha256": source.sha256,
                "application_id": source.application_id,
                "user_version": source.user_version,
                "journal_mode": "delete",
            },
            "source": {
                "path": "synthetic.pcap",
                "size_bytes": 1,
                "sha256": "c" * 64,
            },
            "database": {
                "path": database_path.relative_to(root).as_posix(),
                "size_bytes": database_path.stat().st_size,
                "sha256": dataset.sha256_path(database_path),
                "application_id": dataset.TERMINAL_SHARD_APPLICATION_ID,
                "user_version": dataset.TERMINAL_SHARD_USER_VERSION,
                "journal_mode": "delete",
                "integrity_check": "ok",
                "rows": rows,
            },
            "summary": {"rows": rows},
            "oracle_reconciliation": {
                "key": "capture_id_export_ordinal_then_exact_close_record",
                "matched_rows": rows,
                "mismatches": 0,
            },
        },
    )


def create_inputs(
    root: Path, duplicate_assignment: bool = False
) -> tuple[dataset.DatasetInputs, Path, Path]:
    source = create_source_database(root / "source.sqlite3")
    assignment = create_assignment_database(
        root / "assignment.sqlite3", duplicate_assignment
    )
    feature_schema_path = root / "feature-schema.json"
    feature_schema_sha256 = create_feature_schema(feature_schema_path)
    split_map_path, split_map_sha256, split_manifest_path = create_split_map(
        root
    )
    shard_path, shard_manifest_path = create_terminal_shard(
        root,
        source,
        feature_schema_path,
        feature_schema_sha256,
    )
    inputs = dataset.DatasetInputs(
        root=root,
        source=source,
        assignment=assignment,
        feature_schema_path=feature_schema_path,
        feature_schema_sha256=feature_schema_sha256,
        split_map_path=split_map_path,
        split_map_sha256=split_map_sha256,
        split_manifest_path=split_manifest_path,
        shard_root=root / "terminal-shards",
        output_root=root / "dataset",
        capture_ids=(CAPTURE_ID,),
        expected_capture_rows={CAPTURE_ID: 4},
        enforce_production_accounting=False,
    )
    return inputs, shard_path, shard_manifest_path


class FullFlowDatasetTest(unittest.TestCase):
    def test_build_resume_and_paired_f9_metadata(self) -> None:
        with temporary_root() as root:
            inputs, _, _ = create_inputs(root)

            manifest = dataset.build_dataset(inputs)
            self.assertEqual(manifest["rows"], 4)
            self.assertEqual(manifest["assigned_rows"], 3)
            self.assertEqual(manifest["quarantine_rows"], 1)
            self.assertEqual(
                manifest["family_counts"],
                {
                    "Benign": 1,
                    "FTP-Bruteforce": 1,
                    "PortScan": 1,
                },
            )
            self.assertEqual(
                manifest["quarantine_counts"],
                {"no_eligible_candidate": 1},
            )
            self.assertEqual(len(manifest["model_feature_columns"]), 70)
            self.assertNotIn("paired_f9", manifest["model_feature_columns"])
            self.assertEqual(
                manifest["paired_f9"]["rows"],
                2,
            )
            self.assertEqual(
                manifest["paired_f9"]["assigned_rows"],
                1,
            )
            capture_membership = manifest["paired_f9"][
                "capture_memberships"
            ][0]
            self.assertEqual(
                capture_membership["membership_sha256"],
                dataset.paired_membership_sha256(CAPTURE_ID, [3, 4]),
            )
            self.assertEqual(
                capture_membership["assigned_membership_sha256"],
                dataset.paired_membership_sha256(CAPTURE_ID, [3]),
            )
            self.assertFalse(manifest["paired_f9"]["model_input"])

            parts = {
                (record["kind"], record["partition"]): record
                for record in manifest["parts"]
            }
            self.assertEqual(
                set(parts),
                {
                    ("assigned", "train"),
                    ("assigned", "validation"),
                    ("assigned", "test"),
                    ("quarantine", None),
                },
            )
            with pq.ParquetFile(
                root / parts[("assigned", "test")]["path"]
            ) as parquet:
                test_table = parquet.read(
                    columns=["flow_id", "packet_count", "paired_f9"]
                )
            self.assertEqual(test_table.column("flow_id").to_pylist(), [3])
            self.assertEqual(
                test_table.column("packet_count").to_pylist(), [9]
            )
            self.assertEqual(
                test_table.column("paired_f9").to_pylist(), [True]
            )

            resumed = dataset.build_dataset(inputs)
            self.assertEqual(resumed, manifest)
            self.assertEqual(dataset.validate_dataset(inputs), manifest)

    def test_assignment_and_quarantine_must_be_xor(self) -> None:
        with temporary_root() as root:
            inputs, _, _ = create_inputs(
                root, duplicate_assignment=True
            )
            with self.assertRaisesRegex(
                ValueError, "assignment XOR quarantine"
            ):
                dataset.build_dataset(inputs)
            self.assertFalse(
                dataset.capture_directory(inputs, CAPTURE_ID).exists()
            )

    def test_source_reconciliation_rejects_trusted_manifest_claim(self) -> None:
        with temporary_root() as root:
            inputs, shard_path, shard_manifest_path = create_inputs(root)
            with contextlib.closing(
                sqlite3.connect(shard_path)
            ) as connection:
                connection.execute(
                    """
                    UPDATE terminal_flow
                    SET last_event_timestamp_ns=last_event_timestamp_ns+1
                    WHERE flow_id=1
                    """
                )
                connection.commit()
            write_shard_manifest(
                root,
                shard_path,
                shard_manifest_path,
                inputs.source,
                inputs.feature_schema_path,
                inputs.feature_schema_sha256,
            )
            with self.assertRaisesRegex(
                ValueError, "terminal/source reconciliation failed"
            ):
                dataset.build_dataset(inputs)


if __name__ == "__main__":
    unittest.main()
