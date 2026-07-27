from __future__ import annotations

import contextlib
import shutil
import sqlite3
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
from nids_mvp import full_flow_split as split


CAPTURE_ID = "synthetic-working-hours"
SOURCE_APPLICATION_ID = 0x22340001
ASSIGNMENT_APPLICATION_ID = 0x22340002


@contextlib.contextmanager
def temporary_root() -> Iterator[Path]:
    path = ROOT / f".t91-full-flow-split-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def flow(
    flow_id: int,
    block_index: int,
    packet_count: int,
    assigned_class: str,
    assignment_method: str = "mutual_unique",
) -> split.FlowDescriptor:
    return split.FlowDescriptor(
        capture_id=CAPTURE_ID,
        flow_id=flow_id,
        creation_timestamp_ns=block_index * split.BLOCK_NS + flow_id,
        packet_count=packet_count,
        assigned_class=assigned_class,
        assignment_method=assignment_method,
    )


def fixture_flows() -> list[split.FlowDescriptor]:
    return [
        flow(1, 0, 3, "BENIGN"),
        flow(2, 0, 1, "PortScan"),
        flow(3, 1, 4, "PortScan", "class_consensus"),
        flow(4, 1, 2, "BENIGN"),
        flow(5, 2, 1, "BENIGN"),
        flow(6, 2, 2, "PortScan"),
        flow(7, 3, 2, "BENIGN"),
        flow(8, 4, 9, "FTP-Patator"),
        flow(9, 4, 1, "BENIGN"),
    ]


def legacy_schema() -> pa.Schema:
    return pa.schema(
        [
            pa.field("capture_id", pa.string(), nullable=False),
            pa.field("flow_id", pa.uint64(), nullable=False),
            pa.field(
                "flow_start_timestamp_ns", pa.int64(), nullable=False
            ),
            pa.field("time_block_index", pa.int64(), nullable=False),
            pa.field(
                "time_block_start_timestamp_ns", pa.int64(), nullable=False
            ),
            pa.field("partition", pa.string(), nullable=False),
            pa.field("assigned_class", pa.string(), nullable=False),
            pa.field("label_binary", pa.bool_(), nullable=False),
            pa.field("assignment_method", pa.string(), nullable=False),
        ]
    )


def legacy_table(
    flows: list[split.FlowDescriptor],
    partitions: dict[int, str],
) -> pa.Table:
    selected = [
        item for item in flows if item.flow_id in partitions
    ]
    values = {
        "capture_id": [item.capture_id for item in selected],
        "flow_id": [item.flow_id for item in selected],
        "flow_start_timestamp_ns": [
            item.creation_timestamp_ns for item in selected
        ],
        "time_block_index": [item.block_index for item in selected],
        "time_block_start_timestamp_ns": [
            item.block_index * split.BLOCK_NS for item in selected
        ],
        "partition": [partitions[item.flow_id] for item in selected],
        "assigned_class": [item.assigned_class for item in selected],
        "label_binary": [
            item.assigned_class != "BENIGN" for item in selected
        ],
        "assignment_method": [item.assignment_method for item in selected],
    }
    schema = legacy_schema()
    return pa.Table.from_arrays(
        [
            pa.array(values[field.name], type=field.type)
            for field in schema
        ],
        schema=schema,
    )


def configure_database(
    connection: sqlite3.Connection, application_id: int
) -> None:
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute(f"PRAGMA application_id={application_id}")
    connection.execute("PRAGMA user_version=1")


def database_reference(
    path: Path, application_id: int
) -> dataset.DatabaseReference:
    return dataset.DatabaseReference(
        path=path,
        size_bytes=path.stat().st_size,
        sha256=dataset.sha256_path(path),
        application_id=application_id,
        user_version=1,
    )


def create_split_inputs(
    root: Path,
) -> tuple[split.SplitInputs, list[split.FlowDescriptor]]:
    flows = fixture_flows()
    source_path = root / "source.sqlite3"
    with contextlib.closing(sqlite3.connect(source_path)) as connection:
        configure_database(connection, SOURCE_APPLICATION_ID)
        connection.execute(
            """
            CREATE TABLE flow(
                flow_id INTEGER PRIMARY KEY,
                capture_id TEXT NOT NULL,
                creation_timestamp_ns INTEGER NOT NULL,
                packet_count INTEGER NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO flow VALUES(?,?,?,?)",
            [
                (
                    item.flow_id,
                    item.capture_id,
                    item.creation_timestamp_ns,
                    item.packet_count,
                )
                for item in flows
            ],
        )
        connection.commit()
    assignment_path = root / "assignment.sqlite3"
    with contextlib.closing(
        sqlite3.connect(assignment_path)
    ) as connection:
        configure_database(connection, ASSIGNMENT_APPLICATION_ID)
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
        connection.executemany(
            "INSERT INTO flow_assignment VALUES(?,?,?,?)",
            [
                (
                    item.flow_id,
                    item.capture_id,
                    item.assigned_class,
                    item.assignment_method,
                )
                for item in flows
            ],
        )
        connection.commit()
    legacy_path = root / "legacy.parquet"
    pq.write_table(
        legacy_table(
            flows,
            {1: "train", 3: "validation", 8: "test"},
        ),
        legacy_path,
    )
    legacy_reference = split.LegacyMapReference(
        path=legacy_path,
        size_bytes=legacy_path.stat().st_size,
        sha256=dataset.sha256_path(legacy_path),
        rows=3,
    )
    return (
        split.SplitInputs(
            root=root,
            source=database_reference(
                source_path, SOURCE_APPLICATION_ID
            ),
            assignment=database_reference(
                assignment_path, ASSIGNMENT_APPLICATION_ID
            ),
            legacy_map=legacy_reference,
            output_root=root / "split",
            capture_ids=(CAPTURE_ID,),
            expected_assigned_rows=len(flows),
            enforce_production_accounting=False,
        ),
        flows,
    )


class FullFlowSplitTest(unittest.TestCase):
    def test_extension_is_locked_atomic_and_deterministic(self) -> None:
        flows = fixture_flows()
        legacy = legacy_table(
            flows, {1: "train", 3: "validation", 8: "test"}
        )

        first = split.extend_capture(flows, legacy)
        second = split.extend_capture(list(reversed(flows)), legacy)
        self.assertEqual(first, second)

        by_id = {row.flow.flow_id: row for row in first}
        self.assertEqual(
            (by_id[1].partition, by_id[1].partition_source),
            ("train", "legacy_f3"),
        )
        self.assertEqual(
            (by_id[2].partition, by_id[2].partition_source),
            ("train", "locked_block_inheritance"),
        )
        self.assertEqual(
            (by_id[3].partition, by_id[3].partition_source),
            ("validation", "legacy_f3"),
        )
        self.assertEqual(
            (by_id[4].partition, by_id[4].partition_source),
            ("validation", "locked_block_inheritance"),
        )
        self.assertEqual(
            (by_id[8].partition, by_id[8].partition_source),
            ("test", "legacy_f3"),
        )
        self.assertEqual(
            (by_id[9].partition, by_id[9].partition_source),
            ("test", "locked_block_inheritance"),
        )
        self.assertEqual(by_id[5].partition, by_id[6].partition)
        self.assertEqual(
            by_id[5].partition_source, "short_only_block_allocation"
        )
        self.assertEqual(
            by_id[6].partition_source, "short_only_block_allocation"
        )
        block_partitions: dict[int, str] = {}
        for row in first:
            observed = block_partitions.setdefault(
                row.flow.block_index, row.partition
            )
            self.assertEqual(observed, row.partition)

        schema = split.split_schema("d" * 64)
        self.assertNotIn("features", schema.names)
        self.assertEqual(
            schema.metadata[b"nids.feature_columns_copied"], b"false"
        )
        self.assertEqual(
            schema.metadata[b"nids.test_partition_policy"],
            b"sealed_until_model_lock",
        )
        with temporary_root() as root:
            first_record = split.write_split_map(
                root / "first.parquet",
                {CAPTURE_ID: first},
                "d" * 64,
            )
            second_record = split.write_split_map(
                root / "second.parquet",
                {CAPTURE_ID: second},
                "d" * 64,
            )
            self.assertEqual(
                first_record["sha256"], second_record["sha256"]
            )

    def test_invalid_legacy_coverage_and_block_leakage_are_rejected(
        self,
    ) -> None:
        flows = fixture_flows()
        incomplete = legacy_table(
            flows, {1: "train", 8: "test"}
        )
        with self.assertRaisesRegex(
            ValueError, "legacy F3 coverage mismatch"
        ):
            split.extend_capture(flows, incomplete)

        leaking_flows = [
            flow(10, 10, 3, "BENIGN"),
            flow(11, 10, 4, "PortScan"),
        ]
        leaking = legacy_table(
            leaking_flows, {10: "train", 11: "test"}
        )
        with self.assertRaisesRegex(
            ValueError, "legacy time-block leakage"
        ):
            split.extend_capture(leaking_flows, leaking)

        valid = legacy_table(
            flows, {1: "train", 3: "validation", 8: "test"}
        )
        with self.assertRaisesRegex(
            ValueError, "terminal split policy mismatch"
        ):
            split.extend_capture(flows, valid, seed=split.SEED + 1)

    def test_build_is_atomic_resumable_and_metadata_only(self) -> None:
        with temporary_root() as root:
            inputs, flows = create_split_inputs(root)

            manifest, skipped = split.build_split(inputs)
            self.assertFalse(skipped)
            self.assertEqual(manifest["flow_map"]["rows"], len(flows))
            self.assertEqual(
                manifest["accounting"]["by_partition_source"][
                    "legacy_f3"
                ],
                3,
            )
            self.assertEqual(
                manifest["test_partition"],
                {
                    "status": "sealed",
                    "feature_or_metric_reads_allowed": False,
                },
            )
            map_path = root / manifest["flow_map"]["path"]
            with pq.ParquetFile(map_path) as parquet:
                self.assertEqual(
                    parquet.schema_arrow,
                    split.split_schema(inputs.legacy_map.sha256),
                )
                self.assertTrue(
                    set(parquet.schema_arrow.names).isdisjoint(
                        {f"feature_{index:02d}" for index in range(70)}
                    )
                )

            resumed, skipped = split.build_split(inputs)
            self.assertTrue(skipped)
            self.assertEqual(resumed, manifest)
            self.assertEqual(
                split.validate_output_manifest(inputs), manifest
            )


if __name__ == "__main__":
    unittest.main()
