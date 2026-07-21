from __future__ import annotations

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
TEST_ROOT = ROOT / "run_log" / "t3.6" / "test-work"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build = load_script("build_t36_splits", ROOT / "scripts/build_t36_splits.py")
verify = load_script("verify_t36_splits_test", ROOT / "scripts/verify_t36_splits.py")


class SplitFixture:
    capture_id = "fixture-capture"

    def __init__(self) -> None:
        self.root = TEST_ROOT / uuid.uuid4().hex
        self.source_root = self.root / "dataset-v1"
        self.source_root.mkdir(parents=True)
        self.records: list[dict] = []
        self._write_checkpoint("F3", 3, 30)
        self._write_checkpoint("F5", 5, 15)

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _write_checkpoint(self, name: str, value: int, rows: int) -> None:
        path = (
            self.source_root
            / f"checkpoint={name}"
            / f"capture_id={self.capture_id}"
            / "part-00000.parquet"
        )
        path.parent.mkdir(parents=True)
        flow_ids = list(range(1, rows + 1))
        timestamps = [((flow_id - 1) // 3) * build.BLOCK_NS + flow_id for flow_id in flow_ids]
        families = ["BENIGN" if flow_id % 3 else "Attack A" for flow_id in flow_ids]
        table = pa.table(
            {
                "capture_id": pa.array([self.capture_id] * rows, type=pa.string()),
                "flow_id": pa.array(flow_ids, type=pa.uint64()),
                "flow_start_timestamp_ns": pa.array(timestamps, type=pa.int64()),
                "checkpoint": pa.array([value] * rows, type=pa.uint8()),
                "assigned_class": pa.array(families, type=pa.string()),
                "label_binary": pa.array(
                    [family != "BENIGN" for family in families], type=pa.bool_()
                ),
                "assignment_method": pa.array(["class_consensus"] * rows, type=pa.string()),
            }
        )
        pq.write_table(table, path)
        self.records.append(
            {
                "path": path.relative_to(self.root).as_posix(),
                "resolved_path": path,
                "rows": rows,
            }
        )

    def create_map(self, name: str = "known.parquet") -> tuple[Path, dict[int, str]]:
        blocks = build.collect_blocks(self.records)
        assignments = build.allocate_capture(
            self.capture_id,
            blocks[self.capture_id],
            {"train": 70, "validation": 10, "test": 20},
            3607,
        )
        output = self.root / name
        build.write_flow_map(
            output,
            self.records,
            {self.capture_id: assignments},
            build.flow_map_schema("a" * 64),
        )
        return output, assignments


class T36SplitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SplitFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_contract_locks_70_10_20_and_declarative_loafo(self):
        contract = json.loads(
            (ROOT / "config/cicids2017-split-contract.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            contract["known_protocol"]["ratios"],
            {"train": 70, "validation": 10, "test": 20},
        )
        self.assertEqual(contract["known_protocol"]["allocation_unit"], "entire_time_block")
        self.assertTrue(contract["known_protocol"]["same_flow_all_checkpoints_same_partition"])
        self.assertEqual(
            contract["unknown_protocol"]["materialization"], "declarative_manifest_only"
        )
        self.assertFalse(contract["flow_map"]["feature_columns_copied"])
        self.assertEqual(contract["unknown_protocol"]["heartbleed"]["status"], "unavailable")

    def test_allocation_is_deterministic_and_keeps_mixed_blocks_atomic(self):
        blocks = build.collect_blocks(self.fixture.records)[self.fixture.capture_id]
        first = build.allocate_capture(
            self.fixture.capture_id,
            blocks,
            {"train": 70, "validation": 10, "test": 20},
            3607,
        )
        second = build.allocate_capture(
            self.fixture.capture_id,
            blocks,
            {"train": 70, "validation": 10, "test": 20},
            3607,
        )
        self.assertEqual(first, second)
        self.assertEqual(set(first), set(blocks))
        self.assertEqual(set(first.values()), {"train", "validation", "test"})
        self.assertTrue(all(len(counts) == 2 for counts in blocks.values()))

    def test_flow_map_is_byte_reproducible_and_matches_f3_exactly(self):
        first, assignments = self.fixture.create_map("first.parquet")
        second = self.fixture.root / "second.parquet"
        build.write_flow_map(
            second,
            self.fixture.records,
            {self.fixture.capture_id: assignments},
            build.flow_map_schema("a" * 64),
        )
        self.assertEqual(build.sha256_path(first), build.sha256_path(second))
        blocks, flows, accounting = verify.require_exact_source_match(
            first, self.fixture.records
        )
        self.assertEqual(accounting["rows"], 30)
        self.assertEqual(accounting["blocks"], 10)
        self.assertEqual(len(blocks), 10)
        self.assertEqual(len(flows[self.fixture.capture_id]), 30)

    def test_validator_rejects_time_block_leakage(self):
        flow_map, _ = self.fixture.create_map()
        table = pq.read_table(flow_map, partitioning=None)
        values = table.to_pydict()
        original = values["partition"][0]
        values["partition"][0] = next(item for item in verify.PARTITIONS if item != original)
        bad = self.fixture.root / "bad.parquet"
        pq.write_table(pa.Table.from_pydict(values, schema=table.schema), bad)
        with self.assertRaisesRegex(ValueError, "time-block leakage"):
            verify.require_exact_source_match(bad, self.fixture.records)

    def test_checkpoint_accounting_resolves_every_snapshot_through_f3(self):
        flow_map, _ = self.fixture.create_map()
        _, flows, _ = verify.require_exact_source_match(flow_map, self.fixture.records)
        accounting = verify.checkpoint_accounting(self.fixture.records, flows)
        f3 = sum(
            accounting["by_partition_and_checkpoint"][partition].get("F3", 0)
            for partition in verify.PARTITIONS
        )
        f5 = sum(
            accounting["by_partition_and_checkpoint"][partition].get("F5", 0)
            for partition in verify.PARTITIONS
        )
        self.assertEqual((f3, f5), (30, 15))

    def test_loafo_moves_holdout_train_and_validation_to_test(self):
        known = {
            "by_partition_and_checkpoint": {
                "train": {checkpoint: 70 for checkpoint in verify.CHECKPOINTS},
                "validation": {checkpoint: 10 for checkpoint in verify.CHECKPOINTS},
                "test": {checkpoint: 20 for checkpoint in verify.CHECKPOINTS},
            }
        }
        family_counts = {
            "BENIGN": {
                "train": {checkpoint: 60 for checkpoint in verify.CHECKPOINTS},
                "validation": {checkpoint: 8 for checkpoint in verify.CHECKPOINTS},
                "test": {checkpoint: 18 for checkpoint in verify.CHECKPOINTS},
            },
            "Attack A": {
                "train": {checkpoint: 10 for checkpoint in verify.CHECKPOINTS},
                "validation": {checkpoint: 2 for checkpoint in verify.CHECKPOINTS},
                "test": {checkpoint: 2 for checkpoint in verify.CHECKPOINTS},
            },
        }
        experiments, families = build.loafo_experiments(family_counts, known)
        self.assertEqual(families, ["Attack A"])
        rows = experiments[0]["expected_snapshot_rows"]
        self.assertEqual(rows["train"]["F3"], 60)
        self.assertEqual(rows["validation"]["F3"], 8)
        self.assertEqual(rows["test"]["F3"], 32)
        self.assertEqual(experiments[0]["proof"]["holdout_train_rows"], 0)


if __name__ == "__main__":
    unittest.main()
