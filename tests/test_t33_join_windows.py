import contextlib
import importlib.util
import io
import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


support = load_script(
    "t33_label_fixture_support", ROOT / "tests" / "test_t33_label_join.py"
)
shards = load_script(
    "export_t33_flow_shards", ROOT / "scripts" / "export_t33_flow_shards.py"
)
join = load_script(
    "run_t33_join_windows_test", ROOT / "scripts" / "run_t33_join_windows.py"
)


class PipelineFixture:
    def __init__(self):
        self.source = support.Fixture()
        self.root = self.source.root
        self.contract_path = self.source.contract_path
        self.contract = self.source.contract

    def close(self):
        self.source.close()

    def prepare_shards(self):
        with contextlib.redirect_stdout(io.StringIO()):
            for capture in self.contract["captures"]:
                shards.export_capture(
                    self.root,
                    self.contract_path,
                    self.source.exporter,
                    self.source.scratch,
                    capture["id"],
                    enforce_environment=False,
                )

    def run(self, max_stages):
        with contextlib.redirect_stdout(io.StringIO()):
            return join.run_pipeline(
                self.root,
                self.contract_path,
                max_stages,
                enforce_environment=False,
            )


class WindowsJoinTests(unittest.TestCase):
    def test_stage_plan_is_bounded_and_ordered(self):
        fixture = PipelineFixture()
        self.addCleanup(fixture.close)

        plan = join.stage_plan(fixture.contract)
        status = join.status_document(fixture.root, fixture.contract)

        self.assertEqual(22, len(plan))
        self.assertEqual("init", plan[0].key)
        self.assertEqual("flow:monday-working-hours", plan[1].key)
        self.assertEqual("labels:monday-working-hours", plan[2].key)
        self.assertEqual("edges:monday-working-hours", plan[3].key)
        self.assertEqual("sweep:60", plan[-1].key)
        self.assertEqual(0, status["completed_units"])
        self.assertEqual("init", status["next_stage"])

    def test_init_is_a_durable_single_stage_checkpoint(self):
        fixture = PipelineFixture()
        self.addCleanup(fixture.close)

        status = fixture.run(1)

        self.assertEqual(1, status["completed_units"])
        self.assertEqual("flow:monday-working-hours", status["next_stage"])
        _, database = join.work_paths(fixture.root, fixture.contract)
        with contextlib.closing(sqlite3.connect(database)) as connection:
            stages = connection.execute(
                "SELECT stage_key FROM pipeline_stage ORDER BY ordinal"
            ).fetchall()
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
        self.assertEqual([("init",)], stages)
        self.assertTrue(
            {"flow_join_idx", "label_join_idx", "edge_tolerance_idx"} <= indexes
        )

    def test_full_pipeline_completes_all_capture_and_tolerance_stages(self):
        fixture = PipelineFixture()
        self.addCleanup(fixture.close)
        fixture.prepare_shards()

        status = fixture.run(999)

        self.assertEqual("ready_for_phase_c", status["status"])
        self.assertEqual(22, status["completed_units"])
        self.assertIsNone(status["next_stage"])
        _, database = join.work_paths(fixture.root, fixture.contract)
        with contextlib.closing(sqlite3.connect(database)) as connection:
            self.assertEqual(8, connection.execute("SELECT COUNT(*) FROM flow").fetchone()[0])
            self.assertEqual(8, connection.execute("SELECT COUNT(*) FROM label_row").fetchone()[0])
            self.assertEqual(
                2,
                connection.execute(
                    "SELECT COUNT(*) FROM quarantined_label_row"
                ).fetchone()[0],
            )
            self.assertEqual(
                6, connection.execute("SELECT COUNT(*) FROM sweep_summary").fetchone()[0]
            )
        resumed = fixture.run(999)
        self.assertEqual(22, resumed["completed_units"])

    def test_resume_continues_at_next_stage_without_duplicate_imports(self):
        fixture = PipelineFixture()
        self.addCleanup(fixture.close)
        fixture.prepare_shards()
        first = fixture.run(4)
        self.assertEqual("flow:tuesday-working-hours", first["next_stage"])

        second = fixture.run(1)

        self.assertEqual(5, second["completed_units"])
        self.assertEqual("labels:tuesday-working-hours", second["next_stage"])
        _, database = join.work_paths(fixture.root, fixture.contract)
        with contextlib.closing(sqlite3.connect(database)) as connection:
            captures = connection.execute(
                "SELECT capture_id,COUNT(*) FROM flow GROUP BY capture_id ORDER BY capture_id"
            ).fetchall()
        self.assertEqual(
            [("monday-working-hours", 1), ("tuesday-working-hours", 1)], captures
        )

    def test_failed_next_stage_rolls_back_and_keeps_completed_prefix(self):
        fixture = PipelineFixture()
        self.addCleanup(fixture.close)
        fixture.prepare_shards()
        fixture.run(2)
        first_csv = fixture.root / fixture.contract["captures"][0]["csv"][0]["path"]
        with first_csv.open("ab") as output:
            output.write(b"drift")

        with self.assertRaisesRegex(ValueError, "CSV source identity mismatch"):
            fixture.run(1)

        status = join.status_document(fixture.root, fixture.contract)
        self.assertEqual(2, status["completed_units"])
        self.assertEqual("labels:monday-working-hours", status["next_stage"])


if __name__ == "__main__":
    unittest.main()
