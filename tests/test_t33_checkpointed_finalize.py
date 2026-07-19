import contextlib
import importlib.util
import io
import json
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


pipeline_support = load_script(
    "t33_windows_pipeline_support",
    ROOT / "tests" / "test_t33_join_windows.py",
)
finalizer = load_script(
    "finalize_t33_checkpointed_test",
    ROOT / "scripts" / "finalize_t33_checkpointed.py",
)


class CheckpointedFinalizeTests(unittest.TestCase):
    def make_complete_fixture(self):
        fixture = pipeline_support.PipelineFixture()
        self.addCleanup(fixture.close)
        fixture.prepare_shards()
        fixture.run(999)
        return fixture

    def run_finalize(self, fixture):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            acceptance = finalizer.finalize(
                fixture.root,
                fixture.contract_path,
                enforce_environment=False,
            )
        return acceptance, output.getvalue()

    def test_finalize_publishes_legacy_compatible_artifacts_after_independent_check(self):
        fixture = self.make_complete_fixture()

        acceptance, output = self.run_finalize(fixture)

        database, build_path, acceptance_path = finalizer.artifact_paths(
            fixture.root, fixture.contract
        )
        build = finalizer.core.load_json(build_path)
        self.assertEqual("passed", acceptance["status"])
        self.assertTrue(database.is_file())
        self.assertTrue(build_path.is_file())
        self.assertTrue(acceptance_path.is_file())
        self.assertFalse(database.with_name(database.name + "-wal").exists())
        self.assertFalse(database.with_name(database.name + "-shm").exists())
        self.assertFalse(any(database.parent.glob(f".{database.name}.*.tmp")))
        self.assertIn('"stage":"independent-verify"', output)
        self.assertIn('"completed_units":6', output)
        with contextlib.closing(sqlite3.connect(database)) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        self.assertEqual(set(finalizer.verifier.TABLE_COLUMNS), tables)
        self.assertEqual(
            [],
            finalizer.verifier.validate_receipt(
                build,
                fixture.contract,
                fixture.root,
                database,
                rehash_sources=True,
            ),
        )

        resumed, _ = self.run_finalize(fixture)
        self.assertEqual(acceptance, resumed)

    def test_incomplete_join_fails_before_creating_final_artifacts(self):
        fixture = pipeline_support.PipelineFixture()
        self.addCleanup(fixture.close)
        fixture.prepare_shards()
        fixture.run(1)

        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
            ValueError, "Windows join is incomplete: 1/22"
        ):
            finalizer.finalize(
                fixture.root,
                fixture.contract_path,
                enforce_environment=False,
            )

        for path in finalizer.artifact_paths(fixture.root, fixture.contract):
            self.assertFalse(path.exists())

    def test_existing_acceptance_is_rejected_when_its_hash_evidence_is_tampered(self):
        fixture = self.make_complete_fixture()
        self.run_finalize(fixture)
        _, _, acceptance_path = finalizer.artifact_paths(
            fixture.root, fixture.contract
        )
        acceptance = json.loads(acceptance_path.read_text(encoding="utf-8"))
        acceptance["sqlite"]["sha256"] = "0" * 64
        acceptance_path.write_text(
            json.dumps(acceptance, indent=2) + "\n", encoding="utf-8"
        )

        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
            ValueError, "acceptance SQLite evidence mismatch"
        ):
            finalizer.finalize(
                fixture.root,
                fixture.contract_path,
                enforce_environment=False,
            )


if __name__ == "__main__":
    unittest.main()
