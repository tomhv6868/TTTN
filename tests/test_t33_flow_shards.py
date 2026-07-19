import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST_WORK = ROOT / "run_log" / "t3.3" / "test-work"
TEST_WORK.mkdir(parents=True, exist_ok=True)


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


shards = load_script(
    "export_t33_flow_shards_test", ROOT / "scripts" / "export_t33_flow_shards.py"
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    def __init__(self, exclusion_delta=0):
        self.base = TEST_WORK / f"flow-shard-{uuid.uuid4().hex}"
        self.root = self.base / "project"
        self.scratch = self.base / "scratch"
        (self.root / "config").mkdir(parents=True)
        self.scratch.mkdir()
        self.contract_path = (
            self.root / "config" / "cicids2017-label-join-contract.json"
        )
        self.contract = copy.deepcopy(
            shards.core.load_json(
                ROOT / "config" / "cicids2017-label-join-contract.json"
            )
        )
        self.capture = self.contract["captures"][0]
        self.capture_id = self.capture["id"]
        self.pcap = self.root / self.capture["pcap"]["path"]
        self.pcap.parent.mkdir(parents=True)
        self.pcap.write_bytes(b"fixture pcap")
        self.capture["pcap"]["size_bytes"] = self.pcap.stat().st_size
        self.capture["pcap"]["sha256"] = digest(self.pcap)

        receipt_spec = self.contract["exporter"]["parser_exclusion_policy"][
            "evidence"
        ]["file_receipts"][self.capture_id]
        receipt_target = self.root / receipt_spec["path"]
        receipt_target.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / receipt_spec["path"], receipt_target)

        self.contract_path.write_text(
            json.dumps(self.contract, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self.marker = self.base / "exporter-runs.txt"
        self.exporter = self.base / "fake_exporter.py"
        expected = self.contract["exporter"]["parser_exclusion_policy"][
            "expected_by_capture"
        ][self.capture_id]["total"]
        self.exporter.write_text(
            f"""import argparse, json
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--input'); p.add_argument('--capture-id'); a=p.parse_args()
marker=Path({str(self.marker)!r})
with marker.open('a', encoding='utf-8') as output: output.write(a.capture_id+'\\n')
flow={{'schema_version':1,'task':'T3.3','kind':'flow','capture_id':a.capture_id,
'protocol':'tcp','low_ip':'10.0.0.1','low_port':1234,'high_ip':'10.0.0.2','high_port':80,
'forward_source_ip':'10.0.0.1','forward_source_port':1234,'generation':1,
'clock_domain':'unix_epoch','creation_timestamp_ns':100,'last_capture_timestamp_ns':99,
'last_event_timestamp_ns':100,'packet_count':2,'forward_packet_count':1,
'reverse_packet_count':1,'close_reason':'end_of_input'}}
print(json.dumps(flow,separators=(',',':')))
excluded={expected + exclusion_delta}
summary={{'schema_version':1,'task':'T3.3','kind':'summary','status':'passed',
'input':a.input,'capture_id':a.capture_id,
'pcap':{{'records_read':excluded+2,'packets_parsed':2,'parser_errors':excluded,
'captured_bytes':1,'wire_bytes':1}},
'flows':{{'packets_accepted':2,'flow_generations_created':1,'flows_closed':1,
'active_flow_count':0}},'exported_flows':1,'parser_errors':excluded,'ingest_errors':0}}
print(json.dumps(summary,separators=(',',':')))
""",
            encoding="utf-8",
        )

    def close(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def export(self):
        return shards.export_capture(
            self.root,
            self.contract_path,
            self.exporter,
            self.scratch,
            self.capture_id,
            enforce_environment=False,
        )


class FlowShardTests(unittest.TestCase):
    def test_capture_export_publishes_valid_atomic_checkpoint_with_progress(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            receipt, skipped = fixture.export()

        self.assertFalse(skipped)
        self.assertEqual("passed", receipt["status"])
        self.assertEqual(1, receipt["summary"]["exported_flows"])
        capture_root, database, receipt_path = shards.checkpoint_paths(
            fixture.root, fixture.contract, fixture.capture_id
        )
        self.assertTrue(capture_root.is_dir())
        self.assertTrue(database.is_file())
        self.assertTrue(receipt_path.is_file())
        self.assertFalse(any(capture_root.parent.glob(".*.tmp")))
        with contextlib.closing(sqlite3.connect(database)) as connection:
            self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM flow").fetchone()[0])
            self.assertEqual("delete", connection.execute("PRAGMA journal_mode").fetchone()[0])
        self.assertIn("status=running", output.getvalue())
        self.assertIn("status=passed", output.getvalue())
        self.assertEqual(
            receipt,
            shards.validate_checkpoint(
                fixture.root, fixture.contract, fixture.capture_id, fixture.exporter
            ),
        )

    def test_valid_checkpoint_resume_skips_exporter(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        first, skipped = fixture.export()
        self.assertFalse(skipped)

        second, skipped = fixture.export()

        self.assertTrue(skipped)
        self.assertEqual(first, second)
        self.assertEqual([fixture.capture_id], fixture.marker.read_text(encoding="utf-8").splitlines())

    def test_checkpoint_database_tamper_is_fatal(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.export()
        _, database, _ = shards.checkpoint_paths(
            fixture.root, fixture.contract, fixture.capture_id
        )
        with database.open("r+b") as target:
            target.seek(-1, 2)
            value = target.read(1)
            target.seek(-1, 2)
            target.write(bytes([value[0] ^ 0xFF]))

        with self.assertRaisesRegex(ValueError, "checkpoint receipt mismatch"):
            shards.validate_checkpoint(
                fixture.root, fixture.contract, fixture.capture_id, fixture.exporter
            )

    def test_source_drift_fails_before_exporter_runs(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        with fixture.pcap.open("ab") as target:
            target.write(b" drift")

        with self.assertRaisesRegex(ValueError, "source identity mismatch"):
            fixture.export()

        self.assertFalse(fixture.marker.exists())

    def test_parser_exclusion_drift_does_not_publish_checkpoint(self):
        fixture = Fixture(exclusion_delta=1)
        self.addCleanup(fixture.close)

        with self.assertRaisesRegex(ValueError, "parser exclusion count mismatch"):
            fixture.export()

        capture_root, _, _ = shards.checkpoint_paths(
            fixture.root, fixture.contract, fixture.capture_id
        )
        self.assertFalse(capture_root.exists())


if __name__ == "__main__":
    unittest.main()
