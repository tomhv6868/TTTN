import copy
import csv
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import shutil
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path
from zoneinfo import ZoneInfo


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


builder = load_script("build_t33_label_join", ROOT / "scripts" / "build_t33_label_join.py")
verifier = load_script("verify_t33_label_join", ROOT / "scripts" / "verify_t33_label_join.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    def __init__(self, malformed=False):
        self.base = TEST_WORK / f"fixture-{uuid.uuid4().hex}"
        self.root = self.base / "project"
        self.scratch = self.base / "scratch"
        (self.root / "config").mkdir(parents=True)
        self.scratch.mkdir()
        (self.root / "run_log" / "t3.1").mkdir(parents=True)
        self.contract_path = self.root / "config" / "cicids2017-label-join-contract.json"
        self.contract = copy.deepcopy(
            builder.load_json(ROOT / "config" / "cicids2017-label-join-contract.json")
        )
        survey_evidence = self.contract["exporter"]["parser_exclusion_policy"]["evidence"]
        for spec in [survey_evidence, *survey_evidence["file_receipts"].values()]:
            source = ROOT / spec["path"]
            target = self.root / spec["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.contract["attack_audit"]["events"] = []
        self.rows = {}
        dates = ["03/07/2017", "04/07/2017", "05/07/2017", "06/07/2017", "07/07/2017"]
        flow_mapping = {}
        for capture_index, capture in enumerate(self.contract["captures"]):
            pcap = self.root / capture["pcap"]["path"]
            pcap.parent.mkdir(parents=True, exist_ok=True)
            pcap.write_bytes(b"fixture-pcap-" + capture["id"].encode("ascii"))
            capture["pcap"]["size_bytes"] = pcap.stat().st_size
            capture["pcap"]["sha256"] = digest(pcap)
            flow_mapping[capture["id"]] = []
            for csv_index, csv_spec in enumerate(capture["csv"]):
                source_ip = f"10.{capture_index}.0.{csv_index + 1}"
                destination_ip = f"10.{capture_index}.1.{csv_index + 1}"
                source_port = 10000 + capture_index * 100 + csv_index
                destination_port = 443
                row = {
                    "Flow ID": f"fixture-{capture_index}-{csv_index}",
                    "Source IP": source_ip,
                    "Source Port": str(source_port),
                    "Destination IP": destination_ip,
                    "Destination Port": str(destination_port),
                    "Protocol": "6",
                    "Timestamp": f"{dates[capture_index]} 12:00",
                    "Flow Duration": "1000000",
                    "Total Fwd Packets": "1",
                    "Total Backward Packets": "1",
                    "Label": "BENIGN",
                }
                self.rows[csv_spec["path"]] = [row]
                csv_spec["label_counts"] = {"BENIGN": 1}
                csv_spec["protocol_counts"] = {"6": 1}
                csv_spec["negative_duration_count"] = 0
                csv_spec["physical_record_count"] = 1
                csv_spec["all_empty_record_count"] = 0
                csv_spec["nonempty_record_count"] = 1
                start = dt.datetime.strptime(row["Timestamp"], "%d/%m/%Y %H:%M").replace(
                    tzinfo=ZoneInfo("America/Moncton")
                )
                start_ns = int(start.timestamp()) * 1_000_000_000
                low, high = sorted(
                    ((int(ipaddress.ip_address(source_ip)), source_port),
                     (int(ipaddress.ip_address(destination_ip)), 443))
                )
                flow_mapping[capture["id"]].append(
                    {
                        "low_ip": str(ipaddress.ip_address(low[0])),
                        "low_port": low[1],
                        "high_ip": str(ipaddress.ip_address(high[0])),
                        "high_port": high[1],
                        "forward_source_ip": source_ip,
                        "forward_source_port": source_port,
                        "timestamp_ns": start_ns + 500_000_000,
                    }
                )
        first = self.contract["captures"][0]["csv"][0]
        unsupported = copy.deepcopy(self.rows[first["path"]][0])
        unsupported["Flow ID"] += "-unsupported"
        unsupported["Protocol"] = "0"
        self.rows[first["path"]].append(unsupported)
        invalid_duration = copy.deepcopy(self.rows[first["path"]][0])
        invalid_duration["Flow ID"] += "-invalid-duration"
        invalid_duration["Flow Duration"] = "-1"
        self.rows[first["path"]].append(invalid_duration)
        first["physical_record_count"] = 3
        first["nonempty_record_count"] = 3
        first["label_counts"] = {"BENIGN": 3}
        first["protocol_counts"] = {"0": 1, "6": 2}
        first["negative_duration_count"] = 1
        thursday = self.contract["captures"][3]["csv"][0]
        thursday["physical_record_count"] = 2
        thursday["all_empty_record_count"] = 1
        self.empty_csv_path = thursday["path"]
        if malformed:
            first = self.contract["captures"][0]["csv"][0]
            first["physical_record_count"] = 4
            first["nonempty_record_count"] = 4
            first["label_counts"] = {"BENIGN": 4}
            first["protocol_counts"] = {"0": 1, "6": 3}
        self._write_csv_files(malformed)
        inventory = self.root / self.contract["source_evidence"]["inventory_receipt"]["path"]
        inventory.write_text(json.dumps({"task": "T3.1", "status": "passed"}), encoding="utf-8")
        self.contract["source_evidence"]["inventory_receipt"]["sha256"] = digest(inventory)
        self.contract_path.write_text(
            json.dumps(self.contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        self.exporter = self.root / "fake_exporter.py"
        self._write_exporter(flow_mapping)

    def close(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _header(self):
        required = list(self.contract["csv_schema"]["required_columns"])
        return required + ["Fwd Header Length", "Fwd Header Length"] + [
            f"Fixture Field {index}" for index in range(72)
        ]

    def _write_csv_files(self, malformed):
        header = self._header()
        self.assert_header_width = len(header)
        for path_text, rows in self.rows.items():
            path = self.root / path_text
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="cp1252", newline="") as output:
                writer = csv.writer(output, lineterminator="\r\n")
                writer.writerow(header)
                for row in rows:
                    writer.writerow([row.get(name, "0") for name in header])
                if path_text == self.empty_csv_path:
                    writer.writerow([""] * 85)
                if malformed and path_text == self.contract["captures"][0]["csv"][0]["path"]:
                    writer.writerow(["bad"] * 84)
            spec = next(
                item
                for capture in self.contract["captures"]
                for item in capture["csv"]
                if item["path"] == path_text
            )
            spec["size_bytes"] = path.stat().st_size
            spec["sha256"] = digest(path)

    def _write_exporter(self, mapping):
        exclusions = {
            capture_id: counts["total"]
            for capture_id, counts in self.contract["exporter"][
                "parser_exclusion_policy"
            ]["expected_by_capture"].items()
        }
        script = f"""import argparse, json
p=argparse.ArgumentParser(); p.add_argument('--input'); p.add_argument('--capture-id'); a=p.parse_args()
mapping={mapping!r}
exclusions={exclusions!r}
flows=mapping[a.capture_id]
for index, flow in enumerate(flows):
    timestamp=flow.pop('timestamp_ns')
    value={{'schema_version':1,'task':'T3.3','kind':'flow','capture_id':a.capture_id,
      'protocol':'tcp',**flow,'generation':index+1,'clock_domain':'unix_epoch',
      'creation_timestamp_ns':timestamp,'last_capture_timestamp_ns':timestamp-1,
      'last_event_timestamp_ns':timestamp,'packet_count':2,
      'forward_packet_count':1,'reverse_packet_count':1,'close_reason':'end_of_input'}}
    print(json.dumps(value,separators=(',',':')))
count=len(flows)
excluded=exclusions[a.capture_id]
summary={{'schema_version':1,'task':'T3.3','kind':'summary','status':'passed','input':a.input,
 'capture_id':a.capture_id,'pcap':{{'records_read':count*2+excluded,'packets_parsed':count*2,
 'parser_errors':excluded,'captured_bytes':1,'wire_bytes':1}},
 'flows':{{'packets_accepted':count*2,'flow_generations_created':count,'flows_closed':count,
 'active_flow_count':0}},'exported_flows':count,'parser_errors':excluded,'ingest_errors':0}}
print(json.dumps(summary,separators=(',',':')))
"""
        self.exporter.write_text(script, encoding="utf-8")

    def build(self):
        return builder.build_join(
            self.root,
            self.contract_path,
            self.exporter,
            self.scratch,
            enforce_environment=False,
        )


class ContractAndTimeTests(unittest.TestCase):
    def test_locked_contract_has_exact_full_mapping_and_no_timezone_overclaim(self):
        contract = builder.load_json(ROOT / "config" / "cicids2017-label-join-contract.json")

        self.assertEqual([], builder.validate_contract(contract))
        self.assertEqual(5, len(contract["captures"]))
        self.assertEqual(8, sum(len(item["csv"]) for item in contract["captures"]))
        self.assertFalse(contract["source_evidence"]["official_schedule"]["timezone_published"])
        self.assertEqual([0, 1, 5, 10, 30, 60], contract["join"]["tolerance_sweep_seconds"])
        self.assertEqual(
            1696,
            sum(
                spec["protocol_counts"].get("0", 0)
                for capture in contract["captures"]
                for spec in capture["csv"]
            ),
        )
        self.assertEqual(
            "quarantine_without_join_or_training",
            contract["join"]["unsupported_label_protocol_policy"]["action"],
        )
        self.assertEqual(
            115,
            sum(
                spec["negative_duration_count"]
                for capture in contract["captures"]
                for spec in capture["csv"]
            ),
        )
        self.assertEqual(
            "quarantine_without_join_or_training",
            contract["join"]["invalid_flow_duration_policy"]["action"],
        )
        exclusions = contract["exporter"]["parser_exclusion_policy"]
        self.assertEqual(
            418873,
            sum(item["total"] for item in exclusions["expected_by_capture"].values()),
        )
        self.assertEqual(
            "exact_by_capture_from_locked_t1_2_full_scan",
            exclusions["accounting"],
        )

    def test_dmy_minute_and_second_timestamp_variants_preserve_12h_ambiguity(self):
        contract = builder.load_json(ROOT / "config" / "cicids2017-label-join-contract.json")
        zone = ZoneInfo("America/Moncton")

        minute = builder.timestamp_variants("7/7/2017 3:56", contract, zone)
        second = builder.timestamp_variants("03/07/2017 08:55:58", contract, zone)

        self.assertEqual(["as_written", "plus_12h"], [item[0] for item in minute])
        self.assertEqual(60_000_000_000, minute[0][2])
        self.assertEqual(1_000_000_000, second[0][2])
        self.assertEqual(12 * 60 * 60 * 1_000_000_000, minute[1][1] - minute[0][1])

    def test_exporter_flow_accepts_capture_order_regression_with_valid_event_bounds(self):
        flow = {
            "schema_version": 1,
            "task": "T3.3",
            "kind": "flow",
            "capture_id": "capture",
            "protocol": "tcp",
            "low_ip": "10.0.0.1",
            "low_port": 443,
            "high_ip": "10.0.0.2",
            "high_port": 50000,
            "forward_source_ip": "10.0.0.2",
            "forward_source_port": 50000,
            "generation": 1,
            "clock_domain": "unix_epoch",
            "creation_timestamp_ns": 100,
            "last_capture_timestamp_ns": 90,
            "last_event_timestamp_ns": 100,
            "packet_count": 2,
            "forward_packet_count": 1,
            "reverse_packet_count": 1,
            "close_reason": "tcp_reset",
        }

        builder.validate_flow(flow, "capture")

        invalid_bounds = copy.deepcopy(flow)
        invalid_bounds["last_event_timestamp_ns"] = 99
        with self.assertRaisesRegex(ValueError, "event-time bounds"):
            builder.validate_flow(invalid_bounds, "capture")

        invalid_packets = copy.deepcopy(flow)
        invalid_packets["packet_count"] = 3
        with self.assertRaisesRegex(ValueError, "packet accounting"):
            builder.validate_flow(invalid_packets, "capture")

    def test_schedule_and_roles_are_unordered_audits_not_timestamp_rewrites(self):
        contract = builder.load_json(ROOT / "config" / "cicids2017-label-join-contract.json")
        zone = builder.validate_timezone(contract)
        events = builder.compile_events(contract, zone)
        start = builder.timestamp_variants("6/7/2017 9:20", contract, zone)[0][1]

        schedule, role, event_ids = builder.audit_variant(
            "Web Attack – Brute Force",
            int(ipaddress.ip_address("192.168.10.50")),
            int(ipaddress.ip_address("172.16.0.1")),
            start,
            start + 60_000_000_000,
            contract,
            events,
        )
        early = builder.timestamp_variants("6/7/2017 9:15", contract, zone)[0][1]
        early_schedule, _, _ = builder.audit_variant(
            "Web Attack – Brute Force",
            int(ipaddress.ip_address("172.16.0.1")),
            int(ipaddress.ip_address("192.168.10.50")),
            early,
            early + 60_000_000_000,
            contract,
            events,
        )

        self.assertEqual((0, 0), (schedule, role))
        self.assertIn("thu-web-bruteforce", event_ids)
        self.assertEqual(1, early_schedule)


class GraphTests(unittest.TestCase):
    def test_mutual_uniqueness_accounts_matched_ambiguous_unmatched_and_conflict(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript("""
            CREATE TABLE flow(flow_id INTEGER PRIMARY KEY);
            CREATE TABLE label_row(label_id INTEGER PRIMARY KEY);
            CREATE TABLE candidate_edge(
                flow_id INTEGER,label_id INTEGER,variant TEXT,required_tolerance_ns INTEGER,
                schedule_conflict INTEGER,role_conflict INTEGER
            );
            CREATE TABLE sweep_summary(
                tolerance_seconds INTEGER PRIMARY KEY,raw_edge_count INTEGER,eligible_edge_count INTEGER,
                matched_count INTEGER,flow_total INTEGER,flow_unmatched INTEGER,flow_ambiguous INTEGER,
                flow_audit_conflict INTEGER,label_total INTEGER,label_unmatched INTEGER,
                label_ambiguous INTEGER,label_audit_conflict INTEGER
            );
        """)
        connection.executemany("INSERT INTO flow VALUES(?)", [(1,), (2,), (3,), (4,)])
        connection.executemany("INSERT INTO label_row VALUES(?)", [(10,), (11,), (12,), (13,), (14,)])
        connection.executemany(
            "INSERT INTO candidate_edge VALUES(?,?,?,?,?,?)",
            [(1, 10, "v", 0, 0, 0), (2, 11, "v", 0, 0, 0),
             (2, 12, "v", 0, 0, 0), (4, 13, "v", 0, 1, 0)],
        )
        contract = {"join": {"tolerance_sweep_seconds": [0, 1, 5, 10, 30, 60]}}

        zero = builder.compute_sweeps(connection, contract)[0]

        self.assertEqual(1, zero["matched_count"])
        self.assertEqual((1, 1, 1), (zero["flow_unmatched"], zero["flow_ambiguous"], zero["flow_audit_conflict"]))
        self.assertEqual((1, 2, 1), (zero["label_unmatched"], zero["label_ambiguous"], zero["label_audit_conflict"]))


class BuildAndVerifierTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()

    def test_fake_streaming_exporter_builds_sqlite_and_independent_verifier_accepts(self):
        receipt = self.fixture.build()
        database = self.fixture.root / receipt["sqlite"]["path"]

        errors = verifier.validate_receipt(
            receipt,
            self.fixture.contract,
            self.fixture.root,
            database,
            rehash_sources=True,
        )

        self.assertEqual([], errors)
        self.assertEqual(1, receipt["labels"]["all_empty_records"])
        self.assertEqual(2, receipt["labels"]["quarantined_records"])
        self.assertEqual(
            {"invalid_flow_duration": 1, "unsupported_protocol": 1},
            receipt["labels"]["quarantine_reason_counts"],
        )
        self.assertEqual(
            418873,
            sum(item["parser_errors"] for item in receipt["exporter"]["summaries"]),
        )
        self.assertEqual(receipt["flows"]["total"], receipt["sweeps"][0]["matched_count"])
        self.assertFalse(database.with_name(database.name + "-wal").exists())
        connection = sqlite3.connect(database)
        try:
            self.assertEqual(
                [
                    (0, 1_000_000, "BENIGN", "unsupported_protocol"),
                    (6, -1, "BENIGN", "invalid_flow_duration"),
                ],
                connection.execute(
                    "SELECT protocol,duration_us,label,reason "
                    "FROM quarantined_label_row ORDER BY quarantine_id"
                ).fetchall(),
            )
        finally:
            connection.close()

    def test_nonempty_malformed_csv_record_fails_closed(self):
        self.fixture.close()
        self.fixture = Fixture(malformed=True)

        with self.assertRaisesRegex(ValueError, "nonempty malformed CSV record"):
            self.fixture.build()

    def test_exporter_process_parser_exclusion_drift_and_ingest_failures_are_fatal(self):
        self.fixture.exporter.write_text("import sys; sys.exit(3)\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "exporter failed"):
            self.fixture.build()

        summary = {
            "schema_version": 1, "task": "T3.3", "kind": "summary", "status": "passed",
            "input": "x", "capture_id": "capture", "pcap": {
                "records_read": 1, "packets_parsed": 0, "parser_errors": 1,
            },
            "flows": {"packets_accepted": 0, "flow_generations_created": 0, "flows_closed": 0, "active_flow_count": 0},
            "exported_flows": 0, "parser_errors": 1, "ingest_errors": 0,
        }
        counters = builder.validate_summary(
            summary, "capture", 0, expected_parser_exclusions=1
        )
        self.assertEqual(1, counters["parser_errors"])
        with self.assertRaisesRegex(ValueError, "parser exclusion count mismatch"):
            builder.validate_summary(summary, "capture", 0)
        ingest_summary = copy.deepcopy(summary)
        ingest_summary["pcap"].update(
            {"records_read": 1, "packets_parsed": 1, "parser_errors": 0}
        )
        ingest_summary["parser_errors"] = 0
        ingest_summary["ingest_errors"] = 1
        with self.assertRaisesRegex(ValueError, "fatal"):
            builder.validate_summary(ingest_summary, "capture", 0)

    def test_verifier_detects_database_tamper_instead_of_trusting_receipt(self):
        receipt = self.fixture.build()
        database = self.fixture.root / receipt["sqlite"]["path"]
        connection = sqlite3.connect(database)
        connection.execute("UPDATE metadata SET value='tampered' WHERE key='decision'")
        connection.commit()
        connection.close()

        errors = verifier.validate_receipt(
            receipt, self.fixture.contract, self.fixture.root, database
        )

        self.assertTrue(any("hash mismatch" in error or "decision mismatch" in error for error in errors))

    def test_verifier_independently_rederives_candidate_graph(self):
        receipt = self.fixture.build()
        database = self.fixture.root / receipt["sqlite"]["path"]
        connection = sqlite3.connect(database)
        connection.execute("DELETE FROM candidate_edge WHERE flow_id=1")
        connection.execute("DELETE FROM sweep_summary")
        receipt["sweeps"] = builder.compute_sweeps(connection, self.fixture.contract)
        receipt["candidate_edges"] = connection.execute(
            "SELECT COUNT(*) FROM candidate_edge"
        ).fetchone()[0]
        connection.commit()
        connection.close()
        receipt["sqlite"]["size_bytes"] = database.stat().st_size
        receipt["sqlite"]["sha256"] = digest(database)

        errors = verifier.validate_receipt(
            receipt, self.fixture.contract, self.fixture.root, database
        )

        self.assertIn(
            "candidate graph differs from independently derived graph",
            errors,
        )

    def test_verifier_detects_quarantine_tamper(self):
        receipt = self.fixture.build()
        database = self.fixture.root / receipt["sqlite"]["path"]
        connection = sqlite3.connect(database)
        connection.execute("UPDATE quarantined_label_row SET reason='tampered'")
        connection.commit()
        connection.close()
        receipt["sqlite"]["size_bytes"] = database.stat().st_size
        receipt["sqlite"]["sha256"] = digest(database)

        errors = verifier.validate_receipt(
            receipt, self.fixture.contract, self.fixture.root, database
        )

        self.assertIn("invalid quarantined label identity or reason", errors)

    def test_exporter_summary_must_name_the_scanned_pcap(self):
        summary = {
            "schema_version": 1,
            "task": "T3.3",
            "kind": "summary",
            "status": "passed",
            "input": "wrong.pcap",
            "capture_id": "capture",
            "pcap": {"records_read": 0, "packets_parsed": 0, "parser_errors": 0},
            "flows": {
                "packets_accepted": 0,
                "flow_generations_created": 0,
                "flows_closed": 0,
                "active_flow_count": 0,
            },
            "exported_flows": 0,
            "parser_errors": 0,
            "ingest_errors": 0,
        }

        with self.assertRaisesRegex(ValueError, "input mismatch"):
            builder.validate_summary(summary, "capture", 0, Path("expected.pcap"))

    def test_normalized_database_content_is_deterministic(self):
        first = self.fixture.build()
        first_database = self.fixture.root / first["sqlite"]["path"]
        other = Fixture()
        try:
            second = other.build()
            second_database = other.root / second["sqlite"]["path"]

            def normalized(path):
                connection = sqlite3.connect(path)
                try:
                    return {
                        table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                        for table in verifier.TABLE_COLUMNS
                    }
                finally:
                    connection.close()

            self.assertEqual(normalized(first_database), normalized(second_database))
        finally:
            other.close()


class GuardTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected_by_builder_and_verifier(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            builder.parse_json_line('{"kind":"flow","kind":"summary"}', "fixture")
        temporary = TEST_WORK / f"duplicate-{uuid.uuid4().hex}"
        temporary.mkdir()
        try:
            path = temporary / "duplicate.json"
            path.write_text('{"task":"T3.3","task":"T3.2"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                verifier.load_json(path)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def test_scratch_inside_shared_project_is_rejected(self):
        root = TEST_WORK / f"guard-{uuid.uuid4().hex}"
        root.mkdir()
        try:
            output = root / "run_log" / "t3.3"
            output.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "outside the shared"):
                builder.require_local_scratch(root / "scratch", root, output)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_host_guard_rejects_windows_root_and_non_vmware(self):
        host = {
            "system": "Linux", "os_id": "ubuntu", "os_version": "24.04",
            "architecture": "x86_64", "python": "3.12.3", "effective_uid": 1000,
            "virtualization_product": "VMware Virtual Platform",
        }
        self.assertEqual([], verifier.host_errors(host))
        self.assertTrue(verifier.host_errors({**host, "system": "Windows"}))
        self.assertTrue(verifier.host_errors({**host, "effective_uid": 0}))
        self.assertTrue(verifier.host_errors({**host, "virtualization_product": "WSL"}))


if __name__ == "__main__":
    unittest.main()
