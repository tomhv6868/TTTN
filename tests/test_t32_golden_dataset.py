import copy
import csv
import importlib.util
import ipaddress
import shutil
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = load_script(
    "build_t32_golden_dataset",
    ROOT / "scripts" / "build_t32_golden_dataset.py",
)
verifier = load_script(
    "verify_t32_golden_dataset",
    ROOT / "scripts" / "verify_t32_golden_dataset.py",
)


class Fixture:
    def __init__(self):
        self.root = ROOT / "run_log" / "t3.2" / "test-work" / uuid.uuid4().hex
        self.root.mkdir(parents=True)

    def close(self):
        shutil.rmtree(self.root)


def packet(timestamp_ns, forward=True, payload=b"packet"):
    client = int(ipaddress.ip_address("10.0.0.1"))
    server = int(ipaddress.ip_address("10.0.0.2"))
    source_ip, source_port = (client, 50000) if forward else (server, 443)
    destination_ip, destination_port = (server, 443) if forward else (client, 50000)
    return builder.CapturedPacket(
        timestamp_ns=timestamp_ns,
        captured_length=len(payload),
        original_length=len(payload) + 4,
        data=payload,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=6,
    )


def window_sample():
    return {
        "id": "window",
        "category": "benign_tcp",
        "output_name": "window.pcap",
        "csv_line": 2,
        "row": {
            "Flow ID": "flow",
            "Source IP": "10.0.0.1",
            "Source Port": "50000",
            "Destination IP": "10.0.0.2",
            "Destination Port": "443",
            "Protocol": "6",
            "Timestamp": "time",
            "Flow Duration": "2",
            "Total Fwd Packets": "2",
            "Total Backward Packets": "1",
            "Label": "BENIGN",
        },
    }


def csv_fixture_contract(sample, data_records=1, blank_records=0):
    required = list(sample["row"])
    header = [*required, "Fwd Header Length", "Fwd Header Length"]
    header.extend(f"Field {index}" for index in range(85 - len(header)))
    labels = {
        "encoding": "cp1252",
        "header_field_count": 85,
        "data_record_count": data_records,
        "all_empty_record_count": blank_records,
        "duplicate_trimmed_headers": {"Fwd Header Length": 2},
        "required_columns": required,
    }
    return labels, header


def write_csv(path, header, rows):
    with path.open("w", encoding="cp1252", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(header)
        writer.writerows(rows)


def csv_row(header, values):
    return [values.get(name, "0") for name in header]


class ContractTests(unittest.TestCase):
    def test_locked_contract_is_valid_and_keeps_payload_untracked(self):
        contract = builder.load_json(
            ROOT / "config" / "cicids2017-golden-contract.json"
        )

        self.assertEqual([], builder.validate_contract(contract))
        self.assertFalse(contract["repository_payload_policy"]["raw_payload_tracked"])
        self.assertEqual("not_used", contract["selection"]["timestamp_timezone_join"])
        self.assertTrue(contract["shared_parser"]["required_for_acceptance"])

    def test_contract_rejects_payload_tracking_and_weakened_prefix(self):
        contract = builder.load_json(
            ROOT / "config" / "cicids2017-golden-contract.json"
        )
        contract["repository_payload_policy"]["raw_payload_tracked"] = True
        contract["selection"]["prefix_packet_count"] = 7

        errors = builder.validate_contract(contract)

        self.assertIn("contract.repository_payload_policy", errors)
        self.assertIn("contract.selection.lock", errors)

    def test_t31_archive_member_identity_maps_to_extracted_label_file(self):
        contract = builder.load_json(
            ROOT / "config" / "cicids2017-golden-contract.json"
        )

        prerequisite = builder.verify_t31_prerequisite(ROOT, contract)

        self.assertEqual("T3.1", prerequisite["task"])
        self.assertEqual("passed", prerequisite["status"])


class UbuntuDependencyTests(unittest.TestCase):
    def test_scapy_lock_uses_the_official_wheel_hash(self):
        lock = (ROOT / "config" / "t32-scapy-requirements.txt").read_text()

        self.assertEqual(
            "--only-binary=:all:\n"
            "scapy==2.7.0 "
            "--hash=sha256:eb22786da92be6fd8e5c694ae5595e4f5b9ac1f4364c9c45986844f3e3063561\n",
            lock,
        )

    def test_installer_is_user_scoped_transactional_and_hash_locked(self):
        script = (ROOT / "scripts" / "setup_t32_scapy_ubuntu.sh").read_text()

        for token in (
            'readonly VENV_ROOT="$VENV_PARENT/t3.2"',
            "run as the normal Ubuntu user",
            '[[ "${VERSION_ID:-}" == "24.04"* ]]',
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            ".t3.2-staging.",
            'mv -- "$STAGING_ROOT" "$VENV_ROOT"',
            "--install",
            "--verify",
        ):
            self.assertIn(token, script)
        self.assertNotIn("sudo ", script)


class LabelSelectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.sample = window_sample()

    def tearDown(self):
        self.fixture.close()

    def test_duplicate_trimmed_header_is_handled_by_required_column_position(self):
        labels, header = csv_fixture_contract(self.sample)
        path = self.fixture.root / "labels.csv"
        write_csv(path, header, [csv_row(header, self.sample["row"])])

        evidence = builder.scan_label_csv(path, labels, [self.sample])

        self.assertEqual(85, evidence["header_field_count"])
        self.assertEqual(
            1, evidence["selected_rows"][0]["selector_signature_occurrences"]
        )

    def test_only_completely_empty_records_may_be_skipped(self):
        labels, header = csv_fixture_contract(
            self.sample, data_records=2, blank_records=1
        )
        path = self.fixture.root / "labels.csv"
        write_csv(path, header, [csv_row(header, self.sample["row"]), [""] * 85])

        evidence = builder.scan_label_csv(path, labels, [self.sample])

        self.assertEqual(1, evidence["all_empty_record_count"])
        self.assertEqual(1, evidence["nonempty_record_count"])

    def test_non_transport_label_rows_remain_valid_dataset_records(self):
        labels, header = csv_fixture_contract(self.sample, data_records=2)
        path = self.fixture.root / "labels.csv"
        non_transport = {
            **self.sample["row"],
            "Flow ID": "protocol-zero",
            "Source Port": "0",
            "Destination Port": "0",
            "Protocol": "0",
            "Flow Duration": "0",
            "Total Fwd Packets": "0",
            "Total Backward Packets": "0",
        }
        write_csv(
            path,
            header,
            [csv_row(header, self.sample["row"]), csv_row(header, non_transport)],
        )

        evidence = builder.scan_label_csv(path, labels, [self.sample])

        self.assertEqual(2, evidence["nonempty_record_count"])

    def test_nonempty_malformed_record_fails(self):
        labels, header = csv_fixture_contract(self.sample, data_records=2)
        path = self.fixture.root / "labels.csv"
        write_csv(path, header, [csv_row(header, self.sample["row"]), ["not", "empty"]])

        with self.assertRaisesRegex(ValueError, "nonempty malformed"):
            builder.scan_label_csv(path, labels, [self.sample])

    def test_reused_flow_key_with_distinct_signature_is_allowed(self):
        labels, header = csv_fixture_contract(self.sample, data_records=2)
        path = self.fixture.root / "labels.csv"
        reused = {**self.sample["row"], "Flow Duration": "3"}
        write_csv(
            path,
            header,
            [csv_row(header, self.sample["row"]), csv_row(header, reused)],
        )

        evidence = builder.scan_label_csv(path, labels, [self.sample])

        self.assertEqual(
            1, evidence["selected_rows"][0]["selector_signature_occurrences"]
        )

    def test_duplicate_selector_signature_fails_instead_of_picking_first(self):
        labels, header = csv_fixture_contract(self.sample, data_records=2)
        path = self.fixture.root / "labels.csv"
        row = csv_row(header, self.sample["row"])
        write_csv(path, header, [row, row])

        with self.assertRaisesRegex(ValueError, "ambiguous"):
            builder.scan_label_csv(path, labels, [self.sample])


class WindowSelectionTests(unittest.TestCase):
    def test_exact_duration_and_direction_counts_select_one_window(self):
        packets = [packet(1_000), packet(2_000, False), packet(3_000)]

        start, selected = builder.find_unique_window(packets, window_sample())

        self.assertEqual(0, start)
        self.assertEqual(packets, selected)

    def test_multiple_exact_windows_fail_as_ambiguous(self):
        packets = [
            packet(1_000),
            packet(2_000, False),
            packet(3_000),
            packet(11_000),
            packet(12_000, False),
            packet(13_000),
        ]

        with self.assertRaisesRegex(ValueError, "found 2"):
            builder.find_unique_window(packets, window_sample())

    def test_direction_mismatch_does_not_match_duration_only(self):
        packets = [packet(1_000), packet(2_000), packet(3_000)]

        with self.assertRaisesRegex(ValueError, "found 0"):
            builder.find_unique_window(packets, window_sample())


class PcapArtifactTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.path = self.fixture.root / "sample.pcap"
        self.packets = [
            packet(1_700_000_000_000_000_001 + index, payload=f"p{index}".encode())
            for index in range(9)
        ]

    def tearDown(self):
        self.fixture.close()

    def test_nanosecond_pcap_round_trip_preserves_packet_evidence(self):
        builder.write_classic_pcap_atomic(self.path, self.packets, 262144, 1)

        header, records = builder.read_classic_pcap(self.path)

        self.assertEqual({"snaplen": 262144, "linktype": 1}, header)
        self.assertEqual(
            [item.timestamp_ns for item in self.packets],
            [r["timestamp_ns"] for r in records],
        )
        self.assertEqual(
            [item.data for item in self.packets], [r["data"] for r in records]
        )
        self.assertEqual(
            [item.original_length for item in self.packets],
            [r["original_length"] for r in records],
        )

    def test_writer_refuses_to_overwrite_existing_payload(self):
        builder.write_classic_pcap_atomic(self.path, self.packets, 262144, 1)

        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            builder.write_classic_pcap_atomic(self.path, self.packets, 262144, 1)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.contract = builder.load_json(
            ROOT / "config" / "cicids2017-golden-contract.json"
        )
        self.sample = self.contract["samples"][0]
        self.path = (
            self.fixture.root
            / self.contract["output"]["directory"]
            / self.sample["output_name"]
        )
        packets = [
            packet(1_700_000_000_000_000_000 + index, payload=f"raw-{index}".encode())
            for index in range(9)
        ]
        builder.write_classic_pcap_atomic(self.path, packets, 262144, 1)
        self.artifact = {
            "id": self.sample["id"],
            "category": self.sample["category"],
            "label": self.sample["row"]["Label"],
            "csv_line": self.sample["csv_line"],
            "source_match": {
                "candidate_packet_count": 53,
                "window_start_index": 0,
                "flow_packet_count": 53,
                "flow_duration_ns": 10_706_606_000,
                "forward_packet_count": 29,
                "backward_packet_count": 24,
            },
            "file": {
                "path": f"run_log/t3.2/{self.sample['output_name']}",
                "size_bytes": self.path.stat().st_size,
                "magic_hex": "4d3cb2a1",
                "sha256": builder.sha256_path(self.path),
                "record_count": 9,
            },
            "packets": [
                builder.packet_manifest(item, index)
                for index, item in enumerate(packets, start=1)
            ],
        }

    def tearDown(self):
        self.fixture.close()

    def test_valid_output_artifact_is_accepted(self):
        errors = verifier.validate_output_artifact(
            self.artifact, self.sample, self.contract, self.fixture.root
        )

        self.assertEqual([], errors)

    def test_tampered_output_payload_is_rejected(self):
        with self.path.open("r+b") as output:
            output.seek(-1, 2)
            output.write(b"X")

        errors = verifier.validate_output_artifact(
            self.artifact, self.sample, self.contract, self.fixture.root
        )

        self.assertTrue(any("hash mismatch" in error for error in errors))
        self.assertTrue(any("packet 9 evidence mismatch" in error for error in errors))

    def test_escaping_output_path_is_rejected(self):
        artifact = copy.deepcopy(self.artifact)
        artifact["file"]["path"] = "../outside.pcap"

        errors = verifier.validate_output_artifact(
            artifact, self.sample, self.contract, self.fixture.root
        )

        self.assertTrue(any("escapes project root" in error for error in errors))

    def test_shared_parser_result_requires_all_nine_records(self):
        paths = [self.path, self.path, self.path]
        result = {
            "schema_version": "1.0.0",
            "task": "T3.2",
            "status": "passed",
            "reader": self.contract["shared_parser"]["reader"],
            "parser": self.contract["shared_parser"]["parser"],
            "files": [
                {
                    "path": str(path),
                    "record_count": 9,
                    "accepted_count": 9,
                    "rejected_count": 0,
                }
                for path in paths
            ],
        }

        self.assertEqual(
            [], verifier.validate_shared_parser_result(result, paths, self.contract)
        )
        result["files"][1]["accepted_count"] = 8
        self.assertTrue(
            verifier.validate_shared_parser_result(result, paths, self.contract)
        )

    def test_rehash_allows_cross_host_mtime_but_not_content_drift(self):
        source = self.fixture.root / "source.bin"
        source.write_bytes(b"locked-content")
        expected = {
            "path": "source.bin",
            "size_bytes": source.stat().st_size,
            "sha256": builder.sha256_path(source),
        }
        recorded = {
            **expected,
            "modified_time_ns": source.stat().st_mtime_ns - 1,
        }

        self.assertTrue(
            verifier.validate_current_source(
                recorded, expected, self.fixture.root, rehash=False
            )
        )
        self.assertEqual(
            [],
            verifier.validate_current_source(
                recorded, expected, self.fixture.root, rehash=True
            ),
        )
        source.write_bytes(b"changed-content")
        self.assertTrue(
            verifier.validate_current_source(
                recorded, expected, self.fixture.root, rehash=True
            )
        )

    def test_ubuntu_host_guard_rejects_root_and_non_vm_host(self):
        host = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
        }

        verifier.require_supported_host(host)
        with self.assertRaisesRegex(RuntimeError, "normal user"):
            verifier.require_supported_host({**host, "effective_uid": 0})
        with self.assertRaisesRegex(RuntimeError, "Ubuntu Linux VM"):
            verifier.require_supported_host({**host, "system": "Windows"})

    def test_pipeline_requires_locked_scapy_before_acceptance(self):
        executable = self.fixture.root / "nids_t32_golden_dataset_test"
        executable.write_bytes(b"binary")
        commands = [
            {
                "name": name,
                "return_code": 0,
                "stdout": "",
                "stderr": "",
            }
            for name in verifier.COMMAND_NAMES
        ]
        next(item for item in commands if item["name"] == "scapy_version")["stdout"] = (
            "2.7.0"
        )
        next(item for item in commands if item["name"] == "libpcap_version")[
            "stdout"
        ] = "1.10.4"
        next(item for item in commands if item["name"] == "ctest")["stdout"] = (
            "\n".join(verifier.EXPECTED_CTESTS) + "\n100% tests passed"
        )
        cache = {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
            "NIDS_BUILD_DPDK": "OFF",
        }

        checks, libpcap_version, scapy_version = verifier.assess_pipeline(
            commands, cache, executable
        )

        self.assertTrue(all(check["status"] == "passed" for check in checks))
        self.assertEqual("1.10.4", libpcap_version)
        self.assertEqual("2.7.0", scapy_version)
        next(item for item in commands if item["name"] == "scapy_version")["stdout"] = (
            "2.6.1"
        )
        checks, _, scapy_version = verifier.assess_pipeline(commands, cache, executable)
        self.assertIsNone(scapy_version)
        self.assertIn({"name": "versions.scapy_locked", "status": "failed"}, checks)


if __name__ == "__main__":
    unittest.main()
