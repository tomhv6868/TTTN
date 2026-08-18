import copy
import hashlib
import importlib.util
import io
import json
import shutil
import sys
import unittest
import uuid
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


inventory = load_script(
    "inventory_cicids2017",
    ROOT / "scripts" / "inventory_cicids2017.py",
)
verifier = load_script(
    "verify_t31_cicids2017_inventory",
    ROOT / "scripts" / "verify_t31_cicids2017_inventory.py",
)


class Fixture:
    def __init__(self):
        self.root = ROOT / "run_log" / "t3.1" / "test-work" / uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.data_dir = self.root / "pcap"
        self.config_dir = self.root / "config"
        self.data_dir.mkdir()
        self.config_dir.mkdir()
        self.contract_path = self.config_dir / "cicids2017-inventory-contract.json"
        shutil.copyfile(
            ROOT / "config" / "cicids2017-inventory-contract.json",
            self.contract_path,
        )
        self.contract = inventory.load_json(self.contract_path)
        self._write_pcaps()
        self._write_labels()
        self._write_prerequisites()

    def close(self):
        shutil.rmtree(self.root)

    def _write_pcaps(self):
        for index, name in enumerate(self.contract["pcap"]["expected_files"]):
            (self.data_dir / name).write_bytes(bytes.fromhex("0a0d0d0a") + bytes([index]) * 32)

    def _write_labels(self, omitted_columns=()):
        required = [
            column
            for column in self.contract["labels"]["required_columns"]
            if column not in omitted_columns
        ]
        header = ",".join(required)
        row = ",".join("value" for _ in required)
        archive_path = self.data_dir / self.contract["labels"]["archive"]
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in self.contract["labels"]["expected_csv_basenames"]:
                archive.writestr(f"TrafficLabelling /{name}", f"{header}\r\n{row}\r\n")

    def _write_prerequisites(self):
        phase2_path = self.root / self.contract["prerequisites"]["phase2_acceptance"]
        phase2_path.parent.mkdir(parents=True, exist_ok=True)
        phase2_path.write_text(
            json.dumps({"task": "T2.6", "status": "passed"}),
            encoding="utf-8",
        )
        survey_path = self.root / self.contract["prerequisites"]["prior_full_scan"]
        survey_path.parent.mkdir(parents=True, exist_ok=True)
        files = []
        for name in self.contract["pcap"]["expected_files"]:
            path = self.data_dir / name
            stat = path.stat()
            files.append(
                {
                    "name": name,
                    "size_bytes": stat.st_size,
                    "modified_time_ns": stat.st_mtime_ns,
                    "magic_hex": path.read_bytes()[:4].hex(),
                }
            )
        survey_path.write_text(
            json.dumps({"task": "T1.2", "status": "passed", "files": files}),
            encoding="utf-8",
        )

    def build(self):
        return inventory.build_inventory(
            self.root,
            self.data_dir,
            self.contract_path,
        )


class ContractTests(unittest.TestCase):
    def test_locked_contract_is_valid_and_explicit_about_checksum_limits(self):
        contract = inventory.load_json(
            ROOT / "config" / "cicids2017-inventory-contract.json"
        )

        self.assertEqual([], inventory.validate_contract(contract))
        self.assertEqual(
            "not_published_on_cited_landing_page",
            contract["checksum_policy"]["publisher_digest_status"],
        )
        self.assertIsNone(contract["license_evidence"]["spdx_identifier"])
        self.assertFalse(contract["license_evidence"]["redistribution_grant_verified"])

    def test_contract_rejects_unverified_license_and_publisher_match_claims(self):
        contract = inventory.load_json(
            ROOT / "config" / "cicids2017-inventory-contract.json"
        )
        contract["license_evidence"]["spdx_identifier"] = "MIT"
        contract["checksum_policy"]["publisher_digest_match"] = "passed"

        errors = inventory.validate_contract(contract)

        self.assertIn("contract.license_evidence.spdx_identifier", errors)
        self.assertIn("contract.checksum_policy", errors)


class StreamingTests(unittest.TestCase):
    def test_hashing_uses_bounded_reads(self):
        class BoundedStream(io.BytesIO):
            def read(self, size=-1):
                if size < 0 or size > inventory.READ_SIZE:
                    raise AssertionError("unbounded read")
                return super().read(size)

        content = b"bounded" * 100
        digest, size = inventory.sha256_stream(BoundedStream(content))

        self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
        self.assertEqual(len(content), size)

    def test_csv_member_records_columns_rows_and_content_hash(self):
        content = b"Flow ID, Source IP, Label\r\na,10.0.0.1,BENIGN\r\n"

        inspected = inventory.inspect_csv_member(io.BytesIO(content))

        self.assertEqual(1, inspected["row_count"])
        self.assertEqual(["Flow ID", "Source IP", "Label"], inspected["columns"])
        self.assertEqual(hashlib.sha256(content).hexdigest(), inspected["sha256"])


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()

    def test_complete_sources_produce_passed_content_addressed_receipt(self):
        receipt = self.fixture.build()

        self.assertEqual("passed", receipt["status"])
        self.assertEqual(5, len(receipt["source"]["pcaps"]))
        self.assertEqual(8, receipt["source"]["labels"]["csv_member_count"])
        self.assertEqual(8, receipt["source"]["labels"]["csv_row_count"])
        self.assertTrue(all(check["status"] == "passed" for check in receipt["checks"]))

    def test_missing_pcap_is_reported_without_substitution(self):
        missing = self.fixture.contract["pcap"]["expected_files"][0]
        (self.fixture.data_dir / missing).unlink()

        receipt = self.fixture.build()
        checks = {check["name"]: check["status"] for check in receipt["checks"]}

        self.assertEqual("failed", receipt["status"])
        self.assertEqual([missing], receipt["source"]["missing_pcaps"])
        self.assertEqual("failed", checks["pcap.file_set_exact"])
        self.assertEqual("failed", checks["prerequisites.prior_full_scan_consistent"])

    def test_label_csv_without_join_column_fails_acceptance(self):
        self.fixture._write_labels(omitted_columns={"Timestamp"})

        receipt = self.fixture.build()
        checks = {check["name"]: check["status"] for check in receipt["checks"]}

        self.assertEqual("failed", receipt["status"])
        self.assertEqual("failed", checks["labels.required_columns"])

    def test_atomic_writer_refuses_to_overwrite_receipt(self):
        output = self.fixture.root / "run_log" / "t3.1" / "acceptance.json"
        inventory.write_json_atomic(output, {"status": "first"})

        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            inventory.write_json_atomic(output, {"status": "second"})


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.receipt = self.fixture.build()

    def tearDown(self):
        self.fixture.close()

    def test_valid_receipt_is_accepted(self):
        errors = verifier.validate_receipt(
            self.receipt,
            self.fixture.contract,
            self.fixture.root,
        )

        self.assertEqual([], errors)

    def test_rehash_rejects_tampered_pcap_digest(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["source"]["pcaps"][0]["sha256"] = "0" * 64

        errors = verifier.validate_receipt(
            receipt,
            self.fixture.contract,
            self.fixture.root,
            rehash_sources=True,
        )

        self.assertTrue(any("source content hash mismatch" in error for error in errors))

    def test_rehash_rejects_tampered_csv_member_digest(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["source"]["labels"]["members"][0]["sha256"] = "0" * 64

        errors = verifier.validate_receipt(
            receipt,
            self.fixture.contract,
            self.fixture.root,
            rehash_sources=True,
        )

        self.assertIn("labeled-flow archive content evidence mismatch", errors)

    def test_escaping_source_path_is_rejected(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["source"]["pcaps"][0]["path"] = "../outside.pcap"

        errors = verifier.validate_receipt(
            receipt,
            self.fixture.contract,
            self.fixture.root,
        )

        self.assertTrue(any("escaping source path" in error for error in errors))

    def test_changed_source_metadata_is_rejected(self):
        path = self.fixture.data_dir / self.fixture.contract["pcap"]["expected_files"][0]
        path.write_bytes(path.read_bytes() + b"changed")

        errors = verifier.validate_receipt(
            self.receipt,
            self.fixture.contract,
            self.fixture.root,
        )

        self.assertTrue(any("source size changed" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
