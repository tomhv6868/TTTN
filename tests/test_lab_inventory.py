import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab_inventory.py"
FIXTURES = ROOT / "tests" / "fixtures"
SPEC = importlib.util.spec_from_file_location("lab_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
lab_inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab_inventory)


class LabInventoryValidationTests(unittest.TestCase):
    def load_fixture(self, name: str):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def test_sample_inventories_are_valid(self):
        self.assertEqual([], lab_inventory.validate_inventory(self.load_fixture("kali-inventory.json"), "kali"))
        self.assertEqual([], lab_inventory.validate_inventory(self.load_fixture("ubuntu-inventory.json"), "ubuntu"))

    def test_expected_role_mismatch_is_rejected(self):
        errors = lab_inventory.validate_inventory(self.load_fixture("kali-inventory.json"), "ubuntu")
        self.assertIn("role must equal ubuntu", errors)

    def test_missing_required_section_is_rejected(self):
        document = self.load_fixture("ubuntu-inventory.json")
        del document["network"]
        errors = lab_inventory.validate_inventory(document)
        self.assertIn("network must be an object", errors)
        self.assertIn("network.interfaces must be an array", errors)

    def test_sensitive_identifier_field_is_rejected(self):
        document = self.load_fixture("ubuntu-inventory.json")
        document["host"]["product_uuid"] = "must-not-be-collected"
        errors = lab_inventory.validate_inventory(document)
        self.assertTrue(any("forbidden sensitive field" in error for error in errors))

    def test_collection_refuses_non_linux_host(self):
        with mock.patch.object(lab_inventory.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(RuntimeError, "must run inside"):
                lab_inventory.collect_inventory("ubuntu")


class LabInventoryCliTests(unittest.TestCase):
    def scratch_path(self, suffix: str) -> Path:
        safe_test_name = self._testMethodName.replace("test_", "")
        path = ROOT / "tests" / f".runtime-{os.getpid()}-{safe_test_name}-{suffix}"
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def run_cli(self, *arguments: str):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_validate_command_accepts_fixture(self):
        result = self.run_cli(
            "validate",
            "--input",
            str(FIXTURES / "ubuntu-inventory.json"),
            "--expected-role",
            "ubuntu",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("valid inventory", result.stdout)

    def test_validate_command_rejects_malformed_json(self):
        path = self.scratch_path("bad.json")
        path.write_text("not json", encoding="utf-8")
        result = self.run_cli("validate", "--input", str(path))
        self.assertEqual(2, result.returncode)
        self.assertIn("invalid JSON", result.stderr)

    def test_render_manifest_uses_both_roles_and_hashes(self):
        output = self.scratch_path("manifest.yaml")
        result = self.run_cli(
            "render-manifest",
            "--kali",
            str(FIXTURES / "kali-inventory.json"),
            "--ubuntu",
            str(FIXTURES / "ubuntu-inventory.json"),
            "--data-vmnet",
            "VMnet5",
            "--output",
            str(output),
        )
        rendered = output.read_text(encoding="utf-8") if output.exists() else ""
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('manifest_status: "observed"', rendered)
        self.assertIn('data_vmnet: "VMnet5"', rendered)
        self.assertIn("kali_attacker:", rendered)
        self.assertIn("ubuntu_sensor_victim:", rendered)
        self.assertEqual(2, rendered.count("source_sha256:"))

    def test_render_refuses_to_overwrite_by_default(self):
        output = self.scratch_path("manifest.yaml")
        output.write_text("keep me", encoding="utf-8")
        result = self.run_cli(
            "render-manifest",
            "--kali",
            str(FIXTURES / "kali-inventory.json"),
            "--ubuntu",
            str(FIXTURES / "ubuntu-inventory.json"),
            "--output",
            str(output),
        )
        content = output.read_text(encoding="utf-8")
        self.assertEqual(2, result.returncode)
        self.assertIn("refusing to overwrite", result.stderr)
        self.assertEqual("keep me", content)

    def test_render_can_record_user_acceptance(self):
        output = self.scratch_path("accepted-manifest.yaml")
        result = self.run_cli(
            "render-manifest",
            "--kali",
            str(FIXTURES / "kali-inventory.json"),
            "--ubuntu",
            str(FIXTURES / "ubuntu-inventory.json"),
            "--data-vmnet",
            "VMnet8",
            "--t0-1-acceptance",
            "accepted",
            "--output",
            str(output),
        )
        rendered = output.read_text(encoding="utf-8") if output.exists() else ""
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('t0_1_user_acceptance: "accepted"', rendered)


if __name__ == "__main__":
    unittest.main()
