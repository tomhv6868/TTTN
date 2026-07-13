import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "toolchain.lock.json"
VERIFIER_PATH = ROOT / "scripts" / "verify_project.py"
SAMPLE_RECEIPT = ROOT / "tests" / "fixtures" / "t0.5-project-receipt.sample.json"
SPEC = importlib.util.spec_from_file_location("verify_project", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_project = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_project)


class ProjectReceiptTests(unittest.TestCase):
    def load_sample(self):
        return json.loads(SAMPLE_RECEIPT.read_text(encoding="utf-8"))

    def test_sample_receipt_is_valid_against_lock(self):
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            [],
            verify_project.validate_receipt(
                self.load_sample(), lock, verify_project.sha256_file(LOCK_PATH)
            ),
        )

    def test_inconsistent_aggregate_status_is_rejected(self):
        receipt = self.load_sample()
        receipt["checks"][0]["status"] = "failed"
        self.assertIn(
            "receipt status must match aggregate check status",
            verify_project.validate_receipt(receipt),
        )

    def test_validate_cli_accepts_sample(self):
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER_PATH),
                "validate",
                "--input",
                str(SAMPLE_RECEIPT),
                "--lock",
                str(LOCK_PATH),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("valid receipt", result.stdout)


class ProjectVerifierHostTests(unittest.TestCase):
    def test_supported_host_requires_normal_user_on_ubuntu_2404_x86_64(self):
        with (
            mock.patch.object(verify_project.platform, "system", return_value="Linux"),
            mock.patch.object(verify_project.platform, "machine", return_value="x86_64"),
            mock.patch.object(verify_project.platform, "python_version", return_value="3.12.3"),
            mock.patch.object(verify_project, "read_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}),
            mock.patch.object(verify_project.os, "geteuid", return_value=1000, create=True),
        ):
            host = verify_project.inspect_host()
        verify_project.require_supported_host(host)

    def test_root_execution_is_rejected(self):
        host = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 0,
        }
        with self.assertRaisesRegex(RuntimeError, "normal user"):
            verify_project.require_supported_host(host)

    def test_python_313_is_rejected(self):
        host = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.13.1",
            "effective_uid": 1000,
        }
        with self.assertRaisesRegex(RuntimeError, "Python 3.12"):
            verify_project.require_supported_host(host)


class ProjectVerifierPipelineTests(unittest.TestCase):
    def test_pipeline_is_release_offline_and_runs_both_test_suites(self):
        outputs = (
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess(
                [],
                0,
                "toolchain_runtime\nDPDK 25.11.2\nONNX Runtime 1.27.1\n100% tests passed",
                "",
            ),
            subprocess.CompletedProcess([], 0, "", "OK"),
        )
        build = ROOT / "build-test-sentinel"
        with mock.patch.object(verify_project.subprocess, "run", side_effect=outputs) as runner:
            commands = verify_project.run_pipeline(ROOT, build)

        self.assertEqual(list(verify_project.COMMAND_NAMES), [command["name"] for command in commands])
        configure_args = runner.call_args_list[0].args[0]
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", configure_args)
        self.assertIn("-DFETCHCONTENT_FULLY_DISCONNECTED=ON", configure_args)
        self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=ON", configure_args)
        ctest_args = runner.call_args_list[2].args[0]
        self.assertIn("--verbose", ctest_args)
        python_args = runner.call_args_list[3].args[0]
        self.assertEqual([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], python_args)

    def test_receipt_writer_refuses_overwrite(self):
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            verify_project.write_new_receipt(SAMPLE_RECEIPT, {"status": "passed"})


class ProjectCiTests(unittest.TestCase):
    def test_ci_uses_locked_dependencies_and_the_hermetic_suite(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("ubuntu-24.04", workflow)
        self.assertIn('python-version: "3.12"', workflow)
        self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", workflow)
        self.assertIn("libpcap-dev", workflow)
        self.assertIn("pkg-config", workflow)
        self.assertIn(
            "cache-dependency-path: config/reproducibility-requirements.txt",
            workflow,
        )
        self.assertIn(
            "pip install --requirement config/reproducibility-requirements.txt",
            workflow,
        )
        self.assertIn("python tools/run_ci_tests.py", workflow)
        self.assertNotIn("unittest discover -s tests", workflow)
        self.assertNotIn("setup_toolchain_ubuntu.sh", workflow)


if __name__ == "__main__":
    unittest.main()
