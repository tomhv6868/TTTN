import contextlib
import importlib.util
import json
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_t11_packet_contract.py"
SPEC = importlib.util.spec_from_file_location("verify_t11_packet_contract", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def test_workspace():
    directory = ROOT / f".t11-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t11-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def successful_commands():
    return [
        {
            "name": name,
            "arguments": [name],
            "return_code": 0,
            "stdout": (
                "nids_core.packet_contract\n100% tests passed"
                if name == "ctest"
                else "OK"
            ),
            "stderr": "",
            "duration_seconds": 0.1,
            "log": f"run_log/t1.1/attempts/example/{name}.log",
            "log_sha256": "a" * 64,
        }
        for name in verifier.COMMAND_NAMES
    ]


def valid_receipt():
    commands = successful_commands()
    checks = verifier.assess(
        commands,
        {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
        },
    )
    return {
        "schema_version": verifier.SCHEMA_VERSION,
        "task": verifier.TASK,
        "kind": verifier.KIND,
        "status": "passed",
        "generated_at_utc": "2026-07-14T10:00:00Z",
        "host": {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
        },
        "source": {
            "path": "/mnt/hgfs/TTTN",
            "files": [
                {"path": path, "sha256": "b" * 64}
                for path in verifier.SOURCE_FILES
            ],
        },
        "artifacts": {
            "directory": "run_log/t1.1/attempts/example",
            "final_receipt": "run_log/t1.1/acceptance.json",
        },
        "build": {
            "generator": "Ninja",
            "configuration": "Release",
            "testing_enabled": True,
            "toolchain_smoke_enabled": False,
            "temporary_workspace_outside_source": True,
            "temporary_workspace_retained": False,
            "offline_dependency_mode": True,
        },
        "commands": commands,
        "checks": checks,
    }


class T11HostTests(unittest.TestCase):
    def test_supported_host_is_accepted(self):
        verifier.require_supported_host(
            {
                "system": "Linux",
                "os_id": "ubuntu",
                "os_version": "24.04.4",
                "architecture": "x86_64",
                "python": "3.12.3",
                "effective_uid": 1000,
            }
        )

    def test_root_and_non_linux_hosts_are_rejected(self):
        root = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 0,
        }
        with self.assertRaisesRegex(RuntimeError, "normal user"):
            verifier.require_supported_host(root)
        windows = {**root, "system": "Windows", "effective_uid": None}
        with self.assertRaisesRegex(RuntimeError, "Ubuntu Linux VM"):
            verifier.require_supported_host(windows)


class T11PipelineTests(unittest.TestCase):
    def test_pipeline_is_clean_release_offline_and_logs_every_command(self):
        outputs = (
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess(
                [],
                0,
                "nids_core.version\nnids_core.packet_contract\n100% tests passed",
                "",
            ),
            subprocess.CompletedProcess([], 0, "", "Ran 87 tests\nOK"),
        )
        with test_workspace() as root:
            artifacts = root / "artifacts"
            with mock.patch.object(verifier.subprocess, "run", side_effect=outputs) as runner:
                commands = verifier.run_pipeline(ROOT, root / "build", artifacts)

            self.assertEqual(
                list(verifier.COMMAND_NAMES),
                [command["name"] for command in commands],
            )
            configure_args = runner.call_args_list[0].args[0]
            self.assertIn("-DCMAKE_BUILD_TYPE=Release", configure_args)
            self.assertIn("-DFETCHCONTENT_FULLY_DISCONNECTED=ON", configure_args)
            self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", configure_args)
            for command in commands:
                log_path = Path(command["log"])
                self.assertTrue(log_path.is_file())
                self.assertEqual(verifier.sha256_file(log_path), command["log_sha256"])

    def test_failed_configure_skips_cpp_steps_but_runs_python_tests(self):
        outputs = (
            subprocess.CompletedProcess([], 1, "", "configure failed"),
            subprocess.CompletedProcess([], 0, "", "OK"),
        )
        with test_workspace() as root:
            with mock.patch.object(verifier.subprocess, "run", side_effect=outputs) as runner:
                commands = verifier.run_pipeline(ROOT, root / "build", root / "artifacts")

        self.assertEqual(2, runner.call_count)
        self.assertEqual("configure failed", commands[1]["skipped"])
        self.assertEqual("build failed or was skipped", commands[2]["skipped"])
        self.assertEqual(0, commands[3]["return_code"])

    def test_assessment_requires_named_ctest_and_locked_build_flags(self):
        checks = verifier.assess(
            successful_commands(),
            {
                "CMAKE_BUILD_TYPE": "Release",
                "BUILD_TESTING": "ON",
                "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
            },
        )
        self.assertTrue(all(check["status"] == "passed" for check in checks))

        wrong_cache = {
            "CMAKE_BUILD_TYPE": "Debug",
            "BUILD_TESTING": "OFF",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "ON",
        }
        failed = verifier.assess(successful_commands(), wrong_cache)
        failed_names = {check["name"] for check in failed if check["status"] == "failed"}
        self.assertEqual(
            {
                "build.release",
                "build.testing_enabled",
                "build.toolchain_smoke_disabled",
            },
            failed_names,
        )


class T11ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_inconsistent_aggregate_status_is_rejected(self):
        receipt = valid_receipt()
        receipt["checks"][0]["status"] = "failed"
        self.assertIn(
            "receipt status must match aggregate check status",
            verifier.validate_receipt(receipt),
        )

    def test_writer_refuses_to_overwrite_receipt(self):
        with test_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})
            self.assertEqual("passed", json.loads(output.read_text(encoding="utf-8"))["status"])


if __name__ == "__main__":
    unittest.main()
