import argparse
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
VERIFIER_PATH = ROOT / "scripts" / "verify_t21_packet_parser.py"
SPEC = importlib.util.spec_from_file_location("verify_t21_packet_parser", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def test_workspace():
    directory = ROOT / f".t21-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t21-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def successful_commands():
    artifact_directory = "run_log/t2.1/attempts/ubuntu-acceptance-example"
    return [
        {
            "name": name,
            "arguments": [name],
            "return_code": 0,
            "stdout": (
                "nids_core.packet_parser\n100% tests passed"
                if name == "ctest"
                else "OK"
            ),
            "stderr": "",
            "duration_seconds": 0.1,
            "log": f"{artifact_directory}/{verifier.LOG_FILES[name]}",
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
        [],
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
            "os_version": "24.04.4",
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
            "contract_errors": [],
        },
        "artifacts": {
            "directory": "run_log/t2.1/attempts/ubuntu-acceptance-example",
            "final_receipt": "run_log/t2.1/acceptance.json",
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
        "contract": verifier.EXPECTED_CONTRACT,
        "commands": commands,
        "checks": checks,
    }


def write_source_contract(root: Path) -> None:
    files = {
        "CMakeLists.txt": "\n".join(
            (
                "add_library(nids_core cpp/src/packet.cpp)",
                "add_executable(parser cpp/tests/packet_parser_test.cpp)",
                "add_test(NAME nids_core.packet_parser COMMAND parser)",
            )
        ),
        "cpp/include/nids/packet.hpp": "\n".join(
            (
                "using PacketBytes = std::span<const std::uint8_t>;",
                "enum class ParseErrorCode {",
                *[f"    {code}," for code in verifier.ERROR_CODES],
                "};",
                "ParseResult<PacketView> parse_packet(PacketInput input) noexcept;",
            )
        ),
        "cpp/src/packet.cpp": "\n".join(
            (
                "constexpr auto vlan = 0x8100U;",
                "constexpr auto provider_vlan = 0x88A8U;",
                "constexpr auto alternate_vlan = 0x9100U;",
                "ParseResult<PacketView> parse_packet(PacketInput input) noexcept { return {}; }",
            )
        ),
        "cpp/tests/packet_parser_test.cpp": "\n".join(
            (
                "auto result = parse_packet(input);",
                "TcpView tcp; UdpView udp;",
                *[f"auto code_{code} = ParseErrorCode::{code};" for code in verifier.ERROR_CODES],
            )
        ),
        "scripts/verify_t21_packet_parser.py": "fixture",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class T21HostTests(unittest.TestCase):
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

    def test_unsupported_hosts_are_rejected(self):
        supported = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
        }
        invalid = (
            ({**supported, "effective_uid": 0}, "normal user"),
            ({**supported, "effective_uid": None}, "normal user"),
            ({**supported, "system": "Windows"}, "Ubuntu Linux VM"),
            ({**supported, "os_version": "22.04"}, "Ubuntu 24.04"),
            ({**supported, "architecture": "aarch64"}, "x86_64"),
            ({**supported, "python": "3.11.9"}, "Python 3.12"),
        )
        for host, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                verifier.require_supported_host(host)


class T21SourceContractTests(unittest.TestCase):
    def test_complete_source_contract_is_accepted(self):
        with test_workspace() as root:
            write_source_contract(root)
            self.assertEqual([], verifier.contract_source_errors(root))

    def test_missing_named_ctest_and_typed_error_coverage_are_rejected(self):
        with test_workspace() as root:
            write_source_contract(root)
            cmake = root / "CMakeLists.txt"
            cmake.write_text(
                cmake.read_text(encoding="utf-8").replace(verifier.EXPECTED_CTEST, "wrong.test"),
                encoding="utf-8",
            )
            tests = root / "cpp/tests/packet_parser_test.cpp"
            tests.write_text(
                tests.read_text(encoding="utf-8").replace("invalid_udp_length", "wrong_error"),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("CMake" in error for error in errors))
        self.assertTrue(any("invalid_udp_length" in error for error in errors))


class T21PipelineTests(unittest.TestCase):
    def test_pipeline_is_clean_release_offline_and_hashes_every_log(self):
        outputs = (
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess(
                [],
                0,
                "nids_core.packet_parser\n100% tests passed",
                "",
            ),
            subprocess.CompletedProcess([], 0, "", "Ran 125 tests\nOK"),
        )
        with test_workspace() as root:
            artifacts = root / "artifacts"
            with mock.patch.object(verifier.runner.subprocess, "run", side_effect=outputs) as runner:
                commands = verifier.run_pipeline(ROOT, root / "build", artifacts)

            self.assertEqual(list(verifier.COMMAND_NAMES), [item["name"] for item in commands])
            configure_args = runner.call_args_list[0].args[0]
            self.assertIn("-DCMAKE_BUILD_TYPE=Release", configure_args)
            self.assertIn("-DFETCHCONTENT_FULLY_DISCONNECTED=ON", configure_args)
            self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", configure_args)
            ctest_args = runner.call_args_list[2].args[0]
            self.assertNotIn("-R", ctest_args)
            python_args = runner.call_args_list[3].args[0]
            self.assertEqual("discover", python_args[4])
            for command in commands:
                log_path = Path(command["log"])
                self.assertTrue(log_path.is_file())
                self.assertEqual(verifier.sha256_file(log_path), command["log_sha256"])

    def test_assessment_requires_source_named_ctest_and_locked_build(self):
        checks = verifier.assess(
            successful_commands(),
            {
                "CMAKE_BUILD_TYPE": "Debug",
                "BUILD_TESTING": "OFF",
                "NIDS_BUILD_TOOLCHAIN_SMOKE": "ON",
            },
            ["source error"],
        )
        failed = {check["name"] for check in checks if check["status"] == "failed"}
        self.assertEqual(
            {
                "source.contract_consistent",
                "build.release",
                "build.testing_enabled",
                "build.toolchain_smoke_disabled",
            },
            failed,
        )


class T21ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_receipt_rejects_log_escape_and_inconsistent_status(self):
        receipt = valid_receipt()
        receipt["commands"][0]["log"] = "outside/configure.log"
        receipt["checks"][0]["status"] = "failed"
        receipt["build"]["temporary_workspace_outside_source"] = False
        errors = verifier.validate_receipt(receipt)
        self.assertIn("every command log must be inside the recorded attempt directory", errors)
        self.assertIn("receipt status must match aggregate check status", errors)
        self.assertIn("build flags do not match the T2.1 acceptance contract", errors)

    def test_writer_and_run_command_refuse_to_overwrite_receipts(self):
        with test_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})
            self.assertEqual("passed", json.loads(output.read_text(encoding="utf-8"))["status"])

            artifact_root = root / "run_log/t2.1"
            artifact_root.mkdir(parents=True)
            (artifact_root / "acceptance.json").write_text("{}", encoding="utf-8")
            args = argparse.Namespace(source=root, artifact_root=artifact_root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite existing acceptance"):
                verifier.command_run(args)


if __name__ == "__main__":
    unittest.main()
