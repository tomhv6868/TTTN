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
VERIFIER_PATH = ROOT / "scripts" / "verify_t22_flow_table.py"
SPEC = importlib.util.spec_from_file_location("verify_t22_flow_table", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def test_workspace():
    directory = ROOT / f".t22-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t22-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def ctest_output(
    current: int = 4096,
    peak: int = 16384,
    budget: int = 268435456,
    flow_state: int = 128,
    fixed: int = 1024,
    allocator_current: int = 3072,
    allocator_peak: int = 15360,
) -> str:
    return "\n".join(
        (
            "nids_core.flow_table",
            (
                "T2.2 memory accounting: "
                f"flow_state_bytes={flow_state} fixed_bytes={fixed} "
                f"allocator_current_bytes={allocator_current} "
                f"allocator_peak_bytes={allocator_peak} "
                f"current_bytes={current} peak_bytes={peak} budget_bytes={budget}"
            ),
            "100% tests passed",
        )
    )


def successful_commands():
    artifact_directory = "run_log/t2.2/attempts/ubuntu-acceptance-example"
    return [
        {
            "name": name,
            "arguments": [name],
            "return_code": 0,
            "stdout": ctest_output() if name == "ctest" else "OK",
            "stderr": "",
            "duration_seconds": 0.1,
            "log": f"{artifact_directory}/{verifier.LOG_FILES[name]}",
            "log_sha256": "a" * 64,
        }
        for name in verifier.COMMAND_NAMES
    ]


def valid_receipt():
    commands = successful_commands()
    memory = verifier.parse_memory_measurement(commands)
    checks = verifier.assess(
        commands,
        {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
        },
        [],
        memory,
    )
    return {
        "schema_version": verifier.SCHEMA_VERSION,
        "task": verifier.TASK,
        "kind": verifier.KIND,
        "status": "passed",
        "generated_at_utc": "2026-07-15T10:00:00Z",
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
            "directory": "run_log/t2.2/attempts/ubuntu-acceptance-example",
            "final_receipt": "run_log/t2.2/acceptance.json",
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
        "resources": memory,
        "commands": commands,
        "checks": checks,
    }


def write_source_contract(root: Path) -> None:
    files = {
        "CMakeLists.txt": "\n".join(
            (
                "add_library(nids_core cpp/src/flow_table.cpp)",
                "add_executable(flow_table cpp/tests/flow_table_test.cpp)",
                "add_test(NAME nids_core.flow_table COMMAND flow_table)",
            )
        ),
        "cpp/include/nids/flow.hpp": "\n".join(
            (
                "struct FlowKey {};",
                "enum class FlowDirection { forward, reverse };",
                "enum class FlowCloseReason {",
                *[f"    {reason}," for reason in verifier.CLOSE_REASONS],
                "};",
                "constexpr auto idle = 60LL * 1'000'000'000LL;",
                "constexpr auto age = 30LL * 60LL * 1'000'000'000LL;",
                "constexpr auto hard_limit = 65'536U;",
                "constexpr auto budget = 256ULL * 1024ULL * 1024ULL;",
            )
        ),
        "cpp/include/nids/flow_table.hpp": "\n".join(
            (
                "struct FlowState {",
                "    int packet_count;",
                "};",
                "struct FlowCounters {};",
                "class FlowObserver {",
                "    void on_packet();",
                "    void on_close();",
                "};",
                "class FlowTable {};",
            )
        ),
        "cpp/src/flow_table.cpp": "\n".join(
            (
                "signed_iat_ns();",
                "advance_timestamp_watermark();",
                "idle_timeout_expired();",
                "maximum_age_expired();",
                *[f"FlowCloseReason::{reason};" for reason in verifier.CLOSE_REASONS],
            )
        ),
        "cpp/tests/flow_table_test.cpp": "\n".join(
            (
                "FlowDirection::forward;",
                "FlowDirection::reverse;",
                *[f"FlowCloseReason::{reason};" for reason in verifier.CLOSE_REASONS],
                "counters.fixed_memory_bytes;",
                "counters.current_allocator_bytes;",
                "counters.peak_allocator_bytes;",
                "counters.current_memory_bytes;",
                "counters.peak_memory_bytes;",
                "config.memory_budget_bytes;",
                'print("T2.2 memory accounting:");',
            )
        ),
        "scripts/verify_t22_flow_table.py": "fixture",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class T22HostTests(unittest.TestCase):
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


class T22SourceContractTests(unittest.TestCase):
    def test_complete_source_contract_is_accepted(self):
        with test_workspace() as root:
            write_source_contract(root)
            self.assertEqual([], verifier.contract_source_errors(root))

    def test_raw_packet_retention_and_missing_lifecycle_coverage_are_rejected(self):
        with test_workspace() as root:
            write_source_contract(root)
            header = root / "cpp/include/nids/flow_table.hpp"
            header.write_text(
                header.read_text(encoding="utf-8").replace(
                    "    int packet_count;",
                    "    PacketBytes raw_bytes;",
                ),
                encoding="utf-8",
            )
            tests = root / "cpp/tests/flow_table_test.cpp"
            tests.write_text(
                tests.read_text(encoding="utf-8").replace("tuple_reuse", "wrong_reason"),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("must not retain packet bytes" in error for error in errors))
        self.assertTrue(any("tuple_reuse" in error for error in errors))


class T22MemoryEvidenceTests(unittest.TestCase):
    def test_exactly_one_bounded_measurement_is_accepted(self):
        commands = successful_commands()
        measurement = verifier.parse_memory_measurement(commands)
        self.assertEqual(
            {
                "accounting": "pmr_requested_bytes_plus_fixed_state",
                "flow_state_bytes": 128,
                "fixed_bytes": 1024,
                "allocator_current_bytes": 3072,
                "allocator_peak_bytes": 15360,
                "current_bytes": 4096,
                "peak_bytes": 16384,
                "budget_bytes": 268435456,
            },
            measurement,
        )
        self.assertTrue(verifier.valid_memory_measurement(measurement))

    def test_missing_duplicate_and_over_budget_measurements_are_rejected(self):
        commands = successful_commands()
        commands[2]["stdout"] = "100% tests passed"
        self.assertIsNone(verifier.parse_memory_measurement(commands))

        commands[2]["stdout"] = "\n".join((ctest_output(), ctest_output()))
        self.assertIsNone(verifier.parse_memory_measurement(commands))

        commands[2]["stdout"] = ctest_output(4096, 268435457)
        measurement = verifier.parse_memory_measurement(commands)
        self.assertFalse(verifier.valid_memory_measurement(measurement))

        commands[2]["stdout"] = ctest_output(current=4097)
        measurement = verifier.parse_memory_measurement(commands)
        self.assertFalse(verifier.valid_memory_measurement(measurement))


class T22PipelineTests(unittest.TestCase):
    def test_pipeline_is_clean_release_offline_and_hashes_every_log(self):
        outputs = (
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess([], 0, ctest_output(), ""),
            subprocess.CompletedProcess([], 0, "", "Ran 130 tests\nOK"),
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

    def test_assessment_requires_source_ctest_memory_and_locked_build(self):
        checks = verifier.assess(
            successful_commands(),
            {
                "CMAKE_BUILD_TYPE": "Debug",
                "BUILD_TESTING": "OFF",
                "NIDS_BUILD_TOOLCHAIN_SMOKE": "ON",
            },
            ["source error"],
            None,
        )
        failed = {check["name"] for check in checks if check["status"] == "failed"}
        self.assertEqual(
            {
                "source.contract_consistent",
                "resources.allocator_measurement_present",
                "resources.memory_budget_respected",
                "build.release",
                "build.testing_enabled",
                "build.toolchain_smoke_disabled",
            },
            failed,
        )


class T22ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_receipt_rejects_log_escape_resource_overflow_and_inconsistent_status(self):
        receipt = valid_receipt()
        receipt["commands"][0]["log"] = "outside/configure.log"
        receipt["resources"]["peak_bytes"] = 268435457
        receipt["checks"][0]["status"] = "failed"
        errors = verifier.validate_receipt(receipt)
        self.assertIn("every command log must be inside the recorded attempt directory", errors)
        self.assertIn(
            "resources must contain bounded PMR-requested and fixed-state byte measurements",
            errors,
        )
        self.assertIn("receipt status must match aggregate check status", errors)

    def test_writer_and_run_command_refuse_to_overwrite_receipts(self):
        with test_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})
            self.assertEqual("passed", json.loads(output.read_text(encoding="utf-8"))["status"])

            artifact_root = root / "run_log/t2.2"
            artifact_root.mkdir(parents=True)
            (artifact_root / "acceptance.json").write_text("{}", encoding="utf-8")
            args = argparse.Namespace(source=root, artifact_root=artifact_root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite existing acceptance"):
                verifier.command_run(args)


if __name__ == "__main__":
    unittest.main()
