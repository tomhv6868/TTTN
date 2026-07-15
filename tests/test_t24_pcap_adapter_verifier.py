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
VERIFIER_PATH = ROOT / "scripts" / "verify_t24_pcap_adapter.py"
SPEC = importlib.util.spec_from_file_location("verify_t24_pcap_adapter", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def temporary_workspace():
    directory = ROOT / f".t24-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t24-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def coverage_marker(
    packets_seen=5,
    packets_parsed=4,
    parser_errors=1,
    **overrides,
):
    fields = {name: 1 for name in verifier.COVERAGE_FIELDS}
    fields.update(overrides)
    coverage = " ".join(f"{name}={fields[name]}" for name in verifier.COVERAGE_FIELDS)
    return (
        f"T2.4 coverage: {coverage} packets_seen={packets_seen} "
        f"packets_parsed={packets_parsed} parser_errors={parser_errors}"
    )


def full_ctest_output():
    return "\n".join((verifier.EXPECTED_CTEST, "100% tests passed"))


def named_ctest_output(marker=None):
    return "\n".join(
        (
            verifier.EXPECTED_CTEST,
            marker or coverage_marker(),
            "100% tests passed",
        )
    )


def successful_commands():
    artifact_directory = "run_log/t2.4/attempts/ubuntu-acceptance-example"
    outputs = {
        "libpcap_version": "1.10.4",
        "ctest": full_ctest_output(),
        "ctest_pcap_adapter": named_ctest_output(),
    }
    return [
        {
            "name": name,
            "arguments": [name],
            "return_code": 0,
            "stdout": outputs.get(name, "OK"),
            "stderr": "",
            "duration_seconds": 0.1,
            "log": f"{artifact_directory}/{verifier.LOG_FILES[name]}",
            "log_sha256": "a" * 64,
        }
        for name in verifier.COMMAND_NAMES
    ]


def valid_receipt():
    commands = successful_commands()
    version = verifier.libpcap_version(commands)
    results = verifier.parse_coverage(commands)
    checks = verifier.assess(
        commands,
        {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
        },
        [],
        version,
        results,
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
            "files": [{"path": path, "sha256": "b" * 64} for path in verifier.SOURCE_FILES],
            "contract_errors": [],
        },
        "artifacts": {
            "directory": "run_log/t2.4/attempts/ubuntu-acceptance-example",
            "final_receipt": "run_log/t2.4/acceptance.json",
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
        "versions": {
            "libpcap": "1.10.4",
            "command": "pkg-config --modversion libpcap",
        },
        "contract": verifier.EXPECTED_CONTRACT,
        "results": results,
        "commands": commands,
        "checks": checks,
    }


def write_source_contract(root: Path):
    files = {
        "CMakeLists.txt": "\n".join(
            (
                "find_package(PkgConfig REQUIRED)",
                "pkg_check_modules(libpcap REQUIRED IMPORTED_TARGET libpcap)",
                "add_library(nids_dataset cpp/src/pcap_adapter.cpp)",
                "add_library(nids::dataset ALIAS nids_dataset)",
                "target_link_libraries(nids_dataset PRIVATE PkgConfig::libpcap nids::core)",
                "add_executable(nids_pcap_adapter_test cpp/tests/pcap_adapter_test.cpp)",
                "add_test(NAME nids_dataset.pcap_adapter COMMAND nids_pcap_adapter_test)",
            )
        ),
        ".github/workflows/ci.yml": "\n".join(
            (
                "runs-on: ubuntu-24.04",
                "run: sudo apt-get install -y libpcap-dev pkg-config",
            )
        ),
        "cpp/include/nids/pcap_adapter.hpp": (
            "struct PcapSummary { int records_read; int packets_parsed; int parser_errors; };"
        ),
        "cpp/src/pcap_adapter.cpp": "\n".join(
            (
                "pcap_open_offline_with_tstamp_precision();",
                "pcap_next_ex();",
                "pcap_datalink();",
                "auto parsed = nids::parse_packet(input);",
            )
        ),
        "cpp/tests/pcap_adapter_test.cpp": "\n".join(
            (
                *[f'auto {name} = "{name}";' for name in verifier.COVERAGE_FIELDS],
                'auto packets_seen = "packets_seen";',
                'auto packets_parsed = "packets_parsed";',
                'auto parser_errors = "parser_errors";',
                'print("T2.4 coverage:");',
            )
        ),
        "scripts/verify_t24_pcap_adapter.py": "fixture",
    }
    for relative in verifier.CORE_FILES:
        files[relative] = "core contract without external capture dependencies"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class T24HostAndToolTests(unittest.TestCase):
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
            ({**supported, "system": "Windows"}, "Ubuntu Linux VM"),
            ({**supported, "os_version": "22.04"}, "Ubuntu 24.04"),
            ({**supported, "architecture": "aarch64"}, "x86_64"),
            ({**supported, "python": "3.11.9"}, "Python 3.12"),
        )
        for host, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                verifier.require_supported_host(host)

    def test_required_tools_include_pkg_config(self):
        with mock.patch.object(verifier.shutil, "which", return_value="/usr/bin/tool"):
            verifier.require_tools()
        with mock.patch.object(
            verifier.shutil,
            "which",
            side_effect=lambda name: None if name == "pkg-config" else f"/usr/bin/{name}",
        ), self.assertRaisesRegex(RuntimeError, "pkg-config"):
            verifier.require_tools()


class T24SourceContractTests(unittest.TestCase):
    def test_complete_source_contract_is_accepted(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            self.assertEqual([], verifier.contract_source_errors(root))

    def test_core_libpcap_include_duplicate_parser_and_missing_coverage_are_rejected(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            core = root / verifier.CORE_FILES[0]
            core.write_text("#include <pcap/pcap.h>", encoding="utf-8")
            adapter = root / "cpp/src/pcap_adapter.cpp"
            adapter.write_text(
                adapter.read_text(encoding="utf-8")
                + "\nParseResult<PacketView> parse_packet(PacketInput input) { return {}; }",
                encoding="utf-8",
            )
            tests = root / "cpp/tests/pcap_adapter_test.cpp"
            tests.write_text(
                tests.read_text(encoding="utf-8").replace("pcapng", "wrong_format"),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("must not include libpcap" in error for error in errors))
        self.assertTrue(any("not define parse_packet" in error for error in errors))
        self.assertTrue(any("pcapng" in error for error in errors))


class T24CoverageAndVersionTests(unittest.TestCase):
    def test_libpcap_version_and_consistent_coverage_are_accepted(self):
        commands = successful_commands()
        self.assertEqual("1.10.4", verifier.libpcap_version(commands))
        results = verifier.parse_coverage(commands)
        self.assertEqual(5, results["records_read"])
        self.assertEqual(4, results["packets_parsed"])
        self.assertEqual(1, results["parser_errors"])
        self.assertTrue(verifier.valid_coverage(results))

    def test_noisy_version_duplicate_marker_and_inconsistent_counts_are_rejected(self):
        commands = successful_commands()
        version = next(command for command in commands if command["name"] == "libpcap_version")
        version["stderr"] = "warning"
        self.assertIsNone(verifier.libpcap_version(commands))

        named = next(command for command in commands if command["name"] == "ctest_pcap_adapter")
        named["stdout"] = "\n".join((named_ctest_output(), coverage_marker()))
        self.assertIsNone(verifier.parse_coverage(commands))

        named["stdout"] = named_ctest_output(
            coverage_marker(packets_seen=6, packets_parsed=4, parser_errors=1)
        )
        self.assertFalse(verifier.valid_coverage(verifier.parse_coverage(commands)))

    def test_missing_branch_marker_is_rejected(self):
        commands = successful_commands()
        named = next(command for command in commands if command["name"] == "ctest_pcap_adapter")
        named["stdout"] = named_ctest_output(coverage_marker(pcapng=0))
        self.assertFalse(verifier.valid_coverage(verifier.parse_coverage(commands)))


class T24PipelineTests(unittest.TestCase):
    def test_pipeline_versions_builds_and_runs_full_then_named_tests(self):
        outputs = (
            subprocess.CompletedProcess([], 0, "1.10.4", ""),
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess([], 0, full_ctest_output(), ""),
            subprocess.CompletedProcess([], 0, named_ctest_output(), ""),
            subprocess.CompletedProcess([], 0, "", "Ran 160 tests\nOK"),
        )
        with temporary_workspace() as root:
            artifacts = root / "artifacts"
            with mock.patch.object(verifier.runner.subprocess, "run", side_effect=outputs) as runner:
                commands = verifier.run_pipeline(ROOT, root / "build", artifacts)

            self.assertEqual(list(verifier.COMMAND_NAMES), [item["name"] for item in commands])
            version_args = runner.call_args_list[0].args[0]
            self.assertEqual(("pkg-config", "--modversion", "libpcap"), tuple(version_args))
            configure_args = runner.call_args_list[1].args[0]
            self.assertIn("-DCMAKE_BUILD_TYPE=Release", configure_args)
            self.assertIn("-DFETCHCONTENT_FULLY_DISCONNECTED=ON", configure_args)
            self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", configure_args)
            full_args = runner.call_args_list[3].args[0]
            self.assertNotIn("-R", full_args)
            named_args = runner.call_args_list[4].args[0]
            self.assertIn("-R", named_args)
            self.assertIn(
                f"^{verifier.re.escape(verifier.EXPECTED_CTEST)}$", named_args
            )
            python_args = runner.call_args_list[5].args[0]
            self.assertEqual("discover", python_args[4])
            for command in commands:
                log_path = Path(command["log"])
                self.assertTrue(log_path.is_file())
                self.assertEqual(verifier.sha256_file(log_path), command["log_sha256"])

    def test_assessment_requires_source_version_coverage_and_locked_build(self):
        checks = verifier.assess(
            successful_commands(),
            {
                "CMAKE_BUILD_TYPE": "Debug",
                "BUILD_TESTING": "OFF",
                "NIDS_BUILD_TOOLCHAIN_SMOKE": "ON",
            },
            ["source"],
            None,
            None,
        )
        failed = {check["name"] for check in checks if check["status"] == "failed"}
        self.assertEqual(
            {
                "source.contract_consistent",
                "versions.libpcap_present",
                "coverage.marker_present",
                "coverage.complete_and_counts_consistent",
                "build.release",
                "build.testing_enabled",
                "build.toolchain_smoke_disabled",
            },
            failed,
        )


class T24ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_receipt_rejects_version_counts_log_and_status_tampering(self):
        receipt = valid_receipt()
        receipt["versions"]["libpcap"] = "unknown"
        receipt["results"]["records_read"] += 1
        receipt["commands"][0]["log"] = "outside/version.log"
        receipt["checks"][0]["status"] = "failed"
        errors = verifier.validate_receipt(receipt)
        self.assertIn("receipt must record the libpcap pkg-config version", errors)
        self.assertIn(
            "receipt must record complete PCAP coverage and consistent result counts",
            errors,
        )
        self.assertIn("every command log must be inside the recorded attempt directory", errors)
        self.assertIn("receipt status must match aggregate check status", errors)

    def test_writer_and_run_command_refuse_to_overwrite_receipts(self):
        with temporary_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})
            self.assertEqual("passed", json.loads(output.read_text(encoding="utf-8"))["status"])

            artifact_root = root / "run_log/t2.4"
            artifact_root.mkdir(parents=True)
            (artifact_root / "acceptance.json").write_text("{}", encoding="utf-8")
            args = argparse.Namespace(source=root, artifact_root=artifact_root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite existing acceptance"):
                verifier.command_run(args)


if __name__ == "__main__":
    unittest.main()
