import argparse
import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_t25_dpdk_adapter.py"
SPEC = importlib.util.spec_from_file_location("verify_t25_dpdk_adapter", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def temporary_workspace():
    directory = ROOT / f".t25-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t25-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def parity_marker(compared=3, parsed=3, parser_errors=0, **overrides):
    fields = {name: 1 for name in verifier.PARITY_FIELDS}
    fields.update(overrides)
    coverage = " ".join(f"{name}={fields[name]}" for name in verifier.PARITY_FIELDS)
    return (
        f"T2.5 parity: {coverage} packets_compared={compared} "
        f"packets_parsed={parsed} parser_errors={parser_errors}"
    )


def capture_marker(copied=4, dropped=0, **overrides):
    fields = {name: 1 for name in verifier.CAPTURE_FIELDS}
    fields.update(overrides)
    return (
        "T2.5 capture: "
        f"pcapng={fields['pcapng']} copied={copied} dropped={dropped} "
        f"bounded={fields['bounded']} default_off={fields['default_off']} "
        f"benchmark_forbidden={fields['benchmark_forbidden']}"
    )


def full_ctest_output():
    return "\n".join((verifier.PARITY_CTEST, verifier.CAPTURE_CTEST, "100% tests passed"))


def named_output(name, marker):
    return "\n".join((name, marker, "100% tests passed"))


def successful_commands():
    artifact_directory = "run_log/t2.5/attempts/ubuntu-acceptance-example"
    dumpcap = "/opt/nids/dpdk/bin/dpdk-dumpcap"
    outputs = {
        "libdpdk_version": verifier.LOCKED_DPDK_VERSION,
        "dumpcap_version": f"dpdk-dumpcap version {verifier.LOCKED_DPDK_VERSION}",
        "dumpcap_linkage": "librte_eal.so.26 => /opt/nids/dpdk/lib/librte_eal.so.26",
        "ctest": full_ctest_output(),
        "ctest_adapter_parity": named_output(verifier.PARITY_CTEST, parity_marker()),
        "ctest_capture_verification": named_output(
            verifier.CAPTURE_CTEST, capture_marker()
        ),
    }
    arguments = {
        "libdpdk_version": ["pkg-config", "--modversion", "libdpdk"],
        "dumpcap_version": [dumpcap, "--version"],
        "dumpcap_linkage": ["ldd", dumpcap],
    }
    return [
        {
            "name": name,
            "arguments": arguments.get(name, [name]),
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
    version = verifier.libdpdk_version(commands)
    dumpcap = verifier.dumpcap_evidence(commands)
    results = verifier.parse_results(commands)
    checks = verifier.assess(
        commands,
        {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_DPDK": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
        },
        [],
        version,
        dumpcap,
        results,
        "c" * 64,
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
            "cpu_count": 2,
            "hugepage_size_kb": 2048,
            "hugepage_total": 64,
            "hugepage_free": 64,
            "capture_huge_dir": "/dev/hugepages/nids-t25-1000-1234",
        },
        "source": {
            "path": "/mnt/hgfs/TTTN",
            "files": [{"path": path, "sha256": "b" * 64} for path in verifier.SOURCE_FILES],
            "contract_errors": [],
        },
        "artifacts": {
            "directory": "run_log/t2.5/attempts/ubuntu-acceptance-example",
            "final_receipt": "run_log/t2.5/acceptance.json",
            "capture": "run_log/t2.5/attempts/ubuntu-acceptance-example/sample.pcapng",
            "capture_sha256": "c" * 64,
        },
        "build": {
            "generator": "Ninja",
            "configuration": "Release",
            "testing_enabled": True,
            "dpdk_enabled": True,
            "toolchain_smoke_enabled": False,
            "temporary_workspace_outside_source": True,
            "temporary_workspace_retained": False,
            "offline_dependency_mode": True,
            "parallel_jobs": 2,
        },
        "versions": {
            "libdpdk": version,
            "libdpdk_command": "pkg-config --modversion libdpdk",
            "dpdk_dumpcap": dumpcap,
        },
        "contract": verifier.EXPECTED_CONTRACT,
        "results": results,
        "commands": commands,
        "checks": checks,
    }


def write_source_contract(root: Path):
    presets = {
        "version": 6,
        "configurePresets": [
            {
                "name": verifier.PRESET,
                "inherits": "ubuntu-release",
                "binaryDir": f"$env{{HOME}}/.cache/nids/{verifier.PRESET}",
                "cacheVariables": {
                    "NIDS_BUILD_DPDK": True,
                    "NIDS_BUILD_TOOLCHAIN_SMOKE": False,
                },
            }
        ],
        "buildPresets": [
            {"name": verifier.PRESET, "configurePreset": verifier.PRESET, "jobs": 2}
        ],
        "testPresets": [
            {
                "name": verifier.PRESET,
                "configurePreset": verifier.PRESET,
                "output": {"outputOnFailure": True},
            }
        ],
    }
    files = {
        "CMakeLists.txt": "\n".join(
            (
                'option(NIDS_BUILD_DPDK "Build adapter" OFF)',
                "find_package(PkgConfig REQUIRED)",
                "pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)",
                "find_library(DPDK_BUS_VDEV_LIBRARY NAMES rte_bus_vdev REQUIRED)",
                "add_library(nids_dpdk cpp/src/dpdk_adapter.cpp)",
                "add_library(nids::dpdk ALIAS nids_dpdk)",
                "target_link_libraries(nids_dpdk PRIVATE nids::core nids::dataset)",
                "add_executable(nids_dpdk_adapter_test cpp/tests/dpdk_adapter_test.cpp)",
                "target_link_libraries(nids_dpdk_adapter_test PRIVATE ${DPDK_BUS_VDEV_LIBRARY})",
                "add_executable(nids_dpdk_adapter_probe cpp/apps/dpdk_adapter_probe.cpp)",
                "add_test(NAME nids_dpdk.adapter_parity COMMAND nids_dpdk_adapter_test)",
                "add_test(NAME nids_dpdk.capture_verification",
                "  COMMAND Python::Interpreter scripts/verify_t25_dpdk_adapter.py capture-test",
                "  --source source --probe probe --validator validator)",
            )
        ),
        "CMakePresets.json": json.dumps(presets),
        "cpp/include/nids/pcap_adapter.hpp": "pcap fixture",
        "cpp/src/pcap_adapter.cpp": "pcap fixture",
        "cpp/include/nids/dpdk_adapter.hpp": "adapt_mbuf(const rte_mbuf* input);",
        "cpp/src/dpdk_adapter.cpp": "\n".join(
            (
                "rte_pktmbuf_read(mbuf, 0, length, scratch);",
                "return nids::parse_packet(input);",
            )
        ),
        "cpp/tests/dpdk_adapter_test.cpp": "\n".join(
            (
                *[f'auto {name} = "{name}";' for name in verifier.PARITY_FIELDS],
                'auto packets_compared = "packets_compared";',
                'auto packets_parsed = "packets_parsed";',
                'auto parser_errors = "parser_errors";',
                'print("T2.5 parity:");',
                'auto validate = "--validate-pcapng";',
                'auto expected = "--expected-packets";',
                'print("T2.5 pcapng reopen:");',
                "rte_eth_from_rings(name, rings.data(), 1U, rings.data(), 1U, 0U);",
            )
        ),
        "cpp/apps/dpdk_adapter_probe.cpp": "\n".join(
            (
                'auto enable = "--enable-verification-capture";',
                'auto prefix = "--file-prefix";',
                'auto huge = "--huge-dir";',
                'auto ready = "--ready-file";',
                'auto arm = "--arm-file";',
                'auto result = "--result-file";',
                'auto maximum = "--max-packets";',
                "bool verification_capture_enabled{false};",
                "rte_pdump_init();",
                'constexpr char ring_port_name[] = "t25_capture";',
                'static_assert(sizeof("net_ring_") - 1U + sizeof(ring_port_name) <= RTE_RING_NAMESIZE);',
                'print("T2.5 probe failure: stage=");',
                "rte_eth_from_rings(name, rings.data(), 1U, rings.data(), 1U, 0U);",
                "rte_eth_dev_configure(port, 1U, 1U, &configuration);",
                "rte_eth_rx_queue_setup(port, 0U, 128U, 0U, nullptr, pool);",
                "rte_eth_tx_queue_setup(port, 0U, 128U, 0U, nullptr);",
                'report_dpdk_failure("eth_tx_queue_setup", result);',
                "rte_eth_dev_info_get(port, &device_info);",
                "device_info.nb_rx_queues;",
                "device_info.nb_tx_queues;",
                'auto eal = std::vector{"-l", "0", "--proc-type=primary", "--no-pci"};',
            )
        ),
        "scripts/verify_t25_dpdk_adapter.py": "fixture",
        "scripts/run_t25_acceptance_ubuntu.sh": "\n".join(
            (
                "HUGEPAGE_TARGET=64",
                "nr_hugepages",
                "free_hugepages",
                "NIDS_T25_HUGE_DIR",
                "trap cleanup EXIT",
                "shellcheck --severity=error",
                "--artifact-root",
                "--capture-debug",
                "--trace-dir",
            )
        ),
    }
    for relative in verifier.CORE_FILES:
        files[relative] = "core contract without external packet I/O dependencies"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class FakeProcess:
    def __init__(self, stdout="", stderr="", return_code=0):
        self._stdout = stdout
        self._stderr = stderr
        self._return_code = return_code
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        self.returncode = self._return_code
        return self._stdout, self._stderr

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class T25HostAndToolTests(unittest.TestCase):
    def test_supported_host_is_accepted_and_invalid_hosts_are_rejected(self):
        supported = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04.4",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
            "cpu_count": 2,
            "hugepage_size_kb": 2048,
            "hugepage_total": 64,
            "hugepage_free": 64,
            "capture_huge_dir": "/dev/hugepages/nids-t25-1000-1234",
        }
        verifier.require_supported_host(supported)
        invalid = (
            ({**supported, "effective_uid": 0}, "normal user"),
            ({**supported, "system": "Windows"}, "Ubuntu Linux VM"),
            ({**supported, "os_version": "22.04"}, "Ubuntu 24.04"),
            ({**supported, "architecture": "aarch64"}, "x86_64"),
            ({**supported, "python": "3.11.9"}, "Python 3.12"),
            ({**supported, "cpu_count": 1}, "at least two logical CPUs"),
            ({**supported, "hugepage_total": 0}, "hugepage wrapper"),
        )
        for host, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                verifier.require_supported_host(host)

    def test_dumpcap_resolves_from_dpdk_root_and_tools_require_it(self):
        with temporary_workspace() as root:
            dumpcap = root / "dpdk/bin/dpdk-dumpcap"
            dumpcap.parent.mkdir(parents=True)
            dumpcap.write_text("binary", encoding="utf-8")
            with mock.patch.object(verifier.shutil, "which", return_value=None):
                self.assertEqual(
                    dumpcap.resolve(), verifier.resolve_dpdk_dumpcap({"DPDK_ROOT": str(root / "dpdk")})
                )
                with self.assertRaisesRegex(RuntimeError, "dpdk-dumpcap"):
                    verifier.resolve_dpdk_dumpcap({})

        with mock.patch.object(verifier.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(
            verifier, "resolve_dpdk_dumpcap", return_value=Path("/usr/bin/dpdk-dumpcap")
        ):
            verifier.require_tools()


class T25SourceContractTests(unittest.TestCase):
    def test_complete_source_and_preset_contract_is_accepted(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            self.assertEqual([], verifier.contract_source_errors(root))

    def test_capture_requires_vdev_linkage_cmake_validator_and_validator_mode_tokens(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            cmake = root / "CMakeLists.txt"
            cmake.write_text(
                cmake.read_text(encoding="utf-8")
                .replace("rte_bus_vdev", "missing_bus_vdev")
                .replace("${DPDK_BUS_VDEV_LIBRARY}", "${MISSING_BUS_VDEV_LIBRARY}")
                .replace("--validator", "--missing-validator"),
                encoding="utf-8",
            )
            tests = root / "cpp/tests/dpdk_adapter_test.cpp"
            tests.write_text(
                tests.read_text(encoding="utf-8").replace(
                    "--validate-pcapng", "--missing-validate-pcapng"
                ),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("rte_bus_vdev" in error for error in errors))
        self.assertTrue(any("must link DPDK_BUS_VDEV_LIBRARY" in error for error in errors))
        self.assertTrue(any("--validator" in error for error in errors))
        self.assertTrue(any("--validate-pcapng" in error for error in errors))

    def test_acceptance_wrapper_safety_tokens_are_required(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            wrapper = root / "scripts/run_t25_acceptance_ubuntu.sh"
            wrapper.write_text(
                wrapper.read_text(encoding="utf-8").replace(
                    "trap cleanup EXIT", "trap missing_cleanup EXIT"
                ),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("trap cleanup EXIT" in error for error in errors))

    def test_ring_pmd_requires_symmetric_rx_and_tx_rings(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            probe = root / "cpp/apps/dpdk_adapter_probe.cpp"
            probe.write_text(
                probe.read_text(encoding="utf-8").replace(
                    "rings.data(), 1U, rings.data(), 1U",
                    "rings.data(), 1U, nullptr, 0U",
                ),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("symmetric RX/TX rings" in error for error in errors))

    def test_dumpcap_rxtx_requires_configured_rx_and_tx_queues(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            probe = root / "cpp/apps/dpdk_adapter_probe.cpp"
            probe.write_text(
                probe.read_text(encoding="utf-8").replace(
                    "rte_eth_dev_configure(port, 1U, 1U, &configuration)",
                    "rte_eth_dev_configure(port, 1U, 0U, &configuration)",
                ),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("nonzero RX/TX queues" in error for error in errors))

    def test_ring_pmd_rejects_name_that_overflows_internal_ring_buffer(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            probe = root / "cpp/apps/dpdk_adapter_probe.cpp"
            probe.write_text(
                probe.read_text(encoding="utf-8").replace(
                    'ring_port_name[] = "t25_capture"',
                    'ring_port_name[] = "net_ring_t25_capture"',
                ),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("PMD adds net_ring_" in error for error in errors))

    def test_core_capture_api_duplicate_parser_and_benchmark_capture_are_rejected(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            (root / verifier.CORE_FILES[0]).write_text("#include <rte_mbuf.h>", encoding="utf-8")
            header = root / "cpp/include/nids/dpdk_adapter.hpp"
            header.write_text(header.read_text(encoding="utf-8") + " rte_pdump_init", encoding="utf-8")
            implementation = root / "cpp/src/dpdk_adapter.cpp"
            implementation.write_text(
                implementation.read_text(encoding="utf-8")
                + "\nParseResult<PacketView> parse_packet(PacketInput input) { return {}; }",
                encoding="utf-8",
            )
            benchmark = root / "cpp/benchmarks/bad.cpp"
            benchmark.parent.mkdir(parents=True)
            benchmark.write_text('auto flag = "--enable-verification-capture";', encoding="utf-8")
            probe = root / "cpp/apps/dpdk_adapter_probe.cpp"
            probe.write_text(
                probe.read_text(encoding="utf-8")
                .replace('"-l", "0"', '"-l", "1"')
                .replace("T2.5 probe failure: stage=", "missing stage diagnostics"),
                encoding="utf-8",
            )
            errors = verifier.contract_source_errors(root)

        self.assertTrue(any("must not include DPDK" in error for error in errors))
        self.assertTrue(any("must not expose verification capture" in error for error in errors))
        self.assertTrue(any("not define parse_packet" in error for error in errors))
        self.assertTrue(any("benchmark path" in error for error in errors))
        self.assertTrue(any("primary must use lcore 0" in error for error in errors))
        self.assertTrue(any("T2.5 probe failure: stage=" in error for error in errors))


class T25EvidenceAndMarkerTests(unittest.TestCase):
    def test_locked_versions_linkage_and_consistent_markers_are_accepted(self):
        commands = successful_commands()
        self.assertEqual(verifier.LOCKED_DPDK_VERSION, verifier.libdpdk_version(commands))
        self.assertTrue(verifier.valid_dumpcap_evidence(verifier.dumpcap_evidence(commands)))
        results = verifier.parse_results(commands)
        self.assertTrue(verifier.valid_results(results))
        self.assertEqual(3, results["parity"]["packets_compared"])
        self.assertEqual(4, results["capture"]["packets_copied"])

    def test_wrong_version_missing_linkage_and_duplicate_marker_are_rejected(self):
        commands = successful_commands()
        dpdk = next(item for item in commands if item["name"] == "libdpdk_version")
        dpdk["stdout"] = "25.11.1"
        self.assertIsNone(verifier.libdpdk_version(commands))

        linkage = next(item for item in commands if item["name"] == "dumpcap_linkage")
        linkage["stdout"] = "librte_eal.so.26 => not found"
        self.assertFalse(verifier.valid_dumpcap_evidence(verifier.dumpcap_evidence(commands)))

        parity = next(item for item in commands if item["name"] == "ctest_adapter_parity")
        parity["stdout"] += "\n" + parity_marker()
        self.assertIsNone(verifier.parse_results(commands))

    def test_bad_parity_and_capture_counters_are_rejected(self):
        commands = successful_commands()
        parity = next(item for item in commands if item["name"] == "ctest_adapter_parity")
        parity["stdout"] = named_output(
            verifier.PARITY_CTEST, parity_marker(compared=3, parsed=2, parser_errors=1)
        )
        capture = next(item for item in commands if item["name"] == "ctest_capture_verification")
        capture["stdout"] = named_output(
            verifier.CAPTURE_CTEST, capture_marker(copied=4, dropped=1, bounded=0)
        )
        self.assertFalse(verifier.valid_results(verifier.parse_results(commands)))


class T25CaptureSessionTests(unittest.TestCase):
    def test_capture_huge_dir_is_explicit_and_must_exist(self):
        with temporary_workspace() as root:
            huge_dir = root / "huge"
            with self.assertRaisesRegex(RuntimeError, verifier.CAPTURE_HUGE_DIR_ENV):
                verifier.resolve_capture_huge_dir({})
            with self.assertRaisesRegex(RuntimeError, "does not exist"):
                verifier.resolve_capture_huge_dir(
                    {verifier.CAPTURE_HUGE_DIR_ENV: str(huge_dir)}
                )
            huge_dir.mkdir()
            self.assertEqual(
                huge_dir.resolve(),
                verifier.resolve_capture_huge_dir(
                    {verifier.CAPTURE_HUGE_DIR_ENV: str(huge_dir)}
                ),
            )

    def test_capture_command_requires_existing_validator(self):
        parser = verifier.build_parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                ["capture-test", "--source", str(ROOT), "--probe", str(ROOT / "probe")]
            )

        with temporary_workspace() as root:
            probe = root / "probe"
            probe.write_text("probe", encoding="utf-8")
            args = argparse.Namespace(
                source=root,
                probe=probe,
                validator=root / "missing-validator",
            )
            with self.assertRaisesRegex(ValueError, "validator executable does not exist"):
                verifier.command_capture_test(args)

    def test_bounded_session_uses_ready_interface_and_writes_pcapng(self):
        with temporary_workspace() as root:
            workspace = root / "workspace"
            workspace.mkdir()
            probe = root / "probe"
            dumpcap = root / "dpdk-dumpcap"
            validator = root / "validator"
            huge_dir = root / "huge"
            output = root / "sample.pcapng"
            probe.write_text("probe", encoding="utf-8")
            dumpcap.write_text("dumpcap", encoding="utf-8")
            validator.write_text("validator", encoding="utf-8")
            huge_dir.mkdir()
            trace_dir = root / "trace"
            trace_dir.mkdir()
            calls = []
            sleeps = []

            def factory(arguments, **kwargs):
                calls.append(arguments)
                if len(calls) == 1:
                    ready = Path(arguments[arguments.index("--ready-file") + 1])
                    result = Path(arguments[arguments.index("--result-file") + 1])
                    ready.write_text(
                        json.dumps(
                            {
                                "interface": "ring_from_ready",
                                "max_packets": verifier.CAPTURE_LIMIT,
                                "rx_queues": 1,
                                "tx_queues": 1,
                            }
                        ),
                        encoding="utf-8",
                    )
                    result.write_text(
                        json.dumps(
                            {
                                "packets_sent": verifier.CAPTURE_LIMIT,
                                "packets_parsed": verifier.CAPTURE_LIMIT,
                                "parser_errors": 0,
                            }
                        ),
                        encoding="utf-8",
                    )
                    return FakeProcess()
                if len(calls) == 2:
                    output_path = Path(arguments[arguments.index("-w") + 1])
                    output_path.write_bytes(verifier.PCAPNG_SECTION_HEADER + b"bounded sample")
                    return FakeProcess(
                        stderr=(
                            "File: /tmp/sample.pcapng\n"
                            f"Packets captured: 0 \b\b{verifier.CAPTURE_LIMIT} \n"
                            "Packets received/dropped on interface 'ring_from_ready': 4/0"
                        )
                    )
                return FakeProcess(stdout=verifier.CAPTURE_VALIDATOR_MARKER)

            copied, dropped = verifier.run_capture_session(
                root,
                probe,
                dumpcap,
                validator,
                output,
                workspace,
                huge_dir,
                process_factory=factory,
                sleeper=sleeps.append,
                trace_dir=trace_dir,
            )

            self.assertEqual((verifier.CAPTURE_LIMIT, 0), (copied, dropped))
            self.assertEqual("--lcore=1", calls[1][1])
            probe_prefix = calls[0][calls[0].index("--file-prefix") + 1]
            self.assertEqual(f"--file-prefix={probe_prefix}", calls[1][2])
            for unsupported in ("-l", "--no-pci", "--huge-dir", "--proc-type=secondary", "--"):
                self.assertNotIn(unsupported, calls[1])
            self.assertEqual(str(huge_dir), calls[0][calls[0].index("--huge-dir") + 1])
            self.assertEqual("ring_from_ready", calls[1][calls[1].index("-i") + 1])
            self.assertIn("--enable-verification-capture", calls[0])
            self.assertEqual(
                [
                    str(validator),
                    "--validate-pcapng",
                    str(output),
                    "--expected-packets",
                    str(verifier.CAPTURE_LIMIT),
                ],
                calls[2],
            )
            self.assertEqual([0.5], sleeps)
            self.assertTrue((workspace / "arm.json").is_file())
            self.assertIsNotNone(verifier.capture_sample_hash(output))
            self.assertEqual(
                "passed",
                json.loads((trace_dir / "session.json").read_text(encoding="utf-8"))["status"],
            )
            self.assertIn(
                "0 \b\b4",
                (trace_dir / "dumpcap.stderr.log").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Packets captured: 4",
                (trace_dir / "dumpcap-rendered.log").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                {"captured": 4, "dropped": 0, "received": 4},
                json.loads((trace_dir / "dumpcap-counters.json").read_text(encoding="utf-8")),
            )

    def test_magic_only_corrupt_capture_fails_through_validator(self):
        with temporary_workspace() as root:
            workspace = root / "workspace"
            workspace.mkdir()
            probe = root / "probe"
            dumpcap = root / "dpdk-dumpcap"
            validator = root / "validator"
            huge_dir = root / "huge"
            output = root / "corrupt.pcapng"
            for executable in (probe, dumpcap, validator):
                executable.write_text("executable", encoding="utf-8")
            huge_dir.mkdir()
            calls = []

            def factory(arguments, **kwargs):
                calls.append(arguments)
                if len(calls) == 1:
                    Path(arguments[arguments.index("--ready-file") + 1]).write_text(
                        json.dumps(
                            {
                                "interface": "ring_from_ready",
                                "max_packets": verifier.CAPTURE_LIMIT,
                                "rx_queues": 1,
                                "tx_queues": 1,
                            }
                        ),
                        encoding="utf-8",
                    )
                    Path(arguments[arguments.index("--result-file") + 1]).write_text(
                        json.dumps(
                            {
                                "packets_sent": verifier.CAPTURE_LIMIT,
                                "packets_parsed": verifier.CAPTURE_LIMIT,
                                "parser_errors": 0,
                            }
                        ),
                        encoding="utf-8",
                    )
                    return FakeProcess()
                if len(calls) == 2:
                    Path(arguments[arguments.index("-w") + 1]).write_bytes(
                        verifier.PCAPNG_SECTION_HEADER + b"not a valid PCAPNG block"
                    )
                    return FakeProcess(
                        stdout=(
                            f"Packets captured: {verifier.CAPTURE_LIMIT}\n"
                            "Packets received/dropped on interface 'ring_from_ready': 4/0"
                        )
                    )
                return FakeProcess(stderr="invalid PCAPNG block", return_code=1)

            with self.assertRaisesRegex(RuntimeError, "PCAPNG validator failed"):
                verifier.run_capture_session(
                    root,
                    probe,
                    dumpcap,
                    validator,
                    output,
                    workspace,
                    huge_dir,
                    process_factory=factory,
                    sleeper=lambda _: None,
                )

            self.assertEqual(str(validator), calls[2][0])
            self.assertEqual("--validate-pcapng", calls[2][1])

    def test_dumpcap_summary_must_be_unique_and_consistent(self):
        good = "Packets captured: 4\nPackets received/dropped on interface 'ring': 4/0"
        self.assertEqual((4, 0), verifier._parse_dumpcap_stats(good))
        live_progress = (
            "File: /tmp/sample.pcapng\n"
            "Packets captured: 0 \b\b4 \n"
            "Packets received/dropped on interface 'ring': 4/0 (100.0)\n"
        )
        self.assertEqual((4, 0), verifier._parse_dumpcap_stats(live_progress))
        with self.assertRaisesRegex(
            RuntimeError, "captured=4 received=3 dropped=0"
        ):
            verifier._parse_dumpcap_stats(
                "Packets captured: 4\nPackets received/dropped on interface 'ring': 3/0"
            )
        with self.assertRaisesRegex(RuntimeError, "one bounded"):
            verifier._parse_dumpcap_stats(good + "\n" + good)


class T25PipelineTests(unittest.TestCase):
    def test_pipeline_records_evidence_builds_dpdk_and_runs_full_then_named_tests(self):
        outputs = (
            subprocess.CompletedProcess([], 0, verifier.LOCKED_DPDK_VERSION, ""),
            subprocess.CompletedProcess(
                [], 0, f"dpdk-dumpcap version {verifier.LOCKED_DPDK_VERSION}", ""
            ),
            subprocess.CompletedProcess(
                [], 0, "librte_eal.so.26 => /opt/dpdk/lib/librte_eal.so.26", ""
            ),
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess([], 0, full_ctest_output(), ""),
            subprocess.CompletedProcess(
                [], 0, named_output(verifier.PARITY_CTEST, parity_marker()), ""
            ),
            subprocess.CompletedProcess(
                [], 0, named_output(verifier.CAPTURE_CTEST, capture_marker()), ""
            ),
            subprocess.CompletedProcess([], 0, "", "Ran tests\nOK"),
        )
        with temporary_workspace() as root:
            artifacts = root / "artifacts"
            dumpcap = root / "dpdk-dumpcap"
            dumpcap.write_text("binary", encoding="utf-8")
            with mock.patch.object(verifier, "resolve_dpdk_dumpcap", return_value=dumpcap), mock.patch.object(
                verifier.runner.subprocess, "run", side_effect=outputs
            ) as runner:
                commands = verifier.run_pipeline(ROOT, root / "build", artifacts)

            self.assertEqual(list(verifier.COMMAND_NAMES), [item["name"] for item in commands])
            self.assertEqual(
                ("pkg-config", "--modversion", "libdpdk"), tuple(runner.call_args_list[0].args[0])
            )
            self.assertEqual((str(dumpcap), "--version"), tuple(runner.call_args_list[1].args[0]))
            self.assertEqual(("ldd", str(dumpcap)), tuple(runner.call_args_list[2].args[0]))
            configure = runner.call_args_list[3].args[0]
            self.assertIn("-DNIDS_BUILD_DPDK=ON", configure)
            self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", configure)
            self.assertIn("-DFETCHCONTENT_FULLY_DISCONNECTED=ON", configure)
            self.assertNotIn("-R", runner.call_args_list[5].args[0])
            parity = runner.call_args_list[6].args[0]
            self.assertIn(f"^{verifier.re.escape(verifier.PARITY_CTEST)}$", parity)
            capture = runner.call_args_list[7].args[0]
            self.assertEqual(("cmake", "-E", "env"), tuple(capture[:3]))
            self.assertTrue(any(item.startswith(f"{verifier.CAPTURE_OUTPUT_ENV}=") for item in capture))
            self.assertIn(f"^{verifier.re.escape(verifier.CAPTURE_CTEST)}$", capture)
            for command in commands:
                log_path = Path(command["log"])
                self.assertTrue(log_path.is_file())
                self.assertEqual(verifier.sha256_file(log_path), command["log_sha256"])


class T25ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_receipt_rejects_version_capture_log_and_status_tampering(self):
        receipt = valid_receipt()
        receipt["versions"]["libdpdk"] = "25.11.1"
        receipt["artifacts"]["capture_sha256"] = "bad"
        receipt["commands"][0]["log"] = "outside/version.log"
        receipt["checks"][0]["status"] = "failed"
        errors = verifier.validate_receipt(receipt)
        self.assertIn(f"receipt must record locked libdpdk {verifier.LOCKED_DPDK_VERSION}", errors)
        self.assertIn("artifacts must hash the retained bounded PCAPNG sample", errors)
        self.assertIn("every command log must be inside the recorded attempt directory", errors)
        self.assertIn("receipt status must match aggregate check status", errors)

    def test_writer_and_run_command_refuse_to_overwrite_receipts(self):
        with temporary_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})

            artifact_root = root / "run_log/t2.5"
            artifact_root.mkdir(parents=True)
            (artifact_root / "acceptance.json").write_text("{}", encoding="utf-8")
            args = argparse.Namespace(source=root, artifact_root=artifact_root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite existing acceptance"):
                verifier.command_run(args)


if __name__ == "__main__":
    unittest.main()
