import argparse
import contextlib
import importlib.util
import json
import shutil
import struct
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_t26_core_acceptance.py"
SPEC = importlib.util.spec_from_file_location("verify_t26_core_acceptance", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def temporary_workspace():
    directory = ROOT / f".t26-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t26-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def core_marker(**overrides):
    flags = {name: 1 for name in verifier.FLAG_FIELDS}
    counts = {
        "parser_valid_header_adjustments": verifier.PARSER_VALID_HEADER_ADJUSTMENTS,
        "packets_compared": verifier.PACKET_COUNT,
        "flows": verifier.FLOW_COUNT,
        "flow_snapshots_compared": verifier.VECTOR_COUNT,
        "vectors_compared": verifier.VECTOR_COUNT,
        "features_per_vector": verifier.FEATURE_COUNT,
        "feature_values_compared": verifier.VECTOR_COUNT * verifier.FEATURE_COUNT,
        "prefix_runs": verifier.PREFIX_RUN_COUNT,
        "prefix_vectors_compared": verifier.PREFIX_VECTOR_COUNT,
        "prefix_feature_values_compared": verifier.PREFIX_VECTOR_COUNT * verifier.FEATURE_COUNT,
        "nonvacuous_prefixes": verifier.VECTOR_COUNT,
        "future_sentinel_packets": verifier.FUTURE_SENTINEL_PACKETS,
        "parser_errors": 0,
        "ingest_errors": 0,
    }
    for name, value in overrides.items():
        if name in flags:
            flags[name] = value
        else:
            counts[name] = value
    ordered = (
        f"golden_pcap={flags['golden_pcap']}",
        f"parser_valid_header_adjustments={counts['parser_valid_header_adjustments']}",
        *(
            f"{name}={flags[name]}"
            for name in verifier.FLAG_FIELDS
            if name != "golden_pcap"
        ),
        *(f"{name}={counts[name]}" for name in verifier.COUNT_FIELDS if name != "parser_valid_header_adjustments"),
    )
    return "T2.6 core acceptance: " + " ".join(ordered)


def successful_commands(marker=None):
    artifact = "run_log/t2.6/attempts/ubuntu-acceptance-example"
    marker = marker or core_marker()
    outputs = {
        "libpcap_version": verifier.LOCKED_LIBPCAP_VERSION,
        "libdpdk_version": verifier.LOCKED_DPDK_VERSION,
        "linkage": "\n".join(
            (
                "libpcap.so.0.8 => /lib/libpcap.so.0.8",
                "librte_eal.so.26 => /opt/lib/librte_eal.so.26",
                "librte_net_ring.so.26 => /opt/lib/librte_net_ring.so.26",
            )
        ),
        "ctest_without_capture": "\n".join((*verifier.REQUIRED_CTESTS, "100% tests passed")),
        "ctest_core_parity": f"{verifier.EXPECTED_CTEST}\n{marker}\n100% tests passed",
        "core_evidence": marker,
    }
    arguments = {
        "libpcap_version": ["pkg-config", "--modversion", "libpcap"],
        "libdpdk_version": ["pkg-config", "--modversion", "libdpdk"],
        "configure": ["cmake", "-S", "/source", "-B", "/build"],
        "build": ["cmake", "--build", "/build", "--parallel", "2"],
        "linkage": ["ldd", f"/build/{verifier.TEST_EXECUTABLE}"],
        "ctest_without_capture": [
            "ctest",
            "--test-dir",
            "/build",
            "-E",
            rf"^{verifier.re.escape(verifier.CAPTURE_CTEST)}$",
        ],
        "ctest_core_parity": [
            "ctest",
            "--test-dir",
            "/build",
            "-R",
            rf"^{verifier.re.escape(verifier.EXPECTED_CTEST)}$",
        ],
        "core_evidence": [
            "cmake",
            "-E",
            "env",
            f"{verifier.GOLDEN_OUTPUT_ENV}=/mnt/hgfs/TTTN/{artifact}/golden.pcap",
            f"/build/{verifier.TEST_EXECUTABLE}",
        ],
        "python_unittest": ["python3", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
    }
    return [
        {
            "name": name,
            "arguments": arguments[name],
            "return_code": 0,
            "stdout": outputs.get(name, "OK"),
            "stderr": "",
            "duration_seconds": 0.1,
            "log": f"{artifact}/{verifier.LOG_FILES[name]}",
            "log_sha256": "a" * 64,
        }
        for name in verifier.COMMAND_NAMES
    ]


def golden_receipt():
    return {
        "path": "run_log/t2.6/attempts/ubuntu-acceptance-example/golden.pcap",
        "format": "pcap_nanosecond",
        "version": "2.4",
        "snaplen": 65_535,
        "linktype": 1,
        "record_count": verifier.PACKET_COUNT,
        "size_bytes": 1024,
        "sha256": "c" * 64,
        "runtime_generated": True,
        "synthetic_payload": True,
    }


def valid_receipt():
    commands = successful_commands()
    versions = {
        "libpcap": verifier.LOCKED_LIBPCAP_VERSION,
        "libdpdk": verifier.LOCKED_DPDK_VERSION,
    }
    linkage = verifier.linkage_evidence(commands)
    results = verifier.parse_results(commands)
    golden = golden_receipt()
    checks = verifier.assess(
        commands,
        {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_DPDK": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
        },
        [],
        [],
        versions,
        linkage,
        results,
        golden,
    )
    return {
        "schema_version": verifier.SCHEMA_VERSION,
        "task": verifier.TASK,
        "kind": verifier.KIND,
        "status": "passed",
        "generated_at_utc": "2026-07-15T12:00:00Z",
        "host": {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04.4",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
            "cpu_count": 2,
        },
        "source": {
            "path": "/mnt/hgfs/TTTN",
            "files": [{"path": path, "sha256": "b" * 64} for path in verifier.SOURCE_FILES],
            "contract_errors": [],
        },
        "prerequisites": {
            "receipts": [
                {"task": task, "path": path, "sha256": digest, "status": "passed"}
                for task, path, digest in verifier.PREREQUISITE_RECEIPTS
            ],
            "supplemental_pcapng": {
                "path": verifier.SUPPLEMENTAL_PCAPNG_PATH,
                "sha256": verifier.SUPPLEMENTAL_PCAPNG_SHA256,
                "role": "visual_only_not_parity_input",
            },
            "contract_errors": [],
        },
        "artifacts": {
            "directory": "run_log/t2.6/attempts/ubuntu-acceptance-example",
            "final_receipt": "run_log/t2.6/acceptance.json",
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
            "capture_ctest_excluded": verifier.CAPTURE_CTEST,
        },
        "versions": versions,
        "linkage": linkage,
        "contract": verifier.EXPECTED_CONTRACT,
        "results": results,
        "golden_capture": golden,
        "commands": commands,
        "checks": checks,
    }


def write_source_contract(root: Path):
    files = {path: "fixture" for path in verifier.SOURCE_FILES}
    files["CMakeLists.txt"] = "\n".join(
        (
            "option(NIDS_BUILD_DPDK value OFF)",
            f"add_executable({verifier.TEST_EXECUTABLE} cpp/tests/core_acceptance_test.cpp)",
            f"target_link_libraries({verifier.TEST_EXECUTABLE} PRIVATE",
            "nids::dataset nids::dpdk ${DPDK_BUS_VDEV_LIBRARY} ${DPDK_NET_RING_LIBRARY}",
            "PkgConfig::DPDK PkgConfig::PCAP)",
            f"add_test(NAME {verifier.EXPECTED_CTEST} COMMAND {verifier.TEST_EXECUTABLE})",
        )
    )
    for path in verifier.CORE_FILES:
        files[path] = "core contract without external capture includes"
    files["cpp/src/pcap_adapter.cpp"] = "auto parsed = parse_packet(input);"
    files["cpp/src/dpdk_adapter.cpp"] = "auto parsed = parse_packet(input);"
    files["cpp/tests/core_acceptance_test.cpp"] = "\n".join(
        (
            *verifier.FLAG_FIELDS,
            *verifier.COUNT_FIELDS,
            "std::bit_cast<std::uint64_t> flow_feature_count_v1",
            "read_pcap_file adapt_mbuf rte_eth_from_rings",
            '"--no-pci" "--no-huge" "--in-memory"',
            verifier.GOLDEN_OUTPUT_ENV,
            "TemporaryCapture prefix_capture",
            ".first(item.record_count)",
            "future_sentinel_packets same_snapshot",
            "T2.6 core acceptance:",
        )
    )
    files["scripts/run_t26_acceptance_ubuntu.sh"] = "\n".join(
        (
            "set -Eeuo pipefail",
            "shellcheck --severity=error",
            "verify_t26_core_acceptance.py check --source",
            "verify_t26_core_acceptance.py run --artifact-root",
            "verify_t26_core_acceptance.py validate",
            "acceptance-run.log",
        )
    )
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "config/flow-feature-schema-v1.json").write_bytes(
        (ROOT / "config/flow-feature-schema-v1.json").read_bytes()
    )


def write_pcap(path: Path, records=verifier.PACKET_COUNT):
    data = bytearray(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 1))
    for index in range(records):
        frame = bytes((index + 1, 2, 3, 4))
        data.extend(struct.pack("<IIII", 1, index, len(frame), len(frame)))
        data.extend(frame)
    path.write_bytes(data)


class T26HostAndPrerequisiteTests(unittest.TestCase):
    def test_supported_host_and_locked_prerequisites_are_accepted(self):
        verifier.require_supported_host(
            {
                "system": "Linux",
                "os_id": "ubuntu",
                "os_version": "24.04.4",
                "architecture": "x86_64",
                "python": "3.12.3",
                "effective_uid": 1000,
                "cpu_count": 2,
            }
        )
        receipts, supplemental, errors = verifier.prerequisite_evidence(ROOT)
        self.assertEqual([], errors)
        self.assertEqual(3, len(receipts))
        self.assertEqual("visual_only_not_parity_input", supplemental["role"])

    def test_invalid_hosts_are_rejected(self):
        supported = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
            "cpu_count": 2,
        }
        invalid = (
            ({**supported, "effective_uid": 0}, "normal user"),
            ({**supported, "system": "Windows"}, "Ubuntu Linux VM"),
            ({**supported, "os_version": "22.04"}, "Ubuntu 24.04"),
            ({**supported, "architecture": "aarch64"}, "x86_64"),
            ({**supported, "python": "3.11.9"}, "Python 3.12"),
            ({**supported, "cpu_count": 0}, "logical CPU"),
        )
        for host, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                verifier.require_supported_host(host)

    def test_required_tools_include_linkage_and_shellcheck(self):
        with mock.patch.object(verifier.shutil, "which", return_value="/usr/bin/tool"):
            verifier.require_tools()
        with mock.patch.object(
            verifier.shutil,
            "which",
            side_effect=lambda name: None if name == "ldd" else f"/usr/bin/{name}",
        ), self.assertRaisesRegex(RuntimeError, "ldd"):
            verifier.require_tools()


class T26SourceContractTests(unittest.TestCase):
    def test_complete_source_contract_is_accepted(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            self.assertEqual([], verifier.contract_source_errors(root))

    def test_approximate_comparison_missing_ring_link_and_mutating_runner_are_rejected(self):
        with temporary_workspace() as root:
            write_source_contract(root)
            test = root / "cpp/tests/core_acceptance_test.cpp"
            test.write_text(test.read_text(encoding="utf-8") + "\nstd::fabs(value);", encoding="utf-8")
            cmake = root / "CMakeLists.txt"
            cmake.write_text(
                cmake.read_text(encoding="utf-8").replace("${DPDK_NET_RING_LIBRARY}", "missing_ring"),
                encoding="utf-8",
            )
            wrapper = root / "scripts/run_t26_acceptance_ubuntu.sh"
            wrapper.write_text(wrapper.read_text(encoding="utf-8") + "\nsudo true", encoding="utf-8")
            schema = root / "config/flow-feature-schema-v1.json"
            schema.write_bytes(schema.read_bytes() + b"\n")
            errors = verifier.contract_source_errors(root)
        self.assertTrue(any("schema hash" in error for error in errors))
        self.assertTrue(any("approximate comparison" in error for error in errors))
        self.assertTrue(any("DPDK_NET_RING_LIBRARY" in error or "ring PMD" in error for error in errors))
        self.assertTrue(any("must not mutate" in error for error in errors))


class T26MarkerAndGoldenTests(unittest.TestCase):
    def test_complete_equal_markers_are_accepted(self):
        results = verifier.parse_results(successful_commands())
        self.assertTrue(verifier.valid_results(results))
        self.assertEqual(270, results["feature_values_compared"])
        self.assertEqual(540, results["prefix_feature_values_compared"])

    def test_zero_flag_wrong_prefix_count_duplicate_and_disagreement_are_rejected(self):
        self.assertFalse(
            verifier.valid_results(verifier.parse_results(successful_commands(core_marker(feature_bits_equal=0))))
        )
        self.assertFalse(
            verifier.valid_results(verifier.parse_results(successful_commands(core_marker(prefix_runs=8))))
        )
        duplicate = successful_commands()
        direct = next(item for item in duplicate if item["name"] == "core_evidence")
        direct["stdout"] = f"{direct['stdout']}\n{direct['stdout']}"
        self.assertIsNone(verifier.parse_results(duplicate))
        disagreement = successful_commands()
        direct = next(item for item in disagreement if item["name"] == "core_evidence")
        direct["stdout"] = core_marker(packets_compared=13)
        self.assertIsNone(verifier.parse_results(disagreement))

    def test_nanosecond_pcap_requires_all_fourteen_complete_records(self):
        with temporary_workspace() as root:
            capture = root / "golden.pcap"
            write_pcap(capture)
            evidence = verifier.inspect_classic_pcap(capture)
            self.assertEqual("pcap_nanosecond", evidence["format"])
            self.assertEqual(verifier.PACKET_COUNT, evidence["record_count"])
            capture.write_bytes(capture.read_bytes()[:-1])
            self.assertIsNone(verifier.inspect_classic_pcap(capture))


class T26PipelineTests(unittest.TestCase):
    def test_pipeline_is_locked_release_and_excludes_only_capture(self):
        marker = core_marker()
        outputs = (
            subprocess.CompletedProcess([], 0, verifier.LOCKED_LIBPCAP_VERSION, ""),
            subprocess.CompletedProcess([], 0, verifier.LOCKED_DPDK_VERSION, ""),
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess([], 0, "libpcap librte_eal librte_net_ring", ""),
            subprocess.CompletedProcess(
                [], 0, "\n".join((*verifier.REQUIRED_CTESTS, "100% tests passed")), ""
            ),
            subprocess.CompletedProcess([], 0, f"{verifier.EXPECTED_CTEST}\n{marker}\n100% tests passed", ""),
            subprocess.CompletedProcess([], 0, marker, ""),
            subprocess.CompletedProcess([], 0, "", "Ran 200 tests\nOK"),
        )
        with temporary_workspace() as root:
            artifacts = root / "artifacts"
            with mock.patch.object(verifier.runner.subprocess, "run", side_effect=outputs) as run:
                commands = verifier.run_pipeline(ROOT, root / "build", artifacts)

            self.assertEqual(list(verifier.COMMAND_NAMES), [item["name"] for item in commands])
            configure = run.call_args_list[2].args[0]
            self.assertIn("-DCMAKE_BUILD_TYPE=Release", configure)
            self.assertIn("-DNIDS_BUILD_DPDK=ON", configure)
            self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", configure)
            full = run.call_args_list[5].args[0]
            self.assertEqual(rf"^{verifier.re.escape(verifier.CAPTURE_CTEST)}$", full[full.index("-E") + 1])
            named = run.call_args_list[6].args[0]
            self.assertEqual(rf"^{verifier.re.escape(verifier.EXPECTED_CTEST)}$", named[named.index("-R") + 1])
            direct = run.call_args_list[7].args[0]
            self.assertTrue(any(str(item).startswith(f"{verifier.GOLDEN_OUTPUT_ENV}=") for item in direct))
            for command in commands:
                path = Path(command["log"])
                self.assertTrue(path.is_file())
                self.assertEqual(verifier.sha256_file(path), command["log_sha256"])

    def test_assessment_fails_wrong_scope_and_incomplete_results(self):
        commands = successful_commands(core_marker(prefix_equal=0))
        full = next(item for item in commands if item["name"] == "ctest_without_capture")
        full["arguments"][full["arguments"].index("-E") + 1] = ".*"
        checks = verifier.assess(
            commands,
            {
                "CMAKE_BUILD_TYPE": "Release",
                "BUILD_TESTING": "ON",
                "NIDS_BUILD_DPDK": "ON",
                "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
            },
            [],
            [],
            {"libpcap": verifier.LOCKED_LIBPCAP_VERSION, "libdpdk": verifier.LOCKED_DPDK_VERSION},
            verifier.linkage_evidence(commands),
            verifier.parse_results(commands),
            golden_receipt(),
        )
        failed = {item["name"] for item in checks if item["status"] == "failed"}
        self.assertIn("ctest.scope_excludes_only_capture", failed)
        self.assertIn("results.bitwise_parity_complete", failed)


class T26ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_receipt_rejects_prerequisite_result_log_and_status_tampering(self):
        receipt = valid_receipt()
        receipt["prerequisites"]["receipts"][0]["sha256"] = "0" * 64
        receipt["results"]["prefix_feature_values_compared"] = 539
        receipt["commands"][0]["log"] = "outside/version.log"
        receipt["checks"][0]["status"] = "failed"
        errors = verifier.validate_receipt(receipt)
        self.assertIn("prerequisite receipts and supplemental PCAPNG must match locked evidence", errors)
        self.assertIn("receipt must record complete bitwise parity and no-future counters", errors)
        self.assertIn("every command log must be inside the recorded attempt directory", errors)
        self.assertIn("receipt status must match aggregate check status", errors)

    def test_writer_and_run_refuse_to_overwrite_acceptance(self):
        with temporary_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})
            self.assertEqual("passed", json.loads(output.read_text(encoding="utf-8"))["status"])

            artifact_root = root / "run_log/t2.6"
            artifact_root.mkdir(parents=True)
            (artifact_root / "acceptance.json").write_text("{}", encoding="utf-8")
            args = argparse.Namespace(source=root, artifact_root=artifact_root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite existing acceptance"):
                verifier.command_run(args)


if __name__ == "__main__":
    unittest.main()
