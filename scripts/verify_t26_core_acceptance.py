#!/usr/bin/env python3
"""Build and verify T2.6 adapter-to-feature parity on the locked Ubuntu host."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import re
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_t11_packet_contract as runner


SCHEMA_VERSION = "1.0.0"
TASK = "T2.6"
KIND = "core_acceptance"
LOCKED_LIBPCAP_VERSION = "1.10.4"
LOCKED_DPDK_VERSION = "25.11.2"
EXPECTED_CTEST = "nids_core.adapter_feature_parity"
CAPTURE_CTEST = "nids_dpdk.capture_verification"
REQUIRED_CTESTS = (
    "nids_core.feature_engine",
    "nids_dataset.pcap_adapter",
    "nids_dpdk.adapter_parity",
    EXPECTED_CTEST,
)
TEST_EXECUTABLE = "nids_core_acceptance_test"
GOLDEN_OUTPUT_ENV = "NIDS_T26_GOLDEN_PCAP_OUTPUT"
FEATURE_COUNT = 54
VECTOR_COUNT = 5
PACKET_COUNT = 14
FLOW_COUNT = 2
PREFIX_RUN_COUNT = 10
PREFIX_VECTOR_COUNT = 10
PARSER_VALID_HEADER_ADJUSTMENTS = 6
FUTURE_SENTINEL_PACKETS = 2
FLOW_SCHEMA_SHA256 = "69241cb5069ce68f941836332cfc556d15fba00253288eb6f985155bac1bc6eb"

PREREQUISITE_RECEIPTS = (
    (
        "T2.3",
        "run_log/t2.3/acceptance.json",
        "88b04e327bda876e3adba2b0223bc80c40fe62d78459e0b0b493f3b234acf7a4",
    ),
    (
        "T2.4",
        "run_log/t2.4/acceptance.json",
        "1f425b8a9fec4fa4f57f38db005b358062d39c2c84302ace7ce695d8daa150b9",
    ),
    (
        "T2.5",
        "run_log/t2.5/acceptance.json",
        "21095b9753913967c5e5d9d4678ec74e85ba426b9f79f4552913ddd5e7a45623",
    ),
)
SUPPLEMENTAL_PCAPNG_PATH = (
    "run_log/t2.5/attempts/ubuntu-acceptance-20260715T102215831372Z/sample.pcapng"
)
SUPPLEMENTAL_PCAPNG_SHA256 = (
    "6651aa55131847e8ba38ceea48288d8ff3a1d318a1a3f7be3c252b3c4610a08d"
)

CORE_FILES = (
    "cpp/include/nids/packet.hpp",
    "cpp/src/packet.cpp",
    "cpp/include/nids/flow.hpp",
    "cpp/include/nids/flow_table.hpp",
    "cpp/src/flow_table.cpp",
    "cpp/include/nids/feature.hpp",
    "cpp/src/feature.cpp",
)
SOURCE_FILES = (
    "CMakeLists.txt",
    "config/flow-feature-schema-v1.json",
    *CORE_FILES,
    "cpp/include/nids/pcap_adapter.hpp",
    "cpp/src/pcap_adapter.cpp",
    "cpp/include/nids/dpdk_adapter.hpp",
    "cpp/src/dpdk_adapter.cpp",
    "cpp/tests/core_acceptance_test.cpp",
    "scripts/run_t26_acceptance_ubuntu.sh",
    "scripts/verify_t26_core_acceptance.py",
    "tests/test_t26_core_acceptance_verifier.py",
)
COMMAND_NAMES = (
    "libpcap_version",
    "libdpdk_version",
    "configure",
    "build",
    "linkage",
    "ctest_without_capture",
    "ctest_core_parity",
    "core_evidence",
    "python_unittest",
)
LOG_FILES = {
    "libpcap_version": "libpcap-version.log",
    "libdpdk_version": "libdpdk-version.log",
    "configure": "configure.log",
    "build": "build.log",
    "linkage": "core-linkage.log",
    "ctest_without_capture": "ctest-without-capture.log",
    "ctest_core_parity": "ctest-core-parity.log",
    "core_evidence": "core-evidence.log",
    "python_unittest": "python-unittest.log",
}
FLAG_FIELDS = (
    "golden_pcap",
    "pcap_adapter",
    "dpdk_ring",
    "input_bytes_equal",
    "input_timestamps_equal",
    "input_clock_domains_equal",
    "input_wire_lengths_equal",
    "packet_views_equal",
    "flow_snapshots_equal",
    "feature_bits_equal",
    "prefix_equal",
    "tcp_f3",
    "tcp_f5",
    "tcp_f7",
    "tcp_f9",
    "udp_f3",
)
COUNT_FIELDS = (
    "parser_valid_header_adjustments",
    "packets_compared",
    "flows",
    "flow_snapshots_compared",
    "vectors_compared",
    "features_per_vector",
    "feature_values_compared",
    "prefix_runs",
    "prefix_vectors_compared",
    "prefix_feature_values_compared",
    "nonvacuous_prefixes",
    "future_sentinel_packets",
    "parser_errors",
    "ingest_errors",
)
EXPECTED_CONTRACT = {
    "adapters": ["libpcap", "dpdk_ring_pmd"],
    "shared_parser": "nids_core.parse_packet",
    "same_input": ["raw_bytes", "timestamp_ns", "clock_domain", "wire_length"],
    "feature_vector": {
        "schema": "nids.flow_features.v1",
        "schema_sha256": FLOW_SCHEMA_SHA256,
        "count": FEATURE_COUNT,
        "comparison": "float64_bit_pattern_uint64",
        "checkpoints": ["TCP_F3", "TCP_F5", "TCP_F7", "TCP_F9", "UDP_F3"],
    },
    "no_future_information": {
        "method": "physical_capture_prefix_replay",
        "prefix_runs": PREFIX_RUN_COUNT,
        "future_sentinel_packets": FUTURE_SENTINEL_PACKETS,
    },
    "golden_capture": {
        "format": "classic_pcap_nanosecond",
        "source": "runtime_generated_synthetic_packets",
        "records": PACKET_COUNT,
        "retention": "run_log_attempt_only",
    },
    "supplemental_pcapng": "visual_only_not_parity_input",
    "dpdk_runtime": ["no_pci", "no_huge", "in_memory"],
    "capture_ctest_excluded": CAPTURE_CTEST,
    "clean_release_build": True,
    "offline_dependency_mode": True,
}

CORE_MARKER = re.compile(
    r"T2\.6 core acceptance:\s*"
    r"golden_pcap=(?P<golden_pcap>\d+)\s+"
    r"parser_valid_header_adjustments=(?P<parser_valid_header_adjustments>\d+)\s+"
    r"pcap_adapter=(?P<pcap_adapter>\d+)\s+"
    r"dpdk_ring=(?P<dpdk_ring>\d+)\s+"
    r"input_bytes_equal=(?P<input_bytes_equal>\d+)\s+"
    r"input_timestamps_equal=(?P<input_timestamps_equal>\d+)\s+"
    r"input_clock_domains_equal=(?P<input_clock_domains_equal>\d+)\s+"
    r"input_wire_lengths_equal=(?P<input_wire_lengths_equal>\d+)\s+"
    r"packet_views_equal=(?P<packet_views_equal>\d+)\s+"
    r"flow_snapshots_equal=(?P<flow_snapshots_equal>\d+)\s+"
    r"feature_bits_equal=(?P<feature_bits_equal>\d+)\s+"
    r"prefix_equal=(?P<prefix_equal>\d+)\s+"
    r"tcp_f3=(?P<tcp_f3>\d+)\s+"
    r"tcp_f5=(?P<tcp_f5>\d+)\s+"
    r"tcp_f7=(?P<tcp_f7>\d+)\s+"
    r"tcp_f9=(?P<tcp_f9>\d+)\s+"
    r"udp_f3=(?P<udp_f3>\d+)\s+"
    r"packets_compared=(?P<packets_compared>\d+)\s+"
    r"flows=(?P<flows>\d+)\s+"
    r"flow_snapshots_compared=(?P<flow_snapshots_compared>\d+)\s+"
    r"vectors_compared=(?P<vectors_compared>\d+)\s+"
    r"features_per_vector=(?P<features_per_vector>\d+)\s+"
    r"feature_values_compared=(?P<feature_values_compared>\d+)\s+"
    r"prefix_runs=(?P<prefix_runs>\d+)\s+"
    r"prefix_vectors_compared=(?P<prefix_vectors_compared>\d+)\s+"
    r"prefix_feature_values_compared=(?P<prefix_feature_values_compared>\d+)\s+"
    r"nonvacuous_prefixes=(?P<nonvacuous_prefixes>\d+)\s+"
    r"future_sentinel_packets=(?P<future_sentinel_packets>\d+)\s+"
    r"parser_errors=(?P<parser_errors>\d+)\s+"
    r"ingest_errors=(?P<ingest_errors>\d+)"
)
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+._A-Za-z0-9]*)?")
PCAP_MAGICS = {
    bytes.fromhex("4d3cb2a1"): ("<", "pcap_nanosecond", 1_000_000_000),
    bytes.fromhex("a1b23c4d"): (">", "pcap_nanosecond", 1_000_000_000),
    bytes.fromhex("d4c3b2a1"): ("<", "pcap_microsecond", 1_000_000),
    bytes.fromhex("a1b2c3d4"): (">", "pcap_microsecond", 1_000_000),
}

sha256_file = runner.sha256_file
write_new_json = runner.write_new_json


def inspect_host() -> dict[str, Any]:
    os_release = runner.read_os_release()
    return {
        "system": platform.system(),
        "os_id": os_release.get("ID"),
        "os_version": os_release.get("VERSION_ID"),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "cpu_count": os.cpu_count(),
    }


def require_supported_host(host: Mapping[str, Any]) -> None:
    uid = host.get("effective_uid")
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        raise RuntimeError("T2.6 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T2.6 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T2.6 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T2.6 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T2.6 verification requires Python 3.12.x")
    cpu_count = host.get("cpu_count")
    if not isinstance(cpu_count, int) or isinstance(cpu_count, bool) or cpu_count < 1:
        raise RuntimeError("T2.6 verification requires at least one logical CPU")


def require_tools() -> None:
    required = ("cmake", "ninja", "c++", "ctest", "pkg-config", "ldd", "shellcheck")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")


def run_pipeline(source: Path, build: Path, artifacts: Path) -> list[dict[str, Any]]:
    libpcap = runner.run_command(
        "libpcap_version",
        ("pkg-config", "--modversion", "libpcap"),
        source,
        artifacts / LOG_FILES["libpcap_version"],
        30.0,
    )
    libdpdk = runner.run_command(
        "libdpdk_version",
        ("pkg-config", "--modversion", "libdpdk"),
        source,
        artifacts / LOG_FILES["libdpdk_version"],
        30.0,
    )
    commands = [libpcap, libdpdk]

    if libpcap["return_code"] == 0 and libdpdk["return_code"] == 0:
        configure = runner.run_command(
            "configure",
            (
                "cmake",
                "-S",
                str(source),
                "-B",
                str(build),
                "-G",
                "Ninja",
                "-DBUILD_TESTING=ON",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
                "-DNIDS_BUILD_DPDK=ON",
                "-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF",
            ),
            source,
            artifacts / LOG_FILES["configure"],
            300.0,
        )
    else:
        configure = runner.skipped_command(
            "configure",
            "dependency version check failed",
            artifacts / LOG_FILES["configure"],
        )
    commands.append(configure)

    if configure["return_code"] == 0:
        build_result = runner.run_command(
            "build",
            ("cmake", "--build", str(build), "--parallel", "2"),
            source,
            artifacts / LOG_FILES["build"],
            900.0,
        )
    else:
        build_result = runner.skipped_command(
            "build", "configure failed or was skipped", artifacts / LOG_FILES["build"]
        )
    commands.append(build_result)

    if build_result["return_code"] == 0:
        executable = build / TEST_EXECUTABLE
        linkage = runner.run_command(
            "linkage",
            ("ldd", str(executable)),
            source,
            artifacts / LOG_FILES["linkage"],
            30.0,
        )
        ctest_without_capture = runner.run_command(
            "ctest_without_capture",
            (
                "ctest",
                "--test-dir",
                str(build),
                "--build-config",
                "Release",
                "--output-on-failure",
                "--verbose",
                "-E",
                rf"^{re.escape(CAPTURE_CTEST)}$",
            ),
            source,
            artifacts / LOG_FILES["ctest_without_capture"],
            900.0,
        )
        ctest_core = runner.run_command(
            "ctest_core_parity",
            (
                "ctest",
                "--test-dir",
                str(build),
                "--build-config",
                "Release",
                "--output-on-failure",
                "--verbose",
                "-R",
                rf"^{re.escape(EXPECTED_CTEST)}$",
            ),
            source,
            artifacts / LOG_FILES["ctest_core_parity"],
            180.0,
        )
        core_evidence = runner.run_command(
            "core_evidence",
            (
                "cmake",
                "-E",
                "env",
                f"{GOLDEN_OUTPUT_ENV}={artifacts / 'golden.pcap'}",
                str(executable),
            ),
            source,
            artifacts / LOG_FILES["core_evidence"],
            180.0,
        )
    else:
        linkage = runner.skipped_command(
            "linkage", "build failed or was skipped", artifacts / LOG_FILES["linkage"]
        )
        ctest_without_capture = runner.skipped_command(
            "ctest_without_capture",
            "build failed or was skipped",
            artifacts / LOG_FILES["ctest_without_capture"],
        )
        ctest_core = runner.skipped_command(
            "ctest_core_parity",
            "build failed or was skipped",
            artifacts / LOG_FILES["ctest_core_parity"],
        )
        core_evidence = runner.skipped_command(
            "core_evidence",
            "build failed or was skipped",
            artifacts / LOG_FILES["core_evidence"],
        )
    commands.extend((linkage, ctest_without_capture, ctest_core, core_evidence))
    commands.append(
        runner.run_command(
            "python_unittest",
            (sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"),
            source,
            artifacts / LOG_FILES["python_unittest"],
            900.0,
        )
    )
    return commands


def dependency_version(commands: Sequence[Mapping[str, Any]], name: str, locked: str) -> str | None:
    command = runner.find_command(commands, name)
    stdout = str(command.get("stdout", "")).strip()
    stderr = str(command.get("stderr", "")).strip()
    if stderr or VERSION.fullmatch(stdout) is None or stdout != locked:
        return None
    return stdout


def linkage_evidence(commands: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    command = runner.find_command(commands, "linkage")
    output = "\n".join(
        part
        for part in (str(command.get("stdout", "")).strip(), str(command.get("stderr", "")).strip())
        if part
    )
    if command.get("return_code") != 0:
        return None
    lowered = output.lower()
    return {
        "target": TEST_EXECUTABLE,
        "return_code": command.get("return_code"),
        "missing_dependencies": [
            line.strip() for line in output.splitlines() if "not found" in line.lower()
        ],
        "libpcap_present": "libpcap" in lowered,
        "dpdk_eal_present": "librte_eal" in lowered,
        "dpdk_ring_pmd_present": "librte_net_ring" in lowered,
        "output": output,
    }


def valid_linkage(evidence: Mapping[str, Any] | None) -> bool:
    return evidence is not None and (
        evidence.get("target") == TEST_EXECUTABLE
        and evidence.get("return_code") == 0
        and evidence.get("missing_dependencies") == []
        and evidence.get("libpcap_present") is True
        and evidence.get("dpdk_eal_present") is True
        and evidence.get("dpdk_ring_pmd_present") is True
    )


def _single_marker(command: Mapping[str, Any]) -> re.Match[str] | None:
    output = "\n".join((str(command.get("stdout", "")), str(command.get("stderr", ""))))
    matches = list(CORE_MARKER.finditer(output))
    return matches[0] if len(matches) == 1 else None


def parse_results(commands: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    named = _single_marker(runner.find_command(commands, "ctest_core_parity"))
    direct = _single_marker(runner.find_command(commands, "core_evidence"))
    if named is None or direct is None or named.groupdict() != direct.groupdict():
        return None
    values = {name: int(direct.group(name)) for name in (*FLAG_FIELDS, *COUNT_FIELDS)}
    return {
        "coverage": {name: values[name] == 1 for name in FLAG_FIELDS},
        **{name: values[name] for name in COUNT_FIELDS},
    }


def valid_results(results: Mapping[str, Any] | None) -> bool:
    if results is None:
        return False
    coverage = results.get("coverage")
    expected_counts = {
        "parser_valid_header_adjustments": PARSER_VALID_HEADER_ADJUSTMENTS,
        "packets_compared": PACKET_COUNT,
        "flows": FLOW_COUNT,
        "flow_snapshots_compared": VECTOR_COUNT,
        "vectors_compared": VECTOR_COUNT,
        "features_per_vector": FEATURE_COUNT,
        "feature_values_compared": VECTOR_COUNT * FEATURE_COUNT,
        "prefix_runs": PREFIX_RUN_COUNT,
        "prefix_vectors_compared": PREFIX_VECTOR_COUNT,
        "prefix_feature_values_compared": PREFIX_VECTOR_COUNT * FEATURE_COUNT,
        "nonvacuous_prefixes": VECTOR_COUNT,
        "future_sentinel_packets": FUTURE_SENTINEL_PACKETS,
        "parser_errors": 0,
        "ingest_errors": 0,
    }
    return (
        isinstance(coverage, Mapping)
        and set(coverage) == set(FLAG_FIELDS)
        and all(coverage.get(name) is True for name in FLAG_FIELDS)
        and all(
            isinstance(results.get(name), int)
            and not isinstance(results.get(name), bool)
            and results.get(name) == value
            for name, value in expected_counts.items()
        )
    )


def inspect_classic_pcap(path: Path) -> dict[str, Any] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 24 or data[:4] not in PCAP_MAGICS:
        return None
    endian, capture_format, fraction_limit = PCAP_MAGICS[data[:4]]
    try:
        major, minor, _, _, snaplen, linktype = struct.unpack_from(f"{endian}HHiiii", data, 4)
    except struct.error:
        return None
    offset = 24
    records = 0
    while offset < len(data):
        if len(data) - offset < 16:
            return None
        seconds, fraction, captured, original = struct.unpack_from(f"{endian}IIII", data, offset)
        del seconds
        offset += 16
        if fraction >= fraction_limit or captured > snaplen or captured != original:
            return None
        if captured == 0 or offset + captured > len(data):
            return None
        offset += captured
        records += 1
    return {
        "format": capture_format,
        "version": f"{major}.{minor}",
        "snaplen": snaplen,
        "linktype": linktype,
        "record_count": records,
        "size_bytes": len(data),
        "sha256": sha256_file(path),
    }


def golden_evidence(path: Path, source: Path) -> dict[str, Any] | None:
    inspected = inspect_classic_pcap(path)
    if inspected is None:
        return None
    return {
        "path": str(path.relative_to(source)).replace("\\", "/"),
        **inspected,
        "runtime_generated": True,
        "synthetic_payload": True,
    }


def valid_golden(evidence: Mapping[str, Any] | None, artifact_directory: str | None = None) -> bool:
    if evidence is None:
        return False
    path = evidence.get("path")
    expected_path = f"{artifact_directory}/golden.pcap" if artifact_directory else None
    return (
        isinstance(path, str)
        and (expected_path is None or path == expected_path)
        and evidence.get("format") == "pcap_nanosecond"
        and evidence.get("version") == "2.4"
        and evidence.get("snaplen") == 65_535
        and evidence.get("linktype") == 1
        and evidence.get("record_count") == PACKET_COUNT
        and isinstance(evidence.get("size_bytes"), int)
        and not isinstance(evidence.get("size_bytes"), bool)
        and evidence.get("size_bytes", 0) > 24
        and re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("sha256", ""))) is not None
        and evidence.get("runtime_generated") is True
        and evidence.get("synthetic_payload") is True
    )


def prerequisite_evidence(source: Path) -> tuple[list[dict[str, Any]], dict[str, Any] | None, list[str]]:
    receipts: list[dict[str, Any]] = []
    errors: list[str] = []
    for task, relative, expected_hash in PREREQUISITE_RECEIPTS:
        path = source / relative
        actual_hash = sha256_file(path) if path.is_file() else None
        document: Any = None
        if path.is_file():
            try:
                document = runner.load_json(path)
            except (OSError, ValueError) as error:
                errors.append(f"invalid prerequisite receipt {relative}: {error}")
        valid_document = (
            isinstance(document, Mapping)
            and document.get("task") == task
            and document.get("status") == "passed"
        )
        if actual_hash != expected_hash:
            errors.append(f"prerequisite receipt hash changed: {relative}")
        if not valid_document:
            errors.append(f"prerequisite receipt must be passed {task}: {relative}")
        receipts.append(
            {
                "task": task,
                "path": relative,
                "sha256": actual_hash,
                "status": document.get("status") if isinstance(document, Mapping) else None,
            }
        )

    supplemental_path = source / SUPPLEMENTAL_PCAPNG_PATH
    supplemental_hash = sha256_file(supplemental_path) if supplemental_path.is_file() else None
    supplemental = {
        "path": SUPPLEMENTAL_PCAPNG_PATH,
        "sha256": supplemental_hash,
        "role": "visual_only_not_parity_input",
    }
    if supplemental_hash != SUPPLEMENTAL_PCAPNG_SHA256:
        errors.append("T2.5 supplemental PCAPNG hash changed or file is missing")
    else:
        try:
            if supplemental_path.read_bytes()[:4] != bytes.fromhex("0a0d0d0a"):
                errors.append("T2.5 supplemental capture is not PCAPNG")
        except OSError as error:
            errors.append(f"cannot read T2.5 supplemental PCAPNG: {error}")
    return receipts, supplemental, errors


def _has_external_capture_include(text: str) -> bool:
    return re.search(
        r"#\s*include\s*[<\"](?:(?:pcap/)?pcap\.h|(?:dpdk/)?rte_[^>\"]+)[>\"]",
        text,
    ) is not None


def contract_source_errors(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        return [f"missing source file: {path}" for path in missing]

    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    test = (source / "cpp/tests/core_acceptance_test.cpp").read_text(encoding="utf-8")
    pcap_adapter = (source / "cpp/src/pcap_adapter.cpp").read_text(encoding="utf-8")
    dpdk_adapter = (source / "cpp/src/dpdk_adapter.cpp").read_text(encoding="utf-8")
    wrapper = (source / "scripts/run_t26_acceptance_ubuntu.sh").read_text(encoding="utf-8")
    errors: list[str] = []

    if sha256_file(source / "config/flow-feature-schema-v1.json") != FLOW_SCHEMA_SHA256:
        errors.append("flow feature schema must match the locked T2.3 schema hash")

    cmake_tokens = (
        "NIDS_BUILD_DPDK",
        TEST_EXECUTABLE,
        "cpp/tests/core_acceptance_test.cpp",
        EXPECTED_CTEST,
        "nids::dataset",
        "nids::dpdk",
        "DPDK_BUS_VDEV_LIBRARY",
        "DPDK_NET_RING_LIBRARY",
        "PkgConfig::DPDK",
        "PkgConfig::PCAP",
    )
    missing_cmake = [token for token in cmake_tokens if token not in cmake]
    if missing_cmake:
        errors.append(f"CMake is missing T2.6 tokens: {', '.join(missing_cmake)}")
    link_match = re.search(
        rf"target_link_libraries\s*\(\s*{TEST_EXECUTABLE}\b(?P<body>.*?)\)",
        cmake,
        re.DOTALL,
    )
    required_links = (
        "nids::dataset",
        "nids::dpdk",
        "DPDK_BUS_VDEV_LIBRARY",
        "DPDK_NET_RING_LIBRARY",
        "PkgConfig::DPDK",
        "PkgConfig::PCAP",
    )
    if link_match is None or any(token not in link_match.group("body") for token in required_links):
        errors.append("core acceptance target must explicitly link PCAP, DPDK bus, and ring PMD")

    contaminated = [
        path
        for path in CORE_FILES
        if _has_external_capture_include((source / path).read_text(encoding="utf-8"))
    ]
    if contaminated:
        errors.append(f"core packet/flow/feature files must not include PCAP or DPDK: {', '.join(contaminated)}")
    if "parse_packet" not in pcap_adapter or "parse_packet" not in dpdk_adapter:
        errors.append("both adapters must delegate to the shared parse_packet implementation")
    if re.search(r"ParseResult\s*<\s*PacketView\s*>\s+parse_packet\s*\(", pcap_adapter + dpdk_adapter):
        errors.append("adapters must not define a duplicate parse_packet implementation")

    test_tokens = (
        "std::bit_cast<std::uint64_t>",
        "flow_feature_count_v1",
        "read_pcap_file",
        "adapt_mbuf",
        "rte_eth_from_rings",
        '"--no-pci"',
        '"--no-huge"',
        '"--in-memory"',
        GOLDEN_OUTPUT_ENV,
        "TemporaryCapture prefix_capture",
        ".first(item.record_count)",
        "future_sentinel_packets",
        "same_snapshot",
        "T2.6 core acceptance:",
        *FLAG_FIELDS,
        *COUNT_FIELDS,
    )
    missing_test = [token for token in test_tokens if token not in test]
    if missing_test:
        errors.append(f"core acceptance test is missing evidence tokens: {', '.join(missing_test)}")
    approximate = [token for token in ("epsilon", "tolerance", "std::fabs", "isclose") if token in test]
    if approximate:
        errors.append(f"feature parity must not use approximate comparison: {', '.join(approximate)}")

    wrapper_tokens = (
        "set -Eeuo pipefail",
        "shellcheck --severity=error",
        "verify_t26_core_acceptance.py",
        "check",
        "run",
        "validate",
        "--artifact-root",
        "acceptance-run.log",
    )
    missing_wrapper = [token for token in wrapper_tokens if token not in wrapper]
    if missing_wrapper:
        errors.append(f"Ubuntu runner is missing acceptance tokens: {', '.join(missing_wrapper)}")
    forbidden_wrapper = [token for token in ("sudo", "nr_hugepages", "dpdk-dumpcap") if token in wrapper]
    if forbidden_wrapper:
        errors.append(f"T2.6 runner must not mutate hugepages or invoke capture: {', '.join(forbidden_wrapper)}")
    return errors


def _ctest_scope_is_exact(commands: Sequence[Mapping[str, Any]]) -> bool:
    command = runner.find_command(commands, "ctest_without_capture")
    arguments = command.get("arguments")
    if not isinstance(arguments, list):
        return False
    try:
        exclusion = arguments[arguments.index("-E") + 1]
    except (ValueError, IndexError):
        return False
    return exclusion == rf"^{re.escape(CAPTURE_CTEST)}$" and arguments.count("-E") == 1


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
    prerequisite_errors: Sequence[str],
    versions: Mapping[str, Any],
    linkage: Mapping[str, Any] | None,
    results: Mapping[str, Any] | None,
    golden: Mapping[str, Any] | None,
) -> list[dict[str, str]]:
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed" if runner.find_command(commands, name).get("return_code") == 0 else "failed",
        }
        for name in COMMAND_NAMES
    ]
    full = runner.find_command(commands, "ctest_without_capture")
    full_output = "\n".join((str(full.get("stdout", "")), str(full.get("stderr", ""))))
    named = runner.find_command(commands, "ctest_core_parity")
    named_output = "\n".join((str(named.get("stdout", "")), str(named.get("stderr", ""))))
    checks.extend(
        (
            {"name": "source.contract_consistent", "status": "passed" if not source_errors else "failed"},
            {"name": "prerequisites.locked_receipts_valid", "status": "passed" if not prerequisite_errors else "failed"},
            {
                "name": "versions.locked_dependencies",
                "status": "passed"
                if versions.get("libpcap") == LOCKED_LIBPCAP_VERSION
                and versions.get("libdpdk") == LOCKED_DPDK_VERSION
                else "failed",
            },
            {"name": "linkage.complete", "status": "passed" if valid_linkage(linkage) else "failed"},
            {
                "name": "ctest.scope_excludes_only_capture",
                "status": "passed"
                if _ctest_scope_is_exact(commands) and CAPTURE_CTEST not in full_output
                else "failed",
            },
            {
                "name": "ctest.core_present",
                "status": "passed" if EXPECTED_CTEST in full_output else "failed",
            },
            {
                "name": "ctest.prerequisite_coverage_present",
                "status": "passed"
                if all(name in full_output for name in REQUIRED_CTESTS)
                else "failed",
            },
            {
                "name": "ctest.all_selected_passed",
                "status": "passed" if "100% tests passed" in full_output else "failed",
            },
            {
                "name": "ctest.core_named_passed",
                "status": "passed"
                if EXPECTED_CTEST in named_output and "100% tests passed" in named_output
                else "failed",
            },
            {"name": "results.marker_unique_and_equal", "status": "passed" if results is not None else "failed"},
            {"name": "results.bitwise_parity_complete", "status": "passed" if valid_results(results) else "failed"},
            {"name": "golden.runtime_pcap_valid", "status": "passed" if valid_golden(golden) else "failed"},
            {"name": "build.release", "status": "passed" if cache.get("CMAKE_BUILD_TYPE") == "Release" else "failed"},
            {"name": "build.testing_enabled", "status": "passed" if cache.get("BUILD_TESTING") == "ON" else "failed"},
            {"name": "build.dpdk_enabled", "status": "passed" if cache.get("NIDS_BUILD_DPDK") == "ON" else "failed"},
            {
                "name": "build.toolchain_smoke_disabled",
                "status": "passed" if cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") == "OFF" else "failed",
            },
        )
    )
    return checks


def collect_receipt(source: Path, artifacts: Path, host: Mapping[str, Any]) -> dict[str, Any]:
    source_errors = contract_source_errors(source)
    prerequisite_receipts, supplemental, prerequisite_errors = prerequisite_evidence(source)
    with tempfile.TemporaryDirectory(prefix="nids-t2.6-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifacts)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        versions = {
            "libpcap": dependency_version(commands, "libpcap_version", LOCKED_LIBPCAP_VERSION),
            "libdpdk": dependency_version(commands, "libdpdk_version", LOCKED_DPDK_VERSION),
        }
        linkage = linkage_evidence(commands)
        results = parse_results(commands)
        golden = golden_evidence(artifacts / "golden.pcap", source)
        checks = assess(
            commands,
            cache,
            source_errors,
            prerequisite_errors,
            versions,
            linkage,
            results,
            golden,
        )

    for command in commands:
        command["log"] = str(Path(str(command["log"])).relative_to(source)).replace("\\", "/")
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "status": status,
        "generated_at_utc": runner.utc_now(),
        "host": dict(host),
        "source": {
            "path": str(source),
            "files": [{"path": path, "sha256": sha256_file(source / path)} for path in SOURCE_FILES],
            "contract_errors": list(source_errors),
        },
        "prerequisites": {
            "receipts": prerequisite_receipts,
            "supplemental_pcapng": supplemental,
            "contract_errors": list(prerequisite_errors),
        },
        "artifacts": {
            "directory": str(artifacts.relative_to(source)).replace("\\", "/"),
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
            "capture_ctest_excluded": CAPTURE_CTEST,
        },
        "versions": versions,
        "linkage": linkage,
        "contract": EXPECTED_CONTRACT,
        "results": results,
        "golden_capture": golden,
        "commands": commands,
        "checks": checks,
    }


def _valid_host(host: Any) -> bool:
    return isinstance(host, Mapping) and (
        host.get("system") == "Linux"
        and host.get("os_id") == "ubuntu"
        and str(host.get("os_version", "")).startswith("24.04")
        and host.get("architecture") == "x86_64"
        and re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is not None
        and isinstance(host.get("effective_uid"), int)
        and not isinstance(host.get("effective_uid"), bool)
        and host.get("effective_uid", 0) > 0
        and isinstance(host.get("cpu_count"), int)
        and not isinstance(host.get("cpu_count"), bool)
        and host.get("cpu_count", 0) >= 1
    )


def _valid_prerequisites(value: Any) -> bool:
    if not isinstance(value, Mapping) or value.get("contract_errors") != []:
        return False
    receipts = value.get("receipts")
    expected = [
        {"task": task, "path": path, "sha256": digest, "status": "passed"}
        for task, path, digest in PREREQUISITE_RECEIPTS
    ]
    supplemental = value.get("supplemental_pcapng")
    return receipts == expected and supplemental == {
        "path": SUPPLEMENTAL_PCAPNG_PATH,
        "sha256": SUPPLEMENTAL_PCAPNG_SHA256,
        "role": "visual_only_not_parity_input",
    }


def validate_receipt(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["receipt root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    if document.get("task") != TASK:
        errors.append(f"task must equal {TASK}")
    if document.get("kind") != KIND:
        errors.append(f"kind must equal {KIND}")
    if document.get("status") not in ("passed", "failed"):
        errors.append("status must be passed or failed")
    if not _valid_host(document.get("host")):
        errors.append("receipt host must be Ubuntu 24.04 x86_64 with Python 3.12.x as a normal user")
    if document.get("contract") != EXPECTED_CONTRACT:
        errors.append("contract values do not match the approved T2.6 boundaries")
    if not _valid_prerequisites(document.get("prerequisites")):
        errors.append("prerequisite receipts and supplemental PCAPNG must match locked evidence")

    versions = document.get("versions")
    if not isinstance(versions, Mapping) or not (
        versions.get("libpcap") == LOCKED_LIBPCAP_VERSION
        and versions.get("libdpdk") == LOCKED_DPDK_VERSION
    ):
        errors.append("receipt must record the locked libpcap and libdpdk versions")
    linkage = document.get("linkage")
    if not valid_linkage(linkage if isinstance(linkage, Mapping) else None):
        errors.append("receipt must record complete PCAP, DPDK EAL, and ring PMD linkage")
    results = document.get("results")
    if not valid_results(results if isinstance(results, Mapping) else None):
        errors.append("receipt must record complete bitwise parity and no-future counters")

    build = document.get("build")
    if not isinstance(build, Mapping) or not (
        build.get("generator") == "Ninja"
        and build.get("configuration") == "Release"
        and build.get("testing_enabled") is True
        and build.get("dpdk_enabled") is True
        and build.get("toolchain_smoke_enabled") is False
        and build.get("temporary_workspace_outside_source") is True
        and build.get("temporary_workspace_retained") is False
        and build.get("offline_dependency_mode") is True
        and build.get("parallel_jobs") == 2
        and build.get("capture_ctest_excluded") == CAPTURE_CTEST
    ):
        errors.append("build flags do not match the T2.6 acceptance contract")

    artifacts = document.get("artifacts")
    artifact_directory = artifacts.get("directory") if isinstance(artifacts, Mapping) else None
    if not isinstance(artifact_directory, str) or re.fullmatch(
        r"run_log/t2\.6/attempts/ubuntu-acceptance-[A-Za-z0-9._-]+", artifact_directory
    ) is None or artifacts.get("final_receipt") != "run_log/t2.6/acceptance.json":
        errors.append("artifacts must remain under run_log/t2.6 with the locked final receipt")
    golden = document.get("golden_capture")
    if not valid_golden(golden if isinstance(golden, Mapping) else None, artifact_directory):
        errors.append("runtime golden PCAP evidence is invalid or outside the attempt directory")

    commands = document.get("commands")
    recomputed_checks: list[dict[str, str]] | None = None
    valid_commands = (
        isinstance(commands, list)
        and len(commands) == len(COMMAND_NAMES)
        and all(isinstance(command, Mapping) for command in commands)
        and [command.get("name") for command in commands] == list(COMMAND_NAMES)
    )
    if not valid_commands:
        errors.append("commands must contain the complete T2.6 pipeline in order")
    else:
        for command in commands:
            expected_log = f"{artifact_directory}/{LOG_FILES[command['name']]}"
            if command.get("log") != expected_log:
                errors.append("every command log must be inside the recorded attempt directory")
            if re.fullmatch(r"[0-9a-f]{64}", str(command.get("log_sha256", ""))) is None:
                errors.append("every command log must have a lowercase SHA-256")
        if document.get("status") == "passed" and any(
            command.get("return_code") != 0 for command in commands
        ):
            errors.append("a passed receipt requires every command to return zero")
        parsed_versions = {
            "libpcap": dependency_version(commands, "libpcap_version", LOCKED_LIBPCAP_VERSION),
            "libdpdk": dependency_version(commands, "libdpdk_version", LOCKED_DPDK_VERSION),
        }
        parsed_linkage = linkage_evidence(commands)
        parsed_results = parse_results(commands)
        if versions != parsed_versions:
            errors.append("recorded dependency versions must match command output")
        if linkage != parsed_linkage:
            errors.append("recorded linkage must match ldd command output")
        if results != parsed_results:
            errors.append("recorded results must match equal named and direct markers")
        direct = runner.find_command(commands, "core_evidence")
        direct_arguments = direct.get("arguments")
        source_document = document.get("source")
        source_root = str(source_document.get("path", "")).rstrip("/\\").replace("\\", "/") \
            if isinstance(source_document, Mapping) else ""
        expected_output_argument = (
            f"{GOLDEN_OUTPUT_ENV}={source_root}/{artifact_directory}/golden.pcap"
        )
        if not isinstance(direct_arguments, list) or expected_output_argument not in direct_arguments:
            errors.append("core evidence command must generate golden.pcap inside the attempt directory")
        cache = {
            "CMAKE_BUILD_TYPE": "Release" if isinstance(build, Mapping)
            and build.get("configuration") == "Release" else "",
            "BUILD_TESTING": "ON" if isinstance(build, Mapping)
            and build.get("testing_enabled") is True else "OFF",
            "NIDS_BUILD_DPDK": "ON" if isinstance(build, Mapping)
            and build.get("dpdk_enabled") is True else "OFF",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF" if isinstance(build, Mapping)
            and build.get("toolchain_smoke_enabled") is False else "ON",
        }
        recomputed_checks = assess(
            commands,
            cache,
            [],
            [],
            parsed_versions,
            parsed_linkage,
            parsed_results,
            golden if isinstance(golden, Mapping) else None,
        )

    checks = document.get("checks")
    required_checks = {
        "source.contract_consistent",
        "prerequisites.locked_receipts_valid",
        "versions.locked_dependencies",
        "linkage.complete",
        "ctest.scope_excludes_only_capture",
        "ctest.core_present",
        "ctest.prerequisite_coverage_present",
        "ctest.all_selected_passed",
        "ctest.core_named_passed",
        "results.marker_unique_and_equal",
        "results.bitwise_parity_complete",
        "golden.runtime_pcap_valid",
        "build.dpdk_enabled",
    }
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty array")
    else:
        invalid_checks = [
            check
            for check in checks
            if not isinstance(check, Mapping) or check.get("status") not in ("passed", "failed")
        ]
        names = {check.get("name") for check in checks if isinstance(check, Mapping)}
        if invalid_checks:
            errors.append("every check must have passed or failed status")
        if not required_checks.issubset(names):
            errors.append("receipt must check source, prerequisites, build, linkage, parity, and golden PCAP")
        if recomputed_checks is not None and checks != recomputed_checks:
            errors.append("recorded checks must match recomputed command evidence")
        all_passed = not invalid_checks and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or len(files) != len(SOURCE_FILES) or not all(
        isinstance(item, Mapping) for item in files
    ) or [item.get("path") for item in files] != list(SOURCE_FILES):
        errors.append("source files must match the T2.6 inputs")
    elif any(
        re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None for item in files
    ):
        errors.append("every source file must have a lowercase SHA-256")
    if not isinstance(source, Mapping) or source.get("contract_errors") != []:
        errors.append("source contract must have no validation errors")

    timestamp = document.get("generated_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    return errors


def command_check(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    errors = contract_source_errors(source)
    _, _, prerequisite_errors = prerequisite_evidence(source)
    errors.extend(prerequisite_errors)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T2.6 source contract: PCAP and DPDK ring compare 54 feature bit patterns")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_root = (source / "run_log" / "t2.6").resolve()
    if artifact_root != expected_root:
        raise ValueError(f"artifact root must equal {expected_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    if any(not (source / path).is_file() for path in SOURCE_FILES) or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T2.6 project root: {source}")

    host = inspect_host()
    require_supported_host(host)
    require_tools()
    attempt = artifact_root / "attempts" / runner.attempt_name()
    attempt.mkdir(parents=True, exist_ok=False)
    receipt = collect_receipt(source, attempt, host)
    write_new_json(attempt / "receipt.json", receipt)
    print(f"wrote {attempt / 'receipt.json'} ({receipt['status']})")
    if receipt["status"] == "passed":
        write_new_json(final_receipt, receipt)
        print(f"wrote {final_receipt} (passed)")
        return 0
    for check in receipt["checks"]:
        if check["status"] == "failed":
            print(f"failed: {check['name']}", file=sys.stderr)
    return 1


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_receipt(runner.load_json(args.input))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid receipt: {args.input}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="validate T2.6 source and prerequisite contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T2.6 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t2.6")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T2.6 receipt")
    validate.add_argument("--input", required=True, type=Path)
    validate.set_defaults(handler=command_validate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
