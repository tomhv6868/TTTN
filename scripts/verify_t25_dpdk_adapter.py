#!/usr/bin/env python3
"""Build and verify the T2.5 DPDK adapter on the locked Ubuntu host."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_t11_packet_contract as runner


SCHEMA_VERSION = "1.0.0"
TASK = "T2.5"
KIND = "dpdk_adapter_acceptance"
LOCKED_DPDK_VERSION = "25.11.2"
PRESET = "ubuntu-release-dpdk"
DPDK_TARGET = "nids_dpdk"
DPDK_ALIAS = "nids::dpdk"
PROBE_EXECUTABLE = "nids_dpdk_adapter_probe"
PARITY_CTEST = "nids_dpdk.adapter_parity"
CAPTURE_CTEST = "nids_dpdk.capture_verification"
CAPTURE_LIMIT = 4
CAPTURE_OUTPUT_ENV = "NIDS_T25_CAPTURE_OUTPUT"
CAPTURE_HUGE_DIR_ENV = "NIDS_T25_HUGE_DIR"
CAPTURE_VALIDATOR_MARKER = (
    f"T2.5 pcapng reopen: records={CAPTURE_LIMIT} parsed={CAPTURE_LIMIT} parser_errors=0"
)
COMMAND_NAMES = (
    "libdpdk_version",
    "dumpcap_version",
    "dumpcap_linkage",
    "configure",
    "build",
    "ctest",
    "ctest_adapter_parity",
    "ctest_capture_verification",
    "python_unittest",
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
    "CMakePresets.json",
    *CORE_FILES,
    "cpp/include/nids/pcap_adapter.hpp",
    "cpp/src/pcap_adapter.cpp",
    "cpp/include/nids/dpdk_adapter.hpp",
    "cpp/src/dpdk_adapter.cpp",
    "cpp/tests/dpdk_adapter_test.cpp",
    "cpp/apps/dpdk_adapter_probe.cpp",
    "scripts/run_t25_acceptance_ubuntu.sh",
    "scripts/verify_t25_dpdk_adapter.py",
)
PARITY_FIELDS = (
    "pcap",
    "ring",
    "contiguous",
    "multisegment",
    "bytes_equal",
    "timestamp_equal",
    "parse_equal",
)
CAPTURE_FIELDS = (
    "pcapng",
    "bounded",
    "default_off",
    "benchmark_forbidden",
)
EXPECTED_CONTRACT = {
    "library": DPDK_TARGET,
    "alias": DPDK_ALIAS,
    "dependency": f"libdpdk {LOCKED_DPDK_VERSION}",
    "parser": "nids_core.parse_packet",
    "packet_sources": ["contiguous_mbuf", "multisegment_mbuf"],
    "pcap_parity": "bytes_timestamp_parse_result",
    "verification_capture": {
        "format": "pcapng",
        "bounded": True,
        "default_enabled": False,
        "benchmark_allowed": False,
        "primary_lcore": 0,
        "secondary_lcore": 1,
        "device_selection": "--no-pci",
        "temporary_hugepages_2mb": 64,
    },
    "core_dpdk_dependency": False,
    "clean_release_build": True,
    "offline_dependency_mode": True,
}
LOG_FILES = {
    "libdpdk_version": "libdpdk-version.log",
    "dumpcap_version": "dpdk-dumpcap-version.log",
    "dumpcap_linkage": "dpdk-dumpcap-linkage.log",
    "configure": "configure.log",
    "build": "build.log",
    "ctest": "ctest.log",
    "ctest_adapter_parity": "ctest-adapter-parity.log",
    "ctest_capture_verification": "ctest-capture-verification.log",
    "python_unittest": "python-unittest.log",
}
LIBDPDK_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+._A-Za-z0-9]*)?")
PARITY_MARKER = re.compile(
    r"T2\.5 parity:\s*"
    r"pcap=(?P<pcap>\d+)\s+"
    r"ring=(?P<ring>\d+)\s+"
    r"contiguous=(?P<contiguous>\d+)\s+"
    r"multisegment=(?P<multisegment>\d+)\s+"
    r"bytes_equal=(?P<bytes_equal>\d+)\s+"
    r"timestamp_equal=(?P<timestamp_equal>\d+)\s+"
    r"parse_equal=(?P<parse_equal>\d+)\s+"
    r"packets_compared=(?P<packets_compared>\d+)\s+"
    r"packets_parsed=(?P<packets_parsed>\d+)\s+"
    r"parser_errors=(?P<parser_errors>\d+)"
)
CAPTURE_MARKER = re.compile(
    r"T2\.5 capture:\s*"
    r"pcapng=(?P<pcapng>\d+)\s+"
    r"copied=(?P<copied>\d+)\s+"
    r"dropped=(?P<dropped>\d+)\s+"
    r"bounded=(?P<bounded>\d+)\s+"
    r"default_off=(?P<default_off>\d+)\s+"
    r"benchmark_forbidden=(?P<benchmark_forbidden>\d+)"
)
DUMPCAP_CAPTURED = re.compile(r"Packets\s+captured:\s*(?P<copied>\d+)", re.IGNORECASE)
DUMPCAP_RECEIVED = re.compile(
    r"Packets\s+received/dropped\s+on\s+interface\s+['\"][^'\"]+['\"]:\s*"
    r"(?P<received>\d+)\s*/\s*(?P<dropped>\d+)",
    re.IGNORECASE,
)
PCAPNG_SECTION_HEADER = bytes.fromhex("0a0d0d0a")

sha256_file = runner.sha256_file
write_new_json = runner.write_new_json


def inspect_host() -> dict[str, Any]:
    os_release = runner.read_os_release()
    hugepage_size_match = re.search(
        r"^Hugepagesize:\s*(\d+)\s+kB$",
        Path("/proc/meminfo").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    total_path = Path("/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages")
    free_path = Path("/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages")
    configured_huge_dir = os.environ.get(CAPTURE_HUGE_DIR_ENV)
    return {
        "system": platform.system(),
        "os_id": os_release.get("ID"),
        "os_version": os_release.get("VERSION_ID"),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "cpu_count": os.cpu_count(),
        "hugepage_size_kb": int(hugepage_size_match.group(1)) if hugepage_size_match else None,
        "hugepage_total": int(total_path.read_text(encoding="utf-8").strip()),
        "hugepage_free": int(free_path.read_text(encoding="utf-8").strip()),
        "capture_huge_dir": (
            str(Path(configured_huge_dir).expanduser().resolve()) if configured_huge_dir else None
        ),
    }


def require_supported_host(host: Mapping[str, Any]) -> None:
    effective_uid = host.get("effective_uid")
    if not isinstance(effective_uid, int) or isinstance(effective_uid, bool) or effective_uid <= 0:
        raise RuntimeError("T2.5 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T2.5 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T2.5 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T2.5 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T2.5 verification requires Python 3.12.x")
    cpu_count = host.get("cpu_count")
    if not isinstance(cpu_count, int) or isinstance(cpu_count, bool) or cpu_count < 2:
        raise RuntimeError("T2.5 verification requires at least two logical CPUs")
    if not (
        host.get("hugepage_size_kb") == 2048
        and host.get("hugepage_total") == 64
        and host.get("hugepage_free") == 64
        and re.fullmatch(
            r"/dev/hugepages/nids-t25-[0-9]+-[0-9]+",
            str(host.get("capture_huge_dir", "")),
        )
    ):
        raise RuntimeError("T2.5 verification requires the bounded private 64-page hugepage wrapper")


def resolve_dpdk_dumpcap(environment: Mapping[str, str] | None = None) -> Path:
    path = shutil.which("dpdk-dumpcap")
    if path:
        executable = Path(path).resolve()
        if executable.is_file():
            return executable
    values = os.environ if environment is None else environment
    dpdk_root = values.get("DPDK_ROOT")
    if dpdk_root:
        executable = (Path(dpdk_root).expanduser() / "bin" / "dpdk-dumpcap").resolve()
        if executable.is_file():
            return executable
    raise RuntimeError("missing required tool: dpdk-dumpcap (PATH or DPDK_ROOT/bin)")


def resolve_capture_huge_dir(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    configured = values.get(CAPTURE_HUGE_DIR_ENV)
    if not configured:
        raise RuntimeError(f"{CAPTURE_HUGE_DIR_ENV} must name the private hugetlbfs directory")
    huge_dir = Path(configured).expanduser().resolve()
    if not huge_dir.is_dir():
        raise RuntimeError(f"capture hugepage directory does not exist: {huge_dir}")
    return huge_dir


def require_tools() -> None:
    required = ("cmake", "ninja", "c++", "ctest", "pkg-config", "ldd")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")
    resolve_dpdk_dumpcap()


def run_pipeline(source: Path, build: Path, artifact_directory: Path) -> list[dict[str, Any]]:
    dumpcap = resolve_dpdk_dumpcap()
    commands = [
        runner.run_command(
            "libdpdk_version",
            ("pkg-config", "--modversion", "libdpdk"),
            source,
            artifact_directory / LOG_FILES["libdpdk_version"],
            30.0,
        ),
        runner.run_command(
            "dumpcap_version",
            (str(dumpcap), "--version"),
            source,
            artifact_directory / LOG_FILES["dumpcap_version"],
            30.0,
        ),
        runner.run_command(
            "dumpcap_linkage",
            ("ldd", str(dumpcap)),
            source,
            artifact_directory / LOG_FILES["dumpcap_linkage"],
            30.0,
        ),
    ]
    prerequisites_ok = all(command["return_code"] == 0 for command in commands)
    if prerequisites_ok:
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
            artifact_directory / LOG_FILES["configure"],
            300.0,
        )
    else:
        configure = runner.skipped_command(
            "configure",
            "DPDK version or dpdk-dumpcap evidence failed",
            artifact_directory / LOG_FILES["configure"],
        )
    commands.append(configure)

    if configure["return_code"] == 0:
        build_result = runner.run_command(
            "build",
            ("cmake", "--build", str(build), "--parallel", "2"),
            source,
            artifact_directory / LOG_FILES["build"],
            900.0,
        )
    else:
        build_result = runner.skipped_command(
            "build", "configure failed or was skipped", artifact_directory / LOG_FILES["build"]
        )
    commands.append(build_result)

    if build_result["return_code"] == 0:
        ctest = runner.run_command(
            "ctest",
            (
                "ctest",
                "--test-dir",
                str(build),
                "--build-config",
                "Release",
                "--output-on-failure",
                "--verbose",
            ),
            source,
            artifact_directory / LOG_FILES["ctest"],
            900.0,
        )
        parity = runner.run_command(
            "ctest_adapter_parity",
            (
                "ctest",
                "--test-dir",
                str(build),
                "--build-config",
                "Release",
                "--output-on-failure",
                "--verbose",
                "-R",
                f"^{re.escape(PARITY_CTEST)}$",
            ),
            source,
            artifact_directory / LOG_FILES["ctest_adapter_parity"],
            180.0,
        )
        sample = artifact_directory / "sample.pcapng"
        capture = runner.run_command(
            "ctest_capture_verification",
            (
                "cmake",
                "-E",
                "env",
                f"{CAPTURE_OUTPUT_ENV}={sample}",
                "ctest",
                "--test-dir",
                str(build),
                "--build-config",
                "Release",
                "--output-on-failure",
                "--verbose",
                "-R",
                f"^{re.escape(CAPTURE_CTEST)}$",
            ),
            source,
            artifact_directory / LOG_FILES["ctest_capture_verification"],
            180.0,
        )
    else:
        ctest = runner.skipped_command(
            "ctest", "build failed or was skipped", artifact_directory / LOG_FILES["ctest"]
        )
        parity = runner.skipped_command(
            "ctest_adapter_parity",
            "build failed or was skipped",
            artifact_directory / LOG_FILES["ctest_adapter_parity"],
        )
        capture = runner.skipped_command(
            "ctest_capture_verification",
            "build failed or was skipped",
            artifact_directory / LOG_FILES["ctest_capture_verification"],
        )
    commands.extend((ctest, parity, capture))
    commands.append(
        runner.run_command(
            "python_unittest",
            (sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"),
            source,
            artifact_directory / LOG_FILES["python_unittest"],
            900.0,
        )
    )
    return commands


def libdpdk_version(commands: Sequence[Mapping[str, Any]]) -> str | None:
    command = runner.find_command(commands, "libdpdk_version")
    stdout = str(command.get("stdout", "")).strip()
    stderr = str(command.get("stderr", "")).strip()
    if stderr or LIBDPDK_VERSION.fullmatch(stdout) is None or stdout != LOCKED_DPDK_VERSION:
        return None
    return stdout


def dumpcap_evidence(commands: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    version = runner.find_command(commands, "dumpcap_version")
    linkage = runner.find_command(commands, "dumpcap_linkage")
    version_output = "\n".join(
        part for part in (str(version.get("stdout", "")).strip(), str(version.get("stderr", "")).strip()) if part
    )
    linkage_output = "\n".join(
        part for part in (str(linkage.get("stdout", "")).strip(), str(linkage.get("stderr", "")).strip()) if part
    )
    version_arguments = version.get("arguments")
    linkage_arguments = linkage.get("arguments")
    if not (
        version.get("return_code") == 0
        and linkage.get("return_code") == 0
        and isinstance(version_arguments, list)
        and len(version_arguments) == 2
        and isinstance(linkage_arguments, list)
        and len(linkage_arguments) == 2
        and version_arguments[0] == linkage_arguments[1]
        and LOCKED_DPDK_VERSION in version_output
    ):
        return None
    missing = [line.strip() for line in linkage_output.splitlines() if "not found" in line.lower()]
    dpdk_libraries = [line.strip() for line in linkage_output.splitlines() if "librte_" in line.lower()]
    return {
        "path": version_arguments[0],
        "version": LOCKED_DPDK_VERSION,
        "version_output": version_output,
        "linkage_output": linkage_output,
        "linkage_return_code": linkage.get("return_code"),
        "missing_dependencies": missing,
        "dpdk_libraries": dpdk_libraries,
    }


def valid_dumpcap_evidence(evidence: Mapping[str, Any] | None) -> bool:
    if evidence is None:
        return False
    path = evidence.get("path")
    return (
        isinstance(path, str)
        and Path(path).name == "dpdk-dumpcap"
        and evidence.get("version") == LOCKED_DPDK_VERSION
        and LOCKED_DPDK_VERSION in str(evidence.get("version_output", ""))
        and evidence.get("linkage_return_code") == 0
        and evidence.get("missing_dependencies") == []
        and isinstance(evidence.get("dpdk_libraries"), list)
        and bool(evidence.get("dpdk_libraries"))
        and "librte_" in str(evidence.get("linkage_output", "")).lower()
    )


def _single_marker(command: Mapping[str, Any], marker: re.Pattern[str]) -> re.Match[str] | None:
    output = "\n".join((str(command.get("stdout", "")), str(command.get("stderr", ""))))
    matches = list(marker.finditer(output))
    return matches[0] if len(matches) == 1 else None


def parse_results(commands: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    parity_match = _single_marker(runner.find_command(commands, "ctest_adapter_parity"), PARITY_MARKER)
    capture_match = _single_marker(
        runner.find_command(commands, "ctest_capture_verification"), CAPTURE_MARKER
    )
    if parity_match is None or capture_match is None:
        return None
    parity_values = {
        name: int(parity_match.group(name))
        for name in (*PARITY_FIELDS, "packets_compared", "packets_parsed", "parser_errors")
    }
    capture_values = {
        name: int(capture_match.group(name))
        for name in (*CAPTURE_FIELDS, "copied", "dropped")
    }
    return {
        "parity": {
            "coverage": {name: parity_values[name] == 1 for name in PARITY_FIELDS},
            "packets_compared": parity_values["packets_compared"],
            "packets_parsed": parity_values["packets_parsed"],
            "parser_errors": parity_values["parser_errors"],
        },
        "capture": {
            "coverage": {name: capture_values[name] == 1 for name in CAPTURE_FIELDS},
            "packets_copied": capture_values["copied"],
            "packets_dropped": capture_values["dropped"],
        },
    }


def valid_results(results: Mapping[str, Any] | None) -> bool:
    if results is None:
        return False
    parity = results.get("parity")
    capture = results.get("capture")
    if not isinstance(parity, Mapping) or not isinstance(capture, Mapping):
        return False
    parity_coverage = parity.get("coverage")
    capture_coverage = capture.get("coverage")
    compared = parity.get("packets_compared")
    parsed = parity.get("packets_parsed")
    parser_errors = parity.get("parser_errors")
    copied = capture.get("packets_copied")
    dropped = capture.get("packets_dropped")
    return (
        isinstance(parity_coverage, Mapping)
        and set(parity_coverage) == set(PARITY_FIELDS)
        and all(parity_coverage.get(name) is True for name in PARITY_FIELDS)
        and isinstance(capture_coverage, Mapping)
        and set(capture_coverage) == set(CAPTURE_FIELDS)
        and all(capture_coverage.get(name) is True for name in CAPTURE_FIELDS)
        and isinstance(compared, int)
        and not isinstance(compared, bool)
        and isinstance(parsed, int)
        and not isinstance(parsed, bool)
        and compared >= 2
        and compared == parsed
        and parser_errors == 0
        and isinstance(copied, int)
        and not isinstance(copied, bool)
        and copied > 0
        and dropped == 0
    )


def _has_dpdk_include(text: str) -> bool:
    return re.search(r"#\s*include\s*[<\"](?:dpdk/)?rte_[^>\"]+[>\"]", text) is not None


def _preset_errors(source: Path) -> list[str]:
    try:
        document = json.loads((source / "CMakePresets.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"CMakePresets.json is invalid: {error}"]
    configure = {
        item.get("name"): item
        for item in document.get("configurePresets", [])
        if isinstance(item, Mapping)
    }.get(PRESET)
    build = {
        item.get("name"): item for item in document.get("buildPresets", []) if isinstance(item, Mapping)
    }.get(PRESET)
    test = {
        item.get("name"): item for item in document.get("testPresets", []) if isinstance(item, Mapping)
    }.get(PRESET)
    errors: list[str] = []
    cache = configure.get("cacheVariables") if isinstance(configure, Mapping) else None
    if not (
        isinstance(configure, Mapping)
        and configure.get("inherits") == "ubuntu-release"
        and isinstance(configure.get("binaryDir"), str)
        and PRESET in configure.get("binaryDir", "")
        and isinstance(cache, Mapping)
        and cache.get("NIDS_BUILD_DPDK") is True
        and cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") is False
    ):
        errors.append(f"configure preset {PRESET} must be Ubuntu Release with DPDK on and smoke off")
    if not (
        isinstance(build, Mapping)
        and build.get("configurePreset") == PRESET
        and build.get("jobs") == 2
    ):
        errors.append(f"build preset {PRESET} must use two jobs")
    if not (
        isinstance(test, Mapping)
        and test.get("configurePreset") == PRESET
        and isinstance(test.get("output"), Mapping)
        and test["output"].get("outputOnFailure") is True
    ):
        errors.append(f"test preset {PRESET} must enable output on failure")
    return errors


def _benchmark_capture_errors(source: Path, cmake: str) -> list[str]:
    forbidden = ("enable-verification-capture", "rte_pdump_init", "verify_t25_dpdk_adapter.py")
    errors: list[str] = []
    for line in cmake.splitlines():
        lowered = line.lower()
        if "benchmark" in lowered and any(token in line for token in forbidden):
            errors.append("benchmark CMake paths must not enable or invoke verification capture")
            break
    roots = [source / "benchmark", source / "benchmarks", source / "cpp"]
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or not any(
                part.lower() in ("benchmark", "benchmarks") for part in path.parts
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            found = [token for token in forbidden if token in text]
            if found:
                relative = path.relative_to(source)
                errors.append(f"benchmark path {relative} contains capture tokens: {', '.join(found)}")
    return errors


def contract_source_errors(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        return [f"missing source file: {path}" for path in missing]

    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    header = (source / "cpp/include/nids/dpdk_adapter.hpp").read_text(encoding="utf-8")
    implementation = (source / "cpp/src/dpdk_adapter.cpp").read_text(encoding="utf-8")
    tests = (source / "cpp/tests/dpdk_adapter_test.cpp").read_text(encoding="utf-8")
    probe = (source / "cpp/apps/dpdk_adapter_probe.cpp").read_text(encoding="utf-8")
    wrapper = (source / "scripts/run_t25_acceptance_ubuntu.sh").read_text(encoding="utf-8")
    errors = _preset_errors(source)

    cmake_tokens = (
        "NIDS_BUILD_DPDK",
        DPDK_TARGET,
        DPDK_ALIAS,
        PROBE_EXECUTABLE,
        "cpp/src/dpdk_adapter.cpp",
        "cpp/tests/dpdk_adapter_test.cpp",
        "cpp/apps/dpdk_adapter_probe.cpp",
        PARITY_CTEST,
        CAPTURE_CTEST,
        "PkgConfig",
        "libdpdk",
        "rte_bus_vdev",
        "nids::core",
        "nids::dataset",
        "verify_t25_dpdk_adapter.py",
        "capture-test",
        "--validator",
    )
    missing_cmake = [token for token in cmake_tokens if token not in cmake]
    if missing_cmake:
        errors.append(f"CMake is missing DPDK adapter tokens: {', '.join(missing_cmake)}")
    if re.search(
        r"target_link_libraries\s*\(\s*nids_dpdk_adapter_test\b.*?\$\{DPDK_BUS_VDEV_LIBRARY\}",
        cmake,
        re.DOTALL,
    ) is None:
        errors.append("nids_dpdk_adapter_test must link DPDK_BUS_VDEV_LIBRARY explicitly")
    if re.search(r"option\s*\(\s*NIDS_BUILD_DPDK\b[^\)]*\bOFF\s*\)", cmake, re.DOTALL) is None:
        errors.append("NIDS_BUILD_DPDK must default to OFF")

    contaminated = []
    for path in CORE_FILES:
        text = (source / path).read_text(encoding="utf-8")
        if _has_dpdk_include(text):
            contaminated.append(path)
    if contaminated:
        errors.append(f"core packet/flow/feature files must not include DPDK: {', '.join(contaminated)}")

    adapter_api = "\n".join((header, implementation))
    adapter_tokens = ("adapt_mbuf", "rte_mbuf", "rte_pktmbuf_read", "parse_packet")
    missing_adapter = [token for token in adapter_tokens if token not in adapter_api]
    if missing_adapter:
        errors.append(f"DPDK adapter is missing shared-parser tokens: {', '.join(missing_adapter)}")
    if re.search(r"ParseResult\s*<\s*PacketView\s*>\s+parse_packet\s*\(", adapter_api):
        errors.append("DPDK adapter must call the shared parser, not define parse_packet")
    if any(token in header for token in ("rte_pdump", "verification_capture", "enable-verification")):
        errors.append("public DPDK adapter API must not expose verification capture")
    if "rte_pdump" in implementation:
        errors.append("DPDK adapter implementation must not own verification capture")

    probe_tokens = (
        "--enable-verification-capture",
        "--file-prefix",
        "--huge-dir",
        "--ready-file",
        "--arm-file",
        "--result-file",
        "--max-packets",
        "verification_capture_enabled{false}",
        "rte_pdump_init",
        'ring_port_name[] = "t25_capture"',
        "RTE_RING_NAMESIZE",
        "rte_eth_dev_info_get",
        "nb_rx_queues",
        "nb_tx_queues",
        "T2.5 probe failure: stage=",
    )
    missing_probe = [token for token in probe_tokens if token not in probe.replace(" ", "") if token == "verification_capture_enabled{false}"]
    missing_probe.extend(
        token for token in probe_tokens if token != "verification_capture_enabled{false}" and token not in probe
    )
    if missing_probe:
        errors.append(f"DPDK probe is missing bounded capture tokens: {', '.join(missing_probe)}")
    if '"net_ring_t25_capture"' in probe:
        errors.append(
            "DPDK probe must pass t25_capture to rte_eth_from_rings; "
            "the PMD adds net_ring_ within RTE_RING_NAMESIZE"
        )
    if not (
        re.search(r'"-l"\s*,\s*"0"', probe) is not None
        and '"--proc-type=primary"' in probe
        and '"--no-pci"' in probe
    ):
        errors.append("DPDK probe primary must use lcore 0 with --no-pci")
    for relative, ring_source in (
        ("cpp/tests/dpdk_adapter_test.cpp", tests),
        ("cpp/apps/dpdk_adapter_probe.cpp", probe),
    ):
        if "rte_eth_from_rings" not in ring_source or re.search(
            r"rte_eth_from_rings\s*\([^;]*?nullptr\s*,\s*0U",
            ring_source,
            re.DOTALL,
        ):
            errors.append(f"{relative} must provide symmetric RX/TX rings to rte_eth_from_rings")
    if (
        re.search(
            r"rte_eth_dev_configure\s*\([^;]*?,\s*1U\s*,\s*1U\s*,",
            probe,
            re.DOTALL,
        )
        is None
        or "rte_eth_tx_queue_setup" not in probe
        or 'report_dpdk_failure("eth_tx_queue_setup"' not in probe
    ):
        errors.append(
            "DPDK probe must configure and set up nonzero RX/TX queues for dumpcap RXTX capture"
        )

    wrapper_tokens = (
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
    missing_wrapper = [token for token in wrapper_tokens if token not in wrapper]
    if missing_wrapper:
        errors.append(
            f"Ubuntu acceptance wrapper is missing safety tokens: {', '.join(missing_wrapper)}"
        )

    test_tokens = (
        *PARITY_FIELDS,
        "packets_compared",
        "packets_parsed",
        "parser_errors",
        "T2.5 parity:",
        "--validate-pcapng",
        "--expected-packets",
        "T2.5 pcapng reopen:",
    )
    missing_tests = [token for token in test_tokens if token not in tests]
    if missing_tests:
        errors.append(f"DPDK adapter tests are missing parity tokens: {', '.join(missing_tests)}")
    errors.extend(_benchmark_capture_errors(source, cmake))
    return errors


def capture_sample_hash(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size <= len(PCAPNG_SECTION_HEADER):
            return None
        with path.open("rb") as handle:
            if handle.read(len(PCAPNG_SECTION_HEADER)) != PCAPNG_SECTION_HEADER:
                return None
        return sha256_file(path)
    except OSError:
        return None


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
    version: str | None,
    dumpcap: Mapping[str, Any] | None,
    results: Mapping[str, Any] | None,
    sample_hash: str | None,
) -> list[dict[str, str]]:
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed" if runner.find_command(commands, name).get("return_code") == 0 else "failed",
        }
        for name in COMMAND_NAMES
    ]
    ctest = runner.find_command(commands, "ctest")
    ctest_output = "\n".join((str(ctest.get("stdout", "")), str(ctest.get("stderr", ""))))
    parity = runner.find_command(commands, "ctest_adapter_parity")
    parity_output = "\n".join((str(parity.get("stdout", "")), str(parity.get("stderr", ""))))
    capture = runner.find_command(commands, "ctest_capture_verification")
    capture_output = "\n".join((str(capture.get("stdout", "")), str(capture.get("stderr", ""))))
    checks.extend(
        (
            {"name": "source.contract_consistent", "status": "passed" if not source_errors else "failed"},
            {"name": "versions.libdpdk_locked", "status": "passed" if version == LOCKED_DPDK_VERSION else "failed"},
            {"name": "dumpcap.version_and_linkage", "status": "passed" if valid_dumpcap_evidence(dumpcap) else "failed"},
            {"name": "ctest.adapter_parity_present", "status": "passed" if PARITY_CTEST in ctest_output else "failed"},
            {"name": "ctest.capture_verification_present", "status": "passed" if CAPTURE_CTEST in ctest_output else "failed"},
            {"name": "ctest.all_passed", "status": "passed" if "100% tests passed" in ctest_output else "failed"},
            {"name": "ctest.adapter_parity_passed", "status": "passed" if "100% tests passed" in parity_output else "failed"},
            {"name": "ctest.capture_verification_passed", "status": "passed" if "100% tests passed" in capture_output else "failed"},
            {"name": "coverage.markers_present", "status": "passed" if results is not None else "failed"},
            {"name": "coverage.parity_capture_consistent", "status": "passed" if valid_results(results) else "failed"},
            {"name": "capture.sample_pcapng_hashed", "status": "passed" if sample_hash is not None else "failed"},
            {"name": "build.release", "status": "passed" if cache.get("CMAKE_BUILD_TYPE") == "Release" else "failed"},
            {"name": "build.testing_enabled", "status": "passed" if cache.get("BUILD_TESTING") == "ON" else "failed"},
            {"name": "build.dpdk_enabled", "status": "passed" if cache.get("NIDS_BUILD_DPDK") == "ON" else "failed"},
            {"name": "build.toolchain_smoke_disabled", "status": "passed" if cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") == "OFF" else "failed"},
        )
    )
    return checks


def collect_receipt(source: Path, artifact_directory: Path, host: Mapping[str, Any]) -> dict[str, Any]:
    source_errors = contract_source_errors(source)
    with tempfile.TemporaryDirectory(prefix="nids-t2.5-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        version = libdpdk_version(commands)
        dumpcap = dumpcap_evidence(commands)
        results = parse_results(commands)
        sample_hash = capture_sample_hash(artifact_directory / "sample.pcapng")
        checks = assess(commands, cache, source_errors, version, dumpcap, results, sample_hash)

    for command in commands:
        command["log"] = str(Path(str(command["log"])).relative_to(source)).replace("\\", "/")
    relative_artifacts = str(artifact_directory.relative_to(source)).replace("\\", "/")
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
        "artifacts": {
            "directory": relative_artifacts,
            "final_receipt": "run_log/t2.5/acceptance.json",
            "capture": f"{relative_artifacts}/sample.pcapng",
            "capture_sha256": sample_hash,
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
        "contract": EXPECTED_CONTRACT,
        "results": results,
        "commands": commands,
        "checks": checks,
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

    host = document.get("host")
    if not isinstance(host, Mapping) or not (
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
        and host.get("cpu_count", 0) >= 2
        and host.get("hugepage_size_kb") == 2048
        and host.get("hugepage_total") == 64
        and host.get("hugepage_free") == 64
        and re.fullmatch(
            r"/dev/hugepages/nids-t25-[0-9]+-[0-9]+",
            str(host.get("capture_huge_dir", "")),
        )
    ):
        errors.append(
            "receipt host must be Ubuntu 24.04 x86_64 with Python 3.12.x, "
            "at least two logical CPUs, a normal user, and the bounded private hugepage wrapper"
        )
    if document.get("contract") != EXPECTED_CONTRACT:
        errors.append("contract values do not match the approved T2.5 DPDK adapter boundaries")

    versions = document.get("versions")
    if not isinstance(versions, Mapping) or not (
        versions.get("libdpdk") == LOCKED_DPDK_VERSION
        and versions.get("libdpdk_command") == "pkg-config --modversion libdpdk"
    ):
        errors.append(f"receipt must record locked libdpdk {LOCKED_DPDK_VERSION}")
    dumpcap = versions.get("dpdk_dumpcap") if isinstance(versions, Mapping) else None
    if not valid_dumpcap_evidence(dumpcap if isinstance(dumpcap, Mapping) else None):
        errors.append("receipt must record valid dpdk-dumpcap version and linkage evidence")
    results = document.get("results")
    if not valid_results(results if isinstance(results, Mapping) else None):
        errors.append("receipt must record complete and consistent DPDK parity/capture results")

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
    ):
        errors.append("build flags do not match the T2.5 acceptance contract")

    artifacts = document.get("artifacts")
    artifact_directory = artifacts.get("directory") if isinstance(artifacts, Mapping) else None
    if not isinstance(artifact_directory, str) or re.fullmatch(
        r"run_log/t2\.5/attempts/ubuntu-acceptance-[A-Za-z0-9._-]+", artifact_directory
    ) is None or artifacts.get("final_receipt") != "run_log/t2.5/acceptance.json":
        errors.append("artifacts must remain under run_log/t2.5 with the locked final receipt")
    if not isinstance(artifacts, Mapping) or not (
        artifacts.get("capture") == f"{artifact_directory}/sample.pcapng"
        and re.fullmatch(r"[0-9a-f]{64}", str(artifacts.get("capture_sha256", ""))) is not None
    ):
        errors.append("artifacts must hash the retained bounded PCAPNG sample")

    commands = document.get("commands")
    valid_commands = (
        isinstance(commands, list)
        and len(commands) == len(COMMAND_NAMES)
        and all(isinstance(command, Mapping) for command in commands)
        and [command.get("name") for command in commands] == list(COMMAND_NAMES)
    )
    if not valid_commands:
        errors.append("commands must contain the complete T2.5 pipeline in order")
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

    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty array")
    else:
        invalid = [
            check
            for check in checks
            if not isinstance(check, Mapping) or check.get("status") not in ("passed", "failed")
        ]
        names = {check.get("name") for check in checks if isinstance(check, Mapping)}
        required_checks = {
            "source.contract_consistent",
            "versions.libdpdk_locked",
            "dumpcap.version_and_linkage",
            "ctest.adapter_parity_present",
            "ctest.capture_verification_present",
            "ctest.all_passed",
            "ctest.adapter_parity_passed",
            "ctest.capture_verification_passed",
            "coverage.markers_present",
            "coverage.parity_capture_consistent",
            "capture.sample_pcapng_hashed",
        }
        if invalid:
            errors.append("every check must have passed or failed status")
        if not required_checks.issubset(names):
            errors.append("receipt must check DPDK/dumpcap, full/named CTest, markers, capture, and source")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or len(files) != len(SOURCE_FILES) or not all(
        isinstance(item, Mapping) for item in files
    ) or [item.get("path") for item in files] != list(SOURCE_FILES):
        errors.append("source files must match the T2.5 DPDK adapter inputs")
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


def _load_capture_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid {label} JSON: {error}") from error
    if not isinstance(document, Mapping):
        raise RuntimeError(f"{label} JSON must be an object")
    return document


def _write_capture_trace_text(trace_dir: Path | None, name: str, content: str) -> None:
    if trace_dir is not None:
        (trace_dir / name).write_text(content, encoding="utf-8")


def _write_capture_trace_json(
    trace_dir: Path | None, name: str, document: Mapping[str, Any]
) -> None:
    _write_capture_trace_text(
        trace_dir,
        name,
        json.dumps(document, indent=2, sort_keys=True) + "\n",
    )


def _wait_for_ready(
    path: Path,
    process: subprocess.Popen[str],
    timeout: float,
    sleeper: Callable[[float], None],
) -> Mapping[str, Any]:
    deadline = time.monotonic() + timeout
    while not path.is_file():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                f"DPDK probe exited before ready: rc={process.returncode} stdout={stdout!r} stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError("timed out waiting for DPDK probe ready JSON")
        sleeper(0.05)
    return _load_capture_json(path, "ready")


def _terminate(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.communicate(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=2.0)


def _render_terminal_output(output: str) -> str:
    lines: list[list[str]] = [[]]
    cursor = 0
    for character in output:
        if character == "\b":
            cursor = max(0, cursor - 1)
        elif character == "\r":
            cursor = 0
        elif character == "\n":
            lines.append([])
            cursor = 0
        else:
            line = lines[-1]
            if cursor < len(line):
                line[cursor] = character
            else:
                line.extend(" " for _ in range(cursor - len(line)))
                line.append(character)
            cursor += 1
    return "\n".join("".join(line) for line in lines)


def _parse_dumpcap_stats(output: str, trace_dir: Path | None = None) -> tuple[int, int]:
    rendered_output = _render_terminal_output(output)
    _write_capture_trace_text(trace_dir, "dumpcap-rendered.log", rendered_output)
    copied_matches = list(DUMPCAP_CAPTURED.finditer(rendered_output))
    received_matches = list(DUMPCAP_RECEIVED.finditer(rendered_output))
    if len(copied_matches) != 1 or len(received_matches) != 1:
        raise RuntimeError("dpdk-dumpcap did not emit one bounded captured/received summary")
    copied = int(copied_matches[0].group("copied"))
    received = int(received_matches[0].group("received"))
    dropped = int(received_matches[0].group("dropped"))
    _write_capture_trace_json(
        trace_dir,
        "dumpcap-counters.json",
        {"captured": copied, "received": received, "dropped": dropped},
    )
    if copied != received:
        raise RuntimeError(
            "dpdk-dumpcap captured and received counters differ: "
            f"captured={copied} received={received} dropped={dropped}"
        )
    return copied, dropped


def run_capture_session(
    source: Path,
    probe: Path,
    dumpcap: Path,
    validator: Path,
    output: Path,
    workspace: Path,
    huge_dir: Path,
    process_factory: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
    sleeper: Callable[[float], None] = time.sleep,
    trace_dir: Path | None = None,
) -> tuple[int, int]:
    if output.exists():
        raise ValueError(f"refusing to overwrite capture output: {output}")
    if not output.parent.is_dir():
        raise ValueError(f"capture output parent does not exist: {output.parent}")
    if trace_dir is not None and not trace_dir.is_dir():
        raise ValueError(f"capture trace directory does not exist: {trace_dir}")
    prefix = f"nids25_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    ready = workspace / "ready.json"
    arm = workspace / "arm.json"
    result = workspace / "result.json"
    environment = {**os.environ, "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    probe_arguments = (
        str(probe),
        "--enable-verification-capture",
        "--file-prefix",
        prefix,
        "--huge-dir",
        str(huge_dir),
        "--ready-file",
        str(ready),
        "--arm-file",
        str(arm),
        "--result-file",
        str(result),
        "--max-packets",
        str(CAPTURE_LIMIT),
    )
    probe_process: subprocess.Popen[str] | None = None
    dumpcap_process: subprocess.Popen[str] | None = None
    validator_process: subprocess.Popen[str] | None = None
    trace_state: dict[str, Any] = {"status": "running", "stage": "probe_start"}

    def update_trace(stage: str, status: str = "running", **facts: Any) -> None:
        trace_state.update(facts)
        trace_state["stage"] = stage
        trace_state["status"] = status
        _write_capture_trace_json(trace_dir, "session.json", trace_state)

    _write_capture_trace_json(trace_dir, "probe-command.json", {"arguments": list(probe_arguments)})
    update_trace("probe_start")
    try:
        probe_process = process_factory(
            list(probe_arguments),
            cwd=source,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready_document = _wait_for_ready(ready, probe_process, 10.0, sleeper)
        _write_capture_trace_json(trace_dir, "probe-ready.json", ready_document)
        interface = ready_document.get("interface")
        if not (
            isinstance(interface, str)
            and interface
            and ready_document.get("max_packets") == CAPTURE_LIMIT
            and ready_document.get("rx_queues") == 1
            and ready_document.get("tx_queues") == 1
        ):
            raise RuntimeError(
                "probe ready JSON must contain interface, locked max_packets, and one RX/TX queue"
            )
        update_trace("probe_ready", ready=dict(ready_document))
        dumpcap_arguments = (
            str(dumpcap),
            "--lcore=1",
            f"--file-prefix={prefix}",
            "-i",
            interface,
            "-c",
            str(CAPTURE_LIMIT),
            "-w",
            str(output),
        )
        _write_capture_trace_json(
            trace_dir, "dumpcap-command.json", {"arguments": list(dumpcap_arguments)}
        )
        update_trace("dumpcap_start")
        dumpcap_process = process_factory(
            list(dumpcap_arguments),
            cwd=source,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        sleeper(0.5)
        if dumpcap_process.poll() is not None:
            stdout, stderr = dumpcap_process.communicate()
            _write_capture_trace_text(trace_dir, "dumpcap.stdout.log", stdout)
            _write_capture_trace_text(trace_dir, "dumpcap.stderr.log", stderr)
            raise RuntimeError(
                f"dpdk-dumpcap exited before arm: rc={dumpcap_process.returncode} "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        arm.write_text('{"armed":true}\n', encoding="utf-8")
        try:
            probe_stdout, probe_stderr = probe_process.communicate(timeout=20.0)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("DPDK probe exceeded the bounded capture timeout") from error
        _write_capture_trace_text(trace_dir, "probe.stdout.log", probe_stdout)
        _write_capture_trace_text(trace_dir, "probe.stderr.log", probe_stderr)
        if probe_process.returncode != 0:
            raise RuntimeError(
                f"DPDK probe failed: rc={probe_process.returncode} "
                f"stdout={probe_stdout!r} stderr={probe_stderr!r}"
            )
        try:
            dumpcap_stdout, dumpcap_stderr = dumpcap_process.communicate(timeout=20.0)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("dpdk-dumpcap exceeded the bounded capture timeout") from error
        _write_capture_trace_text(trace_dir, "dumpcap.stdout.log", dumpcap_stdout)
        _write_capture_trace_text(trace_dir, "dumpcap.stderr.log", dumpcap_stderr)
        update_trace(
            "dumpcap_complete",
            probe_return_code=probe_process.returncode,
            dumpcap_return_code=dumpcap_process.returncode,
        )
        if dumpcap_process.returncode != 0:
            raise RuntimeError(
                f"dpdk-dumpcap failed: rc={dumpcap_process.returncode} "
                f"stdout={dumpcap_stdout!r} stderr={dumpcap_stderr!r}"
            )
        result_document = _load_capture_json(result, "result")
        _write_capture_trace_json(trace_dir, "probe-result.json", result_document)
        if not (
            result_document.get("packets_sent") == CAPTURE_LIMIT
            and result_document.get("packets_parsed") == CAPTURE_LIMIT
            and result_document.get("parser_errors") == 0
        ):
            raise RuntimeError("probe result JSON has inconsistent sent/parsed/error counters")
        copied, dropped = _parse_dumpcap_stats(
            "\n".join((dumpcap_stdout, dumpcap_stderr)),
            trace_dir,
        )
        if copied != CAPTURE_LIMIT or dropped != 0:
            raise RuntimeError("dpdk-dumpcap did not capture the bounded packet count without drops")
        if capture_sample_hash(output) is None:
            raise RuntimeError("capture output is not a non-empty PCAPNG file")
        validator_arguments = (
            str(validator),
            "--validate-pcapng",
            str(output),
            "--expected-packets",
            str(CAPTURE_LIMIT),
        )
        _write_capture_trace_json(
            trace_dir, "validator-command.json", {"arguments": list(validator_arguments)}
        )
        update_trace("validator_start")
        validator_process = process_factory(
            list(validator_arguments),
            cwd=source,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            validator_stdout, validator_stderr = validator_process.communicate(timeout=10.0)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("PCAPNG validator exceeded the bounded timeout") from error
        _write_capture_trace_text(trace_dir, "validator.stdout.log", validator_stdout)
        _write_capture_trace_text(trace_dir, "validator.stderr.log", validator_stderr)
        if validator_process.returncode != 0:
            raise RuntimeError(
                f"PCAPNG validator failed: rc={validator_process.returncode} "
                f"stdout={validator_stdout!r} stderr={validator_stderr!r}"
            )
        validator_output = "\n".join((validator_stdout, validator_stderr))
        if validator_output.splitlines().count(CAPTURE_VALIDATOR_MARKER) != 1:
            raise RuntimeError("PCAPNG validator did not emit the exact single reopen marker")
        update_trace("complete", "passed", captured=copied, dropped=dropped)
        return copied, dropped
    except (OSError, RuntimeError, ValueError) as error:
        update_trace("failed", "failed", error=str(error))
        raise
    finally:
        _terminate(validator_process)
        _terminate(dumpcap_process)
        _terminate(probe_process)


def command_capture_test(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    probe = args.probe.resolve()
    validator = args.validator.resolve()
    if not probe.is_file():
        raise ValueError(f"probe executable does not exist: {probe}")
    if not validator.is_file():
        raise ValueError(f"validator executable does not exist: {validator}")
    huge_dir = resolve_capture_huge_dir()
    dumpcap = resolve_dpdk_dumpcap()
    requested_trace_dir = getattr(args, "trace_dir", None)
    trace_dir = requested_trace_dir.resolve() if requested_trace_dir is not None else None
    if trace_dir is not None:
        if trace_dir.exists():
            raise ValueError(f"refusing to overwrite capture trace directory: {trace_dir}")
        if not trace_dir.parent.is_dir():
            raise ValueError(f"capture trace parent does not exist: {trace_dir.parent}")
        trace_dir.mkdir()
    requested_output = os.environ.get(CAPTURE_OUTPUT_ENV)
    with tempfile.TemporaryDirectory(prefix="nids-t2.5-capture-") as temporary:
        workspace = Path(temporary).resolve()
        output = Path(requested_output).resolve() if requested_output else workspace / "sample.pcapng"
        copied, dropped = run_capture_session(
            source,
            probe,
            dumpcap,
            validator,
            output,
            workspace,
            huge_dir,
            trace_dir=trace_dir,
        )
    print(
        "T2.5 capture: "
        f"pcapng=1 copied={copied} dropped={dropped} bounded=1 "
        "default_off=1 benchmark_forbidden=1"
    )
    return 0


def command_check(args: argparse.Namespace) -> int:
    errors = contract_source_errors(args.source.resolve())
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T2.5 source contract: DPDK mbufs delegate to nids_core.parse_packet")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t2.5").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    if any(not (source / path).is_file() for path in SOURCE_FILES) or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T2.5 project root: {source}")

    resolve_capture_huge_dir()
    host = inspect_host()
    require_supported_host(host)
    require_tools()
    attempt_directory = artifact_root / "attempts" / runner.attempt_name()
    attempt_directory.mkdir(parents=True, exist_ok=False)
    receipt = collect_receipt(source, attempt_directory, host)
    write_new_json(attempt_directory / "receipt.json", receipt)
    print(f"wrote {attempt_directory / 'receipt.json'} ({receipt['status']})")
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
    check = subparsers.add_parser("check", help="validate T2.5 DPDK adapter source contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T2.5 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t2.5")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T2.5 receipt")
    validate.add_argument("--input", required=True, type=Path)
    validate.set_defaults(handler=command_validate)
    capture = subparsers.add_parser("capture-test", help="run bounded dpdk-dumpcap verification")
    capture.add_argument("--source", required=True, type=Path)
    capture.add_argument("--probe", required=True, type=Path)
    capture.add_argument("--validator", required=True, type=Path)
    capture.add_argument("--trace-dir", type=Path)
    capture.set_defaults(handler=command_capture_test)
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
