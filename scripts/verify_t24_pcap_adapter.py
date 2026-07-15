#!/usr/bin/env python3
"""Build and verify the T2.4 libpcap adapter on the locked Ubuntu host."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_t11_packet_contract as runner


SCHEMA_VERSION = "1.0.0"
TASK = "T2.4"
KIND = "pcap_adapter_acceptance"
EXPECTED_CTEST = "nids_dataset.pcap_adapter"
DATASET_TARGET = "nids_dataset"
DATASET_ALIAS = "nids::dataset"
TEST_EXECUTABLE = "nids_pcap_adapter_test"
COMMAND_NAMES = (
    "libpcap_version",
    "configure",
    "build",
    "ctest",
    "ctest_pcap_adapter",
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
    ".github/workflows/ci.yml",
    *CORE_FILES,
    "cpp/include/nids/pcap_adapter.hpp",
    "cpp/src/pcap_adapter.cpp",
    "cpp/tests/pcap_adapter_test.cpp",
    "scripts/verify_t24_pcap_adapter.py",
)
COVERAGE_FIELDS = (
    "pcap_micro",
    "pcap_nano",
    "pcapng",
    "open_error",
    "read_error",
    "linktype_error",
    "timestamp_overflow",
    "parser_error_continue",
)
EXPECTED_CONTRACT = {
    "library": DATASET_TARGET,
    "alias": DATASET_ALIAS,
    "dependency": "libpcap",
    "accepted_formats": ["pcap_microsecond", "pcap_nanosecond", "pcapng"],
    "accepted_linktype": "ethernet",
    "parser": "nids_core.parse_packet",
    "duplicate_parser": False,
    "parser_error_policy": "count_and_continue",
    "timestamp_overflow_policy": "typed_error",
    "core_libpcap_dependency": False,
    "clean_release_build": True,
    "offline_dependency_mode": True,
}
LOG_FILES = {
    "libpcap_version": "libpcap-version.log",
    "configure": "configure.log",
    "build": "build.log",
    "ctest": "ctest.log",
    "ctest_pcap_adapter": "ctest-pcap-adapter.log",
    "python_unittest": "python-unittest.log",
}
LIBPCAP_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+._A-Za-z0-9]*)?")
COVERAGE_MARKER = re.compile(
    r"T2\.4 coverage:\s*"
    r"pcap_micro=(?P<pcap_micro>\d+)\s+"
    r"pcap_nano=(?P<pcap_nano>\d+)\s+"
    r"pcapng=(?P<pcapng>\d+)\s+"
    r"open_error=(?P<open_error>\d+)\s+"
    r"read_error=(?P<read_error>\d+)\s+"
    r"linktype_error=(?P<linktype_error>\d+)\s+"
    r"timestamp_overflow=(?P<timestamp_overflow>\d+)\s+"
    r"parser_error_continue=(?P<parser_error_continue>\d+)\s+"
    r"packets_seen=(?P<packets_seen>\d+)\s+"
    r"packets_parsed=(?P<packets_parsed>\d+)\s+"
    r"parser_errors=(?P<parser_errors>\d+)"
)

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
    }


def require_supported_host(host: Mapping[str, Any]) -> None:
    effective_uid = host.get("effective_uid")
    if not isinstance(effective_uid, int) or isinstance(effective_uid, bool) or effective_uid <= 0:
        raise RuntimeError("T2.4 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T2.4 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T2.4 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T2.4 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T2.4 verification requires Python 3.12.x")


def require_tools() -> None:
    required = ("cmake", "ninja", "c++", "ctest", "pkg-config")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")


def run_pipeline(source: Path, build: Path, artifact_directory: Path) -> list[dict[str, Any]]:
    version = runner.run_command(
        "libpcap_version",
        ("pkg-config", "--modversion", "libpcap"),
        source,
        artifact_directory / LOG_FILES["libpcap_version"],
        30.0,
    )
    commands = [version]

    if version["return_code"] == 0:
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
                "-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF",
            ),
            source,
            artifact_directory / LOG_FILES["configure"],
            300.0,
        )
    else:
        configure = runner.skipped_command(
            "configure", "libpcap version check failed", artifact_directory / LOG_FILES["configure"]
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
            600.0,
        )
        named_ctest = runner.run_command(
            "ctest_pcap_adapter",
            (
                "ctest",
                "--test-dir",
                str(build),
                "--build-config",
                "Release",
                "--output-on-failure",
                "--verbose",
                "-R",
                f"^{re.escape(EXPECTED_CTEST)}$",
            ),
            source,
            artifact_directory / LOG_FILES["ctest_pcap_adapter"],
            120.0,
        )
    else:
        ctest = runner.skipped_command(
            "ctest", "build failed or was skipped", artifact_directory / LOG_FILES["ctest"]
        )
        named_ctest = runner.skipped_command(
            "ctest_pcap_adapter",
            "build failed or was skipped",
            artifact_directory / LOG_FILES["ctest_pcap_adapter"],
        )
    commands.extend((ctest, named_ctest))
    commands.append(
        runner.run_command(
            "python_unittest",
            (sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"),
            source,
            artifact_directory / LOG_FILES["python_unittest"],
            600.0,
        )
    )
    return commands


def libpcap_version(commands: Sequence[Mapping[str, Any]]) -> str | None:
    command = runner.find_command(commands, "libpcap_version")
    stdout = str(command.get("stdout", "")).strip()
    stderr = str(command.get("stderr", "")).strip()
    if stderr or LIBPCAP_VERSION.fullmatch(stdout) is None:
        return None
    return stdout


def parse_coverage(commands: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    command = runner.find_command(commands, "ctest_pcap_adapter")
    output = "\n".join((str(command.get("stdout", "")), str(command.get("stderr", ""))))
    matches = list(COVERAGE_MARKER.finditer(output))
    if len(matches) != 1:
        return None
    values = {
        name: int(matches[0].group(name))
        for name in (*COVERAGE_FIELDS, "packets_seen", "packets_parsed", "parser_errors")
    }
    return {
        "coverage": {name: values[name] == 1 for name in COVERAGE_FIELDS},
        "records_read": values["packets_seen"],
        "packets_parsed": values["packets_parsed"],
        "parser_errors": values["parser_errors"],
    }


def valid_coverage(results: Mapping[str, Any] | None) -> bool:
    if results is None:
        return False
    coverage = results.get("coverage")
    records_read = results.get("records_read")
    packets_parsed = results.get("packets_parsed")
    parser_errors = results.get("parser_errors")
    return (
        isinstance(coverage, Mapping)
        and set(coverage) == set(COVERAGE_FIELDS)
        and all(coverage.get(name) is True for name in COVERAGE_FIELDS)
        and isinstance(records_read, int)
        and not isinstance(records_read, bool)
        and isinstance(packets_parsed, int)
        and not isinstance(packets_parsed, bool)
        and isinstance(parser_errors, int)
        and not isinstance(parser_errors, bool)
        and records_read > packets_parsed >= 3
        and parser_errors > 0
        and records_read == packets_parsed + parser_errors
    )


def _has_libpcap_include(text: str) -> bool:
    return re.search(r"#\s*include\s*[<\"](?:pcap/)?pcap\.h[>\"]", text) is not None


def contract_source_errors(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        return [f"missing source file: {path}" for path in missing]

    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    ci = (source / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    header = (source / "cpp/include/nids/pcap_adapter.hpp").read_text(encoding="utf-8")
    implementation = (source / "cpp/src/pcap_adapter.cpp").read_text(encoding="utf-8")
    tests = (source / "cpp/tests/pcap_adapter_test.cpp").read_text(encoding="utf-8")
    errors: list[str] = []

    cmake_tokens = (
        DATASET_TARGET,
        DATASET_ALIAS,
        "cpp/src/pcap_adapter.cpp",
        "cpp/tests/pcap_adapter_test.cpp",
        TEST_EXECUTABLE,
        EXPECTED_CTEST,
        "PkgConfig",
        "libpcap",
        "nids::core",
    )
    missing_cmake = [token for token in cmake_tokens if token not in cmake]
    if missing_cmake:
        errors.append(f"CMake is missing PCAP adapter tokens: {', '.join(missing_cmake)}")

    ci_lower = ci.lower()
    missing_ci = [
        token for token in ("ubuntu-24.04", "libpcap-dev", "pkg-config") if token not in ci_lower
    ]
    if missing_ci:
        errors.append(f"CI is missing libpcap build tokens: {', '.join(missing_ci)}")

    contaminated = []
    for path in CORE_FILES:
        text = (source / path).read_text(encoding="utf-8")
        if _has_libpcap_include(text):
            contaminated.append(path)
    if contaminated:
        errors.append(f"core packet/flow/feature files must not include libpcap: {', '.join(contaminated)}")

    adapter_api = "\n".join((header, implementation))
    adapter_tokens = (
        "records_read",
        "packets_parsed",
        "parser_errors",
        "pcap_open_offline",
        "pcap_next_ex",
        "pcap_datalink",
        "parse_packet",
    )
    missing_adapter = [token for token in adapter_tokens if token not in adapter_api]
    if missing_adapter:
        errors.append(f"PCAP adapter is missing shared-reader tokens: {', '.join(missing_adapter)}")
    duplicate_parser = re.search(
        r"ParseResult\s*<\s*PacketView\s*>\s+parse_packet\s*\(", adapter_api
    )
    if duplicate_parser is not None:
        errors.append("PCAP adapter must call the shared parser, not define parse_packet")

    test_tokens = (
        "pcap_micro",
        "pcap_nano",
        "pcapng",
        "open_error",
        "read_error",
        "linktype_error",
        "timestamp_overflow",
        "parser_error_continue",
        "packets_seen",
        "packets_parsed",
        "parser_errors",
        "T2.4 coverage:",
    )
    missing_tests = [token for token in test_tokens if token not in tests]
    if missing_tests:
        errors.append(f"PCAP adapter tests are missing coverage tokens: {', '.join(missing_tests)}")
    return errors


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
    version: str | None,
    results: Mapping[str, Any] | None,
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
    named = runner.find_command(commands, "ctest_pcap_adapter")
    named_output = "\n".join((str(named.get("stdout", "")), str(named.get("stderr", ""))))
    checks.extend(
        (
            {"name": "source.contract_consistent", "status": "passed" if not source_errors else "failed"},
            {"name": "versions.libpcap_present", "status": "passed" if version is not None else "failed"},
            {"name": "ctest.pcap_adapter_present", "status": "passed" if EXPECTED_CTEST in ctest_output else "failed"},
            {"name": "ctest.all_passed", "status": "passed" if "100% tests passed" in ctest_output else "failed"},
            {"name": "ctest.pcap_adapter_passed", "status": "passed" if "100% tests passed" in named_output else "failed"},
            {"name": "coverage.marker_present", "status": "passed" if results is not None else "failed"},
            {"name": "coverage.complete_and_counts_consistent", "status": "passed" if valid_coverage(results) else "failed"},
            {"name": "build.release", "status": "passed" if cache.get("CMAKE_BUILD_TYPE") == "Release" else "failed"},
            {"name": "build.testing_enabled", "status": "passed" if cache.get("BUILD_TESTING") == "ON" else "failed"},
            {"name": "build.toolchain_smoke_disabled", "status": "passed" if cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") == "OFF" else "failed"},
        )
    )
    return checks


def collect_receipt(source: Path, artifact_directory: Path, host: Mapping[str, Any]) -> dict[str, Any]:
    source_errors = contract_source_errors(source)
    with tempfile.TemporaryDirectory(prefix="nids-t2.4-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        version = libpcap_version(commands)
        results = parse_coverage(commands)
        checks = assess(commands, cache, source_errors, version, results)

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
        "artifacts": {
            "directory": str(artifact_directory.relative_to(source)).replace("\\", "/"),
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
            "libpcap": version,
            "command": "pkg-config --modversion libpcap",
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
    ):
        errors.append("receipt host must be Ubuntu 24.04 x86_64 with Python 3.12.x as a normal user")
    if document.get("contract") != EXPECTED_CONTRACT:
        errors.append("contract values do not match the approved T2.4 PCAP adapter boundaries")

    versions = document.get("versions")
    if not isinstance(versions, Mapping) or not (
        LIBPCAP_VERSION.fullmatch(str(versions.get("libpcap", ""))) is not None
        and versions.get("command") == "pkg-config --modversion libpcap"
    ):
        errors.append("receipt must record the libpcap pkg-config version")
    results = document.get("results")
    if not valid_coverage(results if isinstance(results, Mapping) else None):
        errors.append("receipt must record complete PCAP coverage and consistent result counts")

    build = document.get("build")
    if not isinstance(build, Mapping) or not (
        build.get("generator") == "Ninja"
        and build.get("configuration") == "Release"
        and build.get("testing_enabled") is True
        and build.get("toolchain_smoke_enabled") is False
        and build.get("temporary_workspace_outside_source") is True
        and build.get("temporary_workspace_retained") is False
        and build.get("offline_dependency_mode") is True
    ):
        errors.append("build flags do not match the T2.4 acceptance contract")

    artifacts = document.get("artifacts")
    artifact_directory = artifacts.get("directory") if isinstance(artifacts, Mapping) else None
    if not isinstance(artifact_directory, str) or re.fullmatch(
        r"run_log/t2\.4/attempts/ubuntu-acceptance-[A-Za-z0-9._-]+", artifact_directory
    ) is None or artifacts.get("final_receipt") != "run_log/t2.4/acceptance.json":
        errors.append("artifacts must remain under run_log/t2.4 with the locked final receipt")

    commands = document.get("commands")
    valid_commands = (
        isinstance(commands, list)
        and len(commands) == len(COMMAND_NAMES)
        and all(isinstance(command, Mapping) for command in commands)
        and [command.get("name") for command in commands] == list(COMMAND_NAMES)
    )
    if not valid_commands:
        errors.append("commands must contain the complete T2.4 pipeline in order")
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
            "versions.libpcap_present",
            "ctest.pcap_adapter_present",
            "ctest.all_passed",
            "ctest.pcap_adapter_passed",
            "coverage.marker_present",
            "coverage.complete_and_counts_consistent",
        }
        if invalid:
            errors.append("every check must have passed or failed status")
        if not required_checks.issubset(names):
            errors.append("receipt must check libpcap, full/named CTest, coverage, and source boundaries")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or len(files) != len(SOURCE_FILES) or not all(
        isinstance(item, Mapping) for item in files
    ) or [item.get("path") for item in files] != list(SOURCE_FILES):
        errors.append("source files must match the T2.4 PCAP adapter inputs")
    elif any(
        re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None
        for item in files
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
    errors = contract_source_errors(args.source.resolve())
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T2.4 source contract: libpcap adapter delegates bytes to nids_core.parse_packet")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t2.4").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    if any(not (source / path).is_file() for path in SOURCE_FILES) or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T2.4 project root: {source}")

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
    check = subparsers.add_parser("check", help="validate T2.4 PCAP adapter source contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T2.4 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t2.4")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T2.4 receipt")
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
