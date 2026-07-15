#!/usr/bin/env python3
"""Build and verify the T2.2 flow table on the locked Ubuntu host."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_t11_packet_contract as runner


SCHEMA_VERSION = "1.0.0"
TASK = "T2.2"
KIND = "flow_table_acceptance"
EXPECTED_CTEST = "nids_core.flow_table"
MEMORY_ACCOUNTING = "pmr_requested_bytes_plus_fixed_state"
COMMAND_NAMES = runner.COMMAND_NAMES
SOURCE_FILES = (
    "CMakeLists.txt",
    "cpp/include/nids/flow.hpp",
    "cpp/include/nids/flow_table.hpp",
    "cpp/src/flow_table.cpp",
    "cpp/tests/flow_table_test.cpp",
    "scripts/verify_t22_flow_table.py",
)
EXPECTED_CONTRACT = {
    "flow_key": "canonical_bidirectional_ipv4_5_tuple",
    "direction": "first_packet_source",
    "incremental_state": True,
    "event_delivery": "synchronous_observer",
    "packet_event_before_close": True,
    "capture_order": "preserved",
    "iat": "signed_int64",
    "timeout_watermark": "nondecreasing",
    "single_clock_domain": True,
    "idle_timeout_ns": 60_000_000_000,
    "maximum_age_ns": 1_800_000_000_000,
    "timeout_boundary": "greater_than_or_equal",
    "tcp_reset_packet_included": True,
    "fin_requires_peer_ack_after_second_fin": True,
    "non_ack_syn_reuses_tuple": True,
    "identical_initial_syn_is_retransmission": True,
    "hard_active_flow_limit": 65_536,
    "memory_budget_bytes": 256 * 1024 * 1024,
    "eviction_order": "least_recently_active_then_creation_order",
    "memory_accounting": MEMORY_ACCOUNTING,
    "retain_packet_bytes_in_flow_state": False,
}
CLOSE_REASONS = (
    "idle_timeout",
    "maximum_age",
    "tcp_reset",
    "tcp_fin_handshake",
    "tuple_reuse",
    "capacity_eviction",
    "end_of_input",
)
TEST_COVERAGE_TOKENS = (
    "FlowDirection::forward",
    "FlowDirection::reverse",
    "tcp_reset",
    "tcp_fin_handshake",
    "tuple_reuse",
    "capacity_eviction",
    "idle_timeout",
    "maximum_age",
    "end_of_input",
)
LOG_FILES = {
    "configure": "configure.log",
    "build": "build.log",
    "ctest": "ctest.log",
    "python_unittest": "python-unittest.log",
}
MEMORY_MARKER = re.compile(
    r"T2\.2 memory accounting:\s*"
    r"flow_state_bytes=(?P<flow_state>\d+)\s+"
    r"fixed_bytes=(?P<fixed>\d+)\s+"
    r"allocator_current_bytes=(?P<allocator_current>\d+)\s+"
    r"allocator_peak_bytes=(?P<allocator_peak>\d+)\s+"
    r"current_bytes=(?P<current>\d+)\s+"
    r"peak_bytes=(?P<peak>\d+)\s+"
    r"budget_bytes=(?P<budget>\d+)"
)

run_pipeline = runner.run_pipeline
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
        raise RuntimeError("T2.2 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T2.2 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T2.2 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T2.2 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T2.2 verification requires Python 3.12.x")


def _flow_state_body(header: str) -> str | None:
    match = re.search(r"struct\s+FlowState\s*\{(?P<body>.*?)\n\};", header, re.DOTALL)
    return match.group("body") if match is not None else None


def contract_source_errors(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        return [f"missing source file: {path}" for path in missing]

    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    flow_contract = (source / "cpp/include/nids/flow.hpp").read_text(encoding="utf-8")
    header = (source / "cpp/include/nids/flow_table.hpp").read_text(encoding="utf-8")
    implementation = (source / "cpp/src/flow_table.cpp").read_text(encoding="utf-8")
    tests = (source / "cpp/tests/flow_table_test.cpp").read_text(encoding="utf-8")
    errors: list[str] = []

    cmake_tokens = (
        "cpp/src/flow_table.cpp",
        "cpp/tests/flow_table_test.cpp",
        EXPECTED_CTEST,
    )
    missing_cmake = [token for token in cmake_tokens if token not in cmake]
    if missing_cmake:
        errors.append(f"CMake is missing flow table tokens: {', '.join(missing_cmake)}")

    locked_contract_tokens = (
        "FlowKey",
        "FlowDirection",
        "FlowCloseReason",
        "60LL * 1'000'000'000LL",
        "30LL * 60LL * 1'000'000'000LL",
        "65'536U",
        "256ULL * 1024ULL * 1024ULL",
        *CLOSE_REASONS,
    )
    missing_contract = [token for token in locked_contract_tokens if token not in flow_contract]
    if missing_contract:
        errors.append(f"flow contract is missing locked T1.2 tokens: {', '.join(missing_contract)}")

    header_tokens = (
        "FlowState",
        "FlowTable",
        "FlowCounters",
        "FlowObserver",
        "on_packet",
        "on_close",
    )
    missing_header = [token for token in header_tokens if token not in header]
    if missing_header:
        errors.append(f"flow table header is missing API tokens: {', '.join(missing_header)}")

    state_body = _flow_state_body(header)
    if state_body is None:
        errors.append("flow table header must define FlowState as a struct")
    else:
        retained = [
            token
            for token in ("PacketBytes", "PacketView", "std::span", "payload", "raw_bytes")
            if token in state_body
        ]
        if retained:
            errors.append(f"FlowState must not retain packet bytes: {', '.join(retained)}")

    implementation_tokens = (
        "signed_iat_ns",
        "advance_timestamp_watermark",
        "idle_timeout_expired",
        "maximum_age_expired",
        *CLOSE_REASONS,
    )
    missing_implementation = [token for token in implementation_tokens if token not in implementation]
    if missing_implementation:
        errors.append(
            "flow table implementation is missing lifecycle tokens: "
            + ", ".join(missing_implementation)
        )

    missing_tests = [token for token in TEST_COVERAGE_TOKENS if token not in tests]
    memory_test_tokens = (
        "fixed_memory_bytes",
        "current_allocator_bytes",
        "peak_allocator_bytes",
        "current_memory_bytes",
        "peak_memory_bytes",
        "memory_budget_bytes",
    )
    if any(token not in tests for token in memory_test_tokens):
        missing_tests.append("actual allocator byte accounting")
    if "T2.2 memory accounting:" not in tests:
        missing_tests.append("memory accounting receipt marker")
    if missing_tests:
        errors.append(f"flow table tests are missing coverage tokens: {', '.join(missing_tests)}")
    return errors


def parse_memory_measurement(commands: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    ctest = runner.find_command(commands, "ctest")
    output = "\n".join((str(ctest.get("stdout", "")), str(ctest.get("stderr", ""))))
    matches = list(MEMORY_MARKER.finditer(output))
    if len(matches) != 1:
        return None
    values = {
        name: int(matches[0].group(name))
        for name in (
            "flow_state",
            "fixed",
            "allocator_current",
            "allocator_peak",
            "current",
            "peak",
            "budget",
        )
    }
    return {
        "accounting": MEMORY_ACCOUNTING,
        "flow_state_bytes": values["flow_state"],
        "fixed_bytes": values["fixed"],
        "allocator_current_bytes": values["allocator_current"],
        "allocator_peak_bytes": values["allocator_peak"],
        "current_bytes": values["current"],
        "peak_bytes": values["peak"],
        "budget_bytes": values["budget"],
    }


def valid_memory_measurement(measurement: Mapping[str, Any] | None) -> bool:
    if measurement is None:
        return False
    current = measurement.get("current_bytes")
    peak = measurement.get("peak_bytes")
    budget = measurement.get("budget_bytes")
    flow_state = measurement.get("flow_state_bytes")
    fixed = measurement.get("fixed_bytes")
    allocator_current = measurement.get("allocator_current_bytes")
    allocator_peak = measurement.get("allocator_peak_bytes")
    integers = (flow_state, fixed, allocator_current, allocator_peak, current, peak)
    return (
        measurement.get("accounting") == MEMORY_ACCOUNTING
        and all(isinstance(value, int) and not isinstance(value, bool) for value in integers)
        and budget == EXPECTED_CONTRACT["memory_budget_bytes"]
        and flow_state > 0
        and fixed > 0
        and 0 <= allocator_current <= allocator_peak
        and current == fixed + allocator_current
        and peak == fixed + allocator_peak
        and 0 <= current <= peak
        and 0 < peak <= budget
    )


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
    memory: Mapping[str, Any] | None = None,
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
    checks.extend(
        (
            {
                "name": "source.contract_consistent",
                "status": "passed" if not source_errors else "failed",
            },
            {
                "name": "ctest.flow_table_present",
                "status": "passed" if EXPECTED_CTEST in ctest_output else "failed",
            },
            {
                "name": "ctest.all_passed",
                "status": "passed" if "100% tests passed" in ctest_output else "failed",
            },
            {
                "name": "resources.allocator_measurement_present",
                "status": "passed" if memory is not None else "failed",
            },
            {
                "name": "resources.memory_budget_respected",
                "status": "passed" if valid_memory_measurement(memory) else "failed",
            },
            {
                "name": "build.release",
                "status": "passed" if cache.get("CMAKE_BUILD_TYPE") == "Release" else "failed",
            },
            {
                "name": "build.testing_enabled",
                "status": "passed" if cache.get("BUILD_TESTING") == "ON" else "failed",
            },
            {
                "name": "build.toolchain_smoke_disabled",
                "status": "passed" if cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") == "OFF" else "failed",
            },
        )
    )
    return checks


def collect_receipt(
    source: Path,
    artifact_directory: Path,
    host: Mapping[str, Any],
) -> dict[str, Any]:
    source_errors = contract_source_errors(source)
    with tempfile.TemporaryDirectory(prefix="nids-t2.2-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        memory = parse_memory_measurement(commands)
        checks = assess(commands, cache, source_errors, memory)

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
            "files": [
                {"path": path, "sha256": sha256_file(source / path)}
                for path in SOURCE_FILES
            ],
            "contract_errors": list(source_errors),
        },
        "artifacts": {
            "directory": str(artifact_directory.relative_to(source)).replace("\\", "/"),
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
        "contract": EXPECTED_CONTRACT,
        "resources": memory,
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
        errors.append("contract values do not match the approved T2.2 flow table boundaries")
    if not valid_memory_measurement(
        document.get("resources") if isinstance(document.get("resources"), Mapping) else None
    ):
        errors.append("resources must contain bounded PMR-requested and fixed-state byte measurements")

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
        errors.append("build flags do not match the T2.2 acceptance contract")

    artifacts = document.get("artifacts")
    artifact_directory = artifacts.get("directory") if isinstance(artifacts, Mapping) else None
    if not isinstance(artifact_directory, str) or re.fullmatch(
        r"run_log/t2\.2/attempts/ubuntu-acceptance-[A-Za-z0-9._-]+", artifact_directory
    ) is None or artifacts.get("final_receipt") != "run_log/t2.2/acceptance.json":
        errors.append("artifacts must remain under run_log/t2.2 with the locked final receipt")

    commands = document.get("commands")
    if not isinstance(commands, list) or [
        command.get("name") for command in commands if isinstance(command, Mapping)
    ] != list(COMMAND_NAMES):
        errors.append("commands must contain the complete T2.2 pipeline in order")
    else:
        for command in commands:
            if not isinstance(command, Mapping):
                continue
            expected_log = (
                f"{artifact_directory}/{LOG_FILES[command['name']]}"
                if isinstance(artifact_directory, str)
                else None
            )
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
            "ctest.flow_table_present",
            "ctest.all_passed",
            "resources.allocator_measurement_present",
            "resources.memory_budget_respected",
        }
        if invalid:
            errors.append("every check must have passed or failed status")
        if not required_checks.issubset(names):
            errors.append("receipt must check source, flow table CTest, and allocator byte accounting")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or [
        item.get("path") for item in files if isinstance(item, Mapping)
    ] != list(SOURCE_FILES):
        errors.append("source files must match the T2.2 flow table inputs")
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
    print("valid T2.2 source contract: biflow lifecycle, bounded resources, synchronous events")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t2.2").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    missing_sources = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing_sources or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T2.2 project root: {source}")

    host = inspect_host()
    require_supported_host(host)
    runner.require_tools()
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
    check = subparsers.add_parser("check", help="validate T2.2 flow table source contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T2.2 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t2.2")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T2.2 receipt")
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
