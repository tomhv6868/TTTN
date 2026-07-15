#!/usr/bin/env python3
"""Build and verify the T2.1 packet parser on the locked Ubuntu host."""

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
TASK = "T2.1"
KIND = "packet_parser_acceptance"
EXPECTED_CTEST = "nids_core.packet_parser"
COMMAND_NAMES = runner.COMMAND_NAMES
SOURCE_FILES = (
    "CMakeLists.txt",
    "cpp/include/nids/packet.hpp",
    "cpp/src/packet.cpp",
    "cpp/tests/packet_parser_test.cpp",
    "scripts/verify_t21_packet_parser.py",
)
EXPECTED_CONTRACT = {
    "input": "byte_span",
    "adapter_independent": True,
    "link_layer": "ethernet_ii",
    "vlan_tpids": ["0x8100", "0x88A8", "0x9100"],
    "maximum_vlan_tags": 1,
    "nested_vlan_policy": "reject",
    "network_layer": "ipv4",
    "fragmented_ipv4_policy": "reject",
    "transport_layers": ["tcp", "udp"],
    "checksum_validation": False,
}
ERROR_CODES = (
    "inconsistent_lengths",
    "unsupported_link_layer",
    "truncated_ethernet_header",
    "unsupported_ether_type",
    "truncated_vlan_header",
    "nested_vlan",
    "truncated_ipv4_header",
    "invalid_ipv4_version",
    "invalid_ipv4_header_length",
    "truncated_ipv4_packet",
    "invalid_ipv4_total_length",
    "fragmented_ipv4",
    "unsupported_transport_protocol",
    "truncated_tcp_header",
    "invalid_tcp_header_length",
    "truncated_udp_header",
    "invalid_udp_length",
)
LOG_FILES = {
    "configure": "configure.log",
    "build": "build.log",
    "ctest": "ctest.log",
    "python_unittest": "python-unittest.log",
}

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
        raise RuntimeError("T2.1 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T2.1 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T2.1 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T2.1 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T2.1 verification requires Python 3.12.x")


def contract_source_errors(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        return [f"missing source file: {path}" for path in missing]

    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    header = (source / "cpp/include/nids/packet.hpp").read_text(encoding="utf-8")
    implementation = (source / "cpp/src/packet.cpp").read_text(encoding="utf-8")
    tests = (source / "cpp/tests/packet_parser_test.cpp").read_text(encoding="utf-8")
    errors: list[str] = []

    cmake_tokens = (
        "cpp/src/packet.cpp",
        "cpp/tests/packet_parser_test.cpp",
        EXPECTED_CTEST,
    )
    missing_cmake = [token for token in cmake_tokens if token not in cmake]
    if missing_cmake:
        errors.append(f"CMake is missing packet parser tokens: {', '.join(missing_cmake)}")

    if "std::span<const std::uint8_t>" not in header:
        errors.append("packet contract must expose an immutable byte span")
    signature = r"ParseResult\s*<\s*PacketView\s*>\s+parse_packet\s*\(\s*PacketInput\s+input\s*\)\s*noexcept\s*;"
    if re.search(signature, header) is None:
        errors.append("packet header is missing the noexcept parse_packet contract")
    missing_header_codes = [code for code in ERROR_CODES if code not in header]
    if missing_header_codes:
        errors.append(f"packet header is missing typed errors: {', '.join(missing_header_codes)}")

    definition = r"parse_packet\s*\(\s*PacketInput\s+input\s*\)\s*noexcept"
    if re.search(definition, implementation) is None:
        errors.append("packet implementation is missing the noexcept parse_packet definition")
    implementation_lower = implementation.lower()
    for label, alternatives in (
        ("0x8100 VLAN", ("0x8100", "33024")),
        ("0x88A8 VLAN", ("0x88a8", "34984")),
        ("0x9100 VLAN", ("0x9100", "37120")),
    ):
        if not any(token in implementation_lower for token in alternatives):
            errors.append(f"packet implementation is missing {label} support")

    required_test_tokens = ("TcpView", "UdpView", *ERROR_CODES)
    missing_test_tokens = [token for token in required_test_tokens if token not in tests]
    if re.search(r"parse_packet\s*\(", tests) is None:
        missing_test_tokens.insert(0, "parse_packet call")
    if missing_test_tokens:
        errors.append(f"packet parser tests are missing coverage tokens: {', '.join(missing_test_tokens)}")
    return errors


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
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
                "name": "ctest.packet_parser_present",
                "status": "passed" if EXPECTED_CTEST in ctest_output else "failed",
            },
            {
                "name": "ctest.all_passed",
                "status": "passed" if "100% tests passed" in ctest_output else "failed",
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
    with tempfile.TemporaryDirectory(prefix="nids-t2.1-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        checks = assess(commands, cache, source_errors)

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
        "contract": EXPECTED_CONTRACT,
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
        errors.append("contract values do not match the approved T2.1 parser boundaries")

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
        errors.append("build flags do not match the T2.1 acceptance contract")

    artifacts = document.get("artifacts")
    artifact_directory = artifacts.get("directory") if isinstance(artifacts, Mapping) else None
    if not isinstance(artifact_directory, str) or re.fullmatch(
        r"run_log/t2\.1/attempts/ubuntu-acceptance-[A-Za-z0-9._-]+", artifact_directory
    ) is None or artifacts.get("final_receipt") != "run_log/t2.1/acceptance.json":
        errors.append("artifacts must remain under run_log/t2.1 with the locked final receipt")

    commands = document.get("commands")
    if not isinstance(commands, list) or [
        command.get("name") for command in commands if isinstance(command, Mapping)
    ] != list(COMMAND_NAMES):
        errors.append("commands must contain the complete T2.1 pipeline in order")
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
        required_checks = {"source.contract_consistent", "ctest.packet_parser_present", "ctest.all_passed"}
        if invalid:
            errors.append("every check must have passed or failed status")
        if not required_checks.issubset(names):
            errors.append("receipt must check the source contract and packet parser CTest")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or [
        item.get("path") for item in files if isinstance(item, Mapping)
    ] != list(SOURCE_FILES):
        errors.append("source files must match the T2.1 parser inputs")
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
    print("valid T2.1 source contract: Ethernet II, single VLAN, IPv4, TCP/UDP")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t2.1").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    missing_sources = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing_sources or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T2.1 project root: {source}")

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
    check = subparsers.add_parser("check", help="validate T2.1 parser source contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T2.1 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t2.1")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T2.1 receipt")
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
