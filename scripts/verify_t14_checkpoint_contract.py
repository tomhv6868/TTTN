#!/usr/bin/env python3
"""Build and verify the approved T1.4 checkpoint contract on Ubuntu."""

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

import verify_t11_packet_contract as runner
import verify_t13_feature_schema as schema_verifier


SCHEMA_VERSION = "1.0.0"
TASK = "T1.4"
KIND = "checkpoint_contract_acceptance"
EXPECTED_CTEST = "nids_core.checkpoint_contract"
COMMAND_NAMES = runner.COMMAND_NAMES
SOURCE_FILES = (
    "CMakeLists.txt",
    "config/flow-feature-schema-v1.json",
    "config/packet-sequence-schema-v1.json",
    "cpp/include/nids/checkpoint.hpp",
    "cpp/tests/checkpoint_contract_test.cpp",
    "scripts/verify_t14_checkpoint_contract.py",
)
EXPECTED_CONTRACT = {
    "checkpoints": [3, 5, 7, 9],
    "feature_count": 54,
    "flow_id_bits": 128,
    "update_before_snapshot": True,
    "sequence_record_before_snapshot": True,
    "emit_before_terminal_close": True,
    "synthesize_final_checkpoint": False,
    "snapshot_owns_feature_vector": True,
    "snapshot_owns_packet_bytes": False,
    "metadata_is_model_input": False,
    "offline_error_policy": "abort_run",
    "live_error_policy": "discard_flow_generation_increment_counter_and_continue",
}


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
    if host.get("effective_uid") == 0:
        raise RuntimeError("T1.4 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T1.4 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T1.4 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T1.4 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T1.4 verification requires Python 3.12.x")


def contract_source_errors(source: Path) -> list[str]:
    errors: list[str] = []
    flow_schema = runner.load_json(source / "config/flow-feature-schema-v1.json")
    packet_schema = runner.load_json(source / "config/packet-sequence-schema-v1.json")
    errors.extend(schema_verifier.validate_flow_schema(flow_schema))
    errors.extend(schema_verifier.validate_packet_schema(packet_schema))

    header = (source / "cpp/include/nids/checkpoint.hpp").read_text(encoding="utf-8")
    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    required_header_tokens = (
        "flow_feature_count_v1 = 54U",
        "Checkpoint::f3",
        "Checkpoint::f5",
        "Checkpoint::f7",
        "Checkpoint::f9",
        "packet_sequence_record_precedes_snapshot",
        "metadata_is_model_input",
        "packet_sequence_prefix_unavailable",
        "discard_flow_generation_increment_counter_and_continue",
    )
    missing = [token for token in required_header_tokens if token not in header]
    if missing:
        errors.append(f"checkpoint header is missing contract tokens: {', '.join(missing)}")
    if EXPECTED_CTEST not in cmake:
        errors.append(f"CMake does not register {EXPECTED_CTEST}")
    return errors


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
) -> list[dict[str, str]]:
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed"
            if runner.find_command(commands, name).get("return_code") == 0
            else "failed",
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
                "name": "ctest.checkpoint_contract_present",
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
                "status": "passed"
                if cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") == "OFF"
                else "failed",
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
    with tempfile.TemporaryDirectory(prefix="nids-t1.4-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = runner.run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        checks = assess(commands, cache, source_errors)

    for command in commands:
        command["log"] = str(Path(str(command["log"])).relative_to(source))
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
                {"path": path, "sha256": runner.sha256_file(source / path)}
                for path in SOURCE_FILES
            ],
            "contract_errors": list(source_errors),
        },
        "artifacts": {
            "directory": str(artifact_directory.relative_to(source)),
            "final_receipt": "run_log/t1.4/acceptance.json",
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
    if not isinstance(host, Mapping) or (
        host.get("system") != "Linux"
        or host.get("os_id") != "ubuntu"
        or not str(host.get("os_version", "")).startswith("24.04")
        or host.get("architecture") != "x86_64"
        or re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None
    ):
        errors.append("receipt host must be Ubuntu 24.04 x86_64 with Python 3.12.x")
    if document.get("contract") != EXPECTED_CONTRACT:
        errors.append("contract values do not match the approved T1.4 decisions")

    build = document.get("build")
    if not isinstance(build, Mapping) or not (
        build.get("configuration") == "Release"
        and build.get("testing_enabled") is True
        and build.get("toolchain_smoke_enabled") is False
        and build.get("temporary_workspace_outside_source") is True
        and build.get("offline_dependency_mode") is True
    ):
        errors.append("build flags do not match the T1.4 acceptance contract")

    commands = document.get("commands")
    if not isinstance(commands, list) or [
        command.get("name") for command in commands if isinstance(command, Mapping)
    ] != list(COMMAND_NAMES):
        errors.append("commands must contain the complete T1.4 pipeline in order")
    else:
        for command in commands:
            if not isinstance(command, Mapping):
                continue
            if not isinstance(command.get("log"), str):
                errors.append("every command must reference a log")
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
        if invalid:
            errors.append("every check must have passed or failed status")
        if "ctest.checkpoint_contract_present" not in names:
            errors.append("receipt must check the checkpoint contract CTest")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or [
        item.get("path") for item in files if isinstance(item, Mapping)
    ] != list(SOURCE_FILES):
        errors.append("source files must match the T1.4 checkpoint contract inputs")
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
    print("valid T1.4 source contract: F3/F5/F7/F9, 54 features, external packet prefix")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t1.4").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    missing_sources = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing_sources or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T1.4 project root: {source}")

    host = inspect_host()
    require_supported_host(host)
    runner.require_tools()
    attempt_directory = artifact_root / "attempts" / runner.attempt_name()
    attempt_directory.mkdir(parents=True, exist_ok=False)
    receipt = collect_receipt(source, attempt_directory, host)
    runner.write_new_json(attempt_directory / "receipt.json", receipt)
    print(f"wrote {attempt_directory / 'receipt.json'} ({receipt['status']})")
    if receipt["status"] == "passed":
        runner.write_new_json(final_receipt, receipt)
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
    check = subparsers.add_parser("check", help="validate T1.4 source contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T1.4 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t1.4")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T1.4 receipt")
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
