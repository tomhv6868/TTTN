#!/usr/bin/env python3
"""Build and verify the approved T1.2 flow contract on the locked Ubuntu host."""

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


SCHEMA_VERSION = "1.0.0"
TASK = "T1.2"
KIND = "flow_contract_acceptance"
EXPECTED_CTEST = "nids_core.flow_contract"
COMMAND_NAMES = runner.COMMAND_NAMES
SOURCE_FILES = (
    "CMakeLists.txt",
    "cpp/include/nids/packet.hpp",
    "cpp/include/nids/flow.hpp",
    "cpp/tests/flow_contract_test.cpp",
    "scripts/survey_cicids2017_flows.py",
    "tests/test_flow_survey.py",
)
SURVEY_FILE = "run_log/t1.2/flow-survey.json"


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
        raise RuntimeError("T1.2 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T1.2 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T1.2 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T1.2 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T1.2 verification requires Python 3.12.x")


def load_survey(source: Path) -> dict[str, Any]:
    path = source / SURVEY_FILE
    document = runner.load_json(path)
    if not isinstance(document, dict):
        raise ValueError(f"survey receipt must be an object: {path}")
    return document


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    survey: Mapping[str, Any],
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
    totals = survey.get("totals") if isinstance(survey.get("totals"), Mapping) else {}
    settings = survey.get("settings") if isinstance(survey.get("settings"), Mapping) else {}
    checks.extend(
        (
            {
                "name": "ctest.flow_contract_present",
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
            {
                "name": "survey.passed",
                "status": "passed" if survey.get("status") == "passed" else "failed",
            },
            {
                "name": "survey.packet_count",
                "status": "passed"
                if totals.get("packet_count") == 56_370_702
                else "failed",
            },
            {
                "name": "survey.approved_candidates_present",
                "status": "passed"
                if 60 in settings.get("idle_timeout_candidates_seconds", [])
                and 1_800 in settings.get("max_age_candidates_seconds", [])
                else "failed",
            },
            {
                "name": "survey.capacity_headroom",
                "status": "passed"
                if isinstance(totals.get("active_flow_peak"), int)
                and 0 < totals["active_flow_peak"] <= 65_536
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
    survey = load_survey(source)
    with tempfile.TemporaryDirectory(prefix="nids-t1.2-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = runner.run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        checks = assess(commands, cache, survey)

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
        },
        "survey": {
            "path": SURVEY_FILE,
            "sha256": runner.sha256_file(source / SURVEY_FILE),
            "packet_count": survey["totals"]["packet_count"],
            "reference_flow_count": survey["totals"]["reference_flow_count"],
            "active_flow_peak": survey["totals"]["active_flow_peak"],
        },
        "artifacts": {
            "directory": str(artifact_directory.relative_to(source)),
            "final_receipt": "run_log/t1.2/acceptance.json",
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
        "contract": {
            "idle_timeout_seconds": 60,
            "maximum_age_seconds": 1_800,
            "hard_active_flow_limit": 65_536,
            "memory_budget_bytes": 256 * 1024 * 1024,
        },
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

    contract = document.get("contract")
    expected_contract = {
        "idle_timeout_seconds": 60,
        "maximum_age_seconds": 1_800,
        "hard_active_flow_limit": 65_536,
        "memory_budget_bytes": 256 * 1024 * 1024,
    }
    if contract != expected_contract:
        errors.append("contract values do not match the approved T1.2 values")

    build = document.get("build")
    if not isinstance(build, Mapping) or not (
        build.get("configuration") == "Release"
        and build.get("testing_enabled") is True
        and build.get("toolchain_smoke_enabled") is False
        and build.get("temporary_workspace_outside_source") is True
        and build.get("offline_dependency_mode") is True
    ):
        errors.append("build flags do not match the T1.2 acceptance contract")

    commands = document.get("commands")
    if not isinstance(commands, list) or [
        command.get("name") for command in commands if isinstance(command, Mapping)
    ] != list(COMMAND_NAMES):
        errors.append("commands must contain the complete T1.2 pipeline in order")
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
        if "ctest.flow_contract_present" not in names:
            errors.append("receipt must check the flow contract CTest")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or [
        item.get("path") for item in files if isinstance(item, Mapping)
    ] != list(SOURCE_FILES):
        errors.append("source files must match the T1.2 flow contract inputs")
    elif any(
        re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None
        for item in files
    ):
        errors.append("every source file must have a lowercase SHA-256")

    survey = document.get("survey")
    if not isinstance(survey, Mapping) or (
        survey.get("path") != SURVEY_FILE
        or survey.get("packet_count") != 56_370_702
        or not isinstance(survey.get("active_flow_peak"), int)
        or survey["active_flow_peak"] > 65_536
        or re.fullmatch(r"[0-9a-f]{64}", str(survey.get("sha256", ""))) is None
    ):
        errors.append("survey evidence is missing or inconsistent")

    timestamp = document.get("generated_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    return errors


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t1.2").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    missing_sources = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing_sources or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T1.2 project root: {source}")

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
    run = subparsers.add_parser("run", help="perform a clean T1.2 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t1.2")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T1.2 receipt")
    validate.add_argument("--input", required=True, type=Path)
    validate.set_defaults(handler=command_validate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
