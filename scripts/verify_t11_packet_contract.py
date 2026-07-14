#!/usr/bin/env python3
"""Build and verify the T1.1 packet contract on the locked Ubuntu host."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T1.1"
KIND = "packet_contract_acceptance"
EXPECTED_CTEST = "nids_core.packet_contract"
COMMAND_NAMES = ("configure", "build", "ctest", "python_unittest")
SOURCE_FILES = (
    "CMakeLists.txt",
    "cpp/include/nids/packet.hpp",
    "cpp/tests/packet_contract_test.cpp",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def attempt_name() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"ubuntu-acceptance-{stamp}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        content = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in content.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def inspect_host() -> dict[str, Any]:
    os_release = read_os_release()
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
        raise RuntimeError("T1.1 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T1.1 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T1.1 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T1.1 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T1.1 verification requires Python 3.12.x")


def write_command_log(
    path: Path,
    arguments: Sequence[str],
    return_code: int | None,
    duration_seconds: float,
    stdout: str,
    stderr: str,
    skipped: str | None = None,
) -> None:
    lines = [
        f"command: {shlex.join(arguments)}" if arguments else "command: <not run>",
        f"return_code: {return_code}",
        f"duration_seconds: {duration_seconds:.3f}",
    ]
    if skipped is not None:
        lines.append(f"skipped: {skipped}")
    lines.extend(("--- stdout ---", stdout, "--- stderr ---", stderr, ""))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            output.write("\n".join(lines))
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite existing log: {path}") from error


def run_command(
    name: str,
    arguments: Sequence[str],
    cwd: Path,
    log_path: Path,
    timeout: float,
) -> dict[str, Any]:
    started = time.monotonic()
    environment = {
        **os.environ,
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "FETCHCONTENT_FULLY_DISCONNECTED": "ON",
    }
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return_code = completed.returncode
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
    except (OSError, subprocess.SubprocessError) as error:
        return_code = None
        stdout = ""
        stderr = f"{type(error).__name__}: {error}"
    duration = round(time.monotonic() - started, 3)
    write_command_log(log_path, arguments, return_code, duration, stdout, stderr)
    return {
        "name": name,
        "arguments": list(arguments),
        "return_code": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_seconds": duration,
        "log": str(log_path),
        "log_sha256": sha256_file(log_path),
    }


def skipped_command(name: str, reason: str, log_path: Path) -> dict[str, Any]:
    write_command_log(log_path, (), None, 0.0, "", "", skipped=reason)
    return {
        "name": name,
        "arguments": [],
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "duration_seconds": 0.0,
        "skipped": reason,
        "log": str(log_path),
        "log_sha256": sha256_file(log_path),
    }


def run_pipeline(source: Path, build: Path, artifact_directory: Path) -> list[dict[str, Any]]:
    configure = run_command(
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
        artifact_directory / "configure.log",
        300.0,
    )
    commands = [configure]

    if configure["return_code"] == 0:
        build_result = run_command(
            "build",
            ("cmake", "--build", str(build), "--parallel", "2"),
            source,
            artifact_directory / "build.log",
            900.0,
        )
    else:
        build_result = skipped_command("build", "configure failed", artifact_directory / "build.log")
    commands.append(build_result)

    if build_result["return_code"] == 0:
        ctest = run_command(
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
            artifact_directory / "ctest.log",
            600.0,
        )
    else:
        ctest = skipped_command("ctest", "build failed or was skipped", artifact_directory / "ctest.log")
    commands.append(ctest)

    commands.append(
        run_command(
            "python_unittest",
            (sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"),
            source,
            artifact_directory / "python-unittest.log",
            600.0,
        )
    )
    return commands


def find_command(commands: Sequence[Mapping[str, Any]], name: str) -> Mapping[str, Any]:
    return next((command for command in commands if command.get("name") == name), {})


def read_cmake_cache(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        if not line or line.startswith(("#", "//")) or "=" not in line or ":" not in line:
            continue
        name_and_type, value = line.split("=", 1)
        name, _ = name_and_type.split(":", 1)
        values[name] = value
    return values


def assess(commands: Sequence[Mapping[str, Any]], cache: Mapping[str, str]) -> list[dict[str, str]]:
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed" if find_command(commands, name).get("return_code") == 0 else "failed",
        }
        for name in COMMAND_NAMES
    ]
    ctest = find_command(commands, "ctest")
    ctest_output = "\n".join((str(ctest.get("stdout", "")), str(ctest.get("stderr", ""))))
    checks.extend(
        (
            {
                "name": "ctest.packet_contract_present",
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
    with tempfile.TemporaryDirectory(prefix="nids-t1.1-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifact_directory)
        cache = read_cmake_cache(build / "CMakeCache.txt")
        checks = assess(commands, cache)

    for command in commands:
        command["log"] = str(Path(str(command["log"])).relative_to(source))
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "status": status,
        "generated_at_utc": utc_now(),
        "host": dict(host),
        "source": {
            "path": str(source),
            "files": [
                {"path": path, "sha256": sha256_file(source / path)}
                for path in SOURCE_FILES
            ],
        },
        "artifacts": {
            "directory": str(artifact_directory.relative_to(source)),
            "final_receipt": "run_log/t1.1/acceptance.json",
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
    if not isinstance(host, Mapping):
        errors.append("host must be an object")
    elif (
        host.get("system") != "Linux"
        or host.get("os_id") != "ubuntu"
        or not str(host.get("os_version", "")).startswith("24.04")
        or host.get("architecture") != "x86_64"
        or re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None
    ):
        errors.append("receipt host must be Ubuntu 24.04 x86_64 with Python 3.12.x")

    build = document.get("build")
    if not isinstance(build, Mapping):
        errors.append("build must be an object")
    elif not (
        build.get("configuration") == "Release"
        and build.get("testing_enabled") is True
        and build.get("toolchain_smoke_enabled") is False
        and build.get("temporary_workspace_outside_source") is True
        and build.get("offline_dependency_mode") is True
    ):
        errors.append("build flags do not match the T1.1 acceptance contract")

    commands = document.get("commands")
    if not isinstance(commands, list):
        errors.append("commands must be an array")
    elif [command.get("name") for command in commands if isinstance(command, Mapping)] != list(COMMAND_NAMES):
        errors.append("commands must contain the complete T1.1 pipeline in order")
    else:
        for command in commands:
            if not isinstance(command, Mapping):
                continue
            if not isinstance(command.get("log"), str):
                errors.append("every command must reference a log")
            digest = command.get("log_sha256")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                errors.append("every command log must have a lowercase SHA-256")
        if document.get("status") == "passed" and any(command.get("return_code") != 0 for command in commands):
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
        if invalid:
            errors.append("every check must have passed or failed status")
        names = {check.get("name") for check in checks if isinstance(check, Mapping)}
        if "ctest.packet_contract_present" not in names:
            errors.append("receipt must check the packet contract CTest")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, Mapping)] != list(SOURCE_FILES):
        errors.append("source files must match the T1.1 packet contract inputs")
    elif any(
        not isinstance(item.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
        for item in files
    ):
        errors.append("every source file must have a lowercase SHA-256")

    timestamp = document.get("generated_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    return errors


def write_new_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite existing file: {path}") from error


def require_tools() -> None:
    missing = [name for name in ("cmake", "ninja", "c++", "ctest") if shutil.which(name) is None]
    if missing:
        names = ", ".join(missing)
        raise RuntimeError(
            f"missing required tools: {names}; source $HOME/.local/nids-toolchain/env.sh first"
        )


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t1.1").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    missing_sources = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing_sources or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T1.1 project root: {source}")

    host = inspect_host()
    require_supported_host(host)
    require_tools()

    attempt_directory = artifact_root / "attempts" / attempt_name()
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
    receipt = load_json(args.input)
    errors = validate_receipt(receipt)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid receipt: {args.input} ({receipt['status']})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="perform a clean T1.1 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t1.1")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T1.1 receipt")
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
