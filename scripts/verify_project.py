#!/usr/bin/env python3
"""Build and verify the T0.5 project in a clean, offline workspace."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T0.5"
KIND = "project_acceptance"
LOCKED_DPDK_VERSION = "25.11.2"
LOCKED_ONNXRUNTIME_VERSION = "1.27.1"
COMMAND_NAMES = ("configure", "build", "ctest", "python_unittest")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def validate_lock(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["lock root must be an object"]
    errors: list[str] = []
    target = document.get("target")
    dpdk = document.get("dpdk")
    onnxruntime = document.get("onnxruntime")
    if document.get("task") != "T0.2":
        errors.append("lock task must equal T0.2")
    if not isinstance(target, Mapping):
        errors.append("lock target must be an object")
    elif (
        target.get("os_id") != "ubuntu"
        or target.get("os_version_prefix") != "24.04"
        or target.get("architecture") != "x86_64"
    ):
        errors.append("lock target must be Ubuntu 24.04 x86_64")
    if not isinstance(dpdk, Mapping) or dpdk.get("version") != LOCKED_DPDK_VERSION:
        errors.append(f"lock DPDK version must equal {LOCKED_DPDK_VERSION}")
    if not isinstance(onnxruntime, Mapping) or onnxruntime.get("version") != LOCKED_ONNXRUNTIME_VERSION:
        errors.append(f"lock ONNX Runtime version must equal {LOCKED_ONNXRUNTIME_VERSION}")
    return errors


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
        raise RuntimeError("project verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("project verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("project verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("project verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("project verification requires Python 3.12.x")


def run_command(name: str, arguments: Sequence[str], cwd: Path, timeout: float) -> dict[str, Any]:
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
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "name": name,
            "arguments": list(arguments),
            "return_code": None,
            "stdout": "",
            "stderr": f"{type(error).__name__}: {error}",
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    return {
        "name": name,
        "arguments": list(arguments),
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def skipped_command(name: str, reason: str) -> dict[str, Any]:
    return {
        "name": name,
        "arguments": [],
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "duration_seconds": 0.0,
        "skipped": reason,
    }


def run_pipeline(source: Path, build: Path) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
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
            "-DNIDS_BUILD_TOOLCHAIN_SMOKE=ON",
        ),
        source,
        300.0,
    )
    commands.append(configure)
    if configure["return_code"] == 0:
        build_result = run_command("build", ("cmake", "--build", str(build), "--parallel", "2"), source, 900.0)
        commands.append(build_result)
    else:
        build_result = skipped_command("build", "configure failed")
        commands.append(build_result)

    if build_result["return_code"] == 0:
        commands.append(
            run_command(
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
                600.0,
            )
        )
    else:
        commands.append(skipped_command("ctest", "build failed or was skipped"))

    commands.append(
        run_command(
            "python_unittest",
            (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
            source,
            600.0,
        )
    )
    return commands


def find_command(commands: Sequence[Mapping[str, Any]], name: str) -> Mapping[str, Any]:
    return next((command for command in commands if command.get("name") == name), {})


def collect_receipt(source: Path, lock_path: Path, host: Mapping[str, Any]) -> dict[str, Any]:
    lock = load_json(lock_path)
    lock_errors = validate_lock(lock)
    if lock_errors:
        raise ValueError("invalid toolchain lock: " + "; ".join(lock_errors))

    with tempfile.TemporaryDirectory(prefix="nids-t0.5-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build)

    ctest = find_command(commands, "ctest")
    ctest_output = "\n".join((str(ctest.get("stdout", "")), str(ctest.get("stderr", ""))))
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed" if find_command(commands, name).get("return_code") == 0 else "failed",
        }
        for name in COMMAND_NAMES
    ]
    checks.extend(
        (
            {
                "name": "ctest.toolchain_runtime",
                "status": "passed" if "toolchain_runtime" in ctest_output else "failed",
            },
            {
                "name": "runtime.dpdk_version",
                "status": "passed" if f"DPDK {LOCKED_DPDK_VERSION}" in ctest_output else "failed",
                "expected": LOCKED_DPDK_VERSION,
            },
            {
                "name": "runtime.onnxruntime_version",
                "status": "passed"
                if f"ONNX Runtime {LOCKED_ONNXRUNTIME_VERSION}" in ctest_output
                else "failed",
                "expected": LOCKED_ONNXRUNTIME_VERSION,
            },
        )
    )
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "status": status,
        "generated_at_utc": utc_now(),
        "host": dict(host),
        "source": {"path": str(source)},
        "lock": {
            "path": str(lock_path),
            "sha256": sha256_file(lock_path),
            "dpdk_version": lock["dpdk"]["version"],
            "onnxruntime_version": lock["onnxruntime"]["version"],
        },
        "build": {
            "generator": "Ninja",
            "configuration": "Release",
            "runtime_smoke_enabled": True,
            "temporary_workspace_outside_source": True,
            "temporary_workspace_retained": False,
            "offline_dependency_mode": True,
        },
        "commands": commands,
        "checks": checks,
    }


def validate_receipt(
    document: Any,
    lock: Mapping[str, Any] | None = None,
    expected_lock_sha256: str | None = None,
) -> list[str]:
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
    elif not all(
        build.get(key) is True
        for key in ("runtime_smoke_enabled", "temporary_workspace_outside_source", "offline_dependency_mode")
    ):
        errors.append("build safety and runtime-smoke flags must be enabled")
    commands = document.get("commands")
    if not isinstance(commands, list):
        errors.append("commands must be an array")
    elif [command.get("name") for command in commands if isinstance(command, Mapping)] != list(COMMAND_NAMES):
        errors.append("commands must contain the complete verification pipeline in order")
    elif document.get("status") == "passed" and any(command.get("return_code") != 0 for command in commands):
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
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")
    timestamp = document.get("generated_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    receipt_lock = document.get("lock")
    if not isinstance(receipt_lock, Mapping):
        errors.append("lock must be an object")
    else:
        if receipt_lock.get("dpdk_version") != LOCKED_DPDK_VERSION:
            errors.append("receipt DPDK version does not match the project lock")
        if receipt_lock.get("onnxruntime_version") != LOCKED_ONNXRUNTIME_VERSION:
            errors.append("receipt ONNX Runtime version does not match the project lock")
        digest = receipt_lock.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            errors.append("receipt lock sha256 must be lowercase SHA-256")
        elif expected_lock_sha256 is not None and digest != expected_lock_sha256:
            errors.append("receipt lock sha256 does not match the supplied lock file")
    if lock is not None:
        lock_errors = validate_lock(lock)
        if lock_errors:
            errors.extend("invalid supplied lock: " + error for error in lock_errors)
    return errors


def write_new_receipt(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite existing file: {path}") from error


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    lock_path = args.lock.resolve()
    output = args.output.resolve()
    artifact_root = (source / "run_log" / "t0.5").resolve()
    if output == artifact_root or artifact_root not in output.parents:
        raise ValueError(f"output must be a file below {artifact_root}")
    if os.path.lexists(output):
        raise ValueError(f"refusing to overwrite existing file: {output}")
    if not all(
        (
            (source / ".git").is_dir(),
            (source / ".gitignore").is_file(),
            (source / "CMakeLists.txt").is_file(),
            (source / "tests").is_dir(),
        )
    ):
        raise ValueError(f"source is not a T0.5 project root: {source}")
    if lock_path != (source / "config" / "toolchain.lock.json").resolve():
        raise ValueError("verification must use the version-controlled project toolchain lock")
    host = inspect_host()
    require_supported_host(host)
    receipt = collect_receipt(source, lock_path, host)
    write_new_receipt(output, receipt)
    print(f"wrote {output} ({receipt['status']})")
    if receipt["status"] == "failed":
        for check in receipt["checks"]:
            if check["status"] == "failed":
                print(f"failed: {check['name']}", file=sys.stderr)
        return 1
    return 0


def command_validate(args: argparse.Namespace) -> int:
    receipt = load_json(args.input)
    lock = load_json(args.lock) if args.lock else None
    lock_sha256 = sha256_file(args.lock) if args.lock else None
    errors = validate_receipt(receipt, lock, lock_sha256)
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
    run = subparsers.add_parser("run", help="perform a clean Ubuntu project verification")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--lock", type=Path, default=project_root / "config" / "toolchain.lock.json")
    run.add_argument("--output", type=Path, default=project_root / "run_log" / "t0.5" / "acceptance.json")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T0.5 receipt")
    validate.add_argument("--input", type=Path, required=True)
    validate.add_argument("--lock", type=Path)
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
