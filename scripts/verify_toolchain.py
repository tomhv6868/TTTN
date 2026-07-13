#!/usr/bin/env python3
"""Collect and validate T0.2 toolchain verification receipts."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
REQUIRED_DPDK_EXECUTABLES = ("dpdk-testpmd", "dpdk-dumpcap")
REQUIRED_DPDK_CHECKS = {
    "dpdk.install_marker",
    "dpdk.testpmd_linkage",
    "dpdk.dumpcap_linkage",
}


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


def build_options_fingerprint(options: Any) -> str | None:
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        return None
    encoded = json.dumps(options, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_lock(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["lock root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    if document.get("task") != "T0.2":
        errors.append("task must equal T0.2")
    target = document.get("target")
    if not isinstance(target, Mapping):
        errors.append("target must be an object")
    else:
        for key in ("os_id", "os_version_prefix", "architecture"):
            if not isinstance(target.get(key), str) or not target.get(key):
                errors.append(f"target.{key} must be a non-empty string")
    for component in ("dpdk", "onnxruntime"):
        artifact = document.get(component)
        if not isinstance(artifact, Mapping):
            errors.append(f"{component} must be an object")
            continue
        for key in ("version", "url", "archive_name", "archive_root", "sha256", "install_subdir"):
            if not isinstance(artifact.get(key), str) or not artifact.get(key):
                errors.append(f"{component}.{key} must be a non-empty string")
        if isinstance(artifact.get("url"), str) and not artifact["url"].startswith("https://"):
            errors.append(f"{component}.url must use HTTPS")
        if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))):
            errors.append(f"{component}.sha256 must be lowercase SHA-256")
        if not isinstance(artifact.get("size_bytes"), int) or artifact.get("size_bytes", 0) <= 0:
            errors.append(f"{component}.size_bytes must be a positive integer")
    dpdk = document.get("dpdk")
    if isinstance(dpdk, Mapping):
        options = dpdk.get("meson_options")
        fingerprint = build_options_fingerprint(options)
        if fingerprint is None:
            errors.append("dpdk.meson_options must be an array of strings")
        elif dpdk.get("build_options_sha256") != fingerprint:
            errors.append("dpdk.build_options_sha256 must match canonical meson_options")
        if not isinstance(options, list) or "-Denable_apps=test-pmd,dumpcap" not in options:
            errors.append("dpdk.meson_options must enable test-pmd and dumpcap")
        if dpdk.get("required_executables") != list(REQUIRED_DPDK_EXECUTABLES):
            errors.append("dpdk.required_executables must lock dpdk-testpmd and dpdk-dumpcap")
    packages = document.get("apt_packages")
    if not isinstance(packages, list) or not packages or not all(isinstance(item, str) for item in packages):
        errors.append("apt_packages must be a non-empty array of strings")
    elif len(packages) != len(set(packages)):
        errors.append("apt_packages must not contain duplicates")
    acceptance = document.get("acceptance")
    if not isinstance(acceptance, Mapping):
        errors.append("acceptance must be an object")
    elif acceptance.get("cxx_standard") != 20:
        errors.append("acceptance.cxx_standard must equal 20")
    return errors


def run_command(arguments: Sequence[str], timeout: float = 15.0) -> dict[str, Any]:
    executable = shutil.which(arguments[0])
    if executable is None:
        return {"available": False, "return_code": None, "stdout": "", "stderr": "command not found"}
    try:
        completed = subprocess.run(
            [executable, *arguments[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "available": False,
            "return_code": None,
            "stdout": "",
            "stderr": type(error).__name__,
        }
    return {
        "available": True,
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def parse_os_release() -> dict[str, str]:
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


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+)+", value)
    return tuple(int(component) for component in match.group(0).split(".")) if match else ()


def version_at_least(observed: str, minimum: str) -> bool:
    observed_parts = version_tuple(observed)
    minimum_parts = version_tuple(minimum)
    length = max(len(observed_parts), len(minimum_parts))
    return observed_parts + (0,) * (length - len(observed_parts)) >= minimum_parts + (0,) * (
        length - len(minimum_parts)
    )


def command_version(arguments: Sequence[str], pattern: str | None = None) -> tuple[str | None, str]:
    result = run_command(arguments)
    combined = result.get("stdout") or result.get("stderr") or ""
    if not result.get("available") or result.get("return_code") != 0:
        return None, combined
    if pattern:
        match = re.search(pattern, combined)
        return (match.group(1) if match else None), combined
    first_line = combined.splitlines()[0] if combined else ""
    return first_line.strip() or None, combined


def inspect_dynamic_executable(
    name: str,
    expected_directory: Path | None = None,
) -> tuple[bool, dict[str, Any], str | None]:
    """Check an ELF executable and its shared-library resolution without running it."""
    path = shutil.which(name)
    if path is None:
        return False, {"path": None, "missing_dependencies": []}, "executable not found in PATH"
    executable = Path(path)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        return False, {"path": path, "missing_dependencies": []}, "path is not an executable file"
    if expected_directory is not None and executable.resolve().parent != expected_directory.resolve():
        return (
            False,
            {"path": path, "missing_dependencies": []},
            f"executable is outside locked directory: {expected_directory}",
        )

    linkage = run_command(("ldd", path))
    output = linkage.get("stdout") or ""
    missing = [line.strip() for line in output.splitlines() if "not found" in line]
    passed = linkage.get("available") is True and linkage.get("return_code") == 0 and not missing
    observed = {
        "path": path,
        "ldd_return_code": linkage.get("return_code"),
        "missing_dependencies": missing,
    }
    detail_parts = [part for part in (output, linkage.get("stderr") or "") if part]
    return passed, observed, "\n".join(detail_parts) or None


def load_marker(prefix: str | None) -> Any:
    if not prefix:
        return None
    path = Path(prefix) / ".nids-artifact.json"
    return load_json(path) if path.is_file() else None


def collect_apt_versions(packages: Sequence[str]) -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for package in packages:
        result = run_command(("dpkg-query", "-W", "-f=${Version}", package))
        versions[package] = result.get("stdout") if result.get("return_code") == 0 else None
    return versions


def collect_receipt(lock_path: Path, smoke_binary: Path) -> dict[str, Any]:
    lock = load_json(lock_path)
    lock_errors = validate_lock(lock)
    if lock_errors:
        raise ValueError("invalid toolchain lock: " + "; ".join(lock_errors))

    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, expected: Any, observed: Any, detail: str | None = None) -> None:
        entry = {
            "name": name,
            "status": "passed" if passed else "failed",
            "expected": expected,
            "observed": observed,
        }
        if detail:
            entry["detail"] = detail
        checks.append(entry)

    os_release = parse_os_release()
    target = lock["target"]
    check("target.os", os_release.get("ID") == target["os_id"], target["os_id"], os_release.get("ID"))
    check(
        "target.os_version",
        str(os_release.get("VERSION_ID", "")).startswith(target["os_version_prefix"]),
        target["os_version_prefix"] + ".x",
        os_release.get("VERSION_ID"),
    )
    architecture = platform.machine()
    check("target.architecture", architecture == target["architecture"], target["architecture"], architecture)

    gxx, gxx_raw = command_version(("g++", "-dumpfullversion", "-dumpversion"))
    cmake, cmake_raw = command_version(("cmake", "--version"), r"cmake version\s+([^\s]+)")
    meson, meson_raw = command_version(("meson", "--version"))
    ninja, ninja_raw = command_version(("ninja", "--version"))
    pkg_config, pkg_config_raw = command_version(("pkg-config", "--version"))
    python_version = platform.python_version()
    acceptance = lock["acceptance"]
    check("compiler.g++", bool(gxx) and version_at_least(gxx, "10.0"), ">=10.0", gxx, gxx_raw or None)
    check(
        "build.cmake",
        bool(cmake) and version_at_least(cmake, acceptance["cmake_minimum"]),
        f">={acceptance['cmake_minimum']}",
        cmake,
        cmake_raw or None,
    )
    check(
        "build.meson",
        bool(meson) and version_at_least(meson, acceptance["meson_minimum"]),
        f">={acceptance['meson_minimum']}",
        meson,
        meson_raw or None,
    )
    check("build.ninja", bool(ninja), "available", ninja, ninja_raw or None)
    check("build.pkg_config", bool(pkg_config), "available", pkg_config, pkg_config_raw or None)
    check(
        "python.version",
        python_version.startswith(acceptance["python_major_minor"] + "."),
        acceptance["python_major_minor"] + ".x",
        python_version,
    )

    dpdk_version, dpdk_raw = command_version(("pkg-config", "--modversion", "libdpdk"))
    ort_version, ort_raw = command_version(("pkg-config", "--modversion", "onnxruntime"))
    check("dpdk.pkg_config_version", dpdk_version == lock["dpdk"]["version"], lock["dpdk"]["version"], dpdk_version, dpdk_raw or None)
    check(
        "onnxruntime.pkg_config_version",
        ort_version == lock["onnxruntime"]["version"],
        lock["onnxruntime"]["version"],
        ort_version,
        ort_raw or None,
    )

    dpdk_root = os.environ.get("DPDK_ROOT")
    ort_root = os.environ.get("ONNXRUNTIME_ROOT")
    expected_dpdk_suffix = lock["dpdk"]["install_subdir"]
    expected_ort_suffix = lock["onnxruntime"]["install_subdir"]
    check("environment.DPDK_ROOT", bool(dpdk_root) and dpdk_root.endswith(expected_dpdk_suffix), expected_dpdk_suffix, dpdk_root)
    check("environment.ONNXRUNTIME_ROOT", bool(ort_root) and ort_root.endswith(expected_ort_suffix), expected_ort_suffix, ort_root)

    for component, root, artifact in (
        ("dpdk", dpdk_root, lock["dpdk"]),
        ("onnxruntime", ort_root, lock["onnxruntime"]),
    ):
        try:
            marker = load_marker(root)
        except ValueError as error:
            marker = None
            marker_detail = str(error)
        else:
            marker_detail = None
        expected_marker = {
            "component": component,
            "version": artifact["version"],
            "source_sha256": artifact["sha256"],
        }
        if component == "dpdk":
            expected_marker["build_options_sha256"] = artifact["build_options_sha256"]
        marker_passed = isinstance(marker, Mapping) and all(
            marker.get(key) == value for key, value in expected_marker.items()
        )
        check(
            f"{component}.install_marker",
            marker_passed,
            expected_marker,
            marker,
            marker_detail,
        )

    expected_dpdk_bin = Path(dpdk_root) / "bin" if dpdk_root else None
    for executable_name in lock["dpdk"]["required_executables"]:
        executable_passed, executable_observed, executable_detail = inspect_dynamic_executable(
            executable_name,
            expected_dpdk_bin,
        )
        check_name = executable_name.removeprefix("dpdk-").replace("-", "_")
        check(
            f"dpdk.{check_name}_linkage",
            executable_passed,
            "locked-prefix executable with all dynamic dependencies resolved",
            executable_observed,
            executable_detail,
        )

    ort_library = Path(ort_root or "") / "lib" / "libonnxruntime.so"
    ort_load_detail = None
    ort_load_passed = False
    try:
        if ort_root and ort_library.is_file():
            library = ctypes.CDLL(str(ort_library))
            getattr(library, "OrtGetApiBase")
            ort_load_passed = True
    except (OSError, AttributeError) as error:
        ort_load_detail = str(error)
    check("onnxruntime.dynamic_load", ort_load_passed, "OrtGetApiBase symbol", str(ort_library), ort_load_detail)

    smoke_result = run_command((str(smoke_binary),), timeout=30.0) if smoke_binary.is_file() else {
        "available": False,
        "return_code": None,
        "stdout": "",
        "stderr": "smoke binary not found",
    }
    smoke_output = smoke_result.get("stdout", "")
    smoke_passed = (
        smoke_result.get("return_code") == 0
        and lock["dpdk"]["version"] in smoke_output
        and lock["onnxruntime"]["version"] in smoke_output
    )
    check(
        "smoke.runtime",
        smoke_passed,
        f"DPDK {lock['dpdk']['version']} and ONNX Runtime {lock['onnxruntime']['version']}",
        smoke_output or None,
        smoke_result.get("stderr") or None,
    )

    apt_versions = collect_apt_versions(lock["apt_packages"])
    for package, version in apt_versions.items():
        check(f"apt.{package}", bool(version), "installed", version)

    status = "passed" if all(item["status"] == "passed" for item in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": "T0.2",
        "status": status,
        "generated_at_utc": utc_now(),
        "lock": {
            "file": lock_path.name,
            "sha256": sha256_file(lock_path),
            "dpdk_version": lock["dpdk"]["version"],
            "dpdk_build_options_sha256": lock["dpdk"]["build_options_sha256"],
            "onnxruntime_version": lock["onnxruntime"]["version"],
        },
        "host": {
            "hostname": socket.gethostname(),
            "os_id": os_release.get("ID"),
            "os_version": os_release.get("VERSION_ID"),
            "kernel": platform.release(),
            "architecture": architecture,
        },
        "toolchain": {
            "g++": gxx,
            "cmake": cmake,
            "meson": meson,
            "ninja": ninja,
            "pkg_config": pkg_config,
            "python": python_version,
            "dpdk": dpdk_version,
            "onnxruntime": ort_version,
        },
        "apt_packages": apt_versions,
        "smoke": {
            "binary": smoke_binary.name,
            "return_code": smoke_result.get("return_code"),
            "stdout": smoke_output,
            "stderr": smoke_result.get("stderr", ""),
        },
        "checks": checks,
    }


def validate_receipt(
    document: Any,
    lock: Mapping[str, Any] | None = None,
    lock_sha256: str | None = None,
) -> list[str]:
    if not isinstance(document, Mapping):
        return ["receipt root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    if document.get("task") != "T0.2":
        errors.append("task must equal T0.2")
    if document.get("status") not in ("passed", "failed"):
        errors.append("status must be passed or failed")
    for key in ("lock", "host", "toolchain", "apt_packages", "smoke"):
        if not isinstance(document.get(key), Mapping):
            errors.append(f"{key} must be an object")
    receipt_lock = document.get("lock")
    if isinstance(receipt_lock, Mapping):
        for key in ("sha256", "dpdk_build_options_sha256"):
            if re.fullmatch(r"[0-9a-f]{64}", str(receipt_lock.get(key, ""))) is None:
                errors.append(f"lock.{key} must be a lowercase SHA-256")
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty array")
    else:
        invalid = [item for item in checks if not isinstance(item, Mapping) or item.get("status") not in ("passed", "failed")]
        if invalid:
            errors.append("every check must be an object with passed/failed status")
        names = {item.get("name") for item in checks if isinstance(item, Mapping)}
        if not REQUIRED_DPDK_CHECKS.issubset(names):
            errors.append("receipt must check the DPDK marker and both app linkages")
        all_passed = not invalid and all(item.get("status") == "passed" for item in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")
    timestamp = document.get("generated_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    if document.get("sample") is True and not isinstance(document.get("sample_notice"), str):
        errors.append("sample receipts must carry a sample_notice")
    if lock is not None and isinstance(document.get("apt_packages"), Mapping):
        missing = sorted(set(lock.get("apt_packages", [])) - set(document["apt_packages"]))
        if missing:
            errors.append("receipt is missing APT packages: " + ", ".join(missing))
        if isinstance(receipt_lock, Mapping):
            if receipt_lock.get("dpdk_version") != lock.get("dpdk", {}).get("version"):
                errors.append("receipt DPDK version does not match lock")
            if receipt_lock.get("dpdk_build_options_sha256") != lock.get("dpdk", {}).get(
                "build_options_sha256"
            ):
                errors.append("receipt DPDK build-options fingerprint does not match lock")
            if receipt_lock.get("onnxruntime_version") != lock.get("onnxruntime", {}).get("version"):
                errors.append("receipt ONNX Runtime version does not match lock")
            if lock_sha256 is not None and receipt_lock.get("sha256") != lock_sha256:
                errors.append("receipt lock SHA-256 does not match lock file")
    return errors


def write_new_file(path: Path, document: Mapping[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"refusing to overwrite existing file: {path}; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def command_collect(args: argparse.Namespace) -> int:
    if platform.system() != "Linux":
        raise RuntimeError("toolchain verification must run inside the Ubuntu Linux VM")
    receipt = collect_receipt(args.lock, args.smoke_binary)
    write_new_file(args.output, receipt, args.force)
    print(f"wrote {args.output} ({receipt['status']})")
    if receipt["status"] != "passed":
        for item in receipt["checks"]:
            if item["status"] == "failed":
                print(f"failed: {item['name']} (observed={item.get('observed')!r})", file=sys.stderr)
        return 1
    return 0


def command_validate(args: argparse.Namespace) -> int:
    receipt = load_json(args.input)
    lock = load_json(args.lock) if args.lock else None
    if lock is not None:
        lock_errors = validate_lock(lock)
        if lock_errors:
            raise ValueError("invalid toolchain lock: " + "; ".join(lock_errors))
    lock_sha256 = sha256_file(args.lock) if args.lock else None
    errors = validate_receipt(receipt, lock, lock_sha256)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid receipt: {args.input} ({receipt['status']})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect", help="collect a receipt on the configured Ubuntu VM")
    collect.add_argument("--lock", required=True, type=Path)
    collect.add_argument("--smoke-binary", required=True, type=Path)
    collect.add_argument("--output", required=True, type=Path)
    collect.add_argument("--force", action="store_true")
    collect.set_defaults(handler=command_collect)
    validate = subparsers.add_parser("validate", help="validate a saved receipt")
    validate.add_argument("--input", required=True, type=Path)
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
