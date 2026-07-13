#!/usr/bin/env python3
"""Run bounded commands on the VMware NIDS lab over non-interactive SSH."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, TextIO


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "config/lab-hosts.json"
ROLES = ("kali", "ubuntu", "windows")
ALIAS_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TOP_LEVEL_FIELDS = {"schema_version", "vmrun", "ssh", "timeouts", "hosts"}
TIMEOUT_FIELDS = {"discovery_seconds", "connect_seconds", "command_seconds"}
HOST_FIELDS = {"alias", "vmx"}
DISCOVERY_CONFIRMATION_REASON = "dhcp_discovery_unavailable"
VMX_SETTING_PATTERN = re.compile(
    r'^\s*ethernet(?P<index>[0-9]+)\.(?P<name>[A-Za-z]+)'
    r'\s*=\s*"(?P<value>[^"]*)"\s*$',
    re.IGNORECASE,
)
LEASE_BLOCK_PATTERN = re.compile(
    r"lease\s+(?P<address>[0-9.]+)\s*\{(?P<body>.*?)\}",
    re.IGNORECASE | re.DOTALL,
)
LEASE_MAC_PATTERN = re.compile(
    r"hardware\s+ethernet\s+(?P<mac>[0-9a-f:]+)\s*;",
    re.IGNORECASE,
)
LEASE_START_PATTERN = re.compile(
    r"starts\s+[0-6]\s+(?P<timestamp>[0-9/]+\s+[0-9:]+)\s*;",
    re.IGNORECASE,
)
LEASE_END_PATTERN = re.compile(
    r"ends\s+(?:[0-6]\s+(?P<timestamp>[0-9/]+\s+[0-9:]+)|(?P<never>never))\s*;",
    re.IGNORECASE,
)
PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
DEFAULT_VMWARE_LEASE_PATHS = (
    PROGRAM_DATA / "VMware/vmnetdhcp.leases",
    PROGRAM_DATA / "VMware/vmnetdhcp.leases~",
)


@dataclass(frozen=True)
class HostConfig:
    alias: str
    vmx: Path


@dataclass(frozen=True)
class LabConfig:
    vmrun: Path
    ssh: Path
    discovery_timeout_seconds: int
    connect_timeout_seconds: int
    command_timeout_seconds: int
    hosts: Mapping[str, HostConfig]


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def require_exact_fields(
    value: Mapping[str, Any],
    expected: set[str],
    label: str,
) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        raise ValueError(
            f"{label} fields mismatch: missing={missing} unknown={unknown}"
        )


def require_timeout(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        raise ValueError(f"{label} must be an integer in 1..{maximum}")
    return value


def require_absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty path string")
    path = Path(os.path.expandvars(value)).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    return path


def load_config(path: Path) -> LabConfig:
    try:
        with path.open("r", encoding="utf-8") as source:
            document = json.load(source, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"invalid JSON at line {error.lineno}, column {error.colno}"
        ) from error
    document = require_object(document, "config")
    require_exact_fields(document, TOP_LEVEL_FIELDS, "config")
    if document["schema_version"] != "1.0.0":
        raise ValueError("config schema_version must equal 1.0.0")

    timeouts = require_object(document["timeouts"], "timeouts")
    require_exact_fields(timeouts, TIMEOUT_FIELDS, "timeouts")
    hosts_value = require_object(document["hosts"], "hosts")
    if set(hosts_value) != set(ROLES):
        raise ValueError(f"hosts must contain exactly {list(ROLES)}")

    hosts: dict[str, HostConfig] = {}
    aliases: set[str] = set()
    for role in ROLES:
        record = require_object(hosts_value[role], f"hosts.{role}")
        require_exact_fields(record, HOST_FIELDS, f"hosts.{role}")
        alias = record["alias"]
        if not isinstance(alias, str) or ALIAS_PATTERN.fullmatch(alias) is None:
            raise ValueError(f"hosts.{role}.alias is invalid")
        if alias in aliases:
            raise ValueError(f"duplicate SSH alias: {alias}")
        aliases.add(alias)
        hosts[role] = HostConfig(
            alias=alias,
            vmx=require_absolute_path(record["vmx"], f"hosts.{role}.vmx"),
        )

    return LabConfig(
        vmrun=require_absolute_path(document["vmrun"], "vmrun"),
        ssh=require_absolute_path(document["ssh"], "ssh"),
        discovery_timeout_seconds=require_timeout(
            timeouts["discovery_seconds"], "timeouts.discovery_seconds", 120
        ),
        connect_timeout_seconds=require_timeout(
            timeouts["connect_seconds"], "timeouts.connect_seconds", 60
        ),
        command_timeout_seconds=require_timeout(
            timeouts["command_seconds"], "timeouts.command_seconds", 3_600
        ),
        hosts=hosts,
    )


def timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def normalize_exit_code(value: int) -> int:
    return value - 2**32 if value > 2**31 - 1 else value


def normalize_mac(value: str) -> str:
    compact = value.strip().lower().replace("-", ":")
    parts = compact.split(":")
    if len(parts) != 6 or any(
        len(part) != 2
        or any(character not in "0123456789abcdef" for character in part)
        for part in parts
    ):
        raise ValueError(f"invalid MAC address: {value}")
    return ":".join(parts)


def vmx_nat_mac(path: Path) -> str:
    adapters: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            match = VMX_SETTING_PATTERN.fullmatch(line.rstrip("\r\n"))
            if match is None:
                continue
            adapters.setdefault(match.group("index"), {})[
                match.group("name").lower()
            ] = match.group("value")
    nat_adapters = [
        settings
        for settings in adapters.values()
        if settings.get("connectiontype", "").lower() == "nat"
    ]
    if len(nat_adapters) != 1:
        raise ValueError(
            f"expected exactly one NAT adapter in VMX, observed {len(nat_adapters)}"
        )
    address = nat_adapters[0].get("address") or nat_adapters[0].get(
        "generatedaddress"
    )
    if address is None:
        raise ValueError("NAT adapter has no MAC address in VMX")
    return normalize_mac(address)


def parse_lease_timestamp(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y/%m/%d %H:%M:%S").replace(
        tzinfo=dt.timezone.utc
    )


def vmware_dhcp_address(
    vmx: Path,
    *,
    lease_paths: Sequence[Path] | None = None,
    now: dt.datetime | None = None,
) -> tuple[str, Path]:
    mac = vmx_nat_mac(vmx)
    observed_at = now or dt.datetime.now(dt.timezone.utc)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("DHCP lease comparison time must be timezone-aware")
    candidates: list[tuple[dt.datetime, str, Path]] = []
    io_errors: list[str] = []
    paths = DEFAULT_VMWARE_LEASE_PATHS if lease_paths is None else lease_paths
    for path in paths:
        try:
            if not path.is_file() or path.stat().st_size == 0:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            io_errors.append(f"{path}: {error}")
            continue
        for block in LEASE_BLOCK_PATTERN.finditer(text):
            body = block.group("body")
            mac_match = LEASE_MAC_PATTERN.search(body)
            start_match = LEASE_START_PATTERN.search(body)
            end_match = LEASE_END_PATTERN.search(body)
            if (
                mac_match is None
                or start_match is None
                or end_match is None
                or normalize_mac(mac_match.group("mac")) != mac
            ):
                continue
            address = ipaddress.ip_address(block.group("address"))
            if address.version != 4:
                continue
            starts = parse_lease_timestamp(start_match.group("timestamp"))
            end_text = end_match.group("timestamp")
            ends = (
                dt.datetime.max.replace(tzinfo=dt.timezone.utc)
                if end_text is None
                else parse_lease_timestamp(end_text)
            )
            if starts <= observed_at < ends:
                candidates.append((starts, str(address), path))
    if not candidates:
        if io_errors:
            raise OSError(
                "could not read VMware DHCP lease source(s): "
                + "; ".join(io_errors)
            )
        raise ValueError(f"no active VMware DHCP lease for NAT MAC {mac}")
    newest_start = max(item[0] for item in candidates)
    newest = [item for item in candidates if item[0] == newest_start]
    addresses = {item[1] for item in newest}
    if len(addresses) != 1:
        raise ValueError(f"ambiguous newest VMware DHCP leases for NAT MAC {mac}")
    selected = newest[-1]
    return selected[1], selected[2]


def run_process(
    arguments: Sequence[str],
    timeout_seconds: int,
) -> tuple[int | None, bool, str, str, str | None]:
    try:
        completed = subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=timeout_seconds,
        )
        return (
            normalize_exit_code(completed.returncode),
            False,
            completed.stdout,
            completed.stderr,
            None,
        )
    except subprocess.TimeoutExpired as error:
        return (
            None,
            True,
            timeout_text(error.stdout),
            timeout_text(error.stderr),
            f"process exceeded {timeout_seconds} seconds",
        )
    except OSError as error:
        return None, False, "", "", str(error)


def base_result(role: str, host: HostConfig, command: str) -> dict[str, Any]:
    return {
        "role": role,
        "alias": host.alias,
        "address": None,
        "discovery_method": None,
        "discovery_source": None,
        "command": command,
        "stage": "discovery",
        "status": "local_error",
        "exit_code": None,
        "timed_out": False,
        "duration_ms": 0.0,
        "stdout": "",
        "stderr": "",
        "error": None,
        "user_confirmation": None,
    }


def discovery_confirmation(
    role: str,
    host: HostConfig,
) -> dict[str, Any]:
    return {
        "required": True,
        "reason": DISCOVERY_CONFIRMATION_REASON,
        "question": (
            "Bạn đã mở VMware Workstation và bật VM "
            f"{role} ({host.alias}) chưa?"
        ),
    }


def execute_role(
    config: LabConfig,
    role: str,
    command: str,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    if role not in config.hosts:
        raise ValueError(f"unknown role: {role}")
    if not isinstance(command, str) or not command.strip() or "\x00" in command:
        raise ValueError("remote command must be a non-empty string without NUL")
    remote_timeout = (
        config.command_timeout_seconds
        if timeout_seconds is None
        else require_timeout(timeout_seconds, "timeout-seconds", 3_600)
    )
    host = config.hosts[role]
    result = base_result(role, host, command)
    started = time.perf_counter()

    for label, path in (
        ("vmrun", config.vmrun),
        ("ssh", config.ssh),
        (f"{role} VMX", host.vmx),
    ):
        if not path.is_file():
            result["error"] = f"{label} file is missing"
            result["duration_ms"] = round(
                (time.perf_counter() - started) * 1_000.0, 3
            )
            return result

    discovery = [
        str(config.vmrun),
        "getGuestIPAddress",
        str(host.vmx),
        "-wait",
    ]
    exit_code, timed_out, stdout, stderr, error = run_process(
        discovery, config.discovery_timeout_seconds
    )
    discovery_method = "vmrun"
    discovery_source = str(host.vmx)
    if timed_out or error is not None or exit_code != 0:
        powered_off = "not powered on" in f"{stdout}\n{stderr}".lower()
        if powered_off:
            result.update(
                {
                    "status": "powered_off",
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "stdout": stdout,
                    "stderr": stderr,
                    "error": "virtual machine is not powered on",
                    "duration_ms": round(
                        (time.perf_counter() - started) * 1_000.0, 3
                    ),
                }
            )
            return result
        address_text = ""
    else:
        address_text = stdout.strip()

    address: ipaddress.IPv4Address | None = None
    if address_text:
        try:
            parsed_address = ipaddress.ip_address(address_text)
            if isinstance(parsed_address, ipaddress.IPv4Address):
                address = parsed_address
        except ValueError:
            pass
    lease_error: str | None = None
    lease_local_error = False
    try:
        lease_address, lease_path = vmware_dhcp_address(host.vmx)
        address = ipaddress.IPv4Address(lease_address)
        discovery_method = "vmware_dhcp_lease"
        discovery_source = str(lease_path)
    except OSError as lease_exception:
        lease_error = str(lease_exception)
        lease_local_error = True
    except ValueError as lease_exception:
        lease_error = str(lease_exception)
    if address is None:
        if error is not None or lease_local_error:
            status = "local_error"
        elif timed_out:
            status = "timeout"
        else:
            status = "discovery_error"
        base_error = (
            error
            or (
                "vmrun did not return a valid IPv4 address"
                if exit_code == 0
                else "vmrun address discovery failed"
            )
        )
        result.update(
            {
                "status": status,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "stdout": stdout,
                "stderr": stderr,
                "error": (
                    f"{base_error}; DHCP lease fallback failed: {lease_error}"
                    if lease_error
                    else base_error
                ),
                "user_confirmation": (
                    discovery_confirmation(role, host)
                    if status in {"timeout", "discovery_error"}
                    else None
                ),
                "duration_ms": round(
                    (time.perf_counter() - started) * 1_000.0, 3
                ),
            }
        )
        return result

    result["address"] = str(address)
    result["discovery_method"] = discovery_method
    result["discovery_source"] = discovery_source
    result["stage"] = "ssh"
    ssh_arguments = [
        str(config.ssh),
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"ConnectTimeout={config.connect_timeout_seconds}",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        f"HostName={address}",
        "-o",
        f"HostKeyAlias={host.alias}",
        "--",
        host.alias,
        command,
    ]
    exit_code, timed_out, stdout, stderr, error = run_process(
        ssh_arguments, remote_timeout
    )
    if timed_out:
        status = "timeout"
    elif error is not None:
        status = "local_error"
    elif exit_code == 0:
        status = "ok"
    elif exit_code == 255:
        status = "ssh_error"
    else:
        status = "remote_error"
    result.update(
        {
            "status": status,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "error": error,
            "duration_ms": round(
                (time.perf_counter() - started) * 1_000.0, 3
            ),
        }
    )
    return result


def status_document(
    config: LabConfig,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(ROLES)
    ) as executor:
        futures = {
            role: executor.submit(
                execute_role,
                config,
                role,
                "hostname",
                timeout_seconds,
            )
            for role in ROLES
        }
        hosts = {role: futures[role].result() for role in ROLES}
    successful = sum(item["status"] == "ok" for item in hosts.values())
    overall = "ok" if successful == len(ROLES) else (
        "partial" if successful else "failed"
    )
    return {
        "schema_version": "1.0.0",
        "operation": "status",
        "status": overall,
        "user_confirmation_required": any(
            item.get("user_confirmation", {}).get("required") is True
            if isinstance(item.get("user_confirmation"), Mapping)
            else False
            for item in hosts.values()
        ),
        "hosts": hosts,
    }


def emit_json(
    document: Mapping[str, Any],
    output: TextIO | None = None,
) -> None:
    destination = sys.stdout if output is None else output
    json.dump(
        document,
        destination,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    destination.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    status = subparsers.add_parser("status")
    status.add_argument("--timeout-seconds", type=int)

    execute = subparsers.add_parser("exec")
    execute.add_argument("role", choices=ROLES)
    execute.add_argument("--timeout-seconds", type=int)
    execute.add_argument("command")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.operation == "status":
            document = status_document(config, args.timeout_seconds)
            exit_code = 0 if document["status"] == "ok" else 1
        else:
            result = execute_role(
                config,
                args.role,
                args.command,
                args.timeout_seconds,
            )
            document = {
                "schema_version": "1.0.0",
                "operation": "exec",
                **result,
            }
            exit_code = 0 if result["status"] == "ok" else 1
    except (OSError, ValueError) as error:
        emit_json(
            {
                "schema_version": "1.0.0",
                "operation": getattr(args, "operation", None),
                "status": "invalid_config_or_input",
                "error": str(error),
            }
        )
        return 2
    emit_json(document)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
