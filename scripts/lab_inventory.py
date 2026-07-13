#!/usr/bin/env python3
"""Collect and validate reproducible Linux lab inventory artifacts for T0.1.

The collector is deliberately read-only: it does not invoke sudo, load kernel
modules, bind NICs, or change hugepage settings.  It also avoids collecting
machine serial numbers and UUIDs.
"""

from __future__ import annotations

import argparse
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
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
ROLES = ("kali", "ubuntu")
FORBIDDEN_KEY_FRAGMENTS = ("serial", "uuid", "machine_id", "machine-id")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return None


def parse_key_value_file(path: str | Path, separator: str = "=") -> dict[str, str]:
    result: dict[str, str] = {}
    content = read_text(path)
    if content is None:
        return result
    for line in content.splitlines():
        if not line or line.lstrip().startswith("#") or separator not in line:
            continue
        key, value = line.split(separator, 1)
        result[key.strip()] = value.strip().strip('"')
    return result


def run_command(arguments: Sequence[str], timeout: float = 5.0) -> dict[str, Any]:
    executable = shutil.which(arguments[0])
    if executable is None:
        return {"available": False, "reason": "command_not_found"}
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
        return {"available": False, "reason": type(error).__name__}
    return {
        "available": True,
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def command_json(arguments: Sequence[str]) -> tuple[Any | None, str | None]:
    result = run_command(arguments)
    if not result.get("available"):
        return None, f"{' '.join(arguments)}: {result.get('reason', 'unavailable')}"
    if result.get("return_code") != 0:
        return None, f"{' '.join(arguments)}: exit {result.get('return_code')}"
    try:
        return json.loads(result.get("stdout", "")), None
    except json.JSONDecodeError:
        return None, f"{' '.join(arguments)}: invalid JSON output"


def first_line_version(arguments: Sequence[str]) -> dict[str, Any]:
    result = run_command(arguments)
    if not result.get("available"):
        return {"available": False}
    combined = result.get("stdout") or result.get("stderr") or ""
    first_line = combined.splitlines()[0].strip() if combined else None
    return {
        "available": result.get("return_code") == 0,
        "version": first_line,
    }


def parse_meminfo() -> dict[str, int | None]:
    raw = read_text("/proc/meminfo")
    values: dict[str, int] = {}
    if raw:
        for line in raw.splitlines():
            match = re.match(r"^([^:]+):\s+(\d+)\s*(kB)?$", line)
            if match:
                multiplier = 1024 if match.group(3) else 1
                values[match.group(1)] = int(match.group(2)) * multiplier
    return {
        "total_bytes": values.get("MemTotal"),
        "available_bytes": values.get("MemAvailable"),
    }


def parse_cpu_info() -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    lscpu, error = command_json(("lscpu", "--json", "--bytes"))
    normalized: dict[str, str] = {}
    if isinstance(lscpu, dict):
        for entry in lscpu.get("lscpu", []):
            if isinstance(entry, dict):
                field = str(entry.get("field", "")).rstrip(":")
                if field:
                    normalized[field] = str(entry.get("data", ""))
    elif error:
        warnings.append(error)

    cpuinfo = read_text("/proc/cpuinfo") or ""
    model_name = normalized.get("Model name")
    if not model_name:
        for key in ("model name", "Hardware", "Processor"):
            match = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
            if match:
                model_name = match.group(1).strip()
                break

    def integer(field: str) -> int | None:
        value = normalized.get(field)
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    return {
        "model": model_name,
        "architecture": normalized.get("Architecture", platform.machine()),
        "logical_cpus": integer("CPU(s)") or os.cpu_count(),
        "cores_per_socket": integer("Core(s) per socket"),
        "sockets": integer("Socket(s)"),
        "numa_nodes": integer("NUMA node(s)"),
        "virtualization": normalized.get("Virtualization"),
    }, warnings


def collect_storage() -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    devices, error = command_json(
        ("lsblk", "--json", "--bytes", "--output", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS")
    )
    if error:
        warnings.append(error)
    try:
        root_usage = shutil.disk_usage("/")
        root_filesystem = {
            "total_bytes": root_usage.total,
            "used_bytes": root_usage.used,
            "free_bytes": root_usage.free,
        }
    except OSError:
        root_filesystem = {"total_bytes": None, "used_bytes": None, "free_bytes": None}
        warnings.append("root filesystem usage unavailable")
    return {
        "root_filesystem": root_filesystem,
        "block_devices": devices.get("blockdevices", []) if isinstance(devices, dict) else [],
    }, warnings


def sysfs_link_name(path: Path) -> str | None:
    try:
        return path.resolve(strict=True).name
    except (OSError, RuntimeError):
        return None


def collect_network() -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    raw_interfaces, error = command_json(("ip", "-json", "address", "show"))
    if error:
        warnings.append(error)
    interfaces: list[dict[str, Any]] = []
    if isinstance(raw_interfaces, list):
        for item in raw_interfaces:
            if not isinstance(item, dict):
                continue
            name = str(item.get("ifname", "unknown"))
            sysfs = Path("/sys/class/net") / name
            addresses = []
            for address in item.get("addr_info", []):
                if isinstance(address, dict):
                    addresses.append(
                        {
                            "family": address.get("family"),
                            "local": address.get("local"),
                            "prefix_length": address.get("prefixlen"),
                            "scope": address.get("scope"),
                        }
                    )
            device_link = sysfs / "device"
            interfaces.append(
                {
                    "name": name,
                    "state": item.get("operstate"),
                    "mtu": item.get("mtu"),
                    "mac_address": item.get("address"),
                    "addresses": addresses,
                    "driver": sysfs_link_name(device_link / "driver"),
                    "pci_address": sysfs_link_name(device_link),
                }
            )
    raw_routes, route_error = command_json(("ip", "-json", "route", "show", "default"))
    if route_error:
        warnings.append(route_error)
    return {
        "interfaces": interfaces,
        "default_routes": raw_routes if isinstance(raw_routes, list) else [],
        "vmnet_mapping": "pending_user_mapping",
    }, warnings


def collect_hugepages() -> dict[str, Any]:
    raw = read_text("/proc/meminfo") or ""
    values: dict[str, int] = {}
    for name in ("HugePages_Total", "HugePages_Free", "HugePages_Rsvd", "Hugepagesize"):
        match = re.search(rf"^{name}:\s+(\d+)", raw, re.MULTILINE)
        if match:
            values[name] = int(match.group(1))
    numa: list[dict[str, Any]] = []
    node_root = Path("/sys/devices/system/node")
    if node_root.exists():
        for node in sorted(node_root.glob("node[0-9]*")):
            sizes: dict[str, int | None] = {}
            for directory in sorted((node / "hugepages").glob("hugepages-*kB")):
                total = read_text(directory / "nr_hugepages")
                sizes[directory.name] = int(total) if total and total.isdigit() else None
            numa.append({"node": node.name, "page_counts": sizes})
    return {
        "total_pages": values.get("HugePages_Total"),
        "free_pages": values.get("HugePages_Free"),
        "reserved_pages": values.get("HugePages_Rsvd"),
        "page_size_kb": values.get("Hugepagesize"),
        "numa": numa,
    }


def collect_dpdk_prerequisites() -> dict[str, Any]:
    cmdline = read_text("/proc/cmdline") or ""
    iommu_tokens = [
        token for token in cmdline.split() if token.startswith(("intel_iommu=", "amd_iommu=", "iommu="))
    ]
    groups_root = Path("/sys/kernel/iommu_groups")
    try:
        iommu_group_count = sum(1 for item in groups_root.iterdir() if item.is_dir())
    except OSError:
        iommu_group_count = 0
    modules = read_text("/proc/modules") or ""
    loaded_modules = {line.split()[0] for line in modules.splitlines() if line.split()}
    return {
        "hugepages": collect_hugepages(),
        "iommu": {
            "kernel_parameters": iommu_tokens,
            "group_count": iommu_group_count,
        },
        "vfio": {
            "vfio_loaded": "vfio" in loaded_modules,
            "vfio_pci_loaded": "vfio_pci" in loaded_modules,
        },
    }


def collect_virtualization() -> dict[str, Any]:
    detected = run_command(("systemd-detect-virt",))
    virt_type = None
    if detected.get("available") and detected.get("return_code") == 0:
        virt_type = detected.get("stdout") or None
    return {
        "detected_type": virt_type,
        "dmi_product_name": read_text("/sys/class/dmi/id/product_name"),
        "vmware_tools": first_line_version(("vmware-toolbox-cmd", "-v")),
    }


def collect_tool_versions() -> dict[str, Any]:
    return {
        "python3": first_line_version(("python3", "--version")),
        "gcc": first_line_version(("gcc", "--version")),
        "g++": first_line_version(("g++", "--version")),
        "cmake": first_line_version(("cmake", "--version")),
        "meson": first_line_version(("meson", "--version")),
        "ninja": first_line_version(("ninja", "--version")),
        "dpdk": first_line_version(("pkg-config", "--modversion", "libdpdk")),
        "testpmd": first_line_version(("dpdk-testpmd", "--version")),
    }


def collect_inventory(role: str) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError(f"role must be one of: {', '.join(ROLES)}")
    if platform.system() != "Linux":
        raise RuntimeError("inventory collection must run inside the Kali or Ubuntu Linux VM")

    os_release = parse_key_value_file("/etc/os-release")
    cpu, cpu_warnings = parse_cpu_info()
    storage, storage_warnings = collect_storage()
    network, network_warnings = collect_network()
    warnings = [*cpu_warnings, *storage_warnings, *network_warnings]
    return {
        "schema_version": SCHEMA_VERSION,
        "role": role,
        "collected_at_utc": utc_now(),
        "collection_status": "observed",
        "host": {
            "hostname": socket.gethostname(),
            "os": {
                "id": os_release.get("ID"),
                "name": os_release.get("PRETTY_NAME"),
                "version_id": os_release.get("VERSION_ID"),
            },
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "virtualization": collect_virtualization(),
        },
        "compute": {"cpu": cpu, "memory": parse_meminfo()},
        "storage": storage,
        "network": network,
        "dpdk_prerequisites": collect_dpdk_prerequisites(),
        "permissions": {
            "effective_uid": os.geteuid(),
            "running_as_root": os.geteuid() == 0,
            "sudo_command_available": shutil.which("sudo") is not None,
        },
        "toolchain_observed": collect_tool_versions(),
        "collection_warnings": warnings,
    }


def nested_get(value: Mapping[str, Any], path: Sequence[str]) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    return current


def walk_keys(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path
            yield from walk_keys(child, path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_keys(child, f"{prefix}[{index}]")


def validate_inventory(document: Any, expected_role: str | None = None) -> list[str]:
    if not isinstance(document, Mapping):
        return ["root must be a JSON object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    role = document.get("role")
    if role not in ROLES:
        errors.append(f"role must be one of: {', '.join(ROLES)}")
    if expected_role and role != expected_role:
        errors.append(f"role must equal {expected_role}")
    if document.get("collection_status") != "observed":
        errors.append("collection_status must equal observed")
    timestamp = document.get("collected_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("collected_at_utc must be an ISO-8601 UTC timestamp ending in Z")

    required_mappings = (
        ("host",),
        ("host", "os"),
        ("host", "virtualization"),
        ("compute",),
        ("compute", "cpu"),
        ("compute", "memory"),
        ("storage",),
        ("network",),
        ("dpdk_prerequisites",),
        ("permissions",),
        ("toolchain_observed",),
    )
    for path in required_mappings:
        if not isinstance(nested_get(document, path), Mapping):
            errors.append(f"{'.'.join(path)} must be an object")
    required_lists = (("network", "interfaces"), ("collection_warnings",))
    for path in required_lists:
        if not isinstance(nested_get(document, path), list):
            errors.append(f"{'.'.join(path)} must be an array")

    for key_path in walk_keys(document):
        leaf = key_path.rsplit(".", 1)[-1].lower()
        if any(fragment in leaf for fragment in FORBIDDEN_KEY_FRAGMENTS):
            errors.append(f"forbidden sensitive field: {key_path}")
    return errors


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


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def yaml_key(value: Any) -> str:
    text = str(value)
    return text if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", text) else yaml_scalar(text)


def to_yaml(value: Any, indent: int = 0) -> str:
    spaces = " " * indent
    if isinstance(value, Mapping):
        if not value:
            return f"{spaces}{{}}"
        lines: list[str] = []
        for key, child in value.items():
            if isinstance(child, Mapping) and child:
                lines.append(f"{spaces}{yaml_key(key)}:")
                lines.append(to_yaml(child, indent + 2))
            elif isinstance(child, list) and child:
                lines.append(f"{spaces}{yaml_key(key)}:")
                lines.append(to_yaml(child, indent + 2))
            elif isinstance(child, Mapping):
                lines.append(f"{spaces}{yaml_key(key)}: {{}}")
            elif isinstance(child, list):
                lines.append(f"{spaces}{yaml_key(key)}: []")
            else:
                lines.append(f"{spaces}{yaml_key(key)}: {yaml_scalar(child)}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return f"{spaces}[]"
        lines = []
        for child in value:
            if isinstance(child, (Mapping, list)):
                rendered = to_yaml(child, indent + 2).splitlines()
                lines.append(f"{spaces}- {rendered[0].lstrip()}")
                lines.extend(rendered[1:])
            else:
                lines.append(f"{spaces}- {yaml_scalar(child)}")
        return "\n".join(lines)
    return f"{spaces}{yaml_scalar(value)}"


def inventory_summary(document: Mapping[str, Any], source_path: Path) -> dict[str, Any]:
    return {
        "inventory_status": "observed",
        "source_artifact": source_path.name,
        "source_sha256": sha256_file(source_path),
        "collected_at_utc": document.get("collected_at_utc"),
        "host": document.get("host"),
        "compute": document.get("compute"),
        "storage": document.get("storage"),
        "network": document.get("network"),
        "dpdk_prerequisites": document.get("dpdk_prerequisites"),
        "permissions": document.get("permissions"),
        "toolchain_observed": document.get("toolchain_observed"),
        "collection_warnings": document.get("collection_warnings"),
    }


def build_manifest(
    kali: Mapping[str, Any],
    ubuntu: Mapping[str, Any],
    kali_path: Path,
    ubuntu_path: Path,
    data_vmnet: str,
    management_vmnet: str,
    t0_1_acceptance: str,
) -> dict[str, Any]:
    vmnet_confirmed = data_vmnet != "pending_user_mapping"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": "T0.1",
        "manifest_status": "observed" if vmnet_confirmed else "pending_network_mapping",
        "generated_at_utc": utc_now(),
        "official_environment": {
            "hypervisor": "VMware Workstation 17",
            "topology_mode": "endpoint_combined_sensor_victim",
            "attacker": "kali",
            "sensor_victim_model_host": "ubuntu",
        },
        "networks": {
            "data_vmnet": data_vmnet,
            "management_vmnet": management_vmnet,
            "guest_to_vmnet_mapping_requires_manual_confirmation": True,
        },
        "nodes": {
            "kali_attacker": inventory_summary(kali, kali_path),
            "ubuntu_sensor_victim": inventory_summary(ubuntu, ubuntu_path),
        },
        "limitations": [
            "This two-VM topology observes traffic terminating on Ubuntu; it does not prove passive visibility of third-party unicast traffic.",
            "Passive versus inline feasibility remains a separate T0.4 gate.",
        ],
        "acceptance": {
            "official_environment_confirmed": True,
            "topology_confirmed": True,
            "observed_inventories_complete": True,
            "vmnet_mapping_confirmed": vmnet_confirmed,
            "t0_1_user_acceptance": t0_1_acceptance,
        },
    }


def write_new_file(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"refusing to overwrite existing file: {path}; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def command_collect(args: argparse.Namespace) -> int:
    inventory = collect_inventory(args.role)
    write_new_file(
        args.output,
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        args.force,
    )
    print(f"wrote {args.output}")
    for warning in inventory["collection_warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


def command_validate(args: argparse.Namespace) -> int:
    document = load_json(args.input)
    errors = validate_inventory(document, args.expected_role)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid inventory: {args.input}")
    return 0


def command_render(args: argparse.Namespace) -> int:
    kali = load_json(args.kali)
    ubuntu = load_json(args.ubuntu)
    errors = [
        *(f"kali: {error}" for error in validate_inventory(kali, "kali")),
        *(f"ubuntu: {error}" for error in validate_inventory(ubuntu, "ubuntu")),
    ]
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    manifest = build_manifest(
        kali,
        ubuntu,
        args.kali,
        args.ubuntu,
        args.data_vmnet,
        args.management_vmnet,
        args.t0_1_acceptance,
    )
    write_new_file(args.output, "---\n" + to_yaml(manifest) + "\n", args.force)
    print(f"wrote {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser("collect", help="collect a read-only inventory inside a Linux VM")
    collect.add_argument("--role", required=True, choices=ROLES)
    collect.add_argument("--output", required=True, type=Path)
    collect.add_argument("--force", action="store_true", help="replace an existing output file")
    collect.set_defaults(handler=command_collect)

    validate = subparsers.add_parser("validate", help="validate one inventory JSON artifact")
    validate.add_argument("--input", required=True, type=Path)
    validate.add_argument("--expected-role", choices=ROLES)
    validate.set_defaults(handler=command_validate)

    render = subparsers.add_parser("render-manifest", help="render YAML from two validated inventories")
    render.add_argument("--kali", required=True, type=Path)
    render.add_argument("--ubuntu", required=True, type=Path)
    render.add_argument("--output", required=True, type=Path)
    render.add_argument("--data-vmnet", default="pending_user_mapping")
    render.add_argument("--management-vmnet", default="not_configured")
    render.add_argument("--t0-1-acceptance", choices=("pending", "accepted"), default="pending")
    render.add_argument("--force", action="store_true", help="replace an existing output file")
    render.set_defaults(handler=command_render)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
