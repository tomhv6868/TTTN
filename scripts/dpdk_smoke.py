#!/usr/bin/env python3
"""Run the reversible T0.3 DPDK/VFIO smoke-test workflow on Ubuntu."""

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
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T0.3"
APPROVED_IOMMU_POLICY = "singleton_or_vmware_root_ports"
DPDK_FILE_PREFIX = "nids-t03"
APPROVED_HUGE_UNLINK = "always"
APPROVED_TOTAL_NUM_MBUFS = 8192
HUGEPAGE_MOUNTPOINT = Path("/dev/hugepages")
DPDK_RUNTIME_ROOT = Path("/var/run/dpdk")
APPROVED_VMWARE_BRIDGE = {
    "vendor": "15ad",
    "device": "07a0",
    "class_base_subclass": "0604",
    "driver": "pcieport",
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


def json_sha256(document: Mapping[str, Any]) -> str:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def write_new_json(path: Path, document: Mapping[str, Any], force: bool = False) -> None:
    if path.exists() and not force:
        raise ValueError(f"refusing to overwrite existing file: {path}; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def replace_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_config(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["config root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    if document.get("task") != TASK:
        errors.append(f"task must equal {TASK}")
    for section in ("topology", "ubuntu", "kali", "runtime", "safety"):
        if not isinstance(document.get(section), Mapping):
            errors.append(f"{section} must be an object")
    ubuntu = document.get("ubuntu", {})
    for key in ("management_interface", "management_gateway", "expected_data_driver", "toolchain_root"):
        if not isinstance(ubuntu.get(key), str) or not ubuntu.get(key):
            errors.append(f"ubuntu.{key} must be a non-empty string")
    runtime = document.get("runtime", {})
    for key in (
        "hugepage_size_kb",
        "hugepage_count",
        "dpdk_memory_mb",
        "total_num_mbufs",
        "memory_channels",
        "duration_seconds",
    ):
        if not isinstance(runtime.get(key), int) or runtime.get(key, 0) <= 0:
            errors.append(f"runtime.{key} must be a positive integer")
    if runtime.get("hugepage_size_kb") != 2048:
        errors.append("runtime.hugepage_size_kb must equal 2048 for T0.3")
    if runtime.get("hugepage_count") != 128:
        errors.append("runtime.hugepage_count must equal 128 for T0.3")
    if runtime.get("dpdk_memory_mb") != 256:
        errors.append("runtime.dpdk_memory_mb must equal 256 for T0.3")
    if runtime.get("file_prefix") != DPDK_FILE_PREFIX:
        errors.append(f"runtime.file_prefix must equal {DPDK_FILE_PREFIX} for T0.3")
    if runtime.get("huge_unlink") != APPROVED_HUGE_UNLINK:
        errors.append(f"runtime.huge_unlink must equal {APPROVED_HUGE_UNLINK} for T0.3")
    if runtime.get("total_num_mbufs") != APPROVED_TOTAL_NUM_MBUFS:
        errors.append(f"runtime.total_num_mbufs must equal {APPROVED_TOTAL_NUM_MBUFS} for T0.3")
    if (
        isinstance(runtime.get("hugepage_size_kb"), int)
        and isinstance(runtime.get("hugepage_count"), int)
        and isinstance(runtime.get("dpdk_memory_mb"), int)
        and runtime["hugepage_size_kb"] * runtime["hugepage_count"]
        != runtime["dpdk_memory_mb"] * 1024
    ):
        errors.append("runtime hugepage reservation must equal runtime.dpdk_memory_mb")
    if runtime.get("forward_mode") != "macswap":
        errors.append("runtime.forward_mode must equal macswap")
    safety = document.get("safety", {})
    required = {
        "require_iommu": True,
        "allow_no_iommu": False,
        "preserve_management_connectivity": True,
        "persistent_boot_changes": False,
    }
    for key, expected in required.items():
        if safety.get(key) is not expected:
            errors.append(f"safety.{key} must equal {str(expected).lower()}")
    if safety.get("iommu_group_policy") != APPROVED_IOMMU_POLICY:
        errors.append(f"safety.iommu_group_policy must equal {APPROVED_IOMMU_POLICY}")
    bridge = safety.get("allowed_iommu_bridge_companion")
    if not isinstance(bridge, Mapping):
        errors.append("safety.allowed_iommu_bridge_companion must be an object")
    else:
        for key, expected in APPROVED_VMWARE_BRIDGE.items():
            if bridge.get(key) != expected:
                errors.append(f"safety.allowed_iommu_bridge_companion.{key} must equal {expected}")
    return errors


def require_linux() -> None:
    if platform.system() != "Linux":
        raise RuntimeError("this operation must run inside a Linux VM")


def require_root() -> None:
    require_linux()
    if os.geteuid() != 0:
        raise RuntimeError("this operation requires root; run it with sudo and preserve the toolchain environment")


def run(arguments: Sequence[str], timeout: float = 15.0, check: bool = False) -> dict[str, Any]:
    executable = shutil.which(arguments[0]) if not os.path.isabs(arguments[0]) else arguments[0]
    if not executable or not Path(executable).exists():
        result = {"return_code": None, "stdout": "", "stderr": f"command not found: {arguments[0]}"}
    else:
        try:
            completed = subprocess.run(
                [executable, *arguments[1:]],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "LC_ALL": "C"},
            )
            result = {
                "return_code": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        except (OSError, subprocess.SubprocessError) as error:
            result = {"return_code": None, "stdout": "", "stderr": str(error)}
    if check and result["return_code"] != 0:
        detail = result["stderr"] or result["stdout"] or "unknown error"
        raise RuntimeError(f"command failed ({' '.join(arguments)}): {detail}")
    return result


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


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def read_json_command(arguments: Sequence[str]) -> Any:
    result = run(arguments)
    if result["return_code"] != 0:
        return []
    try:
        return json.loads(result["stdout"])
    except (TypeError, json.JSONDecodeError):
        return []


def pci_device_facts(pci_address: str) -> dict[str, Any]:
    base = Path("/sys/bus/pci/devices") / pci_address
    class_code = (read_text(base / "class") or "").lower().removeprefix("0x")
    vendor = (read_text(base / "vendor") or "").lower().removeprefix("0x")
    device = (read_text(base / "device") or "").lower().removeprefix("0x")
    driver_link = base / "driver"
    network_directory = base / "net"
    try:
        network_interfaces = sorted(item.name for item in network_directory.iterdir())
    except OSError:
        network_interfaces = []
    return {
        "pci_address": pci_address,
        "class_code": class_code,
        "class_base_subclass": class_code[:4] if len(class_code) >= 4 else None,
        "vendor": vendor or None,
        "device": device or None,
        "driver": driver_link.resolve().name if driver_link.exists() else None,
        "network_interfaces": network_interfaces,
    }


def interface_facts(name: str, addresses: Mapping[str, Any], default_interfaces: set[str]) -> dict[str, Any]:
    base = Path("/sys/class/net") / name
    device_link = base / "device"
    pci_address = None
    if device_link.exists():
        resolved = device_link.resolve()
        if re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", resolved.name):
            pci_address = resolved.name
    driver_link = device_link / "driver"
    driver = driver_link.resolve().name if driver_link.exists() else None
    group_link = device_link / "iommu_group"
    group_id = group_link.resolve().name if group_link.exists() else None
    group_members: list[str] = []
    group_details: list[dict[str, Any]] = []
    if group_id:
        devices = group_link.resolve() / "devices"
        try:
            group_members = sorted(item.name for item in devices.iterdir())
        except OSError:
            group_members = []
        group_details = [pci_device_facts(item) for item in group_members]
    address_items = addresses.get(name, {}).get("addr_info", [])
    ip_addresses = [
        f"{item['local']}/{item['prefixlen']}"
        for item in address_items
        if item.get("family") in ("inet", "inet6") and item.get("local") is not None
    ]
    return {
        "name": name,
        "mac": read_text(base / "address"),
        "mtu": int(read_text(base / "mtu") or 0),
        "operstate": read_text(base / "operstate"),
        "has_default_route": name in default_interfaces,
        "addresses": ip_addresses,
        "pci_address": pci_address,
        "driver": driver,
        "iommu_group": group_id,
        "iommu_group_devices": group_members,
        "iommu_group_device_details": group_details,
    }


def management_ping(gateway: str) -> dict[str, Any]:
    result = run(("ping", "-c", "1", "-W", "2", gateway), timeout=5.0)
    return {"target": gateway, "passed": result["return_code"] == 0, "return_code": result["return_code"]}


def resolve_toolchain_root(configured: str) -> Path:
    """Resolve a user-scoped prefix correctly even when invoked through sudo."""
    if configured.startswith("~/") and os.environ.get("SUDO_USER"):
        try:
            import pwd

            home = Path(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir)
            return home / configured[2:]
        except (ImportError, KeyError):
            pass
    return Path(os.path.expanduser(configured))


def collect_discovery(config: Mapping[str, Any]) -> dict[str, Any]:
    require_linux()
    address_list = read_json_command(("ip", "-json", "address", "show"))
    addresses = {item.get("ifname"): item for item in address_list if item.get("ifname")}
    default_routes = read_json_command(("ip", "-json", "route", "show", "default"))
    default_interfaces = {item.get("dev") for item in default_routes if item.get("dev")}
    try:
        interface_names = sorted(item.name for item in Path("/sys/class/net").iterdir())
    except OSError:
        interface_names = []
    interfaces = {
        name: interface_facts(name, addresses, default_interfaces)
        for name in interface_names
        if name != "lo"
    }
    toolchain_root = resolve_toolchain_root(config["ubuntu"]["toolchain_root"])
    dpdk_prefix = toolchain_root / "dpdk" / "25.11.2"
    testpmd = dpdk_prefix / "bin" / "dpdk-testpmd"
    devbind_candidates = (
        dpdk_prefix / "bin" / "dpdk-devbind.py",
        dpdk_prefix / "share" / "dpdk" / "usertools" / "dpdk-devbind.py",
    )
    devbind = next((item for item in devbind_candidates if item.is_file()), None)
    hugepage_path = Path(
        f"/sys/kernel/mm/hugepages/hugepages-{config['runtime']['hugepage_size_kb']}kB/nr_hugepages"
    )
    mount = run(("findmnt", "--noheadings", "--output", "FSTYPE", "/dev/hugepages"))
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "discovery",
        "generated_at_utc": utc_now(),
        "host": {
            "hostname": socket.gethostname(),
            "os": parse_os_release(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
        },
        "default_routes": default_routes,
        "interfaces": interfaces,
        "iommu": {
            "groups_present": Path("/sys/kernel/iommu_groups").is_dir()
            and any(Path("/sys/kernel/iommu_groups").iterdir()),
        },
        "hugepages": {
            "path": str(hugepage_path),
            "supported": hugepage_path.is_file(),
            "current_count": int(read_text(hugepage_path) or 0),
            "mountpoint": "/dev/hugepages",
            "mounted": mount["return_code"] == 0 and mount["stdout"] == "hugetlbfs",
        },
        "toolchain": {
            "root": str(toolchain_root),
            "dpdk_prefix": str(dpdk_prefix),
            "library_directory": str(dpdk_prefix / "lib"),
            "testpmd": str(testpmd),
            "testpmd_present": testpmd.is_file() and os.access(testpmd, os.X_OK),
            "devbind": str(devbind) if devbind else None,
            "devbind_present": devbind is not None,
        },
        "management_ping": management_ping(config["ubuntu"]["management_gateway"]),
    }


def assess_iommu_group(
    config: Mapping[str, Any], data: Mapping[str, Any] | None, management: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Approve a singleton group or the exact VMware root-port topology observed in this lab."""
    if not isinstance(data, Mapping) or not data.get("pci_address") or not data.get("iommu_group"):
        return {"approved": False, "mode": None, "reason": "data PCI device has no IOMMU group", "companions": []}
    target = data["pci_address"]
    members = data.get("iommu_group_devices", [])
    if not isinstance(members, list) or target not in members:
        return {"approved": False, "mode": None, "reason": "IOMMU membership does not contain the data PCI device", "companions": []}
    if len(members) == 1:
        return {"approved": True, "mode": "singleton", "reason": "data PCI device is the only group member", "companions": []}
    if config.get("safety", {}).get("iommu_group_policy") != APPROVED_IOMMU_POLICY:
        return {"approved": False, "mode": None, "reason": "shared IOMMU groups are not enabled by policy", "companions": []}
    management_pci = management.get("pci_address") if isinstance(management, Mapping) else None
    if management_pci in members:
        return {"approved": False, "mode": None, "reason": "management PCI device shares the data IOMMU group", "companions": []}
    details = data.get("iommu_group_device_details", [])
    if not isinstance(details, list):
        details = []
    detail_by_address = {
        item.get("pci_address"): item
        for item in details
        if isinstance(item, Mapping) and isinstance(item.get("pci_address"), str)
    }
    if set(detail_by_address) != set(members):
        return {
            "approved": False,
            "mode": None,
            "reason": "complete PCI class/driver facts are required for every shared-group member",
            "companions": [],
        }
    expected = config["safety"]["allowed_iommu_bridge_companion"]
    companions: list[dict[str, Any]] = []
    for pci_address in members:
        if pci_address == target:
            continue
        item = detail_by_address[pci_address]
        matches = all(item.get(key) == expected[key] for key in APPROVED_VMWARE_BRIDGE)
        if not matches or item.get("network_interfaces"):
            return {
                "approved": False,
                "mode": None,
                "reason": f"unapproved IOMMU companion: {pci_address}",
                "companions": companions,
                "rejected": dict(item),
            }
        companions.append(dict(item))
    if not companions:
        return {"approved": False, "mode": None, "reason": "shared group has no approved bridge companions", "companions": []}
    return {
        "approved": True,
        "mode": "vmware_root_ports",
        "reason": "all non-target members are approved VMware PCIe Root Ports",
        "companions": companions,
    }


def evaluate_preflight(
    config: Mapping[str, Any], discovery: Mapping[str, Any], data_interface: str
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def check(name: str, condition: bool, expected: Any, observed: Any) -> None:
        checks.append(
            {"name": name, "status": "passed" if condition else "failed", "expected": expected, "observed": observed}
        )

    os_release = discovery.get("host", {}).get("os", {})
    check("host.os", os_release.get("ID") == "ubuntu", "ubuntu", os_release.get("ID"))
    check("host.version", str(os_release.get("VERSION_ID", "")).startswith("24.04"), "24.04.x", os_release.get("VERSION_ID"))
    check("host.architecture", discovery.get("host", {}).get("architecture") == "x86_64", "x86_64", discovery.get("host", {}).get("architecture"))
    interfaces = discovery.get("interfaces", {})
    management_name = config["ubuntu"]["management_interface"]
    management = interfaces.get(management_name)
    data = interfaces.get(data_interface)
    check("management.present", isinstance(management, Mapping), True, management is not None)
    check(
        "management.default_route",
        isinstance(management, Mapping) and management.get("has_default_route") is True,
        True,
        management.get("has_default_route") if isinstance(management, Mapping) else None,
    )
    check("management.ping", discovery.get("management_ping", {}).get("passed") is True, True, discovery.get("management_ping", {}).get("passed"))
    check("data.distinct", data_interface != management_name, f"not {management_name}", data_interface)
    check("data.present", isinstance(data, Mapping), True, data is not None)
    check(
        "data.no_default_route",
        isinstance(data, Mapping) and data.get("has_default_route") is False,
        False,
        data.get("has_default_route") if isinstance(data, Mapping) else None,
    )
    check(
        "data.driver",
        isinstance(data, Mapping) and data.get("driver") == config["ubuntu"]["expected_data_driver"],
        config["ubuntu"]["expected_data_driver"],
        data.get("driver") if isinstance(data, Mapping) else None,
    )
    check("data.pci", isinstance(data, Mapping) and bool(data.get("pci_address")), "PCI address", data.get("pci_address") if isinstance(data, Mapping) else None)
    group = data.get("iommu_group") if isinstance(data, Mapping) else None
    check("iommu.available", discovery.get("iommu", {}).get("groups_present") is True and bool(group), True, {"groups_present": discovery.get("iommu", {}).get("groups_present"), "data_group": group})
    group_assessment = assess_iommu_group(config, data if isinstance(data, Mapping) else None, management if isinstance(management, Mapping) else None)
    check(
        "iommu.group_policy",
        group_assessment["approved"],
        APPROVED_IOMMU_POLICY,
        group_assessment,
    )
    check("hugepages.supported", discovery.get("hugepages", {}).get("supported") is True, True, discovery.get("hugepages", {}).get("supported"))
    check("toolchain.testpmd", discovery.get("toolchain", {}).get("testpmd_present") is True, True, discovery.get("toolchain", {}).get("testpmd"))
    check("toolchain.devbind", discovery.get("toolchain", {}).get("devbind_present") is True, True, discovery.get("toolchain", {}).get("devbind"))
    return checks


def validate_preflight(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["preflight root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION or document.get("task") != TASK:
        errors.append("preflight schema/task mismatch")
    if document.get("kind") != "preflight":
        errors.append("kind must equal preflight")
    if document.get("status") not in ("passed", "failed"):
        errors.append("status must be passed or failed")
    if not isinstance(document.get("configuration"), Mapping):
        errors.append("configuration must be an object")
    else:
        config_errors = validate_config(document["configuration"])
        if config_errors:
            errors.append("embedded configuration is invalid: " + "; ".join(config_errors))
    if not isinstance(document.get("discovery"), Mapping):
        errors.append("discovery must be an object")
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty array")
    else:
        all_passed = all(isinstance(item, Mapping) and item.get("status") == "passed" for item in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("preflight status must match aggregate checks")
    return errors


def ensure_management(config: Mapping[str, Any]) -> None:
    ping = management_ping(config["ubuntu"]["management_gateway"])
    if not ping["passed"]:
        raise RuntimeError(f"management gateway {ping['target']} is unreachable")


def validate_dpdk_file_prefix(file_prefix: str) -> None:
    if file_prefix != DPDK_FILE_PREFIX:
        raise ValueError(f"DPDK file prefix must equal {DPDK_FILE_PREFIX}")


def hugepage_artifacts_for_prefix(
    file_prefix: str,
    mountpoint: Path = HUGEPAGE_MOUNTPOINT,
) -> list[Path]:
    """Return only exact DPDK hugepage artifacts owned by the smoke-test prefix."""
    validate_dpdk_file_prefix(file_prefix)
    pattern = re.compile(rf"^{re.escape(file_prefix)}map_[0-9]+$")
    try:
        return sorted((item for item in mountpoint.iterdir() if pattern.fullmatch(item.name)), key=lambda item: item.name)
    except FileNotFoundError:
        return []


def dpdk_runtime_path(file_prefix: str, runtime_root: Path = DPDK_RUNTIME_ROOT) -> Path:
    validate_dpdk_file_prefix(file_prefix)
    return runtime_root / file_prefix


def ensure_dpdk_prefix_clean(
    file_prefix: str,
    mountpoint: Path = HUGEPAGE_MOUNTPOINT,
    runtime_root: Path = DPDK_RUNTIME_ROOT,
) -> None:
    hugepage_artifacts = hugepage_artifacts_for_prefix(file_prefix, mountpoint)
    runtime_path = dpdk_runtime_path(file_prefix, runtime_root)
    if hugepage_artifacts or runtime_path.exists() or runtime_path.is_symlink():
        names = [str(item) for item in hugepage_artifacts]
        if runtime_path.exists() or runtime_path.is_symlink():
            names.append(str(runtime_path))
        raise RuntimeError(
            f"stale DPDK artifacts exist for prefix {file_prefix}: {', '.join(names)}; "
            "run rollback or inspect them before apply"
        )


def cleanup_dpdk_prefix_artifacts(
    file_prefix: str,
    mountpoint: Path = HUGEPAGE_MOUNTPOINT,
    runtime_root: Path = DPDK_RUNTIME_ROOT,
) -> dict[str, Any]:
    """Delete only artifacts whose exact owner is the locked smoke-test prefix."""
    hugepage_artifacts = hugepage_artifacts_for_prefix(file_prefix, mountpoint)
    for artifact in hugepage_artifacts:
        if artifact.is_dir() and not artifact.is_symlink():
            raise RuntimeError(f"refusing unexpected hugepage directory: {artifact}")
        artifact.unlink()

    runtime_path = dpdk_runtime_path(file_prefix, runtime_root)
    runtime_removed = False
    if runtime_path.is_symlink() or runtime_path.is_file():
        runtime_path.unlink()
        runtime_removed = True
    elif runtime_path.is_dir():
        shutil.rmtree(runtime_path)
        runtime_removed = True

    remaining = hugepage_artifacts_for_prefix(file_prefix, mountpoint)
    if remaining or runtime_path.exists() or runtime_path.is_symlink():
        raise RuntimeError(f"DPDK artifacts remain for prefix {file_prefix}")
    return {
        "file_prefix": file_prefix,
        "hugepage_files_removed": len(hugepage_artifacts),
        "runtime_path": str(runtime_path),
        "runtime_path_removed": runtime_removed,
    }


def bind_driver(devbind: str, driver: str, pci_address: str) -> None:
    run((sys.executable, devbind, f"--bind={driver}", pci_address), timeout=30.0, check=True)


def driver_for_pci(pci_address: str) -> str | None:
    link = Path("/sys/bus/pci/devices") / pci_address / "driver"
    return link.resolve().name if link.exists() else None


def write_pci_driver_control(path: Path, pci_address: str) -> None:
    path.write_text(pci_address, encoding="ascii")


def unbind_pci_driver(pci_address: str, expected_driver: str) -> None:
    observed = driver_for_pci(pci_address)
    if observed != expected_driver:
        raise RuntimeError(f"PCI {pci_address} driver is {observed!r}, expected {expected_driver!r} before unbind")
    control = Path("/sys/bus/pci/devices") / pci_address / "driver" / "unbind"
    write_pci_driver_control(control, pci_address)
    observed = driver_for_pci(pci_address)
    if observed is not None:
        raise RuntimeError(f"PCI {pci_address} is still bound to {observed!r} after unbind")


def bind_pci_kernel_driver(pci_address: str, expected_driver: str) -> None:
    observed = driver_for_pci(pci_address)
    if observed == expected_driver:
        return
    if observed is not None:
        raise RuntimeError(f"PCI {pci_address} is bound to unexpected driver {observed!r}")
    control = Path("/sys/bus/pci/drivers") / expected_driver / "bind"
    write_pci_driver_control(control, pci_address)
    observed = driver_for_pci(pci_address)
    if observed != expected_driver:
        raise RuntimeError(f"PCI {pci_address} driver is {observed!r}, expected {expected_driver!r} after rebind")


def restore_pci_drivers(devices: Sequence[Mapping[str, Any]]) -> None:
    errors: list[str] = []
    for device in devices:
        try:
            bind_pci_kernel_driver(str(device["pci_address"]), str(device["driver"]))
        except (KeyError, RuntimeError, OSError) as error:
            errors.append(str(error))
    if errors:
        raise RuntimeError("failed to restore one or more IOMMU bridges: " + "; ".join(errors))


def interfaces_for_pci(pci_address: str) -> list[str]:
    return sorted(
        item.name
        for item in Path("/sys/class/net").glob("*")
        if (item / "device").exists() and (item / "device").resolve().name == pci_address
    )


def find_interface_for_pci(
    pci_address: str, timeout: float = 10.0, preferred_name: str | None = None
) -> str | None:
    deadline = time.monotonic() + timeout
    fallback: str | None = None
    while time.monotonic() < deadline:
        names = interfaces_for_pci(pci_address)
        if preferred_name in names:
            return preferred_name
        if names:
            fallback = names[0]
        time.sleep(0.2)
    return fallback


def restore_interface_address(interface: str, address: str) -> None:
    family = "-6" if ":" in address else "-4"
    local_address = address.split("/", 1)[0]
    show_command = ("ip", family, "-o", "address", "show", "dev", interface)

    def address_is_present(output: str) -> bool:
        return any(
            token.split("/", 1)[0] == local_address
            for token in output.split()
        )

    current = run(show_command, check=True)
    if address_is_present(current["stdout"]):
        return

    add_command = ("ip", family, "address", "add", address, "dev", interface)
    added = run(add_command)
    if added["return_code"] == 0:
        return

    current = run(show_command, check=True)
    if address_is_present(current["stdout"]):
        return
    detail = added["stderr"] or added["stdout"] or "unknown error"
    raise RuntimeError(f"command failed ({' '.join(add_command)}): {detail}")


def rollback_state(state: dict[str, Any]) -> dict[str, Any]:
    config = state["configuration"]
    original = state["original"]
    pci_address = original["pci_address"]
    original_driver = original["driver"]
    devbind = state["toolchain"]["devbind"]
    checks: list[dict[str, Any]] = []

    def action(name: str, function: Any) -> None:
        try:
            function()
            checks.append({"name": name, "status": "passed"})
        except Exception as error:  # rollback must attempt every independent restoration
            checks.append({"name": name, "status": "failed", "detail": str(error)})

    active = run(("pgrep", "-x", "dpdk-testpmd"))
    if active["return_code"] == 0:
        raise RuntimeError("dpdk-testpmd is still running; stop it before rollback")

    bridge_companions = original.get("iommu_bridge_companions", [])

    def restore_bridges() -> None:
        restore_pci_drivers(bridge_companions)

    action("iommu_bridges.restored", restore_bridges)

    def restore_driver() -> None:
        run(("modprobe", original_driver), check=True)
        if driver_for_pci(pci_address) != original_driver:
            bind_driver(devbind, original_driver, pci_address)
        if driver_for_pci(pci_address) != original_driver:
            raise RuntimeError(f"driver did not return to {original_driver}")

    action("driver.restored", restore_driver)
    interface_holder: dict[str, str | None] = {"name": None}

    def restore_interface() -> None:
        run(("udevadm", "settle", "--timeout=15"))
        name = find_interface_for_pci(pci_address, timeout=15.0, preferred_name=original["interface"])
        interface_holder["name"] = name
        if not name:
            raise RuntimeError("kernel interface did not reappear")
        run(("ip", "link", "set", "dev", name, "mtu", str(original["mtu"])), check=True)
        for address in original["addresses"]:
            restore_interface_address(name, address)
        link_mode = "up" if original["operstate"] not in ("down", "notpresent") else "down"
        run(("ip", "link", "set", "dev", name, link_mode), check=True)

    action("interface.restored", restore_interface)

    def cleanup_prefix() -> None:
        state["dpdk_prefix_cleanup"] = cleanup_dpdk_prefix_artifacts(
            config["runtime"]["file_prefix"]
        )

    action("dpdk_prefix.cleaned", cleanup_prefix)

    def restore_hugepages() -> None:
        Path(original["hugepage_path"]).write_text(str(original["hugepage_count"]), encoding="ascii")
        observed = int(read_text(Path(original["hugepage_path"])) or -1)
        if observed != original["hugepage_count"]:
            raise RuntimeError(f"hugepage count is {observed}, expected {original['hugepage_count']}")

    action("hugepages.restored", restore_hugepages)

    def restore_mount() -> None:
        if not original["hugepages_mounted"]:
            mounted = run(("findmnt", "--noheadings", "/dev/hugepages"))["return_code"] == 0
            if mounted:
                run(("umount", "/dev/hugepages"), check=True)

    action("hugepages.mount_restored", restore_mount)
    action("management.reachable", lambda: ensure_management(config))
    status = "passed" if all(item["status"] == "passed" for item in checks) else "failed"
    state["status"] = "rolled_back" if status == "passed" else "rollback_failed"
    state["rollback"] = {"completed_at_utc": utc_now(), "status": status, "checks": checks}
    state["restored_interface"] = interface_holder["name"]
    return state


def command_discover(args: argparse.Namespace) -> int:
    config = load_json(args.config)
    errors = validate_config(config)
    if errors:
        raise ValueError("invalid config: " + "; ".join(errors))
    document = collect_discovery(config)
    document["config"] = {"file": args.config.name, "sha256": sha256_file(args.config)}
    write_new_json(args.output, document, args.force)
    print(f"wrote {args.output}; found {len(document['interfaces'])} non-loopback interface(s)")
    return 0


def command_preflight(args: argparse.Namespace) -> int:
    config = load_json(args.config)
    errors = validate_config(config)
    if errors:
        raise ValueError("invalid config: " + "; ".join(errors))
    discovery = collect_discovery(config)
    checks = evaluate_preflight(config, discovery, args.data_interface)
    status = "passed" if all(item["status"] == "passed" for item in checks) else "failed"
    document = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "preflight",
        "status": status,
        "generated_at_utc": utc_now(),
        "data_interface": args.data_interface,
        "configuration": config,
        "config": {"file": args.config.name, "sha256": sha256_file(args.config)},
        "discovery": discovery,
        "checks": checks,
    }
    write_new_json(args.output, document, args.force)
    print(f"wrote {args.output} ({status})")
    for item in checks:
        if item["status"] == "failed":
            print(f"failed: {item['name']} (observed={item['observed']!r})", file=sys.stderr)
    return 0 if status == "passed" else 1


def command_apply(args: argparse.Namespace) -> int:
    require_root()
    preflight = load_json(args.preflight)
    errors = validate_preflight(preflight)
    if errors:
        raise ValueError("invalid preflight receipt: " + "; ".join(errors))
    if preflight["status"] != "passed":
        raise ValueError("refusing to apply a failed preflight")
    config = preflight["configuration"]
    current = collect_discovery(config)
    checks = evaluate_preflight(config, current, preflight["data_interface"])
    failed = [item["name"] for item in checks if item["status"] != "passed"]
    if failed:
        raise RuntimeError("current host no longer matches preflight: " + ", ".join(failed))
    data = current["interfaces"][preflight["data_interface"]]
    management = current["interfaces"].get(config["ubuntu"]["management_interface"])
    group_assessment = assess_iommu_group(config, data, management)
    if not group_assessment["approved"]:
        raise RuntimeError(f"IOMMU group policy changed after preflight: {group_assessment['reason']}")
    ensure_dpdk_prefix_clean(config["runtime"]["file_prefix"])
    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "state",
        "status": "prepared",
        "prepared_at_utc": utc_now(),
        "preflight": {"file": args.preflight.name, "sha256": sha256_file(args.preflight)},
        "configuration": config,
        "configuration_sha256": json_sha256(config),
        "toolchain": current["toolchain"],
        "original": {
            "interface": preflight["data_interface"],
            "pci_address": data["pci_address"],
            "driver": data["driver"],
            "mac": data["mac"],
            "mtu": data["mtu"],
            "operstate": data["operstate"],
            "addresses": data["addresses"],
            "iommu_group": data["iommu_group"],
            "iommu_group_devices": data["iommu_group_devices"],
            "iommu_group_mode": group_assessment["mode"],
            "iommu_bridge_companions": group_assessment["companions"],
            "hugepage_path": current["hugepages"]["path"],
            "hugepage_count": current["hugepages"]["current_count"],
            "hugepages_mounted": current["hugepages"]["mounted"],
        },
    }
    write_new_json(args.state, state, args.force)
    mutated = False
    try:
        ensure_management(config)
        run(("modprobe", "vfio-pci"), check=True)
        hugepage_path = Path(state["original"]["hugepage_path"])
        requested_hugepages = config["runtime"]["hugepage_count"]
        hugepage_path.write_text(str(requested_hugepages), encoding="ascii")
        mutated = True
        actual_hugepages = int(read_text(hugepage_path) or -1)
        if actual_hugepages < requested_hugepages:
            raise RuntimeError(
                "the kernel could not reserve the requested number of hugepages "
                f"(requested={requested_hugepages}, actual={actual_hugepages}, "
                f"page_size_kb={config['runtime']['hugepage_size_kb']})"
            )
        if not current["hugepages"]["mounted"]:
            Path("/dev/hugepages").mkdir(parents=True, exist_ok=True)
            run(("mount", "-t", "hugetlbfs", "nodev", "/dev/hugepages"), check=True)
        run(("ip", "link", "set", "dev", preflight["data_interface"], "down"), check=True)
        for companion in group_assessment["companions"]:
            unbind_pci_driver(companion["pci_address"], companion["driver"])
        ensure_management(config)
        bind_driver(current["toolchain"]["devbind"], "vfio-pci", data["pci_address"])
        if driver_for_pci(data["pci_address"]) != "vfio-pci":
            raise RuntimeError("data PCI device was not bound to vfio-pci")
        for companion in group_assessment["companions"]:
            if driver_for_pci(companion["pci_address"]) is not None:
                raise RuntimeError(f"IOMMU bridge {companion['pci_address']} was rebound unexpectedly")
        vfio_group = Path("/dev/vfio") / str(data["iommu_group"])
        if not vfio_group.exists():
            raise RuntimeError(f"VFIO group device did not appear: {vfio_group}")
        ensure_management(config)
        state["status"] = "applied"
        state["applied_at_utc"] = utc_now()
        state["checks"] = {
            "data_driver": "vfio-pci",
            "iommu_group_mode": group_assessment["mode"],
            "iommu_bridges_unbound": [item["pci_address"] for item in group_assessment["companions"]],
            "vfio_group_device": str(vfio_group),
            "management_ping": True,
        }
        replace_json(args.state, state)
        print(f"applied reversible runtime state; saved rollback data to {args.state}")
        return 0
    except Exception:
        if mutated:
            try:
                rollback_state(state)
            finally:
                replace_json(args.state, state)
        raise


def parse_testpmd_counters(output: str) -> dict[str, int]:
    labels = {
        "rx_packets": r"RX-packets:\s*(\d+)",
        "tx_packets": r"TX-packets:\s*(\d+)",
        "rx_missed": r"RX-missed:\s*(\d+)",
        "rx_errors": r"RX-errors:\s*(\d+)",
        "tx_errors": r"TX-errors:\s*(\d+)",
        "rx_nombuf": r"RX-nombuf:\s*(\d+)",
    }
    counters: dict[str, int] = {}
    for name, pattern in labels.items():
        values = [int(value) for value in re.findall(pattern, output, flags=re.IGNORECASE)]
        counters[name] = max(values, default=0)
    return counters


def build_testpmd_command(state: Mapping[str, Any]) -> list[str]:
    config = state["configuration"]
    runtime = config["runtime"]
    return [
        state["toolchain"]["testpmd"],
        "-l", runtime["lcores"],
        "-n", str(runtime["memory_channels"]),
        "-a", state["original"]["pci_address"],
        "-m", str(runtime["dpdk_memory_mb"]),
        f"--file-prefix={runtime['file_prefix']}",
        f"--huge-unlink={runtime['huge_unlink']}",
        "--",
        "-i",
        f"--total-num-mbufs={runtime['total_num_mbufs']}",
        "--port-topology=loop",
        f"--forward-mode={runtime['forward_mode']}",
        "--stats-period=10",
    ]


def command_run(args: argparse.Namespace) -> int:
    require_root()
    state = load_json(args.state)
    if state.get("schema_version") != SCHEMA_VERSION or state.get("task") != TASK or state.get("status") != "applied":
        raise ValueError("state must be an applied T0.3 state")
    if args.output.exists() and not args.force:
        raise ValueError(f"refusing to overwrite existing file: {args.output}; pass --force to replace it")
    if args.log.exists() and not args.force:
        raise ValueError(f"refusing to overwrite existing file: {args.log}; pass --force to replace it")
    config = state["configuration"]
    pci_address = state["original"]["pci_address"]
    if driver_for_pci(pci_address) != "vfio-pci":
        raise RuntimeError("data PCI device is not bound to vfio-pci")
    for companion in state["original"].get("iommu_bridge_companions", []):
        observed_driver = driver_for_pci(companion["pci_address"])
        if observed_driver is not None:
            raise RuntimeError(
                f"IOMMU bridge {companion['pci_address']} must remain unbound during testpmd; observed {observed_driver!r}"
            )
    ensure_management(config)
    duration = args.duration if args.duration is not None else config["runtime"]["duration_seconds"]
    if duration <= 0:
        raise ValueError("duration must be positive")
    command = build_testpmd_command(state)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    monotonic_start = time.monotonic()
    with args.log.open("w", encoding="utf-8", newline="\n") as log:
        library_directory = state["toolchain"]["library_directory"]
        library_path = library_directory
        if os.environ.get("LD_LIBRARY_PATH"):
            library_path += os.pathsep + os.environ["LD_LIBRARY_PATH"]
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "LC_ALL": "C", "LD_LIBRARY_PATH": library_path},
        )
        try:
            time.sleep(3.0)
            if process.poll() is not None:
                raise RuntimeError(f"dpdk-testpmd exited during startup with code {process.returncode}")
            assert process.stdin is not None
            process.stdin.write("start\n")
            process.stdin.flush()
            print(
                f"READY: send traffic to {state['original']['mac']} on "
                f"{state['configuration']['topology']['data_network']['name']} for {duration} seconds",
                flush=True,
            )
            time.sleep(duration)
            process.stdin.write("show port stats all\nstop\nshow port stats all\nquit\n")
            process.stdin.flush()
            return_code = process.wait(timeout=20.0)
        except Exception:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
            raise
    ended_at = utc_now()
    elapsed = time.monotonic() - monotonic_start - 3.0
    output_text = args.log.read_text(encoding="utf-8", errors="replace")
    counters = parse_testpmd_counters(output_text)
    management_after = management_ping(config["ubuntu"]["management_gateway"])
    passed = return_code == 0 and counters["rx_packets"] > 0 and counters["tx_packets"] > 0 and management_after["passed"]
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "run",
        "status": "passed" if passed else "failed",
        "generated_at_utc": utc_now(),
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_seconds": round(elapsed, 3),
        "requested_duration_seconds": duration,
        "pci_address": pci_address,
        "data_mac": state["original"]["mac"],
        "command": command,
        "return_code": return_code,
        "counters": counters,
        "management_ping_after": management_after,
        "log": {"file": args.log.name, "sha256": sha256_file(args.log)},
        "state": {"file": args.state.name, "sha256": sha256_file(args.state)},
    }
    write_new_json(args.output, receipt, args.force)
    print(f"wrote {args.output} ({receipt['status']}); RX={counters['rx_packets']} TX={counters['tx_packets']}")
    return 0 if passed else 1


def command_rollback(args: argparse.Namespace) -> int:
    require_root()
    state = load_json(args.state)
    if state.get("schema_version") != SCHEMA_VERSION or state.get("task") != TASK:
        raise ValueError("invalid T0.3 state")
    if state.get("status") == "rolled_back":
        raise ValueError("state has already been rolled back")
    state = rollback_state(state)
    replace_json(args.state, state)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "rollback",
        "status": state["rollback"]["status"],
        "generated_at_utc": utc_now(),
        "checks": state["rollback"]["checks"],
        "restored": {
            "driver": state["original"]["driver"],
            "interface": state.get("restored_interface"),
            "iommu_bridges": [
                {"pci_address": item["pci_address"], "driver": item["driver"]}
                for item in state["original"].get("iommu_bridge_companions", [])
            ],
            "hugepage_count": state["original"]["hugepage_count"],
            "management_gateway": state["configuration"]["ubuntu"]["management_gateway"],
        },
        "state": {"file": args.state.name, "sha256": sha256_file(args.state)},
    }
    write_new_json(args.output, receipt, args.force)
    print(f"wrote {args.output} ({receipt['status']})")
    return 0 if receipt["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    discover = subparsers.add_parser("discover", help="collect read-only host/NIC facts")
    discover.add_argument("--config", required=True, type=Path)
    discover.add_argument("--output", required=True, type=Path)
    discover.add_argument("--force", action="store_true")
    discover.set_defaults(handler=command_discover)
    preflight = subparsers.add_parser("preflight", help="apply all safety gates without changing the host")
    preflight.add_argument("--config", required=True, type=Path)
    preflight.add_argument("--data-interface", required=True)
    preflight.add_argument("--output", required=True, type=Path)
    preflight.add_argument("--force", action="store_true")
    preflight.set_defaults(handler=command_preflight)
    apply = subparsers.add_parser("apply", help="reserve runtime hugepages and bind only the approved data NIC")
    apply.add_argument("--preflight", required=True, type=Path)
    apply.add_argument("--state", required=True, type=Path)
    apply.add_argument("--force", action="store_true")
    apply.set_defaults(handler=command_apply)
    execute = subparsers.add_parser("run", help="run interactive testpmd and collect counters")
    execute.add_argument("--state", required=True, type=Path)
    execute.add_argument("--output", required=True, type=Path)
    execute.add_argument("--log", required=True, type=Path)
    execute.add_argument("--duration", type=int)
    execute.add_argument("--force", action="store_true")
    execute.set_defaults(handler=command_run)
    rollback = subparsers.add_parser("rollback", help="restore the original driver, addresses and hugepages")
    rollback.add_argument("--state", required=True, type=Path)
    rollback.add_argument("--output", required=True, type=Path)
    rollback.add_argument("--force", action="store_true")
    rollback.set_defaults(handler=command_rollback)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (RuntimeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
