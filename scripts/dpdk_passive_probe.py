#!/usr/bin/env python3
"""Prepare and run the bounded T0.4 DPDK passive-visibility probe."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import errno
import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

import dpdk_smoke as dpdk
import kali_passive_traffic as passive_contract


SCHEMA_VERSION = "1.0.0"
TASK = "T0.4"
RESOURCE_PURPOSE = "T0.4_passive_resource"
RESOURCE_PREFIX = "nids-t03"
PASSIVE_PREFIX = "nids-t04"
HUGEPAGE_ROOT = Path("/dev/hugepages")
RUNTIME_ROOT = Path("/var/run/dpdk")
DEFAULT_ARM_TIMEOUT_SECONDS = 600
DEFAULT_POST_SENDER_GRACE_SECONDS = 3
RETRY_ARTIFACTS = (
    "testpmd.log",
    "probe-console.log",
    "windows-receiver.json",
    "windows-receiver.log",
    "kali-sender.json",
    "kali-sender.log",
    "sensor.json",
    "rollback.json",
    "rollback.log",
    "acceptance.json",
    "acceptance.log",
)

FRAME_PATTERN = re.compile(
    r"src\s*=\s*([0-9a-f:-]{17})\s*-\s*dst\s*=\s*([0-9a-f:-]{17})"
    r"[^\r\n]*?\btype\s*=\s*(0x[0-9a-f]{4})"
    r"[^\r\n]*?\blength\s*=\s*(\d+)",
    re.IGNORECASE,
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_mac(value: str) -> str:
    return value.replace("-", ":").lower()


def project_paths(config_path: Path, *paths: Path) -> list[Path]:
    project_root = config_path.resolve().parent.parent
    artifact_root = (project_root / "run_log/t0.4").resolve()
    resolved: list[Path] = []
    for path in paths:
        candidate = path if path.is_absolute() else project_root / path
        item = candidate.resolve()
        if item == artifact_root or artifact_root not in item.parents:
            raise ValueError(f"artifact must be a file below {artifact_root}: {item}")
        resolved.append(item)
    return resolved


def build_resource_config(config: Mapping[str, Any]) -> dict[str, Any]:
    topology = config["topology"]
    sensor = config["ubuntu_sensor"]
    runtime = config["dpdk"]
    return {
        "schema_version": SCHEMA_VERSION,
        "task": "T0.3",
        "topology": {
            "hypervisor": "VMware Workstation 17",
            "management_network": dict(topology["management_network"]),
            "data_network": dict(topology["data_network"]),
        },
        "ubuntu": {
            "management_interface": sensor["management_interface"],
            "management_gateway": sensor["management_gateway"],
            "expected_data_driver": sensor["expected_driver"],
            "toolchain_root": "~/.local/nids-toolchain",
        },
        "kali": {
            "management_interface": "eth0",
            "data_ipv4": f"{config['kali']['data_ipv4']}/24",
        },
        "runtime": {
            "hugepage_size_kb": runtime["hugepage_size_kb"],
            "hugepage_count": runtime["hugepage_count"],
            "dpdk_memory_mb": runtime["memory_mb"],
            "file_prefix": RESOURCE_PREFIX,
            "huge_unlink": runtime["huge_unlink"],
            "total_num_mbufs": runtime["total_num_mbufs"],
            "lcores": runtime["lcores"],
            "memory_channels": runtime["memory_channels"],
            "duration_seconds": config["traffic"]["receiver_timeout_seconds"],
            "forward_mode": "macswap",
        },
        "safety": {
            "require_iommu": True,
            "allow_no_iommu": False,
            "iommu_group_policy": "singleton_or_vmware_root_ports",
            "allowed_iommu_bridge_companion": dict(dpdk.APPROVED_VMWARE_BRIDGE),
            "preserve_management_connectivity": True,
            "persistent_boot_changes": False,
        },
    }


def command_preflight(args: argparse.Namespace) -> int:
    dpdk.require_linux()
    config_path = args.config.resolve()
    config = passive_contract.load_and_validate_config(config_path)
    output, = project_paths(config_path, args.output)
    if output.exists():
        raise ValueError(f"refusing to overwrite existing receipt: {output}")

    resource_config = build_resource_config(config)
    errors = dpdk.validate_config(resource_config)
    if errors:
        raise ValueError("generated resource configuration is invalid: " + "; ".join(errors))
    data_interface = config["ubuntu_sensor"]["data_interface"]
    discovery = dpdk.collect_discovery(resource_config)
    checks = dpdk.evaluate_preflight(resource_config, discovery, data_interface)
    observed_mac = discovery.get("interfaces", {}).get(data_interface, {}).get("mac")
    expected_mac = config["ubuntu_sensor"]["expected_mac"]
    checks.append(
        {
            "name": "data.mac",
            "status": "passed" if normalize_mac(str(observed_mac)) == normalize_mac(expected_mac) else "failed",
            "expected": normalize_mac(expected_mac),
            "observed": normalize_mac(str(observed_mac)),
        }
    )
    status = "passed" if all(item["status"] == "passed" for item in checks) else "failed"
    document = {
        "schema_version": SCHEMA_VERSION,
        "task": "T0.3",
        "kind": "preflight",
        "status": status,
        "purpose": RESOURCE_PURPOSE,
        "generated_at_utc": utc_now(),
        "data_interface": data_interface,
        "configuration": resource_config,
        "config": {"file": "embedded:T0.4", "sha256": dpdk.json_sha256(resource_config)},
        "passive_config": {"file": str(config_path), "sha256": dpdk.sha256_file(config_path)},
        "discovery": discovery,
        "checks": checks,
    }
    dpdk.write_new_json(output, document)
    print(f"wrote {output} ({status})")
    for item in checks:
        if item["status"] == "failed":
            print(f"failed: {item['name']} (observed={item['observed']!r})", file=sys.stderr)
    return 0 if status == "passed" else 1


def archive_failed_attempt(artifact_root: Path, preserve: Sequence[str] = ()) -> Path | None:
    preserved = set(preserve)
    existing = [
        artifact_root / name
        for name in RETRY_ARTIFACTS
        if name not in preserved and (artifact_root / name).is_file()
    ]
    if not existing:
        return None
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = artifact_root / "attempts" / f"failed-{stamp}"
    suffix = 1
    while archive.exists():
        archive = artifact_root / "attempts" / f"failed-{stamp}-{suffix:02d}"
        suffix += 1
    archive.mkdir(parents=True)
    records: list[dict[str, str]] = []
    for source in existing:
        digest = dpdk.sha256_file(source)
        destination = archive / source.name
        shutil.move(str(source), str(destination))
        records.append(
            {
                "original": str(source),
                "archived": str(destination),
                "sha256": digest,
            }
        )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "failed_attempt_archive",
        "generated_at_utc": utc_now(),
        "files": records,
    }
    dpdk.write_new_json(archive / "archive.json", manifest)
    return archive


def command_retry(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    passive_contract.load_and_validate_config(config_path)
    artifact_root = (config_path.parent.parent / "run_log/t0.4").resolve()
    state_path = artifact_root / "state.json"
    if state_path.is_file():
        state = dpdk.load_json(state_path)
        if state.get("status") != "applied":
            raise ValueError("resource state is not applied; retry cannot replace preflight/apply")
    preserve: list[str] = []
    if args.keep_windows:
        preserve.extend(("windows-receiver.json", "windows-receiver.log"))
    if args.keep_ubuntu:
        preserve.extend(("testpmd.log", "probe-console.log"))
    archive = archive_failed_attempt(artifact_root, preserve)
    if archive is None:
        print("retry workspace is already clean; no attempt artifacts were moved")
    else:
        print(f"archived failed attempt to {archive}")
    return 0


def validate_passive_prefix(prefix: str) -> None:
    if prefix != PASSIVE_PREFIX:
        raise ValueError(f"passive DPDK prefix must equal {PASSIVE_PREFIX}")


def prefix_artifacts(prefix: str) -> tuple[list[Path], Path]:
    validate_passive_prefix(prefix)
    pattern = re.compile(rf"^{re.escape(prefix)}map_[0-9]+$")
    try:
        maps = sorted(item for item in HUGEPAGE_ROOT.iterdir() if pattern.fullmatch(item.name))
    except FileNotFoundError:
        maps = []
    return maps, RUNTIME_ROOT / prefix


def require_clean_prefix(prefix: str) -> None:
    maps, runtime = prefix_artifacts(prefix)
    existing = [str(item) for item in maps]
    if runtime.exists() or runtime.is_symlink():
        existing.append(str(runtime))
    if existing:
        raise RuntimeError(f"stale DPDK artifacts for {prefix}: {', '.join(existing)}")


def cleanup_prefix(prefix: str) -> dict[str, Any]:
    maps, runtime = prefix_artifacts(prefix)
    for item in maps:
        if item.is_dir() and not item.is_symlink():
            raise RuntimeError(f"refusing unexpected hugepage directory: {item}")
        item.unlink()
    if runtime.is_symlink() or runtime.is_file():
        runtime.unlink()
    elif runtime.is_dir():
        shutil.rmtree(runtime)
    remaining, _ = prefix_artifacts(prefix)
    clean = not remaining and not runtime.exists() and not runtime.is_symlink()
    if not clean:
        raise RuntimeError(f"DPDK artifacts remain for {prefix}")
    return {
        "file_prefix": prefix,
        "hugepage_files_removed": len(maps),
        "runtime_path": str(runtime),
        "runtime_path_removed": True,
    }


def build_testpmd_command(config: Mapping[str, Any], state: Mapping[str, Any]) -> list[str]:
    runtime = config["dpdk"]
    return [
        state["toolchain"]["testpmd"],
        "-l", runtime["lcores"],
        "-n", str(runtime["memory_channels"]),
        "-a", state["original"]["pci_address"],
        "-m", str(runtime["memory_mb"]),
        f"--file-prefix={runtime['file_prefix']}",
        f"--huge-unlink={runtime['huge_unlink']}",
        "--",
        "-i",
        f"--total-num-mbufs={runtime['total_num_mbufs']}",
        "--port-topology=loop",
        f"--forward-mode={runtime['forward_mode']}",
    ]


def send_commands(process: subprocess.Popen[bytes], commands: Sequence[str], input_fd: int) -> None:
    if process.poll() is not None:
        raise RuntimeError(f"testpmd exited before command dispatch with code {process.returncode}")
    try:
        os.write(input_fd, ("\n".join(commands) + "\n").encode("ascii"))
    except BrokenPipeError as error:
        raise RuntimeError(f"testpmd closed its command pipe with code {process.poll()}") from error


def drain_output(
    process: subprocess.Popen[bytes], log: Any, captured: bytearray, output_fd: int,
    seconds: float, stop_on_exit: bool = False
) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select([output_fd], [], [], min(0.25, max(0.0, deadline - time.monotonic())))
        if ready:
            try:
                chunk = os.read(output_fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO or process.poll() is not None:
                    break
                raise RuntimeError(f"could not read testpmd terminal: {error}") from error
            if not chunk:
                break
            captured.extend(chunk)
            log.write(chunk)
            log.flush()
        elif stop_on_exit and process.poll() is not None:
            break


def wait_for_prompt(
    process: subprocess.Popen[bytes], log: Any, captured: bytearray, terminal_fd: int,
    start_offset: int, timeout: float
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        drain_output(process, log, captured, terminal_fd, 0.25)
        segment = captured[start_offset:].decode("utf-8", errors="replace")
        if "testpmd>" in segment:
            return segment
        if process.poll() is not None:
            raise RuntimeError(f"dpdk-testpmd exited while waiting for its prompt with code {process.returncode}")
    raise RuntimeError(f"testpmd prompt did not appear within {timeout:g} seconds")


def run_prompt_command(
    process: subprocess.Popen[bytes], log: Any, captured: bytearray, terminal_fd: int,
    command: str, timeout: float = 10.0
) -> str:
    start_offset = len(captured)
    send_commands(process, (command,), terminal_fd)
    return wait_for_prompt(process, log, captured, terminal_fd, start_offset, timeout)


def parse_frames(output: str) -> list[dict[str, Any]]:
    return [
        {
            "source_mac": normalize_mac(match.group(1)),
            "destination_mac": normalize_mac(match.group(2)),
            "ethertype": match.group(3).lower(),
            "length": int(match.group(4)),
        }
        for match in FRAME_PATTERN.finditer(output)
    ]


def maximum_counter(output: str, label: str) -> int:
    values = [int(value) for value in re.findall(rf"{re.escape(label)}:\s*(\d+)", output, re.IGNORECASE)]
    return max(values, default=0)


def parse_counters(output: str) -> dict[str, int]:
    return {
        "rx_packets": maximum_counter(output, "RX-packets"),
        "rx_missed": maximum_counter(output, "RX-missed"),
        "rx_errors": maximum_counter(output, "RX-errors"),
        "rx_nombuf": maximum_counter(output, "RX-nombuf"),
        "port_tx_packets": maximum_counter(output, "TX-packets"),
        "fwd_rx_packets": maximum_counter(output, "RX-packets"),
        "fwd_tx_packets": maximum_counter(output, "TX-packets"),
        "tx_errors": maximum_counter(output, "TX-errors"),
    }


def sender_mac(path: Path, config: Mapping[str, Any]) -> str:
    receipt = dpdk.load_json(path)
    if receipt.get("task") != TASK or receipt.get("kind") != "kali_sender" or receipt.get("status") != "passed":
        raise ValueError(f"sender receipt is not a passed T0.4 receipt: {path}")
    if receipt.get("config", {}).get("sha256") != dpdk.sha256_file(config["_config_path"]):
        raise ValueError("sender receipt references a different passive config")
    value = receipt.get("interface", {}).get("mac")
    if not isinstance(value, str) or not value:
        raise ValueError("sender receipt has no interface MAC")
    return normalize_mac(value)


def validate_applied_state(state: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    if state.get("schema_version") != SCHEMA_VERSION or state.get("task") != "T0.3" or state.get("status") != "applied":
        raise ValueError("state must be an applied T0.3 resource state")
    expected_resource = build_resource_config(config)
    if state.get("configuration_sha256") != dpdk.json_sha256(expected_resource):
        raise ValueError("resource state does not match the T0.4 generated configuration")
    original = state.get("original", {})
    sensor = config["ubuntu_sensor"]
    if original.get("interface") != sensor["data_interface"]:
        raise ValueError("resource state belongs to a different data interface")
    if normalize_mac(str(original.get("mac"))) != normalize_mac(sensor["expected_mac"]):
        raise ValueError("resource state belongs to a different sensor MAC")
    if dpdk.driver_for_pci(original.get("pci_address")) != "vfio-pci":
        raise RuntimeError("sensor PCI device is not bound to vfio-pci")
    for companion in original.get("iommu_bridge_companions", []):
        if dpdk.driver_for_pci(companion["pci_address"]) is not None:
            raise RuntimeError(f"IOMMU bridge is unexpectedly bound: {companion['pci_address']}")
    dpdk.ensure_management(expected_resource)


def command_run(args: argparse.Namespace) -> int:
    dpdk.require_root()
    config_path = args.config.resolve()
    config = passive_contract.load_and_validate_config(config_path)
    config["_config_path"] = config_path
    output, log_path, state_path, sender_path = project_paths(
        config_path, args.output, args.log, args.state, args.sender
    )
    for path in (output, log_path):
        if path.exists():
            raise ValueError(f"artifact already exists: {path}; run the retry subcommand once")
    if sender_path.exists():
        raise ValueError(f"sender receipt already exists: {sender_path}; run the retry subcommand once")
    state = dpdk.load_json(state_path)
    validate_applied_state(state, config)
    prefix = config["dpdk"]["file_prefix"]
    require_clean_prefix(prefix)
    arm_timeout = args.arm_timeout
    post_sender_grace = args.post_sender_grace
    if not 60 <= arm_timeout <= 3600:
        raise ValueError("arm timeout must be between 60 and 3600 seconds")
    if not 1 <= post_sender_grace <= 30:
        raise ValueError("post-sender grace must be between 1 and 30 seconds")

    command = build_testpmd_command(config, state)
    interactive = [
        "set verbose 1",
        "set fwd rxonly",
        "set promisc 0 on",
        "show port info 0",
        "clear port stats all",
        "clear fwd stats all",
        "start",
        "stop",
        "show fwd stats all",
        "show port stats all",
        "quit",
    ]
    library_path = state["toolchain"]["library_directory"]
    if os.environ.get("LD_LIBRARY_PATH"):
        library_path += os.pathsep + os.environ["LD_LIBRARY_PATH"]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    captured = bytearray()
    process: subprocess.Popen[bytes] | None = None
    terminal_fd: int | None = None
    terminal_slave_fd: int | None = None
    started_at = utc_now()
    start = time.monotonic()
    return_code = -1
    link_up = False
    promiscuous = False
    cleanup: dict[str, Any] | None = None
    try:
        with log_path.open("xb") as log:
            import pty

            terminal_fd, terminal_slave_fd = pty.openpty()
            process = subprocess.Popen(
                command,
                stdin=terminal_slave_fd,
                stdout=terminal_slave_fd,
                stderr=terminal_slave_fd,
                close_fds=True,
                env={**os.environ, "LC_ALL": "C", "LD_LIBRARY_PATH": library_path},
            )
            os.close(terminal_slave_fd)
            terminal_slave_fd = None
            wait_for_prompt(process, log, captured, terminal_fd, 0, 30.0)
            for command_item in interactive[:3]:
                run_prompt_command(process, log, captured, terminal_fd, command_item)
            port_info = run_prompt_command(process, log, captured, terminal_fd, interactive[3])
            link_up = re.search(r"Link\s+status:\s*up", port_info, re.IGNORECASE) is not None
            promiscuous = re.search(r"Promiscuous\s+mode:\s*enabled", port_info, re.IGNORECASE) is not None
            if not link_up or not promiscuous:
                raise RuntimeError(
                    f"testpmd readiness failed (link_up={link_up}, promiscuous_enabled={promiscuous})"
                )
            for command_item in interactive[4:7]:
                run_prompt_command(process, log, captured, terminal_fd, command_item)
            print(
                f"READY: armed for up to {arm_timeout}s; start Kali after Windows is READY; "
                f"observing {config['windows_victim']['expected_mac']} on VMnet1",
                flush=True,
            )
            deadline = time.monotonic() + arm_timeout
            sender_completed_at: float | None = None
            while time.monotonic() < deadline:
                drain_output(process, log, captured, terminal_fd, 0.5)
                if process.poll() is not None:
                    raise RuntimeError(f"dpdk-testpmd exited while armed with code {process.returncode}")
                if sender_path.is_file():
                    sender_mac(sender_path, config)
                    if sender_completed_at is None:
                        sender_completed_at = time.monotonic()
                        print(
                            f"Kali sender receipt detected; capturing {post_sender_grace}s grace period",
                            flush=True,
                        )
                    if time.monotonic() - sender_completed_at >= post_sender_grace:
                        break
            else:
                raise RuntimeError(f"Kali sender receipt did not appear within {arm_timeout} seconds")
            for command_item in interactive[7:10]:
                run_prompt_command(process, log, captured, terminal_fd, command_item, 20.0)
            send_commands(process, (interactive[10],), terminal_fd)
            drain_output(process, log, captured, terminal_fd, 20.0, stop_on_exit=True)
            return_code = process.wait(timeout=5.0)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)
        if terminal_slave_fd is not None:
            os.close(terminal_slave_fd)
        if terminal_fd is not None:
            os.close(terminal_fd)
        cleanup = cleanup_prefix(prefix)

    ended_at = utc_now()
    text = log_path.read_text(encoding="utf-8", errors="replace")
    frames = parse_frames(text)
    expected_source = sender_mac(sender_path, config)
    expected_destination = normalize_mac(config["windows_victim"]["expected_mac"])
    matches = [
        frame for frame in frames
        if frame["source_mac"] == expected_source
        and frame["destination_mac"] == expected_destination
        and frame["ethertype"] == "0x0800"
    ]
    counters = parse_counters(text)
    minimum = config["acceptance"]["minimum_packet_count"]
    status = "passed" if len(matches) >= minimum else "failed"
    management_after = dpdk.management_ping(config["ubuntu_sensor"]["management_gateway"])
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "sensor_probe",
        "status": status,
        "generated_at_utc": utc_now(),
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_seconds": round(time.monotonic() - start, 3),
        "config": {"file": str(config_path), "sha256": dpdk.sha256_file(config_path)},
        "resource_state": {"file": str(state_path), "sha256": dpdk.sha256_file(state_path)},
        "command": command,
        "interactive_commands": interactive,
        "return_code": return_code,
        "link_up": link_up,
        "promiscuous_enabled": promiscuous,
        "expected_frames": {
            "source_mac": expected_source,
            "destination_mac": expected_destination,
            "ethertype": "0x0800",
            "packet_count": config["traffic"]["packet_count"],
            "minimum_count": minimum,
        },
        "matching_frames": len(matches),
        "first_match_at_utc": None,
        "last_match_at_utc": None,
        "frame_samples": matches[:5],
        "observed_source_counts_to_victim": dict(
            collections.Counter(
                frame["source_mac"]
                for frame in frames
                if frame["destination_mac"] == expected_destination and frame["ethertype"] == "0x0800"
            )
        ),
        "counters": counters,
        "management_ping_after": management_after,
        "prefix_cleanup": cleanup,
        "log": {"file": str(log_path), "sha256": dpdk.sha256_file(log_path)},
    }
    dpdk.write_new_json(output, receipt)
    print(
        f"wrote {output} ({status}); matching={len(matches)} "
        f"RX={counters['rx_packets']} TX={counters['port_tx_packets']}",
        flush=True,
    )
    return 0 if status == "passed" else 1


def command_reconcile(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    config = passive_contract.load_and_validate_config(config_path)
    config["_config_path"] = config_path
    output, log_path, state_path, sender_path = project_paths(
        config_path, args.output, args.log, args.state, args.sender
    )
    for path in (output, log_path, state_path, sender_path):
        if not path.is_file():
            raise ValueError(f"required artifact does not exist: {path}")

    original = dpdk.load_json(output)
    if (
        original.get("schema_version") != SCHEMA_VERSION
        or original.get("task") != TASK
        or original.get("kind") != "sensor_probe"
        or original.get("status") != "failed"
    ):
        raise ValueError("reconcile requires the failed T0.4 sensor receipt from this capture")
    config_hash = dpdk.sha256_file(config_path)
    state_hash = dpdk.sha256_file(state_path)
    log_hash = dpdk.sha256_file(log_path)
    if original.get("config", {}).get("sha256") != config_hash:
        raise ValueError("sensor receipt references a different passive config")
    if original.get("resource_state", {}).get("sha256") != state_hash:
        raise ValueError("sensor receipt references a different resource state")
    if original.get("log", {}).get("sha256") != log_hash:
        raise ValueError("testpmd log changed after the sensor receipt was written")
    state = dpdk.load_json(state_path)
    if state.get("task") != "T0.3" or state.get("status") != "applied":
        raise ValueError("resource state is not the applied T0.3 state")

    text = log_path.read_text(encoding="utf-8", errors="replace")
    frames = parse_frames(text)
    expected_source = sender_mac(sender_path, config)
    expected_destination = normalize_mac(config["windows_victim"]["expected_mac"])
    matches = [
        frame for frame in frames
        if frame["source_mac"] == expected_source
        and frame["destination_mac"] == expected_destination
        and frame["ethertype"] == "0x0800"
    ]
    minimum = config["acceptance"]["minimum_packet_count"]
    counters = parse_counters(text)
    if len(matches) < minimum:
        raise ValueError(f"capture still has only {len(matches)} matching frames; expected at least {minimum}")
    if counters["rx_packets"] < len(matches) or counters["rx_missed"] != 0 or counters["rx_errors"] != 0:
        raise ValueError("capture counters do not support a successful reconciliation")
    if original.get("return_code") != 0 or not original.get("link_up") or not original.get("promiscuous_enabled"):
        raise ValueError("original sensor readiness checks did not pass")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = output.parent / "attempts" / f"reconciled-{stamp}"
    suffix = 1
    while archive.exists():
        archive = output.parent / "attempts" / f"reconciled-{stamp}-{suffix:02d}"
        suffix += 1
    archive.mkdir(parents=True)
    original_hash = dpdk.sha256_file(output)
    archived_receipt = archive / "sensor.original.json"
    shutil.move(str(output), str(archived_receipt))

    corrected = dict(original)
    corrected.update(
        {
            "status": "passed",
            "generated_at_utc": utc_now(),
            "matching_frames": len(matches),
            "frame_samples": matches[:5],
            "observed_source_counts_to_victim": dict(
                collections.Counter(
                    frame["source_mac"]
                    for frame in frames
                    if frame["destination_mac"] == expected_destination and frame["ethertype"] == "0x0800"
                )
            ),
            "counters": counters,
            "reconciliation": {
                "reason": "testpmd_verbose_parser_compatibility",
                "original_receipt": {"file": str(archived_receipt), "sha256": original_hash},
                "immutable_log": {"file": str(log_path), "sha256": log_hash},
            },
        }
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "sensor_receipt_reconciliation",
        "generated_at_utc": utc_now(),
        "reason": "testpmd verbose output includes fields between dst and type",
        "original_receipt": {"file": str(archived_receipt), "sha256": original_hash},
        "corrected_receipt": {"file": str(output)},
        "immutable_log": {"file": str(log_path), "sha256": log_hash},
    }
    dpdk.write_new_json(output, corrected)
    manifest["corrected_receipt"]["sha256"] = dpdk.sha256_file(output)
    dpdk.write_new_json(archive / "reconciliation.json", manifest)
    print(f"wrote {output} (passed); reconciled matching={len(matches)} from immutable testpmd log")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight", help="create the read-only T0.4 resource preflight")
    preflight.add_argument("--config", type=Path, default=Path("config/dpdk-passive.json"))
    preflight.add_argument("--output", type=Path, default=Path("run_log/t0.4/preflight.json"))
    preflight.set_defaults(handler=command_preflight)
    retry = subparsers.add_parser("retry", help="archive only failed live-attempt artifacts and reuse applied state")
    retry.add_argument("--config", type=Path, default=Path("config/dpdk-passive.json"))
    retry.add_argument("--keep-windows", action="store_true", help="preserve an already armed Windows receiver")
    retry.add_argument("--keep-ubuntu", action="store_true", help="preserve an already armed Ubuntu probe")
    retry.set_defaults(handler=command_retry)
    execute = subparsers.add_parser("run", help="run the passive rxonly probe on an applied resource state")
    execute.add_argument("--config", type=Path, default=Path("config/dpdk-passive.json"))
    execute.add_argument("--state", type=Path, default=Path("run_log/t0.4/state.json"))
    execute.add_argument("--sender", type=Path, default=Path("run_log/t0.4/kali-sender.json"))
    execute.add_argument("--output", type=Path, default=Path("run_log/t0.4/sensor.json"))
    execute.add_argument("--log", type=Path, default=Path("run_log/t0.4/testpmd.log"))
    execute.add_argument("--arm-timeout", type=int, default=DEFAULT_ARM_TIMEOUT_SECONDS)
    execute.add_argument("--post-sender-grace", type=int, default=DEFAULT_POST_SENDER_GRACE_SECONDS)
    execute.set_defaults(handler=command_run)
    reconcile = subparsers.add_parser(
        "reconcile", help="correct a parser-only false negative from the immutable testpmd log"
    )
    reconcile.add_argument("--config", type=Path, default=Path("config/dpdk-passive.json"))
    reconcile.add_argument("--state", type=Path, default=Path("run_log/t0.4/state.json"))
    reconcile.add_argument("--sender", type=Path, default=Path("run_log/t0.4/kali-sender.json"))
    reconcile.add_argument("--output", type=Path, default=Path("run_log/t0.4/sensor.json"))
    reconcile.add_argument("--log", type=Path, default=Path("run_log/t0.4/testpmd.log"))
    reconcile.set_defaults(handler=command_reconcile)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
