#!/usr/bin/env python3
"""Validate and finalize the T3.2 CIC-IDS2017 golden dataset evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_t32_golden_dataset as builder  # noqa: E402
import verify_t11_packet_contract as runner  # noqa: E402


ACCEPTANCE_KIND = "cicids2017_golden_acceptance"
ATTEMPT_KIND = "cicids2017_golden_acceptance_attempt"
EXPECTED_CTESTS = (
    "nids_core.version",
    "nids_core.packet_contract",
    "nids_core.packet_parser",
    "nids_core.flow_contract",
    "nids_core.flow_table",
    "nids_core.feature_engine",
    "nids_core.checkpoint_contract",
    "nids_dataset.pcap_adapter",
)
COMMAND_NAMES = (
    "scapy_version",
    "libpcap_version",
    "configure",
    "build",
    "ctest",
    "python_unittest",
)
LOG_FILES = {
    "scapy_version": "scapy-version.log",
    "libpcap_version": "libpcap-version.log",
    "configure": "configure.log",
    "build": "build.log",
    "ctest": "ctest.log",
    "python_unittest": "python-unittest.log",
}
LIBPCAP_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+._A-Za-z0-9]*)?")
LOCKED_SCAPY_VERSION = "2.7.0"
FINAL_CHECK_NAMES = (
    "build.receipt_valid",
    "build.sources_rehashed",
    "build.source_packets_rescanned",
    "shared_parser.all_records_accepted",
    "acceptance.content_addressed",
)


def expected_label_scan(contract: Mapping[str, Any]) -> dict[str, Any]:
    labels = contract["sources"]["labels"]
    return {
        "header_field_count": labels["header_field_count"],
        "data_record_count": labels["data_record_count"],
        "nonempty_record_count": labels["data_record_count"]
        - labels["all_empty_record_count"],
        "all_empty_record_count": labels["all_empty_record_count"],
        "selected_rows": [
            {
                "id": sample["id"],
                "csv_line": sample["csv_line"],
                "selector_signature_occurrences": 1,
                "exact_row_occurrences": 1,
            }
            for sample in contract["samples"]
        ],
    }


def validate_current_source(
    recorded: Any,
    expected: Mapping[str, Any],
    project_root: Path,
    rehash: bool,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(recorded, Mapping):
        return [f"source evidence is missing for {expected['path']}"]
    try:
        path = builder.resolve_path(project_root, recorded.get("path"))
    except ValueError as error:
        return [str(error)]
    if recorded.get("path") != expected["path"]:
        errors.append(f"source path mismatch: {expected['path']}")
    try:
        stat = path.stat()
    except OSError as error:
        return [f"cannot stat source {path}: {error}"]
    if (
        recorded.get("size_bytes") != expected["size_bytes"]
        or stat.st_size != expected["size_bytes"]
    ):
        errors.append(f"source size mismatch: {expected['path']}")
    if not rehash and recorded.get("modified_time_ns") != stat.st_mtime_ns:
        errors.append(f"source modification time changed: {expected['path']}")
    if recorded.get("sha256") != expected["sha256"]:
        errors.append(f"recorded source hash mismatch: {expected['path']}")
    expected_magic = expected.get("magic_hex")
    if expected_magic is not None:
        try:
            with path.open("rb") as source:
                current_magic = source.read(4).hex()
        except OSError as error:
            errors.append(f"cannot read source magic {path}: {error}")
        else:
            if (
                recorded.get("magic_hex") != expected_magic
                or current_magic != expected_magic
            ):
                errors.append(f"source magic mismatch: {expected['path']}")
    if rehash:
        try:
            current_hash = builder.sha256_path(path)
        except OSError as error:
            errors.append(f"cannot hash source {path}: {error}")
        else:
            if current_hash != expected["sha256"]:
                errors.append(f"source content hash mismatch: {expected['path']}")
    return errors


def validate_output_artifact(
    artifact: Any,
    sample: Mapping[str, Any],
    contract: Mapping[str, Any],
    project_root: Path,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(artifact, Mapping):
        return [f"sample artifact is missing: {sample['id']}"]
    for field in ("id", "category", "csv_line"):
        if artifact.get(field) != sample[field]:
            errors.append(f"sample {sample['id']} field mismatch: {field}")
    if artifact.get("label") != sample["row"]["Label"]:
        errors.append(f"sample {sample['id']} label mismatch")
    source_match = artifact.get("source_match")
    expected_forward = int(sample["row"]["Total Fwd Packets"])
    expected_backward = int(sample["row"]["Total Backward Packets"])
    expected_flow_count = expected_forward + expected_backward
    expected_duration = int(sample["row"]["Flow Duration"]) * 1_000
    if not isinstance(source_match, Mapping):
        errors.append(f"sample {sample['id']} source match is missing")
    else:
        expected_values = {
            "flow_packet_count": expected_flow_count,
            "flow_duration_ns": expected_duration,
            "forward_packet_count": expected_forward,
            "backward_packet_count": expected_backward,
        }
        if any(
            source_match.get(key) != value for key, value in expected_values.items()
        ):
            errors.append(f"sample {sample['id']} source match mismatch")
        if (
            not isinstance(source_match.get("candidate_packet_count"), int)
            or source_match["candidate_packet_count"] < expected_flow_count
        ):
            errors.append(f"sample {sample['id']} candidate packet count is invalid")
        if (
            not isinstance(source_match.get("window_start_index"), int)
            or source_match["window_start_index"] < 0
        ):
            errors.append(f"sample {sample['id']} window index is invalid")
    file_record = artifact.get("file")
    expected_path = f"{contract['output']['directory']}/{sample['output_name']}"
    if not isinstance(file_record, Mapping):
        return [*errors, f"sample {sample['id']} file evidence is missing"]
    if file_record.get("path") != expected_path:
        errors.append(f"sample {sample['id']} output path mismatch")
    try:
        path = builder.resolve_path(project_root, file_record.get("path"))
        stat = path.stat()
        header, records = builder.read_classic_pcap(path)
    except (OSError, ValueError) as error:
        return [*errors, f"cannot read sample {sample['id']}: {error}"]
    if stat.st_size != file_record.get("size_bytes"):
        errors.append(f"sample {sample['id']} output size mismatch")
    if builder.sha256_path(path) != file_record.get("sha256"):
        errors.append(f"sample {sample['id']} output hash mismatch")
    with path.open("rb") as source:
        magic = source.read(4).hex()
    if (
        magic != contract["output"]["magic_hex"]
        or file_record.get("magic_hex") != magic
    ):
        errors.append(f"sample {sample['id']} output magic mismatch")
    expected_header = {
        "snaplen": contract["output"]["snaplen"],
        "linktype": contract["output"]["linktype"],
    }
    if header != expected_header:
        errors.append(f"sample {sample['id']} output header mismatch")
    expected_count = contract["selection"]["prefix_packet_count"]
    if (
        len(records) != expected_count
        or file_record.get("record_count") != expected_count
    ):
        errors.append(f"sample {sample['id']} record count mismatch")
    manifests = artifact.get("packets")
    if not isinstance(manifests, list) or len(manifests) != expected_count:
        errors.append(f"sample {sample['id']} packet manifest mismatch")
        return errors
    for index, (record, manifest) in enumerate(zip(records, manifests), start=1):
        if not isinstance(manifest, Mapping):
            errors.append(f"sample {sample['id']} packet manifest is malformed")
            continue
        expected_manifest = {
            "index": index,
            "timestamp_ns": record["timestamp_ns"],
            "captured_length": record["captured_length"],
            "original_length": record["original_length"],
            "sha256": hashlib.sha256(record["data"]).hexdigest(),
        }
        if manifest != expected_manifest:
            errors.append(f"sample {sample['id']} packet {index} evidence mismatch")
    return errors


def compare_rescanned_source(
    document: Mapping[str, Any],
    contract: Mapping[str, Any],
    project_root: Path,
    progress_packets: int,
) -> list[str]:
    errors: list[str] = []
    label_path = builder.resolve_path(
        project_root, contract["sources"]["labels"]["path"]
    )
    pcap_path = builder.resolve_path(project_root, contract["sources"]["pcap"]["path"])
    try:
        label_scan = builder.scan_label_csv(
            label_path, contract["sources"]["labels"], contract["samples"]
        )
        hits, pcap_scan = builder.collect_candidate_packets(
            pcap_path,
            contract["sources"]["pcap"],
            contract["samples"],
            progress_packets,
        )
    except (OSError, ValueError) as error:
        return [f"source rescan failed: {error}"]
    if document.get("label_scan") != label_scan:
        errors.append("label rescan evidence mismatch")
    if document.get("pcap_scan") != pcap_scan:
        errors.append("PCAP rescan evidence mismatch")
    artifacts = {
        item.get("id"): item
        for item in document.get("samples", [])
        if isinstance(item, Mapping)
    }
    prefix_count = contract["selection"]["prefix_packet_count"]
    for sample in contract["samples"]:
        try:
            start, window = builder.find_unique_window(hits[sample["id"]], sample)
        except ValueError as error:
            errors.append(str(error))
            continue
        artifact = artifacts.get(sample["id"])
        if not isinstance(artifact, Mapping):
            continue
        source_match = artifact.get("source_match", {})
        if source_match.get("window_start_index") != start:
            errors.append(f"sample {sample['id']} rescanned window index mismatch")
        path = builder.resolve_path(project_root, artifact.get("file", {}).get("path"))
        try:
            _, output_records = builder.read_classic_pcap(path)
        except (OSError, ValueError) as error:
            errors.append(f"cannot compare rescanned sample {sample['id']}: {error}")
            continue
        for source_packet, output_packet in zip(window[:prefix_count], output_records):
            if (
                source_packet.timestamp_ns != output_packet["timestamp_ns"]
                or source_packet.captured_length != output_packet["captured_length"]
                or source_packet.original_length != output_packet["original_length"]
                or source_packet.data != output_packet["data"]
            ):
                errors.append(f"sample {sample['id']} differs from rescanned source")
                break
    return errors


def validate_build_receipt(
    document: Mapping[str, Any],
    contract: Mapping[str, Any],
    project_root: Path,
    rehash_sources: bool = False,
    rescan_source: bool = False,
    progress_packets: int = 0,
) -> list[str]:
    errors = builder.validate_contract(contract)
    if errors:
        return errors
    if document.get("schema_version") != builder.SCHEMA_VERSION:
        errors.append("build receipt schema version mismatch")
    if document.get("task") != builder.TASK or document.get("kind") != builder.KIND:
        errors.append("build receipt task or kind mismatch")
    if (
        document.get("status") != "passed"
        or document.get("acceptance_status") != "pending_shared_parser"
    ):
        errors.append("build receipt status mismatch")
    contract_record = document.get("contract")
    contract_path = project_root / "config" / "cicids2017-golden-contract.json"
    expected_contract = {
        "path": "config/cicids2017-golden-contract.json",
        "sha256": builder.sha256_path(contract_path),
    }
    if contract_record != expected_contract:
        errors.append("build receipt contract identity mismatch")
    prerequisite = contract["prerequisite"]
    prerequisite_path = builder.resolve_path(project_root, prerequisite["path"])
    expected_prerequisite = {
        "path": prerequisite["path"],
        "sha256": builder.sha256_path(prerequisite_path),
        "task": prerequisite["task"],
        "status": prerequisite["status"],
    }
    if document.get("prerequisite") != expected_prerequisite:
        errors.append("build receipt prerequisite identity mismatch")
    sources = document.get("sources")
    if not isinstance(sources, Mapping):
        errors.append("build receipt source evidence is missing")
    else:
        errors.extend(
            validate_current_source(
                sources.get("pcap"),
                contract["sources"]["pcap"],
                project_root,
                rehash_sources,
            )
        )
        errors.extend(
            validate_current_source(
                sources.get("labels"),
                contract["sources"]["labels"],
                project_root,
                rehash_sources,
            )
        )
    if document.get("label_scan") != expected_label_scan(contract):
        errors.append("build receipt label scan mismatch")
    pcap_scan = document.get("pcap_scan")
    samples = document.get("samples")
    if not isinstance(samples, list) or len(samples) != 3:
        errors.append("build receipt must contain exactly three samples")
        samples = []
    artifacts = {item.get("id"): item for item in samples if isinstance(item, Mapping)}
    if set(artifacts) != {sample["id"] for sample in contract["samples"]}:
        errors.append("build receipt sample set mismatch")
    for sample in contract["samples"]:
        errors.extend(
            validate_output_artifact(
                artifacts.get(sample["id"]), sample, contract, project_root
            )
        )
    if not isinstance(pcap_scan, Mapping):
        errors.append("build receipt PCAP scan is missing")
    else:
        pcap_spec = contract["sources"]["pcap"]
        expected_scan = {
            "reader": "scapy.RawPcapNgReader",
            "scapy_version": pcap_spec["scapy_version"],
            "packet_count": pcap_spec["packet_count"],
            "linktypes": [pcap_spec["linktype"]],
            "timestamp_rounding_count": 0,
        }
        if any(pcap_scan.get(key) != value for key, value in expected_scan.items()):
            errors.append("build receipt PCAP scan contract mismatch")
        counts = pcap_scan.get("candidate_packet_counts")
        if not isinstance(counts, Mapping) or set(counts) != set(artifacts):
            errors.append("build receipt candidate packet counts mismatch")
        else:
            for sample_id, artifact in artifacts.items():
                if counts.get(sample_id) != artifact.get("source_match", {}).get(
                    "candidate_packet_count"
                ):
                    errors.append(f"sample {sample_id} candidate count is inconsistent")
    if (
        document.get("repository_payload_policy")
        != contract["repository_payload_policy"]
    ):
        errors.append("build receipt payload policy mismatch")
    expected_pending = {
        "required": True,
        "status": "pending",
        "target": contract["shared_parser"]["target"],
    }
    if document.get("shared_parser") != expected_pending:
        errors.append("build receipt shared-parser state mismatch")
    expected_checks = [
        {"name": name, "status": "passed"} for name in builder.CHECK_NAMES
    ]
    if document.get("checks") != expected_checks:
        errors.append("build receipt checks mismatch")
    if rescan_source:
        errors.extend(
            compare_rescanned_source(document, contract, project_root, progress_packets)
        )
    return errors


def validate_shared_parser_result(
    result: Any,
    paths: Sequence[Path],
    contract: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, Mapping):
        return ["shared parser result must be a JSON object"]
    if result.get("schema_version") != builder.SCHEMA_VERSION:
        errors.append("shared parser schema version mismatch")
    if result.get("task") != builder.TASK or result.get("status") != "passed":
        errors.append("shared parser task or status mismatch")
    if result.get("reader") != contract["shared_parser"]["reader"]:
        errors.append("shared parser reader mismatch")
    if result.get("parser") != contract["shared_parser"]["parser"]:
        errors.append("shared parser identity mismatch")
    files = result.get("files")
    if not isinstance(files, list) or len(files) != len(paths):
        return [*errors, "shared parser file result count mismatch"]
    expected_records = contract["shared_parser"]["expected_record_count_per_file"]
    expected_accepted = contract["shared_parser"]["expected_accepted_count_per_file"]
    for path, item in zip(paths, files):
        if not isinstance(item, Mapping):
            errors.append("shared parser file result is malformed")
            continue
        expected = {
            "path": str(path),
            "record_count": expected_records,
            "accepted_count": expected_accepted,
            "rejected_count": 0,
        }
        if item != expected:
            errors.append(f"shared parser result mismatch: {path}")
    return errors


def run_shared_parser(
    executable: Path,
    paths: Sequence[Path],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    if executable.stem != contract["shared_parser"]["target"]:
        raise ValueError("shared parser executable name disagrees with contract target")
    completed = subprocess.run(
        [str(executable), *(str(path) for path in paths)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ValueError(
            f"shared parser failed with code {completed.returncode}: {completed.stderr.strip()}"
        )
    if completed.stderr:
        raise ValueError("shared parser wrote unexpected stderr output")
    try:
        result = json.loads(
            completed.stdout, object_pairs_hook=builder.reject_duplicate_keys
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"shared parser returned invalid JSON: {error}") from error
    errors = validate_shared_parser_result(result, paths, contract)
    if errors:
        raise ValueError(f"invalid shared parser result: {errors}")
    return {
        "executable": {
            "path": str(executable),
            "size_bytes": executable.stat().st_size,
            "sha256": builder.sha256_path(executable),
        },
        "return_code": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        "result": result,
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
    effective_uid = host.get("effective_uid")
    if (
        not isinstance(effective_uid, int)
        or isinstance(effective_uid, bool)
        or effective_uid <= 0
    ):
        raise RuntimeError("T3.2 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T3.2 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith(
        "24.04"
    ):
        raise RuntimeError("T3.2 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T3.2 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T3.2 verification requires Python 3.12.x")


def require_tools() -> None:
    required = ("cmake", "ninja", "c++", "ctest", "pkg-config")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")


def run_pipeline(
    source: Path, build: Path, artifact_directory: Path
) -> list[dict[str, Any]]:
    scapy_version = runner.run_command(
        "scapy_version",
        (
            sys.executable,
            "-c",
            "import scapy; from scapy.utils import RawPcapNgReader; "
            "print(scapy.__version__)",
        ),
        source,
        artifact_directory / LOG_FILES["scapy_version"],
        30.0,
    )
    version = runner.run_command(
        "libpcap_version",
        ("pkg-config", "--modversion", "libpcap"),
        source,
        artifact_directory / LOG_FILES["libpcap_version"],
        30.0,
    )
    commands = [scapy_version, version]
    if scapy_version["return_code"] == 0 and version["return_code"] == 0:
        configure = runner.run_command(
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
                "-DNIDS_BUILD_DPDK=OFF",
            ),
            source,
            artifact_directory / LOG_FILES["configure"],
            300.0,
        )
    else:
        configure = runner.skipped_command(
            "configure",
            "Scapy or libpcap version check failed",
            artifact_directory / LOG_FILES["configure"],
        )
    commands.append(configure)
    if configure["return_code"] == 0:
        build_result = runner.run_command(
            "build",
            ("cmake", "--build", str(build), "--parallel", "2"),
            source,
            artifact_directory / LOG_FILES["build"],
            900.0,
        )
    else:
        build_result = runner.skipped_command(
            "build",
            "configure failed or was skipped",
            artifact_directory / LOG_FILES["build"],
        )
    commands.append(build_result)
    if build_result["return_code"] == 0:
        ctest = runner.run_command(
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
            artifact_directory / LOG_FILES["ctest"],
            600.0,
        )
    else:
        ctest = runner.skipped_command(
            "ctest",
            "build failed or was skipped",
            artifact_directory / LOG_FILES["ctest"],
        )
    commands.append(ctest)
    commands.append(
        runner.run_command(
            "python_unittest",
            (sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"),
            source,
            artifact_directory / LOG_FILES["python_unittest"],
            600.0,
        )
    )
    return commands


def assess_pipeline(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    executable: Path,
) -> tuple[list[dict[str, str]], str | None, str | None]:
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed"
            if runner.find_command(commands, name).get("return_code") == 0
            else "failed",
        }
        for name in COMMAND_NAMES
    ]
    scapy_output = str(
        runner.find_command(commands, "scapy_version").get("stdout", "")
    ).strip()
    scapy_version = scapy_output if scapy_output == LOCKED_SCAPY_VERSION else None
    libpcap_output = str(
        runner.find_command(commands, "libpcap_version").get("stdout", "")
    ).strip()
    libpcap_version = (
        libpcap_output if LIBPCAP_VERSION.fullmatch(libpcap_output) else None
    )
    ctest = runner.find_command(commands, "ctest")
    ctest_output = "\n".join(
        (str(ctest.get("stdout", "")), str(ctest.get("stderr", "")))
    )
    checks.extend(
        (
            {
                "name": "versions.scapy_locked",
                "status": "passed" if scapy_version is not None else "failed",
            },
            {
                "name": "versions.libpcap_present",
                "status": "passed" if libpcap_version is not None else "failed",
            },
            {
                "name": "ctest.nondpdk_suite_present",
                "status": "passed"
                if all(name in ctest_output for name in EXPECTED_CTESTS)
                else "failed",
            },
            {
                "name": "ctest.all_passed",
                "status": "passed" if "100% tests passed" in ctest_output else "failed",
            },
            {
                "name": "build.release",
                "status": "passed"
                if cache.get("CMAKE_BUILD_TYPE") == "Release"
                else "failed",
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
                "name": "build.dpdk_disabled",
                "status": "passed"
                if cache.get("NIDS_BUILD_DPDK") == "OFF"
                else "failed",
            },
            {
                "name": "build.shared_parser_present",
                "status": "passed" if executable.is_file() else "failed",
            },
        )
    )
    return checks, libpcap_version, scapy_version


def relative_command_logs(commands: Sequence[dict[str, Any]], source: Path) -> None:
    for command in commands:
        command["log"] = builder.relative_path(Path(command["log"]), source)


def finalize_acceptance(
    build_path: Path,
    executable: Path,
    output_path: Path | None,
    project_root: Path,
    progress_packets: int,
    host: Mapping[str, Any],
    verification: Mapping[str, Any],
) -> dict[str, Any]:
    contract_path = project_root / "config" / "cicids2017-golden-contract.json"
    contract = builder.load_json(contract_path)
    build_receipt = builder.load_json(build_path)
    errors = validate_build_receipt(
        build_receipt,
        contract,
        project_root,
        rehash_sources=True,
        rescan_source=True,
        progress_packets=progress_packets,
    )
    if errors:
        raise ValueError(f"cannot accept invalid T3.2 build: {errors}")
    artifacts = {item["id"]: item for item in build_receipt["samples"]}
    paths = [
        builder.resolve_path(project_root, artifacts[sample["id"]]["file"]["path"])
        for sample in contract["samples"]
    ]
    shared_parser = run_shared_parser(executable.resolve(), paths, contract)
    receipt = {
        "schema_version": builder.SCHEMA_VERSION,
        "task": builder.TASK,
        "kind": ACCEPTANCE_KIND,
        "status": "passed",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "host": dict(host),
        "contract": {
            "path": "config/cicids2017-golden-contract.json",
            "sha256": builder.sha256_path(contract_path),
        },
        "build": {
            "path": builder.relative_path(build_path, project_root),
            "sha256": builder.sha256_path(build_path),
            "source_rehashed": True,
            "source_packets_rescanned": True,
        },
        "samples": build_receipt["samples"],
        "shared_parser": shared_parser,
        "verification": dict(verification),
        "checks": [{"name": name, "status": "passed"} for name in FINAL_CHECK_NAMES],
    }
    if output_path is not None:
        builder.write_json_atomic(output_path, receipt)
    return receipt


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t3.2").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    build_receipt = artifact_root / "build.json"
    required = (
        source / ".git",
        source / "CMakeLists.txt",
        source / "config" / "cicids2017-golden-contract.json",
        build_receipt,
    )
    if not required[0].is_dir() or any(not path.is_file() for path in required[1:]):
        raise ValueError(f"source is not the prepared T3.2 project root: {source}")

    host = inspect_host()
    require_supported_host(host)
    require_tools()
    attempt_directory = artifact_root / "attempts" / runner.attempt_name()
    attempt_directory.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="nids-t3.2-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError(
                "temporary build workspace must be outside the shared tree"
            )
        build = workspace / "build"
        executable = build / "nids_t32_golden_dataset_test"
        commands = run_pipeline(source, build, attempt_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        checks, libpcap_version, scapy_version = assess_pipeline(
            commands, cache, executable
        )
        relative_command_logs(commands, source)
        verification = {
            "status": "passed"
            if all(check["status"] == "passed" for check in checks)
            else "failed",
            "artifact_directory": builder.relative_path(attempt_directory, source),
            "python_executable": sys.executable,
            "scapy_version": scapy_version,
            "libpcap_version": libpcap_version,
            "build": {
                "generator": "Ninja",
                "configuration": "Release",
                "testing_enabled": True,
                "toolchain_smoke_enabled": False,
                "dpdk_enabled": False,
                "offline_dependency_mode": True,
                "temporary_workspace_outside_source": True,
                "temporary_workspace_retained": False,
            },
            "commands": commands,
            "checks": checks,
        }
        if verification["status"] != "passed":
            failed = {
                "schema_version": builder.SCHEMA_VERSION,
                "task": builder.TASK,
                "kind": ATTEMPT_KIND,
                "status": "failed",
                "generated_at_utc": runner.utc_now(),
                "host": host,
                "verification": verification,
            }
            builder.write_json_atomic(attempt_directory / "receipt.json", failed)
            print(f"wrote {attempt_directory / 'receipt.json'} (failed)")
            for check in checks:
                if check["status"] == "failed":
                    print(f"failed: {check['name']}", file=sys.stderr)
            return 1
        try:
            receipt = finalize_acceptance(
                build_receipt,
                executable,
                None,
                source,
                args.progress_packets,
                host,
                verification,
            )
        except (OSError, RuntimeError, ValueError) as error:
            verification["status"] = "failed"
            verification["checks"].append(
                {"name": "acceptance.finalization", "status": "failed"}
            )
            failed = {
                "schema_version": builder.SCHEMA_VERSION,
                "task": builder.TASK,
                "kind": ATTEMPT_KIND,
                "status": "failed",
                "generated_at_utc": runner.utc_now(),
                "host": host,
                "error": str(error),
                "verification": verification,
            }
            builder.write_json_atomic(attempt_directory / "receipt.json", failed)
            raise

    builder.write_json_atomic(attempt_directory / "receipt.json", receipt)
    builder.write_json_atomic(final_receipt, receipt)
    print(f"wrote {attempt_directory / 'receipt.json'} (passed)")
    print(f"wrote {final_receipt} (passed)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check")
    check.add_argument(
        "--contract",
        type=Path,
        default=project_root / "config" / "cicids2017-golden-contract.json",
    )
    validate = subparsers.add_parser("validate-build")
    validate.add_argument("--input", type=Path, required=True)
    validate.add_argument("--project-root", type=Path, default=project_root)
    validate.add_argument("--rehash-sources", action="store_true")
    validate.add_argument("--rescan-source", action="store_true")
    validate.add_argument("--progress-packets", type=int, default=2_000_000)
    run = subparsers.add_parser("run")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument(
        "--artifact-root",
        type=Path,
        default=project_root / "run_log" / "t3.2",
    )
    run.add_argument("--progress-packets", type=int, default=2_000_000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            contract = builder.load_json(args.contract)
            errors = builder.validate_contract(contract)
            message = "valid T3.2 golden contract"
        elif args.command == "validate-build":
            project_root = args.project_root.resolve()
            contract = builder.load_json(
                project_root / "config" / "cicids2017-golden-contract.json"
            )
            errors = validate_build_receipt(
                builder.load_json(args.input),
                contract,
                project_root,
                args.rehash_sources,
                args.rescan_source,
                args.progress_packets,
            )
            message = f"valid T3.2 build receipt: {args.input}"
        else:
            return command_run(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
