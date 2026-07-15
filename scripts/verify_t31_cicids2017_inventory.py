#!/usr/bin/env python3
"""Validate the T3.1 CIC-IDS2017 inventory contract and saved receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import inventory_cicids2017 as inventory


SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
CRC32_PATTERN = re.compile(r"[0-9a-f]{8}")
CHECK_NAMES = (
    "contract.valid",
    "pcap.file_set_exact",
    "pcap.files_nonempty",
    "pcap.container_magic",
    "pcap.sha256_complete",
    "labels.archive_present",
    "labels.csv_member_set_exact",
    "labels.required_columns",
    "labels.sha256_complete",
    "prerequisites.phase2_passed",
    "prerequisites.prior_full_scan_consistent",
    "license.evidence_locked",
    "checksum.policy_explicit",
    "scope.nf_uq_nids_excluded",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(inventory.READ_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_receipt_path(project_root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    candidate = (project_root / value).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError:
        return None
    return candidate


def valid_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.utcoffset() == dt.timedelta(0)


def validate_current_file(
    record: Mapping[str, Any],
    project_root: Path,
    expected_name: str,
    expected_magic: str | None = None,
    rehash: bool = False,
) -> list[str]:
    errors: list[str] = []
    path = resolve_receipt_path(project_root, record.get("path"))
    if path is None or path.name.casefold() != expected_name.casefold():
        return [f"invalid or escaping source path for {expected_name}"]
    if not path.is_file():
        return [f"source file is missing: {record.get('path')}"]
    stat = path.stat()
    if record.get("size_bytes") != stat.st_size:
        errors.append(f"source size changed: {record.get('path')}")
    if record.get("modified_time_ns") != stat.st_mtime_ns:
        errors.append(f"source modification time changed: {record.get('path')}")
    if expected_magic is not None:
        with path.open("rb") as source:
            magic = source.read(4).hex()
        if record.get("magic_hex") != expected_magic or magic != expected_magic:
            errors.append(f"source container magic mismatch: {record.get('path')}")
    if SHA256_PATTERN.fullmatch(str(record.get("sha256", ""))) is None:
        errors.append(f"invalid SHA-256: {record.get('path')}")
    elif rehash and record.get("sha256") != file_sha256(path):
        errors.append(f"source content hash mismatch: {record.get('path')}")
    return errors


def validate_prerequisite(
    record: Any,
    project_root: Path,
    expected_path: str,
    expected_task: str,
) -> list[str]:
    if not isinstance(record, Mapping):
        return [f"missing prerequisite record: {expected_path}"]
    if record.get("path") != expected_path:
        return [f"wrong prerequisite path: {expected_path}"]
    path = resolve_receipt_path(project_root, record.get("path"))
    if path is None or not path.is_file():
        return [f"prerequisite is missing or escapes root: {expected_path}"]
    errors: list[str] = []
    if record.get("sha256") != file_sha256(path):
        errors.append(f"prerequisite hash mismatch: {expected_path}")
    if record.get("task") != expected_task or record.get("status") != "passed":
        errors.append(f"prerequisite did not pass: {expected_path}")
    return errors


def validate_receipt(
    document: Any,
    contract: Mapping[str, Any],
    project_root: Path,
    rehash_sources: bool = False,
) -> list[str]:
    if not isinstance(document, Mapping):
        return ["receipt must be a JSON object"]
    errors: list[str] = []
    if document.get("schema_version") != inventory.SCHEMA_VERSION:
        errors.append("receipt schema_version must equal 1.0.0")
    if document.get("task") != inventory.TASK:
        errors.append("receipt task must equal T3.1")
    if document.get("kind") != inventory.KIND:
        errors.append("receipt kind must identify the CIC-IDS2017 source inventory")
    if document.get("inventory_revision") != inventory.INVENTORY_REVISION:
        errors.append("receipt inventory revision is not supported")
    if not valid_utc_timestamp(document.get("generated_at_utc")):
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")

    contract_record = document.get("contract")
    contract_path = project_root / "config" / "cicids2017-inventory-contract.json"
    if not isinstance(contract_record, Mapping):
        errors.append("receipt contract record is missing")
    else:
        if contract_record.get("path") != "config/cicids2017-inventory-contract.json":
            errors.append("receipt must use the locked T3.1 contract path")
        if contract_record.get("sha256") != file_sha256(contract_path):
            errors.append("receipt contract hash does not match the locked contract")
        if contract_record.get("dataset_id") != "CIC-IDS2017":
            errors.append("receipt dataset_id must equal CIC-IDS2017")

    source = document.get("source")
    pcaps = source.get("pcaps") if isinstance(source, Mapping) else None
    expected_pcaps = {
        name.casefold(): name for name in contract["pcap"]["expected_files"]
    }
    pcap_set_exact = False
    pcap_nonempty = False
    pcap_magic = False
    pcap_hashes = False
    if not isinstance(source, Mapping) or source.get("directory") != "pcap":
        errors.append("source directory must equal pcap")
    if not isinstance(pcaps, list) or not all(isinstance(item, Mapping) for item in pcaps):
        errors.append("source pcaps must be an array of objects")
        pcaps = []
    else:
        names = [str(item.get("name", "")).casefold() for item in pcaps]
        pcap_set_exact = (
            set(names) == set(expected_pcaps)
            and len(names) == len(set(names))
            and source.get("missing_pcaps") == []
            and source.get("unexpected_pcaps") == []
        )
        if not pcap_set_exact:
            errors.append("receipt must contain exactly the five contracted PCAP files")
        for item in pcaps:
            expected_name = expected_pcaps.get(str(item.get("name", "")).casefold())
            if expected_name is not None:
                errors.extend(
                    validate_current_file(
                        item,
                        project_root,
                        expected_name,
                        contract["pcap"]["magic_hex"],
                        rehash_sources,
                    )
                )
        pcap_nonempty = len(pcaps) == 5 and all(item.get("size_bytes", 0) > 0 for item in pcaps)
        pcap_magic = len(pcaps) == 5 and all(
            item.get("magic_hex") == contract["pcap"]["magic_hex"] for item in pcaps
        )
        pcap_hashes = len(pcaps) == 5 and all(
            SHA256_PATTERN.fullmatch(str(item.get("sha256", ""))) is not None for item in pcaps
        )
        if source.get("pcap_total_size_bytes") != sum(item.get("size_bytes", 0) for item in pcaps):
            errors.append("pcap_total_size_bytes is inconsistent")

    labels = source.get("labels") if isinstance(source, Mapping) else None
    label_present = isinstance(labels, Mapping)
    label_set_exact = False
    label_columns = False
    label_hashes = False
    if not label_present:
        errors.append("labeled-flow archive inventory is missing")
    else:
        errors.extend(
            validate_current_file(
                labels,
                project_root,
                contract["labels"]["archive"],
            )
        )
        if rehash_sources:
            label_path = resolve_receipt_path(project_root, labels.get("path"))
            if label_path is not None and label_path.is_file():
                current_labels = inventory.inspect_label_archive(
                    label_path,
                    project_root,
                    contract["labels"]["required_columns"],
                    0,
                )
                if current_labels != labels:
                    errors.append("labeled-flow archive content evidence mismatch")
        members = labels.get("members")
        if not isinstance(members, list) or not all(isinstance(item, Mapping) for item in members):
            errors.append("label members must be an array of objects")
            members = []
        expected_members = {
            name.casefold() for name in contract["labels"]["expected_csv_basenames"]
        }
        actual_members = [str(item.get("basename", "")).casefold() for item in members]
        label_set_exact = (
            set(actual_members) == expected_members
            and len(actual_members) == len(set(actual_members))
            and labels.get("duplicate_csv_basenames") == []
            and labels.get("csv_member_count") == 8
        )
        if not label_set_exact:
            errors.append("receipt must contain exactly the eight contracted labeled-flow CSV files")
        required_columns = set(contract["labels"]["required_columns"])
        label_columns = label_set_exact and all(
            item.get("required_columns_present") is True
            and isinstance(item.get("columns"), list)
            and required_columns.issubset(item["columns"])
            and item.get("row_count", 0) > 0
            for item in members
        )
        if not label_columns:
            errors.append("every labeled-flow CSV must contain join columns and data rows")
        label_hashes = (
            SHA256_PATTERN.fullmatch(str(labels.get("sha256", ""))) is not None
            and all(
                SHA256_PATTERN.fullmatch(str(item.get("sha256", ""))) is not None
                and CRC32_PATTERN.fullmatch(str(item.get("crc32_hex", ""))) is not None
                for item in members
            )
        )
        if labels.get("csv_uncompressed_size_bytes") != sum(
            item.get("uncompressed_size_bytes", 0) for item in members
        ):
            errors.append("label uncompressed size total is inconsistent")
        if labels.get("csv_row_count") != sum(item.get("row_count", 0) for item in members):
            errors.append("label row count total is inconsistent")

    prerequisite_contract = contract["prerequisites"]
    prerequisites = document.get("prerequisites")
    phase2_errors: list[str] = []
    survey_errors: list[str] = []
    survey_consistent = False
    if not isinstance(prerequisites, Mapping):
        errors.append("prerequisite evidence is missing")
    else:
        phase2_errors = validate_prerequisite(
            prerequisites.get("phase2_acceptance"),
            project_root,
            prerequisite_contract["phase2_acceptance"],
            "T2.6",
        )
        survey_errors = validate_prerequisite(
            prerequisites.get("prior_full_scan"),
            project_root,
            prerequisite_contract["prior_full_scan"],
            "T1.2",
        )
        errors.extend(phase2_errors)
        errors.extend(survey_errors)
        if not survey_errors:
            survey_document = inventory.load_json(
                project_root / prerequisite_contract["prior_full_scan"]
            )
            survey_consistent = inventory.prior_scan_matches(pcaps, survey_document)
            if not survey_consistent:
                errors.append("current PCAP identities disagree with the prior full scan")

    license_matches = document.get("license_evidence") == contract["license_evidence"]
    checksum_record = document.get("checksum_policy")
    checksum_matches = isinstance(checksum_record, Mapping) and all(
        checksum_record.get(key) == value
        for key, value in contract["checksum_policy"].items()
    )
    exclusions_match = document.get("exclusions") == contract["exclusions"]
    if not license_matches:
        errors.append("license evidence must match the locked contract")
    if not checksum_matches:
        errors.append("checksum limitations must match the locked contract")
    if not exclusions_match:
        errors.append("dataset exclusions must match the locked contract")

    recomputed = {
        "contract.valid": not inventory.validate_contract(contract),
        "pcap.file_set_exact": pcap_set_exact,
        "pcap.files_nonempty": pcap_nonempty,
        "pcap.container_magic": pcap_magic,
        "pcap.sha256_complete": pcap_hashes,
        "labels.archive_present": label_present,
        "labels.csv_member_set_exact": label_set_exact,
        "labels.required_columns": label_columns,
        "labels.sha256_complete": label_hashes,
        "prerequisites.phase2_passed": not phase2_errors,
        "prerequisites.prior_full_scan_consistent": survey_consistent,
        "license.evidence_locked": license_matches,
        "checksum.policy_explicit": checksum_matches,
        "scope.nf_uq_nids_excluded": exclusions_match,
    }
    checks = document.get("checks")
    expected_checks = [
        {"name": name, "status": "passed" if recomputed[name] else "failed"}
        for name in CHECK_NAMES
    ]
    if checks != expected_checks:
        errors.append("recorded checks must match recomputed receipt evidence")
    all_passed = all(check["status"] == "passed" for check in expected_checks)
    if document.get("status") != ("passed" if all_passed else "failed"):
        errors.append("receipt status must match aggregate check status")
    if document.get("status") != "passed":
        errors.append("T3.1 acceptance receipt did not pass")
    return errors


def command_check(args: argparse.Namespace) -> int:
    contract = inventory.load_json(args.contract)
    errors = inventory.validate_contract(contract)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T3.1 contract: five PCAPs, eight labeled-flow CSV files, local SHA-256")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    project_root = args.project_root.resolve()
    contract = inventory.load_json(
        project_root / "config" / "cicids2017-inventory-contract.json"
    )
    errors = validate_receipt(
        inventory.load_json(args.input),
        contract,
        project_root,
        args.rehash_sources,
    )
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid T3.1 receipt: {args.input}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check")
    check.add_argument(
        "--contract",
        type=Path,
        default=project_root / "config" / "cicids2017-inventory-contract.json",
    )
    check.set_defaults(handler=command_check)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--input", required=True, type=Path)
    validate.add_argument("--project-root", type=Path, default=project_root)
    validate.add_argument("--rehash-sources", action="store_true")
    validate.set_defaults(handler=command_validate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
