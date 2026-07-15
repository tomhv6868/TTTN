#!/usr/bin/env python3
"""Build the bounded, content-addressed CIC-IDS2017 source inventory for T3.1."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import platform
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T3.1"
KIND = "cicids2017_source_inventory"
INVENTORY_REVISION = "1.0.0"
READ_SIZE = 8 * 1024 * 1024
MAXIMUM_CSV_HEADER_BYTES = 64 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            document = json.load(source, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return document


def sha256_stream(source: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(READ_SIZE):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def sha256_path(path: Path, progress_bytes: int = 0) -> str:
    digest = hashlib.sha256()
    processed = 0
    next_progress = progress_bytes
    with path.open("rb") as source:
        while chunk := source.read(READ_SIZE):
            digest.update(chunk)
            processed += len(chunk)
            if progress_bytes and processed >= next_progress:
                print(f"HASH {path.name} bytes={processed}", flush=True)
                while next_progress <= processed:
                    next_progress += progress_bytes
    return digest.hexdigest()


def relative_path(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError as error:
        raise ValueError(f"path escapes project root: {path}") from error


def validate_contract(contract: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append("contract.schema_version")
    if contract.get("task") != TASK:
        errors.append("contract.task")

    dataset = contract.get("dataset")
    if not isinstance(dataset, Mapping) or dataset.get("id") != "CIC-IDS2017":
        errors.append("contract.dataset")
    elif not str(dataset.get("official_landing_page", "")).startswith("https://www.unb.ca/"):
        errors.append("contract.dataset.official_landing_page")

    checksum = contract.get("checksum_policy")
    expected_checksum = {
        "algorithm": "sha256",
        "publisher_digest_status": "not_published_on_cited_landing_page",
        "verification_mode": "local_content_identity",
        "publisher_digest_match": "not_performed",
    }
    if checksum != expected_checksum:
        errors.append("contract.checksum_policy")

    license_evidence = contract.get("license_evidence")
    if not isinstance(license_evidence, Mapping):
        errors.append("contract.license_evidence")
    else:
        if license_evidence.get("spdx_identifier") is not None:
            errors.append("contract.license_evidence.spdx_identifier")
        if license_evidence.get("redistribution_grant_verified") is not False:
            errors.append("contract.license_evidence.redistribution_grant_verified")
        if license_evidence.get("publicly_available_for_researchers") is not True:
            errors.append("contract.license_evidence.public_availability")

    pcap = contract.get("pcap")
    pcap_names = pcap.get("expected_files") if isinstance(pcap, Mapping) else None
    if not isinstance(pcap_names, list) or len(pcap_names) != 5:
        errors.append("contract.pcap.expected_files")
    elif len({str(name).casefold() for name in pcap_names}) != len(pcap_names):
        errors.append("contract.pcap.expected_files_unique")
    if not isinstance(pcap, Mapping) or pcap.get("magic_hex") != "0a0d0d0a":
        errors.append("contract.pcap.magic_hex")

    labels = contract.get("labels")
    csv_names = labels.get("expected_csv_basenames") if isinstance(labels, Mapping) else None
    if not isinstance(csv_names, list) or len(csv_names) != 8:
        errors.append("contract.labels.expected_csv_basenames")
    elif len({str(name).casefold() for name in csv_names}) != len(csv_names):
        errors.append("contract.labels.expected_csv_basenames_unique")
    required_columns = labels.get("required_columns") if isinstance(labels, Mapping) else None
    if not isinstance(required_columns, list) or not required_columns:
        errors.append("contract.labels.required_columns")

    exclusions = contract.get("exclusions")
    if not isinstance(exclusions, Mapping) or exclusions.get("nf_uq_nids_may_substitute") is not False:
        errors.append("contract.exclusions.nf_uq_nids")
    return errors


def file_identity(path: Path, project_root: Path, progress_bytes: int) -> dict[str, Any]:
    before = path.stat()
    with path.open("rb") as source:
        magic = source.read(4)
    digest = sha256_path(path, progress_bytes)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"source changed while hashing: {path}")
    return {
        "name": path.name,
        "path": relative_path(path, project_root),
        "size_bytes": after.st_size,
        "modified_time_ns": after.st_mtime_ns,
        "magic_hex": magic.hex(),
        "sha256": digest,
    }


def inspect_csv_member(source: BinaryIO) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    newline_count = 0
    final_byte = b""
    header = bytearray()
    header_complete = False

    while chunk := source.read(READ_SIZE):
        digest.update(chunk)
        size += len(chunk)
        newline_count += chunk.count(b"\n")
        final_byte = chunk[-1:]
        if not header_complete:
            newline = chunk.find(b"\n")
            if newline >= 0:
                header.extend(chunk[:newline])
                header_complete = True
            else:
                header.extend(chunk)
            if len(header) > MAXIMUM_CSV_HEADER_BYTES:
                raise ValueError("CSV header exceeds bounded limit")

    if not header_complete:
        raise ValueError("CSV member has no complete header")
    try:
        header_text = bytes(header).rstrip(b"\r").decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("CSV header is not UTF-8 compatible") from error
    columns = [column.strip() for column in header_text.split(",")]
    logical_lines = newline_count + (1 if size and final_byte != b"\n" else 0)
    return {
        "uncompressed_size_bytes": size,
        "row_count": max(0, logical_lines - 1),
        "sha256": digest.hexdigest(),
        "columns": columns,
    }


def inspect_label_archive(
    path: Path,
    project_root: Path,
    required_columns: Sequence[str],
    progress_bytes: int,
) -> dict[str, Any]:
    before = path.stat()
    archive_sha256 = sha256_path(path, progress_bytes)
    members: list[dict[str, Any]] = []
    duplicate_basenames: list[str] = []
    seen_basenames: set[str] = set()

    try:
        with zipfile.ZipFile(path) as archive:
            for info in sorted(archive.infolist(), key=lambda entry: entry.filename.casefold()):
                if info.is_dir() or not info.filename.casefold().endswith(".csv"):
                    continue
                basename_key = Path(info.filename).name.casefold()
                if basename_key in seen_basenames:
                    duplicate_basenames.append(Path(info.filename).name)
                seen_basenames.add(basename_key)
                if info.flag_bits & 0x1:
                    raise ValueError(f"encrypted CSV member is not supported: {info.filename}")
                with archive.open(info, "r") as source:
                    inspected = inspect_csv_member(source)
                columns = inspected.pop("columns")
                members.append(
                    {
                        "path": info.filename,
                        "basename": Path(info.filename).name,
                        "compressed_size_bytes": info.compress_size,
                        "crc32_hex": f"{info.CRC:08x}",
                        **inspected,
                        "required_columns_present": all(
                            column in columns for column in required_columns
                        ),
                        "columns": columns,
                    }
                )
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ValueError(f"invalid labeled-flow archive {path}: {error}") from error

    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"source changed while reading: {path}")
    return {
        "name": path.name,
        "path": relative_path(path, project_root),
        "size_bytes": after.st_size,
        "modified_time_ns": after.st_mtime_ns,
        "sha256": archive_sha256,
        "csv_member_count": len(members),
        "csv_uncompressed_size_bytes": sum(
            member["uncompressed_size_bytes"] for member in members
        ),
        "csv_row_count": sum(member["row_count"] for member in members),
        "duplicate_csv_basenames": sorted(duplicate_basenames, key=str.casefold),
        "members": members,
    }


def prerequisite_record(path: Path, project_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    document = load_json(path)
    with path.open("rb") as source:
        digest, _ = sha256_stream(source)
    return (
        {
            "path": relative_path(path, project_root),
            "sha256": digest,
            "task": document.get("task"),
            "status": document.get("status"),
        },
        document,
    )


def prior_scan_matches(pcaps: Sequence[Mapping[str, Any]], survey: Mapping[str, Any]) -> bool:
    prior_files = survey.get("files")
    if not isinstance(prior_files, list):
        return False
    prior = {
        str(item.get("name", "")).casefold(): item
        for item in prior_files
        if isinstance(item, Mapping)
    }
    current = {str(item.get("name", "")).casefold(): item for item in pcaps}
    if prior.keys() != current.keys():
        return False
    fields = ("size_bytes", "modified_time_ns", "magic_hex")
    return all(
        all(prior[name].get(field) == current[name].get(field) for field in fields)
        for name in current
    )


def make_check(name: str, passed: bool) -> dict[str, str]:
    return {"name": name, "status": "passed" if passed else "failed"}


def build_inventory(
    project_root: Path,
    data_dir: Path,
    contract_path: Path,
    progress_bytes: int = 0,
) -> dict[str, Any]:
    contract = load_json(contract_path)
    contract_errors = validate_contract(contract)
    if contract_errors:
        raise ValueError(f"invalid inventory contract: {contract_errors}")
    with contract_path.open("rb") as source:
        contract_sha256, _ = sha256_stream(source)

    pcap_contract = contract["pcap"]
    expected_pcap_names = {
        name.casefold(): name for name in pcap_contract["expected_files"]
    }
    found_pcap_paths = {
        path.name.casefold(): path
        for path in data_dir.glob("*.pcap")
        if path.is_file()
    }
    pcaps = [
        file_identity(found_pcap_paths[key], project_root, progress_bytes)
        for key in sorted(expected_pcap_names)
        if key in found_pcap_paths
    ]
    unexpected_pcaps = sorted(
        (path.name for key, path in found_pcap_paths.items() if key not in expected_pcap_names),
        key=str.casefold,
    )

    labels_contract = contract["labels"]
    archive_path = data_dir / labels_contract["archive"]
    labels = (
        inspect_label_archive(
            archive_path,
            project_root,
            labels_contract["required_columns"],
            progress_bytes,
        )
        if archive_path.is_file()
        else None
    )

    prerequisites = contract["prerequisites"]
    phase2_record, phase2 = prerequisite_record(
        project_root / prerequisites["phase2_acceptance"], project_root
    )
    survey_record, survey = prerequisite_record(
        project_root / prerequisites["prior_full_scan"], project_root
    )

    expected_csv_names = {
        name.casefold() for name in labels_contract["expected_csv_basenames"]
    }
    actual_csv_names = (
        {member["basename"].casefold() for member in labels["members"]}
        if labels is not None
        else set()
    )
    pcap_set_exact = set(found_pcap_paths) == set(expected_pcap_names)
    label_set_exact = (
        labels is not None
        and actual_csv_names == expected_csv_names
        and not labels["duplicate_csv_basenames"]
    )
    checks = [
        make_check("contract.valid", True),
        make_check("pcap.file_set_exact", pcap_set_exact and not unexpected_pcaps),
        make_check("pcap.files_nonempty", len(pcaps) == 5 and all(item["size_bytes"] > 0 for item in pcaps)),
        make_check(
            "pcap.container_magic",
            len(pcaps) == 5 and all(item["magic_hex"] == pcap_contract["magic_hex"] for item in pcaps),
        ),
        make_check("pcap.sha256_complete", len(pcaps) == 5 and all(len(item["sha256"]) == 64 for item in pcaps)),
        make_check("labels.archive_present", labels is not None),
        make_check("labels.csv_member_set_exact", label_set_exact),
        make_check(
            "labels.required_columns",
            label_set_exact
            and all(member["required_columns_present"] for member in labels["members"]),
        ),
        make_check(
            "labels.sha256_complete",
            labels is not None
            and len(labels["sha256"]) == 64
            and all(len(member["sha256"]) == 64 for member in labels["members"]),
        ),
        make_check(
            "prerequisites.phase2_passed",
            phase2.get("task") == "T2.6" and phase2.get("status") == "passed",
        ),
        make_check(
            "prerequisites.prior_full_scan_consistent",
            survey.get("task") == "T1.2"
            and survey.get("status") == "passed"
            and prior_scan_matches(pcaps, survey),
        ),
        make_check(
            "license.evidence_locked",
            contract["license_evidence"]["spdx_identifier"] is None
            and contract["license_evidence"]["redistribution_grant_verified"] is False,
        ),
        make_check(
            "checksum.policy_explicit",
            contract["checksum_policy"]["algorithm"] == "sha256"
            and contract["checksum_policy"]["publisher_digest_match"] == "not_performed",
        ),
        make_check(
            "scope.nf_uq_nids_excluded",
            contract["exclusions"]["nf_uq_nids_may_substitute"] is False,
        ),
    ]
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "inventory_revision": INVENTORY_REVISION,
        "status": status,
        "generated_at_utc": utc_now(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "contract": {
            "path": relative_path(contract_path, project_root),
            "sha256": contract_sha256,
            "dataset_id": contract["dataset"]["id"],
        },
        "source": {
            "directory": relative_path(data_dir, project_root),
            "pcaps": pcaps,
            "pcap_total_size_bytes": sum(item["size_bytes"] for item in pcaps),
            "missing_pcaps": sorted(
                (expected_pcap_names[key] for key in expected_pcap_names.keys() - found_pcap_paths.keys()),
                key=str.casefold,
            ),
            "unexpected_pcaps": unexpected_pcaps,
            "labels": labels,
        },
        "prerequisites": {
            "phase2_acceptance": phase2_record,
            "prior_full_scan": survey_record,
        },
        "license_evidence": contract["license_evidence"],
        "checksum_policy": {
            **contract["checksum_policy"],
            "interpretation": "Local SHA-256 identifies these files; publisher provenance is not digest-verified.",
        },
        "exclusions": contract["exclusions"],
        "checks": checks,
    }


def write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing receipt: {path}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise


def run_self_test() -> None:
    content = b"Flow ID, Source IP, Label\r\nflow-1,10.0.0.1,BENIGN\r\n"
    digest, size = sha256_stream(io.BytesIO(content))
    inspected = inspect_csv_member(io.BytesIO(content))
    assert digest == hashlib.sha256(content).hexdigest()
    assert size == len(content)
    assert inspected["row_count"] == 1
    assert inspected["columns"] == ["Flow ID", "Source IP", "Label"]
    print("self-test passed")


def command_inventory(args: argparse.Namespace) -> int:
    project_root = Path(__file__).resolve().parents[1]
    expected_data_dir = (project_root / "pcap").resolve()
    expected_contract = (project_root / "config" / "cicids2017-inventory-contract.json").resolve()
    output_root = (project_root / "run_log" / "t3.1").resolve()
    data_dir = args.data_dir.resolve()
    contract_path = args.contract.resolve()
    output = args.output.resolve()
    if data_dir != expected_data_dir:
        raise ValueError(f"data directory must equal {expected_data_dir}")
    if contract_path != expected_contract:
        raise ValueError(f"contract must equal {expected_contract}")
    if output == output_root or output_root not in output.parents:
        raise ValueError(f"output must be a file below {output_root}")
    if os.path.lexists(output):
        raise ValueError(f"refusing to overwrite existing receipt: {output}")
    if args.progress_bytes < 0:
        raise ValueError("--progress-bytes must not be negative")

    receipt = build_inventory(project_root, data_dir, contract_path, args.progress_bytes)
    write_json_atomic(output, receipt)
    print(f"wrote {output} ({receipt['status']})", flush=True)
    return 0 if receipt["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--data-dir", type=Path, default=project_root / "pcap")
    parser.add_argument(
        "--contract",
        type=Path,
        default=project_root / "config" / "cicids2017-inventory-contract.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "run_log" / "t3.1" / "acceptance.json",
    )
    parser.add_argument("--progress-bytes", type=int, default=1024 * 1024 * 1024)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0
        return command_inventory(args)
    except (AssertionError, OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
