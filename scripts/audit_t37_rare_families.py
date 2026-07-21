#!/usr/bin/env python3
"""Audit CIC-IDS2017 rare-family support and enforce the T3.7 macro-LOAFO gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T3.7"
PYARROW_VERSION = "23.0.1"
CHECKPOINTS = ("F3", "F5", "F7", "F9")
PARTITIONS = ("train", "validation", "test")
METHODS = ("mutual_unique", "class_consensus")
HEARTBLEED = "Heartbleed"


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def resolve_inside(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    content = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    write_text_atomic(path, content)


def verify_runtime(contract: Mapping[str, Any]) -> None:
    execution = contract.get("execution", {})
    if (
        os.name != "nt"
        or execution.get("host") != "windows_native"
        or execution.get("python_major_minor")
        != f"{sys.version_info.major}.{sys.version_info.minor}"
        or execution.get("pyarrow_exact_version") != PYARROW_VERSION
        or pa.__version__ != PYARROW_VERSION
        or contract.get("eligibility", {}).get("minimum_distinct_flows_at_f9") != 100
        or contract.get("sample_unit", {}).get("eligibility_checkpoint") != "F9"
    ):
        raise RuntimeError("T3.7 runtime or rare-family contract mismatch")


def verify_reference(root: Path, reference: Mapping[str, Any], label: str) -> Path:
    path = resolve_inside(root, str(reference.get("path", "")))
    if (
        not path.is_file()
        or path.stat().st_size != reference.get("size_bytes")
        or sha256_path(path) != reference.get("sha256")
    ):
        raise ValueError(f"{label} content address mismatch")
    return path


def verify_inputs(
    root: Path, contract: Mapping[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, dict[str, Any]]:
    prerequisites = contract["prerequisites"]
    user_path = verify_reference(root, prerequisites["t3_6_user_acceptance"], "T3.6 user acceptance")
    user = load_json(user_path)
    if (
        user.get("task") != "T3.6"
        or user.get("status") != "passed"
        or user.get("decision") != "accepted"
        or not user.get("gate", {}).get("t3_7_authorized")
    ):
        raise ValueError("T3.6 user acceptance does not authorize T3.7")
    acceptance_path = verify_reference(root, prerequisites["t3_6_acceptance"], "T3.6 acceptance")
    acceptance = load_json(acceptance_path)
    if acceptance.get("task") != "T3.6" or acceptance.get("status") != "passed":
        raise ValueError("invalid T3.6 technical acceptance")
    flow_map = verify_reference(root, prerequisites["known_flow_map"], "T3.6 flow map")
    if pq.ParquetFile(flow_map).metadata.num_rows != prerequisites["known_flow_map"]["rows"]:
        raise ValueError("T3.6 flow-map row count mismatch")
    loafo_path = verify_reference(root, prerequisites["loafo_manifest"], "T3.6 LOAFO manifest")
    loafo = load_json(loafo_path)
    if loafo.get("task") != "T3.6" or loafo.get("status") != "passed":
        raise ValueError("invalid T3.6 LOAFO manifest")
    manifest_path = verify_reference(root, prerequisites["t3_5_manifest"], "T3.5 manifest")
    manifest = load_json(manifest_path)
    parts = manifest.get("parts")
    if (
        manifest.get("task") != "T3.5"
        or manifest.get("status") != "passed"
        or not isinstance(parts, list)
        or len(parts) != prerequisites["t3_5_manifest"]["parts"]
        or manifest.get("row_count") != prerequisites["t3_5_manifest"]["rows"]
    ):
        raise ValueError("invalid T3.5 manifest")
    verified_parts: list[dict[str, Any]] = []
    for record in parts:
        path = resolve_inside(root, str(record.get("path", "")))
        if (
            not path.is_file()
            or path.stat().st_size != record.get("size_bytes")
            or sha256_path(path) != record.get("sha256")
            or pq.ParquetFile(path).metadata.num_rows != record.get("rows")
        ):
            raise ValueError(f"T3.5 part content mismatch: {record.get('path')}")
        verified_parts.append({**record, "resolved_path": path})
    return manifest, verified_parts, flow_map, loafo


def increment(target: dict[str, Any], keys: Sequence[str]) -> None:
    node = target
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    node[keys[-1]] = node.get(keys[-1], 0) + 1


def capture_from_path(value: str) -> str:
    marker = "capture_id="
    return value.split(marker, 1)[1].split("/", 1)[0]


def load_flow_map(flow_map: Path, capture_id: str) -> dict[int, tuple[str, str, str]]:
    table = pq.read_table(
        flow_map,
        columns=["flow_id", "partition", "assigned_class", "assignment_method"],
        filters=[("capture_id", "=", capture_id)],
        partitioning=None,
    )
    values = table.to_pydict()
    result = {
        flow_id: (partition, family, method)
        for flow_id, partition, family, method in zip(
            values["flow_id"],
            values["partition"],
            values["assigned_class"],
            values["assignment_method"],
            strict=True,
        )
    }
    if len(result) != table.num_rows:
        raise ValueError(f"duplicate flow-map key in capture: {capture_id}")
    return result


def scan_distributions(
    parts: Sequence[dict[str, Any]], flow_map: Path
) -> dict[str, Any]:
    distributions: dict[str, Any] = {
        "family_and_checkpoint": {},
        "family_partition_and_checkpoint": {},
        "family_assignment_method_and_checkpoint": {},
        "family_capture_and_checkpoint": {},
        "binary_label_and_checkpoint": {},
        "checkpoint": {},
    }
    cached_capture = ""
    mapped: dict[int, tuple[str, str, str]] = {}
    for record in sorted(parts, key=lambda item: item["path"]):
        capture_id = capture_from_path(record["path"])
        if capture_id != cached_capture:
            mapped = load_flow_map(flow_map, capture_id)
            cached_capture = capture_id
        table = pq.ParquetFile(record["resolved_path"]).read(
            columns=["flow_id", "capture_id", "checkpoint", "assigned_class", "label_binary", "assignment_method"]
        )
        values = table.to_pydict()
        previous_flow_id: int | None = None
        for flow_id, row_capture, checkpoint_value, family, binary, method in zip(
            values["flow_id"],
            values["capture_id"],
            values["checkpoint"],
            values["assigned_class"],
            values["label_binary"],
            values["assignment_method"],
            strict=True,
        ):
            if previous_flow_id is not None and flow_id <= previous_flow_id:
                raise ValueError(f"non-unique or unsorted snapshot flow: {record['path']}")
            previous_flow_id = flow_id
            map_value = mapped.get(flow_id)
            if row_capture != capture_id or map_value is None or map_value[1:] != (family, method):
                raise ValueError(f"snapshot does not reconcile with flow map: {capture_id}/{flow_id}")
            partition = map_value[0]
            checkpoint = f"F{checkpoint_value}"
            if partition not in PARTITIONS or method not in METHODS or binary != (family != "BENIGN"):
                raise ValueError(f"invalid snapshot metadata: {capture_id}/{flow_id}/{checkpoint}")
            increment(distributions["family_and_checkpoint"], [family, checkpoint])
            increment(
                distributions["family_partition_and_checkpoint"],
                [family, partition, checkpoint],
            )
            increment(
                distributions["family_assignment_method_and_checkpoint"],
                [family, method, checkpoint],
            )
            increment(
                distributions["family_capture_and_checkpoint"],
                [family, capture_id, checkpoint],
            )
            increment(
                distributions["binary_label_and_checkpoint"],
                ["attack" if binary else "benign", checkpoint],
            )
            increment(distributions["checkpoint"], [checkpoint])
    return distributions


def wilson_worst_case_half_width(n: int, z: float) -> float | None:
    if n <= 0:
        return None
    return z / (2.0 * math.sqrt(n + z * z))


def family_gate(
    distributions: Mapping[str, Any], contract: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    family_counts = distributions["family_and_checkpoint"]
    methods = distributions["family_assignment_method_and_checkpoint"]
    partitions = distributions["family_partition_and_checkpoint"]
    captures = distributions["family_capture_and_checkpoint"]
    threshold = contract["eligibility"]["minimum_distinct_flows_at_f9"]
    z = contract["eligibility"]["statistical_rationale"]["z"]
    warning_threshold = contract["provenance"]["consensus_dependency_warning"]["threshold"]
    attack_families = sorted(family for family in family_counts if family != "BENIGN")
    records: list[dict[str, Any]] = []
    gate = {"macro_eligible": [], "case_study_only": [], "unavailable": []}
    for family in [*attack_families, HEARTBLEED]:
        counts = {checkpoint: family_counts.get(family, {}).get(checkpoint, 0) for checkpoint in CHECKPOINTS}
        f9 = counts["F9"]
        if sum(counts.values()) == 0:
            status = "unavailable"
        elif f9 >= threshold:
            status = "macro_eligible"
        else:
            status = "case_study_only"
        gate[status].append(family)
        method_counts = {
            method: {
                checkpoint: methods.get(family, {}).get(method, {}).get(checkpoint, 0)
                for checkpoint in CHECKPOINTS
            }
            for method in METHODS
        }
        consensus_share = method_counts["class_consensus"]["F9"] / f9 if f9 else None
        records.append(
            {
                "family": family,
                "status": status,
                "snapshot_and_distinct_flow_counts": counts,
                "known_partition_counts": partitions.get(family, {}),
                "assignment_method_counts": method_counts,
                "capture_counts": captures.get(family, {}),
                "eligibility_checkpoint": "F9",
                "eligibility_count": f9,
                "minimum_required": threshold,
                "worst_case_wilson_95_half_width": wilson_worst_case_half_width(f9, z),
                "class_consensus_share_at_f9": consensus_share,
                "provenance_warning": consensus_share is not None and consensus_share > warning_threshold,
            }
        )
    for key in gate:
        gate[key].sort()
    return records, gate


def reconcile_loafo(
    loafo: Mapping[str, Any], distributions: Mapping[str, Any], gate: Mapping[str, list[str]]
) -> None:
    observed = sorted(
        family for family in distributions["family_and_checkpoint"] if family != "BENIGN"
    )
    if loafo.get("available_holdout_families") != observed:
        raise ValueError("T3.6 LOAFO family list differs from T3.7 source scan")
    experiments = {item.get("holdout_family"): item for item in loafo.get("experiments", [])}
    if set(experiments) != set(observed):
        raise ValueError("T3.6 LOAFO experiments do not cover every available family")
    partition_counts = distributions["family_partition_and_checkpoint"]
    for family in observed:
        if experiments[family].get("holdout_snapshot_counts_by_known_partition") != partition_counts[family]:
            raise ValueError(f"T3.6 LOAFO accounting drift: {family}")
    unavailable = loafo.get("unavailable_families")
    if not isinstance(unavailable, list) or [item.get("family") for item in unavailable] != gate["unavailable"]:
        raise ValueError("T3.6 unavailable-family declaration drift")


def analyze(
    root: Path, contract_path: Path
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    contract = load_json(contract_path)
    if contract.get("task") != TASK:
        raise ValueError("invalid T3.7 contract")
    verify_runtime(contract)
    manifest, parts, flow_map, loafo = verify_inputs(root, contract)
    distributions = scan_distributions(parts, flow_map)
    if distributions["checkpoint"] != manifest.get("distributions", {}).get("checkpoint"):
        raise ValueError("T3.5 checkpoint accounting drift")
    records, gate = family_gate(distributions, contract)
    if gate != contract["expected_gate"]:
        raise ValueError("rare-family gate result differs from accepted contract")
    reconcile_loafo(loafo, distributions, gate)
    audit = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "rare_family_audit",
        "status": "passed",
        "generated_at_utc": utc_now(),
        "contract_sha256": sha256_path(contract_path),
        "threshold": contract["eligibility"],
        "provenance_policy": contract["provenance"],
        "gate": gate,
        "families": records,
        "benign_context": {
            "snapshot_counts": distributions["family_and_checkpoint"]["BENIGN"],
            "known_partition_counts": distributions["family_partition_and_checkpoint"]["BENIGN"],
        },
        "distributions": distributions,
        "macro_family_scope": "one_common_list_for_F3_F5_F7_F9",
        "next_gate": {"decision": "pending_user_decision", "t4_1_authorized": False},
    }
    return audit, contract, records


def percentage(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def render_report(audit: Mapping[str, Any]) -> str:
    labels = {
        "macro_eligible": "Đủ mẫu macro LOAFO",
        "case_study_only": "Chỉ case study",
        "unavailable": "Không khả dụng",
    }
    lines = [
        "# Báo cáo T3.7 — Rare-family gate CIC-IDS2017",
        "",
        "## Trạng thái",
        "",
        "Audit kỹ thuật đã pass. Gate đang `pending_user_decision`; T4.1 chưa được mở.",
        "",
        "Ngưỡng đủ mẫu là ít nhất 100 distinct flow tại F9. Một danh sách family chung được dùng cho F3/F5/F7/F9. Ngưỡng tính trên toàn bộ assignment đã được T3.4R1 chấp nhận; provenance vẫn được báo cáo riêng.",
        "",
        "## Số mẫu và quyết định",
        "",
        "| Family | F3 | F5 | F7 | F9 | Consensus F9 | Cảnh báo provenance | Quyết định |",
        "|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for record in audit["families"]:
        counts = record["snapshot_and_distinct_flow_counts"]
        lines.append(
            f"| {record['family']} | {counts['F3']:,} | {counts['F5']:,} | "
            f"{counts['F7']:,} | {counts['F9']:,} | "
            f"{percentage(record['class_consensus_share_at_f9'])} | "
            f"{'Có' if record['provenance_warning'] else 'Không'} | {labels[record['status']]} |"
        )
    gate = audit["gate"]
    lines.extend(
        [
            "",
            "## Phạm vi macro LOAFO",
            "",
            "Đủ mẫu: " + ", ".join(f"`{item}`" for item in gate["macro_eligible"]) + ".",
            "",
            "Chỉ case study: " + ", ".join(f"`{item}`" for item in gate["case_study_only"]) + ".",
            "",
            "Không khả dụng: " + ", ".join(f"`{item}`" for item in gate["unavailable"]) + ".",
            "",
            "Family case study vẫn được giữ trong artifact và có thể báo cáo metric riêng, nhưng không đóng góp vào macro LOAFO. Cảnh báo provenance chỉ cho biết hơn 50% mẫu F9 đến từ `class_consensus`; nó không tự loại family vì T3.4R1 đã chấp nhận cả hai phương thức assignment.",
            "",
            "## Cơ sở thống kê và giới hạn",
            "",
            "Ở n=100, Wilson 95% có worst-case half-width khoảng 9,62 điểm phần trăm khi tỷ lệ thật gần 0,5. Đây là ngưỡng tối thiểu để tránh đưa family cực hiếm vào macro average; nó không chứng minh label accuracy hoặc khả năng tổng quát ngoài CIC-IDS2017.",
            "",
            "F9 là population nhỏ nhất nên được dùng làm conservative bound. Nhờ dùng một danh sách chung, macro score giữa F3/F5/F7/F9 so sánh trên cùng tập family.",
            "",
            "## Artifact và tái lập",
            "",
            "- Audit: `run_log/t3.7/rare-family-audit.json`.",
            "- Acceptance: `run_log/t3.7/acceptance.json`.",
            "- Contract: `config/cicids2017-rare-family-contract.json`.",
            "",
            "```powershell",
            "python scripts/audit_t37_rare_families.py check",
            "python -m unittest discover -s tests -p \"test_t37_rare_families.py\" -v",
            "python scripts/audit_t37_rare_families.py run",
            "python scripts/audit_t37_rare_families.py validate --input run_log/t3.7/acceptance.json",
            "```",
            "",
            "Các lệnh trên không chạy hook, không replay PCAP và không train model.",
        ]
    )
    return "\n".join(lines) + "\n"


def publish(root: Path, contract_path: Path) -> dict[str, Any]:
    audit, contract, _ = analyze(root, contract_path)
    audit_path = resolve_inside(root, contract["outputs"]["audit"])
    report_path = resolve_inside(root, contract["outputs"]["report"])
    acceptance_path = resolve_inside(root, contract["outputs"]["acceptance_receipt"])
    outputs = (audit_path, report_path, acceptance_path)
    if any(path.exists() for path in outputs):
        raise FileExistsError("T3.7 output already exists; refusing to overwrite evidence")
    created: list[Path] = []
    try:
        write_json_atomic(audit_path, audit)
        created.append(audit_path)
        report = render_report(audit)
        write_text_atomic(report_path, report)
        created.append(report_path)
        source_paths = [
            contract_path,
            root / "scripts/audit_t37_rare_families.py",
            root / "tests/test_t37_rare_families.py",
        ]
        acceptance = {
            "schema_version": "1.0.0",
            "task": TASK,
            "kind": "rare_family_acceptance",
            "status": "passed",
            "generated_at_utc": utc_now(),
            "contract": {"path": relative(contract_path, root), "sha256": sha256_path(contract_path)},
            "audit": {"path": relative(audit_path, root), "sha256": sha256_path(audit_path)},
            "report": {"path": relative(report_path, root), "sha256": sha256_path(report_path)},
            "source_files": {
                relative(path, root): sha256_path(path) for path in source_paths
            },
            "gate": {
                "decision": "pending_user_decision",
                "t4_1_authorized": False,
                "macro_eligible_families": audit["gate"]["macro_eligible"],
                "case_study_only_families": audit["gate"]["case_study_only"],
                "unavailable_families": audit["gate"]["unavailable"],
            },
            "validation": {
                "all_t3_5_part_hashes_verified": True,
                "t3_6_flow_map_hash_verified": True,
                "checkpoint_coverage_exact": True,
                "distinct_flow_identity_verified": True,
                "loafo_scope_reconciled": True,
                "provenance_recomputed": True,
                "report_rendered_from_audit": True,
            },
        }
        write_json_atomic(acceptance_path, acceptance)
        return acceptance
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def validate_receipt(root: Path, contract_path: Path, receipt_path: Path) -> None:
    receipt = load_json(receipt_path)
    if receipt.get("task") != TASK or receipt.get("status") != "passed":
        raise ValueError("invalid T3.7 acceptance receipt")
    references = {
        "contract": contract_path,
        "audit": resolve_inside(root, receipt.get("audit", {}).get("path", "")),
        "report": resolve_inside(root, receipt.get("report", {}).get("path", "")),
    }
    for key, path in references.items():
        if not path.is_file() or receipt.get(key, {}).get("sha256") != sha256_path(path):
            raise ValueError(f"T3.7 receipt {key} mismatch")
    audit = load_json(references["audit"])
    receipt_gate = receipt.get("gate", {})
    audit_gate = audit.get("gate", {})
    if (
        audit_gate.get("macro_eligible") != receipt_gate.get("macro_eligible_families")
        or audit_gate.get("case_study_only") != receipt_gate.get("case_study_only_families")
        or audit_gate.get("unavailable") != receipt_gate.get("unavailable_families")
        or receipt_gate.get("decision") != "pending_user_decision"
        or receipt_gate.get("t4_1_authorized") is not False
    ):
        raise ValueError("T3.7 receipt gate is malformed")
    for value, expected_hash in receipt.get("source_files", {}).items():
        path = resolve_inside(root, value)
        if not path.is_file() or sha256_path(path) != expected_hash:
            raise ValueError(f"T3.7 receipt source mismatch: {value}")


def main(argv: Sequence[str] | None = None) -> int:
    root_default = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=root_default)
    parser.add_argument(
        "--contract",
        type=Path,
        default=root_default / "config/cicids2017-rare-family-contract.json",
    )
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        contract_path = args.contract.resolve()
        if args.command == "check":
            contract = load_json(contract_path)
            verify_runtime(contract)
            verify_inputs(root, contract)
            print("[T3.7 check] status=passed", flush=True)
        elif args.command == "run":
            receipt = publish(root, contract_path)
            print(
                f"[T3.7 audit] status=passed macro={len(receipt['gate']['macro_eligible_families'])} "
                f"case_study={len(receipt['gate']['case_study_only_families'])}",
                flush=True,
            )
        else:
            if args.input is None:
                raise ValueError("--input is required for validate")
            validate_receipt(root, contract_path, args.input.resolve())
            print("[T3.7 receipt] status=passed", flush=True)
        return 0
    except (OSError, RuntimeError, ValueError, pa.ArrowException) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
