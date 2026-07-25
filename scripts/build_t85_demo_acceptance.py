from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


TASK = "T8.5"
SPEED_RECEIPT = "run_log/t7.4-t7.6/acceptance.json"
SPEED_SHA256 = "3066a0d56eb2fe14f8c02279cc48d6fd222b72aaed37f3fd81e3e672f38a3498"
HANDOFF_RECEIPT = "run_log/t8.3-t8.4/acceptance.json"
HANDOFF_SHA256 = "ee70c9f5eabd089d171a73dd7fc21f3cc8c5796185e02afda05e289f19379178"
HISTORICAL_AUDIT = "run_log/t8.5/detection-stream-audit.json"
HISTORICAL_AUDIT_SHA256 = (
    "b8d9722ab09f5bcfa2732dc98b63670f9162ce3e56824082473aca6e364d933c"
)
CURRENT_TASK = "config/agent/current-task.json"

SEGMENTS = [
    ("monday", "Monday-WorkingHours.pcap", []),
    ("tuesday", "Tuesday-WorkingHours.pcap", ["FTP-Patator", "SSH-Patator"]),
    (
        "wednesday",
        "Wednesday-workingHours.pcap",
        ["DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris"],
    ),
    (
        "thursday",
        "Thursday-WorkingHours.pcap",
        [
            "Infiltration",
            "Web Attack – Brute Force",
            "Web Attack – Sql Injection",
            "Web Attack – XSS",
        ],
    ),
    ("friday", "Friday-WorkingHours.pcap", ["Bot", "PortScan", "DDoS"]),
]

WORKFLOW_FILES = {
    "streaming_auditor": "scripts/audit_detection_jsonl.py",
    "ubuntu_segment_sensor": "scripts/ubuntu_t85_detection.sh",
    "kali_segment_replay": "scripts/kali_t85_bulk_replay.sh",
    "runbook": "docs/lab/T8.5-live-demo.vi.md",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


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


def file_record(root: Path, relative_path: str) -> dict[str, Any]:
    path = root / relative_path
    require(path.is_file(), f"missing file: {relative_path}")
    return {
        "path": relative_path,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_path(path),
    }


def value_at(document: Mapping[str, Any], keys: Sequence[str]) -> Any:
    value: Any = document
    for key in keys:
        require(isinstance(value, Mapping), f"missing field: {'.'.join(keys)}")
        require(key in value, f"missing field: {'.'.join(keys)}")
        value = value[key]
    return value


def require_values(
    document: Mapping[str, Any],
    expected: Mapping[tuple[str, ...], Any],
    label: str,
) -> None:
    for keys, expected_value in expected.items():
        require(
            value_at(document, keys) == expected_value,
            f"{label} drifted: {'.'.join(keys)}",
        )


def validate_locked_sources(root: Path) -> dict[str, dict[str, Any]]:
    speed_record = file_record(root, SPEED_RECEIPT)
    require(speed_record["sha256"] == SPEED_SHA256, "speed-run receipt hash drifted")
    speed = load_json(root / SPEED_RECEIPT)
    require_values(
        speed,
        {
            ("status",): "accepted_for_speed_run_demo",
            ("scope", "formal_phase_7_acceptance"): False,
            ("t7_4_capacity", "baseline", "sustained_lower_bound_pps"): 5_000,
            ("t7_4_capacity", "baseline", "failed_upper_bound_pps"): 10_000,
            ("t7_4_capacity", "baseline", "maximum_precisely_located"): False,
            ("t7_4_capacity", "full_pipeline", "sustained_pps"): 1_800,
            (
                "t7_4_capacity",
                "full_pipeline",
                "selected_stability_rate_pps",
            ): 1_000,
            (
                "t7_5_system_benchmark",
                "alert_queue",
                "pressure_available",
            ): False,
            ("t7_6_stability", "status"): "passed",
            ("t7_6_stability", "requested_duration_seconds"): 1_800,
            ("t7_6_stability", "sender_packets"): 1_800_000,
            ("t7_6_stability", "ambient_or_nonbenchmark_packets"): 408,
            ("t7_6_stability", "parser_errors"): 202,
            ("t7_6_stability", "port_imissed"): 0,
            ("t7_6_stability", "port_rx_nombuf"): 0,
            ("t7_6_stability", "rollback_status"): "passed",
        },
        "speed-run receipt",
    )

    handoff_record = file_record(root, HANDOFF_RECEIPT)
    require(handoff_record["sha256"] == HANDOFF_SHA256, "handoff receipt hash drifted")
    handoff = load_json(root / HANDOFF_RECEIPT)
    require_values(
        handoff,
        {
            ("status",): "accepted_for_demo",
            ("reproducibility", "benchmark", "status"): (
                "accepted_for_speed_run_demo"
            ),
            ("reproducibility", "benchmark", "formal_phase_7_acceptance"): False,
            ("validation", "speed_run_receipt_hash_verified"): True,
            ("validation", "speed_run_receipt_contract_verified"): True,
        },
        "T8.3-T8.4 handoff",
    )

    audit_record = file_record(root, HISTORICAL_AUDIT)
    require(
        audit_record["sha256"] == HISTORICAL_AUDIT_SHA256,
        "historical detection audit hash drifted",
    )
    audit = load_json(root / HISTORICAL_AUDIT)
    require_values(
        audit,
        {
            ("status",): "failed",
            ("input", "sha256"): (
                "28151610809e5f7725ffeef7c450a63efa581830ed5976f1c6ba346268040e30"
            ),
            ("input", "line_count"): 58_593,
            ("integrity", "invalid_json_lines"): 1,
            ("alerts", "total"): 58_590,
            ("alerts", "chronology_scope_non_lab"): 55_834,
            ("alerts", "lab_hping3_flood", "count"): 2_756,
            ("chronology", "status"): "not_verifiable",
        },
        "historical detection audit",
    )
    return {
        "speed": speed_record,
        "handoff": handoff_record,
        "historical_audit": audit_record,
    }


def speed_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **record,
        "status": "accepted_for_speed_run_demo",
        "formal_phase_7_acceptance": False,
        "baseline_capacity_pps_bracket": {
            "passed_lower_bound": 5_000,
            "failed_upper_bound": 10_000,
            "maximum_precisely_located": False,
        },
        "full_pipeline": {
            "passed_pps": 1_800,
            "cpu_percent": 97.26216064946657,
            "selected_stability_rate_pps": 1_000,
        },
        "system_benchmark_1800_pps": {
            "flows_per_second": 195.832,
            "port_imissed": 0,
            "port_rx_nombuf": 0,
        },
        "stability": {
            "duration_seconds": 1_800,
            "sender_packets": 1_800_000,
            "sender_observed_pps": 999.982152981855,
            "cpu_percent": 54.2958976887289,
            "max_rss_kb": 342_440,
            "max_rss_delta_vs_short_full_run_kb": 64,
            "ambient_or_nonbenchmark_packets": 408,
            "parser_errors": 202,
            "port_imissed": 0,
            "port_rx_nombuf": 0,
            "rollback_status": "passed",
        },
        "limitations": {
            "identity_level_sender_delivery_proven": False,
            "alert_queue_pressure_available": False,
            "production_traffic_mix": False,
            "vmware_is_production_performance_evidence": False,
            "synthetic_benchmark_alerts_per_hour": 703.9874356992259,
            "replaces_t8_1_detection_study_alerts_per_hour": False,
        },
    }


def refresh_receipt(
    receipt: Mapping[str, Any],
    root: Path,
    updated_at_utc: str,
) -> dict[str, Any]:
    require_values(
        receipt,
        {
            ("task",): TASK,
            ("kind",): "demo_critical_path_acceptance",
            ("status",): "passed",
            ("scope", "formal_phase_8_acceptance"): False,
            ("result", "summary_status"): "passed",
            ("result", "ubuntu_rollback_status"): "passed",
            ("result", "kali_rollback_status"): "passed",
        },
        "base T8.5 acceptance",
    )
    records = validate_locked_sources(root)
    refreshed = dict(receipt)
    refreshed["handoff_updated_at_utc"] = updated_at_utc
    refreshed["supplemental_handoff_evidence"] = {
        "t7_4_t7_6_speed_run": speed_summary(records["speed"]),
        "t8_3_t8_4_final_handoff": {
            **records["handoff"],
            "status": "accepted_for_demo",
        },
        "historical_combined_full_replay_audit": {
            **records["historical_audit"],
            "status": "failed",
            "chronology_status": "not_verifiable",
            "invalid_json_lines": 1,
            "alerts": 58_590,
            "lab_hping3_alerts_excluded_from_chronology": 2_756,
            "conclusion": (
                "The combined five-PCAP log cannot prove source-day chronology and "
                "is retained only as historical failed evidence."
            ),
        },
    }
    refreshed["segmented_full_replay_workflow"] = {
        "status": "ready_for_new_evidence",
        "execution_completed": False,
        "ordered_segments": [
            {
                "id": segment_id,
                "source_pcap": source_pcap,
                "allowed_known_attack_candidates": allowed,
            }
            for segment_id, source_pcap, allowed in SEGMENTS
        ],
        "one_sensor_process_per_pcap": True,
        "one_detection_log_per_pcap": True,
        "flow_state_reset_between_pcaps": True,
        "topspeed_retained": True,
        "topspeed_timing_semantics": (
            "receiver_arrival_compressed_not_source_pcap"
        ),
        "source_pcap_delta_time_preserved": False,
        "chronology_gate": "known_attack candidate must belong to its source-PCAP allowlist",
        "lab_hping3_exclusion": (
            "exclude only when both source and destination are in 192.168.252.0/24"
        ),
        "workflow_files": {
            name: file_record(root, path)
            for name, path in WORKFLOW_FILES.items()
        },
    }
    validate_receipt(refreshed, root)
    return refreshed


def validate_receipt(receipt: Mapping[str, Any], root: Path) -> None:
    require_values(
        receipt,
        {
            ("task",): TASK,
            ("status",): "passed",
            ("scope", "formal_phase_8_acceptance"): False,
            (
                "supplemental_handoff_evidence",
                "t7_4_t7_6_speed_run",
                "formal_phase_7_acceptance",
            ): False,
            (
                "supplemental_handoff_evidence",
                "t7_4_t7_6_speed_run",
                "baseline_capacity_pps_bracket",
                "maximum_precisely_located",
            ): False,
            (
                "supplemental_handoff_evidence",
                "historical_combined_full_replay_audit",
                "status",
            ): "failed",
            (
                "supplemental_handoff_evidence",
                "historical_combined_full_replay_audit",
                "chronology_status",
            ): "not_verifiable",
            ("segmented_full_replay_workflow", "status"): "ready_for_new_evidence",
            ("segmented_full_replay_workflow", "execution_completed"): False,
            ("segmented_full_replay_workflow", "one_sensor_process_per_pcap"): True,
            ("segmented_full_replay_workflow", "topspeed_retained"): True,
            (
                "segmented_full_replay_workflow",
                "source_pcap_delta_time_preserved",
            ): False,
        },
        "T8.5 acceptance",
    )
    records = validate_locked_sources(root)
    supplement = receipt["supplemental_handoff_evidence"]
    require(
        supplement["t7_4_t7_6_speed_run"]["sha256"]
        == records["speed"]["sha256"],
        "speed-run reference hash mismatch",
    )
    require(
        supplement["t8_3_t8_4_final_handoff"]["sha256"]
        == records["handoff"]["sha256"],
        "handoff reference hash mismatch",
    )
    require(
        supplement["historical_combined_full_replay_audit"]["sha256"]
        == records["historical_audit"]["sha256"],
        "historical audit reference hash mismatch",
    )
    workflow = receipt["segmented_full_replay_workflow"]
    require(
        workflow["ordered_segments"]
        == [
            {
                "id": segment_id,
                "source_pcap": source_pcap,
                "allowed_known_attack_candidates": allowed,
            }
            for segment_id, source_pcap, allowed in SEGMENTS
        ],
        "segment order or allowlist drifted",
    )
    for name, relative_path in WORKFLOW_FILES.items():
        require(
            workflow["workflow_files"][name] == file_record(root, relative_path),
            f"workflow file drifted: {name}",
        )


def validate_current_task(current_task: Mapping[str, Any], root: Path) -> None:
    require_values(
        current_task,
        {
            ("task",): TASK,
            ("phase",): "segmented_full_replay_ready_for_execution",
            ("status",): "in_progress",
            ("demo_acceptance", "status"): "passed",
            ("demo_acceptance", "formal_phase_8_acceptance"): False,
            ("historical_combined_full_replay_audit", "status"): "failed",
            (
                "historical_combined_full_replay_audit",
                "chronology_status",
            ): "not_verifiable",
            ("segmented_full_replay_workflow", "status"): "ready_for_new_evidence",
            ("segmented_full_replay_workflow", "execution_completed"): False,
            (
                "segmented_full_replay_workflow",
                "source_pcap_delta_time_preserved",
            ): False,
            (
                "gate",
                "historical_combined_full_replay_chronology_verified",
            ): False,
            ("gate", "segmented_full_replay_workflow_ready"): True,
            ("gate", "segmented_full_replay_execution_completed"): False,
        },
        "current task",
    )
    acceptance_record = file_record(root, "run_log/t8.5/demo-acceptance.json")
    for field in ("path", "size_bytes", "sha256"):
        require(
            current_task["demo_acceptance"][field] == acceptance_record[field],
            f"current task demo acceptance reference drifted: {field}",
        )
    audit_record = file_record(root, HISTORICAL_AUDIT)
    for field in ("path", "size_bytes", "sha256"):
        require(
            current_task["historical_combined_full_replay_audit"][field]
            == audit_record[field],
            f"current task historical audit reference drifted: {field}",
        )
    relevant_paths = current_task.get("relevant_paths")
    require(isinstance(relevant_paths, list), "current task relevant_paths is invalid")
    for required_path in (
        "scripts/audit_detection_jsonl.py",
        "scripts/build_t85_demo_acceptance.py",
        "scripts/ubuntu_t85_detection.sh",
        "scripts/kali_t85_bulk_replay.sh",
        "tests/test_audit_detection_jsonl.py",
        "tests/test_t85_demo_acceptance.py",
        "run_log/t8.5/detection-stream-audit.json",
        "docs/lab/T8.5-live-demo.vi.md",
    ):
        require(
            required_path in relevant_paths,
            f"current task missing relevant path: {required_path}",
        )
    commands = value_at(current_task, ("commands", "allowed"))
    require(isinstance(commands, list), "current task command allowlist is invalid")
    for command in (
        "python tests/test_audit_detection_jsonl.py",
        "python tests/test_t85_demo_acceptance.py",
        "python scripts/build_t85_demo_acceptance.py validate",
    ):
        require(command in commands, f"current task missing command: {command}")


def write_json(path: Path, value: Mapping[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_parser(root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    refresh = subparsers.add_parser("refresh")
    refresh.add_argument(
        "--input",
        type=Path,
        default=root / "run_log/t8.5/demo-acceptance.json",
    )
    refresh.add_argument(
        "--output",
        type=Path,
        default=root / "run_log/t8.5/demo-acceptance.json",
    )
    refresh.add_argument("--force", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument(
        "--input",
        type=Path,
        default=root / "run_log/t8.5/demo-acceptance.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    args = build_parser(root).parse_args(argv)
    if args.command == "validate":
        validate_receipt(load_json(args.input), root)
        validate_current_task(load_json(root / CURRENT_TASK), root)
        print(f"[{TASK}] validation passed: {args.input}")
        return 0
    receipt = refresh_receipt(load_json(args.input), root, utc_now())
    write_json(args.output, receipt, args.force)
    print(f"[{TASK}] acceptance refreshed: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
