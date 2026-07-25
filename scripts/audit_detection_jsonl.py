#!/usr/bin/env python3
"""Stream a NIDS detection JSONL log and audit ordering and replay chronology."""

from __future__ import annotations

import argparse
import collections
import hashlib
import heapq
import ipaddress
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TOOL_VERSION = "1.1.0"
SAMPLE_LIMIT = 20


@dataclass(frozen=True)
class AlertRecord:
    line_number: int
    runtime_index: int
    timestamp_ns: int
    namespace: str
    sequence: int
    decision: str
    candidate: str
    source_ip: str
    destination_ip: str

    def compact(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "runtime_index": self.runtime_index,
            "checkpoint_timestamp_ns": self.timestamp_ns,
            "flow_id": {
                "namespace": self.namespace,
                "sequence": str(self.sequence),
            },
            "decision": self.decision,
            "top_candidate": self.candidate,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
        }


@dataclass
class Segment:
    segment_id: str
    source_pcap: str
    start_line: int
    end_line: int
    allowed_candidates: frozenset[str]
    alerts: int = 0
    known_attacks: int = 0
    decisions: collections.Counter[str] = field(default_factory=collections.Counter)
    candidates: collections.Counter[str] = field(default_factory=collections.Counter)
    unexpected_known_attacks: int = 0
    unexpected_samples: list[dict[str, Any]] = field(default_factory=list)

    def contains(self, line_number: int) -> bool:
        return self.start_line <= line_number <= self.end_line

    def observe(self, alert: AlertRecord) -> None:
        self.alerts += 1
        self.decisions[alert.decision] += 1
        self.candidates[alert.candidate] += 1
        if alert.decision != "known_attack":
            return
        self.known_attacks += 1
        if alert.candidate in self.allowed_candidates:
            return
        self.unexpected_known_attacks += 1
        if len(self.unexpected_samples) < SAMPLE_LIMIT:
            self.unexpected_samples.append(alert.compact())

    def result(self) -> dict[str, Any]:
        return {
            "id": self.segment_id,
            "source_pcap": self.source_pcap,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "allowed_known_attack_candidates": sorted(self.allowed_candidates),
            "alerts": self.alerts,
            "known_attacks": self.known_attacks,
            "decision_counts": sorted_counter(self.decisions),
            "top_candidate_counts": sorted_counter(self.candidates),
            "unexpected_known_attacks": self.unexpected_known_attacks,
            "unexpected_known_attack_samples": self.unexpected_samples,
        }


def sorted_counter(counter: Mapping[str, int]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def parse_positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def write_json_atomic(path: Path, value: Mapping[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"output exists; pass --force to replace it: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    content = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return value


def require_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def nested(value: Mapping[str, Any], path: Sequence[str]) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            raise ValueError(f"missing alert field: {'.'.join(path)}")
        current = current[key]
    return current


def parse_alert(
    value: Mapping[str, Any],
    line_number: int,
    runtime_index: int,
) -> AlertRecord:
    return AlertRecord(
        line_number=line_number,
        runtime_index=runtime_index,
        timestamp_ns=require_integer(
            value.get("checkpoint_timestamp_ns"),
            "checkpoint_timestamp_ns",
        ),
        namespace=require_string(
            nested(value, ("flow", "id", "namespace")),
            "flow.id.namespace",
        ),
        sequence=int(
            require_string(
                nested(value, ("flow", "id", "sequence")),
                "flow.id.sequence",
            )
        ),
        decision=require_string(value.get("decision"), "decision"),
        candidate=require_string(
            nested(value, ("evidence", "known_family", "top_candidate")),
            "evidence.known_family.top_candidate",
        ),
        source_ip=require_string(
            nested(value, ("flow", "source", "ip")),
            "flow.source.ip",
        ),
        destination_ip=require_string(
            nested(value, ("flow", "destination", "ip")),
            "flow.destination.ip",
        ),
    )


def parse_lab_subnets(values: Sequence[str]) -> tuple[ipaddress._BaseNetwork, ...]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        networks.append(ipaddress.ip_network(value, strict=True))
    return tuple(networks)


def is_lab_alert(
    alert: AlertRecord,
    networks: Sequence[ipaddress._BaseNetwork],
) -> bool:
    try:
        source = ipaddress.ip_address(alert.source_ip)
        destination = ipaddress.ip_address(alert.destination_ip)
    except ValueError:
        return False
    return any(source in network and destination in network for network in networks)


def load_segments(
    manifest_path: Path | None,
) -> tuple[dict[str, Any] | None, list[Segment]]:
    if manifest_path is None:
        return None, []
    manifest = load_json_object(manifest_path, "segment manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("segment manifest schema_version mismatch")
    expected_hash = manifest.get("input_sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise ValueError("segment manifest input_sha256 must be a SHA-256 hex digest")
    raw_segments = manifest.get("segments")
    if not isinstance(raw_segments, list) or not raw_segments:
        raise ValueError("segment manifest must contain at least one segment")
    segments: list[Segment] = []
    previous_end = 0
    identifiers: set[str] = set()
    for index, raw in enumerate(raw_segments):
        if not isinstance(raw, dict):
            raise ValueError(f"segment {index} must be an object")
        segment_id = require_string(raw.get("id"), f"segments[{index}].id")
        if segment_id in identifiers:
            raise ValueError(f"duplicate segment id: {segment_id}")
        identifiers.add(segment_id)
        start_line = require_integer(
            raw.get("start_line"),
            f"segments[{index}].start_line",
        )
        end_line = require_integer(
            raw.get("end_line"),
            f"segments[{index}].end_line",
        )
        if start_line <= previous_end or end_line < start_line:
            raise ValueError("segment line ranges must be positive, ordered and disjoint")
        previous_end = end_line
        raw_allowed = raw.get("allowed_known_attack_candidates")
        if not isinstance(raw_allowed, list) or any(
            not isinstance(candidate, str) or not candidate
            for candidate in raw_allowed
        ):
            raise ValueError(
                f"segments[{index}].allowed_known_attack_candidates must be strings"
            )
        segments.append(
            Segment(
                segment_id=segment_id,
                source_pcap=require_string(
                    raw.get("source_pcap"),
                    f"segments[{index}].source_pcap",
                ),
                start_line=start_line,
                end_line=end_line,
                allowed_candidates=frozenset(raw_allowed),
            )
        )
    return manifest, segments


def push_gap(
    heap: list[tuple[int, int, dict[str, Any], dict[str, Any]]],
    limit: int,
    before: AlertRecord,
    after: AlertRecord,
) -> None:
    gap = after.timestamp_ns - before.timestamp_ns
    item = (gap, after.line_number, before.compact(), after.compact())
    if len(heap) < limit:
        heapq.heappush(heap, item)
    elif gap > heap[0][0]:
        heapq.heapreplace(heap, item)


def audit_detection_log(
    input_path: Path,
    *,
    input_label: str,
    top_gaps: int,
    lab_subnets: Sequence[str],
    manifest_path: Path | None = None,
    manifest_label: str | None = None,
) -> dict[str, Any]:
    if not input_path.is_file():
        raise FileNotFoundError(f"input JSONL does not exist: {input_path}")
    networks = parse_lab_subnets(lab_subnets)
    manifest, segments = load_segments(manifest_path)
    digest = hashlib.sha256()
    byte_count = 0
    line_count = 0
    invalid_json_lines = 0
    invalid_json_samples: list[dict[str, Any]] = []
    invalid_event_lines = 0
    invalid_event_samples: list[dict[str, Any]] = []
    event_counts: collections.Counter[str] = collections.Counter()
    decision_counts: collections.Counter[str] = collections.Counter()
    candidate_counts: collections.Counter[str] = collections.Counter()
    known_attack_candidates: collections.Counter[str] = collections.Counter()
    lab_decisions: collections.Counter[str] = collections.Counter()
    lab_candidates: collections.Counter[str] = collections.Counter()
    clock_domains: collections.Counter[str] = collections.Counter()
    ready_events: list[dict[str, Any]] = []
    summary_events: list[dict[str, Any]] = []
    timestamp_violation_count = 0
    timestamp_violations: list[dict[str, Any]] = []
    sequence_regressions = 0
    duplicate_flow_ids = 0
    duplicate_flow_id_samples: list[dict[str, Any]] = []
    seen_flow_ids: set[tuple[int, str, int]] = set()
    largest_gaps: list[tuple[int, int, dict[str, Any], dict[str, Any]]] = []
    runtime_index = 0
    alerts = 0
    analyzable_alerts = 0
    lab_alerts = 0
    uncovered_alerts = 0
    uncovered_samples: list[dict[str, Any]] = []
    segment_index = 0
    previous_alert: AlertRecord | None = None
    previous_analyzable_alert: AlertRecord | None = None
    first_alert: AlertRecord | None = None
    last_alert: AlertRecord | None = None

    with input_path.open("rb") as source:
        for raw_line in source:
            line_count += 1
            byte_count += len(raw_line)
            digest.update(raw_line)
            try:
                line = raw_line.decode("utf-8")
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                invalid_json_lines += 1
                if len(invalid_json_samples) < SAMPLE_LIMIT:
                    invalid_json_samples.append(
                        {
                            "line_number": line_count,
                            "error": str(error),
                            "prefix": raw_line[:160].decode("utf-8", errors="replace"),
                        }
                    )
                continue
            if not isinstance(value, dict):
                invalid_event_lines += 1
                if len(invalid_event_samples) < SAMPLE_LIMIT:
                    invalid_event_samples.append(
                        {
                            "line_number": line_count,
                            "error": "JSONL event must be an object",
                        }
                    )
                continue
            event_type = value.get("event_type")
            if not isinstance(event_type, str) or not event_type:
                invalid_event_lines += 1
                if len(invalid_event_samples) < SAMPLE_LIMIT:
                    invalid_event_samples.append(
                        {
                            "line_number": line_count,
                            "error": "event_type must be a non-empty string",
                        }
                    )
                continue
            event_counts[event_type] += 1
            if event_type == "nids_dpdk_live_ready":
                runtime_index += 1
                ready_events.append(
                    {
                        "line_number": line_count,
                        "runtime_index": runtime_index,
                        "checkpoint": value.get("checkpoint"),
                        "clock_domain": value.get("clock_domain"),
                        "continuous": value.get("continuous"),
                    }
                )
                previous_alert = None
                previous_analyzable_alert = None
                continue
            if event_type == "nids_dpdk_live_summary":
                summary_events.append(
                    {
                        "line_number": line_count,
                        "runtime_index": runtime_index,
                        "stop_reason": value.get("stop_reason"),
                        "packets_seen": value.get("packets_seen"),
                        "alerts": value.get("alerts"),
                    }
                )
                continue
            if event_type != "nids_alert":
                continue
            try:
                alert = parse_alert(value, line_count, runtime_index)
                ipaddress.ip_address(alert.source_ip)
                ipaddress.ip_address(alert.destination_ip)
            except (ValueError, OverflowError) as error:
                invalid_event_lines += 1
                if len(invalid_event_samples) < SAMPLE_LIMIT:
                    invalid_event_samples.append(
                        {
                            "line_number": line_count,
                            "error": str(error),
                        }
                    )
                continue
            alerts += 1
            if first_alert is None:
                first_alert = alert
            last_alert = alert
            clock_domain = value.get("clock_domain")
            if isinstance(clock_domain, str):
                clock_domains[clock_domain] += 1
            decision_counts[alert.decision] += 1
            candidate_counts[alert.candidate] += 1
            if alert.decision == "known_attack":
                known_attack_candidates[alert.candidate] += 1
            flow_id = (alert.runtime_index, alert.namespace, alert.sequence)
            if flow_id in seen_flow_ids:
                duplicate_flow_ids += 1
                if len(duplicate_flow_id_samples) < SAMPLE_LIMIT:
                    duplicate_flow_id_samples.append(alert.compact())
            else:
                seen_flow_ids.add(flow_id)
            if previous_alert is not None:
                if alert.timestamp_ns < previous_alert.timestamp_ns:
                    timestamp_violation_count += 1
                    if len(timestamp_violations) < SAMPLE_LIMIT:
                        timestamp_violations.append(
                            {
                                "before": previous_alert.compact(),
                                "after": alert.compact(),
                            }
                        )
                if alert.sequence <= previous_alert.sequence:
                    sequence_regressions += 1
            previous_alert = alert
            if is_lab_alert(alert, networks):
                lab_alerts += 1
                lab_decisions[alert.decision] += 1
                lab_candidates[alert.candidate] += 1
                continue
            analyzable_alerts += 1
            if previous_analyzable_alert is not None:
                push_gap(
                    largest_gaps,
                    top_gaps,
                    previous_analyzable_alert,
                    alert,
                )
            previous_analyzable_alert = alert
            if not segments:
                continue
            while (
                segment_index < len(segments)
                and line_count > segments[segment_index].end_line
            ):
                segment_index += 1
            if (
                segment_index >= len(segments)
                or not segments[segment_index].contains(line_count)
            ):
                uncovered_alerts += 1
                if len(uncovered_samples) < SAMPLE_LIMIT:
                    uncovered_samples.append(alert.compact())
                continue
            segments[segment_index].observe(alert)

    input_sha256 = digest.hexdigest()
    manifest_hash_matches = (
        manifest is None or manifest.get("input_sha256") == input_sha256
    )
    if manifest is None:
        chronology_status = "not_verifiable"
        chronology_reasons = [
            "no segment manifest was supplied",
            "alerts do not carry a source PCAP or dataset-day identifier",
        ]
    else:
        chronology_reasons = []
        unexpected = sum(segment.unexpected_known_attacks for segment in segments)
        if not manifest_hash_matches:
            chronology_reasons.append("segment manifest input_sha256 does not match")
        if invalid_json_lines or invalid_event_lines:
            chronology_reasons.append("invalid input lines can hide chronology evidence")
        if uncovered_alerts:
            chronology_reasons.append("non-lab alerts are outside segment line ranges")
        if unexpected:
            chronology_reasons.append(
                "known_attack candidates occur outside their allowed replay segment"
            )
        chronology_status = "passed" if not chronology_reasons else "failed"

    integrity_failures = (
        invalid_json_lines
        + invalid_event_lines
        + timestamp_violation_count
        + duplicate_flow_ids
    )
    if integrity_failures or chronology_status == "failed":
        audit_status = "failed"
    elif chronology_status == "not_verifiable":
        audit_status = "completed_with_limitations"
    else:
        audit_status = "passed"

    gap_results = [
        {
            "gap_ns": gap,
            "gap_seconds": gap / 1_000_000_000.0,
            "before": before,
            "after": after,
        }
        for gap, _, before, after in sorted(largest_gaps, reverse=True)
    ]
    manifest_reference = None
    if manifest_path is not None:
        manifest_reference = {
            "path": manifest_label or manifest_path.as_posix(),
            "input_sha256_matches": manifest_hash_matches,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "nids_detection_jsonl_stream_audit",
        "tool": {
            "name": "scripts/audit_detection_jsonl.py",
            "version": TOOL_VERSION,
            "read_mode": "binary_line_stream",
            "whole_file_loaded": False,
        },
        "status": audit_status,
        "input": {
            "path": input_label,
            "size_bytes": byte_count,
            "sha256": input_sha256,
            "line_count": line_count,
        },
        "configuration": {
            "top_gaps": top_gaps,
            "lab_subnets": [str(network) for network in networks],
            "lab_rule": "both_source_and_destination_inside_same_configured_subnet",
            "segment_manifest": manifest_reference,
        },
        "integrity": {
            "status": "passed" if integrity_failures == 0 else "failed",
            "invalid_json_lines": invalid_json_lines,
            "invalid_json_samples": invalid_json_samples,
            "invalid_event_lines": invalid_event_lines,
            "invalid_event_samples": invalid_event_samples,
            "duplicate_flow_ids_within_runtime": duplicate_flow_ids,
            "duplicate_flow_id_samples": duplicate_flow_id_samples,
        },
        "events": {
            "counts": sorted_counter(event_counts),
            "ready_events": ready_events,
            "summary_events": summary_events,
        },
        "alerts": {
            "total": alerts,
            "chronology_scope_non_lab": analyzable_alerts,
            "lab_hping3_flood": {
                "count": lab_alerts,
                "decision_counts": sorted_counter(lab_decisions),
                "top_candidate_counts": sorted_counter(lab_candidates),
            },
            "decision_counts": sorted_counter(decision_counts),
            "top_candidate_counts": sorted_counter(candidate_counts),
            "known_attack_candidate_counts": sorted_counter(
                known_attack_candidates
            ),
            "clock_domain_counts": sorted_counter(clock_domains),
            "first": first_alert.compact() if first_alert else None,
            "last": last_alert.compact() if last_alert else None,
        },
        "ordering": {
            "checkpoint_timestamps_nondecreasing_within_runtime": (
                timestamp_violation_count == 0
            ),
            "timestamp_violation_count": timestamp_violation_count,
            "timestamp_violation_samples": timestamp_violations,
            "flow_sequence_regressions": sequence_regressions,
            "flow_sequence_note": (
                "informational only: flow generation order is not alert emission order"
            ),
            "largest_adjacent_non_lab_alert_gaps": gap_results,
        },
        "chronology": {
            "status": chronology_status,
            "scope": (
                "known_attack top_candidate per source-PCAP segment; "
                "alerts classified as lab_hping3_flood are excluded"
            ),
            "reasons": chronology_reasons,
            "uncovered_non_lab_alerts": uncovered_alerts,
            "uncovered_samples": uncovered_samples,
            "segments": [segment.result() for segment in segments],
        },
    }


def display_path(path: Path) -> str:
    return path.as_posix()


def single_segment_manifest(
    audit: Mapping[str, Any],
    segment_id: str,
    source_pcap: str,
    allowed_candidates: Sequence[str],
) -> dict[str, Any]:
    require_string(segment_id, "segment_id")
    require_string(source_pcap, "source_pcap")
    if any(
        not isinstance(candidate, str) or not candidate
        for candidate in allowed_candidates
    ):
        raise ValueError("allowed known-attack candidates must be non-empty strings")
    input_summary = audit.get("input")
    if not isinstance(input_summary, Mapping):
        raise ValueError("preliminary audit has no input summary")
    line_count = require_integer(input_summary.get("line_count"), "input.line_count")
    input_sha256 = require_string(input_summary.get("sha256"), "input.sha256")
    if line_count <= 0:
        raise ValueError("cannot create a segment manifest for an empty JSONL file")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "nids_detection_single_segment_manifest",
        "input_sha256": input_sha256,
        "segments": [
            {
                "id": segment_id,
                "source_pcap": source_pcap,
                "start_line": 1,
                "end_line": line_count,
                "allowed_known_attack_candidates": sorted(set(allowed_candidates)),
            }
        ],
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--top-gaps", type=parse_positive, default=12)
    parser.add_argument("--lab-subnet", action="append", default=[])
    parser.add_argument("--segment-manifest", type=Path)
    parser.add_argument("--create-single-segment-manifest", type=Path)
    parser.add_argument("--segment-id")
    parser.add_argument("--source-pcap")
    parser.add_argument(
        "--allow-known-attack-candidate",
        action="append",
        default=[],
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--require-passed", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        create_manifest = args.create_single_segment_manifest
        segment_details_supplied = (
            args.segment_id is not None
            or args.source_pcap is not None
            or bool(args.allow_known_attack_candidate)
        )
        if args.segment_manifest is not None and create_manifest is not None:
            raise ValueError(
                "--segment-manifest and --create-single-segment-manifest are exclusive"
            )
        if create_manifest is None and segment_details_supplied:
            raise ValueError(
                "segment details require --create-single-segment-manifest"
            )
        if create_manifest is not None and (
            args.segment_id is None or args.source_pcap is None
        ):
            raise ValueError(
                "--segment-id and --source-pcap are required when creating a manifest"
            )
        resolved_input = args.input.resolve()
        output_paths = [
            path.resolve()
            for path in (args.output, create_manifest)
            if path is not None
        ]
        if (
            resolved_input in output_paths
            or len(output_paths) != len(set(output_paths))
        ):
            raise ValueError("input, output and generated manifest paths must be distinct")
        if not args.force:
            for path in (args.output, create_manifest):
                if path is not None and path.exists():
                    raise FileExistsError(
                        f"output exists; pass --force to replace it: {path}"
                    )
        manifest_path = args.segment_manifest
        manifest_label = (
            display_path(manifest_path) if manifest_path is not None else None
        )
        if create_manifest is not None:
            preliminary = audit_detection_log(
                args.input,
                input_label=display_path(args.input),
                top_gaps=args.top_gaps,
                lab_subnets=args.lab_subnet,
            )
            manifest = single_segment_manifest(
                preliminary,
                args.segment_id,
                args.source_pcap,
                args.allow_known_attack_candidate,
            )
            write_json_atomic(create_manifest, manifest, args.force)
            manifest_path = create_manifest
            manifest_label = display_path(create_manifest)
        audit = audit_detection_log(
            args.input,
            input_label=display_path(args.input),
            top_gaps=args.top_gaps,
            lab_subnets=args.lab_subnet,
            manifest_path=manifest_path,
            manifest_label=manifest_label,
        )
        if args.output is None:
            print(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            write_json_atomic(args.output, audit, args.force)
            print(
                f"detection audit: status={audit['status']} "
                f"alerts={audit['alerts']['total']} "
                f"chronology={audit['chronology']['status']} "
                f"output={args.output}",
                flush=True,
            )
        if args.require_passed and audit["status"] != "passed":
            return 1
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
