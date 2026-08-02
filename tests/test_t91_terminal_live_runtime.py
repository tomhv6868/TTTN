#!/usr/bin/env python3
"""Exercise the T9.1 terminal DPDK runtime through the net_pcap PMD."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


SOURCE_IP = "10.77.1.41"
TARGET_IP = "10.77.1.99"
AMBIENT_IP = "10.77.1.7"
RUN_CONTRACT_SHA256 = "7" * 64
CLASS_ORDER = [
    "Benign",
    "FTP-Bruteforce",
    "SSH-Bruteforce",
    "PortScan",
    "DoS",
    "Other",
]
FEATURE_SCHEMA_ID = "nids.terminal_flow_features.v1"
FEATURE_COUNT = 70
DECISION_EVENT_HARD_LIMIT = 4_096
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise RuntimeError(detail)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_frame(
    source_ip: str,
    source_port: int,
    target_ip: str,
    target_port: int,
    flags: int,
    sequence: int,
    *,
    ttl: int = 64,
    window: int = 32_768,
    options: bytes = b"",
    minimum_frame_size: int = 0,
) -> bytes:
    require(len(options) % 4 == 0 and len(options) <= 40, "invalid TCP options")
    source = ipaddress.IPv4Address(source_ip).packed
    target = ipaddress.IPv4Address(target_ip).packed
    data_offset = (20 + len(options)) // 4
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        target_port,
        sequence,
        0,
        data_offset << 4,
        flags,
        window,
        0,
        0,
    ) + options
    pseudo_header = source + target + struct.pack("!BBH", 0, 6, len(tcp))
    tcp_checksum = checksum(pseudo_header + tcp)
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        target_port,
        sequence,
        0,
        data_offset << 4,
        flags,
        window,
        tcp_checksum,
        0,
    ) + options
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        sequence & 0xFFFF,
        0x4000,
        ttl,
        6,
        0,
        source,
        target,
    )
    ipv4_checksum = checksum(ipv4)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        sequence & 0xFFFF,
        0x4000,
        ttl,
        6,
        ipv4_checksum,
        source,
        target,
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return (ethernet + ipv4 + tcp).ljust(minimum_frame_size, b"\x00")


def ethernet_frame(ether_type: int, payload: bytes = b"") -> bytes:
    frame = (
        bytes.fromhex("00112233445566778899aabb")
        + struct.pack("!H", ether_type)
        + payload
    )
    return frame.ljust(60, b"\x00")


def write_pcap(path: Path, frames: Sequence[bytes]) -> None:
    data = bytearray(
        struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 1)
    )
    for index, frame in enumerate(frames, start=1):
        data.extend(
            struct.pack("<IIII", 1, index * 1_000_000, len(frame), len(frame))
        )
        data.extend(frame)
    path.write_bytes(data)


def command(
    args: argparse.Namespace,
    pcap: Path,
    case_id: str,
    *,
    source_ip: str = SOURCE_IP,
    target_ip: str = TARGET_IP,
    any_source: bool = False,
    output_mode: str | None = None,
    manifest_sha256: str | None = None,
    lifecycle_mode: str = "bounded",
    alerts_file: Path | None = None,
    shutdown_grace_ms: int = 5_000,
    max_packets: int | None,
    max_runtime_ms: int = 2_000,
    arm_timeout_ms: int = 1_000,
    idle_timeout_ms: int = 1_000,
) -> list[str]:
    unique = f"{case_id}{os.getpid()}"
    scope_arguments = (
        ["--any-source"]
        if any_source
        else ["--source-ip", source_ip]
    )
    output_arguments = (
        [] if output_mode is None else ["--output-mode", output_mode]
    )
    if lifecycle_mode == "bounded":
        require(max_packets is not None, "bounded test command needs max_packets")
        lifecycle_arguments = [
            "--lifecycle-mode",
            "bounded",
            "--max-packets",
            str(max_packets),
            "--max-runtime-ms",
            str(max_runtime_ms),
            "--arm-timeout-ms",
            str(arm_timeout_ms),
            "--idle-timeout-ms",
            str(idle_timeout_ms),
        ]
    elif lifecycle_mode == "signal-only":
        require(
            output_mode == "alerts-only" and alerts_file is not None,
            "signal-only test command needs alerts-only output and alert path",
        )
        lifecycle_arguments = [
            "--lifecycle-mode",
            "signal-only",
            "--alerts-file",
            str(alerts_file.resolve()),
            "--shutdown-grace-ms",
            str(shutdown_grace_ms),
        ]
    else:
        raise RuntimeError(f"unsupported test lifecycle: {lifecycle_mode}")
    return [
        str(args.binary),
        "-l",
        "0",
        "--no-pci",
        "--no-huge",
        "--in-memory",
        "--no-telemetry",
        "--log-level=*:warning",
        f"--file-prefix=t91{unique}",
        f"--vdev=net_pcap_{case_id},rx_pcap={pcap}",
        "--",
        "--bundle",
        str(args.bundle),
        "--manifest-sha256",
        manifest_sha256 or args.manifest_sha256,
        *scope_arguments,
        "--target-ip",
        target_ip,
        *output_arguments,
        "--attempt-id",
        f"phase8-{case_id}",
        "--run-token",
        f"run-{case_id}",
        "--run-contract-sha256",
        RUN_CONTRACT_SHA256,
        "--port-id",
        "0",
        *lifecycle_arguments,
    ]


def run_command(
    arguments: Sequence[str],
    *,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def parse_events(result: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if not line:
            continue
        value = json.loads(line)
        require(isinstance(value, dict), f"event is not an object: {value!r}")
        events.append(value)
    return events


def one_event(
    events: Sequence[dict[str, Any]],
    event_type: str,
) -> dict[str, Any]:
    selected = [event for event in events if event.get("event_type") == event_type]
    require(
        len(selected) == 1,
        f"expected one {event_type}, observed {len(selected)}: {events!r}",
    )
    return selected[0]


def require_sorted_objects(value: Any) -> None:
    if isinstance(value, dict):
        require(list(value) == sorted(value), f"JSON object keys are not sorted: {value}")
        for child in value.values():
            require_sorted_objects(child)
    elif isinstance(value, list):
        for child in value:
            require_sorted_objects(child)


def require_run_identity(
    event: dict[str, Any],
    case_id: str,
    *,
    source_ip: str = SOURCE_IP,
    target_ip: str = TARGET_IP,
    any_source: bool = False,
) -> None:
    require(event.get("schema_version") == "1.0.0", f"schema mismatch: {event}")
    require(event.get("task") == "T9.1", f"task mismatch: {event}")
    require(event.get("attempt_id") == f"phase8-{case_id}", f"attempt mismatch: {event}")
    require(event.get("run_token") == f"run-{case_id}", f"token mismatch: {event}")
    require(
        event.get("run_contract_sha256") == RUN_CONTRACT_SHA256,
        f"contract hash mismatch: {event}",
    )
    require(
        event.get("scope_mode")
        == ("target_ip" if any_source else "endpoint_pair"),
        f"scope mode mismatch: {event}",
    )
    require(
        event.get("source_ip") == (None if any_source else source_ip),
        f"source contract mismatch: {event}",
    )
    require(event.get("target_ip") == target_ip, f"target contract mismatch: {event}")


def require_artifact(event: dict[str, Any], args: argparse.Namespace) -> None:
    artifact = event.get("artifact")
    require(isinstance(artifact, dict), f"artifact identity missing: {event}")
    require(
        artifact.get("bundle_manifest_sha256") == args.manifest_sha256,
        f"bundle manifest mismatch: {event}",
    )
    require(
        artifact.get("feature_schema_id") == FEATURE_SCHEMA_ID,
        f"feature schema mismatch: {event}",
    )
    for name in ("feature_schema_sha256", "model_sha256"):
        value = artifact.get(name)
        require(
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value),
            f"invalid {name}: {event}",
        )
    for name in ("artifact_id", "artifact_version", "profile_id"):
        require(
            isinstance(artifact.get(name), str) and bool(artifact[name]),
            f"missing {name}: {event}",
        )


def require_clean_summary(
    summary: dict[str, Any],
    args: argparse.Namespace,
    *,
    output_mode: str = "diagnostic",
    lifecycle_mode: str = "bounded",
    shutdown_grace_ms: int = 250,
) -> None:
    require(summary.get("status") == "passed", f"summary failed: {summary}")
    require(
        summary.get("bounded") is (lifecycle_mode == "bounded")
        and summary.get("lifecycle_mode") == lifecycle_mode
        and summary.get("shutdown_grace_ms") == shutdown_grace_ms,
        f"lifecycle mismatch: {summary}",
    )
    require(summary.get("shutdown_complete") is True, f"shutdown incomplete: {summary}")
    require(
        summary.get("shutdown_deadline_overruns") == 0,
        f"shutdown deadline overrun: {summary}",
    )
    require(summary.get("active_flow_limit") == 2_048, f"flow bound mismatch: {summary}")
    require(summary.get("rx_queues") == 1, f"RX queue mismatch: {summary}")
    require(summary.get("tx_queues") == 0, f"TX queue mismatch: {summary}")
    require(summary.get("class_order") == CLASS_ORDER, f"class order mismatch: {summary}")
    require(summary.get("output_mode") == output_mode, f"output mode mismatch: {summary}")
    if output_mode == "diagnostic":
        require(
            summary.get("decision_event_policy") == "fail_closed_no_sampling",
            f"decision event policy mismatch: {summary}",
        )
        require(
            isinstance(summary.get("decision_event_limit"), int)
            and 0 < summary["decision_event_limit"] <= DECISION_EVENT_HARD_LIMIT,
            f"decision event limit mismatch: {summary}",
        )
        require(
            summary.get("decision_diagnostics_complete") is True
            and summary.get("decision_event_limit_rejections") == 0
            and summary.get("decision_events") == summary.get("inferences")
            and summary.get("decision_diagnostics_suppressed") == 0,
            f"decision diagnostic accounting mismatch: {summary}",
        )
    else:
        require(
            output_mode == "alerts_only"
            and summary.get("decision_event_policy") == "disabled_alerts_only"
            and summary.get("decision_event_limit") == 0
            and summary.get("decision_event_limit_rejections") == 0
            and summary.get("decision_events") == 0
            and summary.get("decision_diagnostics_complete") is False
            and summary.get("decision_diagnostics_suppressed")
                == summary.get("inferences"),
            f"alerts-only accounting mismatch: {summary}",
        )
    require(
        summary.get("alerts_complete") is True
        and summary.get("alerts") == summary.get("attack_decisions")
        and summary.get("benign_decisions", 0)
            + summary.get("attack_decisions", 0)
            == summary.get("inferences"),
        f"alert accounting mismatch: {summary}",
    )
    require(
        isinstance(summary.get("attack_threshold"), float),
        f"threshold missing: {summary}",
    )
    require_artifact(summary, args)
    errors = summary.get("errors")
    require(
        isinstance(errors, dict) and all(value == 0 for value in errors.values()),
        f"runtime errors are nonzero: {summary}",
    )
    stats = summary.get("port_stats")
    require(isinstance(stats, dict) and stats.get("available") is True, f"stats missing: {summary}")
    for name in ("imissed", "ierrors", "rx_nombuf", "opackets", "oerrors"):
        require(stats.get(name) == 0, f"port stat {name} is nonzero: {summary}")


def require_flow_record(event: dict[str, Any]) -> None:
    eligible = event.get("close_reason") in {"tcp_reset", "tcp_fin_handshake"}
    require(
        event.get("acceptance_eligible") is eligible,
        f"eligibility mismatch: {event}",
    )
    flow = event.get("flow")
    require(isinstance(flow, dict), f"flow missing: {event}")
    require(flow.get("protocol") == "tcp", f"protocol mismatch: {event}")
    require(flow.get("source", {}).get("ip") == SOURCE_IP, f"source mismatch: {event}")
    require(flow.get("destination", {}).get("ip") == TARGET_IP, f"target mismatch: {event}")
    for endpoint in ("source", "destination"):
        port = flow.get(endpoint, {}).get("port")
        require(
            isinstance(port, int) and 0 < port <= 65_535,
            f"{endpoint} port mismatch: {event}",
        )
    packet_count = event.get("packet_count")
    forward_count = event.get("forward_packet_count")
    reverse_count = event.get("reverse_packet_count")
    require(
        isinstance(packet_count, int)
        and packet_count > 0
        and forward_count + reverse_count == packet_count,
        f"packet accounting mismatch: {event}",
    )
    for name in (
        "creation_timestamp_ns",
        "last_capture_timestamp_ns",
        "last_event_timestamp_ns",
        "duration_ns",
    ):
        require(
            isinstance(event.get(name), int) and event[name] >= 0,
            f"invalid {name}: {event}",
        )
    require(
        event["last_event_timestamp_ns"] >= event["creation_timestamp_ns"]
        and event["duration_ns"]
        == event["last_event_timestamp_ns"] - event["creation_timestamp_ns"],
        f"duration mismatch: {event}",
    )


def require_probabilities(
    scores: dict[str, Any],
    event: dict[str, Any],
) -> list[float]:
    require(scores.get("class_order") == CLASS_ORDER, f"class order mismatch: {event}")
    probabilities = scores.get("class_probabilities")
    require(
        isinstance(probabilities, list) and len(probabilities) == len(CLASS_ORDER),
        f"probability shape mismatch: {event}",
    )
    require(
        all(
            isinstance(value, float) and math.isfinite(value) and 0.0 <= value <= 1.0
            for value in probabilities
        ),
        f"invalid probabilities: {event}",
    )
    require(
        math.isclose(sum(probabilities), 1.0, rel_tol=1e-5, abs_tol=1e-5),
        f"probabilities are not normalized: {event}",
    )
    return probabilities


def validate_decisions(
    events: Sequence[dict[str, Any]],
    case_id: str,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    decisions = [
        event
        for event in events
        if event.get("event_type") == "nids_terminal_flow_decision"
    ]
    for ordinal, event in enumerate(decisions, start=1):
        require_run_identity(event, case_id)
        require_artifact(event, args)
        require(
            event.get("decision_ordinal") == ordinal,
            f"decision order mismatch: {event}",
        )
        require_flow_record(event)

        features = event.get("features")
        require(isinstance(features, dict), f"features missing: {event}")
        require(features.get("count") == FEATURE_COUNT, f"feature count mismatch: {event}")
        require(
            features.get("encoding") == "ascending_feature_index_float64",
            f"feature encoding mismatch: {event}",
        )
        values = features.get("values")
        require(
            isinstance(values, list)
            and len(values) == FEATURE_COUNT
            and all(
                isinstance(value, float) and math.isfinite(value)
                for value in values
            ),
            f"feature vector mismatch: {event}",
        )

        scores = event.get("scores")
        require(isinstance(scores, dict), f"scores missing: {event}")
        require(
            scores.get("probability_dtype") == "float32",
            f"probability dtype mismatch: {event}",
        )
        probabilities = require_probabilities(scores, event)

        raw_index = max(range(len(CLASS_ORDER)), key=probabilities.__getitem__)
        raw = scores.get("raw_argmax")
        require(
            isinstance(raw, dict)
            and raw.get("class_index") == raw_index
            and raw.get("class_name") == CLASS_ORDER[raw_index]
            and math.isclose(
                raw.get("class_confidence", math.inf),
                probabilities[raw_index],
                rel_tol=1e-6,
                abs_tol=1e-6,
            ),
            f"raw argmax mismatch: {event}",
        )

        candidate_index = max(
            range(1, len(CLASS_ORDER)),
            key=probabilities.__getitem__,
        )
        candidate = scores.get("top_attack_candidate")
        require(
            isinstance(candidate, dict)
            and candidate.get("class_index") == candidate_index
            and candidate.get("class_name") == CLASS_ORDER[candidate_index]
            and math.isclose(
                candidate.get("class_confidence", math.inf),
                probabilities[candidate_index],
                rel_tol=1e-6,
                abs_tol=1e-6,
            ),
            f"top attack candidate mismatch: {event}",
        )

        gate = scores.get("attack_gate")
        require(isinstance(gate, dict), f"attack gate missing: {event}")
        expected_score = 1.0 - probabilities[0]
        require(
            gate.get("score_name") == "one_minus_benign_probability"
            and gate.get("comparison") == ">="
            and isinstance(gate.get("threshold"), float)
            and math.isclose(
                gate.get("attack_score", math.inf),
                expected_score,
                rel_tol=1e-6,
                abs_tol=1e-6,
            )
            and gate.get("passed") is (
                gate["attack_score"] >= gate["threshold"]
            ),
            f"attack gate mismatch: {event}",
        )

        expected_index = candidate_index if gate["passed"] else 0
        gated = scores.get("gated_decision")
        require(
            isinstance(gated, dict)
            and gated.get("class_index") == expected_index
            and gated.get("class_name") == CLASS_ORDER[expected_index]
            and math.isclose(
                gated.get("class_confidence", math.inf),
                probabilities[expected_index],
                rel_tol=1e-6,
                abs_tol=1e-6,
            )
            and event.get("decision") == CLASS_ORDER[expected_index],
            f"gated decision mismatch: {event}",
        )
    return decisions


def validate_alerts(
    events: Sequence[dict[str, Any]],
    case_id: str,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    alerts = [
        event
        for event in events
        if event.get("event_type") == "nids_terminal_flow_alert"
    ]
    require(alerts, f"locked scoped fixture emitted no attack alert: {events!r}")
    for ordinal, event in enumerate(alerts, start=1):
        require_run_identity(event, case_id)
        require_artifact(event, args)
        require(event.get("alert_ordinal") == ordinal, f"alert order mismatch: {event}")
        require(event.get("decision") in CLASS_ORDER[1:], f"family is not exact: {event}")
        scores = event.get("scores")
        require(isinstance(scores, dict), f"scores missing: {event}")
        require(scores.get("attack") is True, f"non-attack alert: {event}")
        probabilities = require_probabilities(scores, event)
        index = scores.get("class_index")
        require(
            isinstance(index, int)
            and 0 < index < len(CLASS_ORDER)
            and event["decision"] == CLASS_ORDER[index],
            f"class index mismatch: {event}",
        )
        require(
            isinstance(scores.get("attack_score"), float)
            and scores["attack_score"] >= scores.get("attack_threshold", math.inf),
            f"threshold comparison mismatch: {event}",
        )
        require(
            math.isclose(
                scores.get("class_confidence", math.inf),
                probabilities[index],
                rel_tol=1e-6,
                abs_tol=1e-6,
            ),
            f"class confidence mismatch: {event}",
        )
        require_flow_record(event)
    return alerts


def exercise_scoped_closures(
    args: argparse.Namespace,
    root: Path,
) -> None:
    scan_frames: list[bytes] = []
    for offset in range(20):
        source_port = 42_100 + offset
        target_port = offset + 1
        scan_frames.extend(
            [
                tcp_frame(
                    SOURCE_IP,
                    source_port,
                    TARGET_IP,
                    target_port,
                    0x02,
                    100 + offset * 2,
                    ttl=62,
                    window=29_200,
                    options=b"\x01" * 20,
                ),
                tcp_frame(
                    TARGET_IP,
                    target_port,
                    SOURCE_IP,
                    source_port,
                    0x14,
                    101 + offset * 2,
                    window=0,
                    minimum_frame_size=60,
                ),
            ]
        )
    unsupported_scoped = bytearray(
        tcp_frame(SOURCE_IP, 42_003, TARGET_IP, 53, 0x10, 7)
    )
    unsupported_scoped[23] = 1
    frames = [
        ethernet_frame(0x0806),
        bytes(unsupported_scoped),
        tcp_frame(AMBIENT_IP, 41_000, TARGET_IP, 80, 0x14, 1),
        tcp_frame(SOURCE_IP, 42_001, TARGET_IP, 22, 0x11, 3),
        tcp_frame(TARGET_IP, 22, SOURCE_IP, 42_001, 0x11, 4),
        tcp_frame(SOURCE_IP, 42_001, TARGET_IP, 22, 0x10, 5),
        tcp_frame(SOURCE_IP, 42_002, TARGET_IP, 80, 0x02, 6),
        *scan_frames,
    ]
    capture = root / "scoped.pcap"
    write_pcap(capture, frames)
    result = run_command(
        command(args, capture, "scope", max_packets=len(frames))
    )
    require(
        result.returncode == 0,
        f"scoped run returned {result.returncode}; stdout={result.stdout!r}; "
        f"stderr={result.stderr!r}",
    )
    require(result.stdout.endswith("\n"), "JSONL output has no final LF")
    events = parse_events(result)
    for event in events:
        require_sorted_objects(event)
    ready = one_event(events, "nids_terminal_live_ready")
    summary = one_event(events, "nids_terminal_live_summary")
    require_run_identity(ready, "scope")
    require_run_identity(summary, "scope")
    require(ready.get("class_order") == CLASS_ORDER, f"ready class order mismatch: {ready}")
    require(ready.get("active_flow_limit") == 2_048, f"ready flow bound mismatch: {ready}")
    require(
        ready.get("decision_event_limit")
        == min(len(frames), DECISION_EVENT_HARD_LIMIT)
        and ready.get("decision_event_policy") == "fail_closed_no_sampling"
        and ready.get("output_mode") == "diagnostic",
        f"ready decision bound mismatch: {ready}",
    )
    require_artifact(ready, args)
    require_clean_summary(summary, args)
    require(summary.get("stop_reason") == "packet_limit", f"stop mismatch: {summary}")
    require(summary.get("packets_seen") == len(frames), f"seen mismatch: {summary}")
    require(summary.get("packets_parsed") == len(frames) - 2, f"parsed mismatch: {summary}")
    require(summary.get("ambient_packets") == 3, f"ambient mismatch: {summary}")
    require(summary.get("ambient_parse_rejections") == 2, f"ambient parse mismatch: {summary}")
    require(summary.get("scoped_packets") == 44, f"scope mismatch: {summary}")
    require(summary.get("terminal_flows") == 22, f"terminal flow mismatch: {summary}")
    require(summary.get("inferences") == 22, f"inference mismatch: {summary}")
    require(summary.get("inference_attempts") == 22, f"attempt mismatch: {summary}")
    require(summary.get("skipped_eof_inferences") == 0, f"skipped EOF mismatch: {summary}")
    require(summary.get("eligible_flows") == 21, f"eligible mismatch: {summary}")
    require(summary.get("non_eof_flows") == 21, f"non-EOF mismatch: {summary}")
    require(summary.get("eof_flows") == 1, f"EOF mismatch: {summary}")
    reasons = summary.get("flows", {}).get("close_reason_count", {})
    require(reasons.get("tcp_reset") == 20, f"RST close mismatch: {summary}")
    require(reasons.get("tcp_fin_handshake") == 1, f"FIN close mismatch: {summary}")
    require(reasons.get("end_of_input") == 1, f"EOF close mismatch: {summary}")
    decisions = validate_decisions(events, "scope", args)
    require(len(decisions) == 22, f"decision count mismatch: {summary}")
    require(
        summary.get("decision_events") == len(decisions),
        f"decision summary mismatch: {summary}",
    )
    decision_by_generation = {
        decision["flow"]["generation"]: decision for decision in decisions
    }
    require(
        len(decision_by_generation) == len(decisions),
        f"duplicate decision generation: {decisions}",
    )

    alerts = validate_alerts(events, "scope", args)
    require(summary.get("alerts") == len(alerts), f"alert count mismatch: {summary}")
    require(summary.get("attack_decisions") == len(alerts), f"attack count mismatch: {summary}")
    require(
        summary.get("benign_decisions", 0) + summary.get("attack_decisions", 0)
        == summary.get("inferences"),
        f"decision accounting mismatch: {summary}",
    )
    eligible_alerts = sum(
        alert.get("acceptance_eligible") is True for alert in alerts
    )
    require(eligible_alerts >= 1, f"no acceptance-eligible alert: {summary}")
    require(
        summary.get("eligible_alerts") == eligible_alerts,
        f"eligible alert mismatch: {summary}",
    )
    alert_generations = {alert["flow"]["generation"] for alert in alerts}
    require(
        len(alert_generations) == len(alerts),
        f"duplicate alert generation: {alerts}",
    )
    for alert in alerts:
        generation = alert["flow"]["generation"]
        decision = decision_by_generation.get(generation)
        require(decision is not None, f"alert has no decision: {alert}")
        require(
            events.index(decision) < events.index(alert)
            and decision["scores"]["attack_gate"]["passed"] is True
            and decision["decision"] == alert["decision"]
            and decision["scores"]["class_probabilities"]
            == alert["scores"]["class_probabilities"],
            f"alert does not match its decision: {alert}",
        )
    require(
        all(
            decision["flow"]["generation"] not in alert_generations
            for decision in decisions
            if decision["scores"]["attack_gate"]["passed"] is False
        ),
        f"benign decision emitted an alert: {events}",
    )
    require(
        sum(
            decision["scores"]["attack_gate"]["passed"] is False
            for decision in decisions
        )
        == summary.get("benign_decisions")
        and sum(
            decision["scores"]["attack_gate"]["passed"] is True
            for decision in decisions
        )
        == summary.get("attack_decisions"),
        f"decision partition mismatch: {summary}",
    )
    alerts_by_class = summary.get("alerts_by_class")
    require(
        isinstance(alerts_by_class, dict)
        and set(alerts_by_class) == set(CLASS_ORDER)
        and sum(alerts_by_class.values()) == len(alerts),
        f"class alert accounting mismatch: {summary}",
    )
    for family in CLASS_ORDER:
        require(
            alerts_by_class[family]
            == sum(alert.get("decision") == family for alert in alerts),
            f"{family} alert count mismatch: {summary}",
        )

    wrong = run_command(
        command(
            args,
            capture,
            "wrong",
            target_ip="10.77.1.100",
            max_packets=len(frames),
        )
    )
    require(
        wrong.returncode == 0,
        f"wrong-scope run failed: stdout={wrong.stdout!r}; stderr={wrong.stderr!r}",
    )
    wrong_summary = one_event(
        parse_events(wrong),
        "nids_terminal_live_summary",
    )
    require_clean_summary(wrong_summary, args)
    require(wrong_summary.get("ambient_packets") == len(frames), f"wrong ambient count: {wrong_summary}")
    require(
        wrong_summary.get("ambient_parse_rejections") == 2,
        f"wrong ambient parse count: {wrong_summary}",
    )
    require(wrong_summary.get("scoped_packets") == 0, f"wrong scope count: {wrong_summary}")
    require(wrong_summary.get("terminal_flows") == 0, f"wrong flow count: {wrong_summary}")
    require(wrong_summary.get("inferences") == 0, f"wrong inference count: {wrong_summary}")


def exercise_target_scope(
    args: argparse.Namespace,
    root: Path,
) -> None:
    frames = [
        tcp_frame(SOURCE_IP, 44_001, TARGET_IP, 21, 0x02, 1),
        tcp_frame(TARGET_IP, 21, SOURCE_IP, 44_001, 0x14, 2),
        tcp_frame(AMBIENT_IP, 44_002, TARGET_IP, 80, 0x02, 3),
        tcp_frame(TARGET_IP, 80, AMBIENT_IP, 44_002, 0x14, 4),
        tcp_frame(SOURCE_IP, 44_003, "10.77.1.55", 443, 0x14, 5),
    ]
    capture = root / "target-scope.pcap"
    write_pcap(capture, frames)
    result = run_command(
        command(
            args,
            capture,
            "target",
            any_source=True,
            max_packets=len(frames),
        )
    )
    require(
        result.returncode == 0,
        f"target scope returned {result.returncode}; "
        f"stdout={result.stdout!r}; stderr={result.stderr!r}",
    )
    events = parse_events(result)
    ready = one_event(events, "nids_terminal_live_ready")
    summary = one_event(events, "nids_terminal_live_summary")
    require_run_identity(ready, "target", any_source=True)
    require_run_identity(summary, "target", any_source=True)
    require_clean_summary(summary, args)
    require(summary.get("stop_reason") == "packet_limit", f"stop mismatch: {summary}")
    require(summary.get("packets_seen") == 5, f"seen mismatch: {summary}")
    require(summary.get("ambient_packets") == 1, f"ambient mismatch: {summary}")
    require(summary.get("scoped_packets") == 4, f"scope mismatch: {summary}")
    require(summary.get("terminal_flows") == 2, f"flow mismatch: {summary}")
    require(summary.get("inferences") == 2, f"inference mismatch: {summary}")
    decisions = [
        event
        for event in events
        if event.get("event_type") == "nids_terminal_flow_decision"
    ]
    require(len(decisions) == 2, f"decision count mismatch: {events}")
    peers = set()
    for decision in decisions:
        require_run_identity(decision, "target", any_source=True)
        flow = decision.get("flow", {})
        source = flow.get("source", {}).get("ip")
        destination = flow.get("destination", {}).get("ip")
        require(destination == TARGET_IP, f"target was not retained: {decision}")
        peers.add(source)
    require(
        peers == {SOURCE_IP, AMBIENT_IP},
        f"target scope did not accept both peers: {decisions}",
    )


def exercise_alerts_only_beyond_diagnostic_limit(
    args: argparse.Namespace,
    root: Path,
) -> None:
    frames = [
        tcp_frame(
            SOURCE_IP,
            10_000 + offset,
            TARGET_IP,
            65_000,
            0x14,
            offset + 1,
        )
        for offset in range(DECISION_EVENT_HARD_LIMIT + 1)
    ]
    for offset in range(20):
        source_port = 42_100 + offset
        target_port = offset + 1
        frames.extend(
            [
                tcp_frame(
                    SOURCE_IP,
                    source_port,
                    TARGET_IP,
                    target_port,
                    0x02,
                    10_000 + offset * 2,
                    ttl=62,
                    window=29_200,
                    options=b"\x01" * 20,
                ),
                tcp_frame(
                    TARGET_IP,
                    target_port,
                    SOURCE_IP,
                    source_port,
                    0x14,
                    10_001 + offset * 2,
                    window=0,
                    minimum_frame_size=60,
                ),
            ]
        )

    capture = root / "alerts-only.pcap"
    write_pcap(capture, frames)
    result = run_command(
        command(
            args,
            capture,
            "alertsonly",
            output_mode="alerts-only",
            max_packets=len(frames),
            max_runtime_ms=100_000,
            arm_timeout_ms=100_000,
            idle_timeout_ms=100_000,
        ),
        timeout=110.0,
    )
    require(
        result.returncode == 0,
        f"alerts-only run returned {result.returncode}; "
        f"stdout={result.stdout!r}; stderr={result.stderr!r}",
    )
    events = parse_events(result)
    ready = one_event(events, "nids_terminal_live_ready")
    summary = one_event(events, "nids_terminal_live_summary")
    require_run_identity(ready, "alertsonly")
    require_run_identity(summary, "alertsonly")
    require(
        ready.get("output_mode") == "alerts_only"
        and ready.get("decision_event_policy") == "disabled_alerts_only"
        and ready.get("decision_event_limit") == 0,
        f"alerts-only READY mismatch: {ready}",
    )
    require_clean_summary(summary, args, output_mode="alerts_only")
    require(
        summary.get("inferences", 0) > DECISION_EVENT_HARD_LIMIT,
        f"alerts-only run did not cross the diagnostic cap: {summary}",
    )
    require(
        not [
            event
            for event in events
            if event.get("event_type") == "nids_terminal_flow_decision"
        ],
        f"alerts-only run emitted decision diagnostics: {events!r}",
    )
    alerts = validate_alerts(events, "alertsonly", args)
    require(
        summary.get("alerts") == len(alerts),
        f"alerts-only alert count mismatch: {summary}",
    )
    require(
        any(
            alert.get("flow", {}).get("generation", 0)
            > DECISION_EVENT_HARD_LIMIT + 1
            for alert in alerts
        ),
        "no alert was preserved after the diagnostic cap boundary",
    )


def exercise_signal_only_lifecycle(
    args: argparse.Namespace,
    root: Path,
) -> None:
    frames: list[bytes] = []
    for offset in range(20):
        source_port = 46_000 + offset
        target_port = offset + 1
        frames.extend(
            [
                tcp_frame(
                    SOURCE_IP,
                    source_port,
                    TARGET_IP,
                    target_port,
                    0x02,
                    20_000 + offset * 2,
                    ttl=62,
                    window=29_200,
                    options=b"\x01" * 20,
                ),
                tcp_frame(
                    TARGET_IP,
                    target_port,
                    SOURCE_IP,
                    source_port,
                    0x14,
                    20_001 + offset * 2,
                    window=0,
                    minimum_frame_size=60,
                ),
            ]
        )
    frames.append(
        tcp_frame(SOURCE_IP, 47_000, TARGET_IP, 443, 0x02, 30_000)
    )

    capture = root / "signal-only.pcap"
    alerts_path = root / "signal-only-alerts.jsonl"
    write_pcap(capture, frames)
    alerts_path.touch()
    process = subprocess.Popen(
        command(
            args,
            capture,
            "signalonly",
            output_mode="alerts-only",
            lifecycle_mode="signal-only",
            alerts_file=alerts_path,
            max_packets=None,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout = ""
    stderr = ""
    try:
        alert_deadline = time.monotonic() + 10.0
        while alerts_path.stat().st_size == 0:
            require(
                process.poll() is None,
                "signal-only runtime exited before writing a live alert",
            )
            require(
                time.monotonic() < alert_deadline,
                "signal-only runtime did not write a live alert",
            )
            time.sleep(0.02)
        time.sleep(1.2)
        require(
            process.poll() is None,
            "signal-only runtime stopped without an operator signal",
        )

        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10.0)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    require(
        process.returncode == 0,
        f"signal-only run failed: "
        f"stdout={stdout!r}; stderr={stderr!r}",
    )

    events = [
        json.loads(line)
        for line in stdout.splitlines()
        if line
    ]
    ready = one_event(events, "nids_terminal_live_ready")
    require(
        ready.get("bounded") is False
        and ready.get("lifecycle_mode") == "signal_only"
        and ready.get("output_mode") == "alerts_only"
        and ready.get("max_packets") == 0
        and ready.get("max_runtime_ms") == 0
        and ready.get("arm_timeout_ms") == 0
        and ready.get("idle_timeout_ms") == 0
        and ready.get("shutdown_grace_ms") == 5_000,
        f"signal-only READY mismatch: {ready}",
    )
    summary = one_event(events, "nids_terminal_live_summary")
    require_clean_summary(
        summary,
        args,
        output_mode="alerts_only",
        lifecycle_mode="signal_only",
        shutdown_grace_ms=5_000,
    )
    require(
        summary.get("stop_reason") == "signal"
        and summary.get("packets_seen") == len(frames)
        and summary.get("terminal_flows") == 21
        and summary.get("non_eof_flows") == 20
        and summary.get("eof_flows") == 1
        and summary.get("inferences") == 21
        and summary.get("skipped_eof_inferences") == 0,
        f"signal-only shutdown accounting mismatch: {summary}",
    )
    stdout_alerts = validate_alerts(events, "signalonly", args)
    alert_events = [
        json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    file_alerts = validate_alerts(alert_events, "signalonly", args)
    require(
        file_alerts == stdout_alerts
        and summary.get("alerts") == len(file_alerts),
        "live alert file does not match the sensor alert stream",
    )


def exercise_bounds_and_failures(
    args: argparse.Namespace,
    root: Path,
) -> None:
    ambient = root / "ambient.pcap"
    write_pcap(
        ambient,
        [tcp_frame(AMBIENT_IP, 43_000, TARGET_IP, 443, 0x10, 7)],
    )
    bounded = run_command(
        command(
            args,
            ambient,
            "arm",
            max_packets=100,
            max_runtime_ms=500,
            arm_timeout_ms=80,
            idle_timeout_ms=80,
        )
    )
    require(
        bounded.returncode == 0,
        f"bounded run failed: stdout={bounded.stdout!r}; stderr={bounded.stderr!r}",
    )
    summary = one_event(
        parse_events(bounded),
        "nids_terminal_live_summary",
    )
    require_clean_summary(summary, args)
    require(summary.get("stop_reason") == "arm_timeout", f"arm timeout mismatch: {summary}")
    require(summary.get("ambient_packets") == 1, f"arm ambient mismatch: {summary}")
    require(summary.get("scoped_packets") == 0, f"arm scope mismatch: {summary}")
    require(summary.get("duration_ms", 0) < 500, f"hard bound exceeded: {summary}")

    idle_capture = root / "idle.pcap"
    write_pcap(
        idle_capture,
        [tcp_frame(SOURCE_IP, 43_001, TARGET_IP, 443, 0x02, 8)],
    )
    idle = run_command(
        command(
            args,
            idle_capture,
            "idle",
            max_packets=100,
            max_runtime_ms=500,
            arm_timeout_ms=500,
            idle_timeout_ms=80,
        )
    )
    require(
        idle.returncode == 0,
        f"idle run failed: stdout={idle.stdout!r}; stderr={idle.stderr!r}",
    )
    idle_events = parse_events(idle)
    idle_summary = one_event(idle_events, "nids_terminal_live_summary")
    require_clean_summary(idle_summary, args)
    require(
        idle_summary.get("stop_reason") == "scoped_idle_timeout",
        f"scoped idle mismatch: {idle_summary}",
    )
    require(idle_summary.get("scoped_packets") == 1, f"idle scope mismatch: {idle_summary}")
    require(idle_summary.get("terminal_flows") == 1, f"idle flow mismatch: {idle_summary}")
    require(idle_summary.get("inferences") == 1, f"idle inference mismatch: {idle_summary}")
    require(idle_summary.get("eof_flows") == 1, f"idle EOF mismatch: {idle_summary}")
    require(
        len(validate_decisions(idle_events, "idle", args)) == 1,
        f"idle decision mismatch: {idle_events}",
    )

    deadline_capture = root / "deadline.pcap"
    write_pcap(
        deadline_capture,
        [tcp_frame(SOURCE_IP, 43_002, TARGET_IP, 8443, 0x02, 9)],
    )
    deadline = run_command(
        command(
            args,
            deadline_capture,
            "deadline",
            max_packets=100,
            max_runtime_ms=80,
            arm_timeout_ms=80,
            idle_timeout_ms=80,
        )
    )
    require(
        deadline.returncode != 0,
        f"deadline run unexpectedly passed: stdout={deadline.stdout!r}",
    )
    deadline_events = parse_events(deadline)
    deadline_summary = one_event(
        deadline_events,
        "nids_terminal_live_summary",
    )
    require(
        deadline_summary.get("status") == "failed"
        and deadline_summary.get("stop_reason") == "max_runtime",
        f"deadline status mismatch: {deadline_summary}",
    )
    require(
        deadline_summary.get("terminal_flows") == 1
        and deadline_summary.get("inferences") == 0
        and deadline_summary.get("skipped_eof_inferences") == 1
        and deadline_summary.get("shutdown_deadline_overruns") == 0,
        f"deadline inference bound mismatch: {deadline_summary}",
    )
    require(
        deadline_summary.get("shutdown_complete") is False,
        f"deadline shutdown was reported complete: {deadline_summary}",
    )
    require(
        not validate_decisions(deadline_events, "deadline", args),
        f"skipped EOF inference emitted a decision: {deadline_events}",
    )

    malformed_capture = root / "malformed.pcap"
    write_pcap(malformed_capture, [b"\x00\x11\x22"])
    malformed = run_command(
        command(args, malformed_capture, "malformed", max_packets=1)
    )
    require(malformed.returncode != 0, "malformed packet unexpectedly passed")
    malformed_summary = one_event(
        parse_events(malformed),
        "nids_terminal_live_summary",
    )
    require(
        malformed_summary.get("status") == "failed"
        and malformed_summary.get("stop_reason") == "pipeline_failure",
        f"malformed status mismatch: {malformed_summary}",
    )
    require(
        malformed_summary.get("errors", {}).get("parser") == 1
        and malformed_summary.get("terminal_flows") == 0
        and malformed_summary.get("inferences") == 0,
        f"malformed accounting mismatch: {malformed_summary}",
    )

    mismatch = run_command(
        command(
            args,
            ambient,
            "hash",
            manifest_sha256="0" * 64,
            max_packets=1,
        )
    )
    require(mismatch.returncode == 2, f"manifest mismatch returned {mismatch.returncode}")
    require(
        not parse_events(mismatch),
        f"manifest mismatch emitted READY/output: {mismatch.stdout!r}",
    )

    same_endpoint = run_command(
        command(
            args,
            ambient,
            "same",
            target_ip=SOURCE_IP,
            max_packets=1,
        )
    )
    require(same_endpoint.returncode == 2, f"same endpoint returned {same_endpoint.returncode}")
    require(
        not parse_events(same_endpoint),
        f"invalid CLI emitted READY/output: {same_endpoint.stdout!r}",
    )

    invalid_output_mode = run_command(
        command(
            args,
            ambient,
            "badmode",
            output_mode="all-events",
            max_packets=1,
        )
    )
    require(
        invalid_output_mode.returncode == 2
        and not parse_events(invalid_output_mode),
        f"invalid output mode was accepted: {invalid_output_mode.stdout!r}",
    )

    duplicate_output_mode = run_command(
        [
            *command(
                args,
                ambient,
                "dupmode",
                output_mode="diagnostic",
                max_packets=1,
            ),
            "--output-mode",
            "alerts-only",
        ]
    )
    require(
        duplicate_output_mode.returncode == 2
        and not parse_events(duplicate_output_mode),
        f"duplicate output mode was accepted: {duplicate_output_mode.stdout!r}",
    )

    invalid_signal_alerts = root / "invalid-signal-alerts.jsonl"
    invalid_signal_alerts.touch()
    signal_with_bound = run_command(
        [
            *command(
                args,
                ambient,
                "signalbound",
                output_mode="alerts-only",
                lifecycle_mode="signal-only",
                alerts_file=invalid_signal_alerts,
                max_packets=None,
            ),
            "--max-packets",
            "1",
        ]
    )
    require(
        signal_with_bound.returncode == 2
        and not parse_events(signal_with_bound),
        "signal-only lifecycle accepted a bounded stop flag",
    )

    missing_bound_arguments = command(
        args,
        ambient,
        "missingbound",
        max_packets=1,
    )
    idle_index = missing_bound_arguments.index("--idle-timeout-ms")
    del missing_bound_arguments[idle_index : idle_index + 2]
    missing_bound = run_command(missing_bound_arguments)
    require(
        missing_bound.returncode == 2 and not parse_events(missing_bound),
        "bounded lifecycle accepted a missing stop bound",
    )

    full = Path("/dev/full")
    if full.exists():
        with full.open("w", encoding="utf-8") as output:
            failed_output = subprocess.run(
                command(args, ambient, "full", max_packets=1),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=20.0,
            )
        require(
            failed_output.returncode != 0,
            "runtime accepted an unwritable stdout sink",
        )


def exercise_one_command_allocator(root: Path) -> None:
    launcher_path = (
        PROJECT_ROOT / "scripts" / "run_t91_live_engine_ubuntu.sh"
    )
    launcher = launcher_path.read_text(encoding="utf-8")
    require("flock -n 9" in launcher, "launcher has no singleton lock")
    require(
        "trap 'handle_signal 129' HUP" in launcher,
        "launcher does not stop the sensor on terminal close",
    )
    require(
        '"scope_mode": "target_ip"' in launcher,
        "launcher does not use target scope",
    )
    require(
        '"output": {"mode": "alerts_only"}' in launcher,
        "launcher does not select alerts-only output",
    )
    require(
        '"mode": "signal_only"' in launcher
        and '"bounded": False' in launcher
        and "heartbeat_loop" in launcher,
        "launcher does not lock the persistent lifecycle and lease",
    )
    require(
        "write_heartbeat" in launcher
        and 'printf \'%s\\n\' "$(date +%s)"' in launcher
        and 'mv -f -- "$HEARTBEAT_STAGING" "$HEARTBEAT"' in launcher,
        "launcher heartbeat is not content-based and atomic",
    )
    require(
        "sleep 0.2 || true" in launcher,
        "launcher can exit before collection when signal interrupts wait",
    )
    require(
        'event.get("event_type") == "nids_terminal_flow_alert"' in launcher,
        "launcher does not extract exact alert events",
    )
    blocks = re.findall(
        r"<<'PY'\n(.*?)\nPY(?:\n|$)",
        launcher,
        flags=re.DOTALL,
    )
    allocators = [
        block
        for block in blocks
        if '"kind": "terminal_live_run_contract"' in block
    ]
    require(len(allocators) == 1, "launcher allocator block is ambiguous")
    collectors = [
        block
        for block in blocks
        if '"integrity_verified"' in block
        and "nids_terminal_flow_alert" in block
    ]
    require(len(collectors) == 1, "launcher alert collector is ambiguous")
    sensor_wrapper = (
        PROJECT_ROOT / "scripts" / "ubuntu_t91_live_sensor.sh"
    ).read_text(encoding="utf-8")
    require(
        '"$PROJECT_ROOT/$DPDK_CONFIG"' in sensor_wrapper
        and "load_and_validate_config(config_path)" in sensor_wrapper,
        "sensor does not apply the contract-selected DPDK config",
    )
    require(
        'output_mode not in {"diagnostic", "alerts_only"}' in sensor_wrapper
        and '--output-mode "$OUTPUT_MODE_CLI"' in sensor_wrapper,
        "sensor does not validate and pass the output mode",
    )
    require(
        "setsid timeout --signal=TERM" in sensor_wrapper
        and "stop_sensor_group" in sensor_wrapper
        and "sensor group remains alive; rollback withheld" in sensor_wrapper
        and "heartbeat_is_fresh" in sensor_wrapper
        and "verified_sensor_group" in sensor_wrapper
        and 'flock -w "$RECOVERY_WAIT_SECONDS" 8' in sensor_wrapper,
        "sensor does not enforce process-group stop and launcher lease",
    )

    run_root = root / "allocator"
    observed = []
    for expected_id in (1, 2):
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-",
                str(PROJECT_ROOT),
                str(PROJECT_ROOT / "config" / "t91-live-campaign.json"),
                str(run_root),
            ],
            input=allocators[0] + "\n",
            text=True,
            capture_output=True,
            cwd=PROJECT_ROOT,
            check=False,
            timeout=10.0,
        )
        require(
            completed.returncode == 0,
            f"launcher allocator failed: {completed.stderr}",
        )
        contract_path = Path(completed.stdout.strip())
        require(
            contract_path == run_root / f"run-{expected_id:06d}" / "contract.json",
            f"run ID mismatch: {contract_path}",
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        require(
            contract["attempt_id"] == f"t91-live-engine-{expected_id:06d}",
            f"attempt ID mismatch: {contract}",
        )
        require(
            contract["topology"]["scope_mode"] == "target_ip"
            and "source_ip" not in contract["topology"],
            f"target scope contract mismatch: {contract}",
        )
        require(
            contract.get("output") == {"mode": "alerts_only"},
            f"output mode contract mismatch: {contract}",
        )
        require(
            contract.get("bounds") == {"ready_timeout_seconds": 30}
            and contract.get("lifecycle")
            == {
                "mode": "signal_only",
                "lease_timeout_seconds": 10,
                "shutdown_grace_ms": 5_000,
            }
            and contract.get("tool")
            == {"name": "external", "bounded": False},
            f"operator lifecycle mismatch: {contract}",
        )
        alerts = contract_path.parent / "alerts.jsonl"
        require(alerts.is_file() and alerts.stat().st_size == 0, "alert log missing")
        observed.append(contract_path.parent.name)
    require(
        observed == ["run-000001", "run-000002"],
        f"run IDs are not sequential: {observed}",
    )
    require(
        (run_root / ".next-id").read_text(encoding="ascii").strip() == "3",
        "next run ID was not persisted",
    )

    ubuntu = contract_path.parent / "ubuntu"
    ubuntu.mkdir()
    sensor_log = ubuntu / "sensor.jsonl"
    contract_sha256 = hashlib.sha256(contract_path.read_bytes()).hexdigest()
    alert = {
        "event_type": "nids_terminal_flow_alert",
        "attempt_id": contract["attempt_id"],
        "run_token": contract["run_token"],
        "run_contract_sha256": contract_sha256,
        "alert_ordinal": 1,
    }
    alert_line = json.dumps(
        alert,
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    sensor_log.write_text(
        alert_line,
        encoding="utf-8",
        newline="\n",
    )
    alerts_path = contract_path.parent / "alerts.jsonl"
    alerts_path.write_text(alert_line, encoding="utf-8", newline="\n")
    identity = {
        "attempt_id": contract["attempt_id"],
        "run_token": contract["run_token"],
        "run_contract_sha256": contract_sha256,
    }
    receipt = {
        **identity,
        "status": "passed",
        "sensor_return_code": 0,
        "termination_cause": "operator_request",
        "sensor_log": {
            "path": str(sensor_log.resolve()),
            "sha256": hashlib.sha256(sensor_log.read_bytes()).hexdigest(),
        },
        "alert_log": {
            "path": str(alerts_path.resolve()),
            "sha256": hashlib.sha256(alerts_path.read_bytes()).hexdigest(),
        },
    }
    summary = {
        **identity,
        "status": "passed",
        "stop_reason": "signal",
        "bounded": False,
        "lifecycle_mode": "signal_only",
        "shutdown_grace_ms": 5_000,
        "shutdown_complete": True,
        "output_mode": "alerts_only",
        "decision_event_policy": "disabled_alerts_only",
        "decision_diagnostics_complete": False,
        "decision_diagnostics_suppressed": 1,
        "decision_event_limit": 0,
        "decision_event_limit_rejections": 0,
        "decision_events": 0,
        "inferences": 1,
        "benign_decisions": 0,
        "attack_decisions": 1,
        "alerts": 1,
        "alerts_complete": True,
    }
    rollback = {"status": "passed"}
    receipt_path = ubuntu / "sensor.json"
    summary_path = ubuntu / "summary.json"
    rollback_path = ubuntu / "rollback.json"
    stop_request_path = ubuntu / "stop.requested"
    stop_request_path.touch()
    for path, document in (
        (receipt_path, receipt),
        (summary_path, summary),
        (rollback_path, rollback),
    ):
        path.write_text(
            json.dumps(document, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    collector_arguments = [
        sys.executable,
        "-B",
        "-",
        str(sensor_log),
        str(alerts_path),
        str(receipt_path),
        str(summary_path),
        str(rollback_path),
        str(contract_path),
    ]
    collected = subprocess.run(
        collector_arguments,
        input=collectors[0] + "\n",
        text=True,
        capture_output=True,
        cwd=PROJECT_ROOT,
        check=False,
        timeout=10.0,
    )
    require(
        collected.returncode == 0,
        f"alert collector failed: {collected.stderr}",
    )
    collection = json.loads(collected.stdout)
    require(
        collection == {
            "alert_count": 1,
            "failure_reasons": [],
            "integrity_verified": True,
            "status": "passed",
        },
        f"alert collection result mismatch: {collection}",
    )
    accepted_alerts = alerts_path.read_bytes()

    summary_path.write_text(
        json.dumps(
            {**summary, "output_mode": "diagnostic"},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    wrong_mode = subprocess.run(
        collector_arguments,
        input=collectors[0] + "\n",
        text=True,
        capture_output=True,
        cwd=PROJECT_ROOT,
        check=False,
        timeout=10.0,
    )
    require(wrong_mode.returncode != 0, "collector accepted diagnostic output")
    wrong_mode_result = json.loads(wrong_mode.stdout)
    require(
        wrong_mode_result.get("integrity_verified") is False
        and "runtime_accounting_failed"
            in wrong_mode_result.get("failure_reasons", []),
        f"collector did not report output-mode drift: {wrong_mode_result}",
    )
    require(
        alerts_path.read_bytes() == accepted_alerts,
        "collector replaced alerts after output-mode drift",
    )
    summary_path.write_text(
        json.dumps(summary, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    stop_request_path.unlink()
    wrong_termination = subprocess.run(
        collector_arguments,
        input=collectors[0] + "\n",
        text=True,
        capture_output=True,
        cwd=PROJECT_ROOT,
        check=False,
        timeout=10.0,
    )
    require(
        wrong_termination.returncode != 0,
        "collector accepted missing operator-stop evidence",
    )
    wrong_termination_result = json.loads(wrong_termination.stdout)
    require(
        "termination_evidence_failed"
        in wrong_termination_result.get("failure_reasons", []),
        f"collector did not report termination drift: "
        f"{wrong_termination_result}",
    )
    stop_request_path.touch()

    sensor_log.write_text(
        json.dumps({"event_type": "tampered"}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    rejected = subprocess.run(
        collector_arguments,
        input=collectors[0] + "\n",
        text=True,
        capture_output=True,
        cwd=PROJECT_ROOT,
        check=False,
        timeout=10.0,
    )
    require(rejected.returncode != 0, "collector accepted a log hash mismatch")
    require(
        alerts_path.read_bytes() == accepted_alerts,
        "collector replaced alerts after integrity failure",
    )


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        require(args.binary.is_file(), f"binary missing: {args.binary}")
        require(args.bundle.is_dir(), f"bundle missing: {args.bundle}")
        require(
            len(args.manifest_sha256) == 64,
            "manifest SHA-256 must contain 64 characters",
        )
        with tempfile.TemporaryDirectory(prefix="nids-t91-live-") as temporary:
            root = Path(temporary)
            exercise_one_command_allocator(root)
            exercise_scoped_closures(args, root)
            exercise_target_scope(args, root)
            exercise_alerts_only_beyond_diagnostic_limit(args, root)
            exercise_signal_only_lifecycle(args, root)
            exercise_bounds_and_failures(args, root)
        print("T9.1 terminal live runtime: passed")
        return 0
    except (
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"T9.1 terminal live runtime: failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
