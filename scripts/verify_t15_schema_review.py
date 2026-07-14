#!/usr/bin/env python3
"""Validate the T1.5 schema review and hand-calculated reference vectors."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


TASK = "T1.5"
SCHEMA_VERSION = "1.0.0"
KIND = "schema_review_acceptance"
FLOW_SCHEMA = "config/flow-feature-schema-v1.json"
PACKET_SCHEMA = "config/packet-sequence-schema-v1.json"
REFERENCE_DOC = "docs/feature-schema-v1.vi.md"
FIXTURE = "tests/fixtures/feature-vector-v1.json"
FLOW_SCHEMA_SHA256 = "69241cb5069ce68f941836332cfc556d15fba00253288eb6f985155bac1bc6eb"
PACKET_SCHEMA_SHA256 = "50235d3c398ff5925ff953f17dee4e433f1db15e58a8fc79f76438b602daa6d6"
SOURCE_FILES = (
    FLOW_SCHEMA,
    PACKET_SCHEMA,
    REFERENCE_DOC,
    FIXTURE,
    "scripts/verify_t15_schema_review.py",
    "tests/test_schema_review.py",
)
EXPECTED_TRACES = {
    "tcp_bidirectional_9": ("TCP", (3, 5, 7, 9)),
    "udp_bidirectional_3": ("UDP", (3,)),
}
TCP_FLAGS = frozenset({"SYN", "ACK", "FIN", "RST", "PSH"})
ABS_TOLERANCE = 1e-12
REL_TOLERANCE = 1e-12


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def population_summary(values: Sequence[int | float]) -> tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    count = 0
    mean = 0.0
    m2 = 0.0
    minimum = math.inf
    maximum = -math.inf
    for value in values:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("statistics input must be finite")
        count += 1
        minimum = min(minimum, number)
        maximum = max(maximum, number)
        delta = number - mean
        mean += delta / count
        m2 += delta * (number - mean)
    variance = m2 / count
    if variance < 0.0 or not math.isfinite(variance):
        raise ValueError("statistics output must be finite and nonnegative")
    return minimum, maximum, mean, math.sqrt(variance)


def safe_divide(numerator: int | float, denominator: int | float) -> float:
    if not math.isfinite(numerator) or not math.isfinite(denominator):
        raise ValueError("division operands must be finite")
    result = 0.0 if denominator == 0 else numerator / denominator
    if not math.isfinite(result):
        raise ValueError("division result must be finite")
    return result


def signed_deltas(values: Sequence[int]) -> list[int]:
    return [current - previous for previous, current in zip(values, values[1:])]


def compute_feature_vector(packets: Sequence[Mapping[str, Any]], transport: str) -> list[int | float]:
    timestamps = [packet["timestamp_ns"] for packet in packets]
    forward = [packet for packet in packets if packet["direction"] == "forward"]
    reverse = [packet for packet in packets if packet["direction"] == "reverse"]
    wire_lengths = [packet["wire_length"] for packet in packets]
    payload_lengths = [packet["payload_length"] for packet in packets]
    header_lengths = [packet["header_length"] for packet in packets]
    ttl_values = [packet["ttl"] for packet in packets]
    flow_iat = signed_deltas(timestamps)
    forward_iat = signed_deltas([packet["timestamp_ns"] for packet in forward])
    reverse_iat = signed_deltas([packet["timestamp_ns"] for packet in reverse])

    wire = population_summary(wire_lengths)
    forward_wire = population_summary([packet["wire_length"] for packet in forward])
    reverse_wire = population_summary([packet["wire_length"] for packet in reverse])
    flow_iat_stats = population_summary(flow_iat)
    forward_iat_stats = population_summary(forward_iat)
    reverse_iat_stats = population_summary(reverse_iat)
    ttl = population_summary(ttl_values)
    payload = population_summary(payload_lengths)
    header = population_summary(header_lengths)

    age_us = (max(timestamps) - timestamps[0]) / 1000.0
    wire_byte_count = sum(wire_lengths)
    forward_wire_byte_count = sum(packet["wire_length"] for packet in forward)
    reverse_wire_byte_count = sum(packet["wire_length"] for packet in reverse)
    direction_changes = sum(
        current["direction"] != previous["direction"]
        for previous, current in zip(packets, packets[1:])
    )

    flag_counts = {flag: 0 for flag in TCP_FLAGS}
    windows: list[int] = []
    if transport == "TCP":
        for packet in packets:
            windows.append(packet["tcp_window"])
            for flag in packet["tcp_flags"]:
                flag_counts[flag] += 1
    window = population_summary(windows)
    initial_forward_window = forward[0]["tcp_window"] if transport == "TCP" and forward else 0
    initial_reverse_window = reverse[0]["tcp_window"] if transport == "TCP" and reverse else 0

    vector: list[int | float] = [
        age_us,
        len(packets),
        len(forward),
        len(reverse),
        wire_byte_count,
        forward_wire_byte_count,
        reverse_wire_byte_count,
        wire[0],
        wire[1],
        wire[2],
        wire[3],
        forward_wire[2],
        forward_wire[3],
        reverse_wire[2],
        reverse_wire[3],
        flow_iat_stats[0] / 1000.0,
        flow_iat_stats[1] / 1000.0,
        flow_iat_stats[2] / 1000.0,
        flow_iat_stats[3] / 1000.0,
        forward_iat_stats[2] / 1000.0,
        forward_iat_stats[3] / 1000.0,
        reverse_iat_stats[2] / 1000.0,
        reverse_iat_stats[3] / 1000.0,
        0.0 if age_us <= 0.0 else len(packets) * 1_000_000.0 / age_us,
        0.0 if age_us <= 0.0 else wire_byte_count * 1_000_000.0 / age_us,
        safe_divide(len(forward), len(reverse)),
        safe_divide(forward_wire_byte_count, reverse_wire_byte_count),
        direction_changes,
        flag_counts["SYN"],
        flag_counts["ACK"],
        flag_counts["FIN"],
        flag_counts["RST"],
        flag_counts["PSH"],
        safe_divide(flag_counts["SYN"], flag_counts["ACK"]),
        initial_forward_window,
        initial_reverse_window,
        window[2],
        window[3],
        ttl[0],
        ttl[1],
        ttl[2],
        ttl[3],
        sum(length > 0 for length in payload_lengths),
        sum(packet["payload_length"] > 0 for packet in forward),
        sum(packet["payload_length"] > 0 for packet in reverse),
        sum(payload_lengths),
        sum(packet["payload_length"] for packet in forward),
        sum(packet["payload_length"] for packet in reverse),
        payload[0],
        payload[1],
        payload[2],
        payload[3],
        header[2],
        header[3],
    ]
    if len(vector) != 54 or any(not math.isfinite(value) for value in vector):
        raise ValueError("reference vector must contain 54 finite values")
    return vector


def validate_packet(packet: Any, transport: str, location: str) -> list[str]:
    if not isinstance(packet, Mapping):
        return [f"{location} must be an object"]
    errors: list[str] = []
    timestamp = packet.get("timestamp_ns")
    if not is_integer(timestamp) or not -(2**63) <= timestamp < 2**63:
        errors.append(f"{location}.timestamp_ns must be int64")
    if packet.get("direction") not in {"forward", "reverse"}:
        errors.append(f"{location}.direction must be forward or reverse")
    for field, maximum in (("wire_length", 2**32 - 1), ("payload_length", 2**32 - 1), ("header_length", 2**32 - 1), ("ttl", 255)):
        value = packet.get(field)
        if not is_integer(value) or not 0 <= value <= maximum:
            errors.append(f"{location}.{field} is outside its unsigned range")
    wire_length = packet.get("wire_length")
    payload_length = packet.get("payload_length")
    header_length = packet.get("header_length")
    if all(is_integer(value) for value in (wire_length, payload_length, header_length)) and header_length + payload_length > wire_length:
        errors.append(f"{location} header and payload exceed wire length")
    if transport == "TCP":
        window = packet.get("tcp_window")
        flags = packet.get("tcp_flags")
        if not is_integer(window) or not 0 <= window <= 65535:
            errors.append(f"{location}.tcp_window must be uint16")
        if not isinstance(flags, list) or any(flag not in TCP_FLAGS for flag in flags) or len(flags) != len(set(flags)):
            errors.append(f"{location}.tcp_flags must be a unique supported flag list")
    elif "tcp_window" in packet or "tcp_flags" in packet:
        errors.append(f"{location} UDP packet must not contain TCP fields")
    return errors


def validate_fixture(document: Any, flow_schema: Mapping[str, Any]) -> list[str]:
    if not isinstance(document, Mapping):
        return ["fixture root must be an object"]
    errors: list[str] = []
    features = flow_schema.get("features")
    if not isinstance(features, list) or len(features) != 54:
        return ["flow schema must expose 54 features"]
    feature_names = [feature.get("name") for feature in features]
    logical_types = [feature.get("logical_type") for feature in features]

    if document.get("fixture_id") != "nids.feature_vectors.v1" or document.get("fixture_version") != SCHEMA_VERSION or document.get("task") != TASK:
        errors.append("fixture identity must match T1.5 v1")
    references = document.get("schema_references")
    if not isinstance(references, Mapping) or references.get("flow_feature_sha256") != FLOW_SCHEMA_SHA256 or references.get("packet_sequence_sha256") != PACKET_SCHEMA_SHA256:
        errors.append("fixture must lock both accepted T1.3 schema hashes")
    decision = document.get("review_decision")
    if not isinstance(decision, Mapping) or not (
        decision.get("mandatory_feature_count") == 54
        and decision.get("mandatory_feature_names") == feature_names
        and decision.get("retransmission_and_out_of_order") == "deferred"
        and decision.get("port_category") == "ablation_only"
    ):
        errors.append("review decision must keep all 54 features and both exclusions")
    comparison = document.get("comparison_policy")
    if not isinstance(comparison, Mapping) or not (
        comparison.get("integer_logical_types") == "exact"
        and comparison.get("float64_absolute_tolerance") == ABS_TOLERANCE
        and comparison.get("float64_relative_tolerance") == REL_TOLERANCE
    ):
        errors.append("comparison policy differs from the accepted tolerance")
    if document.get("feature_names") != feature_names:
        errors.append("fixture feature names or order differ from Schema v1")

    traces = document.get("traces")
    if not isinstance(traces, list):
        return errors + ["traces must be an array"]
    if [trace.get("trace_id") for trace in traces if isinstance(trace, Mapping)] != list(EXPECTED_TRACES):
        errors.append("fixture must contain the TCP and UDP traces in fixed order")
    for trace in traces:
        if not isinstance(trace, Mapping):
            errors.append("every trace must be an object")
            continue
        trace_id = trace.get("trace_id")
        if trace_id not in EXPECTED_TRACES:
            errors.append(f"unexpected trace: {trace_id}")
            continue
        expected_transport, expected_counts = EXPECTED_TRACES[trace_id]
        transport = trace.get("transport")
        packets = trace.get("packets")
        checkpoints = trace.get("checkpoints")
        if transport != expected_transport:
            errors.append(f"{trace_id} transport must be {expected_transport}")
        if not isinstance(packets, list) or len(packets) != max(expected_counts):
            errors.append(f"{trace_id} packet count is invalid")
            continue
        packet_errors: list[str] = []
        for index, packet in enumerate(packets, start=1):
            packet_errors.extend(validate_packet(packet, expected_transport, f"{trace_id}.packet[{index}]"))
        errors.extend(packet_errors)
        if not isinstance(checkpoints, list) or [item.get("packet_count") for item in checkpoints if isinstance(item, Mapping)] != list(expected_counts):
            errors.append(f"{trace_id} checkpoints differ from the accepted schedule")
            continue
        if packet_errors:
            continue
        for checkpoint in checkpoints:
            count = checkpoint["packet_count"]
            name = f"F{count}"
            if checkpoint.get("checkpoint") != name:
                errors.append(f"{trace_id} checkpoint {count} must be named {name}")
            expected = checkpoint.get("expected_vector")
            if not isinstance(expected, list) or len(expected) != 54:
                errors.append(f"{trace_id}.{name} must contain 54 expected values")
                continue
            actual = compute_feature_vector(packets[:count], expected_transport)
            for index, (wanted, observed, logical_type) in enumerate(zip(expected, actual, logical_types)):
                location = f"{trace_id}.{name}[{index}]"
                if isinstance(wanted, bool) or not isinstance(wanted, (int, float)) or not math.isfinite(wanted):
                    errors.append(f"{location} must be a finite number")
                elif logical_type != "float64" and not is_integer(wanted):
                    errors.append(f"{location} must preserve its integer logical type")
                elif logical_type != "float64" and wanted != observed:
                    errors.append(f"{location} expected {wanted}, computed {observed}")
                elif logical_type == "float64" and not math.isclose(wanted, observed, rel_tol=REL_TOLERANCE, abs_tol=ABS_TOLERANCE):
                    errors.append(f"{location} expected {wanted}, computed {observed}")
    return errors


def validate_review(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        return [f"missing T1.5 source files: {', '.join(missing)}"]
    errors: list[str] = []
    if sha256_file(source / FLOW_SCHEMA) != FLOW_SCHEMA_SHA256:
        errors.append("flow-feature Schema v1 hash differs from the accepted T1.3 artifact")
    if sha256_file(source / PACKET_SCHEMA) != PACKET_SCHEMA_SHA256:
        errors.append("packet-sequence Schema v1 hash differs from the accepted T1.3 artifact")
    flow_schema = load_json(source / FLOW_SCHEMA)
    fixture = load_json(source / FIXTURE)
    errors.extend(validate_fixture(fixture, flow_schema))
    return errors


def write_new_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite existing file: {path}") from error


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def run_logged(arguments: Sequence[str], source: Path, log_path: Path) -> dict[str, Any]:
    started = time.monotonic()
    result = subprocess.run(arguments, cwd=source, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    duration = time.monotonic() - started
    body = f"command: {' '.join(arguments)}\nreturn_code: {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(body, encoding="utf-8", newline="\n")
    return {
        "arguments": list(arguments),
        "return_code": result.returncode,
        "duration_seconds": round(duration, 6),
        "log": str(log_path.relative_to(source)).replace("\\", "/"),
        "log_sha256": sha256_file(log_path),
    }


def validate_receipt(document: Any, source: Path) -> list[str]:
    if not isinstance(document, Mapping):
        return ["receipt root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION or document.get("task") != TASK or document.get("kind") != KIND:
        errors.append("receipt identity does not match T1.5")
    checks = document.get("checks")
    if not isinstance(checks, list) or [item.get("name") for item in checks if isinstance(item, Mapping)] != ["schema_review", "python_unittest"]:
        errors.append("receipt checks must contain schema review and Python unittest")
    else:
        all_passed = all(item.get("status") == "passed" for item in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")
    files = document.get("source", {}).get("files")
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, Mapping)] != list(SOURCE_FILES):
        errors.append("receipt source files differ from T1.5")
    else:
        for item in files:
            digest = item.get("sha256")
            path = item.get("path")
            if re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None or digest != sha256_file(source / path):
                errors.append(f"source hash mismatch: {path}")
    commands = document.get("commands")
    if not isinstance(commands, Mapping):
        errors.append("receipt commands must be an object")
    else:
        for name in ("schema_review", "python_unittest"):
            command = commands.get(name)
            if not isinstance(command, Mapping) or command.get("return_code") != 0:
                errors.append(f"receipt command failed or is missing: {name}")
                continue
            log = source / str(command.get("log", ""))
            if not log.is_file() or sha256_file(log) != command.get("log_sha256"):
                errors.append(f"log hash mismatch: {name}")
    return errors


def command_check(args: argparse.Namespace) -> int:
    errors = validate_review(args.source.resolve())
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T1.5 review: 54 mandatory features and 5 reference vectors")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    errors = validate_review(source)
    if errors:
        raise ValueError("; ".join(errors))
    artifact_root = source / "run_log" / "t1.5"
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    attempt = artifact_root / "attempts" / dt.datetime.now(dt.timezone.utc).strftime("schema-review-%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    commands = {
        "schema_review": run_logged((sys.executable, "-B", str(source / SOURCE_FILES[4]), "check", "--source", str(source)), source, attempt / "schema-review.log"),
        "python_unittest": run_logged((sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"), source, attempt / "python-unittest.log"),
    }
    checks = [{"name": name, "status": "passed" if command["return_code"] == 0 else "failed"} for name, command in commands.items()]
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "generated_at_utc": utc_now(),
        "host": {"system": platform.system(), "architecture": platform.machine(), "python": platform.python_version()},
        "source": {"path": str(source), "files": [{"path": path, "sha256": sha256_file(source / path)} for path in SOURCE_FILES]},
        "contract": {
            "mandatory_feature_count": 54,
            "reference_vector_count": 5,
            "integer_comparison": "exact",
            "float64_absolute_tolerance": ABS_TOLERANCE,
            "float64_relative_tolerance": REL_TOLERANCE,
            "retransmission_and_out_of_order": "deferred",
            "port_category": "ablation_only",
        },
        "commands": commands,
        "checks": checks,
    }
    write_new_json(attempt / "receipt.json", receipt)
    if receipt["status"] != "passed":
        print(f"wrote {attempt / 'receipt.json'} (failed)", file=sys.stderr)
        return 1
    receipt_errors = validate_receipt(receipt, source)
    if receipt_errors:
        raise ValueError("; ".join(receipt_errors))
    write_new_json(final_receipt, receipt)
    print(f"wrote {final_receipt} (passed)")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    errors = validate_review(source)
    errors.extend(validate_receipt(load_json(args.input), source))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid T1.5 receipt: {args.input}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run")
    run.add_argument("--source", type=Path, default=project_root)
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--source", type=Path, default=project_root)
    validate.add_argument("--input", type=Path, required=True)
    validate.set_defaults(handler=command_validate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
