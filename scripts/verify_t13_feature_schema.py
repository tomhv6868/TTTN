#!/usr/bin/env python3
"""Validate the T1.3 flow-feature and packet-sequence contracts."""

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


SCHEMA_VERSION = "1.0.0"
TASK = "T1.3"
KIND = "feature_schema_acceptance"
FLOW_SCHEMA = "config/flow-feature-schema-v1.json"
PACKET_SCHEMA = "config/packet-sequence-schema-v1.json"
SOURCE_FILES = (
    FLOW_SCHEMA,
    PACKET_SCHEMA,
    "scripts/verify_t13_feature_schema.py",
    "tests/test_feature_schema.py",
)
FEATURE_NAMES = (
    "flow_age_us",
    "packet_count",
    "forward_packet_count",
    "reverse_packet_count",
    "wire_byte_count",
    "forward_wire_byte_count",
    "reverse_wire_byte_count",
    "packet_length_min",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_std",
    "forward_packet_length_mean",
    "forward_packet_length_std",
    "reverse_packet_length_mean",
    "reverse_packet_length_std",
    "flow_iat_min_us",
    "flow_iat_max_us",
    "flow_iat_mean_us",
    "flow_iat_std_us",
    "forward_iat_mean_us",
    "forward_iat_std_us",
    "reverse_iat_mean_us",
    "reverse_iat_std_us",
    "packet_rate_per_second",
    "wire_byte_rate_per_second",
    "forward_reverse_packet_ratio",
    "forward_reverse_wire_byte_ratio",
    "direction_change_count",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "tcp_syn_ack_ratio",
    "tcp_initial_forward_window",
    "tcp_initial_reverse_window",
    "tcp_window_mean",
    "tcp_window_std",
    "ttl_min",
    "ttl_max",
    "ttl_mean",
    "ttl_std",
    "payload_packet_count",
    "forward_payload_packet_count",
    "reverse_payload_packet_count",
    "payload_byte_count",
    "forward_payload_byte_count",
    "reverse_payload_byte_count",
    "payload_length_min",
    "payload_length_max",
    "payload_length_mean",
    "payload_length_std",
    "header_length_mean",
    "header_length_std",
)
PACKET_FIELD_NAMES = (
    "capture_id",
    "packet_index",
    "flow_generation_id",
    "flow_packet_ordinal",
    "direction",
    "timestamp_ns",
    "delta_time_ns",
    "clock_domain",
    "captured_length",
    "wire_length",
    "link_layer",
    "transport_protocol",
    "raw_frame",
    "ethernet_header_range",
    "vlan_header_range",
    "ipv4_header_range",
    "transport_header_range",
    "payload_range",
)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_flow_schema(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["flow schema root must be an object"]
    errors: list[str] = []
    if document.get("schema_id") != "nids.flow_features.v1":
        errors.append("flow schema_id must be nids.flow_features.v1")
    if document.get("schema_version") != SCHEMA_VERSION or document.get("task") != TASK:
        errors.append("flow schema version and task must match T1.3 v1")

    vector = document.get("feature_vector")
    if not isinstance(vector, Mapping) or not (
        vector.get("length") == len(FEATURE_NAMES)
        and vector.get("encoded_type") == "float64"
        and vector.get("finite_only") is True
        and vector.get("float32_conversion_stage") == "T4.1 preprocessing only"
    ):
        errors.append("feature vector must contain 54 finite float64 values until T4.1")

    features = document.get("features")
    if not isinstance(features, list):
        errors.append("features must be an array")
    else:
        indices = [item.get("index") for item in features if isinstance(item, Mapping)]
        names = [item.get("name") for item in features if isinstance(item, Mapping)]
        if indices != list(range(len(FEATURE_NAMES))):
            errors.append("feature indices must be contiguous and ordered from 0 to 53")
        if names != list(FEATURE_NAMES):
            errors.append("feature names or order differ from Feature Schema v1")
        allowed_types = {"uint8", "uint16", "uint32", "uint64", "float64"}
        for item in features:
            if not isinstance(item, Mapping) or item.get("logical_type") not in allowed_types:
                errors.append("every feature must declare an exact supported logical type")
                break
            if not all(isinstance(item.get(key), str) and item[key] for key in ("unit", "formula", "zero_policy")):
                errors.append("every feature must define unit, formula, and zero_policy")
                break
        forbidden_name = re.compile(r"(?:^|_)(?:ip|port|timestamp|label|flow_id|capture_id|packet_index)(?:_|$)")
        if any(isinstance(name, str) and forbidden_name.search(name) for name in names):
            errors.append("the model vector contains a forbidden leakage-prone feature name")

    time_policy = document.get("time_policy")
    if not isinstance(time_policy, Mapping) or not (
        time_policy.get("conversion") == "value_ns / 1000.0"
        and time_policy.get("rounding") == "none"
        and time_policy.get("signed_iat_preserved") is True
        and time_policy.get("packets_sorted_by_timestamp") is False
    ):
        errors.append("time policy must preserve exact signed capture-order deltas")

    statistics = document.get("statistics_policy")
    if not isinstance(statistics, Mapping) or not (
        statistics.get("algorithm") == "Welford"
        and statistics.get("variance") == "population"
        and statistics.get("variance_formula") == "M2 / n"
        and statistics.get("empty_group") == "all statistics are 0"
        and statistics.get("single_sample") == "standard deviation is 0"
        and statistics.get("non_finite_input_or_output") == "fail-fast"
    ):
        errors.append("statistics policy must lock Welford population variance and fail-fast handling")

    forbidden = document.get("leakage_policy", {}).get("forbidden_model_inputs", [])
    required_forbidden = {"raw IPv4 address", "raw transport port", "absolute timestamp", "future packet information"}
    if not isinstance(forbidden, list) or not required_forbidden.issubset(forbidden):
        errors.append("leakage policy does not ban all required raw or future information")
    return errors


def validate_packet_schema(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["packet sequence schema root must be an object"]
    errors: list[str] = []
    if document.get("schema_id") != "nids.packet_sequence.v1":
        errors.append("packet schema_id must be nids.packet_sequence.v1")
    scope = document.get("scope")
    if not isinstance(scope, Mapping) or not (
        scope.get("current_model_input") is False
        and scope.get("prefix_packet_limit") == 9
        and scope.get("flow_generation_boundaries_required") is True
    ):
        errors.append("packet sequence scope must be non-MVP input limited to nine packets per generation")
    sequence = document.get("sequence_policy")
    if not isinstance(sequence, Mapping) or not (
        sequence.get("packet_ordinal_origin") == 1
        and sequence.get("packets_sorted_by_timestamp") is False
        and sequence.get("first_packet_delta_time_ns") == 0
        and sequence.get("signed_delta_time_preserved") is True
        and sequence.get("timestamp_overflow") == "fail-fast"
    ):
        errors.append("packet sequence must preserve capture order and signed delta time")
    storage = document.get("storage_policy")
    if not isinstance(storage, Mapping) or not (
        storage.get("raw_frame_required_at_ingest") is True
        and storage.get("raw_bytes_in_flow_state") is False
        and storage.get("flow_state_retains_packet_history") is False
    ):
        errors.append("raw frames must remain recoverable outside FlowState")

    fields = document.get("record_fields")
    if not isinstance(fields, list):
        errors.append("record_fields must be an array")
    else:
        names = [item.get("name") for item in fields if isinstance(item, Mapping)]
        if names != list(PACKET_FIELD_NAMES):
            errors.append("packet record fields or order differ from Packet Sequence Schema v1")
        raw = next((item for item in fields if isinstance(item, Mapping) and item.get("name") == "raw_frame"), {})
        delta = next((item for item in fields if isinstance(item, Mapping) and item.get("name") == "delta_time_ns"), {})
        if raw.get("logical_type") != "bytes" or raw.get("role") != "derivation_input":
            errors.append("raw_frame must remain byte-valued derivation input")
        if delta.get("logical_type") != "int64" or delta.get("role") != "sequence_input":
            errors.append("delta_time_ns must remain signed sequence input")

    spin = document.get("spin_compatibility")
    adapter = spin.get("future_adapter_contract") if isinstance(spin, Mapping) else None
    if not isinstance(spin, Mapping) or not isinstance(adapter, Mapping) or not (
        spin.get("status") == "preparation_only"
        and spin.get("implemented_in_t1_3") is False
        and adapter.get("separate_version_required") is True
        and adapter.get("selected_byte_width") == 1486
    ):
        errors.append("SPIN compatibility must remain a separately versioned future adapter")
    return errors


def welford_population(values: Sequence[float]) -> tuple[float, float, float, float]:
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
            raise ValueError("Welford input must be finite")
        count += 1
        minimum = min(minimum, number)
        maximum = max(maximum, number)
        delta = number - mean
        mean += delta / count
        m2 += delta * (number - mean)
    variance = m2 / count
    if variance < 0.0 or not math.isfinite(variance):
        raise ValueError("Welford output must be finite and nonnegative")
    return minimum, maximum, mean, math.sqrt(variance)


def safe_ratio(numerator: float, denominator: float) -> float:
    if not math.isfinite(numerator) or not math.isfinite(denominator):
        raise ValueError("ratio operands must be finite")
    result = 0.0 if denominator == 0.0 else numerator / denominator
    if not math.isfinite(result):
        raise ValueError("ratio result must be finite")
    return result


def ns_to_us(value_ns: int) -> float:
    result = value_ns / 1000.0
    if not math.isfinite(result):
        raise ValueError("time conversion result must be finite")
    return result


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
        "log": str(log_path.relative_to(source)),
        "log_sha256": sha256_file(log_path),
    }


def validate_receipt(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["receipt root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION or document.get("task") != TASK or document.get("kind") != KIND:
        errors.append("receipt identity does not match T1.3")
    checks = document.get("checks")
    if not isinstance(checks, list) or not checks or any(item.get("status") not in ("passed", "failed") for item in checks if isinstance(item, Mapping)):
        errors.append("receipt checks must be a non-empty passed/failed array")
    else:
        all_passed = all(isinstance(item, Mapping) and item.get("status") == "passed" for item in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")
    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, Mapping)] != list(SOURCE_FILES):
        errors.append("receipt source files must match T1.3")
    elif any(re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None for item in files):
        errors.append("every source file must have a lowercase SHA-256")
    return errors


def command_check(args: argparse.Namespace) -> int:
    errors = validate_flow_schema(load_json(args.source / FLOW_SCHEMA))
    errors.extend(validate_packet_schema(load_json(args.source / PACKET_SCHEMA)))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T1.3 schemas: 54 flow features and 18 packet-sequence fields")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = (source / "run_log" / "t1.3").resolve()
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    if missing:
        raise ValueError(f"missing T1.3 source files: {', '.join(missing)}")
    attempt = artifact_root / "attempts" / dt.datetime.now(dt.timezone.utc).strftime("schema-%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    commands = {
        "schema_validation": run_logged((sys.executable, "-B", str(source / SOURCE_FILES[2]), "check", "--source", str(source)), source, attempt / "schema-validation.log"),
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
        "contract": {"flow_feature_count": 54, "packet_sequence_field_count": 18, "encoded_type": "float64", "prefix_packet_limit": 9},
        "commands": commands,
        "checks": checks,
    }
    write_new_json(attempt / "receipt.json", receipt)
    if receipt["status"] == "passed":
        write_new_json(final_receipt, receipt)
        print(f"wrote {final_receipt} (passed)")
        return 0
    print(f"wrote {attempt / 'receipt.json'} (failed)", file=sys.stderr)
    return 1


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_receipt(load_json(args.input))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid receipt: {args.input}")
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
