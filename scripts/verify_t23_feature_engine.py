#!/usr/bin/env python3
"""Build and verify the T2.3 incremental feature engine on Ubuntu."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import platform
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import verify_t11_packet_contract as runner
import verify_t22_flow_table as flow_verifier


SCHEMA_VERSION = "1.0.0"
TASK = "T2.3"
KIND = "feature_engine_acceptance"
EXPECTED_CTEST = "nids_core.feature_engine"
FEATURE_EXECUTABLE = "nids_feature_engine_test"
EMIT_ARGUMENT = "--emit-fixture-vectors"
COMMAND_NAMES = ("configure", "build", "ctest", "fixture_vectors", "python_unittest")
SOURCE_FILES = (
    "CMakeLists.txt",
    "config/flow-feature-schema-v1.json",
    "tests/fixtures/feature-vector-v1.json",
    "cpp/include/nids/feature.hpp",
    "cpp/include/nids/flow_table.hpp",
    "cpp/src/feature.cpp",
    "cpp/src/flow_table.cpp",
    "cpp/tests/flow_table_test.cpp",
    "cpp/tests/feature_engine_test.cpp",
    "scripts/verify_t23_feature_engine.py",
)
FLOW_SCHEMA_PATH = "config/flow-feature-schema-v1.json"
FIXTURE_PATH = "tests/fixtures/feature-vector-v1.json"
BASELINE_RECEIPT_PATH = "run_log/t2.2/acceptance.json"
FLOW_SCHEMA_SHA256 = "69241cb5069ce68f941836332cfc556d15fba00253288eb6f985155bac1bc6eb"
FIXTURE_SHA256 = "f313b66cd878031d668bb8b056ca010700e0f0d98197d45e2729979b4f7fd318"
BASELINE_RECEIPT_SHA256 = "b76c5f0ecf5ddec63829a40374bab00f6ba3096efbd79e1b0c80719c55820049"
BASELINE_FLOW_STATE_BYTES = 136
FEATURE_COUNT = 54
VECTOR_COUNT = 5
ABS_TOLERANCE = 1e-12
REL_TOLERANCE = 1e-12
EXPECTED_RECORDS = (
    ("tcp_bidirectional_9", "F3", 3),
    ("tcp_bidirectional_9", "F5", 5),
    ("tcp_bidirectional_9", "F7", 7),
    ("tcp_bidirectional_9", "F9", 9),
    ("udp_bidirectional_3", "F3", 3),
)
EXPECTED_CONTRACT = {
    "schema_id": "nids.flow_features.v1",
    "feature_count": FEATURE_COUNT,
    "reference_vector_count": VECTOR_COUNT,
    "checkpoints": ["F3", "F5", "F7", "F9"],
    "incremental_update": True,
    "packet_history_rescan": False,
    "capture_order": "preserved",
    "integer_logical_types": "exact_type_and_value",
    "float64_absolute_tolerance": ABS_TOLERANCE,
    "float64_relative_tolerance": REL_TOLERANCE,
    "emit_format": "json_lines",
    "emit_argument": EMIT_ARGUMENT,
    "flow_state_memory_baseline_task": "T2.2",
    "memory_budget_bytes": 256 * 1024 * 1024,
}
LOG_FILES = {
    "configure": "configure.log",
    "build": "build.log",
    "ctest": "ctest.log",
    "fixture_vectors": "fixture-vectors.log",
    "python_unittest": "python-unittest.log",
}

sha256_file = runner.sha256_file
write_new_json = runner.write_new_json


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
    if not isinstance(effective_uid, int) or isinstance(effective_uid, bool) or effective_uid <= 0:
        raise RuntimeError("T2.3 verification must run as a normal user, not root")
    if host.get("system") != "Linux":
        raise RuntimeError("T2.3 verification must run inside the Ubuntu Linux VM")
    if host.get("os_id") != "ubuntu" or not str(host.get("os_version", "")).startswith("24.04"):
        raise RuntimeError("T2.3 verification requires Ubuntu 24.04")
    if host.get("architecture") != "x86_64":
        raise RuntimeError("T2.3 verification requires x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        raise RuntimeError("T2.3 verification requires Python 3.12.x")


def run_pipeline(source: Path, build: Path, artifact_directory: Path) -> list[dict[str, Any]]:
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
        ),
        source,
        artifact_directory / LOG_FILES["configure"],
        300.0,
    )
    commands = [configure]

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
            "build", "configure failed", artifact_directory / LOG_FILES["build"]
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
        fixture_vectors = runner.run_command(
            "fixture_vectors",
            (str(build / FEATURE_EXECUTABLE), EMIT_ARGUMENT),
            source,
            artifact_directory / LOG_FILES["fixture_vectors"],
            60.0,
        )
    else:
        ctest = runner.skipped_command(
            "ctest", "build failed or was skipped", artifact_directory / LOG_FILES["ctest"]
        )
        fixture_vectors = runner.skipped_command(
            "fixture_vectors",
            "build failed or was skipped",
            artifact_directory / LOG_FILES["fixture_vectors"],
        )
    commands.extend((ctest, fixture_vectors))
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


def load_inputs(source: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for relative in (FLOW_SCHEMA_PATH, FIXTURE_PATH, BASELINE_RECEIPT_PATH):
        document = runner.load_json(source / relative)
        if not isinstance(document, dict):
            raise ValueError(f"input must be a JSON object: {relative}")
        documents.append(document)
    return documents[0], documents[1], documents[2]


def expected_vector_records(fixture: Mapping[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    traces = fixture.get("traces")
    if not isinstance(traces, list):
        return records
    for trace in traces:
        if not isinstance(trace, Mapping):
            continue
        checkpoints = trace.get("checkpoints")
        if not isinstance(checkpoints, list):
            continue
        for checkpoint in checkpoints:
            if not isinstance(checkpoint, Mapping):
                continue
            records.append(
                {
                    "trace_id": trace.get("trace_id"),
                    "checkpoint": checkpoint.get("checkpoint"),
                    "packet_count": checkpoint.get("packet_count"),
                    "values": checkpoint.get("expected_vector"),
                }
            )
    return records


def input_contract_errors(
    source: Path,
    schema: Mapping[str, Any],
    fixture: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    expected_hashes = (
        (FLOW_SCHEMA_PATH, FLOW_SCHEMA_SHA256),
        (FIXTURE_PATH, FIXTURE_SHA256),
        (BASELINE_RECEIPT_PATH, BASELINE_RECEIPT_SHA256),
    )
    for path, expected in expected_hashes:
        if sha256_file(source / path) != expected:
            errors.append(f"accepted input hash changed: {path}")

    vector = schema.get("feature_vector")
    features = schema.get("features")
    if not isinstance(vector, Mapping) or not (
        schema.get("schema_id") == "nids.flow_features.v1"
        and vector.get("length") == FEATURE_COUNT
        and vector.get("encoded_type") == "float64"
        and vector.get("finite_only") is True
    ):
        errors.append("flow schema identity or fixed vector contract changed")
    if not isinstance(features, list) or len(features) != FEATURE_COUNT or any(
        not isinstance(feature, Mapping)
        or feature.get("index") != index
        or feature.get("logical_type") not in {"uint8", "uint16", "uint32", "uint64", "float64"}
        for index, feature in enumerate(features if isinstance(features, list) else [])
    ):
        errors.append("flow schema must expose 54 ordered supported logical types")

    comparison = fixture.get("comparison_policy")
    records = expected_vector_records(fixture)
    record_keys = tuple(
        (record.get("trace_id"), record.get("checkpoint"), record.get("packet_count"))
        for record in records
    )
    if fixture.get("fixture_id") != "nids.feature_vectors.v1" or record_keys != EXPECTED_RECORDS:
        errors.append("fixture must retain the accepted TCP/UDP checkpoint order")
    if not isinstance(comparison, Mapping) or not (
        comparison.get("integer_logical_types") == "exact"
        and comparison.get("float64_absolute_tolerance") == ABS_TOLERANCE
        and comparison.get("float64_relative_tolerance") == REL_TOLERANCE
    ):
        errors.append("fixture comparison policy changed")
    if len(records) != VECTOR_COUNT or any(
        not isinstance(record.get("values"), list) or len(record["values"]) != FEATURE_COUNT
        for record in records
    ):
        errors.append("fixture must contain five complete 54-value vectors")

    if baseline.get("task") != "T2.2" or baseline.get("status") != "passed":
        errors.append("T2.2 baseline receipt must be passed")
    baseline_resources = baseline.get("resources")
    if not isinstance(baseline_resources, Mapping) or not flow_verifier.valid_memory_measurement(
        baseline_resources
    ) or baseline_resources.get("flow_state_bytes") != BASELINE_FLOW_STATE_BYTES:
        errors.append("T2.2 baseline memory evidence is invalid")
    return errors


def contract_source_errors(source: Path) -> list[str]:
    missing = [path for path in SOURCE_FILES if not (source / path).is_file()]
    missing.extend(
        path
        for path in (BASELINE_RECEIPT_PATH,)
        if not (source / path).is_file()
    )
    if missing:
        return [f"missing source or evidence file: {path}" for path in missing]

    cmake = (source / "CMakeLists.txt").read_text(encoding="utf-8")
    header = (source / "cpp/include/nids/feature.hpp").read_text(encoding="utf-8")
    flow_header = (source / "cpp/include/nids/flow_table.hpp").read_text(encoding="utf-8")
    implementation = (source / "cpp/src/feature.cpp").read_text(encoding="utf-8")
    tests = (source / "cpp/tests/feature_engine_test.cpp").read_text(encoding="utf-8")
    errors: list[str] = []

    cmake_tokens = (
        "cpp/src/feature.cpp",
        "cpp/tests/feature_engine_test.cpp",
        FEATURE_EXECUTABLE,
        EXPECTED_CTEST,
    )
    missing_cmake = [token for token in cmake_tokens if token not in cmake]
    if missing_cmake:
        errors.append(f"CMake is missing feature engine tokens: {', '.join(missing_cmake)}")

    api_text = "\n".join((header, implementation))
    missing_api = [token for token in ("FeatureState", "FeatureVector") if token not in api_text]
    if missing_api:
        errors.append(f"feature engine API is missing tokens: {', '.join(missing_api)}")
    if "FeatureState" not in flow_header:
        errors.append("FlowState must own the incremental FeatureState")
    forbidden_history = (
        r"std::vector\s*<\s*PacketView",
        r"std::deque\s*<\s*PacketView",
        r"std::vector\s*<\s*PacketInput",
        r"std::deque\s*<\s*PacketInput",
    )
    if any(re.search(pattern, api_text) is not None for pattern in forbidden_history):
        errors.append("feature engine must not retain packet history for rescanning")

    test_tokens = (
        EMIT_ARGUMENT,
        "tcp_bidirectional_9",
        "udp_bidirectional_3",
        "F3",
        "F5",
        "F7",
        "F9",
        "trace_id",
        "checkpoint",
        "packet_count",
        "values",
    )
    missing_tests = [token for token in test_tokens if token not in tests]
    if missing_tests:
        errors.append(f"feature engine tests are missing fixture tokens: {', '.join(missing_tests)}")
    return errors


class DuplicateJsonKey(ValueError):
    pass


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_emitted_vectors(
    commands: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    command = runner.find_command(commands, "fixture_vectors")
    stdout = str(command.get("stdout", ""))
    stderr = str(command.get("stderr", ""))
    lines = stdout.splitlines()
    errors: list[str] = []
    records: list[dict[str, Any]] = []
    if stderr:
        errors.append("fixture vector emitter must not write stderr")
    if len(lines) != VECTOR_COUNT:
        errors.append(f"fixture vector emitter must write exactly {VECTOR_COUNT} JSON lines")
    for index, line in enumerate(lines):
        if not line.strip():
            errors.append(f"emitted line {index + 1} must be a JSON object")
            continue
        try:
            record = json.loads(line, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, DuplicateJsonKey) as error:
            errors.append(f"emitted line {index + 1} is invalid JSON: {error}")
            continue
        if not isinstance(record, dict) or set(record) != {
            "trace_id",
            "checkpoint",
            "packet_count",
            "values",
        }:
            errors.append(f"emitted line {index + 1} has an invalid object shape")
            continue
        if not isinstance(record.get("trace_id"), str) or not isinstance(
            record.get("checkpoint"), str
        ):
            errors.append(f"emitted line {index + 1} has invalid identifiers")
        packet_count = record.get("packet_count")
        if not isinstance(packet_count, int) or isinstance(packet_count, bool):
            errors.append(f"emitted line {index + 1} packet_count must be an integer")
        if not isinstance(record.get("values"), list):
            errors.append(f"emitted line {index + 1} values must be an array")
        records.append(record)
    return records, errors


def compare_emitted_vectors(
    records: Sequence[Mapping[str, Any]],
    schema: Mapping[str, Any],
    fixture: Mapping[str, Any],
) -> list[str]:
    expected = expected_vector_records(fixture)
    features = schema.get("features")
    if not isinstance(features, list) or len(features) != FEATURE_COUNT:
        return ["cannot compare vectors without the locked 54-feature schema"]
    errors: list[str] = []
    if len(records) != len(expected):
        return [f"emitted vector count {len(records)} does not equal {len(expected)}"]
    for record_index, (actual, wanted) in enumerate(zip(records, expected)):
        location = f"record[{record_index}]"
        for field in ("trace_id", "checkpoint", "packet_count"):
            if actual.get(field) != wanted.get(field):
                errors.append(f"{location}.{field} expected {wanted.get(field)!r}, got {actual.get(field)!r}")
        actual_values = actual.get("values")
        wanted_values = wanted.get("values")
        if not isinstance(actual_values, list) or len(actual_values) != FEATURE_COUNT:
            errors.append(f"{location}.values must contain exactly {FEATURE_COUNT} values")
            continue
        if not isinstance(wanted_values, list) or len(wanted_values) != FEATURE_COUNT:
            errors.append(f"{location} fixture vector is invalid")
            continue
        for feature_index, (actual_value, wanted_value, feature) in enumerate(
            zip(actual_values, wanted_values, features)
        ):
            value_location = f"{location}.values[{feature_index}]"
            if isinstance(actual_value, bool) or not isinstance(actual_value, (int, float)):
                errors.append(f"{value_location} must be a finite JSON number")
                continue
            if not math.isfinite(actual_value):
                errors.append(f"{value_location} must be finite")
                continue
            logical_type = feature.get("logical_type") if isinstance(feature, Mapping) else None
            if logical_type != "float64":
                if not isinstance(actual_value, int) or isinstance(actual_value, bool):
                    errors.append(f"{value_location} must preserve its integer logical type")
                elif actual_value != wanted_value:
                    errors.append(f"{value_location} expected {wanted_value}, got {actual_value}")
            elif not math.isclose(
                float(actual_value),
                float(wanted_value),
                rel_tol=REL_TOLERANCE,
                abs_tol=ABS_TOLERANCE,
            ):
                errors.append(f"{value_location} expected {wanted_value}, got {actual_value}")
    return errors


def build_resource_evidence(
    current: Mapping[str, Any] | None,
    baseline: Mapping[str, Any],
) -> dict[str, Any] | None:
    if current is None:
        return None
    baseline_resources = baseline.get("resources")
    if not isinstance(baseline_resources, Mapping):
        return None
    result = dict(current)
    baseline_bytes = baseline_resources.get("flow_state_bytes")
    current_bytes = result.get("flow_state_bytes")
    result.update(
        {
            "baseline_receipt": BASELINE_RECEIPT_PATH,
            "baseline_receipt_sha256": BASELINE_RECEIPT_SHA256,
            "baseline_flow_state_bytes": baseline_bytes,
            "flow_state_growth_bytes": (
                current_bytes - baseline_bytes
                if isinstance(current_bytes, int) and isinstance(baseline_bytes, int)
                else None
            ),
        }
    )
    return result


def valid_resource_evidence(resources: Mapping[str, Any] | None) -> bool:
    if resources is None:
        return False
    current = {
        key: resources.get(key)
        for key in (
            "accounting",
            "flow_state_bytes",
            "fixed_bytes",
            "allocator_current_bytes",
            "allocator_peak_bytes",
            "current_bytes",
            "peak_bytes",
            "budget_bytes",
        )
    }
    flow_state = resources.get("flow_state_bytes")
    baseline = resources.get("baseline_flow_state_bytes")
    growth = resources.get("flow_state_growth_bytes")
    return (
        flow_verifier.valid_memory_measurement(current)
        and resources.get("baseline_receipt") == BASELINE_RECEIPT_PATH
        and resources.get("baseline_receipt_sha256") == BASELINE_RECEIPT_SHA256
        and baseline == BASELINE_FLOW_STATE_BYTES
        and isinstance(flow_state, int)
        and not isinstance(flow_state, bool)
        and isinstance(growth, int)
        and not isinstance(growth, bool)
        and flow_state > baseline
        and growth == flow_state - baseline
    )


def assess(
    commands: Sequence[Mapping[str, Any]],
    cache: Mapping[str, str],
    source_errors: Sequence[str],
    input_errors: Sequence[str],
    parse_errors: Sequence[str],
    comparison_errors: Sequence[str],
    resources: Mapping[str, Any] | None,
) -> list[dict[str, str]]:
    checks = [
        {
            "name": f"command.{name}",
            "status": "passed" if runner.find_command(commands, name).get("return_code") == 0 else "failed",
        }
        for name in COMMAND_NAMES
    ]
    ctest = runner.find_command(commands, "ctest")
    ctest_output = "\n".join((str(ctest.get("stdout", "")), str(ctest.get("stderr", ""))))
    checks.extend(
        (
            {"name": "source.contract_consistent", "status": "passed" if not source_errors else "failed"},
            {"name": "inputs.schema_fixture_baseline_locked", "status": "passed" if not input_errors else "failed"},
            {"name": "ctest.feature_engine_present", "status": "passed" if EXPECTED_CTEST in ctest_output else "failed"},
            {"name": "ctest.all_passed", "status": "passed" if "100% tests passed" in ctest_output else "failed"},
            {"name": "vectors.jsonl_well_formed", "status": "passed" if not parse_errors else "failed"},
            {"name": "vectors.all_reference_values_match", "status": "passed" if not comparison_errors else "failed"},
            {"name": "resources.measurement_present", "status": "passed" if resources is not None else "failed"},
            {"name": "resources.feature_state_growth_bounded", "status": "passed" if valid_resource_evidence(resources) else "failed"},
            {"name": "build.release", "status": "passed" if cache.get("CMAKE_BUILD_TYPE") == "Release" else "failed"},
            {"name": "build.testing_enabled", "status": "passed" if cache.get("BUILD_TESTING") == "ON" else "failed"},
            {"name": "build.toolchain_smoke_disabled", "status": "passed" if cache.get("NIDS_BUILD_TOOLCHAIN_SMOKE") == "OFF" else "failed"},
        )
    )
    return checks


def collect_receipt(source: Path, artifact_directory: Path, host: Mapping[str, Any]) -> dict[str, Any]:
    schema, fixture, baseline = load_inputs(source)
    source_errors = contract_source_errors(source)
    input_errors = input_contract_errors(source, schema, fixture, baseline)
    with tempfile.TemporaryDirectory(prefix="nids-t2.3-") as temporary:
        workspace = Path(temporary).resolve()
        if workspace == source or workspace.is_relative_to(source):
            raise RuntimeError("temporary build workspace must be outside the shared source tree")
        build = workspace / "build"
        commands = run_pipeline(source, build, artifact_directory)
        cache = runner.read_cmake_cache(build / "CMakeCache.txt")
        records, parse_errors = parse_emitted_vectors(commands)
        comparison_errors = compare_emitted_vectors(records, schema, fixture)
        current_memory = flow_verifier.parse_memory_measurement(commands)
        resources = build_resource_evidence(current_memory, baseline)
        checks = assess(
            commands,
            cache,
            source_errors,
            input_errors,
            parse_errors,
            comparison_errors,
            resources,
        )

    for command in commands:
        command["log"] = str(Path(str(command["log"])).relative_to(source)).replace("\\", "/")
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "status": status,
        "generated_at_utc": runner.utc_now(),
        "host": dict(host),
        "source": {
            "path": str(source),
            "files": [{"path": path, "sha256": sha256_file(source / path)} for path in SOURCE_FILES],
            "contract_errors": list(source_errors),
        },
        "inputs": {
            "flow_schema": {"path": FLOW_SCHEMA_PATH, "sha256": FLOW_SCHEMA_SHA256},
            "fixture": {"path": FIXTURE_PATH, "sha256": FIXTURE_SHA256},
            "baseline_receipt": {"path": BASELINE_RECEIPT_PATH, "sha256": BASELINE_RECEIPT_SHA256},
            "contract_errors": list(input_errors),
        },
        "artifacts": {
            "directory": str(artifact_directory.relative_to(source)).replace("\\", "/"),
            "final_receipt": "run_log/t2.3/acceptance.json",
        },
        "build": {
            "generator": "Ninja",
            "configuration": "Release",
            "testing_enabled": True,
            "toolchain_smoke_enabled": False,
            "temporary_workspace_outside_source": True,
            "temporary_workspace_retained": False,
            "offline_dependency_mode": True,
        },
        "contract": EXPECTED_CONTRACT,
        "vectors": {
            "record_count": len(records),
            "feature_count": FEATURE_COUNT,
            "records": [
                {
                    "trace_id": record.get("trace_id"),
                    "checkpoint": record.get("checkpoint"),
                    "packet_count": record.get("packet_count"),
                }
                for record in records
            ],
            "parse_errors": list(parse_errors),
            "comparison_errors": list(comparison_errors),
        },
        "resources": resources,
        "commands": commands,
        "checks": checks,
    }


def validate_receipt(document: Any) -> list[str]:
    if not isinstance(document, Mapping):
        return ["receipt root must be an object"]
    errors: list[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")
    if document.get("task") != TASK:
        errors.append(f"task must equal {TASK}")
    if document.get("kind") != KIND:
        errors.append(f"kind must equal {KIND}")
    if document.get("status") not in ("passed", "failed"):
        errors.append("status must be passed or failed")

    host = document.get("host")
    if not isinstance(host, Mapping) or not (
        host.get("system") == "Linux"
        and host.get("os_id") == "ubuntu"
        and str(host.get("os_version", "")).startswith("24.04")
        and host.get("architecture") == "x86_64"
        and re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is not None
        and isinstance(host.get("effective_uid"), int)
        and not isinstance(host.get("effective_uid"), bool)
        and host.get("effective_uid", 0) > 0
    ):
        errors.append("receipt host must be Ubuntu 24.04 x86_64 with Python 3.12.x as a normal user")
    if document.get("contract") != EXPECTED_CONTRACT:
        errors.append("contract values do not match the approved T2.3 feature boundaries")

    inputs = document.get("inputs")
    if not isinstance(inputs, Mapping) or not (
        inputs.get("flow_schema") == {"path": FLOW_SCHEMA_PATH, "sha256": FLOW_SCHEMA_SHA256}
        and inputs.get("fixture") == {"path": FIXTURE_PATH, "sha256": FIXTURE_SHA256}
        and inputs.get("baseline_receipt") == {
            "path": BASELINE_RECEIPT_PATH,
            "sha256": BASELINE_RECEIPT_SHA256,
        }
        and inputs.get("contract_errors") == []
    ):
        errors.append("schema, fixture, or T2.2 baseline evidence is missing or inconsistent")
    resources = document.get("resources")
    if not valid_resource_evidence(resources if isinstance(resources, Mapping) else None):
        errors.append("resources must prove bounded FlowState growth over the accepted T2.2 baseline")

    build = document.get("build")
    if not isinstance(build, Mapping) or not (
        build.get("generator") == "Ninja"
        and build.get("configuration") == "Release"
        and build.get("testing_enabled") is True
        and build.get("toolchain_smoke_enabled") is False
        and build.get("temporary_workspace_outside_source") is True
        and build.get("temporary_workspace_retained") is False
        and build.get("offline_dependency_mode") is True
    ):
        errors.append("build flags do not match the T2.3 acceptance contract")

    artifacts = document.get("artifacts")
    artifact_directory = artifacts.get("directory") if isinstance(artifacts, Mapping) else None
    if not isinstance(artifact_directory, str) or re.fullmatch(
        r"run_log/t2\.3/attempts/ubuntu-acceptance-[A-Za-z0-9._-]+", artifact_directory
    ) is None or artifacts.get("final_receipt") != "run_log/t2.3/acceptance.json":
        errors.append("artifacts must remain under run_log/t2.3 with the locked final receipt")

    commands = document.get("commands")
    valid_commands = (
        isinstance(commands, list)
        and len(commands) == len(COMMAND_NAMES)
        and all(isinstance(command, Mapping) for command in commands)
        and [command.get("name") for command in commands] == list(COMMAND_NAMES)
    )
    if not valid_commands:
        errors.append("commands must contain the complete T2.3 pipeline in order")
    else:
        for command in commands:
            expected_log = f"{artifact_directory}/{LOG_FILES[command['name']]}"
            if command.get("log") != expected_log:
                errors.append("every command log must be inside the recorded attempt directory")
            if re.fullmatch(r"[0-9a-f]{64}", str(command.get("log_sha256", ""))) is None:
                errors.append("every command log must have a lowercase SHA-256")
        if document.get("status") == "passed" and any(
            command.get("return_code") != 0 for command in commands
        ):
            errors.append("a passed receipt requires every command to return zero")

    vectors = document.get("vectors")
    expected_summary = [
        {"trace_id": trace, "checkpoint": checkpoint, "packet_count": count}
        for trace, checkpoint, count in EXPECTED_RECORDS
    ]
    if not isinstance(vectors, Mapping) or not (
        vectors.get("record_count") == VECTOR_COUNT
        and vectors.get("feature_count") == FEATURE_COUNT
        and vectors.get("records") == expected_summary
        and vectors.get("parse_errors") == []
        and vectors.get("comparison_errors") == []
    ):
        errors.append("receipt must record five matching 54-value reference vectors")

    checks = document.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("checks must be a non-empty array")
    else:
        invalid = [
            check
            for check in checks
            if not isinstance(check, Mapping) or check.get("status") not in ("passed", "failed")
        ]
        names = {check.get("name") for check in checks if isinstance(check, Mapping)}
        required_checks = {
            "source.contract_consistent",
            "inputs.schema_fixture_baseline_locked",
            "ctest.feature_engine_present",
            "ctest.all_passed",
            "vectors.jsonl_well_formed",
            "vectors.all_reference_values_match",
            "resources.measurement_present",
            "resources.feature_state_growth_bounded",
        }
        if invalid:
            errors.append("every check must have passed or failed status")
        if not required_checks.issubset(names):
            errors.append("receipt must check feature vectors, inputs, CTest, and FlowState memory growth")
        all_passed = not invalid and all(check.get("status") == "passed" for check in checks)
        if (document.get("status") == "passed") != all_passed:
            errors.append("receipt status must match aggregate check status")

    source = document.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    if not isinstance(files, list) or len(files) != len(SOURCE_FILES) or not all(
        isinstance(item, Mapping) for item in files
    ) or [item.get("path") for item in files] != list(SOURCE_FILES):
        errors.append("source files must match the T2.3 feature engine inputs")
    elif any(
        re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None
        for item in files
    ):
        errors.append("every source file must have a lowercase SHA-256")
    if not isinstance(source, Mapping) or source.get("contract_errors") != []:
        errors.append("source contract must have no validation errors")

    timestamp = document.get("generated_at_utc")
    try:
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise ValueError
        dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp ending in Z")
    return errors


def command_check(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    errors = contract_source_errors(source)
    if not errors:
        schema, fixture, baseline = load_inputs(source)
        errors.extend(input_contract_errors(source, schema, fixture, baseline))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("valid T2.3 source contract: incremental 54-value F3/F5/F7/F9 feature engine")
    return 0


def command_run(args: argparse.Namespace) -> int:
    source = args.source.resolve()
    artifact_root = args.artifact_root.resolve()
    expected_artifact_root = (source / "run_log" / "t2.3").resolve()
    if artifact_root != expected_artifact_root:
        raise ValueError(f"artifact root must equal {expected_artifact_root}")
    final_receipt = artifact_root / "acceptance.json"
    if final_receipt.exists():
        raise ValueError(f"refusing to overwrite existing acceptance: {final_receipt}")
    required = (*SOURCE_FILES, BASELINE_RECEIPT_PATH)
    if any(not (source / path).is_file() for path in required) or not (source / ".git").is_dir():
        raise ValueError(f"source is not the T2.3 project root: {source}")

    host = inspect_host()
    require_supported_host(host)
    runner.require_tools()
    attempt_directory = artifact_root / "attempts" / runner.attempt_name()
    attempt_directory.mkdir(parents=True, exist_ok=False)
    receipt = collect_receipt(source, attempt_directory, host)
    write_new_json(attempt_directory / "receipt.json", receipt)
    print(f"wrote {attempt_directory / 'receipt.json'} ({receipt['status']})")
    if receipt["status"] == "passed":
        write_new_json(final_receipt, receipt)
        print(f"wrote {final_receipt} (passed)")
        return 0
    for check in receipt["checks"]:
        if check["status"] == "failed":
            print(f"failed: {check['name']}", file=sys.stderr)
    return 1


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_receipt(runner.load_json(args.input))
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
    check = subparsers.add_parser("check", help="validate T2.3 feature engine source contracts")
    check.add_argument("--source", type=Path, default=project_root)
    check.set_defaults(handler=command_check)
    run = subparsers.add_parser("run", help="perform a clean T2.3 verification on Ubuntu")
    run.add_argument("--source", type=Path, default=project_root)
    run.add_argument("--artifact-root", type=Path, default=project_root / "run_log" / "t2.3")
    run.set_defaults(handler=command_run)
    validate = subparsers.add_parser("validate", help="validate a saved T2.3 receipt")
    validate.add_argument("--input", required=True, type=Path)
    validate.set_defaults(handler=command_validate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
