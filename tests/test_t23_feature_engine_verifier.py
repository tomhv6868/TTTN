import argparse
import contextlib
import copy
import importlib.util
import json
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_t23_feature_engine.py"
SPEC = importlib.util.spec_from_file_location("verify_t23_feature_engine", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@contextlib.contextmanager
def test_workspace():
    directory = ROOT / f".t23-test-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        resolved = directory.resolve()
        if resolved.parent != ROOT or not resolved.name.startswith(".t23-test-"):
            raise RuntimeError(f"refusing to remove unexpected test directory: {resolved}")
        shutil.rmtree(resolved)


def load_locked_inputs():
    schema = json.loads((ROOT / verifier.FLOW_SCHEMA_PATH).read_text(encoding="utf-8"))
    fixture = json.loads((ROOT / verifier.FIXTURE_PATH).read_text(encoding="utf-8"))
    baseline = json.loads((ROOT / verifier.BASELINE_RECEIPT_PATH).read_text(encoding="utf-8"))
    return schema, fixture, baseline


def emitted_output(fixture=None):
    if fixture is None:
        _, fixture, _ = load_locked_inputs()
    return "\n".join(
        json.dumps(record, separators=(",", ":"), allow_nan=False)
        for record in verifier.expected_vector_records(fixture)
    )


def ctest_output(
    flow_state=512,
    fixed=1024,
    allocator_current=3072,
    allocator_peak=15360,
    current=4096,
    peak=16384,
    budget=268435456,
):
    return "\n".join(
        (
            "nids_core.feature_engine",
            (
                "T2.2 memory accounting: "
                f"flow_state_bytes={flow_state} fixed_bytes={fixed} "
                f"allocator_current_bytes={allocator_current} "
                f"allocator_peak_bytes={allocator_peak} "
                f"current_bytes={current} peak_bytes={peak} budget_bytes={budget}"
            ),
            "100% tests passed",
        )
    )


def successful_commands():
    artifact_directory = "run_log/t2.3/attempts/ubuntu-acceptance-example"
    outputs = {
        "ctest": ctest_output(),
        "fixture_vectors": emitted_output(),
    }
    return [
        {
            "name": name,
            "arguments": [name],
            "return_code": 0,
            "stdout": outputs.get(name, "OK"),
            "stderr": "",
            "duration_seconds": 0.1,
            "log": f"{artifact_directory}/{verifier.LOG_FILES[name]}",
            "log_sha256": "a" * 64,
        }
        for name in verifier.COMMAND_NAMES
    ]


def resource_evidence(commands=None):
    if commands is None:
        commands = successful_commands()
    _, _, baseline = load_locked_inputs()
    current = verifier.flow_verifier.parse_memory_measurement(commands)
    return verifier.build_resource_evidence(current, baseline)


def valid_receipt():
    commands = successful_commands()
    schema, fixture, _ = load_locked_inputs()
    records, parse_errors = verifier.parse_emitted_vectors(commands)
    comparison_errors = verifier.compare_emitted_vectors(records, schema, fixture)
    resources = resource_evidence(commands)
    checks = verifier.assess(
        commands,
        {
            "CMAKE_BUILD_TYPE": "Release",
            "BUILD_TESTING": "ON",
            "NIDS_BUILD_TOOLCHAIN_SMOKE": "OFF",
        },
        [],
        [],
        parse_errors,
        comparison_errors,
        resources,
    )
    return {
        "schema_version": verifier.SCHEMA_VERSION,
        "task": verifier.TASK,
        "kind": verifier.KIND,
        "status": "passed",
        "generated_at_utc": "2026-07-15T10:00:00Z",
        "host": {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04.4",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
        },
        "source": {
            "path": "/mnt/hgfs/TTTN",
            "files": [{"path": path, "sha256": "b" * 64} for path in verifier.SOURCE_FILES],
            "contract_errors": [],
        },
        "inputs": {
            "flow_schema": {
                "path": verifier.FLOW_SCHEMA_PATH,
                "sha256": verifier.FLOW_SCHEMA_SHA256,
            },
            "fixture": {"path": verifier.FIXTURE_PATH, "sha256": verifier.FIXTURE_SHA256},
            "baseline_receipt": {
                "path": verifier.BASELINE_RECEIPT_PATH,
                "sha256": verifier.BASELINE_RECEIPT_SHA256,
            },
            "contract_errors": [],
        },
        "artifacts": {
            "directory": "run_log/t2.3/attempts/ubuntu-acceptance-example",
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
        "contract": verifier.EXPECTED_CONTRACT,
        "vectors": {
            "record_count": 5,
            "feature_count": 54,
            "records": [
                {"trace_id": trace, "checkpoint": checkpoint, "packet_count": count}
                for trace, checkpoint, count in verifier.EXPECTED_RECORDS
            ],
            "parse_errors": [],
            "comparison_errors": [],
        },
        "resources": resources,
        "commands": commands,
        "checks": checks,
    }


def write_source_contract(root: Path):
    copied = (
        verifier.FLOW_SCHEMA_PATH,
        verifier.FIXTURE_PATH,
        verifier.BASELINE_RECEIPT_PATH,
    )
    for relative in copied:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)

    files = {
        "CMakeLists.txt": "\n".join(
            (
                "add_library(nids_core cpp/src/feature.cpp cpp/src/flow_table.cpp)",
                "add_executable(nids_feature_engine_test cpp/tests/feature_engine_test.cpp)",
                "add_test(NAME nids_core.feature_engine COMMAND nids_feature_engine_test)",
            )
        ),
        "cpp/include/nids/feature.hpp": "struct FeatureState {}; using FeatureVector = int;",
        "cpp/include/nids/flow_table.hpp": "struct FlowState { FeatureState feature_state; };",
        "cpp/src/feature.cpp": "FeatureVector snapshot(const FeatureState& state);",
        "cpp/src/flow_table.cpp": "feature_state.update();",
        "cpp/tests/flow_table_test.cpp": 'print("T2.2 memory accounting:");',
        "cpp/tests/feature_engine_test.cpp": "\n".join(
            (
                'auto mode = "--emit-fixture-vectors";',
                'auto tcp = "tcp_bidirectional_9";',
                'auto udp = "udp_bidirectional_3";',
                'auto checkpoints = "F3 F5 F7 F9";',
                'auto fields = "trace_id checkpoint packet_count values";',
            )
        ),
        "scripts/verify_t23_feature_engine.py": "fixture",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class T23HostTests(unittest.TestCase):
    def test_supported_host_is_accepted(self):
        verifier.require_supported_host(
            {
                "system": "Linux",
                "os_id": "ubuntu",
                "os_version": "24.04.4",
                "architecture": "x86_64",
                "python": "3.12.3",
                "effective_uid": 1000,
            }
        )

    def test_unsupported_hosts_are_rejected(self):
        supported = {
            "system": "Linux",
            "os_id": "ubuntu",
            "os_version": "24.04",
            "architecture": "x86_64",
            "python": "3.12.3",
            "effective_uid": 1000,
        }
        invalid = (
            ({**supported, "effective_uid": 0}, "normal user"),
            ({**supported, "system": "Windows"}, "Ubuntu Linux VM"),
            ({**supported, "os_version": "22.04"}, "Ubuntu 24.04"),
            ({**supported, "architecture": "aarch64"}, "x86_64"),
            ({**supported, "python": "3.11.9"}, "Python 3.12"),
        )
        for host, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                verifier.require_supported_host(host)


class T23SourceAndInputTests(unittest.TestCase):
    def test_complete_contract_and_locked_inputs_are_accepted(self):
        with test_workspace() as root:
            write_source_contract(root)
            self.assertEqual([], verifier.contract_source_errors(root))
            schema, fixture, baseline = verifier.load_inputs(root)
            self.assertEqual([], verifier.input_contract_errors(root, schema, fixture, baseline))

    def test_packet_history_and_changed_fixture_are_rejected(self):
        with test_workspace() as root:
            write_source_contract(root)
            feature = root / "cpp/src/feature.cpp"
            feature.write_text("std::vector<PacketView> history;", encoding="utf-8")
            source_errors = verifier.contract_source_errors(root)

            fixture_path = root / verifier.FIXTURE_PATH
            fixture_path.write_text(fixture_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            schema, fixture, baseline = verifier.load_inputs(root)
            input_errors = verifier.input_contract_errors(root, schema, fixture, baseline)

        self.assertTrue(any("packet history" in error for error in source_errors))
        self.assertTrue(any(verifier.FIXTURE_PATH in error for error in input_errors))


class T23VectorTests(unittest.TestCase):
    def test_locked_jsonl_vectors_match_all_270_values(self):
        commands = successful_commands()
        records, parse_errors = verifier.parse_emitted_vectors(commands)
        schema, fixture, _ = load_locked_inputs()
        self.assertEqual([], parse_errors)
        self.assertEqual([], verifier.compare_emitted_vectors(records, schema, fixture))

    def test_extra_output_duplicate_keys_and_stderr_are_rejected(self):
        commands = successful_commands()
        emit = next(command for command in commands if command["name"] == "fixture_vectors")
        emit["stdout"] += "\nnot-json"
        emit["stderr"] = "noise"
        _, errors = verifier.parse_emitted_vectors(commands)
        self.assertTrue(any("exactly 5" in error for error in errors))
        self.assertTrue(any("stderr" in error for error in errors))

        emit["stdout"] = emitted_output().splitlines()[0].replace(
            '"trace_id":', '"trace_id":"duplicate","trace_id":', 1
        )
        _, errors = verifier.parse_emitted_vectors(commands)
        self.assertTrue(any("duplicate JSON key" in error for error in errors))

    def test_integer_type_float_tolerance_and_order_are_enforced(self):
        schema, fixture, _ = load_locked_inputs()
        records = verifier.expected_vector_records(fixture)

        changed = copy.deepcopy(records)
        changed[0]["values"][1] = 3.0
        errors = verifier.compare_emitted_vectors(changed, schema, fixture)
        self.assertTrue(any("integer logical type" in error for error in errors))

        changed = copy.deepcopy(records)
        changed[0]["values"][0] += 1e-6
        errors = verifier.compare_emitted_vectors(changed, schema, fixture)
        self.assertTrue(any("values[0]" in error for error in errors))

        changed = copy.deepcopy(records)
        changed[0], changed[1] = changed[1], changed[0]
        errors = verifier.compare_emitted_vectors(changed, schema, fixture)
        self.assertTrue(any("checkpoint" in error for error in errors))


class T23ResourceTests(unittest.TestCase):
    def test_flow_state_growth_and_total_budget_are_accepted(self):
        resources = resource_evidence()
        self.assertEqual(136, resources["baseline_flow_state_bytes"])
        self.assertEqual(376, resources["flow_state_growth_bytes"])
        self.assertTrue(verifier.valid_resource_evidence(resources))

    def test_no_growth_or_over_budget_is_rejected(self):
        resources = resource_evidence()
        resources["flow_state_bytes"] = 136
        resources["flow_state_growth_bytes"] = 0
        self.assertFalse(verifier.valid_resource_evidence(resources))

        commands = successful_commands()
        ctest = next(command for command in commands if command["name"] == "ctest")
        ctest["stdout"] = ctest_output(peak=268435457, allocator_peak=268434433)
        resources = resource_evidence(commands)
        self.assertFalse(verifier.valid_resource_evidence(resources))


class T23PipelineTests(unittest.TestCase):
    def test_pipeline_is_clean_offline_and_runs_emitter_before_python(self):
        outputs = (
            subprocess.CompletedProcess([], 0, "configured", ""),
            subprocess.CompletedProcess([], 0, "built", ""),
            subprocess.CompletedProcess([], 0, ctest_output(), ""),
            subprocess.CompletedProcess([], 0, emitted_output(), ""),
            subprocess.CompletedProcess([], 0, "", "Ran 150 tests\nOK"),
        )
        with test_workspace() as root:
            artifacts = root / "artifacts"
            with mock.patch.object(verifier.runner.subprocess, "run", side_effect=outputs) as runner:
                commands = verifier.run_pipeline(ROOT, root / "build", artifacts)

            self.assertEqual(list(verifier.COMMAND_NAMES), [item["name"] for item in commands])
            configure_args = runner.call_args_list[0].args[0]
            self.assertIn("-DCMAKE_BUILD_TYPE=Release", configure_args)
            self.assertIn("-DFETCHCONTENT_FULLY_DISCONNECTED=ON", configure_args)
            self.assertIn("-DNIDS_BUILD_TOOLCHAIN_SMOKE=OFF", configure_args)
            ctest_args = runner.call_args_list[2].args[0]
            self.assertNotIn("-R", ctest_args)
            emit_args = runner.call_args_list[3].args[0]
            self.assertTrue(str(emit_args[0]).endswith(verifier.FEATURE_EXECUTABLE))
            self.assertEqual(verifier.EMIT_ARGUMENT, emit_args[1])
            python_args = runner.call_args_list[4].args[0]
            self.assertEqual("discover", python_args[4])
            for command in commands:
                log_path = Path(command["log"])
                self.assertTrue(log_path.is_file())
                self.assertEqual(verifier.sha256_file(log_path), command["log_sha256"])

    def test_assessment_requires_vectors_memory_ctest_and_locked_build(self):
        checks = verifier.assess(
            successful_commands(),
            {
                "CMAKE_BUILD_TYPE": "Debug",
                "BUILD_TESTING": "OFF",
                "NIDS_BUILD_TOOLCHAIN_SMOKE": "ON",
            },
            ["source"],
            ["input"],
            ["parse"],
            ["comparison"],
            None,
        )
        failed = {check["name"] for check in checks if check["status"] == "failed"}
        self.assertEqual(
            {
                "source.contract_consistent",
                "inputs.schema_fixture_baseline_locked",
                "vectors.jsonl_well_formed",
                "vectors.all_reference_values_match",
                "resources.measurement_present",
                "resources.feature_state_growth_bounded",
                "build.release",
                "build.testing_enabled",
                "build.toolchain_smoke_disabled",
            },
            failed,
        )


class T23ReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        self.assertEqual([], verifier.validate_receipt(valid_receipt()))

    def test_receipt_rejects_vector_memory_log_and_status_tampering(self):
        receipt = valid_receipt()
        receipt["vectors"]["records"][0]["checkpoint"] = "F5"
        receipt["resources"]["flow_state_growth_bytes"] += 1
        receipt["commands"][0]["log"] = "outside/configure.log"
        receipt["checks"][0]["status"] = "failed"
        errors = verifier.validate_receipt(receipt)
        self.assertIn("receipt must record five matching 54-value reference vectors", errors)
        self.assertIn(
            "resources must prove bounded FlowState growth over the accepted T2.2 baseline",
            errors,
        )
        self.assertIn("every command log must be inside the recorded attempt directory", errors)
        self.assertIn("receipt status must match aggregate check status", errors)

    def test_writer_and_run_command_refuse_to_overwrite_receipts(self):
        with test_workspace() as root:
            output = root / "receipt.json"
            verifier.write_new_json(output, {"status": "passed"})
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                verifier.write_new_json(output, {"status": "failed"})

            artifact_root = root / "run_log/t2.3"
            artifact_root.mkdir(parents=True)
            (artifact_root / "acceptance.json").write_text("{}", encoding="utf-8")
            args = argparse.Namespace(source=root, artifact_root=artifact_root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite existing acceptance"):
                verifier.command_run(args)


if __name__ == "__main__":
    unittest.main()
