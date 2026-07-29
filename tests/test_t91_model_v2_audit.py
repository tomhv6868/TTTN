from __future__ import annotations

import copy
import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_TMP = ROOT / "run_log" / ".test-tmp"
sys.path.insert(0, str(ROOT / "python"))

from nids_mvp import full_flow_v2_audit as audit  # noqa: E402


def write_bytes(root: Path, relative: str, value: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {
        "path": relative,
        "size_bytes": path.stat().st_size,
        "sha256": audit.sha256_path(path),
    }


def write_json(root: Path, relative: str, value: object) -> dict[str, object]:
    data = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return write_bytes(root, relative, data + b"\n")


def temporary_workspace(test_case: unittest.TestCase) -> Path:
    WORKSPACE_TMP.mkdir(parents=True, exist_ok=True)
    root = WORKSPACE_TMP / f"t91-v2-audit-{uuid.uuid4().hex}"
    root.mkdir()
    test_case.addCleanup(shutil.rmtree, root, ignore_errors=True)
    return root


def write_part(
    root: Path, relative: str, partition: str, feature_names: list[str]
) -> dict[str, object]:
    rows = 2
    feature_values = [[0.0, 0.0] for _ in feature_names]
    locked_values = {
        0: [1_000.0, 2_000.0],
        1: [12.0, 13.0],
        2: [6.0, 7.0],
        3: [6.0, 6.0],
        30: [2.0, 3.0],
        31: [0.0, 1.0],
        34: [64_240.0, 8_192.0],
        35: [8_192.0, 64_240.0],
        36: [16_000.0, 20_000.0],
        37: [100.0, 200.0],
        38: [64.0, 64.0],
        39: [128.0, 128.0],
        40: [96.0, 96.0],
        41: [32.0, 32.0],
        54: [6.0, 6.0],
        55: [64.0, 64.0],
        56: [128.0, 128.0],
        66: [0.0, 0.0],
        67: [1.0, 1.0],
        68: [0.0, 0.0],
        69: [0.0, 0.0],
    }
    for index, values in locked_values.items():
        feature_values[index] = values
    prefix = {
        "partition": [partition] * rows,
        "label_status": ["assigned"] * rows,
        "assigned_class": ["BENIGN", "FTP-Patator"],
        "label_family": ["Benign", "FTP-Bruteforce"],
        "protocol": [6, 6],
        "packet_count": [12, 13],
        "forward_packet_count": [6, 7],
        "reverse_packet_count": [6, 6],
    }
    table = pa.Table.from_arrays(
        [
            *(pa.array(values) for values in prefix.values()),
            *(pa.array(values, type=pa.float64()) for values in feature_values),
        ],
        names=[*prefix, *feature_names],
    )
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, path)
    return {
        "partition": partition,
        "path": relative,
        "rows": rows,
        "sha256": audit.sha256_path(path),
        "size_bytes": path.stat().st_size,
    }


class T91ModelV2AuditTest(unittest.TestCase):
    def make_workspace(self, root: Path) -> tuple[Path, Path]:
        production_schema = json.loads(
            (ROOT / "config/terminal-flow-feature-schema-v1.json").read_text(
                encoding="utf-8"
            )
        )
        feature_names = [
            str(record["name"]) for record in production_schema["features"]
        ]
        schema = {
            "schema_version": "1.0.0",
            "features": [
                {"index": index, "name": name}
                for index, name in enumerate(feature_names)
            ],
        }
        train_part = write_part(
            root,
            "run_log/full-flow-v1/dataset/capture_id=unit/assigned/partition=train/part-00000.parquet",
            "train",
            feature_names,
        )
        validation_part = write_part(
            root,
            "run_log/full-flow-v1/dataset/capture_id=unit/assigned/partition=validation/part-00000.parquet",
            "validation",
            feature_names,
        )
        sealed_path = "../../sealed-poison-do-not-touch.parquet"
        model_test = {
            "status": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_resolution_or_hash_reads": 0,
        }
        dataset_manifest = {
            "task": audit.TASK,
            "status": "complete",
            "model_feature_columns": feature_names,
            "training_parts": [train_part["path"]],
            "validation_parts": [validation_part["path"]],
            "test_partition": {
                "status": "sealed",
                "parts": [sealed_path],
            },
        }
        base_contract = json.loads(
            (ROOT / audit.DEFAULT_CONTRACT).read_text(encoding="utf-8")
        )
        v1_classes = base_contract["architecture"]["current_v1"]["class_order"]
        model_manifest = {
            "inputs": {"allowed_parts": [train_part, validation_part]},
            "labels": {"class_order": v1_classes},
            "test_partition": model_test,
        }
        bundle_manifest = {
            "class_order": v1_classes,
            "selected_feature_indices": list(range(54)),
            "selected_threshold": 0.9984837643022101,
            "test_partition": model_test,
        }
        references = {
            "source_plan": write_bytes(root, "plan-2.md", b"locked plan\n"),
            "feature_schema": write_json(
                root, "config/terminal-flow-feature-schema-v1.json", schema
            ),
            "dataset_manifest": write_json(
                root, "run_log/full-flow-v1/dataset/manifest.json", dataset_manifest
            ),
            "model_manifest_v1": write_json(
                root, "run_log/full-flow-v1/model/manifest.json", model_manifest
            ),
            "bundle_manifest_v1": write_json(
                root,
                "run_log/full-flow-v1/model/terminal-flow.bundle/manifest.json",
                bundle_manifest,
            ),
        }
        contract = copy.deepcopy(base_contract)
        contract["source_plan"] = {
            "path": references["source_plan"]["path"],
            "sha256": references["source_plan"]["sha256"],
        }
        for key in (
            "feature_schema",
            "dataset_manifest",
            "model_manifest_v1",
            "bundle_manifest_v1",
        ):
            contract["inputs"][key] = {
                "path": references[key]["path"],
                "sha256": references[key]["sha256"],
            }
        contract["inputs"]["diagnostic_attempt"] = {
            "path": "run_log/full-flow-v1/live/ftp-patator/unit",
            "attempt_id": "unit",
            "run_contract_sha256": "0" * 64,
            "usage": "audit_only_never_training_holdout_or_acceptance",
        }
        contract_path = root / audit.DEFAULT_CONTRACT
        write_json(root, audit.DEFAULT_CONTRACT, contract)
        return contract_path, root / sealed_path

    def verify_fixture_inputs(self, root: Path, contract_path: Path) -> audit.AuditInputs:
        with mock.patch.object(audit, "verify_runtime", return_value=None):
            return audit.verify_inputs(root, contract_path)

    def test_cli_has_no_arbitrary_input_and_validates_locked_receipt(self) -> None:
        script = (ROOT / "scripts" / "audit_t91_model_v2.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("--input", script)
        self.assertIn(
            "audit.validate_receipt(inputs, audit.audit_receipt_path(inputs))",
            script,
        )

    def test_contract_rejects_taxonomy_profile_path_or_revision_drift(self) -> None:
        contract = json.loads((ROOT / audit.DEFAULT_CONTRACT).read_text("utf-8"))
        audit.verify_contract(contract)
        for mutate in (
            lambda value: value["architecture"]["binary_head"]["class_order"].reverse(),
            lambda value: value["feature_policy"]["candidate_profiles"][0][
                "feature_indices"
            ].append(34),
            lambda value: value["test_partition"]["forbidden_operations"].remove(
                "hash_test_part"
            ),
            lambda value: value.__setitem__("audit_revision", "r1"),
            lambda value: value["audit_policy"].__setitem__(
                "reference_column_binding", "name_selection"
            ),
            lambda value: value["outputs"].__setitem__(
                "audit_receipt", "run_log/full-flow-v2/audit/stale.json"
            ),
        ):
            candidate = copy.deepcopy(contract)
            mutate(candidate)
            with self.assertRaisesRegex(ValueError, "contract"):
                audit.verify_contract(candidate)

    def test_reference_batch_uses_exact_physical_feature_suffix(self) -> None:
        root = temporary_workspace(self)
        contract_path, _ = self.make_workspace(root)
        inputs = self.verify_fixture_inputs(root, contract_path)
        with pq.ParquetFile(inputs.parts[0].path) as parquet:
            batch = next(parquet.iter_batches(batch_size=2))
        prefix = batch.schema.names[: -audit.FEATURE_COUNT]
        self.assertEqual(2, batch.schema.names.count("packet_count"))
        self.assertEqual(1, prefix.count("packet_count"))

        assigned, families, features = audit.decode_reference_batch(
            batch, inputs.feature_names, "train"
        )
        self.assertEqual(["BENIGN", "FTP-Patator"], assigned.tolist())
        self.assertEqual(["Benign", "FTP-Bruteforce"], families.tolist())
        self.assertEqual([2.0, 3.0], features[:, 30].tolist())
        self.assertEqual([0.0, 1.0], features[:, 31].tolist())
        self.assertEqual([64_240.0, 8_192.0], features[:, 34].tolist())
        self.assertEqual([64.0, 64.0], features[:, 38].tolist())
        self.assertEqual([6.0, 6.0], features[:, 54].tolist())
        self.assertEqual([64.0, 64.0], features[:, 55].tolist())
        self.assertEqual([0.0, 0.0], features[:, 66].tolist())
        self.assertEqual([1.0, 1.0], features[:, 67].tolist())

        columns = [batch.column(index) for index in range(batch.num_columns)]
        packet_index = prefix.index("packet_count")
        columns[packet_index] = pa.array([99, 99])
        mismatched = pa.RecordBatch.from_arrays(
            columns, names=batch.schema.names
        )
        with self.assertRaisesRegex(ValueError, "semantics"):
            audit.decode_reference_batch(
                mismatched, inputs.feature_names, "train"
            )

        reordered_names = list(batch.schema.names)
        feature_start = batch.num_columns - audit.FEATURE_COUNT
        reordered_names[feature_start + 30], reordered_names[feature_start + 31] = (
            reordered_names[feature_start + 31],
            reordered_names[feature_start + 30],
        )
        reordered = pa.RecordBatch.from_arrays(
            [batch.column(index) for index in range(batch.num_columns)],
            names=reordered_names,
        )
        with self.assertRaisesRegex(ValueError, "physical feature suffix"):
            audit.decode_reference_batch(
                reordered, inputs.feature_names, "train"
            )

    def test_verify_inputs_rejects_alternate_contract_before_load(self) -> None:
        root = temporary_workspace(self)
        contract_path, _ = self.make_workspace(root)
        alternate = contract_path.with_name("alternate.json")
        with mock.patch.object(audit, "load_json") as load_json:
            with self.assertRaisesRegex(ValueError, "locked"):
                audit.verify_inputs(root, alternate)
        load_json.assert_not_called()

    def test_write_json_new_refuses_overwrite_without_replacing(self) -> None:
        root = temporary_workspace(self)
        path = root / "receipt.json"
        audit.write_json_new(path, {"first": True})
        with self.assertRaises(FileExistsError):
            audit.write_json_new(path, {"second": True})
        self.assertEqual({"first": True}, json.loads(path.read_text("utf-8")))

    def test_windows_post_status_is_create_new_and_strictly_validated(self) -> None:
        script = (ROOT / "scripts" / "windows_t91_live_target.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[IO.FileMode]::CreateNew", script)
        for required in (
            'operation = "status"',
            'role = "windows"',
            "scenario_label = $contract.scenario_label",
            "expected_model_family = $contract.expected_model_family",
            "observed_at_utc = [DateTimeOffset]::UtcNow.ToString",
            'Test-ObjectProperty -Object $existingPostStatus -Name "facts"',
            "[string]$existingPostStatus.operation -cne \"status\"",
            "[bool]$existingPostStatus.ready",
            "[string]$existingPostStatus.facts.status -cne \"rolled_back\"",
            "$existingPostStatus.facts.rollback_receipt_valid -isnot [bool]",
            "[bool]$existingPostStatus.facts.deadline_overrun",
        ):
            self.assertIn(required, script)

    def test_verify_inputs_does_not_resolve_sealed_test_part(self) -> None:
        root = temporary_workspace(self)
        contract_path, sealed_path = self.make_workspace(root)
        observed: list[str] = []
        real_resolve = audit.resolve_inside

        def spy_resolve(project_root: Path, value: str) -> Path:
            observed.append(str(value))
            self.assertNotEqual(str(sealed_path), str(value))
            self.assertNotIn("sealed-poison-do-not-touch", str(value))
            return real_resolve(project_root, value)

        with mock.patch.object(audit, "resolve_inside", side_effect=spy_resolve):
            inputs = self.verify_fixture_inputs(root, contract_path)
        self.assertEqual(2, len(inputs.parts))
        self.assertFalse(
            any("sealed-poison-do-not-touch" in value for value in observed)
        )

    def test_allowed_part_records_rejects_partial_allowlist(self) -> None:
        valid = {
            "partition": "train",
            "path": "run_log/full-flow-v1/dataset/train.parquet",
            "rows": 1,
            "sha256": "0" * 64,
            "size_bytes": 1,
        }
        with self.assertRaisesRegex(ValueError, "allowlist"):
            audit.allowed_part_records([], [valid["path"]], [], [])
        with self.assertRaisesRegex(ValueError, "allowlist"):
            audit.allowed_part_records(
                [{**valid, "unexpected": True}],
                [valid["path"]],
                [],
                [],
            )
        with self.assertRaisesRegex(ValueError, "allowlist"):
            audit.allowed_part_records(
                [{**valid, "rows": "1"}],
                [valid["path"]],
                [],
                [],
            )

    def test_validate_rejects_non_locked_receipt_path_before_load(self) -> None:
        root = temporary_workspace(self)
        contract_path, _ = self.make_workspace(root)
        inputs = self.verify_fixture_inputs(root, contract_path)
        with mock.patch.object(audit, "load_json") as load_json:
            with self.assertRaisesRegex(ValueError, "contract-locked"):
                audit.validate_receipt(
                    inputs,
                    root / str(audit.SUPERSEDED_AUDIT["receipt_path"]),
                )
        load_json.assert_not_called()

    def test_validate_rejects_source_allowlist_before_source_filesystem(self) -> None:
        root = temporary_workspace(self)
        contract_path, _ = self.make_workspace(root)
        inputs = self.verify_fixture_inputs(root, contract_path)
        receipt_path = audit.audit_receipt_path(inputs)
        write_json(
            root,
            receipt_path.relative_to(root).as_posix(),
            {
                "schema_version": audit.AUDIT_RECEIPT_SCHEMA_VERSION,
                "audit_revision": audit.AUDIT_REVISION,
                "supersedes": audit.SUPERSEDED_AUDIT,
                "generated_at_utc": "2026-07-29T00:00:00Z",
                "task": audit.TASK,
                "kind": "terminal_flow_model_v2_audit",
                "status": "passed",
                "contract": {
                    "path": audit.relative(inputs.contract_path, inputs.root),
                    "sha256": audit.sha256_path(inputs.contract_path),
                },
                "source_files": {"not-allowed.py": "0" * 64},
                "inputs": inputs.input_records,
                "gate": {
                    "training_authorized": False,
                    "test_partition_may_be_opened": False,
                },
                "partition_policy": {
                    "test": inputs.input_records["sealed_test_guard"]
                },
            },
        )
        real_resolve = audit.resolve_inside

        def spy_resolve(project_root: Path, value: str) -> Path:
            self.assertNotIn(str(value), audit.SOURCE_FILES)
            self.assertNotEqual("not-allowed.py", str(value))
            return real_resolve(project_root, value)

        with mock.patch.object(audit, "resolve_inside", side_effect=spy_resolve):
            with self.assertRaisesRegex(ValueError, "receipt"):
                audit.validate_receipt(inputs, receipt_path)


if __name__ == "__main__":
    unittest.main()
