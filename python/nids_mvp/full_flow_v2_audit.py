"""Core audit logic for the T9.1 Model V2 training boundary."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq


TASK = "T9.1"
PYARROW_VERSION = "23.0.1"
NUMPY_VERSION = "2.2.5"
FEATURE_COUNT = 70
DEFAULT_CONTRACT = "config/terminal-flow-model-v2-audit-contract.json"
AUDIT_CONTRACT_SCHEMA_VERSION = "1.1.0"
AUDIT_RECEIPT_SCHEMA_VERSION = "1.1.0"
AUDIT_REVISION = "r2_physical_feature_suffix"
AUDIT_OUTPUTS = {
    "root": "run_log/full-flow-v1/model-v2",
    "audit_receipt": (
        "run_log/full-flow-v1/model-v2/audit/model-v2-audit-r2.json"
    ),
}
SUPERSEDED_AUDIT = {
    "status": "invalid_reference_column_alignment",
    "receipt_path": "run_log/full-flow-v2/audit/model-v2-audit.json",
    "receipt_sha256": (
        "925684b21a9fd83c5d9b200d22035f749327eb83f83a59d49972dadf3dfa0736"
    ),
    "contract_sha256": (
        "129720c1667e9a49976913c06346c8e725ce2f602d0f00b4b3c139f3e6d56572"
    ),
    "reuse_allowed": False,
}
SOURCE_FILES = (
    "python/nids_mvp/full_flow_v2_audit.py",
    "scripts/audit_t91_model_v2.py",
    "scripts/windows_t91_live_target.ps1",
    "tests/test_t91_model_v2_audit.py",
)
V1_CLASS_ORDER = (
    "Benign",
    "FTP-Bruteforce",
    "SSH-Bruteforce",
    "PortScan",
    "DoS",
    "Other",
)
V2_BINARY_CLASS_ORDER = ("Benign", "Attack")
V2_ATTACK_FAMILY_CLASS_ORDER = (
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "FTP-Patator",
    "Infiltration",
    "PortScan",
    "SSH-Patator",
    "Web Attack \u2013 Brute Force",
    "Web Attack \u2013 Sql Injection",
    "Web Attack \u2013 XSS",
)
V2_ALGORITHM_CANDIDATES = ("lightgbm", "hist_gradient_boosting", "sgd_log_loss")
V2_EXCLUDED_GROUPS = {
    "tcp_window": (34, 35, 36, 37),
    "aggregate_ttl": (38, 39, 40, 41),
    "directional_ttl": (55, 56),
    "first_observed_ports": (64, 65),
}
V2_PROFILES = (
    {
        "id": "V2A",
        "name": "stable_terminal_traffic",
        "feature_indices": (
            *range(0, 34),
            *range(42, 55),
            *range(57, 61),
        ),
    },
    {
        "id": "V2B",
        "name": "stable_terminal_context",
        "feature_indices": (
            *range(0, 34),
            *range(42, 55),
            *range(57, 64),
        ),
    },
    {
        "id": "V2C",
        "name": "stable_terminal_context_lifecycle",
        "feature_indices": (
            *range(0, 34),
            *range(42, 55),
            *range(57, 64),
            *range(66, 70),
        ),
    },
)
V2_DISTRIBUTION_AUDIT_INDICES = (
    1,
    30,
    31,
    *range(34, 42),
    *range(54, 64),
    *range(66, 70),
)
SEALED_TEST_FORBIDDEN_OPERATIONS = (
    "resolve_test_part_path",
    "stat_test_part",
    "hash_test_part",
    "open_test_part",
    "read_test_features_or_labels",
)
REFERENCE_METADATA_COLUMNS = (
    "partition",
    "label_status",
    "assigned_class",
    "label_family",
    "protocol",
    "packet_count",
    "forward_packet_count",
    "reverse_packet_count",
)


@dataclass(frozen=True)
class VerifiedPart:
    path: Path
    relative_path: str
    partition: str
    rows: int
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class AuditInputs:
    root: Path
    contract_path: Path
    contract: Mapping[str, Any]
    feature_names: tuple[str, ...]
    dataset_manifest: Mapping[str, Any]
    model_manifest: Mapping[str, Any]
    bundle_manifest: Mapping[str, Any]
    parts: tuple[VerifiedPart, ...]
    input_records: Mapping[str, Any]


class VectorStats:
    def __init__(self, width: int) -> None:
        self.count = 0
        self.mean = np.zeros(width, dtype=np.float64)
        self.m2 = np.zeros(width, dtype=np.float64)
        self.minimum = np.full(width, np.inf, dtype=np.float64)
        self.maximum = np.full(width, -np.inf, dtype=np.float64)

    def update(self, values: np.ndarray) -> None:
        if values.ndim != 2 or values.shape[1] != len(self.mean):
            raise ValueError("invalid feature batch shape")
        if not len(values):
            return
        if not np.isfinite(values).all():
            raise ValueError("non-finite reference feature")
        batch_count = len(values)
        batch_mean = values.mean(axis=0)
        centered = values - batch_mean
        batch_m2 = np.square(centered).sum(axis=0)
        if self.count:
            delta = batch_mean - self.mean
            total = self.count + batch_count
            self.m2 += batch_m2 + np.square(delta) * self.count * batch_count / total
            self.mean += delta * batch_count / total
            self.count = total
        else:
            self.count = batch_count
            self.mean = batch_mean
            self.m2 = batch_m2
        self.minimum = np.minimum(self.minimum, values.min(axis=0))
        self.maximum = np.maximum(self.maximum, values.max(axis=0))

    def record(self, names: Sequence[str]) -> dict[str, Any]:
        if self.count < 1:
            raise ValueError("empty reference cohort")
        standard_deviation = np.sqrt(self.m2 / self.count)
        return {
            name: {
                "count": self.count,
                "minimum": float(self.minimum[index]),
                "maximum": float(self.maximum[index]),
                "mean": float(self.mean[index]),
                "standard_deviation": float(standard_deviation[index]),
            }
            for index, name in enumerate(names)
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def resolve_inside(root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"path escapes project root: {value}") from error
    return resolved


def relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def write_json_new(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(
                value,
                output,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise FileExistsError(f"JSON receipt already exists: {path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def verify_runtime(contract: Mapping[str, Any]) -> None:
    runtime = contract.get("runtime", {})
    observed_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if (
        os.name != "nt"
        or runtime.get("host") != "windows_native"
        or runtime.get("python_major_minor") != observed_python
        or runtime.get("numpy_exact_version") != NUMPY_VERSION
        or runtime.get("pyarrow_exact_version") != PYARROW_VERSION
        or np.__version__ != NUMPY_VERSION
        or pa.__version__ != PYARROW_VERSION
    ):
        raise RuntimeError("T9.1 Model V2 audit runtime mismatch")


def verified_reference(
    root: Path, record: Mapping[str, Any], label: str
) -> tuple[Path, dict[str, Any]]:
    path = resolve_inside(root, str(record.get("path", "")))
    expected_hash = record.get("sha256")
    if not path.is_file() or not is_sha256(expected_hash):
        raise ValueError(f"{label} reference is invalid")
    observed_hash = sha256_path(path)
    if observed_hash != expected_hash:
        raise ValueError(f"{label} content address mismatch")
    return path, {
        "path": relative(path, root),
        "size_bytes": path.stat().st_size,
        "sha256": observed_hash,
    }


def feature_names(schema: Mapping[str, Any]) -> tuple[str, ...]:
    features = schema.get("features")
    if not isinstance(features, list) or len(features) != FEATURE_COUNT:
        raise ValueError("terminal feature schema must contain 70 features")
    names: list[str] = []
    for index, record in enumerate(features):
        if (
            not isinstance(record, Mapping)
            or record.get("index") != index
            or not isinstance(record.get("name"), str)
        ):
            raise ValueError("terminal feature schema ordering mismatch")
        names.append(str(record["name"]))
    return tuple(names)


def physical_feature_start(
    schema_names: Sequence[str], required_feature_names: Sequence[str]
) -> int:
    if (
        len(required_feature_names) != FEATURE_COUNT
        or len(schema_names) <= FEATURE_COUNT
    ):
        raise ValueError("reference Parquet physical feature suffix mismatch")
    feature_start = len(schema_names) - FEATURE_COUNT
    if tuple(schema_names[feature_start:]) != tuple(required_feature_names):
        raise ValueError("reference Parquet physical feature suffix mismatch")
    prefix = tuple(schema_names[:feature_start])
    if any(prefix.count(name) != 1 for name in REFERENCE_METADATA_COLUMNS):
        raise ValueError("reference Parquet metadata prefix mismatch")
    return feature_start


def decode_reference_batch(
    batch: pa.RecordBatch,
    required_feature_names: Sequence[str],
    expected_partition: str,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    feature_start = physical_feature_start(
        batch.schema.names, required_feature_names
    )
    prefix = tuple(batch.schema.names[:feature_start])
    metadata_indices = {
        name: prefix.index(name) for name in REFERENCE_METADATA_COLUMNS
    }
    partitions = batch.column(metadata_indices["partition"]).to_pylist()
    statuses = batch.column(metadata_indices["label_status"]).to_pylist()
    assigned = np.asarray(
        batch.column(metadata_indices["assigned_class"]).to_pylist(),
        dtype=object,
    )
    families = np.asarray(
        batch.column(metadata_indices["label_family"]).to_pylist(),
        dtype=object,
    )
    if (
        any(value != expected_partition for value in partitions)
        or any(value != "assigned" for value in statuses)
        or any(value is None for value in assigned)
        or any(value is None for value in families)
    ):
        raise ValueError(f"reference metadata drift: {expected_partition}")
    try:
        features = np.column_stack(
            [
                batch.column(feature_start + index).to_numpy(
                    zero_copy_only=False
                )
                for index in range(FEATURE_COUNT)
            ]
        ).astype(np.float64, copy=False)
        metadata_protocol = np.asarray(
            batch.column(metadata_indices["protocol"]).to_numpy(
                zero_copy_only=False
            ),
            dtype=np.float64,
        )
        metadata_packet_count = np.asarray(
            batch.column(metadata_indices["packet_count"]).to_numpy(
                zero_copy_only=False
            ),
            dtype=np.float64,
        )
        metadata_forward_count = np.asarray(
            batch.column(metadata_indices["forward_packet_count"]).to_numpy(
                zero_copy_only=False
            ),
            dtype=np.float64,
        )
        metadata_reverse_count = np.asarray(
            batch.column(metadata_indices["reverse_packet_count"]).to_numpy(
                zero_copy_only=False
            ),
            dtype=np.float64,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"reference numeric column mismatch: {expected_partition}"
        ) from error
    if (
        features.shape != (len(batch), FEATURE_COUNT)
        or not np.isfinite(features).all()
        or not np.isfinite(metadata_protocol).all()
        or not np.isfinite(metadata_packet_count).all()
        or not np.isfinite(metadata_forward_count).all()
        or not np.isfinite(metadata_reverse_count).all()
    ):
        raise ValueError(f"non-finite reference feature: {expected_partition}")

    packet_count = features[:, 1]
    forward_count = features[:, 2]
    reverse_count = features[:, 3]
    protocol = features[:, 54]
    tcp_close_counts = features[:, (30, 31)]
    windows = features[:, 34:38]
    ttl = features[:, (38, 39, 40, 41, 55, 56)]
    lifecycle = features[:, 66:70]
    if (
        not np.array_equal(metadata_packet_count, packet_count)
        or not np.array_equal(metadata_forward_count, forward_count)
        or not np.array_equal(metadata_reverse_count, reverse_count)
        or not np.array_equal(metadata_protocol, protocol)
        or not np.array_equal(packet_count, forward_count + reverse_count)
        or np.any(packet_count < 1)
        or np.any(packet_count != np.floor(packet_count))
        or np.any(tcp_close_counts < 0)
        or np.any(tcp_close_counts > packet_count[:, None])
        or np.any((windows < 0) | (windows > 65_535))
        or np.any((ttl < 0) | (ttl > 255))
        or not np.isin(protocol, (6.0, 17.0)).all()
        or not np.isin(lifecycle, (0.0, 1.0)).all()
        or not np.all(lifecycle.sum(axis=1) == 1.0)
    ):
        raise ValueError(
            f"reference feature semantics drift: {expected_partition}"
        )
    return assigned, families, features


def verify_contract(contract: Mapping[str, Any]) -> None:
    architecture = contract.get("architecture", {})
    binary = architecture.get("binary_head", {})
    family = architecture.get("attack_family_head", {})
    feature_policy = contract.get("feature_policy", {})
    profiles = feature_policy.get("candidate_profiles")
    expected_profiles = [
        {
            "id": profile["id"],
            "name": profile["name"],
            "feature_indices": list(profile["feature_indices"]),
        }
        for profile in V2_PROFILES
    ]
    expected_excluded_groups = {
        key: list(values) for key, values in V2_EXCLUDED_GROUPS.items()
    }
    test_partition = contract.get("test_partition", {})
    if (
        contract.get("schema_version") != AUDIT_CONTRACT_SCHEMA_VERSION
        or contract.get("audit_revision") != AUDIT_REVISION
        or contract.get("supersedes") != SUPERSEDED_AUDIT
        or contract.get("task") != TASK
        or contract.get("kind") != "terminal_flow_model_v2_audit_contract"
        or contract.get("status") != "locked"
        or architecture.get("required") != "binary_head_plus_attack_family_head"
        or binary.get("class_order") != list(V2_BINARY_CLASS_ORDER)
        or family.get("source_column") != "assigned_class"
        or family.get("benign_source_value") != "BENIGN"
        or family.get("class_order") != list(V2_ATTACK_FAMILY_CLASS_ORDER)
        or family.get("unavailable") != ["Heartbleed"]
        or architecture.get("algorithm_candidates") != list(V2_ALGORITHM_CANDIDATES)
        or architecture.get("current_v1", {}).get("class_order")
        != list(V1_CLASS_ORDER)
        or architecture.get("current_v1", {}).get("accepted_as_v2") is not False
        or architecture.get("expected_pair_count")
        != len(V2_ALGORITHM_CANDIDATES) ** 2
        or architecture.get("evaluate_all_binary_family_pairs") is not True
        or feature_policy.get("schema_feature_count") != FEATURE_COUNT
        or feature_policy.get("excluded_groups") != expected_excluded_groups
        or profiles != expected_profiles
        or feature_policy.get("distribution_audit_indices")
        != list(V2_DISTRIBUTION_AUDIT_INDICES)
        or test_partition.get("status") != "sealed"
        or test_partition.get("allowed_operations")
        != ["read_manifest_path_strings_only"]
        or test_partition.get("forbidden_operations")
        != list(SEALED_TEST_FORBIDDEN_OPERATIONS)
        or contract.get("audit_policy", {}).get("reference_partitions")
        != ["train", "validation"]
        or contract.get("audit_policy", {}).get("reference_column_binding")
        != "physical_suffix_exact_70"
        or contract.get("audit_policy", {}).get("domain_shift_conclusion")
        != "inconclusive_without_same_traffic_offline_replay"
        or contract.get("outputs") != AUDIT_OUTPUTS
    ):
        raise ValueError("Model V2 audit contract mismatch")
    previous: set[int] = set()
    excluded = {
        index for values in V2_EXCLUDED_GROUPS.values() for index in values
    }
    for profile in expected_profiles:
        indices = profile.get("feature_indices")
        if (
            not isinstance(indices, list)
            or indices != sorted(set(indices))
            or any(
                not isinstance(index, int)
                or not 0 <= index < FEATURE_COUNT
                for index in indices
            )
            or set(indices) & excluded
            or not previous.issubset(indices)
        ):
            raise ValueError(f"invalid Model V2 feature profile: {profile.get('id')}")
        previous = set(indices)
    if contract.get("live_data_policy", {}).get("diagnostic_attempt_reuse") is not False:
        raise ValueError("diagnostic attempt reuse must remain forbidden")


def allowed_part_records(
    allowed_parts: Sequence[Any],
    training_paths: Sequence[Any],
    validation_paths: Sequence[Any],
    sealed_paths: Sequence[str],
) -> tuple[dict[str, Any], ...]:
    expected_paths = [*training_paths, *validation_paths]
    expected_partitions = [
        *(["train"] * len(training_paths)),
        *(["validation"] * len(validation_paths)),
    ]
    if (
        len(allowed_parts) != len(expected_paths)
        or any(not isinstance(value, str) for value in expected_paths)
        or len(set(expected_paths)) != len(expected_paths)
        or set(expected_paths) & set(sealed_paths)
    ):
        raise ValueError("train/validation allowlist mismatch")
    records: list[dict[str, Any]] = []
    for index, record in enumerate(allowed_parts):
        if (
            not isinstance(record, Mapping)
            or set(record) != {"partition", "path", "rows", "sha256", "size_bytes"}
            or record.get("partition") != expected_partitions[index]
            or record.get("path") != expected_paths[index]
            or not isinstance(record.get("rows"), int)
            or record.get("rows") < 1
            or not isinstance(record.get("size_bytes"), int)
            or record.get("size_bytes") < 1
            or not is_sha256(record.get("sha256"))
        ):
            raise ValueError("train/validation allowlist mismatch")
        records.append(
            {
                "partition": record["partition"],
                "path": record["path"],
                "rows": record["rows"],
                "sha256": record["sha256"],
                "size_bytes": record["size_bytes"],
            }
        )
    return tuple(records)


def verify_part(
    root: Path,
    record: Mapping[str, Any],
    expected_path: str,
    required_feature_names: Sequence[str],
) -> VerifiedPart:
    partition = record.get("partition")
    if partition not in {"train", "validation"} or record.get("path") != expected_path:
        raise ValueError("non-allowed dataset part reached verifier")
    path = resolve_inside(root, expected_path)
    rows = record.get("rows")
    size_bytes = record.get("size_bytes")
    expected_hash = record.get("sha256")
    if (
        not isinstance(rows, int)
        or rows < 1
        or not isinstance(size_bytes, int)
        or size_bytes < 1
        or not is_sha256(expected_hash)
        or not path.is_file()
        or path.stat().st_size != size_bytes
        or sha256_path(path) != expected_hash
    ):
        raise ValueError(f"dataset part content mismatch: {expected_path}")
    with pq.ParquetFile(path) as parquet:
        if parquet.metadata.num_rows != rows:
            raise ValueError(f"dataset part row count mismatch: {expected_path}")
        try:
            physical_feature_start(
                parquet.schema_arrow.names, required_feature_names
            )
        except ValueError as error:
            raise ValueError(
                f"dataset part schema mismatch: {expected_path}"
            ) from error
    return VerifiedPart(
        path=path,
        relative_path=expected_path,
        partition=str(partition),
        rows=rows,
        size_bytes=size_bytes,
        sha256=str(expected_hash),
    )


def verify_inputs(root: Path, contract_path: Path) -> AuditInputs:
    root = root.resolve()
    contract_path = resolve_inside(root, str(contract_path))
    expected_contract_path = resolve_inside(root, DEFAULT_CONTRACT)
    if contract_path != expected_contract_path:
        raise ValueError("only the locked Model V2 audit contract may be used")
    contract = load_json(contract_path)
    verify_contract(contract)
    verify_runtime(contract)
    records: dict[str, Any] = {}
    plan_path, records["source_plan"] = verified_reference(
        root, contract["source_plan"], "source plan"
    )
    if plan_path.name != "plan-2.md":
        raise ValueError("unexpected source plan")
    input_contract = contract["inputs"]
    schema_path, records["feature_schema"] = verified_reference(
        root, input_contract["feature_schema"], "feature schema"
    )
    dataset_path, records["dataset_manifest"] = verified_reference(
        root, input_contract["dataset_manifest"], "dataset manifest"
    )
    model_path, records["model_manifest_v1"] = verified_reference(
        root, input_contract["model_manifest_v1"], "model manifest"
    )
    bundle_path, records["bundle_manifest_v1"] = verified_reference(
        root, input_contract["bundle_manifest_v1"], "bundle manifest"
    )
    schema = load_json(schema_path)
    names = feature_names(schema)
    dataset_manifest = load_json(dataset_path)
    model_manifest = load_json(model_path)
    bundle_manifest = load_json(bundle_path)
    test_record = dataset_manifest.get("test_partition", {})
    model_test = model_manifest.get("test_partition", {})
    allowed_parts = model_manifest.get("inputs", {}).get("allowed_parts")
    training_paths = dataset_manifest.get("training_parts")
    validation_paths = dataset_manifest.get("validation_parts")
    sealed_paths = test_record.get("parts")
    if (
        dataset_manifest.get("task") != TASK
        or dataset_manifest.get("status") != "complete"
        or dataset_manifest.get("model_feature_columns") != list(names)
        or test_record.get("status") != "sealed"
        or not isinstance(sealed_paths, list)
        or any(not isinstance(value, str) for value in sealed_paths)
        or model_test
        != {
            "status": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_resolution_or_hash_reads": 0,
        }
        or not isinstance(allowed_parts, list)
        or not isinstance(training_paths, list)
        or not isinstance(validation_paths, list)
    ):
        raise ValueError("sealed dataset/model manifest mismatch")
    allowed_records = allowed_part_records(
        allowed_parts,
        training_paths,
        validation_paths,
        sealed_paths,
    )
    parts = tuple(
        verify_part(root, record, str(record["path"]), names)
        for record in allowed_records
    )
    expected_v1_classes = contract["architecture"]["current_v1"]["class_order"]
    if (
        model_manifest.get("labels", {}).get("class_order") != expected_v1_classes
        or bundle_manifest.get("class_order") != expected_v1_classes
        or bundle_manifest.get("selected_feature_indices") != list(range(54))
        or bundle_manifest.get("test_partition") != model_test
    ):
        raise ValueError("current V1 model/bundle contract drift")
    records["allowed_parts"] = [
        {
            "path": part.relative_path,
            "partition": part.partition,
            "rows": part.rows,
            "size_bytes": part.size_bytes,
            "sha256": part.sha256,
        }
        for part in parts
    ]
    records["sealed_test_guard"] = {
        "status": "sealed",
        "manifest_path_strings_observed": len(sealed_paths),
        "feature_reads": 0,
        "metric_reads": 0,
        "parquet_metadata_reads": 0,
        "path_resolution_or_hash_reads": 0,
    }
    return AuditInputs(
        root=root,
        contract_path=contract_path,
        contract=contract,
        feature_names=names,
        dataset_manifest=dataset_manifest,
        model_manifest=model_manifest,
        bundle_manifest=bundle_manifest,
        parts=parts,
        input_records=records,
    )


def require_identity(
    document: Mapping[str, Any], attempt_id: str, run_token: str, label: str
) -> None:
    if (
        document.get("attempt_id") != attempt_id
        or document.get("run_token") != run_token
    ):
        raise ValueError(f"{label} attempt identity mismatch")


def bundle_member_sha256(bundle_manifest: Mapping[str, Any], member_path: str) -> str:
    members = bundle_manifest.get("members")
    if not isinstance(members, list):
        raise ValueError("bundle manifest members missing")
    matches = [
        member.get("sha256")
        for member in members
        if isinstance(member, Mapping) and member.get("path") == member_path
    ]
    if len(matches) != 1 or not is_sha256(matches[0]):
        raise ValueError(f"bundle member hash missing: {member_path}")
    return str(matches[0])


def audit_live_attempt(inputs: AuditInputs) -> tuple[dict[str, Any], np.ndarray]:
    attempt_record = inputs.contract["inputs"]["diagnostic_attempt"]
    attempt_root = resolve_inside(inputs.root, str(attempt_record["path"]))
    live_contract_path = attempt_root / "contract.json"
    if (
        not live_contract_path.is_file()
        or sha256_path(live_contract_path)
        != attempt_record["run_contract_sha256"]
    ):
        raise ValueError("diagnostic run contract mismatch")
    live_contract = load_json(live_contract_path)
    attempt_id = str(live_contract.get("attempt_id"))
    run_token = str(live_contract.get("run_token"))
    contract_hash = sha256_path(live_contract_path)
    if (
        attempt_id != attempt_record["attempt_id"]
        or live_contract.get("schema_version") != "2.0.0"
        or live_contract.get("scenario_label") != "FTP-Patator"
        or live_contract.get("expected_model_family") != "FTP-Bruteforce"
    ):
        raise ValueError("diagnostic run contract semantics mismatch")
    bundle_manifest_hash = inputs.input_records["bundle_manifest_v1"]["sha256"]
    selected_threshold = float(inputs.bundle_manifest["selected_threshold"])
    expected_artifact = {
        "artifact_id": inputs.bundle_manifest["artifact_id"],
        "artifact_version": inputs.bundle_manifest["artifact_version"],
        "bundle_manifest_sha256": bundle_manifest_hash,
        "feature_schema_id": inputs.bundle_manifest["feature_schema_id"],
        "feature_schema_sha256": bundle_member_sha256(
            inputs.bundle_manifest, "feature_schema.json"
        ),
        "model_sha256": bundle_member_sha256(
            inputs.bundle_manifest, "models/terminal_multiclass.onnx"
        ),
        "profile_id": inputs.bundle_manifest["selected_profile"],
    }

    artifacts: dict[str, Any] = {
        "contract": {
            "path": relative(live_contract_path, inputs.root),
            "sha256": contract_hash,
        }
    }

    def artifact(name: str, relative_name: str) -> Path:
        path = attempt_root / relative_name
        if not path.is_file():
            raise ValueError(f"missing live artifact: {relative_name}")
        artifacts[name] = {
            "path": relative(path, inputs.root),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_path(path),
        }
        return path

    sender_path = artifact("sender_receipt", "kali/sender.json")
    sender_log_path = artifact("sender_log", "kali/sender.log")
    sensor_path = artifact("sensor_receipt", "ubuntu/sensor.json")
    sensor_log_path = artifact("sensor_log", "ubuntu/sensor.jsonl")
    summary_path = artifact("summary", "ubuntu/summary.json")
    ubuntu_state_path = artifact("ubuntu_state", "ubuntu/state.json")
    ubuntu_rollback_path = artifact("ubuntu_rollback", "ubuntu/rollback.json")
    windows_ready_path = artifact("windows_ready", "windows/ready.json")
    windows_rollback_path = artifact("windows_rollback", "windows/rollback.json")
    target_log_path = artifact("windows_target_log_unbound", "windows/target.log")

    sender = load_json(sender_path)
    sensor = load_json(sensor_path)
    summary = load_json(summary_path)
    windows_ready = load_json(windows_ready_path)
    windows_rollback = load_json(windows_rollback_path)
    ubuntu_state = load_json(ubuntu_state_path)
    ubuntu_rollback = load_json(ubuntu_rollback_path)
    for label, document in (
        ("sender", sender),
        ("sensor", sensor),
        ("summary", summary),
        ("Windows ready", windows_ready),
        ("Windows rollback", windows_rollback),
    ):
        require_identity(document, attempt_id, run_token, label)
    if (
        sender.get("status") != "passed"
        or sender.get("tool_return_code") != 0
        or sender.get("run_contract_sha256") != contract_hash
        or sender.get("log", {}).get("sha256") != artifacts["sender_log"]["sha256"]
        or sensor.get("status") != "passed"
        or sensor.get("sensor_return_code") != 0
        or sensor.get("run_contract_sha256") != contract_hash
        or sensor.get("sensor_log", {}).get("sha256")
        != artifacts["sensor_log"]["sha256"]
        or summary.get("run_contract_sha256") != contract_hash
        or windows_ready.get("contract_sha256") != contract_hash
        or live_contract.get("model", {}).get("bundle_manifest_sha256")
        != bundle_manifest_hash
        or live_contract.get("model", {}).get("feature_schema_id")
        != expected_artifact["feature_schema_id"]
        or live_contract.get("model", {}).get("bundle_directory")
        != Path(inputs.input_records["bundle_manifest_v1"]["path"]).parent.as_posix()
        or summary.get("artifact") != expected_artifact
    ):
        raise ValueError("live sender/sensor/ready hash binding mismatch")

    events: list[dict[str, Any]] = []
    with sensor_log_path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid sensor JSONL line {line_number}") from error
            if not isinstance(event, dict):
                raise ValueError(f"sensor JSONL line {line_number} is not an object")
            events.append(event)
    types = Counter(event.get("event_type") for event in events)
    decisions = [
        event for event in events if event.get("event_type") == "nids_terminal_flow_decision"
    ]
    if (
        types
        != {
            "nids_terminal_live_ready": 1,
            "nids_terminal_flow_decision": 20,
            "nids_terminal_live_summary": 1,
        }
        or events[-1] != summary
        or [event.get("decision_ordinal") for event in decisions]
        != list(range(1, 21))
    ):
        raise ValueError("live decision event sequence mismatch")

    vectors: list[list[float]] = []
    raw_counts: Counter[str] = Counter()
    gated_counts: Counter[str] = Counter()
    top_attack_counts: Counter[str] = Counter()
    gate_passed = 0
    packet_sum = 0
    ftp_probability_max = 0.0
    attack_score_max = 0.0
    for event in decisions:
        require_identity(event, attempt_id, run_token, "decision")
        values = event.get("features", {}).get("values")
        scores = event.get("scores", {})
        probabilities = scores.get("class_probabilities")
        class_order = scores.get("class_order")
        if (
            event.get("acceptance_eligible") is not True
            or event.get("artifact") != expected_artifact
            or event.get("run_contract_sha256") != contract_hash
            or event.get("close_reason") == "end_of_input"
            or not isinstance(values, list)
            or len(values) != 70
            or not all(isinstance(value, (int, float)) for value in values)
            or not all(math.isfinite(float(value)) for value in values)
            or class_order
            != inputs.contract["architecture"]["current_v1"]["class_order"]
            or not isinstance(probabilities, list)
            or len(probabilities) != len(class_order)
            or not all(math.isfinite(float(value)) for value in probabilities)
        ):
            raise ValueError("invalid live decision diagnostic")
        probability = np.asarray(probabilities, dtype=np.float64)
        raw_index = int(np.argmax(probability))
        attack_index = 1 + int(np.argmax(probability[1:]))
        raw = scores.get("raw_argmax", {})
        top_attack = scores.get("top_attack_candidate", {})
        gate = scores.get("attack_gate", {})
        gated = scores.get("gated_decision", {})
        attack_score = 1.0 - float(probability[0])
        gate_threshold = gate.get("threshold")
        if not isinstance(gate_threshold, (int, float)):
            raise ValueError("live decision gate threshold missing")
        threshold = float(gate_threshold)
        passed = attack_score >= selected_threshold
        expected_gated_index = attack_index if passed else 0
        expected_gated = class_order[expected_gated_index]
        if (
            raw.get("class_index") != raw_index
            or raw.get("class_name") != class_order[raw_index]
            or not math.isclose(
                float(raw.get("class_confidence")),
                float(probability[raw_index]),
                abs_tol=1e-7,
            )
            or top_attack.get("class_index") != attack_index
            or top_attack.get("class_name") != class_order[attack_index]
            or not math.isclose(
                float(top_attack.get("class_confidence")),
                float(probability[attack_index]),
                abs_tol=1e-7,
            )
            or not math.isclose(threshold, selected_threshold, abs_tol=1e-12)
            or gate.get("comparison") != ">="
            or gate.get("score_name") != "one_minus_benign_probability"
            or not math.isclose(
                float(gate.get("attack_score")), attack_score, abs_tol=1e-7
            )
            or gate.get("passed") is not passed
            or gated.get("class_index") != expected_gated_index
            or gated.get("class_name") != expected_gated
            or not math.isclose(
                float(gated.get("class_confidence")),
                float(probability[expected_gated_index]),
                abs_tol=1e-7,
            )
            or event.get("decision") != expected_gated
        ):
            raise ValueError("live decision score semantics mismatch")
        vectors.append([float(value) for value in values])
        raw_counts.update([str(raw["class_name"])])
        gated_counts.update([str(gated["class_name"])])
        top_attack_counts.update([str(top_attack["class_name"])])
        gate_passed += int(passed)
        packet_sum += int(event["packet_count"])
        ftp_probability_max = max(ftp_probability_max, float(probability[1]))
        attack_score_max = max(attack_score_max, attack_score)

    port_stats = summary.get("port_stats", {})
    errors = summary.get("errors", {})
    close_counts = summary.get("flows", {}).get("close_reason_count", {})
    if (
        summary.get("status") != "passed"
        or summary.get("artifact") != expected_artifact
        or summary.get("class_order") != list(V1_CLASS_ORDER)
        or not math.isclose(
            float(summary.get("attack_threshold")), selected_threshold, abs_tol=1e-12
        )
        or summary.get("terminal_flows") != 20
        or summary.get("non_eof_flows") != 20
        or summary.get("eof_flows") != 0
        or summary.get("decision_events") != 20
        or summary.get("inferences") != 20
        or summary.get("packets_seen") != 243
        or packet_sum != 243
        or close_counts.get("tcp_fin_handshake") != 20
        or summary.get("alerts") != 0
        or summary.get("eligible_alerts") != 0
        or any(int(port_stats.get(name, -1)) != 0 for name in ("imissed", "ierrors", "rx_nombuf", "opackets", "oerrors"))
        or any(int(value) != 0 for value in errors.values())
        or dict(raw_counts) != {"Benign": 20}
        or dict(gated_counts) != {"Benign": 20}
        or gate_passed != 0
    ):
        raise ValueError("live diagnostic summary/model-gate mismatch")

    required_windows_flags = (
        "firewall_rule_removed",
        "responder_task_removed",
        "responder_identity_stopped",
        "rollback_task_removed",
        "ftp_service_restored",
    )
    if (
        windows_ready.get("schema_version") != "1.0.0"
        or windows_ready.get("task") != TASK
        or windows_ready.get("kind") != "windows_target_ready"
        or windows_ready.get("status") != "ready"
        or windows_ready.get("source_ip")
        != live_contract.get("topology", {}).get("source_ip")
        or windows_ready.get("target_ip")
        != live_contract.get("topology", {}).get("target_ip")
        or windows_ready.get("firewall_remote_address")
        != windows_ready.get("source_ip")
        or windows_ready.get("firewall_local_ports")
        != live_contract.get("target", {}).get("firewall_tcp_ports")
        or windows_rollback.get("kind") != "windows_target_rollback"
        or windows_rollback.get("status") != "passed"
        or windows_rollback.get("schema_version") != "1.0.0"
        or windows_rollback.get("task") != TASK
        or windows_rollback.get("firewall_rule")
        != windows_ready.get("firewall_rule")
        or windows_rollback.get("responder_task")
        != windows_ready.get("responder_task")
        or windows_rollback.get("rollback_task")
        != windows_ready.get("rollback_task")
        or windows_rollback.get("ftp_service_restore_required") is not True
        or not all(windows_rollback.get(name) is True for name in required_windows_flags)
    ):
        raise ValueError("Windows rollback receipt mismatch")
    ubuntu_checks = ubuntu_rollback.get("checks")
    if (
        ubuntu_state.get("status") != "rolled_back"
        or ubuntu_rollback.get("status") != "passed"
        or not isinstance(ubuntu_checks, list)
        or any(item.get("status") != "passed" for item in ubuntu_checks)
        or ubuntu_rollback.get("state", {}).get("sha256")
        != artifacts["ubuntu_state"]["sha256"]
    ):
        raise ValueError("Ubuntu rollback receipt mismatch")

    sender_match = re.search(
        r"Hits/Done/Skip/Fail/Size:\s+0/20/0/0/20",
        sender_log_path.read_text(encoding="utf-8"),
    )
    target_lines = target_log_path.read_text(encoding="utf-8").splitlines()
    passwords = [line[5:] for line in target_lines if line.startswith("PASS ")]
    if (
        sender_match is None
        or len(passwords) != 20
        or len(set(passwords)) != 20
        or live_contract["target"]["ftp_valid_password"] in passwords
    ):
        raise ValueError("bounded FTP sender evidence mismatch")

    post_status_path = attempt_root / "windows/post-status.json"
    post_status = {
        "required_for_fresh_attempts": True,
        "present": post_status_path.is_file(),
        "historical_console_claim_promoted": False,
    }
    if post_status_path.is_file():
        artifacts["windows_post_status"] = {
            "path": relative(post_status_path, inputs.root),
            "size_bytes": post_status_path.stat().st_size,
            "sha256": sha256_path(post_status_path),
        }
        document = load_json(post_status_path)
        require_identity(document, attempt_id, run_token, "Windows post-status")
        if (
            document.get("kind") != "windows_target_post_status"
            or document.get("status") != "rolled_back"
            or document.get("safe") is not True
            or document.get("run_contract_sha256") != contract_hash
            or document.get("rollback_receipt_sha256")
            != artifacts["windows_rollback"]["sha256"]
        ):
            raise ValueError("Windows post-status receipt mismatch")

    limitations = [
        "Kali and Ubuntu wrapper source hashes were not bound by the run contract",
        "Ubuntu rollback receipt has no attempt_id, run_token, or run-contract hash",
        "Windows target.log is not hash-bound by the sender receipt",
    ]
    if not post_status["present"]:
        limitations.append("historical Windows safe=true console output is not persisted")

    return {
        "attempt_id": attempt_id,
        "run_token": run_token,
        "usage": attempt_record["usage"],
        "artifacts": artifacts,
        "sender": {
            "status": "passed",
            "wrong_passwords": 20,
            "target_log_hash_bound_by_sender_receipt": False,
        },
        "flow_and_dpdk": {
            "terminal_flows": 20,
            "non_eof_flows": 20,
            "tcp_fin_handshake_flows": 20,
            "packets": 243,
            "clean_counters": True,
        },
        "decision_aggregate": {
            "decisions": 20,
            "raw_argmax": dict(sorted(raw_counts.items())),
            "gated_decision": dict(sorted(gated_counts.items())),
            "top_attack_candidate": dict(sorted(top_attack_counts.items())),
            "attack_gate_passed": gate_passed,
            "ftp_bruteforce_probability_max": ftp_probability_max,
            "attack_score_max": attack_score_max,
            "attack_threshold": float(summary["attack_threshold"]),
            "model_gate_failure": "proven",
        },
        "rollback": {
            "ubuntu": "passed",
            "ubuntu_binding": "attempt_directory_plus_state_sha256",
            "windows": "passed",
            "windows_post_status": post_status,
        },
        "limitations": limitations,
    }, np.asarray(vectors, dtype=np.float64)


def scan_reference(
    inputs: AuditInputs, live_vectors: np.ndarray
) -> dict[str, Any]:
    indices = tuple(inputs.contract["feature_policy"]["distribution_audit_indices"])
    names = tuple(inputs.feature_names[index] for index in indices)
    stats = {
        cohort: {
            partition: VectorStats(len(indices))
            for partition in ("train", "validation", "combined")
        }
        for cohort in ("BENIGN", "FTP-Patator")
    }
    exact_class_counts: Counter[str] = Counter()
    v1_family_counts: Counter[str] = Counter()
    structural: dict[str, Counter[str]] = {}
    live_packet_counts = Counter(int(value) for value in live_vectors[:, 1])
    live_packet_count, live_packet_count_frequency = live_packet_counts.most_common(1)[0]
    if list(live_packet_counts.values()).count(live_packet_count_frequency) != 1:
        raise ValueError("live packet_count mode is not unique")
    rows_scanned = 0
    for ordinal, part in enumerate(inputs.parts, start=1):
        part_rows = 0
        with pq.ParquetFile(part.path) as parquet:
            for batch in parquet.iter_batches(
                batch_size=int(inputs.contract["runtime"]["batch_rows"]),
            ):
                assigned, families, features = decode_reference_batch(
                    batch, inputs.feature_names, part.partition
                )
                matrix = features[:, indices]
                exact_class_counts.update(str(value) for value in assigned)
                v1_family_counts.update(str(value) for value in families)
                for cohort in stats:
                    selected = matrix[assigned == cohort]
                    stats[cohort][part.partition].update(selected)
                    stats[cohort]["combined"].update(selected)
                packet_count = features[:, 1]
                tcp_reset = features[:, 66]
                tcp_fin = features[:, 67]
                for label in np.unique(assigned):
                    label_mask = assigned == label
                    counter = structural.setdefault(str(label), Counter())
                    counter["rows"] += int(np.count_nonzero(label_mask))
                    counter["packet_count_live_mode"] += int(
                        np.count_nonzero(label_mask & (packet_count == live_packet_count))
                    )
                    counter["lifecycle_tcp_reset"] += int(
                        np.count_nonzero(label_mask & (tcp_reset == 1.0))
                    )
                    counter["lifecycle_tcp_fin_handshake"] += int(
                        np.count_nonzero(label_mask & (tcp_fin == 1.0))
                    )
                    counter["live_mode_and_fin"] += int(
                        np.count_nonzero(
                            label_mask
                            & (packet_count == live_packet_count)
                            & (tcp_fin == 1.0)
                        )
                    )
                part_rows += len(batch)
        if part_rows != part.rows:
            raise ValueError(f"reference part row mismatch: {part.relative_path}")
        rows_scanned += part_rows
        print(
            f"[T9.1 V2 audit] part={ordinal}/{len(inputs.parts)} "
            f"partition={part.partition} rows={part_rows}",
            flush=True,
        )

    required_classes = {
        "BENIGN",
        *inputs.contract["architecture"]["attack_family_head"]["class_order"],
    }
    if set(exact_class_counts) != required_classes or "Heartbleed" in exact_class_counts:
        raise ValueError("exact assigned-class taxonomy mismatch")
    live_selected = live_vectors[:, indices]
    comparison: list[dict[str, Any]] = []
    reference_records = {
        cohort: {
            partition: values.record(names)
            for partition, values in partitions.items()
        }
        for cohort, partitions in stats.items()
    }
    for position, (index, name) in enumerate(zip(indices, names, strict=True)):
        values = live_selected[:, position]
        references: dict[str, Any] = {}
        for cohort in ("BENIGN", "FTP-Patator"):
            record = reference_records[cohort]["combined"][name]
            references[cohort] = {
                **record,
                "live_below_minimum": int(np.count_nonzero(values < record["minimum"])),
                "live_above_maximum": int(np.count_nonzero(values > record["maximum"])),
                "live_mean_standardized_delta": (
                    None
                    if record["standard_deviation"] == 0.0
                    else (float(values.mean()) - record["mean"])
                    / record["standard_deviation"]
                ),
            }
        comparison.append(
            {
                "index": index,
                "name": name,
                "live": {
                    "count": len(values),
                    "minimum": float(values.min()),
                    "median": float(np.median(values)),
                    "maximum": float(values.max()),
                    "mean": float(values.mean()),
                },
                "reference": references,
            }
        )
    ftp_structure = structural["FTP-Patator"]
    domain_shift_supported = (
        np.all(live_vectors[:, 1] == live_packet_count)
        and ftp_structure["packet_count_live_mode"] == 0
        and ftp_structure["lifecycle_tcp_fin_handshake"] > 0
    )
    return {
        "rows_scanned": rows_scanned,
        "partitions": {
            partition: sum(part.rows for part in inputs.parts if part.partition == partition)
            for partition in ("train", "validation")
        },
        "exact_assigned_class_counts": dict(sorted(exact_class_counts.items())),
        "v1_collapsed_family_counts": dict(sorted(v1_family_counts.items())),
        "structural_counts_by_assigned_class": {
            key: dict(sorted(value.items())) for key, value in sorted(structural.items())
        },
        "reference_feature_moments": reference_records,
        "feature_comparison": comparison,
        "assessment": {
            "live_packet_count_histogram": {
                str(key): value for key, value in sorted(live_packet_counts.items())
            },
            "live_packet_count_mode": live_packet_count,
            "live_packet_count_mode_frequency": live_packet_count_frequency,
            "domain_shift": "supported" if domain_shift_supported else "inconclusive",
            "feature_serving_parity": "not_proven_requires_same_traffic_offline_replay",
            "automatic_feature_selection_performed": False,
        },
    }


def build_receipt(inputs: AuditInputs) -> dict[str, Any]:
    live, live_vectors = audit_live_attempt(inputs)
    reference = scan_reference(inputs, live_vectors)
    post_status_present = live["rollback"]["windows_post_status"]["present"]
    blockers = [
        "v2_two_head_trainer_bundle_and_runtime_not_implemented",
        "live_attempt_counts_and_preregistered_split_are_pending",
    ]
    if not post_status_present:
        blockers.append("historical_attempt_has_no_persisted_windows_post_status")
    source_files = {}
    for value in SOURCE_FILES:
        path = resolve_inside(inputs.root, value)
        if not path.is_file():
            raise ValueError(f"missing audit source file: {value}")
        source_files[value] = sha256_path(path)
    return {
        "schema_version": AUDIT_RECEIPT_SCHEMA_VERSION,
        "audit_revision": AUDIT_REVISION,
        "supersedes": SUPERSEDED_AUDIT,
        "task": TASK,
        "kind": "terminal_flow_model_v2_audit",
        "status": "passed",
        "generated_at_utc": utc_now(),
        "contract": {
            "path": relative(inputs.contract_path, inputs.root),
            "sha256": sha256_path(inputs.contract_path),
        },
        "source_files": source_files,
        "inputs": inputs.input_records,
        "taxonomies": {
            "required_v2": {
                "binary": inputs.contract["architecture"]["binary_head"]["class_order"],
                "attack_family": inputs.contract["architecture"]["attack_family_head"][
                    "class_order"
                ],
                "source_column": "assigned_class",
            },
            "observed_v1": {
                "class_order": inputs.contract["architecture"]["current_v1"][
                    "class_order"
                ],
                "source_column": "label_family",
            },
            "exact_v2_source_available_in_train_validation": True,
        },
        "candidate_profiles": inputs.contract["feature_policy"]["candidate_profiles"],
        "live_evidence": live,
        "reference_audit": reference,
        "partition_policy": {
            "test": inputs.input_records["sealed_test_guard"],
            "live": inputs.contract["live_data_policy"],
        },
        "gate": {
            "decision": "blocked_pending_next_phase",
            "training_authorized": False,
            "test_partition_may_be_opened": False,
            "blockers": blockers,
            "next_phase": "two_head_training_implementation_and_live_split_lock",
        },
    }


def audit_receipt_path(inputs: AuditInputs) -> Path:
    return resolve_inside(
        inputs.root, str(inputs.contract["outputs"]["audit_receipt"])
    )


def publish(inputs: AuditInputs) -> dict[str, Any]:
    output = audit_receipt_path(inputs)
    if output.exists():
        raise FileExistsError(f"audit receipt already exists: {output}")
    receipt = build_receipt(inputs)
    write_json_new(output, receipt)
    return receipt


def validate_receipt(inputs: AuditInputs, receipt_path: Path) -> None:
    expected_path = audit_receipt_path(inputs)
    if receipt_path != expected_path:
        raise ValueError("only the contract-locked audit receipt may be validated")
    receipt = load_json(receipt_path)
    source_files = receipt.get("source_files")
    if (
        receipt.get("schema_version") != AUDIT_RECEIPT_SCHEMA_VERSION
        or receipt.get("audit_revision") != AUDIT_REVISION
        or receipt.get("supersedes") != SUPERSEDED_AUDIT
        or not isinstance(receipt.get("generated_at_utc"), str)
        or receipt.get("task") != TASK
        or receipt.get("kind") != "terminal_flow_model_v2_audit"
        or receipt.get("status") != "passed"
        or receipt.get("contract", {}).get("path")
        != relative(inputs.contract_path, inputs.root)
        or receipt.get("contract", {}).get("sha256")
        != sha256_path(inputs.contract_path)
        or receipt.get("inputs") != inputs.input_records
        or receipt.get("gate", {}).get("training_authorized") is not False
        or receipt.get("gate", {}).get("test_partition_may_be_opened") is not False
        or receipt.get("partition_policy", {}).get("test")
        != inputs.input_records["sealed_test_guard"]
        or not isinstance(source_files, Mapping)
        or set(source_files) != set(SOURCE_FILES)
        or any(not is_sha256(value) for value in source_files.values())
    ):
        raise ValueError("invalid Model V2 audit receipt")
    for value in SOURCE_FILES:
        path = resolve_inside(inputs.root, value)
        if not path.is_file() or sha256_path(path) != source_files[value]:
            raise ValueError(f"audit source hash mismatch: {value}")
    for part in inputs.parts:
        if not part.path.is_file() or sha256_path(part.path) != part.sha256:
            raise ValueError("audit allowed-part hash mismatch")
    expected = build_receipt(inputs)
    expected["generated_at_utc"] = receipt["generated_at_utc"]
    if receipt != expected:
        raise ValueError("Model V2 audit receipt content drift")
