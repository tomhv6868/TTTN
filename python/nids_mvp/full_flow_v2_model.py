"""Fail-closed Model V2 trainer boundary and label projection."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pyarrow as pa

from nids_mvp import full_flow_v2_audit as audit
from nids_mvp import full_flow_v2_split as live_split


TASK = "T9.1"
FEATURE_COUNT = 70
CURRENT_TASK_PATH = "config/agent/current-task.json"
AUDIT_CONTRACT_PATH = "config/terminal-flow-model-v2-audit-contract.json"
AUDIT_CONTRACT_SHA256 = (
    "0431f9e44923eb0805a2a1c82c772b4f6b690bbeb91878695ba88d0cb4a36c7b"
)
AUDIT_RECEIPT_PATH = (
    "run_log/full-flow-v1/model-v2/audit/model-v2-audit-r2.json"
)
AUDIT_RECEIPT_SHA256 = (
    "188607e2ee12c2658c9e3b07311673507d0357143a8b8deb015e723e876fd038"
)
AUDIT_REVISION = "r2_physical_feature_suffix"
LIVE_SPLIT_POLICY_PATH = live_split.POLICY_PATH
LIVE_SPLIT_POLICY_SHA256 = live_split.POLICY_SHA256
LIVE_SPLIT_LOCK_PATH = live_split.SPLIT_LOCK_PATH
LIVE_SPLIT_LOCK_SHA256 = live_split.SPLIT_LOCK_SHA256
APPROVED_REQUIRED_PER_CAMPAIGN = {
    "train": 3,
    "validation": 2,
    "holdout": 2,
}
APPROVED_RESERVE_PER_CAMPAIGN = {
    "train": 1,
    "validation": 1,
    "holdout": 1,
}
PRODUCTION_PATH_ALLOWLIST = {
    "current_task": CURRENT_TASK_PATH,
    "audit_contract": AUDIT_CONTRACT_PATH,
    "audit_receipt": AUDIT_RECEIPT_PATH,
    "live_split_policy": LIVE_SPLIT_POLICY_PATH,
    "live_split_lock": LIVE_SPLIT_LOCK_PATH,
}


@dataclass(frozen=True)
class FeatureProfile:
    profile_id: str
    name: str
    feature_indices: tuple[int, ...]


@dataclass(frozen=True)
class AllowedPart:
    path: Path
    relative_path: str
    partition: str
    rows: int
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class EncodedLabels:
    binary: np.ndarray
    end_to_end: np.ndarray
    attack_rows: np.ndarray
    attack_family: np.ndarray


@dataclass(frozen=True)
class LabeledBatch:
    full_features: np.ndarray
    profile_features: np.ndarray
    profile_id: str
    labels: EncodedLabels


@dataclass(frozen=True)
class VerifiedPreflight:
    feature_names: tuple[str, ...]
    profiles: tuple[FeatureProfile, ...]
    train_parts: tuple[AllowedPart, ...]
    validation_parts: tuple[AllowedPart, ...]
    train_rows: int
    validation_rows: int
    audit_contract_sha256: str
    audit_receipt_sha256: str
    audit_revision: str
    live_split_policy_sha256: str
    live_split_lock_sha256: str
    live_split_counts_status: str
    live_split_slot_count: int
    live_split_required_slot_count: int
    live_split_reserve_slot_count: int
    production_fit_authorized: bool
    threshold_selection_authorized: bool
    holdout_access_authorized: bool
    test_partition_may_be_opened: bool


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{where} must be an object")
    return value


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        document = json.load(source)
    return _mapping(document, str(path))


def _production_paths(project_root: Path) -> dict[str, Path]:
    expected = {
        "current_task": CURRENT_TASK_PATH,
        "audit_contract": AUDIT_CONTRACT_PATH,
        "audit_receipt": AUDIT_RECEIPT_PATH,
        "live_split_policy": LIVE_SPLIT_POLICY_PATH,
        "live_split_lock": LIVE_SPLIT_LOCK_PATH,
    }
    if PRODUCTION_PATH_ALLOWLIST != expected:
        raise ValueError("Model V2 production path allowlist drifted")
    root = project_root.resolve()
    resolved: dict[str, Path] = {}
    for name, relative_path in expected.items():
        if Path(relative_path).is_absolute():
            raise ValueError(f"allowlisted path must be relative: {name}")
        path = (root / relative_path).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError(f"allowlisted path escapes project root: {name}") from error
        resolved[name] = path
    return resolved


def _verify_current_task(document: Mapping[str, Any]) -> None:
    artifacts = _mapping(document.get("artifacts"), "current_task.artifacts")
    audit_contract = _mapping(
        artifacts.get("model_v2_audit_contract"),
        "current_task.artifacts.model_v2_audit_contract",
    )
    audit_receipt = _mapping(
        artifacts.get("model_v2_audit_receipt"),
        "current_task.artifacts.model_v2_audit_receipt",
    )
    split_policy = _mapping(
        artifacts.get("model_v2_live_split_policy"),
        "current_task.artifacts.model_v2_live_split_policy",
    )
    split_lock = _mapping(
        artifacts.get("model_v2_live_split_lock"),
        "current_task.artifacts.model_v2_live_split_lock",
    )
    gate = _mapping(document.get("gate"), "current_task.gate")
    authorized_by = _mapping(
        document.get("authorized_by"), "current_task.authorized_by"
    )
    expected_contract = {
        "path": AUDIT_CONTRACT_PATH,
        "sha256": AUDIT_CONTRACT_SHA256,
        "schema_version": "1.1.0",
        "audit_revision": AUDIT_REVISION,
        "status": "locked",
    }
    expected_receipt = {
        "path": AUDIT_RECEIPT_PATH,
        "sha256": AUDIT_RECEIPT_SHA256,
        "schema_version": "1.1.0",
        "audit_revision": AUDIT_REVISION,
        "status": "passed",
        "gate_decision": "blocked_pending_next_phase",
    }
    expected_policy = {
        "path": LIVE_SPLIT_POLICY_PATH,
        "sha256": LIVE_SPLIT_POLICY_SHA256,
        "schema_version": "1.0.0",
        "status": "policy_locked_counts_pending",
        "attempt_counts_status": "pending_user_lock",
    }
    expected_lock = {
        "path": LIVE_SPLIT_LOCK_PATH,
        "sha256": LIVE_SPLIT_LOCK_SHA256,
        "schema_version": "1.0.0",
        "status": "counts_locked_capture_not_authorized",
        "locked_at_utc": "2026-07-29T21:04:06.1197933+07:00",
        "required_per_campaign": APPROVED_REQUIRED_PER_CAMPAIGN,
        "reserve_per_campaign": APPROVED_RESERVE_PER_CAMPAIGN,
        "slot_count": 40,
        "required_slot_count": 28,
        "reserve_slot_count": 12,
        "gate_decision": "blocked_pending_capture_authorization",
    }
    if (
        document.get("schema_version") != "1.1.0"
        or document.get("task") != TASK
        or document.get("phase")
        != "model_v2_live_split_counts_locked_pending_capture_authorization"
        or document.get("status") != "in_progress"
        or document.get("model_training_allowed") is not False
        or document.get("threshold_selection_allowed") is not False
        or document.get("test_partition_policy")
        != (
            "sealed until feature profile, algorithm, hyperparameters, "
            "and threshold are locked"
        )
        or audit_contract != expected_contract
        or audit_receipt != expected_receipt
        or split_policy != expected_policy
        or split_lock != expected_lock
        or authorized_by.get("model_v2_trainer_implementation_authorized")
        is not True
        or authorized_by.get("live_split_lock_implementation_authorized")
        is not True
        or gate.get("decision") != "blocked_pending_capture_authorization"
        or gate.get("training_implementation_authorized") is not True
        or gate.get("live_split_lock_implementation_authorized") is not True
        or gate.get("training_authorized") is not False
        or gate.get("threshold_selection_authorized") is not False
        or gate.get("holdout_access_authorized") is not False
        or gate.get("test_partition_may_be_opened") is not False
        or gate.get("train_validation_capture_authorized") is not False
        or gate.get("holdout_capture_authorized") is not False
        or gate.get("next_phase") != "implement_train_validation_capture_claims"
    ):
        raise ValueError("current-task Model V2 preflight contract mismatch")


def _allowed_part(part: audit.VerifiedPart) -> AllowedPart:
    if part.partition not in {"train", "validation"}:
        raise ValueError("audit preflight exposed a sealed partition")
    return AllowedPart(
        path=part.path,
        relative_path=part.relative_path,
        partition=part.partition,
        rows=part.rows,
        size_bytes=part.size_bytes,
        sha256=part.sha256,
    )


def _profiles() -> tuple[FeatureProfile, ...]:
    profiles = tuple(
        FeatureProfile(
            profile_id=str(profile["id"]),
            name=str(profile["name"]),
            feature_indices=tuple(int(value) for value in profile["feature_indices"]),
        )
        for profile in audit.V2_PROFILES
    )
    for profile in profiles:
        if (
            not profile.feature_indices
            or len(set(profile.feature_indices)) != len(profile.feature_indices)
            or min(profile.feature_indices) < 0
            or max(profile.feature_indices) >= FEATURE_COUNT
        ):
            raise ValueError(f"invalid Model V2 profile: {profile.profile_id}")
    return profiles


def _approved_attempt_counts() -> dict[str, dict[str, dict[str, int]]]:
    return {
        campaign: {
            partition: {
                "required": APPROVED_REQUIRED_PER_CAMPAIGN[partition],
                "reserve": APPROVED_RESERVE_PER_CAMPAIGN[partition],
            }
            for partition in live_split.PARTITIONS
        }
        for campaign in live_split.CAMPAIGNS
    }


def verify_preflight(project_root: Path) -> VerifiedPreflight:
    paths = _production_paths(project_root)
    current_task = _load_json(paths["current_task"])
    _verify_current_task(current_task)
    split_lock = live_split.load_split_lock(project_root)

    if _hash_path(paths["audit_contract"]) != AUDIT_CONTRACT_SHA256:
        raise ValueError("locked Model V2 audit contract SHA-256 mismatch")
    if _hash_path(paths["audit_receipt"]) != AUDIT_RECEIPT_SHA256:
        raise ValueError("locked Model V2 audit receipt SHA-256 mismatch")
    inputs = audit.verify_inputs(project_root, paths["audit_contract"])
    audit.validate_receipt(inputs, paths["audit_receipt"])

    parts = tuple(_allowed_part(part) for part in inputs.parts)
    train_parts = tuple(part for part in parts if part.partition == "train")
    validation_parts = tuple(
        part for part in parts if part.partition == "validation"
    )
    if (
        not train_parts
        or not validation_parts
        or len(parts) != len(train_parts) + len(validation_parts)
    ):
        raise ValueError("Model V2 audit part inventory mismatch")
    if (
        split_lock.document_sha256 != LIVE_SPLIT_LOCK_SHA256
        or split_lock.attempt_counts != _approved_attempt_counts()
        or len(split_lock.slots) != 40
        or sum(slot.role == "required" for slot in split_lock.slots) != 28
        or sum(slot.role == "reserve" for slot in split_lock.slots) != 12
        or split_lock.training_authorized is not False
        or split_lock.threshold_selection_authorized is not False
        or split_lock.holdout_access_authorized is not False
        or split_lock.test_partition_may_be_opened is not False
        or current_task.get("model_training_allowed") is not False
        or current_task.get("threshold_selection_allowed") is not False
    ):
        raise ValueError("authorization advanced beyond trainer implementation")
    return VerifiedPreflight(
        feature_names=tuple(inputs.feature_names),
        profiles=_profiles(),
        train_parts=train_parts,
        validation_parts=validation_parts,
        train_rows=sum(part.rows for part in train_parts),
        validation_rows=sum(part.rows for part in validation_parts),
        audit_contract_sha256=AUDIT_CONTRACT_SHA256,
        audit_receipt_sha256=AUDIT_RECEIPT_SHA256,
        audit_revision=AUDIT_REVISION,
        live_split_policy_sha256=LIVE_SPLIT_POLICY_SHA256,
        live_split_lock_sha256=LIVE_SPLIT_LOCK_SHA256,
        live_split_counts_status="locked",
        live_split_slot_count=40,
        live_split_required_slot_count=28,
        live_split_reserve_slot_count=12,
        production_fit_authorized=False,
        threshold_selection_authorized=False,
        holdout_access_authorized=False,
        test_partition_may_be_opened=False,
    )


def encode_assigned_labels(values: Sequence[Any] | np.ndarray) -> EncodedLabels:
    assigned = np.asarray(values, dtype=object)
    if assigned.ndim != 1:
        raise ValueError("assigned_class labels must be one-dimensional")
    end_to_end_lookup = {
        "Benign": 0,
        **{
            family: index
            for index, family in enumerate(
                audit.V2_ATTACK_FAMILY_CLASS_ORDER,
                start=1,
            )
        },
    }
    end_to_end = np.empty(len(assigned), dtype=np.uint8)
    for index, value in enumerate(assigned):
        if not isinstance(value, str) or value not in end_to_end_lookup:
            raise ValueError(f"unsupported assigned_class label: {value!r}")
        end_to_end[index] = end_to_end_lookup[value]
    binary = (end_to_end != 0).astype(np.uint8, copy=False)
    attack_rows = binary.astype(bool, copy=False)
    attack_family = (end_to_end[attack_rows] - 1).astype(np.uint8, copy=False)
    return EncodedLabels(
        binary=binary,
        end_to_end=end_to_end,
        attack_rows=attack_rows,
        attack_family=attack_family,
    )


def project_profile(features: np.ndarray, profile_id: str) -> np.ndarray:
    values = np.asarray(features)
    if (
        values.ndim != 2
        or values.shape[1] != FEATURE_COUNT
        or not np.issubdtype(values.dtype, np.number)
        or not np.isfinite(values).all()
    ):
        raise ValueError("Model V2 feature matrix must be finite Nx70 numeric data")
    matches = [
        profile for profile in _profiles() if profile.profile_id == profile_id
    ]
    if len(matches) != 1:
        raise ValueError(f"unknown Model V2 feature profile: {profile_id}")
    with np.errstate(over="ignore", invalid="ignore"):
        projected = values[:, matches[0].feature_indices].astype(
            np.float32,
            copy=False,
        )
    if not np.isfinite(projected).all():
        raise ValueError("Model V2 float32 feature projection overflow")
    return np.ascontiguousarray(projected)


def decode_labeled_batch(
    batch: pa.RecordBatch,
    feature_names: Sequence[str],
    expected_partition: str,
    profile_id: str,
) -> LabeledBatch:
    if expected_partition not in {"train", "validation"}:
        raise ValueError("trainer may decode only train or validation batches")
    assigned, _ignored_label_family, features = audit.decode_reference_batch(
        batch,
        feature_names,
        expected_partition,
    )
    labels = encode_assigned_labels(assigned)
    with np.errstate(over="ignore", invalid="ignore"):
        full_features = features.astype(np.float32, copy=False)
    if not np.isfinite(full_features).all():
        raise ValueError("Model V2 float32 feature conversion overflow")
    return LabeledBatch(
        full_features=np.ascontiguousarray(full_features),
        profile_features=project_profile(features, profile_id),
        profile_id=profile_id,
        labels=labels,
    )


def preflight_summary(preflight: VerifiedPreflight) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "terminal_flow_model_v2_trainer_preflight",
        "status": "passed_blocked_capture_authorization",
        "audit": {
            "revision": preflight.audit_revision,
            "contract_sha256": preflight.audit_contract_sha256,
            "receipt_sha256": preflight.audit_receipt_sha256,
        },
        "reference": {
            "feature_count": len(preflight.feature_names),
            "profile_ids": [
                profile.profile_id for profile in preflight.profiles
            ],
            "train_parts": len(preflight.train_parts),
            "train_rows": preflight.train_rows,
            "validation_parts": len(preflight.validation_parts),
            "validation_rows": preflight.validation_rows,
        },
        "live_split": {
            "policy_sha256": preflight.live_split_policy_sha256,
            "lock_sha256": preflight.live_split_lock_sha256,
            "attempt_counts_status": preflight.live_split_counts_status,
            "required_per_campaign": APPROVED_REQUIRED_PER_CAMPAIGN,
            "reserve_per_campaign": APPROVED_RESERVE_PER_CAMPAIGN,
            "slot_count": preflight.live_split_slot_count,
            "required_slot_count": preflight.live_split_required_slot_count,
            "reserve_slot_count": preflight.live_split_reserve_slot_count,
        },
        "gate": {
            "production_fit_authorized": preflight.production_fit_authorized,
            "threshold_selection_authorized": (
                preflight.threshold_selection_authorized
            ),
            "holdout_access_authorized": preflight.holdout_access_authorized,
            "test_partition_may_be_opened": (
                preflight.test_partition_may_be_opened
            ),
            "next_gate": "capture_authorization_review",
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the locked Model V2 trainer boundary."
    )
    parser.add_argument("command", choices=("check",))
    arguments = parser.parse_args(argv)
    if arguments.command != "check":
        raise ValueError("unsupported Model V2 trainer command")
    project_root = Path(__file__).resolve().parents[2]
    summary = preflight_summary(verify_preflight(project_root))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
