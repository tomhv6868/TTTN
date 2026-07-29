"""Immutable live-split policy and claim validation for Model V2."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


TASK = "T9.1"
POLICY_SCHEMA_VERSION = "1.0.0"
POLICY_PATH = "config/terminal-flow-model-v2-live-split-policy.json"
POLICY_SHA256 = "a9d3e2eb24427e2bbd9293edc87e2a234c21bca53b3dcae96a2f8dcd262daf25"
SPLIT_LOCK_PATH = "config/terminal-flow-model-v2-live-split-lock.json"
SPLIT_LOCK_SHA256 = (
    "16da2b7a5e9a0b7e1e0306e9080f2d48413bb45205f71b292c6950d36505503f"
)
CLAIM_ROOT = "run_log/full-flow-v1/model-v2/live-split/claims"
CLAIM_WRITER_LOCK = ".writer.lock"
CURRENT_TASK_PATH = "config/agent/current-task.json"
AUDIT_CONTRACT_PATH = "config/terminal-flow-model-v2-audit-contract.json"
AUDIT_CONTRACT_SHA256 = (
    "0431f9e44923eb0805a2a1c82c772b4f6b690bbeb91878695ba88d0cb4a36c7b"
)
AUDIT_REVISION = "r2_physical_feature_suffix"
AUDIT_RECEIPT_PATH = (
    "run_log/full-flow-v1/model-v2/audit/model-v2-audit-r2.json"
)
AUDIT_RECEIPT_SHA256 = (
    "188607e2ee12c2658c9e3b07311673507d0357143a8b8deb015e723e876fd038"
)
POLICY_LOCKED_AT_UTC = "2026-07-29T05:11:26.4775975Z"
CAMPAIGNS = (
    "ftp_patator_wrong_password",
    "ftp_valid_login",
    "http_normal",
    "https_normal",
)
PARTITIONS = ("train", "validation", "holdout")
SLOT_ROLES = ("required", "reserve")
SLOT_USAGE = {
    "train": "fit",
    "validation": "model_and_threshold_selection",
    "holdout": "final_generalization_only_after_model_lock",
}
FORBIDDEN_ATTEMPTS = (
    {
        "attempt_id": "t91-ftp-patator-20260729033157-36b1db91",
        "run_contract_sha256": (
            "5e937c17245412d3728f0d7a89f5da3526db2f0b8f617d2be678f832d613a07a"
        ),
        "reason": "orchestration_failure",
    },
    {
        "attempt_id": "t91-ftp-patator-20260729034112-f8763728",
        "run_contract_sha256": (
            "892d76384d331573cf6657002cb524186a498165f0322b04add2f67ea135b263"
        ),
        "reason": "diagnostic_attempt_before_policy_lock",
    },
)
LOCKED_FILESYSTEM_ALLOWLIST = {
    "policy_path": "config/terminal-flow-model-v2-live-split-policy.json",
    "future_split_lock_path": (
        "config/terminal-flow-model-v2-live-split-lock.json"
    ),
    "claim_root": "run_log/full-flow-v1/model-v2/live-split/claims",
    "current_task_path": "config/agent/current-task.json",
    "audit_contract_path": "config/terminal-flow-model-v2-audit-contract.json",
    "audit_receipt_path": (
        "run_log/full-flow-v1/model-v2/audit/model-v2-audit-r2.json"
    ),
}
FILESYSTEM_ALLOWLIST = dict(LOCKED_FILESYSTEM_ALLOWLIST)
CLAIMABLE_PARTITIONS = frozenset(("train", "validation"))
LOCKED_CAMPAIGN_ATTEMPT_PREFIXES = {
    "ftp_patator_wrong_password": "ftp-patator",
    "ftp_valid_login": "ftp-valid-login",
    "http_normal": "http-normal",
    "https_normal": "https-normal",
}
CAMPAIGN_ATTEMPT_PREFIXES = dict(LOCKED_CAMPAIGN_ATTEMPT_PREFIXES)
SAFE_TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
ATTEMPT_ID_PATTERN = re.compile(
    r"t91-(?P<campaign>[a-z0-9][a-z0-9._-]{0,96})-"
    r"(?P<stamp>[0-9]{14})-"
    r"(?P<nonce>[0-9a-f]{8})"
)
RUN_TOKEN_PATTERN = re.compile(
    r"rt-(?P<stamp>[0-9]{14})-(?P<nonce>[0-9a-f]{8})"
)


@dataclass(frozen=True)
class LiveSplitPolicy:
    locked_at_utc: str
    campaigns: tuple[str, ...]
    partitions: tuple[str, ...]
    counts_status: str
    forbidden_attempt_ids: frozenset[str]


@dataclass(frozen=True)
class SplitSlot:
    slot_id: str
    campaign: str
    partition: str
    role: str
    ordinal: int
    usage: str
    state: str


@dataclass(frozen=True)
class LiveSplitLock:
    locked_at_utc: str
    policy_sha256: str
    attempt_counts: Mapping[str, Mapping[str, Mapping[str, int]]]
    slots: tuple[SplitSlot, ...]
    train_validation_capture_authorized: bool
    training_authorized: bool
    threshold_selection_authorized: bool
    holdout_access_authorized: bool
    test_partition_may_be_opened: bool
    document_sha256: str | None = None


@dataclass(frozen=True)
class SplitClaim:
    slot_id: str
    campaign: str
    partition: str
    collection_session_id: str
    attempt_id: str
    run_token: str
    run_contract_sha256: str


@dataclass(frozen=True)
class ClaimRequest:
    slot_id: str
    collection_session_id: str
    attempt_id: str
    run_token: str
    run_contract_sha256: str


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{where} must be an object")
    return value


def _exact_keys(
    value: Mapping[str, Any], expected: Sequence[str], where: str
) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        missing = sorted(wanted - actual)
        extra = sorted(actual - wanted)
        raise ValueError(f"{where} keys mismatch; missing={missing}, extra={extra}")


def _strict_equal(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        return (
            isinstance(actual, Mapping)
            and set(actual) == set(expected)
            and all(
                _strict_equal(actual[key], expected[key]) for key in expected
            )
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(
                _strict_equal(observed, wanted)
                for observed, wanted in zip(actual, expected)
            )
        )
    return type(actual) is type(expected) and actual == expected


def _equal(actual: Any, expected: Any, where: str) -> None:
    if not _strict_equal(actual, expected):
        raise ValueError(f"{where} must equal {expected!r}")


def _sha256(value: Any, where: str) -> str:
    if not (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{where} must be a lowercase SHA-256")
    return value


def _nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{where} must be a non-empty string")
    return value


def _utc_timestamp(value: Any, where: str) -> datetime:
    text = _nonempty_string(value, where)
    normalized = f"{text[:-1]}+00:00" if text.endswith("Z") else text
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{where} must be an ISO-8601 timestamp") from error
    if timestamp.tzinfo is None:
        raise ValueError(f"{where} must include a UTC offset")
    return timestamp.astimezone(timezone.utc)


def _claim_identity(
    slot_id: Any,
    collection_session_id: Any,
    attempt_id: Any,
    run_token: Any,
    run_contract_sha256: Any,
    where: str,
) -> tuple[str, str, str, str, str, str, datetime]:
    normalized = []
    for value, field in (
        (slot_id, "slot_id"),
        (collection_session_id, "collection_session_id"),
        (attempt_id, "attempt_id"),
        (run_token, "run_token"),
    ):
        text = _nonempty_string(value, f"{where}.{field}")
        if SAFE_TOKEN_PATTERN.fullmatch(text) is None:
            raise ValueError(f"{where}.{field} has invalid syntax")
        normalized.append(text)
    slot_text, session_text, attempt_text, run_token_text = normalized
    attempt_match = ATTEMPT_ID_PATTERN.fullmatch(attempt_text)
    if attempt_match is None:
        raise ValueError(f"{where}.attempt_id has invalid syntax")
    run_token_match = RUN_TOKEN_PATTERN.fullmatch(run_token_text)
    if run_token_match is None:
        raise ValueError(f"{where}.run_token has invalid syntax")
    if (
        attempt_match.group("stamp") != run_token_match.group("stamp")
        or attempt_match.group("nonce") != run_token_match.group("nonce")
    ):
        raise ValueError(f"{where}.run_token does not match attempt_id")
    try:
        attempt_timestamp = datetime.strptime(
            attempt_match.group("stamp"), "%Y%m%d%H%M%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError(
            f"{where}.attempt_id contains an invalid UTC timestamp"
        ) from error
    contract_sha256 = _sha256(
        run_contract_sha256,
        f"{where}.run_contract_sha256",
    )
    return (
        slot_text,
        session_text,
        attempt_text,
        run_token_text,
        contract_sha256,
        attempt_match.group("campaign"),
        attempt_timestamp,
    )


def _validate_pending_counts(value: Any) -> None:
    counts = _mapping(value, "split.attempt_counts")
    _exact_keys(counts, ("status", "by_campaign"), "split.attempt_counts")
    _equal(counts["status"], "pending_user_lock", "split.attempt_counts.status")
    by_campaign = _mapping(
        counts["by_campaign"], "split.attempt_counts.by_campaign"
    )
    _exact_keys(by_campaign, CAMPAIGNS, "split.attempt_counts.by_campaign")
    for campaign in CAMPAIGNS:
        partitions = _mapping(
            by_campaign[campaign],
            f"split.attempt_counts.by_campaign.{campaign}",
        )
        _exact_keys(
            partitions,
            PARTITIONS,
            f"split.attempt_counts.by_campaign.{campaign}",
        )
        for partition in PARTITIONS:
            roles = _mapping(
                partitions[partition],
                f"split.attempt_counts.by_campaign.{campaign}.{partition}",
            )
            _exact_keys(
                roles,
                SLOT_ROLES,
                f"split.attempt_counts.by_campaign.{campaign}.{partition}",
            )
            for role in SLOT_ROLES:
                _equal(
                    roles[role],
                    None,
                    (
                        "split.attempt_counts.by_campaign."
                        f"{campaign}.{partition}.{role}"
                    ),
                )


def validate_policy_document(document: Mapping[str, Any]) -> LiveSplitPolicy:
    policy = _mapping(document, "policy")
    _exact_keys(
        policy,
        (
            "schema_version",
            "task",
            "kind",
            "status",
            "policy_locked_at_utc",
            "audit",
            "split",
            "claim_identity",
            "forbidden_attempts",
            "access_policy",
            "filesystem_allowlist",
            "gate",
        ),
        "policy",
    )
    _equal(policy["schema_version"], POLICY_SCHEMA_VERSION, "schema_version")
    _equal(policy["task"], TASK, "task")
    _equal(
        policy["kind"],
        "terminal_flow_model_v2_live_split_policy",
        "kind",
    )
    _equal(policy["status"], "policy_locked_counts_pending", "status")
    _equal(
        policy["policy_locked_at_utc"],
        POLICY_LOCKED_AT_UTC,
        "policy_locked_at_utc",
    )

    expected_audit = {
        "contract_path": AUDIT_CONTRACT_PATH,
        "contract_sha256": AUDIT_CONTRACT_SHA256,
        "revision": AUDIT_REVISION,
        "receipt_path": AUDIT_RECEIPT_PATH,
        "receipt_sha256": AUDIT_RECEIPT_SHA256,
        "receipt_status": "passed",
        "gate_decision": "blocked",
    }
    _equal(dict(_mapping(policy["audit"], "audit")), expected_audit, "audit")

    split = _mapping(policy["split"], "split")
    _exact_keys(
        split,
        (
            "unit",
            "assignment_mode",
            "assignment_time",
            "partitions",
            "campaigns",
            "attempt_counts",
            "reserved_slots",
            "cross_partition_attempt_reuse",
            "collection_session_cross_partition",
            "failed_claim_reuse",
            "replacement_policy",
        ),
        "split",
    )
    _equal(split["unit"], "whole_attempt", "split.unit")
    _equal(
        split["assignment_mode"],
        "deterministic_reserved_slots",
        "split.assignment_mode",
    )
    _equal(
        split["assignment_time"],
        "claim_receipt_create_new_before_capture",
        "split.assignment_time",
    )
    _equal(split["partitions"], list(PARTITIONS), "split.partitions")
    _equal(split["campaigns"], list(CAMPAIGNS), "split.campaigns")
    _validate_pending_counts(split["attempt_counts"])
    _equal(split["reserved_slots"], [], "split.reserved_slots")
    for field in (
        "cross_partition_attempt_reuse",
        "collection_session_cross_partition",
        "failed_claim_reuse",
    ):
        _equal(split[field], False, f"split.{field}")
    _equal(
        split["replacement_policy"],
        "predeclared_reserve_slot_only",
        "split.replacement_policy",
    )

    expected_claim_identity = {
        "required_fields": [
            "schema_version",
            "task",
            "policy_sha256",
            "split_lock_sha256",
            "slot_id",
            "campaign",
            "partition",
            "collection_session_id",
            "attempt_id",
            "run_token",
            "run_contract_sha256",
            "claim_phase",
            "traffic_started",
        ],
        "claim_phase": "before_capture",
        "traffic_started": False,
        "write_semantics": "create_new",
    }
    _equal(
        dict(_mapping(policy["claim_identity"], "claim_identity")),
        expected_claim_identity,
        "claim_identity",
    )
    _equal(
        policy["forbidden_attempts"],
        list(FORBIDDEN_ATTEMPTS),
        "forbidden_attempts",
    )
    expected_access = {
        "train_usage": "fit_only_after_counts_lock_and_gate_approval",
        "validation_usage": (
            "model_and_threshold_selection_only_after_counts_lock_and_gate_approval"
        ),
        "holdout_usage": "sealed_until_immutable_model_lock",
        "cicids_test_usage": "sealed_until_final_model_and_threshold_lock",
        "holdout_path_disclosure_allowed": False,
        "test_path_disclosure_allowed": False,
    }
    _equal(
        dict(_mapping(policy["access_policy"], "access_policy")),
        expected_access,
        "access_policy",
    )
    _equal(
        dict(_mapping(policy["filesystem_allowlist"], "filesystem_allowlist")),
        FILESYSTEM_ALLOWLIST,
        "filesystem_allowlist",
    )
    expected_gate = {
        "decision": "blocked_counts_pending",
        "training_authorized": False,
        "threshold_selection_authorized": False,
        "train_validation_capture_authorized": False,
        "holdout_capture_authorized": False,
        "holdout_access_authorized": False,
        "test_partition_may_be_opened": False,
        "next_gate": "user_locks_attempt_count_matrix",
    }
    _equal(dict(_mapping(policy["gate"], "gate")), expected_gate, "gate")
    return LiveSplitPolicy(
        locked_at_utc=POLICY_LOCKED_AT_UTC,
        campaigns=CAMPAIGNS,
        partitions=PARTITIONS,
        counts_status="pending_user_lock",
        forbidden_attempt_ids=frozenset(
            item["attempt_id"] for item in FORBIDDEN_ATTEMPTS
        ),
    )


def _safe_fixed_path(project_root: Path, relative_path: str) -> Path:
    if relative_path not in FILESYSTEM_ALLOWLIST.values():
        raise ValueError(f"path is not allowlisted: {relative_path}")
    root = project_root.resolve()
    resolved = (root / relative_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"path escapes project root: {relative_path}") from error
    return resolved


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_filesystem_allowlist() -> None:
    constants = {
        "policy_path": POLICY_PATH,
        "future_split_lock_path": SPLIT_LOCK_PATH,
        "claim_root": CLAIM_ROOT,
        "current_task_path": CURRENT_TASK_PATH,
        "audit_contract_path": AUDIT_CONTRACT_PATH,
        "audit_receipt_path": AUDIT_RECEIPT_PATH,
    }
    if (
        FILESYSTEM_ALLOWLIST != LOCKED_FILESYSTEM_ALLOWLIST
        or constants != LOCKED_FILESYSTEM_ALLOWLIST
    ):
        raise ValueError("production filesystem allowlist drifted")
    if (
        CAMPAIGN_ATTEMPT_PREFIXES != LOCKED_CAMPAIGN_ATTEMPT_PREFIXES
        or tuple(CAMPAIGN_ATTEMPT_PREFIXES) != CAMPAIGNS
    ):
        raise ValueError("production campaign identity mapping drifted")


def load_policy(project_root: Path) -> LiveSplitPolicy:
    _assert_filesystem_allowlist()
    path = _safe_fixed_path(project_root, POLICY_PATH)
    if _hash_path(path) != POLICY_SHA256:
        raise ValueError("live-split policy SHA-256 mismatch")
    with path.open("r", encoding="utf-8") as source:
        document = json.load(source)
    return validate_policy_document(_mapping(document, "policy"))


def _normalize_locked_counts(
    value: Mapping[str, Any],
) -> dict[str, dict[str, dict[str, int]]]:
    source = _mapping(value, "attempt_counts")
    _exact_keys(source, CAMPAIGNS, "attempt_counts")
    normalized: dict[str, dict[str, dict[str, int]]] = {}
    for campaign in CAMPAIGNS:
        partitions = _mapping(source[campaign], f"attempt_counts.{campaign}")
        _exact_keys(partitions, PARTITIONS, f"attempt_counts.{campaign}")
        normalized[campaign] = {}
        for partition in PARTITIONS:
            roles = _mapping(
                partitions[partition],
                f"attempt_counts.{campaign}.{partition}",
            )
            _exact_keys(
                roles,
                SLOT_ROLES,
                f"attempt_counts.{campaign}.{partition}",
            )
            normalized[campaign][partition] = {}
            for role in SLOT_ROLES:
                count = roles[role]
                minimum = 1 if role == "required" else 0
                if (
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count < minimum
                ):
                    raise ValueError(
                        f"attempt_counts.{campaign}.{partition}.{role} "
                        + (
                            "must be a positive integer"
                            if role == "required"
                            else "must be a non-negative integer"
                        )
                    )
                normalized[campaign][partition][role] = count
    return normalized


def build_split_lock(
    policy_sha256: str,
    attempt_counts: Mapping[str, Any],
    locked_at_utc: str,
) -> dict[str, Any]:
    _equal(policy_sha256, POLICY_SHA256, "policy_sha256")
    if _utc_timestamp(
        locked_at_utc, "locked_at_utc"
    ) <= _utc_timestamp(POLICY_LOCKED_AT_UTC, "policy_locked_at_utc"):
        raise ValueError("locked_at_utc must be after the policy lock")
    counts = _normalize_locked_counts(attempt_counts)
    slots: list[dict[str, Any]] = []
    for campaign in CAMPAIGNS:
        for partition in PARTITIONS:
            for role in SLOT_ROLES:
                for ordinal in range(1, counts[campaign][partition][role] + 1):
                    slots.append(
                        {
                            "slot_id": (
                                f"{campaign}-{partition}-{role}-{ordinal:03d}"
                            ),
                            "campaign": campaign,
                            "partition": partition,
                            "role": role,
                            "ordinal": ordinal,
                            "usage": SLOT_USAGE[partition],
                            "state": "reserved",
                        }
                    )
    return {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "terminal_flow_model_v2_live_split_lock",
        "status": "counts_locked_capture_not_authorized",
        "locked_at_utc": locked_at_utc,
        "policy": {
            "path": POLICY_PATH,
            "sha256": policy_sha256,
        },
        "split": {
            "unit": "whole_attempt",
            "assignment_mode": "deterministic_reserved_slots",
            "assignment_time": "claim_receipt_create_new_before_capture",
            "attempt_counts": {
                "status": "locked",
                "by_campaign": counts,
            },
            "slots": slots,
            "cross_partition_attempt_reuse": False,
            "collection_session_cross_partition": False,
            "failed_claim_reuse": False,
            "replacement_policy": "predeclared_reserve_slot_only",
        },
        "gate": {
            "decision": "blocked_pending_capture_authorization",
            "training_authorized": False,
            "threshold_selection_authorized": False,
            "train_validation_capture_authorized": False,
            "holdout_capture_authorized": False,
            "holdout_access_authorized": False,
            "test_partition_may_be_opened": False,
            "next_gate": "capture_authorization_review",
        },
    }


def validate_split_lock_document(
    document: Mapping[str, Any],
    policy: LiveSplitPolicy,
    document_sha256: str | None = None,
) -> LiveSplitLock:
    if document_sha256 is not None:
        _sha256(document_sha256, "split_lock.document_sha256")
    lock = _mapping(document, "split_lock")
    _exact_keys(
        lock,
        (
            "schema_version",
            "task",
            "kind",
            "status",
            "locked_at_utc",
            "policy",
            "split",
            "gate",
        ),
        "split_lock",
    )
    policy_reference = _mapping(lock["policy"], "split_lock.policy")
    _exact_keys(policy_reference, ("path", "sha256"), "split_lock.policy")
    _equal(policy_reference["path"], POLICY_PATH, "split_lock.policy.path")
    _equal(policy_reference["sha256"], POLICY_SHA256, "split_lock.policy.sha256")
    _equal(policy.counts_status, "pending_user_lock", "policy.counts_status")
    split = _mapping(lock["split"], "split_lock.split")
    attempt_counts = _mapping(
        split.get("attempt_counts"), "split_lock.split.attempt_counts"
    )
    _exact_keys(
        attempt_counts,
        ("status", "by_campaign"),
        "split_lock.split.attempt_counts",
    )
    _equal(
        attempt_counts["status"],
        "locked",
        "split_lock.split.attempt_counts.status",
    )
    expected = build_split_lock(
        POLICY_SHA256,
        _mapping(
            attempt_counts["by_campaign"],
            "split_lock.split.attempt_counts.by_campaign",
        ),
        _nonempty_string(lock["locked_at_utc"], "split_lock.locked_at_utc"),
    )
    _equal(dict(lock), expected, "split_lock")
    slots = tuple(
        SplitSlot(
            slot_id=item["slot_id"],
            campaign=item["campaign"],
            partition=item["partition"],
            role=item["role"],
            ordinal=item["ordinal"],
            usage=item["usage"],
            state=item["state"],
        )
        for item in expected["split"]["slots"]
    )
    return LiveSplitLock(
        locked_at_utc=expected["locked_at_utc"],
        policy_sha256=POLICY_SHA256,
        attempt_counts=expected["split"]["attempt_counts"]["by_campaign"],
        slots=slots,
        train_validation_capture_authorized=expected["gate"][
            "train_validation_capture_authorized"
        ],
        training_authorized=False,
        threshold_selection_authorized=False,
        holdout_access_authorized=False,
        test_partition_may_be_opened=False,
        document_sha256=document_sha256,
    )


def load_split_lock(project_root: Path) -> LiveSplitLock:
    _assert_filesystem_allowlist()
    policy = load_policy(project_root)
    path = _safe_fixed_path(project_root, SPLIT_LOCK_PATH)
    if _hash_path(path) != SPLIT_LOCK_SHA256:
        raise ValueError("live-split lock SHA-256 mismatch")
    with path.open("r", encoding="utf-8") as source:
        document = json.load(source)
    return validate_split_lock_document(
        _mapping(document, "split_lock"),
        policy,
        document_sha256=SPLIT_LOCK_SHA256,
    )


def validate_claim_documents(
    documents: Sequence[Mapping[str, Any]],
    split_lock: LiveSplitLock,
    split_lock_sha256: str,
) -> tuple[SplitClaim, ...]:
    _sha256(split_lock_sha256, "split_lock_sha256")
    if split_lock.document_sha256 is not None:
        _equal(
            split_lock_sha256,
            split_lock.document_sha256,
            "split_lock_sha256",
        )
    slots = {slot.slot_id: slot for slot in split_lock.slots}
    seen_slots: set[str] = set()
    seen_attempts: set[str] = set()
    seen_run_tokens: set[str] = set()
    seen_contracts: set[str] = set()
    session_partitions: dict[str, str] = {}
    claims: list[SplitClaim] = []
    required_fields = (
        "schema_version",
        "task",
        "policy_sha256",
        "split_lock_sha256",
        "slot_id",
        "campaign",
        "partition",
        "collection_session_id",
        "attempt_id",
        "run_token",
        "run_contract_sha256",
        "claim_phase",
        "traffic_started",
    )
    for index, value in enumerate(documents):
        where = f"claims[{index}]"
        claim = _mapping(value, where)
        _exact_keys(claim, required_fields, where)
        _equal(claim["schema_version"], "1.0.0", f"{where}.schema_version")
        _equal(claim["task"], TASK, f"{where}.task")
        _equal(claim["policy_sha256"], POLICY_SHA256, f"{where}.policy_sha256")
        _equal(
            claim["split_lock_sha256"],
            split_lock_sha256,
            f"{where}.split_lock_sha256",
        )
        _equal(claim["claim_phase"], "before_capture", f"{where}.claim_phase")
        _equal(claim["traffic_started"], False, f"{where}.traffic_started")
        (
            slot_id,
            session_id,
            attempt_id,
            run_token,
            contract_sha256,
            attempt_campaign,
            attempt_timestamp,
        ) = _claim_identity(
            claim["slot_id"],
            claim["collection_session_id"],
            claim["attempt_id"],
            claim["run_token"],
            claim["run_contract_sha256"],
            where,
        )
        if slot_id not in slots:
            raise ValueError(f"{where}.slot_id is not reserved")
        slot = slots[slot_id]
        if slot.role != "required":
            raise ValueError(
                f"{where}.slot_id is a reserve slot; validated failure "
                "completion is not implemented"
            )
        if slot.partition not in CLAIMABLE_PARTITIONS:
            raise ValueError(
                f"{where}.slot_id partition is sealed before model lock"
            )
        _equal(claim["campaign"], slot.campaign, f"{where}.campaign")
        _equal(claim["partition"], slot.partition, f"{where}.partition")
        _equal(
            attempt_campaign,
            CAMPAIGN_ATTEMPT_PREFIXES[slot.campaign],
            f"{where}.attempt_id campaign prefix",
        )
        if attempt_timestamp <= _utc_timestamp(
            split_lock.locked_at_utc,
            "split_lock.locked_at_utc",
        ):
            raise ValueError(
                f"{where}.attempt_id must be created after the split lock"
            )
        forbidden_attempt_ids = {
            item["attempt_id"] for item in FORBIDDEN_ATTEMPTS
        }
        forbidden_contracts = {
            item["run_contract_sha256"] for item in FORBIDDEN_ATTEMPTS
        }
        if (
            attempt_id in forbidden_attempt_ids
            or contract_sha256 in forbidden_contracts
        ):
            raise ValueError(f"{where} reuses evidence forbidden by policy")
        for observed, seen, field in (
            (slot_id, seen_slots, "slot_id"),
            (attempt_id, seen_attempts, "attempt_id"),
            (run_token, seen_run_tokens, "run_token"),
            (contract_sha256, seen_contracts, "run_contract_sha256"),
        ):
            if observed in seen:
                raise ValueError(f"{where}.{field} is reused")
            seen.add(observed)
        prior_partition = session_partitions.setdefault(
            session_id, slot.partition
        )
        if prior_partition != slot.partition:
            raise ValueError(
                f"{where}.collection_session_id crosses partitions"
            )
        claims.append(
            SplitClaim(
                slot_id=slot_id,
                campaign=slot.campaign,
                partition=slot.partition,
                collection_session_id=session_id,
                attempt_id=attempt_id,
                run_token=run_token,
                run_contract_sha256=contract_sha256,
            )
        )
    return tuple(claims)


def build_claim_document(
    split_lock: LiveSplitLock,
    request: ClaimRequest,
    split_lock_sha256: str,
) -> dict[str, Any]:
    if not isinstance(request, ClaimRequest):
        raise TypeError("request must be a ClaimRequest")
    (
        slot_id,
        session_id,
        attempt_id,
        run_token,
        contract_sha256,
        _attempt_campaign,
        _attempt_timestamp,
    ) = _claim_identity(
        request.slot_id,
        request.collection_session_id,
        request.attempt_id,
        request.run_token,
        request.run_contract_sha256,
        "request",
    )
    slots = {slot.slot_id: slot for slot in split_lock.slots}
    if slot_id not in slots:
        raise ValueError("request.slot_id is not reserved")
    slot = slots[slot_id]
    document = {
        "schema_version": "1.0.0",
        "task": TASK,
        "policy_sha256": POLICY_SHA256,
        "split_lock_sha256": split_lock_sha256,
        "slot_id": slot_id,
        "campaign": slot.campaign,
        "partition": slot.partition,
        "collection_session_id": session_id,
        "attempt_id": attempt_id,
        "run_token": run_token,
        "run_contract_sha256": contract_sha256,
        "claim_phase": "before_capture",
        "traffic_started": False,
    }
    validate_claim_documents([document], split_lock, split_lock_sha256)
    return document


def _claimable_filenames(split_lock: LiveSplitLock) -> frozenset[str]:
    return frozenset(
        f"{slot.slot_id}.json"
        for slot in split_lock.slots
        if slot.role == "required" and slot.partition in CLAIMABLE_PARTITIONS
    )


def _claim_root_path(project_root: Path) -> Path:
    _assert_filesystem_allowlist()
    root = project_root.resolve()
    relative = Path(CLAIM_ROOT)
    candidate = root / relative
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError("claim root escapes project root") from error
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if _is_linklike(cursor):
            raise ValueError(f"claim root contains a link: {cursor}")
    return resolved


def _is_linklike(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (
        is_junction is not None and bool(is_junction())
    )


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON object contains duplicate key: {key}")
        value[key] = item
    return value


def _read_claim_documents(
    claim_root: Path,
    split_lock: LiveSplitLock,
    writer_lock_held: bool = False,
) -> tuple[Mapping[str, Any], ...]:
    allowed_filenames = _claimable_filenames(split_lock)
    if not claim_root.exists():
        return ()
    if _is_linklike(claim_root) or not claim_root.is_dir():
        raise ValueError("claim root must be a real directory")
    entries = tuple(claim_root.iterdir())
    allowed_entries = set(allowed_filenames)
    if writer_lock_held:
        allowed_entries.add(CLAIM_WRITER_LOCK)
    unexpected = sorted(
        entry.name for entry in entries if entry.name not in allowed_entries
    )
    if unexpected:
        raise ValueError(f"claim root contains unexpected entries: {unexpected}")
    documents: list[Mapping[str, Any]] = []
    for entry in sorted(entries, key=lambda item: item.name):
        if entry.name == CLAIM_WRITER_LOCK:
            if _is_linklike(entry) or not entry.is_file():
                raise ValueError("writer lock must be a regular file")
            continue
        if _is_linklike(entry) or not entry.is_file():
            raise ValueError(f"claim receipt is not a regular file: {entry.name}")
        try:
            with entry.open("rb") as source:
                document = json.load(
                    source,
                    object_pairs_hook=_unique_json_object,
                )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(
                f"claim receipt is unreadable: {entry.name}"
            ) from error
        claim = _mapping(document, f"claim receipt {entry.name}")
        slot_id = claim.get("slot_id")
        if not isinstance(slot_id, str) or entry.name != f"{slot_id}.json":
            raise ValueError(
                f"claim receipt filename does not match slot_id: {entry.name}"
            )
        documents.append(claim)
    validate_claim_documents(documents, split_lock, SPLIT_LOCK_SHA256)
    return tuple(documents)


def _write_json_new(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(
            value,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise FileExistsError(
                f"claim receipt already exists: {path.name}"
            ) from error
    finally:
        temporary.unlink(missing_ok=True)


def _load_claim_context(
    project_root: Path,
    request: ClaimRequest,
) -> tuple[LiveSplitLock, Path, dict[str, Any]]:
    _assert_filesystem_allowlist()
    if not isinstance(request, ClaimRequest):
        raise TypeError("request must be a ClaimRequest")
    _claim_identity(
        request.slot_id,
        request.collection_session_id,
        request.attempt_id,
        request.run_token,
        request.run_contract_sha256,
        "request",
    )
    split_lock = load_split_lock(project_root)
    if not split_lock.train_validation_capture_authorized:
        raise PermissionError("train/validation capture is not authorized")
    document = build_claim_document(
        split_lock,
        request,
        SPLIT_LOCK_SHA256,
    )
    return split_lock, _claim_root_path(project_root), document


def _prepare_claim_at_root(
    project_root: Path,
    request: ClaimRequest,
) -> tuple[Path, Mapping[str, Any]]:
    split_lock, claim_root, document = _load_claim_context(
        project_root,
        request,
    )
    existing = _read_claim_documents(claim_root, split_lock)
    validate_claim_documents(
        (*existing, document),
        split_lock,
        SPLIT_LOCK_SHA256,
    )
    return claim_root / f"{request.slot_id}.json", document


def _publish_claim_at_root(
    project_root: Path,
    request: ClaimRequest,
) -> tuple[Path, Mapping[str, Any]]:
    split_lock, claim_root, document = _load_claim_context(
        project_root,
        request,
    )
    claim_root.mkdir(parents=True, exist_ok=True)
    verified_claim_root = _claim_root_path(project_root)
    if verified_claim_root != claim_root:
        raise ValueError("claim root changed while it was being created")
    claim_root = verified_claim_root
    if _is_linklike(claim_root) or not claim_root.is_dir():
        raise ValueError("claim root must be a real directory")
    writer_lock = claim_root / CLAIM_WRITER_LOCK
    acquired = False
    try:
        with writer_lock.open("x", encoding="ascii", newline="\n") as output:
            acquired = True
            output.write(f"{os.getpid()}\n")
            output.flush()
            os.fsync(output.fileno())
        existing = _read_claim_documents(
            claim_root,
            split_lock,
            writer_lock_held=True,
        )
        validate_claim_documents(
            (*existing, document),
            split_lock,
            SPLIT_LOCK_SHA256,
        )
        target = claim_root / f"{request.slot_id}.json"
        _write_json_new(target, document)
        published = _read_claim_documents(
            claim_root,
            split_lock,
            writer_lock_held=True,
        )
        matching = [
            item for item in published if item.get("slot_id") == request.slot_id
        ]
        if len(matching) != 1 or dict(matching[0]) != document:
            raise RuntimeError("published claim failed read-back validation")
        return target, document
    finally:
        if acquired:
            writer_lock.unlink(missing_ok=True)


def _production_project_root() -> Path:
    _assert_filesystem_allowlist()
    return Path(__file__).resolve().parents[2]


def prepare_claim(
    request: ClaimRequest,
) -> tuple[Path, Mapping[str, Any]]:
    _assert_filesystem_allowlist()
    if not isinstance(request, ClaimRequest):
        raise TypeError("request must be a ClaimRequest")
    _claim_identity(
        request.slot_id,
        request.collection_session_id,
        request.attempt_id,
        request.run_token,
        request.run_contract_sha256,
        "request",
    )
    return _prepare_claim_at_root(_production_project_root(), request)


def publish_claim(
    request: ClaimRequest,
) -> tuple[Path, Mapping[str, Any]]:
    _assert_filesystem_allowlist()
    if not isinstance(request, ClaimRequest):
        raise TypeError("request must be a ClaimRequest")
    _claim_identity(
        request.slot_id,
        request.collection_session_id,
        request.attempt_id,
        request.run_token,
        request.run_contract_sha256,
        "request",
    )
    return _publish_claim_at_root(_production_project_root(), request)


def validate_published_claims() -> tuple[SplitClaim, ...]:
    _assert_filesystem_allowlist()
    project_root = _production_project_root()
    split_lock = load_split_lock(project_root)
    claim_root = _claim_root_path(project_root)
    documents = _read_claim_documents(claim_root, split_lock)
    return validate_claim_documents(
        documents,
        split_lock,
        SPLIT_LOCK_SHA256,
    )
