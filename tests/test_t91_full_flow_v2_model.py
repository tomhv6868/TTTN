from __future__ import annotations

import copy
import hashlib
import io
import inspect
import json
import shutil
import sys
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stderr
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import numpy as np
import pyarrow as pa


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT))

from nids_mvp import full_flow_v2_audit as audit  # noqa: E402
from nids_mvp import full_flow_v2_model as model  # noqa: E402
from nids_mvp import full_flow_v2_split as split  # noqa: E402
from scripts import claim_t91_model_v2_live_slot as claim_cli  # noqa: E402


def count_matrix(
    required: int = 1, reserve: int = 0
) -> dict[str, dict[str, dict[str, int]]]:
    return {
        campaign: {
            partition: {
                "required": required,
                "reserve": reserve,
            }
            for partition in split.PARTITIONS
        }
        for campaign in split.CAMPAIGNS
    }


def locked_split(
    reserve: int = 0,
    required: int = 1,
) -> tuple[dict[str, object], split.LiveSplitLock]:
    policy_document = json.loads(
        (ROOT / split.POLICY_PATH).read_text(encoding="utf-8")
    )
    policy = split.validate_policy_document(policy_document)
    document = split.build_split_lock(
        split.POLICY_SHA256,
        count_matrix(required=required, reserve=reserve),
        "2026-07-29T13:00:00+07:00",
    )
    return document, split.validate_split_lock_document(document, policy)


def claim_for(
    slot: split.SplitSlot,
    serial: int,
    split_lock_sha256: str,
    session_id: str | None = None,
) -> dict[str, object]:
    timestamp = datetime(
        2026,
        7,
        29,
        15,
        tzinfo=timezone.utc,
    ) + timedelta(seconds=serial)
    stamp = timestamp.strftime("%Y%m%d%H%M%S")
    nonce = f"{serial:08x}"
    attempt_prefix = split.CAMPAIGN_ATTEMPT_PREFIXES[slot.campaign]
    return {
        "schema_version": "1.0.0",
        "task": split.TASK,
        "policy_sha256": split.POLICY_SHA256,
        "split_lock_sha256": split_lock_sha256,
        "slot_id": slot.slot_id,
        "campaign": slot.campaign,
        "partition": slot.partition,
        "collection_session_id": session_id or f"session-{serial}",
        "attempt_id": f"t91-{attempt_prefix}-{stamp}-{nonce}",
        "run_token": f"rt-{stamp}-{nonce}",
        "run_contract_sha256": f"{serial + 1:064x}",
        "claim_phase": "before_capture",
        "traffic_started": False,
    }


def request_for(
    slot: split.SplitSlot,
    serial: int,
    session_id: str | None = None,
) -> split.ClaimRequest:
    claim = claim_for(
        slot,
        serial,
        split.SPLIT_LOCK_SHA256,
        session_id=session_id,
    )
    return split.ClaimRequest(
        slot_id=str(claim["slot_id"]),
        collection_session_id=str(claim["collection_session_id"]),
        attempt_id=str(claim["attempt_id"]),
        run_token=str(claim["run_token"]),
        run_contract_sha256=str(claim["run_contract_sha256"]),
    )


def authorized_split(
    reserve: int = 0,
    required: int = 1,
) -> split.LiveSplitLock:
    _document, verified = locked_split(
        reserve=reserve,
        required=required,
    )
    return replace(
        verified,
        train_validation_capture_authorized=True,
        document_sha256=split.SPLIT_LOCK_SHA256,
    )


@contextmanager
def workspace_project_root():
    parent = ROOT / "run_log" / ".test-model-v2-claims"
    project_root = parent / uuid.uuid4().hex
    project_root.mkdir(parents=True)
    try:
        yield project_root
    finally:
        resolved = project_root.resolve()
        resolved.relative_to(parent.resolve())
        shutil.rmtree(resolved)
        try:
            parent.rmdir()
        except OSError:
            pass


def reference_batch() -> tuple[pa.RecordBatch, tuple[str, ...]]:
    feature_names = [f"feature_{index}" for index in range(audit.FEATURE_COUNT)]
    feature_names[1] = "packet_count"
    feature_names[2] = "forward_packet_count"
    feature_names[3] = "reverse_packet_count"
    feature_names[54] = "protocol"
    features = np.zeros((2, audit.FEATURE_COUNT), dtype=np.float64)
    features[:, 0] = (100.0, 200.0)
    features[:, 1] = 2.0
    features[:, 2] = 1.0
    features[:, 3] = 1.0
    features[:, 54] = 6.0
    features[:, 66] = 1.0
    arrays = [
        pa.array(["train", "train"]),
        pa.array(["assigned", "assigned"]),
        pa.array(["Benign", "FTP-Patator"]),
        pa.array(["ignored-value", "ignored-value"]),
        pa.array([6, 6]),
        pa.array([2, 2]),
        pa.array([1, 1]),
        pa.array([1, 1]),
    ]
    arrays.extend(
        pa.array(features[:, index]) for index in range(audit.FEATURE_COUNT)
    )
    names = list(audit.REFERENCE_METADATA_COLUMNS) + feature_names
    return pa.record_batch(arrays, names=names), tuple(feature_names)


class LiveSplitPolicyTests(unittest.TestCase):
    def test_production_policy_is_exact_and_counts_remain_pending(self) -> None:
        path = ROOT / split.POLICY_PATH
        document = json.loads(path.read_text(encoding="utf-8"))
        policy = split.validate_policy_document(document)

        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            split.POLICY_SHA256,
        )
        self.assertEqual(policy.counts_status, "pending_user_lock")
        self.assertEqual(document["split"]["reserved_slots"], [])
        self.assertFalse(document["gate"]["training_authorized"])
        self.assertFalse(document["gate"]["test_partition_may_be_opened"])

    def test_pending_policy_rejects_mixed_counts_and_reserved_slots(self) -> None:
        original = json.loads(
            (ROOT / split.POLICY_PATH).read_text(encoding="utf-8")
        )
        cases = []
        mixed = copy.deepcopy(original)
        mixed["split"]["attempt_counts"]["by_campaign"][
            split.CAMPAIGNS[0]
        ]["train"]["required"] = 1
        cases.append(mixed)
        populated = copy.deepcopy(original)
        populated["split"]["reserved_slots"] = [{"slot_id": "unlocked"}]
        cases.append(populated)
        numeric_false = copy.deepcopy(original)
        numeric_false["gate"]["training_authorized"] = 0
        cases.append(numeric_false)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    split.validate_policy_document(document)

    def test_split_lock_slots_are_deterministic_and_complete(self) -> None:
        policy = split.validate_policy_document(
            json.loads((ROOT / split.POLICY_PATH).read_text(encoding="utf-8"))
        )
        counts = count_matrix(required=1, reserve=1)
        first = split.build_split_lock(
            split.POLICY_SHA256,
            counts,
            "2026-07-29T13:00:00+07:00",
        )
        second = split.build_split_lock(
            split.POLICY_SHA256,
            counts,
            "2026-07-29T13:00:00+07:00",
        )
        verified = split.validate_split_lock_document(first, policy)

        self.assertEqual(first, second)
        self.assertEqual(
            len(verified.slots),
            len(split.CAMPAIGNS)
            * len(split.PARTITIONS)
            * len(split.SLOT_ROLES),
        )
        self.assertEqual(
            verified.slots[0].slot_id,
            "ftp_patator_wrong_password-train-required-001",
        )
        self.assertEqual(
            verified.slots[1].slot_id,
            "ftp_patator_wrong_password-train-reserve-001",
        )

    def test_production_split_lock_matches_user_approved_matrix(self) -> None:
        path = ROOT / split.SPLIT_LOCK_PATH
        document = json.loads(path.read_text(encoding="utf-8"))
        verified = split.load_split_lock(ROOT)

        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            split.SPLIT_LOCK_SHA256,
        )
        self.assertEqual(
            verified.attempt_counts,
            model._approved_attempt_counts(),
        )
        self.assertEqual(verified.document_sha256, split.SPLIT_LOCK_SHA256)
        self.assertEqual(len(verified.slots), 40)
        self.assertEqual(
            sum(slot.role == "required" for slot in verified.slots),
            28,
        )
        self.assertEqual(
            sum(slot.role == "reserve" for slot in verified.slots),
            12,
        )
        self.assertFalse(verified.training_authorized)
        self.assertFalse(verified.holdout_access_authorized)

        policy = split.validate_policy_document(
            json.loads((ROOT / split.POLICY_PATH).read_text(encoding="utf-8"))
        )
        tampered = copy.deepcopy(document)
        tampered["split"]["attempt_counts"]["by_campaign"][
            split.CAMPAIGNS[0]
        ]["train"]["required"] = 4
        with self.assertRaises(ValueError):
            split.validate_split_lock_document(tampered, policy)

    def test_split_lock_rejects_invalid_count_or_timestamp(self) -> None:
        for value in (True, 0):
            counts = count_matrix()
            counts[split.CAMPAIGNS[0]]["train"]["required"] = value
            with self.subTest(required=value):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    split.build_split_lock(
                        split.POLICY_SHA256,
                        counts,
                        "2026-07-29T13:00:00+07:00",
                    )
        with self.assertRaisesRegex(ValueError, "after the policy lock"):
            split.build_split_lock(
                split.POLICY_SHA256,
                count_matrix(),
                "2026-07-29T05:00:00Z",
            )

    def test_claims_reject_reuse_cross_partition_and_diagnostics(self) -> None:
        _document, verified = locked_split()
        lock_sha = "a" * 64
        train_slot = verified.slots[0]
        validation_slot = verified.slots[1]
        valid = claim_for(train_slot, 1, lock_sha)
        self.assertEqual(
            split.validate_claim_documents([valid], verified, lock_sha)[0].slot_id,
            train_slot.slot_id,
        )
        production = split.load_split_lock(ROOT)
        production_claim = claim_for(
            production.slots[0],
            99,
            split.SPLIT_LOCK_SHA256,
        )
        split.validate_claim_documents(
            [production_claim],
            production,
            split.SPLIT_LOCK_SHA256,
        )
        with self.assertRaisesRegex(ValueError, "split_lock_sha256"):
            split.validate_claim_documents(
                [production_claim],
                production,
                "b" * 64,
            )

        duplicate_slot = [
            claim_for(train_slot, 1, lock_sha),
            claim_for(train_slot, 2, lock_sha),
        ]
        duplicate_attempt = [
            claim_for(train_slot, 1, lock_sha),
            claim_for(validation_slot, 2, lock_sha),
        ]
        duplicate_attempt[1]["attempt_id"] = duplicate_attempt[0]["attempt_id"]
        duplicate_attempt[1]["run_token"] = duplicate_attempt[0]["run_token"]
        cross_partition = [
            claim_for(train_slot, 1, lock_sha, session_id="shared-session"),
            claim_for(
                validation_slot,
                2,
                lock_sha,
                session_id="shared-session",
            ),
        ]
        forbidden = claim_for(train_slot, 1, lock_sha)
        forbidden["attempt_id"] = split.FORBIDDEN_ATTEMPTS[1]["attempt_id"]
        forbidden["run_token"] = "rt-20260729034112-f8763728"
        renamed_forbidden = claim_for(train_slot, 1, lock_sha)
        renamed_forbidden["run_contract_sha256"] = split.FORBIDDEN_ATTEMPTS[1][
            "run_contract_sha256"
        ]
        numeric_false = claim_for(train_slot, 1, lock_sha)
        numeric_false["traffic_started"] = 0

        for claims in (
            duplicate_slot,
            duplicate_attempt,
            cross_partition,
            [forbidden],
            [renamed_forbidden],
            [numeric_false],
        ):
            with self.subTest(claims=claims):
                with self.assertRaises(ValueError):
                    split.validate_claim_documents(claims, verified, lock_sha)

        _document, with_reserve = locked_split(reserve=1)
        reserve_claim = claim_for(with_reserve.slots[1], 1, lock_sha)
        with self.assertRaisesRegex(ValueError, "reserve slot"):
            split.validate_claim_documents(
                [reserve_claim],
                with_reserve,
                lock_sha,
            )

    def test_claims_reject_holdout_and_invalid_identity(self) -> None:
        _document, verified = locked_split()
        train_slot = next(
            slot for slot in verified.slots if slot.partition == "train"
        )
        holdout_slot = next(
            slot for slot in verified.slots if slot.partition == "holdout"
        )
        holdout_claim = claim_for(holdout_slot, 1, "a" * 64)
        with self.assertRaisesRegex(ValueError, "sealed"):
            split.validate_claim_documents(
                [holdout_claim],
                verified,
                "a" * 64,
            )

        mismatched = claim_for(train_slot, 2, "a" * 64)
        mismatched["run_token"] = "rt-20260729150003-00000003"
        before_lock = claim_for(train_slot, 3, "a" * 64)
        attempt_prefix = split.CAMPAIGN_ATTEMPT_PREFIXES[train_slot.campaign]
        before_lock["attempt_id"] = (
            f"t91-{attempt_prefix}-20260729050000-00000003"
        )
        before_lock["run_token"] = "rt-20260729050000-00000003"
        traversal = claim_for(train_slot, 4, "a" * 64)
        traversal["slot_id"] = "../train"
        wrong_campaign = claim_for(train_slot, 5, "a" * 64)
        wrong_prefix = (
            "http-normal"
            if attempt_prefix != "http-normal"
            else "ftp-patator"
        )
        wrong_campaign["attempt_id"] = (
            f"t91-{wrong_prefix}-20260729150005-00000005"
        )
        wrong_campaign["run_token"] = "rt-20260729150005-00000005"
        with self.assertRaisesRegex(ValueError, "campaign prefix"):
            split.validate_claim_documents(
                [wrong_campaign],
                verified,
                "a" * 64,
            )

        for claim in (mismatched, before_lock, traversal):
            with self.subTest(claim=claim):
                with self.assertRaises(ValueError):
                    split.validate_claim_documents(
                        [claim],
                        verified,
                        "a" * 64,
                    )


class ClaimWriterTests(unittest.TestCase):
    def test_publish_train_and_validation_create_new(self) -> None:
        verified = authorized_split()
        train_slot = next(
            slot for slot in verified.slots if slot.partition == "train"
        )
        validation_slot = next(
            slot for slot in verified.slots if slot.partition == "validation"
        )
        with workspace_project_root() as project_root:
            with mock.patch.object(
                split,
                "load_split_lock",
                return_value=verified,
            ):
                train_target, train_document = split._publish_claim_at_root(
                    project_root,
                    request_for(train_slot, 10),
                )
                validation_target, validation_document = (
                    split._publish_claim_at_root(
                        project_root,
                        request_for(validation_slot, 11),
                    )
                )
                original = train_target.read_bytes()
                with self.assertRaisesRegex(ValueError, "slot_id is reused"):
                    split._publish_claim_at_root(
                        project_root,
                        request_for(train_slot, 10),
                    )

            claim_root = project_root / split.CLAIM_ROOT
            self.assertEqual(
                train_target,
                claim_root / f"{train_slot.slot_id}.json",
            )
            self.assertEqual(
                validation_target,
                claim_root / f"{validation_slot.slot_id}.json",
            )
            self.assertEqual(json.loads(original), train_document)
            self.assertEqual(
                json.loads(validation_target.read_bytes()),
                validation_document,
            )
            self.assertEqual(train_target.read_bytes(), original)
            self.assertFalse((claim_root / split.CLAIM_WRITER_LOCK).exists())

    def test_holdout_reserve_and_closed_gate_do_not_create_root(self) -> None:
        verified = authorized_split(reserve=1)
        holdout_slot = next(
            slot
            for slot in verified.slots
            if slot.partition == "holdout" and slot.role == "required"
        )
        reserve_slot = next(
            slot for slot in verified.slots if slot.role == "reserve"
        )
        with workspace_project_root() as project_root:
            with mock.patch.object(
                split,
                "load_split_lock",
                return_value=verified,
            ):
                for slot in (holdout_slot, reserve_slot):
                    with self.subTest(slot=slot.slot_id):
                        with self.assertRaises(ValueError):
                            split._publish_claim_at_root(
                                project_root,
                                request_for(slot, slot.ordinal + 20),
                            )
            self.assertFalse((project_root / split.CLAIM_ROOT).exists())

        _document, closed = locked_split()
        request = request_for(closed.slots[0], 30)
        with (
            mock.patch.object(split, "load_split_lock", return_value=closed),
            mock.patch.object(
                split,
                "_claim_root_path",
                side_effect=AssertionError("claim root was accessed"),
            ) as claim_root_path,
        ):
            with self.assertRaisesRegex(PermissionError, "not authorized"):
                split._prepare_claim_at_root(ROOT, request)
        claim_root_path.assert_not_called()

    def test_allowlist_drift_stops_before_filesystem(self) -> None:
        verified = authorized_split()
        poisoned = dict(split.FILESYSTEM_ALLOWLIST)
        poisoned["claim_root"] = "run_log/not-locked"
        with (
            mock.patch.object(split, "FILESYSTEM_ALLOWLIST", poisoned),
            mock.patch.object(
                split,
                "_production_project_root",
                side_effect=AssertionError("filesystem access occurred"),
            ) as production_root,
        ):
            with self.assertRaisesRegex(ValueError, "allowlist drifted"):
                split.publish_claim(request_for(verified.slots[0], 40))
        production_root.assert_not_called()

    def test_unexpected_entry_is_rejected_before_open(self) -> None:
        verified = authorized_split()
        request = request_for(verified.slots[0], 50)
        with workspace_project_root() as project_root:
            claim_root = project_root / split.CLAIM_ROOT
            claim_root.mkdir(parents=True)
            (claim_root / "foreign.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    split,
                    "load_split_lock",
                    return_value=verified,
                ),
                mock.patch.object(
                    Path,
                    "open",
                    side_effect=AssertionError("foreign entry was opened"),
                ) as open_path,
            ):
                with self.assertRaisesRegex(ValueError, "unexpected entries"):
                    split._prepare_claim_at_root(project_root, request)
            open_path.assert_not_called()

    def test_malformed_duplicate_key_and_filename_mismatch_block(self) -> None:
        verified = authorized_split()
        slots = [
            slot
            for slot in verified.slots
            if slot.role == "required"
            and slot.partition in split.CLAIMABLE_PARTITIONS
        ]
        mismatched = claim_for(slots[1], 55, split.SPLIT_LOCK_SHA256)
        cases = (
            b"{",
            (
                '{"slot_id":"%s","slot_id":"%s"}\n'
                % (slots[0].slot_id, slots[0].slot_id)
            ).encode("utf-8"),
            (json.dumps(mismatched) + "\n").encode("utf-8"),
        )
        for payload in cases:
            with self.subTest(payload=payload[:40]):
                with workspace_project_root() as project_root:
                    claim_root = project_root / split.CLAIM_ROOT
                    claim_root.mkdir(parents=True)
                    receipt = claim_root / f"{slots[0].slot_id}.json"
                    receipt.write_bytes(payload)
                    with mock.patch.object(
                        split,
                        "load_split_lock",
                        return_value=verified,
                    ):
                        with self.assertRaises(ValueError):
                            split._prepare_claim_at_root(
                                project_root,
                                request_for(slots[0], 56),
                            )

    def test_stale_writer_lock_blocks_publication(self) -> None:
        verified = authorized_split()
        request = request_for(verified.slots[0], 60)
        with workspace_project_root() as project_root:
            claim_root = project_root / split.CLAIM_ROOT
            claim_root.mkdir(parents=True)
            writer_lock = claim_root / split.CLAIM_WRITER_LOCK
            writer_lock.write_text("stale\n", encoding="ascii")
            with mock.patch.object(
                split,
                "load_split_lock",
                return_value=verified,
            ):
                with self.assertRaises(FileExistsError):
                    split._publish_claim_at_root(project_root, request)
            self.assertEqual(writer_lock.read_text(encoding="ascii"), "stale\n")

    def test_concurrent_identity_reuse_publishes_once(self) -> None:
        verified = authorized_split(required=2)
        train_slots = [
            slot
            for slot in verified.slots
            if slot.campaign == split.CAMPAIGNS[0]
            and slot.partition == "train"
            and slot.role == "required"
        ]
        first = request_for(train_slots[0], 70)
        second = replace(first, slot_id=train_slots[1].slot_id)
        barrier = threading.Barrier(2)

        with workspace_project_root() as project_root:

            def publish(request: split.ClaimRequest) -> str:
                barrier.wait()
                try:
                    split._publish_claim_at_root(project_root, request)
                    return "published"
                except (FileExistsError, ValueError):
                    return "rejected"

            with (
                mock.patch.object(
                    split,
                    "load_split_lock",
                    return_value=verified,
                ),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                results = list(executor.map(publish, (first, second)))

            self.assertEqual(results.count("published"), 1)
            self.assertEqual(results.count("rejected"), 1)
            receipts = list((project_root / split.CLAIM_ROOT).glob("*.json"))
            self.assertEqual(len(receipts), 1)

    def test_claim_cli_rejects_path_flags(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(split.prepare_claim).parameters),
            ("request",),
        )
        self.assertEqual(
            tuple(inspect.signature(split.publish_claim).parameters),
            ("request",),
        )
        self.assertEqual(
            tuple(inspect.signature(split.validate_published_claims).parameters),
            (),
        )
        forbidden_flags = (
            "--input",
            "--output",
            "--root",
            "--project-root",
            "--claim-root",
            "--contract",
        )
        for flag in forbidden_flags:
            with (
                self.subTest(flag=flag),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                claim_cli.build_parser().parse_args(["validate", flag, "x"])


class ModelV2BoundaryTests(unittest.TestCase):
    def test_exact_fourteen_class_label_encoding(self) -> None:
        labels = ("Benign",) + audit.V2_ATTACK_FAMILY_CLASS_ORDER
        encoded = model.encode_assigned_labels(labels)

        np.testing.assert_array_equal(
            encoded.binary,
            np.asarray([0] + [1] * 13, dtype=np.uint8),
        )
        np.testing.assert_array_equal(
            encoded.end_to_end,
            np.arange(14, dtype=np.uint8),
        )
        np.testing.assert_array_equal(
            encoded.attack_family,
            np.arange(13, dtype=np.uint8),
        )
        self.assertFalse(encoded.attack_rows[0])

    def test_unknown_or_excluded_label_fails_closed(self) -> None:
        for label in ("Heartbleed", "FTP-Bruteforce", None):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    model.encode_assigned_labels([label])

    def test_profile_projection_uses_exact_non_prefix_indices(self) -> None:
        features = np.arange(model.FEATURE_COUNT, dtype=np.float64)[None, :]
        profile = model._profiles()[0]
        projected = model.project_profile(features, profile.profile_id)

        self.assertEqual(projected.dtype, np.float32)
        np.testing.assert_array_equal(
            projected[0],
            np.asarray(profile.feature_indices, dtype=np.float32),
        )
        with self.assertRaisesRegex(ValueError, "overflow"):
            model.project_profile(
                np.full(
                    (1, model.FEATURE_COUNT),
                    np.finfo(np.float64).max,
                ),
                profile.profile_id,
            )

    def test_decode_uses_physical_suffix_and_ignores_label_family(self) -> None:
        batch, feature_names = reference_batch()
        profile_id = model._profiles()[0].profile_id
        decoded = model.decode_labeled_batch(
            batch,
            feature_names,
            "train",
            profile_id,
        )

        np.testing.assert_array_equal(decoded.full_features[:, 1], [2.0, 2.0])
        np.testing.assert_array_equal(decoded.labels.binary, [0, 1])
        np.testing.assert_array_equal(decoded.labels.attack_family, [6])
        with self.assertRaisesRegex(ValueError, "only train or validation"):
            model.decode_labeled_batch(
                batch,
                feature_names,
                "holdout",
                profile_id,
            )

    def test_allowlist_drift_stops_before_path_resolution(self) -> None:
        poisoned = dict(model.PRODUCTION_PATH_ALLOWLIST)
        poisoned["holdout"] = "Z:/must-not-resolve/holdout.parquet"
        with (
            mock.patch.object(model, "PRODUCTION_PATH_ALLOWLIST", poisoned),
            mock.patch.object(
                Path,
                "resolve",
                side_effect=AssertionError("filesystem access occurred"),
            ) as resolve,
        ):
            with self.assertRaisesRegex(ValueError, "allowlist drifted"):
                model._production_paths(ROOT)
        resolve.assert_not_called()

    def test_current_task_keeps_every_execution_gate_closed(self) -> None:
        current_task = json.loads(
            (ROOT / model.CURRENT_TASK_PATH).read_text(encoding="utf-8")
        )
        model._verify_current_task(current_task)
        gate = current_task["gate"]

        self.assertFalse(gate["training_authorized"])
        self.assertFalse(gate["threshold_selection_authorized"])
        self.assertFalse(gate["train_validation_capture_authorized"])
        self.assertFalse(gate["holdout_capture_authorized"])
        self.assertFalse(gate["holdout_access_authorized"])
        self.assertFalse(gate["test_partition_may_be_opened"])

    def test_cli_exposes_check_only(self) -> None:
        with (
            mock.patch.object(
                model,
                "verify_preflight",
                side_effect=AssertionError("preflight must not run"),
            ),
            self.assertRaises(SystemExit),
        ):
            model.main(["fit"])


if __name__ == "__main__":
    unittest.main()
