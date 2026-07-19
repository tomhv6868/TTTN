#!/usr/bin/env python3
"""Independently verify and accept the T3.3 SQLite label-join artifact."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T3.3"
BUILD_KIND = "label_join_build"
ACCEPTANCE_KIND = "label_join_acceptance"
READ_SIZE = 8 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
TABLE_COLUMNS = {
    "metadata": ["key", "value"],
    "input_file": ["input_id", "capture_id", "kind", "path", "size_bytes", "sha256"],
    "flow": [
        "flow_id", "capture_id", "export_ordinal", "protocol", "low_ip", "low_port",
        "high_ip", "high_port", "forward_source_ip", "forward_source_port", "generation",
        "creation_timestamp_ns", "last_capture_timestamp_ns", "last_event_timestamp_ns",
        "packet_count", "forward_packet_count", "reverse_packet_count", "close_reason",
    ],
    "label_row": [
        "label_id", "capture_id", "csv_path", "csv_line", "flow_id_text", "source_ip",
        "source_port", "destination_ip", "destination_port", "protocol", "low_ip", "low_port",
        "high_ip", "high_port", "timestamp_text", "duration_us", "forward_packet_count",
        "backward_packet_count", "label",
    ],
    "quarantined_label_row": [
        "quarantine_id", "capture_id", "csv_path", "csv_line", "flow_id_text",
        "source_ip", "source_port", "destination_ip", "destination_port", "protocol",
        "low_ip", "low_port", "high_ip", "high_port", "timestamp_text", "duration_us",
        "forward_packet_count", "backward_packet_count", "label", "reason",
    ],
    "label_time_variant": [
        "label_id", "variant", "start_min_ns", "start_max_ns", "end_min_ns", "end_max_ns",
        "schedule_conflict", "role_conflict", "event_ids_json",
    ],
    "exporter_summary": [
        "capture_id", "records_read", "packets_parsed", "parser_errors", "packets_accepted",
        "ingest_errors", "exported_flows", "flows_closed",
    ],
    "candidate_edge": [
        "flow_id", "label_id", "variant", "required_tolerance_ns", "schedule_conflict",
        "role_conflict",
    ],
    "sweep_summary": [
        "tolerance_seconds", "raw_edge_count", "eligible_edge_count", "matched_count",
        "flow_total", "flow_unmatched", "flow_ambiguous", "flow_audit_conflict",
        "label_total", "label_unmatched", "label_ambiguous", "label_audit_conflict",
    ],
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source, object_pairs_hook=reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(READ_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError(f"expected relative project path: {value!r}")
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"path escapes project root: {value}")
    return path


def read_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                result[key] = value.strip().strip('"')
    except OSError:
        pass
    return result


def inspect_host() -> dict[str, Any]:
    release = read_os_release()
    try:
        product = Path("/sys/class/dmi/id/product_name").read_text(encoding="utf-8").strip()
    except OSError:
        product = ""
    return {
        "system": platform.system(), "os_id": release.get("ID"),
        "os_version": release.get("VERSION_ID"), "architecture": platform.machine(),
        "python": platform.python_version(),
        "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "virtualization_product": product,
    }


def host_errors(host: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    uid = host.get("effective_uid")
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        errors.append("host must be a normal user")
    if host.get("system") != "Linux" or host.get("os_id") != "ubuntu" or not str(
        host.get("os_version", "")
    ).startswith("24.04"):
        errors.append("host must be Ubuntu 24.04 Linux")
    if host.get("architecture") != "x86_64":
        errors.append("host architecture must be x86_64")
    if re.fullmatch(r"3\.12(?:\.\d+)?", str(host.get("python", ""))) is None:
        errors.append("host Python must be 3.12.x")
    if "vmware" not in str(host.get("virtualization_product", "")).casefold():
        errors.append("host must be the approved VMware guest")
    return errors


def contract_errors(contract: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != SCHEMA_VERSION or contract.get("task") != TASK:
        errors.append("contract schema/task mismatch")
    captures = contract.get("captures")
    if not isinstance(captures, list) or len(captures) != 5 or sum(
        len(item.get("csv", [])) for item in captures if isinstance(item, Mapping)
    ) != 8:
        errors.append("contract must map five PCAPs to eight CSVs")
    join = contract.get("join")
    if not isinstance(join, Mapping) or join.get("tolerance_sweep_seconds") != [0, 1, 5, 10, 30, 60]:
        errors.append("contract tolerance sweep mismatch")
    elif join.get("decision") != "exactly_one_mutual_eligible_candidate":
        errors.append("contract must require mutual uniqueness")
    elif join.get("unsupported_label_protocol_policy") != {
        "values": [0],
        "action": "quarantine_without_join_or_training",
        "reason": "unsupported_protocol",
        "retain_source_label": True,
        "other_values": "fail",
    }:
        errors.append("contract unsupported protocol policy mismatch")
    elif join.get("invalid_flow_duration_policy") != {
        "negative_values": "quarantine",
        "action": "quarantine_without_join_or_training",
        "reason": "invalid_flow_duration",
        "retain_source_value": True,
        "retain_source_label": True,
        "non_decimal_values": "fail",
    }:
        errors.append("contract invalid Flow Duration policy mismatch")
    for capture in captures if isinstance(captures, list) else []:
        for spec in capture.get("csv", []) if isinstance(capture, Mapping) else []:
            counts = spec.get("protocol_counts") if isinstance(spec, Mapping) else None
            if not isinstance(counts, Mapping) or set(counts) - {"0", "6", "17"} or sum(
                value for value in counts.values() if isinstance(value, int)
            ) != spec.get("nonempty_record_count"):
                errors.append("contract protocol accounting mismatch")
            negative_duration_count = (
                spec.get("negative_duration_count") if isinstance(spec, Mapping) else None
            )
            nonempty_record_count = (
                spec.get("nonempty_record_count") if isinstance(spec, Mapping) else None
            )
            if (
                not isinstance(negative_duration_count, int)
                or isinstance(negative_duration_count, bool)
                or negative_duration_count < 0
                or not isinstance(nonempty_record_count, int)
                or isinstance(nonempty_record_count, bool)
                or negative_duration_count > nonempty_record_count
            ):
                errors.append("contract negative Flow Duration accounting mismatch")
    capture_ids = {
        capture.get("id")
        for capture in captures if isinstance(capture, Mapping)
    }
    exporter_spec = contract.get("exporter")
    exclusion_policy = (
        exporter_spec.get("parser_exclusion_policy")
        if isinstance(exporter_spec, Mapping)
        else None
    )
    expected_exclusions = (
        exclusion_policy.get("expected_by_capture")
        if isinstance(exclusion_policy, Mapping)
        else None
    )
    evidence = (
        exclusion_policy.get("evidence")
        if isinstance(exclusion_policy, Mapping)
        else None
    )
    if (
        not isinstance(exporter_spec, Mapping)
        or exporter_spec.get("ingest_errors_allowed") != 0
        or not isinstance(exclusion_policy, Mapping)
        or exclusion_policy.get("action")
        != "exclude_from_flow_reconstruction_and_label_join"
        or exclusion_policy.get("accounting")
        != "exact_by_capture_from_locked_t1_2_full_scan"
        or exclusion_policy.get("allowed_categories")
        != ["non_ipv4", "ipv4_fragmented", "unsupported_transport"]
        or not isinstance(evidence, Mapping)
        or evidence.get("path") != "run_log/t1.2/flow-survey.json"
        or evidence.get("sha256")
        != "e92a3183caf1c2075da6f071eeaebf026787047a882985b45529a40ce2826afc"
        or evidence.get("task") != "T1.2"
        or evidence.get("status") != "passed"
        or not isinstance(evidence.get("file_receipts"), Mapping)
        or set(evidence["file_receipts"]) != capture_ids
        or not isinstance(expected_exclusions, Mapping)
        or set(expected_exclusions) != capture_ids
    ):
        errors.append("contract parser exclusion policy mismatch")
    else:
        fields = {"non_ipv4", "ipv4_fragmented", "unsupported_transport", "total"}
        valid = True
        for counts in expected_exclusions.values():
            if (
                not isinstance(counts, Mapping)
                or set(counts) != fields
                or any(
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                    for value in counts.values()
                )
                or counts["total"]
                != counts["non_ipv4"]
                + counts["ipv4_fragmented"]
                + counts["unsupported_transport"]
            ):
                valid = False
        if not valid or sum(
            counts["total"] for counts in expected_exclusions.values()
        ) != 418873:
            errors.append("contract parser exclusion accounting mismatch")
    sqlite_spec = contract.get("sqlite")
    if not isinstance(sqlite_spec, Mapping) or sqlite_spec.get("raw_packet_or_payload_storage") is not False:
        errors.append("contract raw payload policy mismatch")
    source = contract.get("source_evidence")
    schedule = source.get("official_schedule") if isinstance(source, Mapping) else None
    if not isinstance(schedule, Mapping) or schedule.get("timezone_published") is not False:
        errors.append("contract overclaims publisher timezone")
    return errors


def database_uri(path: Path) -> str:
    return f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"


def scalar(connection: sqlite3.Connection, sql: str, parameters: tuple[Any, ...] = ()) -> int:
    value = connection.execute(sql, parameters).fetchone()
    if value is None or not isinstance(value[0], int):
        raise ValueError(f"expected integer scalar for {sql}")
    return value[0]


def recompute_sweep(connection: sqlite3.Connection, seconds: int) -> dict[str, int]:
    tolerance = seconds * 1_000_000_000
    flow_total = scalar(connection, "SELECT COUNT(*) FROM flow")
    label_total = scalar(connection, "SELECT COUNT(*) FROM label_row")
    query = """
        WITH raw_pair AS (
            SELECT DISTINCT flow_id,label_id FROM candidate_edge WHERE required_tolerance_ns<=?
        ), eligible_pair AS (
            SELECT DISTINCT flow_id,label_id FROM candidate_edge
            WHERE required_tolerance_ns<=? AND schedule_conflict=0 AND role_conflict=0
        ), raw_fd AS (SELECT flow_id,COUNT(*) degree FROM raw_pair GROUP BY flow_id),
        raw_ld AS (SELECT label_id,COUNT(*) degree FROM raw_pair GROUP BY label_id),
        fd AS (SELECT flow_id,COUNT(*) degree FROM eligible_pair GROUP BY flow_id),
        ld AS (SELECT label_id,COUNT(*) degree FROM eligible_pair GROUP BY label_id),
        matched AS (
            SELECT e.flow_id,e.label_id FROM eligible_pair e
            JOIN fd ON fd.flow_id=e.flow_id AND fd.degree=1
            JOIN ld ON ld.label_id=e.label_id AND ld.degree=1
        )
        SELECT
            (SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<=?),
            (SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<=? AND schedule_conflict=0 AND role_conflict=0),
            (SELECT COUNT(*) FROM matched),
            (SELECT COUNT(*) FROM raw_fd),
            (SELECT COUNT(*) FROM raw_fd LEFT JOIN fd USING(flow_id) WHERE fd.flow_id IS NULL),
            (SELECT COUNT(*) FROM raw_ld),
            (SELECT COUNT(*) FROM raw_ld LEFT JOIN ld USING(label_id) WHERE ld.label_id IS NULL)
    """
    row = connection.execute(query, (tolerance, tolerance, tolerance, tolerance)).fetchone()
    if row is None:
        raise ValueError("could not recompute sweep")
    raw_edges, eligible_edges, matched, raw_flows, conflict_flows, raw_labels, conflict_labels = row
    flow_unmatched = flow_total - raw_flows
    label_unmatched = label_total - raw_labels
    return {
        "tolerance_seconds": seconds,
        "raw_edge_count": raw_edges,
        "eligible_edge_count": eligible_edges,
        "matched_count": matched,
        "flow_total": flow_total,
        "flow_unmatched": flow_unmatched,
        "flow_ambiguous": flow_total - matched - flow_unmatched - conflict_flows,
        "flow_audit_conflict": conflict_flows,
        "label_total": label_total,
        "label_unmatched": label_unmatched,
        "label_ambiguous": label_total - matched - label_unmatched - conflict_labels,
        "label_audit_conflict": conflict_labels,
    }


def expected_edge_difference(
    connection: sqlite3.Connection,
    maximum_tolerance_ns: int,
) -> int:
    query = """
        WITH expected AS (
            SELECT f.flow_id, l.label_id, v.variant,
                   CASE
                       WHEN f.last_event_timestamp_ns < v.start_min_ns
                           THEN v.start_min_ns - f.last_event_timestamp_ns
                       WHEN v.end_max_ns <= f.creation_timestamp_ns
                           THEN f.creation_timestamp_ns - v.end_max_ns + 1
                       ELSE 0
                   END AS required_tolerance_ns,
                   v.schedule_conflict, v.role_conflict
            FROM flow AS f
            JOIN label_row AS l
              ON l.capture_id=f.capture_id AND l.protocol=f.protocol
             AND l.low_ip=f.low_ip AND l.low_port=f.low_port
             AND l.high_ip=f.high_ip AND l.high_port=f.high_port
            JOIN label_time_variant AS v ON v.label_id=l.label_id
            WHERE f.last_event_timestamp_ns + ? >= v.start_min_ns
              AND v.end_max_ns + ? > f.creation_timestamp_ns
        )
        SELECT
            (SELECT COUNT(*) FROM (
                SELECT * FROM expected
                EXCEPT
                SELECT * FROM candidate_edge
            ))
            +
            (SELECT COUNT(*) FROM (
                SELECT * FROM candidate_edge
                EXCEPT
                SELECT * FROM expected
            ))
    """
    return scalar(
        connection,
        query,
        (maximum_tolerance_ns, maximum_tolerance_ns),
    )


def validate_database(
    database: Path,
    contract: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    if not database.is_file():
        return [f"database missing: {database}"]
    if database.with_name(database.name + "-wal").exists() or database.with_name(database.name + "-shm").exists():
        errors.append("final database must not have WAL/SHM sidecars")
    try:
        connection = sqlite3.connect(database_uri(database), uri=True)
    except sqlite3.Error as error:
        return [f"cannot open database read-only: {error}"]
    try:
        sqlite_spec = contract["sqlite"]
        if scalar(connection, "PRAGMA application_id") != sqlite_spec["application_id"]:
            errors.append("SQLite application_id mismatch")
        if scalar(connection, "PRAGMA user_version") != sqlite_spec["user_version"]:
            errors.append("SQLite user_version mismatch")
        journal = connection.execute("PRAGMA journal_mode").fetchone()
        if journal != ("delete",):
            errors.append("final SQLite journal mode is not DELETE")
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            errors.append("SQLite integrity_check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            errors.append("SQLite foreign_key_check failed")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != set(TABLE_COLUMNS):
            errors.append("SQLite table set mismatch")
        for table, expected in TABLE_COLUMNS.items():
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            if columns != expected:
                errors.append(f"SQLite columns mismatch: {table}")
            forbidden = [name for name in columns if "payload" in name.casefold() or name.casefold() in {"raw", "raw_bytes", "packet_bytes"}]
            if forbidden:
                errors.append(f"raw/payload columns are forbidden: {table}.{forbidden}")
        strict_tables = {
            row[1]
            for row in connection.execute("PRAGMA table_list")
            if row[1] in TABLE_COLUMNS and row[5] == 1
        }
        if strict_tables != set(TABLE_COLUMNS):
            errors.append("all application tables must be STRICT")
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        if metadata.get("contract_sha256") != receipt.get("contract", {}).get("sha256"):
            errors.append("database contract hash metadata mismatch")
        if metadata.get("timezone_status") != "inference_to_be_audited_not_publisher_metadata":
            errors.append("database timezone status overclaim")
        if metadata.get("decision") != "exactly_one_mutual_eligible_candidate":
            errors.append("database join decision mismatch")
        exporter_record = receipt.get("exporter")
        if not isinstance(exporter_record, Mapping) or metadata.get(
            "exporter_sha256"
        ) != exporter_record.get("sha256"):
            errors.append("database exporter hash metadata mismatch")
        sources = receipt.get("sources")
        db_sources = [
            {"capture_id": row[0], "kind": row[1], "path": row[2], "size_bytes": row[3], "sha256": row[4]}
            for row in connection.execute(
                "SELECT capture_id,kind,path,size_bytes,sha256 FROM input_file ORDER BY input_id"
            )
        ]
        if sources != db_sources:
            errors.append("database source provenance differs from receipt")
        flow_total = scalar(connection, "SELECT COUNT(*) FROM flow")
        label_total = scalar(connection, "SELECT COUNT(*) FROM label_row")
        quarantined_total = scalar(connection, "SELECT COUNT(*) FROM quarantined_label_row")
        variant_total = scalar(connection, "SELECT COUNT(*) FROM label_time_variant")
        edge_total = scalar(connection, "SELECT COUNT(*) FROM candidate_edge")
        if receipt.get("flows", {}).get("total") != flow_total:
            errors.append("flow total mismatch")
        if receipt.get("labels", {}).get("eligible_records") != label_total:
            errors.append("eligible label total mismatch")
        if receipt.get("labels", {}).get("quarantined_records") != quarantined_total:
            errors.append("quarantined label total mismatch")
        if receipt.get("labels", {}).get("timestamp_variants") != variant_total:
            errors.append("timestamp variant total mismatch")
        if receipt.get("candidate_edges") != edge_total:
            errors.append("candidate edge total mismatch")
        expected_physical = sum(
            spec["physical_record_count"]
            for capture in contract["captures"]
            for spec in capture["csv"]
        )
        expected_empty = sum(
            spec["all_empty_record_count"]
            for capture in contract["captures"]
            for spec in capture["csv"]
        )
        expected_nonempty = sum(
            spec["nonempty_record_count"]
            for capture in contract["captures"]
            for spec in capture["csv"]
        )
        expected_unsupported_protocol = sum(
            spec["protocol_counts"].get("0", 0)
            for capture in contract["captures"]
            for spec in capture["csv"]
        )
        expected_invalid_duration = sum(
            spec["negative_duration_count"]
            for capture in contract["captures"]
            for spec in capture["csv"]
        )
        expected_quarantined = expected_unsupported_protocol + expected_invalid_duration
        labels_record = receipt.get("labels")
        if not isinstance(labels_record, Mapping) or (
            labels_record.get("physical_records"),
            labels_record.get("all_empty_records"),
            labels_record.get("nonempty_records"),
            labels_record.get("eligible_records"),
            labels_record.get("quarantined_records"),
            labels_record.get("quarantine_reason_counts"),
        ) != (
            expected_physical,
            expected_empty,
            expected_nonempty,
            expected_nonempty - expected_quarantined,
            expected_quarantined,
            {
                "invalid_flow_duration": expected_invalid_duration,
                "unsupported_protocol": expected_unsupported_protocol,
            },
        ):
            errors.append("label receipt accounting differs from locked contract")
        expected_label_groups = {
            (capture["id"], spec["path"], label): count
            for capture in contract["captures"]
            for spec in capture["csv"]
            for label, count in spec["label_counts"].items()
        }
        observed_label_groups = {
            (row[0], row[1], row[2]): row[3]
            for row in connection.execute(
                "SELECT capture_id,csv_path,label,COUNT(*) FROM ("
                "SELECT capture_id,csv_path,label FROM label_row UNION ALL "
                "SELECT capture_id,csv_path,label FROM quarantined_label_row) "
                "GROUP BY capture_id,csv_path,label"
            )
        }
        if observed_label_groups != expected_label_groups:
            errors.append("database label provenance/counts differ from locked contract")
        expected_protocol_groups = {
            (capture["id"], spec["path"], int(protocol)): count
            for capture in contract["captures"]
            for spec in capture["csv"]
            for protocol, count in spec["protocol_counts"].items()
        }
        observed_protocol_groups = {
            (row[0], row[1], row[2]): row[3]
            for row in connection.execute(
                "SELECT capture_id,csv_path,protocol,COUNT(*) FROM ("
                "SELECT capture_id,csv_path,protocol FROM label_row UNION ALL "
                "SELECT capture_id,csv_path,protocol FROM quarantined_label_row) "
                "GROUP BY capture_id,csv_path,protocol"
            )
        }
        if observed_protocol_groups != expected_protocol_groups:
            errors.append("database protocol provenance/counts differ from locked contract")
        expected_negative_duration_groups = {
            (capture["id"], spec["path"]): spec["negative_duration_count"]
            for capture in contract["captures"]
            for spec in capture["csv"]
            if spec["negative_duration_count"]
        }
        observed_negative_duration_groups = {
            (row[0], row[1]): row[2]
            for row in connection.execute(
                "SELECT capture_id,csv_path,COUNT(*) FROM quarantined_label_row "
                "WHERE duration_us<0 GROUP BY capture_id,csv_path"
            )
        }
        if observed_negative_duration_groups != expected_negative_duration_groups:
            errors.append("negative Flow Duration provenance/counts differ from locked contract")
        invalid_flow = scalar(
            connection,
            "SELECT COUNT(*) FROM flow WHERE packet_count!=forward_packet_count+reverse_packet_count OR creation_timestamp_ns>last_event_timestamp_ns OR protocol NOT IN(6,17)"
        )
        if invalid_flow:
            errors.append("invalid flow scalar accounting")
        invalid_flow_identity = scalar(
            connection,
            """
                SELECT COUNT(*) FROM flow
                WHERE generation<1
                   OR low_port NOT BETWEEN 0 AND 65535
                   OR high_port NOT BETWEEN 0 AND 65535
                   OR forward_source_port NOT BETWEEN 0 AND 65535
                   OR low_ip NOT BETWEEN 0 AND 4294967295
                   OR high_ip NOT BETWEEN 0 AND 4294967295
                   OR forward_source_ip NOT BETWEEN 0 AND 4294967295
                   OR (low_ip,low_port)>(high_ip,high_port)
                   OR (forward_source_ip,forward_source_port) NOT IN (
                       (low_ip,low_port),(high_ip,high_port)
                   )
            """,
        )
        if invalid_flow_identity:
            errors.append("invalid flow identity")
        expected_capture_ids = {capture["id"] for capture in contract["captures"]}
        observed_flow_counts = dict(
            connection.execute("SELECT capture_id,COUNT(*) FROM flow GROUP BY capture_id")
        )
        if set(observed_flow_counts) - expected_capture_ids:
            errors.append("flow contains an unknown capture_id")
        invalid_variant = scalar(
            connection,
            "SELECT COUNT(*) FROM label_time_variant WHERE start_min_ns>=start_max_ns OR end_min_ns>end_max_ns OR schedule_conflict NOT IN(0,1) OR role_conflict NOT IN(0,1)"
        )
        if invalid_variant:
            errors.append("invalid label timestamp/audit variant")
        invalid_variant_duration = scalar(
            connection,
            """
                SELECT COUNT(*)
                FROM label_time_variant AS v
                JOIN label_row AS l USING(label_id)
                WHERE v.variant NOT IN('as_written','plus_12h')
                   OR v.start_max_ns-v.start_min_ns NOT IN(1000000000,60000000000)
                   OR v.end_min_ns-v.start_min_ns!=l.duration_us*1000
                   OR v.end_max_ns-v.start_max_ns!=l.duration_us*1000
            """,
        )
        if invalid_variant_duration:
            errors.append("label timestamp variant does not match duration/resolution")
        invalid_label_identity = scalar(
            connection,
            """
                SELECT COUNT(*) FROM label_row
                WHERE protocol NOT IN(6,17)
                   OR source_port NOT BETWEEN 0 AND 65535
                   OR destination_port NOT BETWEEN 0 AND 65535
                   OR low_port NOT BETWEEN 0 AND 65535
                   OR high_port NOT BETWEEN 0 AND 65535
                   OR source_ip NOT BETWEEN 0 AND 4294967295
                   OR destination_ip NOT BETWEEN 0 AND 4294967295
                   OR low_ip NOT BETWEEN 0 AND 4294967295
                   OR high_ip NOT BETWEEN 0 AND 4294967295
                   OR duration_us<0 OR forward_packet_count<0 OR backward_packet_count<0
                   OR (low_ip,low_port)>(high_ip,high_port)
                   OR NOT (
                       ((source_ip,source_port)=(low_ip,low_port)
                        AND (destination_ip,destination_port)=(high_ip,high_port))
                       OR
                       ((destination_ip,destination_port)=(low_ip,low_port)
                        AND (source_ip,source_port)=(high_ip,high_port))
                   )
            """,
        )
        if invalid_label_identity:
            errors.append("invalid label canonical identity")
        invalid_quarantine = scalar(
            connection,
            """
                SELECT COUNT(*) FROM quarantined_label_row
                WHERE NOT (
                       (reason='unsupported_protocol' AND protocol=0 AND duration_us>=0)
                       OR
                       (reason='invalid_flow_duration' AND protocol IN(6,17) AND duration_us<0)
                   )
                   OR source_port NOT BETWEEN 0 AND 65535
                   OR destination_port NOT BETWEEN 0 AND 65535
                   OR low_port NOT BETWEEN 0 AND 65535
                   OR high_port NOT BETWEEN 0 AND 65535
                   OR source_ip NOT BETWEEN 0 AND 4294967295
                   OR destination_ip NOT BETWEEN 0 AND 4294967295
                   OR low_ip NOT BETWEEN 0 AND 4294967295
                   OR high_ip NOT BETWEEN 0 AND 4294967295
                   OR forward_packet_count<0 OR backward_packet_count<0
                   OR (low_ip,low_port)>(high_ip,high_port)
                   OR NOT (
                       ((source_ip,source_port)=(low_ip,low_port)
                        AND (destination_ip,destination_port)=(high_ip,high_port))
                       OR
                       ((destination_ip,destination_port)=(low_ip,low_port)
                        AND (source_ip,source_port)=(high_ip,high_port))
                   )
            """,
        )
        if invalid_quarantine:
            errors.append("invalid quarantined label identity or reason")
        invalid_edge = scalar(
            connection,
            "SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<0 OR required_tolerance_ns>60000000000 OR schedule_conflict NOT IN(0,1) OR role_conflict NOT IN(0,1)"
        )
        if invalid_edge:
            errors.append("invalid candidate edge")
        maximum_tolerance_ns = (
            contract["join"]["maximum_candidate_tolerance_seconds"]
            * 1_000_000_000
        )
        if expected_edge_difference(connection, maximum_tolerance_ns):
            errors.append("candidate graph differs from independently derived graph")
        receipt_summaries = receipt.get("exporter", {}).get("summaries")
        db_summaries = [
            {
                "capture_id": row[0], "records_read": row[1], "packets_parsed": row[2],
                "parser_errors": row[3], "packets_accepted": row[4], "ingest_errors": row[5],
                "exported_flows": row[6], "flows_closed": row[7],
            }
            for row in connection.execute("SELECT * FROM exporter_summary ORDER BY rowid")
        ]
        if receipt_summaries != db_summaries:
            errors.append("exporter summaries differ from database")
        expected_parser_exclusions = contract["exporter"][
            "parser_exclusion_policy"
        ]["expected_by_capture"]
        if any(item["ingest_errors"] for item in db_summaries):
            errors.append("exporter ingest error is fatal")
        if sum(item["exported_flows"] for item in db_summaries) != flow_total:
            errors.append("exporter summary flow accounting mismatch")
        if {item["capture_id"] for item in db_summaries} != expected_capture_ids:
            errors.append("exporter summaries do not cover the five captures exactly")
        elif any(
            observed_flow_counts.get(item["capture_id"], 0) != item["exported_flows"]
            or item["parser_errors"]
            != expected_parser_exclusions[item["capture_id"]]["total"]
            or item["records_read"]
            != item["packets_parsed"] + item["parser_errors"]
            or item["packets_parsed"] != item["packets_accepted"]
            or item["exported_flows"] != item["flows_closed"]
            for item in db_summaries
        ):
            errors.append("per-capture exporter accounting mismatch")
        recorded_sweeps = receipt.get("sweeps")
        db_sweeps = [dict(zip(TABLE_COLUMNS["sweep_summary"], row)) for row in connection.execute("SELECT * FROM sweep_summary ORDER BY tolerance_seconds")]
        recomputed = [recompute_sweep(connection, seconds) for seconds in [0, 1, 5, 10, 30, 60]]
        if recorded_sweeps != db_sweeps or db_sweeps != recomputed:
            errors.append("sweep summary does not match independently recomputed graph")
        for sweep in recomputed:
            if sweep["flow_total"] != sweep["matched_count"] + sweep["flow_unmatched"] + sweep["flow_ambiguous"] + sweep["flow_audit_conflict"]:
                errors.append("flow sweep equation failed")
            if sweep["label_total"] != sweep["matched_count"] + sweep["label_unmatched"] + sweep["label_ambiguous"] + sweep["label_audit_conflict"]:
                errors.append("label sweep equation failed")
    except (KeyError, sqlite3.Error, TypeError, ValueError) as error:
        errors.append(f"database validation error: {error}")
    finally:
        connection.close()
    return errors


def validate_receipt(
    receipt: Mapping[str, Any],
    contract: Mapping[str, Any],
    project_root: Path,
    database: Path,
    rehash_sources: bool = False,
    enforce_host: bool = False,
) -> list[str]:
    errors = contract_errors(contract)
    if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("task") != TASK or receipt.get("kind") != BUILD_KIND or receipt.get("status") != "passed":
        errors.append("build receipt schema/task/status mismatch")
    contract_record = receipt.get("contract")
    expected_contract_path = project_root / "config" / "cicids2017-label-join-contract.json"
    if not isinstance(contract_record, Mapping) or contract_record.get("path") != "config/cicids2017-label-join-contract.json":
        errors.append("build receipt contract path mismatch")
    elif contract_record.get("sha256") != sha256_path(expected_contract_path):
        errors.append("build receipt contract hash mismatch")
    try:
        exclusion_policy = contract["exporter"]["parser_exclusion_policy"]
        evidence = exclusion_policy["evidence"]
        aggregate_path = resolve_path(project_root, evidence["path"])
        if sha256_path(aggregate_path) != evidence["sha256"]:
            errors.append("T1.2 aggregate flow-survey hash mismatch")
        expected_exclusions = exclusion_policy["expected_by_capture"]
        captures_by_id = {
            capture["id"]: capture for capture in contract["captures"]
        }
        for capture_id, spec in evidence["file_receipts"].items():
            path = resolve_path(project_root, spec["path"])
            if sha256_path(path) != spec["sha256"]:
                errors.append(f"T1.2 file-survey hash mismatch: {capture_id}")
                continue
            document = load_json(path)
            ignored = document.get("statistics", {}).get("ignored_packets", {})
            expected = expected_exclusions[capture_id]
            observed = {
                "non_ipv4": ignored.get("non_ipv4"),
                "ipv4_fragmented": ignored.get("ipv4_fragmented"),
                "unsupported_transport": ignored.get("unsupported_transport"),
            }
            if (
                document.get("task") != "T1.2"
                or document.get("status") != "passed"
                or document.get("source", {}).get("name")
                != Path(captures_by_id[capture_id]["pcap"]["path"]).name
                or observed != {key: expected[key] for key in observed}
                or sum(observed.values()) != expected["total"]
            ):
                errors.append(f"T1.2 file-survey content mismatch: {capture_id}")
    except (KeyError, OSError, TypeError, ValueError) as error:
        errors.append(f"parser exclusion evidence validation error: {error}")
    sqlite_record = receipt.get("sqlite")
    if not isinstance(sqlite_record, Mapping):
        errors.append("build receipt SQLite evidence missing")
    else:
        if sqlite_record.get("path") != contract["sqlite"]["artifact"]:
            errors.append("SQLite artifact path mismatch")
        if sqlite_record.get("size_bytes") != database.stat().st_size:
            errors.append("SQLite artifact size mismatch")
        if sqlite_record.get("sha256") != sha256_path(database):
            errors.append("SQLite artifact hash mismatch")
        if sqlite_record.get("journal_mode") != "delete" or sqlite_record.get("integrity_check") != "ok":
            errors.append("SQLite finalization evidence mismatch")
    sources = receipt.get("sources")
    if not isinstance(sources, list) or len(sources) != 13:
        errors.append("source provenance must contain five PCAPs and eight CSVs")
        sources = []
    contracted = {
        spec["path"]: (capture["id"], kind, spec["size_bytes"], spec["sha256"])
        for capture in contract.get("captures", [])
        for kind, spec in [("pcap", capture["pcap"]), *[("csv", item) for item in capture["csv"]]]
    }
    if {item.get("path") for item in sources if isinstance(item, Mapping)} != set(contracted):
        errors.append("source provenance set mismatch")
    for item in sources:
        if not isinstance(item, Mapping) or item.get("path") not in contracted:
            continue
        capture_id, kind, size, digest = contracted[item["path"]]
        if (item.get("capture_id"), item.get("kind"), item.get("size_bytes"), item.get("sha256")) != (capture_id, kind, size, digest):
            errors.append(f"source provenance mismatch: {item['path']}")
            continue
        if rehash_sources:
            path = resolve_path(project_root, item["path"])
            if path.stat().st_size != size or sha256_path(path) != digest:
                errors.append(f"current source content mismatch: {item['path']}")
    expected_checks = {
        "sources.content_addressed_before_processing", "exporter.strict_jsonl_contract",
        "exporter.exact_parser_exclusions_and_zero_ingest_errors",
        "labels.unsupported_protocol_quarantined",
        "labels.invalid_flow_duration_quarantined",
        "join.fail_closed_mutual_uniqueness", "join.sweep_accounting",
        "sqlite.local_single_writer_then_copy", "sqlite.integrity",
    }
    checks = receipt.get("checks")
    if not isinstance(checks, list) or {
        item.get("name") for item in checks if isinstance(item, Mapping) and item.get("status") == "passed"
    } != expected_checks or len(checks) != len(expected_checks):
        errors.append("build receipt checks mismatch")
    if enforce_host:
        errors.extend(host_errors(receipt.get("host", {})))
    errors.extend(validate_database(database, contract, receipt))
    return errors


def write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists() or os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary = output.name
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
        raise


def command_validate(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract = load_json(root / "config" / "cicids2017-label-join-contract.json")
    receipt = load_json(args.input)
    errors = validate_receipt(
        receipt, contract, root, args.database.resolve(),
        rehash_sources=args.rehash_sources, enforce_host=args.enforce_host,
    )
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid T3.3 build: {args.database}")
    return 0


def command_accept(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    host = inspect_host()
    current_host_errors = host_errors(host)
    if current_host_errors:
        raise RuntimeError("; ".join(current_host_errors))
    contract_path = root / "config" / "cicids2017-label-join-contract.json"
    contract = load_json(contract_path)
    receipt = load_json(args.input)
    database = args.database.resolve()
    errors = validate_receipt(
        receipt, contract, root, database,
        rehash_sources=True, enforce_host=True,
    )
    if errors:
        raise ValueError(f"cannot accept invalid T3.3 build: {errors}")
    acceptance = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": ACCEPTANCE_KIND,
        "status": "passed",
        "generated_at_utc": utc_now(),
        "host": host,
        "contract": {"path": "config/cicids2017-label-join-contract.json", "sha256": sha256_path(contract_path)},
        "build": {"path": args.input.resolve().relative_to(root).as_posix(), "sha256": sha256_path(args.input)},
        "sqlite": {"path": database.relative_to(root).as_posix(), "size_bytes": database.stat().st_size, "sha256": sha256_path(database)},
        "source_rehashed": True,
        "independent_graph_recomputed": True,
        "checks": [
            {"name": "build.receipt_independent_validation", "status": "passed"},
            {"name": "sqlite.read_only_integrity_and_schema", "status": "passed"},
            {"name": "sources.current_content_rehashed", "status": "passed"},
            {"name": "join.graph_and_accounting_recomputed", "status": "passed"},
        ],
    }
    write_json_atomic(args.output, acceptance)
    print(f"wrote {args.output} (passed)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "accept"):
        command = subparsers.add_parser(name)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument("--input", type=Path, default=root / "run_log" / "t3.3" / "build.json")
        command.add_argument("--database", type=Path, default=root / "run_log" / "t3.3" / "label-join.sqlite3")
        if name == "validate":
            command.add_argument("--rehash-sources", action="store_true")
            command.add_argument("--enforce-host", action="store_true")
            command.set_defaults(handler=command_validate)
        else:
            command.add_argument("--output", type=Path, default=root / "run_log" / "t3.3" / "acceptance.json")
            command.set_defaults(handler=command_accept)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
