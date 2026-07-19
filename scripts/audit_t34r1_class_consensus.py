from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence


SOURCE_COLUMNS = {
    "candidate_edge": {
        "flow_id", "label_id", "required_tolerance_ns", "schedule_conflict", "role_conflict"
    },
    "flow": {
        "flow_id", "capture_id", "forward_source_ip", "forward_source_port",
        "creation_timestamp_ns", "last_event_timestamp_ns", "packet_count",
        "forward_packet_count", "reverse_packet_count",
    },
    "label_row": {
        "label_id", "label", "source_ip", "source_port", "duration_us",
        "forward_packet_count", "backward_packet_count",
    },
    "quarantined_label_row": {"label", "reason"},
}
DERIVED_COLUMNS = {
    "flow_assignment": {
        "flow_id", "capture_id", "assigned_class", "assignment_method",
        "eligible_candidate_count", "distinct_eligible_candidate_class_count",
        "eligible_candidate_label_ids_json", "mutual_unique_label_id",
    },
    "assignment_candidate": {
        "flow_id", "label_id", "candidate_class", "eligible_variant_count",
        "minimum_required_tolerance_ns",
    },
    "quarantine": {
        "flow_id", "capture_id", "reason", "raw_candidate_count",
        "eligible_candidate_count", "distinct_eligible_candidate_class_count",
    },
    "build_metadata": {"key", "value"},
}


class Progress:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.stage = ""
        self.started = 0.0
        self.last = 0.0
        connection.set_progress_handler(self._report, 1_000_000)

    def start(self, stage: str) -> None:
        self.stage = stage
        self.started = self.last = time.monotonic()
        print(f"T3.4R1 stage={stage} status=running elapsed=0.0s", flush=True)

    def _report(self) -> int:
        now = time.monotonic()
        if self.stage and now - self.last >= 15:
            print(
                f"T3.4R1 stage={self.stage} status=running elapsed={now-self.started:.1f}s",
                flush=True,
            )
            self.last = now
        return 0

    def finish(self) -> None:
        print(
            f"T3.4R1 stage={self.stage} status=passed "
            f"elapsed={time.monotonic()-self.started:.1f}s",
            flush=True,
        )
        self.stage = ""

    def close(self) -> None:
        self.connection.set_progress_handler(None, 0)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=reject_duplicate_keys)
    if not isinstance(document, dict):
        raise ValueError(f"expected JSON object: {path}")
    return document


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def resolve_relative(root: Path, value: str) -> Path:
    if not value or "\\" in value:
        raise ValueError(f"repository path must use POSIX relative form: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or PureWindowsPath(value).is_absolute():
        raise ValueError(f"repository path must be relative: {value}")
    path = (root / Path(*pure.parts)).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"repository path escapes workspace: {value}") from error
    return path


def validate_reference(
    root: Path, reference: Mapping[str, Any], *, task: str, status: str
) -> tuple[Path, dict[str, Any]]:
    path = resolve_relative(root, str(reference.get("path", "")))
    expected = str(reference.get("sha256", ""))
    if len(expected) != 64 or sha256_path(path) != expected:
        raise ValueError(f"SHA-256 mismatch: {reference.get('path')}")
    document = load_json(path)
    if document.get("task") != task or document.get("status") != status:
        raise ValueError(f"identity mismatch: {reference.get('path')}")
    return path, document


def validate_database_reference(root: Path, reference: Mapping[str, Any]) -> Path:
    path = resolve_relative(root, str(reference.get("path", "")))
    if path.stat().st_size != reference.get("size_bytes") or sha256_path(path) != reference.get("sha256"):
        raise ValueError(f"database size or SHA-256 mismatch: {reference.get('path')}")
    if reference.get("access") != "read_only_immutable":
        raise ValueError("database access must be read_only_immutable")
    return path


def validate_inputs(root: Path, contract_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = load_json(contract_path)
    if contract.get("task") != "T3.4R1" or contract.get("schema_version") != "1.0.0":
        raise ValueError("invalid T3.4R1 contract identity")
    policy = contract.get("audit", {})
    if not (
        policy.get("database_access") == "read_only_immutable"
        and policy.get("source_mutation_allowed") is False
        and policy.get("automatic_relabeling_allowed") is False
        and policy.get("automatic_flow_boundary_changes_allowed") is False
        and policy.get("automatic_family_exclusion_allowed") is False
    ):
        raise ValueError("contract weakens the fail-closed audit policy")
    gate = contract.get("gate", {})
    if not (
        gate.get("initial_status") == "pending_user_decision"
        and gate.get("t3_5_authorized") is False
        and gate.get("user_approval_required") is True
    ):
        raise ValueError("contract weakens the user gate")
    prerequisite = contract.get("prerequisite", {})
    _, acceptance = validate_reference(
        root, prerequisite.get("acceptance", {}), task="T3.3R1", status="passed"
    )
    _, build = validate_reference(
        root, prerequisite.get("build", {}), task="T3.3R1", status="passed"
    )
    derived = validate_database_reference(root, prerequisite.get("derived_database", {}))
    source = validate_database_reference(root, prerequisite.get("source_database", {}))
    if acceptance.get("derived_database", {}).get("sha256") != sha256_path(derived):
        raise ValueError("T3.3R1 acceptance derived database mismatch")
    if build.get("derived_database", {}).get("sha256") != sha256_path(derived):
        raise ValueError("T3.3R1 build derived database mismatch")
    source_hash = sha256_path(source)
    if acceptance.get("source_database", {}).get("sha256_after") != source_hash:
        raise ValueError("T3.3R1 acceptance source database mismatch")
    if build.get("source_database", {}).get("sha256_after") != source_hash:
        raise ValueError("T3.3R1 build source database mismatch")
    if acceptance.get("producer") != build.get("producer"):
        raise ValueError("T3.3R1 acceptance and build producer identities differ")
    if acceptance.get("contract") != build.get("contract"):
        raise ValueError("T3.3R1 acceptance and build contract identities differ")
    return contract, {
        "acceptance": acceptance,
        "build": build,
        "derived": derived,
        "source": source,
    }


def open_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA temp_store=FILE")
    return connection


def validate_database(
    connection: sqlite3.Connection,
    reference: Mapping[str, Any],
    required_columns: Mapping[str, set[str]],
    *,
    exact_tables: bool,
) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("database integrity_check failed")
    if connection.execute("PRAGMA application_id").fetchone()[0] != reference.get("application_id"):
        raise ValueError("database application_id mismatch")
    if connection.execute("PRAGMA user_version").fetchone()[0] != reference.get("user_version"):
        raise ValueError("database user_version mismatch")
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    expected_tables = set(required_columns)
    if (exact_tables and tables != expected_tables) or not expected_tables.issubset(tables):
        raise ValueError(f"database table set mismatch: {sorted(tables)}")
    for table, required in required_columns.items():
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        missing = sorted(required - columns)
        if missing:
            raise ValueError(f"database table {table} missing columns: {', '.join(missing)}")


def attach_derived(connection: sqlite3.Connection, derived: Path) -> None:
    connection.execute(
        "ATTACH DATABASE ? AS derived",
        (f"file:{derived.as_posix()}?mode=ro&immutable=1",),
    )


def validate_build_metadata(
    connection: sqlite3.Connection,
    contract: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> None:
    actual = dict(connection.execute("SELECT key,value FROM derived.build_metadata"))
    build = inputs["build"]
    expected = {
        "schema_version": "1.0.0",
        "task": "T3.3R1",
        "contract_sha256": build["contract"]["sha256"],
        "producer_sha256": build["producer"]["sha256"],
        "selected_tolerance_seconds": "0",
        "source_database_sha256": contract["prerequisite"]["source_database"]["sha256"],
    }
    if actual != expected:
        raise ValueError("derived build metadata differs from locked T3.3R1 provenance")


def create_independent_projection(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TEMP TABLE audit_raw_pair AS
        SELECT flow_id,label_id FROM candidate_edge WHERE required_tolerance_ns<=0
        GROUP BY flow_id,label_id;
        CREATE TEMP TABLE audit_eligible_pair AS
        SELECT e.flow_id,e.label_id,l.label candidate_class,COUNT(*) eligible_variant_count,
               MIN(e.required_tolerance_ns) minimum_required_tolerance_ns
        FROM candidate_edge e JOIN label_row l USING(label_id)
        WHERE e.required_tolerance_ns<=0 AND e.schedule_conflict=0 AND e.role_conflict=0
        GROUP BY e.flow_id,e.label_id,l.label;
        CREATE INDEX audit_eligible_flow ON audit_eligible_pair(flow_id,label_id);
        CREATE INDEX audit_eligible_label ON audit_eligible_pair(label_id,flow_id);
        CREATE TEMP TABLE audit_flow_stats AS
        SELECT flow_id,COUNT(*) candidate_count,COUNT(DISTINCT candidate_class) class_count,
               MIN(candidate_class) only_class
        FROM audit_eligible_pair GROUP BY flow_id;
        CREATE UNIQUE INDEX audit_flow_stats_id ON audit_flow_stats(flow_id);
        CREATE TEMP TABLE audit_label_degree AS
        SELECT label_id,COUNT(DISTINCT flow_id) degree
        FROM audit_eligible_pair GROUP BY label_id;
        CREATE UNIQUE INDEX audit_label_degree_id ON audit_label_degree(label_id);
        CREATE TEMP TABLE audit_candidate_json AS
        SELECT flow_id,'['||group_concat(label_id,',')||']' ids
        FROM (SELECT flow_id,label_id FROM audit_eligible_pair ORDER BY flow_id,label_id)
        GROUP BY flow_id;
        CREATE TEMP TABLE expected_assignment AS
        SELECT f.flow_id,f.capture_id,s.only_class assigned_class,
               CASE WHEN s.candidate_count=1 AND d.degree=1
                    THEN 'mutual_unique' ELSE 'class_consensus' END assignment_method,
               s.candidate_count eligible_candidate_count,
               s.class_count distinct_eligible_candidate_class_count,
               j.ids eligible_candidate_label_ids_json,
               CASE WHEN s.candidate_count=1 AND d.degree=1
                    THEN p.label_id END mutual_unique_label_id
        FROM flow f JOIN audit_flow_stats s USING(flow_id)
        JOIN audit_candidate_json j USING(flow_id)
        LEFT JOIN audit_eligible_pair p ON p.flow_id=f.flow_id AND s.candidate_count=1
        LEFT JOIN audit_label_degree d ON d.label_id=p.label_id
        WHERE s.class_count=1;
        CREATE TEMP TABLE expected_candidate AS
        SELECT p.flow_id,p.label_id,p.candidate_class,p.eligible_variant_count,
               p.minimum_required_tolerance_ns
        FROM audit_eligible_pair p JOIN expected_assignment a USING(flow_id);
        CREATE TEMP TABLE expected_quarantine AS
        SELECT f.flow_id,f.capture_id,
               CASE WHEN s.class_count>1 THEN 'mixed_candidate_classes'
                    WHEN r.raw_count>0 THEN 'audit_conflict'
                    ELSE 'no_eligible_candidate' END reason,
               COALESCE(r.raw_count,0) raw_candidate_count,
               COALESCE(s.candidate_count,0) eligible_candidate_count,
               COALESCE(s.class_count,0) distinct_eligible_candidate_class_count
        FROM flow f
        LEFT JOIN (
          SELECT flow_id,COUNT(*) raw_count FROM audit_raw_pair GROUP BY flow_id
        ) r USING(flow_id)
        LEFT JOIN audit_flow_stats s USING(flow_id)
        WHERE s.class_count IS NULL OR s.class_count<>1;
    """)


def assert_same(connection: sqlite3.Connection, expected: str, actual: str, columns: str) -> None:
    if connection.execute(
        f"SELECT 1 FROM (SELECT {columns} FROM {expected} EXCEPT "
        f"SELECT {columns} FROM {actual}) LIMIT 1"
    ).fetchone() is not None:
        raise ValueError(f"derived projection missing or changed rows: {actual}")
    if connection.execute(
        f"SELECT 1 FROM (SELECT {columns} FROM {actual} EXCEPT "
        f"SELECT {columns} FROM {expected}) LIMIT 1"
    ).fetchone() is not None:
        raise ValueError(f"derived projection contains unexpected rows: {actual}")


def validate_projection(connection: sqlite3.Connection) -> None:
    assert_same(
        connection, "expected_assignment", "derived.flow_assignment",
        "flow_id,capture_id,assigned_class,assignment_method,eligible_candidate_count,"
        "distinct_eligible_candidate_class_count,eligible_candidate_label_ids_json,"
        "mutual_unique_label_id",
    )
    assert_same(
        connection, "expected_candidate", "derived.assignment_candidate",
        "flow_id,label_id,candidate_class,eligible_variant_count,minimum_required_tolerance_ns",
    )
    assert_same(
        connection, "expected_quarantine", "derived.quarantine",
        "flow_id,capture_id,reason,raw_candidate_count,eligible_candidate_count,"
        "distinct_eligible_candidate_class_count",
    )


def bucket_case(column: str) -> str:
    return (
        f"CASE WHEN {column}=1 THEN '1' WHEN {column}=2 THEN '2' "
        f"WHEN {column} BETWEEN 3 AND 5 THEN '3_to_5' "
        f"WHEN {column} BETWEEN 6 AND 10 THEN '6_to_10' "
        f"WHEN {column} BETWEEN 11 AND 100 THEN '11_to_100' "
        "ELSE 'greater_than_100' END"
    )


def assignment_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    source_total = connection.execute("SELECT COUNT(*) FROM flow").fetchone()[0]
    assigned = connection.execute("SELECT COUNT(*) FROM derived.flow_assignment").fetchone()[0]
    quarantined = connection.execute("SELECT COUNT(*) FROM derived.quarantine").fetchone()[0]
    methods = [dict(row) for row in connection.execute("""
        SELECT assignment_method,COUNT(*) assigned_flows,
               CAST(COUNT(*) AS REAL)/(SELECT COUNT(*) FROM derived.flow_assignment) assigned_share
        FROM derived.flow_assignment GROUP BY assignment_method ORDER BY assignment_method
    """)]
    by_capture = [dict(row) for row in connection.execute("""
        WITH source_count AS (
          SELECT capture_id,COUNT(*) source_flows FROM flow GROUP BY capture_id
        ), assigned_count AS (
          SELECT capture_id,COUNT(*) assigned_flows,
                 SUM(assignment_method='mutual_unique') mutual_unique,
                 SUM(assignment_method='class_consensus') class_consensus
          FROM derived.flow_assignment GROUP BY capture_id
        ), quarantine_count AS (
          SELECT capture_id,COUNT(*) quarantined_flows FROM derived.quarantine GROUP BY capture_id
        )
        SELECT s.capture_id,s.source_flows,COALESCE(a.assigned_flows,0) assigned_flows,
               COALESCE(q.quarantined_flows,0) quarantined_flows,
               COALESCE(a.mutual_unique,0) mutual_unique,
               COALESCE(a.class_consensus,0) class_consensus,
               CAST(COALESCE(a.assigned_flows,0) AS REAL)/s.source_flows assignment_rate
        FROM source_count s LEFT JOIN assigned_count a USING(capture_id)
        LEFT JOIN quarantine_count q USING(capture_id) ORDER BY s.capture_id
    """)]
    return {
        "overall": {
            "source_flows": source_total,
            "assigned_flows": assigned,
            "quarantined_flows": quarantined,
            "assignment_rate": assigned / source_total if source_total else 0.0,
            "quarantine_rate": quarantined / source_total if source_total else 0.0,
        },
        "by_method": methods,
        "by_capture": by_capture,
    }


def class_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    joinable = dict(connection.execute("SELECT label,COUNT(*) FROM label_row GROUP BY label"))
    source_quarantined = dict(connection.execute(
        "SELECT label,COUNT(*) FROM quarantined_label_row GROUP BY label"
    ))
    assigned = {
        row[0]: (row[1], row[2], row[3])
        for row in connection.execute("""
          SELECT assigned_class,COUNT(*),SUM(assignment_method='mutual_unique'),
                 SUM(assignment_method='class_consensus')
          FROM derived.flow_assignment GROUP BY assigned_class
        """)
    }
    represented = dict(connection.execute("""
        SELECT candidate_class,COUNT(DISTINCT label_id)
        FROM derived.assignment_candidate GROUP BY candidate_class
    """))
    rows = []
    for label in sorted(set(joinable) | set(source_quarantined) | set(assigned)):
        values = assigned.get(label, (0, 0, 0))
        rows.append({
            "label": label,
            "source_label_rows": joinable.get(label, 0),
            "source_quarantined_label_rows": source_quarantined.get(label, 0),
            "represented_source_label_rows": represented.get(label, 0),
            "source_label_row_representation_rate": (
                represented.get(label, 0) / joinable[label] if joinable.get(label, 0) else None
            ),
            "assigned_flows": values[0],
            "mutual_unique": values[1],
            "class_consensus": values[2],
            "assigned_flow_minus_source_label_rows": values[0] - joinable.get(label, 0),
        })
    capture_class_method = [dict(row) for row in connection.execute("""
        SELECT capture_id,assigned_class label,assignment_method,COUNT(*) assigned_flows
        FROM derived.flow_assignment
        GROUP BY capture_id,assigned_class,assignment_method
        ORDER BY capture_id,assigned_class,assignment_method
    """)]
    return {"by_class": rows, "by_capture_class_and_method": capture_class_method}


def candidate_distribution(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    case = bucket_case("eligible_candidate_count")
    return [dict(row) for row in connection.execute(f"""
        SELECT assignment_method,assigned_class label,{case} bucket,COUNT(*) assigned_flows
        FROM derived.flow_assignment
        GROUP BY assignment_method,assigned_class,bucket
        ORDER BY assignment_method,assigned_class,
          CASE bucket WHEN '1' THEN 1 WHEN '2' THEN 2 WHEN '3_to_5' THEN 3
                      WHEN '6_to_10' THEN 4 WHEN '11_to_100' THEN 5 ELSE 6 END
    """)]


def fanout_metrics(connection: sqlite3.Connection, limit: int) -> dict[str, Any]:
    connection.executescript("""
        CREATE TEMP TABLE audit_label_fanout AS
        SELECT label_id,MIN(candidate_class) candidate_class,
               COUNT(DISTINCT flow_id) eligible_flow_count
        FROM audit_eligible_pair GROUP BY label_id;
    """)
    row = connection.execute("""
        SELECT COUNT(*),MIN(eligible_flow_count),MAX(eligible_flow_count),AVG(eligible_flow_count)
        FROM audit_label_fanout
    """).fetchone()
    case = bucket_case("eligible_flow_count")
    buckets = [dict(item) for item in connection.execute(f"""
        SELECT {case} bucket,COUNT(*) source_label_count
        FROM audit_label_fanout GROUP BY bucket
        ORDER BY CASE bucket WHEN '1' THEN 1 WHEN '2' THEN 2 WHEN '3_to_5' THEN 3
                             WHEN '6_to_10' THEN 4 WHEN '11_to_100' THEN 5 ELSE 6 END
    """)]
    examples = [dict(item) for item in connection.execute("""
        SELECT label_id,candidate_class,eligible_flow_count
        FROM audit_label_fanout ORDER BY eligible_flow_count DESC,label_id LIMIT ?
    """, (limit,))]
    return {
        "eligible_source_labels": row[0] or 0,
        "minimum_eligible_flows_per_source_label": row[1] or 0,
        "maximum_eligible_flows_per_source_label": row[2] or 0,
        "mean_eligible_flows_per_source_label": row[3] or 0.0,
        "fanout_buckets": buckets,
        "top_bounded_examples": examples,
    }


def consensus_sharing_risk(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute("""
        WITH profile AS (
          SELECT a.flow_id,a.assigned_class,
                 CASE
                   WHEN COUNT(*)=1 THEN 'singleton_shared_label'
                   WHEN MAX(d.degree)=1 THEN 'multiple_rows_all_exclusive'
                   WHEN MIN(d.degree)>1 THEN 'multiple_rows_all_shared'
                   ELSE 'multiple_rows_mixed_sharing'
                 END risk_profile
          FROM derived.flow_assignment a
          JOIN audit_eligible_pair p USING(flow_id)
          JOIN audit_label_degree d USING(label_id)
          WHERE a.assignment_method='class_consensus'
          GROUP BY a.flow_id,a.assigned_class
        )
        SELECT assigned_class label,risk_profile,COUNT(*) flows
        FROM profile GROUP BY assigned_class,risk_profile
        ORDER BY assigned_class,risk_profile
    """)]


def create_candidate_agreement(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TEMP TABLE audit_candidate_agreement AS
        WITH candidate AS (
          SELECT a.flow_id,a.assignment_method,a.assigned_class,
                 ABS((f.last_event_timestamp_ns-f.creation_timestamp_ns)/1000-l.duration_us)
                   duration_delta_us,
                 ABS(f.packet_count-(l.forward_packet_count+l.backward_packet_count))
                   packet_delta,
                 CASE
                   WHEN f.forward_source_ip=l.source_ip AND f.forward_source_port=l.source_port
                     THEN f.forward_packet_count=l.forward_packet_count
                          AND f.reverse_packet_count=l.backward_packet_count
                   ELSE f.forward_packet_count=l.backward_packet_count
                        AND f.reverse_packet_count=l.forward_packet_count
                 END direction_exact
          FROM derived.flow_assignment a
          JOIN derived.assignment_candidate c USING(flow_id)
          JOIN flow f USING(flow_id) JOIN label_row l USING(label_id)
        )
        SELECT flow_id,assignment_method,assigned_class,
               MIN(duration_delta_us) minimum_duration_delta_us,
               MIN(packet_delta) minimum_packet_delta,
               MAX(direction_exact) any_direction_exact,
               MAX(duration_delta_us=0 AND packet_delta=0 AND direction_exact)
                 any_single_candidate_full_exact
        FROM candidate GROUP BY flow_id,assignment_method,assigned_class;
        CREATE UNIQUE INDEX audit_candidate_agreement_flow ON audit_candidate_agreement(flow_id);
    """)


def candidate_agreement_metrics(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute("""
        SELECT assignment_method,assigned_class label,COUNT(*) assigned_flows,
               SUM(minimum_duration_delta_us=0) any_duration_exact,
               SUM(minimum_duration_delta_us<=1000) any_duration_within_1000us,
               SUM(minimum_duration_delta_us<=1000000) any_duration_within_1000000us,
               SUM(minimum_duration_delta_us<=60000000) any_duration_within_60000000us,
               AVG(minimum_duration_delta_us) mean_minimum_duration_delta_us,
               MAX(minimum_duration_delta_us) maximum_minimum_duration_delta_us,
               SUM(minimum_packet_delta=0) any_packet_count_exact,
               SUM(minimum_packet_delta<=1) any_packet_count_within_1,
               SUM(minimum_packet_delta<=10) any_packet_count_within_10,
               AVG(minimum_packet_delta) mean_minimum_packet_delta,
               MAX(minimum_packet_delta) maximum_minimum_packet_delta,
               SUM(any_direction_exact) any_direction_counts_exact,
               SUM(any_single_candidate_full_exact) any_single_candidate_full_exact
        FROM audit_candidate_agreement
        GROUP BY assignment_method,assigned_class
        ORDER BY assignment_method,assigned_class
    """)]


def bounded_examples(connection: sqlite3.Connection, limit: int) -> dict[str, list[dict[str, Any]]]:
    return {
        "highest_candidate_count": [dict(row) for row in connection.execute("""
          SELECT flow_id,capture_id,assigned_class,assignment_method,eligible_candidate_count
          FROM derived.flow_assignment
          ORDER BY eligible_candidate_count DESC,flow_id LIMIT ?
        """, (limit,))],
        "highest_source_label_fanout": [dict(row) for row in connection.execute("""
          SELECT label_id,candidate_class,eligible_flow_count
          FROM audit_label_fanout ORDER BY eligible_flow_count DESC,label_id LIMIT ?
        """, (limit,))],
        "mixed_candidate_classes": [dict(row) for row in connection.execute("""
          SELECT flow_id,capture_id,raw_candidate_count,eligible_candidate_count,
                 distinct_eligible_candidate_class_count
          FROM derived.quarantine WHERE reason='mixed_candidate_classes'
          ORDER BY eligible_candidate_count DESC,flow_id LIMIT ?
        """, (limit,))],
        "no_eligible_candidate": [dict(row) for row in connection.execute("""
          SELECT flow_id,capture_id,raw_candidate_count,eligible_candidate_count
          FROM derived.quarantine WHERE reason='no_eligible_candidate'
          ORDER BY flow_id LIMIT ?
        """, (limit,))],
        "audit_conflict": [dict(row) for row in connection.execute("""
          SELECT flow_id,capture_id,raw_candidate_count,eligible_candidate_count
          FROM derived.quarantine WHERE reason='audit_conflict'
          ORDER BY raw_candidate_count DESC,flow_id LIMIT ?
        """, (limit,))],
    }


def compute_audit(
    connection: sqlite3.Connection,
    contract: Mapping[str, Any],
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    progress = Progress(connection)
    try:
        progress.start("independent_projection")
        validate_build_metadata(connection, contract, inputs)
        create_independent_projection(connection)
        validate_projection(connection)
        progress.finish()
        progress.start("audit_metrics")
        assignment = assignment_metrics(connection)
        classes = class_metrics(connection)
        distribution = candidate_distribution(connection)
        limit = contract["audit"]["examples"]["maximum_per_category"]
        fanout = fanout_metrics(connection, limit)
        sharing_risk = consensus_sharing_risk(connection)
        create_candidate_agreement(connection)
        agreement = candidate_agreement_metrics(connection)
        source_label_rows = connection.execute("SELECT COUNT(*) FROM label_row").fetchone()[0]
        assigned = assignment["overall"]["assigned_flows"]
        result = {
            "assignment": assignment,
            "classes": classes,
            "quarantine": {
                "flow_by_reason": [dict(row) for row in connection.execute(
                    "SELECT reason,COUNT(*) count FROM derived.quarantine "
                    "GROUP BY reason ORDER BY reason"
                )],
                "source_label_by_reason": [dict(row) for row in connection.execute(
                    "SELECT reason,COUNT(*) count FROM quarantined_label_row "
                    "GROUP BY reason ORDER BY reason"
                )],
            },
            "candidate_count_distribution": distribution,
            "source_label_fanout": fanout,
            "class_consensus_sharing_risk_by_class": sharing_risk,
            "candidate_agreement_by_method_and_class": agreement,
            "flow_count_vs_source_label_rows": {
                "assigned_flows": assigned,
                "source_label_rows": source_label_rows,
                "delta": assigned - source_label_rows,
                "interpretation": "diagnostic_non_parity_only",
                "notice": contract["audit"]["class_consensus_risk_signals"]
                    ["flow_count_vs_source_label_rows"]["explicit_statement"],
                "by_class": [{
                    "label": row["label"],
                    "assigned_flows": row["assigned_flows"],
                    "source_label_rows": row["source_label_rows"],
                    "delta": row["assigned_flow_minus_source_label_rows"],
                } for row in classes["by_class"]],
            },
            "examples": bounded_examples(connection, limit),
        }
        progress.finish()
        return result
    finally:
        progress.close()


def gate_document() -> dict[str, Any]:
    return {
        "status": "pending_user_decision",
        "decision": None,
        "thresholds": {
            "minimum_overall_assignment_rate": None,
            "minimum_per_family_assignment_count": None,
            "minimum_per_family_assignment_rate": None,
            "maximum_class_consensus_share": None,
            "maximum_source_label_fanout": None,
            "maximum_quarantine_rate": None,
        },
        "approved_family_scope": None,
        "decision_by": None,
        "t3_5_authorized": False,
    }


def make_receipt(
    root: Path,
    contract_path: Path,
    contract: Mapping[str, Any],
    inputs: Mapping[str, Any],
    audit: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "task": "T3.4R1",
        "kind": "class_consensus_audit",
        "status": "passed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host": {
            "system": platform.system(), "architecture": platform.machine(),
            "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        },
        "producer": {
            "path": "scripts/audit_t34r1_class_consensus.py",
            "sha256": sha256_path(root / "scripts/audit_t34r1_class_consensus.py"),
        },
        "contract": {
            "path": contract_path.resolve().relative_to(root).as_posix(),
            "sha256": sha256_path(contract_path),
        },
        "prerequisite": contract["prerequisite"],
        "database_hashes_after_audit": {
            "source": sha256_path(inputs["source"]),
            "derived": sha256_path(inputs["derived"]),
        },
        "audit": audit,
        "gate": gate_document(),
        "checks": [
            {"name": "inputs.content_addressed_and_immutable", "status": "passed"},
            {"name": "projection.independently_recomputed", "status": "passed"},
            {"name": "provenance.candidates_and_methods", "status": "passed"},
            {"name": "audit.accounting_risk_and_agreement", "status": "passed"},
            {"name": "gate.user_decision_required_and_t3_5_locked", "status": "passed"},
        ],
    }


def render_report(receipt: Mapping[str, Any]) -> str:
    audit = receipt["audit"]
    overall = audit["assignment"]["overall"]
    methods = {row["assignment_method"]: row for row in audit["assignment"]["by_method"]}
    lines = [
        "# Báo cáo T3.4R1 — Audit class-consensus CIC-IDS2017", "",
        "## Trạng thái", "",
        "Audit kỹ thuật đã pass ở chế độ chỉ đọc. Gate vẫn `pending_user_decision`; "
        "T3.5 chưa được mở và không có nhãn, flow boundary hay family scope nào được tự động thay đổi.", "",
        "## Tổng quan", "",
        f"- Flow nguồn: {overall['source_flows']:,}",
        f"- Flow được gán: {overall['assigned_flows']:,} ({overall['assignment_rate']:.4%})",
        f"- Flow quarantine: {overall['quarantined_flows']:,} ({overall['quarantine_rate']:.4%})",
        f"- Mutual unique: {methods.get('mutual_unique', {}).get('assigned_flows', 0):,}",
        f"- Class consensus: {methods.get('class_consensus', {}).get('assigned_flows', 0):,}", "",
        "## Theo capture", "",
        "| Capture | Source flow | Assigned | Quarantine | Mutual unique | Consensus | Assignment rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in audit["assignment"]["by_capture"]:
        lines.append(
            f"| {row['capture_id']} | {row['source_flows']:,} | {row['assigned_flows']:,} | "
            f"{row['quarantined_flows']:,} | {row['mutual_unique']:,} | "
            f"{row['class_consensus']:,} | {row['assignment_rate']:.4%} |"
        )
    lines += [
        "", "## Theo class", "",
        "Flow và CSV-row là hai đơn vị khác nhau; delta chỉ là chẩn đoán non-parity, "
        "không phải coverage hoặc bằng chứng đúng/sai. Representation chỉ cho biết tỷ lệ CSV row hợp lệ "
        "tham gia ít nhất một flow đã gán, không phải accuracy hay recall.", "",
        "| Class | Source rows | Represented | Representation | Source quarantine | Assigned flow | Mutual unique | Consensus | Delta |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in audit["classes"]["by_class"]:
        representation_rate = row["source_label_row_representation_rate"]
        representation_text = (
            f"{representation_rate:.4%}" if representation_rate is not None else "n/a"
        )
        lines.append(
            f"| {row['label']} | {row['source_label_rows']:,} | "
            f"{row['represented_source_label_rows']:,} | "
            f"{representation_text} | "
            f"{row['source_quarantined_label_rows']:,} | {row['assigned_flows']:,} | "
            f"{row['mutual_unique']:,} | {row['class_consensus']:,} | "
            f"{row['assigned_flow_minus_source_label_rows']:+,} |"
        )
    fanout = audit["source_label_fanout"]
    lines += [
        "", "## Rủi ro multiplicity", "",
        f"Có {fanout['eligible_source_labels']:,} source label_id trong toàn bộ đồ thị candidate hợp lệ; "
        f"fanout lớn nhất là {fanout['maximum_eligible_flows_per_source_label']:,} flow/label_id "
        f"và trung bình {fanout['mean_eligible_flows_per_source_label']:.4f}.", "",
        "Candidate agreement được tính trên tất cả candidate hợp lệ. Auditor không chọn một CSV row "
        "đại diện và các delta không được dùng để tự động relabel.", "",
        "## Gate", "",
        "Tolerance vẫn khóa ở `0s`. Người dùng phải duyệt ngưỡng assignment, quarantine, "
        "multiplicity và family scope trước khi T3.5 có thể được mở.", "",
    ]
    return "\n".join(lines)


def write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def execute_audit(
    contract: Mapping[str, Any], inputs: Mapping[str, Any]
) -> dict[str, Any]:
    with contextlib.closing(open_read_only(inputs["derived"])) as derived_connection:
        validate_database(
            derived_connection, contract["prerequisite"]["derived_database"], DERIVED_COLUMNS,
            exact_tables=True,
        )
    with contextlib.closing(open_read_only(inputs["source"])) as source_connection:
        validate_database(
            source_connection, contract["prerequisite"]["source_database"], SOURCE_COLUMNS,
            exact_tables=False,
        )
        attach_derived(source_connection, inputs["derived"])
        return compute_audit(source_connection, contract, inputs)


def run(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract_path = args.contract.resolve()
    contract, inputs = validate_inputs(root, contract_path)
    source_before = sha256_path(inputs["source"])
    derived_before = sha256_path(inputs["derived"])
    audit = execute_audit(contract, inputs)
    if sha256_path(inputs["source"]) != source_before or sha256_path(inputs["derived"]) != derived_before:
        raise ValueError("source or derived database changed during read-only audit")
    receipt = make_receipt(root, contract_path, contract, inputs, audit)
    report = render_report(receipt).encode("utf-8")
    receipt["report"] = {
        "path": args.report.resolve().relative_to(root).as_posix(),
        "sha256": hashlib.sha256(report).hexdigest(),
    }
    write_atomic(args.report, report)
    write_atomic(
        args.output,
        (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    print("T3.4R1 audit: passed; gate=pending_user_decision; T3.5 locked", flush=True)
    return 0


def validate(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract_path = args.contract.resolve()
    contract, inputs = validate_inputs(root, contract_path)
    receipt = load_json(args.input)
    if receipt.get("task") != "T3.4R1" or receipt.get("status") != "passed":
        raise ValueError("invalid T3.4R1 audit receipt identity")
    expected_producer = {
        "path": "scripts/audit_t34r1_class_consensus.py",
        "sha256": sha256_path(root / "scripts/audit_t34r1_class_consensus.py"),
    }
    if receipt.get("producer") != expected_producer:
        raise ValueError("T3.4R1 producer hash mismatch")
    expected_contract = {
        "path": contract_path.resolve().relative_to(root).as_posix(),
        "sha256": sha256_path(contract_path),
    }
    if receipt.get("contract") != expected_contract or receipt.get("prerequisite") != contract["prerequisite"]:
        raise ValueError("T3.4R1 contract or prerequisite mismatch")
    if receipt.get("gate") != gate_document():
        raise ValueError("T3.4R1 gate differs from pending user decision")
    source_before = sha256_path(inputs["source"])
    derived_before = sha256_path(inputs["derived"])
    recomputed = execute_audit(contract, inputs)
    if receipt.get("audit") != recomputed:
        raise ValueError("T3.4R1 audit differs from independent recomputation")
    if sha256_path(inputs["source"]) != source_before or sha256_path(inputs["derived"]) != derived_before:
        raise ValueError("source or derived database changed during validation")
    expected_hashes = {"source": source_before, "derived": derived_before}
    if receipt.get("database_hashes_after_audit") != expected_hashes:
        raise ValueError("T3.4R1 database hash evidence mismatch")
    report = render_report(receipt).encode("utf-8")
    if args.report.read_bytes() != report:
        raise ValueError("T3.4R1 report content mismatch")
    if receipt.get("report", {}).get("sha256") != hashlib.sha256(report).hexdigest():
        raise ValueError("T3.4R1 report hash mismatch")
    print("T3.4R1 validation: passed; gate=pending_user_decision; T3.5 locked", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument(
            "--contract", type=Path,
            default=root / "config/cicids2017-class-consensus-audit-contract.json",
        )
        command.add_argument("--input", type=Path, default=root / "run_log/t3.4r1/audit.json")
        command.add_argument("--output", type=Path, default=root / "run_log/t3.4r1/audit.json")
        command.add_argument(
            "--report", type=Path,
            default=root / "docs/dataset/cicids2017-class-consensus-audit.vi.md",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args) if args.command == "run" else validate(args)
    except (OSError, ValueError, KeyError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
