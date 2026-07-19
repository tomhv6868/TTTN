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


REQUIRED_COLUMNS = {
    "candidate_edge": {
        "flow_id", "label_id", "required_tolerance_ns", "schedule_conflict", "role_conflict"
    },
    "flow": {
        "flow_id", "capture_id", "forward_source_ip", "forward_source_port",
        "creation_timestamp_ns", "last_event_timestamp_ns", "packet_count",
        "forward_packet_count", "reverse_packet_count", "close_reason"
    },
    "label_row": {
        "label_id", "capture_id", "source_ip", "source_port", "duration_us",
        "forward_packet_count", "backward_packet_count", "label"
    },
    "exporter_summary": {
        "capture_id", "records_read", "packets_parsed", "parser_errors",
        "packets_accepted", "ingest_errors", "exported_flows", "flows_closed"
    },
    "sweep_summary": {
        "tolerance_seconds", "raw_edge_count", "eligible_edge_count", "matched_count",
        "flow_total", "flow_unmatched", "flow_ambiguous", "flow_audit_conflict",
        "label_total", "label_unmatched", "label_ambiguous", "label_audit_conflict"
    },
}


class SqliteProgress:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.stage = ""
        self.started = 0.0
        self.last_report = 0.0
        connection.set_progress_handler(self.report, 1_000_000)

    def start(self, stage: str) -> None:
        self.stage = stage
        self.started = time.monotonic()
        self.last_report = self.started
        print(f"audit stage={stage} status=running elapsed=0.0s", flush=True)

    def report(self) -> int:
        now = time.monotonic()
        if self.stage and now - self.last_report >= 15.0:
            print(
                f"audit stage={self.stage} status=running elapsed={now-self.started:.1f}s",
                flush=True,
            )
            self.last_report = now
        return 0

    def finish(self) -> None:
        elapsed = time.monotonic() - self.started
        print(f"audit stage={self.stage} status=passed elapsed={elapsed:.1f}s", flush=True)
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


def validate_reference(root: Path, reference: Mapping[str, Any], *, task: str | None = None,
                       status: str | None = None) -> tuple[Path, dict[str, Any]]:
    path = resolve_relative(root, str(reference.get("path", "")))
    expected = str(reference.get("sha256", ""))
    if len(expected) != 64 or sha256_path(path) != expected:
        raise ValueError(f"SHA-256 mismatch: {reference.get('path')}")
    document = load_json(path)
    if task is not None and document.get("task") != task:
        raise ValueError(f"task mismatch: {reference.get('path')}")
    if status is not None and document.get("status") != status:
        raise ValueError(f"status mismatch: {reference.get('path')}")
    return path, document


def validate_inputs(root: Path, contract_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = load_json(contract_path)
    if contract.get("task") != "T3.4" or contract.get("schema_version") != "1.0.0":
        raise ValueError("invalid T3.4 contract identity")
    audit_policy = contract.get("audit", {})
    if not isinstance(audit_policy, dict) or not (
        audit_policy.get("database_access") == "read_only_immutable"
        and audit_policy.get("source_mutation_allowed") is False
        and audit_policy.get("automatic_relabeling_allowed") is False
        and audit_policy.get("automatic_flow_boundary_changes_allowed") is False
    ):
        raise ValueError("contract weakens the read-only fail-closed policy")
    prerequisite = contract.get("prerequisite", {})
    _, acceptance = validate_reference(
        root, prerequisite.get("acceptance", {}), task="T3.3", status="passed"
    )
    _, build = validate_reference(root, prerequisite.get("build", {}), task="T3.3", status="passed")
    database_ref = prerequisite.get("database", {})
    database = resolve_relative(root, str(database_ref.get("path", "")))
    stat = database.stat()
    if stat.st_size != database_ref.get("size_bytes") or sha256_path(database) != database_ref.get("sha256"):
        raise ValueError("T3.3 database size or SHA-256 mismatch")
    if acceptance.get("sqlite", {}).get("sha256") != database_ref.get("sha256"):
        raise ValueError("T3.3 acceptance database evidence mismatch")
    if build.get("sqlite", {}).get("sha256") != database_ref.get("sha256"):
        raise ValueError("T3.3 build database evidence mismatch")
    comparison_ref = contract.get("comparison_evidence", {}).get("t1_2_flow_survey", {})
    _, survey = validate_reference(root, comparison_ref, task="T1.2", status="passed")
    return contract, {"acceptance": acceptance, "build": build, "database": database, "survey": survey}


def open_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA temp_store=FILE")
    return connection


def validate_database(connection: sqlite3.Connection, database_ref: Mapping[str, Any]) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("T3.3 database integrity_check failed")
    if connection.execute("PRAGMA application_id").fetchone()[0] != database_ref.get("application_id"):
        raise ValueError("T3.3 database application_id mismatch")
    if connection.execute("PRAGMA user_version").fetchone()[0] != database_ref.get("user_version"):
        raise ValueError("T3.3 database user_version mismatch")
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, required in REQUIRED_COLUMNS.items():
        if table not in tables:
            raise ValueError(f"T3.3 database missing table: {table}")
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        missing = sorted(required - columns)
        if missing:
            raise ValueError(f"T3.3 database table {table} missing columns: {', '.join(missing)}")


def create_pair_summary(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TEMP TABLE audit_pair AS
        SELECT flow_id,label_id,
               MIN(required_tolerance_ns) AS raw_required_ns,
               MIN(CASE WHEN schedule_conflict=0 AND role_conflict=0
                        THEN required_tolerance_ns END) AS eligible_required_ns,
               MAX(schedule_conflict) AS has_schedule_conflict,
               MAX(role_conflict) AS has_role_conflict
        FROM candidate_edge GROUP BY flow_id,label_id;
        CREATE INDEX audit_pair_flow ON audit_pair(flow_id,raw_required_ns,eligible_required_ns);
        CREATE INDEX audit_pair_label ON audit_pair(label_id,raw_required_ns,eligible_required_ns);
    """)


def prepare_tolerance(connection: sqlite3.Connection, seconds: int) -> None:
    tolerance = seconds * 1_000_000_000
    connection.executescript("""
        DROP TABLE IF EXISTS audit_raw_fd; DROP TABLE IF EXISTS audit_raw_ld;
        DROP TABLE IF EXISTS audit_fd; DROP TABLE IF EXISTS audit_ld; DROP TABLE IF EXISTS audit_matched;
    """)
    connection.execute(
        "CREATE TEMP TABLE audit_raw_fd AS SELECT flow_id,COUNT(*) degree FROM audit_pair "
        "WHERE raw_required_ns<=? GROUP BY flow_id", (tolerance,)
    )
    connection.execute(
        "CREATE TEMP TABLE audit_raw_ld AS SELECT label_id,COUNT(*) degree FROM audit_pair "
        "WHERE raw_required_ns<=? GROUP BY label_id", (tolerance,)
    )
    connection.execute(
        "CREATE TEMP TABLE audit_fd AS SELECT flow_id,COUNT(*) degree FROM audit_pair "
        "WHERE eligible_required_ns<=? GROUP BY flow_id", (tolerance,)
    )
    connection.execute(
        "CREATE TEMP TABLE audit_ld AS SELECT label_id,COUNT(*) degree FROM audit_pair "
        "WHERE eligible_required_ns<=? GROUP BY label_id", (tolerance,)
    )
    connection.executescript("""
        CREATE UNIQUE INDEX audit_raw_fd_id ON audit_raw_fd(flow_id);
        CREATE UNIQUE INDEX audit_raw_ld_id ON audit_raw_ld(label_id);
        CREATE UNIQUE INDEX audit_fd_id ON audit_fd(flow_id);
        CREATE UNIQUE INDEX audit_ld_id ON audit_ld(label_id);
        CREATE TEMP TABLE audit_matched AS
        SELECT p.flow_id,p.label_id FROM audit_pair p
        JOIN audit_fd fd ON fd.flow_id=p.flow_id AND fd.degree=1
        JOIN audit_ld ld ON ld.label_id=p.label_id AND ld.degree=1
        WHERE p.eligible_required_ns IS NOT NULL AND p.eligible_required_ns<=%d;
        CREATE UNIQUE INDEX audit_matched_flow ON audit_matched(flow_id);
        CREATE UNIQUE INDEX audit_matched_label ON audit_matched(label_id);
    """ % tolerance)


def status_expression(identifier: str, raw: str, eligible: str, matched: str) -> str:
    return (
        f"CASE WHEN {matched}.{identifier} IS NOT NULL THEN 'matched' "
        f"WHEN {raw}.{identifier} IS NULL THEN 'unmatched' "
        f"WHEN {eligible}.{identifier} IS NULL THEN 'audit_conflict' ELSE 'ambiguous' END"
    )


def sweep_row(connection: sqlite3.Connection, seconds: int) -> dict[str, Any]:
    flow_total = connection.execute("SELECT COUNT(*) FROM flow").fetchone()[0]
    label_total = connection.execute("SELECT COUNT(*) FROM label_row").fetchone()[0]
    matched = connection.execute("SELECT COUNT(*) FROM audit_matched").fetchone()[0]
    raw_flows = connection.execute("SELECT COUNT(*) FROM audit_raw_fd").fetchone()[0]
    eligible_flows = connection.execute("SELECT COUNT(*) FROM audit_fd").fetchone()[0]
    raw_labels = connection.execute("SELECT COUNT(*) FROM audit_raw_ld").fetchone()[0]
    eligible_labels = connection.execute("SELECT COUNT(*) FROM audit_ld").fetchone()[0]
    tolerance = seconds * 1_000_000_000
    raw_edges = connection.execute(
        "SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<=?", (tolerance,)
    ).fetchone()[0]
    eligible_edges = connection.execute(
        "SELECT COUNT(*) FROM candidate_edge WHERE required_tolerance_ns<=? "
        "AND schedule_conflict=0 AND role_conflict=0", (tolerance,)
    ).fetchone()[0]
    result = {
        "tolerance_seconds": seconds, "raw_edge_count": raw_edges,
        "eligible_edge_count": eligible_edges, "matched_count": matched,
        "flow_total": flow_total, "flow_unmatched": flow_total - raw_flows,
        "flow_ambiguous": flow_total - matched - (flow_total - raw_flows) - (raw_flows - eligible_flows),
        "flow_audit_conflict": raw_flows - eligible_flows,
        "label_total": label_total, "label_unmatched": label_total - raw_labels,
        "label_ambiguous": label_total - matched - (label_total - raw_labels) - (raw_labels - eligible_labels),
        "label_audit_conflict": raw_labels - eligible_labels,
    }
    result["flow_match_rate"] = matched / flow_total if flow_total else 0.0
    result["label_match_rate"] = matched / label_total if label_total else 0.0
    stored = connection.execute("SELECT * FROM sweep_summary WHERE tolerance_seconds=?", (seconds,)).fetchone()
    result["stored_summary_consistent"] = stored is not None and all(
        stored[key] == result[key] for key in stored.keys() if key in result
    )
    return result


def label_class_rows(connection: sqlite3.Connection, seconds: int) -> list[dict[str, Any]]:
    status = status_expression("label_id", "r", "d", "m")
    rows = connection.execute(f"""
        SELECT l.capture_id,l.label,{status} status,COUNT(*) count
        FROM label_row l LEFT JOIN audit_raw_ld r USING(label_id)
        LEFT JOIN audit_ld d USING(label_id) LEFT JOIN audit_matched m USING(label_id)
        GROUP BY l.capture_id,l.label,status ORDER BY l.capture_id,l.label,status
    """).fetchall()
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["capture_id"], row["label"])
        item = grouped.setdefault(key, {
            "tolerance_seconds": seconds, "capture_id": key[0], "label": key[1],
            "total": 0, "matched": 0, "unmatched": 0, "ambiguous": 0, "audit_conflict": 0
        })
        item[row["status"]] = row["count"]
        item["total"] += row["count"]
    for item in grouped.values():
        item["coverage_rate"] = item["matched"] / item["total"] if item["total"] else 0.0
    return list(grouped.values())


def flow_capture_rows(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    status = status_expression("flow_id", "r", "d", "m")
    rows = connection.execute(f"""
        SELECT f.capture_id,{status} status,COUNT(*) count
        FROM flow f LEFT JOIN audit_raw_fd r USING(flow_id)
        LEFT JOIN audit_fd d USING(flow_id) LEFT JOIN audit_matched m USING(flow_id)
        GROUP BY f.capture_id,status ORDER BY f.capture_id,status
    """).fetchall()
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = grouped.setdefault(row["capture_id"], {
            "capture_id": row["capture_id"], "total": 0, "matched": 0,
            "unmatched": 0, "ambiguous": 0, "audit_conflict": 0
        })
        item[row["status"]] = row["count"]
        item["total"] += row["count"]
    return list(grouped.values())


def ambiguity_topology(connection: sqlite3.Connection, seconds: int) -> dict[str, int]:
    tolerance = seconds * 1_000_000_000
    row = connection.execute("""
        SELECT
          SUM(CASE WHEN fd.degree>1 AND ld.degree=1 THEN 1 ELSE 0 END),
          SUM(CASE WHEN fd.degree=1 AND ld.degree>1 THEN 1 ELSE 0 END),
          SUM(CASE WHEN fd.degree>1 AND ld.degree>1 THEN 1 ELSE 0 END)
        FROM audit_pair p JOIN audit_fd fd USING(flow_id) JOIN audit_ld ld USING(label_id)
        WHERE p.eligible_required_ns<=?
    """, (tolerance,)).fetchone()
    return {
        "one_flow_many_labels_pair_count": row[0] or 0,
        "many_flows_one_label_pair_count": row[1] or 0,
        "many_to_many_pair_count": row[2] or 0,
    }


def ambiguity_class_purity(connection: sqlite3.Connection, seconds: int) -> dict[str, Any]:
    tolerance = seconds * 1_000_000_000
    summary = connection.execute("""
        WITH ambiguous AS (
          SELECT fd.flow_id FROM audit_fd fd LEFT JOIN audit_matched m USING(flow_id)
          WHERE m.flow_id IS NULL
        ), class_count AS (
          SELECT a.flow_id,COUNT(DISTINCT l.label) count,MIN(l.label) only_label
          FROM ambiguous a JOIN audit_pair p USING(flow_id) JOIN label_row l USING(label_id)
          WHERE p.eligible_required_ns<=? GROUP BY a.flow_id
        )
        SELECT COUNT(*),SUM(count=1),SUM(count>1) FROM class_count
    """, (tolerance,)).fetchone()
    homogeneous = [dict(row) for row in connection.execute("""
        WITH ambiguous AS (
          SELECT fd.flow_id FROM audit_fd fd LEFT JOIN audit_matched m USING(flow_id)
          WHERE m.flow_id IS NULL
        ), class_count AS (
          SELECT a.flow_id,COUNT(DISTINCT l.label) count,MIN(l.label) only_label
          FROM ambiguous a JOIN audit_pair p USING(flow_id) JOIN label_row l USING(label_id)
          WHERE p.eligible_required_ns<=? GROUP BY a.flow_id
        )
        SELECT only_label label,COUNT(*) flow_count FROM class_count WHERE count=1
        GROUP BY only_label ORDER BY flow_count DESC,only_label
    """, (tolerance,)).fetchall()]
    return {
        "ambiguous_flow_count_with_eligible_candidates": summary[0] or 0,
        "candidate_class_homogeneous_flow_count": summary[1] or 0,
        "candidate_class_mixed_flow_count": summary[2] or 0,
        "homogeneous_flow_count_by_candidate_class": homogeneous,
        "notice": "candidate class purity is diagnostic and is not an assigned label",
    }


def matched_agreement(connection: sqlite3.Connection, contract: Mapping[str, Any]) -> dict[str, Any]:
    duration = contract["audit"]["matched_pair_agreement"]["duration_delta_buckets_microseconds"]
    packet = contract["audit"]["matched_pair_agreement"]["packet_count_delta_buckets"]
    row = connection.execute("""
        WITH paired AS (
          SELECT ABS((f.last_event_timestamp_ns-f.creation_timestamp_ns)/1000-l.duration_us) duration_delta,
                 ABS(f.packet_count-(l.forward_packet_count+l.backward_packet_count)) packet_delta,
                 CASE WHEN f.forward_source_ip=l.source_ip AND f.forward_source_port=l.source_port THEN 1
                      WHEN f.forward_source_ip<>l.source_ip OR f.forward_source_port<>l.source_port THEN -1
                      ELSE 0 END orientation,
                 f.forward_packet_count,f.reverse_packet_count,l.forward_packet_count label_forward,
                 l.backward_packet_count label_reverse
          FROM audit_matched m JOIN flow f USING(flow_id) JOIN label_row l USING(label_id)
        )
        SELECT COUNT(*),AVG(duration_delta),MAX(duration_delta),
          SUM(duration_delta=0),SUM(duration_delta<=?),SUM(duration_delta<=?),SUM(duration_delta<=?),
          AVG(packet_delta),MAX(packet_delta),SUM(packet_delta=?),SUM(packet_delta<=?),SUM(packet_delta<=?),
          SUM(orientation<>0),
          SUM(CASE WHEN orientation=1 THEN forward_packet_count=label_forward AND reverse_packet_count=label_reverse
                   WHEN orientation=-1 THEN forward_packet_count=label_reverse AND reverse_packet_count=label_forward
                   ELSE 0 END)
        FROM paired
    """, (*duration, packet[0], packet[1], packet[2])).fetchone()
    names = [
        "matched_pairs", "duration_abs_delta_mean_us", "duration_abs_delta_max_us",
        "duration_exact", f"duration_within_{duration[0]}us", f"duration_within_{duration[1]}us",
        f"duration_within_{duration[2]}us", "packet_abs_delta_mean", "packet_abs_delta_max",
        "packet_exact", f"packet_within_{packet[1]}", f"packet_within_{packet[2]}",
        "direction_comparable", "direction_counts_exact"
    ]
    return {name: (value or 0) for name, value in zip(names, row)}


def bounded_examples(connection: sqlite3.Connection, limit: int) -> dict[str, list[dict[str, Any]]]:
    queries = {
        "unmatched_flow": """
          SELECT f.flow_id,f.capture_id,f.packet_count,f.close_reason FROM flow f
          LEFT JOIN audit_raw_fd r USING(flow_id) WHERE r.flow_id IS NULL ORDER BY f.flow_id LIMIT ?""",
        "audit_conflict_flow": """
          SELECT f.flow_id,f.capture_id,f.packet_count,f.close_reason,r.degree raw_candidate_degree
          FROM flow f JOIN audit_raw_fd r USING(flow_id) LEFT JOIN audit_fd d USING(flow_id)
          WHERE d.flow_id IS NULL ORDER BY f.flow_id LIMIT ?""",
        "ambiguous_flow": """
          SELECT f.flow_id,f.capture_id,f.packet_count,f.close_reason,d.degree eligible_label_degree
          FROM flow f JOIN audit_fd d USING(flow_id) LEFT JOIN audit_matched m USING(flow_id)
          WHERE m.flow_id IS NULL ORDER BY d.degree DESC,f.flow_id LIMIT ?""",
        "matched_disagreement": """
          SELECT f.flow_id,l.label_id,f.capture_id,l.label,
            ABS((f.last_event_timestamp_ns-f.creation_timestamp_ns)/1000-l.duration_us) duration_delta_us,
            ABS(f.packet_count-(l.forward_packet_count+l.backward_packet_count)) packet_count_delta
          FROM audit_matched m JOIN flow f USING(flow_id) JOIN label_row l USING(label_id)
          ORDER BY packet_count_delta DESC,duration_delta_us DESC,f.flow_id LIMIT ?""",
    }
    return {
        name: [dict(row) for row in connection.execute(query, (limit,)).fetchall()]
        for name, query in queries.items()
    }


def flowtable_profile(connection: sqlite3.Connection, survey: Mapping[str, Any], profile_seconds: int) -> dict[str, Any]:
    production = {row[0]: row[1] for row in connection.execute(
        "SELECT close_reason,COUNT(*) FROM flow GROUP BY close_reason ORDER BY close_reason"
    )}
    exporter = [dict(row) for row in connection.execute("""
        SELECT e.*,
          (SELECT COUNT(*) FROM flow f WHERE f.capture_id=e.capture_id) observed_flow_count,
          (SELECT COALESCE(SUM(packet_count),0) FROM flow f WHERE f.capture_id=e.capture_id) observed_packet_count
        FROM exporter_summary e ORDER BY capture_id
    """)]
    for row in exporter:
        row["accounting_consistent"] = (
            row["records_read"] == row["packets_parsed"] + row["parser_errors"]
            and row["ingest_errors"] == 0
            and row["exported_flows"] == row["flows_closed"] == row["observed_flow_count"]
            and row["packets_accepted"] == row["observed_packet_count"]
        )
    if not all(row["accounting_consistent"] for row in exporter):
        raise ValueError("FlowTable exporter accounting mismatch")
    profile = survey["totals"]["idle_timeout_profiles"][str(profile_seconds)]
    mapping = {
        "end_of_input": profile["completion_reasons"].get("end_of_file", 0),
        "idle_timeout": profile["completion_reasons"].get("idle_timeout", 0),
        "maximum_age": 0,
        "tcp_fin_handshake": profile["completion_reasons"].get("fin_handshake", 0),
        "tcp_reset": profile["completion_reasons"].get("rst", 0),
        "tuple_reuse": profile["completion_reasons"].get("tuple_reuse", 0),
    }
    reasons = sorted(set(production) | set(mapping))
    comparison = [{
        "reason": reason, "production": production.get(reason, 0), "t1_2_survey": mapping.get(reason, 0),
        "delta": production.get(reason, 0) - mapping.get(reason, 0)
    } for reason in reasons]
    total = sum(production.values())
    return {
        "production_flow_total": total, "t1_2_survey_flow_total": profile["session_count"],
        "flow_total_delta": total - profile["session_count"], "close_reason_comparison": comparison,
        "exporter_summary": exporter,
    }


def compute_audit(connection: sqlite3.Connection, contract: Mapping[str, Any], inputs: Mapping[str, Any]) -> dict[str, Any]:
    progress = SqliteProgress(connection)
    try:
        progress.start("pair_summary")
        create_pair_summary(connection)
        progress.finish()
        tolerances = contract["audit"]["tolerance_seconds"]
        sweeps = []
        class_coverage = []
        for index, seconds in enumerate(tolerances, 1):
            progress.start(f"tolerance_{index}_of_{len(tolerances)}_{seconds}s")
            prepare_tolerance(connection, seconds)
            sweeps.append(sweep_row(connection, seconds))
            class_coverage.extend(label_class_rows(connection, seconds))
            progress.finish()
        if not all(row["stored_summary_consistent"] for row in sweeps):
            raise ValueError("stored T3.3 sweep_summary differs from independent recomputation")
        recommended = min(sweeps, key=lambda row: (-row["matched_count"], row["tolerance_seconds"]))[
            "tolerance_seconds"
        ]
        progress.start(f"recommended_tolerance_detail_{recommended}s")
        prepare_tolerance(connection, recommended)
        detailed_classes = [row for row in class_coverage if row["tolerance_seconds"] == recommended]
        zero_match = sorted({
            row["label"] for row in detailed_classes
            if row["label"] != "BENIGN" and row["total"] > 0 and row["matched"] == 0
        })
        result = {
            "sweeps": sweeps,
            "recommended_tolerance_seconds": recommended,
            "recommendation_basis": "maximum_mutual_unique_match_count_then_smallest_tolerance",
            "flow_status_by_capture": flow_capture_rows(connection),
            "label_status_by_capture_and_class_at_recommended_tolerance": detailed_classes,
            "class_coverage_by_tolerance": class_coverage,
            "ambiguity_topology_at_recommended_tolerance": ambiguity_topology(connection, recommended),
            "ambiguity_candidate_class_purity_at_recommended_tolerance": ambiguity_class_purity(
                connection, recommended
            ),
            "matched_pair_agreement_at_recommended_tolerance": matched_agreement(connection, contract),
            "examples_at_recommended_tolerance": bounded_examples(
                connection, contract["audit"]["examples"]["maximum_per_category"]
            ),
            "zero_match_attack_families_at_recommended_tolerance": zero_match,
            "flowtable_profile": flowtable_profile(
                connection, inputs["survey"],
                contract["comparison_evidence"]["t1_2_flow_survey"]["idle_timeout_profile_seconds"]
            ),
        }
        progress.finish()
        return result
    finally:
        progress.close()


def render_report(receipt: Mapping[str, Any]) -> str:
    audit = receipt["audit"]
    recommended = audit["recommended_tolerance_seconds"]
    sweep = next(row for row in audit["sweeps"] if row["tolerance_seconds"] == recommended)
    lines = [
        "# Báo cáo T3.4 — Audit chất lượng label join CIC-IDS2017", "",
        "## Trạng thái", "",
        "Auditor đã chạy thành công ở chế độ chỉ đọc. Gate vẫn `pending_user_decision`; "
        "T3.5 chưa được mở và không có nhãn nào được tự động thay đổi.", "",
        "## Tolerance sweep", "",
        "| Tolerance | Match | Flow match | Flow ambiguous | Flow unmatched | Flow conflict |", "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in audit["sweeps"]:
        lines.append(
            f"| {row['tolerance_seconds']} giây | {row['matched_count']:,} | "
            f"{row['flow_match_rate']:.4%} | {row['flow_ambiguous']:,} | "
            f"{row['flow_unmatched']:,} | {row['flow_audit_conflict']:,} |"
        )
    lines += [
        "", "## Khuyến nghị kỹ thuật", "",
        f"Tolerance `{recommended}` giây cho số mutual-unique match cao nhất: "
        f"{sweep['matched_count']:,}/{sweep['flow_total']:,} flow ({sweep['flow_match_rate']:.4%}). "
        "Đây chưa phải quyết định được duyệt.", "",
        "## Coverage theo lớp tại tolerance khuyến nghị", "",
        "| Capture | Lớp | Tổng label | Match | Ambiguous | Unmatched | Conflict | Coverage |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in audit["label_status_by_capture_and_class_at_recommended_tolerance"]:
        lines.append(
            f"| {row['capture_id']} | {row['label']} | {row['total']:,} | {row['matched']:,} | "
            f"{row['ambiguous']:,} | {row['unmatched']:,} | {row['audit_conflict']:,} | "
            f"{row['coverage_rate']:.4%} |"
        )
    profile = audit["flowtable_profile"]
    lines += [
        "", "## Đối chiếu FlowTable với khảo sát T1.2", "",
        f"Production export có {profile['production_flow_total']:,} flow; profile 60 giây T1.2 có "
        f"{profile['t1_2_survey_flow_total']:,}, chênh {profile['flow_total_delta']:+,}. "
        "T1.2 là khảo sát trước production, không phải ground truth nhãn.", "",
        "| Close reason | Production | T1.2 survey | Delta |", "|---|---:|---:|---:|",
    ]
    for row in profile["close_reason_comparison"]:
        lines.append(f"| {row['reason']} | {row['production']:,} | {row['t1_2_survey']:,} | {row['delta']:+,} |")
    zero = audit["zero_match_attack_families_at_recommended_tolerance"]
    lines += [
        "", "## Blocker trước T3.5", "",
        "Các attack family có label nguồn nhưng không có mutual-unique match: "
        + (", ".join(f"`{name}`" for name in zero) if zero else "không có") + ".", "",
        "Người dùng phải duyệt tolerance, ngưỡng coverage và family exclusion trước khi T3.4 có thể đóng.", "",
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


def make_receipt(root: Path, contract_path: Path, contract: Mapping[str, Any], inputs: Mapping[str, Any],
                 database_hash: str, audit: Mapping[str, Any]) -> dict[str, Any]:
    relative_contract = contract_path.resolve().relative_to(root.resolve()).as_posix()
    return {
        "schema_version": "1.0.0", "task": "T3.4", "kind": "cicids2017_label_audit",
        "status": "passed", "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host": {"system": platform.system(), "release": platform.release(),
                 "architecture": platform.machine(), "python": platform.python_version(),
                 "sqlite": sqlite3.sqlite_version},
        "producer": {"path": "scripts/audit_t34_label_join.py",
                     "sha256": sha256_path(root / "scripts/audit_t34_label_join.py")},
        "contract": {"path": relative_contract, "sha256": sha256_path(contract_path)},
        "prerequisite": {
            "acceptance": contract["prerequisite"]["acceptance"],
            "build": contract["prerequisite"]["build"],
            "database": {**contract["prerequisite"]["database"], "sha256_after_audit": database_hash},
            "t1_2_flow_survey": contract["comparison_evidence"]["t1_2_flow_survey"],
        },
        "audit": audit,
        "gate": {"status": "pending_user_decision", "selected_tolerance_seconds": None,
                 "thresholds": None, "decision_by": None},
        "checks": [
            {"name": "inputs.content_addressed", "status": "passed"},
            {"name": "database.read_only_integrity_and_schema", "status": "passed"},
            {"name": "join_graph.independently_recomputed", "status": "passed"},
            {"name": "audit.accounting_and_breakdowns", "status": "passed"},
            {"name": "gate.user_decision_required", "status": "passed"},
        ],
    }


def run(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract_path = args.contract.resolve()
    contract, inputs = validate_inputs(root, contract_path)
    database = inputs["database"]
    database_hash_before = sha256_path(database)
    with contextlib.closing(open_database(database)) as connection:
        validate_database(connection, contract["prerequisite"]["database"])
        audit = compute_audit(connection, contract, inputs)
    database_hash_after = sha256_path(database)
    if database_hash_after != database_hash_before:
        raise ValueError("T3.3 database changed during read-only audit")
    receipt = make_receipt(root, contract_path, contract, inputs, database_hash_after, audit)
    report_content = render_report(receipt).encode("utf-8")
    receipt["report"] = {
        "path": args.report.resolve().relative_to(root).as_posix(),
        "sha256": hashlib.sha256(report_content).hexdigest(),
    }
    write_atomic(args.report, report_content)
    write_atomic(args.output, (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(f"T3.4 audit: passed; gate=pending_user_decision; output={args.output}")
    return 0


def validate(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract_path = args.contract.resolve()
    contract, inputs = validate_inputs(root, contract_path)
    receipt = load_json(args.input)
    if receipt.get("task") != "T3.4" or receipt.get("status") != "passed":
        raise ValueError("invalid T3.4 audit receipt identity")
    if receipt.get("contract", {}).get("sha256") != sha256_path(contract_path):
        raise ValueError("audit receipt contract hash mismatch")
    expected_producer = {
        "path": "scripts/audit_t34_label_join.py",
        "sha256": sha256_path(root / "scripts/audit_t34_label_join.py"),
    }
    if receipt.get("producer") != expected_producer:
        raise ValueError("audit receipt producer hash mismatch")
    if receipt.get("gate") != {"status": "pending_user_decision", "selected_tolerance_seconds": None,
                               "thresholds": None, "decision_by": None}:
        raise ValueError("audit receipt gate was decided without user approval")
    with contextlib.closing(open_database(inputs["database"])) as connection:
        validate_database(connection, contract["prerequisite"]["database"])
        recomputed = compute_audit(connection, contract, inputs)
    if receipt.get("audit") != recomputed:
        raise ValueError("audit receipt does not match independent recomputation")
    expected_report = render_report(receipt).encode("utf-8")
    if args.report.read_bytes() != expected_report:
        raise ValueError("T3.4 report content mismatch")
    if receipt.get("report", {}).get("sha256") != hashlib.sha256(expected_report).hexdigest():
        raise ValueError("T3.4 report hash mismatch")
    print("T3.4 audit validation: passed; gate=pending_user_decision")
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument("--contract", type=Path, default=root / "config/cicids2017-label-audit-contract.json")
        command.add_argument("--input", type=Path, default=root / "run_log/t3.4/audit.json")
        command.add_argument("--output", type=Path, default=root / "run_log/t3.4/audit.json")
        command.add_argument("--report", type=Path, default=root / "docs/dataset/cicids2017-label-audit.vi.md")
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
