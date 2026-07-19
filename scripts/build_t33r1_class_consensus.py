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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence


APPLICATION_ID = 0x4E435331
USER_VERSION = 331
REQUIRED_SOURCE_COLUMNS = {
    "candidate_edge": {
        "flow_id", "label_id", "required_tolerance_ns", "schedule_conflict", "role_conflict"
    },
    "flow": {"flow_id", "capture_id"},
    "label_row": {"label_id", "label"},
    "quarantined_label_row": {"label", "reason"},
}
DERIVED_TABLES = {"assignment_candidate", "build_metadata", "flow_assignment", "quarantine"}


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
    root: Path,
    reference: Mapping[str, Any],
    *,
    task: str,
    status: str,
) -> tuple[Path, dict[str, Any]]:
    path = resolve_relative(root, str(reference.get("path", "")))
    expected = str(reference.get("sha256", ""))
    if len(expected) != 64 or sha256_path(path) != expected:
        raise ValueError(f"SHA-256 mismatch: {reference.get('path')}")
    document = load_json(path)
    if document.get("task") != task or document.get("status") != status:
        raise ValueError(f"identity mismatch: {reference.get('path')}")
    return path, document


def validate_inputs(root: Path, contract_path: Path) -> tuple[dict[str, Any], Path]:
    contract = load_json(contract_path)
    if contract.get("task") != "T3.3R1" or contract.get("schema_version") != "1.0.0":
        raise ValueError("invalid T3.3R1 contract identity")
    execution = contract.get("execution", {})
    if not (
        execution.get("host") == "windows_native"
        and execution.get("source_database_uri_mode") == "ro"
        and execution.get("source_database_immutable") is True
        and execution.get("selected_tolerance_seconds") == 0
        and execution.get("source_mutation_allowed") is False
        and execution.get("source_label_mutation_allowed") is False
        and execution.get("source_flow_boundary_changes_allowed") is False
        and execution.get("historical_evidence_rewrite_allowed") is False
    ):
        raise ValueError("contract weakens immutable fail-closed execution")
    assignment = contract.get("assignment", {})
    if assignment.get("decision_order") != ["mutual_unique", "class_consensus", "quarantine"]:
        raise ValueError("invalid assignment decision order")
    if assignment.get("family_scope", {}).get("implicit_family_exclusions_allowed") is not False:
        raise ValueError("implicit family exclusions must remain forbidden")
    prerequisites = contract.get("prerequisites", {})
    _, t33 = validate_reference(
        root, prerequisites.get("t3_3_acceptance", {}), task="T3.3", status="passed"
    )
    _, t34 = validate_reference(
        root, prerequisites.get("t3_4_acceptance", {}), task="T3.4", status="passed"
    )
    _, audit = validate_reference(
        root, prerequisites.get("t3_4_audit", {}), task="T3.4", status="passed"
    )
    if t34.get("gate", {}).get("decision") != "rejected":
        raise ValueError("T3.4 did not reject the mutual-unique join for T3.5")
    if t34.get("gate", {}).get("t3_5_authorized") is not False:
        raise ValueError("T3.4 unexpectedly authorizes T3.5")
    if t34.get("user_approval", {}).get("selected_tolerance_seconds") != 0:
        raise ValueError("T3.4 acceptance did not approve tolerance zero")
    if audit.get("gate", {}).get("status") != "pending_user_decision":
        raise ValueError("T3.4 raw audit gate was mutated")
    database_ref = prerequisites.get("t3_3_database", {})
    source = resolve_relative(root, str(database_ref.get("path", "")))
    if source.stat().st_size != database_ref.get("size_bytes"):
        raise ValueError("T3.3 source database size mismatch")
    source_hash = sha256_path(source)
    if source_hash != database_ref.get("sha256"):
        raise ValueError("T3.3 source database hash mismatch")
    if t33.get("sqlite", {}).get("sha256") != source_hash:
        raise ValueError("T3.3 acceptance database mismatch")
    return contract, source


def open_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA temp_store=FILE")
    return connection


def validate_source(connection: sqlite3.Connection, reference: Mapping[str, Any]) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("T3.3 source database integrity_check failed")
    if connection.execute("PRAGMA application_id").fetchone()[0] != reference.get("application_id"):
        raise ValueError("T3.3 source application_id mismatch")
    if connection.execute("PRAGMA user_version").fetchone()[0] != reference.get("user_version"):
        raise ValueError("T3.3 source user_version mismatch")
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, required in REQUIRED_SOURCE_COLUMNS.items():
        if table not in tables:
            raise ValueError(f"T3.3 source database missing table: {table}")
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        missing = sorted(required - columns)
        if missing:
            raise ValueError(f"T3.3 source table {table} missing columns: {', '.join(missing)}")


def validate_source_label_quarantine(
    connection: sqlite3.Connection, contract: Mapping[str, Any]
) -> None:
    expected = set(
        contract["assignment"]["quarantine"]["source_label_quarantine_accounting"]
    )
    observed = {
        row[0] for row in connection.execute(
            "SELECT DISTINCT reason FROM quarantined_label_row"
        )
    }
    if observed != expected:
        raise ValueError(
            "source label quarantine reasons differ from contract: "
            f"expected={sorted(expected)} observed={sorted(observed)}"
        )


def attach_source(connection: sqlite3.Connection, source: Path) -> None:
    uri = f"file:{source.as_posix()}?mode=ro&immutable=1"
    connection.execute("ATTACH DATABASE ? AS source", (uri,))


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(f"""
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        PRAGMA application_id={APPLICATION_ID};
        PRAGMA user_version={USER_VERSION};
        CREATE TABLE build_metadata(
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        ) STRICT;
        CREATE TABLE flow_assignment(
          flow_id INTEGER PRIMARY KEY,
          capture_id TEXT NOT NULL,
          assigned_class TEXT NOT NULL,
          assignment_method TEXT NOT NULL CHECK(assignment_method IN ('mutual_unique','class_consensus')),
          eligible_candidate_count INTEGER NOT NULL CHECK(eligible_candidate_count>=1),
          distinct_eligible_candidate_class_count INTEGER NOT NULL
            CHECK(distinct_eligible_candidate_class_count=1),
          eligible_candidate_label_ids_json TEXT NOT NULL CHECK(json_valid(eligible_candidate_label_ids_json)),
          mutual_unique_label_id INTEGER,
          CHECK(
            (assignment_method='mutual_unique' AND eligible_candidate_count=1
             AND mutual_unique_label_id IS NOT NULL)
            OR
            (assignment_method='class_consensus' AND mutual_unique_label_id IS NULL)
          )
        ) STRICT;
        CREATE TABLE assignment_candidate(
          flow_id INTEGER NOT NULL REFERENCES flow_assignment(flow_id),
          label_id INTEGER NOT NULL,
          candidate_class TEXT NOT NULL,
          eligible_variant_count INTEGER NOT NULL CHECK(eligible_variant_count>=1),
          minimum_required_tolerance_ns INTEGER NOT NULL CHECK(minimum_required_tolerance_ns=0),
          PRIMARY KEY(flow_id,label_id)
        ) STRICT;
        CREATE TABLE quarantine(
          flow_id INTEGER PRIMARY KEY,
          capture_id TEXT NOT NULL,
          reason TEXT NOT NULL CHECK(reason IN (
            'mixed_candidate_classes','audit_conflict','no_eligible_candidate'
          )),
          raw_candidate_count INTEGER NOT NULL CHECK(raw_candidate_count>=0),
          eligible_candidate_count INTEGER NOT NULL CHECK(eligible_candidate_count>=0),
          distinct_eligible_candidate_class_count INTEGER NOT NULL
            CHECK(distinct_eligible_candidate_class_count>=0)
        ) STRICT;
    """)


def build_projection(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TEMP TABLE raw_pair AS
        SELECT flow_id,label_id,COUNT(*) raw_variant_count
        FROM source.candidate_edge WHERE required_tolerance_ns<=0
        GROUP BY flow_id,label_id;
        CREATE UNIQUE INDEX raw_pair_key ON raw_pair(flow_id,label_id);
        CREATE TEMP TABLE eligible_pair AS
        SELECT e.flow_id,e.label_id,l.label candidate_class,
               COUNT(*) eligible_variant_count,MIN(e.required_tolerance_ns) minimum_required_tolerance_ns
        FROM source.candidate_edge e JOIN source.label_row l USING(label_id)
        WHERE e.required_tolerance_ns<=0 AND e.schedule_conflict=0 AND e.role_conflict=0
        GROUP BY e.flow_id,e.label_id,l.label;
        CREATE UNIQUE INDEX eligible_pair_key ON eligible_pair(flow_id,label_id);
        CREATE TEMP TABLE flow_stats AS
        SELECT flow_id,COUNT(*) eligible_candidate_count,
               COUNT(DISTINCT candidate_class) distinct_class_count,MIN(candidate_class) only_class
        FROM eligible_pair GROUP BY flow_id;
        CREATE UNIQUE INDEX flow_stats_key ON flow_stats(flow_id);
        CREATE TEMP TABLE label_degree AS
        SELECT label_id,COUNT(*) flow_degree FROM eligible_pair GROUP BY label_id;
        CREATE UNIQUE INDEX label_degree_key ON label_degree(label_id);
        CREATE TEMP TABLE mutual_flow AS
        SELECT p.flow_id,p.label_id FROM eligible_pair p
        JOIN flow_stats f USING(flow_id) JOIN label_degree l USING(label_id)
        WHERE f.eligible_candidate_count=1 AND l.flow_degree=1;
        CREATE UNIQUE INDEX mutual_flow_key ON mutual_flow(flow_id);
        CREATE TEMP TABLE candidate_json AS
        SELECT flow_id,'['||group_concat(label_id,',')||']' candidate_ids
        FROM (SELECT flow_id,label_id FROM eligible_pair ORDER BY flow_id,label_id)
        GROUP BY flow_id;

        INSERT INTO flow_assignment
        SELECT f.flow_id,f.capture_id,s.only_class,
               CASE WHEN m.flow_id IS NOT NULL THEN 'mutual_unique' ELSE 'class_consensus' END,
               s.eligible_candidate_count,s.distinct_class_count,j.candidate_ids,m.label_id
        FROM source.flow f JOIN flow_stats s USING(flow_id)
        JOIN candidate_json j USING(flow_id) LEFT JOIN mutual_flow m USING(flow_id)
        WHERE s.distinct_class_count=1 ORDER BY f.flow_id;

        INSERT INTO assignment_candidate
        SELECT p.flow_id,p.label_id,p.candidate_class,p.eligible_variant_count,
               p.minimum_required_tolerance_ns
        FROM eligible_pair p JOIN flow_assignment a USING(flow_id)
        ORDER BY p.flow_id,p.label_id;

        INSERT INTO quarantine
        SELECT f.flow_id,f.capture_id,
               CASE WHEN s.distinct_class_count>1 THEN 'mixed_candidate_classes'
                    WHEN r.raw_candidate_count>0 THEN 'audit_conflict'
                    ELSE 'no_eligible_candidate' END,
               COALESCE(r.raw_candidate_count,0),COALESCE(s.eligible_candidate_count,0),
               COALESCE(s.distinct_class_count,0)
        FROM source.flow f
        LEFT JOIN (SELECT flow_id,COUNT(*) raw_candidate_count FROM raw_pair GROUP BY flow_id) r
          USING(flow_id)
        LEFT JOIN flow_stats s USING(flow_id)
        WHERE s.distinct_class_count IS NULL OR s.distinct_class_count<>1
        ORDER BY f.flow_id;
    """)


def validate_derived_structure(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("derived database integrity_check failed")
    if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
        raise ValueError("derived database application_id mismatch")
    if connection.execute("PRAGMA user_version").fetchone()[0] != USER_VERSION:
        raise ValueError("derived database user_version mismatch")
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if tables != DERIVED_TABLES:
        raise ValueError(f"derived database table set mismatch: {sorted(tables)}")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("derived database foreign_key_check failed")
    non_strict = connection.execute(
        "SELECT name FROM pragma_table_list WHERE schema='main' AND name NOT LIKE 'sqlite_%' AND strict<>1"
    ).fetchall()
    if non_strict:
        raise ValueError("all derived tables must be STRICT")


def expected_metadata(root: Path, contract_path: Path, source_hash: str) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "task": "T3.3R1",
        "contract_sha256": sha256_path(contract_path),
        "producer_sha256": sha256_path(root / "scripts/build_t33r1_class_consensus.py"),
        "source_database_sha256": source_hash,
        "selected_tolerance_seconds": "0",
    }


def validate_metadata(
    connection: sqlite3.Connection,
    root: Path,
    contract_path: Path,
    source_hash: str,
) -> None:
    observed = dict(connection.execute("SELECT key,value FROM build_metadata"))
    if observed != expected_metadata(root, contract_path, source_hash):
        raise ValueError("derived build_metadata mismatch")


def scalar(connection: sqlite3.Connection, sql: str) -> int:
    return int(connection.execute(sql).fetchone()[0])


def summarize(source: sqlite3.Connection, derived: sqlite3.Connection) -> dict[str, Any]:
    totals = {
        "source_flows": scalar(source, "SELECT COUNT(*) FROM flow"),
        "assigned": scalar(derived, "SELECT COUNT(*) FROM flow_assignment"),
        "mutual_unique": scalar(
            derived, "SELECT COUNT(*) FROM flow_assignment WHERE assignment_method='mutual_unique'"
        ),
        "class_consensus": scalar(
            derived, "SELECT COUNT(*) FROM flow_assignment WHERE assignment_method='class_consensus'"
        ),
        "quarantined": scalar(derived, "SELECT COUNT(*) FROM quarantine"),
    }
    if totals["source_flows"] != totals["assigned"] + totals["quarantined"]:
        raise ValueError("source flow accounting mismatch")
    if totals["assigned"] != totals["mutual_unique"] + totals["class_consensus"]:
        raise ValueError("assignment method accounting mismatch")
    by_capture = [dict(row) for row in derived.execute("""
        SELECT capture_id,SUM(assigned) assigned,SUM(quarantined) quarantined
        FROM (
          SELECT capture_id,COUNT(*) assigned,0 quarantined FROM flow_assignment GROUP BY capture_id
          UNION ALL
          SELECT capture_id,0,COUNT(*) FROM quarantine GROUP BY capture_id
        ) GROUP BY capture_id ORDER BY capture_id
    """)]
    source_captures = {row[0]: row[1] for row in source.execute(
        "SELECT capture_id,COUNT(*) FROM flow GROUP BY capture_id"
    )}
    if {row["capture_id"]: row["assigned"] + row["quarantined"] for row in by_capture} != source_captures:
        raise ValueError("per-capture flow accounting mismatch")
    assigned = {
        row[0]: (row[1], row[2], row[3])
        for row in derived.execute("""
          SELECT assigned_class,COUNT(*),SUM(assignment_method='mutual_unique'),
                 SUM(assignment_method='class_consensus')
          FROM flow_assignment GROUP BY assigned_class
        """)
    }
    joinable = dict(source.execute(
        "SELECT label,COUNT(*) FROM label_row GROUP BY label"
    ))
    source_quarantined = dict(source.execute(
        "SELECT label,COUNT(*) FROM quarantined_label_row GROUP BY label"
    ))
    by_class = []
    for label in sorted(set(joinable) | set(source_quarantined)):
        values = assigned.get(label, (0, 0, 0))
        by_class.append({
            "label": label,
            "source_label_rows": joinable.get(label, 0),
            "source_quarantined_label_rows": source_quarantined.get(label, 0),
            "assigned_flows": values[0],
            "mutual_unique": values[1], "class_consensus": values[2],
        })
    if set(assigned) - {row["label"] for row in by_class}:
        raise ValueError("assignment introduced a class absent from source labels")
    source_label_quarantine = [dict(row) for row in source.execute(
        "SELECT reason,COUNT(*) count FROM quarantined_label_row GROUP BY reason ORDER BY reason"
    )]
    return {
        "totals": totals,
        "by_capture": by_capture,
        "by_class": by_class,
        "flow_quarantine_by_reason": [dict(row) for row in derived.execute(
            "SELECT reason,COUNT(*) count FROM quarantine GROUP BY reason ORDER BY reason"
        )],
        "source_label_quarantine_by_reason": source_label_quarantine,
    }


def write_json_new(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists() or os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def build_receipt(
    root: Path,
    contract_path: Path,
    contract: Mapping[str, Any],
    source: Path,
    source_hash: str,
    derived: Path,
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "task": "T3.3R1",
        "kind": "class_consensus_build",
        "status": "passed",
        "acceptance_status": "pending_independent_validation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host": {
            "system": platform.system(), "architecture": platform.machine(),
            "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        },
        "producer": {
            "path": "scripts/build_t33r1_class_consensus.py",
            "sha256": sha256_path(root / "scripts/build_t33r1_class_consensus.py"),
        },
        "contract": {
            "path": contract_path.resolve().relative_to(root.resolve()).as_posix(),
            "sha256": sha256_path(contract_path),
        },
        "prerequisites": contract["prerequisites"],
        "source_database": {
            "path": source.resolve().relative_to(root.resolve()).as_posix(),
            "sha256_before": source_hash,
            "sha256_after": sha256_path(source),
        },
        "derived_database": {
            "path": derived.resolve().relative_to(root.resolve()).as_posix(),
            "size_bytes": derived.stat().st_size,
            "sha256": sha256_path(derived),
            "application_id": APPLICATION_ID,
            "user_version": USER_VERSION,
        },
        "projection": {
            "selected_tolerance_seconds": 0,
            "assignment_methods": ["mutual_unique", "class_consensus"],
            "candidate_count_unit": "distinct_label_id",
            "representative_label_selected_for_class_consensus": False,
        },
        "summary": summary,
        "gate": {"t3_5_authorized": False, "next_task": "T3.4R1"},
        "checks": [
            {"name": "source.read_only_immutable_and_hash_stable", "status": "passed"},
            {"name": "projection.fail_closed_class_consensus", "status": "passed"},
            {"name": "projection.provenance_preserved", "status": "passed"},
            {"name": "accounting.flow_partition", "status": "passed"},
            {"name": "t3_5.remains_locked", "status": "passed"},
        ],
    }


def run(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract_path = args.contract.resolve()
    contract, source = validate_inputs(root, contract_path)
    database_output = args.database_output.resolve()
    build_output = args.build_output.resolve()
    if database_output.exists() or os.path.lexists(database_output):
        raise ValueError(f"refusing to overwrite existing file: {database_output}")
    if build_output.exists() or os.path.lexists(build_output):
        raise ValueError(f"refusing to overwrite existing file: {build_output}")
    source_hash = sha256_path(source)
    database_output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=database_output.name + ".", suffix=".tmp", dir=database_output.parent
    )
    os.close(handle)
    temporary = Path(temporary_name)
    try:
        with contextlib.closing(open_read_only(source)) as source_connection:
            validate_source(source_connection, contract["prerequisites"]["t3_3_database"])
            validate_source_label_quarantine(source_connection, contract)
        with contextlib.closing(sqlite3.connect(temporary, uri=True)) as output:
            output.row_factory = sqlite3.Row
            create_schema(output)
            attach_source(output, source)
            build_projection(output)
            output.executemany(
                "INSERT INTO build_metadata(key,value) VALUES(?,?)",
                sorted(expected_metadata(root, contract_path, source_hash).items()),
            )
            output.commit()
            output.execute("DETACH DATABASE source")
            validate_derived_structure(output)
            output.execute("VACUUM")
        if sha256_path(source) != source_hash:
            raise ValueError("T3.3 source database changed during projection")
        os.replace(temporary, database_output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    with contextlib.closing(open_read_only(source)) as source_connection, contextlib.closing(
        open_read_only(database_output)
    ) as derived_connection:
        summary = summarize(source_connection, derived_connection)
    receipt = build_receipt(
        root, contract_path, contract, source, source_hash, database_output, summary
    )
    write_json_new(build_output, receipt)
    print(
        f"T3.3R1 build: passed; assigned={summary['totals']['assigned']}; "
        f"quarantined={summary['totals']['quarantined']}; output={database_output}",
        flush=True,
    )
    return 0


def create_expected_projection(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TEMP TABLE verify_raw AS
        SELECT flow_id,label_id FROM candidate_edge WHERE required_tolerance_ns<=0
        GROUP BY flow_id,label_id;
        CREATE TEMP TABLE verify_eligible AS
        SELECT e.flow_id,e.label_id,l.label candidate_class,COUNT(*) variant_count,
               MIN(e.required_tolerance_ns) minimum_required_tolerance_ns
        FROM candidate_edge e JOIN label_row l USING(label_id)
        WHERE e.required_tolerance_ns<=0 AND NOT e.schedule_conflict AND NOT e.role_conflict
        GROUP BY e.flow_id,e.label_id,l.label;
        CREATE TEMP TABLE verify_label_degree AS
        SELECT label_id,COUNT(DISTINCT flow_id) degree FROM verify_eligible GROUP BY label_id;
        CREATE TEMP TABLE verify_flow AS
        SELECT flow_id,COUNT(DISTINCT label_id) candidate_count,
               COUNT(DISTINCT candidate_class) class_count,MIN(candidate_class) only_class
        FROM verify_eligible GROUP BY flow_id;
        CREATE TEMP TABLE verify_ids AS
        SELECT flow_id,'['||group_concat(label_id,',')||']' ids
        FROM (SELECT flow_id,label_id FROM verify_eligible ORDER BY flow_id,label_id)
        GROUP BY flow_id;
        CREATE TEMP TABLE expected_assignment AS
        SELECT f.flow_id,f.capture_id,v.only_class assigned_class,
               CASE WHEN v.candidate_count=1 AND d.degree=1
                    THEN 'mutual_unique' ELSE 'class_consensus' END assignment_method,
               v.candidate_count eligible_candidate_count,
               v.class_count distinct_eligible_candidate_class_count,
               i.ids eligible_candidate_label_ids_json,
               CASE WHEN v.candidate_count=1 AND d.degree=1
                    THEN e.label_id END mutual_unique_label_id
        FROM flow f JOIN verify_flow v USING(flow_id) JOIN verify_ids i USING(flow_id)
        LEFT JOIN verify_eligible e ON e.flow_id=f.flow_id AND v.candidate_count=1
        LEFT JOIN verify_label_degree d ON d.label_id=e.label_id
        WHERE v.class_count=1;
        CREATE TEMP TABLE expected_candidate AS
        SELECT e.flow_id,e.label_id,e.candidate_class,
               e.variant_count eligible_variant_count,e.minimum_required_tolerance_ns
        FROM verify_eligible e JOIN expected_assignment a USING(flow_id);
        CREATE TEMP TABLE expected_quarantine AS
        SELECT f.flow_id,f.capture_id,
               CASE WHEN v.class_count>1 THEN 'mixed_candidate_classes'
                    WHEN r.raw_count>0 THEN 'audit_conflict'
                    ELSE 'no_eligible_candidate' END reason,
               COALESCE(r.raw_count,0) raw_candidate_count,
               COALESCE(v.candidate_count,0) eligible_candidate_count,
               COALESCE(v.class_count,0) distinct_eligible_candidate_class_count
        FROM flow f
        LEFT JOIN (SELECT flow_id,COUNT(*) raw_count FROM verify_raw GROUP BY flow_id) r USING(flow_id)
        LEFT JOIN verify_flow v USING(flow_id)
        WHERE v.class_count IS NULL OR v.class_count<>1;
    """)


def assert_same(connection: sqlite3.Connection, expected: str, actual: str, columns: str) -> None:
    forward = connection.execute(
        f"SELECT 1 FROM (SELECT {columns} FROM {expected} EXCEPT SELECT {columns} FROM {actual}) LIMIT 1"
    ).fetchone()
    reverse = connection.execute(
        f"SELECT 1 FROM (SELECT {columns} FROM {actual} EXCEPT SELECT {columns} FROM {expected}) LIMIT 1"
    ).fetchone()
    if forward is not None or reverse is not None:
        raise ValueError(f"derived projection differs from independent recomputation: {actual}")


def validate(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract_path = args.contract.resolve()
    contract, source = validate_inputs(root, contract_path)
    receipt = load_json(args.build_input)
    if receipt.get("task") != "T3.3R1" or receipt.get("status") != "passed":
        raise ValueError("invalid T3.3R1 build receipt identity")
    expected_producer = {
        "path": "scripts/build_t33r1_class_consensus.py",
        "sha256": sha256_path(root / "scripts/build_t33r1_class_consensus.py"),
    }
    if receipt.get("producer") != expected_producer:
        raise ValueError("T3.3R1 producer hash mismatch")
    expected_contract = {
        "path": contract_path.resolve().relative_to(root).as_posix(),
        "sha256": sha256_path(contract_path),
    }
    if receipt.get("contract") != expected_contract:
        raise ValueError("T3.3R1 contract hash mismatch")
    if receipt.get("prerequisites") != contract["prerequisites"]:
        raise ValueError("T3.3R1 prerequisite evidence mismatch")
    derived_ref = receipt.get("derived_database", {})
    derived = resolve_relative(root, str(derived_ref.get("path", "")))
    if derived.stat().st_size != derived_ref.get("size_bytes") or sha256_path(derived) != derived_ref.get("sha256"):
        raise ValueError("derived database size or hash mismatch")
    if (
        derived_ref.get("application_id") != APPLICATION_ID
        or derived_ref.get("user_version") != USER_VERSION
    ):
        raise ValueError("derived database identity receipt mismatch")
    source_hash = sha256_path(source)
    expected_source = {
        "path": source.resolve().relative_to(root).as_posix(),
        "sha256_before": source_hash,
        "sha256_after": source_hash,
    }
    if receipt.get("source_database") != expected_source:
        raise ValueError("build receipt source hash mismatch")
    if receipt.get("gate") != {"t3_5_authorized": False, "next_task": "T3.4R1"}:
        raise ValueError("build receipt unexpectedly authorizes T3.5")
    with contextlib.closing(open_read_only(derived)) as derived_connection:
        validate_derived_structure(derived_connection)
        validate_metadata(derived_connection, root, contract_path, source_hash)
    with contextlib.closing(open_read_only(source)) as connection:
        validate_source(connection, contract["prerequisites"]["t3_3_database"])
        validate_source_label_quarantine(connection, contract)
        connection.execute(
            "ATTACH DATABASE ? AS derived",
            (f"file:{derived.as_posix()}?mode=ro&immutable=1",),
        )
        create_expected_projection(connection)
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
        overlap = connection.execute("""
            SELECT 1 FROM derived.flow_assignment a JOIN derived.quarantine q USING(flow_id) LIMIT 1
        """).fetchone()
        if overlap is not None:
            raise ValueError("flow appears in both assignment and quarantine")
    if sha256_path(source) != source_hash:
        raise ValueError("T3.3 source database changed during validation")
    with contextlib.closing(open_read_only(source)) as source_connection, contextlib.closing(
        open_read_only(derived)
    ) as derived_connection:
        expected_summary = summarize(source_connection, derived_connection)
    if receipt.get("summary") != expected_summary:
        raise ValueError("build receipt summary mismatch")
    acceptance = {
        "schema_version": "1.0.0",
        "task": "T3.3R1",
        "kind": "class_consensus_acceptance",
        "status": "passed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "producer": expected_producer,
        "contract": receipt["contract"],
        "build": {
            "path": args.build_input.resolve().relative_to(root).as_posix(),
            "sha256": sha256_path(args.build_input),
            "status": "passed",
        },
        "source_database": receipt["source_database"],
        "derived_database": receipt["derived_database"],
        "summary": expected_summary,
        "independent_recomputation": True,
        "gate": {"t3_5_authorized": False, "next_task": "T3.4R1"},
        "checks": [
            {"name": "source.integrity_hash_and_immutability", "status": "passed"},
            {"name": "derived.integrity_schema_and_constraints", "status": "passed"},
            {"name": "projection.independent_bidirectional_set_comparison", "status": "passed"},
            {"name": "receipt.accounting_and_provenance", "status": "passed"},
            {"name": "t3_5.remains_locked", "status": "passed"},
        ],
    }
    write_json_new(args.acceptance_output, acceptance)
    print("T3.3R1 validation: passed; next=T3.4R1; T3.5 locked", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    validate_parser = subparsers.add_parser("validate")
    for command in (run_parser, validate_parser):
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument(
            "--contract", type=Path,
            default=root / "config/cicids2017-class-consensus-contract.json",
        )
    run_parser.add_argument(
        "--database-output", type=Path,
        default=root / "run_log/t3.3r1/class-consensus.sqlite3",
    )
    run_parser.add_argument(
        "--build-output", type=Path, default=root / "run_log/t3.3r1/build.json"
    )
    validate_parser.add_argument(
        "--build-input", type=Path, default=root / "run_log/t3.3r1/build.json"
    )
    validate_parser.add_argument(
        "--acceptance-output", type=Path,
        default=root / "run_log/t3.3r1/acceptance.json",
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
