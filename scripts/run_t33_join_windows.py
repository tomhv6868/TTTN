#!/usr/bin/env python3
"""Run the restartable native-Windows T3.3 join pipeline one stage at a time."""

from __future__ import annotations

import argparse
import copy
import importlib
import json
import os
import platform
import shutil
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("build_t33_label_join")
shards = importlib.import_module("export_t33_flow_shards")
verifier = importlib.import_module("verify_t33_label_join")


SCHEMA_VERSION = "1.0.0"
TASK = "T3.3"
KIND = "windows_join_checkpoint"


@dataclass(frozen=True)
class Stage:
    key: str
    kind: str
    ordinal: int
    total: int
    capture_id: str | None = None
    tolerance_seconds: int | None = None


def emit(**fields: Any) -> None:
    print(
        "[T3.3 windows-join] "
        + json.dumps(fields, ensure_ascii=False, separators=(",", ":")),
        flush=True,
    )


def version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for part in value.split("."):
        digits = "".join(character for character in part if character.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def windows_join_spec(contract: Mapping[str, Any]) -> Mapping[str, Any]:
    pipeline = shards.pipeline_spec(contract)
    spec = pipeline.get("windows_join")
    if (
        not isinstance(spec, Mapping)
        or spec.get("database_name") != "label-join.work.sqlite3"
        or spec.get("checkpoint_table") != "pipeline_stage"
        or spec.get("capture_stage_order") != ["flow", "labels", "edges"]
        or spec.get("tolerance_stage_order_seconds")
        != contract["join"]["tolerance_sweep_seconds"]
        or spec.get("transaction_policy") != "one_stage_per_transaction"
        or spec.get("index_build_policy")
        != "create_empty_indexes_before_bulk_import"
        or not isinstance(spec.get("heartbeat_seconds"), int)
        or spec["heartbeat_seconds"] <= 0
        or not isinstance(spec.get("default_max_stages"), int)
        or spec["default_max_stages"] <= 0
    ):
        raise ValueError("invalid Windows join pipeline contract")
    return spec


def stage_plan(contract: Mapping[str, Any]) -> list[Stage]:
    spec = windows_join_spec(contract)
    definitions: list[tuple[str, str, str | None, int | None]] = [
        ("init", "init", None, None)
    ]
    for capture in contract["captures"]:
        capture_id = capture["id"]
        for kind in spec["capture_stage_order"]:
            definitions.append((f"{kind}:{capture_id}", kind, capture_id, None))
    for seconds in spec["tolerance_stage_order_seconds"]:
        definitions.append((f"sweep:{seconds}", "sweep", None, seconds))
    total = len(definitions)
    return [
        Stage(key, kind, index, total, capture_id, tolerance)
        for index, (key, kind, capture_id, tolerance) in enumerate(
            definitions, start=1
        )
    ]


def join_contract_record(contract: Mapping[str, Any]) -> dict[str, Any]:
    pipeline = contract["execution_pipeline"]
    join_spec = pipeline["windows_join"]
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "join": contract["join"],
        "csv_schema": contract["csv_schema"],
        "captures": contract["captures"],
        "attack_audit": contract["attack_audit"],
        "flow_shards": pipeline["flow_shards"],
        "windows_join": {
            key: join_spec[key]
            for key in (
                "checkpoint_table",
                "capture_stage_order",
                "tolerance_stage_order_seconds",
                "transaction_policy",
                "source_rehash_scope",
                "index_build_policy",
            )
        },
        "sqlite": {
            key: contract["sqlite"][key]
            for key in (
                "application_id",
                "user_version",
                "page_size",
                "raw_packet_or_payload_storage",
            )
        },
    }


def join_contract_sha256(contract: Mapping[str, Any]) -> str:
    return shards.stable_sha256(join_contract_record(contract))


def work_paths(
    root: Path, contract: Mapping[str, Any]
) -> tuple[Path, Path]:
    spec = windows_join_spec(contract)
    work_root = core.resolve_path(root, spec["directory"])
    return work_root, work_root / spec["database_name"]


def inspect_windows_host() -> dict[str, Any]:
    timezone_ok = False
    try:
        ZoneInfo("America/Moncton")
        timezone_ok = True
    except ZoneInfoNotFoundError:
        pass
    return {
        "system": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "timezone_available": timezone_ok,
    }


def require_windows_host(contract: Mapping[str, Any]) -> dict[str, Any]:
    host = inspect_windows_host()
    runtime = contract["execution_pipeline"]["windows_runtime"]
    if host["system"] != "Windows" or os.name != "nt":
        raise RuntimeError("T3.3 portable join requires native Windows")
    if not str(host["python"]).startswith(runtime["python_major_minor"] + "."):
        raise RuntimeError(
            f"T3.3 portable join requires Python {runtime['python_major_minor']}.x"
        )
    if version_tuple(str(host["sqlite"])) < version_tuple(
        runtime["sqlite_minimum"]
    ):
        raise RuntimeError(
            f"T3.3 portable join requires SQLite >= {runtime['sqlite_minimum']}"
        )
    if host["timezone_available"] is not True:
        raise RuntimeError(
            f"T3.3 portable join requires timezone {runtime['required_timezone']}"
        )
    return host


def validate_contract(root: Path, contract_path: Path) -> dict[str, Any]:
    contract = core.load_json(contract_path)
    errors = core.validate_contract(contract)
    if errors:
        raise ValueError(f"invalid T3.3 contract: {errors}")
    windows_join_spec(contract)
    if contract_path.resolve() != (
        root / "config" / "cicids2017-label-join-contract.json"
    ):
        raise ValueError("contract must be the project T3.3 contract")
    core.validate_timezone(contract)
    return contract


def create_work_database(
    root: Path,
    contract_path: Path,
    contract: Mapping[str, Any],
    enforce_environment: bool,
) -> dict[str, Any]:
    work_root, database = work_paths(root, contract)
    if database.exists():
        raise ValueError(f"work database already exists: {database}")
    host = require_windows_host(contract) if enforce_environment else inspect_windows_host()
    work_root.mkdir(parents=True, exist_ok=True)
    temporary = work_root / f".{database.name}.{uuid.uuid4().hex}.tmp"
    plan = stage_plan(contract)
    stage = plan[0]
    started = time.monotonic()
    emit(
        stage=stage.key,
        status="running",
        completed_units=0,
        total_units=stage.total,
        elapsed_seconds=0.0,
        artifact_path=str(database),
    )
    connection = core.sqlite3.connect(temporary)
    try:
        core.create_schema(connection, contract)
        connection.execute("""
            CREATE TABLE pipeline_stage(
                stage_key TEXT PRIMARY KEY,
                ordinal INTEGER NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                capture_id TEXT,
                tolerance_seconds INTEGER,
                generated_at_utc TEXT NOT NULL,
                elapsed_seconds REAL NOT NULL,
                metrics_json TEXT NOT NULL
            ) STRICT
        """)
        connection.executescript("""
            CREATE INDEX flow_join_idx ON flow(
                capture_id,protocol,low_ip,low_port,high_ip,high_port,
                creation_timestamp_ns,last_event_timestamp_ns
            );
            CREATE INDEX label_join_idx ON label_row(
                capture_id,protocol,low_ip,low_port,high_ip,high_port
            );
            CREATE INDEX variant_time_idx ON label_time_variant(start_min_ns,end_max_ns);
            CREATE INDEX edge_tolerance_idx ON candidate_edge(
                required_tolerance_ns,schedule_conflict,role_conflict
            );
            CREATE INDEX edge_label_idx ON candidate_edge(label_id,required_tolerance_ns);
        """)
        producer_sha256 = core.sha256_path(Path(__file__))
        semantic_sha256 = join_contract_sha256(contract)
        connection.executemany(
            "INSERT INTO metadata VALUES(?,?)",
            [
                ("schema_version", SCHEMA_VERSION),
                ("task", TASK),
                ("kind", KIND),
                ("join_contract_sha256", semantic_sha256),
                ("task_contract_sha256", core.sha256_path(contract_path)),
                ("producer_sha256", producer_sha256),
                ("candidate_timezone", contract["join"]["candidate_timezone"]["iana_name"]),
                ("timezone_status", contract["join"]["candidate_timezone"]["status"]),
                ("decision", contract["join"]["decision"]),
                ("host", json.dumps(host, sort_keys=True, separators=(",", ":"))),
            ],
        )
        elapsed = time.monotonic() - started
        metrics = {"database_created": True, "indexes_created_empty": 5}
        record_stage(connection, stage, elapsed, metrics)
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.commit()
    except Exception:
        connection.close()
        temporary.unlink(missing_ok=True)
        temporary.with_name(temporary.name + "-wal").unlink(missing_ok=True)
        temporary.with_name(temporary.name + "-shm").unlink(missing_ok=True)
        raise
    connection.close()
    if database.exists():
        temporary.unlink(missing_ok=True)
        raise ValueError(f"work database appeared concurrently: {database}")
    os.replace(temporary, database)
    emit(
        stage=stage.key,
        status="passed",
        completed_units=1,
        total_units=stage.total,
        elapsed_seconds=round(elapsed, 3),
        artifact_path=str(database),
        metrics=metrics,
    )
    return metrics


def record_stage(
    connection: sqlite3.Connection,
    stage: Stage,
    elapsed: float,
    metrics: Mapping[str, Any],
) -> None:
    connection.execute(
        "INSERT INTO pipeline_stage VALUES(?,?,?,?,?,?,?,?)",
        (
            stage.key,
            stage.ordinal,
            stage.kind,
            stage.capture_id,
            stage.tolerance_seconds,
            core.utc_now(),
            round(elapsed, 3),
            json.dumps(metrics, sort_keys=True, separators=(",", ":")),
        ),
    )


def completed_stages(
    connection: sqlite3.Connection, plan: Sequence[Stage]
) -> list[tuple[str, str, float]]:
    rows = connection.execute(
        "SELECT stage_key,kind,elapsed_seconds FROM pipeline_stage ORDER BY ordinal"
    ).fetchall()
    keys = [row[0] for row in rows]
    if keys != [stage.key for stage in plan[: len(keys)]]:
        raise ValueError("pipeline checkpoints are not a strict stage prefix")
    return [(str(row[0]), str(row[1]), float(row[2])) for row in rows]


def open_work_database(
    root: Path, contract: Mapping[str, Any]
) -> sqlite3.Connection:
    _, database = work_paths(root, contract)
    if not database.is_file():
        raise ValueError(f"work database is missing: {database}")
    connection = sqlite3.connect(database, timeout=30)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    metadata = dict(connection.execute("SELECT key,value FROM metadata"))
    if (
        connection.execute("PRAGMA application_id").fetchone()[0]
        != contract["sqlite"]["application_id"]
        or connection.execute("PRAGMA user_version").fetchone()[0]
        != contract["sqlite"]["user_version"]
        or metadata.get("schema_version") != SCHEMA_VERSION
        or metadata.get("task") != TASK
        or metadata.get("kind") != KIND
        or metadata.get("join_contract_sha256") != join_contract_sha256(contract)
        or metadata.get("producer_sha256") != core.sha256_path(Path(__file__))
    ):
        connection.close()
        raise ValueError("Windows join work database contract mismatch")
    completed_stages(connection, stage_plan(contract))
    return connection


class Heartbeat:
    def __init__(
        self,
        stage: Stage,
        completed: int,
        artifact: Path,
        interval_seconds: int,
        started: float,
    ) -> None:
        self.stage = stage
        self.completed = completed
        self.artifact = artifact
        self.interval_seconds = interval_seconds
        self.started = started
        self.last = started

    def __call__(self) -> int:
        now = time.monotonic()
        if now - self.last >= self.interval_seconds:
            emit(
                stage=self.stage.key,
                status="running",
                completed_units=self.completed,
                total_units=self.stage.total,
                elapsed_seconds=round(now - self.started, 1),
                artifact_path=str(self.artifact),
                heartbeat=True,
            )
            self.last = now
        return 0


def transaction_stage(
    connection: sqlite3.Connection,
    contract: Mapping[str, Any],
    stage: Stage,
    operation: Callable[[], dict[str, Any]],
    artifact: Path,
) -> dict[str, Any]:
    plan = stage_plan(contract)
    started = time.monotonic()
    connection.execute("BEGIN IMMEDIATE")
    try:
        completed = completed_stages(connection, plan)
        if len(completed) >= len(plan) or plan[len(completed)].key != stage.key:
            raise ValueError(f"stage is not next: {stage.key}")
        emit(
            stage=stage.key,
            status="running",
            completed_units=len(completed),
            total_units=stage.total,
            elapsed_seconds=0.0,
            artifact_path=str(artifact),
        )
        heartbeat = Heartbeat(
            stage,
            len(completed),
            artifact,
            windows_join_spec(contract)["heartbeat_seconds"],
            started,
        )
        connection.set_progress_handler(heartbeat, 100_000)
        metrics = operation()
        elapsed = time.monotonic() - started
        record_stage(connection, stage, elapsed, metrics)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.set_progress_handler(None, 0)
    emit(
        stage=stage.key,
        status="passed",
        completed_units=stage.ordinal,
        total_units=stage.total,
        elapsed_seconds=round(elapsed, 3),
        artifact_path=str(artifact),
        metrics=metrics,
    )
    return metrics


def capture_by_id(
    contract: Mapping[str, Any], capture_id: str
) -> Mapping[str, Any]:
    return next(capture for capture in contract["captures"] if capture["id"] == capture_id)


def run_flow_stage(
    connection: sqlite3.Connection,
    root: Path,
    contract: Mapping[str, Any],
    stage: Stage,
    database: Path,
) -> dict[str, Any]:
    assert stage.capture_id is not None
    capture_id = stage.capture_id
    receipt = shards.validate_checkpoint(root, contract, capture_id)
    _, shard_database, receipt_path = shards.checkpoint_paths(root, contract, capture_id)
    connection.execute("ATTACH DATABASE ? AS flow_shard", (str(shard_database),))
    try:
        def operation() -> dict[str, Any]:
            if connection.execute(
                "SELECT COUNT(*) FROM flow WHERE capture_id=?", (capture_id,)
            ).fetchone()[0]:
                raise ValueError(f"flow capture already imported: {capture_id}")
            offset = connection.execute("SELECT COALESCE(MAX(flow_id),0) FROM flow").fetchone()[0]
            connection.execute("""
                INSERT INTO flow
                SELECT ?+flow_ordinal,capture_id,flow_ordinal,protocol,low_ip,low_port,
                       high_ip,high_port,forward_source_ip,forward_source_port,generation,
                       creation_timestamp_ns,last_capture_timestamp_ns,last_event_timestamp_ns,
                       packet_count,forward_packet_count,reverse_packet_count,close_reason
                FROM flow_shard.flow ORDER BY flow_ordinal
            """, (offset,))
            connection.execute(
                "INSERT INTO exporter_summary SELECT * FROM flow_shard.exporter_summary"
            )
            source = receipt["source"]
            connection.execute(
                "INSERT INTO input_file(capture_id,kind,path,size_bytes,sha256) VALUES(?,?,?,?,?)",
                (capture_id, "pcap", source["path"], source["size_bytes"], source["sha256"]),
            )
            imported = connection.execute(
                "SELECT COUNT(*) FROM flow WHERE capture_id=?", (capture_id,)
            ).fetchone()[0]
            if imported != receipt["summary"]["exported_flows"]:
                raise ValueError(f"flow shard import count mismatch: {capture_id}")
            return {
                "capture_id": capture_id,
                "flows_imported": imported,
                "shard_receipt_sha256": core.sha256_path(receipt_path),
                "shard_database_sha256": receipt["sqlite"]["sha256"],
            }

        return transaction_stage(connection, contract, stage, operation, database)
    finally:
        connection.execute("DETACH DATABASE flow_shard")


def validate_csv_sources(
    root: Path, capture: Mapping[str, Any], stage: Stage, database: Path
) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for index, spec in enumerate(capture["csv"], start=1):
        path = core.resolve_path(root, spec["path"])
        emit(
            stage=stage.key,
            status="hashing_source",
            completed_units=index - 1,
            total_units=len(capture["csv"]),
            elapsed_seconds=0.0,
            artifact_path=str(database),
            source_path=spec["path"],
        )
        before = path.stat()
        digest = core.sha256_path(path)
        after = path.stat()
        if (
            before.st_size != spec["size_bytes"]
            or digest != spec["sha256"]
            or (before.st_size, before.st_mtime_ns)
            != (after.st_size, after.st_mtime_ns)
        ):
            raise ValueError(f"CSV source identity mismatch: {spec['path']}")
        identities.append(
            {"path": spec["path"], "size_bytes": after.st_size, "sha256": digest}
        )
    return identities


def build_capture_label_database(
    root: Path,
    contract: Mapping[str, Any],
    capture: Mapping[str, Any],
    temporary: Path,
) -> dict[str, Any]:
    subset = copy.deepcopy(contract)
    subset["captures"] = [copy.deepcopy(capture)]
    connection = sqlite3.connect(temporary)
    try:
        core.create_schema(connection, subset)
        totals = core.ingest_labels(
            connection, root, subset, core.validate_timezone(contract)
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.commit()
    finally:
        connection.close()
    core.check_database(temporary)
    return totals


def run_label_stage(
    connection: sqlite3.Connection,
    root: Path,
    contract: Mapping[str, Any],
    stage: Stage,
    database: Path,
) -> dict[str, Any]:
    assert stage.capture_id is not None
    capture_id = stage.capture_id
    capture = capture_by_id(contract, capture_id)
    identities = validate_csv_sources(root, capture, stage, database)
    directory = database.parent / f".nids-t33-labels-{capture_id}-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        temporary = directory / "labels.sqlite3"
        totals = build_capture_label_database(root, contract, capture, temporary)
        connection.execute("ATTACH DATABASE ? AS label_stage", (str(temporary),))
        try:
            def operation() -> dict[str, Any]:
                if connection.execute(
                    "SELECT COUNT(*) FROM label_row WHERE capture_id=?", (capture_id,)
                ).fetchone()[0]:
                    raise ValueError(f"label capture already imported: {capture_id}")
                label_offset = connection.execute(
                    "SELECT COALESCE(MAX(label_id),0) FROM label_row"
                ).fetchone()[0]
                quarantine_offset = connection.execute(
                    "SELECT COALESCE(MAX(quarantine_id),0) FROM quarantined_label_row"
                ).fetchone()[0]
                connection.execute("""
                    INSERT INTO label_row
                    SELECT ?+label_id,capture_id,csv_path,csv_line,flow_id_text,
                           source_ip,source_port,destination_ip,destination_port,protocol,
                           low_ip,low_port,high_ip,high_port,timestamp_text,duration_us,
                           forward_packet_count,backward_packet_count,label
                    FROM label_stage.label_row ORDER BY label_id
                """, (label_offset,))
                connection.execute("""
                    INSERT INTO label_time_variant
                    SELECT ?+label_id,variant,start_min_ns,start_max_ns,end_min_ns,end_max_ns,
                           schedule_conflict,role_conflict,event_ids_json
                    FROM label_stage.label_time_variant ORDER BY label_id,variant
                """, (label_offset,))
                connection.execute("""
                    INSERT INTO quarantined_label_row
                    SELECT ?+quarantine_id,capture_id,csv_path,csv_line,flow_id_text,
                           source_ip,source_port,destination_ip,destination_port,protocol,
                           low_ip,low_port,high_ip,high_port,timestamp_text,duration_us,
                           forward_packet_count,backward_packet_count,label,reason
                    FROM label_stage.quarantined_label_row ORDER BY quarantine_id
                """, (quarantine_offset,))
                connection.executemany(
                    "INSERT INTO input_file(capture_id,kind,path,size_bytes,sha256) VALUES(?,?,?,?,?)",
                    [
                        (capture_id, "csv", item["path"], item["size_bytes"], item["sha256"])
                        for item in identities
                    ],
                )
                eligible = connection.execute(
                    "SELECT COUNT(*) FROM label_row WHERE capture_id=?", (capture_id,)
                ).fetchone()[0]
                quarantined = connection.execute(
                    "SELECT COUNT(*) FROM quarantined_label_row WHERE capture_id=?",
                    (capture_id,),
                ).fetchone()[0]
                if (
                    eligible != totals["eligible_records"]
                    or quarantined != totals["quarantined_records"]
                ):
                    raise ValueError(f"label import count mismatch: {capture_id}")
                return {
                    "capture_id": capture_id,
                    "csv_files": len(identities),
                    "eligible_records": eligible,
                    "quarantined_records": quarantined,
                    "timestamp_variants": totals["timestamp_variants"],
                }

            return transaction_stage(connection, contract, stage, operation, database)
        finally:
            connection.execute("DETACH DATABASE label_stage")
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def run_edge_stage(
    connection: sqlite3.Connection,
    contract: Mapping[str, Any],
    stage: Stage,
    database: Path,
) -> dict[str, Any]:
    assert stage.capture_id is not None
    capture_id = stage.capture_id
    maximum = contract["join"]["maximum_candidate_tolerance_seconds"] * 1_000_000_000

    def operation() -> dict[str, Any]:
        existing = connection.execute("""
            SELECT COUNT(*) FROM candidate_edge e
            JOIN flow f ON f.flow_id=e.flow_id WHERE f.capture_id=?
        """, (capture_id,)).fetchone()[0]
        if existing:
            raise ValueError(f"candidate edges already exist: {capture_id}")
        connection.execute("""
            INSERT INTO candidate_edge
            SELECT f.flow_id,l.label_id,v.variant,
                   CASE
                       WHEN f.last_event_timestamp_ns<v.start_min_ns
                           THEN v.start_min_ns-f.last_event_timestamp_ns
                       WHEN v.end_max_ns<=f.creation_timestamp_ns
                           THEN f.creation_timestamp_ns-v.end_max_ns+1
                       ELSE 0
                   END,
                   v.schedule_conflict,v.role_conflict
            FROM flow AS f
            JOIN label_row AS l
              ON l.capture_id=f.capture_id AND l.protocol=f.protocol
             AND l.low_ip=f.low_ip AND l.low_port=f.low_port
             AND l.high_ip=f.high_ip AND l.high_port=f.high_port
            JOIN label_time_variant AS v ON v.label_id=l.label_id
            WHERE f.capture_id=?
              AND f.last_event_timestamp_ns+?>=v.start_min_ns
              AND v.end_max_ns+?>f.creation_timestamp_ns
        """, (capture_id, maximum, maximum))
        edges = connection.execute("SELECT changes()").fetchone()[0]
        return {
            "capture_id": capture_id,
            "candidate_edges": edges,
            "flows": connection.execute(
                "SELECT COUNT(*) FROM flow WHERE capture_id=?", (capture_id,)
            ).fetchone()[0],
            "labels": connection.execute(
                "SELECT COUNT(*) FROM label_row WHERE capture_id=?", (capture_id,)
            ).fetchone()[0],
        }

    return transaction_stage(connection, contract, stage, operation, database)


def run_sweep_stage(
    connection: sqlite3.Connection,
    contract: Mapping[str, Any],
    stage: Stage,
    database: Path,
) -> dict[str, Any]:
    assert stage.tolerance_seconds is not None
    seconds = stage.tolerance_seconds

    def operation() -> dict[str, Any]:
        if connection.execute(
            "SELECT COUNT(*) FROM sweep_summary WHERE tolerance_seconds=?", (seconds,)
        ).fetchone()[0]:
            raise ValueError(f"sweep already exists: {seconds}")
        row = verifier.recompute_sweep(connection, seconds)
        if row["flow_total"] != (
            row["matched_count"]
            + row["flow_unmatched"]
            + row["flow_ambiguous"]
            + row["flow_audit_conflict"]
        ) or row["label_total"] != (
            row["matched_count"]
            + row["label_unmatched"]
            + row["label_ambiguous"]
            + row["label_audit_conflict"]
        ):
            raise ValueError(f"sweep accounting failed: {seconds}")
        connection.execute(
            "INSERT INTO sweep_summary VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                row["tolerance_seconds"],
                row["raw_edge_count"],
                row["eligible_edge_count"],
                row["matched_count"],
                row["flow_total"],
                row["flow_unmatched"],
                row["flow_ambiguous"],
                row["flow_audit_conflict"],
                row["label_total"],
                row["label_unmatched"],
                row["label_ambiguous"],
                row["label_audit_conflict"],
            ),
        )
        return row

    return transaction_stage(connection, contract, stage, operation, database)


def run_one_stage(
    root: Path,
    contract_path: Path,
    contract: Mapping[str, Any],
    enforce_environment: bool,
) -> bool:
    plan = stage_plan(contract)
    _, database = work_paths(root, contract)
    if not database.exists():
        create_work_database(root, contract_path, contract, enforce_environment)
        return True
    connection = open_work_database(root, contract)
    try:
        completed = completed_stages(connection, plan)
        if len(completed) == len(plan):
            return False
        stage = plan[len(completed)]
        if stage.kind == "flow":
            run_flow_stage(connection, root, contract, stage, database)
        elif stage.kind == "labels":
            run_label_stage(connection, root, contract, stage, database)
        elif stage.kind == "edges":
            run_edge_stage(connection, contract, stage, database)
        elif stage.kind == "sweep":
            run_sweep_stage(connection, contract, stage, database)
        else:
            raise ValueError(f"unsupported stage: {stage.key}")
        return True
    finally:
        connection.close()


def status_document(root: Path, contract: Mapping[str, Any]) -> dict[str, Any]:
    plan = stage_plan(contract)
    _, database = work_paths(root, contract)
    completed: list[tuple[str, str, float]] = []
    if database.exists():
        connection = open_work_database(root, contract)
        try:
            completed = completed_stages(connection, plan)
        finally:
            connection.close()
    durations: dict[str, list[float]] = {}
    for _, kind, elapsed in completed:
        durations.setdefault(kind, []).append(elapsed)
    pending = plan[len(completed) :]
    estimates: list[float] = []
    eta_known = True
    for stage in pending:
        samples = durations.get(stage.kind, [])
        if not samples:
            eta_known = False
            break
        estimates.append(sum(samples) / len(samples))
    shard_ready = sum(
        shards.checkpoint_paths(root, contract, capture["id"])[0].is_dir()
        for capture in contract["captures"]
    )
    return {
        "task": TASK,
        "kind": KIND,
        "status": "ready_for_phase_c" if not pending else "in_progress",
        "completed_units": len(completed),
        "total_units": len(plan),
        "next_stage": pending[0].key if pending else None,
        "eta_seconds": round(sum(estimates), 1) if eta_known else None,
        "flow_shards_ready": shard_ready,
        "flow_shards_total": len(contract["captures"]),
        "artifact_path": str(database),
        "completed_stages": [key for key, _, _ in completed],
    }


def run_pipeline(
    root: Path,
    contract_path: Path,
    max_stages: int,
    enforce_environment: bool = True,
) -> dict[str, Any]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    contract = validate_contract(root, contract_path)
    if max_stages <= 0:
        raise ValueError("max_stages must be positive")
    if enforce_environment:
        require_windows_host(contract)
    for _ in range(max_stages):
        if not run_one_stage(root, contract_path, contract, enforce_environment):
            break
    status = status_document(root, contract)
    emit(**status)
    return status


def command_status(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract = validate_contract(root, args.contract.resolve())
    if args.enforce_host:
        require_windows_host(contract)
    emit(**status_document(root, contract))
    return 0


def command_run(args: argparse.Namespace) -> int:
    run_pipeline(args.project_root, args.contract, args.max_stages)
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "run"):
        command = subparsers.add_parser(name)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument(
            "--contract",
            type=Path,
            default=root / "config" / "cicids2017-label-join-contract.json",
        )
        if name == "status":
            command.add_argument("--enforce-host", action="store_true")
            command.set_defaults(handler=command_status)
        else:
            command.add_argument("--max-stages", type=int, default=1)
            command.set_defaults(handler=command_run)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
