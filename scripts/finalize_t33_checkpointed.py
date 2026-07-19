#!/usr/bin/env python3
"""Finalize and independently verify the checkpointed T3.3 join artifact."""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import os
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("build_t33_label_join")
shards = importlib.import_module("export_t33_flow_shards")
join_pipeline = importlib.import_module("run_t33_join_windows")
verifier = importlib.import_module("verify_t33_label_join")


SCHEMA_VERSION = "1.0.0"
TASK = "T3.3"
TOTAL_STAGES = 6


def emit(stage: str, status: str, completed: int, artifact: Path, started: float) -> None:
    print(
        "[T3.3 finalize] "
        + json.dumps(
            {
                "stage": stage,
                "status": status,
                "completed_units": completed,
                "total_units": TOTAL_STAGES,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "artifact_path": str(artifact),
            },
            separators=(",", ":"),
        ),
        flush=True,
    )


@contextlib.contextmanager
def visible_stage(
    name: str,
    ordinal: int,
    artifact: Path,
    interval_seconds: int,
    pipeline_started: float,
):
    stage_started = time.monotonic()
    emit(name, "running", ordinal - 1, artifact, pipeline_started)
    stopped = threading.Event()

    def heartbeat() -> None:
        while not stopped.wait(interval_seconds):
            emit(name, "running", ordinal - 1, artifact, pipeline_started)

    worker = threading.Thread(target=heartbeat, daemon=True)
    worker.start()
    try:
        yield
    except Exception:
        stopped.set()
        worker.join()
        emit(name, "failed", ordinal - 1, artifact, pipeline_started)
        raise
    else:
        stopped.set()
        worker.join()
        emit(name, "passed", ordinal, artifact, pipeline_started)
        print(
            f"[T3.3 finalize] stage={name} "
            f"stage_elapsed_seconds={time.monotonic() - stage_started:.3f}",
            flush=True,
        )


def artifact_paths(root: Path, contract: Mapping[str, Any]) -> tuple[Path, Path, Path]:
    sqlite_spec = contract["sqlite"]
    return (
        core.resolve_path(root, sqlite_spec["artifact"]),
        core.resolve_path(root, sqlite_spec["build_receipt"]),
        core.resolve_path(root, sqlite_spec["acceptance_receipt"]),
    )


def relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def validate_complete_work(
    root: Path, contract: Mapping[str, Any]
) -> list[dict[str, Any]]:
    plan = join_pipeline.stage_plan(contract)
    with contextlib.closing(
        join_pipeline.open_work_database(root, contract)
    ) as connection:
        completed = join_pipeline.completed_stages(connection, plan)
    if len(completed) != len(plan):
        next_stage = plan[len(completed)].key
        raise ValueError(
            f"Windows join is incomplete: {len(completed)}/{len(plan)}; next={next_stage}"
        )

    receipts = [
        shards.validate_checkpoint(root, contract, capture["id"])
        for capture in contract["captures"]
    ]
    exporter_hashes = {receipt["exporter"]["sha256"] for receipt in receipts}
    if len(exporter_hashes) != 1:
        raise ValueError("flow shards were produced by different exporter binaries")
    return receipts


def snapshot_work_database(
    root: Path, contract: Mapping[str, Any], staging: Path
) -> None:
    with contextlib.closing(
        join_pipeline.open_work_database(root, contract)
    ) as source, contextlib.closing(sqlite3.connect(staging)) as destination:
        source.backup(destination, pages=16384, sleep=0.05)


def finalize_snapshot(
    database: Path,
    contract_sha256: str,
    exporter_sha256: str,
) -> None:
    with contextlib.closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("DROP TABLE pipeline_stage")
        connection.executemany(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
            [
                ("kind", verifier.BUILD_KIND),
                ("contract_sha256", contract_sha256),
                ("exporter_sha256", exporter_sha256),
            ],
        )
        connection.commit()
        connection.execute("PRAGMA optimize")
        journal = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if journal != ("delete",):
            raise ValueError(f"could not finalize SQLite journal mode: {journal}")
        connection.commit()
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite integrity_check failed during finalization")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("SQLite foreign_key_check failed during finalization")
    for suffix in ("-wal", "-shm"):
        if database.with_name(database.name + suffix).exists():
            raise ValueError(f"SQLite sidecar remained after finalization: {suffix}")


def database_rows(database: Path, sql: str) -> list[sqlite3.Row]:
    uri = verifier.database_uri(database)
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(sql).fetchall()


def make_build_receipt(
    root: Path,
    contract_path: Path,
    contract: Mapping[str, Any],
    database: Path,
    shard_receipts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    sources = [
        dict(row)
        for row in database_rows(
            database,
            "SELECT capture_id,kind,path,size_bytes,sha256 "
            "FROM input_file ORDER BY input_id",
        )
    ]
    summaries = [
        dict(row)
        for row in database_rows(
            database, "SELECT * FROM exporter_summary ORDER BY rowid"
        )
    ]
    sweeps = [
        dict(row)
        for row in database_rows(
            database, "SELECT * FROM sweep_summary ORDER BY tolerance_seconds"
        )
    ]
    counts = dict(
        database_rows(
            database,
            "SELECT 'flows',COUNT(*) FROM flow UNION ALL "
            "SELECT 'eligible',COUNT(*) FROM label_row UNION ALL "
            "SELECT 'quarantined',COUNT(*) FROM quarantined_label_row UNION ALL "
            "SELECT 'variants',COUNT(*) FROM label_time_variant UNION ALL "
            "SELECT 'edges',COUNT(*) FROM candidate_edge",
        )
    )
    quarantine_reasons = dict(
        database_rows(
            database,
            "SELECT reason,COUNT(*) FROM quarantined_label_row GROUP BY reason",
        )
    )
    physical = sum(
        spec["physical_record_count"]
        for capture in contract["captures"]
        for spec in capture["csv"]
    )
    empty = sum(
        spec["all_empty_record_count"]
        for capture in contract["captures"]
        for spec in capture["csv"]
    )
    nonempty = sum(
        spec["nonempty_record_count"]
        for capture in contract["captures"]
        for spec in capture["csv"]
    )
    exporter = shard_receipts[0]["exporter"]
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": verifier.BUILD_KIND,
        "status": "passed",
        "generated_at_utc": core.utc_now(),
        "host": join_pipeline.inspect_windows_host(),
        "contract": {
            "path": relative_path(contract_path, root),
            "sha256": core.sha256_path(contract_path),
        },
        "exporter": {
            "path": exporter["path"],
            "sha256": exporter["sha256"],
            "summaries": summaries,
            "flow_shard_receipts": [
                relative_path(
                    shards.checkpoint_paths(root, contract, receipt["capture_id"])[2],
                    root,
                )
                for receipt in shard_receipts
            ],
        },
        "sources": sources,
        "labels": {
            "physical_records": physical,
            "all_empty_records": empty,
            "nonempty_records": nonempty,
            "timestamp_variants": counts["variants"],
            "eligible_records": counts["eligible"],
            "quarantined_records": counts["quarantined"],
            "quarantine_reason_counts": quarantine_reasons,
        },
        "flows": {"total": counts["flows"]},
        "candidate_edges": counts["edges"],
        "sweeps": sweeps,
        "sqlite": {
            "path": contract["sqlite"]["artifact"],
            "size_bytes": database.stat().st_size,
            "sha256": core.sha256_path(database),
            "application_id": contract["sqlite"]["application_id"],
            "user_version": contract["sqlite"]["user_version"],
            "journal_mode": "delete",
            "integrity_check": "ok",
        },
        "checks": [
            {"name": "sources.content_addressed_before_processing", "status": "passed"},
            {"name": "exporter.strict_jsonl_contract", "status": "passed"},
            {"name": "exporter.exact_parser_exclusions_and_zero_ingest_errors", "status": "passed"},
            {"name": "labels.unsupported_protocol_quarantined", "status": "passed"},
            {"name": "labels.invalid_flow_duration_quarantined", "status": "passed"},
            {"name": "join.fail_closed_mutual_uniqueness", "status": "passed"},
            {"name": "join.sweep_accounting", "status": "passed"},
            {"name": "sqlite.local_single_writer_then_copy", "status": "passed"},
            {"name": "sqlite.integrity", "status": "passed"},
        ],
    }


def make_acceptance(
    root: Path,
    contract: Mapping[str, Any],
    contract_path: Path,
    build_path: Path,
    database: Path,
    build: Mapping[str, Any],
    shard_receipts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    build_sqlite = build["sqlite"]
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": verifier.ACCEPTANCE_KIND,
        "status": "passed",
        "generated_at_utc": core.utc_now(),
        "host": join_pipeline.inspect_windows_host(),
        "producer": {
            "path": "scripts/finalize_t33_checkpointed.py",
            "sha256": core.sha256_path(Path(__file__)),
        },
        "contract": {
            "path": relative_path(contract_path, root),
            "sha256": core.sha256_path(contract_path),
        },
        "build": {
            "path": relative_path(build_path, root),
            "sha256": core.sha256_path(build_path),
        },
        "sqlite": {
            "path": relative_path(database, root),
            "size_bytes": build_sqlite["size_bytes"],
            "sha256": build_sqlite["sha256"],
        },
        "flow_shards": [
            {
                "capture_id": receipt["capture_id"],
                "receipt_sha256": core.sha256_path(
                    shards.checkpoint_paths(root, contract, receipt["capture_id"])[2]
                ),
            }
            for receipt in shard_receipts
        ],
        "source_rehashed_by_bounded_stage": True,
        "independent_graph_recomputed": True,
        "checks": [
            {"name": "build.receipt_independent_validation", "status": "passed"},
            {"name": "sqlite.read_only_integrity_and_schema", "status": "passed"},
            {"name": "sources.content_addressed_by_stage", "status": "passed"},
            {"name": "flow_shards.receipts_and_databases_revalidated", "status": "passed"},
            {"name": "join.graph_and_accounting_recomputed", "status": "passed"},
        ],
    }


def validate_acceptance(
    root: Path,
    contract: Mapping[str, Any],
    contract_path: Path,
    build_path: Path,
    database: Path,
    acceptance: Mapping[str, Any],
    build: Mapping[str, Any],
    shard_receipts: Sequence[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if (
        acceptance.get("schema_version") != SCHEMA_VERSION
        or acceptance.get("task") != TASK
        or acceptance.get("kind") != verifier.ACCEPTANCE_KIND
        or acceptance.get("status") != "passed"
    ):
        errors.append("acceptance schema/task/status mismatch")
    if acceptance.get("contract") != {
        "path": relative_path(contract_path, root),
        "sha256": core.sha256_path(contract_path),
    }:
        errors.append("acceptance contract evidence mismatch")
    if acceptance.get("build") != {
        "path": relative_path(build_path, root),
        "sha256": core.sha256_path(build_path),
    }:
        errors.append("acceptance build evidence mismatch")
    build_sqlite = build.get("sqlite", {})
    expected_sqlite = {
        "path": relative_path(database, root),
        "size_bytes": build_sqlite.get("size_bytes"),
        "sha256": build_sqlite.get("sha256"),
    }
    if acceptance.get("sqlite") != expected_sqlite:
        errors.append("acceptance SQLite evidence mismatch")
    if acceptance.get("producer") != {
        "path": "scripts/finalize_t33_checkpointed.py",
        "sha256": core.sha256_path(Path(__file__)),
    }:
        errors.append("acceptance producer evidence mismatch")
    expected_shards = [
        {
            "capture_id": receipt["capture_id"],
            "receipt_sha256": core.sha256_path(
                shards.checkpoint_paths(root, contract, receipt["capture_id"])[2]
            ),
        }
        for receipt in shard_receipts
    ]
    if acceptance.get("flow_shards") != expected_shards:
        errors.append("acceptance flow-shard evidence mismatch")
    expected_checks = {
        "build.receipt_independent_validation",
        "sqlite.read_only_integrity_and_schema",
        "sources.content_addressed_by_stage",
        "flow_shards.receipts_and_databases_revalidated",
        "join.graph_and_accounting_recomputed",
    }
    checks = acceptance.get("checks")
    if (
        not isinstance(checks, list)
        or len(checks) != len(expected_checks)
        or {
            item.get("name")
            for item in checks
            if isinstance(item, Mapping) and item.get("status") == "passed"
        }
        != expected_checks
    ):
        errors.append("acceptance checks mismatch")
    if (
        acceptance.get("source_rehashed_by_bounded_stage") is not True
        or acceptance.get("independent_graph_recomputed") is not True
    ):
        errors.append("acceptance independent evidence missing")
    return errors


def finalize(
    project_root: Path,
    contract_path: Path,
    enforce_environment: bool = True,
) -> dict[str, Any]:
    root = project_root.resolve()
    contract_path = contract_path.resolve()
    contract = join_pipeline.validate_contract(root, contract_path)
    if enforce_environment:
        join_pipeline.require_windows_host(contract)
    database, build_path, acceptance_path = artifact_paths(root, contract)
    started = time.monotonic()
    interval = contract["execution_pipeline"]["windows_join"]["heartbeat_seconds"]

    if acceptance_path.exists() and (not database.is_file() or not build_path.is_file()):
        raise ValueError("acceptance exists without complete build artifacts")
    if build_path.exists() and not database.is_file():
        raise ValueError("build receipt exists without final SQLite artifact")

    with visible_stage("preflight", 1, database, interval, started):
        shard_receipts = validate_complete_work(root, contract)

    staging: Path | None = None
    if not database.exists():
        database.parent.mkdir(parents=True, exist_ok=True)
        staging = database.parent / f".{database.name}.{uuid.uuid4().hex}.tmp"
        try:
            with visible_stage("snapshot", 2, database, interval, started):
                snapshot_work_database(root, contract, staging)
            with visible_stage("schema-finalize", 3, database, interval, started):
                finalize_snapshot(
                    staging,
                    core.sha256_path(contract_path),
                    shard_receipts[0]["exporter"]["sha256"],
                )
            candidate_database = staging
        except Exception:
            staging.unlink(missing_ok=True)
            staging.with_name(staging.name + "-wal").unlink(missing_ok=True)
            staging.with_name(staging.name + "-shm").unlink(missing_ok=True)
            raise
    else:
        emit("snapshot", "skipped", 2, database, started)
        emit("schema-finalize", "skipped", 3, database, started)
        candidate_database = database

    try:
        with visible_stage("receipt-build", 4, database, interval, started):
            if build_path.exists():
                build = core.load_json(build_path)
            else:
                build = make_build_receipt(
                    root, contract_path, contract, candidate_database, shard_receipts
                )

        with visible_stage("independent-verify", 5, database, interval, started):
            errors = verifier.validate_receipt(
                build,
                contract,
                root,
                candidate_database,
                rehash_sources=False,
                enforce_host=False,
            )
            if errors:
                raise ValueError(f"independent final validation failed: {errors}")

        with visible_stage("publish", 6, database, interval, started):
            if staging is not None:
                if database.exists():
                    raise ValueError(f"final artifact appeared concurrently: {database}")
                os.replace(staging, database)
                staging = None
            if not build_path.exists():
                core.write_json_atomic(build_path, build)
            if acceptance_path.exists():
                acceptance = core.load_json(acceptance_path)
            else:
                acceptance = make_acceptance(
                    root,
                    contract,
                    contract_path,
                    build_path,
                    database,
                    build,
                    shard_receipts,
                )
            acceptance_errors = validate_acceptance(
                root,
                contract,
                contract_path,
                build_path,
                database,
                acceptance,
                build,
                shard_receipts,
            )
            if acceptance_errors:
                raise ValueError(f"acceptance validation failed: {acceptance_errors}")
            if not acceptance_path.exists():
                core.write_json_atomic(acceptance_path, acceptance)
    finally:
        if staging is not None:
            staging.unlink(missing_ok=True)
            staging.with_name(staging.name + "-wal").unlink(missing_ok=True)
            staging.with_name(staging.name + "-shm").unlink(missing_ok=True)
    return acceptance


def command_finalize(args: argparse.Namespace) -> int:
    acceptance = finalize(args.project_root, args.contract)
    print(
        f"final T3.3 acceptance: {acceptance['status']} "
        f"({args.project_root.resolve() / acceptance['sqlite']['path']})"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root)
    parser.add_argument(
        "--contract",
        type=Path,
        default=root / "config" / "cicids2017-label-join-contract.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return command_finalize(args)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
