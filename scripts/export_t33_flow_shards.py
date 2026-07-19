#!/usr/bin/env python3
"""Export restartable, content-addressed T3.3 flow shards one capture at a time."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("build_t33_label_join")


SCHEMA_VERSION = "1.0.0"
TASK = "T3.3"
KIND = "flow_shard_checkpoint"
BATCH_SIZE = 10_000
SUMMARY_FIELDS = (
    "records_read", "packets_parsed", "parser_errors", "packets_accepted",
    "ingest_errors", "exported_flows", "flows_closed",
)


def progress(message: str) -> None:
    print(f"[T3.3 flow-shard] {message}", flush=True)


def stable_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def pipeline_spec(contract: Mapping[str, Any]) -> Mapping[str, Any]:
    spec = contract.get("execution_pipeline")
    if not isinstance(spec, Mapping):
        raise ValueError("contract execution_pipeline is missing")
    shards = spec.get("flow_shards")
    if (
        spec.get("mode") != "checkpointed_hybrid"
        or spec.get("flow_export_host") != "ubuntu_24_04_vmware"
        or spec.get("portable_join_host") != "windows_native"
        or not isinstance(shards, Mapping)
        or shards.get("database_name") != "flow-shard.sqlite3"
        or shards.get("receipt_name") != "receipt.json"
        or shards.get("application_id") != 1_311_983_187
        or shards.get("user_version") != 1
        or shards.get("page_size") != 4096
        or not isinstance(shards.get("progress_interval_flows"), int)
        or shards["progress_interval_flows"] <= 0
    ):
        raise ValueError("invalid checkpointed hybrid pipeline contract")
    return spec


def capture_spec(contract: Mapping[str, Any], capture_id: str) -> Mapping[str, Any]:
    captures = contract.get("captures")
    if not isinstance(captures, list):
        raise ValueError("contract captures are missing")
    matches = [item for item in captures if item.get("id") == capture_id]
    if len(matches) != 1:
        raise ValueError(f"unknown or duplicate capture id: {capture_id}")
    return matches[0]


def export_contract_record(
    contract: Mapping[str, Any], capture: Mapping[str, Any]
) -> dict[str, Any]:
    exporter = contract["exporter"]
    exclusion = exporter["parser_exclusion_policy"]
    capture_id = capture["id"]
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "capture": {"id": capture_id, "pcap": capture["pcap"]},
        "exporter": {
            "target": exporter["target"],
            "schema_version": exporter["schema_version"],
            "flow_kind": exporter["flow_kind"],
            "summary_kind": exporter["summary_kind"],
            "parser_exclusion_policy": {
                "action": exclusion["action"],
                "accounting": exclusion["accounting"],
                "allowed_categories": exclusion["allowed_categories"],
                "file_receipt": exclusion["evidence"]["file_receipts"][capture_id],
                "expected": exclusion["expected_by_capture"][capture_id],
            },
            "ingest_errors_allowed": exporter["ingest_errors_allowed"],
        },
        "flow_shard": dict(pipeline_spec(contract)["flow_shards"]),
    }


def checkpoint_paths(
    root: Path, contract: Mapping[str, Any], capture_id: str
) -> tuple[Path, Path, Path]:
    shards = pipeline_spec(contract)["flow_shards"]
    checkpoint_root = core.resolve_path(root, shards["directory"])
    capture_root = checkpoint_root / capture_id
    return (
        capture_root,
        capture_root / shards["database_name"],
        capture_root / shards["receipt_name"],
    )


def validate_capture_evidence(
    root: Path, contract: Mapping[str, Any], capture: Mapping[str, Any]
) -> dict[str, Any]:
    capture_id = capture["id"]
    pcap_spec = capture["pcap"]
    pcap = core.resolve_path(root, pcap_spec["path"])
    progress(f"capture={capture_id} hashing source size={pcap_spec['size_bytes']}")
    before = pcap.stat()
    digest = core.sha256_path(pcap)
    after = pcap.stat()
    if before.st_size != pcap_spec["size_bytes"] or digest != pcap_spec["sha256"]:
        raise ValueError(f"source identity mismatch: {pcap_spec['path']}")
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"source changed while hashing: {pcap_spec['path']}")

    exclusion = contract["exporter"]["parser_exclusion_policy"]
    receipt_spec = exclusion["evidence"]["file_receipts"][capture_id]
    receipt_path = core.resolve_path(root, receipt_spec["path"])
    if core.sha256_path(receipt_path) != receipt_spec["sha256"]:
        raise ValueError(f"T1.2 file survey hash mismatch: {capture_id}")
    receipt = core.load_json(receipt_path)
    ignored = receipt.get("statistics", {}).get("ignored_packets", {})
    expected = exclusion["expected_by_capture"][capture_id]
    observed = {
        "non_ipv4": ignored.get("non_ipv4"),
        "ipv4_fragmented": ignored.get("ipv4_fragmented"),
        "unsupported_transport": ignored.get("unsupported_transport"),
    }
    if (
        receipt.get("task") != "T1.2"
        or receipt.get("status") != "passed"
        or receipt.get("source", {}).get("name") != pcap.name
        or observed != {key: expected[key] for key in observed}
        or sum(observed.values()) != expected["total"]
    ):
        raise ValueError(f"T1.2 file survey evidence mismatch: {capture_id}")
    return {
        "path": pcap_spec["path"],
        "size_bytes": after.st_size,
        "sha256": digest,
        "survey_receipt": receipt_spec,
    }


def create_database(
    path: Path,
    contract: Mapping[str, Any],
    capture_id: str,
    metadata: Mapping[str, str],
) -> sqlite3.Connection:
    shards = pipeline_spec(contract)["flow_shards"]
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA page_size={shards['page_size']}")
    connection.execute(f"PRAGMA application_id={shards['application_id']}")
    connection.execute(f"PRAGMA user_version={shards['user_version']}")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript("""
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
        CREATE TABLE flow(
            flow_ordinal INTEGER PRIMARY KEY, capture_id TEXT NOT NULL,
            protocol INTEGER NOT NULL, low_ip INTEGER NOT NULL, low_port INTEGER NOT NULL,
            high_ip INTEGER NOT NULL, high_port INTEGER NOT NULL,
            forward_source_ip INTEGER NOT NULL, forward_source_port INTEGER NOT NULL,
            generation INTEGER NOT NULL, creation_timestamp_ns INTEGER NOT NULL,
            last_capture_timestamp_ns INTEGER NOT NULL, last_event_timestamp_ns INTEGER NOT NULL,
            packet_count INTEGER NOT NULL, forward_packet_count INTEGER NOT NULL,
            reverse_packet_count INTEGER NOT NULL, close_reason TEXT NOT NULL
        ) STRICT;
        CREATE TABLE exporter_summary(
            capture_id TEXT PRIMARY KEY, records_read INTEGER NOT NULL,
            packets_parsed INTEGER NOT NULL, parser_errors INTEGER NOT NULL,
            packets_accepted INTEGER NOT NULL, ingest_errors INTEGER NOT NULL,
            exported_flows INTEGER NOT NULL, flows_closed INTEGER NOT NULL
        ) STRICT;
    """)
    connection.executemany("INSERT INTO metadata VALUES(?,?)", metadata.items())
    connection.execute(
        "INSERT INTO metadata VALUES('capture_id',?)", (capture_id,)
    )
    connection.commit()
    return connection


def consume_exporter(
    connection: sqlite3.Connection,
    exporter: Path,
    pcap: Path,
    capture_id: str,
    expected_exclusions: int,
    stderr_path: Path,
    progress_interval: int,
) -> dict[str, int]:
    stderr_output = stderr_path.open("w", encoding="utf-8", newline="\n")
    try:
        process = subprocess.Popen(
            core.exporter_command(exporter, pcap, capture_id),
            cwd=pcap.parents[1],
            stdout=subprocess.PIPE,
            stderr=stderr_output,
            text=True,
            encoding="utf-8",
            errors="strict",
            bufsize=1,
        )
    except Exception:
        stderr_output.close()
        raise
    assert process.stdout is not None
    started = time.monotonic()
    batch: list[tuple[Any, ...]] = []
    flow_count = 0
    summary: dict[str, Any] | None = None
    try:
        for line_number, line in enumerate(process.stdout, start=1):
            if len(line) > 1024 * 1024:
                raise ValueError("exporter JSON line exceeds 1 MiB")
            value = core.parse_json_line(line, f"{capture_id}:{line_number}")
            if value.get("kind") == "summary":
                if summary is not None:
                    raise ValueError("exporter emitted more than one summary")
                summary = value
                continue
            if summary is not None:
                raise ValueError("exporter emitted flow after summary")
            try:
                fields = core.validate_flow(value, capture_id)
            except ValueError as error:
                raise ValueError(
                    f"invalid exporter flow at {capture_id}:{line_number}: {error}"
                ) from error
            flow_count += 1
            batch.append((flow_count, capture_id, *fields))
            if len(batch) >= BATCH_SIZE:
                connection.executemany(
                    "INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch
                )
                connection.commit()
                batch.clear()
            if flow_count % progress_interval == 0:
                elapsed = max(time.monotonic() - started, 0.001)
                progress(
                    f"capture={capture_id} flows={flow_count} "
                    f"elapsed={elapsed:.1f}s rate={flow_count / elapsed:.0f}/s"
                )
        return_code = process.wait()
    except Exception:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        process.stdout.close()
        stderr_output.close()
    if batch:
        connection.executemany(
            "INSERT INTO flow VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch
        )
        connection.commit()
    error_text = stderr_path.read_text(encoding="utf-8")
    if return_code != 0:
        raise ValueError(
            f"exporter failed for {capture_id} rc={return_code}: {error_text[-2000:]}"
        )
    if summary is None:
        raise ValueError(f"exporter omitted summary for {capture_id}")
    counters = core.validate_summary(
        summary, capture_id, flow_count, pcap, expected_exclusions
    )
    connection.execute(
        "INSERT INTO exporter_summary VALUES(?,?,?,?,?,?,?,?)",
        (capture_id, *counters.values()),
    )
    connection.commit()
    return counters


def finalize_database(path: Path, connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA optimize")
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.commit()
    connection.close()
    core.check_database(path)
    if path.with_name(path.name + "-wal").exists() or path.with_name(
        path.name + "-shm"
    ).exists():
        raise ValueError("flow shard WAL/SHM remained after clean close")


def validate_checkpoint(
    root: Path,
    contract: Mapping[str, Any],
    capture_id: str,
    exporter: Path | None = None,
    rehash_source: bool = False,
) -> dict[str, Any]:
    capture = capture_spec(contract, capture_id)
    capture_root, database, receipt_path = checkpoint_paths(root, contract, capture_id)
    if not capture_root.is_dir() or not database.is_file() or not receipt_path.is_file():
        raise ValueError(f"checkpoint is incomplete: {capture_id}")
    receipt = core.load_json(receipt_path)
    expected_export_contract = stable_sha256(export_contract_record(contract, capture))
    producer = receipt.get("producer")
    sqlite_record = receipt.get("sqlite")
    source = receipt.get("source")
    exporter_record = receipt.get("exporter")
    expected_summary = receipt.get("summary")
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("task") != TASK
        or receipt.get("kind") != KIND
        or receipt.get("status") != "passed"
        or receipt.get("capture_id") != capture_id
        or receipt.get("export_contract_sha256") != expected_export_contract
        or not isinstance(producer, Mapping)
        or producer.get("sha256") != core.sha256_path(Path(__file__))
        or not isinstance(sqlite_record, Mapping)
        or sqlite_record.get("sha256") != core.sha256_path(database)
        or sqlite_record.get("size_bytes") != database.stat().st_size
        or not isinstance(source, Mapping)
        or source.get("path") != capture["pcap"]["path"]
        or source.get("size_bytes") != capture["pcap"]["size_bytes"]
        or source.get("sha256") != capture["pcap"]["sha256"]
        or not isinstance(exporter_record, Mapping)
        or not isinstance(expected_summary, Mapping)
        or set(expected_summary) != set(SUMMARY_FIELDS)
    ):
        raise ValueError(f"checkpoint receipt mismatch: {capture_id}")
    if exporter is not None and exporter_record.get("sha256") != core.sha256_path(
        exporter
    ):
        raise ValueError(f"checkpoint exporter mismatch: {capture_id}")
    if rehash_source:
        pcap = core.resolve_path(root, capture["pcap"]["path"])
        if core.sha256_path(pcap) != capture["pcap"]["sha256"]:
            raise ValueError(f"checkpoint source drift: {capture_id}")

    uri = f"file:{database.as_posix()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        shards = pipeline_spec(contract)["flow_shards"]
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        flow_count = connection.execute("SELECT COUNT(*) FROM flow").fetchone()[0]
        summary_row = connection.execute(
            "SELECT records_read,packets_parsed,parser_errors,packets_accepted,"
            "ingest_errors,exported_flows,flows_closed FROM exporter_summary "
            "WHERE capture_id=?", (capture_id,)
        ).fetchone()
        if (
            integrity != [("ok",)]
            or connection.execute("PRAGMA application_id").fetchone()[0]
            != shards["application_id"]
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != shards["user_version"]
            or metadata.get("capture_id") != capture_id
            or metadata.get("export_contract_sha256") != expected_export_contract
            or flow_count != expected_summary.get("exported_flows")
            or summary_row != tuple(expected_summary[field] for field in SUMMARY_FIELDS)
        ):
            raise ValueError(f"checkpoint database mismatch: {capture_id}")
    finally:
        connection.close()
    return receipt


def export_capture(
    root: Path,
    contract_path: Path,
    exporter: Path,
    scratch_root: Path,
    capture_id: str,
    enforce_environment: bool = True,
) -> tuple[dict[str, Any], bool]:
    root = root.resolve()
    contract_path = contract_path.resolve()
    exporter = exporter.resolve()
    contract = core.load_json(contract_path)
    errors = core.validate_contract(contract)
    if errors:
        raise ValueError(f"invalid T3.3 contract: {errors}")
    pipeline_spec(contract)
    if contract_path != root / "config" / "cicids2017-label-join-contract.json":
        raise ValueError("contract must be the project T3.3 contract")
    if not exporter.is_file():
        raise ValueError(f"exporter does not exist: {exporter}")
    capture = capture_spec(contract, capture_id)
    capture_root, _, _ = checkpoint_paths(root, contract, capture_id)
    if capture_root.exists():
        receipt = validate_checkpoint(root, contract, capture_id, exporter)
        progress(f"capture={capture_id} status=skipped checkpoint=valid")
        return receipt, True
    if enforce_environment:
        core.require_supported_host(core.inspect_host())
        core.require_local_scratch(
            scratch_root, root, checkpoint_paths(root, contract, capture_id)[0].parent
        )

    started = time.monotonic()
    source = validate_capture_evidence(root, contract, capture)
    pcap = core.resolve_path(root, capture["pcap"]["path"])
    export_contract_sha256 = stable_sha256(export_contract_record(contract, capture))
    contract_sha256 = core.sha256_path(contract_path)
    exporter_sha256 = core.sha256_path(exporter)
    producer_sha256 = core.sha256_path(Path(__file__))
    progress(f"capture={capture_id} status=running")
    with core.scratch_directory(scratch_root) as scratch:
        local_database = scratch / "flow-shard.sqlite3"
        stderr_path = scratch / "exporter.stderr"
        connection = create_database(
            local_database,
            contract,
            capture_id,
            {
                "schema_version": SCHEMA_VERSION,
                "task": TASK,
                "export_contract_sha256": export_contract_sha256,
                "exporter_sha256": exporter_sha256,
                "source_sha256": source["sha256"],
                "producer_sha256": producer_sha256,
            },
        )
        try:
            counters = consume_exporter(
                connection,
                exporter,
                pcap,
                capture_id,
                contract["exporter"]["parser_exclusion_policy"][
                    "expected_by_capture"
                ][capture_id]["total"],
                stderr_path,
                pipeline_spec(contract)["flow_shards"]["progress_interval_flows"],
            )
            finalize_database(local_database, connection)
        except Exception:
            connection.close()
            raise

        checkpoint_root = capture_root.parent
        checkpoint_root.mkdir(parents=True, exist_ok=True)
        staging = checkpoint_root / f".{capture_id}.{uuid.uuid4().hex}.tmp"
        staging.mkdir()
        try:
            database_name = pipeline_spec(contract)["flow_shards"]["database_name"]
            receipt_name = pipeline_spec(contract)["flow_shards"]["receipt_name"]
            staged_database = staging / database_name
            core.copy_atomic(local_database, staged_database)
            elapsed = time.monotonic() - started
            receipt = {
                "schema_version": SCHEMA_VERSION,
                "task": TASK,
                "kind": KIND,
                "status": "passed",
                "capture_id": capture_id,
                "generated_at_utc": core.utc_now(),
                "elapsed_seconds": round(elapsed, 3),
                "host": core.inspect_host(),
                "producer": {
                    "path": "scripts/export_t33_flow_shards.py",
                    "sha256": producer_sha256,
                },
                "task_contract": {
                    "path": "config/cicids2017-label-join-contract.json",
                    "sha256": contract_sha256,
                },
                "export_contract_sha256": export_contract_sha256,
                "exporter": {"path": str(exporter), "sha256": exporter_sha256},
                "source": source,
                "summary": counters,
                "sqlite": {
                    "path": (
                        Path(pipeline_spec(contract)["flow_shards"]["directory"])
                        / capture_id
                        / database_name
                    ).as_posix(),
                    "size_bytes": staged_database.stat().st_size,
                    "sha256": core.sha256_path(staged_database),
                    "integrity_check": "ok",
                    "journal_mode": "delete",
                },
                "checks": [
                    {"name": "source.content_addressed", "status": "passed"},
                    {"name": "parser_exclusions.exact", "status": "passed"},
                    {"name": "ingest_errors.zero", "status": "passed"},
                    {"name": "flow_shard.integrity", "status": "passed"},
                ],
            }
            core.write_json_atomic(staging / receipt_name, receipt)
            os.replace(staging, capture_root)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    progress(
        f"capture={capture_id} status=passed flows={counters['exported_flows']} "
        f"elapsed={receipt['elapsed_seconds']:.1f}s checkpoint={capture_root}"
    )
    return receipt, False


def command_list(args: argparse.Namespace) -> int:
    contract = core.load_json(args.contract.resolve())
    pipeline_spec(contract)
    for capture in contract["captures"]:
        print(capture["id"])
    return 0


def command_export(args: argparse.Namespace) -> int:
    export_capture(
        args.project_root,
        args.contract,
        args.exporter,
        args.scratch_root,
        args.capture_id,
    )
    return 0


def command_status(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    contract = core.load_json(args.contract.resolve())
    pipeline_spec(contract)
    complete = 0
    invalid = 0
    for index, capture in enumerate(contract["captures"], start=1):
        capture_id = capture["id"]
        capture_root, _, _ = checkpoint_paths(root, contract, capture_id)
        if not capture_root.exists():
            progress(
                f"status {index}/{len(contract['captures'])} capture={capture_id} missing"
            )
            continue
        try:
            receipt = validate_checkpoint(
                root,
                contract,
                capture_id,
                args.exporter,
                rehash_source=args.rehash_sources,
            )
        except (OSError, ValueError, sqlite3.Error) as error:
            invalid += 1
            progress(
                f"status {index}/{len(contract['captures'])} capture={capture_id} "
                f"invalid={error}"
            )
            continue
        complete += 1
        progress(
            f"status {index}/{len(contract['captures'])} capture={capture_id} "
            f"passed flows={receipt['summary']['exported_flows']} "
            f"elapsed={receipt['elapsed_seconds']:.1f}s"
        )
    progress(
        f"completed={complete}/{len(contract['captures'])} invalid={invalid}"
    )
    return 0 if complete == len(contract["captures"]) and invalid == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("list", "export", "status"):
        command = subparsers.add_parser(name)
        command.add_argument("--project-root", type=Path, default=root)
        command.add_argument(
            "--contract",
            type=Path,
            default=root / "config" / "cicids2017-label-join-contract.json",
        )
        if name == "list":
            command.set_defaults(handler=command_list)
        elif name == "export":
            command.add_argument("--capture-id", required=True)
            command.add_argument("--exporter", type=Path, required=True)
            command.add_argument("--scratch-root", type=Path, default=Path("/tmp"))
            command.set_defaults(handler=command_export)
        else:
            command.add_argument("--exporter", type=Path)
            command.add_argument("--rehash-sources", action="store_true")
            command.set_defaults(handler=command_status)
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
