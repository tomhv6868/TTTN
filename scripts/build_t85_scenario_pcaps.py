#!/usr/bin/env python3
"""Extract one bounded CICIDS2017 diagnostic replay window per attack label."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sqlite3
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from survey_cicids2017_flows import (  # noqa: E402
    canonical_key,
    load_scapy,
    parse_flow_packet,
    timestamp_ns,
)


LABEL_TO_CASE = {
    "Bot": "bot",
    "DDoS": "ddos",
    "DoS GoldenEye": "dos-goldeneye",
    "DoS Hulk": "dos-hulk",
    "DoS Slowhttptest": "dos-slowhttptest",
    "DoS slowloris": "dos-slowloris",
    "FTP-Patator": "ftp-patator",
    "Heartbleed": "heartbleed",
    "Infiltration": "infiltration",
    "PortScan": "portscan",
    "SSH-Patator": "ssh-patator",
    "Web Attack – Brute Force": "web-brute-force",
    "Web Attack – Sql Injection": "web-sql-injection",
    "Web Attack – XSS": "web-xss",
}
METHOD_PRIORITY = {"mutual_unique": 0, "class_consensus": 1}
PCAP_MAGIC = 0xA1B23C4D


@dataclass(frozen=True)
class Selector:
    case_id: str
    label: str
    capture_id: str
    tuple_key: tuple[int, int, int, int, int]
    start_ns: int
    end_ns: int
    semantic_kind: str
    flow_id: int | None
    assignment_method: str | None


@dataclass(frozen=True)
class Packet:
    timestamp_ns: int
    data: bytes
    wire_length: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def open_immutable(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)


def select_f9_rows() -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as error:
        raise RuntimeError("pyarrow is required to select T3.5 F9 rows") from error
    selected: dict[str, dict[str, Any]] = {}
    root = ROOT / "run_log/t3.5/dataset-v1/checkpoint=F9"
    for part in sorted(root.glob("capture_id=*/part-00000.parquet")):
        rows = pq.ParquetFile(part).read(
            columns=[
                "flow_id",
                "capture_id",
                "flow_start_timestamp_ns",
                "checkpoint_timestamp_ns",
                "assigned_class",
                "assignment_method",
            ],
        ).to_pylist()
        for row in rows:
            label = str(row["assigned_class"])
            if label not in LABEL_TO_CASE or label == "Heartbleed":
                continue
            candidate = (
                METHOD_PRIORITY.get(str(row["assignment_method"]), 99),
                int(row["flow_id"]),
            )
            current = selected.get(label)
            if current is None or candidate < (
                METHOD_PRIORITY.get(str(current["assignment_method"]), 99),
                int(current["flow_id"]),
            ):
                selected[label] = row
    missing = sorted(set(LABEL_TO_CASE) - {"Heartbleed"} - set(selected))
    if missing:
        raise ValueError(f"T3.5 has no F9 selector for: {missing}")
    return [selected[label] for label in LABEL_TO_CASE if label != "Heartbleed"]


def flow_selectors(rows: Iterable[dict[str, Any]]) -> list[Selector]:
    database = ROOT / "run_log/t3.3/label-join.sqlite3"
    selectors: list[Selector] = []
    with open_immutable(database) as connection:
        for row in rows:
            flow_id = int(row["flow_id"])
            record = connection.execute(
                """
                SELECT protocol,low_ip,low_port,high_ip,high_port,capture_id
                FROM flow WHERE flow_id=?
                """,
                (flow_id,),
            ).fetchone()
            if record is None:
                raise ValueError(f"missing T3.3 flow_id {flow_id}")
            label = str(row["assigned_class"])
            capture_id = str(row["capture_id"])
            if capture_id != record[5]:
                raise ValueError(f"capture mismatch for flow_id {flow_id}")
            selectors.append(
                Selector(
                    case_id=LABEL_TO_CASE[label],
                    label=label,
                    capture_id=capture_id,
                    tuple_key=tuple(int(value) for value in record[:5]),
                    start_ns=int(row["flow_start_timestamp_ns"]),
                    end_ns=int(row["checkpoint_timestamp_ns"]),
                    semantic_kind="t3.5_f9_prefix",
                    flow_id=flow_id,
                    assignment_method=str(row["assignment_method"]),
                )
            )
    return selectors


def heartbleed_selector() -> Selector:
    database = ROOT / "run_log/t3.3/label-join.sqlite3"
    with open_immutable(database) as connection:
        row = connection.execute(
            """
            SELECT l.capture_id,l.protocol,l.low_ip,l.low_port,l.high_ip,l.high_port,
                   v.start_min_ns,v.end_max_ns,l.csv_line
            FROM label_row l
            JOIN label_time_variant v USING(label_id)
            WHERE l.label='Heartbleed'
              AND v.schedule_conflict=0
              AND v.role_conflict=0
              AND v.event_ids_json<>'[]'
            ORDER BY l.csv_line,v.variant
            LIMIT 1
            """
        ).fetchone()
    if row is None:
        raise ValueError("T3.3 contains no Heartbleed label window")
    return Selector(
        case_id="heartbleed",
        label="Heartbleed",
        capture_id=str(row[0]),
        tuple_key=tuple(int(value) for value in row[1:6]),
        start_ns=int(row[6]),
        end_ns=int(row[7]),
        semantic_kind="raw_label_window_not_f9",
        flow_id=None,
        assignment_method=f"label_csv_line_{int(row[8])}",
    )


def write_pcap(path: Path, packets: Sequence[Packet]) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        for packet in packets:
            seconds, nanoseconds = divmod(packet.timestamp_ns, 1_000_000_000)
            output.write(
                struct.pack(
                    "<IIII",
                    seconds,
                    nanoseconds,
                    len(packet.data),
                    packet.wire_length,
                )
            )
            output.write(packet.data)


def selector_document(selector: Selector) -> dict[str, Any]:
    return {
        "case_id": selector.case_id,
        "label": selector.label,
        "capture_id": selector.capture_id,
        "tuple": list(selector.tuple_key),
        "start_ns": selector.start_ns,
        "end_ns": selector.end_ns,
        "semantic_kind": selector.semantic_kind,
        "flow_id": selector.flow_id,
        "assignment_method": selector.assignment_method,
    }


def selector_hash(selectors: Sequence[Selector]) -> str:
    payload = json.dumps(
        [selector_document(item) for item in selectors],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def scan_capture(
    source: Path,
    selectors: Sequence[Selector],
    progress_packets: int,
) -> tuple[dict[str, list[Packet]], int]:
    _, reader_type = load_scapy()
    targets: dict[tuple[int, int, int, int, int], list[Selector]] = defaultdict(list)
    for selector in selectors:
        targets[selector.tuple_key].append(selector)
    hits: dict[str, list[Packet]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    records = 0
    reader = reader_type(str(source))
    try:
        for raw, metadata in reader:
            records += 1
            current_ns, rounded = timestamp_ns(metadata)
            if rounded:
                raise ValueError("source timestamp is not exactly representable in ns")
            data = bytes(raw)
            parsed, _ = parse_flow_packet(data, current_ns)
            if parsed is not None:
                for selector in targets.get(canonical_key(parsed), ()):
                    if selector.start_ns <= current_ns <= selector.end_ns:
                        counts[selector.case_id] += 1
                        if len(hits[selector.case_id]) < 9:
                            hits[selector.case_id].append(
                                Packet(current_ns, data, int(metadata.wirelen))
                            )
            if progress_packets and records % progress_packets == 0:
                print(f"SCAN {source.name} packets={records}", flush=True)
    finally:
        reader.close()
    for selector in selectors:
        observed = counts[selector.case_id]
        if selector.semantic_kind == "t3.5_f9_prefix" and observed != 9:
            raise ValueError(
                f"{selector.case_id}: expected exactly 9 F9 packets, observed {observed}"
            )
        if selector.semantic_kind != "t3.5_f9_prefix" and observed < 9:
            raise ValueError(
                f"{selector.case_id}: expected at least 9 raw-window packets, observed {observed}"
            )
    return hits, records


def resume_outputs(
    checkpoint: Path,
    expected_selector_hash: str,
    run_root: Path,
) -> list[dict[str, Any]]:
    document = load_json(checkpoint)
    outputs = document.get("outputs")
    if (
        document.get("kind") != "diagnostic_demo_evidence"
        or document.get("formal_acceptance") is not False
        or document.get("status") != "completed"
        or document.get("selector_sha256") != expected_selector_hash
        or not isinstance(outputs, list)
    ):
        raise ValueError(f"invalid or stale capture checkpoint: {checkpoint}")
    for record in outputs:
        if not isinstance(record, dict):
            raise ValueError(f"invalid checkpoint output: {checkpoint}")
        path = (ROOT / str(record.get("path", ""))).resolve()
        path.relative_to(run_root.resolve())
        if (
            not path.is_file()
            or record.get("records") != 9
            or sha256_path(path) != record.get("sha256")
        ):
            raise ValueError(f"checkpoint output content drift: {path}")
    return outputs


def build(run_id: str, progress_packets: int) -> Path:
    if not re_fullmatch_run_id(run_id):
        raise ValueError("invalid run-id")
    run_root = ROOT / "run_log/t8.5/scenarios" / run_id
    if not (run_root / "scenario.json").is_file():
        raise ValueError("initialize the scenario before extracting PCAPs")
    output_root = run_root / "pcap"
    manifest_path = output_root / "manifest.json"
    if manifest_path.exists():
        raise ValueError("refusing to overwrite PCAP manifest")

    snapshot_contract = load_json(ROOT / "config/cicids2017-snapshot-contract.json")
    capture_records = {item["id"]: item["pcap"] for item in snapshot_contract["captures"]}
    selectors = flow_selectors(select_f9_rows()) + [heartbleed_selector()]
    grouped: dict[str, list[Selector]] = defaultdict(list)
    for selector in selectors:
        grouped[selector.capture_id].append(selector)

    outputs: list[dict[str, Any]] = []
    for capture_id in sorted(grouped):
        checkpoint = output_root / f"capture-{capture_id}.json"
        current_selector_hash = selector_hash(grouped[capture_id])
        if checkpoint.exists():
            resumed = resume_outputs(checkpoint, current_selector_hash, run_root)
            outputs.extend(resumed)
            print(f"RESUME {capture_id} outputs={len(resumed)}", flush=True)
            continue
        source_record = capture_records[capture_id]
        source = ROOT / source_record["path"]
        if source.stat().st_size != int(source_record["size_bytes"]):
            raise ValueError(f"source size mismatch: {source}")
        hits, records = scan_capture(source, grouped[capture_id], progress_packets)
        capture_outputs: list[dict[str, Any]] = []
        for selector in grouped[capture_id]:
            path = output_root / "original" / f"{selector.case_id}.pcap"
            write_pcap(path, hits[selector.case_id])
            capture_outputs.append({
                **selector_document(selector),
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": sha256_path(path),
                "records": 9,
                "source": {
                    "path": source_record["path"],
                    "size_bytes": source_record["size_bytes"],
                    "accepted_sha256": source_record["sha256"],
                    "content_validation": "accepted_contract_hash_plus_current_size",
                    "records_scanned": records,
                },
            })
        outputs.extend(capture_outputs)
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        with checkpoint.open("x", encoding="utf-8") as destination:
            json.dump(
                {
                    "kind": "diagnostic_demo_evidence",
                    "formal_acceptance": False,
                    "capture_id": capture_id,
                    "selector_sha256": current_selector_hash,
                    "status": "completed",
                    "outputs": capture_outputs,
                },
                destination,
                indent=2,
            )
            destination.write("\n")

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("x", encoding="utf-8") as destination:
        json.dump(
            {
                "schema_version": "1.0.0",
                "kind": "diagnostic_demo_evidence",
                "mode": "demo_critical_path",
                "formal_acceptance": False,
                "roadmap_mutated": False,
                "status": "completed",
                "run_id": run_id,
                "generated_at_utc": utc_now(),
                "model_f9_outputs": 13,
                "heartbleed_semantic_kind": "raw_label_window_not_f9",
                "outputs": sorted(outputs, key=lambda item: item["case_id"]),
            },
            destination,
            indent=2,
            ensure_ascii=False,
        )
        destination.write("\n")
    return manifest_path


def re_fullmatch_run_id(value: str) -> bool:
    import re

    return re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", value) is not None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--progress-packets", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    try:
        print(build(args.run_id, args.progress_packets))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
