#!/usr/bin/env python3
"""Validate and aggregate the receipts from the T0.3 DPDK smoke test."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_timestamp(value: Any) -> dt.datetime | None:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            return None
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate_receipts(
    preflight: Any, run: Any, traffic: Any, rollback: Any
) -> tuple[list[dict[str, Any]], float]:
    checks: list[dict[str, Any]] = []

    def check(name: str, condition: bool, expected: Any, observed: Any) -> None:
        checks.append(
            {"name": name, "status": "passed" if condition else "failed", "expected": expected, "observed": observed}
        )

    documents = {"preflight": preflight, "run": run, "traffic": traffic, "rollback": rollback}
    for kind, document in documents.items():
        check(f"{kind}.object", isinstance(document, Mapping), True, isinstance(document, Mapping))
        if not isinstance(document, Mapping):
            continue
        check(f"{kind}.schema", document.get("schema_version") == SCHEMA_VERSION, SCHEMA_VERSION, document.get("schema_version"))
        check(f"{kind}.task", document.get("task") == "T0.3", "T0.3", document.get("task"))
        check(f"{kind}.kind", document.get("kind") == kind, kind, document.get("kind"))
        check(f"{kind}.status", document.get("status") == "passed", "passed", document.get("status"))

    if not all(isinstance(item, Mapping) for item in documents.values()):
        return checks, 0.0
    preflight_checks = preflight.get("checks", [])
    mandatory = {
        "management.default_route",
        "management.ping",
        "data.no_default_route",
        "data.driver",
        "data.pci",
        "iommu.available",
        "iommu.group_policy",
        "hugepages.supported",
        "toolchain.testpmd",
        "toolchain.devbind",
    }
    passed_names = {
        item.get("name") for item in preflight_checks if isinstance(item, Mapping) and item.get("status") == "passed"
    }
    check("preflight.safety_gates", mandatory <= passed_names, sorted(mandatory), sorted(passed_names & mandatory))
    counters = run.get("counters", {})
    check("run.rx_packets", isinstance(counters.get("rx_packets"), int) and counters.get("rx_packets", 0) > 0, ">0", counters.get("rx_packets"))
    check("run.tx_packets", isinstance(counters.get("tx_packets"), int) and counters.get("tx_packets", 0) > 0, ">0", counters.get("tx_packets"))
    command = run.get("command", [])
    separator = command.index("--") if isinstance(command, list) and "--" in command else -1
    memory_options_ok = (
        separator > 0
        and any(command[index : index + 2] == ["-m", "256"] for index in range(separator - 1))
        and "--file-prefix=nids-t03" in command[:separator]
        and "--huge-unlink=always" in command[:separator]
        and "--total-num-mbufs=8192" in command[separator + 1 :]
    )
    check(
        "run.memory_options",
        memory_options_ok,
        "-m/file-prefix/huge-unlink before -- and total-num-mbufs after --",
        command,
    )
    requested = run.get("requested_duration_seconds")
    elapsed = run.get("duration_seconds")
    duration_ok = isinstance(requested, (int, float)) and isinstance(elapsed, (int, float)) and elapsed >= max(1, requested - 5)
    check("run.duration", duration_ok, "within 5 seconds of requested duration", elapsed)
    check("run.management_after", run.get("management_ping_after", {}).get("passed") is True, True, run.get("management_ping_after", {}).get("passed"))
    check("traffic.sent", isinstance(traffic.get("sent_packets"), int) and traffic.get("sent_packets", 0) > 0, ">0", traffic.get("sent_packets"))
    check("traffic.errors", traffic.get("send_errors") == 0, 0, traffic.get("send_errors"))
    data_interface = preflight.get("discovery", {}).get("interfaces", {}).get(preflight.get("data_interface"), {})
    check("traffic.destination_mac", traffic.get("destination_mac", "").lower() == str(data_interface.get("mac", "")).lower(), data_interface.get("mac"), traffic.get("destination_mac"))
    original_driver = preflight.get("configuration", {}).get("ubuntu", {}).get("expected_data_driver")
    check("rollback.driver", rollback.get("restored", {}).get("driver") == original_driver, original_driver, rollback.get("restored", {}).get("driver"))
    original_hugepages = preflight.get("discovery", {}).get("hugepages", {}).get("current_count")
    check("rollback.hugepages", rollback.get("restored", {}).get("hugepage_count") == original_hugepages, original_hugepages, rollback.get("restored", {}).get("hugepage_count"))
    rollback_checks = rollback.get("checks", [])
    required_rollback = {
        "iommu_bridges.restored",
        "driver.restored",
        "interface.restored",
        "dpdk_prefix.cleaned",
        "hugepages.restored",
        "management.reachable",
    }
    rollback_passed = {
        item.get("name") for item in rollback_checks if isinstance(item, Mapping) and item.get("status") == "passed"
    }
    check("rollback.actions", required_rollback <= rollback_passed, sorted(required_rollback), sorted(rollback_passed & required_rollback))
    run_start = parse_timestamp(run.get("started_at_utc"))
    run_end = parse_timestamp(run.get("ended_at_utc"))
    traffic_start = parse_timestamp(traffic.get("started_at_utc"))
    traffic_end = parse_timestamp(traffic.get("ended_at_utc"))
    overlap = 0.0
    if all((run_start, run_end, traffic_start, traffic_end)):
        overlap = max(0.0, (min(run_end, traffic_end) - max(run_start, traffic_start)).total_seconds())
    overlap_expected = max(1.0, min(float(requested or 0), float(traffic.get("requested_duration_seconds") or 0)) - 5.0)
    check("run_traffic.overlap", overlap >= overlap_expected, f">={overlap_expected:.1f}s", round(overlap, 3))
    return checks, overlap


def write_new_json(path: Path, document: Mapping[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"refusing to overwrite existing file: {path}; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def command_verify(args: argparse.Namespace) -> int:
    documents = {
        "preflight": load_json(args.preflight),
        "run": load_json(args.run),
        "traffic": load_json(args.traffic),
        "rollback": load_json(args.rollback),
    }
    checks, overlap = validate_receipts(**documents)
    status = "passed" if all(item["status"] == "passed" for item in checks) else "failed"
    paths = {
        name: {"file": str(path), "sha256": sha256_file(path)}
        for name, path in {
            "preflight": args.preflight,
            "run": args.run,
            "traffic": args.traffic,
            "rollback": args.rollback,
        }.items()
    }
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": "T0.3",
        "kind": "acceptance",
        "status": status,
        "generated_at_utc": utc_now(),
        "artifacts": paths,
        "summary": {
            "rx_packets": documents["run"].get("counters", {}).get("rx_packets"),
            "tx_packets": documents["run"].get("counters", {}).get("tx_packets"),
            "traffic_packets": documents["traffic"].get("sent_packets"),
            "overlap_seconds": round(overlap, 3),
        },
        "checks": checks,
    }
    write_new_json(args.output, receipt, args.force)
    print(f"wrote {args.output} ({status})")
    for item in checks:
        if item["status"] == "failed":
            print(f"failed: {item['name']} (observed={item['observed']!r})", file=sys.stderr)
    return 0 if status == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--traffic", required=True, type=Path)
    parser.add_argument("--rollback", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return command_verify(build_parser().parse_args(argv))
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
