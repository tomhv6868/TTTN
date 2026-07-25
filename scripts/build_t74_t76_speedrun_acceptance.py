from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


TASK = "T7.4-T7.6"
RUNS = {
    "baseline_pass": "run_log/t0.4/t7.4-t7.6/baseline/baseline-5000-a1",
    "baseline_fail": "run_log/t0.4/t7.4-t7.6/baseline/baseline-10000-a1",
    "full_capacity": "run_log/t0.4/t7.4-t7.6/full/full-1800-a1",
    "stability": "run_log/t0.4/t7.4-t7.6/stability/stability-1000-30m-a1",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def load_summary(path: Path) -> dict[str, Any]:
    summary = None
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid JSONL at {path}:{line_number}: {error}"
                ) from error
            if event.get("event_type") == "nids_dpdk_live_summary":
                summary = event
    if not isinstance(summary, dict):
        raise ValueError(f"missing live summary: {path}")
    return summary


def evidence_record(root: Path, relative_path: str) -> dict[str, Any]:
    path = root / relative_path
    if not path.is_file():
        raise ValueError(f"missing evidence: {relative_path}")
    return {
        "sha256": sha256_path(path),
        "size_bytes": path.stat().st_size,
    }


def load_runs(
    root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    runs: dict[str, dict[str, Any]] = {}
    evidence: dict[str, dict[str, Any]] = {}
    for name, directory in RUNS.items():
        paths = {
            "sender": f"{directory}/kali-sender.json",
            "sensor": f"{directory}/sensor.jsonl",
            "rollback": f"{directory}/rollback.json",
        }
        for relative_path in paths.values():
            evidence[relative_path] = evidence_record(root, relative_path)
        runs[name] = {
            "path": directory,
            "sender": load_json(root / paths["sender"]),
            "sensor": load_summary(root / paths["sensor"]),
            "rollback": load_json(root / paths["rollback"]),
        }
    return runs, evidence


def cpu_percent(summary: Mapping[str, Any]) -> float:
    active_duration_ns = summary.get("active_duration_ns")
    resources = summary.get("process_resource", {})
    require(
        isinstance(active_duration_ns, int) and active_duration_ns > 0,
        "active duration must be positive",
    )
    require(resources.get("available") is True, "process resources unavailable")
    cpu_us = resources.get("user_cpu_us", 0) + resources.get("system_cpu_us", 0)
    require(isinstance(cpu_us, int) and cpu_us >= 0, "invalid CPU duration")
    return cpu_us * 100_000.0 / active_duration_ns


def latency_ms(summary: Mapping[str, Any], name: str) -> dict[str, float]:
    latency = summary.get("latency_ns", {}).get(name, {})
    values = {}
    for percentile in ("p50", "p95", "p99", "max"):
        value = latency.get(percentile)
        require(isinstance(value, int) and value >= 0, f"missing {name} {percentile}")
        values[percentile] = value / 1_000_000.0
    return values


def validate_sources(runs: Mapping[str, Mapping[str, Any]]) -> None:
    baseline_pass = runs["baseline_pass"]
    baseline_fail = runs["baseline_fail"]
    full = runs["full_capacity"]
    stability = runs["stability"]

    for name, run in runs.items():
        require(run["sender"].get("status") == "passed", f"{name} sender failed")
        require(run["rollback"].get("status") == "passed", f"{name} rollback failed")

    require(
        baseline_pass["sender"].get("requested_pps") == 5_000,
        "baseline pass rate drifted",
    )
    require(
        baseline_pass["sensor"].get("status") == "passed",
        "5,000 pps baseline did not pass",
    )
    require(
        baseline_pass["sensor"].get("packets_seen")
        == baseline_pass["sender"].get("packets_sent"),
        "5,000 pps baseline packet count mismatch",
    )
    require(
        baseline_fail["sender"].get("requested_pps") == 10_000,
        "baseline fail rate drifted",
    )
    require(
        baseline_fail["sensor"].get("status") == "failed",
        "10,000 pps baseline must remain the failed upper bound",
    )
    require(
        full["sender"].get("requested_pps") == 1_800,
        "full capacity rate drifted",
    )
    require(full["sensor"].get("status") == "passed", "full capacity run failed")
    require(
        full["sensor"].get("packets_seen") == full["sender"].get("packets_sent"),
        "full capacity packet count mismatch",
    )
    require(
        stability["sender"].get("packets_sent") == 1_800_000,
        "stability sender packet count drifted",
    )
    require(
        stability["sensor"].get("status") == "passed",
        "stability sensor failed",
    )
    require(
        stability["sensor"].get("f9_snapshots", 0)
        >= stability["sender"].get("flows", 0),
        "stability F9 coverage is incomplete",
    )
    for name in ("port_imissed", "port_rx_nombuf", "adapter_errors", "ingest_errors"):
        require(stability["sensor"].get(name) == 0, f"stability counter nonzero: {name}")


def build_receipt(
    runs: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Any],
    generated_at_utc: str,
) -> dict[str, Any]:
    validate_sources(runs)
    baseline_pass = runs["baseline_pass"]
    baseline_fail = runs["baseline_fail"]
    full = runs["full_capacity"]
    stability = runs["stability"]
    full_sensor = full["sensor"]
    stability_sensor = stability["sensor"]
    stability_sender = stability["sender"]
    full_rss = full_sensor["process_resource"]["max_rss_kb"]
    stability_rss = stability_sensor["process_resource"]["max_rss_kb"]
    sender_duration = stability_sender["duration_seconds"]

    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "dpdk_benchmark_speedrun_acceptance",
        "status": "accepted_for_speed_run_demo",
        "generated_at_utc": generated_at_utc,
        "scope": {
            "profile": "speed_run_demo",
            "formal_phase_7_acceptance": False,
            "execution_host": "ubuntu_vmware",
            "sender_host": "kali_vmware",
            "checkpoint": "F9",
        },
        "t7_4_capacity": {
            "baseline": {
                "sustained_lower_bound_pps": 5_000,
                "failed_upper_bound_pps": 10_000,
                "maximum_precisely_located": False,
                "pass_sensor_pps": baseline_pass["sensor"]["packets_per_second"],
                "pass_sender_pps": baseline_pass["sender"]["observed_pps"],
                "failed_upper_bound_packets_seen": baseline_fail["sensor"]["packets_seen"],
            },
            "full_pipeline": {
                "sustained_pps": 1_800,
                "sensor_pps": full_sensor["packets_per_second"],
                "sender_pps": full["sender"]["observed_pps"],
                "cpu_percent": cpu_percent(full_sensor),
                "selected_stability_rate_pps": 1_000,
                "selection_reason": "1,800 pps passed but consumed approximately 97% CPU",
            },
        },
        "t7_5_system_benchmark": {
            "full_pipeline_1800_pps": {
                "flows_per_second": full_sensor["flows_per_second"],
                "cpu_percent": cpu_percent(full_sensor),
                "max_rss_kb": full_rss,
                "peak_flow_memory_bytes": full_sensor["peak_flow_memory_bytes"],
                "parse_latency_ms": latency_ms(full_sensor, "parse"),
                "pipeline_latency_ms": latency_ms(full_sensor, "pipeline"),
                "inference_latency_ms": latency_ms(full_sensor, "inference"),
                "alert_latency_ms": latency_ms(full_sensor, "alert"),
                "port_imissed": full_sensor["port_imissed"],
                "port_rx_nombuf": full_sensor["port_rx_nombuf"],
            },
            "alert_queue": {
                "implemented": False,
                "pressure_available": False,
                "reason": "T6.5 asynchronous alert queue was skipped in the demo vertical slice",
            },
        },
        "t7_6_stability": {
            "status": "passed",
            "requested_duration_seconds": 1_800,
            "sender_duration_seconds": sender_duration,
            "requested_pps": 1_000,
            "sender_observed_pps": stability_sender["observed_pps"],
            "sender_packets": stability_sender["packets_sent"],
            "sensor_packets_seen": stability_sensor["packets_seen"],
            "sensor_packets_parsed": stability_sensor["packets_parsed"],
            "ambient_or_nonbenchmark_packets": (
                stability_sensor["packets_seen"] - stability_sender["packets_sent"]
            ),
            "parser_errors": stability_sensor["parser_errors"],
            "f9_snapshots": stability_sensor["f9_snapshots"],
            "flow_generations_created": stability_sensor["flow_generations_created"],
            "flows_closed": stability_sensor["flows_closed"],
            "active_flows_at_shutdown": stability_sensor["active_flows"],
            "peak_active_flows": stability_sensor["peak_active_flows"],
            "port_imissed": stability_sensor["port_imissed"],
            "port_rx_nombuf": stability_sensor["port_rx_nombuf"],
            "cpu_percent": cpu_percent(stability_sensor),
            "max_rss_kb": stability_rss,
            "max_rss_delta_vs_full_capacity_kb": stability_rss - full_rss,
            "peak_flow_memory_bytes": stability_sensor["peak_flow_memory_bytes"],
            "inference_latency_ms": latency_ms(stability_sensor, "inference"),
            "alert_latency_ms": latency_ms(stability_sensor, "alert"),
            "alerts": stability_sensor["alerts"],
            "synthetic_benchmark_alerts_per_hour": (
                stability_sensor["alerts"] * 3_600.0 / sender_duration
            ),
            "rollback_status": stability["rollback"]["status"],
            "unbounded_memory_growth_observed": False,
            "memory_evidence": "end-of-run peak RSS comparison, not a time-series profile",
        },
        "limitations": [
            "baseline maximum is bracketed at [5,000, 10,000) pps, not precisely located",
            "traffic is synthetic multi-flow TCP F9 benchmark traffic, not a production traffic mix",
            "408 additional port packets prevent identity-level proof that every sender packet arrived",
            "alert queue pressure is unavailable because the asynchronous queue is not implemented",
            "memory stability uses peak endpoint comparison rather than periodic time-series samples",
        ],
        "evidence": dict(evidence),
    }
    validate_receipt(receipt)
    return receipt


def validate_receipt(receipt: Mapping[str, Any]) -> None:
    require(receipt.get("task") == TASK, "wrong task")
    require(
        receipt.get("status") == "accepted_for_speed_run_demo",
        "wrong acceptance status",
    )
    require(
        receipt.get("scope", {}).get("formal_phase_7_acceptance") is False,
        "formal acceptance must remain false",
    )
    require(
        receipt.get("t7_4_capacity", {})
        .get("baseline", {})
        .get("maximum_precisely_located")
        is False,
        "baseline maximum precision was overstated",
    )
    require(
        receipt.get("t7_5_system_benchmark", {})
        .get("alert_queue", {})
        .get("pressure_available")
        is False,
        "alert queue pressure was fabricated",
    )
    stability = receipt.get("t7_6_stability", {})
    require(stability.get("status") == "passed", "stability status is not passed")
    require(stability.get("rollback_status") == "passed", "rollback is not passed")
    require(stability.get("port_imissed") == 0, "stability port drop is nonzero")
    require(stability.get("port_rx_nombuf") == 0, "stability mbuf drop is nonzero")


def write_json(path: Path, value: Mapping[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_parser(root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument(
        "--output",
        type=Path,
        default=root / "run_log/t7.4-t7.6/acceptance.json",
    )
    build.add_argument("--force", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument(
        "--input",
        type=Path,
        default=root / "run_log/t7.4-t7.6/acceptance.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    args = build_parser(root).parse_args(argv)
    if args.command == "validate":
        validate_receipt(load_json(args.input))
        print(f"[{TASK}] validation passed: {args.input}")
        return 0
    runs, evidence = load_runs(root)
    receipt = build_receipt(runs, evidence, utc_now())
    write_json(args.output, receipt, args.force)
    print(f"[{TASK}] accepted for speed-run demo: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
