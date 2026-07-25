#!/usr/bin/env python3
"""Create and summarize bounded T8.5 diagnostic demo scenario evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "config/t85-demo-scenario.json"
RUN_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
EVIDENCE_FIELDS = {
    "kind": "diagnostic_demo_evidence",
    "mode": "demo_critical_path",
    "formal_acceptance": False,
    "roadmap_mutated": False,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def scenario_root(config: dict[str, Any], run_id: str) -> Path:
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError("run-id must be 3-64 lowercase letters, digits, '.', '_' or '-'")
    configured = config.get("artifact_root")
    if configured != "run_log/t8.5/scenarios":
        raise ValueError("scenario artifact_root is not locked")
    parent = (PROJECT_ROOT / configured).resolve()
    root = (parent / run_id).resolve()
    root.relative_to(parent)
    return root


def write_new_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as destination:
        json.dump(document, destination, indent=2, ensure_ascii=False)
        destination.write("\n")


def init_run(config_path: Path, run_id: str) -> Path:
    config = load_json(config_path)
    root = scenario_root(config, run_id)
    root.mkdir(parents=True, exist_ok=False)
    for child in ("windows", "ubuntu", "kali/replay", "kali/tools"):
        (root / child).mkdir(parents=True)
    write_new_json(
        root / "scenario.json",
        {
            **EVIDENCE_FIELDS,
            "schema_version": "1.0.0",
            "status": "initialized",
            "run_id": run_id,
            "generated_at_utc": utc_now(),
            "config": {
                "path": config_path.resolve().relative_to(PROJECT_ROOT).as_posix(),
                "sha256": sha256_path(config_path),
            },
            "taxonomy": config["taxonomy"],
            "cases": config["cases"],
        },
    )
    return root


def record_tool(
    config_path: Path,
    run_id: str,
    case_id: str,
    command: Sequence[str],
) -> Path:
    config = load_json(config_path)
    root = scenario_root(config, run_id)
    scenario = load_json(root / "scenario.json")
    cases = {case["id"]: case for case in scenario["cases"]}
    if case_id not in cases or cases[case_id]["tier"] == "presentation_only":
        raise ValueError(f"unknown or non-executable case: {case_id}")
    if not command:
        raise ValueError("tool command is required after --")
    timeout = int(config["safety"]["maximum_tool_duration_seconds"])
    started = utc_now()
    timed_out = False
    try:
        result = subprocess.run(
            list(command),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        return_code = 124
        stdout = error.stdout or ""
        stderr = error.stderr or ""
    path = root / "kali/tools" / f"{case_id}.json"
    write_new_json(
        path,
        {
            **EVIDENCE_FIELDS,
            "schema_version": "1.0.0",
            "status": "observed" if return_code == 0 else "failed_demo",
            "run_id": run_id,
            "case": cases[case_id],
            "started_at_utc": started,
            "ended_at_utc": utc_now(),
            "command": list(command),
            "timeout_seconds": timeout,
            "timed_out": timed_out,
            "return_code": return_code,
            "stdout": stdout,
            "stderr": stderr,
            "dataset_equivalence_claimed": False,
        },
    )
    return path


def summarize(config_path: Path, run_id: str) -> Path:
    config = load_json(config_path)
    root = scenario_root(config, run_id)
    scenario = load_json(root / "scenario.json")
    evidence = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.name not in {"scenario.json", "summary.json"}
    )
    path = root / "summary.json"
    write_new_json(
        path,
        {
            **EVIDENCE_FIELDS,
            "schema_version": "1.0.0",
            "status": "observed",
            "run_id": run_id,
            "generated_at_utc": utc_now(),
            "source_attack_label_count": scenario["taxonomy"]["source_attack_label_count"],
            "model_family_count": scenario["taxonomy"]["model_family_count"],
            "evidence_files": evidence,
            "formal_phase_8_acceptance": False,
        },
    )
    return path


def build_resource_config(config_path: Path, run_id: str, attempt: str) -> Path:
    config = load_json(config_path)
    root = scenario_root(config, run_id)
    if RUN_ID_PATTERN.fullmatch(attempt) is None:
        raise ValueError("attempt must follow the run-id character rules")
    if not (root / "scenario.json").is_file():
        raise ValueError("initialize the scenario before building resource config")
    scripts = PROJECT_ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import dpdk_passive_probe
    import kali_passive_traffic

    passive_path = PROJECT_ROOT / "config/dpdk-passive.json"
    passive = kali_passive_traffic.load_and_validate_config(passive_path)
    resource = dpdk_passive_probe.build_resource_config(passive)
    path = root / "ubuntu" / attempt / "resource-config.json"
    write_new_json(path, resource)
    return path


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="action", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--run-id", required=True)
    tool = subparsers.add_parser("record-tool")
    tool.add_argument("--run-id", required=True)
    tool.add_argument("--case", required=True)
    tool.add_argument("command", nargs=argparse.REMAINDER)
    summary = subparsers.add_parser("summarize")
    summary.add_argument("--run-id", required=True)
    resource = subparsers.add_parser("resource-config")
    resource.add_argument("--run-id", required=True)
    resource.add_argument("--attempt", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        if args.action == "init":
            path = init_run(args.config.resolve(), args.run_id)
        elif args.action == "record-tool":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            path = record_tool(args.config.resolve(), args.run_id, args.case, command)
        elif args.action == "resource-config":
            path = build_resource_config(
                args.config.resolve(), args.run_id, args.attempt
            )
        else:
            path = summarize(args.config.resolve(), args.run_id)
        print(path)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
