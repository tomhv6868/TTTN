from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


TASK = "T8.1/T8.2"
CHECKPOINTS = ("F3", "F5", "F7", "F9")
MODELS = ("flow_rf", "hbos", "isolation_forest", "rf_stacker")
EXPECTED_SOURCES = {
    "run_log/t4.2/acceptance.json": "720805a1cd25dab6b2129a125df1a65a3100d5ee891d0f40fc4742aac041b98d",
    "run_log/t4.3/acceptance.json": "88599430c7739f29e454d95f57c34a5c24974159359795bacad8bd0b3f48266c",
    "run_log/t4.5/acceptance.json": "ef94e26bcd04725b463466a34dc15bec58bce92dd75da3cae55881a89dea56d1",
    "run_log/t4.7-rf300/acceptance.json": "481a8d0793febeb8e0330a245ad73def04b86675f876008d5b5c93b0ec85dc4e",
    "run_log/t4.7-rf300/user-acceptance.json": "3cac230727a20e4398c71c55424e651ac8bc7f4ed7c0147e9505022631487837",
    "run_log/t4.8/acceptance.json": "9bd14e7195c7affc8d7477939826a9fa5299f46a522cf71eecb02bdad6a3c086",
    "run_log/t4.8/user-acceptance.json": "3ebdfb5c26985826707fe783e8f633c4a4a3da4611b53b807e7ae71c91f2bf8f",
    "run_log/t6.1/acceptance.json": "bd3cb0d6c539cfb95a8eb015cc086615fb0c960b39443ebba604421fdb8949ea",
    "run_log/t6.1/thresholds.json": "82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4",
    "run_log/t7.3/acceptance.json": "da4df77a5b99efacaa5b0b228084a4d98677c29586d46fa0cb1355e80a143f26",
}


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


def load_locked_sources(root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    evidence: dict[str, Any] = {}
    for relative_path, expected_sha256 in EXPECTED_SOURCES.items():
        path = root / relative_path
        if not path.is_file():
            raise ValueError(f"missing locked source: {relative_path}")
        actual_sha256 = sha256_path(path)
        if actual_sha256 != expected_sha256:
            raise ValueError(f"locked source SHA-256 mismatch: {relative_path}")
        documents[relative_path] = load_json(path)
        evidence[relative_path] = {
            "sha256": actual_sha256,
            "size_bytes": path.stat().st_size,
        }
    return documents, evidence


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_source_semantics(documents: Mapping[str, Mapping[str, Any]]) -> None:
    for path in (
        "run_log/t4.2/acceptance.json",
        "run_log/t4.3/acceptance.json",
        "run_log/t4.5/acceptance.json",
        "run_log/t4.7-rf300/acceptance.json",
        "run_log/t4.7-rf300/user-acceptance.json",
        "run_log/t4.8/acceptance.json",
        "run_log/t4.8/user-acceptance.json",
        "run_log/t6.1/acceptance.json",
    ):
        require(documents[path].get("status") == "passed", f"source is not passed: {path}")

    t47 = documents["run_log/t4.7-rf300/acceptance.json"]
    t47_validation = t47.get("validation", {})
    require(
        t47.get("analysis", {}).get("macro_aggregate", {}).get("family_count") == 9,
        "T4.7 macro family count must be nine",
    )
    for key in (
        "all_family_receipts_verified",
        "all_metrics_recomputed_from_predictions",
        "equal_family_macro_weighting",
        "nine_family_macro_scope_exact",
        "rf300_primary_final",
    ):
        require(t47_validation.get(key) is True, f"T4.7 validation failed: {key}")

    t48 = documents["run_log/t4.8/acceptance.json"]
    decision = t48.get("analysis", {}).get("decision", {})
    require(decision.get("all_safeguards_passed") is True, "T4.8 safeguards failed")
    require(
        decision.get("selection", {}).get("phase_5_binary_classifier") == "flow_rf",
        "T4.8 classifier selection drifted",
    )
    require(
        documents["run_log/t4.8/user-acceptance.json"].get("decision") == "accepted",
        "T4.8 manual acceptance is missing",
    )

    t61 = documents["run_log/t6.1/acceptance.json"]
    require(
        t61.get("artifact", {}).get("sha256")
        == EXPECTED_SOURCES["run_log/t6.1/thresholds.json"],
        "T6.1 threshold reference drifted",
    )
    require(
        t61.get("acceptance", {}).get("model_training_performed") is False,
        "T6.1 unexpectedly trained a model",
    )

    t73 = documents["run_log/t7.3/acceptance.json"]
    require(t73.get("status") == "accepted_for_demo", "T7.3 is not accepted for demo")
    require(
        t73.get("paced_live_replay", {}).get("status") == "passed",
        "T7.3 paced live replay failed",
    )
    require(
        t73.get("resource_rollback", {}).get("retry_status") == "passed",
        "T7.3 resource rollback did not pass",
    )


def metric_summary(model: Mapping[str, Any], metric: str) -> dict[str, Any]:
    value = model.get("metrics", {}).get(metric)
    if not isinstance(value, Mapping):
        raise ValueError(f"missing LOAFO metric: {metric}")
    summary = {
        "mean": value.get("mean"),
        "ci95_low": value.get("ci95_low"),
        "ci95_high": value.get("ci95_high"),
        "family_units": value.get("family_units"),
    }
    require(
        all(isinstance(summary[key], (int, float)) for key in ("mean", "ci95_low", "ci95_high")),
        f"invalid LOAFO metric: {metric}",
    )
    require(summary["family_units"] == 9, f"wrong family unit count: {metric}")
    return summary


def model_summary(model: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "known_recall": metric_summary(model, "known_attack_recall"),
        "unknown_recall": metric_summary(model, "unknown_holdout_recall"),
        "benign_fpr": metric_summary(model, "benign_fpr"),
        "novel_f1": metric_summary(model, "novel_f1"),
    }


def build_detection_study(t47: Mapping[str, Any]) -> dict[str, Any]:
    checkpoints = t47["analysis"]["macro_aggregate"]["checkpoints"]
    study: dict[str, Any] = {}
    for checkpoint in CHECKPOINTS:
        models = checkpoints[checkpoint]["models"]
        require(
            tuple(models.keys()) == MODELS,
            f"unexpected model order or scope at {checkpoint}",
        )
        study[checkpoint] = {
            "flow_rf": model_summary(models["flow_rf"]),
            "anomaly_only": {
                "interpretation": "independent_benign_only_baselines_no_ensemble",
                "hbos": model_summary(models["hbos"]),
                "isolation_forest": model_summary(models["isolation_forest"]),
            },
            "rf_stacker": model_summary(models["rf_stacker"]),
        }
    return study


def build_receipt(
    documents: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Any],
    generated_at_utc: str,
) -> dict[str, Any]:
    validate_source_semantics(documents)
    t47 = documents["run_log/t4.7-rf300/acceptance.json"]
    t48 = documents["run_log/t4.8/acceptance.json"]
    t61 = documents["run_log/t6.1/acceptance.json"]
    t73 = documents["run_log/t7.3/acceptance.json"]
    decision = t48["analysis"]["decision"]
    bootstrap = t48["analysis"]["loafo"]["comparisons"]["flow_rf"]["global_novel_f1"]

    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "demo_detection_study_and_ablation_acceptance",
        "status": "accepted_for_demo",
        "mode": "demo_critical_path",
        "generated_at_utc": generated_at_utc,
        "scope": {
            "checkpoints": list(CHECKPOINTS),
            "confirmatory_loafo_families": 9,
            "tree_count": 300,
            "configuration_groups": [
                "flow_rf",
                "anomaly_only",
                "rf_stacker",
            ],
            "anomaly_only_variants": ["hbos", "isolation_forest"],
            "model_training_performed": False,
        },
        "detection_study": {
            "population": "equal-family macro over nine confirmatory LOAFO families",
            "checkpoints": build_detection_study(t47),
            "alerts_per_hour": {
                "value": None,
                "status": "not_computable_from_locked_evidence",
                "reason": "validation snapshots do not contain a wall-clock observation duration",
            },
        },
        "model_selection": {
            "selected_binary_classifier": decision["selection"]["phase_5_binary_classifier"],
            "rf_stacker_role": decision["selection"]["rf_stacker"],
            "stacker_improvement_claim_supported": decision[
                "stacker_improvement_claim_supported"
            ],
            "primary_endpoint": "global novel F1, RF Stacker minus Flow RF",
            "primary_delta": bootstrap["delta"],
            "ci95_low": bootstrap["ci95_low"],
            "ci95_high": bootstrap["ci95_high"],
            "bootstrap_samples": bootstrap["bootstrap_samples"],
            "bootstrap_seed": bootstrap["bootstrap_seed"],
            "family_units": bootstrap["family_units"],
            "reason_codes": decision["reason_codes"],
        },
        "ablation": {
            "flow_rf": "completed",
            "anomaly_only": {
                "status": "completed_as_two_independent_baselines",
                "models": ["hbos", "isolation_forest"],
                "combined_ensemble_metric": None,
                "reason": "the locked T4.8 contract forbids inventing an anomaly ensemble baseline",
            },
            "rf_stacker": "completed_and_retained_as_ablation",
            "port_category": {
                "status": "deferred_for_demo",
                "reason": "PortScan is case-study-only and excluded from confirmatory inference",
            },
            "excluded_models": ["SPIN", "KitNET"],
        },
        "runtime_handoff": {
            "threshold_artifact": t61["artifact"],
            "paced_live_replay": t73["paced_live_replay"],
            "offline_live_comparison": t73["comparison"],
            "resource_rollback": t73["resource_rollback"],
        },
        "deferred_for_demo": [
            "offline aggregate metrics for the calibrated runtime fusion decision",
            "alerts/hour until a wall-clock observation window is recorded",
            "port-category ablation",
            *t73["deferred_for_demo"],
        ],
        "evidence": dict(evidence),
        "validation": {
            "all_source_hashes_verified": True,
            "no_prediction_rows_reprocessed": True,
            "no_model_training_performed": True,
            "equal_family_macro_weighting_preserved": True,
            "anomaly_baselines_kept_independent": True,
            "stacker_selection_gate_preserved": True,
            "missing_alert_rate_not_fabricated": True,
            "live_demo_evidence_linked": True,
        },
    }
    validate_receipt(receipt)
    return receipt


def validate_receipt(receipt: Mapping[str, Any]) -> None:
    require(receipt.get("task") == TASK, "wrong task")
    require(receipt.get("status") == "accepted_for_demo", "wrong status")
    require(receipt.get("scope", {}).get("model_training_performed") is False, "training drift")
    require(
        receipt.get("detection_study", {}).get("alerts_per_hour", {}).get("value") is None,
        "alerts/hour must not be fabricated",
    )
    require(
        receipt.get("model_selection", {}).get("selected_binary_classifier") == "flow_rf",
        "wrong selected classifier",
    )
    require(
        receipt.get("model_selection", {}).get("stacker_improvement_claim_supported") is False,
        "unsupported Stacker claim",
    )
    checkpoints = receipt.get("detection_study", {}).get("checkpoints", {})
    require(tuple(checkpoints.keys()) == CHECKPOINTS, "checkpoint scope drifted")


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
        default=root / "run_log/t8.1-t8.2/acceptance.json",
    )
    build.add_argument("--force", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument(
        "--input",
        type=Path,
        default=root / "run_log/t8.1-t8.2/acceptance.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    args = build_parser(root).parse_args(argv)
    if args.command == "validate":
        validate_receipt(load_json(args.input))
        print(f"[{TASK}] validation passed: {args.input}")
        return 0
    documents, evidence = load_locked_sources(root)
    receipt = build_receipt(documents, evidence, utc_now())
    write_json(args.output, receipt, args.force)
    print(f"[{TASK}] accepted for demo: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
