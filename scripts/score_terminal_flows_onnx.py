#!/usr/bin/env python3
"""Score exported T9.1 terminal flows with the locked ONNX bundle.

The scorer is intentionally independent from training code.  It verifies every
bundle member against the locked manifest, streams terminal-flow JSONL in
batches, applies the recorded attack gate, and writes per-flow plus aggregate
evidence.  It never resolves or reads the sealed test partition.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence


DIAGNOSTIC_FEATURES = {
    0: "flow_age_us",
    15: "flow_iat_min_us",
    16: "flow_iat_max_us",
    17: "flow_iat_mean_us",
    18: "flow_iat_std_us",
    23: "packet_rate_per_second",
    24: "wire_byte_rate_per_second",
    57: "forward_wire_bit_rate_per_second",
    58: "reverse_wire_bit_rate_per_second",
}


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_bundle(bundle_dir: Path) -> dict:
    manifest_path = bundle_dir / "manifest.json"
    manifest = read_json(manifest_path)
    if manifest.get("status") != "locked":
        raise ValueError("bundle manifest is not locked")
    if manifest.get("test_partition", {}).get("status") != "sealed":
        raise ValueError("bundle does not declare a sealed test partition")
    if manifest.get("test_partition", {}).get("feature_reads") != 0:
        raise ValueError("bundle records non-zero sealed-test feature reads")
    members = manifest.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("bundle manifest has no members")
    for member in members:
        path = bundle_dir / member["path"]
        observed = sha256_file(path)
        if observed != member["sha256"]:
            raise ValueError(f"bundle checksum mismatch: {member['path']}")

    preprocessing = read_json(bundle_dir / "preprocessing.json")
    thresholds = read_json(bundle_dir / "thresholds.json")
    indices = preprocessing.get("selection", {}).get("feature_indices")
    if indices != manifest.get("selected_feature_indices"):
        raise ValueError("selected feature indices disagree")
    threshold = thresholds.get("decision", {}).get("gate", {}).get("threshold")
    if threshold != manifest.get("selected_threshold"):
        raise ValueError("selected threshold disagrees")
    if thresholds.get("class_order") != manifest.get("class_order"):
        raise ValueError("class order disagrees")
    return {
        "manifest": manifest,
        "manifest_sha256": sha256_file(manifest_path),
        "model_path": bundle_dir / "models" / "terminal_multiclass.onnx",
        "selected_indices": indices,
        "class_order": manifest["class_order"],
        "benign_index": manifest["benign_index"],
        "threshold": threshold,
    }


def decide(
    probabilities: Sequence[float],
    class_order: Sequence[str],
    benign_index: int,
    threshold: float,
) -> dict:
    if len(probabilities) != len(class_order):
        raise ValueError("probability/class count mismatch")
    values = [float(value) for value in probabilities]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("non-finite model probability")
    raw_index = max(range(len(values)), key=values.__getitem__)
    attack_indices = [index for index in range(len(values)) if index != benign_index]
    attack_index = max(attack_indices, key=values.__getitem__)
    attack_score = 1.0 - values[benign_index]
    passed = attack_score >= threshold
    gated_index = attack_index if passed else benign_index
    return {
        "probabilities": values,
        "raw_argmax": class_order[raw_index],
        "top_attack_candidate": class_order[attack_index],
        "top_attack_probability": values[attack_index],
        "attack_score": attack_score,
        "gate_passed": passed,
        "decision": class_order[gated_index],
    }


def percentile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(math.floor(position))
    high = int(math.ceil(position))
    if low == high:
        return ordered[low]
    weight = position - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def distribution(values: Sequence[float]) -> dict:
    return {
        "count": len(values),
        "min": min(values) if values else None,
        "p25": percentile(values, 0.25),
        "median": percentile(values, 0.5),
        "p75": percentile(values, 0.75),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values) if values else None,
    }


def batches(items: Iterable[tuple[dict, list[float]]], size: int):
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--output-jsonl", required=True, type=Path)
    parser.add_argument("--summary-json", required=True, type=Path)
    parser.add_argument("--expected-label", default="PortScan")
    parser.add_argument("--source-pcap", type=Path)
    parser.add_argument("--batch-size", type=int, default=4096)
    args = parser.parse_args()
    if args.batch_size <= 0:
        parser.error("--batch-size must be positive")

    # Imported lazily so unit tests for validation and gate semantics do not
    # require ONNX Runtime on the Windows host.
    import numpy as np
    import onnxruntime as ort

    bundle = verify_bundle(args.bundle_dir)
    session = ort.InferenceSession(
        str(bundle["model_path"]), providers=["CPUExecutionProvider"]
    )
    input_name = session.get_inputs()[0].name
    output_names = [output.name for output in session.get_outputs()]
    if "probabilities" not in output_names:
        raise ValueError(f"ONNX probabilities output missing: {output_names}")

    diagnostics: dict[int, list[float]] = {
        index: [] for index in DIAGNOSTIC_FEATURES
    }
    decision_counts: Counter[str] = Counter()
    raw_counts: Counter[str] = Counter()
    candidate_counts: Counter[str] = Counter()
    total = 0
    correct = 0
    gate_passed = 0
    input_digest = hashlib.sha256()
    exporter_summary = None

    def records():
        nonlocal exporter_summary
        with args.input.open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                input_digest.update(raw)
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
                if record.get("kind") == "summary":
                    if exporter_summary is not None:
                        raise ValueError("multiple exporter summary records")
                    exporter_summary = record
                    continue
                if record.get("kind") != "terminal_flow":
                    raise ValueError(f"line {line_number}: unexpected kind")
                if record.get("feature_schema_id") != "nids.terminal_flow_features.v1":
                    raise ValueError(f"line {line_number}: unexpected feature schema")
                features = record.get("features")
                if not isinstance(features, list) or len(features) != 70:
                    raise ValueError(f"line {line_number}: expected 70 features")
                numeric = [float(value) for value in features]
                if not all(math.isfinite(value) for value in numeric):
                    raise ValueError(f"line {line_number}: non-finite feature")
                for index in diagnostics:
                    diagnostics[index].append(numeric[index])
                selected = [numeric[index] for index in bundle["selected_indices"]]
                yield record, selected

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output_jsonl.with_suffix(args.output_jsonl.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            for batch in batches(records(), args.batch_size):
                matrix = np.asarray([selected for _, selected in batch], dtype=np.float32)
                result = session.run(["probabilities"], {input_name: matrix})[0]
                if result.shape != (len(batch), len(bundle["class_order"])):
                    raise ValueError(f"unexpected probability shape: {result.shape}")
                for (record, _), probabilities in zip(batch, result, strict=True):
                    scored = decide(
                        probabilities,
                        bundle["class_order"],
                        bundle["benign_index"],
                        bundle["threshold"],
                    )
                    total += 1
                    correct += scored["decision"] == args.expected_label
                    gate_passed += scored["gate_passed"]
                    decision_counts[scored["decision"]] += 1
                    raw_counts[scored["raw_argmax"]] += 1
                    candidate_counts[scored["top_attack_candidate"]] += 1
                    evidence = {
                        "schema_version": "1.0.0",
                        "kind": "terminal_flow_offline_score",
                        "source_capture_id": record.get("capture_id"),
                        "source_export_ordinal": record.get("export_ordinal"),
                        "flow": {
                            "protocol": record.get("protocol"),
                            "low_ip": record.get("low_ip"),
                            "low_port": record.get("low_port"),
                            "high_ip": record.get("high_ip"),
                            "high_port": record.get("high_port"),
                            "generation": record.get("generation"),
                        },
                        **scored,
                    }
                    output.write(json.dumps(evidence, ensure_ascii=False, separators=(",", ":")))
                    output.write("\n")
        os.replace(temporary, args.output_jsonl)
    finally:
        if temporary.exists():
            temporary.unlink()

    if exporter_summary is None:
        raise ValueError("exporter summary record missing")
    exported_flows = exporter_summary.get("exported_flows")
    if exported_flows != total:
        raise ValueError(
            f"exporter summary mismatch: exported_flows={exported_flows}, scored={total}"
        )

    summary = {
        "schema_version": "1.0.0",
        "kind": "terminal_flow_offline_score_summary",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "input": {
            "path": str(args.input),
            "sha256": input_digest.hexdigest(),
            "rows": total,
            "exporter_summary": exporter_summary,
        },
        "source_pcap": (
            {"path": str(args.source_pcap), "sha256": sha256_file(args.source_pcap)}
            if args.source_pcap
            else None
        ),
        "bundle": {
            "path": str(args.bundle_dir),
            "manifest_sha256": bundle["manifest_sha256"],
            "model_sha256": sha256_file(bundle["model_path"]),
            "selected_profile": bundle["manifest"]["selected_profile"],
            "selected_feature_count": len(bundle["selected_indices"]),
            "threshold": bundle["threshold"],
            "class_order": bundle["class_order"],
        },
        "runtime": {
            "onnxruntime": ort.__version__,
            "numpy": np.__version__,
            "provider": "CPUExecutionProvider",
        },
        "expected_label": args.expected_label,
        "metrics": {
            "rows": total,
            "correct": correct,
            "accuracy": correct / total if total else None,
            "gate_passed": gate_passed,
            "attack_detection_rate": gate_passed / total if total else None,
            "decision_counts": dict(decision_counts),
            "raw_argmax_counts": dict(raw_counts),
            "top_attack_candidate_counts": dict(candidate_counts),
        },
        "diagnostic_feature_distributions": {
            DIAGNOSTIC_FEATURES[index]: distribution(values)
            for index, values in diagnostics.items()
        },
        "output": {
            "path": str(args.output_jsonl),
            "sha256": sha256_file(args.output_jsonl),
            "rows": total,
        },
        "test_partition": {
            "status": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_resolution_or_hash_reads": 0,
        },
    }
    args.summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_tmp = args.summary_json.with_suffix(args.summary_json.suffix + ".tmp")
    summary_tmp.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(summary_tmp, args.summary_json)
    print(json.dumps(summary["metrics"], ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
