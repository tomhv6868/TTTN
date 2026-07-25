from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


TASK = "T8.3/T8.4"
CHECKPOINTS = ("F3", "F5", "F7", "F9")
T74_T76_RECEIPT = "run_log/t7.4-t7.6/acceptance.json"
T74_T76_SHA256 = "3066a0d56eb2fe14f8c02279cc48d6fd222b72aaed37f3fd81e3e672f38a3498"
EXPECTED_REQUIREMENTS = (
    "joblib==1.5.2",
    "ml_dtypes==0.5.3",
    "numpy==2.2.5",
    "onnx==1.20.1",
    "protobuf==6.32.1",
    "pyarrow==23.0.1",
    "scikit-learn==1.7.2",
    "scipy==1.15.2",
    "skl2onnx==1.20.0",
    "typing_extensions==4.14.1",
)
EXPECTED_ARTIFACTS = {
    "run_log/t3.1/acceptance.json": "4a08454a0818b2665e2efd8c628db0e70f74f9f61da949185ec92cb9468522cd",
    "run_log/t3.5/acceptance.json": "ed2cf650f862fcd102f9ba872f650da4a4c476c6198ade37def05a4b93f25042",
    "run_log/t3.6/acceptance.json": "9e6249d65dfc7fab7a31d411c6fd27e18e3320edde0b823776d4261e31df69ca",
    "run_log/t4.2/acceptance.json": "720805a1cd25dab6b2129a125df1a65a3100d5ee891d0f40fc4742aac041b98d",
    "run_log/t4.3/acceptance.json": "88599430c7739f29e454d95f57c34a5c24974159359795bacad8bd0b3f48266c",
    "run_log/t4.4/acceptance.json": "691648e4b95f8e575ed032df43885aef7b97e7ff76e1df359568db293a69bc7c",
    "run_log/t4.5/acceptance.json": "ef94e26bcd04725b463466a34dc15bec58bce92dd75da3cae55881a89dea56d1",
    "run_log/t4.6/acceptance.json": "1b1d45a186b82a13d5d4f1958dc81dfa06efb8208b407497e69f0c1d3f43e42c",
    "run_log/t4.7-rf300/acceptance.json": "481a8d0793febeb8e0330a245ad73def04b86675f876008d5b5c93b0ec85dc4e",
    "run_log/t4.8/acceptance.json": "9bd14e7195c7affc8d7477939826a9fa5299f46a522cf71eecb02bdad6a3c086",
    "run_log/t5.1/acceptance.json": "fbd0ee96ac3a84a5f9caf8d30d80cf260cd25f3a5841b11fa2f5173c12320ace",
    "run_log/t5.3/acceptance.json": "1808f2ef433b0b239a5d8fca6cd829e0c42b22b971ed3b0889a5811ca834db90",
    "run_log/t6.1/acceptance.json": "bd3cb0d6c539cfb95a8eb015cc086615fb0c960b39443ebba604421fdb8949ea",
    "run_log/t6.1/thresholds.json": "82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4",
    "run_log/t7.3/acceptance.json": "da4df77a5b99efacaa5b0b228084a4d98677c29586d46fa0cb1355e80a143f26",
    T74_T76_RECEIPT: T74_T76_SHA256,
    "run_log/t8.1-t8.2/acceptance.json": "092c8ad88586eb16dd9b216aaf9cd610e8aa2909889b05d6f5e68badb43ed36e",
}
SEED_CONTRACTS = {
    "split": (
        "config/cicids2017-split-contract.json",
        ("known_protocol", "seed"),
        3607,
    ),
    "flow_rf": (
        "config/cicids2017-rf-baseline-contract.json",
        ("random_forest", "parameters", "random_state"),
        4202,
    ),
    "isolation_forest": (
        "config/cicids2017-anomaly-baseline-contract.json",
        ("isolation_forest", "parameters", "random_state"),
        4303,
    ),
    "oof_folds": (
        "config/cicids2017-oof-contract.json",
        ("folding", "seed"),
        4404,
    ),
    "oof_isolation_forest": (
        "config/cicids2017-oof-contract.json",
        ("isolation_forest", "random_state_formula"),
        "4404 + held_out_fold",
    ),
    "rf_stacker": (
        "config/cicids2017-rf-stacker-contract.json",
        ("random_forest", "parameters", "random_state"),
        4202,
    ),
    "known_family_rf": (
        "config/cicids2017-known-family-contract.json",
        ("random_forest", "parameters", "random_state"),
        4202,
    ),
    "loafo_bootstrap": (
        "config/cicids2017-model-acceptance-contract.json",
        ("primary_endpoint", "confidence_interval", "seed"),
        1729,
    ),
    "known_validation_bootstrap": (
        "config/cicids2017-model-acceptance-contract.json",
        ("known_validation", "bootstrap", "seed"),
        1729,
    ),
}
COMMAND_TARGETS = (
    "scripts/inventory_cicids2017.py",
    "scripts/build_t32_golden_dataset.py",
    "scripts/run_t33_flow_export_ubuntu.sh",
    "scripts/run_t33_join_windows.ps1",
    "scripts/run_t35_snapshot_replay_ubuntu.sh",
    "scripts/package_t35_parquet.py",
    "scripts/verify_t35_snapshot_dataset.py",
    "scripts/build_t36_splits.py",
    "scripts/verify_t36_splits.py",
    "scripts/audit_t37_rare_families.py",
    "python/nids_mvp/preprocessing.py",
    "python/nids_mvp/rf_baseline.py",
    "python/nids_mvp/anomaly_baseline.py",
    "python/nids_mvp/oof_meta_features.py",
    "python/nids_mvp/rf_stacker.py",
    "python/nids_mvp/known_family_rf.py",
    "python/nids_mvp/loafo.py",
    "python/nids_mvp/loafo_aggregate.py",
    "python/nids_mvp/model_acceptance.py",
    "python/nids_mvp/artifact_bundle.py",
    "python/nids_mvp/model_staging.py",
    "python/nids_mvp/threshold_calibration.py",
    "scripts/run_t85_live_sensor_ubuntu.sh",
    "scripts/kali_t85_golden_sender.py",
)


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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def nested_value(value: Mapping[str, Any], keys: Sequence[str]) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            raise ValueError(f"missing contract key: {'.'.join(keys)}")
        current = current[key]
    return current


def validate_speed_run_receipt(receipt: Mapping[str, Any]) -> None:
    expected_values = {
        ("task",): "T7.4-T7.6",
        ("status",): "accepted_for_speed_run_demo",
        ("scope", "formal_phase_7_acceptance"): False,
        ("t7_4_capacity", "baseline", "sustained_lower_bound_pps"): 5_000,
        ("t7_4_capacity", "baseline", "failed_upper_bound_pps"): 10_000,
        ("t7_4_capacity", "baseline", "maximum_precisely_located"): False,
        ("t7_4_capacity", "full_pipeline", "sustained_pps"): 1_800,
        ("t7_4_capacity", "full_pipeline", "cpu_percent"): 97.26216064946657,
        ("t7_4_capacity", "full_pipeline", "selected_stability_rate_pps"): 1_000,
        ("t7_5_system_benchmark", "full_pipeline_1800_pps", "flows_per_second"): 195.832,
        ("t7_5_system_benchmark", "full_pipeline_1800_pps", "port_imissed"): 0,
        ("t7_5_system_benchmark", "full_pipeline_1800_pps", "port_rx_nombuf"): 0,
        ("t7_5_system_benchmark", "alert_queue", "pressure_available"): False,
        ("t7_6_stability", "status"): "passed",
        ("t7_6_stability", "requested_duration_seconds"): 1_800,
        ("t7_6_stability", "sender_packets"): 1_800_000,
        ("t7_6_stability", "sender_observed_pps"): 999.982152981855,
        ("t7_6_stability", "ambient_or_nonbenchmark_packets"): 408,
        ("t7_6_stability", "parser_errors"): 202,
        ("t7_6_stability", "cpu_percent"): 54.2958976887289,
        ("t7_6_stability", "max_rss_kb"): 342_440,
        ("t7_6_stability", "max_rss_delta_vs_full_capacity_kb"): 64,
        ("t7_6_stability", "port_imissed"): 0,
        ("t7_6_stability", "port_rx_nombuf"): 0,
        ("t7_6_stability", "synthetic_benchmark_alerts_per_hour"): 703.9874356992259,
        ("t7_6_stability", "rollback_status"): "passed",
    }
    for keys, expected in expected_values.items():
        require(
            nested_value(receipt, keys) == expected,
            f"T7.4-T7.6 receipt drifted: {'.'.join(keys)}",
        )

    expected_latencies = {
        ("parse_latency_ms", "p50"): 0.000079,
        ("parse_latency_ms", "p95"): 0.000516,
        ("parse_latency_ms", "p99"): 0.000858,
        ("inference_latency_ms", "p50"): 4.771423,
        ("inference_latency_ms", "p95"): 6.358154,
        ("inference_latency_ms", "p99"): 8.317251,
        ("alert_latency_ms", "p50"): 4.514019,
        ("alert_latency_ms", "p95"): 6.020913,
        ("alert_latency_ms", "p99"): 7.026434,
    }
    benchmark = nested_value(
        receipt, ("t7_5_system_benchmark", "full_pipeline_1800_pps")
    )
    for keys, expected in expected_latencies.items():
        require(
            nested_value(benchmark, keys) == expected,
            f"T7.5 latency drifted: {'.'.join(keys)}",
        )


def verify_workspace(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    requirements_path = root / "config/reproducibility-requirements.txt"
    requirements = tuple(
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    require(requirements == EXPECTED_REQUIREMENTS, "reproducibility requirements drifted")

    artifacts: dict[str, Any] = {}
    documents: dict[str, Any] = {}
    for relative_path, expected_sha256 in EXPECTED_ARTIFACTS.items():
        path = root / relative_path
        require(path.is_file(), f"missing accepted artifact: {relative_path}")
        actual_sha256 = sha256_path(path)
        require(actual_sha256 == expected_sha256, f"artifact SHA-256 mismatch: {relative_path}")
        artifacts[relative_path] = {
            "sha256": actual_sha256,
            "size_bytes": path.stat().st_size,
        }
        documents[relative_path] = load_json(path)

    validate_speed_run_receipt(documents[T74_T76_RECEIPT])

    for target in COMMAND_TARGETS:
        require((root / target).is_file(), f"reproducibility command target missing: {target}")

    seeds: dict[str, Any] = {}
    for name, (relative_path, keys, expected) in SEED_CONTRACTS.items():
        contract = load_json(root / relative_path)
        observed = nested_value(contract, keys)
        require(observed == expected, f"seed contract drifted: {name}")
        seeds[name] = {
            "value": observed,
            "contract": relative_path,
            "contract_sha256": sha256_path(root / relative_path),
        }

    artifacts["config/reproducibility-requirements.txt"] = {
        "sha256": sha256_path(requirements_path),
        "size_bytes": requirements_path.stat().st_size,
    }
    return {"artifacts": artifacts, "seeds": seeds}, documents


def commands() -> dict[str, Any]:
    return {
        "environment_windows_powershell": [
            "py -3.13 -m venv .venv",
            r".\.venv\Scripts\python.exe -m pip install -r config\reproducibility-requirements.txt",
            r".\.venv\Scripts\python.exe -m pip install --no-deps -e .",
            r"$python = (Resolve-Path .\.venv\Scripts\python.exe).Path",
        ],
        "inventory_windows": [
            "& $python scripts/inventory_cicids2017.py",
            "& $python scripts/verify_t31_cicids2017_inventory.py validate "
            "--input run_log/t3.1/acceptance.json --rehash-sources",
        ],
        "dataset_cross_host": [
            "& $python scripts/build_t32_golden_dataset.py",
            "cd /mnt/hgfs/TTTN && bash scripts/run_t33_flow_export_ubuntu.sh",
            r"powershell -ExecutionPolicy Bypass -File scripts\run_t33_join_windows.ps1 -Mode All",
            r"powershell -ExecutionPolicy Bypass -File scripts\run_t33_join_windows.ps1 -Mode Finalize",
            "cd /mnt/hgfs/TTTN && bash scripts/run_t35_snapshot_replay_ubuntu.sh",
            "& $python scripts/package_t35_parquet.py",
            "& $python scripts/verify_t35_snapshot_dataset.py --write-outputs",
        ],
        "split_windows": [
            "& $python scripts/build_t36_splits.py",
            "& $python scripts/verify_t36_splits.py run",
            "& $python scripts/audit_t37_rare_families.py run",
        ],
        "train_windows": [
            "& $python -m nids_mvp.preprocessing run",
            "& $python -m nids_mvp.rf_baseline run",
            "& $python -m nids_mvp.anomaly_baseline run",
            "& $python -m nids_mvp.oof_meta_features run",
            "& $python -m nids_mvp.rf_stacker run",
            "& $python -m nids_mvp.known_family_rf run",
            "$families = (Get-Content config/cicids2017-loafo-contract.json -Raw "
            "| ConvertFrom-Json).family_scope.execute_in_order",
            "foreach ($family in $families) { & $python -m nids_mvp.loafo "
            "--contract config/cicids2017-loafo-rf300-contract.json --family $family; "
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }",
            "& $python -m nids_mvp.loafo_aggregate run",
            "& $python -m nids_mvp.model_acceptance run",
        ],
        "export_windows": [
            "& $python -m nids_mvp.artifact_bundle run",
            "& $python -m nids_mvp.threshold_calibration run",
        ],
        "offline_replay_ubuntu": [
            'cd /mnt/hgfs/TTTN && source "$HOME/.local/nids-toolchain/env.sh"',
            "PYTHONPATH=/mnt/hgfs/TTTN/python python3 -m nids_mvp.model_staging "
            "--project-root /mnt/hgfs/TTTN --checkpoint F9 "
            "--output-root /home/tom/.cache/nids-partial-flow/t5.2/bundles",
            "cmake --preset ubuntu-release -DNIDS_BUILD_DPDK=ON "
            "-DNIDS_BUILD_MODEL_RUNTIME=ON "
            "-DNIDS_T52_STAGED_BUNDLE=/home/tom/.cache/nids-partial-flow/t5.2/bundles/F9",
            "cmake --build --preset ubuntu-release --target nids_demo_replay nids_dpdk_live -j 2",
            '"$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay" '
            "--input run_log/t3.2/attack-tcp-f9.pcap "
            "--bundle /home/tom/.cache/nids-partial-flow/t5.2/bundles/F9 "
            "--max-records 9 --expect-records 9 --expect-f9 1 "
            "--thresholds run_log/t6.1/thresholds.json "
            "--thresholds-sha256 82c9732f2667498c48da84d6304a62ebca34ea3c419e925f2fecd6c3bb7979c4",
        ],
        "live_replay": {
            "ubuntu_sensor": [
                "cd /mnt/hgfs/TTTN",
                "bash scripts/run_t85_live_sensor_ubuntu.sh "
                "--bundle /home/tom/.cache/nids-partial-flow/t5.2/bundles/F9",
            ],
            "kali_sender_after_ready": [
                "cd /mnt/hgfs/TTTN",
                "sudo python3 -B scripts/kali_t85_golden_sender.py",
            ],
        },
        "benchmark": {
            "status": "accepted_for_speed_run_demo",
            "receipt": T74_T76_RECEIPT,
            "receipt_sha256": T74_T76_SHA256,
            "formal_phase_7_acceptance": False,
            "rerun_command": None,
            "validation_commands": [
                "python tests/test_t74_t76_speedrun_acceptance.py",
                "python scripts/build_t74_t76_speedrun_acceptance.py validate",
            ],
        },
    }


def percent(value: float) -> str:
    return f"{value * 100:.3f}%"


def vi_number(value: float | int, decimals: int = 0) -> str:
    rendered = f"{value:,.{decimals}f}"
    return rendered.replace(",", "_").replace(".", ",").replace("_", ".")


def render_report(
    t81: Mapping[str, Any],
    t61: Mapping[str, Any],
    t73: Mapping[str, Any],
    t74_t76: Mapping[str, Any],
    evidence: Mapping[str, Any],
    seeds: Mapping[str, Any],
    reproducibility_commands: Mapping[str, Any],
) -> str:
    lines = [
        "# Báo cáo bàn giao MVP NIDS partial-flow",
        "",
        "Trạng thái: **accepted_for_demo**. Hệ thống đã chạy trọn luồng packet → "
        "flow/checkpoint → native inference → decision → JSON alert trên VMware, "
        "nhưng chưa phải nghiệm thu hiệu năng production.",
        "",
        "## Kiến trúc và quyết định",
        "",
        "- Flow RF dùng flow features và ngưỡng `0.5`; nếu vượt ngưỡng, quyết định là "
        "`known_attack` và Known-family RF cung cấp nhãn ứng viên.",
        "- Nếu Flow RF không vượt ngưỡng, HBOS và Isolation Forest bỏ phiếu độc lập. "
        "Hai phiếu tạo `unknown_candidate`, một phiếu tạo `uncertain`, không phiếu tạo `benign`.",
        "- OOF anomaly meta-features chống leakage được dùng để huấn luyện RF Stacker. "
        "Stacker chỉ được giữ làm ablation vì gate cải thiện không đạt.",
        "",
        "## Kết quả LOAFO 9-family",
        "",
        "| Checkpoint | Flow RF known recall | Flow RF unknown recall | Flow RF FPR | "
        "Stacker unknown recall |",
        "|---|---:|---:|---:|---:|",
    ]
    for checkpoint in CHECKPOINTS:
        item = t81["detection_study"]["checkpoints"][checkpoint]
        flow = item["flow_rf"]
        stacker = item["rf_stacker"]
        lines.append(
            f"| {checkpoint} | {percent(flow['known_recall']['mean'])} | "
            f"{percent(flow['unknown_recall']['mean'])} | "
            f"{percent(flow['benign_fpr']['mean'])} | "
            f"{percent(stacker['unknown_recall']['mean'])} |"
        )
    selection = t81["model_selection"]
    f9_thresholds = t61["checkpoints"]["F9"]
    live = t73["paced_live_replay"]
    capacity = t74_t76["t7_4_capacity"]
    system_benchmark = t74_t76["t7_5_system_benchmark"]["full_pipeline_1800_pps"]
    stability = t74_t76["t7_6_stability"]
    lines.extend(
        [
            "",
            "Unknown recall trong bảng là tỷ lệ phát hiện trên family bị giữ lại của từng "
            "model, không phải tỷ lệ quyết định runtime mang nhãn `unknown_candidate`. "
            f"Với fusion đã hiệu chuẩn ở F9, macro unknown-candidate recall là "
            f"{percent(f9_thresholds['loafo']['macro_unknown_candidate_recall'])}; "
            "PortScan case study là 0%.",
            "",
            f"RF Stacker minus Flow RF có delta novel-F1 `{selection['primary_delta']:.6f}`, "
            f"CI95% `[{selection['ci95_low']:.6f}, {selection['ci95_high']:.6f}]`. "
            "Khoảng tin cậy cắt qua 0, do đó Flow RF vẫn là binary classifier chính.",
            "",
            "## Native và live demo",
            "",
            f"- Paced sender gửi `{live['sender_records']}` frame; F9 tạo "
            f"`{live['alerts']}` alert `known_attack`, candidate `{live['known_family']}`.",
            f"- Flow RF probability live: `{live['flow_attack_probability']:.10f}`; "
            f"pacing lateness tối đa `{live['sender_maximum_schedule_lateness_ns']} ns`.",
            f"- Adapter errors `{live['adapter_errors']}`, ingest errors `{live['ingest_errors']}`, "
            f"`port_imissed={live['port_imissed']}`, `port_rx_nombuf={live['port_rx_nombuf']}`.",
            "- Rollback retry đã pass; management connectivity được giữ.",
            "",
            "## Kết quả T7.4–T7.6 speed-run",
            "",
            f"- T7.4 baseline: `{vi_number(capacity['baseline']['sustained_lower_bound_pps'])} pps` "
            f"passed; `{vi_number(capacity['baseline']['failed_upper_bound_pps'])} pps` failed. "
            "Chỉ được công bố bracket `[5.000, 10.000) pps`; chưa tìm chính xác maximum.",
            f"- Full pipeline passed ở `{vi_number(capacity['full_pipeline']['sustained_pps'])} pps`, "
            f"CPU `{vi_number(capacity['full_pipeline']['cpu_percent'], 3)}%`; stability rate được khóa "
            f"ở `{vi_number(capacity['full_pipeline']['selected_stability_rate_pps'])} pps`.",
            f"- T7.5 tại 1.800 pps: `{vi_number(system_benchmark['flows_per_second'], 3)} flows/s`; "
            "Parse p50/p95/p99 `0,079/0,516/0,858 microsecond`; "
            "Inference p50/p95/p99 `4,771/6,358/8,317 ms`; "
            "Alert p50/p95/p99 `4,514/6,021/7,026 ms`; "
            f"`imissed={system_benchmark['port_imissed']}`, "
            f"`rx_nombuf={system_benchmark['port_rx_nombuf']}`.",
            f"- T7.6: 30 phút, `{vi_number(stability['sender_packets'])} packet`, sender "
            f"`{vi_number(stability['sender_observed_pps'], 3)} pps`, CPU "
            f"`{vi_number(stability['cpu_percent'], 3)}%`, max RSS "
            f"`{vi_number(stability['max_rss_kb'])} KiB`; "
            f"chỉ tăng `{stability['max_rss_delta_vs_full_capacity_kb']} KiB` so với lượt full "
            f"ngắn; DPDK drop=0 và rollback passed.",
            "- Mọi lượt dùng làm evidence đều rollback passed; NIC `ens160` đã về `vmxnet3`.",
            "",
            "## Tái lập",
            "",
            "Các lệnh build tạo evidence mới phải chạy trong workspace sạch vì các publisher "
            "từ chối ghi đè receipt đã tồn tại.",
        ]
    )
    for stage, stage_commands in reproducibility_commands.items():
        lines.extend(["", f"### {stage}", ""])
        if isinstance(stage_commands, list):
            lines.append("```text")
            lines.extend(stage_commands)
            lines.append("```")
        elif stage == "live_replay":
            for host, host_commands in stage_commands.items():
                lines.extend([f"`{host}`:", "", "```text", *host_commands, "```", ""])
        elif stage == "benchmark":
            lines.extend(
                [
                    f"`{stage_commands['status']}` từ receipt "
                    f"`{stage_commands['receipt']}` (`{stage_commands['receipt_sha256']}`). "
                    "Formal Phase 7 acceptance vẫn là `false`; không chạy lại benchmark.",
                    "",
                    "```text",
                    *stage_commands["validation_commands"],
                    "```",
                ]
            )
    lines.extend(["", "## Seed đã khóa", "", "| Thành phần | Seed/công thức | Contract |", "|---|---:|---|"])
    for name, item in seeds.items():
        lines.append(f"| `{name}` | `{item['value']}` | `{item['contract']}` |")
    lines.extend(
        [
            "",
            "## Giới hạn và cách diễn giải",
            "",
            "- `unknown_candidate` chỉ có nghĩa hai anomaly detector cùng vượt ngưỡng sau khi "
            "Flow RF không báo attack. Nó không đồng nghĩa với zero-day thực tế, không chứng minh "
            "CVE mới và không tự xác định attack family.",
            "- PortScan chưa được chứng minh ở runtime: case study sau calibration có recall 0%. "
            "Không được tuyên bố hệ thống hiện tại phát hiện được mọi lượt `nmap`.",
            "- Speed-run chạy trên VMware, vì vậy không phải bằng chứng hiệu năng production.",
            "- Stability dùng synthetic multi-flow TCP F9, không phải production traffic mix. "
            "Sensor thấy thêm 408 packet ngoài benchmark và có 202 parser errors, nên không được "
            "tuyên bố identity-level delivery của từng sender packet.",
            "- Alert queue pressure chưa có vì T6.5 async queue chưa được triển khai.",
            "- `703,99 alerts/hour` chỉ là synthetic benchmark alert rate; không thay thế "
            "alerts/hour của detection study T8.1.",
            "- CIC sample attacker-VM replay, automated isolated flow-count equality và "
            "automated feature-hash equality vẫn được hoãn trong T7.3.",
            "",
            "## Artifact chính",
            "",
            "| Artifact | SHA-256 |",
            "|---|---|",
        ]
    )
    for path in (
        "run_log/t3.5/acceptance.json",
        "run_log/t3.6/acceptance.json",
        "run_log/t4.8/acceptance.json",
        "run_log/t5.1/acceptance.json",
        "run_log/t5.3/acceptance.json",
        "run_log/t6.1/thresholds.json",
        "run_log/t7.3/acceptance.json",
        T74_T76_RECEIPT,
        "run_log/t8.1-t8.2/acceptance.json",
    ):
        lines.append(f"| `{path}` | `{evidence[path]['sha256']}` |")
    return "\n".join(lines) + "\n"


def validate_acceptance(receipt: Mapping[str, Any], report: str) -> None:
    require(receipt.get("task") == TASK, "wrong task")
    require(receipt.get("status") == "accepted_for_demo", "wrong status")
    require(
        receipt.get("reproducibility", {}).get("benchmark", {}).get("status")
        == "accepted_for_speed_run_demo",
        "speed-run benchmark acceptance missing",
    )
    require(
        receipt.get("reproducibility", {}).get("benchmark", {}).get("receipt_sha256")
        == T74_T76_SHA256,
        "speed-run receipt hash missing",
    )
    require(
        receipt.get("reproducibility", {})
        .get("benchmark", {})
        .get("formal_phase_7_acceptance")
        is False,
        "formal Phase 7 scope was overstated",
    )
    require("không đồng nghĩa với zero-day thực tế" in report, "zero-day disclaimer missing")
    require("[5.000, 10.000) pps" in report, "baseline bracket missing")
    require("195,832 flows/s" in report, "flow rate missing")
    require("0,079/0,516/0,858 microsecond" in report, "parse latency missing")
    require("4,771/6,358/8,317 ms" in report, "inference latency missing")
    require("4,514/6,021/7,026 ms" in report, "alert latency missing")
    require("identity-level delivery" in report and "202 parser errors" in report, "delivery limit missing")
    require("T6.5 async queue" in report, "alert queue limit missing")
    require("703,99 alerts/hour" in report and "detection study T8.1" in report, "alert rate limit missing")
    require(
        "synthetic multi-flow TCP F9" in report and "production traffic mix" in report,
        "traffic limitation missing",
    )
    require("VMware" in report and "hiệu năng production" in report, "VMware limit missing")
    require("PortScan" in report and "recall 0%" in report, "PortScan limit missing")


def write_text(path: Path, value: str, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as output:
            output.write(value)
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def build(root: Path, report_path: Path, output_path: Path, force: bool) -> dict[str, Any]:
    workspace, documents = verify_workspace(root)
    command_registry = commands()
    report = render_report(
        documents["run_log/t8.1-t8.2/acceptance.json"],
        documents["run_log/t6.1/thresholds.json"],
        documents["run_log/t7.3/acceptance.json"],
        documents[T74_T76_RECEIPT],
        workspace["artifacts"],
        workspace["seeds"],
        command_registry,
    )
    write_text(report_path, report, force)
    receipt = {
        "schema_version": "1.0.0",
        "task": TASK,
        "kind": "demo_reproducibility_and_final_report_acceptance",
        "status": "accepted_for_demo",
        "mode": "demo_critical_path",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "reproducibility": {
            "status": "documented_with_speed_run_evidence",
            "requirements": workspace["artifacts"]["config/reproducibility-requirements.txt"],
            "seeds": workspace["seeds"],
            "commands": command_registry,
            "benchmark": command_registry["benchmark"],
        },
        "final_report": {
            "path": report_path.relative_to(root).as_posix(),
            "sha256": sha256_path(report_path),
            "size_bytes": report_path.stat().st_size,
            "language": "vi",
        },
        "limitations": {
            "unknown_candidate_is_zero_day": False,
            "vmware_is_production_performance_evidence": False,
            "formal_phase_7_acceptance": False,
            "speed_run_capacity_evidence_available": True,
            "speed_run_system_benchmark_available": True,
            "speed_run_stability_test_completed": True,
            "baseline_maximum_precisely_located": False,
            "identity_level_sender_delivery_proven": False,
            "alert_queue_pressure_available": False,
            "synthetic_benchmark_alert_rate_available": True,
            "detection_study_alerts_per_hour_available": False,
        },
        "deferred_for_demo": [
            "formal Phase 7 acceptance",
            "precise baseline maximum",
            "T6.5 asynchronous alert queue pressure",
            "T8.1 detection-study alerts/hour",
            "CIC sample attacker-VM replay",
            "automated isolated flow-count equality",
            "automated feature-hash equality",
        ],
        "evidence": workspace["artifacts"],
        "validation": {
            "all_artifact_hashes_verified": True,
            "all_seed_contracts_verified": True,
            "all_command_targets_exist": True,
            "requirements_versions_match_accepted_runtime": True,
            "speed_run_receipt_hash_verified": True,
            "speed_run_receipt_contract_verified": True,
            "zero_day_disclaimer_present": True,
            "vmware_limitations_present": True,
        },
    }
    validate_acceptance(receipt, report)
    write_text(
        output_path,
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
        force,
    )
    return receipt


def validate(root: Path, report_path: Path, input_path: Path) -> dict[str, Any]:
    receipt = load_json(input_path)
    report = report_path.read_text(encoding="utf-8")
    validate_acceptance(receipt, report)
    require(sha256_path(report_path) == receipt["final_report"]["sha256"], "report hash mismatch")
    for relative_path, record in receipt["evidence"].items():
        path = root / relative_path
        require(path.is_file(), f"evidence missing: {relative_path}")
        require(sha256_path(path) == record["sha256"], f"evidence drifted: {relative_path}")
    validate_speed_run_receipt(load_json(root / T74_T76_RECEIPT))
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "validate"))
    parser.add_argument("--report", type=Path, default=root / "docs/final-report.vi.md")
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "run_log/t8.3-t8.4/acceptance.json",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            receipt = build(root, args.report.resolve(), args.output.resolve(), args.force)
        else:
            receipt = validate(root, args.report.resolve(), args.output.resolve())
        print(f"[{TASK}] status={receipt['status']} report={receipt['final_report']['path']}")
        return 0
    except (KeyError, OSError, ValueError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
