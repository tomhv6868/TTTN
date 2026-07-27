#!/usr/bin/env python3
"""Build thesis-ready evidence explaining Terminal V1 offline limitations."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OFFLINE_ROOT = ROOT / "run_log/full-flow-v1/matched-terminal-20260809/offline"
MODEL_MANIFEST = ROOT / "run_log/full-flow-v1/model/manifest.json"
OUTPUT_ROOT = ROOT / "run_log/full-flow-v1/thesis-evidence"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def build() -> dict:
    manifest = read_json(MODEL_MANIFEST)
    rows = []
    for path in sorted(OFFLINE_ROOT.glob("*/summary.json")):
        summary = read_json(path)
        metrics = summary["metrics"]
        rows.append(
            {
                "case": path.parent.name,
                "expected_label": summary["expected_label"],
                "rows": metrics["rows"],
                "correct": metrics["correct"],
                "correct_rate": metrics["accuracy"],
                "decision_counts": metrics["decision_counts"],
                "raw_argmax_counts": metrics["raw_argmax_counts"],
                "top_attack_candidate_counts": metrics["top_attack_candidate_counts"],
                "source": rel(path),
                "source_sha256": sha256(path),
            }
        )
    by_case = {row["case"]: row for row in rows}
    supporting_paths = [
        MODEL_MANIFEST,
        ROOT / "run_log/full-flow-v1/family-windows/cut-logs/infiltration.log",
        ROOT / "run_log/full-flow-v1/family-windows/cut-logs/web-sql-injection.log",
        ROOT / "docs/dataset/cicids2017-splits.vi.md",
        *sorted(OFFLINE_ROOT.glob("*/summary.json")),
    ]
    return {
        "schema_version": "1.0.0",
        "kind": "terminal_v1_offline_limitations_evidence",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "current_tag": "t91-terminal-offline-limitations-evidence-r1",
        "question": "Why is Terminal V1 offline coverage/performance not complete?",
        "model_contract": {
            "output_labels": manifest["labels"]["class_order"],
            "target_families": manifest["labels"]["target_families"],
            "selected_threshold": manifest["selection"]["selected_threshold"],
            "training_family_counts": manifest["population"]["family_counts"]["train"],
            "validation_family_counts": manifest["population"]["family_counts"]["validation"],
            "selected_profile": manifest["selection"]["selected_profile"],
            "selected_feature_count": manifest["selection"]["selected_feature_count"],
            "source": rel(MODEL_MANIFEST),
            "source_sha256": sha256(MODEL_MANIFEST),
        },
        "observed_examples": {
            "portscan": by_case["portscan"],
            "ddos": by_case["ddos"],
            "web_brute_force": by_case["web-brute-force"],
            "web_sql_injection": by_case["web-sql-injection"],
            "web_xss": by_case["web-xss"],
            "infiltration": by_case["infiltration"],
        },
        "causes": [
            {
                "id": "high_binary_attack_gate",
                "status": "directly_evidenced",
                "finding": (
                    "The final decision is not raw multiclass argmax. A flow is attack only "
                    "when 1-P(Benign) reaches the locked 0.9984837643022101 threshold; "
                    "otherwise it becomes Benign. This removes many attack candidates."
                ),
                "examples": {
                    "portscan_raw_argmax_portscan": 84217,
                    "portscan_final_portscan": 82414,
                    "ddos_top_attack_candidate_dos": 15763,
                    "ddos_final_dos": 10725,
                    "web_sql_raw_argmax_other": 13,
                    "web_sql_final_other": 10,
                },
            },
            {
                "id": "coarse_six_label_taxonomy",
                "status": "directly_evidenced",
                "finding": (
                    "The locked model has six output labels. Bot, Infiltration and the three "
                    "Web Attack families are intentionally merged into Other; all DDoS/DoS "
                    "variants are merged into DoS. Offline therefore cannot identify every "
                    "original CICIDS family by name."
                ),
            },
            {
                "id": "severe_training_support_imbalance",
                "status": "directly_evidenced",
                "finding": (
                    "Training support is highly imbalanced: Other has 576 rows versus "
                    "1,296,000 Benign, 223,314 DoS and 77,709 PortScan rows. Class weighting "
                    "is enabled, but it cannot create missing behavioral diversity."
                ),
            },
            {
                "id": "demo_target_selection",
                "status": "directly_evidenced",
                "finding": (
                    "The locked selection contract names only FTP-Bruteforce and PortScan as "
                    "target families. Aggregate validation metrics do not guarantee equal "
                    "performance for every family later collapsed into Other or DoS."
                ),
            },
            {
                "id": "family_window_not_full_capture",
                "status": "directly_evidenced",
                "finding": (
                    "The measurement uses densest family windows, normally 180 seconds, not "
                    "the complete CICIDS capture. Oracle CSV rows, unique directional keys and "
                    "Terminal bidirectional flow generations are different counting units."
                ),
                "examples": {
                    "infiltration": {
                        "oracle_rows": 36,
                        "unique_directional_keys": 6,
                        "terminal_exported_flows": 3,
                        "cut_packets": 22856,
                        "cut_span_seconds": 180,
                        "source": "run_log/full-flow-v1/family-windows/cut-logs/infiltration.log",
                    },
                    "web_sql_injection": {
                        "oracle_rows": 21,
                        "unique_directional_keys": 12,
                        "terminal_exported_flows": 13,
                        "cut_packets": 126,
                        "cut_span_seconds": 168,
                        "source": "run_log/full-flow-v1/family-windows/cut-logs/web-sql-injection.log",
                    },
                },
            },
            {
                "id": "heartbleed_unavailable",
                "status": "directly_evidenced",
                "finding": (
                    "Heartbleed is absent from Terminal V1 because the accepted snapshot stage "
                    "contains zero Heartbleed snapshots; adding it now would require a new "
                    "dataset/model version, not merely another replay."
                ),
                "source": "docs/dataset/cicids2017-splits.vi.md",
            },
            {
                "id": "unproven_feature_level_cause",
                "status": "not_established",
                "finding": (
                    "The evidence does not isolate one specific feature as the cause of Web "
                    "Attack errors. The poor raw argmax for Web Brute Force and XSS proves the "
                    "high gate is not the only cause, but feature-level attribution would need "
                    "a separate ablation/error-analysis experiment."
                ),
            },
        ],
        "offline_rows": rows,
        "supporting_sources": [
            {
                "path": rel(path),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in supporting_paths
        ],
        "test_partition": {
            "status": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_resolution_or_hash_reads": 0,
        },
    }


def markdown(doc: dict) -> str:
    counts = doc["model_contract"]["training_family_counts"]
    lines = [
        "# Bằng chứng giải thích giới hạn kết quả offline của Terminal V1",
        "",
        "## Kết luận có thể dùng trong luận văn",
        "",
        "Kết quả offline chưa đầy đủ không có nghĩa là chương trình chỉ hỗ trợ hai hoặc ba loại "
        "tấn công. Terminal V1 sử dụng sáu nhãn đầu ra; nhiều họ CICIDS gốc được chủ động gom "
        "vào `DoS` hoặc `Other`. Tỷ lệ đúng dưới 100% đến từ cả ngưỡng phát hiện tấn công rất "
        "cao, dữ liệu huấn luyện mất cân bằng và phạm vi PCAP family-window không phải toàn bộ "
        "capture. Riêng lỗi của Web Brute Force và XSS đã xuất hiện từ raw argmax, vì vậy không "
        "thể quy toàn bộ sai số cho ngưỡng quyết định.",
        "",
        "## Bằng chứng định lượng",
        "",
        f"- Model bị khóa ở ngưỡng `attack_score >= {doc['model_contract']['selected_threshold']}`. "
        "Flow dưới ngưỡng bị trả về `Benign` dù lớp tấn công có xác suất cao nhất.",
        "- PortScan: raw argmax có 84.217 flow PortScan nhưng quyết định cuối còn 82.414; "
        "DDoS có 15.763 top candidate DoS nhưng chỉ 10.725 quyết định DoS.",
        "- Web SQL Injection: 13/13 raw argmax là `Other`, sau gate còn 10/13. Ngược lại, "
        "Web Brute Force chỉ 13/112 raw argmax `Other` và XSS chỉ 3/105; đây là sai số "
        "phân lớp trước gate.",
        f"- Hỗ trợ train: Benign {counts['Benign']:,}, DoS {counts['DoS']:,}, PortScan "
        f"{counts['PortScan']:,}, FTP {counts['FTP-Bruteforce']:,}, SSH "
        f"{counts['SSH-Bruteforce']:,}, Other chỉ {counts['Other']:,} row.",
        "- Contract chọn model chỉ đặt `FTP-Bruteforce` và `PortScan` là target family; "
        "metric validation tổng hợp không bảo đảm từng họ con trong `Other` đều tốt.",
        "- Infiltration: oracle có 36 row và 6 directional key trong cửa sổ 180 giây, "
        "nhưng Terminal xuất 3 bidirectional flow generation. SQL Injection: 21 oracle row, "
        "12 key và 13 Terminal flow. Các số này không cùng đơn vị nên không được gọi là mất flow "
        "chỉ dựa trên chênh lệch số đếm.",
        "- Heartbleed không có snapshot trong dataset Terminal được chấp nhận, nên không nằm "
        "trong model V1. Muốn bổ sung phải tạo dataset/model version mới.",
        "",
        "## Điều chưa được phép kết luận",
        "",
        "Evidence hiện tại chưa chứng minh một feature cụ thể gây lỗi Web Attack. Muốn kết luận "
        "ở mức feature phải chạy thêm ablation/error analysis; không được suy diễn từ accuracy.",
        "Kết quả chỉ có giá trị trong phạm vi phòng thí nghiệm VMware và family-window PCAP.",
        "",
        "## Nguồn evidence",
        "",
        "- `run_log/full-flow-v1/model/manifest.json`",
        "- `run_log/full-flow-v1/matched-terminal-20260809/offline/*/summary.json`",
        "- `run_log/full-flow-v1/family-windows/cut-logs/infiltration.log`",
        "- `run_log/full-flow-v1/family-windows/cut-logs/web-sql-injection.log`",
        "- `docs/dataset/cicids2017-splits.vi.md`",
        "- Phân vùng test vẫn sealed, mọi bộ đếm đọc bằng 0.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    document = build()
    json_path = OUTPUT_ROOT / "terminal-offline-limitations-20260809.json"
    md_path = OUTPUT_ROOT / "terminal-offline-limitations-20260809.md"
    json_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown(document), encoding="utf-8")
    print(json_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
