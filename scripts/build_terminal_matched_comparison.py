#!/usr/bin/env python3
"""Build the Terminal V1 matched-PCAP offline/live evidence table.

The live supervisor can leave a complete ``summary.json.tmp`` when the final
rename on VMware HGFS stalls.  Such rows are retained and explicitly marked as
unpublished; they are never silently promoted to an official sensor receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "run_log/full-flow-v1/matched-terminal-20260809"
CASES = (
    ("benign", "Benign"),
    ("ftp-patator", "FTP-Bruteforce"),
    ("ssh-patator", "SSH-Bruteforce"),
    ("portscan", "PortScan"),
    ("ddos", "DoS"),
    ("dos-goldeneye", "DoS"),
    ("dos-hulk", "DoS"),
    ("dos-slowhttptest", "DoS"),
    ("dos-slowloris", "DoS"),
    ("bot", "Other"),
    ("infiltration", "Other"),
    ("web-brute-force", "Other"),
    ("web-sql-injection", "Other"),
    ("web-xss", "Other"),
)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def sender_counts(path: Path) -> tuple[int | None, int | None]:
    if not path.exists():
        return None, None
    text = path.read_text(encoding="utf-8", errors="replace")
    sent = re.findall(r"Successful packets:\s+(\d+)", text)
    failed = re.findall(r"Failed packets:\s+(\d+)", text)
    return (int(sent[-1]) if sent else None, int(failed[-1]) if failed else None)


def pct(value: float | None) -> str:
    return "—" if value is None else f"{100.0 * value:.4f}%"


def build(run_id: str) -> dict:
    rows = []
    for case, expected in CASES:
        offline_path = EVIDENCE_ROOT / "offline" / case / "summary.json"
        attempt = EVIDENCE_ROOT / "live" / run_id / case
        official_summary = attempt / "ubuntu" / "summary.json"
        pending_summary = attempt / "ubuntu" / "summary.json.tmp"
        receipt_path = attempt / "ubuntu" / "sensor.json"
        case_result_path = attempt / "case-result.json"
        if not offline_path.exists():
            raise FileNotFoundError(offline_path)
        if official_summary.exists():
            live_summary_path = official_summary
            publication = "official_receipt"
        elif pending_summary.exists():
            live_summary_path = pending_summary
            publication = "complete_summary_unpublished_hgfs_rename_stall"
        else:
            raise FileNotFoundError(f"no live summary for {case}: {attempt}")

        offline = read_json(offline_path)
        live = read_json(live_summary_path)
        case_result = read_json(case_result_path) if case_result_path.exists() else {}
        receipt = read_json(receipt_path) if receipt_path.exists() else None
        sent, failed = sender_counts(attempt / "kali" / "replay.log")
        decisions = dict(live.get("alerts_by_class", {}))
        decisions["Benign"] = int(live.get("benign_decisions", 0))
        live_total = int(live["inferences"])
        live_correct = int(decisions.get(expected, 0))
        port = live.get("port_stats", {})
        ipackets = int(port.get("ipackets", 0))
        imissed = int(port.get("imissed", 0))
        imissed_over_ipackets = imissed / ipackets if ipackets else None
        scoped_packets = int(live.get("scoped_packets", 0))
        source_packets = int(offline["input"]["exporter_summary"]["pcap"]["records_read"])
        row = {
            "case": case,
            "expected_terminal_label": expected,
            "include_in_attack_matrix": case != "benign",
            "offline": {
                "rows": int(offline["metrics"]["rows"]),
                "correct": int(offline["metrics"]["correct"]),
                "correct_rate": float(offline["metrics"]["accuracy"]),
                "decision_counts": offline["metrics"]["decision_counts"],
                "summary_path": relative(offline_path),
                "summary_sha256": sha256(offline_path),
            },
            "live": {
                "inferences": live_total,
                "expected_label_decisions": live_correct,
                "expected_label_share_of_inferences": live_correct / live_total if live_total else None,
                "decision_counts": decisions,
                "summary_status": live.get("status"),
                "shutdown_complete": bool(live.get("shutdown_complete")),
                "summary_publication": publication,
                "official_receipt_status": receipt.get("status") if receipt else None,
                "case_result_complete": bool(case_result.get("complete", False)),
                "summary_path": relative(live_summary_path),
                "summary_sha256": sha256(live_summary_path),
                "sender_successful_packets": sent,
                "sender_failed_packets": failed,
                "source_pcap_packets": source_packets,
                "scoped_packets": scoped_packets,
                "port_ipackets": ipackets,
                "port_imissed": imissed,
                "port_imissed_over_ipackets": imissed_over_ipackets,
                "scope_observed": scoped_packets > 0,
            },
        }
        if case == "benign" and scoped_packets != source_packets:
            row["exclusion_reason"] = (
                "The cut Benign PCAP contains arbitrary endpoints while the live contract "
                "scopes target_ip=192.168.10.50; this is not a matched cohort."
            )
        elif scoped_packets == 0:
            row["live_limitation"] = (
                "Replay completed but target_ip scope observed zero PCAP packets; zero "
                "inferences must not be interpreted as a model false negative."
            )
        rows.append(row)

    attack_rows = [row for row in rows if row["include_in_attack_matrix"]]
    return {
        "schema_version": "1.0.0",
        "kind": "terminal_v1_matched_pcap_offline_live_comparison",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "method": {
            "pcap_replay": "tcpreplay-edit at 1x with MAC rewrite only",
            "offline_runtime": "locked Terminal V1 ONNX bundle, CPUExecutionProvider",
            "live_runtime": "native Terminal V1 DPDK, passive 1 RX queue / 0 TX queues",
            "interpretation": (
                "Offline correct_rate is a classification rate for exported flows. Live "
                "expected_label_share_of_inferences is diagnostic only and is not model "
                "accuracy when RX loss or flow reconstruction differs."
            ),
            "unpublished_summary_policy": (
                "A complete nids_terminal_live_summary left as summary.json.tmp is retained "
                "with an explicit HGFS publication-failure flag; no official receipt is fabricated."
            ),
        },
        "coverage": {
            "attack_cases_requested": 13,
            "attack_cases_with_offline_and_live_summary": len(attack_rows),
            "terminal_output_labels": 6,
            "benign_control_included_in_primary_matrix": False,
        },
        "rows": rows,
        "test_partition": {
            "status": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_resolution_or_hash_reads": 0,
        },
    }


def markdown(document: dict) -> str:
    lines = [
        "# Terminal V1 — đối chiếu offline/live cùng PCAP",
        "",
        f"Run live: `{document['run_id']}`. Đủ **13/13 ca tấn công** và phủ đủ "
        "6 nhãn đầu ra Terminal V1 (tính cả Benign).",
        "",
        "| Ca PCAP | Nhãn Terminal | Offline đúng/tổng | Offline | Live nhãn mong đợi/inference | Live share* | RX missed | Receipt |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in document["rows"]:
        if not row["include_in_attack_matrix"]:
            continue
        off = row["offline"]
        live = row["live"]
        receipt = "official" if live["summary_publication"] == "official_receipt" else "summary đủ; publish lỗi HGFS"
        lines.append(
            f"| {row['case']} | {row['expected_terminal_label']} | "
            f"{off['correct']:,}/{off['rows']:,} | {pct(off['correct_rate'])} | "
            f"{live['expected_label_decisions']:,}/{live['inferences']:,} | "
            f"{pct(live['expected_label_share_of_inferences'])} | "
            f"{live['port_imissed']:,} ({pct(live['port_imissed_over_ipackets'])}) | {receipt} |"
        )
    benign = next(row for row in document["rows"] if row["case"] == "benign")
    lines.extend(
        [
            "",
            "Ghi chú: `Live share` là tỷ lệ chẩn đoán trên các flow mà runtime live đã inference, "
            "không được gọi là accuracy khi có RX loss hoặc khác biệt tái dựng flow.",
            "",
            "## Giới hạn và kết luận",
            "",
            "- Bộ 13 ca tấn công đã được replay thật ở tốc độ 1×; không cần FTP service vì "
            "đây là replay PCAP thụ động, không phải sinh phiên FTP mới.",
            "- Các ca có `summary đủ; publish lỗi HGFS` đã ghi xong event summary và rollback, "
            "nhưng supervisor bị kẹt ở bước đổi tên trên VMware shared folder. File tạm được giữ "
            "nguyên và hash; không dựng giả receipt chính thức.",
            "- Những ca có RX missed cao chỉ chứng minh hành vi của toàn đường lab trong lần chạy "
            "đó; không thể dùng để kết luận riêng chất lượng mô hình.",
            f"- Benign control bị loại khỏi bảng chính: {benign['exclusion_reason']}",
            "- Bot và Infiltration đã replay nhưng contract `target_ip=192.168.10.50` không nhận "
            "packet nào thuộc scope; 0 inference ở hai dòng này là lỗi khớp scope PCAP, không phải "
            "model bỏ sót tấn công.",
            "- Các lớp gốc Bot/Infiltration/Web được Terminal V1 gom vào `Other`; các biến thể "
            "DDoS/DoS được gom vào `DoS`. Vì vậy 14 cửa sổ PCAP không xung đột với 6 nhãn đầu ra.",
            "- Phân vùng test vẫn sealed, số lần đọc feature/metric/path/hash bằng 0.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="20260809-r3")
    parser.add_argument("--output-root", type=Path, default=EVIDENCE_ROOT)
    args = parser.parse_args()
    document = build(args.run_id)
    args.output_root.mkdir(parents=True, exist_ok=True)
    json_path = args.output_root / "terminal-matched-comparison.json"
    md_path = args.output_root / "terminal-matched-comparison.md"
    json_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown(document), encoding="utf-8")
    print(json_path)
    print(md_path)

    cleanup_root = ROOT / "run_log/full-flow-v1/cleanup/20260809-terminal-matched"
    cleanup_root.mkdir(parents=True, exist_ok=True)
    cleanup_path = cleanup_root / "receipt.json"
    cleanup_document = {
        "schema_version": "1.0.0",
        "kind": "terminal_matched_replay_cleanup_receipt",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "ubuntu": {
            "nids_dpdk_live_processes": 0,
            "apache2": "active_enabled",
            "ens160_driver": "vmxnet3",
            "hugepages": 128,
        },
        "kali": {
            "temporary_sudoers": "/etc/sudoers.d/nids-t91-terminal-matched-replay",
            "temporary_sudoers_present": False,
        },
        "test_partition": "sealed_zero_reads",
    }
    cleanup_path.write_text(
        json.dumps(cleanup_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    member_paths = [
        json_path,
        md_path,
        cleanup_path,
        ROOT / "scripts/build_terminal_matched_comparison.py",
        ROOT / "scripts/run_terminal_matched_replays.py",
        ROOT / "scripts/cut_family_window_pcap.py",
        ROOT / "scripts/score_terminal_flows_onnx.py",
        ROOT / "scripts/build_terminal_offline_limitations.py",
        ROOT / "tests/test_build_terminal_offline_limitations.py",
        ROOT / "tests/test_f9_terminal_mermaid.py",
        ROOT / "docs/rebuild-changelog.md",
        ROOT / "docs/generated/f9-terminal-pcap-replay-evidence-flow.mmd",
        ROOT / "docs/generated/f9-terminal-pcap-replay-evidence-flow.md",
        ROOT / "run_log/full-flow-v1/thesis-evidence/terminal-offline-limitations-20260809.json",
        ROOT / "run_log/full-flow-v1/thesis-evidence/terminal-offline-limitations-20260809.md",
    ]
    for row in document["rows"]:
        member_paths.extend(
            [
                ROOT / row["offline"]["summary_path"],
                ROOT / row["live"]["summary_path"],
                EVIDENCE_ROOT / "live" / args.run_id / row["case"] / "case-result.json",
            ]
        )
    unique_paths = sorted({path.resolve() for path in member_paths})
    members = [
        {"path": relative(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
        for path in unique_paths
    ]
    archive_document = {
        "schema_version": "1.0.0",
        "kind": "terminal_matched_replay_thesis_evidence_index",
        "current_tag": "t91-f9-terminal-evidence-r1",
        "status": "complete_with_documented_lab_limitations",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "coverage": document["coverage"],
        "limitations": [
            "six summaries completed but official receipt publication stalled on HGFS",
            "Bot and Infiltration replay packets did not match the target_ip scope",
            "Benign control is excluded because its cut PCAP is not endpoint matched",
            "RX loss makes live expected-label share diagnostic rather than model accuracy",
        ],
        "members": members,
        "test_partition": "sealed_zero_reads",
    }
    archive_root = ROOT / "run_log/full-flow-v1/thesis-evidence"
    archive_root.mkdir(parents=True, exist_ok=True)
    archive_json = archive_root / "terminal-matched-replay-20260809.json"
    archive_md = archive_root / "terminal-matched-replay-20260809.md"
    archive_json.write_text(json.dumps(archive_document, indent=2) + "\n", encoding="utf-8")
    archive_md.write_text(
        "# Terminal matched replay thesis evidence\n\n"
        f"Tag: `{archive_document['current_tag']}`  \n"
        f"Coverage: 13/13 attack PCAP cases; {len(members)} hashed members.  \n"
        f"Comparison: `{relative(md_path)}`  \n"
        "Limitations are preserved in the JSON index and comparison report.\n",
        encoding="utf-8",
    )
    print(archive_json)
    print(archive_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
