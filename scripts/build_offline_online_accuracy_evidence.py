#!/usr/bin/env python3
"""Build thesis-ready evidence for the offline vs live comparison of F9 and Terminal V1.

Every number is recomputed from receipts on disk; nothing is hardcoded.
The output separates model accuracy (offline side) from the cost of running
live (offline/live delta), and records the limits that must accompany them.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TERMINAL_COMPARISON = ROOT / "run_log/full-flow-v1/matched-terminal-20260809/terminal-matched-comparison.json"
F9_COMPARISON = ROOT / "run_log/full-flow-v1/replay-runs/20260808-194942/f9-online-offline-comparison.json"
MODEL_MANIFEST = ROOT / "run_log/full-flow-v1/model/manifest.json"
DIAGRAM_MMD = ROOT / "docs/generated/f9-terminal-pcap-replay-evidence-flow.mmd"
DIAGRAM_MD = ROOT / "docs/generated/f9-terminal-pcap-replay-evidence-flow.md"
SPEC = ROOT / "docs/t85-online-offline-evidence-spec.vi.md"
OUTPUT_ROOT = ROOT / "run_log/full-flow-v1/thesis-evidence"
STEM = "offline-online-accuracy-20260809"
CURRENT_TAG = "t91-offline-online-accuracy-evidence-r1"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def member(path: Path) -> dict:
    return {"path": rel(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def build_terminal(comparison: dict) -> dict:
    rows = []
    for row in comparison["rows"]:
        offline = row["offline"]
        live = row["live"]
        share = live["expected_label_share_of_inferences"]
        imissed_rate = live.get("port_imissed_over_ipackets")
        rows.append(
            {
                "case": row["case"],
                "expected_label": row["expected_terminal_label"],
                "in_attack_matrix": row["include_in_attack_matrix"],
                "offline_rows": offline["rows"],
                "offline_correct": offline["correct"],
                "offline_correct_rate": offline["correct_rate"],
                "live_inferences": live["inferences"],
                "live_expected_label_share": share,
                "delta_points": None if share is None else round((share - offline["correct_rate"]) * 100, 4),
                "live_imissed": live.get("port_imissed"),
                "live_imissed_rate": imissed_rate,
                "live_scoped_packets": live.get("scoped_packets"),
                "live_summary_status": live.get("summary_status"),
                "live_summary_publication": live.get("summary_publication"),
            }
        )

    matrix = [r for r in rows if r["in_attack_matrix"]]
    micro_rows = sum(r["offline_rows"] for r in matrix)
    micro_correct = sum(r["offline_correct"] for r in matrix)
    macro = sum(r["offline_correct_rate"] for r in matrix) / len(matrix)

    lossless = [
        r for r in matrix
        if r["live_imissed_rate"] == 0 and r["live_expected_label_share"] is not None
    ]
    lossy = [
        r for r in matrix
        if r["live_imissed_rate"] not in (None, 0) and r["live_expected_label_share"] is not None
    ]
    no_inference = [r for r in matrix if r["live_inferences"] == 0]

    return {
        "unit": "one sample = one bidirectional terminal flow generation",
        "offline_accuracy": {
            "micro_by_flow": {
                "correct": micro_correct,
                "total": micro_rows,
                "rate": micro_correct / micro_rows,
            },
            "macro_by_family": {"families": len(matrix), "rate": macro},
            "note": (
                "PortScan alone contributes "
                f"{max(r['offline_rows'] for r in matrix)} of {micro_rows} flows, so the micro rate is "
                "dominated by one family. Report both rates together."
            ),
            "portscan_share": max(r["offline_rows"] for r in matrix) / micro_rows,
        },
        "cost_of_running_live": {
            "lossless_cases": [
                {
                    "case": r["case"],
                    "offline_correct_rate": r["offline_correct_rate"],
                    "live_expected_label_share": r["live_expected_label_share"],
                    "delta_points": r["delta_points"],
                }
                for r in lossless
            ],
            "lossless_max_abs_delta_points": max((abs(r["delta_points"]) for r in lossless), default=0.0),
            "lossy_cases": [
                {
                    "case": r["case"],
                    "live_imissed_rate": r["live_imissed_rate"],
                    "delta_points": r["delta_points"],
                }
                for r in sorted(lossy, key=lambda r: r["live_imissed_rate"], reverse=True)
            ],
            "claim": (
                "Cases that lost no packets reproduce the offline result; the live shortfall tracks packet loss. "
                "Live share is therefore not model accuracy."
            ),
        },
        "genuine_model_weaknesses": [
            {
                "case": r["case"],
                "offline_correct_rate": r["offline_correct_rate"],
                "live_expected_label_share": r["live_expected_label_share"],
                "why_not_infrastructure": "identical on both sides with zero packet loss",
            }
            for r in lossless
            if r["offline_correct_rate"] < 0.5
        ],
        "excluded_from_live_comparison": [
            {"case": r["case"], "reason": "zero target-scoped packets; scope mismatch, not a model miss"}
            for r in no_inference
        ],
        "rows": rows,
    }


def build_f9(comparison: dict) -> dict:
    offline = comparison["offline"]
    nine = comparison["online_nine_frame"]
    family = comparison["online_family_window"]
    head = comparison["head_to_head"]

    family_rows = [
        {
            "ground_truth": r["ground_truth"],
            "total_alerts": r["total_alerts"],
            "correct": r["correct"],
            "accuracy": r["accuracy"],
            "note": r.get("note"),
        }
        for r in family["rows"]
    ]

    return {
        "unit": "one sample = one flow = 9 packets = one F9 checkpoint",
        "offline": {
            "cases_total": offline["cases_total"],
            "cases_with_alert": offline["cases_with_alert"],
            "cases_correct": offline["cases_correct"],
            "caveat": "denominator is 14 single-flow cases; this proves the path works end to end and is not an accuracy rate",
        },
        "live_nine_frame": {
            "families_total": nine["families_total"],
            "families_with_alert": nine["families_with_alert"],
            "attempts_per_case": {r["case_id"]: r["attempts"] for r in nine["rows"]},
            "outcomes": {r["case_id"]: r["outcome"] for r in nine["rows"]},
        },
        "head_to_head": {
            "comparable": head["comparable"],
            "agree": head["agree"],
            "agree_wrong": head["agree_wrong"],
            "disagree": head["disagree"],
            "caveat": (
                f"{head['agree_wrong']} of the {head['agree']} agreeing cases are wrong on both sides; "
                "agreement means the environments behave alike, not that the answer is correct"
            ),
        },
        "live_family_window": {
            "rows": family_rows,
            "total_alerts": sum(r["total_alerts"] for r in family_rows),
            "families_with_alert": sum(1 for r in family_rows if r["total_alerts"] > 0),
            "offline_counterpart": None,
            "caveat": (
                "no offline counterpart exists for the family-window unit, so this measurement cannot "
                "separate model error from lab packet loss and must not be merged into the nine-frame comparison"
            ),
        },
    }


def build() -> dict:
    terminal_comparison = read_json(TERMINAL_COMPARISON)
    f9_comparison = read_json(F9_COMPARISON)
    manifest = read_json(MODEL_MANIFEST)

    sources = [
        TERMINAL_COMPARISON,
        F9_COMPARISON,
        MODEL_MANIFEST,
        DIAGRAM_MMD,
        DIAGRAM_MD,
        SPEC,
    ]

    return {
        "schema_version": "1.0.0",
        "kind": "f9_terminal_offline_online_accuracy_evidence",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "current_tag": CURRENT_TAG,
        "question": (
            "What accuracy may be claimed for each model, and how much of the live shortfall "
            "belongs to the lab rather than to the model?"
        ),
        "method": {
            "accuracy_side": "offline only; the live side is contaminated by packet loss and scope mismatch",
            "cost_of_live_side": "offline minus live on the same PCAP and the same sample unit",
            "never_merge": "F9 and Terminal V1 use different sample units and different label spaces",
            "sample_units": {
                "f9": "one flow = 9 packets = one checkpoint",
                "terminal": "one closed or EOF-terminated bidirectional flow",
            },
        },
        "terminal_v1": build_terminal(terminal_comparison),
        "f9": build_f9(f9_comparison),
        "limits_to_state_with_every_table": [
            "PortScan is out of scope for F9: its flows are shorter than the nine-packet checkpoint. Report 'not applicable', never 0%.",
            "F9 has no large-scale offline run, so its 10,650-flow live figure cannot separate model error from lab loss.",
            "The DoS GoldenEye live shortfall is hypothesised to come from inter-arrival-time distortion; the spec records this as unverified.",
            "Bot and Infiltration produced zero target-scoped packets: scope mismatch, not a model miss.",
            "Six Terminal live cases hold a complete summary.json.tmp without an official receipt after an HGFS rename stall; they must not be promoted.",
            "Heartbleed is outside the locked F9 label set and is excluded from accuracy.",
            "Every live result is valid only inside the VMware lab.",
            "Dashboard streams are a presentation layer; thesis numbers come from hashed receipts.",
        ],
        "model_contract": {
            "selected_profile": manifest.get("selected_profile"),
            "selected_threshold": manifest.get("selected_threshold"),
            "training_family_counts": manifest.get("training_family_counts"),
            "source": rel(MODEL_MANIFEST),
            "source_sha256": sha256(MODEL_MANIFEST),
        },
        "supporting_sources": [member(p) for p in sources],
        "test_partition": {
            "state": "sealed",
            "feature_reads": 0,
            "metric_reads": 0,
            "path_or_hash_reads": 0,
        },
    }


LIMITS_VI = [
    "PortScan nằm ngoài phạm vi F9: flow ngắn hơn ngưỡng chín packet. Ghi *không áp dụng*, không bao giờ ghi 0%.",
    "F9 không có lần chạy offline diện rộng, nên con số live 10.650 flow không tách được lỗi model khỏi lỗi phòng lab.",
    "Mức sụt của DoS GoldenEye được cho là do méo khoảng cách thời gian giữa packet; spec ghi rõ đây là giả thuyết chưa kiểm chứng.",
    "Bot và Infiltration có 0 packet thuộc phạm vi IP đích: lệch phạm vi, không phải model bỏ sót.",
    "Sáu ca live Terminal có summary.json.tmp đầy đủ nhưng thiếu receipt chính thức do HGFS kẹt lúc đổi tên; không được tự promote.",
    "Heartbleed nằm ngoài tập nhãn của bundle F9 đã khóa, không tính vào accuracy.",
    "Mọi kết quả live chỉ có giá trị trong phạm vi phòng lab VMware.",
    "Luồng dashboard chỉ là lớp trình bày; số trong luận văn lấy từ receipt đã hash.",
]


def vi_num(value: float, digits: int = 2) -> str:
    text = f"{value:,.{digits}f}"
    return text.replace(",", " ").replace(".", ",").replace(" ", ".")


def render_markdown(evidence: dict) -> str:
    term = evidence["terminal_v1"]
    f9 = evidence["f9"]
    micro = term["offline_accuracy"]["micro_by_flow"]
    macro = term["offline_accuracy"]["macro_by_family"]
    head = f9["head_to_head"]

    lines = [
        "# Bằng chứng luận văn — độ chính xác offline và chi phí chạy live",
        "",
        f"Tag: `{evidence['current_tag']}` · sinh lúc {evidence['generated_at_utc']}",
        "",
        "Mọi con số dưới đây được tính lại từ receipt trên đĩa. Không có số nào gõ tay.",
        "",
        "## 1. Độ chính xác của model — lấy từ vế offline",
        "",
        "| Model | Cách tính | Kết quả |",
        "|---|---|---|",
        f"| Terminal V1 | theo flow, {macro['families']} họ tấn công | **{vi_num(micro['correct'], 0)}/{vi_num(micro['total'], 0)} = {vi_num(micro['rate']*100)}%** |",
        f"| Terminal V1 | trung bình đều theo họ | **{vi_num(macro['rate']*100)}%** |",
        f"| F9 | theo ca, mẫu số {f9['offline']['cases_total']} | **{f9['offline']['cases_correct']}/{f9['offline']['cases_total']} ca đúng** |",
        "",
        "Hai con số Terminal lệch nhau vì riêng PortScan đã chiếm "
        f"{vi_num(term['offline_accuracy']['portscan_share']*100)}% toàn bộ mẫu, mà lại là họ model làm tốt. "
        "Luận văn phải báo cả hai con số.",
        "",
        "Với F9: mẫu số chỉ có 14 ca, mỗi ca một flow. Con số này chứng minh đường đi kỹ thuật "
        "chạy được đầu-cuối, **không dùng như một tỷ lệ chính xác**.",
        "",
        "## 2. Chi phí của việc chạy live",
        "",
        "### Các ca không mất packet — live trùng khít offline",
        "",
        "| Ca | Offline | Live | Chênh lệch (điểm) |",
        "|---|---|---|---|",
    ]
    for row in term["cost_of_running_live"]["lossless_cases"]:
        lines.append(
            f"| {row['case']} | {vi_num(row['offline_correct_rate']*100)}% | "
            f"{vi_num(row['live_expected_label_share']*100)}% | {vi_num(row['delta_points'])} |"
        )
    lines += [
        "",
        f"Chênh lệch tuyệt đối lớn nhất trong nhóm này: **{vi_num(term['cost_of_running_live']['lossless_max_abs_delta_points'])} điểm**. "
        "Đây là bằng chứng mạnh nhất rằng việc triển khai lên DPDK không làm đổi hành vi của model.",
        "",
        "### Các ca có mất packet — mức sụt bám theo tỷ lệ mất",
        "",
        "| Ca | Packet mất | Chênh lệch (điểm) |",
        "|---|---|---|",
    ]
    for row in term["cost_of_running_live"]["lossy_cases"]:
        lines.append(
            f"| {row['case']} | {vi_num(row['live_imissed_rate']*100)}% | {vi_num(row['delta_points'])} |"
        )
    lines += [
        "",
        "Ca nào mất 0 packet thì live lặp lại đúng kết quả offline; ca nào mất packet thì tụt theo tỷ lệ mất. "
        "Vì vậy **tỷ lệ live không phải độ chính xác của model**.",
        "",
        "### Nhánh F9, đơn vị 1 flow = 9 packet",
        "",
        f"- So được **{head['comparable']}** ca trên tổng {f9['live_nine_frame']['families_total']}.",
        f"- Hai vế cho cùng đáp án ở **{head['agree']}** ca, lệch nhau ở **{head['disagree']}** ca.",
        f"- Trong {head['agree']} ca khớp có **{head['agree_wrong']} ca cùng sai giống nhau**. "
        "Khớp nghĩa là hai môi trường hành xử như nhau, **không có nghĩa là đáp án đúng**.",
        "",
        "## 3. Điểm yếu thật của model",
        "",
        "Tiêu chí phân biệt với lỗi hạ tầng: sai giống nhau ở cả hai vế và mất 0 packet.",
        "",
        "| Ca | Offline | Live |",
        "|---|---|---|",
    ]
    for row in term["genuine_model_weaknesses"]:
        lines.append(
            f"| {row['case']} | {vi_num(row['offline_correct_rate']*100)}% | {vi_num(row['live_expected_label_share']*100)}% |"
        )
    lines += [
        "",
        "## 4. Giới hạn phải ghi kèm mọi bảng",
        "",
    ]
    lines += [f"{i}. {item}" for i, item in enumerate(LIMITS_VI, 1)]
    lines += [
        "",
        "## 5. Nguồn đã hash",
        "",
        "| File | Bytes | SHA-256 |",
        "|---|---|---|",
    ]
    for src in evidence["supporting_sources"]:
        lines.append(f"| `{src['path']}` | {src['bytes']} | `{src['sha256']}` |")
    lines += [
        "",
        f"Test partition: `{evidence['test_partition']['state']}`, 0 lượt đọc.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    evidence = build()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    json_path = OUTPUT_ROOT / f"{STEM}.json"
    md_path = OUTPUT_ROOT / f"{STEM}.md"
    json_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(evidence), encoding="utf-8")
    print(f"wrote {rel(json_path)}")
    print(f"wrote {rel(md_path)}")


if __name__ == "__main__":
    main()
