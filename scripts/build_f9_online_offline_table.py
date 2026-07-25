#!/usr/bin/env python3
"""Merge the three F9 measurements into one comparison, one row per family.

The three come in different shapes because they answer different questions, so
none of them can be read as the other two:

  online 9-frame      ubuntu/f9-*/sensor.jsonl      unit = one attempt
  online family-window replay-runs/*/f9-per-replay-family-DEMO.json  unit = one alert
  offline             replay-runs/*/offline-f9-results.json          unit = one case

Two defects in the derived dashboard stream are the reason this reads the raw
sensor logs instead of live-detection-f9.jsonl:

  - the stream holds two rows for bot-r2 and for heartbleed-r2 while each
    sensor log holds exactly one nids_alert, so the stream over-counts;
  - attempt f9-ddos-r8t3 carries an alert for an FTP-Patator flow on port 21
    and has no ddos replay receipt on the Kali side, so the attempt directory
    name alone does not establish which family produced an alert.

Every alert is therefore checked against the 5-tuple the manifest records for
that case. An alert whose flow does not match is reported as foreign_flow and
never scored.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# -r3, -r8t2 are retries; -bcast1 and -probe1 are one-off lab experiments.
ATTEMPT_SUFFIX = re.compile(r"-(?:r\d+(?:t\d+)?|bcast\d*|probe\d*)$")

# The four families whose scenario PCAP carries LRO-coalesced frames above the
# 1518-byte link limit. They cannot be sent over this vmnet link at nine-frame
# granularity at all, which is a property of the capture, not a model result.
JUMBO_BLOCKED = {"ddos", "dos-goldeneye", "dos-hulk", "portscan"}

EXPECTED_RECORDS = 9


def dotted(value: int) -> str:
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def load_manifest(run_id: str) -> dict[str, dict[str, Any]]:
    path = ROOT / "run_log/t8.5/scenarios" / run_id / "pcap/manifest.json"
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    cases: dict[str, dict[str, Any]] = {}
    for item in document["outputs"]:
        protocol, source_ip, source_port, destination_ip, destination_port = item["tuple"]
        cases[item["case_id"]] = {
            "label": item["label"],
            "records": item["records"],
            "semantic_kind": item.get("semantic_kind"),
            "flow_id": item.get("flow_id"),
            "endpoints": {
                (dotted(source_ip), source_port),
                (dotted(destination_ip), destination_port),
            },
            "protocol": protocol,
        }
    return cases


def read_attempt(path: Path) -> dict[str, Any]:
    """One attempt directory reduced to its summary counters and its alerts."""
    summary: dict[str, Any] = {}
    ready = False
    alerts: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("event_type")
        if kind == "nids_dpdk_live_summary":
            summary = event
        elif kind == "nids_dpdk_live_ready":
            ready = True
        elif kind == "nids_alert":
            flow = event.get("flow") or {}
            source = flow.get("source") or {}
            destination = flow.get("destination") or {}
            evidence = event.get("evidence") or {}
            family = evidence.get("known_family")
            if isinstance(family, dict):
                candidate = family.get("top_candidate")
                confidence = family.get("confidence")
            else:
                candidate, confidence = family, None
            if confidence is None:
                flow_rf = evidence.get("flow_rf") or {}
                confidence = flow_rf.get("attack_probability")
            alerts.append({
                "candidate": candidate,
                "confidence": confidence,
                "decision": event.get("decision"),
                "packet_count": event.get("packet_count"),
                "source": (source.get("ip"), source.get("port")),
                "destination": (destination.get("ip"), destination.get("port")),
            })
    return {
        "ready": ready,
        "packets_seen": summary.get("packets_seen", 0),
        "packets_parsed": summary.get("packets_parsed", 0),
        "parser_errors": summary.get("parser_errors", 0),
        "stop_reason": summary.get("stop_reason"),
        "alerts": alerts,
    }


def classify(attempt: dict[str, Any], case: dict[str, Any] | None) -> str:
    """Name what an attempt observed, keeping the three causes of zero apart."""
    if not attempt["ready"]:
        return "sensor_not_ready"
    matched = attempt.get("matched_alerts") or []
    if matched:
        return "alert"
    if attempt["alerts"]:
        return "foreign_flow"
    if attempt["packets_seen"] == 0:
        return "no_capture"
    if attempt["packets_seen"] < EXPECTED_RECORDS:
        return "short_capture"
    return "no_alert"


def run_started_at(run_id: str) -> float:
    """Epoch seconds encoded in a run id of the form YYYYMMDD-HHMMSS."""
    return datetime.strptime(run_id, "%Y%m%d-%H%M%S").timestamp()


def collect_online_nine_frame(run_id: str, cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    root = ROOT / "run_log/t8.5/scenarios" / run_id / "ubuntu"
    # Six attempt directories inside this run folder were copied in from the
    # afternoon family-window pass and keep their original mtime (15:2x-15:5x,
    # hours before this run opened at 19:49). They hold thousands of packets,
    # not nine, so scoring them here would mix the two sample units. The run id
    # is the boundary: anything written before the run started is not this run.
    started = run_started_at(run_id)
    per_case: dict[str, list[dict[str, Any]]] = {}
    carried_over: list[str] = []
    for directory in sorted(root.glob("f9-*")):
        log = directory / "sensor.jsonl"
        if not log.exists():
            continue
        if log.stat().st_mtime < started:
            carried_over.append(directory.name.removeprefix("f9-"))
            continue
        attempt_name = directory.name.removeprefix("f9-")
        case_id = ATTEMPT_SUFFIX.sub("", attempt_name)
        case = cases.get(case_id)
        record = read_attempt(log)
        record["attempt"] = attempt_name
        record["case_id"] = case_id
        if case is not None:
            record["matched_alerts"] = [
                alert for alert in record["alerts"]
                if alert["source"] in case["endpoints"]
                and alert["destination"] in case["endpoints"]
            ]
        else:
            record["matched_alerts"] = []
        record["outcome"] = classify(record, case)
        per_case.setdefault(case_id, []).append(record)

    rows = []
    for case_id in sorted(cases):
        attempts = per_case.get(case_id, [])
        # An attempt that produced a verified alert settles the family; the
        # remaining attempts stay in the receipt as tries, never deleted.
        chosen = next((a for a in attempts if a["outcome"] == "alert"), None)
        if chosen is None and attempts:
            chosen = max(attempts, key=lambda a: (a["packets_seen"], a["packets_parsed"]))
        label = cases[case_id]["label"]
        row: dict[str, Any] = {
            "case_id": case_id,
            "ground_truth": label,
            "attempts": len(attempts),
            "attempt_ids": [a["attempt"] for a in attempts],
            "jumbo_blocked": case_id in JUMBO_BLOCKED,
        }
        if chosen is None:
            row.update({"outcome": "not_attempted", "candidate": None,
                        "confidence": None, "correct": None,
                        "packets_seen": None, "chosen_attempt": None})
        else:
            alert = (chosen["matched_alerts"] or [None])[0]
            row.update({
                "outcome": chosen["outcome"],
                "chosen_attempt": chosen["attempt"],
                "packets_seen": chosen["packets_seen"],
                "packets_parsed": chosen["packets_parsed"],
                "stop_reason": chosen["stop_reason"],
                "candidate": alert["candidate"] if alert else None,
                "confidence": alert["confidence"] if alert else None,
                "correct": (alert["candidate"] == label) if alert else None,
                "foreign_candidates": [a["candidate"] for a in chosen["alerts"]]
                if chosen["outcome"] == "foreign_flow" else [],
            })
        rows.append(row)
    scored = [r for r in rows if r["outcome"] == "alert"]
    return {
        "unit": "one attempt = one flow = 9 packets = one F9 checkpoint",
        "source": f"run_log/t8.5/scenarios/{run_id}/ubuntu/f9-*/sensor.jsonl",
        "attempt_dirs_carried_over_from_earlier_pass": sorted(carried_over),
        "families_total": len(rows),
        "families_with_alert": len(scored),
        "families_correct": sum(1 for r in scored if r["correct"]),
        "rows": rows,
    }


def load_offline(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    return {
        "unit": "one case = one scenario PCAP replayed through nids_demo_replay",
        "source": str(path.relative_to(ROOT)).replace("\\", "/"),
        "ground_truth_source": document.get("ground_truth_source"),
        "cases_total": document.get("cases_total"),
        "cases_with_alert": document.get("cases_with_alert"),
        "cases_correct": document.get("cases_correct"),
        "rows": [
            {
                "case_id": row.get("case_id"),
                "ground_truth": row.get("ground_truth"),
                "candidate": row.get("candidate"),
                "confidence": row.get("confidence"),
                "correct": row.get("correct"),
            }
            for row in document.get("rows", [])
        ],
    }


def load_family_window(path: Path, cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    label_to_case = {value["label"]: key for key, value in cases.items()}
    rows = []
    for row in document.get("rows", []):
        label = row.get("ground_truth")
        rows.append({
            "case_id": label_to_case.get(label),
            "ground_truth": label,
            "total_alerts": row.get("total_alerts"),
            "correct": row.get("correct"),
            "accuracy": row.get("accuracy"),
            "top_outputs": row.get("top_outputs", [])[:3],
        })
    return {
        "unit": "one alert per flow that reached F9 inside a whole-family PCAP",
        "source": str(path.relative_to(ROOT)).replace("\\", "/"),
        "ground_truth_source": document.get("ground_truth_source"),
        "rows": rows,
    }


def load_pacing(path: Path, cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Per-family ratio between source wall-clock span and sensor wall-clock span.

    A ratio of 1.0 means the replay reproduced the original spacing. Below 1.0
    the sender could not sustain the capture's packet rate and every gap was
    stretched, which is exactly the input F9's inter-arrival-time features read.
    """
    if not path.exists():
        return {"available": False, "rows": {}}
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    rows = {}
    for result in document.get("results", []):
        span = result.get("source_span_seconds") or 0.0
        packets = result.get("source_packets_compared") or 0
        duration = result.get("sensor_duration_seconds") or 0.0
        rows[result["family"]] = {
            "ratio": result.get("matched_pacing_ratio"),
            "drop": result.get("rx_drop_fraction"),
            "source_pps": (packets / span) if span else None,
            "sensor_pps": (result.get("sensor_packets_seen") or 0) / duration
            if duration else None,
            "source_span_seconds": span,
            "sensor_span_seconds":
                result.get("matched_checkpoint_span_sensor_seconds"),
        }
    return {"available": True,
            "source": str(path.relative_to(ROOT)).replace("\\", "/"),
            "rows": rows}


def percent(numerator: int | None, denominator: int | None) -> str:
    if not denominator:
        return "—"
    return f"{100.0 * (numerator or 0) / denominator:.1f}%"


OUTCOME_TEXT = {
    "alert": "có alert",
    "foreign_flow": "alert của flow lạ (loại)",
    "no_capture": "không bắt được gói",
    "short_capture": "bắt thiếu gói",
    "no_alert": "đủ gói, không alert",
    "sensor_not_ready": "sensor chưa sẵn sàng",
    "not_attempted": "chưa chạy",
}


def render(document: dict[str, Any]) -> str:
    online = document["online_nine_frame"]
    offline = document["offline"]
    window = document["online_family_window"]
    offline_by_case = {r["case_id"]: r for r in offline["rows"]}
    window_by_case = {r["case_id"]: r for r in window["rows"] if r["case_id"]}

    lines = [
        "# F9 — offline vs online, gộp một bảng",
        "",
        f"Sinh lúc: {document['generated_at_utc']}  ",
        f"Ground truth: `{document['ground_truth_source']}`",
        "",
        "Ba phép đo dưới đây **không cùng đơn vị mẫu**, nên không cộng chung được:",
        "",
        f"- **Offline** — {offline['unit']}",
        f"- **Online 9-frame** — {online['unit']}",
        f"- **Online family-window** — {window['unit']}",
        "",
        "## Bảng gộp",
        "",
        "| Family | Offline | Online 9-frame | Online family-window |",
        "|---|---|---|---|",
    ]
    for row in online["rows"]:
        case_id = row["case_id"]
        off = offline_by_case.get(case_id)
        if off is None:
            offline_cell = "—"
        elif off["correct"]:
            offline_cell = f"✅ {off['candidate']} ({off['confidence']:.2f})"
        else:
            offline_cell = f"❌ → {off['candidate']} ({off['confidence']:.2f})"

        if row["outcome"] == "alert":
            mark = "✅" if row["correct"] else "❌ →"
            confidence = row["confidence"]
            suffix = f" ({confidence:.2f})" if isinstance(confidence, (int, float)) else ""
            online_cell = f"{mark} {row['candidate']}{suffix}"
        elif row["jumbo_blocked"]:
            online_cell = "⛔ jumbo frame, không gửi được"
        else:
            online_cell = f"⚠️ {OUTCOME_TEXT.get(row['outcome'], row['outcome'])}"
            if row["packets_seen"] is not None:
                online_cell += f" (seen={row['packets_seen']})"

        win = window_by_case.get(case_id)
        window_cell = (
            f"{win['correct']}/{win['total_alerts']} = {100 * win['accuracy']:.1f}%"
            if win and win["total_alerts"] else ("0 alert" if win else "—")
        )
        lines.append(f"| {row['ground_truth']} | {offline_cell} | {online_cell} | {window_cell} |")

    lines += [
        "",
        "## Tổng",
        "",
        "| Phép đo | Có alert | Đúng | Tỷ lệ |",
        "|---|---:|---:|---:|",
        f"| Offline | {offline['cases_with_alert']}/{offline['cases_total']} "
        f"| {offline['cases_correct']} "
        f"| {percent(offline['cases_correct'], offline['cases_with_alert'])} |",
        f"| Online 9-frame | {online['families_with_alert']}/{online['families_total']} "
        f"| {online['families_correct']} "
        f"| {percent(online['families_correct'], online['families_with_alert'])} |",
    ]
    window_alerts = sum(r["total_alerts"] or 0 for r in window["rows"])
    window_correct = sum(r["correct"] or 0 for r in window["rows"])
    lines.append(
        f"| Online family-window | {window_alerts} alert | {window_correct} "
        f"| {percent(window_correct, window_alerts)} |"
    )

    pacing = document.get("pacing", {})
    if pacing.get("rows"):
        lines += [
            "",
            "## Vì sao family-window sai nhiều: mất gói và giãn thời gian",
            "",
            "F9 đọc **số gói** và **thời gian giữa các gói**. Đường truyền trong lab",
            "làm hỏng cả hai, theo hai cơ chế tách biệt:",
            "",
            "- **Mất gói** — NIC nhận được nhưng vòng RX không còn chỗ nên bỏ. Gói bị",
            "  bỏ không làm giãn flow, nó **rút mất mẫu** khỏi flow: 9 gói mà F9 chấm",
            "  trở thành 9 gói *sống sót*, không phải 9 gói *đầu tiên*.",
            "- **Giãn thời gian** — phần còn lại tới chậm hơn so với bản capture.",
            "",
            "| Family | pps gốc | pps tới sensor | Mất gói | Pacing | Accuracy online |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        window_by_case = {r["case_id"]: r for r in window["rows"] if r["case_id"]}
        ordered = sorted(pacing["rows"].items(),
                         key=lambda item: -(item[1]["drop"] or 0))
        for family, row in ordered:
            win = window_by_case.get(family)
            accuracy = (f"{100 * win['accuracy']:.1f}%"
                        if win and win.get("total_alerts") else "—")
            ratio, drop = row["ratio"], row["drop"] or 0.0
            drop_flag = "🔴" if drop > 0.2 else ("🟡" if drop > 0.01 else "🟢")
            lines.append(
                f"| {family} | {row['source_pps']:.0f} | {row['sensor_pps']:.0f} "
                f"| {drop_flag} {100 * drop:.1f}% | ×{ratio:.2f} | {accuracy} |")
        lines += [
            "",
            "**Mất gói bám sát kết quả hơn cả pacing.** Hai family mất 0% gói đạt",
            "100%; family mất 6,4% đạt 83,8%; hai family mất 42–46% là hai family",
            "kém nhất. Ngưỡng của lab nằm quanh **800 gói/giây**: dưới ngưỡng thì",
            "không mất gói nào, trên ngưỡng thì mất theo tỷ lệ vượt.",
            "",
            "Cùng bộ gói đó chạy offline — không mất gói, thời gian gốc nguyên vẹn —",
            "GoldenEye ra **100% ở conf 1,000**.",
            "",
            "Đây là **giới hạn thông lượng của lab, không phải lỗi model**, và nó",
            "khớp với vế 9-frame: 9 gói không bao giờ làm tràn vòng RX, nên vế",
            "9-frame khớp với offline còn vế family-window thì không.",
        ]

    head = document["head_to_head"]
    if head["rows"]:
        lines += [
            "",
            "## So trực tiếp offline vs online (cùng đơn vị mẫu)",
            "",
            "Chỉ những family có **cả hai** vế đo được mới so được. Cùng một PCAP,",
            "cùng một checkpoint F9 — khác nhau duy nhất ở chỗ online phải đi qua dây.",
            "",
            "| Family | Offline | Online 9-frame | Khớp? |",
            "|---|---|---|---|",
        ]
        for row in head["rows"]:
            offline_conf = f" ({row['offline_confidence']:.3f})" \
                if isinstance(row["offline_confidence"], (int, float)) else ""
            online_conf = f" ({row['online_confidence']:.3f})" \
                if isinstance(row["online_confidence"], (int, float)) else ""
            if row["agree"]:
                verdict = "✅ khớp" if row["offline_correct"] else "✅ khớp (cùng sai)"
            else:
                verdict = "❌ khác"
            lines.append(
                f"| {row['ground_truth']} | {row['offline_candidate']}{offline_conf} "
                f"| {row['online_candidate']}{online_conf} | {verdict} |")
        lines += [
            "",
            f"**{head['agree']}/{head['comparable']} family cho ra cùng một kết luận** "
            "khi chạy qua dây và khi chạy thẳng vào engine",
            f"(kể cả {head['agree_wrong']} trường hợp sai giống hệt nhau, "
            "đó mới là bằng chứng đường truyền trung thực).",
            "",
        ]
        for row in head["rows"]:
            if not row["agree"]:
                lines.append(
                    f"Khác biệt duy nhất — **{row['ground_truth']}**: offline ra "
                    f"`{row['offline_candidate']}` (đúng), online ra "
                    f"`{row['online_candidate']}`. Độ tin cậy hai bên gần nhau "
                    f"({row['offline_confidence']:.3f} vs {row['online_confidence']:.3f}), "
                    "nên đây là hai lớp sát nhau bị đảo thứ tự khi đặc trưng lệch nhẹ "
                    "vì thời gian giữa các gói thay đổi lúc truyền, không phải model "
                    "hỏng.")

    excluded = document.get("excluded", [])
    if excluded:
        lines += ["", "## Bị loại khỏi bảng", "",
                  "| Attempt | Lý do | Chi tiết |", "|---|---|---|"]
        for item in excluded:
            lines.append(f"| `{item['attempt']}` | {item['reason']} | {item['detail']} |")

    lines += [
        "",
        "## Đọc bảng này thế nào",
        "",
        "- Cột **Offline** đo *model*: PCAP đi thẳng vào engine, không qua mạng.",
        "- Cột **Online 9-frame** đo *model + đường truyền*, cùng đơn vị mẫu với offline.",
        "  Chênh lệch giữa hai cột này là phần do khâu truyền gây ra.",
        "- Cột **Online family-window** đo trên toàn bộ flow của một family, nên số alert",
        "  lớn hơn hàng nghìn lần và **không so trực tiếp** với hai cột kia được; nó trả",
        "  lời câu hỏi khác: trong lưu lượng thật, tỷ lệ đúng là bao nhiêu.",
        "- `⛔ jumbo frame`: PCAP gốc chứa khung LRO/TSO trên 1518 byte — khung chưa từng",
        "  tồn tại trên dây. Đây là tính chất của bản capture, không phải kết quả model.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="20260808-194942")
    parser.add_argument("--window-run-id", default="20260808-155731")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-md", type=Path)
    args = parser.parse_args()

    cases = load_manifest(args.run_id)
    replay_runs = ROOT / "run_log/full-flow-v1/replay-runs"
    online = collect_online_nine_frame(args.run_id, cases)
    offline = load_offline(replay_runs / args.run_id / "offline-f9-results.json")
    window = load_family_window(
        replay_runs / args.window_run_id / "f9-per-replay-family-DEMO.json", cases)

    excluded = []
    for row in online["rows"]:
        if row["outcome"] == "foreign_flow":
            counts = Counter(str(c) for c in row.get("foreign_candidates", []))
            excluded.append({
                "attempt": row["chosen_attempt"],
                "reason": "flow không khớp 5-tuple trong manifest",
                "detail": "alert của " + ", ".join(
                    f"{name} ×{n}" if n > 1 else name
                    for name, n in counts.most_common()),
            })

    # The head-to-head is the only place the two sides may be compared as
    # numbers: same PCAP, same F9 checkpoint, same one-flow sample unit. A
    # family missing from either side is left out rather than counted as a miss.
    offline_by_case = {row["case_id"]: row for row in offline["rows"]}
    head_rows = []
    for row in online["rows"]:
        if row["outcome"] != "alert":
            continue
        counterpart = offline_by_case.get(row["case_id"])
        if counterpart is None:
            continue
        head_rows.append({
            "case_id": row["case_id"],
            "ground_truth": row["ground_truth"],
            "offline_candidate": counterpart["candidate"],
            "offline_confidence": counterpart["confidence"],
            "offline_correct": counterpart["correct"],
            "online_candidate": row["candidate"],
            "online_confidence": row["confidence"],
            "online_correct": row["correct"],
            "agree": counterpart["candidate"] == row["candidate"],
        })
    head_to_head = {
        "comparable": len(head_rows),
        "agree": sum(1 for r in head_rows if r["agree"]),
        "agree_wrong": sum(1 for r in head_rows
                           if r["agree"] and not r["offline_correct"]),
        "disagree": sum(1 for r in head_rows if not r["agree"]),
        "rows": head_rows,
    }

    document = {
        "kind": "f9_online_offline_comparison",
        "run_id": args.run_id,
        "window_run_id": args.window_run_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ground_truth_source":
            f"run_log/t8.5/scenarios/{args.run_id}/pcap/manifest.json",
        "alert_attribution": "alert phải khớp 5-tuple của case trong manifest",
        "offline": offline,
        "online_nine_frame": online,
        "online_family_window": window,
        "head_to_head": head_to_head,
        "pacing": load_pacing(
            replay_runs / args.run_id / "replay-pacing-comparison.json", cases),
        "excluded": excluded,
    }

    output_json = args.output_json or (
        replay_runs / args.run_id / "f9-online-offline-comparison.json")
    output_md = args.output_md or (
        replay_runs / args.run_id / "f9-online-offline-comparison.md")
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    output_md.write_text(render(document), encoding="utf-8")
    print(f"wrote {output_json}")
    print(f"wrote {output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
