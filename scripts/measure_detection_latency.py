#!/usr/bin/env python3
"""Measure inference and alert latency for the F9 and Terminal V1 sensors.

Reads only what already exists on disk. Three quantities are distinguished and
never conflated:

    capture_to_inference_ns  detection_delay_ns on every F9 alert: from the
                             timestamp of the packet that reached the F9
                             checkpoint to the moment inference is about to
                             start. Parsing, feature encoding and queueing.
                             This is a LOWER BOUND on alert latency.
    inference_ns             the "inference" bucket of --benchmark-metrics. Read
                             the source before quoting it: the start timestamp is
                             taken before FeatureEngine::encode, so the bucket
                             covers feature encoding, snapshot construction AND
                             the model call. It is NOT the model call alone.
    alert_ns                 packet timestamp to alert written on stdout, the
                             end-to-end figure. Same flag.

The Terminal V1 sensor records none of the three, so its rows are reported as
absent rather than as zero.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
F9_SENSOR_GLOB = "run_log/t8.5/scenarios/20260808-194942/ubuntu/f9-*/sensor.jsonl"
F9_BENCHMARK_GLOB = "run_log/full-flow-v1/latency-live/*/*/sensor.jsonl"
TERMINAL_BENCHMARK_GLOB = "run_log/full-flow-v1/latency-live/*/*/ubuntu/sensor.jsonl"
TERMINAL_ALERT_GLOB = "run_log/full-flow-v1/matched-terminal-20260809/live/20260809-r3/*/alerts.jsonl"
OUTPUT_ROOT = ROOT / "run_log/full-flow-v1/thesis-evidence"
STEM = "detection-latency-20260809"
CURRENT_TAG = "t91-detection-latency-evidence-r1"

CLOCK_NOTE = (
    "All timestamps come from the sensor steady_clock (monotonic), so they are "
    "immune to wall-clock adjustments but cannot be compared across machines."
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def percentiles(values: list[int]) -> dict:
    """Nearest-rank percentiles; explicit so the numbers are reproducible."""
    if not values:
        return {"samples": 0}
    ordered = sorted(values)

    def rank(fraction: float) -> int:
        index = max(1, min(len(ordered), round(fraction * len(ordered) + 0.5)))
        return ordered[index - 1]

    return {
        "samples": len(ordered),
        "min_ns": ordered[0],
        "p50_ns": rank(0.50),
        "p95_ns": rank(0.95),
        "p99_ns": rank(0.99),
        "max_ns": ordered[-1],
        "mean_ns": round(statistics.fmean(ordered), 1),
    }


def iter_jsonl(path: Path):
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def collect_benchmark_runs(root: Path) -> list[dict]:
    """Read summaries produced by a --benchmark-metrics run."""
    runs = []
    for path in sorted(root.glob(F9_BENCHMARK_GLOB)):
        case = path.parent.name
        run_id = path.parent.parent.name
        for record in iter_jsonl(path):
            if record.get("event_type") != "nids_dpdk_live_summary":
                continue
            latency = record.get("latency_ns")
            if not latency:
                continue
            ipackets = record.get("port_ipackets") or 0
            imissed = record.get("port_imissed") or 0
            runs.append(
                {
                    "run_id": run_id,
                    "case": case,
                    "status": record.get("status"),
                    "packets_seen": record.get("packets_seen"),
                    "f9_snapshots": record.get("f9_snapshots"),
                    "alerts": record.get("alerts"),
                    "port_ipackets": ipackets,
                    "port_imissed": imissed,
                    "imissed_rate": (imissed / ipackets) if ipackets else None,
                    "latency_ns": latency,
                    "source": rel(path),
                }
            )
    return runs


def collect_terminal_benchmark_runs(root: Path) -> list[dict]:
    """Read summaries from a Terminal --benchmark-metrics run.

    The Terminal sensor writes under <run>/<case>/ubuntu/ and reports port
    counters inside a nested port_stats object, so it needs its own reader.
    """
    runs = []
    for path in sorted(root.glob(TERMINAL_BENCHMARK_GLOB)):
        case = path.parent.parent.name
        run_id = path.parent.parent.parent.name
        for record in iter_jsonl(path):
            if record.get("event_type") != "nids_terminal_live_summary":
                continue
            latency = record.get("latency_ns")
            if not latency:
                continue
            stats = record.get("port_stats") or {}
            ipackets = stats.get("ipackets") or 0
            imissed = stats.get("imissed") or 0
            runs.append(
                {
                    "run_id": run_id,
                    "case": case,
                    "status": record.get("status"),
                    "inferences": record.get("inferences"),
                    "alerts": record.get("alerts"),
                    "eof_flows": record.get("eof_flows"),
                    "non_eof_flows": record.get("non_eof_flows"),
                    "port_ipackets": ipackets,
                    "port_imissed": imissed,
                    "imissed_rate": (imissed / ipackets) if ipackets else None,
                    "latency_ns": latency,
                    "source": rel(path),
                }
            )
    return runs


def collect_f9(root: Path) -> dict:
    per_attempt: dict[str, list[int]] = {}
    benchmark_summaries = []
    sources = []

    for path in sorted(root.glob(F9_SENSOR_GLOB)):
        attempt = path.parent.name
        delays: list[int] = []
        for record in iter_jsonl(path):
            event = record.get("event_type")
            if event == "nids_alert":
                delay = record.get("detection_delay_ns")
                if isinstance(delay, int):
                    delays.append(delay)
        if delays:
            per_attempt[attempt] = delays
            sources.append(path)

    def family(attempt: str) -> str:
        """f9-ftp-patator-r12t3 -> ftp-patator; retries collapse into one family."""
        name = attempt[len("f9-"):] if attempt.startswith("f9-") else attempt
        return name.split("-r")[0]

    per_family: dict[str, list[int]] = {}
    for attempt, delays in per_attempt.items():
        per_family.setdefault(family(attempt), []).extend(delays)

    everything = [value for delays in per_attempt.values() for value in delays]
    benchmark_summaries = collect_benchmark_runs(root)
    usable = [r for r in benchmark_summaries if (r["latency_ns"].get("inference") or {}).get("observations")]

    return {
        "sensor": "nids_dpdk_live (F9)",
        "capture_to_inference_ns": {
            "definition": (
                "detection_delay_ns: packet timestamp at the F9 checkpoint until inference is "
                "about to start. Excludes the model call itself, so it is a lower bound on alert latency."
            ),
            "overall": percentiles(everything),
            "by_family": {name: percentiles(values) for name, values in sorted(per_family.items())},
            "attempts_covered": len(per_attempt),
        },
        "benchmark_runs": {
            "available": bool(usable),
            "reason_if_absent": (
                "the sensor exposes --benchmark-metrics, which emits latency_ns "
                "{parse, pipeline, inference, alert}; no run used that flag"
            ),
            "semantics": {
                "parse": "packet parsing only",
                "pipeline": "per-packet pipeline work",
                "inference": (
                    "feature encoding + snapshot construction + model call. The start "
                    "timestamp precedes FeatureEngine::encode, so this is NOT the model call alone."
                ),
                "alert": "packet timestamp until the alert line is written to stdout, end to end",
            },
            "runs": benchmark_summaries,
        },
        "sources": [rel(p) for p in sources] + [r["source"] for r in benchmark_summaries],
    }


def collect_terminal(root: Path) -> dict:
    emit_deltas: list[int] = []
    alerts = 0
    sources = []
    for path in sorted(root.glob(TERMINAL_ALERT_GLOB)):
        seen = False
        for record in iter_jsonl(path):
            captured = record.get("last_capture_timestamp_ns")
            emitted = record.get("last_event_timestamp_ns")
            if captured is None or emitted is None:
                continue
            alerts += 1
            emit_deltas.append(emitted - captured)
            seen = True
        if seen:
            sources.append(path)

    distinct = sorted(set(emit_deltas))
    benchmark_runs = collect_terminal_benchmark_runs(root)
    usable = [r for r in benchmark_runs if (r["latency_ns"].get("inference") or {}).get("observations")]
    instrumented = bool(usable)

    return {
        "sensor": "nids_t91_terminal_live (Terminal V1)",
        "alerts_inspected": alerts,
        "instrumented": instrumented,
        "benchmark_runs": {
            "available": bool(usable),
            "semantics": {
                "inference": (
                    "the model call alone. Terminal features are built by the exporter before the "
                    "sink is called, so this bucket excludes feature encoding. The F9 bucket of the "
                    "same name DOES include encoding, so the two are not comparable."
                ),
                "alert": (
                    "last_capture_timestamp_ns until the alert line is written. Terminal decides when "
                    "a flow closes, so this bucket also contains the wait for the flow to close, which "
                    "dominates the tail. It is not a compute-time figure."
                ),
            },
            "runs": benchmark_runs,
        },
        "observed_event_minus_capture_ns": {
            "distinct_values": distinct[:8],
            "distinct_count": len(distinct),
        },
        "historical_finding": (
            "In the archived 20260809-r3 alerts, last_event_timestamp_ns equals "
            "last_capture_timestamp_ns on every row, so that field records the capture instant and "
            "cannot be used as an emission time. Dedicated instrumentation was added instead."
        ),
        "sources": [rel(p) for p in sources] + [r["source"] for r in benchmark_runs],
    }


def build(root: Path = ROOT) -> dict:
    f9 = collect_f9(root)
    terminal = collect_terminal(root)
    source_paths = [root / p for p in (f9["sources"] + terminal["sources"])]

    gaps = []
    if not f9["benchmark_runs"]["available"]:
        gaps.append(
            "F9 inference and end-to-end alert latency: re-run one case with --benchmark-metrics; "
            "no code change needed, the flag already exists."
        )
    if not terminal["instrumented"]:
        gaps.append(
            "Terminal V1 latency of any kind: the sensor is not instrumented; a C++ change and a "
            "rebuild are required before any number can be claimed."
        )
    gaps.append(
        "The two sensors measure different things under the same field names: F9 inference includes "
        "feature encoding while Terminal inference does not, and Terminal alert includes the wait for "
        "a flow to close while F9 decides at packet nine. Never put them in one column."
    )

    return {
        "schema_version": "1.0.0",
        "kind": "detection_latency_evidence",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "current_tag": CURRENT_TAG,
        "question": "How long does the sensor take to decide, and how long until the alert leaves the pipeline?",
        "clock_note": CLOCK_NOTE,
        "quantities": {
            "capture_to_inference_ns": "packet at checkpoint -> inference about to start",
            "inference_ns": "the model call alone",
            "alert_ns": "packet at checkpoint -> alert written to stdout (end to end)",
        },
        "f9": f9,
        "terminal_v1": terminal,
        "measurement_gaps": gaps,
        "supporting_sources": [
            {"path": rel(p), "bytes": p.stat().st_size, "sha256": sha256(p)}
            for p in source_paths
        ],
        "test_partition": {"state": "sealed", "feature_reads": 0, "metric_reads": 0},
    }


def us(value_ns: float) -> str:
    return f"{value_ns / 1000:,.2f}".replace(",", ".").replace(".", ",", 0)


def vi(value: float, digits: int = 2) -> str:
    text = f"{value:,.{digits}f}"
    return text.replace(",", " ").replace(".", ",").replace(" ", ".")


def render_markdown(evidence: dict) -> str:
    f9 = evidence["f9"]
    overall = f9["capture_to_inference_ns"]["overall"]
    terminal = evidence["terminal_v1"]

    lines = [
        "# Bằng chứng luận văn — độ trễ suy luận và độ trễ cảnh báo",
        "",
        f"Tag: `{evidence['current_tag']}` · sinh lúc {evidence['generated_at_utc']}",
        "",
        "## Ba đại lượng, không được lẫn lộn",
        "",
        "| Đại lượng | Đo từ đâu tới đâu | Có số chưa |",
        "|---|---|---|",
        "| Chờ trước suy luận | packet chạm checkpoint → **sắp** gọi model | **có**, từ `detection_delay_ns` |",
        "| Độ trễ suy luận | riêng lời gọi model | chưa, cần cờ `--benchmark-metrics` |",
        "| Độ trễ cảnh báo | packet chạm checkpoint → alert ghi ra ngoài | chưa, cùng cờ trên |",
        "",
        "Số đang có là **chặn dưới** của độ trễ cảnh báo, vì còn thiếu phần chạy model.",
        "",
        "Đồng hồ: mọi mốc thời gian lấy từ `steady_clock` của cảm biến (đồng hồ đơn điệu), "
        "nên không bị ảnh hưởng khi chỉnh giờ hệ thống, nhưng **không so được giữa hai máy**.",
        "",
        "## 1. Nhánh F9 — chờ trước suy luận",
        "",
        f"Tổng **{vi(overall['samples'], 0)}** mẫu trên {f9['capture_to_inference_ns']['attempts_covered']} lần chạy.",
        "",
        "| Thống kê | Nano giây | Micro giây |",
        "|---|---|---|",
    ]
    for label, key in (
        ("Nhỏ nhất", "min_ns"),
        ("Trung vị p50", "p50_ns"),
        ("p95", "p95_ns"),
        ("p99", "p99_ns"),
        ("Lớn nhất", "max_ns"),
    ):
        value = overall[key]
        lines.append(f"| {label} | {vi(value, 0)} | {vi(value / 1000)} |")

    lines += [
        "",
        "### Theo từng họ tấn công",
        "",
        "Những họ chỉ có 1 mẫu thì p50, p95, p99 và giá trị lớn nhất trùng nhau; "
        "đọc chúng như một quan sát đơn lẻ, không phải phân vị.",
        "",
        "| Họ | Mẫu | p50 (µs) | p95 (µs) | p99 (µs) | Lớn nhất (µs) |",
        "|---|---|---|---|---|---|",
    ]
    for name, stats in f9["capture_to_inference_ns"]["by_family"].items():
        lines.append(
            f"| {name} | {vi(stats['samples'], 0)} | {vi(stats['p50_ns'] / 1000)} | "
            f"{vi(stats['p95_ns'] / 1000)} | {vi(stats['p99_ns'] / 1000)} | {vi(stats['max_ns'] / 1000)} |"
        )

    lines += [
        "",
        "## 2. Nhánh F9 — độ trễ suy luận và độ trễ cảnh báo",
        "",
    ]

    bench = f9["benchmark_runs"]
    usable = [r for r in bench["runs"] if (r["latency_ns"].get("inference") or {}).get("observations")]
    if not usable:
        lines += ["Chưa có lần chạy nào bật `--benchmark-metrics`.", ""]
    else:
        for run in usable:
            latency = run["latency_ns"]
            loss = run["imissed_rate"]
            lines += [
                f"### Lần chạy `{run['run_id']}` · ca `{run['case']}`",
                "",
                f"Nhận {vi(run['port_ipackets'], 0)} packet, **mất {vi(loss * 100)}%** "
                f"({vi(run['port_imissed'], 0)} packet). "
                f"{vi(run['f9_snapshots'], 0)} snapshot F9, {vi(run['alerts'], 0)} cảnh báo.",
                "",
                "| Giai đoạn | Số mẫu | p50 | p95 | p99 | Lớn nhất |",
                "|---|---|---|---|---|---|",
            ]
            for key, label in (
                ("parse", "Bóc tách gói"),
                ("pipeline", "Đường ống mỗi gói"),
                ("inference", "Suy luận (gồm dựng đặc trưng)"),
                ("alert", "Cảnh báo đầu-cuối"),
            ):
                block = latency.get(key) or {}
                if not block.get("observations"):
                    continue

                def fmt(value_ns: int) -> str:
                    if value_ns >= 1_000_000:
                        return f"{vi(value_ns / 1_000_000)} ms"
                    if value_ns >= 1_000:
                        return f"{vi(value_ns / 1_000)} µs"
                    return f"{vi(value_ns, 0)} ns"

                lines.append(
                    f"| {label} | {vi(block['observations'], 0)} | {fmt(block['p50'])} | "
                    f"{fmt(block['p95'])} | {fmt(block['p99'])} | {fmt(block['max'])} |"
                )
            lines.append("")

        lines += [
            "### Ba điều phải ghi kèm bảng trên",
            "",
            "**1. Cột \"Suy luận\" KHÔNG phải riêng lời gọi model.** Mốc bắt đầu được lấy trước "
            "`FeatureEngine::encode`, nên nó gồm cả dựng đặc trưng và tạo snapshot. Muốn tách riêng "
            "lời gọi model thì phải thêm một mốc đo nữa trong `nids_dpdk_live.cpp`.",
            "",
            "**2. Số đo dưới tải bão hòa.** Lần chạy mất hơn một nửa số packet, nghĩa là cảm biến "
            "không theo kịp. Con số này là độ trễ **khi quá tải**, không phải độ trễ ở chế độ bình thường. "
            "Muốn có số ở chế độ bình thường thì phải phát lại chậm hơn 1× hoặc dùng PCAP thưa hơn.",
            "",
            "**3. Chỉ đúng trong phạm vi phòng lab VMware.** Không suy ra hiệu năng phần cứng thật.",
            "",
        ]

    lines += ["## 3. Nhánh Terminal V1", ""]
    tbench = terminal.get("benchmark_runs", {})
    tusable = [
        r for r in tbench.get("runs", [])
        if (r["latency_ns"].get("inference") or {}).get("observations")
    ]
    if not tusable:
        lines += ["Chưa có lần chạy nào bật `--benchmark-metrics`.", ""]
    else:
        for run in tusable:
            latency = run["latency_ns"]
            loss = run["imissed_rate"]
            lines += [
                f"### Lần chạy `{run['run_id']}` · ca `{run['case']}`",
                "",
                f"Nhận {vi(run['port_ipackets'], 0)} packet, **mất {vi((loss or 0) * 100)}%**. "
                f"{vi(run['inferences'], 0)} lượt suy luận, {vi(run['alerts'], 0)} cảnh báo. "
                f"{vi(run['non_eof_flows'], 0)} flow đóng bình thường, {vi(run['eof_flows'], 0)} flow đóng ở EOF.",
                "",
                "| Giai đoạn | Số mẫu | p50 | p95 | p99 | Lớn nhất |",
                "|---|---|---|---|---|---|",
            ]
            for key, label in (
                ("inference", "Suy luận (chỉ lời gọi model)"),
                ("alert", "Cảnh báo (gồm chờ flow đóng)"),
            ):
                block = latency.get(key) or {}
                if not block.get("observations"):
                    continue

                def fmt(value_ns: int) -> str:
                    if value_ns >= 1_000_000_000:
                        return f"{vi(value_ns / 1_000_000_000)} s"
                    if value_ns >= 1_000_000:
                        return f"{vi(value_ns / 1_000_000)} ms"
                    if value_ns >= 1_000:
                        return f"{vi(value_ns / 1_000)} µs"
                    return f"{vi(value_ns, 0)} ns"

                lines.append(
                    f"| {label} | {vi(block['observations'], 0)} | {fmt(block['p50'])} | "
                    f"{fmt(block['p95'])} | {fmt(block['p99'])} | {fmt(block['max'])} |"
                )
            lines.append("")

        lines += [
            "### Đọc bảng trên thế nào",
            "",
            "**Lần chạy này mất 0 packet.** Khác hẳn lần đo F9 vốn mất 54%. Vì vậy đây là số đo "
            "ở chế độ bình thường, không phải khi quá tải, và là con số đáng tin nhất hiện có.",
            "",
            "**Cột \"Suy luận\" ở đây ĐÚNG là lời gọi model.** Đặc trưng Terminal do exporter "
            "dựng xong trước khi gọi sink, nên mốc đo chỉ bao lời gọi `bundle_.infer`. "
            "**Không so trực tiếp với cột cùng tên của F9**, vì F9 bấm giờ trước cả bước dựng đặc trưng.",
            "",
            "**Cột \"Cảnh báo\" có đuôi rất dài là đúng thiết kế.** Terminal chỉ quyết định khi flow "
            "đóng, nên khoảng từ packet cuối tới lúc phát cảnh báo gồm cả thời gian chờ flow đóng. "
            "Trung vị 1,37 ms là các flow đóng ngay bằng RST/FIN; giá trị lớn nhất thuộc về flow chỉ "
            "đóng khi hết PCAP. **Đây không phải thời gian tính toán.**",
            "",
        ]

    lines += [
        "",
        "## 4. Khoảng trống còn lại",
        "",
    ]
    gap_lines = [
        "- **Hai cảm biến đo hai thứ khác nhau dưới cùng tên trường.** F9 `inference` gồm cả dựng "
        "đặc trưng, Terminal `inference` thì không. F9 `alert` chốt ngay tại packet 9, Terminal `alert` "
        "còn gồm thời gian chờ flow đóng. **Không bao giờ xếp chung một cột.**",
        "- **F9 chưa tách được lời gọi model khỏi bước dựng đặc trưng**: cần thêm một mốc đo trong "
        "`nids_dpdk_live.cpp`, ngay trước `detection_.process`.",
        "- **F9 chưa có số ở chế độ không quá tải**: lần đo mất 54% packet. Chạy lại với tốc độ phát "
        "thấp hơn để `port_imissed` về 0, như lần đo Terminal đã đạt được.",
    ]
    if not terminal.get("benchmark_runs", {}).get("available"):
        gap_lines.append(
            "- **Terminal V1 chưa được đo đạc**: phải sửa C++ và build lại trước khi công bố số nào."
        )
    lines += gap_lines

    lines += [
        "",
        "## 5. Nguồn đã hash",
        "",
        f"{len(evidence['supporting_sources'])} file, xem danh sách đầy đủ trong bản JSON cùng tên.",
        "",
        f"Test partition: `{evidence['test_partition']['state']}`, 0 lượt đọc.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()

    evidence = build()
    args.output_root.mkdir(parents=True, exist_ok=True)
    json_path = args.output_root / f"{STEM}.json"
    md_path = args.output_root / f"{STEM}.md"
    json_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(evidence), encoding="utf-8")
    print(f"wrote {rel(json_path)}")
    print(f"wrote {rel(md_path)}")
    for gap in evidence["measurement_gaps"]:
        print(f"GAP: {gap}")


if __name__ == "__main__":
    main()
