#!/usr/bin/env python3
"""Compare packet timing in a source PCAP against timing observed at the sensor.

F9 reads inter-arrival time, so a replay that does not reproduce the original
spacing feeds the model features the model never saw in training. The
family-window pass sent its PCAPs with tcpreplay-edit and no receipt records
which pacing was used, which leaves the DoS GoldenEye result (6.7% online
against 100% offline) with an unresolved explanation.

This measures it two ways:

  global   how long the first N packets span in the source, against how long
           the sensor took to see N packets. A ratio far from 1.0 means the
           replay compressed or stretched the whole capture.

  per-flow for every flow the sensor alerted on, the source time from its first
           to its ninth packet against the same span reconstructed from the
           sensor's own checkpoint clock. This is the span F9 actually measures.

The two clocks never align: the source carries unix epoch, the sensor a
monotonic counter. Both are therefore normalised to their own first event and
only the elapsed values are compared.
"""
from __future__ import annotations

import argparse
import json
import statistics
import struct
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]

PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),
    0x4D3CB2A1: (">", 1_000_000_000),
}
LINKTYPE_ETHERNET = 1
CHECKPOINT_PACKET = 9
# Only the headers are needed to key a flow; the payload is skipped unread.
HEADER_BYTES = 64


def iter_packets(path: Path) -> Iterator[tuple[float, bytes]]:
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise ValueError(f"{path} is too short to be a PCAP")
        (magic,) = struct.unpack("<I", header[:4])
        if magic not in PCAP_MAGICS:
            (magic,) = struct.unpack(">I", header[:4])
        if magic not in PCAP_MAGICS:
            raise ValueError(f"{path} is not a PCAP this reader understands")
        endian, divisor = PCAP_MAGICS[magic]
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"{path} link type {linktype} is not Ethernet")
        record = struct.Struct(endian + "IIII")
        while True:
            raw = handle.read(16)
            if len(raw) < 16:
                return
            seconds, fraction, captured, _original = record.unpack(raw)
            head = handle.read(min(captured, HEADER_BYTES))
            if captured > HEADER_BYTES:
                handle.seek(captured - HEADER_BYTES, 1)
            if len(head) < 34:
                continue
            yield seconds + fraction / divisor, head


def flow_key(frame: bytes) -> tuple[Any, ...] | None:
    """Direction-insensitive key, matching how the engine pairs the two halves."""
    if struct.unpack(">H", frame[12:14])[0] != 0x0800:
        return None
    version_ihl = frame[14]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    protocol = frame[23]
    if protocol not in (6, 17):
        return None
    source_ip = ".".join(str(b) for b in frame[26:30])
    destination_ip = ".".join(str(b) for b in frame[30:34])
    offset = 14 + ip_header_length
    if len(frame) < offset + 4:
        return None
    source_port, destination_port = struct.unpack(">HH", frame[offset:offset + 4])
    return (protocol,) + tuple(sorted(
        ((source_ip, source_port), (destination_ip, destination_port))))


def scan_source(path: Path, limit: int | None) -> dict[str, Any]:
    first_seen: dict[Any, float] = {}
    counts: dict[Any, int] = defaultdict(int)
    checkpoint_at: dict[Any, float] = {}
    total = 0
    first_ts = last_ts = None
    for timestamp, frame in iter_packets(path):
        total += 1
        if first_ts is None:
            first_ts = timestamp
        last_ts = timestamp
        key = flow_key(frame)
        if key is not None:
            counts[key] += 1
            if counts[key] == 1:
                first_seen[key] = timestamp
            elif counts[key] == CHECKPOINT_PACKET:
                checkpoint_at[key] = timestamp
        if limit is not None and total >= limit:
            break
    return {
        "packets": total,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "span_seconds": (last_ts - first_ts) if first_ts is not None else 0.0,
        "flows": len(counts),
        "flows_reaching_f9": len(checkpoint_at),
        "first_seen": first_seen,
        "checkpoint_at": checkpoint_at,
    }


def load_sensor(path: Path) -> dict[str, Any]:
    alerts: list[tuple[Any, int]] = []
    summary: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "nids_dpdk_live_summary":
            summary = event
            continue
        if event.get("event_type") != "nids_alert":
            continue
        flow = event.get("flow") or {}
        source = flow.get("source") or {}
        destination = flow.get("destination") or {}
        protocol = 6 if str(flow.get("protocol", "")).lower() == "tcp" else 17
        key = (protocol,) + tuple(sorted((
            (source.get("ip"), source.get("port")),
            (destination.get("ip"), destination.get("port")),
        )))
        alerts.append((key, event.get("checkpoint_timestamp_ns")))
    return {"alerts": alerts, "summary": summary}


def describe(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "min": ordered[0],
        "p25": ordered[len(ordered) // 4],
        "median": statistics.median(ordered),
        "p75": ordered[3 * len(ordered) // 4],
        "max": ordered[-1],
        "mean": statistics.fmean(ordered),
    }


def analyse(family: str, pcap: Path, sensor_log: Path) -> dict[str, Any]:
    sensor = load_sensor(sensor_log)
    summary = sensor["summary"]
    processed = summary.get("packets_seen") or 0
    arrived = summary.get("port_ipackets") or processed
    missed = summary.get("port_imissed") or 0
    # Truncate the source at what the NIC counted arriving, not at what the
    # sensor processed. port_ipackets includes the packets the RX ring dropped
    # (arrived - imissed == packets_seen exactly on every family here), so
    # cutting at packets_seen would charge the drops to the clock and report
    # stretching that is really loss. The two effects are reported separately:
    # pacing is measured against arrivals, loss against the same total.
    #
    # The sensor was also killed by a signal before the replay finished, so only
    # the leading slice of the source is comparable at all.
    source = scan_source(pcap, arrived)

    sensor_checkpoints: dict[Any, int] = {}
    for key, timestamp in sensor["alerts"]:
        if timestamp is not None:
            sensor_checkpoints.setdefault(key, timestamp)

    matched = []
    for key, sensor_ns in sensor_checkpoints.items():
        started = source["first_seen"].get(key)
        checkpoint = source["checkpoint_at"].get(key)
        if started is None or checkpoint is None:
            continue
        matched.append({
            "source_f9_span": checkpoint - started,
            "sensor_checkpoint_ns": sensor_ns,
            "key": key,
        })

    result: dict[str, Any] = {
        "family": family,
        "pcap": str(pcap.relative_to(ROOT)).replace("\\", "/"),
        "sensor_log": str(sensor_log.relative_to(ROOT)).replace("\\", "/"),
        "sensor_stop_reason": summary.get("stop_reason"),
        "sensor_duration_seconds": (summary.get("duration_ms") or 0) / 1000.0,
        "port_ipackets": arrived,
        "port_imissed": missed,
        "packets_processed": processed,
        "rx_drop_fraction": (missed / arrived) if arrived else None,
        "rx_drop_reading": (
            "packets the NIC received and the RX ring discarded for want of a "
            "descriptor. A dropped packet does not stretch a flow's timing, it "
            "removes a sample from it: the nine packets F9 scores are then nine "
            "survivors, not the flow's first nine, so packet_count and every "
            "inter-arrival feature are computed over the wrong set."),
        "sensor_packets_seen": processed,
        "source_packets_compared": source["packets"],
        "source_span_seconds": source["span_seconds"],
        "source_flows": source["flows"],
        "source_flows_reaching_f9": source["flows_reaching_f9"],
        "sensor_alerts": len(sensor["alerts"]),
        "sensor_flows_alerted": len(sensor_checkpoints),
        "flows_matched_by_5tuple": len(matched),
    }

    span = source["span_seconds"]
    duration = result["sensor_duration_seconds"]
    result["global_pacing_ratio"] = (span / duration) if duration else None
    result["global_reading"] = (
        "ratio ~1.0 means the same packets took the same wall-clock time at the "
        "sensor as in the capture; a ratio far above 1.0 means the replay "
        "compressed the capture and shortened every inter-arrival gap")

    if matched:
        # Sensor-side F9 span cannot be read per flow (the alert carries only the
        # checkpoint instant), so the comparison is between the source spans and
        # the spacing of the checkpoints the sensor produced.
        result["source_f9_span_seconds"] = describe(
            [m["source_f9_span"] for m in matched])
        checkpoints = sorted(m["sensor_checkpoint_ns"] for m in matched)
        gaps = [(b - a) / 1e9 for a, b in zip(checkpoints, checkpoints[1:])]
        if gaps:
            result["sensor_checkpoint_gap_seconds"] = describe(gaps)
        source_checkpoints = sorted(
            source["checkpoint_at"][m["key"]] for m in matched)
        source_gaps = [b - a for a, b in
                       zip(source_checkpoints, source_checkpoints[1:])]
        if source_gaps:
            result["source_checkpoint_gap_seconds"] = describe(source_gaps)
        sensor_span = (checkpoints[-1] - checkpoints[0]) / 1e9
        source_checkpoint_span = source_checkpoints[-1] - source_checkpoints[0]
        result["matched_checkpoint_span_source_seconds"] = source_checkpoint_span
        result["matched_checkpoint_span_sensor_seconds"] = sensor_span
        result["matched_pacing_ratio"] = (
            source_checkpoint_span / sensor_span) if sensor_span else None
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="20260808-194942")
    parser.add_argument("--families", nargs="+",
                        default=["dos-goldeneye", "dos-hulk", "ddos",
                                 "ftp-patator", "ssh-patator"])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    windows = ROOT / "run_log/full-flow-v1/family-windows"
    sensors = ROOT / "run_log/t8.5/scenarios" / args.run_id / "ubuntu"

    results = []
    for family in args.families:
        pcap = windows / f"{family}.pcap"
        sensor_log = sensors / f"f9-{family}" / "sensor.jsonl"
        if not pcap.exists() or not sensor_log.exists():
            print(f"{family}: skipped (missing pcap or sensor log)", flush=True)
            continue
        print(f"{family}: scanning {pcap.name} ...", flush=True)
        result = analyse(family, pcap, sensor_log)
        results.append(result)
        print(f"  source span {result['source_span_seconds']:.1f}s over "
              f"{result['source_packets_compared']} arrivals vs sensor "
              f"{result['sensor_duration_seconds']:.1f}s "
              f"-> pacing x{result['global_pacing_ratio']:.2f}"
              f" | rx drop {100 * (result['rx_drop_fraction'] or 0):.1f}%"
              f" ({result['port_imissed']}/{result['port_ipackets']})", flush=True)
        if result.get("matched_pacing_ratio"):
            print(f"  matched flows {result['flows_matched_by_5tuple']}, "
                  f"checkpoint span {result['matched_checkpoint_span_source_seconds']:.1f}s "
                  f"-> {result['matched_checkpoint_span_sensor_seconds']:.1f}s "
                  f"= x{result['matched_pacing_ratio']:.2f}", flush=True)

    document = {
        "kind": "replay_pacing_comparison",
        "run_id": args.run_id,
        "checkpoint_packet": CHECKPOINT_PACKET,
        "note": ("Source timestamps are unix epoch, sensor timestamps are a "
                 "monotonic counter; only elapsed values are compared. The "
                 "source is truncated to the packet count the sensor actually "
                 "saw, because every sensor run was killed by a signal before "
                 "the replay finished."),
        "results": results,
    }
    output = args.output or (
        ROOT / "run_log/full-flow-v1/replay-runs" / args.run_id /
        "replay-pacing-comparison.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
