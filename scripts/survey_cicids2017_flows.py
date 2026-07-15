#!/usr/bin/env python3
"""Survey CIC-IDS2017 flow timeout and capacity candidates by streaming PCAPNG."""

from __future__ import annotations

import argparse
import datetime as dt
import heapq
import json
import os
import platform
import re
import struct
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T1.2"
KIND = "cicids2017_flow_timeout_survey"
SURVEY_REVISION = "1.0.0"
LOCKED_SCAPY_VERSION = "2.7.0"
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
EXPECTED_FILES = {
    "friday-workinghours.pcap",
    "monday-workinghours.pcap",
    "thursday-workinghours.pcap",
    "tuesday-workinghours.pcap",
    "wednesday-workinghours.pcap",
}
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
IDLE_TIMEOUT_SECONDS = (15, 30, 60, 120)
MAX_AGE_SECONDS = (300, 900, 1800, 3600)
CAPACITY_CANDIDATES = (65_536, 131_072, 262_144, 524_288, 1_048_576)
NANOSECONDS = 1_000_000_000
REFERENCE_IDLE_NS = IDLE_TIMEOUT_SECONDS[-1] * NANOSECONDS
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10
FlowKey = tuple[int, int, int, int, int]
Endpoint = tuple[int, int]


@dataclass(frozen=True, slots=True)
class FlowPacket:
    timestamp_ns: int
    protocol: int
    source_ip: int
    source_port: int
    destination_ip: int
    destination_port: int
    tcp_flags: int = 0
    sequence_number: int = 0


@dataclass(slots=True)
class FlowState:
    generation: int
    first_source: Endpoint
    start_by_idle_ns: list[int]
    start_by_max_age_ns: list[int]
    last_capture_ns: int
    last_event_ns: int
    last_forward_ns: int | None = None
    last_reverse_ns: int | None = None
    packets_seen: int = 0
    initial_syn_signature: tuple[int, int, int] | None = None
    saw_non_initial_syn: bool = False
    fin_forward: bool = False
    fin_reverse: bool = False
    final_ack_direction: int | None = None


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("!H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("!I", data, offset)[0]


def canonical_key(packet: FlowPacket) -> FlowKey:
    source = (packet.source_ip, packet.source_port)
    destination = (packet.destination_ip, packet.destination_port)
    low, high = sorted((source, destination))
    return packet.protocol, low[0], low[1], high[0], high[1]


def packet_direction(state: FlowState, packet: FlowPacket) -> int:
    return 0 if (packet.source_ip, packet.source_port) == state.first_source else 1


def magnitude_bucket(value_ns: int) -> str:
    boundaries = (
        (1_000, "<1us"),
        (10_000, "1us-10us"),
        (100_000, "10us-100us"),
        (1_000_000, "100us-1ms"),
        (10_000_000, "1ms-10ms"),
        (100_000_000, "10ms-100ms"),
        (1_000_000_000, "100ms-1s"),
        (5_000_000_000, "1s-5s"),
        (15_000_000_000, "5s-15s"),
        (30_000_000_000, "15s-30s"),
        (60_000_000_000, "30s-60s"),
        (120_000_000_000, "60s-120s"),
    )
    for upper_bound, label in boundaries:
        if value_ns < upper_bound:
            return label
    return ">=120s"


def duration_bucket(duration_ns: int) -> str:
    return magnitude_bucket(max(0, duration_ns))


def new_delta_statistics() -> dict[str, Any]:
    return {
        "count": 0,
        "negative_count": 0,
        "zero_count": 0,
        "positive_count": 0,
        "sum_ns": 0,
        "minimum_ns": None,
        "maximum_ns": None,
        "histogram": Counter(),
    }


def update_delta_statistics(statistics: dict[str, Any], delta_ns: int) -> None:
    statistics["count"] += 1
    statistics["sum_ns"] += delta_ns
    current_minimum = statistics["minimum_ns"]
    current_maximum = statistics["maximum_ns"]
    statistics["minimum_ns"] = delta_ns if current_minimum is None else min(current_minimum, delta_ns)
    statistics["maximum_ns"] = delta_ns if current_maximum is None else max(current_maximum, delta_ns)
    if delta_ns < 0:
        statistics["negative_count"] += 1
        statistics["histogram"][f"negative:{magnitude_bucket(-delta_ns)}"] += 1
    elif delta_ns == 0:
        statistics["zero_count"] += 1
        statistics["histogram"]["zero"] += 1
    else:
        statistics["positive_count"] += 1
        statistics["histogram"][f"positive:{magnitude_bucket(delta_ns)}"] += 1


def new_profile_statistics() -> dict[str, Any]:
    return {
        "session_count": 0,
        "duration_sum_ns": 0,
        "minimum_duration_ns": None,
        "maximum_duration_ns": None,
        "duration_histogram": Counter(),
        "completion_reasons": Counter(),
    }


def record_session(
    statistics: dict[str, Any],
    start_ns: int,
    last_event_ns: int,
    reason: str,
) -> None:
    duration_ns = max(0, last_event_ns - start_ns)
    statistics["session_count"] += 1
    statistics["duration_sum_ns"] += duration_ns
    minimum = statistics["minimum_duration_ns"]
    maximum = statistics["maximum_duration_ns"]
    statistics["minimum_duration_ns"] = duration_ns if minimum is None else min(minimum, duration_ns)
    statistics["maximum_duration_ns"] = duration_ns if maximum is None else max(maximum, duration_ns)
    statistics["duration_histogram"][duration_bucket(duration_ns)] += 1
    statistics["completion_reasons"][reason] += 1


class FlowSurvey:
    def __init__(self) -> None:
        self.active: dict[FlowKey, FlowState] = {}
        self.expiry_heap: list[tuple[int, int, FlowKey]] = []
        self.watermark_ns: int | None = None
        self.next_generation = 1
        self.eligible_packet_count = 0
        self.reference_flow_count = 0
        self.reference_completion_reasons: Counter[str] = Counter()
        self.active_flow_peak = 0
        self.active_flow_peak_watermark_ns: int | None = None
        self.idle_profiles = {
            str(seconds): new_profile_statistics() for seconds in IDLE_TIMEOUT_SECONDS
        }
        self.max_age_profiles = {
            str(seconds): new_profile_statistics() for seconds in MAX_AGE_SECONDS
        }
        self.iat = {
            "overall": new_delta_statistics(),
            "forward": new_delta_statistics(),
            "reverse": new_delta_statistics(),
        }

    def _create_state(self, packet: FlowPacket) -> tuple[FlowKey, FlowState]:
        key = canonical_key(packet)
        state = FlowState(
            generation=self.next_generation,
            first_source=(packet.source_ip, packet.source_port),
            start_by_idle_ns=[packet.timestamp_ns] * len(IDLE_TIMEOUT_SECONDS),
            start_by_max_age_ns=[packet.timestamp_ns] * len(MAX_AGE_SECONDS),
            last_capture_ns=packet.timestamp_ns,
            last_event_ns=packet.timestamp_ns,
        )
        self.next_generation += 1
        self.reference_flow_count += 1
        self.active[key] = state
        heapq.heappush(
            self.expiry_heap,
            (state.last_event_ns + REFERENCE_IDLE_NS, state.generation, key),
        )
        if len(self.active) > self.active_flow_peak:
            self.active_flow_peak = len(self.active)
            self.active_flow_peak_watermark_ns = self.watermark_ns
        return key, state

    def _finish_state(self, key: FlowKey, state: FlowState, reason: str) -> None:
        if self.active.get(key) is not state:
            return
        for index, seconds in enumerate(IDLE_TIMEOUT_SECONDS):
            record_session(
                self.idle_profiles[str(seconds)],
                state.start_by_idle_ns[index],
                state.last_event_ns,
                reason,
            )
        for index, seconds in enumerate(MAX_AGE_SECONDS):
            record_session(
                self.max_age_profiles[str(seconds)],
                state.start_by_max_age_ns[index],
                state.last_event_ns,
                reason,
            )
        self.reference_completion_reasons[reason] += 1
        del self.active[key]

    def _expire_reference_flows(self, watermark_ns: int) -> None:
        while self.expiry_heap and self.expiry_heap[0][0] <= watermark_ns:
            _, generation, key = heapq.heappop(self.expiry_heap)
            state = self.active.get(key)
            if state is None or state.generation != generation:
                continue
            deadline_ns = state.last_event_ns + REFERENCE_IDLE_NS
            if deadline_ns <= watermark_ns:
                self._finish_state(key, state, "idle_timeout")
            else:
                heapq.heappush(self.expiry_heap, (deadline_ns, state.generation, key))

    def _roll_idle_profiles(
        self,
        state: FlowState,
        packet: FlowPacket,
        watermark_ns: int,
    ) -> None:
        gap_ns = watermark_ns - state.last_event_ns
        if gap_ns < IDLE_TIMEOUT_SECONDS[0] * NANOSECONDS:
            return
        for index, seconds in enumerate(IDLE_TIMEOUT_SECONDS):
            if gap_ns >= seconds * NANOSECONDS:
                record_session(
                    self.idle_profiles[str(seconds)],
                    state.start_by_idle_ns[index],
                    state.last_event_ns,
                    "idle_timeout",
                )
                state.start_by_idle_ns[index] = packet.timestamp_ns

    def _roll_max_age_profiles(
        self,
        state: FlowState,
        packet: FlowPacket,
        watermark_ns: int,
    ) -> None:
        for index, seconds in enumerate(MAX_AGE_SECONDS):
            if watermark_ns - state.start_by_max_age_ns[index] >= seconds * NANOSECONDS:
                record_session(
                    self.max_age_profiles[str(seconds)],
                    state.start_by_max_age_ns[index],
                    state.last_event_ns,
                    "max_age",
                )
                state.start_by_max_age_ns[index] = packet.timestamp_ns

    @staticmethod
    def _is_new_generation_syn(state: FlowState, packet: FlowPacket) -> bool:
        if packet.protocol != 6 or not packet.tcp_flags & TCP_SYN or packet.tcp_flags & TCP_ACK:
            return False
        signature = (packet.source_ip, packet.source_port, packet.sequence_number)
        return not (
            state.initial_syn_signature == signature
            and not state.saw_non_initial_syn
        )

    @staticmethod
    def _update_syn_tracking(state: FlowState, packet: FlowPacket) -> None:
        is_initial_syn = (
            packet.protocol == 6
            and bool(packet.tcp_flags & TCP_SYN)
            and not bool(packet.tcp_flags & TCP_ACK)
        )
        signature = (packet.source_ip, packet.source_port, packet.sequence_number)
        if state.packets_seen == 0 and is_initial_syn:
            state.initial_syn_signature = signature
        elif not is_initial_syn or signature != state.initial_syn_signature:
            state.saw_non_initial_syn = True

    def _update_iat(self, state: FlowState, packet: FlowPacket, direction: int) -> None:
        if state.packets_seen:
            update_delta_statistics(self.iat["overall"], packet.timestamp_ns - state.last_capture_ns)
        if direction == 0:
            if state.last_forward_ns is not None:
                update_delta_statistics(self.iat["forward"], packet.timestamp_ns - state.last_forward_ns)
            state.last_forward_ns = packet.timestamp_ns
        else:
            if state.last_reverse_ns is not None:
                update_delta_statistics(self.iat["reverse"], packet.timestamp_ns - state.last_reverse_ns)
            state.last_reverse_ns = packet.timestamp_ns

    def _update_tcp_close_state(
        self,
        state: FlowState,
        packet: FlowPacket,
        direction: int,
    ) -> str | None:
        if packet.protocol != 6:
            return None
        final_ack_seen = (
            state.final_ack_direction is not None
            and direction == state.final_ack_direction
            and bool(packet.tcp_flags & TCP_ACK)
        )
        if packet.tcp_flags & TCP_FIN:
            had_both_fin = state.fin_forward and state.fin_reverse
            if direction == 0:
                state.fin_forward = True
            else:
                state.fin_reverse = True
            if not had_both_fin and state.fin_forward and state.fin_reverse:
                state.final_ack_direction = 1 - direction
        if packet.tcp_flags & TCP_RST:
            return "rst"
        if final_ack_seen:
            return "fin_handshake"
        return None

    def observe(self, packet: FlowPacket) -> None:
        self.eligible_packet_count += 1
        if self.watermark_ns is None or packet.timestamp_ns > self.watermark_ns:
            self.watermark_ns = packet.timestamp_ns
        watermark_ns = self.watermark_ns
        self._expire_reference_flows(watermark_ns)

        key = canonical_key(packet)
        state = self.active.get(key)
        if state is not None and self._is_new_generation_syn(state, packet):
            self._finish_state(key, state, "tuple_reuse")
            state = None

        if state is None:
            key, state = self._create_state(packet)
        else:
            self._roll_idle_profiles(state, packet, watermark_ns)
            self._roll_max_age_profiles(state, packet, watermark_ns)

        direction = packet_direction(state, packet)
        self._update_iat(state, packet, direction)
        self._update_syn_tracking(state, packet)
        state.packets_seen += 1
        state.last_capture_ns = packet.timestamp_ns
        if packet.timestamp_ns > state.last_event_ns:
            state.last_event_ns = packet.timestamp_ns
        close_reason = self._update_tcp_close_state(state, packet, direction)
        if close_reason is not None:
            self._finish_state(key, state, close_reason)

    def finish_file(self) -> None:
        for key, state in list(self.active.items()):
            self._finish_state(key, state, "end_of_file")
        self.expiry_heap.clear()

    def as_document(self) -> dict[str, Any]:
        return json_ready(
            {
                "eligible_packet_count": self.eligible_packet_count,
                "reference_idle_seconds": IDLE_TIMEOUT_SECONDS[-1],
                "reference_flow_count": self.reference_flow_count,
                "reference_completion_reasons": self.reference_completion_reasons,
                "active_flow_peak": self.active_flow_peak,
                "active_flow_peak_watermark_ns": self.active_flow_peak_watermark_ns,
                "idle_timeout_profiles": self.idle_profiles,
                "max_age_profiles_with_120s_idle": self.max_age_profiles,
                "iat_reference_120s": self.iat,
            }
        )


def parse_flow_packet(data: bytes, timestamp_ns: int) -> tuple[FlowPacket | None, str | None]:
    if len(data) < 14:
        return None, "truncated_ethernet_header"
    ethertype = read_u16(data, 12)
    offset = 14
    while ethertype in VLAN_ETHERTYPES:
        if len(data) < offset + 4:
            return None, "truncated_vlan_header"
        ethertype = read_u16(data, offset + 2)
        offset += 4
    if ethertype != 0x0800:
        return None, "non_ipv4"
    if len(data) < offset + 20:
        return None, "truncated_ipv4_header"
    version_ihl = data[offset]
    if version_ihl >> 4 != 4:
        return None, "invalid_ipv4_version"
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        return None, "invalid_ipv4_ihl"
    if len(data) < offset + ihl:
        return None, "truncated_ipv4_options"
    total_length = read_u16(data, offset + 2)
    if total_length < ihl:
        return None, "invalid_ipv4_total_length"
    ip_end = offset + total_length
    if len(data) < ip_end:
        return None, "truncated_ipv4_packet"
    flags_fragment = read_u16(data, offset + 6)
    if flags_fragment & 0x3FFF:
        return None, "ipv4_fragmented"
    protocol = data[offset + 9]
    if protocol not in (6, 17):
        return None, "unsupported_transport"
    source_ip = read_u32(data, offset + 12)
    destination_ip = read_u32(data, offset + 16)
    transport_offset = offset + ihl
    transport_length = total_length - ihl
    if protocol == 6:
        if transport_length < 20 or len(data) < transport_offset + 20:
            return None, "invalid_tcp_length"
        tcp_header_length = (data[transport_offset + 12] >> 4) * 4
        if tcp_header_length < 20:
            return None, "invalid_tcp_data_offset"
        if tcp_header_length > transport_length:
            return None, "tcp_header_exceeds_ipv4_length"
        return (
            FlowPacket(
                timestamp_ns=timestamp_ns,
                protocol=protocol,
                source_ip=source_ip,
                source_port=read_u16(data, transport_offset),
                destination_ip=destination_ip,
                destination_port=read_u16(data, transport_offset + 2),
                tcp_flags=data[transport_offset + 13],
                sequence_number=read_u32(data, transport_offset + 4),
            ),
            None,
        )
    if transport_length < 8 or len(data) < transport_offset + 8:
        return None, "invalid_udp_length"
    udp_length = read_u16(data, transport_offset + 4)
    if udp_length < 8 or udp_length > transport_length:
        return None, "invalid_udp_length"
    return (
        FlowPacket(
            timestamp_ns=timestamp_ns,
            protocol=protocol,
            source_ip=source_ip,
            source_port=read_u16(data, transport_offset),
            destination_ip=destination_ip,
            destination_port=read_u16(data, transport_offset + 2),
        ),
        None,
    )


def json_ready(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(sorted(value.items()))
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value


def load_scapy() -> tuple[str, Any]:
    try:
        import scapy
        from scapy.utils import RawPcapNgReader
    except ImportError as error:
        raise RuntimeError("Scapy 2.7.0 is required for PCAPNG container reading") from error
    if scapy.__version__ != LOCKED_SCAPY_VERSION:
        raise RuntimeError(
            f"Scapy version must equal {LOCKED_SCAPY_VERSION}, found {scapy.__version__}"
        )
    return scapy.__version__, RawPcapNgReader


def source_identity(path: Path) -> dict[str, Any]:
    stat = path.stat()
    with path.open("rb") as source:
        magic = source.read(4)
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "size_bytes": stat.st_size,
        "modified_time_ns": stat.st_mtime_ns,
        "magic_hex": magic.hex(),
    }


def receipt_name(path: Path) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", path.stem.lower()).strip("-")
    return f"{slug}.json"


def write_json_atomic(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise ValueError(f"refusing to overwrite existing file: {path}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_name = output.name
            json.dump(json_ready(document), output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise


def reusable_receipt(path: Path, identity: Mapping[str, Any]) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot resume from invalid receipt {path}: {error}") from error
    if (
        document.get("status") != "passed"
        or document.get("survey_revision") != SURVEY_REVISION
        or document.get("source") != dict(identity)
        or document.get("settings") != survey_settings()
    ):
        raise ValueError(f"refusing to overwrite stale or incomplete receipt: {path}")
    print(f"REUSE {identity['name']} from {path}", flush=True)
    return document


def survey_settings() -> dict[str, Any]:
    return {
        "flow_key": "canonical bidirectional IPv4 5-tuple",
        "direction": "source endpoint of first packet",
        "capture_order_preserved": True,
        "signed_iat_preserved": True,
        "timeout_clock": "nondecreasing per-file timestamp watermark",
        "idle_timeout_candidates_seconds": list(IDLE_TIMEOUT_SECONDS),
        "max_age_candidates_seconds": list(MAX_AGE_SECONDS),
        "reference_idle_seconds": IDLE_TIMEOUT_SECONDS[-1],
        "capacity_candidates": list(CAPACITY_CANDIDATES),
        "tcp_rst": "include packet then close",
        "tcp_fin": "close after FIN in both directions and later ACK from peer of second FIN",
        "tuple_reuse": "new non-ACK SYN, except identical initial SYN retransmission",
    }


def timestamp_ns(metadata: Any) -> tuple[int, bool]:
    resolution = int(metadata.tsresol)
    ticks = (int(metadata.tshigh) << 32) | int(metadata.tslow)
    value, remainder = divmod(ticks * NANOSECONDS, resolution)
    return value, bool(remainder)


def survey_pcapng_file(
    path: Path,
    receipt_path: Path,
    reader_type: Any,
    scapy_version: str,
    progress_every: int,
) -> dict[str, Any]:
    identity = source_identity(path)
    if identity["magic_hex"] != PCAPNG_MAGIC.hex():
        raise ValueError(f"{path} is not a PCAPNG file")
    reused = reusable_receipt(receipt_path, identity)
    if reused is not None:
        return reused

    print(f"START {path.name} ({identity['size_bytes']} bytes)", flush=True)
    started = time.monotonic()
    survey = FlowSurvey()
    packet_count = 0
    timestamp_duplicate_count = 0
    timestamp_regression_count = 0
    timestamp_rounding_count = 0
    previous_timestamp_ns: int | None = None
    ignored_packets: Counter[str] = Counter()
    reader = reader_type(str(path))
    try:
        for raw, metadata in reader:
            packet_count += 1
            current_timestamp_ns, rounded = timestamp_ns(metadata)
            timestamp_rounding_count += int(rounded)
            if previous_timestamp_ns is not None:
                if current_timestamp_ns == previous_timestamp_ns:
                    timestamp_duplicate_count += 1
                elif current_timestamp_ns < previous_timestamp_ns:
                    timestamp_regression_count += 1
            previous_timestamp_ns = current_timestamp_ns
            if int(metadata.linktype) != 1:
                ignored_packets["unsupported_linktype"] += 1
            else:
                packet, error = parse_flow_packet(raw, current_timestamp_ns)
                if packet is None:
                    ignored_packets[error or "unknown"] += 1
                else:
                    survey.observe(packet)
            if packet_count % progress_every == 0:
                elapsed = time.monotonic() - started
                rate = packet_count / elapsed if elapsed else 0.0
                print(
                    f"PROGRESS {path.name} packets={packet_count} rate={rate:.0f}/s "
                    f"active={len(survey.active)} peak={survey.active_flow_peak}",
                    flush=True,
                )
    finally:
        reader.close()
    survey.finish_file()

    duration = time.monotonic() - started
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "cicids2017_flow_timeout_file_survey",
        "survey_revision": SURVEY_REVISION,
        "status": "passed",
        "generated_at_utc": utc_now(),
        "source": identity,
        "reader": {"name": "Scapy RawPcapNgReader", "version": scapy_version},
        "settings": survey_settings(),
        "statistics": {
            "packet_count": packet_count,
            "timestamp_duplicate_count": timestamp_duplicate_count,
            "timestamp_regression_count": timestamp_regression_count,
            "timestamp_rounding_count": timestamp_rounding_count,
            "ignored_packets": ignored_packets,
            "flow": survey.as_document(),
        },
        "duration_seconds": round(duration, 3),
    }
    write_json_atomic(receipt_path, receipt)
    print(
        f"DONE {path.name} packets={packet_count} flows={survey.reference_flow_count} "
        f"peak={survey.active_flow_peak} duration={duration:.1f}s receipt={receipt_path}",
        flush=True,
    )
    return json_ready(receipt)


def merge_profile_documents(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    result = new_profile_statistics()
    for document in documents:
        result["session_count"] += int(document["session_count"])
        result["duration_sum_ns"] += int(document["duration_sum_ns"])
        minimum = document.get("minimum_duration_ns")
        maximum = document.get("maximum_duration_ns")
        if minimum is not None:
            current = result["minimum_duration_ns"]
            result["minimum_duration_ns"] = minimum if current is None else min(current, minimum)
        if maximum is not None:
            current = result["maximum_duration_ns"]
            result["maximum_duration_ns"] = maximum if current is None else max(current, maximum)
        result["duration_histogram"].update(document.get("duration_histogram", {}))
        result["completion_reasons"].update(document.get("completion_reasons", {}))
    return json_ready(result)


def merge_delta_documents(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    result = new_delta_statistics()
    for document in documents:
        for name in ("count", "negative_count", "zero_count", "positive_count", "sum_ns"):
            result[name] += int(document.get(name, 0))
        minimum = document.get("minimum_ns")
        maximum = document.get("maximum_ns")
        if minimum is not None:
            current = result["minimum_ns"]
            result["minimum_ns"] = minimum if current is None else min(current, minimum)
        if maximum is not None:
            current = result["maximum_ns"]
            result["maximum_ns"] = maximum if current is None else max(current, maximum)
        result["histogram"].update(document.get("histogram", {}))
    return json_ready(result)


def aggregate_receipts(receipts: Sequence[Mapping[str, Any]], scapy_version: str) -> dict[str, Any]:
    flows = [receipt["statistics"]["flow"] for receipt in receipts]
    peak_flow = max(flows, key=lambda flow: int(flow["active_flow_peak"]))
    peak = int(peak_flow["active_flow_peak"])
    idle_profiles = {
        str(seconds): merge_profile_documents(
            flow["idle_timeout_profiles"][str(seconds)] for flow in flows
        )
        for seconds in IDLE_TIMEOUT_SECONDS
    }
    max_age_profiles = {
        str(seconds): merge_profile_documents(
            flow["max_age_profiles_with_120s_idle"][str(seconds)] for flow in flows
        )
        for seconds in MAX_AGE_SECONDS
    }
    iat = {
        direction: merge_delta_documents(
            flow["iat_reference_120s"][direction] for flow in flows
        )
        for direction in ("overall", "forward", "reverse")
    }
    completion_reasons: Counter[str] = Counter()
    ignored_packets: Counter[str] = Counter()
    for receipt, flow in zip(receipts, flows):
        completion_reasons.update(flow["reference_completion_reasons"])
        ignored_packets.update(receipt["statistics"]["ignored_packets"])
    capacity = [
        {
            "active_flow_limit": candidate,
            "observed_peak": peak,
            "headroom_flows": candidate - peak,
            "assessment": (
                "no_capacity_eviction_required"
                if peak <= candidate
                else "exact_capacity_eviction_simulation_required"
            ),
        }
        for candidate in CAPACITY_CANDIDATES
    ]
    reference_flow_count = sum(int(flow["reference_flow_count"]) for flow in flows)
    checks = [
        {
            "name": "source.file_count",
            "status": "passed" if len(receipts) == len(EXPECTED_FILES) else "failed",
        },
        {
            "name": "scan.all_files_complete",
            "status": "passed"
            if all(receipt.get("status") == "passed" for receipt in receipts)
            else "failed",
        },
        {
            "name": "flow.reference_completions",
            "status": "passed"
            if sum(completion_reasons.values()) == reference_flow_count
            else "failed",
        },
        {
            "name": "flow.reference_matches_120s_profile",
            "status": "passed"
            if idle_profiles[str(IDLE_TIMEOUT_SECONDS[-1])]["session_count"]
            == reference_flow_count
            else "failed",
        },
    ]
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": KIND,
        "survey_revision": SURVEY_REVISION,
        "status": status,
        "generated_at_utc": utc_now(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "reader": {"name": "Scapy RawPcapNgReader", "version": scapy_version},
        "settings": survey_settings(),
        "files": [receipt["source"] for receipt in receipts],
        "totals": {
            "packet_count": sum(int(receipt["statistics"]["packet_count"]) for receipt in receipts),
            "eligible_flow_packet_count": sum(
                int(flow["eligible_packet_count"]) for flow in flows
            ),
            "timestamp_duplicate_count": sum(
                int(receipt["statistics"]["timestamp_duplicate_count"])
                for receipt in receipts
            ),
            "timestamp_regression_count": sum(
                int(receipt["statistics"]["timestamp_regression_count"])
                for receipt in receipts
            ),
            "timestamp_rounding_count": sum(
                int(receipt["statistics"]["timestamp_rounding_count"])
                for receipt in receipts
            ),
            "ignored_packets": dict(sorted(ignored_packets.items())),
            "reference_flow_count": reference_flow_count,
            "reference_completion_reasons": dict(sorted(completion_reasons.items())),
            "active_flow_peak": peak,
            "idle_timeout_profiles": idle_profiles,
            "max_age_profiles_with_120s_idle": max_age_profiles,
            "iat_reference_120s": iat,
            "capacity_assessment": capacity,
        },
        "checks": checks,
    }


def require_expected_sources(input_dir: Path) -> list[Path]:
    if not input_dir.is_dir():
        raise ValueError(f"input directory does not exist: {input_dir}")
    files = sorted(input_dir.glob("*.pcap"), key=lambda path: path.name.lower())
    names = {path.name.lower() for path in files}
    if names != EXPECTED_FILES:
        missing = sorted(EXPECTED_FILES - names)
        unexpected = sorted(names - EXPECTED_FILES)
        raise ValueError(
            f"expected the five CIC-IDS2017 PCAP files; missing={missing}, unexpected={unexpected}"
        )
    return files


def run_self_test() -> None:
    load_scapy()
    client = (0x0A000001, 12345)
    server = (0x0A000002, 80)

    def tcp(timestamp: int, source: Endpoint, destination: Endpoint, flags: int, sequence: int = 1) -> FlowPacket:
        return FlowPacket(timestamp, 6, source[0], source[1], destination[0], destination[1], flags, sequence)

    survey = FlowSurvey()
    survey.observe(tcp(100, client, server, TCP_SYN, 10))
    survey.observe(tcp(110, client, server, TCP_SYN, 10))
    survey.observe(tcp(120, server, client, TCP_SYN | TCP_ACK, 20))
    survey.observe(tcp(90, client, server, TCP_ACK, 11))
    survey.observe(tcp(130, client, server, TCP_FIN | TCP_ACK, 12))
    survey.observe(tcp(140, server, client, TCP_FIN | TCP_ACK, 21))
    assert survey.reference_completion_reasons["fin_handshake"] == 0
    survey.observe(tcp(150, client, server, TCP_ACK, 13))
    assert survey.reference_completion_reasons["fin_handshake"] == 1
    assert survey.iat["overall"]["negative_count"] == 1

    survey.observe(tcp(200, client, server, TCP_SYN, 30))
    survey.observe(tcp(210, server, client, TCP_RST | TCP_ACK, 40))
    assert survey.reference_completion_reasons["rst"] == 1

    survey.observe(tcp(300, client, server, TCP_SYN, 50))
    survey.observe(tcp(310, server, client, TCP_ACK, 60))
    survey.observe(tcp(320, client, server, TCP_SYN, 70))
    assert survey.reference_completion_reasons["tuple_reuse"] == 1
    survey.finish_file()

    idle = FlowSurvey()
    udp_a = FlowPacket(0, 17, client[0], 1000, server[0], 2000)
    udp_b = FlowPacket(20 * NANOSECONDS, 17, client[0], 1000, server[0], 2000)
    idle.observe(udp_a)
    idle.observe(udp_b)
    assert idle.idle_profiles["15"]["session_count"] == 1
    assert idle.idle_profiles["30"]["session_count"] == 0
    idle.finish_file()
    assert idle.idle_profiles["15"]["session_count"] == 2
    assert idle.idle_profiles["30"]["session_count"] == 1

    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ipv4_tcp = bytes.fromhex("4500002c0000400040060000c0a80101c0a80102")
    tcp_header = bytes.fromhex("04d2005000000001000000005018200000000000")
    parsed, error = parse_flow_packet(ethernet + ipv4_tcp + tcp_header + b"test", 123)
    assert error is None and parsed is not None
    assert parsed.source_port == 1234 and parsed.destination_port == 80
    print("self-test passed")


def command_scan(args: argparse.Namespace) -> int:
    project_root = Path(__file__).resolve().parents[1]
    expected_input = (project_root / "pcap").resolve()
    expected_output_root = (project_root / "run_log" / "t1.2").resolve()
    input_dir = args.input_dir.resolve()
    output = args.output.resolve()
    if input_dir != expected_input:
        raise ValueError(f"input directory must equal {expected_input}")
    if output == expected_output_root or expected_output_root not in output.parents:
        raise ValueError(f"output must be a file below {expected_output_root}")
    if os.path.lexists(output):
        raise ValueError(f"refusing to overwrite existing aggregate receipt: {output}")
    files = require_expected_sources(input_dir)
    scapy_version, reader_type = load_scapy()
    receipt_dir = output.parent / "flow-survey"
    receipts = [
        survey_pcapng_file(
            path,
            receipt_dir / receipt_name(path),
            reader_type,
            scapy_version,
            args.progress_every,
        )
        for path in files
    ]
    aggregate = aggregate_receipts(receipts, scapy_version)
    write_json_atomic(output, aggregate)
    print(f"wrote {output} ({aggregate['status']})", flush=True)
    return 0 if aggregate["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run bounded internal checks and exit")
    parser.add_argument("--input-dir", type=Path, default=project_root / "pcap")
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "run_log" / "t1.2" / "flow-survey.json",
    )
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.progress_every <= 0:
            raise ValueError("--progress-every must be positive")
        if args.self_test:
            run_self_test()
            return 0
        return command_scan(args)
    except (AssertionError, OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
