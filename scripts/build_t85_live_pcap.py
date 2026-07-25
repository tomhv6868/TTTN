#!/usr/bin/env python3
"""Build the MTU-safe nine-packet DDoS fixture used by the live demo."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


EXPECTED_INPUT_SHA256 = "80e28b10bafa83b060c95b101ab853e2976c4930d566e65f0038a94e465d4988"
EXPECTED_RECORDS = 9
MAX_FRAME_BYTES = 1514
ETHERNET_LINKTYPE = 1


@dataclass(frozen=True)
class PcapFormat:
    endian: str
    nanosecond_resolution: bool


@dataclass(frozen=True)
class PacketRecord:
    timestamp_seconds: int
    timestamp_fraction: int
    data: bytes


PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": PcapFormat("<", False),
    b"\xa1\xb2\xc3\xd4": PcapFormat(">", False),
    b"\x4d\x3c\xb2\xa1": PcapFormat("<", True),
    b"\xa1\xb2\x3c\x4d": PcapFormat(">", True),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_pcap(data: bytes) -> tuple[PcapFormat, bytes, list[PacketRecord]]:
    if len(data) < 24:
        raise ValueError("PCAP global header is truncated")
    pcap_format = PCAP_FORMATS.get(data[:4])
    if pcap_format is None:
        raise ValueError("only classic microsecond/nanosecond PCAP is supported")
    endian = pcap_format.endian
    major, minor, _, _, snaplen, linktype = struct.unpack(
        f"{endian}HHiiii", data[4:24]
    )
    if (major, minor) != (2, 4):
        raise ValueError(f"unexpected PCAP version: {major}.{minor}")
    if snaplen < MAX_FRAME_BYTES or linktype != ETHERNET_LINKTYPE:
        raise ValueError(
            f"PCAP must be Ethernet with snaplen >= {MAX_FRAME_BYTES}"
        )

    records: list[PacketRecord] = []
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("PCAP record header is truncated")
        seconds, fraction, captured_length, original_length = struct.unpack(
            f"{endian}IIII", data[offset : offset + 16]
        )
        offset += 16
        end = offset + captured_length
        if end > len(data):
            raise ValueError("PCAP record payload is truncated")
        if captured_length != original_length:
            raise ValueError("source fixture must contain complete packet records")
        records.append(PacketRecord(seconds, fraction, data[offset:end]))
        offset = end
    if len(records) != EXPECTED_RECORDS:
        raise ValueError(
            f"expected {EXPECTED_RECORDS} records, observed {len(records)}"
        )
    return pcap_format, data[:24], records


def ipv4_offset(frame: bytes) -> int:
    if len(frame) < 14:
        raise ValueError("Ethernet frame is truncated")
    offset = 14
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type in (0x8100, 0x88A8):
        if len(frame) < 18:
            raise ValueError("VLAN Ethernet frame is truncated")
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ether_type != 0x0800:
        raise ValueError(f"live fixture requires IPv4, observed 0x{ether_type:04x}")
    return offset


def mtu_safe_frame(frame: bytes) -> tuple[bytes, bool]:
    ip_offset = ipv4_offset(frame)
    if len(frame) < ip_offset + 20:
        raise ValueError("IPv4 header is truncated")
    ihl = (frame[ip_offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < ip_offset + ihl:
        raise ValueError("invalid IPv4 header length")
    if frame[ip_offset + 9] != 6:
        raise ValueError("live fixture requires TCP packets")
    fragment_field = struct.unpack("!H", frame[ip_offset + 6 : ip_offset + 8])[0]
    if fragment_field & 0x3FFF:
        raise ValueError("fragmented source packets are not supported")

    original_ip_length = struct.unpack(
        "!H", frame[ip_offset + 2 : ip_offset + 4]
    )[0]
    if original_ip_length > len(frame) - ip_offset:
        raise ValueError("IPv4 total length exceeds the captured frame")
    if len(frame) <= MAX_FRAME_BYTES:
        return frame, False

    output = bytearray(frame[:MAX_FRAME_BYTES])
    ip_length = len(output) - ip_offset
    tcp_offset = ip_offset + ihl
    if ip_length < ihl + 20:
        raise ValueError("MTU cap would truncate the TCP header")
    tcp_header_length = (output[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or tcp_offset + tcp_header_length > len(output):
        raise ValueError("invalid TCP header length")

    output[ip_offset + 2 : ip_offset + 4] = struct.pack("!H", ip_length)
    output[ip_offset + 10 : ip_offset + 12] = b"\0\0"
    ip_checksum = internet_checksum(bytes(output[ip_offset : ip_offset + ihl]))
    output[ip_offset + 10 : ip_offset + 12] = struct.pack("!H", ip_checksum)

    tcp_length = ip_length - ihl
    output[tcp_offset + 16 : tcp_offset + 18] = b"\0\0"
    pseudo_header = (
        bytes(output[ip_offset + 12 : ip_offset + 20])
        + b"\0"
        + bytes((output[ip_offset + 9],))
        + struct.pack("!H", tcp_length)
    )
    tcp_checksum = internet_checksum(
        pseudo_header + bytes(output[tcp_offset : tcp_offset + tcp_length])
    )
    output[tcp_offset + 16 : tcp_offset + 18] = struct.pack("!H", tcp_checksum)
    return bytes(output), True


def encode_pcap(
    pcap_format: PcapFormat,
    global_header: bytes,
    records: list[PacketRecord],
) -> tuple[bytes, int, int]:
    output = bytearray(global_header)
    truncated_records = 0
    maximum_input_frame = 0
    for record in records:
        maximum_input_frame = max(maximum_input_frame, len(record.data))
        frame, truncated = mtu_safe_frame(record.data)
        truncated_records += int(truncated)
        output.extend(
            struct.pack(
                f"{pcap_format.endian}IIII",
                record.timestamp_seconds,
                record.timestamp_fraction,
                len(frame),
                len(frame),
            )
        )
        output.extend(frame)
    return bytes(output), truncated_records, maximum_input_frame


def write_idempotent(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as destination:
            destination.write(data)
        return "generated"
    except FileExistsError:
        if path.read_bytes() != data:
            raise ValueError(f"refusing to overwrite different output: {path}")
        return "reused"


def build(input_path: Path, output_path: Path) -> dict[str, object]:
    source = input_path.read_bytes()
    source_sha256 = sha256_bytes(source)
    if source_sha256 != EXPECTED_INPUT_SHA256:
        raise ValueError(
            "input is not the accepted T3.2 attack-tcp-f9.pcap: "
            f"observed SHA-256 {source_sha256}"
        )
    pcap_format, global_header, records = parse_pcap(source)
    output, truncated_records, maximum_input_frame = encode_pcap(
        pcap_format, global_header, records
    )
    output_format, _, output_records = parse_pcap(output)
    if output_format != pcap_format:
        raise RuntimeError("output PCAP format changed unexpectedly")
    if any(len(record.data) > MAX_FRAME_BYTES for record in output_records):
        raise RuntimeError("output contains an oversized Ethernet frame")

    scale = 1_000_000_000 if pcap_format.nanosecond_resolution else 1_000_000
    first = records[0].timestamp_seconds * scale + records[0].timestamp_fraction
    last = records[-1].timestamp_seconds * scale + records[-1].timestamp_fraction
    status = write_idempotent(output_path, output)
    return {
        "event_type": "nids_live_fixture",
        "status": status,
        "input_sha256": source_sha256,
        "output": str(output_path),
        "output_sha256": sha256_bytes(output),
        "records": len(output_records),
        "truncated_records": truncated_records,
        "maximum_input_frame_bytes": maximum_input_frame,
        "maximum_output_frame_bytes": max(
            len(record.data) for record in output_records
        ),
        "timestamp_resolution": (
            "nanosecond" if pcap_format.nanosecond_resolution else "microsecond"
        ),
        "duration_ticks": last - first,
        "duration_tick_hz": scale,
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        print(
            json.dumps(
                build(args.input.resolve(), args.output.expanduser().resolve()),
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
