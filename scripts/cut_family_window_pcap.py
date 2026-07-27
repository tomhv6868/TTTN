#!/usr/bin/env python3
"""Cut a bounded per-family window PCAP from a CICIDS2017 source capture.

Selects the first N flows of one attack family from the T3.3 label-join oracle,
derives the exact 5-tuple set + timestamp window, then streams the source PCAP
once and writes only the packets whose (src,dst,sport,dport,proto) belongs to
that family's flow set within the window. Original packet timestamps are
preserved so a downstream tcpreplay keeps real 1:1 pacing.

Read-only on the oracle and source PCAP. Pure stdlib (no scapy/dpkt/editcap).
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import sqlite3
import struct
import sys
from pathlib import Path

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A


def parse_ts(text: str) -> dt.datetime | None:
    text = text.strip()
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def flow_key(src_ip: int, dst_ip: int, sport: int, dport: int, proto: int) -> tuple:
    """Direction-insensitive key so both halves of a flow are captured."""
    a = (src_ip, sport)
    b = (dst_ip, dport)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo, hi, proto)


def load_family_flows(db: Path, family: str, capture_id: str, limit: int):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT source_ip, source_port, destination_ip, destination_port, "
            "protocol, timestamp_text FROM label_row "
            "WHERE label=? AND capture_id=? ORDER BY timestamp_text LIMIT ?",
            (family, capture_id, limit),
        ).fetchall()
    finally:
        con.close()
    keys = set()
    times = []
    for s_ip, s_pt, d_ip, d_pt, proto, ts_text in rows:
        keys.add(flow_key(int(s_ip), int(d_ip), int(s_pt), int(d_pt), int(proto)))
        t = parse_ts(ts_text)
        if t:
            times.append(t)
    return keys, times, len(rows)


def iter_packets(path: Path):
    """Yield (ts_seconds_float, frame_bytes) from classic pcap OR pcapng."""
    with path.open("rb") as f:
        head = f.read(4)
        if len(head) < 4:
            return
        m_le = struct.unpack("<I", head)[0]
        m_be = struct.unpack(">I", head)[0]
        if m_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS) or m_be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = "<" if m_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS) else ">"
            ns = (m_le if endian == "<" else m_be) == PCAP_MAGIC_NS
            f.read(20)  # rest of 24-byte global header
            rec_fmt = endian + "IIII"
            while True:
                rh = f.read(16)
                if len(rh) < 16:
                    return
                ts_sec, ts_frac, incl, _ = struct.unpack(rec_fmt, rh)
                data = f.read(incl)
                if len(data) < incl:
                    return
                yield ts_sec + (ts_frac / 1e9 if ns else ts_frac / 1e6), data
            return
        if m_le == PCAPNG_SHB or m_be == PCAPNG_SHB:
            yield from _iter_pcapng(f)
            return
        raise SystemExit(f"unsupported pcap magic: {m_le:#x}")


def _iter_pcapng(f):
    f.seek(0)
    endian = "<"
    tsresol = 1_000_000  # default 1e6 (microsecond)
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            return
        btype = struct.unpack(endian + "I", bh[:4])[0]
        blen = struct.unpack(endian + "I", bh[4:8])[0]
        if btype == PCAPNG_SHB:
            rest = f.read(blen - 8)
            bom = struct.unpack("<I", rest[:4])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            continue
        body = f.read(blen - 12)
        f.read(4)  # trailing block_total_length
        if btype == 0x00000001:  # Interface Description Block
            # options may carry if_tsresol (code 9); default stays 1e6
            if len(body) >= 4:
                # scan options for tsresol
                opt = body[4 + ((struct.unpack(endian + "H", body[2:4])[0] + 0) and 0):]  # noop
            # simple parse: options start after 8 bytes (linktype/reserved/snaplen)
            pos = 8
            while pos + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[pos:pos + 4])
                val = body[pos + 4:pos + 4 + olen]
                if code == 0:
                    break
                if code == 9 and olen == 1:
                    r = val[0]
                    tsresol = (10 ** r) if not (r & 0x80) else (2 ** (r & 0x7F))
                pos += 4 + olen + ((4 - olen % 4) % 4)
        elif btype == 0x00000006:  # Enhanced Packet Block
            ts_high, ts_low, caplen = struct.unpack(endian + "III", body[4:16])
            ts = (ts_high << 32) | ts_low
            data = body[20:20 + caplen]
            yield ts / tsresol, data
        elif btype == 0x00000003:  # Simple Packet Block
            orig_len = struct.unpack(endian + "I", body[0:4])[0]
            data = body[4:4 + orig_len]
            yield 0.0, data


def packet_key(data: bytes):
    """Extract flow key from an Ethernet/IPv4/TCP|UDP frame; None if not IPv4 TCP/UDP."""
    if len(data) < 34:
        return None
    etype = struct.unpack(">H", data[12:14])[0]
    off = 14
    if etype == 0x8100:  # VLAN
        etype = struct.unpack(">H", data[16:18])[0]
        off = 18
    if etype != 0x0800:
        return None
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    src_ip = struct.unpack(">I", data[off + 12:off + 16])[0]
    dst_ip = struct.unpack(">I", data[off + 16:off + 20])[0]
    l4 = off + ihl
    if proto not in (6, 17) or len(data) < l4 + 4:
        return None
    sport = struct.unpack(">H", data[l4:l4 + 2])[0]
    dport = struct.unpack(">H", data[l4 + 2:l4 + 4])[0]
    return flow_key(src_ip, dst_ip, sport, dport, proto)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--source-pcap", required=True, type=Path)
    ap.add_argument("--capture-id", required=True)
    ap.add_argument("--family", required=True)
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--max-packets", type=int, default=2_000_000)
    ap.add_argument("--max-span-seconds", type=float, default=0.0,
                    help="if >0, stop once a matched packet exceeds "
                         "first_matched_ts + this (keeps a short continuous window)")
    args = ap.parse_args()

    keys, times, n = load_family_flows(args.db, args.family, args.capture_id, args.limit)
    if not keys:
        raise SystemExit(f"no flows for family={args.family} capture={args.capture_id}")
    print(f"family={args.family} flows={n} unique_keys={len(keys)} "
          f"window={times[0] if times else '?'}..{times[-1] if times else '?'}",
          flush=True)

    # Pass 1: collect all matched packets (ts, data).
    matches = []
    scanned = 0
    for ts, data in iter_packets(args.source_pcap):
        scanned += 1
        if scanned % 2_000_000 == 0:
            print(f"  scanned={scanned:,} matched={len(matches):,}", flush=True)
        k = packet_key(data)
        if k is not None and k in keys:
            matches.append((ts, data))
            if len(matches) >= args.max_packets:
                break
    if not matches:
        raise SystemExit("no matching packets found in source pcap")

    # Choose the densest max-span-seconds window (real attack burst), else all.
    span = args.max_span_seconds
    if span > 0 and len(matches) > 1:
        ts_list = [m[0] for m in matches]
        best_i, best_j, best_cnt = 0, 0, 0
        j = 0
        for i in range(len(ts_list)):
            if j < i:
                j = i
            while j + 1 < len(ts_list) and ts_list[j + 1] - ts_list[i] <= span:
                j += 1
            cnt = j - i + 1
            if cnt > best_cnt:
                best_cnt, best_i, best_j = cnt, i, j
        window = matches[best_i:best_j + 1]
        print(f"  densest {span:.0f}s window: {best_cnt} packets "
              f"(of {len(matches)} matched)", flush=True)
    else:
        window = matches

    with args.output.open("wb") as out:
        out.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 262144, 1))
        for ts, data in window:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            out.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            out.write(data)
    span_s = (window[-1][0] - window[0][0]) if len(window) > 1 else 0
    print(f"DONE family={args.family} written_packets={len(window)} "
          f"span={span_s:.0f}s scanned={scanned} output={args.output}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
