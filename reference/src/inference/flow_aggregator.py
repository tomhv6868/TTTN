"""
flow_aggregator.py — Stateful 5-tuple flow tracking for Layer 2 inference.

FlowTable accumulates per-packet statistics keyed by (src_ip, dst_ip,
src_port, dst_port, proto). When a flow ends (FIN/RST seen or idle timeout),
its feature vector is placed on the output queue for L2 LightGBM inference.
"""

import threading
import time
from typing import NamedTuple

import numpy as np

FLOW_TIMEOUT_S: float = 120.0       # expire idle flows after 2 minutes
CLEANUP_INTERVAL_S: float = 10.0    # sweep interval for the internal cleanup thread

# UDP ports that carry only benign background traffic — skip before L2 inference.
# These services produce high-volume, low-variation flows that the L2 model
# consistently misclassifies as attacks because CICIDS2017/UNSW/Bot-IoT contain
# no such benign UDP traffic at these ports.
_BENIGN_UDP_PORTS: frozenset[int] = frozenset({
    53,        # DNS — queries to local resolver/gateway are background traffic
    67, 68,    # DHCP
    123,       # NTP
    5353,      # mDNS
    1900,      # SSDP / UPnP
})


class FlowKey(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int


class FlowRecord:
    """Accumulates per-packet statistics for a single 5-tuple flow."""

    __slots__ = (
        "key", "start_ts", "last_ts", "_prev_ts",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
        "_pkt_lens", "_iats",
        "psh_flag", "ack_flag", "fin_flag", "rst_flag",
        "init_win_fwd",
    )

    def __init__(self, key: FlowKey, ts: float) -> None:
        self.key = key
        self.start_ts = ts
        self.last_ts = ts
        self._prev_ts = ts
        self.fwd_pkts: int = 0
        self.bwd_pkts: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0
        self._pkt_lens: list[int] = []
        self._iats: list[float] = []
        self.psh_flag: int = 0
        self.ack_flag: int = 0
        self.fin_flag: int = 0
        self.rst_flag: int = 0
        self.init_win_fwd: int = 0

    def add_packet(self, meta: dict, forward: bool) -> None:
        ts: float = meta["ts"]
        iat = ts - self._prev_ts
        if iat > 0:
            self._iats.append(iat)
        self._prev_ts = ts
        self.last_ts = ts

        pkt_len: int = meta["pkt_len"]
        self._pkt_lens.append(pkt_len)
        flags: int = meta.get("flags", 0)

        if forward:
            if self.fwd_pkts == 0:
                self.init_win_fwd = meta.get("win", 0)
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len

        if flags & 0x08:
            self.psh_flag = 1
        if flags & 0x10:
            self.ack_flag = 1
        if flags & 0x01:
            self.fin_flag = 1
        if flags & 0x04:
            self.rst_flag = 1

    @property
    def should_expire(self) -> bool:
        return (
            bool(self.fin_flag or self.rst_flag)
            or (time.time() - self.last_ts) > FLOW_TIMEOUT_S
        )

    def to_feature_vector(self) -> np.ndarray:
        """
        Build a 16-element float32 array: 15 LAYER2_FEATURES + src=0.

        src=0 (CICIDS2017 proxy) is used for live traffic because CICIDS2017
        has the best coverage of Layer 2 features captured from live flows.
        """
        dur_us = (self.last_ts - self.start_ts) * 1e6
        dur_s = max(dur_us / 1e6, 1e-9)
        total_bytes = self.fwd_bytes + self.bwd_bytes
        pkt_len_min = float(min(self._pkt_lens)) if self._pkt_lens else 0.0
        pkt_len_avg = float(sum(self._pkt_lens) / len(self._pkt_lens)) if self._pkt_lens else 0.0
        active_mean = float(sum(self._iats) / len(self._iats)) if self._iats else 0.0
        proto_enc = self.key.proto if self.key.proto in (6, 17) else 0

        return np.array([
            self.key.dst_port,          # dst_port
            dur_us,                     # flow_dur_us
            self.fwd_pkts,              # fwd_pkts
            self.fwd_bytes,             # fwd_bytes
            self.bwd_pkts,              # bwd_pkts
            self.bwd_bytes,             # bwd_bytes
            pkt_len_min,                # pkt_len_min
            pkt_len_avg,                # pkt_len_avg
            total_bytes / dur_s,        # flow_bytes_s
            self.psh_flag,              # psh_flag
            self.ack_flag,              # ack_flag
            self.fin_flag,              # fin_flag
            self.init_win_fwd,          # init_win_fwd
            active_mean,                # active_mean
            proto_enc,                  # protocol_enc
            0,                          # src = 0
        ], dtype=np.float32)


class FlowTable:
    """
    Thread-safe 5-tuple flow table with automatic expiry.

    An internal daemon thread runs every CLEANUP_INTERVAL_S to flush flows
    that have timed out. Flows with FIN/RST are expired inline on the
    next packet that triggers the flag check.
    """

    def __init__(self, output_queue, stop_event: threading.Event) -> None:
        self._table: dict[FlowKey, FlowRecord] = {}
        self._lock = threading.Lock()
        self._out_q = output_queue
        self._stop = stop_event
        threading.Thread(
            target=self._cleanup_loop, daemon=True, name="FlowCleanup"
        ).start()

    def add_packet(self, meta: dict) -> None:
        # Skip flows that are known-benign background services.
        # Multicast destinations (224.0.0.0/4) and specific UDP management ports
        # generate high-volume, repetitive flows that the L2 model misclassifies.
        dst_ip: str = meta["dst_ip"]
        if dst_ip.startswith("224.") or dst_ip.startswith("239."):
            return
        if meta["proto"] == 17 and meta["dst_port"] in _BENIGN_UDP_PORTS:
            return

        fwd_key = FlowKey(
            src_ip=meta["src_ip"], dst_ip=meta["dst_ip"],
            src_port=meta["src_port"], dst_port=meta["dst_port"],
            proto=meta["proto"],
        )
        rev_key = FlowKey(
            src_ip=meta["dst_ip"], dst_ip=meta["src_ip"],
            src_port=meta["dst_port"], dst_port=meta["src_port"],
            proto=meta["proto"],
        )

        with self._lock:
            if fwd_key in self._table:
                key, record = fwd_key, self._table[fwd_key]
                record.add_packet(meta, forward=True)
            elif rev_key in self._table:
                key, record = rev_key, self._table[rev_key]
                record.add_packet(meta, forward=False)
            else:
                record = FlowRecord(fwd_key, meta["ts"])
                record.add_packet(meta, forward=True)
                self._table[fwd_key] = record
                return  # brand-new flow — not ready to expire yet

            if record.should_expire:
                self._emit(key, record)

    def _emit(self, key: FlowKey, record: FlowRecord) -> None:
        """Put expired flow onto L2 queue. Must be called under self._lock."""
        # Single-packet flows carry no bidirectional signal and are almost always
        # RST/SYN-ACK responses to scan probes. Skip them — they produce 5k+
        # false positives per nmap -p- run with zero detection value.
        if record.fwd_pkts + record.bwd_pkts < 2:
            del self._table[key]
            return
        feat = record.to_feature_vector()
        try:
            self._out_q.put_nowait({
                "type": "flow",
                "key": key,
                "features": feat,
                "dur_us": float(feat[1]),
            })
        except Exception:
            pass  # drop if L2 queue full
        del self._table[key]

    def _cleanup_loop(self) -> None:
        while not self._stop.wait(CLEANUP_INTERVAL_S):
            with self._lock:
                expired = [k for k, r in self._table.items() if r.should_expire]
                for key in expired:
                    self._emit(key, self._table[key])
