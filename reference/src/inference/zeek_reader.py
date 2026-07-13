"""
zeek_reader.py — Tails Zeek conn.log and runs Layer 3 LightGBM inference.

Zeek writes completed connections as TSV lines to conn.log. This reader
tails the file (like `tail -f`), parses each new connection record, derives
the 12 LAYER3_FEATURES + src=1, runs L3 inference, and puts the result on
the result queue for the alert aggregator.

Features derived from conn.log:
  flow_dur_us       ← duration * 1e6
  fwd/bwd bytes/pkts ← orig_*/resp_* fields
  src_ttl, dst_ttl  ← not in conn.log; filled as 0 (model trained on Bot-IoT
                       which also fills these with 0)
  sload, dload      ← (orig/resp_bytes * 8) / duration
  state_enc         ← conn_state string mapped to integer
  ct_dst_sport_ltm  ← sliding-window count: same (dst_ip, dst_port) in 60s
  ct_srv_dst        ← sliding-window count: same (service, dst_ip) in 60s
  src               ← 1 (UNSW-NB15 proxy — Zeek sessions match its schema)
"""

import logging
import threading
import time
from collections import deque
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)

# Maps Zeek conn_state strings to the integer encoding used during training.
# Derived from pd.factorize order on UNSW-NB15 'state' column; OTH used as fallback.
_STATE_MAP: dict[str, int] = {
    "SF": 0, "S0": 1, "REJ": 2, "S1": 3, "S2": 4, "S3": 5,
    "RSTO": 6, "RSTR": 7, "RSTOS0": 8, "RSTRH": 9,
    "SH": 10, "SHR": 11, "OTH": 12,
}

_DEFAULT_LOG = Path("/opt/zeek/logs/current/conn.log")
_POLL_INTERVAL_S: float = 0.5   # seconds between readline retries when no new data


class ConnTracker:
    """
    Sliding-window session-count tracker for ct_dst_sport_ltm and ct_srv_dst.

    Maintains a deque of (ts, dst_ip, dst_port, service) tuples from the
    last `window_s` seconds. Thread-safe.
    """

    def __init__(self, window_s: float = 60.0) -> None:
        self._window = window_s
        self._history: deque[tuple[float, str, int, str]] = deque()
        self._lock = threading.Lock()

    def record(self, ts: float, dst_ip: str, dst_port: int, service: str) -> tuple[int, int]:
        """
        Record a new connection and return (ct_dst_sport_ltm, ct_srv_dst).
        Both counts include the current connection.
        """
        cutoff = ts - self._window
        with self._lock:
            self._history.append((ts, dst_ip, dst_port, service))
            while self._history and self._history[0][0] < cutoff:
                self._history.popleft()
            ct_dst_sport = sum(
                1 for t, d, p, s in self._history
                if t >= cutoff and d == dst_ip and p == dst_port
            )
            ct_srv_dst = sum(
                1 for t, d, p, s in self._history
                if t >= cutoff and d == dst_ip and s == service
            )
        return ct_dst_sport, ct_srv_dst


class ZeekConnReader:
    """
    Tails Zeek conn.log, builds Layer 3 feature vectors, runs L3 inference.

    The model and scaler are injected by the engine so this class owns no
    file I/O beyond the log path itself.
    """

    def __init__(
        self,
        model,
        scaler,
        result_queue,
        stop_event: threading.Event,
        log_path: Path = _DEFAULT_LOG,
    ) -> None:
        self._model = model
        self._scaler = scaler
        self._out_q = result_queue
        self._stop = stop_event
        self._log_path = log_path
        self._tracker = ConnTracker()
        self._fields: list[str] = []

    def run(self) -> None:
        records_read: int = 0
        while not self._stop.is_set():
            if not self._log_path.exists():
                log.warning("ZeekReader: conn.log not found at %s — retrying in 5s", self._log_path)
                self._stop.wait(5.0)
                continue
            try:
                with open(self._log_path, encoding="utf-8", errors="replace") as f:
                    # #fields header sits at the top of the file — read it before
                    # seeking to the end, otherwise self._fields stays empty and
                    # every record is silently dropped.
                    for header_line in f:
                        header_line = header_line.rstrip("\n")
                        if header_line.startswith("#fields"):
                            self._fields = header_line.split("\t")[1:]
                            log.info("ZeekReader: parsed %d fields from conn.log header", len(self._fields))
                            break
                        elif not header_line.startswith("#"):
                            break  # data arrived before fields header — unusual

                    f.seek(0, 2)  # jump to end; ignore historical records
                    log.info("ZeekReader: tailing %s (fields=%d)", self._log_path, len(self._fields))
                    while not self._stop.is_set():
                        line = f.readline()
                        if not line:
                            self._stop.wait(_POLL_INTERVAL_S)
                            continue
                        line = line.rstrip("\n")
                        if line.startswith("#fields"):
                            self._fields = line.split("\t")[1:]
                        elif not line.startswith("#") and self._fields:
                            self._process_line(line)
                            records_read += 1
                            if records_read % 50 == 0:
                                log.info("ZeekReader: %d conn.log records processed", records_read)
            except OSError:
                # Log rotated or temporarily unavailable — retry after a pause
                self._stop.wait(2.0)

    def _process_line(self, line: str) -> None:
        parts = line.split("\t")
        if len(parts) != len(self._fields):
            return
        row = dict(zip(self._fields, parts))

        def _f(key: str, default: float = 0.0) -> float:
            v = row.get(key, "-")
            try:
                return float(v) if v not in ("-", "(empty)") else default
            except ValueError:
                return default

        ts = _f("ts")
        dst_ip = row.get("id.resp_h", "")
        dst_port = int(_f("id.resp_p"))
        service = row.get("service", "-")
        duration = _f("duration")
        orig_bytes = _f("orig_bytes")
        resp_bytes = _f("resp_bytes")
        orig_pkts = _f("orig_pkts")
        resp_pkts = _f("resp_pkts")
        conn_state = row.get("conn_state", "OTH")

        dur_us = duration * 1e6
        dur_s = max(duration, 1e-9)
        sload = (orig_bytes * 8.0) / dur_s
        dload = (resp_bytes * 8.0) / dur_s
        state_enc = _STATE_MAP.get(conn_state, 12)

        ct_dst_sport, ct_srv_dst = self._tracker.record(ts, dst_ip, dst_port, service)

        # LAYER3_FEATURES order + src=1 (UNSW-NB15 proxy for Zeek sessions)
        feat = np.array([
            dur_us,          # flow_dur_us
            orig_bytes,      # fwd_bytes
            resp_bytes,      # bwd_bytes
            orig_pkts,       # fwd_pkts
            resp_pkts,       # bwd_pkts
            0.0,             # src_ttl  (not in conn.log; 0 matches Bot-IoT training fill)
            0.0,             # dst_ttl
            sload,           # sload
            dload,           # dload
            float(state_enc),# state_enc
            float(ct_dst_sport),   # ct_dst_sport_ltm
            float(ct_srv_dst),     # ct_srv_dst
            1.0,             # src = 1 (UNSW-NB15 proxy)
        ], dtype=np.float32)

        try:
            feat_scaled = self._scaler.transform(feat.reshape(1, -1))
            prob_attack = float(self._model.predict_proba(feat_scaled)[0, 1])
        except Exception:
            return

        self._out_q.put({
            "type": "zeek",
            "_queued_at": time.monotonic(),
            "ts": ts,
            "src_ip": row.get("id.orig_h", ""),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": row.get("proto", ""),
            "service": service,
            "conn_state": conn_state,
            "dur_s": duration,
            "prob_attack_l3": prob_attack,
        })
