"""
http_reader.py — Tails Zeek http.log and runs Layer 4 HTTP LightGBM inference.

Layer 4 detects L7 attacks (SQLi, XSS, path traversal, command injection)
that L1/L2/L3 cannot see by construction — the malicious signal lives in
the HTTP payload bytes, which the packet/flow features discard.

Features extracted per http.log record (11 total):

    uri_len             integer
    uri_special_ratio   fraction of {'  "  ;  <  >  (  )  %  \\  |  &  =}
    uri_token_hits      count of suspicious tokens (SQL/XSS/PT/CI patterns)
    method_enc          0=GET, 1=POST, 2=PUT, 3=DELETE, 4=HEAD, 5=other
    status_code         numeric
    req_body_len        request_body_len from Zeek
    resp_body_len       response_body_len from Zeek
    ua_len              user-agent length
    ua_entropy          Shannon entropy of user-agent
    host_present        1 if Host header logged
    referrer_present    1 if Referrer header logged
"""

import logging
import math
import re
import threading
import time
from collections import Counter
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)

HTTP_FEATURE_NAMES = [
    "uri_len", "uri_special_ratio", "uri_token_hits",
    "method_enc", "status_code", "req_body_len", "resp_body_len",
    "ua_len", "ua_entropy", "host_present", "referrer_present",
]

_DEFAULT_LOG = Path("/opt/zeek/logs/current/http.log")
_POLL_INTERVAL_S: float = 0.5

_METHOD_MAP: dict[str, int] = {
    "GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4,
}

# Lower-case regex over the URI/query string. Each match contributes 1.
# Token list covers SQLi, XSS, path-traversal and command-injection signatures.
_SUSPICIOUS_TOKEN_RE = re.compile(
    r"(union\s+select|select\s+.+from|or\s+1=1|--\s|/\*|"
    r"<script|onerror\s*=|onload\s*=|alert\(|javascript:|"
    r"\.\./|/etc/passwd|/etc/shadow|"
    r";\s*(rm|wget|curl|nc|bash|sh)\s|exec\(|system\(|\|\|\s*\w+|`[^`]+`)",
    re.IGNORECASE,
)

_SPECIAL_CHARS = set("'\";<>()%\\|&=")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _special_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for ch in s if ch in _SPECIAL_CHARS) / len(s)


class HttpLogReader:
    """
    Tails Zeek http.log, builds Layer 4 feature vectors, runs L4-HTTP inference.

    Mirrors the architecture of ZeekConnReader — model + scaler injected by
    the engine, owns only the tail-and-parse loop.
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
        self._fields: list[str] = []

    def run(self) -> None:
        records_read = 0
        while not self._stop.is_set():
            if not self._log_path.exists():
                log.warning("HttpReader: http.log not found at %s — retrying in 5s", self._log_path)
                self._stop.wait(5.0)
                continue
            try:
                with open(self._log_path, encoding="utf-8", errors="replace") as f:
                    for header_line in f:
                        header_line = header_line.rstrip("\n")
                        if header_line.startswith("#fields"):
                            self._fields = header_line.split("\t")[1:]
                            log.info("HttpReader: parsed %d fields from http.log header", len(self._fields))
                            break
                        elif not header_line.startswith("#"):
                            break

                    f.seek(0, 2)
                    log.info("HttpReader: tailing %s (fields=%d)", self._log_path, len(self._fields))
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
                            if records_read % 25 == 0:
                                log.info("HttpReader: %d http.log records processed", records_read)
            except OSError:
                self._stop.wait(2.0)

    def _process_line(self, line: str) -> None:
        parts = line.split("\t")
        if len(parts) != len(self._fields):
            return
        row = dict(zip(self._fields, parts))

        def _s(key: str, default: str = "") -> str:
            v = row.get(key, "-")
            return default if v in ("-", "(empty)") else v

        def _f(key: str, default: float = 0.0) -> float:
            v = row.get(key, "-")
            try:
                return float(v) if v not in ("-", "(empty)") else default
            except ValueError:
                return default

        ts = _f("ts")
        method = _s("method", "GET").upper()
        uri = _s("uri", "/")
        host = _s("host", "")
        ua = _s("user_agent", "")
        referrer = _s("referrer", "")
        status_code = _f("status_code")
        req_body_len = _f("request_body_len")
        resp_body_len = _f("response_body_len")

        feat = np.array([
            len(uri),
            _special_ratio(uri),
            len(_SUSPICIOUS_TOKEN_RE.findall(uri)),
            float(_METHOD_MAP.get(method, 5)),
            status_code,
            req_body_len,
            resp_body_len,
            len(ua),
            _shannon(ua),
            1.0 if host else 0.0,
            1.0 if referrer else 0.0,
        ], dtype=np.float32)

        try:
            scaled = self._scaler.transform(feat.reshape(1, -1))
            prob = float(self._model.predict_proba(scaled)[0, 1])
        except Exception as exc:
            log.debug("L4-HTTP inference error: %s", exc)
            return

        try:
            self._out_q.put_nowait({
                "type": "http",
                "_queued_at": time.monotonic(),
                "ts": ts,
                "src_ip": row.get("id.orig_h", ""),
                "dst_ip": row.get("id.resp_h", ""),
                "dst_port": int(_f("id.resp_p")),
                "proto": "tcp",
                "method": method,
                "uri": uri[:200],
                "host": host[:100],
                "status_code": int(status_code),
                "prob_attack_l4_http": prob,
            })
        except Exception:
            pass
