"""
dns_reader.py — Tails Zeek dns.log and runs Layer 4 DNS LightGBM inference.

Layer 4 DNS detects DNS tunnelling / exfiltration / amplification — attacks
whose signal lives in the query name structure, not in flow stats.

Features extracted per dns.log record (8 total):

    query_len             length of the queried name
    query_entropy         Shannon entropy of the query name
    subdomain_count       number of '.' separated labels
    qtype_enc             0=A 1=AAAA 2=TXT 3=CNAME 4=MX 5=NS 6=SOA 7=PTR 8=SRV 9=other
    rcode_enc             0=NOERROR 1=NXDOMAIN 2=SERVFAIL 3=REFUSED 4=other
    answer_count          count of comma-separated answers
    resp_size             total length of answers string
    query_special_ratio   ratio of non-alphanumeric in query name
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

DNS_FEATURE_NAMES = [
    "query_len", "query_entropy", "subdomain_count",
    "qtype_enc", "rcode_enc", "answer_count", "resp_size",
    "query_special_ratio",
]

_DEFAULT_LOG = Path("/opt/zeek/logs/current/dns.log")
_POLL_INTERVAL_S: float = 0.5

_QTYPE_MAP: dict[str, int] = {
    "A": 0, "AAAA": 1, "TXT": 2, "CNAME": 3, "MX": 4,
    "NS": 5, "SOA": 6, "PTR": 7, "SRV": 8,
}

_RCODE_MAP: dict[str, int] = {
    "NOERROR": 0, "NXDOMAIN": 1, "SERVFAIL": 2, "REFUSED": 3,
}

_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class DnsLogReader:
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
                log.warning("DnsReader: dns.log not found at %s — retrying in 5s", self._log_path)
                self._stop.wait(5.0)
                continue
            try:
                with open(self._log_path, encoding="utf-8", errors="replace") as f:
                    for header_line in f:
                        header_line = header_line.rstrip("\n")
                        if header_line.startswith("#fields"):
                            self._fields = header_line.split("\t")[1:]
                            log.info("DnsReader: parsed %d fields from dns.log header", len(self._fields))
                            break
                        elif not header_line.startswith("#"):
                            break

                    f.seek(0, 2)
                    log.info("DnsReader: tailing %s (fields=%d)", self._log_path, len(self._fields))
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
                                log.info("DnsReader: %d dns.log records processed", records_read)
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
        query = _s("query", "")
        qtype_name = _s("qtype_name", "A").upper()
        rcode_name = _s("rcode_name", "NOERROR").upper()
        answers = _s("answers", "")

        answer_count = 0 if not answers else answers.count(",") + 1
        resp_size = len(answers)
        special_ratio = (
            len(_NON_ALNUM_RE.findall(query)) / len(query) if query else 0.0
        )

        feat = np.array([
            len(query),
            _shannon(query),
            query.count(".") + 1 if query else 0,
            float(_QTYPE_MAP.get(qtype_name, 9)),
            float(_RCODE_MAP.get(rcode_name, 4)),
            float(answer_count),
            float(resp_size),
            special_ratio,
        ], dtype=np.float32)

        try:
            scaled = self._scaler.transform(feat.reshape(1, -1))
            prob = float(self._model.predict_proba(scaled)[0, 1])
        except Exception as exc:
            log.debug("L4-DNS inference error: %s", exc)
            return

        try:
            self._out_q.put_nowait({
                "type": "dns",
                "_queued_at": time.monotonic(),
                "ts": ts,
                "src_ip": row.get("id.orig_h", ""),
                "dst_ip": row.get("id.resp_h", ""),
                "dst_port": int(_f("id.resp_p")) or 53,
                "proto": "udp",
                "query": query[:200],
                "qtype": qtype_name,
                "rcode": rcode_name,
                "prob_attack_l4_dns": prob,
            })
        except Exception:
            pass
