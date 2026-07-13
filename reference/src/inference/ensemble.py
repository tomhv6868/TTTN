"""
ensemble.py — Ensemble gating logic and JSON alert writer.

Gating rules (applied per-event; no cross-layer buffering in this design
because L1/L2/L3 results arrive with different latencies):

  L1 fast-path  prob >= L1_FAST_THRESHOLD  → immediate alert (no L2/L3 wait)
  L2 result     prob >= L2_THRESHOLD        → alert from flow-level evidence
  L3 result     prob >= L3_THRESHOLD        → alert from session-level evidence

Each alert is one JSON object written to alerts.jsonl (Wazuh localfile input).
"""

import json
import threading
import time
from pathlib import Path

# Probability thresholds
L1_FAST_THRESHOLD: float = 0.90   # very high confidence from DT → skip L2/L3 wait
L2_THRESHOLD: float = 0.65
L3_THRESHOLD: float = 0.70       # raised from 0.50; Wazuh-internal FPs sit at ~0.65
L4_HTTP_THRESHOLD: float = 0.85  # raised from 0.70 — true attacks score 1.000; OOD
                                  # connectivity-check traffic scored 0.71 just above
                                  # the old threshold. 0.85 keeps a clean margin.
L4_DNS_THRESHOLD: float = 0.85

# Deduplication cooldown windows per layer.
# A port sweep generates thousands of Zeek entries (one per probe); without
# dedup, one nmap -p- scan produces 40k+ identical L3 alerts.
# Key: (src_ip, dst_ip, dst_port, layer) for L1/L2; (src_ip, dst_ip, layer) for L3.
_L1_DEDUP_S: float = 15.0
_L2_DEDUP_S: float = 30.0
_L3_DEDUP_S: float = 600.0  # one alert per attacker→target pair per 10-minute window
_L4_HTTP_DEDUP_S: float = 30.0
_L4_DNS_DEDUP_S: float = 60.0
# 10min chosen because the attack script runs 6 stages across ~30min — each stage
# probes the same ports, so a 2-minute window produces 40+ repeat alerts for one scan.

# Once a source IP has fired an alert, it is a "known attacker" for this window.
# Any flow where dst_ip is a known attacker is a victim-response flow (e.g. Ubuntu's
# TCP replies to hydra connections). These look suspicious to L2 but are not attacks.
_KNOWN_ATTACKER_TTL_S: float = 300.0  # 5-minute attacker memory

_DEFAULT_ALERT_LOG = Path("/var/log/multilayer_ids/alerts.jsonl")


class AlertWriter:
    """
    Thread-safe, line-buffered JSON-lines writer.

    Uses buffering=1 (line-buffered) so Wazuh's localfile input sees each
    alert immediately without an explicit flush.
    """

    def __init__(self, log_path: Path = _DEFAULT_ALERT_LOG) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._f = open(log_path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115

    def write(self, alert: dict) -> None:
        line = json.dumps(alert, ensure_ascii=False)
        with self._lock:
            self._f.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._f.flush()
            self._f.close()


class EnsembleGate:
    """
    Routes layer result events to AlertWriter based on gating thresholds.

    Each call to process() handles one event dict produced by T2-L1Infer,
    T3-L2Infer, or T4-ZeekL3. Events are independent — there is intentionally
    no buffering to correlate L2 + L3 results for the same flow, because the
    latency difference between them is unbounded (Zeek logs only after the
    connection closes). Each layer's evidence is acted on independently.
    """

    def __init__(self, writer: AlertWriter, stats_collector=None) -> None:
        self._writer = writer
        self._stats = stats_collector
        self._dedup: dict[tuple, float] = {}        # dedup_key → last_alert_monotonic
        self._known_attackers: dict[str, float] = {}  # src_ip → expiry_monotonic
        self._dedup_lock = threading.Lock()

    def _is_response_to_attacker(self, dst_ip: str) -> bool:
        """Return True if dst_ip is a known attacker (meaning this flow is a victim response)."""
        now = time.monotonic()
        with self._dedup_lock:
            exp = self._known_attackers.get(dst_ip)
            return exp is not None and now < exp

    def _mark_attacker(self, src_ip: str) -> None:
        """Record src_ip as a known attacker for KNOWN_ATTACKER_TTL_S seconds."""
        now = time.monotonic()
        with self._dedup_lock:
            self._known_attackers[src_ip] = now + _KNOWN_ATTACKER_TTL_S

    def _is_duplicate(self, key: tuple, window_s: float) -> bool:
        """Return True if this key was alerted within window_s seconds. Thread-safe."""
        now = time.monotonic()
        with self._dedup_lock:
            last = self._dedup.get(key)
            if last is not None and (now - last) < window_s:
                return True
            self._dedup[key] = now
            # Prune stale entries to prevent unbounded growth
            if len(self._dedup) > 10_000:
                cutoff = now - max(
                    _L1_DEDUP_S, _L2_DEDUP_S, _L3_DEDUP_S,
                    _L4_HTTP_DEDUP_S, _L4_DNS_DEDUP_S,
                )
                self._dedup = {k: v for k, v in self._dedup.items() if v >= cutoff}
            return False

    def process(self, event: dict) -> None:
        etype = event["type"]
        _queued_at = event.get("_queued_at")

        if etype == "l1_fast" and event["prob"] >= L1_FAST_THRESHOLD:
            src, dst, port = event.get("src_ip", ""), event.get("dst_ip", ""), event.get("dst_port", 0)
            # Suppress victim→attacker response flows (e.g. Ubuntu replying to hping3 SYN flood)
            if self._is_response_to_attacker(dst):
                return
            if self._is_duplicate((src, dst, port, "L1"), _L1_DEDUP_S):
                return
            latency_ms = (time.monotonic() - _queued_at) * 1000 if _queued_at else None
            self._emit(
                verdict="ATTACK",
                confidence=event["prob"],
                layers=["L1"],
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=str(event.get("proto", "")),
                detail={"trigger": "L1_fast_path"},
                latency_ms=latency_ms,
            )

        elif etype == "l2" and event["prob_attack_l2"] >= L2_THRESHOLD:
            src, dst, port = event.get("src_ip", ""), event.get("dst_ip", ""), event.get("dst_port", 0)
            # Suppress victim→attacker response flows (e.g. Ubuntu's TCP replies to hydra)
            if self._is_response_to_attacker(dst):
                return
            if self._is_duplicate((src, dst, port, "L2"), _L2_DEDUP_S):
                return
            latency_ms = (time.monotonic() - _queued_at) * 1000 if _queued_at else None
            self._emit(
                verdict="ATTACK",
                confidence=event["prob_attack_l2"],
                layers=["L2"],
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=str(event.get("proto", "")),
                detail={"flow_dur_us": event.get("dur_us", 0)},
                latency_ms=latency_ms,
            )

        elif etype == "http" and event["prob_attack_l4_http"] >= L4_HTTP_THRESHOLD:
            src, dst, port = event.get("src_ip", ""), event.get("dst_ip", ""), event.get("dst_port", 0)
            if self._is_response_to_attacker(dst):
                return
            # L4 dedup MUST include URI: a different URI is a different attack.
            # Without this, 5 distinct curl payloads (SQLi/XSS/PT/CI/...) from
            # the same source within 30s collapsed to a single alert.
            uri_key = (event.get("uri", "") or "")[:120]
            if self._is_duplicate((src, dst, port, uri_key, "L4-HTTP"), _L4_HTTP_DEDUP_S):
                return
            latency_ms = (time.monotonic() - _queued_at) * 1000 if _queued_at else None
            self._emit(
                verdict="ATTACK",
                confidence=event["prob_attack_l4_http"],
                layers=["L4"],
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=str(event.get("proto", "tcp")),
                detail={
                    "head": "http",
                    "method": event.get("method", ""),
                    "uri": event.get("uri", ""),
                    "host": event.get("host", ""),
                    "status_code": event.get("status_code", 0),
                },
                latency_ms=latency_ms,
            )

        elif etype == "dns" and event["prob_attack_l4_dns"] >= L4_DNS_THRESHOLD:
            src, dst = event.get("src_ip", ""), event.get("dst_ip", "")
            if self._is_response_to_attacker(dst):
                return
            # Same rule as HTTP: different query name = different exfil attempt.
            # Tunnel demos send fresh random subdomains each round, so the dedup
            # would never collapse legitimate traffic; this only stops floods of
            # the exact same query.
            query_key = (event.get("query", "") or "")[:120]
            if self._is_duplicate((src, dst, query_key, "L4-DNS"), _L4_DNS_DEDUP_S):
                return
            latency_ms = (time.monotonic() - _queued_at) * 1000 if _queued_at else None
            self._emit(
                verdict="ATTACK",
                confidence=event["prob_attack_l4_dns"],
                layers=["L4"],
                src_ip=src,
                dst_ip=dst,
                dst_port=event.get("dst_port", 53),
                proto=str(event.get("proto", "udp")),
                detail={
                    "head": "dns",
                    "query": event.get("query", ""),
                    "qtype": event.get("qtype", ""),
                    "rcode": event.get("rcode", ""),
                },
                latency_ms=latency_ms,
            )

        elif etype == "zeek" and event["prob_attack_l3"] >= L3_THRESHOLD:
            src, dst, port = event.get("src_ip", ""), event.get("dst_ip", ""), event.get("dst_port", 0)
            # Suppress victim→attacker flows (e.g. ICMP unreachable replies to scan probes)
            if self._is_response_to_attacker(dst):
                return
            # L3 dedup is per (src, dst) only — a port sweep is one attack, not one per port
            if self._is_duplicate((src, dst, "L3"), _L3_DEDUP_S):
                return
            latency_ms = (time.monotonic() - _queued_at) * 1000 if _queued_at else None
            self._emit(
                verdict="ATTACK",
                confidence=event["prob_attack_l3"],
                layers=["L3"],
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=str(event.get("proto", "")),
                detail={
                    "service": event.get("service", ""),
                    "conn_state": event.get("conn_state", ""),
                    "dur_s": event.get("dur_s", 0),
                },
                latency_ms=latency_ms,
            )

    def _emit(
        self,
        verdict: str,
        confidence: float,
        layers: list[str],
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        detail: dict,
        latency_ms: float | None = None,
    ) -> None:
        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "layers": layers,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            **detail,
        }
        if latency_ms is not None:
            alert["latency_ms"] = round(latency_ms, 3)
        self._writer.write(alert)
        # Mark the attacker so subsequent victim-response flows are suppressed
        self._mark_attacker(src_ip)
        if self._stats is not None and latency_ms is not None:
            self._stats.record_alert(layers[0] if layers else "?", latency_ms)
