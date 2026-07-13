"""
stats_collector.py — Thread-safe runtime statistics accumulator for Phase 6 eval.

Collects per-layer latencies, packet/flow throughput, alert counts, and
system resource samples. Passed into IDSEngine at construction time; all
threads write to it concurrently. Call summary() after the engine stops
to get a snapshot suitable for report generation.
"""

import time
import threading


class StatsCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.pkt_count: int = 0
        self.flow_count: int = 0
        self.alert_counts: dict[str, int] = {}
        self.latencies_ms: dict[str, list[float]] = {}
        self.cpu_pct_samples: list[float] = []
        self.ram_mb_samples: list[float] = []
        self._start = time.monotonic()

    def record_packet(self) -> None:
        with self._lock:
            self.pkt_count += 1

    def record_flow(self) -> None:
        with self._lock:
            self.flow_count += 1

    def record_alert(self, layer: str, latency_ms: float) -> None:
        with self._lock:
            self.alert_counts[layer] = self.alert_counts.get(layer, 0) + 1
            self.latencies_ms.setdefault(layer, []).append(latency_ms)

    def record_system(self, cpu_pct: float, ram_mb: float) -> None:
        with self._lock:
            self.cpu_pct_samples.append(cpu_pct)
            self.ram_mb_samples.append(ram_mb)

    def summary(self) -> dict:
        with self._lock:
            elapsed = max(time.monotonic() - self._start, 1e-9)

            def _lat(lats: list[float]) -> dict:
                if not lats:
                    return {"n": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
                s = sorted(lats)
                n = len(s)
                return {
                    "n": n,
                    "mean_ms": round(sum(s) / n, 3),
                    "p50_ms": round(s[n // 2], 3),
                    "p95_ms": round(s[min(int(n * 0.95), n - 1)], 3),
                    "max_ms": round(s[-1], 3),
                }

            cpu = self.cpu_pct_samples
            ram = self.ram_mb_samples
            return {
                "elapsed_s": round(elapsed, 1),
                "packets_processed": self.pkt_count,
                "flows_processed": self.flow_count,
                "pkt_throughput_s": round(self.pkt_count / elapsed, 1),
                "flow_throughput_s": round(self.flow_count / elapsed, 1),
                "alert_counts": dict(self.alert_counts),
                "alert_total": sum(self.alert_counts.values()),
                "latency": {layer: _lat(lats) for layer, lats in self.latencies_ms.items()},
                "cpu_pct_mean": round(sum(cpu) / len(cpu), 1) if cpu else 0.0,
                "cpu_pct_max": round(max(cpu), 1) if cpu else 0.0,
                "ram_mb_mean": round(sum(ram) / len(ram), 1) if ram else 0.0,
                "ram_mb_max": round(max(ram), 1) if ram else 0.0,
            }
