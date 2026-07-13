"""
engine.py — RT-FLID 3-layer live detection engine.

Thread layout (mirrors RT-FLID paper's 7-phase architecture):
  T1  Scapy AsyncSniffer        raw packets → raw_q
  T2  L1 DT inference           raw_q → fast alerts + flow_table.add_packet()
  T3  L2 LightGBM inference     flow_q (expired flows from FlowTable) → result_q
  T4  Zeek conn.log + L3        Zeek TSV → L3 inference → result_q
  T5  Alert aggregation         result_q → AlertWriter → alerts.jsonl
  +   FlowTable cleanup         internal daemon thread inside FlowTable

Models loaded at startup from models/. All queues are bounded to prevent
unbounded memory growth under sustained high-traffic load.
"""

import logging
import os
import queue
import signal
import sys
import threading
import time
import warnings
from pathlib import Path

import joblib

# LightGBM models were fitted with named DataFrames; inference passes numpy
# arrays. Suppress the per-call sklearn warning — it is harmless and floods output.
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.inference.ensemble import AlertWriter, EnsembleGate  # noqa: E402
from src.inference.flow_aggregator import FlowTable  # noqa: E402
from src.inference.packet_parser import parse_packet  # noqa: E402
from src.inference.zeek_reader import ZeekConnReader  # noqa: E402
from src.inference.http_reader import HttpLogReader  # noqa: E402
from src.inference.dns_reader import DnsLogReader  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)-14s] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

_MODELS = ROOT / "models"

# L1 confidence above which we emit an alert without waiting for L2/L3
_L1_FAST_THRESHOLD: float = 0.90

# Online-learning state files (Phase 7)
_ARF_STATE      = _MODELS / "layer2_arf.pkl"
_LEARN_QUEUE    = Path("/var/log/multilayer_ids/training_queue.jsonl")
_FLOW_BUF_LOG   = Path("/var/log/multilayer_ids/flow_buffer.jsonl")
_L2_ONLINE_ENABLED = os.getenv("IDS_L2_ONLINE", "").lower() in {"1", "true", "yes", "on"}


class IDSEngine:
    def __init__(
        self,
        iface: str = "eth0",
        zeek_log: Path | None = None,
        alert_log: Path | None = None,
        bpf_filter: str = "ip",
        stats_collector=None,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._stop = threading.Event()
        self._stats = stats_collector

        # Bounded queues — packets dropped silently under saturation
        self._raw_q: queue.Queue = queue.Queue(maxsize=10_000)
        self._flow_q: queue.Queue = queue.Queue(maxsize=5_000)
        self._result_q: queue.Queue = queue.Queue(maxsize=5_000)

        log.info("Loading models from %s ...", _MODELS)
        self._l1_model  = joblib.load(_MODELS / "layer1_dt.pkl")
        self._l1_scaler = joblib.load(_MODELS / "layer1_scaler.pkl")
        self._l2_model  = joblib.load(_MODELS / "layer2_lgbm.pkl")
        self._l2_scaler = joblib.load(_MODELS / "layer2_scaler.pkl")
        self._l3_model  = joblib.load(_MODELS / "layer3_lgbm.pkl")
        self._l3_scaler = joblib.load(_MODELS / "layer3_scaler.pkl")
        # Layer 4 — HTTP and DNS L7 anomaly detectors (Phase 8)
        self._l4_http_model  = joblib.load(_MODELS / "layer4_http_lgbm.pkl")
        self._l4_http_scaler = joblib.load(_MODELS / "layer4_http_scaler.pkl")
        self._l4_dns_model   = joblib.load(_MODELS / "layer4_dns_lgbm.pkl")
        self._l4_dns_scaler  = joblib.load(_MODELS / "layer4_dns_scaler.pkl")
        log.info("All models loaded.")

        self._flow_table = FlowTable(self._flow_q, self._stop)

        self._flow_buffer = None
        self._l2_online = None
        if _L2_ONLINE_ENABLED:
            from src.online.flow_buffer import FlowBuffer
            from src.online.incremental_l2 import IncrementalL2

            self._flow_buffer = FlowBuffer(log_path=_FLOW_BUF_LOG)
            self._l2_online = IncrementalL2(
                state_path=_ARF_STATE,
                training_queue_path=_LEARN_QUEUE,
            )
            log.info(
                "L2 online learner enabled (samples_seen=%d)",
                self._l2_online.samples_seen,
            )
        else:
            log.info("L2 online learner disabled; using frozen LightGBM only.")

        _alert_path = alert_log or Path("/var/log/multilayer_ids/alerts.jsonl")
        self._writer = AlertWriter(_alert_path)
        self._gate = EnsembleGate(self._writer, stats_collector=stats_collector)

        _zeek_path = zeek_log or Path("/opt/zeek/logs/current/conn.log")
        self._zeek_reader = ZeekConnReader(
            model=self._l3_model,
            scaler=self._l3_scaler,
            result_queue=self._result_q,
            stop_event=self._stop,
            log_path=_zeek_path,
        )

        # Layer 4 readers — derive their log paths from the conn.log parent dir
        _zeek_dir = _zeek_path.parent
        self._http_reader = HttpLogReader(
            model=self._l4_http_model,
            scaler=self._l4_http_scaler,
            result_queue=self._result_q,
            stop_event=self._stop,
            log_path=_zeek_dir / "http.log",
        )
        self._dns_reader = DnsLogReader(
            model=self._l4_dns_model,
            scaler=self._l4_dns_scaler,
            result_queue=self._result_q,
            stop_event=self._stop,
            log_path=_zeek_dir / "dns.log",
        )

    def run(self) -> None:
        signal.signal(signal.SIGINT,  self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

        threads = [
            threading.Thread(target=self._capture_thread,   name="T1-Capture",  daemon=True),
            threading.Thread(target=self._l1_thread,        name="T2-L1Infer",  daemon=True),
            threading.Thread(target=self._l2_thread,        name="T3-L2Infer",  daemon=True),
            threading.Thread(target=self._zeek_reader.run,  name="T4-ZeekL3",   daemon=True),
            threading.Thread(target=self._alert_thread,     name="T5-Alert",    daemon=True),
            threading.Thread(target=self._http_reader.run,  name="T7-L4HTTP",   daemon=True),
            threading.Thread(target=self._dns_reader.run,   name="T8-L4DNS",    daemon=True),
        ]
        for t in threads:
            t.start()
        # T6 is owned by IncrementalL2 — separate to keep its lifecycle private
        if self._l2_online is not None:
            self._l2_online.start_learner_thread(self._stop)
        log.info("IDS engine running on interface '%s'. Ctrl+C to stop.", self.iface)
        self._stop.wait()

        log.info("Stop signal received — draining queues...")
        for t in threads:
            t.join(timeout=5.0)
        self._writer.close()
        if self._flow_buffer is not None:
            self._flow_buffer.close()
        log.info("Engine stopped cleanly.")

    # ── Thread bodies ─────────────────────────────────────────────────────────

    def _capture_thread(self) -> None:
        try:
            from scapy.sendrecv import AsyncSniffer  # type: ignore
        except ImportError:
            log.error("scapy not installed. Run: pip install scapy")
            self._stop.set()
            return

        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._enqueue_packet,
            store=False,
        )
        sniffer.start()
        self._stop.wait()
        sniffer.stop()

    def _enqueue_packet(self, pkt) -> None:
        try:
            self._raw_q.put_nowait(pkt)
        except queue.Full:
            pass  # drop — throughput exceeds processing capacity

    def _l1_thread(self) -> None:
        while not self._stop.is_set():
            try:
                pkt = self._raw_q.get(timeout=0.5)
            except queue.Empty:
                continue

            parsed = parse_packet(pkt)
            if parsed is None:
                continue
            feat_vec, meta = parsed

            try:
                scaled = self._l1_scaler.transform(feat_vec.reshape(1, -1))
                prob = float(self._l1_model.predict_proba(scaled)[0, 1])
            except Exception as exc:
                log.debug("L1 inference error: %s", exc)
                continue

            if self._stats is not None:
                self._stats.record_packet()

            if prob >= _L1_FAST_THRESHOLD:
                try:
                    self._result_q.put_nowait({
                        "type": "l1_fast", "prob": prob,
                        "_queued_at": time.monotonic(),
                        **meta,
                    })
                except queue.Full:
                    pass

            # Always aggregate into flows regardless of L1 verdict
            self._flow_table.add_packet(meta)

    def _l2_thread(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._flow_q.get(timeout=0.5)
            except queue.Empty:
                continue

            raw_feat = event["features"]
            feat = raw_feat.reshape(1, -1)
            try:
                scaled = self._l2_scaler.transform(feat)
                prob_lgbm = float(self._l2_model.predict_proba(scaled)[0, 1])
            except Exception as exc:
                log.debug("L2 inference error: %s", exc)
                continue

            # ARF sees the raw (unscaled) feature vector — it's a tree ensemble.
            # predict_proba returns 0.0 if the ARF has never seen a label,
            # so the ensemble vote degenerates to LGBM-only at cold start.
            prob_arf = 0.0
            prob = prob_lgbm
            if self._l2_online is not None:
                prob_arf = self._l2_online.predict_proba(raw_feat)
                prob = max(prob_lgbm, prob_arf)

            # Feed the LGBM-stream into ADWIN — a shift in the frozen model's
            # output distribution is the canonical concept-drift signal.
            if self._l2_online is not None and self._l2_online.observe_for_drift(prob_lgbm):
                log.warning(
                    "L2 concept drift detected (ADWIN) — recent prob_lgbm distribution shifted"
                )

            if self._stats is not None:
                self._stats.record_flow()

            key = event["key"]
            if self._flow_buffer is not None:
                self._flow_buffer.add(
                    ts=time.time(),
                    key=(key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.proto),
                    features=raw_feat,
                    prob_lgbm=prob_lgbm,
                    prob_arf=prob_arf,
                )

            try:
                self._result_q.put_nowait({
                    "type": "l2",
                    "prob_attack_l2": prob,
                    "prob_l2_lgbm": prob_lgbm,
                    "prob_l2_arf": prob_arf,
                    "_queued_at": time.monotonic(),
                    "src_ip": key.src_ip,
                    "dst_ip": key.dst_ip,
                    "dst_port": key.dst_port,
                    "proto": key.proto,
                    "dur_us": event["dur_us"],
                })
            except queue.Full:
                pass

    def _alert_thread(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._result_q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._gate.process(event)
            except Exception as exc:
                log.debug("Alert processing error: %s", exc)

    def _on_signal(self, signum, _frame) -> None:
        log.info("Signal %d received.", signum)
        self._stop.set()
