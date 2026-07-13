"""
incremental_l2.py — Online-learning companion to the frozen L2 LightGBM.

Wraps river.ensemble.AdaptiveRandomForestClassifier (ARF) with an ADWIN
drift detector. Cold-start safe: predict_proba returns 0.0 until the first
learn_one call, so the ensemble vote in engine._l2_thread falls back to
LGBM-only behaviour until an analyst has labelled at least one flow.

State is persisted to models/layer2_arf.pkl with dill (river models are
not standard-pickle-safe). The learner thread tails a training-queue
JSONL file that the labelling CLI appends to; this avoids cross-process
shared state with the engine.
"""

import json
import logging
import threading
import time
from pathlib import Path

import dill  # type: ignore

from river import drift  # type: ignore

# ARF was renamed and relocated around river 0.19:
#   < 0.19 : river.ensemble.AdaptiveRandomForestClassifier
#   >= 0.19: river.forest.ARFClassifier
# Same algorithm, same constructor kwargs (n_models, seed). Support both so the
# project does not break the next time the user upgrades river.
try:
    from river.forest import ARFClassifier as AdaptiveRandomForestClassifier  # type: ignore
except ImportError:  # pragma: no cover — legacy river
    from river.ensemble import AdaptiveRandomForestClassifier  # type: ignore

log = logging.getLogger(__name__)

_FEATURE_NAMES = [
    "dst_port", "flow_dur_us", "fwd_pkts", "fwd_bytes",
    "bwd_pkts", "bwd_bytes", "pkt_len_min", "pkt_len_avg",
    "flow_bytes_s", "psh_flag", "ack_flag", "fin_flag",
    "init_win_fwd", "active_mean", "protocol_enc", "src",
]

# Persist on EVERY learn_one call. The state file is ~kilobytes; the I/O cost
# is dwarfed by the learning step. Persisting every-N samples lost data when
# the engine was killed before reaching N (e.g., 4 labels then Ctrl+C).
# Daemon threads do not run finally blocks on MainThread exit, so we can't
# rely on a shutdown persist either.
_PERSIST_EVERY = 1


class IncrementalL2:
    """
    River ARF + ADWIN, persisted to disk, fed by a JSONL training queue.

    Thread model:
      * predict_proba / observe_proba_for_drift are called from T3-L2Infer.
      * learn_one is called only from the internal _learner_thread.
      * A single re-entrant lock guards the ARF object across both paths.
    """

    def __init__(
        self,
        state_path: Path,
        training_queue_path: Path,
    ) -> None:
        self._state_path = state_path
        self._queue_path = training_queue_path
        self._lock = threading.RLock()

        self._model: AdaptiveRandomForestClassifier
        self._drift: drift.ADWIN
        self._samples_seen: int = 0
        self._drift_events: list[float] = []  # monotonic timestamps
        self._last_drift_at: float = 0.0

        self._load_or_init()

    # ── persistence ───────────────────────────────────────────────────────────

    def _load_or_init(self) -> None:
        if self._state_path.exists():
            try:
                with open(self._state_path, "rb") as f:
                    blob = dill.load(f)
                self._model = blob["model"]
                self._drift = blob["drift"]
                self._samples_seen = int(blob.get("samples_seen", 0))
                log.info(
                    "IncrementalL2: loaded ARF state from %s (samples_seen=%d)",
                    self._state_path, self._samples_seen,
                )
                return
            except Exception as exc:
                log.warning("IncrementalL2: failed to load state (%s) — reinitialising", exc)

        # Fresh model. n_models=5 keeps memory & inference cheap for live use.
        self._model = AdaptiveRandomForestClassifier(
            n_models=5,
            seed=42,
        )
        self._drift = drift.ADWIN()
        self._samples_seen = 0

    def _persist_locked(self) -> None:
        tmp = self._state_path.with_suffix(".pkl.tmp")
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as f:
            dill.dump(
                {
                    "model": self._model,
                    "drift": self._drift,
                    "samples_seen": self._samples_seen,
                },
                f,
            )
        tmp.replace(self._state_path)

    # ── inference path ────────────────────────────────────────────────────────

    @staticmethod
    def _vec_to_dict(features) -> dict:
        return {name: float(features[i]) for i, name in enumerate(_FEATURE_NAMES)}

    def predict_proba(self, features) -> float:
        """Return P(attack). 0.0 until the model has seen any label."""
        with self._lock:
            if self._samples_seen == 0:
                return 0.0
            try:
                x = self._vec_to_dict(features)
                pred = self._model.predict_proba_one(x)
                return float(pred.get(True, pred.get(1, 0.0)))
            except Exception as exc:
                log.debug("ARF predict_proba error: %s", exc)
                return 0.0

    def observe_for_drift(self, prob: float) -> bool:
        """Feed the ADWIN drift detector. Returns True if drift just fired."""
        with self._lock:
            try:
                self._drift.update(prob)
                if self._drift.drift_detected:
                    self._last_drift_at = time.monotonic()
                    self._drift_events.append(self._last_drift_at)
                    # bound the history to avoid unbounded growth
                    if len(self._drift_events) > 1000:
                        self._drift_events = self._drift_events[-500:]
                    return True
            except Exception as exc:
                log.debug("ADWIN update error: %s", exc)
            return False

    def drift_detected_recently(self, window_s: float = 60.0) -> bool:
        with self._lock:
            return (
                self._last_drift_at > 0
                and (time.monotonic() - self._last_drift_at) < window_s
            )

    @property
    def samples_seen(self) -> int:
        with self._lock:
            return self._samples_seen

    # ── learning path (called only from _learner_thread) ──────────────────────

    def _learn_one(self, features, label: bool) -> None:
        with self._lock:
            try:
                x = self._vec_to_dict(features)
                self._model.learn_one(x, bool(label))
                self._samples_seen += 1
                if self._samples_seen % _PERSIST_EVERY == 0:
                    self._persist_locked()
            except Exception as exc:
                log.warning("ARF learn_one error: %s", exc)

    def start_learner_thread(self, stop_event: threading.Event) -> threading.Thread:
        t = threading.Thread(
            target=self._learner_loop,
            args=(stop_event,),
            daemon=True,
            name="T6-L2Learner",
        )
        t.start()
        return t

    def _learner_loop(self, stop: threading.Event) -> None:
        """Tail training_queue_path; one JSONL line per labelled flow."""
        self._queue_path.parent.mkdir(parents=True, exist_ok=True)
        self._queue_path.touch(exist_ok=True)
        log.info("L2 learner: tailing %s", self._queue_path)
        try:
            f = open(self._queue_path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            log.error("L2 learner: cannot open queue (%s) — disabled", exc)
            return
        try:
            f.seek(0, 2)
            while not stop.is_set():
                line = f.readline()
                if not line:
                    stop.wait(0.5)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    feats = row["features"]
                    label = bool(row["label"])
                except (ValueError, KeyError) as exc:
                    log.warning("L2 learner: bad line skipped (%s)", exc)
                    continue
                self._learn_one(feats, label)
                log.info(
                    "L2 learner: trained on label=%s (total samples=%d)",
                    label, self._samples_seen,
                )
        finally:
            try:
                f.close()
            except Exception:
                pass
            # final persist on shutdown
            with self._lock:
                try:
                    self._persist_locked()
                except Exception:
                    pass
