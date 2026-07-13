"""
flow_buffer.py — Recent-L2-inference ring buffer with JSONL persistence.

Two consumers:
  1. The labelling CLI (`tools/label_and_learn.py`) reads the JSONL file
     to surface recent flows that the analyst can tag attack/benign.
  2. The engine itself can introspect the in-memory ring for diagnostics.

Persistence is append-only JSONL with byte-size rotation. Each line is one
L2 inference event with the full 16-feature vector + the two model verdicts
(LGBM frozen, ARF online). This is the audit trail.
"""

import json
import threading
import time
from collections import deque
from pathlib import Path

import numpy as np

_DEFAULT_BUFFER_LOG = Path("/var/log/multilayer_ids/flow_buffer.jsonl")
_DEFAULT_RING_SIZE = 5000
_ROTATE_BYTES = 50 * 1024 * 1024  # rotate at 50MB


class FlowBuffer:
    """
    Bounded in-memory ring + append-only JSONL on disk.

    Thread-safe. One JSONL line per L2 inference. The CLI tails this file;
    the engine never reads it back.
    """

    def __init__(
        self,
        log_path: Path = _DEFAULT_BUFFER_LOG,
        ring_size: int = _DEFAULT_RING_SIZE,
    ) -> None:
        self._log_path = log_path
        self._ring: deque[dict] = deque(maxlen=ring_size)
        self._lock = threading.Lock()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # line-buffered so the CLI sees writes immediately
        self._f = open(log_path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115

    def add(
        self,
        ts: float,
        key: tuple,
        features: np.ndarray,
        prob_lgbm: float,
        prob_arf: float | None,
    ) -> None:
        """Record one L2 inference. `key` = (src_ip, dst_ip, src_port, dst_port, proto)."""
        record = {
            "ts": ts,
            "src_ip": key[0],
            "dst_ip": key[1],
            "src_port": int(key[2]),
            "dst_port": int(key[3]),
            "proto": int(key[4]),
            "features": [float(x) for x in features.tolist()],
            "prob_lgbm": float(prob_lgbm),
            "prob_arf": float(prob_arf) if prob_arf is not None else None,
        }
        with self._lock:
            self._ring.append(record)
            self._f.write(json.dumps(record, ensure_ascii=False) + "\n")
            if self._f.tell() > _ROTATE_BYTES:
                self._rotate_locked()

    def _rotate_locked(self) -> None:
        self._f.close()
        rotated = self._log_path.with_suffix(
            f".jsonl.{int(time.time())}"
        )
        try:
            self._log_path.rename(rotated)
        except OSError:
            pass
        self._f = open(self._log_path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115

    def close(self) -> None:
        with self._lock:
            try:
                self._f.flush()
                self._f.close()
            except Exception:
                pass

    def snapshot(self) -> list[dict]:
        """Return a shallow copy of the ring for diagnostics."""
        with self._lock:
            return list(self._ring)
