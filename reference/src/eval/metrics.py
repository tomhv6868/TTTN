"""
metrics.py — Offline per-layer F1/AUC evaluation using saved models.

Re-runs inference on the held-out test split (same 70/30 stratified split,
random_state=42 used during training) and returns a metrics dict per layer.
Run on the Ubuntu VM where data/processed/ and models/ are accessible.
"""

import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split

ROOT  = Path(__file__).resolve().parents[2]
PROC  = ROOT / "data" / "processed"
MODELS = ROOT / "models"

sys.path.insert(0, str(ROOT))
from src.pipeline.features import LAYER1_FEATURES, LAYER2_FEATURES, LAYER3_FEATURES  # noqa: E402


def _eval_layer(
    parquet: str,
    feature_cols: list[str],
    model_path: str,
    scaler_path: str,
    label: str = "y",
    test_size: float = 0.30,
    random_state: int = 42,
) -> dict:
    df = pd.read_parquet(PROC / parquet)
    X = df[feature_cols].values.astype(np.float32)
    y = df[label].values

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    model  = joblib.load(MODELS / model_path)
    scaler = joblib.load(MODELS / scaler_path)
    X_test_s = scaler.transform(X_test)

    t0 = time.perf_counter()
    y_pred = model.predict(X_test_s)
    elapsed = time.perf_counter() - t0
    y_prob = model.predict_proba(X_test_s)[:, 1]

    cm = confusion_matrix(y_test, y_pred).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    single = _single_sample_latency(model, X_test_s)

    return {
        "n_test": len(X_test),
        "accuracy": round((tp + tn) / len(y_test), 6),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 6),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 6),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 6),
        "auc": round(roc_auc_score(y_test, y_prob), 6),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "latency_ms_per_sample": round(elapsed / len(X_test) * 1000, 6),
        "throughput_samples_s": round(len(X_test) / elapsed, 1),
        "single_sample_latency_ms": single,
    }


def _single_sample_latency(model, X_test_s: np.ndarray, n: int = 500) -> dict:
    """
    Measure realistic per-sample inference latency by timing individual
    predict calls — the live IDS scores one flow at a time, so the batched
    latency_ms_per_sample above understates the true live cost.

    Returns mean/p50/p95/p99 in milliseconds over n single-row predictions.
    """
    n = min(n, len(X_test_s))
    if n == 0:
        return {"n": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
    rng = np.random.RandomState(42)
    sample_idx = rng.choice(len(X_test_s), size=n, replace=False)
    times_ms: list[float] = []
    for i in sample_idx:
        row = X_test_s[i:i + 1]
        t0 = time.perf_counter()
        model.predict(row)
        times_ms.append((time.perf_counter() - t0) * 1000)
    s = sorted(times_ms)
    return {
        "n": n,
        "mean_ms": round(sum(s) / n, 4),
        "p50_ms": round(s[n // 2], 4),
        "p95_ms": round(s[min(int(n * 0.95), n - 1)], 4),
        "p99_ms": round(s[min(int(n * 0.99), n - 1)], 4),
    }


def evaluate_all_layers() -> dict[str, dict]:
    """Re-evaluate all three layers on held-out test sets. Returns per-layer metrics."""
    print("  [metrics] Layer 1 — Decision Tree (Firewall Logs)...")
    l1 = _eval_layer(
        parquet="layer1.parquet",
        feature_cols=LAYER1_FEATURES,
        model_path="layer1_dt.pkl",
        scaler_path="layer1_scaler.pkl",
    )

    print("  [metrics] Layer 2 — LightGBM (Flow)...")
    l2 = _eval_layer(
        parquet="layer2.parquet",
        feature_cols=LAYER2_FEATURES + ["src"],
        model_path="layer2_lgbm.pkl",
        scaler_path="layer2_scaler.pkl",
    )

    print("  [metrics] Layer 3 — LightGBM (Session)...")
    l3 = _eval_layer(
        parquet="layer3.parquet",
        feature_cols=LAYER3_FEATURES + ["src"],
        model_path="layer3_lgbm.pkl",
        scaler_path="layer3_scaler.pkl",
    )

    return {"L1": l1, "L2": l2, "L3": l3}
