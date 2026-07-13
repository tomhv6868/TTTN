"""
train_layer1.py — Layer 1 Decision Tree trainer (Firewall Logs).

Trains the packet-level classifier that replicates and extends the RT-FLID
paper methodology. Uses 5 features (paper used 4; we add NAT Source Port
based on EDA showing it is the strongest predictor, |r|=0.69).

Output:
  models/layer1_dt.pkl
  models/layer1_scaler.pkl
  data/processed/layer1_eval.json
"""

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

ROOT    = Path(__file__).resolve().parents[2]
PROC    = ROOT / "data" / "processed"
MODELS  = ROOT / "models"
MODELS.mkdir(exist_ok=True)

sys.path.insert(0, str(ROOT))
from src.pipeline.features import LAYER1_FEATURES  # noqa: E402


def train_layer1(test_size: float = 0.30, random_state: int = 42) -> dict:
    print("=" * 60)
    print(" Layer 1 — Decision Tree (Firewall Logs)")
    print("=" * 60)

    # ── Load processed data ───────────────────────────────────────────────────
    df = pd.read_parquet(PROC / "layer1.parquet")
    print(f"  Loaded: {len(df):,} rows | "
          f"benign={int((df['y']==0).sum()):,} "
          f"attack={int((df['y']==1).sum()):,}")

    X = df[LAYER1_FEATURES].values.astype(np.float32)
    y = df["y"].values

    # ── Split 70/30 stratified (optimal per paper) ────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

    # ── Scale ─────────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # Note: binary ratio is ~1.35 (allow vs deny+drop+reset-both) — balanced
    # enough that SMOTE is not needed. class_weight='balanced' handles it.

    # ── Train ─────────────────────────────────────────────────────────────────
    model = DecisionTreeClassifier(
        max_depth=15,
        class_weight="balanced",
        random_state=random_state,
        min_samples_leaf=5,
    )
    t0 = time.perf_counter()
    model.fit(X_train_s, y_train)
    train_time = time.perf_counter() - t0
    print(f"  Training time: {train_time:.4f}s")

    # ── Evaluate ──────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    y_pred = model.predict(X_test_s)
    test_time = time.perf_counter() - t0
    y_prob = model.predict_proba(X_test_s)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_prob)
    cm   = confusion_matrix(y_test, y_pred).tolist()

    latency_ms    = test_time / len(X_test) * 1000
    throughput    = len(X_test) / test_time

    print(f"\n  Results (test set, n={len(X_test):,}):")
    print(f"    Accuracy  : {acc:.4f}")
    print(f"    Precision : {prec:.4f}")
    print(f"    Recall    : {rec:.4f}")
    print(f"    F1        : {f1:.4f}")
    print(f"    AUC-ROC   : {auc:.4f}")
    print(f"    Test time : {test_time:.5f}s ({latency_ms:.4f}ms/sample)")
    print(f"    Throughput: {throughput:,.0f} samples/s")
    print(f"\n  Confusion matrix [[TN FP] [FN TP]]:\n  {cm}")
    print(f"\n  Classification report:\n"
          f"{classification_report(y_test, y_pred, target_names=['Benign','Attack'])}")

    # ── Export ────────────────────────────────────────────────────────────────
    joblib.dump(model,  MODELS / "layer1_dt.pkl")
    joblib.dump(scaler, MODELS / "layer1_scaler.pkl")
    print("  Saved: models/layer1_dt.pkl, models/layer1_scaler.pkl")

    results = {
        "layer": 1, "model": "DecisionTree",
        "features": LAYER1_FEATURES,
        "n_train": len(X_train), "n_test": len(X_test),
        "accuracy": round(acc, 6), "precision": round(prec, 6),
        "recall": round(rec, 6), "f1": round(f1, 6), "auc": round(auc, 6),
        "train_time_s": round(train_time, 6),
        "test_time_s": round(test_time, 6),
        "latency_ms_per_sample": round(latency_ms, 6),
        "throughput_samples_s": round(throughput, 2),
        "confusion_matrix": cm,
    }
    (PROC / "layer1_eval.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    return results


if __name__ == "__main__":
    train_layer1()
