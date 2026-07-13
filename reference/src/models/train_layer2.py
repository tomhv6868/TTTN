"""
train_layer2.py — Layer 2 LightGBM trainer (Flow-level classifier).

Trained on CICIDS2017 + UNSW-NB15 + Bot-IoT NF combined dataset (~1.3M rows).
Handles class imbalance via class_weight='balanced' and SMOTE for Bot-IoT's
severe 98%/2% split (already mixed in by build_layer2 before SMOTE stage).

Output:
  models/layer2_lgbm.pkl
  models/layer2_scaler.pkl
  data/processed/layer2_eval.json
"""

import json
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from lightgbm import LGBMClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

ROOT   = Path(__file__).resolve().parents[2]
PROC   = ROOT / "data" / "processed"
MODELS = ROOT / "models"
MODELS.mkdir(exist_ok=True)

sys.path.insert(0, str(ROOT))
from src.pipeline.features import LAYER2_FEATURES  # noqa: E402


def train_layer2(test_size: float = 0.30, random_state: int = 42) -> dict:
    print("=" * 60)
    print(" Layer 2 — LightGBM (Flow classifier)")
    print("=" * 60)

    # ── Load ──────────────────────────────────────────────────────────────────
    df = pd.read_parquet(PROC / "layer2.parquet")
    print(f"  Loaded: {len(df):,} rows | "
          f"benign={int((df['y']==0).sum()):,} "
          f"attack={int((df['y']==1).sum()):,}")

    # Include 'src' as a feature so the model calibrates per dataset origin
    feature_cols = LAYER2_FEATURES + ["src"]
    X = df[feature_cols].values.astype(np.float32)
    y = df["y"].values

    # ── Split ─────────────────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

    # ── Scale ─────────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── SMOTE — only if severe imbalance (ratio > 5:1) ────────────────────────
    unique, counts = np.unique(y_train, return_counts=True)
    ratio = counts.max() / counts.min()
    print(f"  Class ratio (train): {ratio:.1f}:1", end="")
    if ratio > 5.0:
        print(" — applying SMOTE...")
        smote = SMOTE(random_state=random_state,
                      k_neighbors=min(5, int(counts.min()) - 1))
        X_train_s, y_train = smote.fit_resample(X_train_s, y_train)
        print(f"  After SMOTE: {len(X_train_s):,} samples")
    else:
        print(" — skipping SMOTE (using class_weight='balanced')")

    # ── Train ─────────────────────────────────────────────────────────────────
    model = LGBMClassifier(
        n_estimators=200,
        max_depth=8,
        num_leaves=63,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        n_jobs=-1,
        random_state=random_state,
        verbose=-1,
    )
    t0 = time.perf_counter()
    model.fit(
        X_train_s, y_train,
        eval_set=[(X_test_s, y_test)],
        callbacks=[],
    )
    train_time = time.perf_counter() - t0
    print(f"  Training time: {train_time:.2f}s")

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
    latency_ms = test_time / len(X_test) * 1000
    throughput  = len(X_test) / test_time

    print(f"\n  Results (test set, n={len(X_test):,}):")
    print(f"    Accuracy  : {acc:.4f}")
    print(f"    Precision : {prec:.4f}")
    print(f"    Recall    : {rec:.4f}")
    print(f"    F1        : {f1:.4f}")
    print(f"    AUC-ROC   : {auc:.4f}")
    print(f"    Test time : {test_time:.4f}s ({latency_ms:.4f}ms/sample)")
    print(f"    Throughput: {throughput:,.0f} samples/s")
    print(f"\n  Confusion matrix [[TN FP] [FN TP]]:\n  {cm}")
    print(f"\n  Classification report:\n"
          f"{classification_report(y_test, y_pred, target_names=['Benign','Attack'])}")

    # Feature importance (top 10)
    importances = dict(zip(feature_cols, model.feature_importances_))
    top10 = [(k, int(v)) for k, v in sorted(importances.items(), key=lambda x: -x[1])[:10]]
    print("  Top-10 feature importances:")
    for feat, imp in top10:
        print(f"    {feat:<22} {imp:>6.0f}")

    # ── Export ────────────────────────────────────────────────────────────────
    joblib.dump(model,  MODELS / "layer2_lgbm.pkl")
    joblib.dump(scaler, MODELS / "layer2_scaler.pkl")
    joblib.dump(feature_cols, MODELS / "layer2_features.pkl")
    print("  Saved: models/layer2_lgbm.pkl, layer2_scaler.pkl, layer2_features.pkl")

    results = {
        "layer": 2, "model": "LightGBM",
        "features": feature_cols,
        "n_train": len(X_train_s), "n_test": len(X_test),
        "accuracy": round(acc, 6), "precision": round(prec, 6),
        "recall": round(rec, 6), "f1": round(f1, 6), "auc": round(auc, 6),
        "train_time_s": round(train_time, 4),
        "test_time_s": round(test_time, 6),
        "latency_ms_per_sample": round(latency_ms, 6),
        "throughput_samples_s": round(throughput, 2),
        "confusion_matrix": cm,
        "top10_features": top10,
    }
    (PROC / "layer2_eval.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    return results


if __name__ == "__main__":
    train_layer2()
