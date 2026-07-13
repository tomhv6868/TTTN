"""
error_analysis.py — Pattern-Aware Error Analysis (requirement 3 / 3.1).

For each layer we re-run inference on the held-out test split, isolate the
misclassified samples (FP and FN), group them by dataset of origin, and
produce a diagnostic card answering:

    WHAT  → the feature pattern of the failing samples
    WHY   → the root cause, inferred from computed signals (not hand-waved)
    WHEN  → the feature-region + confidence band under which the model errs
    FIX   → a concrete, system-specific technique to address that root cause

Root cause is decided from three measured signals per error group:

  1. Error confidence — mean predict_proba of the error samples, split into
     "boundary" (just past the 0.5 decision line) vs "confidently wrong"
     (far past it). Boundary errors are a *threshold* problem; confident
     errors are a *knowledge* problem.

  2. Class overlap — histogram-overlap coefficient between the error group
     and the correctly-classified samples of the WRONGLY-PREDICTED class,
     on the top distinguishing features. High overlap means the features
     genuinely cannot separate the two classes here.

  3. Concentration — the group's share of the layer's errors. Tells us if
     the failure is systematic (worth fixing) or scattered.

The split (70/30, stratify, random_state=42) is identical to training and
to metrics.py, so the rows analysed here are exactly the rows scored there.
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[2]
PROC = ROOT / "data" / "processed"
MODELS = ROOT / "models"

sys.path.insert(0, str(ROOT))
from src.pipeline.features import LAYER1_FEATURES, LAYER2_FEATURES, LAYER3_FEATURES  # noqa: E402

# Dataset-origin code → human name, per layer (see src/pipeline/features.py).
_SRC_NAMES = {
    "L1": {0: "Firewall logs"},
    "L2": {0: "CICIDS2017", 1: "UNSW-NB15", 2: "Bot-IoT"},
    "L3": {1: "UNSW-NB15", 2: "Bot-IoT"},
}

_MIN_GROUP = 5
_TOP_K_FEATURES = 3

# Root-cause labels
_CAUSE_THRESHOLD = "Decision-boundary ambiguity (threshold miscalibration)"
_CAUSE_DRIFT     = "Underrepresentation / concept drift"
_CAUSE_OVERLAP   = "Intrinsic class overlap (feature insufficiency)"
_CAUSE_MIXED     = "Heterogeneous errors (no single dominant cause)"


def _load_test_split(parquet: str, feature_cols: list[str]):
    """X uses exactly feature_cols (what the scaler/model expect). src loaded
    separately for grouping regardless of whether it is a model input."""
    df = pd.read_parquet(PROC / parquet)
    X = df[feature_cols].values.astype(np.float32)
    y = df["y"].values
    src = df["src"].values if "src" in df.columns else np.zeros(len(df), dtype=int)
    idx = np.arange(len(df))
    _, idx_test = train_test_split(idx, test_size=0.30, random_state=42, stratify=y)
    return X[idx_test], y[idx_test], src[idx_test], feature_cols


def _top_features(err_rows, ref_rows, feature_names):
    """K features whose error-group mean deviates most (σ units) from ref."""
    if len(err_rows) == 0 or len(ref_rows) == 0:
        return []
    ref_mean = ref_rows.mean(axis=0)
    ref_std = ref_rows.std(axis=0) + 1e-9
    err_mean = err_rows.mean(axis=0)
    std_delta = np.abs(err_mean - ref_mean) / ref_std
    if "src" in feature_names:
        std_delta[feature_names.index("src")] = -1.0
    order = np.argsort(std_delta)[::-1][:_TOP_K_FEATURES]
    return [(feature_names[i], int(i), float(err_mean[i]), float(std_delta[i])) for i in order]


def _overlap_coefficient(a: np.ndarray, b: np.ndarray, bins: int = 30) -> float:
    """Histogram overlap of two 1-D samples. 1.0 = identical, 0.0 = disjoint."""
    if len(a) == 0 or len(b) == 0:
        return 0.0
    lo = float(min(a.min(), b.min()))
    hi = float(max(a.max(), b.max()))
    if hi <= lo:
        return 1.0
    ha, _ = np.histogram(a, bins=bins, range=(lo, hi))
    hb, _ = np.histogram(b, bins=bins, range=(lo, hi))
    pa = ha / max(ha.sum(), 1)
    pb = hb / max(hb.sum(), 1)
    return float(np.minimum(pa, pb).sum())


def _confidence_profile(probs: np.ndarray, error_type: str) -> dict:
    """Split error confidences into boundary vs confidently-wrong fractions.

    FN (model said benign, prob<0.5): boundary=[0.35,0.5), confident=<0.2.
    FP (model said attack, prob>=0.5): boundary=(0.5,0.65], confident=>0.8.
    """
    n = len(probs)
    if n == 0:
        return {"mean": 0.0, "boundary_frac": 0.0, "confident_frac": 0.0}
    if error_type == "FN":
        boundary = np.mean((probs >= 0.35) & (probs < 0.5))
        confident = np.mean(probs < 0.2)
    else:
        boundary = np.mean((probs > 0.5) & (probs <= 0.65))
        confident = np.mean(probs > 0.8)
    return {
        "mean": float(probs.mean()),
        "boundary_frac": float(boundary),
        "confident_frac": float(confident),
    }


def _decide_cause(conf: dict, overlap: float) -> str:
    if conf["boundary_frac"] >= 0.5:
        return _CAUSE_THRESHOLD
    if conf["confident_frac"] >= 0.5 and overlap < 0.5:
        return _CAUSE_DRIFT
    if overlap >= 0.5:
        return _CAUSE_OVERLAP
    return _CAUSE_MIXED


# ── Concrete, system-specific fix recommendations ─────────────────────────────
# Keyed by (layer, cause). Each value is the "FIX" text for the diagnostic card.

_FIX: dict[tuple[str, str], str] = {
    # ── Layer 1 — Decision Tree, 5 packet-header features, latency-critical fast path
    ("L1", _CAUSE_THRESHOLD): (
        "L1 is the 0.90-confidence fast path; do not tune it in isolation. "
        "Ambiguous packets already fall through to L2/L3 — leave them to those "
        "layers rather than calibrating L1 and risking the hot-path latency."
    ),
    ("L1", _CAUSE_DRIFT): (
        "L1 has only 5 header features and cannot represent novel attacks. Do "
        "NOT add online learning here (it is the per-packet hot path). Rely on "
        "the Phase-7 L2 ARF learner to absorb the new attack profile instead."
    ),
    ("L1", _CAUSE_OVERLAP): (
        "Expected: 5 header features can't separate content-based attacks. This "
        "is by design — L1 targets volumetric/scan signals. Route these to L4 "
        "(HTTP/DNS) which inspects payload."
    ),
    # ── Layer 2 — LightGBM, 16 flow features, HAS the Phase-7 ARF online learner
    ("L2", _CAUSE_THRESHOLD): (
        "Replace the single L2_THRESHOLD=0.65 with per-source thresholds + "
        "isotonic probability calibration. CICIDS2017/UNSW/Bot-IoT have very "
        "different attack base-rates, so one global cut is miscalibrated for "
        "each. Calibrate on a per-`src` validation slice."
    ),
    ("L2", _CAUSE_DRIFT): (
        "This is exactly what Mức 2 was built for: route these confidently-"
        "missed flows through the Phase-7 ARF online learner — label them via "
        "tools/label_and_learn.py and the ARF closes the gap (validated 2/5→5/5 "
        "on the slow-scan demo). Optionally add cost-sensitive (focal) loss to "
        "the frozen LGBM retrain to weight this rare profile."
    ),
    ("L2", _CAUSE_OVERLAP): (
        "Single-flow stats overlap here. Add discriminative flow features the "
        "current 16 lack: IAT variance/std (we only keep active_mean), "
        "bidirectional byte/packet ratio, and flow burstiness. If overlap "
        "persists, model flow *sequences* (sliding window of flows per host) "
        "with a 1-D CNN / LSTM rather than scoring flows independently."
    ),
    # ── Layer 3 — LightGBM, session features, TTL-heavy (TTL=0 for live Zeek!)
    ("L3", _CAUSE_THRESHOLD): (
        "Per-network calibration: TTL/state distributions are environment-"
        "specific, so the UNSW/Bot-IoT-trained boundary is miscalibrated for "
        "live Zeek traffic. Recalibrate the L3 threshold on a sample of the "
        "actual deployment network before trusting it."
    ),
    ("L3", _CAUSE_DRIFT): (
        "L3 has no online learner yet (Phase 7 was L2-only). Extend the "
        "IncrementalL2 ARF wrapper to L3 (same pattern, new feature list), or "
        "until then defer this attack class to L4 if it is content-based."
    ),
    ("L3", _CAUSE_OVERLAP): (
        "Root cause is concrete: src_ttl/dst_ttl are filled as 0 for live Zeek "
        "(they are not in conn.log — see zeek_reader.py), so any TTL-based "
        "separation learned from UNSW/Bot-IoT does NOT transfer to deployment. "
        "Drop src_ttl/dst_ttl from the live L3 model and add behavioural session "
        "features instead: inter-request timing, byte-ratio over the session, "
        "and connection-state transition counts."
    ),
}

_FIX_DEFAULT = (
    "Errors are heterogeneous — split this group further (e.g. by service or "
    "port) before prescribing a fix; no single technique dominates."
)


def _fix_text(layer: str, cause: str) -> str:
    if cause == _CAUSE_MIXED:
        return _FIX_DEFAULT
    return _FIX.get((layer, cause), _FIX_DEFAULT)


def _why_text(cause: str, conf: dict, overlap: float) -> str:
    base = {
        _CAUSE_THRESHOLD: (
            f"{conf['boundary_frac']*100:.0f}% of these errors sit just past the "
            f"0.5 decision line (mean P={conf['mean']:.2f}) — the model is "
            f"hesitant here, not ignorant. A better-placed/calibrated threshold "
            f"recovers most of them."
        ),
        _CAUSE_DRIFT: (
            f"{conf['confident_frac']*100:.0f}% are confidently wrong (mean "
            f"P={conf['mean']:.2f}) yet feature-overlap with the predicted class "
            f"is low ({overlap:.2f}) — the model never learned this profile; it "
            f"is rare or absent in training."
        ),
        _CAUSE_OVERLAP: (
            f"feature-overlap with the wrongly-predicted class is high "
            f"({overlap:.2f}) — on the available features these samples are "
            f"genuinely indistinguishable from the other class. More data won't "
            f"help; better features will."
        ),
        _CAUSE_MIXED: (
            f"mixed signature: mean P={conf['mean']:.2f}, overlap={overlap:.2f}, "
            f"boundary={conf['boundary_frac']*100:.0f}%, confident="
            f"{conf['confident_frac']*100:.0f}% — no single cause dominates."
        ),
    }
    return base[cause]


def _when_text(error_type: str, top, benign_mean: np.ndarray, conf: dict) -> str:
    if not top:
        return "insufficient samples to localise."
    parts = []
    for name, idx, mean, _ in top:
        direction = "high" if mean > benign_mean[idx] else "low"
        parts.append(f"{name} is {direction} (≈{mean:.1f})")
    region = ", ".join(parts)
    band = (
        "confidently misclassified" if conf["confident_frac"] >= 0.5
        else "near the decision boundary" if conf["boundary_frac"] >= 0.5
        else "with mixed confidence"
    )
    verb = "missed" if error_type == "FN" else "false-flagged"
    return f"traffic is {verb} when {region}; these are {band}."


def analyze_layer(layer, parquet, feature_cols, model_path, scaler_path):
    X_test, y_test, src_test, cols = _load_test_split(parquet, feature_cols)
    model = joblib.load(MODELS / model_path)
    scaler = joblib.load(MODELS / scaler_path)
    Xs = scaler.transform(X_test)
    y_pred = model.predict(Xs)
    y_prob = model.predict_proba(Xs)[:, 1]

    fp_mask = (y_test == 0) & (y_pred == 1)
    fn_mask = (y_test == 1) & (y_pred == 0)
    correct_benign = (y_test == 0) & (y_pred == 0)
    correct_attack = (y_test == 1) & (y_pred == 1)
    benign_mean = X_test[correct_benign].mean(axis=0) if correct_benign.any() else X_test.mean(axis=0)

    src_names = _SRC_NAMES.get(layer, {})
    rows: list[dict] = []

    for error_type, err_mask, ref_same, ref_opp in (
        ("FP", fp_mask, correct_benign, correct_attack),
        ("FN", fn_mask, correct_attack, correct_benign),
    ):
        total_err = int(err_mask.sum())
        if total_err == 0:
            continue
        for src_code in sorted(set(src_test[err_mask].tolist())):
            group_mask = err_mask & (src_test == src_code)
            n = int(group_mask.sum())
            if n < _MIN_GROUP:
                continue
            group_name = src_names.get(int(src_code), f"src={int(src_code)}")
            top = _top_features(X_test[group_mask], X_test[ref_same], cols)

            # overlap with the WRONGLY-predicted class on the top features
            overlaps = []
            for _, idx, _, _ in top:
                overlaps.append(_overlap_coefficient(
                    X_test[group_mask][:, idx], X_test[ref_opp][:, idx]
                ))
            overlap = float(np.mean(overlaps)) if overlaps else 0.0

            conf = _confidence_profile(y_prob[group_mask], error_type)
            cause = _decide_cause(conf, overlap)

            pattern = "; ".join(
                f"{name}≈{mean:.1f} (Δ{delta:.1f}σ)" for name, _, mean, delta in top
            ) or "—"

            rows.append({
                "error": error_type,
                "group": group_name,
                "n": n,
                "share": n / total_err,
                "mean_prob": round(conf["mean"], 3),
                "overlap": round(overlap, 3),
                "boundary_frac": round(conf["boundary_frac"], 3),
                "confident_frac": round(conf["confident_frac"], 3),
                "cause": cause,
                "pattern": pattern,
                "what": pattern,
                "why": _why_text(cause, conf, overlap),
                "when": _when_text(error_type, top, benign_mean, conf),
                "fix": _fix_text(layer, cause),
            })
    return rows


def analyze_all_layers() -> dict[str, list[dict]]:
    print("  [error-analysis] Layer 1...")
    l1 = analyze_layer("L1", "layer1.parquet", LAYER1_FEATURES,
                       "layer1_dt.pkl", "layer1_scaler.pkl")
    print("  [error-analysis] Layer 2...")
    l2 = analyze_layer("L2", "layer2.parquet", LAYER2_FEATURES + ["src"],
                       "layer2_lgbm.pkl", "layer2_scaler.pkl")
    print("  [error-analysis] Layer 3...")
    l3 = analyze_layer("L3", "layer3.parquet", LAYER3_FEATURES + ["src"],
                       "layer3_lgbm.pkl", "layer3_scaler.pkl")
    return {"L1": l1, "L2": l2, "L3": l3}


def format_report(results: dict[str, list[dict]]) -> str:
    lines = [
        "## 7. Pattern-Aware Error Analysis (Why / When / What → Fix)",
        "",
        "_Each misclassification group is diagnosed from three measured signals — "
        "error confidence, class-overlap, and concentration — then mapped to a "
        "root cause and a concrete, system-specific fix._",
        "",
    ]
    for layer, rows in results.items():
        lines.append(f"### {layer}")
        lines.append("")
        if not rows:
            lines.append("_No error groups above the minimum-size threshold._")
            lines.append("")
            continue
        for r in rows:
            lines += [
                f"#### {r['error']} · {r['group']} · {r['n']:,} samples "
                f"({r['share']*100:.0f}% of {layer} {r['error']})",
                "",
                f"- **Root cause**: {r['cause']}",
                f"- **What** (pattern): {r['what']}",
                f"- **Why**: {r['why']}",
                f"- **When**: {r['when']}",
                f"- **Fix** (proposal): {r['fix']}",
                f"- _signals_: mean P={r['mean_prob']}, overlap={r['overlap']}, "
                f"boundary={r['boundary_frac']}, confident-wrong={r['confident_frac']}",
                "",
            ]
    return "\n".join(lines)


if __name__ == "__main__":
    res = analyze_all_layers()
    print()
    print(format_report(res))
