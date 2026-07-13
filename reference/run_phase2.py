"""
run_phase2.py — Phase 2 orchestrator: feature engineering + model training.

Steps:
  1. Load and clean all 4 datasets
  2. Build layer1/2/3 processed parquet files
  3. Train Layer 1 Decision Tree
  4. Train Layer 2 LightGBM
  5. Train Layer 3 LightGBM
  6. Print consolidated evaluation summary

Usage:
    python run_phase2.py                  # full pipeline
    python run_phase2.py --features-only  # only build parquet files
    python run_phase2.py --train-only     # skip feature engineering
    python run_phase2.py --layer 1        # train single layer only
"""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore


def run_feature_engineering() -> None:
    from src.pipeline.clean import (clean_firewall, clean_cicids,
                                    clean_unsw, clean_botiot)
    from src.pipeline.features import build_all

    print("=" * 60)
    print(" PHASE 2A — Feature Engineering")
    print("=" * 60)

    print("\n[*] Loading Firewall Logs...")
    df_fw = clean_firewall()
    print(f"  Shape: {df_fw.shape}")

    print("\n[*] Loading CICIDS2017 (large — reading in chunks)...")
    df_cic = clean_cicids()

    print("\n[*] Loading UNSW-NB15...")
    df_unsw = clean_unsw()

    print("\n[*] Loading Bot-IoT NF...")
    df_bot = clean_botiot()

    build_all(df_fw, df_cic, df_unsw, df_bot)
    print("\n[✓] Feature engineering complete.")


def run_training(layers: list[int]) -> dict:
    from src.models.train_layer1 import train_layer1
    from src.models.train_layer2 import train_layer2
    from src.models.train_layer3 import train_layer3

    print("\n" + "=" * 60)
    print(" PHASE 2B — Model Training")
    print("=" * 60)

    results = {}
    if 1 in layers:
        print()
        results["layer1"] = train_layer1()
    if 2 in layers:
        print()
        results["layer2"] = train_layer2()
    if 3 in layers:
        print()
        results["layer3"] = train_layer3()

    return results


def print_summary(results: dict) -> None:
    print("\n" + "=" * 60)
    print(" PHASE 2 — Evaluation Summary")
    print("=" * 60)
    header = f"{'Layer':<8} {'Model':<14} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8} {'AUC':>8} {'Train(s)':>10} {'ms/sample':>10}"
    print(header)
    print("-" * len(header))
    for key in ("layer1", "layer2", "layer3"):
        if key not in results:
            continue
        r = results[key]
        print(
            f"  {r['layer']:<6} {r['model']:<14} "
            f"{r['accuracy']:>9.4f} {r['precision']:>10.4f} "
            f"{r['recall']:>8.4f} {r['f1']:>8.4f} {r['auc']:>8.4f} "
            f"{r['train_time_s']:>10.3f} {r['latency_ms_per_sample']:>10.4f}"
        )

    # Save consolidated report
    proc = ROOT / "data" / "processed"
    (proc / "phase2_summary.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print("\n[✓] Summary saved → data/processed/phase2_summary.json")
    print("    Models saved → models/")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2: Feature Engineering + Training")
    parser.add_argument("--features-only", action="store_true")
    parser.add_argument("--train-only",    action="store_true")
    parser.add_argument("--layer", type=int, choices=[1, 2, 3],
                        help="Train a single layer only")
    args = parser.parse_args()

    layers = [args.layer] if args.layer else [1, 2, 3]
    t0 = time.time()

    if not args.train_only:
        run_feature_engineering()

    if not args.features_only:
        # Verify processed files exist
        proc = ROOT / "data" / "processed"
        needed = {1: "layer1.parquet", 2: "layer2.parquet", 3: "layer3.parquet"}
        missing = [needed[lyr] for lyr in layers if not (proc / needed[lyr]).exists()]
        if missing:
            print(f"\n[!] Missing processed files: {missing}")
            print("    Run without --train-only first.")
            sys.exit(1)

        results = run_training(layers)
        print_summary(results)

    elapsed = time.time() - t0
    print(f"\n[✓] Phase 2 complete in {elapsed/60:.1f} min")


if __name__ == "__main__":
    main()
