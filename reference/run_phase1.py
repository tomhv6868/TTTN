"""
run_phase1.py — Phase 1 orchestrator: download datasets then profile them.

Usage:
    python run_phase1.py                   # download all + profile all
    python run_phase1.py --download-only   # skip profiling
    python run_phase1.py --profile-only    # skip download (data must exist)
    python run_phase1.py --ds cicids unsw  # specific datasets only
    python run_phase1.py --force           # re-download even if present
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.pipeline.download import download_kaggle_dataset, download_fw, REGISTRY  # noqa: E402
from src.pipeline.profile import build_report, DATASETS  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 1: Download + Profile datasets")
    parser.add_argument(
        "--ds",
        nargs="+",
        choices=list(REGISTRY.keys()) + ["all"],
        default=["all"],
        help="Dataset(s) to process",
    )
    parser.add_argument("--download-only", action="store_true")
    parser.add_argument("--profile-only", action="store_true")
    parser.add_argument("--force", action="store_true", help="Re-download even if present")
    args = parser.parse_args()

    ds_keys = list(REGISTRY.keys()) if "all" in args.ds else args.ds

    t0 = time.time()

    # ── Download ──────────────────────────────────────────────────────────────
    if not args.profile_only:
        print("=" * 60)
        print(" PHASE 1A — Dataset Download")
        print("=" * 60)
        for key in ds_keys:
            if key == "fw":
                download_fw(force=args.force)
            else:
                download_kaggle_dataset(key, force=args.force)

    # ── Profile ───────────────────────────────────────────────────────────────
    if not args.download_only:
        print("\n" + "=" * 60)
        print(" PHASE 1B — Dataset Profiling")
        print("=" * 60)
        profile_keys = [k for k in ds_keys if k in DATASETS]
        build_report(keys=profile_keys if profile_keys else None)

    elapsed = time.time() - t0
    print(f"\n[✓] Phase 1 complete in {elapsed:.1f}s")
    print("    EDA report → data/processed/eda_report.md")


if __name__ == "__main__":
    main()
