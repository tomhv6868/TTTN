"""
profile.py — Dataset profiler for the Multi-Layer IDS project.

Produces a markdown report (data/processed/eda_report.md) covering:
  - Shape, dtypes, memory
  - Null and infinity counts
  - Class distribution
  - Numeric summary (min/max/mean/std)
  - Top Pearson correlations with the target column
  - Feature redundancy flags (|r| > 0.95 pairs)

Reads in chunks for large datasets to stay within 12 GB RAM.

Usage:
    python -m src.pipeline.profile
    python -m src.pipeline.profile --ds cicids
"""

import argparse
import sys
import warnings
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

import numpy as np
import pandas as pd
from tabulate import tabulate

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
REPORT_PATH = PROCESSED / "eda_report.md"

# ── Dataset configurations ────────────────────────────────────────────────────
# target: the label column name in the raw CSV
# label_map: how to display label values in the report
# chunk_size: rows per chunk for large files (None = load all at once)
DATASETS = {
    "fw": {
        "name": "Firewall Logs",
        "glob": "firewall_logs/*.csv",
        "target": "Action",
        "chunk_size": None,
    },
    "cicids": {
        "name": "CICIDS2017",
        # cleaned version has a single CSV; original has per-day CSVs with ' Label' column
        "glob": "cicids2017/**/*.csv",
        "target": "Attack Type",     # cleaned version uses this; fallback sniffs others
        "chunk_size": 200_000,
    },
    "unsw": {
        "name": "UNSW-NB15",
        # Use the pre-split training/testing CSVs (smaller) for profiling;
        # full files (UNSW-NB15_1..4) are used for training later.
        "glob": "unsw_nb15/UNSW_NB15_*.csv",
        "target": "label",
        "chunk_size": 200_000,
    },
    "botiot": {
        "name": "Bot-IoT NF subset",
        # NF-BoT-IoT is a parquet file; handled specially below
        "glob": "botiot/*.parquet",
        "target": "Label",
        "chunk_size": None,          # small enough to load all at once
        "is_parquet": True,
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_csvs(glob_pattern: str) -> list[Path]:
    return sorted(RAW.glob(glob_pattern))


def _find_data_files(glob_pattern: str) -> list[Path]:
    """Find CSV or parquet files matching a glob."""
    files = sorted(RAW.glob(glob_pattern))
    # Skip tiny metadata files (<5 KB)
    return [f for f in files if f.stat().st_size > 5_000]


def _sniff_target(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Return the first candidate column name that exists (case-insensitive)."""
    lower = {c.lower().strip(): c for c in df.columns}
    for cand in candidates:
        key = cand.lower().strip()
        if key in lower:
            return lower[key]
    return None


def _load_sample(paths: list[Path], chunk_size: int | None,
                 max_rows: int = 500_000, is_parquet: bool = False) -> pd.DataFrame:
    """Load up to max_rows rows from CSV or parquet files."""
    frames = []
    collected = 0

    for path in paths:
        if collected >= max_rows:
            break
        remaining = max_rows - collected
        try:
            if is_parquet or path.suffix.lower() == ".parquet":
                df = pd.read_parquet(path)
                if len(df) > remaining:
                    df = df.head(remaining)
                frames.append(df)
                collected += len(df)
            elif chunk_size is None or chunk_size >= remaining:
                df = pd.read_csv(path, nrows=remaining, low_memory=False)
                frames.append(df)
                collected += len(df)
            else:
                for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
                    frames.append(chunk)
                    collected += len(chunk)
                    if collected >= max_rows:
                        break
        except Exception as exc:
            print(f"  [warn] Could not read {path.name}: {exc}")

    if not frames:
        return pd.DataFrame()

    df = pd.concat(frames, ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    return df


def _count_inf(paths: list[Path], chunk_size: int | None) -> dict[str, int]:
    """Count true infinity occurrences per column (before replacing with NaN)."""
    inf_counts: dict[str, int] = {}
    for path in paths:
        try:
            reader = (
                pd.read_csv(path, chunksize=chunk_size or 100_000, low_memory=False)
                if chunk_size
                else [pd.read_csv(path, low_memory=False)]
            )
            for chunk in reader:
                num = chunk.select_dtypes(include="number")
                for col in num.columns:
                    n = np.isinf(num[col]).sum()
                    inf_counts[col] = inf_counts.get(col, 0) + int(n)
        except Exception:
            pass
    return {k: v for k, v in inf_counts.items() if v > 0}


def _full_class_dist(paths: list[Path], target_col: str, chunk_size: int | None) -> pd.Series:
    """Aggregate class counts across all files without loading everything at once."""
    counts: dict = {}
    for path in paths:
        try:
            reader = (
                pd.read_csv(path, usecols=[target_col], chunksize=chunk_size or 100_000, low_memory=False)
                if chunk_size
                else [pd.read_csv(path, usecols=[target_col], low_memory=False)]
            )
            for chunk in reader:
                for val, n in chunk[target_col].value_counts().items():
                    counts[val] = counts.get(val, 0) + int(n)
        except Exception:
            pass
    return pd.Series(counts).sort_values(ascending=False)


def _pearson_with_target(df: pd.DataFrame, target_col: str) -> pd.DataFrame:
    """Pearson correlation of all numeric features with the target."""
    num_df = df.select_dtypes(include="number").copy()

    # Encode target if categorical
    if target_col in df.columns and df[target_col].dtype == object:
        num_df["__target__"] = pd.factorize(df[target_col])[0].astype(float)
        tcol = "__target__"
    elif target_col in num_df.columns:
        tcol = target_col
    else:
        return pd.DataFrame()

    corr = num_df.corr(numeric_only=True)[tcol].drop(tcol, errors="ignore")
    result = corr.abs().sort_values(ascending=False).reset_index()
    result.columns = ["Feature", "|r| with target"]
    result["r with target"] = corr.loc[result["Feature"]].values
    return result


def _redundant_pairs(df: pd.DataFrame, threshold: float = 0.95) -> list[tuple]:
    """Find feature pairs with |Pearson r| > threshold (multicollinearity)."""
    num = df.select_dtypes(include="number")
    corr = num.corr(numeric_only=True).abs()
    pairs = []
    cols = list(corr.columns)
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            r = corr.iloc[i, j]
            if r >= threshold:
                pairs.append((cols[i], cols[j], round(r, 4)))
    pairs.sort(key=lambda x: -x[2])
    return pairs


# ── Per-dataset profiler ──────────────────────────────────────────────────────

def profile_dataset(key: str, cfg: dict) -> str:
    """Return a markdown section string for one dataset."""
    is_parquet = cfg.get("is_parquet", False)
    paths = _find_data_files(cfg["glob"])
    lines = [f"## {cfg['name']}\n"]

    if not paths:
        lines.append(f"> **No data found** — expected files matching `data/raw/{cfg['glob']}`\n")
        lines.append("> Run `python run_phase1.py --download-only` first.\n")
        return "\n".join(lines)

    lines.append(f"**Files found:** {len(paths)}")
    total_mb = sum(p.stat().st_size for p in paths) / 1024 / 1024
    lines.append(f"**Total raw size:** {total_mb:.1f} MB\n")

    # ── Load sample ──────────────────────────────────────────────────────────
    print(f"  Loading sample for {cfg['name']}...")
    df = _load_sample(paths, cfg["chunk_size"], is_parquet=is_parquet)

    if df.empty:
        lines.append("> Could not load any data.\n")
        return "\n".join(lines)

    # ── Basic shape ──────────────────────────────────────────────────────────
    lines.append(f"**Sample rows loaded:** {len(df):,} (of full dataset)")
    lines.append(f"**Columns:** {df.shape[1]}\n")

    # ── Resolve target column ────────────────────────────────────────────────
    target_candidates = [cfg["target"], "Label", "label", "Action", "action",
                         "attack", "Attack", "category", "Category", "class"]
    target_col = _sniff_target(df, target_candidates)
    if target_col:
        lines.append(f"**Target column:** `{target_col}`\n")
    else:
        lines.append(f"> **[warn]** Could not find target column (tried: {target_candidates})\n")

    # ── Dtypes ───────────────────────────────────────────────────────────────
    dtype_counts = df.dtypes.value_counts().to_dict()
    dtype_str = ", ".join(f"{v}× {k}" for k, v in dtype_counts.items())
    lines.append(f"**Column types:** {dtype_str}\n")

    # ── Null / Inf counts ────────────────────────────────────────────────────
    null_counts = df.isnull().sum()
    null_pct = (null_counts / len(df) * 100).round(2)
    null_report = null_counts[null_counts > 0]

    if null_report.empty:
        lines.append("**Null values:** None\n")
    else:
        lines.append(f"**Columns with nulls:** {len(null_report)}")
        null_table = pd.DataFrame({
            "Column": null_report.index,
            "Null count": null_report.values,
            "Null %": null_pct[null_report.index].values,
        }).head(15)
        lines.append(tabulate(null_table, headers="keys", tablefmt="pipe", showindex=False))
        lines.append("")

    # Infinity counting only meaningful for CSV (parquet stores typed data)
    if not is_parquet:
        print(f"  Counting infinities for {cfg['name']}...")
        inf_counts = _count_inf(paths, cfg["chunk_size"])
        if inf_counts:
            lines.append(f"**Columns with +-inf values:** {len(inf_counts)}")
            inf_table = pd.DataFrame(
                [(k, v) for k, v in sorted(inf_counts.items(), key=lambda x: -x[1])],
                columns=["Column", "Inf count"],
            ).head(10)
            lines.append(tabulate(inf_table, headers="keys", tablefmt="pipe", showindex=False))
            lines.append("")
        else:
            lines.append("**Infinity values:** None\n")
    else:
        lines.append("**Infinity values:** N/A (parquet typed storage)\n")

    # ── Class distribution ───────────────────────────────────────────────────
    if target_col:
        print(f"  Computing class distribution for {cfg['name']}...")
        if is_parquet:
            # For parquet, use already-loaded df (it's small enough)
            dist = df[target_col].value_counts()
        else:
            dist = _full_class_dist(paths, target_col, cfg["chunk_size"])
        total_samples = dist.sum()
        dist_df = pd.DataFrame({
            "Class": dist.index,
            "Count": dist.values,
            "% of total": (dist.values / total_samples * 100).round(2),
        })
        lines.append(f"**Class distribution** (full dataset, N={total_samples:,}):")
        lines.append(tabulate(dist_df, headers="keys", tablefmt="pipe", showindex=False))
        lines.append("")

        # Imbalance flag
        max_ratio = dist.max() / max(dist.min(), 1)
        if max_ratio > 10:
            lines.append(
                f"> **[IMBALANCE]** Max/min class ratio = {max_ratio:.0f}×. "
                f"SMOTE required on training split.\n"
            )

    # ── Numeric summary ──────────────────────────────────────────────────────
    num_df = df.select_dtypes(include="number")
    if not num_df.empty:
        desc = num_df.describe().T[["min", "max", "mean", "std"]].round(3).head(20)
        desc.index.name = "Feature"
        desc.reset_index(inplace=True)
        lines.append("**Numeric summary (first 20 columns, sample):**")
        lines.append(tabulate(desc, headers="keys", tablefmt="pipe", showindex=False))
        lines.append("")

    # ── Pearson correlation with target ──────────────────────────────────────
    if target_col:
        print(f"  Computing Pearson correlations for {cfg['name']}...")
        pearson = _pearson_with_target(df, target_col)
        if not pearson.empty:
            lines.append("**Pearson |r| with target (top 15):**")
            lines.append(tabulate(pearson.head(15), headers="keys", tablefmt="pipe", showindex=False))
            lines.append("")

            # Bottom (near-zero) features
            bottom = pearson.tail(5)
            lines.append("**Lowest correlation features (candidates for removal):**")
            lines.append(tabulate(bottom, headers="keys", tablefmt="pipe", showindex=False))
            lines.append("")

    # ── Redundant feature pairs ──────────────────────────────────────────────
    print(f"  Detecting redundant feature pairs for {cfg['name']}...")
    redundant = _redundant_pairs(df)
    if redundant:
        lines.append("**Highly correlated feature pairs (|r| ≥ 0.95) — drop one from each pair:**")
        red_df = pd.DataFrame(redundant, columns=["Feature A", "Feature B", "|r|"]).head(15)
        lines.append(tabulate(red_df, headers="keys", tablefmt="pipe", showindex=False))
        lines.append("")
    else:
        lines.append("**Highly correlated feature pairs:** None found\n")

    # ── Memory estimate for full dataset ─────────────────────────────────────
    sample_mem_mb = df.memory_usage(deep=True).sum() / 1024 / 1024
    rows_per_mb = len(df) / sample_mem_mb if sample_mem_mb > 0 else 0
    lines.append(
        f"**Memory:** {sample_mem_mb:.1f} MB for {len(df):,} rows "
        f"(sample density: {rows_per_mb:.0f} rows/MB)\n"
    )

    return "\n".join(lines)


# ── Report builder ────────────────────────────────────────────────────────────

def build_report(keys: list[str] | None = None) -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    keys = keys or list(DATASETS.keys())

    sections = [
        "# EDA Report — Multi-Layer IDS Datasets\n",
        "_Auto-generated by `src/pipeline/profile.py`_\n",
        "---\n",
    ]

    for key in keys:
        if key not in DATASETS:
            print(f"[!] Unknown dataset key: {key}")
            continue
        cfg = DATASETS[key]
        print(f"\n[*] Profiling {cfg['name']}...")
        section = profile_dataset(key, cfg)
        sections.append(section)
        sections.append("\n---\n")

    report = "\n".join(sections)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\n[✓] Report written → {REPORT_PATH}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Profile IDS datasets")
    parser.add_argument(
        "--ds",
        nargs="+",
        choices=list(DATASETS.keys()),
        default=None,
        help="Which dataset(s) to profile (default: all)",
    )
    args = parser.parse_args()
    build_report(keys=args.ds)
