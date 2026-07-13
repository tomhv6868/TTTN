"""
download.py — Dataset acquisition for the Multi-Layer IDS project.

Downloads all 4 datasets:
  1. Firewall Logs    — GitHub raw URL (direct HTTP)
  2. CICIDS2017       — Kaggle
  3. UNSW-NB15        — Kaggle
  4. Bot-IoT (10-feat subset) — Kaggle

Usage:
    python -m src.pipeline.download          # download all
    python -m src.pipeline.download --ds fw  # single dataset
"""

import argparse
import shutil
import sys
import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

# Force UTF-8 output on Windows so Unicode symbols don't crash
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

# ── Project root (two levels up from this file) ───────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"

# ── Dataset registry ──────────────────────────────────────────────────────────
# Each entry defines one or more Kaggle slugs to try in order (first success wins).
# 'http_url' is used instead of Kaggle for direct HTTP downloads.
REGISTRY = {
    "fw": {
        "name": "Firewall Logs",
        "target_dir": RAW / "firewall_logs",
        "http_url": (
            "https://raw.githubusercontent.com/MinhLinhEdu/"
            "Firewall-logs-dataset/refs/heads/main/"
            "Firewall%20logs%20dataset.csv"
        ),
        "output_filename": "firewall_logs.csv",
    },
    "cicids": {
        "name": "CICIDS2017",
        "target_dir": RAW / "cicids2017",
        # Verified via Kaggle API search — ~210 MB cleaned version preferred
        "kaggle_slugs": [
            "ericanacletoribeiro/cicids2017-cleaned-and-preprocessed",  # 210 MB
            "mdalamintalukder/cicids2017",                               # 240 MB
            "kk0105/cicids2017",                                         # 296 MB
        ],
    },
    "unsw": {
        "name": "UNSW-NB15",
        "target_dir": RAW / "unsw_nb15",
        # Verified via Kaggle API search — ~156 MB
        "kaggle_slugs": [
            "mrwellsdavid/unsw-nb15",    # 156 MB, standard upload
            "alextamboli/unsw-nb15",     # 164 MB fallback
        ],
    },
    "botiot": {
        "name": "Bot-IoT (10-feature subset)",
        "target_dir": RAW / "botiot",
        # Verified via Kaggle API search — using NF-BoT-IoT compact version
        "kaggle_slugs": [
            "dhoogla/nfbotiot",     # 1.8 MB — compact NF feature subset
            "dhoogla/nfbotiotv2",   # 441 MB — fallback
        ],
    },
}


# ── Kaggle auth ───────────────────────────────────────────────────────────────

def _setup_kaggle_credentials() -> bool:
    """Copy project kaggle.json → ~/.kaggle/kaggle.json if not already there."""
    kaggle_home = Path.home() / ".kaggle"
    dest = kaggle_home / "kaggle.json"

    if dest.exists():
        return True

    project_creds = ROOT / "kaggle.json"
    if not project_creds.exists():
        print("[!] kaggle.json not found in project root or ~/.kaggle/")
        return False

    kaggle_home.mkdir(exist_ok=True)
    shutil.copy(project_creds, dest)
    dest.chmod(0o600)
    print(f"[✓] Kaggle credentials installed → {dest}")
    return True


def _get_kaggle_api():
    """Return an authenticated Kaggle API instance (compatible with kaggle v1 and v2)."""
    if not _setup_kaggle_credentials():
        raise RuntimeError("Kaggle credentials unavailable.")

    try:
        # kaggle >= 2.0.0
        from kaggle import api  # type: ignore
        api.authenticate()
        return api
    except (ImportError, AttributeError):
        # kaggle < 2.0.0
        from kaggle.api.kaggle_api_extended import KaggleApiExtended  # type: ignore
        api = KaggleApiExtended()
        api.authenticate()
        return api


# ── Helpers ───────────────────────────────────────────────────────────────────

def _download_http(url: str, dest: Path) -> None:
    """Stream-download a file with a progress bar."""
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f, tqdm(
        desc=dest.name, total=total, unit="B", unit_scale=True, unit_divisor=1024
    ) as bar:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
            bar.update(len(chunk))


def _extract_zip(zip_path: Path, target_dir: Path) -> None:
    """Extract a zip archive, skipping already-extracted files."""
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        for member in tqdm(members, desc=f"Extracting {zip_path.name}"):
            out = target_dir / member.filename
            if not out.exists():
                zf.extract(member, target_dir)
    zip_path.unlink()  # remove zip after extraction


def _try_kaggle_slugs(api, slugs: list[str], target_dir: Path) -> bool:
    """Try each slug in order; return True on first successful download."""
    target_dir.mkdir(parents=True, exist_ok=True)
    for slug in slugs:
        _, dataset_name = slug.split("/", 1)
        print(f"  Trying {slug} ...")
        try:
            api.dataset_download_files(
                slug,
                path=str(target_dir),
                unzip=False,
                quiet=False,
            )
            # Kaggle saves as <dataset_name>.zip
            downloaded = list(target_dir.glob("*.zip"))
            if downloaded:
                _extract_zip(downloaded[0], target_dir)
            print(f"  [OK] Downloaded {slug}")
            return True
        except Exception as exc:
            err = str(exc)
            if "404" in err or "403" in err or "not found" in err.lower():
                print(f"    [skip] {slug} — not found or access denied")
            else:
                print(f"    [fail] {exc}")
            # Clean up any partial download
            for f in target_dir.glob("*.zip"):
                f.unlink(missing_ok=True)

    return False


def _already_downloaded(entry: dict) -> bool:
    """Return True if the target directory already has CSV/data files."""
    target_dir: Path = entry["target_dir"]
    if not target_dir.exists():
        return False
    csv_files = list(target_dir.rglob("*.csv")) + list(target_dir.rglob("*.parquet"))
    return len(csv_files) > 0


# ── Per-dataset downloaders ───────────────────────────────────────────────────

def download_fw(force: bool = False) -> None:
    entry = REGISTRY["fw"]
    dest = entry["target_dir"] / entry["output_filename"]

    if not force and dest.exists():
        print(f"[✓] {entry['name']}: already downloaded ({dest})")
        return

    print(f"[*] Downloading {entry['name']}...")
    entry["target_dir"].mkdir(parents=True, exist_ok=True)
    _download_http(entry["http_url"], dest)
    print(f"[✓] Saved → {dest}  ({dest.stat().st_size / 1024:.1f} KB)")


def download_kaggle_dataset(key: str, force: bool = False) -> None:
    entry = REGISTRY[key]

    if not force and _already_downloaded(entry):
        csv_count = len(list(entry["target_dir"].rglob("*.csv")))
        print(f"[✓] {entry['name']}: already downloaded ({csv_count} CSV files in {entry['target_dir']})")
        return

    print(f"\n[*] Downloading {entry['name']}...")
    try:
        api = _get_kaggle_api()
    except RuntimeError as e:
        print(f"[!] {e}")
        sys.exit(1)

    success = _try_kaggle_slugs(api, entry["kaggle_slugs"], entry["target_dir"])

    if not success:
        print(
            f"\n[!] All slugs failed for {entry['name']}.\n"
            f"    Manual fallback:\n"
            f"    1. Search https://www.kaggle.com/datasets?search={key}\n"
            f"    2. Download manually and unzip into: {entry['target_dir']}\n"
        )
    else:
        csv_files = list(entry["target_dir"].rglob("*.csv"))
        total_mb = sum(f.stat().st_size for f in csv_files) / 1024 / 1024
        print(f"    {len(csv_files)} CSV files, {total_mb:.1f} MB total")


# ── Public interface ──────────────────────────────────────────────────────────

def download_all(force: bool = False) -> None:
    download_fw(force=force)
    for key in ("cicids", "unsw", "botiot"):
        download_kaggle_dataset(key, force=force)

    print("\n[✓] All downloads complete.")
    _print_summary()


def _print_summary() -> None:
    print("\n── Download Summary ──────────────────────────────────────")
    for key, entry in REGISTRY.items():
        target: Path = entry["target_dir"]
        csv_files = list(target.rglob("*.csv")) if target.exists() else []
        total_mb = sum(f.stat().st_size for f in csv_files) / 1024 / 1024 if csv_files else 0
        status = f"{len(csv_files)} CSV(s), {total_mb:.1f} MB" if csv_files else "MISSING"
        print(f"  {entry['name']:<30} {status}")
    print("──────────────────────────────────────────────────────────\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download IDS datasets")
    parser.add_argument(
        "--ds",
        choices=list(REGISTRY.keys()) + ["all"],
        default="all",
        help="Which dataset to download (default: all)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if already present",
    )
    args = parser.parse_args()

    if args.ds == "all":
        download_all(force=args.force)
    elif args.ds == "fw":
        download_fw(force=args.force)
    else:
        download_kaggle_dataset(args.ds, force=args.force)
