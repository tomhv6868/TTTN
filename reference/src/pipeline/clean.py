"""
clean.py — Dataset-specific cleaners for the Multi-Layer IDS project.

Each cleaner loads raw data, standardises column names, drops redundant/
useless columns identified during EDA, and returns a tidy DataFrame with
a unified binary label column `y` (0=benign, 1=attack).

Nothing is renamed to the shared layer schema here — that happens in
features.py. Cleaners only fix the raw format of each dataset.
"""

import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parents[2]
RAW  = ROOT / "data" / "raw"


# ── Firewall Logs ─────────────────────────────────────────────────────────────

def clean_firewall(path: Path | None = None) -> pd.DataFrame:
    """
    Load and clean the Firewall Logs dataset.

    Raw columns (12): Source Port, Destination Port, NAT Source Port,
    NAT Destination Port, Action, Bytes, Bytes Sent, Bytes Received,
    Packets, Elapsed Time (sec), pkts_sent, pkts_received

    EDA-informed drops:
      - Source Port          (|r|=0.28 vs Action — much lower than NAT Src Port)
      - NAT Destination Port (|r|=0.22 — low)
      - Bytes Sent           (|r|=0.96 with pkts_sent — redundant)
      - Bytes Received       (|r|=0.97 with Bytes — redundant)
      - pkts_received        (|r|=0.97 with Packets — redundant)
      - Elapsed Time (sec)   (|r|=0.17 — weakest remaining predictor)

    Kept (5 features + label):
      Destination Port, NAT Source Port, Bytes, Packets, pkts_sent
    """
    if path is None:
        path = RAW / "firewall_logs" / "firewall_logs.csv"

    df = pd.read_csv(path, low_memory=False)

    # Normalise column names (strip whitespace)
    df.columns = df.columns.str.strip()

    # Binary label: allow=0, everything else (deny/drop/reset-both)=1
    df["y"] = (df["Action"].str.lower().str.strip() != "allow").astype(int)

    keep = ["Destination Port", "NAT Source Port", "Bytes", "Packets",
            "pkts_sent", "y"]
    df = df[keep].copy()

    # Rename to snake_case internal names
    df.rename(columns={
        "Destination Port": "dst_port",
        "NAT Source Port":  "nat_src_port",
        "Bytes":            "total_bytes",
        "Packets":          "pkt_count",
        "pkts_sent":        "pkts_sent",
    }, inplace=True)

    return df.reset_index(drop=True)


# ── CICIDS2017 ────────────────────────────────────────────────────────────────

# EDA-confirmed redundant columns to drop before feature mapping
_CICIDS_DROP = [
    "Subflow Fwd Bytes",      # |r|=1.0 with Total Length of Fwd Packets
    "Fwd IAT Total",          # |r|=0.999 with Flow Duration
    "Packet Length Mean",     # |r|=0.995 with Average Packet Size
    "Idle Max",               # |r|=0.994 with Idle Mean
    "Idle Min",               # |r|=0.993 with Idle Mean
    "Flow IAT Max",           # |r|=0.996 with Fwd IAT Max
    "Bwd IAT Total",          # |r|=0.983 with Flow Duration
    "Fwd Packets/s",          # |r|=0.974 with Flow Packets/s
    "Bwd IAT Max",            # |r|=0.972 with Idle Max chain
    "Bwd IAT Mean",           # |r|=0.972 with Bwd IAT Min
    "Fwd IAT Mean",           # |r|=0.971 with Fwd IAT Min
    "Max Packet Length",      # |r|=0.965 with Packet Length Std
    "Packet Length Variance",  # derivative of Packet Length Std
    # Near-zero correlation with target
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Fwd Header Length",
    "Bwd Header Length",
    "Flow Packets/s",         # |r|<0.001
]

def clean_cicids(path: Path | None = None,
                 chunk_size: int = 250_000) -> pd.DataFrame:
    """
    Load and clean the CICIDS2017 cleaned CSV (2.52M rows, 53 cols).

    Reads in chunks to stay within RAM budget.
    Binary label: Normal Traffic=0, any attack=1.
    """
    if path is None:
        csvs = list((RAW / "cicids2017").glob("*.csv"))
        if not csvs:
            raise FileNotFoundError("No CICIDS2017 CSV found in data/raw/cicids2017/")
        path = csvs[0]

    print(f"  Reading {path.name} in chunks of {chunk_size:,}...")
    frames = []
    for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        # Binary label
        chunk["y"] = (chunk["Attack Type"].str.strip() != "Normal Traffic").astype(int)
        # Drop redundant columns (ignore missing ones gracefully)
        drop_cols = [c for c in _CICIDS_DROP if c in chunk.columns]
        chunk.drop(columns=drop_cols + ["Attack Type"], inplace=True)
        # Replace any residual inf/-inf with NaN then 0
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.fillna(0, inplace=True)
        frames.append(chunk)

    df = pd.concat(frames, ignore_index=True)
    print(f"  CICIDS2017 loaded: {len(df):,} rows, {df.shape[1]} cols")
    return df


# ── UNSW-NB15 ─────────────────────────────────────────────────────────────────

# EDA-confirmed redundant pairs — drop one from each
_UNSW_DROP = [
    "ct_ftp_cmd",     # |r|=0.999 with is_ftp_login
    "dloss",          # |r|=0.997 with dbytes
    "sloss",          # |r|=0.996 with sbytes
    "dwin",           # |r|=0.981 with swin
    "dpkts",          # keep, actually useful — do NOT drop
    # Near-zero correlation with target
    "trans_depth",
    "ackdat",
    # Identifiers / timestamps — not predictive at inference time
    "id",
    "stcpb",
    "dtcpb",
]

# Columns we don't want but might exist
_UNSW_DROP_ALSO = ["Stime", "Ltime", "srcip", "dstip", "sport", "dsport",
                   "attack_cat"]

def clean_unsw(paths: list[Path] | None = None) -> pd.DataFrame:
    """
    Load and clean UNSW-NB15 pre-split CSVs (training + testing sets).

    These files have proper headers. Full raw files (UNSW-NB15_1..4.csv)
    have no header and a different column layout — not used here.

    Binary label: label column (1=attack, 0=normal). Keep as-is.
    """
    if paths is None:
        paths = sorted((RAW / "unsw_nb15").glob("UNSW_NB15_*.csv"))
        paths = [p for p in paths if p.stat().st_size > 5_000]

    if not paths:
        raise FileNotFoundError("No UNSW-NB15 pre-split CSVs found.")

    frames = []
    for p in paths:
        print(f"  Reading {p.name}...")
        df = pd.read_csv(p, low_memory=False)
        df.columns = df.columns.str.strip()

        # Unify label column name
        if "label" in df.columns:
            df.rename(columns={"label": "y"}, inplace=True)
        elif "Label" in df.columns:
            df.rename(columns={"Label": "y"}, inplace=True)

        # Encode categorical columns
        for col in ["proto", "service", "state"]:
            if col in df.columns:
                df[col] = pd.factorize(df[col].astype(str).str.strip())[0]

        drop_cols = [c for c in _UNSW_DROP + _UNSW_DROP_ALSO if c in df.columns]
        df.drop(columns=drop_cols, inplace=True)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        frames.append(df)

    df = pd.concat(frames, ignore_index=True)
    df["y"] = df["y"].astype(int)
    print(f"  UNSW-NB15 loaded: {len(df):,} rows, {df.shape[1]} cols")
    return df


# ── Bot-IoT NF ────────────────────────────────────────────────────────────────

def clean_botiot(path: Path | None = None) -> pd.DataFrame:
    """
    Load and clean the NF-BoT-IoT parquet dataset (595k rows, 12 cols).

    Columns: L4_SRC_PORT, L4_DST_PORT, PROTOCOL, L7_PROTO, IN_BYTES,
             OUT_BYTES, IN_PKTS, OUT_PKTS, TCP_FLAGS,
             FLOW_DURATION_MILLISECONDS, Label, Attack

    EDA: L4_DST_PORT has |r|=0.006 with Label — borderline; keep for
    port-based attack detection (DDoS targets specific ports).
    Drop: Attack (string version of Label — redundant), L7_PROTO (|r|=0.04).
    """
    if path is None:
        parquets = list((RAW / "botiot").glob("*.parquet"))
        if not parquets:
            raise FileNotFoundError("No parquet found in data/raw/botiot/")
        path = parquets[0]

    df = pd.read_parquet(path)

    # Rename label
    df.rename(columns={"Label": "y"}, inplace=True)

    # Drop redundant/low-value columns
    drop_cols = [c for c in ["Attack", "L7_PROTO"] if c in df.columns]
    df.drop(columns=drop_cols, inplace=True)

    # Extract individual TCP flags from the combined TCP_FLAGS integer
    # Bit positions: FIN=0, SYN=1, RST=2, PSH=3, ACK=4, URG=5
    if "TCP_FLAGS" in df.columns:
        flags = df["TCP_FLAGS"].to_numpy(dtype=np.int32)
        df["fin_flag"] = (flags & 1).astype(np.int8)
        df["syn_flag"] = (np.right_shift(flags, 1) & 1).astype(np.int8)
        df["psh_flag"] = (np.right_shift(flags, 3) & 1).astype(np.int8)
        df["ack_flag"] = (np.right_shift(flags, 4) & 1).astype(np.int8)
        df.drop(columns=["TCP_FLAGS"], inplace=True)

    # Convert duration to microseconds (consistent with CICIDS2017)
    if "FLOW_DURATION_MILLISECONDS" in df.columns:
        df["FLOW_DURATION_MILLISECONDS"] = (
            df["FLOW_DURATION_MILLISECONDS"].astype(float) * 1000.0
        )
        df.rename(columns={"FLOW_DURATION_MILLISECONDS": "flow_dur_us"}, inplace=True)

    df["y"] = df["y"].astype(int)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    print(f"  Bot-IoT NF loaded: {len(df):,} rows, {df.shape[1]} cols")
    return df.reset_index(drop=True)
