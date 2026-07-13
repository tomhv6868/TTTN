"""
features.py — Feature engineering per layer for the Multi-Layer IDS.

Produces three processed parquet files in data/processed/:
  layer1.parquet   — 5 features for the Decision Tree packet classifier
  layer2.parquet   — 15 features for the LightGBM flow classifier
  layer3.parquet   — 12 features for the LightGBM session classifier

Each file includes a binary label column `y` (0=benign, 1=attack) and a
`src` column (dataset origin) so the model can calibrate per-dataset.

Common schemas are defined as module-level constants so training scripts
import them directly — single source of truth.
"""

import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore

warnings.filterwarnings("ignore")

ROOT      = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed"

# ── Canonical feature lists (imported by training scripts) ─────────────────────

LAYER1_FEATURES = [
    "dst_port",       # Destination port — strong discriminator (|r|=0.57)
    "nat_src_port",   # NAT source port — strongest predictor (|r|=0.69)
    "total_bytes",    # Total bytes transferred
    "pkt_count",      # Total packet count
    "pkts_sent",      # SYN-proxy for packet direction asymmetry
]

LAYER2_FEATURES = [
    "dst_port",        # Destination port
    "flow_dur_us",     # Flow duration in microseconds
    "fwd_pkts",        # Forward packet count
    "fwd_bytes",       # Forward bytes
    "bwd_pkts",        # Backward packet count
    "bwd_bytes",       # Backward bytes
    "pkt_len_min",     # Minimum packet length
    "pkt_len_avg",     # Average packet size
    "flow_bytes_s",    # Flow bytes per second
    "psh_flag",        # PSH flag count / indicator
    "ack_flag",        # ACK flag count / indicator
    "fin_flag",        # FIN flag count / indicator
    "init_win_fwd",    # Initial forward TCP window size
    "active_mean",     # Mean active time (connection bursts)
    "protocol_enc",    # Protocol (encoded integer)
]

LAYER3_FEATURES = [
    "flow_dur_us",        # Flow duration in microseconds
    "fwd_bytes",          # Forward bytes (sbytes)
    "bwd_bytes",          # Backward bytes (dbytes)
    "fwd_pkts",           # Forward packets (spkts)
    "bwd_pkts",           # Backward packets (dpkts)
    "src_ttl",            # Source TTL
    "dst_ttl",            # Destination TTL
    "sload",              # Source load (bits/sec)
    "dload",              # Destination load (bits/sec)
    "state_enc",          # TCP/UDP state (encoded)
    "ct_dst_sport_ltm",   # Connection count to same dst port (session stat)
    "ct_srv_dst",         # Connection count to same service/dst (session stat)
]


# ── Layer 1: Firewall Logs → already clean from clean.py ─────────────────────

def build_layer1(df_fw: pd.DataFrame) -> pd.DataFrame:
    """
    df_fw is already the output of clean_firewall() — columns are:
    dst_port, nat_src_port, total_bytes, pkt_count, pkts_sent, y
    Just add src tag and return.
    """
    df = df_fw[LAYER1_FEATURES + ["y"]].copy()
    df["src"] = 0  # dataset origin: 0=firewall_logs
    return df


# ── Layer 2: CICIDS2017 + UNSW-NB15 + Bot-IoT NF ─────────────────────────────

def _cicids_to_layer2(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS2017 cleaned columns to Layer 2 schema."""
    out = pd.DataFrame(index=df.index)

    out["dst_port"]     = df.get("Destination Port",               0)
    out["flow_dur_us"]  = df.get("Flow Duration",                  0)   # already µs
    out["fwd_pkts"]     = df.get("Total Fwd Packets",              0)
    out["fwd_bytes"]    = df.get("Total Length of Fwd Packets",    0)
    # bwd_pkts / bwd_bytes not directly available in cleaned version — fill 0
    # LightGBM will learn from the features that ARE available.
    out["bwd_pkts"]     = 0
    out["bwd_bytes"]    = 0
    out["pkt_len_min"]  = df.get("Min Packet Length",              0)
    out["pkt_len_avg"]  = df.get("Average Packet Size",            0)
    out["flow_bytes_s"] = df.get("Flow Bytes/s",                   0)
    out["psh_flag"]     = df.get("PSH Flag Count",                 0)
    out["ack_flag"]     = df.get("ACK Flag Count",                 0)
    out["fin_flag"]     = df.get("FIN Flag Count",                 0)
    out["init_win_fwd"] = df.get("Init_Win_bytes_forward",         0)
    out["active_mean"]  = df.get("Active Mean",                    0)
    out["protocol_enc"] = 0   # Protocol column absent in cleaned version
    out["y"]            = df["y"]
    out["src"]          = 0   # 0 = CICIDS2017
    return out


def _unsw_to_layer2(df: pd.DataFrame) -> pd.DataFrame:
    """Map UNSW-NB15 columns to Layer 2 schema."""
    out = pd.DataFrame(index=df.index)

    out["dst_port"]     = 0   # dsport not in pre-split training set
    # dur is in seconds in UNSW — convert to µs
    dur_us              = df.get("dur", pd.Series(0, index=df.index)).astype(float) * 1e6
    out["flow_dur_us"]  = dur_us
    out["fwd_pkts"]     = df.get("spkts",  0)
    out["fwd_bytes"]    = df.get("sbytes", 0)
    out["bwd_pkts"]     = df.get("dpkts",  0)
    out["bwd_bytes"]    = df.get("dbytes", 0)
    out["pkt_len_min"]  = df.get("smean",  0)   # closest available
    out["pkt_len_avg"]  = df.get("smean",  0)
    out["flow_bytes_s"] = df.get("sload",  0)
    out["psh_flag"]     = 0   # flag breakdown not in UNSW
    out["ack_flag"]     = 0
    out["fin_flag"]     = 0
    out["init_win_fwd"] = df.get("swin",   0)
    out["active_mean"]  = 0
    out["protocol_enc"] = df.get("proto",  0)   # already label-encoded by clean_unsw
    out["y"]            = df["y"]
    out["src"]          = 1   # 1 = UNSW-NB15
    return out


def _botiot_to_layer2(df: pd.DataFrame) -> pd.DataFrame:
    """Map Bot-IoT NF columns (already cleaned) to Layer 2 schema."""
    out = pd.DataFrame(index=df.index)

    out["dst_port"]     = df.get("L4_DST_PORT",  0)
    out["flow_dur_us"]  = df.get("flow_dur_us",  0)   # already µs from clean_botiot
    out["fwd_pkts"]     = df.get("IN_PKTS",      0)
    out["fwd_bytes"]    = df.get("IN_BYTES",      0)
    out["bwd_pkts"]     = df.get("OUT_PKTS",      0)
    out["bwd_bytes"]    = df.get("OUT_BYTES",     0)

    # Approximate min/avg packet length from byte/packet counts
    total_pkts = (df.get("IN_PKTS", 0) + df.get("OUT_PKTS", 0)).replace(0, 1)
    total_bytes = df.get("IN_BYTES", 0) + df.get("OUT_BYTES", 0)
    out["pkt_len_min"]  = (df.get("IN_BYTES", 0) / df.get("IN_PKTS", 1).replace(0, 1))
    out["pkt_len_avg"]  = total_bytes / total_pkts

    # Flow bytes per second (duration already in µs)
    dur_s = (df.get("flow_dur_us", 0) / 1e6).replace(0, np.nan)
    out["flow_bytes_s"] = (total_bytes / dur_s).fillna(0)

    out["psh_flag"]     = df.get("psh_flag", 0)
    out["ack_flag"]     = df.get("ack_flag", 0)
    out["fin_flag"]     = df.get("fin_flag", 0)
    out["init_win_fwd"] = 0   # not available in NF features
    out["active_mean"]  = 0
    out["protocol_enc"] = df.get("PROTOCOL", 0)
    out["y"]            = df["y"]
    out["src"]          = 2   # 2 = Bot-IoT NF
    return out


def build_layer2(df_cic: pd.DataFrame,
                 df_unsw: pd.DataFrame,
                 df_botiot: pd.DataFrame,
                 cic_sample_frac: float = 0.20) -> pd.DataFrame:
    """
    Combine CICIDS2017, UNSW-NB15, and Bot-IoT NF into Layer 2 training data.

    CICIDS2017 is downsampled (cic_sample_frac) to balance dataset sizes:
      CICIDS2017 full: 2.52M rows → ~504k at 20%
      UNSW-NB15:       257k rows
      Bot-IoT NF:      595k rows
      Total:           ~1.36M rows
    """
    print(f"  Mapping CICIDS2017 ({len(df_cic):,} rows) to Layer 2 schema...")
    # Stratified sample to avoid CICIDS2017 dominating
    cic_sample = df_cic.groupby("y", group_keys=False).apply(
        lambda g: g.sample(frac=cic_sample_frac, random_state=42)
    )
    part_cic   = _cicids_to_layer2(cic_sample)

    print(f"  Mapping UNSW-NB15 ({len(df_unsw):,} rows) to Layer 2 schema...")
    part_unsw  = _unsw_to_layer2(df_unsw)

    print(f"  Mapping Bot-IoT NF ({len(df_botiot):,} rows) to Layer 2 schema...")
    part_bot   = _botiot_to_layer2(df_botiot)

    df = pd.concat([part_cic, part_unsw, part_bot], ignore_index=True)

    # Final safety: replace any inf/nan introduced during mapping
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Clip extreme outliers at 99.9th percentile per numeric feature
    for col in LAYER2_FEATURES:
        if col in df.columns and df[col].dtype != object:
            cap = df[col].quantile(0.999)
            df[col] = df[col].clip(upper=cap)

    print(f"  Layer 2 combined: {len(df):,} rows | "
          f"benign={int((df['y']==0).sum()):,} attack={int((df['y']==1).sum()):,}")
    return df


# ── Layer 3: UNSW-NB15 + Bot-IoT NF (session-level features) ─────────────────

def _unsw_to_layer3(df: pd.DataFrame) -> pd.DataFrame:
    """Map UNSW-NB15 columns to Layer 3 session schema."""
    out = pd.DataFrame(index=df.index)

    dur_us              = df.get("dur", pd.Series(0, index=df.index)).astype(float) * 1e6
    out["flow_dur_us"]  = dur_us
    out["fwd_bytes"]    = df.get("sbytes", 0)
    out["bwd_bytes"]    = df.get("dbytes", 0)
    out["fwd_pkts"]     = df.get("spkts",  0)
    out["bwd_pkts"]     = df.get("dpkts",  0)
    out["src_ttl"]      = df.get("sttl",   0)
    out["dst_ttl"]      = df.get("dttl",   0)
    out["sload"]        = df.get("sload",  0)
    out["dload"]        = df.get("dload",  0)
    out["state_enc"]    = df.get("state",  0)   # already encoded by clean_unsw
    out["ct_dst_sport_ltm"] = df.get("ct_dst_sport_ltm", 0)
    out["ct_srv_dst"]   = df.get("ct_srv_dst", 0)
    out["y"]            = df["y"]
    out["src"]          = 1
    return out


def _botiot_to_layer3(df: pd.DataFrame) -> pd.DataFrame:
    """Map Bot-IoT NF columns to Layer 3 session schema."""
    out = pd.DataFrame(index=df.index)

    out["flow_dur_us"]  = df.get("flow_dur_us", 0)
    out["fwd_bytes"]    = df.get("IN_BYTES",   0)
    out["bwd_bytes"]    = df.get("OUT_BYTES",  0)
    out["fwd_pkts"]     = df.get("IN_PKTS",    0)
    out["bwd_pkts"]     = df.get("OUT_PKTS",   0)
    # TTL not available in NF subset — fill 0; model learns from other features
    out["src_ttl"]      = 0
    out["dst_ttl"]      = 0

    dur_s = (df.get("flow_dur_us", pd.Series(0, index=df.index)) / 1e6).replace(0, np.nan)
    out["sload"]        = (df.get("IN_BYTES",  0) * 8 / dur_s).fillna(0)
    out["dload"]        = (df.get("OUT_BYTES", 0) * 8 / dur_s).fillna(0)
    out["state_enc"]    = 0   # not in NF subset
    out["ct_dst_sport_ltm"] = 0
    out["ct_srv_dst"]   = 0
    out["y"]            = df["y"]
    out["src"]          = 2
    return out


def build_layer3(df_unsw: pd.DataFrame,
                 df_botiot: pd.DataFrame) -> pd.DataFrame:
    """Combine UNSW-NB15 and Bot-IoT NF into Layer 3 session training data."""
    print(f"  Mapping UNSW-NB15 ({len(df_unsw):,} rows) to Layer 3 schema...")
    part_unsw = _unsw_to_layer3(df_unsw)

    print(f"  Mapping Bot-IoT NF ({len(df_botiot):,} rows) to Layer 3 schema...")
    part_bot  = _botiot_to_layer3(df_botiot)

    df = pd.concat([part_unsw, part_bot], ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    for col in LAYER3_FEATURES:
        if col in df.columns and df[col].dtype != object:
            cap = df[col].quantile(0.999)
            df[col] = df[col].clip(upper=cap)

    print(f"  Layer 3 combined: {len(df):,} rows | "
          f"benign={int((df['y']==0).sum()):,} attack={int((df['y']==1).sum()):,}")
    return df


# ── Save processed parquet files ──────────────────────────────────────────────

def save_layer(df: pd.DataFrame, name: str) -> Path:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    path = PROCESSED / f"{name}.parquet"
    df.to_parquet(path, index=False, compression="snappy")
    mb = path.stat().st_size / 1024 / 1024
    print(f"  Saved {path.name} ({mb:.1f} MB, {len(df):,} rows)")
    return path


# ── Orchestrator ──────────────────────────────────────────────────────────────

def build_all(df_fw, df_cic, df_unsw, df_botiot) -> None:
    print("\n[*] Building Layer 1 features (Firewall Logs)...")
    l1 = build_layer1(df_fw)
    save_layer(l1, "layer1")

    print("\n[*] Building Layer 2 features (CICIDS2017 + UNSW-NB15 + Bot-IoT)...")
    l2 = build_layer2(df_cic, df_unsw, df_botiot)
    save_layer(l2, "layer2")

    print("\n[*] Building Layer 3 features (UNSW-NB15 + Bot-IoT)...")
    l3 = build_layer3(df_unsw, df_botiot)
    save_layer(l3, "layer3")
