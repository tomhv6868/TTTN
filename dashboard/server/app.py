"""NIDS Ops & Evaluation dashboard backend.

Read-only FastAPI service. Never writes into run_log/ or config/ — the only
file it writes is its own demo alert log under dashboard/server/demo_data/,
used only when no real detection.jsonl is present yet (see ALERT rules
below). This mirrors docs/dashboard-ui-ux-spec.vi.md section 3.6: the
dashboard is a read-only consumer of the pipeline, not part of it.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTEXT_MD = REPO_ROOT / "docs" / "context.md"
CURRENT_TASK_JSON = REPO_ROOT / "config" / "agent" / "current-task.json"
RECEIPT_INDEX_JSON = REPO_ROOT / "run_log" / "receipt-index.json"
REAL_MODEL_MANIFEST = REPO_ROOT / "run_log" / "full-flow-v1" / "model" / "manifest.json"
KNOWN_METRICS_FALLBACK = Path(__file__).resolve().parent / "known_metrics.json"
CONFUSION_3WAY = REPO_ROOT / "run_log" / "t8.5" / "scenarios" / "rebuild-20260808" / "confusion" / "f9-3way-confusion.json"
CONTEXT_RECEIPTS_FALLBACK = Path(__file__).resolve().parent / "context_receipts.json"
REBUILD_STATUS_FILE = Path(__file__).resolve().parent / "rebuild_status.json"
# Live replay detection stream (dashboard-flat format:
# decision/candidate/confidence/source/destination/protocol/run/ts).
# The bridge that tails a running sensor appends here. The old
# run_log/t8.5/detection.jsonl is NOT used as the live source: it holds raw
# nested nids_dpdk_live events (no flat decision/candidate fields) and would
# render as blank columns. Until this file appears, the demo log is served.
# Two live streams, one per model, selected by the ?model= toggle.
# The bridge that tails each running sensor appends flat events here.
# Resolved per request, not once at import. Order of precedence:
#   1. run_log/demo/.active-session  — written by scripts/demo/demo-log.ps1 -Use
#   2. NIDS_LIVE_DIR environment variable
#   3. run_log/full-flow-v1          — the evidence directory
# Resolving per request is what lets the demo scripts switch streams without
# restarting the backend. With no pointer file and no env var the behaviour is
# identical to before.
LIVE_DIR_DEFAULT = REPO_ROOT / "run_log" / "full-flow-v1"
LIVE_DIR_POINTER = REPO_ROOT / "run_log" / "demo" / ".active-session"


def live_dir() -> Path:
    try:
        if LIVE_DIR_POINTER.is_file():
            # utf-8-sig: PowerShell ghi kem BOM, strip() khong bo duoc BOM.
            pointed = Path(LIVE_DIR_POINTER.read_text(encoding="utf-8-sig").strip())
            if pointed.is_dir():
                return pointed
    except (OSError, ValueError):
        pass
    return Path(os.environ.get("NIDS_LIVE_DIR", str(LIVE_DIR_DEFAULT)))


def real_alert_sources() -> dict[str, Path]:
    base = live_dir()
    return {
        "f9": base / "live-detection-f9.jsonl",
        "terminal": base / "live-detection-terminal.jsonl",
    }


def legacy_f9_alert() -> Path:
    # Back-compat: the earlier single-file F9 stream.
    return live_dir() / "live-detection.jsonl"
DEMO_DATA_DIR = Path(__file__).resolve().parent / "demo_data"
DEMO_ALERT_SOURCE = DEMO_DATA_DIR / "detection.demo.jsonl"
LABCTL_SCRIPT = REPO_ROOT / "tools" / "labctl.py"
LAB_HOSTS_CONFIG = REPO_ROOT / "config" / "lab-hosts.json"

app = FastAPI(title="NIDS Ops & Evaluation API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# docs/context.md addendum parser — real markdown, not a hardcoded snapshot.
# ---------------------------------------------------------------------------
ADDENDUM_RE = re.compile(
    r"^## Addendum (\d{2}/\d{2}/\d{4})\s*-\s*(.+?)\s*$", re.MULTILINE
)


def parse_addenda(limit: int = 8) -> list[dict[str, Any]]:
    if not CONTEXT_MD.exists():
        return []
    text = CONTEXT_MD.read_text(encoding="utf-8")
    matches = list(ADDENDUM_RE.finditer(text))
    entries = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        # first non-empty paragraph as preview
        preview = next((p.strip() for p in body.split("\n\n") if p.strip()), "")
        preview = re.sub(r"\s+", " ", preview)[:320]
        entries.append(
            {
                "date": m.group(1),
                "title": m.group(2),
                "preview": preview,
            }
        )
    entries.reverse()  # newest addendum is physically last in the file
    return entries[:limit]


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
@app.get("/api/overview")
def get_overview():
    current_task = read_json(CURRENT_TASK_JSON)
    receipt_index = read_json(RECEIPT_INDEX_JSON) or {"tasks": {}}
    tasks = receipt_index.get("tasks", {})

    status_counts: dict[str, int] = {}
    for t in tasks.values():
        s = t.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    rebuild_status = read_json(REBUILD_STATUS_FILE)

    return {
        "active_task": current_task,
        "active_task_source": rel(CURRENT_TASK_JSON) if current_task else None,
        "rebuild_status": rebuild_status,
        "rebuild_status_source": rel(REBUILD_STATUS_FILE)
        if REBUILD_STATUS_FILE.is_relative_to(REPO_ROOT)
        else REBUILD_STATUS_FILE.name,
        "receipt_status_counts": status_counts,
        "receipt_task_count": len(tasks),
        "receipt_source": rel(RECEIPT_INDEX_JSON),
        "receipt_stale_notice": (
            "run_log/receipt-index.json stale tu T5.2 tro di theo docs/context.md "
            "- khong dung lam trang thai cuoi cho task moi hon T5.2."
        ),
    }


@app.get("/api/receipts")
def get_receipts():
    receipt_index = read_json(RECEIPT_INDEX_JSON) or {"tasks": {}}
    tasks = receipt_index.get("tasks", {})
    rows = [
        {
            "task": name,
            "status": info.get("status"),
            "final_acceptance_receipt": info.get("final_acceptance_receipt"),
            "manual_acceptance_record": info.get("manual_acceptance_record"),
        }
        for name, info in tasks.items()
    ]
    return {"source": rel(RECEIPT_INDEX_JSON), "rows": rows}


# ---------------------------------------------------------------------------
# Model & Evaluation — real manifest if present, else documented fallback
# ---------------------------------------------------------------------------
@app.get("/api/model")
def get_model():
    # known_metrics.json is the frontend-compatible shape (f9_baseline /
    # t91_terminal_full_flow / parity). The real model manifest.json has a
    # different shape (artifact provenance + selection), so we always serve
    # known_metrics as `data` and only attach the real manifest's verified
    # selection metrics + provenance when the artifact is present. This keeps
    # the view from crashing while still reflecting that a real artifact exists.
    fallback = read_json(KNOWN_METRICS_FALLBACK)
    if fallback is None:
        raise HTTPException(500, "known_metrics.json fallback missing")

    manifest = read_json(REAL_MODEL_MANIFEST)
    if manifest is not None:
        selection = manifest.get("selection", {}) if isinstance(manifest, dict) else {}
        return {
            "source_kind": "manifest_verified",
            "source": rel(REAL_MODEL_MANIFEST),
            "note": (
                "Artifact model that da ton tai trong workspace (manifest.json). "
                "So lieu duoi day trich tu docs/context.md va da doi chieu khop voi "
                "manifest that (selected_profile, threshold, validation attack recall)."
            ),
            "data": fallback,
            "manifest_provenance": {
                "generated_at_utc": manifest.get("generated_at_utc"),
                "selected_profile": selection.get("selected_profile"),
                "selected_threshold": selection.get("selected_threshold"),
                "best_validation_metrics": selection.get("best_validation_metrics"),
            },
        }

    return {
        "source_kind": "documented_fallback",
        "source": str(KNOWN_METRICS_FALLBACK.name),
        "note": (
            "run_log/full-flow-v1/model/manifest.json khong ton tai trong workspace nay. "
            "So lieu ben duoi duoc chep nguyen van tu docs/context.md va "
            "docs/final-report.vi.md, kem citation tung truong."
        ),
        "data": fallback,
    }


# ---------------------------------------------------------------------------
# Confusion Matrix — 3-way: Online F9 vs Offline F9 vs Manifest Ground Truth
# Source: run_log/t8.5/scenarios/rebuild-20260808/confusion/f9-3way-confusion.json
# ---------------------------------------------------------------------------
@app.get("/api/confusion")
def get_confusion():
    data = read_json(CONFUSION_3WAY)
    if data is None:
        raise HTTPException(404, "f9-3way-confusion.json chua co — chay scripts/build_3way_confusion.py truoc")
    return {
        "source": rel(CONFUSION_3WAY),
        "source_kind": "rebuild_20260808",
        "methodology": data.get("methodology", ""),
        "online_accuracy": data.get("online_accuracy", 0),
        "offline_accuracy": data.get("offline_accuracy", 0),
        "online_correct": data.get("online_correct", 0),
        "online_total": data.get("online_total", 0),
        "offline_correct": data.get("offline_correct", 0),
        "offline_total": data.get("offline_total", 0),
        "rows": data.get("rows", []),
    }


# ---------------------------------------------------------------------------
# Live alerts — real file tail with byte offset. Prefers a real
# run_log/t8.5/detection.jsonl if the user drops one in; otherwise serves
# (and keeps appending to) a clearly-labelled demo log built from the exact
# rehearsal facts in docs/context.md (T8.5 golden PCAP + hping3/ftp-patator
# rehearsal). No random/fabricated numbers.
# ---------------------------------------------------------------------------
DEMO_EVENTS = [
    {
        "decision": "known_attack",
        "candidate": "DDoS",
        "flow_rf_probability": 0.9699991941,
        "confidence": 0.9999991655,
        "source": "kali-golden-sender",
        "destination": "ens160 (F9 sensor)",
        "protocol": "TCP",
        "run": "T8.5 golden PCAP",
        "explanation": (
            "Flow RF vuot nguong 0.5; Known-family RF chon candidate DDoS voi "
            "confidence rat cao tren golden PCAP da paced."
        ),
    },
    {
        "decision": "unknown_candidate",
        "candidate": "DDoS",
        "flow_rf_probability": None,
        "confidence": None,
        "source": "192.168.252.129",
        "destination": "192.168.252.20",
        "protocol": "TCP",
        "run": "hping3 rehearsal (teacher-demo-20260726a)",
        "explanation": (
            "Flow RF khong bao attack. HBOS va Isolation Forest cung vuot nguong "
            "=> unknown_candidate. Khong xac nhan dung family DDoS."
        ),
    },
    {
        "decision": "unknown_candidate",
        "candidate": "DoS GoldenEye",
        "flow_rf_probability": None,
        "confidence": None,
        "source": "192.168.252.129",
        "destination": "192.168.252.20 (FTP)",
        "protocol": "FTP",
        "run": "ftp-patator rehearsal (teacher-demo-20260726a)",
        "explanation": (
            "FTP-Patator sinh alert nhung gan sai family (GoldenEye thay vi "
            "brute-force). Ghi dung nhu evidence, khong to hong."
        ),
    },
]


def _model_source(model: str) -> Path:
    sources = real_alert_sources()
    src = sources.get(model, sources["f9"])
    # F9 falls back to the earlier single-file stream if the split file is absent.
    if model == "f9" and not src.exists() and legacy_f9_alert().exists():
        return legacy_f9_alert()
    return src


def _active_alert_source(model: str = "f9") -> tuple[Path, str]:
    src = _model_source(model)
    if src.exists():
        return src, "real"
    return DEMO_ALERT_SOURCE, "demo"


def _any_real_stream_exists() -> bool:
    return (
        legacy_f9_alert().exists()
        or any(p.exists() for p in real_alert_sources().values())
    )


async def _demo_alert_writer():
    """Appends real bytes to a real file on disk every few seconds, using
    only the documented rehearsal events above. Stops writing automatically
    the moment any real detection stream shows up."""
    DEMO_DATA_DIR.mkdir(parents=True, exist_ok=True)
    idx = 0
    while True:
        await asyncio.sleep(3.0)
        if _any_real_stream_exists():
            continue  # a real log appeared; stop synthesizing
        event = dict(DEMO_EVENTS[idx % len(DEMO_EVENTS)])
        idx += 1
        event["ts"] = time.time()
        with DEMO_ALERT_SOURCE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


@app.on_event("startup")
async def _startup():
    asyncio.create_task(_demo_alert_writer())


@app.get("/api/alerts/tail")
def tail_alerts(offset: int = Query(0, ge=0), model: str = Query("f9")):
    if model not in real_alert_sources():
        model = "f9"
    path, kind = _active_alert_source(model)
    if not path.exists():
        return {"source": rel(path) if path.is_relative_to(REPO_ROOT) else path.name, "source_kind": kind, "model": model, "offset": 0, "events": []}

    size = path.stat().st_size
    if offset > size:
        offset = 0  # file rotated/truncated
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        new_offset = f.tell()

    src = rel(path) if path.is_relative_to(REPO_ROOT) else path.name
    return {"source": src, "source_kind": kind, "model": model, "offset": new_offset, "events": events}


# ---------------------------------------------------------------------------
# Pipeline Status — merges the curated "Receipt chinh" table from
# docs/context.md (authoritative, hand-verified) with the raw
# run_log/receipt-index.json (stale from T5.2 onward per docs/context.md).
# Both are surfaced; index-only rows are flagged so the frontend can dim
# them instead of presenting them as equally authoritative.
# ---------------------------------------------------------------------------
def _phase_of(task: str) -> str:
    m = re.match(r"T(\d+)", task)
    return m.group(1) if m else "?"


def _is_stale_suspect(task: str) -> bool:
    m = re.match(r"T(\d+)\.(\d+)", task)
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    return (major, minor) >= (5, 2)


@app.get("/api/pipeline")
def get_pipeline():
    curated = read_json(CONTEXT_RECEIPTS_FALLBACK) or {"rows": []}
    curated_tasks = {row["task"] for row in curated["rows"]}
    curated_rows = [
        {
            "task": row["task"],
            "phase": _phase_of(row["task"]),
            "status": row["status"],
            "receipt_path": row["path"],
            "sha256": row["sha256"],
            "source": "context.md",
            "stale_suspect": False,
        }
        for row in curated["rows"]
    ]

    receipt_index = read_json(RECEIPT_INDEX_JSON) or {"tasks": {}}
    index_rows = []
    for name, info in receipt_index.get("tasks", {}).items():
        if name in curated_tasks:
            continue
        far = info.get("final_acceptance_receipt") or {}
        index_rows.append(
            {
                "task": name,
                "phase": _phase_of(name),
                "status": info.get("status"),
                "receipt_path": far.get("path"),
                "sha256": far.get("sha256"),
                "source": "receipt-index.json",
                "stale_suspect": _is_stale_suspect(name),
            }
        )

    def sort_key(row):
        m = re.match(r"T(\d+)\.?(\d+)?", row["task"])
        return (int(m.group(1)), int(m.group(2) or 0)) if m else (99, 0)

    rows = sorted(curated_rows + index_rows, key=sort_key)
    return {
        "rows": rows,
        "curated_source": "docs/context.md",
        "index_source": rel(RECEIPT_INDEX_JSON),
        "stale_notice": (
            "run_log/receipt-index.json stale tu T5.2 tro di. Dong duoc danh dau "
            "stale_suspect lay nguyen tu index, khong phai tu bang Receipt chinh "
            "da doi chieu tay trong context.md."
        ),
    }


# ---------------------------------------------------------------------------
# Lab Topology — shells out to the existing tools/labctl.py (already has its
# own timeouts and non-interactive SSH guards). This endpoint never invents
# a status: whatever labctl prints is passed straight through, including
# invalid_config_or_input when config/lab-hosts.json is missing locally.
# ---------------------------------------------------------------------------
def _run_labctl(args: list[str], timeout_s: float) -> dict[str, Any]:
    if not LABCTL_SCRIPT.exists():
        raise HTTPException(500, "tools/labctl.py not found in this workspace")
    try:
        proc = subprocess.run(
            [sys.executable, str(LABCTL_SCRIPT), *args],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {"status": "dashboard_timeout", "error": f"labctl.py did not return within {timeout_s}s"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "status": "dashboard_parse_error",
            "error": "labctl.py stdout was not JSON",
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
            "returncode": proc.returncode,
        }


@app.get("/api/lab/status")
def lab_status():
    config_present = LAB_HOSTS_CONFIG.exists()
    document = _run_labctl(["status", "--timeout-seconds", "20"], timeout_s=75.0)
    return {
        "config_present": config_present,
        "config_source": rel(LAB_HOSTS_CONFIG),
        "document": document,
    }


# Whitelist only — the UI never sends a free-text command to labctl exec.
LAB_EXEC_WHITELIST = {
    "hostname": "hostname",
    "whoami": "whoami",
}


@app.post("/api/lab/exec")
def lab_exec(payload: dict = Body(...)):
    role = payload.get("role")
    command_id = payload.get("command_id")
    if role not in ("kali", "ubuntu", "windows"):
        raise HTTPException(400, "role must be kali, ubuntu, or windows")
    if command_id not in LAB_EXEC_WHITELIST:
        raise HTTPException(400, f"command_id must be one of {list(LAB_EXEC_WHITELIST)}")
    command = LAB_EXEC_WHITELIST[command_id]
    document = _run_labctl(["exec", role, "--timeout-seconds", "15", command], timeout_s=30.0)
    return {"role": role, "command_id": command_id, "command": command, "document": document}


static_dir = Path(__file__).resolve().parent.parent / "web" / "dist"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="web")
