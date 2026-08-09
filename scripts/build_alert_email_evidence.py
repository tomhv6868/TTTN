#!/usr/bin/env python3
"""Build thesis evidence for the email alerting path.

Describes what the notifier does, what it deliberately refuses to do, and what
it actually sent, using the receipts it wrote. Secrets never enter the output:
only the recipient domain and a count are recorded, never a password.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT_ROOT = ROOT / "run_log/full-flow-v1/alert-email"
NOTIFIER = ROOT / "scripts/alert_email_notifier.py"
NOTIFIER_TESTS = ROOT / "tests/test_alert_email_notifier.py"
SETUP_DOC = ROOT / "docs/alert-email-setup.vi.md"
ENV_EXAMPLE = ROOT / ".env.example"
OUTPUT_ROOT = ROOT / "run_log/full-flow-v1/thesis-evidence"
STEM = "alert-email-20260809"
CURRENT_TAG = "t91-alert-email-evidence-r1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def redact_recipient(address: str) -> str:
    """Keep the domain, drop the mailbox. Enough to prove where mail went."""
    _, _, domain = address.partition("@")
    return f"<redacted>@{domain}" if domain else "<redacted>"


def collect_receipts() -> list[dict]:
    rows = []
    if not RECEIPT_ROOT.is_dir():
        return rows
    for path in sorted(RECEIPT_ROOT.glob("receipt-*.json")):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        rows.append(
            {
                "receipt": rel(path),
                "generated_at_utc": receipt.get("generated_at_utc"),
                "mode": receipt.get("mode"),
                "stream": receipt.get("stream"),
                "lines_consumed": receipt.get("lines_consumed"),
                "confirmed_attacks": receipt.get("confirmed_attacks"),
                "uncertain": receipt.get("uncertain"),
                "skipped_benign": receipt.get("skipped_benign"),
                "skipped_duplicate": receipt.get("skipped_duplicate"),
                "counts_by_decision": receipt.get("counts_by_decision"),
                "subject": receipt.get("subject"),
                "recipients": [
                    redact_recipient(a) for a in (receipt.get("recipients") or [])
                ],
                "body_sha256": receipt.get("body_sha256"),
            }
        )
    return rows


def build() -> dict:
    receipts = collect_receipts()
    sent = [r for r in receipts if r["mode"] == "sent"]
    sources = [p for p in (NOTIFIER, NOTIFIER_TESTS, SETUP_DOC, ENV_EXAMPLE) if p.is_file()]

    return {
        "schema_version": "1.0.0",
        "kind": "alert_email_notification_evidence",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "current_tag": CURRENT_TAG,
        "question": "How does a detection reach a human, and what guarantees does that path give?",
        "component": {
            "entry_point": rel(NOTIFIER),
            "input": "a dashboard alert stream in JSONL (F9 or Terminal V1)",
            "transport": "SMTP with STARTTLS",
            "default_mode": "dry run; sending requires the explicit --send flag",
        },
        "filtering_rules": [
            "Benign rows are dropped, counted separately and never mailed.",
            "Rows whose scores.attack is false are dropped even when the label is not Benign.",
            "Duplicates within one digest collapse on (model, source, destination, protocol, label).",
            "F9 keeps the attack family in `candidate` and only a semantic verdict in `decision`, "
            "so the mail reports `candidate`; reading `decision` would print known_attack on every row.",
            "decision=uncertain and decision=unknown_candidate are still reported but marked "
            "separately and excluded from the confirmed-attack count.",
        ],
        "safety_properties": [
            "Credentials come from the environment or a gitignored .env; none are stored in the repo.",
            "A cursor file records the last consumed line, so a restart cannot resend old alerts.",
            "A failed send exits without advancing the cursor, so no alert is lost.",
            "Every run writes a receipt with the digest counts and a SHA-256 of the body.",
            "Messages carry Auto-Submitted: auto-generated so replies and loops are discouraged.",
            "The body states that its numbers are operational only and that thesis figures come "
            "from hashed receipts.",
        ],
        "scope_limits": [
            "This is a notification layer, not a measurement. Nothing in the mail may be cited as a metric.",
            "Delivery depends on the mail provider; the receipt proves the message was accepted for "
            "delivery by the server, not that a human read it.",
            "Latency of the mail path was not measured and must not be presented as detection latency.",
        ],
        "runs": receipts,
        "summary": {
            "total_runs": len(receipts),
            "sent_runs": len(sent),
            "dry_run_runs": len(receipts) - len(sent),
            "alerts_actually_sent": sum(r["confirmed_attacks"] or 0 for r in sent),
        },
        "supporting_sources": [
            {"path": rel(p), "bytes": p.stat().st_size, "sha256": sha256(p)} for p in sources
        ],
        "test_partition": {"state": "sealed", "feature_reads": 0, "metric_reads": 0},
    }


FILTER_RULES_VI = [
    "Dòng Benign bị loại, đếm riêng, không bao giờ gửi đi.",
    "Dòng có `scores.attack = false` bị loại kể cả khi nhãn không phải Benign.",
    "Trùng lặp trong cùng một bản tin bị gộp theo `(model, nguồn, đích, giao thức, nhãn)`.",
    "F9 để họ tấn công ở trường `candidate`, còn `decision` chỉ là quyết định ngữ nghĩa. "
    "Bản tin hiển thị `candidate`; nếu đọc `decision` thì mọi dòng đều hiện `known_attack`.",
    "`decision = uncertain` và `unknown_candidate` vẫn được báo nhưng đánh dấu riêng và "
    "không cộng vào số tấn công xác nhận.",
]

SAFETY_VI = [
    "Thông tin đăng nhập lấy từ biến môi trường hoặc file `.env` đã gitignore; không có gì nằm trong repo.",
    "File cursor ghi dòng cuối đã đọc, nên chạy lại không gửi trùng cảnh báo cũ.",
    "Gửi thất bại thì thoát mà **không** dời cursor, nên không mất cảnh báo nào.",
    "Mỗi lần chạy ghi một receipt gồm các số đếm và SHA-256 của thân thư.",
    "Thư mang header `Auto-Submitted: auto-generated` để hạn chế trả lời tự động và vòng lặp thư.",
    "Thân thư ghi rõ số trong đó chỉ để vận hành, số luận văn phải lấy từ receipt đã hash.",
]

LIMITS_VI = [
    "Đây là **lớp thông báo, không phải phép đo**. Không con số nào trong thư được trích làm chỉ số.",
    "Việc gửi đến nơi phụ thuộc nhà cung cấp mail. Receipt chỉ chứng minh máy chủ đã nhận thư "
    "để chuyển đi, **không** chứng minh có người đã đọc.",
    "Độ trễ của đường thư **chưa được đo** và không được trình bày như độ trễ phát hiện.",
]


def render_markdown(evidence: dict) -> str:
    summary = evidence["summary"]
    lines = [
        "# Bằng chứng luận văn — cảnh báo qua email",
        "",
        f"Tag: `{evidence['current_tag']}` · sinh lúc {evidence['generated_at_utc']}",
        "",
        "## 1. Thành phần này làm gì",
        "",
        f"Điểm vào: `{evidence['component']['entry_point']}`.",
        "",
        "| Mục | Giá trị |",
        "|---|---|",
        "| Đầu vào | luồng cảnh báo JSONL của dashboard (F9 hoặc Terminal V1) |",
        "| Truyền tải | SMTP kèm STARTTLS |",
        "| Chế độ mặc định | chạy thử; muốn gửi thật phải thêm cờ `--send` |",
        "",
        "Nó đứng **sau** cảm biến: đọc luồng cảnh báo đã có, lọc, gom thành một bản tin rồi gửi. "
        "Nó không tham gia vào việc phát hiện.",
        "",
        "## 2. Quy tắc lọc",
        "",
    ]
    lines += [f"{i}. {rule}" for i, rule in enumerate(FILTER_RULES_VI, 1)]

    lines += [
        "",
        "## 3. Bảo đảm an toàn",
        "",
    ]
    lines += [f"- {item}" for item in SAFETY_VI]

    lines += [
        "",
        "## 4. Đã chạy những gì",
        "",
        f"Tổng **{summary['total_runs']}** lần chạy: **{summary['sent_runs']}** lần gửi thật, "
        f"**{summary['dry_run_runs']}** lần chạy thử. "
        f"Đã gửi **{summary['alerts_actually_sent']}** cảnh báo xác nhận.",
        "",
    ]
    if evidence["runs"]:
        lines += [
            "| Thời điểm | Chế độ | Nguồn | Tấn công | Chưa chắc | Bỏ benign | Bỏ trùng |",
            "|---|---|---|---|---|---|---|",
        ]
        for run in evidence["runs"]:
            lines.append(
                f"| {run['generated_at_utc']} | {run['mode']} | `{run['stream']}` | "
                f"{run['confirmed_attacks']} | {run['uncertain']} | "
                f"{run['skipped_benign']} | {run['skipped_duplicate']} |"
            )
        lines += [
            "",
            "Địa chỉ người nhận đã được che, chỉ giữ tên miền. Mật khẩu không bao giờ được ghi lại.",
            "",
        ]
    else:
        lines += ["Chưa có receipt nào dưới `run_log/full-flow-v1/alert-email/`.", ""]

    lines += [
        "## 5. Giới hạn phải ghi kèm",
        "",
    ]
    lines += [f"- {item}" for item in LIMITS_VI]

    lines += [
        "",
        "## 6. Cách chạy lại",
        "",
        "```powershell",
        "# kiem tra dang nhap, khong gui",
        "python scripts/alert_email_notifier.py --check-smtp",
        "",
        "# chay thu, in nguyen van ban tin",
        "python scripts/alert_email_notifier.py --limit 20 --from-start",
        "",
        "# gui that",
        "python scripts/alert_email_notifier.py --limit 20 --send",
        "```",
        "",
        f"Hướng dẫn cài đặt đầy đủ: `{rel(SETUP_DOC)}`.",
        "",
        "## 7. Nguồn đã hash",
        "",
        "| File | Bytes | SHA-256 |",
        "|---|---|---|",
    ]
    for source in evidence["supporting_sources"]:
        lines.append(f"| `{source['path']}` | {source['bytes']} | `{source['sha256']}` |")
    lines += [
        "",
        f"Test partition: `{evidence['test_partition']['state']}`, 0 lượt đọc.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    evidence = build()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    (OUTPUT_ROOT / f"{STEM}.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUTPUT_ROOT / f"{STEM}.md").write_text(render_markdown(evidence), encoding="utf-8")
    print(f"wrote {rel(OUTPUT_ROOT / f'{STEM}.json')}")
    print(f"wrote {rel(OUTPUT_ROOT / f'{STEM}.md')}")


if __name__ == "__main__":
    main()
