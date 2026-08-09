#!/usr/bin/env python3
"""Send NIDS attack alerts by email.

Reads a dashboard alert stream (JSONL), keeps only records that are actually an
attack decision, removes duplicates, batches what is left into one digest and
sends it over SMTP.

Safety rules baked in:

* Dry run is the default. Sending happens only with --send.
* Credentials are read from the environment, never from a file in the repo.
* A cursor file records how far the stream was consumed, so a restart does not
  resend old alerts.
* Every run writes a receipt so the thesis can cite what was sent and when.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STREAM = ROOT / "run_log/full-flow-v1/live-detection-f9.jsonl"
DEFAULT_STATE = ROOT / "run_log/full-flow-v1/alert-email/cursor.json"
DEFAULT_RECEIPT_DIR = ROOT / "run_log/full-flow-v1/alert-email"

BENIGN_LABELS = {"benign", "normal", "no_alert", "none"}
# F9 emits a semantic decision; only known_attack is a confirmed detection.
UNCERTAIN_DECISIONS = {"uncertain", "unknown_candidate", "unknown"}
ENV_HOST = "NIDS_SMTP_HOST"
ENV_PORT = "NIDS_SMTP_PORT"
ENV_USER = "NIDS_SMTP_USER"
ENV_PASSWORD = "NIDS_SMTP_PASSWORD"
ENV_SENDER = "NIDS_ALERT_SENDER"
ENV_RECIPIENTS = "NIDS_ALERT_RECIPIENTS"
ENV_SMTP_PORT_HINT = ENV_PORT


DEFAULT_ENV_FILE = ROOT / ".env"


class ConfigurationError(RuntimeError):
    """Raised when the SMTP settings are incomplete."""


def parse_env_file(text: str) -> dict[str, str]:
    """Minimal .env parser: KEY=VALUE, '#' comments, optional surrounding quotes."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[len("export "):]
        name, _, value = line.partition("=")
        name = name.strip()
        if not name:
            continue
        value = value.split(" #", 1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name] = value
    return values


def load_env_file(path: Path = DEFAULT_ENV_FILE) -> dict[str, str]:
    """Read .env if it exists.

    Values here win over the process environment on purpose. The file is this
    tool's documented config, and a stale variable left in an old PowerShell
    window is the most common reason an edited .env appears to do nothing.
    """
    if not path.exists():
        return {}
    return parse_env_file(path.read_text(encoding="utf-8-sig"))


def resolve_environment(env_file: Path | None = DEFAULT_ENV_FILE) -> tuple[dict[str, str], dict[str, str]]:
    """Return (merged values, source per variable) for reporting."""
    merged = dict(os.environ)
    sources = {name: "biến môi trường" for name in merged}
    if env_file is not None:
        for name, value in load_env_file(env_file).items():
            merged[name] = value
            sources[name] = env_file.name
    return merged, sources


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    username: str | None
    password: str | None
    sender: str
    recipients: tuple[str, ...]
    use_starttls: bool = True

    @classmethod
    def from_environment(cls, environ: dict[str, str] | None = None) -> "SmtpSettings":
        env = resolve_environment()[0] if environ is None else environ

        def clean(name: str) -> str:
            """Strip whitespace and stray quotes left by copy-paste or shell escaping."""
            return (env.get(name) or "").strip().strip('"').strip("'")

        missing = [name for name in (ENV_HOST, ENV_SENDER, ENV_RECIPIENTS) if not clean(name)]
        if missing:
            raise ConfigurationError(
                "thiếu biến môi trường: " + ", ".join(missing)
                + ". Đặt chúng trong shell, không ghi vào repo."
            )
        recipients = tuple(
            part.strip() for part in clean(ENV_RECIPIENTS).replace(";", ",").split(",") if part.strip()
        )
        if not recipients:
            raise ConfigurationError(f"{ENV_RECIPIENTS} không chứa địa chỉ nào")

        # Google shows app passwords as "abcd efgh ijkl mnop"; the spaces are
        # presentation only and SMTP rejects them, so remove every space.
        password = "".join(clean(ENV_PASSWORD).split()) or None

        port_text = clean(ENV_PORT) or "587"
        try:
            port = int(port_text)
        except ValueError as error:
            raise ConfigurationError(f"{ENV_PORT} phải là số, đang là {port_text!r}") from error

        return cls(
            host=clean(ENV_HOST),
            port=port,
            username=clean(ENV_USER) or None,
            password=password,
            sender=clean(ENV_SENDER),
            recipients=recipients,
        )

    def warnings(self) -> list[str]:
        """Configuration that is accepted but very likely wrong."""
        notes: list[str] = []
        gmail = self.host.lower().endswith("gmail.com")
        if gmail:
            if self.port == 465:
                notes.append(
                    f"cổng {self.port} là SMTPS; Gmail dùng STARTTLS ở cổng 587. Đổi {ENV_SMTP_PORT_HINT}."
                )
            if self.password and len(self.password) != 16:
                notes.append(
                    f"App Password của Gmail dài đúng 16 ký tự, chuỗi đang dùng dài {len(self.password)}. "
                    "Nhiều khả năng đây là mật khẩu đăng nhập thường, Gmail sẽ từ chối."
                )
            if self.password and len(self.password) == 16 and not self.password.isalpha():
                notes.append(
                    "App Password chỉ gồm chữ cái thường. Chuỗi đang dùng có chữ số hoặc ký tự khác, "
                    "nhiều khả năng không phải App Password."
                )
            if self.username and self.sender and self.username.lower() != self.sender.lower():
                notes.append(
                    f"Gmail yêu cầu người gửi trùng tài khoản đăng nhập: {ENV_SENDER}={self.sender} "
                    f"khác {ENV_USER}={self.username}."
                )
        if self.username and not self.password:
            notes.append(f"có {ENV_USER} nhưng thiếu {ENV_PASSWORD}, sẽ không đăng nhập được.")
        return notes


@dataclass
class Alert:
    raw: dict
    line_number: int

    @property
    def decision(self) -> str:
        """Semantic verdict used for gating. F9: known_attack/uncertain/... Terminal: the class."""
        value = self.raw.get("decision")
        return value if isinstance(value, str) and value else ""

    @property
    def label(self) -> str:
        """Human-readable attack family shown in the mail.

        F9 puts the family in `candidate` and a semantic verdict in `decision`,
        so reading `decision` alone would print `known_attack` for every row.
        """
        for key in ("candidate", "terminal_class", "classification", "decision"):
            value = self.raw.get(key)
            if isinstance(value, str) and value:
                return value
        return "unknown"

    @property
    def severity(self) -> str:
        return "uncertain" if self.decision.strip().lower() in UNCERTAIN_DECISIONS else "attack"

    @property
    def confidence(self) -> float | None:
        for key in ("confidence", "attack_score", "class_confidence"):
            value = self.raw.get(key)
            if isinstance(value, (int, float)):
                return float(value)
        return None

    @property
    def source(self) -> str:
        return str(self.raw.get("source") or self.raw.get("src") or "?")

    @property
    def destination(self) -> str:
        return str(self.raw.get("destination") or self.raw.get("dst") or "?")

    @property
    def model(self) -> str:
        return str(self.raw.get("model") or "?")

    def identity(self) -> str:
        """Stable key for de-duplication: flow endpoints plus the label."""
        parts = (self.model, self.source, self.destination, str(self.raw.get("protocol") or ""), self.label)
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def is_attack(self) -> bool:
        decision = self.decision.strip().lower()
        if not decision or decision in BENIGN_LABELS:
            return False
        if self.label.strip().lower() in BENIGN_LABELS:
            return False
        scores = self.raw.get("scores")
        if isinstance(scores, dict) and scores.get("attack") is False:
            return False
        return True


@dataclass
class Digest:
    alerts: list[Alert] = field(default_factory=list)
    skipped_benign: int = 0
    skipped_duplicate: int = 0
    skipped_recent: int = 0
    last_line: int = 0
    family_totals: dict[str, int] = field(default_factory=dict)
    family_suppressed: dict[str, int] = field(default_factory=dict)

    def counts_by_decision(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for alert in self.alerts:
            counts[alert.label] = counts.get(alert.label, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    @property
    def confirmed(self) -> list["Alert"]:
        return [a for a in self.alerts if a.severity == "attack"]

    @property
    def uncertain(self) -> list["Alert"]:
        return [a for a in self.alerts if a.severity == "uncertain"]


def read_cursor(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return int(json.loads(path.read_text(encoding="utf-8")).get("last_line", 0))
    except (json.JSONDecodeError, ValueError, TypeError):
        return 0


def read_state(path: Path) -> dict:
    """Whole state document, or an empty one when missing or corrupt."""
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}
    return document if isinstance(document, dict) else {}


def read_seen(path: Path, window_hours: float) -> dict[str, str]:
    """Identities already mailed inside the window, keyed by Alert.identity().

    Entries older than the window are dropped, so a flow that reappears the next
    day counts as news again instead of staying silent forever.
    """
    if window_hours <= 0:
        return {}
    seen = read_state(path).get("seen")
    if not isinstance(seen, dict):
        return {}
    cutoff = datetime.now(timezone.utc).timestamp() - window_hours * 3600
    fresh: dict[str, str] = {}
    for key, stamp in seen.items():
        try:
            when = datetime.fromisoformat(str(stamp)).timestamp()
        except ValueError:
            continue
        if when >= cutoff:
            fresh[str(key)] = str(stamp)
    return fresh


MAX_SEEN_ENTRIES = 20000


def write_cursor(path: Path, last_line: int, seen: dict[str, str] | None = None) -> None:
    """Persist the cursor. `seen` replaces the dedupe store; None keeps it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if seen is None:
        previous = read_state(path).get("seen")
        seen = previous if isinstance(previous, dict) else {}
    if len(seen) > MAX_SEEN_ENTRIES:
        newest = sorted(seen.items(), key=lambda item: item[1], reverse=True)
        seen = dict(newest[:MAX_SEEN_ENTRIES])
    payload = {
        "last_line": last_line,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "seen": seen,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def select_across_families(
    buckets: dict[str, list[Alert]], limit: int, per_family_limit: int
) -> tuple[list[Alert], dict[str, int]]:
    """Pick alerts round-robin so every family present gets into the mail.

    Taking the first `limit` records in file order lets one noisy family (a port
    scan easily emits hundreds) fill the digest and hide the others. Walking the
    families in rounds means each one contributes its first alert before any
    family contributes its second.
    """
    order = sorted(buckets, key=lambda name: (-len(buckets[name]), name))
    selected: list[Alert] = []
    taken: dict[str, int] = {name: 0 for name in order}
    depth = 0
    while len(selected) < limit:
        progressed = False
        for name in order:
            if len(selected) >= limit:
                break
            items = buckets[name]
            if depth >= len(items):
                continue
            if per_family_limit > 0 and depth >= per_family_limit:
                continue
            selected.append(items[depth])
            taken[name] += 1
            progressed = True
        if not progressed:
            break
        depth += 1
    suppressed = {
        name: len(items) - taken[name]
        for name, items in buckets.items()
        if len(items) - taken[name] > 0
    }
    selected.sort(key=lambda alert: alert.line_number)
    return selected, suppressed


def collect(
    stream: Path,
    start_line: int,
    limit: int,
    per_family_limit: int = 0,
    seen_recent: dict[str, str] | None = None,
) -> Digest:
    """Read new lines, drop benign and repeats, then balance across families.

    `seen_recent` holds identities already mailed inside the dedupe window; they
    are counted and skipped so a long-running flow is reported once, not once
    per run.
    """
    digest = Digest(last_line=start_line)
    recent = seen_recent or {}
    seen_this_run: set[str] = set()
    buckets: dict[str, list[Alert]] = {}
    for number, line in enumerate(stream.read_text(encoding="utf-8-sig").splitlines(), start=1):
        digest.last_line = number
        if number <= start_line:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        alert = Alert(raw=record, line_number=number)
        if not alert.is_attack():
            digest.skipped_benign += 1
            continue
        key = alert.identity()
        if key in seen_this_run:
            digest.skipped_duplicate += 1
            continue
        seen_this_run.add(key)
        if key in recent:
            digest.skipped_recent += 1
            continue
        buckets.setdefault(alert.label, []).append(alert)
        digest.family_totals[alert.label] = digest.family_totals.get(alert.label, 0) + 1
    digest.alerts, digest.family_suppressed = select_across_families(
        buckets, limit, per_family_limit
    )
    return digest


def render_subject(digest: Digest, prefix: str) -> str:
    counts = digest.counts_by_decision()
    if not counts:
        return f"{prefix} khong co canh bao moi"
    top = next(iter(counts))
    tail = f", {len(digest.uncertain)} chua chac chan" if digest.uncertain else ""
    return f"{prefix} {len(digest.confirmed)} tan cong, nhieu nhat: {top}{tail}"


def render_body(digest: Digest, stream: Path, max_rows: int = 50) -> str:
    counts = digest.counts_by_decision()
    lines = [
        "CANH BAO XAM NHAP - BAN TIN TU DONG",
        "",
        f"Thoi diem gui  : {datetime.now(timezone.utc).isoformat()}",
        f"Nguon du lieu  : {stream.name}",
        f"Tan cong xac nhan : {len(digest.confirmed)}",
        f"Chua chac chan    : {len(digest.uncertain)}",
        f"Bo qua benign     : {digest.skipped_benign}",
        f"Bo qua trung      : {digest.skipped_duplicate}",
        f"Bo qua da gui gan day : {digest.skipped_recent}",
        "",
        "TONG HOP THEO NHAN",
    ]
    for decision, count in counts.items():
        total = digest.family_totals.get(decision, count)
        if total > count:
            lines.append(f"  - {decision}: {count} dua vao ban tin / {total} su kien")
        else:
            lines.append(f"  - {decision}: {count}")
    if digest.family_suppressed:
        lines += ["", "DA GOP BOT (moi ho van co dai dien o tren)"]
        for name, extra in sorted(digest.family_suppressed.items(), key=lambda i: (-i[1], i[0])):
            lines.append(f"  - {name}: an bot {extra} su kien cung loai")

    lines += ["", f"CHI TIET (toi da {max_rows} dong)", ""]
    header = f"{'#':>4}  {'model':<8} {'muc':<10} {'nhan':<24} {'tin cay':>9}  nguon -> dich"
    lines.append(header)
    lines.append("-" * len(header))
    for index, alert in enumerate(digest.alerts[:max_rows], start=1):
        confidence = "-" if alert.confidence is None else f"{alert.confidence:.4f}"
        muc = "TAN CONG" if alert.severity == "attack" else "chua chac"
        lines.append(
            f"{index:>4}  {alert.model[:8]:<8} {muc:<10} {alert.label[:24]:<24} {confidence:>9}  "
            f"{alert.source} -> {alert.destination}"
        )
    if len(digest.alerts) > max_rows:
        lines.append(f"... con {len(digest.alerts) - max_rows} canh bao nua, xem file nguon.")

    lines += [
        "",
        "GHI CHU",
        "  Dong 'chua chac' la decision uncertain/unknown_candidate, chua phai tan cong xac nhan.",
        "  Ban tin nay do he thong sinh tu dong, khong tra loi vao dia chi gui.",
        "  Con so trong ban tin chi de canh bao van hanh.",
        "  So lieu dua vao luan van phai lay tu receipt da hash trong run_log.",
    ]
    return "\n".join(lines)


def build_message(digest: Digest, settings: SmtpSettings, stream: Path, prefix: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = render_subject(digest, prefix)
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="nids.lab")
    message["Auto-Submitted"] = "auto-generated"
    message["X-NIDS-Alert-Count"] = str(len(digest.confirmed))
    message["X-NIDS-Uncertain-Count"] = str(len(digest.uncertain))
    message.set_content(render_body(digest, stream))
    return message


AUTH_HELP = f"""Gmail tu choi dang nhap (535 BadCredentials).

Doc dong "password" o tren truoc. App Password hop le la DUNG 16 KY TU, TOAN CHU THUONG.
Neu no co chu so, chu hoa hay ky tu dac biet -> do khong phai App Password.

Cac nguyen nhan, theo thu tu hay gap:

  1. Dang dung MAT KHAU THUONG. Gmail khong cho SMTP bang mat khau dang nhap.
       - Bat 2FA:  https://myaccount.google.com/signinoptions/two-step-verification
       - Tao:      https://myaccount.google.com/apppasswords

  2. App Password tao tren TAI KHOAN KHAC voi {ENV_USER}.
     Dang xuat het roi vao lai dung tai khoan do, tao lai App Password.

  3. App Password da bi thu hoi, hoac vua doi mat khau tai khoan
     (doi mat khau se vo hieu hoa toan bo App Password cu).

  4. Tai khoan Google Workspace bi quan tri vien chan SMTP.
     Kiem tra bang cach thu voi mot tai khoan Gmail ca nhan.

  5. Bien moi truong dat o cua so PowerShell khac voi cua so dang chay python.
     Kiem tra ngay trong cua so do:  echo $env:NIDS_SMTP_PASSWORD

Kiem tra lai:
  python scripts/alert_email_notifier.py --check-smtp"""


def password_shape(password: str | None) -> str:
    """Describe the secret without printing it.

    A Gmail app password is exactly 16 lowercase ASCII letters. Anything else is
    almost certainly the ordinary account password, which Gmail always rejects.
    """
    if not password:
        return "(khong dat)"
    classes = []
    if any(c.islower() for c in password):
        classes.append("chu thuong")
    if any(c.isupper() for c in password):
        classes.append("CHU HOA")
    if any(c.isdigit() for c in password):
        classes.append("chu so")
    if any(not c.isalnum() for c in password):
        classes.append("ky tu dac biet")
    fingerprint = f"{password[:2]}{'*' * max(0, len(password) - 4)}{password[-2:]}"
    return f"{len(password)} ky tu [{', '.join(classes)}] dang {fingerprint}"


def check_smtp(settings: SmtpSettings, verbose: bool = False) -> None:
    """Open a session and log in without sending anything."""
    context = ssl.create_default_context()
    with smtplib.SMTP(settings.host, settings.port, timeout=30) as client:
        client.ehlo()
        if settings.use_starttls:
            client.starttls(context=context)
            client.ehlo()
        if verbose:
            offered = client.esmtp_features.get("auth", "(may chu khong khai bao)")
            print(f"  co che AUTH may chu nhan: {offered.strip()}")
        if settings.username and settings.password:
            client.login(settings.username, settings.password)


def describe_settings(settings: SmtpSettings) -> str:
    masked = password_shape(settings.password)
    return "\n".join(
        [
            f"  host      : {settings.host}:{settings.port}",
            f"  user      : {settings.username or '(khong dat)'}",
            f"  password  : {masked}",
            f"  sender    : {settings.sender}",
            f"  recipients: {', '.join(settings.recipients)}",
        ]
    )


def send(message: EmailMessage, settings: SmtpSettings) -> dict:
    context = ssl.create_default_context()
    with smtplib.SMTP(settings.host, settings.port, timeout=30) as client:
        client.ehlo()
        if settings.use_starttls:
            client.starttls(context=context)
            client.ehlo()
        if settings.username and settings.password:
            client.login(settings.username, settings.password)
        refused = client.send_message(message)
    return {"refused_recipients": sorted(refused)}


def write_receipt(directory: Path, payload: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"receipt-{stamp}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stream", type=Path, default=DEFAULT_STREAM, help="file JSONL chua alert")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE, help="file ghi vi tri da doc")
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--limit", type=int, default=200, help="so alert toi da moi ban tin")
    parser.add_argument(
        "--min-alerts",
        type=int,
        default=1,
        help="chi gui khi gom du bay nhieu canh bao; chua du thi giu cursor de gom tiep",
    )
    parser.add_argument(
        "--per-family-limit",
        type=int,
        default=5,
        help="so dong toi da moi ho tan cong trong mot ban tin (0 = khong gioi han)",
    )
    parser.add_argument(
        "--dedupe-window-hours",
        type=float,
        default=24.0,
        help="khong gui lai luong da bao trong bay nhieu gio (0 = tat)",
    )
    parser.add_argument("--subject-prefix", default="[NIDS]")
    parser.add_argument("--from-start", action="store_true", help="bo qua cursor, doc tu dau file")
    parser.add_argument("--send", action="store_true", help="gui that; mac dinh chi chay thu")
    parser.add_argument("--no-advance", action="store_true", help="khong ghi cursor sau khi chay")
    parser.add_argument(
        "--no-env-file",
        action="store_true",
        help="bo qua file .env, chi dung bien moi truong",
    )
    parser.add_argument(
        "--check-smtp",
        action="store_true",
        help="chi kiem tra dang nhap SMTP roi thoat, khong doc stream, khong gui",
    )
    args = parser.parse_args(argv)

    env_file = None if args.no_env_file else DEFAULT_ENV_FILE
    merged, sources = resolve_environment(env_file)

    if args.check_smtp:
        try:
            settings = SmtpSettings.from_environment(merged)
        except ConfigurationError as error:
            print(f"CAU HINH SAI: {error}")
            return 2
        if env_file is not None and env_file.exists():
            print(f"Da nap {env_file.name} (gia tri trong file ghi de bien moi truong).")
        else:
            print("Khong co file .env, chi dung bien moi truong.")
        print(f"  nguon NIDS_SMTP_PASSWORD: {sources.get(ENV_PASSWORD, '(khong co)')}")
        print("Dang dung cau hinh:")
        print(describe_settings(settings))
        for note in settings.warnings():
            print(f"  CANH BAO: {note}")
        try:
            check_smtp(settings, verbose=True)
        except smtplib.SMTPAuthenticationError as error:
            detail = error.smtp_error.decode("utf-8", "replace") if error.smtp_error else ""
            print()
            print(f"MAY CHU TRA VE {error.smtp_code}: {detail}")
            print()
            print(AUTH_HELP)
            return 2
        except (smtplib.SMTPException, OSError) as error:
            print()
            print(f"KHONG KET NOI DUOC {settings.host}:{settings.port} -> {error}")
            return 2
        print()
        print("DANG NHAP SMTP THANH CONG. Co the chay lai voi --send.")
        return 0

    if not args.stream.exists():
        parser.error(f"khong tim thay stream: {args.stream}")

    start_line = 0 if args.from_start else read_cursor(args.state)
    seen_recent = {} if args.from_start else read_seen(args.state, args.dedupe_window_hours)
    digest = collect(
        args.stream,
        start_line,
        args.limit,
        per_family_limit=args.per_family_limit,
        seen_recent=seen_recent,
    )

    if not digest.alerts:
        held = digest.skipped_recent
        note = f", {held} luong da bao truoc do" if held else ""
        print(f"khong co canh bao moi (da doc toi dong {digest.last_line}{note})")
        if not args.no_advance:
            write_cursor(args.state, digest.last_line, seen_recent)
        return 0

    if len(digest.alerts) < args.min_alerts:
        print(
            f"moi gom duoc {len(digest.alerts)} canh bao, nguong la {args.min_alerts}"
            " -> chua gui. Cursor giu nguyen nen lan chay sau se gom tiep."
        )
        for name, count in digest.counts_by_decision().items():
            print(f"  - {name}: {count}")
        return 0

    try:
        settings = SmtpSettings.from_environment(merged)
    except ConfigurationError as error:
        if args.send:
            parser.error(str(error))
        settings = SmtpSettings(
            host="dry-run.invalid",
            port=587,
            username=None,
            password=None,
            sender="nids-alert@dry-run.invalid",
            recipients=("nguoi-nhan@dry-run.invalid",),
        )

    message = build_message(digest, settings, args.stream, args.subject_prefix)
    receipt = {
        "schema_version": "1.0.0",
        "kind": "nids_alert_email_receipt",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "stream": args.stream.name,
        "lines_consumed": {"from": start_line + 1, "to": digest.last_line},
        "alerts_sent": len(digest.alerts),
        "confirmed_attacks": len(digest.confirmed),
        "uncertain": len(digest.uncertain),
        "skipped_benign": digest.skipped_benign,
        "skipped_duplicate": digest.skipped_duplicate,
        "skipped_recent": digest.skipped_recent,
        "min_alerts": args.min_alerts,
        "per_family_limit": args.per_family_limit,
        "dedupe_window_hours": args.dedupe_window_hours,
        "family_totals": digest.family_totals,
        "family_suppressed": digest.family_suppressed,
        "counts_by_decision": digest.counts_by_decision(),
        "subject": message["Subject"],
        "recipients": list(settings.recipients),
        "mode": "sent" if args.send else "dry_run",
        "body_sha256": hashlib.sha256(message.get_content().encode("utf-8")).hexdigest(),
    }

    if args.send:
        for note in settings.warnings():
            print(f"CANH BAO: {note}")
        try:
            receipt.update(send(message, settings))
        except smtplib.SMTPAuthenticationError:
            print(AUTH_HELP)
            print()
            print("Cau hinh dang dung:")
            print(describe_settings(settings))
            print()
            print("Chua gui gi ca, cursor giu nguyen nen chay lai se khong mat canh bao nao.")
            return 2
        except (smtplib.SMTPException, OSError) as error:
            print(f"GUI THAT BAI: {error}")
            print("Chua gui gi ca, cursor giu nguyen.")
            return 2
        print(f"da gui {len(digest.confirmed)} tan cong toi {', '.join(settings.recipients)}")
    else:
        print("=== CHAY THU, KHONG GUI ===")
        print(f"Subject: {message['Subject']}")
        print(f"To     : {message['To']}")
        print()
        print(message.get_content())

    receipt_path = write_receipt(args.receipt_dir, receipt)
    try:
        shown = receipt_path.relative_to(ROOT).as_posix()
    except ValueError:
        shown = receipt_path.as_posix()
    print(f"receipt: {shown}")

    if args.send:
        stamp = datetime.now(timezone.utc).isoformat()
        for alert in digest.alerts:
            seen_recent[alert.identity()] = stamp

    if not args.no_advance:
        write_cursor(args.state, digest.last_line, seen_recent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
