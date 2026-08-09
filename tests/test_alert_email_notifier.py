import json
import smtplib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.alert_email_notifier import (
    Alert,
    ConfigurationError,
    SmtpSettings,
    parse_env_file,
    resolve_environment,
    build_message,
    collect,
    main,
    read_cursor,
    render_body,
    write_cursor,
)


def write_stream(directory: Path, records: list[dict]) -> Path:
    path = directory / "stream.jsonl"
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
    return path


SETTINGS = SmtpSettings(
    host="smtp.test",
    port=587,
    username="u",
    password="p",
    sender="nids@test",
    recipients=("soc@test",),
)


class AlertClassificationTests(unittest.TestCase):
    def test_benign_decisions_are_not_alerts(self):
        for decision in ("Benign", "benign", "BENIGN", "normal", "none"):
            self.assertFalse(Alert({"decision": decision}, 1).is_attack(), decision)

    def test_attack_decisions_are_alerts(self):
        for decision in ("PortScan", "FTP-Bruteforce", "DoS Hulk", "Other"):
            self.assertTrue(Alert({"decision": decision}, 1).is_attack(), decision)

    def test_scores_attack_false_overrides_a_non_benign_label(self):
        record = {"decision": "PortScan", "scores": {"attack": False}}
        self.assertFalse(Alert(record, 1).is_attack())

    def test_missing_decision_is_not_treated_as_an_attack(self):
        self.assertFalse(Alert({}, 1).is_attack())

    def test_f9_rows_report_the_family_not_the_semantic_verdict(self):
        record = {"decision": "known_attack", "candidate": "DoS Hulk", "model": "F9"}
        alert = Alert(record, 1)
        self.assertEqual(alert.label, "DoS Hulk")
        self.assertEqual(alert.decision, "known_attack")
        self.assertEqual(alert.severity, "attack")

    def test_uncertain_f9_rows_are_surfaced_but_not_called_confirmed(self):
        for decision in ("uncertain", "unknown_candidate"):
            alert = Alert({"decision": decision, "candidate": "DoS Hulk"}, 1)
            self.assertTrue(alert.is_attack(), decision)
            self.assertEqual(alert.severity, "uncertain", decision)

    def test_terminal_benign_rows_are_excluded_even_without_scores(self):
        self.assertFalse(Alert({"decision": "Benign", "candidate": "Benign"}, 1).is_attack())

    def test_identity_ignores_confidence_but_separates_endpoints(self):
        base = {"decision": "PortScan", "source": "a:1", "destination": "b:2", "model": "F9"}
        same = dict(base, confidence=0.9)
        other = dict(base, destination="b:3")
        self.assertEqual(Alert(base, 1).identity(), Alert(same, 2).identity())
        self.assertNotEqual(Alert(base, 1).identity(), Alert(other, 2).identity())


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_benign_and_duplicates_are_counted_not_sent(self):
        stream = write_stream(
            self.dir,
            [
                {"decision": "Benign", "source": "a", "destination": "b"},
                {"decision": "PortScan", "source": "a", "destination": "b"},
                {"decision": "PortScan", "source": "a", "destination": "b"},
                {"decision": "DoS", "source": "c", "destination": "d"},
            ],
        )
        digest = collect(stream, 0, 100)
        self.assertEqual(len(digest.alerts), 2)
        self.assertEqual(digest.skipped_benign, 1)
        self.assertEqual(digest.skipped_duplicate, 1)
        self.assertEqual(digest.counts_by_decision(), {"DoS": 1, "PortScan": 1})

    def test_confirmed_and_uncertain_are_split_in_the_digest(self):
        stream = write_stream(
            self.dir,
            [
                {"decision": "known_attack", "candidate": "DoS Hulk", "source": "a", "destination": "b"},
                {"decision": "uncertain", "candidate": "Bot", "source": "c", "destination": "d"},
            ],
        )
        digest = collect(stream, 0, 100)
        self.assertEqual(len(digest.confirmed), 1)
        self.assertEqual(len(digest.uncertain), 1)

    def test_cursor_prevents_resending_earlier_lines(self):
        stream = write_stream(
            self.dir,
            [
                {"decision": "PortScan", "source": "a", "destination": "b"},
                {"decision": "DoS", "source": "c", "destination": "d"},
            ],
        )
        first = collect(stream, 0, 100)
        self.assertEqual(len(first.alerts), 2)
        second = collect(stream, first.last_line, 100)
        self.assertEqual(second.alerts, [])

    def test_limit_caps_the_digest(self):
        stream = write_stream(
            self.dir,
            [{"decision": "DoS", "source": f"s{i}", "destination": "d"} for i in range(20)],
        )
        digest = collect(stream, 0, 5)
        self.assertEqual(len(digest.alerts), 5)

    def test_malformed_lines_are_skipped_without_raising(self):
        path = self.dir / "stream.jsonl"
        path.write_text('{"decision": "DoS", "source": "a"}\nnot json\n\n', encoding="utf-8")
        digest = collect(path, 0, 100)
        self.assertEqual(len(digest.alerts), 1)

    def test_cursor_roundtrip_and_corrupt_cursor_restarts_at_zero(self):
        state = self.dir / "cursor.json"
        write_cursor(state, 42)
        self.assertEqual(read_cursor(state), 42)
        state.write_text("{ broken", encoding="utf-8")
        self.assertEqual(read_cursor(state), 0)


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_message_headers_mark_the_mail_as_automated(self):
        stream = write_stream(self.dir, [{"decision": "PortScan", "source": "a", "destination": "b"}])
        digest = collect(stream, 0, 100)
        message = build_message(digest, SETTINGS, stream, "[NIDS]")
        self.assertEqual(message["Auto-Submitted"], "auto-generated")
        self.assertEqual(message["X-NIDS-Alert-Count"], "1")
        self.assertEqual(message["X-NIDS-Uncertain-Count"], "0")
        self.assertEqual(message["To"], "soc@test")
        self.assertIn("PortScan", message["Subject"])

    def test_subject_shows_the_family_not_known_attack(self):
        stream = write_stream(
            self.dir,
            [{"decision": "known_attack", "candidate": "DoS Hulk", "source": "a", "destination": "b"}],
        )
        subject = build_message(collect(stream, 0, 100), SETTINGS, stream, "[NIDS]")["Subject"]
        self.assertIn("DoS Hulk", subject)
        self.assertNotIn("known_attack", subject)

    def test_body_states_that_numbers_are_not_thesis_evidence(self):
        stream = write_stream(self.dir, [{"decision": "DoS", "source": "a", "destination": "b"}])
        body = render_body(collect(stream, 0, 100), stream)
        self.assertIn("receipt da hash", body)
        self.assertIn("khong tra loi", body)


class EnvFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_parses_comments_quotes_and_export_prefix(self):
        parsed = parse_env_file(
            "\n".join(
                [
                    "# binh luan",
                    "",
                    "NIDS_SMTP_HOST=smtp.gmail.com",
                    'NIDS_SMTP_USER="me@gmail.com"',
                    "export NIDS_SMTP_PORT=587",
                    "NIDS_SMTP_PASSWORD='abcdefghijklmnop'  # ghi chu",
                    "dong khong hop le",
                ]
            )
        )
        self.assertEqual(parsed["NIDS_SMTP_HOST"], "smtp.gmail.com")
        self.assertEqual(parsed["NIDS_SMTP_USER"], "me@gmail.com")
        self.assertEqual(parsed["NIDS_SMTP_PORT"], "587")
        self.assertEqual(parsed["NIDS_SMTP_PASSWORD"], "abcdefghijklmnop")
        self.assertNotIn("dong khong hop le", parsed)

    def test_env_file_overrides_a_stale_shell_variable(self):
        path = self.dir / ".env"
        path.write_text("NIDS_SMTP_PASSWORD=matmoi1234567890\n", encoding="utf-8")
        with mock.patch.dict("os.environ", {"NIDS_SMTP_PASSWORD": "matcu"}, clear=False):
            merged, sources = resolve_environment(path)
        self.assertEqual(merged["NIDS_SMTP_PASSWORD"], "matmoi1234567890")
        self.assertEqual(sources["NIDS_SMTP_PASSWORD"], ".env")

    def test_missing_env_file_falls_back_to_the_shell(self):
        with mock.patch.dict("os.environ", {"NIDS_SMTP_PASSWORD": "chi-o-shell"}, clear=False):
            merged, sources = resolve_environment(self.dir / "khong-ton-tai")
        self.assertEqual(merged["NIDS_SMTP_PASSWORD"], "chi-o-shell")
        self.assertEqual(sources["NIDS_SMTP_PASSWORD"], "biến môi trường")


class SettingsTests(unittest.TestCase):
    def test_missing_environment_variables_are_reported_by_name(self):
        with self.assertRaises(ConfigurationError) as caught:
            SmtpSettings.from_environment({})
        for name in ("NIDS_SMTP_HOST", "NIDS_ALERT_SENDER", "NIDS_ALERT_RECIPIENTS"):
            self.assertIn(name, str(caught.exception))

    def test_gmail_app_password_spaces_are_stripped(self):
        settings = SmtpSettings.from_environment(
            {
                "NIDS_SMTP_HOST": "smtp.gmail.com",
                "NIDS_SMTP_USER": "me@gmail.com",
                "NIDS_SMTP_PASSWORD": "abcd efgh ijkl mnop",
                "NIDS_ALERT_SENDER": "me@gmail.com",
                "NIDS_ALERT_RECIPIENTS": "me@gmail.com",
            }
        )
        self.assertEqual(settings.password, "abcdefghijklmnop")
        self.assertEqual(settings.warnings(), [])

    def test_surrounding_quotes_and_spaces_are_stripped(self):
        settings = SmtpSettings.from_environment(
            {
                "NIDS_SMTP_HOST": ' "smtp.gmail.com" ',
                "NIDS_ALERT_SENDER": "'me@gmail.com'",
                "NIDS_ALERT_RECIPIENTS": " me@gmail.com ",
            }
        )
        self.assertEqual(settings.host, "smtp.gmail.com")
        self.assertEqual(settings.sender, "me@gmail.com")

    def test_wrong_length_password_is_flagged_before_gmail_rejects_it(self):
        settings = SmtpSettings.from_environment(
            {
                "NIDS_SMTP_HOST": "smtp.gmail.com",
                "NIDS_SMTP_USER": "me@gmail.com",
                "NIDS_SMTP_PASSWORD": "matkhauthuongcuatoi",
                "NIDS_ALERT_SENDER": "me@gmail.com",
                "NIDS_ALERT_RECIPIENTS": "me@gmail.com",
            }
        )
        self.assertTrue(any("16 ký tự" in note for note in settings.warnings()))

    def test_gmail_sender_must_match_the_login_account(self):
        settings = SmtpSettings.from_environment(
            {
                "NIDS_SMTP_HOST": "smtp.gmail.com",
                "NIDS_SMTP_USER": "me@gmail.com",
                "NIDS_SMTP_PASSWORD": "abcdefghijklmnop",
                "NIDS_ALERT_SENDER": "khac@gmail.com",
                "NIDS_ALERT_RECIPIENTS": "me@gmail.com",
            }
        )
        self.assertTrue(any("trùng tài khoản" in note for note in settings.warnings()))

    def test_port_465_is_flagged_for_gmail(self):
        settings = SmtpSettings.from_environment(
            {
                "NIDS_SMTP_HOST": "smtp.gmail.com",
                "NIDS_SMTP_PORT": "465",
                "NIDS_ALERT_SENDER": "me@gmail.com",
                "NIDS_ALERT_RECIPIENTS": "me@gmail.com",
            }
        )
        self.assertTrue(any("587" in note for note in settings.warnings()))

    def test_non_numeric_port_is_rejected_clearly(self):
        with self.assertRaises(ConfigurationError) as caught:
            SmtpSettings.from_environment(
                {
                    "NIDS_SMTP_HOST": "smtp.gmail.com",
                    "NIDS_SMTP_PORT": "587abc",
                    "NIDS_ALERT_SENDER": "me@gmail.com",
                    "NIDS_ALERT_RECIPIENTS": "me@gmail.com",
                }
            )
        self.assertIn("phải là số", str(caught.exception))

    def test_recipients_accept_comma_and_semicolon(self):
        settings = SmtpSettings.from_environment(
            {
                "NIDS_SMTP_HOST": "smtp.test",
                "NIDS_ALERT_SENDER": "nids@test",
                "NIDS_ALERT_RECIPIENTS": "a@test, b@test; c@test",
            }
        )
        self.assertEqual(settings.recipients, ("a@test", "b@test", "c@test"))


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_dry_run_writes_a_receipt_and_never_opens_smtp(self):
        stream = write_stream(self.dir, [{"decision": "PortScan", "source": "a", "destination": "b"}])
        state = self.dir / "cursor.json"
        receipts = self.dir / "receipts"
        code = main([
            "--stream", str(stream),
            "--state", str(state),
            "--receipt-dir", str(receipts),
        ])
        self.assertEqual(code, 0)
        written = list(receipts.glob("receipt-*.json"))
        self.assertEqual(len(written), 1)
        receipt = json.loads(written[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt["mode"], "dry_run")
        self.assertEqual(receipt["alerts_sent"], 1)
        self.assertEqual(read_cursor(state), 1)

    def test_auth_failure_exits_cleanly_and_keeps_the_cursor(self):
        stream = write_stream(self.dir, [{"decision": "PortScan", "source": "a", "destination": "b"}])
        state = self.dir / "cursor.json"
        env = {
            "NIDS_SMTP_HOST": "smtp.gmail.com",
            "NIDS_SMTP_USER": "me@gmail.com",
            "NIDS_SMTP_PASSWORD": "abcdefghijklmnop",
            "NIDS_ALERT_SENDER": "me@gmail.com",
            "NIDS_ALERT_RECIPIENTS": "me@gmail.com",
        }
        failure = smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
        with mock.patch.dict("os.environ", env, clear=False),              mock.patch("scripts.alert_email_notifier.send", side_effect=failure):
            code = main([
                "--stream", str(stream),
                "--state", str(state),
                "--receipt-dir", str(self.dir / "receipts"),
                "--send",
            ])
        self.assertEqual(code, 2)
        self.assertEqual(read_cursor(state), 0, "cursor phai giu nguyen khi gui that bai")

    def test_second_run_over_the_same_stream_sends_nothing(self):
        stream = write_stream(self.dir, [{"decision": "DoS", "source": "a", "destination": "b"}])
        state = self.dir / "cursor.json"
        receipts = self.dir / "receipts"
        argv = ["--stream", str(stream), "--state", str(state), "--receipt-dir", str(receipts)]
        main(argv)
        main(argv)
        self.assertEqual(len(list(receipts.glob("receipt-*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
