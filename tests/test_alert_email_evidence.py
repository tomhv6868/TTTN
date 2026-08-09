import json
import unittest
from pathlib import Path

from scripts.build_alert_email_evidence import build, redact_recipient, render_markdown


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_JSON = ROOT / "run_log/full-flow-v1/thesis-evidence/alert-email-20260809.json"


class RedactionTests(unittest.TestCase):
    def test_mailbox_is_removed_but_domain_is_kept(self):
        self.assertEqual(redact_recipient("nguoi@vidu.com"), "<redacted>@vidu.com")

    def test_address_without_domain_is_fully_redacted(self):
        self.assertEqual(redact_recipient("khonghopley"), "<redacted>")


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = build()

    def test_no_recipient_mailbox_or_secret_reaches_the_evidence(self):
        blob = json.dumps(self.evidence, ensure_ascii=False)
        self.assertNotIn("NIDS_SMTP_PASSWORD=", blob)
        for run in self.evidence["runs"]:
            for address in run["recipients"]:
                self.assertTrue(address.startswith("<redacted>"), address)

    def test_receipts_are_summarised_with_sent_and_dry_run_split(self):
        summary = self.evidence["summary"]
        self.assertEqual(
            summary["total_runs"], summary["sent_runs"] + summary["dry_run_runs"]
        )
        self.assertGreaterEqual(summary["sent_runs"], 1, "phai co it nhat 1 lan gui that")

    def test_every_run_records_a_body_hash_so_the_mail_can_be_verified(self):
        for run in self.evidence["runs"]:
            self.assertEqual(len(run["body_sha256"]), 64, run["receipt"])

    def test_the_mail_is_declared_a_notification_not_a_measurement(self):
        limits = " ".join(self.evidence["scope_limits"])
        self.assertIn("not a measurement", limits)
        self.assertIn("not detection latency", limits.replace("must not be presented as ", "not "))

    def test_sources_are_hashed_and_partition_sealed(self):
        self.assertTrue(self.evidence["supporting_sources"])
        for source in self.evidence["supporting_sources"]:
            self.assertEqual(len(source["sha256"]), 64)
            self.assertTrue((ROOT / source["path"]).exists())
        self.assertEqual(self.evidence["test_partition"]["state"], "sealed")

    def test_published_json_matches_a_fresh_build(self):
        published = json.loads(EVIDENCE_JSON.read_text(encoding="utf-8"))
        fresh = dict(self.evidence)
        published.pop("generated_at_utc")
        fresh.pop("generated_at_utc")
        self.assertEqual(published, fresh)

    def test_markdown_states_the_candidate_versus_decision_trap(self):
        markdown = render_markdown(self.evidence)
        self.assertIn("`candidate`", markdown)
        self.assertIn("known_attack", markdown)
        self.assertIn("không phải phép đo", markdown)


if __name__ == "__main__":
    unittest.main()
