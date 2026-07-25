from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class T85LiveAttackWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ubuntu = (
            ROOT / "scripts/ubuntu_t85_live_attacks.sh"
        ).read_text(encoding="utf-8")
        cls.kali = (
            ROOT / "scripts/kali_t85_live_attacks.sh"
        ).read_text(encoding="utf-8")
        cls.windows = (
            ROOT / "scripts/windows_t85_all_services.ps1"
        ).read_text(encoding="utf-8")
        cls.runbook = (
            ROOT / "docs/lab/T8.5-live-attacks.vi.md"
        ).read_text(encoding="utf-8")

    def test_ubuntu_uses_isolated_attack_evidence_and_process(self) -> None:
        self.assertIn(
            'run_log/t8.5/live-attacks/$RUN_ID/$ATTACK_ID',
            self.ubuntu,
        )
        self.assertNotIn("run_log/t8.5/segments/", self.ubuntu)
        self.assertIn('case "$ATTACK_ID" in', self.ubuntu)
        self.assertIn("hping3|ftp-patator", self.ubuntu)
        self.assertIn("dedicated process; flow state starts empty", self.ubuntu)
        self.assertIn('| tee "$DETECTION_LOG"', self.ubuntu)
        self.assertNotIn('| tee -a "$DETECTION_LOG"', self.ubuntu)

    def test_ubuntu_preserves_dpdk_guards_and_rollback(self) -> None:
        for contract in (
            'source "$TOOLCHAIN_ENV"',
            "sensor MAC mismatch",
            "scripts/dpdk_smoke.py apply",
            "scripts/dpdk_smoke.py\" rollback",
            "--mtu 9000",
            "--require-promiscuous",
            "--idle-timeout-ms 0",
        ):
            self.assertIn(contract, self.ubuntu)
        self.assertIn(
            "live evidence already exists; preserve it and use a new --run-id",
            self.ubuntu,
        )

    def test_kali_is_locked_to_the_passive_lab_network(self) -> None:
        for contract in (
            "readonly INTERFACE=eth1",
            "readonly EXPECTED_DRIVER=vmxnet3",
            "SOURCE_CIDR=192.168.252.129/24",
            "readonly TARGET=192.168.252.20",
            "refusing to use %s because it owns a default route",
            'sudo ip address add "$SOURCE_CIDR" dev "$INTERFACE"',
            "if ! has_source_ip; then",
            'ROUTE_LINE="$(ip -4 route get "$TARGET" oif "$INTERFACE"',
            '" src $SOURCE_IP "',
        ):
            self.assertIn(contract, self.kali)

    def test_hping3_is_bounded_to_at_most_100_pps(self) -> None:
        for contract in (
            "COUNT >= 9 && COUNT <= 3000",
            "INTERVAL_US >= 10000 && INTERVAL_US <= 1000000",
            "maximum_packets_per_second",
            "readonly HPING_SOURCE_PORT=44444",
            '-S -p 80 -s "$HPING_SOURCE_PORT" -c "$COUNT" -i "u$INTERVAL_US"',
        ):
            self.assertIn(contract, self.kali)
        self.assertNotIn("--flood", self.kali)

    def test_patator_uses_bounded_invalid_ftp_attempts(self) -> None:
        for contract in (
            "ftp-patator) TOOL_NAME=patator",
            "ATTEMPTS >= 9 && ATTEMPTS <= 100",
            "patator ftp_login",
            'host="$TARGET" port=21 user=FILE0 password=FILE1',
            "Nids-Wrong-%03d!",
            "deterministic_invalid_demo_values",
        ):
            self.assertIn(contract, self.kali)
        self.assertNotIn("Nids-Lab-2026!", self.kali)

    def test_kali_receipt_is_exclusive_and_does_not_claim_classification(self) -> None:
        for contract in (
            'run_log/t8.5/live-attacks/$RUN_ID/$ATTACK',
            'readonly ATTACK_LOG="$KALI_ROOT/attack.log"',
            'readonly RECEIPT="$KALI_ROOT/receipt.json"',
            'open("x", encoding="utf-8", newline="\\n")',
            '"formal_acceptance": False',
            '"isolated_sensor_process_required": True',
            '"model_classification_claimed": False',
            '"route": route_line',
        ):
            self.assertIn(contract, self.kali)
        lowered = self.kali.lower()
        for installer in ("apt install", "apt-get install", "pip install"):
            self.assertNotIn(installer, lowered)

    def test_windows_ftp_responder_matches_patator_target(self) -> None:
        for contract in (
            '[string]$ListenAddress = "192.168.252.20"',
            "[Net.Sockets.TcpListener]::new(",
            "            21",
            '"220 NIDS T8.5 disposable FTP"',
            '"331 Password required"',
            '"530 Login incorrect"',
        ):
            self.assertIn(contract, self.windows)

    def test_runbook_keeps_live_attack_workflow_separate(self) -> None:
        for contract in (
            "run_log/t8.5/live-attacks/<run-id>/<attack>/",
            "bash scripts/ubuntu_t85_live_attacks.sh",
            "--attack-id hping3",
            "--attack-id ftp-patator",
            "bash scripts/kali_t85_live_attacks.sh",
            "--attack hping3",
            "--attack ftp-patator",
            "windows_t85_all_services.ps1",
            "Moi attack dung mot sensor process rieng",
            "Chi `nids_alert` trong",
            "Khong dung `run_log/t8.5/detection.jsonl` cu",
            "Khong dung `run_log/t8.5/segments/<day>/`",
        ):
            self.assertIn(contract, self.runbook)


if __name__ == "__main__":
    unittest.main()
