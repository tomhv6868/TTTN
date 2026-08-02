from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "t91-live-campaign.json"
KALI_PATH = ROOT / "scripts" / "kali_t91_live_campaign.sh"
UBUNTU_PATH = ROOT / "scripts" / "ubuntu_t91_live_sensor.sh"
WINDOWS_PATH = ROOT / "scripts" / "windows_t91_live_target.ps1"
SUPPORTED_CASES = {
    "ftp-patator": ("FTP-Patator", "FTP-Bruteforce"),
    "portscan": ("PortScan", "PortScan"),
}


class T91LiveCampaignContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cls.kali = KALI_PATH.read_text(encoding="utf-8")
        cls.ubuntu = UBUNTU_PATH.read_text(encoding="utf-8")
        cls.windows = WINDOWS_PATH.read_text(encoding="utf-8")

    def embedded_python(self, script: str, marker: str) -> str:
        blocks = re.findall(
            r"<<'PY'\n(.*?)\nPY(?:\n|$)",
            script,
            flags=re.DOTALL,
        )
        matches = [block for block in blocks if marker in block]
        self.assertEqual(
            1,
            len(matches),
            f"expected one embedded Python block containing {marker!r}",
        )
        return matches[0] + "\n"

    def run_embedded_python(self, source: str, *arguments: object) -> str:
        completed = subprocess.run(
            [sys.executable, "-B", "-", *(str(value) for value in arguments)],
            input=source,
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            0,
            completed.returncode,
            "embedded Python failed\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}",
        )
        return completed.stdout

    def test_config_lists_exactly_fourteen_cicids_cases_without_web_aggregate(
        self,
    ) -> None:
        cases = self.config["cases"]
        self.assertEqual(14, len(cases))
        labels = {case["scenario_label"] for case in cases}
        self.assertEqual(
            {
                "Bot",
                "DDoS",
                "DoS GoldenEye",
                "DoS Hulk",
                "DoS Slowhttptest",
                "DoS slowloris",
                "FTP-Patator",
                "Heartbleed",
                "Infiltration",
                "PortScan",
                "SSH-Patator",
                "Web Attack \u2013 Brute Force",
                "Web Attack \u2013 Sql Injection",
                "Web Attack \u2013 XSS",
            },
            labels,
        )
        self.assertNotIn("web-aggregate", {case["id"] for case in cases})
        supported = {
            case["id"]: (
                case["scenario_label"],
                case["expected_model_family"],
            )
            for case in cases
            if case["status"] == "supported"
        }
        self.assertEqual(SUPPORTED_CASES, supported)
        self.assertNotEqual(
            supported["ftp-patator"][0],
            supported["ftp-patator"][1],
        )
        for case in cases:
            self.assertNotIn("label", case)
            self.assertNotIn("expected_family", case)

    def test_config_v2_model_families_match_locked_bundle_taxonomy(self) -> None:
        self.assertEqual("2.0.0", self.config["schema_version"])
        self.assertNotIn("accepted_live_labels", self.config["model"])
        acceptance = self.config["acceptance"]
        self.assertIs(
            True,
            acceptance["require_non_eof_exact_model_family_alert"],
        )
        self.assertNotIn("require_non_eof_exact_family_alert", acceptance)

        manifest_path = (
            ROOT
            / self.config["model"]["bundle_directory"]
            / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        class_order = set(manifest["class_order"])
        self.assertTrue(
            {
                model_family
                for _, model_family in SUPPORTED_CASES.values()
            }.issubset(class_order)
        )

    def test_contract_consumers_require_v2_taxonomy(self) -> None:
        self.assertGreaterEqual(
            self.kali.count(
                'document.get("schema_version") != "2.0.0"'
            ),
            2,
        )
        self.assertIn(
            'document.get("schema_version") != "2.0.0"',
            self.ubuntu,
        )
        self.assertIn(
            '$contract.schema_version -cne "2.0.0"',
            self.windows,
        )
        for script in (self.kali, self.ubuntu, self.windows):
            self.assertIn("scenario_label", script)
            self.assertIn("expected_model_family", script)
        self.assertIn(
            'CASE_ENV="$(load_case_env)" || exit $?',
            self.kali,
        )
        self.assertEqual(
            2,
            self.kali.count(
                'CONTRACT_ENV="$(load_contract_env)" || exit $?'
            ),
        )
        self.assertIn(
            'CONTRACT_ENV="$(contract_env)" || exit $?',
            self.ubuntu,
        )

    def test_config_hashes_match_current_locked_artifacts(self) -> None:
        expected = {
            "resource_config_sha256": hashlib.sha256(
                (ROOT / self.config["dpdk"]["resource_config"]).read_bytes()
            ).hexdigest(),
            "bundle_manifest_sha256": hashlib.sha256(
                (
                    ROOT
                    / self.config["model"]["bundle_directory"]
                    / "manifest.json"
                ).read_bytes()
            ).hexdigest(),
            "native_parity_reference_sha256": hashlib.sha256(
                (
                    ROOT
                    / "run_log/full-flow-v1/model/native-parity-reference.json"
                ).read_bytes()
            ).hexdigest(),
        }
        self.assertEqual(
            expected["resource_config_sha256"],
            self.config["dpdk"]["resource_config_sha256"],
        )
        self.assertEqual(
            expected["bundle_manifest_sha256"],
            self.config["model"]["bundle_manifest_sha256"],
        )
        self.assertEqual(
            expected["native_parity_reference_sha256"],
            self.config["model"]["native_parity_reference_sha256"],
        )

    def test_config_does_not_persist_kali_dhcp_or_data_source_ip(self) -> None:
        rendered = json.dumps(self.config, sort_keys=True)
        self.assertIn('"target_ip": "192.168.252.20"', rendered)
        self.assertNotIn("192.168.252.10", rendered)
        self.assertNotIn("192.168.252.129", rendered)
        self.assertEqual("VMnet1", self.config["topology"]["data_network"]["name"])
        self.assertEqual("VMnet8", self.config["topology"]["management_network"]["name"])

    def test_kali_init_discovers_source_and_writes_exclusive_contract(self) -> None:
        for text in (
            "ip -4 route get \"$TARGET_IP\" oif \"$KALI_INTERFACE\"",
            "src ([0-9.]+)",
            "ATTEMPT_ID=\"t91-${CASE_ID}-${STAMP}-${NONCE}\"",
            "RUN_TOKEN=\"rt-${STAMP}-${NONCE}\"",
            '"terminal_live_run_contract"',
            '"source_ip": source_ip',
            '"run_token": run_token',
            '"scenario_label": scenario_label',
            '"expected_model_family": expected_model_family',
            '"require_non_eof_exact_model_family_alert"',
            'open("x", encoding="utf-8", newline="\\n")',
        ):
            self.assertIn(text, self.kali)
        self.assertNotIn("SOURCE_CIDR=192.168.252", self.kali)
        self.assertNotIn("readonly SOURCE_IP=192.168.252", self.kali)

    def test_embedded_generators_preserve_v2_taxonomy_and_contract_hash(
        self,
    ) -> None:
        contract_source = self.embedded_python(
            self.kali,
            '"kind": "terminal_live_run_contract"',
        )
        kali_receipt_source = self.embedded_python(
            self.kali,
            '"kind": "kali_sender_receipt"',
        )
        ubuntu_receipt_source = self.embedded_python(
            self.ubuntu,
            '"kind": "ubuntu_sensor_receipt"',
        )

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            temporary_root = Path(temporary_directory)
            config = json.loads(json.dumps(self.config))
            config["acceptance"][
                "require_non_eof_exact_model_family_alert"
            ] = False
            config_path = temporary_root / "campaign.json"
            config_path.write_text(
                json.dumps(config, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            config_sha256 = hashlib.sha256(config_path.read_bytes()).hexdigest()
            cases = {case["id"]: case for case in config["cases"]}

            for case_id, expected in SUPPORTED_CASES.items():
                scenario_label, expected_model_family = expected
                case = cases[case_id]
                case_root = temporary_root / case_id
                case_root.mkdir()
                contract_path = case_root / "contract.json"
                stdout = self.run_embedded_python(
                    contract_source,
                    contract_path,
                    config_path,
                    config_sha256,
                    case_id,
                    case["scenario_label"],
                    case["expected_model_family"],
                    f"t91-{case_id}-test",
                    f"rt-{case_id}-test",
                    "192.168.252.10",
                    config["topology"]["windows"]["target_ip"],
                    config["topology"]["kali"]["interface"],
                    "192.168.252.20 dev eth1 src 192.168.252.10",
                    config["bounds"]["sender_timeout_seconds"],
                    config["bounds"]["ftp_wrong_passwords"],
                    config["bounds"]["ftp_threads"],
                    config["target"]["ftp_username"],
                    config["bounds"]["portscan_ports"],
                    config["bounds"]["portscan_max_rate"],
                    config["bounds"]["portscan_max_retries"],
                    config["bounds"]["portscan_host_timeout_seconds"],
                )
                init_result = json.loads(stdout)
                contract = json.loads(contract_path.read_text(encoding="utf-8"))
                contract_sha256 = hashlib.sha256(
                    contract_path.read_bytes()
                ).hexdigest()

                self.assertEqual("2.0.0", contract["schema_version"])
                self.assertEqual("terminal_live_run_contract", contract["kind"])
                self.assertEqual(case_id, contract["case_id"])
                self.assertEqual(scenario_label, contract["scenario_label"])
                self.assertEqual(
                    expected_model_family,
                    contract["expected_model_family"],
                )
                self.assertNotIn("label", contract)
                self.assertNotIn("expected_family", contract)
                self.assertNotIn("accepted_live_labels", contract["model"])
                self.assertIs(
                    False,
                    contract["acceptance"][
                        "require_non_eof_exact_model_family_alert"
                    ],
                )
                self.assertNotIn(
                    "require_non_eof_exact_family_alert",
                    contract["acceptance"],
                )
                self.assertEqual(
                    config["acceptance"]["minimum_terminal_flows"][case_id],
                    contract["acceptance"]["minimum_terminal_flows"],
                )
                self.assertEqual("2.0.0", init_result["schema_version"])
                self.assertEqual(str(contract_path.resolve()), init_result["contract"])

                sender_log = case_root / "sender.log"
                sender_log.write_text(
                    "bounded sender output\n",
                    encoding="utf-8",
                    newline="\n",
                )
                sender_log_sha256 = hashlib.sha256(
                    sender_log.read_bytes()
                ).hexdigest()
                kali_receipt_path = case_root / "kali-receipt.json"
                self.run_embedded_python(
                    kali_receipt_source,
                    kali_receipt_path,
                    contract_path,
                    "passed",
                    0,
                    "2026-07-29T00:00:00Z",
                    "2026-07-29T00:00:01Z",
                    sender_log,
                    sender_log_sha256,
                    f"bounded-{case_id}",
                )
                kali_receipt = json.loads(
                    kali_receipt_path.read_text(encoding="utf-8")
                )

                sensor_log = case_root / "sensor.jsonl"
                sensor_log.write_text(
                    '{"type":"nids_terminal_live_summary"}\n',
                    encoding="utf-8",
                    newline="\n",
                )
                ready_path = case_root / "ready.json"
                summary_path = case_root / "summary.json"
                alerts_path = case_root / "alerts.jsonl"
                ready_path.write_text("{}\n", encoding="utf-8", newline="\n")
                summary_path.write_text("{}\n", encoding="utf-8", newline="\n")
                alerts_path.write_text("", encoding="utf-8", newline="\n")
                ubuntu_receipt_path = case_root / "ubuntu-receipt.json"
                self.run_embedded_python(
                    ubuntu_receipt_source,
                    ubuntu_receipt_path,
                    contract_path,
                    contract_sha256,
                    0,
                    sensor_log,
                    ready_path,
                    summary_path,
                    alerts_path,
                )
                ubuntu_receipt = json.loads(
                    ubuntu_receipt_path.read_text(encoding="utf-8")
                )
                self.assertEqual(
                    {
                        "path": str(alerts_path.resolve()),
                        "sha256": hashlib.sha256(b"").hexdigest(),
                    },
                    ubuntu_receipt["alert_log"],
                )
                self.assertEqual(
                    "bounded_runtime",
                    ubuntu_receipt["termination_cause"],
                )

                for receipt in (kali_receipt, ubuntu_receipt):
                    self.assertEqual("2.0.0", receipt["schema_version"])
                    self.assertEqual(
                        scenario_label,
                        receipt["scenario_label"],
                    )
                    self.assertEqual(
                        expected_model_family,
                        receipt["expected_model_family"],
                    )
                    self.assertEqual(
                        contract_sha256,
                        receipt["run_contract_sha256"],
                    )
                    self.assertNotIn("label", receipt)
                    self.assertNotIn("expected_family", receipt)

    def test_kali_sender_bounds_ftp_and_portscan_tools(self) -> None:
        for text in (
            "timeout --signal=TERM --kill-after=2s \"${SENDER_TIMEOUT_SECONDS}s\"",
            "patator ftp_login",
            'host="$TARGET_IP" port=21 user=FILE0 password=FILE1',
            '0="$USERS" 1="$PASSWORDS" persistent=0 -t "$FTP_THREADS"',
            "-x ignore,reset:code=530",
            "Nids-Wrong-%03d!",
            "timeout --signal=TERM --kill-after=2s",
            "sudo -n nmap -n -Pn -sS -p \"$PORTSCAN_PORTS\"",
            "nmap -n -Pn -sS -p \"$PORTSCAN_PORTS\"",
            "--max-rate \"$PORTSCAN_MAX_RATE\"",
            "--max-retries \"$PORTSCAN_MAX_RETRIES\"",
            "--host-timeout \"${PORTSCAN_HOST_TIMEOUT_SECONDS}s\"",
            "-e \"$KALI_INTERFACE\" -S \"$SOURCE_IP\" \"$TARGET_IP\"",
        ):
            self.assertIn(text, self.kali)
        for installer in ("apt install", "apt-get install", "pip install"):
            self.assertNotIn(installer, self.kali.lower())

    def test_ubuntu_sensor_uses_terminal_binary_ready_handshake_and_rollback(
        self,
    ) -> None:
        for text in (
            'source "$TOOLCHAIN_ENV"',
            "cmake --build --preset ubuntu-release --target nids_t91_terminal_live",
            "scripts/dpdk_smoke.py\" preflight",
            "scripts/dpdk_smoke.py\" apply",
            "scripts/dpdk_smoke.py\" rollback",
            "setsid timeout --signal=TERM",
            '--kill-after="${KILL_AFTER_SECONDS}s"',
            "KILL_AFTER_SECONDS=3",
            'LIFECYCLE_ARGUMENTS=(--lifecycle-mode "$LIFECYCLE_MODE_CLI")',
            '--shutdown-grace-ms "$SHUTDOWN_GRACE_MS"',
            "sensor group remains alive; rollback withheld",
            "heartbeat_is_fresh",
            "verified_sensor_group",
            'flock -w "$RECOVERY_WAIT_SECONDS" 8',
            '"$BINARY"',
            "--bundle \"$PROJECT_ROOT/$BUNDLE_DIR\"",
            "--manifest-sha256 \"$MANIFEST_SHA256\"",
            "--attempt-id \"$ATTEMPT_ID\" --run-token \"$RUN_TOKEN\"",
            "--run-contract-sha256 \"$CONTRACT_SHA256\"",
            "nids_terminal_live_ready",
            "nids_terminal_live_summary",
            '"kind": "ubuntu_sensor_receipt"',
            '"alert_log": {',
            '"termination_cause": termination_cause',
        ):
            self.assertIn(text, self.ubuntu)
        self.assertNotIn("nids_dpdk_live", self.ubuntu)
        self.assertNotIn("terminal_flow_export", self.ubuntu)

    def test_ubuntu_sensor_group_recovery_is_fail_closed(self) -> None:
        self.assertIn(
            'kill "-$signal_name" -- "-$pgid"',
            self.ubuntu,
        )
        self.assertNotIn(
            'kill "-$signal_name" "$pgid"',
            self.ubuntu,
        )
        self.assertIn(
            "signal_sensor_group KILL",
            self.ubuntu,
        )
        self.assertIn(
            "matching orphan sensor group(s) remain",
            self.ubuntu,
        )

        recover_start = self.ubuntu.index("    recover)")
        recover_end = self.ubuntu.index("    *)", recover_start)
        recover = self.ubuntu[recover_start:recover_end]
        lock_index = recover.index(
            'flock -w "$RECOVERY_WAIT_SECONDS" 8'
        )
        quiescence_index = recover.index(
            "ensure_sensor_quiescent",
            lock_index,
        )
        rollback_index = recover.index(
            'scripts/dpdk_smoke.py" rollback',
            quiescence_index,
        )
        self.assertLess(lock_index, quiescence_index)
        self.assertLess(quiescence_index, rollback_index)
        self.assertIn(
            "refusing rollback while sensor state is unsafe",
            recover,
        )

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "process-group regression requires Linux /proc",
    )
    def test_ubuntu_sensor_group_signal_and_orphan_scanner(self) -> None:
        signal_start = self.ubuntu.index("signal_sensor_group() {")
        signal_end = self.ubuntu.index(
            "\n}\n\nwait_sensor_group_exit()",
            signal_start,
        )
        signal_source = self.ubuntu[signal_start : signal_end + 3]
        leader_code = (
            "import signal, subprocess, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "child = subprocess.Popen(\n"
            "    [sys.executable, '-B', '-c', "
            "'import time; time.sleep(60)'],\n"
            "    preexec_fn=lambda: signal.signal("
            "signal.SIGTERM, signal.SIG_DFL),\n"
            ")\n"
            "print(child.pid, flush=True)\n"
            "while child.poll() is None:\n"
            "    time.sleep(0.05)\n"
        )
        leader = subprocess.Popen(
            [sys.executable, "-B", "-c", leader_code],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        leader_pgid = os.getpgid(leader.pid)
        try:
            self.assertIsNotNone(leader.stdout)
            child_line = leader.stdout.readline().strip()
            self.assertRegex(child_line, r"^[1-9][0-9]*$")
            signaled = subprocess.run(
                [
                    "bash",
                    "-c",
                    signal_source
                    + '\nsignal_sensor_group TERM "$1"\n',
                    "signal-regression",
                    str(leader_pgid),
                ],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(
                0,
                signaled.returncode,
                f"group signal failed: {signaled.stderr}",
            )
            leader.wait(timeout=5)
            self.assertIsNotNone(
                leader.returncode,
                "TERM reached only the group leader, not its child",
            )
        finally:
            if leader.poll() is None:
                try:
                    os.killpg(leader_pgid, 9)
                except ProcessLookupError:
                    pass
                leader.wait(timeout=5)
            if leader.stdout is not None:
                leader.stdout.close()
            if leader.stderr is not None:
                leader.stderr.close()

        scanner = self.embedded_python(
            self.ubuntu,
            "NIDS_T91_EXPECTED_PGID",
        )
        identity = {
            "NIDS_T91_ATTEMPT_ID": "scanner-attempt",
            "NIDS_T91_RUN_TOKEN": "scanner-token",
            "NIDS_T91_CONTRACT_SHA256": "a" * 64,
        }
        orphan = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-c",
                "import time; time.sleep(60)",
                "--attempt-id",
                identity["NIDS_T91_ATTEMPT_ID"],
                "--run-token",
                identity["NIDS_T91_RUN_TOKEN"],
                "--run-contract-sha256",
                identity["NIDS_T91_CONTRACT_SHA256"],
            ],
            start_new_session=True,
        )
        orphan_pgid = os.getpgid(orphan.pid)
        try:
            scanner_env = {**os.environ, **identity}
            scanner_env["NIDS_T91_EXPECTED_PGID"] = ""
            discovered = subprocess.run(
                [sys.executable, "-B", "-"],
                input=scanner,
                text=True,
                capture_output=True,
                env=scanner_env,
                timeout=5,
                check=False,
            )
            self.assertEqual(
                0,
                discovered.returncode,
                f"orphan scan failed: {discovered.stderr}",
            )
            self.assertEqual(str(orphan_pgid), discovered.stdout.strip())

            scanner_env["NIDS_T91_EXPECTED_PGID"] = str(orphan_pgid)
            verified = subprocess.run(
                [sys.executable, "-B", "-"],
                input=scanner,
                text=True,
                capture_output=True,
                env=scanner_env,
                timeout=5,
                check=False,
            )
            self.assertEqual(
                0,
                verified.returncode,
                f"recorded PGID verification failed: {verified.stderr}",
            )
            self.assertEqual(str(orphan_pgid), verified.stdout.strip())

            scanner_env["NIDS_T91_EXPECTED_PGID"] = str(os.getpgrp())
            rejected = subprocess.run(
                [sys.executable, "-B", "-"],
                input=scanner,
                text=True,
                capture_output=True,
                env=scanner_env,
                timeout=5,
                check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("identity mismatch", rejected.stderr)
        finally:
            try:
                os.killpg(orphan_pgid, 9)
            except ProcessLookupError:
                pass
            orphan.wait(timeout=5)

    def test_windows_target_uses_system_scheduled_tasks(self) -> None:
        for text in (
            '[ValidateSet("Prepare", "Status", "Rollback", "Serve")]',
            'Join-Path $env:ProgramData "NIDS-T91"',
            "Protect-StagingRoot -Path $staging.root",
            "New-ScheduledTaskPrincipal",
            '-UserId "SYSTEM"',
            "-LogonType ServiceAccount",
            "-RunLevel Highest",
            "Register-ScheduledTask",
            "Start-ScheduledTask -TaskName $taskNames.serve",
            "New-ScheduledTaskTrigger -Once",
            "New-ScheduledTaskTrigger -AtStartup",
            "-StartWhenAvailable",
            "-MultipleInstances IgnoreNew",
        ):
            self.assertIn(text, self.windows)
        self.assertNotIn("Start-Process", self.windows)
        self.assertNotIn('"Watchdog"', self.windows)
        state_index = self.windows.index(
            "Write-NewJson -Path $localPaths.state"
        )
        rollback_task_index = self.windows.index(
            "Register-ScheduledTask `\n        -TaskName $taskNames.rollback"
        )
        first_mutation_index = min(
            self.windows.index("Stop-Service -Name FTPSVC -Force"),
            self.windows.index("New-NetFirewallRule -Name $ruleName"),
        )
        self.assertLess(state_index, first_mutation_index)
        self.assertLess(rollback_task_index, first_mutation_index)

    def test_windows_ready_proves_exact_responder_identity(self) -> None:
        for text in (
            "New-NetFirewallRule -Name $ruleName",
            "-LocalPort ([string]$contract.target.firewall_tcp_ports)",
            "-RemoteAddress ([string]$contract.topology.source_ip)",
            "[Net.Sockets.TcpListener]::new(",
            '$ExpectedBanner = "220 NIDS T9.1 disposable FTP"',
            '"530 Login incorrect"',
            '"230 Login successful"',
            "$resetAfterResponse = $true",
            "[Net.Sockets.LingerOption]::new($true, 0)",
            "$client.ReceiveTimeout = 2000",
            "$stream.ReadTimeout = 2000",
            "$observedBanner = $reader.ReadLine()",
            "$observedBanner -cne $script:ExpectedBanner",
            "Get-CimInstance `\n                -ClassName Win32_Process",
            "Get-NetTCPConnection -LocalPort 21 -State Listen",
            "OwningProcess",
            "Get-NetFirewallAddressFilter -AssociatedNetFirewallRule",
            "Get-NetFirewallPortFilter -AssociatedNetFirewallRule",
            "process_identity_exact",
            "listener_owned",
            "responder_task = $taskNames.serve",
            "rollback_task = $taskNames.rollback",
            "listener_process_id = $readiness.responder.process_id",
            "observed_banner = $readiness.ftp_probe.observed_banner",
            "Stop-Service -Name FTPSVC -Force",
            "ftp_service_was_running",
            "TCP/21 is already occupied",
            "FTP responder failed exact readiness checks",
        ):
            self.assertIn(text, self.windows)

    def test_windows_status_and_rollback_are_fail_safe_and_immutable(self) -> None:
        for text in (
            '"orphaned_unsafe"',
            "Acquire-LifecycleLock -Path $LocalPaths.lock",
            "[IO.FileShare]::None",
            "[IO.FileMode]::CreateNew",
            "Remove-NetFirewallRule -Name $RuleName",
            "Stop-ScheduledTask -TaskName $TaskNames.serve",
            "Unregister-ScheduledTask",
            "Start-Service -Name FTPSVC",
            "ftp_service_restored",
            "Write-NewJson -Path $LocalPaths.rollback",
            "windows_target_rollback_attempt",
            "Existing rollback receipt does not match this contract",
        ):
            self.assertIn(text, self.windows)
        self.assertNotIn("Write-ReplaceJson", self.windows)
        self.assertNotIn("$TtlSeconds", self.windows)

    def test_artifacts_stay_under_full_flow_namespace(self) -> None:
        self.assertEqual(
            "run_log/full-flow-v1/live",
            self.config["artifact_root"],
        )
        for text in (self.kali, self.ubuntu, self.windows):
            self.assertNotIn("run_log/t8.5", text)
            self.assertNotIn("run_log/t0.4", text)


if __name__ == "__main__":
    unittest.main()
