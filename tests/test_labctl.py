from __future__ import annotations

import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/labctl.py"
SPEC = importlib.util.spec_from_file_location("labctl", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
labctl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = labctl
SPEC.loader.exec_module(labctl)


class LabctlFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.root = ROOT / f".labctl-test-{uuid.uuid4().hex}"
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.vmrun = self.root / "vmrun.exe"
        self.ssh = self.root / "ssh.exe"
        self.vmrun.touch()
        self.ssh.touch()
        self.vmx_paths = {
            role: self.root / f"{role}.vmx" for role in labctl.ROLES
        }
        for path in self.vmx_paths.values():
            path.touch()

    def document(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "vmrun": str(self.vmrun),
            "ssh": str(self.ssh),
            "timeouts": {
                "discovery_seconds": 7,
                "connect_seconds": 3,
                "command_seconds": 11,
            },
            "hosts": {
                role: {
                    "alias": f"nids-{role}",
                    "vmx": str(self.vmx_paths[role]),
                }
                for role in labctl.ROLES
            },
        }

    def write_config(
        self, document: dict[str, object] | None = None
    ) -> Path:
        path = self.root / "hosts.json"
        path.write_text(
            json.dumps(self.document() if document is None else document),
            encoding="utf-8",
        )
        return path

    def config(self) -> labctl.LabConfig:
        return labctl.load_config(self.write_config())

    def configure_nat_vmx(self, role: str, mac: str) -> None:
        self.vmx_paths[role].write_text(
            "\n".join(
                [
                    'ethernet0.connectionType = "nat"',
                    'ethernet0.addressType = "generated"',
                    f'ethernet0.generatedAddress = "{mac}"',
                    'ethernet1.connectionType = "custom"',
                    'ethernet1.vnet = "VMnet1"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    def write_leases(self, text: str) -> Path:
        path = self.root / "vmnetdhcp.leases"
        path.write_text(text, encoding="utf-8")
        return path

    @staticmethod
    def completed(
        arguments: list[str],
        return_code: int,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            arguments,
            return_code,
            stdout,
            stderr,
        )


class LabctlConfigTest(LabctlFixture):
    def test_valid_config_is_loaded(self) -> None:
        config = self.config()
        self.assertEqual(tuple(config.hosts), labctl.ROLES)
        self.assertEqual("nids-ubuntu", config.hosts["ubuntu"].alias)
        self.assertEqual(7, config.discovery_timeout_seconds)

    def test_duplicate_key_and_unknown_field_are_rejected(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            labctl.load_config(duplicate)

        document = self.document()
        document["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "fields mismatch"):
            labctl.load_config(self.write_config(document))

    def test_option_looking_and_duplicate_aliases_are_rejected(self) -> None:
        document = self.document()
        hosts = document["hosts"]
        assert isinstance(hosts, dict)
        hosts["kali"]["alias"] = "-oProxyCommand=bad"
        with self.assertRaisesRegex(ValueError, "alias is invalid"):
            labctl.load_config(self.write_config(document))

        document = self.document()
        hosts = document["hosts"]
        assert isinstance(hosts, dict)
        hosts["windows"]["alias"] = hosts["ubuntu"]["alias"]
        with self.assertRaisesRegex(ValueError, "duplicate SSH alias"):
            labctl.load_config(self.write_config(document))


class LabctlExecutionTest(LabctlFixture):
    def test_exec_resolves_dhcp_address_and_uses_strict_noninteractive_ssh(
        self,
    ) -> None:
        config = self.config()
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(
            arguments: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append((arguments, kwargs))
            if len(calls) == 1:
                return self.completed(arguments, 0, "192.168.100.117\n")
            return self.completed(arguments, 0, "ubuntu-host\n")

        with mock.patch.object(labctl.subprocess, "run", side_effect=run):
            result = labctl.execute_role(config, "ubuntu", "hostname")

        self.assertEqual("ok", result["status"])
        self.assertEqual("192.168.100.117", result["address"])
        self.assertEqual("vmrun", result["discovery_method"])
        self.assertIsNone(result["user_confirmation"])
        self.assertEqual(
            [
                str(self.vmrun),
                "getGuestIPAddress",
                str(self.vmx_paths["ubuntu"]),
                "-wait",
            ],
            calls[0][0],
        )
        self.assertEqual(
            [
                str(self.ssh),
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "NumberOfPasswordPrompts=0",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=3",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "HostName=192.168.100.117",
                "-o",
                "HostKeyAlias=nids-ubuntu",
                "--",
                "nids-ubuntu",
                "hostname",
            ],
            calls[1][0],
        )
        self.assertIs(subprocess.DEVNULL, calls[1][1]["stdin"])
        self.assertIs(False, calls[1][1]["shell"])

    def test_remote_and_transport_failures_are_distinct(self) -> None:
        config = self.config()
        for return_code, expected in ((7, "remote_error"), (255, "ssh_error")):
            with self.subTest(return_code=return_code):
                responses = [
                    self.completed([], 0, "192.168.100.9\n"),
                    self.completed([], return_code, "", "failure"),
                ]
                with mock.patch.object(
                    labctl.subprocess, "run", side_effect=responses
                ):
                    result = labctl.execute_role(
                        config, "kali", "false"
                    )
                self.assertEqual(expected, result["status"])
                self.assertEqual(return_code, result["exit_code"])
                self.assertIsNone(result["user_confirmation"])

    def test_timeout_is_structured(self) -> None:
        config = self.config()
        timeout = subprocess.TimeoutExpired(
            cmd=["ssh"],
            timeout=2,
            output="partial",
            stderr="deadline",
        )
        with mock.patch.object(
            labctl.subprocess,
            "run",
            side_effect=[
                self.completed([], 0, "192.168.100.20\n"),
                timeout,
            ],
        ):
            result = labctl.execute_role(
                config, "windows", "hostname", timeout_seconds=2
            )
        self.assertEqual("timeout", result["status"])
        self.assertTrue(result["timed_out"])
        self.assertEqual("partial", result["stdout"])
        self.assertEqual("deadline", result["stderr"])
        self.assertIsNone(result["user_confirmation"])

    def test_invalid_discovery_output_never_reaches_ssh(self) -> None:
        config = self.config()
        with mock.patch.object(
            labctl.subprocess,
            "run",
            return_value=self.completed([], 0, "not-an-address\n"),
        ) as run:
            result = labctl.execute_role(config, "ubuntu", "hostname")
        self.assertEqual("discovery_error", result["status"])
        self.assertEqual(1, run.call_count)
        self.assertEqual(
            "dhcp_discovery_unavailable",
            result["user_confirmation"]["reason"],
        )
        self.assertIn("nids-ubuntu", result["user_confirmation"]["question"])

    def test_discovery_failure_requests_confirmation_without_prompting_stdin(
        self,
    ) -> None:
        config = self.config()
        with mock.patch.object(
            labctl.subprocess,
            "run",
            return_value=self.completed(
                [],
                1,
                "",
                "vmrun was unable to start",
            ),
        ):
            result = labctl.execute_role(config, "kali", "hostname")

        self.assertEqual("discovery_error", result["status"])
        self.assertEqual(
            {
                "required": True,
                "reason": "dhcp_discovery_unavailable",
                "question": (
                    "Bạn đã mở VMware Workstation và bật VM "
                    "kali (nids-kali) chưa?"
                ),
            },
            result["user_confirmation"],
        )

    def test_vmrun_failure_uses_newest_active_nat_dhcp_lease(self) -> None:
        config = self.config()
        self.configure_nat_vmx("ubuntu", "00:0C:29:AA:BB:CC")
        leases = self.write_leases(
            """
lease 192.168.100.31 {
  starts 0 2020/01/01 00:00:00;
  ends 0 2020/01/01 00:30:00;
  hardware ethernet 00:0c:29:aa:bb:cc;
}
lease 192.168.100.44 {
  starts 0 2025/01/01 00:00:00;
  ends never;
  hardware ethernet 00:0c:29:aa:bb:cc;
}
"""
        )
        responses = [
            self.completed([], -1, "", "vmrun was unable to start"),
            self.completed([], 0, "ubuntu-host\n"),
        ]
        with (
            mock.patch.object(
                labctl, "DEFAULT_VMWARE_LEASE_PATHS", (leases,)
            ),
            mock.patch.object(
                labctl.subprocess, "run", side_effect=responses
            ) as run,
        ):
            result = labctl.execute_role(config, "ubuntu", "hostname")

        self.assertEqual("ok", result["status"])
        self.assertEqual("192.168.100.44", result["address"])
        self.assertEqual(
            "vmware_dhcp_lease", result["discovery_method"]
        )
        self.assertEqual(str(leases), result["discovery_source"])
        self.assertIsNone(result["user_confirmation"])
        self.assertIn("HostName=192.168.100.44", run.call_args_list[1].args[0])

    def test_active_nat_dhcp_lease_is_preferred_over_vmrun_address(self) -> None:
        config = self.config()
        self.configure_nat_vmx("ubuntu", "00:0C:29:AA:BB:CC")
        leases = self.write_leases(
            """
lease 192.168.100.44 {
  starts 0 2025/01/01 00:00:00;
  ends never;
  hardware ethernet 00:0c:29:aa:bb:cc;
}
"""
        )
        responses = [
            self.completed([], 0, "192.168.252.128\n"),
            self.completed([], 0, "ubuntu-host\n"),
        ]
        with (
            mock.patch.object(
                labctl, "DEFAULT_VMWARE_LEASE_PATHS", (leases,)
            ),
            mock.patch.object(
                labctl.subprocess, "run", side_effect=responses
            ) as run,
        ):
            result = labctl.execute_role(config, "ubuntu", "hostname")

        self.assertEqual("ok", result["status"])
        self.assertEqual("192.168.100.44", result["address"])
        self.assertEqual(
            "vmware_dhcp_lease", result["discovery_method"]
        )
        self.assertIn("HostName=192.168.100.44", run.call_args_list[1].args[0])

    def test_vmrun_address_is_used_when_lease_read_has_local_error(
        self,
    ) -> None:
        config = self.config()
        responses = [
            self.completed([], 0, "192.168.100.88\n"),
            self.completed([], 0, "ubuntu-host\n"),
        ]
        with (
            mock.patch.object(
                labctl,
                "vmware_dhcp_address",
                side_effect=PermissionError("leases denied"),
            ),
            mock.patch.object(
                labctl.subprocess, "run", side_effect=responses
            ),
        ):
            result = labctl.execute_role(config, "ubuntu", "hostname")

        self.assertEqual("ok", result["status"])
        self.assertEqual("192.168.100.88", result["address"])
        self.assertEqual("vmrun", result["discovery_method"])
        self.assertIsNone(result["user_confirmation"])

    def test_lease_local_error_does_not_request_vmware_confirmation(
        self,
    ) -> None:
        config = self.config()
        with (
            mock.patch.object(
                labctl,
                "vmware_dhcp_address",
                side_effect=PermissionError("leases denied"),
            ),
            mock.patch.object(
                labctl.subprocess,
                "run",
                return_value=self.completed(
                    [], -1, "", "vmrun was unable to start"
                ),
            ) as run,
        ):
            result = labctl.execute_role(config, "kali", "hostname")

        self.assertEqual("local_error", result["status"])
        self.assertEqual(1, run.call_count)
        self.assertIsNone(result["address"])
        self.assertIsNone(result["user_confirmation"])
        self.assertIn("leases denied", result["error"])

    def test_expired_dhcp_lease_does_not_hide_discovery_failure(self) -> None:
        config = self.config()
        self.configure_nat_vmx("kali", "00:0C:29:01:02:03")
        leases = self.write_leases(
            """
lease 192.168.100.50 {
  starts 0 2020/01/01 00:00:00;
  ends 0 2020/01/01 00:30:00;
  hardware ethernet 00:0c:29:01:02:03;
}
"""
        )
        with (
            mock.patch.object(
                labctl, "DEFAULT_VMWARE_LEASE_PATHS", (leases,)
            ),
            mock.patch.object(
                labctl.subprocess,
                "run",
                return_value=self.completed(
                    [], -1, "", "vmrun was unable to start"
                ),
            ) as run,
        ):
            result = labctl.execute_role(config, "kali", "hostname")

        self.assertEqual("discovery_error", result["status"])
        self.assertEqual(1, run.call_count)
        self.assertIsNone(result["address"])
        self.assertTrue(result["user_confirmation"]["required"])
        self.assertIn("no active VMware DHCP lease", result["error"])

    def test_dhcp_lease_helper_rejects_naive_comparison_time(self) -> None:
        self.configure_nat_vmx("windows", "00:0C:29:10:20:30")
        leases = self.write_leases(
            """
lease 192.168.100.60 {
  starts 0 2025/01/01 00:00:00;
  ends never;
  hardware ethernet 00:0c:29:10:20:30;
}
"""
        )
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            labctl.vmware_dhcp_address(
                self.vmx_paths["windows"],
                lease_paths=(leases,),
                now=dt.datetime(2026, 7, 28),
            )

    def test_powered_off_vm_is_classified(self) -> None:
        config = self.config()
        with mock.patch.object(
            labctl.subprocess,
            "run",
            return_value=self.completed(
                [],
                4_294_967_295,
                "Error: The virtual machine is not powered on\n",
            ),
        ):
            result = labctl.execute_role(config, "windows", "hostname")
        self.assertEqual("powered_off", result["status"])
        self.assertEqual(-1, result["exit_code"])
        self.assertEqual(
            "virtual machine is not powered on",
            result["error"],
        )
        self.assertIsNone(result["user_confirmation"])


class LabctlStatusAndCliTest(LabctlFixture):
    def test_status_runs_all_roles_and_reports_partial(self) -> None:
        config = self.config()

        def execute(
            config_value: labctl.LabConfig,
            role: str,
            command: str,
            timeout_seconds: int | None,
        ) -> dict[str, object]:
            del config_value, timeout_seconds
            return {
                "role": role,
                "command": command,
                "status": "ok" if role != "windows" else "ssh_error",
            }

        with mock.patch.object(labctl, "execute_role", side_effect=execute):
            document = labctl.status_document(config)
        self.assertEqual("partial", document["status"])
        self.assertFalse(document["user_confirmation_required"])
        self.assertEqual(set(labctl.ROLES), set(document["hosts"]))

    def test_status_aggregates_discovery_confirmation(self) -> None:
        config = self.config()

        def execute(
            config_value: labctl.LabConfig,
            role: str,
            command: str,
            timeout_seconds: int | None,
        ) -> dict[str, object]:
            del config_value, command, timeout_seconds
            prompt = (
                labctl.discovery_confirmation(role, config.hosts[role])
                if role == "ubuntu"
                else None
            )
            return {
                "role": role,
                "status": "discovery_error" if prompt else "ok",
                "user_confirmation": prompt,
            }

        with mock.patch.object(labctl, "execute_role", side_effect=execute):
            document = labctl.status_document(config)

        self.assertEqual("partial", document["status"])
        self.assertTrue(document["user_confirmation_required"])
        self.assertTrue(
            document["hosts"]["ubuntu"]["user_confirmation"]["required"]
        )

    def test_cli_emits_one_canonical_json_document(self) -> None:
        config_path = self.write_config()
        result = {
            "role": "ubuntu",
            "alias": "nids-ubuntu",
            "address": "192.168.100.33",
            "command": "hostname",
            "stage": "ssh",
            "status": "ok",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1.25,
            "stdout": "ubuntu\n",
            "stderr": "",
            "error": None,
        }
        output = io.StringIO()
        with (
            mock.patch.object(labctl, "execute_role", return_value=result),
            contextlib.redirect_stdout(output),
        ):
            exit_code = labctl.main(
                [
                    "--config",
                    str(config_path),
                    "exec",
                    "ubuntu",
                    "hostname",
                ]
            )
        rendered = output.getvalue()
        self.assertEqual(0, exit_code)
        self.assertEqual(1, rendered.count("\n"))
        self.assertEqual("exec", json.loads(rendered)["operation"])
        self.assertLess(rendered.index('"alias"'), rendered.index('"command"'))

    def test_confirmation_json_is_safe_on_windows_cp1252_stdout(self) -> None:
        buffer = io.BytesIO()
        output = io.TextIOWrapper(buffer, encoding="cp1252")
        question = (
            "Bạn đã mở VMware Workstation và bật VM "
            "ubuntu (nids-ubuntu) chưa?"
        )
        labctl.emit_json(
            {
                "status": "discovery_error",
                "user_confirmation": {
                    "required": True,
                    "question": question,
                },
            },
            output,
        )
        output.flush()
        rendered = buffer.getvalue()
        output.detach()

        self.assertTrue(rendered.isascii())
        self.assertEqual(
            question,
            json.loads(rendered.decode("ascii"))["user_confirmation"][
                "question"
            ],
        )

    def test_cli_config_error_is_json_and_exit_two(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = labctl.main(
                [
                    "--config",
                    str(self.root / "missing.json"),
                    "status",
                ]
            )
        self.assertEqual(2, exit_code)
        self.assertEqual(
            "invalid_config_or_input",
            json.loads(output.getvalue())["status"],
        )


if __name__ == "__main__":
    unittest.main()
