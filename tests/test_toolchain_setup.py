import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "toolchain.lock.json"
SETUP_PATH = ROOT / "scripts" / "setup_toolchain_ubuntu.sh"
VERIFIER_PATH = ROOT / "scripts" / "verify_toolchain.py"
SAMPLE_RECEIPT = ROOT / "tests" / "fixtures" / "toolchain-receipt.sample.json"
SPEC = importlib.util.spec_from_file_location("verify_toolchain", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_toolchain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_toolchain)


class ToolchainLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))

    def test_lock_schema_is_valid(self):
        self.assertEqual([], verify_toolchain.validate_lock(self.lock))

    def test_release_versions_and_checksums_are_locked(self):
        self.assertEqual("25.11.2", self.lock["dpdk"]["version"])
        self.assertEqual(
            "418bfe3212640ee95a1cb10af6ed360cad2387686fe2721f8a3a9cd02d5ef4f2",
            self.lock["dpdk"]["sha256"],
        )
        self.assertEqual("a017927310a8a545b6bad8ade8a70c85", self.lock["dpdk"]["official_md5"])
        self.assertEqual("1.27.1", self.lock["onnxruntime"]["version"])
        self.assertEqual(
            "25b1ef1fea1acd210d63f8f24dc870ad6e077795ce1f54876252c6d3803c15af",
            self.lock["onnxruntime"]["sha256"],
        )

    def test_downloads_are_https_and_install_is_user_scoped(self):
        self.assertTrue(self.lock["dpdk"]["url"].startswith("https://"))
        self.assertTrue(self.lock["onnxruntime"]["url"].startswith("https://"))
        self.assertFalse(self.lock["installation"]["system_prefix_used"])
        self.assertTrue(self.lock["installation"]["default_root"].startswith("~/"))

    def test_dpdk_apps_and_build_options_fingerprint_are_locked(self):
        dpdk = self.lock["dpdk"]
        self.assertIn("-Denable_apps=test-pmd,dumpcap", dpdk["meson_options"])
        self.assertEqual(["dpdk-testpmd", "dpdk-dumpcap"], dpdk["required_executables"])
        self.assertEqual(
            dpdk["build_options_sha256"],
            verify_toolchain.build_options_fingerprint(dpdk["meson_options"]),
        )

    def test_lock_rejects_stale_build_options_fingerprint(self):
        changed = json.loads(json.dumps(self.lock))
        changed["dpdk"]["meson_options"].remove("-Denable_apps=test-pmd,dumpcap")
        errors = verify_toolchain.validate_lock(changed)
        self.assertIn("dpdk.build_options_sha256 must match canonical meson_options", errors)
        self.assertIn("dpdk.meson_options must enable test-pmd and dumpcap", errors)


class ToolchainReceiptTests(unittest.TestCase):
    def load_sample(self):
        return json.loads(SAMPLE_RECEIPT.read_text(encoding="utf-8"))

    def test_sample_receipt_matches_lock(self):
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            [],
            verify_toolchain.validate_receipt(
                self.load_sample(),
                lock,
                verify_toolchain.sha256_file(LOCK_PATH),
            ),
        )

    def test_sample_is_explicitly_not_acceptance_evidence(self):
        receipt = self.load_sample()
        self.assertIs(receipt["sample"], True)
        self.assertIn("not acceptance evidence", receipt["sample_notice"])

    def test_inconsistent_pass_status_is_rejected(self):
        receipt = self.load_sample()
        receipt["checks"][0]["status"] = "failed"
        errors = verify_toolchain.validate_receipt(receipt)
        self.assertIn("receipt status must match aggregate check status", errors)

    def test_missing_dumpcap_or_stale_fingerprint_is_rejected(self):
        receipt = self.load_sample()
        receipt["checks"] = [
            check for check in receipt["checks"] if check["name"] != "dpdk.dumpcap_linkage"
        ]
        receipt["lock"]["dpdk_build_options_sha256"] = "0" * 64
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        errors = verify_toolchain.validate_receipt(receipt, lock)
        self.assertIn("receipt must check the DPDK marker and both app linkages", errors)
        self.assertIn("receipt DPDK build-options fingerprint does not match lock", errors)

    def test_validate_cli_accepts_sample(self):
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER_PATH),
                "validate",
                "--input",
                str(SAMPLE_RECEIPT),
                "--lock",
                str(LOCK_PATH),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("valid receipt", result.stdout)

    def test_dpdk_app_check_inspects_linkage_without_running_eal(self):
        ldd_result = {
            "available": True,
            "return_code": 0,
            "stdout": "libdpdk.so => /toolchain/lib/libdpdk.so",
            "stderr": "",
        }
        with (
            mock.patch.object(verify_toolchain.shutil, "which", return_value=str(VERIFIER_PATH)),
            mock.patch.object(verify_toolchain.os, "access", return_value=True),
            mock.patch.object(verify_toolchain, "run_command", return_value=ldd_result) as runner,
        ):
            for executable in verify_toolchain.REQUIRED_DPDK_EXECUTABLES:
                with self.subTest(executable=executable):
                    passed, observed, _ = verify_toolchain.inspect_dynamic_executable(
                        executable,
                        VERIFIER_PATH.parent,
                    )
                    self.assertTrue(passed)
                    self.assertEqual([], observed["missing_dependencies"])
        self.assertEqual(2, runner.call_count)
        runner.assert_has_calls([mock.call(("ldd", str(VERIFIER_PATH)))] * 2)

    def test_testpmd_check_rejects_missing_dynamic_dependency(self):
        ldd_result = {
            "available": True,
            "return_code": 0,
            "stdout": "librte_eal.so.26 => not found",
            "stderr": "",
        }
        with (
            mock.patch.object(verify_toolchain.shutil, "which", return_value=str(VERIFIER_PATH)),
            mock.patch.object(verify_toolchain.os, "access", return_value=True),
            mock.patch.object(verify_toolchain, "run_command", return_value=ldd_result),
        ):
            passed, observed, _ = verify_toolchain.inspect_dynamic_executable("dpdk-dumpcap")
        self.assertFalse(passed)
        self.assertEqual(["librte_eal.so.26 => not found"], observed["missing_dependencies"])

    def test_dpdk_app_outside_locked_prefix_is_rejected_before_ldd(self):
        with (
            mock.patch.object(verify_toolchain.shutil, "which", return_value=str(VERIFIER_PATH)),
            mock.patch.object(verify_toolchain.os, "access", return_value=True),
            mock.patch.object(verify_toolchain, "run_command") as runner,
        ):
            passed, _, detail = verify_toolchain.inspect_dynamic_executable(
                "dpdk-dumpcap",
                ROOT / "outside/bin",
            )
        self.assertFalse(passed)
        self.assertIn("outside locked directory", detail)
        runner.assert_not_called()


class ToolchainSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = SETUP_PATH.read_text(encoding="utf-8")
        cls.cmake = (ROOT / "tests" / "toolchain_smoke" / "CMakeLists.txt").read_text(encoding="utf-8")
        cls.main = (ROOT / "tests" / "toolchain_smoke" / "main.cpp").read_text(encoding="utf-8")

    def test_installer_has_explicit_modes_and_root_guard(self):
        for expected in (
            "--dry-run",
            "--install",
            "--verify",
            "--upgrade-dpdk-apps",
            "--rollback-dpdk",
            "run as a normal user",
        ):
            self.assertIn(expected, self.setup)
        self.assertIn("sudo apt-get", self.setup)
        self.assertIn("$HOME/.local/nids-toolchain", self.setup)

    def test_upgrade_is_transactional_reversible_and_refuses_silent_repair(self):
        for expected in (
            'DESTDIR="$destdir" meson install',
            'mv -T -- "$installed" "$staging"',
            'verify_dpdk_prefix "$staging"',
            'atomic_exchange "$DPDK_PREFIX" "$staging"',
            ".nids-dpdk-backup-",
            ".nids-dpdk-operation.lock",
            "existing DPDK prefix is not valid for this lock; run --upgrade-dpdk-apps explicitly",
            "rollback_dpdk",
            "check_target 0",
        ):
            self.assertIn(expected, self.setup)
        self.assertNotIn('rm -rf -- "$backup"', self.setup)

    def test_upgrade_rejects_unsafe_paths_and_collisions(self):
        for expected in (
            "NIDS_TOOLCHAIN_ROOT must be an absolute path",
            "NIDS_TOOLCHAIN_ROOT must remain under HOME",
            "refusing symlinked toolchain path",
            "DPDK staging collision",
            "DPDK backup collision",
            "rollback backup must be a direct child",
        ):
            self.assertIn(expected, self.setup)

    def test_installer_does_not_mutate_dpdk_runtime_configuration(self):
        forbidden_actions = (
            "dpdk-devbind",
            "modprobe ",
            "update-grub",
            "grub-mkconfig",
            "/sys/kernel/mm/hugepages",
            "nr_hugepages",
        )
        for action in forbidden_actions:
            self.assertNotIn(action, self.setup)

    def test_dpdk_build_is_resource_bounded_and_driver_scoped(self):
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        options = lock["dpdk"]["meson_options"]
        self.assertIn("-Dtests=false", options)
        self.assertIn("-Denable_apps=test-pmd,dumpcap", options)
        drivers = next(option for option in options if option.startswith("-Denable_drivers="))
        for driver in ("net/intel/e1000", "net/vmxnet3", "net/pcap", "net/ring"):
            self.assertIn(driver, drivers)
        self.assertEqual(2, lock["installation"]["default_jobs"])

    def test_smoke_project_requires_cxx20_and_both_runtimes(self):
        self.assertIn("cxx_std_20", self.cmake)
        self.assertIn("libdpdk", self.cmake)
        self.assertIn("onnxruntime", self.cmake)
        self.assertIn("rte_version()", self.main)
        self.assertIn("Ort::Env", self.main)

    def test_verifier_does_not_start_dpdk_apps(self):
        verifier = VERIFIER_PATH.read_text(encoding="utf-8")
        for executable in ("dpdk-testpmd", "dpdk-dumpcap"):
            self.assertNotIn(f'(\"{executable}\", \"--version\")', verifier)
        self.assertIn('for executable_name in lock["dpdk"]["required_executables"]', verifier)


if __name__ == "__main__":
    unittest.main()
