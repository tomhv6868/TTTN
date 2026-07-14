import argparse
import contextlib
import copy
import importlib.util
import json
import shutil
import struct
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "dpdk-smoke.example.json"
DPDK_PATH = ROOT / "scripts" / "dpdk_smoke.py"
TRAFFIC_PATH = ROOT / "scripts" / "kali_smoke_traffic.py"
VERIFY_PATH = ROOT / "scripts" / "verify_dpdk_smoke.py"
FIXTURES = ROOT / "tests" / "fixtures"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dpdk_smoke = load_module("dpdk_smoke", DPDK_PATH)
kali_traffic = load_module("kali_smoke_traffic", TRAFFIC_PATH)
verify_smoke = load_module("verify_dpdk_smoke", VERIFY_PATH)


@contextlib.contextmanager
def workspace_temporary_directory():
    path = ROOT / "tests" / f".tmp-dpdk-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


class DpdkConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    def test_example_config_is_valid_and_matches_approved_topology(self):
        self.assertEqual([], dpdk_smoke.validate_config(self.config))
        self.assertEqual("VMnet8", self.config["topology"]["management_network"]["name"])
        self.assertEqual("NAT", self.config["topology"]["management_network"]["mode"])
        self.assertEqual("VMnet1", self.config["topology"]["data_network"]["name"])
        self.assertEqual("192.168.252.0/24", self.config["topology"]["data_network"]["subnet"])
        self.assertEqual("vmxnet3", self.config["ubuntu"]["expected_data_driver"])
        self.assertEqual(128, self.config["runtime"]["hugepage_count"])
        self.assertEqual(256, self.config["runtime"]["dpdk_memory_mb"])
        self.assertEqual("nids-t03", self.config["runtime"]["file_prefix"])
        self.assertEqual("always", self.config["runtime"]["huge_unlink"])
        self.assertEqual(8192, self.config["runtime"]["total_num_mbufs"])
        self.assertEqual(
            self.config["runtime"]["hugepage_count"] * self.config["runtime"]["hugepage_size_kb"],
            self.config["runtime"]["dpdk_memory_mb"] * 1024,
        )

    def test_hugepage_and_eal_memory_pair_is_locked(self):
        changed = copy.deepcopy(self.config)
        changed["runtime"]["hugepage_count"] = 192
        self.assertTrue(dpdk_smoke.validate_config(changed))
        changed = copy.deepcopy(self.config)
        changed["runtime"]["dpdk_memory_mb"] = 128
        self.assertTrue(dpdk_smoke.validate_config(changed))

    def test_testpmd_memory_safety_options_are_locked(self):
        for key, value in (
            ("file_prefix", "other-prefix"),
            ("huge_unlink", "never"),
            ("total_num_mbufs", 155456),
        ):
            changed = copy.deepcopy(self.config)
            changed["runtime"][key] = value
            self.assertTrue(dpdk_smoke.validate_config(changed), key)

    def test_safety_policy_cannot_be_weakened(self):
        for key, unsafe in (
            ("require_iommu", False),
            ("allow_no_iommu", True),
            ("preserve_management_connectivity", False),
            ("persistent_boot_changes", True),
        ):
            changed = copy.deepcopy(self.config)
            changed["safety"][key] = unsafe
            self.assertTrue(dpdk_smoke.validate_config(changed), key)

    def test_bridge_whitelist_is_exact(self):
        changed = copy.deepcopy(self.config)
        changed["safety"]["iommu_group_policy"] = "any_shared_group"
        self.assertTrue(dpdk_smoke.validate_config(changed))
        for key in ("vendor", "device", "class_base_subclass", "driver"):
            changed = copy.deepcopy(self.config)
            changed["safety"]["allowed_iommu_bridge_companion"][key] = "anything"
            self.assertTrue(dpdk_smoke.validate_config(changed), key)


class DpdkPreflightTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        self.discovery = json.loads((FIXTURES / "dpdk-discovery.sample.json").read_text(encoding="utf-8"))

    def failures(self, discovery=None):
        checks = dpdk_smoke.evaluate_preflight(self.config, discovery or self.discovery, "ens37")
        return {item["name"] for item in checks if item["status"] == "failed"}

    def with_companion(self, count=1, **overrides):
        discovery = copy.deepcopy(self.discovery)
        data = discovery["interfaces"]["ens37"]
        for function in range(count):
            companion = {
                "pci_address": f"0000:00:15.{function}",
                "class_code": "060400",
                "class_base_subclass": "0604",
                "vendor": "15ad",
                "device": "07a0",
                "driver": "pcieport",
                "network_interfaces": [],
            }
            companion.update(overrides)
            data["iommu_group_devices"].insert(function, companion["pci_address"])
            data["iommu_group_device_details"].insert(function, companion)
        return discovery

    def test_valid_host_passes_every_gate(self):
        self.assertEqual(set(), self.failures())

    def test_default_route_data_nic_is_rejected(self):
        discovery = copy.deepcopy(self.discovery)
        discovery["interfaces"]["ens37"]["has_default_route"] = True
        self.assertIn("data.no_default_route", self.failures(discovery))

    def test_wrong_data_driver_is_rejected(self):
        discovery = copy.deepcopy(self.discovery)
        discovery["interfaces"]["ens37"]["driver"] = "e1000"
        self.assertIn("data.driver", self.failures(discovery))

    def test_missing_iommu_group_is_rejected(self):
        discovery = copy.deepcopy(self.discovery)
        discovery["interfaces"]["ens37"]["iommu_group"] = None
        discovery["interfaces"]["ens37"]["iommu_group_devices"] = []
        self.assertTrue({"iommu.available", "iommu.group_policy"} <= self.failures(discovery))

    def test_approved_vmware_bridge_companion_is_accepted(self):
        self.assertEqual(set(), self.failures(self.with_companion(count=8)))

    def test_shared_group_without_complete_device_facts_is_rejected(self):
        discovery = copy.deepcopy(self.discovery)
        discovery["interfaces"]["ens37"]["iommu_group_devices"].append("0000:03:00.1")
        self.assertIn("iommu.group_policy", self.failures(discovery))

    def test_non_bridge_companion_is_rejected(self):
        discovery = self.with_companion(class_base_subclass="0106", class_code="010601")
        self.assertIn("iommu.group_policy", self.failures(discovery))

    def test_bridge_with_wrong_driver_is_rejected(self):
        discovery = self.with_companion(driver="vfio-pci")
        self.assertIn("iommu.group_policy", self.failures(discovery))

    def test_bridge_exposing_network_interface_is_rejected(self):
        discovery = self.with_companion(network_interfaces=["ens99"])
        self.assertIn("iommu.group_policy", self.failures(discovery))

    def test_management_pci_in_data_group_is_rejected(self):
        discovery = copy.deepcopy(self.discovery)
        management_pci = discovery["interfaces"]["ens33"]["pci_address"]
        discovery["interfaces"]["ens37"]["iommu_group_devices"].append(management_pci)
        self.assertIn("iommu.group_policy", self.failures(discovery))

    def test_unreachable_management_gateway_is_rejected(self):
        discovery = copy.deepcopy(self.discovery)
        discovery["management_ping"]["passed"] = False
        self.assertIn("management.ping", self.failures(discovery))


class TestpmdParsingTests(unittest.TestCase):
    def test_latest_nonzero_counter_set_is_collected(self):
        output = """
        RX-packets: 0 RX-missed: 0 RX-errors: 0 RX-nombuf: 0
        TX-packets: 0 TX-errors: 0
        RX-packets: 1200 RX-missed: 2 RX-errors: 1 RX-nombuf: 3
        TX-packets: 1199 TX-errors: 4
        """
        counters = dpdk_smoke.parse_testpmd_counters(output)
        self.assertEqual(1200, counters["rx_packets"])
        self.assertEqual(1199, counters["tx_packets"])
        self.assertEqual(2, counters["rx_missed"])
        self.assertEqual(4, counters["tx_errors"])

    def test_command_separates_eal_and_testpmd_memory_options(self):
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        state = {
            "configuration": config,
            "toolchain": {"testpmd": "/opt/dpdk/bin/dpdk-testpmd"},
            "original": {"pci_address": "0000:03:00.0"},
        }
        command = dpdk_smoke.build_testpmd_command(state)
        separator = command.index("--")
        self.assertLess(command.index("--file-prefix=nids-t03"), separator)
        self.assertLess(command.index("--huge-unlink=always"), separator)
        self.assertGreater(command.index("--total-num-mbufs=8192"), separator)
        self.assertIn("-m", command[:separator])
        self.assertEqual("256", command[command.index("-m") + 1])


class DpdkPrefixCleanupTests(unittest.TestCase):
    def test_cleanup_removes_only_exact_smoke_prefix_artifacts(self):
        with workspace_temporary_directory() as base:
            mountpoint = base / "hugepages"
            runtime_root = base / "run" / "dpdk"
            mountpoint.mkdir()
            runtime_root.mkdir(parents=True)
            for name in ("nids-t03map_0", "nids-t03map_127"):
                (mountpoint / name).write_bytes(b"owned")
            unrelated_hugepage = mountpoint / "anothermap_0"
            unrelated_hugepage.write_bytes(b"keep")
            smoke_runtime = runtime_root / "nids-t03"
            smoke_runtime.mkdir()
            (smoke_runtime / "config").write_bytes(b"owned")
            unrelated_runtime = runtime_root / "another"
            unrelated_runtime.mkdir()
            (unrelated_runtime / "config").write_bytes(b"keep")

            result = dpdk_smoke.cleanup_dpdk_prefix_artifacts(
                "nids-t03", mountpoint, runtime_root
            )

            self.assertEqual(2, result["hugepage_files_removed"])
            self.assertTrue(result["runtime_path_removed"])
            self.assertFalse(smoke_runtime.exists())
            self.assertTrue(unrelated_hugepage.exists())
            self.assertTrue(unrelated_runtime.exists())

    def test_apply_guard_rejects_stale_prefix_artifact(self):
        with workspace_temporary_directory() as base:
            mountpoint = base / "hugepages"
            runtime_root = base / "run" / "dpdk"
            mountpoint.mkdir()
            runtime_root.mkdir(parents=True)
            (mountpoint / "nids-t03map_5").write_bytes(b"stale")
            with self.assertRaisesRegex(RuntimeError, "stale DPDK artifacts"):
                dpdk_smoke.ensure_dpdk_prefix_clean(
                    "nids-t03", mountpoint, runtime_root
                )

    def test_cleanup_rejects_unapproved_prefix(self):
        with workspace_temporary_directory() as base:
            with self.assertRaises(ValueError):
                dpdk_smoke.cleanup_dpdk_prefix_artifacts(
                    "other", base / "hugepages", base / "run"
                )


class PciDriverControlTests(unittest.TestCase):
    def test_interface_lookup_waits_for_predictable_name_after_rebind(self):
        with (
            mock.patch.object(dpdk_smoke, "interfaces_for_pci", side_effect=[["eth0"], ["ens160"]]),
            mock.patch.object(dpdk_smoke.time, "monotonic", side_effect=[0.0, 0.1, 0.2]),
            mock.patch.object(dpdk_smoke.time, "sleep"),
        ):
            name = dpdk_smoke.find_interface_for_pci(
                "0000:03:00.0", timeout=1.0, preferred_name="ens160"
            )

        self.assertEqual("ens160", name)

    def test_approved_bridge_is_unbound_and_verified(self):
        with (
            mock.patch.object(dpdk_smoke, "driver_for_pci", side_effect=["pcieport", None]),
            mock.patch.object(dpdk_smoke, "write_pci_driver_control") as writer,
        ):
            dpdk_smoke.unbind_pci_driver("0000:00:15.0", "pcieport")
        writer.assert_called_once()
        self.assertEqual("0000:00:15.0", writer.call_args.args[1])

    def test_unbound_bridge_is_rebound_and_verified(self):
        with (
            mock.patch.object(dpdk_smoke, "driver_for_pci", side_effect=[None, "pcieport"]),
            mock.patch.object(dpdk_smoke, "write_pci_driver_control") as writer,
        ):
            dpdk_smoke.bind_pci_kernel_driver("0000:00:15.0", "pcieport")
        writer.assert_called_once()
        self.assertEqual("0000:00:15.0", writer.call_args.args[1])

    def test_unbind_rejects_unexpected_current_driver(self):
        with mock.patch.object(dpdk_smoke, "driver_for_pci", return_value="vfio-pci"):
            with self.assertRaises(RuntimeError):
                dpdk_smoke.unbind_pci_driver("0000:00:15.0", "pcieport")

    def test_restore_attempts_every_bridge_after_one_failure(self):
        devices = [
            {"pci_address": "0000:00:15.0", "driver": "pcieport"},
            {"pci_address": "0000:00:15.1", "driver": "pcieport"},
        ]
        with mock.patch.object(
            dpdk_smoke,
            "bind_pci_kernel_driver",
            side_effect=[RuntimeError("first failed"), None],
        ) as binder:
            with self.assertRaisesRegex(RuntimeError, "first failed"):
                dpdk_smoke.restore_pci_drivers(devices)
        self.assertEqual(2, binder.call_count)

    def test_address_restore_accepts_concurrent_ipv6_autoconfiguration(self):
        address = "fe80::50d:198f:e000:7aa9/64"
        with mock.patch.object(
            dpdk_smoke,
            "run",
            side_effect=[
                {"return_code": 0, "stdout": "", "stderr": ""},
                {
                    "return_code": 2,
                    "stdout": "",
                    "stderr": "Error: ipv6: address already assigned.",
                },
                {
                    "return_code": 0,
                    "stdout": f"2: ens160 inet6 {address} scope link",
                    "stderr": "",
                },
            ],
        ) as runner:
            dpdk_smoke.restore_interface_address("ens160", address)

        self.assertEqual(3, runner.call_count)

    def test_address_restore_keeps_real_add_failure_fatal(self):
        address = "192.168.252.128/24"
        with mock.patch.object(
            dpdk_smoke,
            "run",
            side_effect=[
                {"return_code": 0, "stdout": "", "stderr": ""},
                {
                    "return_code": 2,
                    "stdout": "",
                    "stderr": "RTNETLINK answers: Operation not permitted",
                },
                {"return_code": 0, "stdout": "", "stderr": ""},
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "Operation not permitted"):
                dpdk_smoke.restore_interface_address("ens160", address)


class KaliTrafficTests(unittest.TestCase):
    def test_frame_contains_valid_ethernet_ipv4_udp_packet(self):
        frame = kali_traffic.build_udp_frame(
            "00:0c:29:44:55:66",
            "00:0c:29:aa:bb:cc",
            "192.168.252.10",
            "192.168.252.20",
            42,
        )
        self.assertEqual(bytes.fromhex("000c29aabbcc"), frame[:6])
        self.assertEqual(bytes.fromhex("000c29445566"), frame[6:12])
        self.assertEqual(0x0800, struct.unpack("!H", frame[12:14])[0])
        ipv4 = frame[14:34]
        self.assertEqual(0, kali_traffic.internet_checksum(ipv4))
        self.assertEqual(17, ipv4[9])
        source_port, destination_port = struct.unpack("!HH", frame[34:38])
        self.assertEqual((40000, 9000), (source_port, destination_port))
        self.assertGreaterEqual(len(frame), 60)

    def test_invalid_mac_is_rejected(self):
        with self.assertRaises(ValueError):
            kali_traffic.parse_mac("not-a-mac")


class DpdkReceiptTests(unittest.TestCase):
    @staticmethod
    def load(name):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def sample_documents(self):
        return {
            "preflight": self.load("dpdk-preflight.sample.json"),
            "run": self.load("dpdk-run.sample.json"),
            "traffic": self.load("dpdk-traffic.sample.json"),
            "rollback": self.load("dpdk-rollback.sample.json"),
        }

    def test_sample_receipts_pass_acceptance(self):
        checks, overlap = verify_smoke.validate_receipts(**self.sample_documents())
        self.assertGreaterEqual(overlap, 55)
        self.assertTrue(all(item["status"] == "passed" for item in checks), checks)

    def test_preflight_embedded_safety_policy_is_validated(self):
        preflight = self.load("dpdk-preflight.sample.json")
        self.assertEqual([], dpdk_smoke.validate_preflight(preflight))
        preflight["configuration"]["safety"]["iommu_group_policy"] = "any_shared_group"
        errors = dpdk_smoke.validate_preflight(preflight)
        self.assertTrue(any("embedded configuration" in error for error in errors), errors)

    def test_zero_rx_is_rejected(self):
        documents = self.sample_documents()
        documents["run"]["counters"]["rx_packets"] = 0
        checks, _ = verify_smoke.validate_receipts(**documents)
        failures = {item["name"] for item in checks if item["status"] == "failed"}
        self.assertIn("run.rx_packets", failures)

    def test_missing_huge_unlink_is_rejected(self):
        documents = self.sample_documents()
        documents["run"]["command"].remove("--huge-unlink=always")
        checks, _ = verify_smoke.validate_receipts(**documents)
        failures = {item["name"] for item in checks if item["status"] == "failed"}
        self.assertIn("run.memory_options", failures)

    def test_missing_prefix_cleanup_is_rejected(self):
        documents = self.sample_documents()
        documents["rollback"]["checks"] = [
            item
            for item in documents["rollback"]["checks"]
            if item["name"] != "dpdk_prefix.cleaned"
        ]
        checks, _ = verify_smoke.validate_receipts(**documents)
        failures = {item["name"] for item in checks if item["status"] == "failed"}
        self.assertIn("rollback.actions", failures)

    def test_aggregate_command_writes_sample_artifact(self):
        output = ROOT / "tests" / "t0.3-receipt.test.json"
        output.unlink(missing_ok=True)
        arguments = argparse.Namespace(
            preflight=FIXTURES / "dpdk-preflight.sample.json",
            run=FIXTURES / "dpdk-run.sample.json",
            traffic=FIXTURES / "dpdk-traffic.sample.json",
            rollback=FIXTURES / "dpdk-rollback.sample.json",
            output=output,
            force=False,
        )
        try:
            self.assertEqual(0, verify_smoke.command_verify(arguments))
            self.assertEqual("passed", json.loads(output.read_text(encoding="utf-8"))["status"])
        finally:
            output.unlink(missing_ok=True)


class DpdkSafetyStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = DPDK_PATH.read_text(encoding="utf-8")

    def test_no_unsafe_or_persistent_binding_path_exists(self):
        forbidden = (
            "enable_unsafe_noiommu_mode",
            "uio_pci_generic",
            "igb_uio",
            "update-grub",
            "grub-mkconfig",
            "/etc/default/grub",
        )
        for value in forbidden:
            self.assertNotIn(value, self.script)

    def test_mutating_commands_have_root_guard_and_rollback(self):
        self.assertIn("def require_root", self.script)
        self.assertIn("def rollback_state", self.script)
        self.assertIn("ensure_management(config)", self.script)
        self.assertIn('driver_for_pci(data["pci_address"]) != "vfio-pci"', self.script)
        self.assertIn("def unbind_pci_driver", self.script)
        self.assertIn("def bind_pci_kernel_driver", self.script)
        self.assertLess(
            self.script.index('action("iommu_bridges.restored"'),
            self.script.index('action("driver.restored"'),
        )
        self.assertLess(
            self.script.index('action("dpdk_prefix.cleaned"'),
            self.script.index('action("hugepages.restored"'),
        )


if __name__ == "__main__":
    unittest.main()
