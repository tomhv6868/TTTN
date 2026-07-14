import json
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dpdk_passive_probe as probe
import kali_passive_traffic as sender
import verify_dpdk_passive as verifier


class PassiveContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config_path = ROOT / "config" / "dpdk-passive.json"
        cls.config = sender.load_and_validate_config(cls.config_path)

    def test_resource_config_is_accepted_by_reversible_t03_apply(self):
        resource = probe.build_resource_config(self.config)
        self.assertEqual([], probe.dpdk.validate_config(resource))
        self.assertEqual("VMnet1", resource["topology"]["data_network"]["name"])
        self.assertEqual("nids-t03", resource["runtime"]["file_prefix"])

    def test_probe_command_is_rxonly_and_uses_a_distinct_prefix(self):
        state = {
            "toolchain": {"testpmd": "/opt/dpdk/bin/dpdk-testpmd"},
            "original": {"pci_address": "0000:03:00.0"},
        }
        command = probe.build_testpmd_command(self.config, state)
        separator = command.index("--")
        self.assertIn("--file-prefix=nids-t04", command[:separator])
        self.assertIn("--huge-unlink=always", command[:separator])
        self.assertIn("--forward-mode=rxonly", command[separator + 1 :])
        self.assertFalse(any(item.startswith("--stats-period") for item in command))

    def test_retry_archives_failed_attempt_without_touching_resource_state(self):
        root = pathlib.Path("D:/synthetic-run-log")
        path_type = type(root)
        with (
            mock.patch.object(path_type, "is_file", autospec=True, side_effect=lambda item: item.name == "testpmd.log"),
            mock.patch.object(path_type, "exists", autospec=True, return_value=False),
            mock.patch.object(path_type, "mkdir", autospec=True) as mkdir,
            mock.patch.object(probe.dpdk, "sha256_file", return_value="a" * 64),
            mock.patch.object(probe.shutil, "move") as move,
            mock.patch.object(probe.dpdk, "write_new_json") as write_json,
        ):
            archive = probe.archive_failed_attempt(root)

        self.assertIsNotNone(archive)
        mkdir.assert_called_once()
        self.assertEqual({"parents": True}, mkdir.call_args.kwargs)
        move.assert_called_once()
        manifest = write_json.call_args.args[1]
        self.assertEqual("failed_attempt_archive", manifest["kind"])
        self.assertEqual("testpmd.log", pathlib.Path(manifest["files"][0]["original"]).name)

    def test_verbose_frame_identity_and_zero_tx_are_parsed(self):
        output = (
            "src=00:0C:29:44:55:66 - dst=00:0C:29:D5:43:8B "
            "- pool=mb_pool_0 - type=0x0800 - length=60 - nb_segs=1\n"
            "RX-packets: 200\nTX-packets: 0\nRX-missed: 0\n"
            "RX-errors: 0\nRX-nombuf: 0\nTX-errors: 0\n"
        )
        frames = probe.parse_frames(output)
        counters = probe.parse_counters(output)
        self.assertEqual("00:0c:29:44:55:66", frames[0]["source_mac"])
        self.assertEqual("00:0c:29:d5:43:8b", frames[0]["destination_mac"])
        self.assertEqual(200, counters["rx_packets"])
        self.assertEqual(0, counters["port_tx_packets"])

    def test_sender_frame_has_locked_l2_l3_l4_and_magic(self):
        frame = sender.build_udp_frame(
            "00:0c:29:44:55:66",
            self.config["windows_victim"]["expected_mac"],
            self.config["kali"]["data_ipv4"],
            self.config["windows_victim"]["data_ipv4"],
            self.config["kali"]["udp_source_port"],
            self.config["windows_victim"]["udp_port"],
            self.config["traffic"]["payload_magic_ascii"],
            199,
        )
        self.assertEqual(60, len(frame))
        self.assertEqual("00:0c:29:d5:43:8b", frame[:6].hex(":"))
        self.assertEqual(b"NIDST04!", frame[42:50])
        self.assertEqual(199, int.from_bytes(frame[50:54], "big"))

    def test_sender_safely_prepares_missing_data_address(self):
        initial = {
            "name": "eth1",
            "mac": "00:0c:29:44:55:66",
            "driver": "vmxnet3",
            "has_default_route": False,
            "ipv4_addresses": [],
        }
        prepared = {**initial, "ipv4_addresses": ["192.168.252.10"]}
        with (
            mock.patch.object(sender.platform, "system", return_value="Linux"),
            mock.patch.object(sender.os, "geteuid", return_value=0, create=True),
            mock.patch.object(sender, "interface_facts", side_effect=(initial, prepared)),
            mock.patch.object(sender, "run_checked") as run_checked,
        ):
            facts = sender.validate_runtime(self.config)

        self.assertTrue(facts["source_address_prepared"])
        self.assertEqual(2, run_checked.call_count)
        self.assertIn("192.168.252.10/24", run_checked.call_args_list[1].args[0])

    def test_sample_acceptance_bundle_passes_all_checks(self):
        bundle = json.loads(
            (ROOT / "tests" / "fixtures" / "dpdk-passive-bundle.sample.json").read_text(encoding="utf-8")
        )
        checks, outcome, summary = verifier.validate_receipts(
            config=bundle["config"],
            preflight=bundle["preflight"],
            sender=bundle["sender"],
            receiver=bundle["receiver"],
            sensor=bundle["sensor"],
            rollback=bundle["rollback"],
            artifact_hashes=bundle["artifact_hashes"],
        )
        self.assertEqual("passed", outcome)
        self.assertTrue(all(item["status"] == "passed" for item in checks))
        self.assertEqual(200, summary["sensor_matching_frames"])


if __name__ == "__main__":
    unittest.main()
