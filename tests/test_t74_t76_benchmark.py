import importlib.util
import socket
import struct
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SENDER_PATH = ROOT / "scripts/kali_t74_t76_benchmark_sender.py"


def load_module():
    spec = importlib.util.spec_from_file_location("t74_t76_sender", SENDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sender = load_module()


class BenchmarkSenderTests(unittest.TestCase):
    def test_nine_packets_share_a_flow_and_next_flow_changes_tuple(self):
        first = sender.flow_ports(0)
        self.assertEqual(first, sender.flow_ports(0))
        self.assertNotEqual(first, sender.flow_ports(1))
        self.assertNotEqual(first, sender.flow_ports(64_000))

    def test_frame_has_valid_ipv4_checksum_requested_tuple_and_final_reset(self):
        frame = sender.build_tcp_frame(
            "00:0c:29:98:f4:17",
            "00:0c:29:d5:43:8b",
            "192.168.252.10",
            "192.168.252.20",
            7,
            sender.PACKETS_PER_FLOW - 1,
        )
        self.assertEqual(64, len(frame))
        self.assertEqual(0x0800, struct.unpack("!H", frame[12:14])[0])
        ipv4 = frame[14:34]
        self.assertEqual(0, sender.internet_checksum(ipv4))
        self.assertEqual(socket.IPPROTO_TCP, ipv4[9])
        self.assertEqual(sender.flow_ports(7), struct.unpack("!HH", frame[34:38]))
        self.assertEqual(0x04, frame[47])

    def test_validation_locks_packet_count_and_rejects_overwrite(self):
        parser = sender.build_parser()
        args = parser.parse_args(
            [
                "--mode",
                "full",
                "--attempt",
                "full-1000",
                "--flows",
                "10",
                "--pps",
                "1000",
                "--output",
                "receipt.json",
            ]
        )
        facts = {
            "name": "eth1",
            "mac": "00:0c:29:98:f4:17",
            "driver": "vmxnet3",
            "has_default_route": False,
        }
        with (
            mock.patch.object(sender.platform, "system", return_value="Linux"),
            mock.patch.object(sender.os, "geteuid", return_value=0, create=True),
            mock.patch.object(sender, "interface_facts", return_value=facts),
            mock.patch.object(Path, "exists", return_value=False),
        ):
            self.assertEqual(90, sender.validate(args))


if __name__ == "__main__":
    unittest.main()
