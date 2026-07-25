from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import kali_t85_golden_sender as sender


class KaliT85GoldenSenderTests(unittest.TestCase):
    def test_schedule_starts_after_raw_socket_bind(self) -> None:
        class FakeSocket:
            bound = False

            def __enter__(self) -> FakeSocket:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def bind(self, _address: tuple[str, int]) -> None:
                self.bound = True

            def send(self, frame: bytes) -> int:
                return len(frame)

        raw_socket = FakeSocket()
        clock_ns = 0

        def monotonic_ns() -> int:
            self.assertTrue(raw_socket.bound)
            return clock_ns

        def sleep(seconds: float) -> None:
            nonlocal clock_ns
            clock_ns += round(seconds * 1_000_000_000)

        with (
            patch.object(sender.socket, "AF_PACKET", 17, create=True),
            patch.object(sender.socket, "socket", return_value=raw_socket),
            patch.object(sender.time, "monotonic_ns", side_effect=monotonic_ns),
            patch.object(sender.time, "sleep", side_effect=sleep),
        ):
            result = sender.send_frames(
                "eth1",
                (b"a", b"b"),
                (0, 1_000_000_000),
                1_000_000_000,
            )

        self.assertEqual(result.records, 2)
        self.assertEqual(result.observed_offsets_ns, (0, 1_000_000_000))
        self.assertEqual(result.duration_seconds, 1.0)

    def test_rewrites_only_layer_two_addresses(self) -> None:
        source_mac = "00:0c:29:98:f4:17"
        destination_mac = "00:0c:29:d5:43:8b"
        input_path = ROOT / "run_log/t3.2/attack-tcp-f9.pcap"
        _, _, original = sender.parse_pcap(input_path.read_bytes())

        frames, offsets, tick_hz = sender.load_frames(
            input_path,
            source_mac,
            destination_mac,
            9000,
        )

        self.assertEqual(len(frames), 9)
        self.assertEqual(len(offsets), 9)
        self.assertEqual(offsets[0], 0)
        self.assertEqual(offsets[-1], 13_724_000)
        self.assertEqual(tick_hz, 1_000_000_000)
        for frame, record in zip(frames, original, strict=True):
            self.assertEqual(frame[:6], sender.parse_mac(destination_mac))
            self.assertEqual(frame[6:12], sender.parse_mac(source_mac))
            self.assertEqual(frame[12:], record.data[12:])

    def test_rejects_fixture_that_exceeds_requested_mtu(self) -> None:
        with self.assertRaisesRegex(ValueError, "larger than MTU 1500"):
            sender.load_frames(
                ROOT / "run_log/t3.2/attack-tcp-f9.pcap",
                "00:0c:29:98:f4:17",
                "00:0c:29:d5:43:8b",
                1500,
            )


if __name__ == "__main__":
    unittest.main()
