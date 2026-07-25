from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UBUNTU = ROOT / "scripts/ubuntu_t85_detection.sh"
KALI = ROOT / "scripts/kali_t85_bulk_replay.sh"
RUNTIME = ROOT / "cpp/apps/nids_dpdk_live.cpp"


class T85RuntimeWorkflowTests(unittest.TestCase):
    def test_ubuntu_launcher_is_continuous_and_scenario_free(self) -> None:
        source = UBUNTU.read_text(encoding="utf-8")
        self.assertNotIn("--run-id", source)
        self.assertNotIn("--attempt", source)
        self.assertNotIn("scenario.json", source)
        self.assertNotIn("run_t85_scenario_sensor_ubuntu.sh", source)
        self.assertIn("--max-packets 0", source)
        self.assertIn("--idle-timeout-ms 0", source)
        self.assertIn("--require-promiscuous", source)
        self.assertNotIn("--stop-after-alert", source)
        self.assertIn(
            'SEGMENT_ROOT="$PROJECT_ROOT/run_log/t8.5/segments/$SEGMENT_ID"',
            source,
        )
        self.assertIn('DETECTION_LOG="$SEGMENT_ROOT/detection.jsonl"', source)
        self.assertIn("dpdk_smoke.py\" rollback", source)

    def test_kali_replay_requires_explicit_functional_speed(self) -> None:
        source = KALI.read_text(encoding="utf-8")
        self.assertIn("--interface IFACE", source)
        self.assertIn("--destination-mac MAC", source)
        self.assertIn("--pcap-dir DIR", source)
        self.assertIn("--speed 1|5|topspeed", source)
        self.assertIn("$SPEED\" == 1", source)
        self.assertIn("$SPEED\" == 5", source)
        self.assertIn("$SPEED\" == topspeed", source)
        self.assertIn("--enet-smac=", source)
        self.assertIn("--enet-dmac=", source)
        self.assertNotIn("--srcipmap", source)
        self.assertNotIn("--dstipmap", source)
        self.assertIn("Failed packets:", source)
        self.assertIn("Message too long \\(errno = 90\\)", source)
        self.assertIn("FAILED_PACKETS == OVERSIZED_PACKETS", source)
        self.assertIn("hardware_unreplayable_oversized_frames", source)
        self.assertIn("unexplained_send_failures", source)
        self.assertIn("run_log/t8.5", source)

    def test_binary_zero_values_mean_unlimited_runtime(self) -> None:
        source = RUNTIME.read_text(encoding="utf-8")
        self.assertIn("arguments->max_packets == 0U", source)
        self.assertIn("const auto timeout = first_packet.has_value()", source)
        self.assertIn("? arguments->idle_timeout", source)
        self.assertIn(": arguments->arm_timeout", source)
        self.assertIn("timeout.count() != 0", source)
        self.assertIn("stop_requested == 0", source)
        self.assertIn("std::signal(SIGINT, request_stop)", source)
        self.assertIn("std::signal(SIGTERM, request_stop)", source)
        self.assertIn('\\"continuous\\"', source)


if __name__ == "__main__":
    unittest.main()
