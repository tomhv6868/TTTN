from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_t85_scenario_pcaps as builder
import kali_t85_scenario_replay as replay


class T85ScenarioPcapTests(unittest.TestCase):
    def test_taxonomy_maps_13_model_families_and_heartbleed(self) -> None:
        self.assertEqual(len(builder.LABEL_TO_CASE), 14)
        self.assertEqual(builder.LABEL_TO_CASE["Heartbleed"], "heartbleed")
        self.assertEqual(len(set(builder.LABEL_TO_CASE.values())), 14)

    def test_selector_hash_is_stable_and_semantic(self) -> None:
        selector = builder.Selector(
            case_id="ddos",
            label="DDoS",
            capture_id="friday-working-hours",
            tuple_key=(6, 1, 2, 3, 4),
            start_ns=10,
            end_ns=20,
            semantic_kind="t3.5_f9_prefix",
            flow_id=7,
            assignment_method="mutual_unique",
        )
        first = builder.selector_hash([selector])
        second = builder.selector_hash([selector])
        changed = builder.selector_hash([replace(selector, end_ns=21)])
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_generic_replay_preserves_payload_after_layer_two(self) -> None:
        path = ROOT / "run_log/t3.2/attack-tcp-f9.pcap"
        _, _, records = replay.parse_pcap(path.read_bytes())
        frames, offsets, tick_hz = replay.load_frames(
            path,
            "00:0c:29:98:f4:17",
            "00:0c:29:d5:43:8b",
            9000,
        )
        self.assertEqual(len(frames), 9)
        self.assertEqual(offsets[0], 0)
        self.assertEqual(tick_hz, 1_000_000_000)
        for frame, record in zip(frames, records, strict=True):
            self.assertEqual(frame[12:], record.data[12:])

    def test_generic_replay_rejects_jumbo_on_1500_mtu(self) -> None:
        with self.assertRaisesRegex(ValueError, "larger than MTU 1500"):
            replay.load_frames(
                ROOT / "run_log/t3.2/attack-tcp-f9.pcap",
                "00:0c:29:98:f4:17",
                "00:0c:29:d5:43:8b",
                1500,
            )


if __name__ == "__main__":
    unittest.main()
