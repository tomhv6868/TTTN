from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "bridge_terminal", ROOT / "scripts" / "bridge_terminal_to_dashboard.py"
)
assert SPEC and SPEC.loader
BRIDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)


class TerminalBridgeTest(unittest.TestCase):
    def test_decision_mapping(self):
        event = {
            "event_type": "nids_terminal_flow_decision",
            "attempt_id": "a1",
            "decision": "Benign",
            "packet_count": 3,
            "close_reason": "tcp_reset",
            "last_event_timestamp_ns": 12,
            "flow": {"protocol": "tcp", "source": {"ip": "1.2.3.4", "port": 9},
                     "destination": {"ip": "5.6.7.8", "port": 22}},
            "scores": {
                "attack_gate": {"attack_score": 0.25},
                "gated_decision": {"class_confidence": 0.75},
                "top_attack_candidate": {"class_name": "PortScan"},
            },
        }
        row = BRIDGE.convert(event, "run", "portscan")
        self.assertEqual("terminal", row["model"])
        self.assertEqual("benign", row["decision"])
        self.assertEqual("PortScan", row["candidate"])
        self.assertEqual("Benign", row["terminal_class"])
        self.assertEqual("1.2.3.4:9", row["source"])
        self.assertEqual("TCP", row["protocol"])

    def test_alert_mapping(self):
        event = {
            "event_type": "nids_terminal_flow_alert",
            "decision": "PortScan",
            "flow": {"protocol": "tcp", "source": {"ip": "1", "port": 2},
                     "destination": {"ip": "3", "port": 4}},
            "scores": {"attack_score": 0.999, "class_confidence": 0.998},
        }
        row = BRIDGE.convert(event, "run", "portscan")
        self.assertEqual("known_attack", row["decision"])
        self.assertEqual("PortScan", row["candidate"])
        self.assertEqual("PortScan", row["terminal_class"])
        self.assertEqual(0.999, row["flow_rf_probability"])

    def test_non_terminal_event_is_ignored(self):
        self.assertIsNone(BRIDGE.convert({"event_type": "nids_alert"}, "r", "f"))


if __name__ == "__main__":
    unittest.main()
