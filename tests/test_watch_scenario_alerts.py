from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'watch_scenario_alerts', ROOT / 'scripts' / 'watch_scenario_alerts.py'
)
assert SPEC and SPEC.loader
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)


class WatchScenarioAlertsTest(unittest.TestCase):
    def test_dedupe_key_matches_attempt_flow_and_candidate(self):
        event = {
            'event_type': 'nids_alert',
            'decision': 'known_attack',
            'flow': {
                'protocol': 'tcp',
                'source': {'ip': '1.2.3.4', 'port': 10},
                'destination': {'ip': '5.6.7.8', 'port': 20},
            },
            'evidence': {'known_family': {'top_candidate': 'Bot'}},
        }
        first = WATCH.dedupe_key(event, 'bot-r2')
        second = WATCH.dedupe_key(dict(event), 'bot-r2')
        self.assertEqual(first, second)
        self.assertIn('Bot', first)

    def test_different_attempt_is_not_deduplicated(self):
        event = {
            'event_type': 'nids_alert',
            'flow': {'source': {}, 'destination': {}},
            'evidence': {'known_family': {'top_candidate': 'Bot'}},
        }
        self.assertNotEqual(
            WATCH.dedupe_key(event, 'bot-r2'),
            WATCH.dedupe_key(event, 'bot-r3'),
        )

    def test_non_alert_has_no_key(self):
        self.assertIsNone(WATCH.dedupe_key({'event_type': 'summary'}, 'x'))


if __name__ == '__main__':
    unittest.main()
