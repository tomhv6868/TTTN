import copy
import importlib.util
import math
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_t15_schema_review.py"
SPEC = importlib.util.spec_from_file_location("verify_t15_schema_review", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class SchemaReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flow_schema = verifier.load_json(ROOT / verifier.FLOW_SCHEMA)
        cls.fixture = verifier.load_json(ROOT / verifier.FIXTURE)
        cls.feature_names = [feature["name"] for feature in cls.flow_schema["features"]]

    def feature_index(self, name):
        return self.feature_names.index(name)

    def test_complete_review_is_valid(self):
        self.assertEqual([], verifier.validate_review(ROOT))
        self.assertEqual([], verifier.validate_fixture(self.fixture, self.flow_schema))

    def test_all_54_features_are_mandatory_and_ordered(self):
        decision = self.fixture["review_decision"]
        self.assertEqual(54, decision["mandatory_feature_count"])
        self.assertEqual(self.feature_names, decision["mandatory_feature_names"])
        self.assertEqual(self.feature_names, self.fixture["feature_names"])
        self.assertEqual("deferred", decision["retransmission_and_out_of_order"])
        self.assertEqual("ablation_only", decision["port_category"])

    def test_fixture_locks_accepted_schema_hashes(self):
        references = self.fixture["schema_references"]
        self.assertEqual(verifier.FLOW_SCHEMA_SHA256, references["flow_feature_sha256"])
        self.assertEqual(verifier.PACKET_SCHEMA_SHA256, references["packet_sequence_sha256"])
        self.assertEqual(verifier.FLOW_SCHEMA_SHA256, verifier.sha256_file(ROOT / verifier.FLOW_SCHEMA))
        self.assertEqual(verifier.PACKET_SCHEMA_SHA256, verifier.sha256_file(ROOT / verifier.PACKET_SCHEMA))

    def test_tcp_trace_covers_all_checkpoints_and_signed_iat(self):
        trace = self.fixture["traces"][0]
        self.assertEqual([3, 5, 7, 9], [item["packet_count"] for item in trace["checkpoints"]])
        timestamps = [packet["timestamp_ns"] for packet in trace["packets"]]
        self.assertIn(-2_000_000, verifier.signed_deltas(timestamps))
        self.assertEqual(["FIN", "ACK"], trace["packets"][-1]["tcp_flags"])
        f9 = trace["checkpoints"][-1]["expected_vector"]
        self.assertEqual(1, f9[self.feature_index("tcp_fin_count")])
        self.assertEqual(-2000.0, f9[self.feature_index("flow_iat_min_us")])

    def test_udp_trace_locks_zero_age_rates_and_tcp_group(self):
        trace = self.fixture["traces"][1]
        vector = trace["checkpoints"][0]["expected_vector"]
        self.assertEqual(0.0, vector[self.feature_index("flow_age_us")])
        self.assertEqual(0.0, vector[self.feature_index("packet_rate_per_second")])
        self.assertEqual(0.0, vector[self.feature_index("wire_byte_rate_per_second")])
        self.assertEqual([0, 0, 0, 0, 0, 0.0, 0, 0, 0.0, 0.0], vector[28:38])

    def test_integer_values_require_exact_type_and_value(self):
        changed_type = copy.deepcopy(self.fixture)
        changed_type["traces"][0]["checkpoints"][0]["expected_vector"][1] = 3.0
        errors = verifier.validate_fixture(changed_type, self.flow_schema)
        self.assertTrue(any("must preserve its integer logical type" in error for error in errors))

        changed_value = copy.deepcopy(self.fixture)
        changed_value["traces"][0]["checkpoints"][0]["expected_vector"][1] = 4
        errors = verifier.validate_fixture(changed_value, self.flow_schema)
        self.assertTrue(any("expected 4, computed 3" in error for error in errors))

    def test_float_values_use_only_the_accepted_tolerance(self):
        index = self.feature_index("ttl_std")
        within = copy.deepcopy(self.fixture)
        within["traces"][0]["checkpoints"][0]["expected_vector"][index] += 5e-13
        self.assertEqual([], verifier.validate_fixture(within, self.flow_schema))

        outside = copy.deepcopy(self.fixture)
        outside["traces"][0]["checkpoints"][0]["expected_vector"][index] += 1e-6
        errors = verifier.validate_fixture(outside, self.flow_schema)
        self.assertTrue(any("tcp_bidirectional_9.F3[41]" in error for error in errors))

    def test_trace_order_and_checkpoint_schedule_are_fixed(self):
        reordered = copy.deepcopy(self.fixture)
        reordered["traces"].reverse()
        self.assertIn(
            "fixture must contain the TCP and UDP traces in fixed order",
            verifier.validate_fixture(reordered, self.flow_schema),
        )

        missing = copy.deepcopy(self.fixture)
        missing["traces"][0]["checkpoints"].pop()
        self.assertIn(
            "tcp_bidirectional_9 checkpoints differ from the accepted schedule",
            verifier.validate_fixture(missing, self.flow_schema),
        )

    def test_packet_contract_rejects_impossible_or_cross_protocol_facts(self):
        udp_with_tcp = copy.deepcopy(self.fixture["traces"][1]["packets"][0])
        udp_with_tcp["tcp_window"] = 1000
        self.assertIn(
            "udp.packet UDP packet must not contain TCP fields",
            verifier.validate_packet(udp_with_tcp, "UDP", "udp.packet"),
        )

        impossible = copy.deepcopy(self.fixture["traces"][0]["packets"][0])
        impossible["payload_length"] = 7
        self.assertIn(
            "tcp.packet header and payload exceed wire length",
            verifier.validate_packet(impossible, "TCP", "tcp.packet"),
        )

    def test_welford_edges_and_zero_division(self):
        self.assertEqual((0.0, 0.0, 0.0, 0.0), verifier.population_summary([]))
        self.assertEqual((5.0, 5.0, 5.0, 0.0), verifier.population_summary([5]))
        minimum, maximum, mean, standard_deviation = verifier.population_summary([-500, 1000])
        self.assertEqual(-500.0, minimum)
        self.assertEqual(1000.0, maximum)
        self.assertEqual(250.0, mean)
        self.assertEqual(750.0, standard_deviation)
        self.assertEqual(0.0, verifier.safe_divide(3, 0))
        with self.assertRaisesRegex(ValueError, "finite"):
            verifier.population_summary([math.inf])


if __name__ == "__main__":
    unittest.main()
