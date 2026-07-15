import copy
import importlib.util
import math
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_t13_feature_schema.py"
SPEC = importlib.util.spec_from_file_location("verify_t13_feature_schema", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class FlowFeatureSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = verifier.load_json(ROOT / verifier.FLOW_SCHEMA)

    def test_schema_is_valid_and_has_fixed_order(self):
        self.assertEqual([], verifier.validate_flow_schema(self.schema))
        self.assertEqual(54, self.schema["feature_vector"]["length"])
        self.assertEqual("float64", self.schema["feature_vector"]["encoded_type"])
        self.assertEqual(
            list(verifier.FEATURE_NAMES),
            [feature["name"] for feature in self.schema["features"]],
        )

    def test_time_and_statistics_policies_are_locked(self):
        time_policy = self.schema["time_policy"]
        self.assertEqual("none", time_policy["rounding"])
        self.assertTrue(time_policy["signed_iat_preserved"])
        self.assertFalse(time_policy["packets_sorted_by_timestamp"])
        statistics = self.schema["statistics_policy"]
        self.assertEqual("Welford", statistics["algorithm"])
        self.assertEqual("M2 / n", statistics["variance_formula"])
        self.assertEqual("fail-fast", statistics["non_finite_input_or_output"])

    def test_schema_rejects_reordering_and_float32_encoding(self):
        reordered = copy.deepcopy(self.schema)
        reordered["features"][0], reordered["features"][1] = (
            reordered["features"][1],
            reordered["features"][0],
        )
        self.assertIn(
            "feature indices must be contiguous and ordered from 0 to 53",
            verifier.validate_flow_schema(reordered),
        )
        float32 = copy.deepcopy(self.schema)
        float32["feature_vector"]["encoded_type"] = "float32"
        self.assertIn(
            "feature vector must contain 54 finite float64 values until T4.1",
            verifier.validate_flow_schema(float32),
        )

    def test_welford_population_edges_and_signed_values(self):
        self.assertEqual((0.0, 0.0, 0.0, 0.0), verifier.welford_population([]))
        self.assertEqual((5.0, 5.0, 5.0, 0.0), verifier.welford_population([5.0]))
        minimum, maximum, mean, std = verifier.welford_population([-2.0, 0.0, 5.0])
        self.assertEqual(-2.0, minimum)
        self.assertEqual(5.0, maximum)
        self.assertAlmostEqual(1.0, mean)
        self.assertAlmostEqual(math.sqrt(26.0 / 3.0), std)

    def test_numeric_conversion_zero_division_and_nonfinite_fail_fast(self):
        self.assertEqual(1.501, verifier.ns_to_us(1501))
        self.assertEqual(-14.0, verifier.ns_to_us(-14_000))
        self.assertEqual(0.0, verifier.safe_ratio(3.0, 0.0))
        self.assertEqual(1.5, verifier.safe_ratio(3.0, 2.0))
        with self.assertRaisesRegex(ValueError, "finite"):
            verifier.welford_population([math.nan])
        with self.assertRaisesRegex(ValueError, "finite"):
            verifier.safe_ratio(math.inf, 1.0)


class PacketSequenceSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = verifier.load_json(ROOT / verifier.PACKET_SCHEMA)

    def test_schema_is_valid_and_retains_spin_derivation_inputs(self):
        self.assertEqual([], verifier.validate_packet_schema(self.schema))
        self.assertEqual(
            list(verifier.PACKET_FIELD_NAMES),
            [field["name"] for field in self.schema["record_fields"]],
        )
        fields = {field["name"]: field for field in self.schema["record_fields"]}
        self.assertEqual("bytes", fields["raw_frame"]["logical_type"])
        self.assertEqual("int64", fields["delta_time_ns"]["logical_type"])
        self.assertIn("payload_range", fields)

    def test_sequence_preserves_capture_order_outside_flow_state(self):
        sequence = self.schema["sequence_policy"]
        storage = self.schema["storage_policy"]
        self.assertFalse(sequence["packets_sorted_by_timestamp"])
        self.assertTrue(sequence["signed_delta_time_preserved"])
        self.assertFalse(storage["raw_bytes_in_flow_state"])
        self.assertTrue(storage["raw_frame_required_at_ingest"])

    def test_schema_rejects_sorting_or_raw_bytes_in_flow_state(self):
        sorted_schema = copy.deepcopy(self.schema)
        sorted_schema["sequence_policy"]["packets_sorted_by_timestamp"] = True
        self.assertIn(
            "packet sequence must preserve capture order and signed delta time",
            verifier.validate_packet_schema(sorted_schema),
        )
        retained = copy.deepcopy(self.schema)
        retained["storage_policy"]["raw_bytes_in_flow_state"] = True
        self.assertIn(
            "raw frames must remain recoverable outside FlowState",
            verifier.validate_packet_schema(retained),
        )

    def test_spin_is_compatibility_only_and_separately_versioned(self):
        spin = self.schema["spin_compatibility"]
        self.assertEqual("preparation_only", spin["status"])
        self.assertFalse(spin["implemented_in_t1_3"])
        self.assertTrue(spin["future_adapter_contract"]["separate_version_required"])
        self.assertEqual(1486, spin["future_adapter_contract"]["selected_byte_width"])


if __name__ == "__main__":
    unittest.main()
