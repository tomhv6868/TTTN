import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SURVEY_PATH = ROOT / "scripts" / "survey_cicids2017_flows.py"
SPEC = importlib.util.spec_from_file_location("survey_cicids2017_flows", SURVEY_PATH)
assert SPEC is not None and SPEC.loader is not None
survey = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = survey
SPEC.loader.exec_module(survey)


CLIENT = (0x0A000001, 12345)
SERVER = (0x0A000002, 80)


def tcp(timestamp, source=CLIENT, destination=SERVER, flags=survey.TCP_ACK, sequence=1):
    return survey.FlowPacket(
        timestamp,
        6,
        source[0],
        source[1],
        destination[0],
        destination[1],
        flags,
        sequence,
    )


def udp(timestamp, source=CLIENT, destination=SERVER):
    return survey.FlowPacket(
        timestamp,
        17,
        source[0],
        source[1],
        destination[0],
        destination[1],
    )


class FlowIdentityTests(unittest.TestCase):
    def test_canonical_key_is_identical_in_both_directions(self):
        forward = udp(1)
        reverse = udp(2, SERVER, CLIENT)

        self.assertEqual(survey.canonical_key(forward), survey.canonical_key(reverse))

    def test_first_packet_defines_direction(self):
        engine = survey.FlowSurvey()
        first = udp(1, SERVER, CLIENT)
        engine.observe(first)
        state = engine.active[survey.canonical_key(first)]

        self.assertEqual(0, survey.packet_direction(state, first))
        self.assertEqual(1, survey.packet_direction(state, udp(2, CLIENT, SERVER)))


class TimestampTests(unittest.TestCase):
    def test_signed_iat_and_nondecreasing_watermark_are_independent(self):
        engine = survey.FlowSurvey()
        engine.observe(udp(100))
        engine.observe(udp(90))

        overall = engine.iat["overall"]
        self.assertEqual(1, overall["negative_count"])
        self.assertEqual(-10, overall["minimum_ns"])
        self.assertEqual(100, engine.watermark_ns)
        state = engine.active[survey.canonical_key(udp(100))]
        self.assertEqual(100, state.last_event_ns)
        self.assertEqual(90, state.last_capture_ns)

    def test_expiry_heap_stays_bounded_for_a_busy_flow(self):
        engine = survey.FlowSurvey()
        for timestamp in range(10_000):
            engine.observe(udp(timestamp))

        self.assertEqual(1, len(engine.active))
        self.assertEqual(1, len(engine.expiry_heap))

    def test_idle_candidates_split_without_parallel_flow_tables(self):
        engine = survey.FlowSurvey()
        engine.observe(udp(0))
        engine.observe(udp(20 * survey.NANOSECONDS))

        self.assertEqual(1, engine.idle_profiles["15"]["session_count"])
        self.assertEqual(0, engine.idle_profiles["30"]["session_count"])
        engine.finish_file()
        self.assertEqual(2, engine.idle_profiles["15"]["session_count"])
        self.assertEqual(1, engine.idle_profiles["30"]["session_count"])

    def test_reference_idle_expires_at_120_seconds(self):
        engine = survey.FlowSurvey()
        engine.observe(udp(0))
        engine.observe(udp(120 * survey.NANOSECONDS, (0x0A000003, 1), (0x0A000004, 2)))

        self.assertEqual(1, engine.reference_completion_reasons["idle_timeout"])
        self.assertEqual(1, len(engine.active))

    def test_max_age_profiles_split_a_continuously_active_flow(self):
        engine = survey.FlowSurvey()
        for seconds in (0, 100, 200, 300):
            engine.observe(udp(seconds * survey.NANOSECONDS))

        self.assertEqual(1, engine.max_age_profiles["300"]["session_count"])
        self.assertEqual(0, engine.max_age_profiles["900"]["session_count"])
        engine.finish_file()
        self.assertEqual(2, engine.max_age_profiles["300"]["session_count"])
        self.assertEqual(1, engine.max_age_profiles["900"]["session_count"])


class TcpTerminationTests(unittest.TestCase):
    def test_rst_packet_is_included_before_close(self):
        engine = survey.FlowSurvey()
        engine.observe(tcp(1, flags=survey.TCP_SYN, sequence=10))
        engine.observe(tcp(2, SERVER, CLIENT, survey.TCP_RST | survey.TCP_ACK, 20))

        self.assertEqual(2, engine.eligible_packet_count)
        self.assertEqual(1, engine.reference_completion_reasons["rst"])
        self.assertEqual(0, len(engine.active))
        self.assertEqual(1, engine.iat["overall"]["count"])

    def test_fin_waits_for_peer_ack_after_second_fin(self):
        engine = survey.FlowSurvey()
        engine.observe(tcp(1, flags=survey.TCP_FIN | survey.TCP_ACK))
        engine.observe(tcp(2, SERVER, CLIENT, survey.TCP_FIN | survey.TCP_ACK))

        self.assertEqual(0, engine.reference_completion_reasons["fin_handshake"])
        self.assertEqual(1, len(engine.active))
        engine.observe(tcp(3, SERVER, CLIENT, survey.TCP_ACK))
        self.assertEqual(0, engine.reference_completion_reasons["fin_handshake"])
        engine.observe(tcp(4, CLIENT, SERVER, survey.TCP_ACK))
        self.assertEqual(1, engine.reference_completion_reasons["fin_handshake"])
        self.assertEqual(0, len(engine.active))

    def test_identical_initial_syn_is_retransmission_but_new_syn_reuses_tuple(self):
        engine = survey.FlowSurvey()
        engine.observe(tcp(1, flags=survey.TCP_SYN, sequence=10))
        engine.observe(tcp(2, flags=survey.TCP_SYN, sequence=10))
        self.assertEqual(0, engine.reference_completion_reasons["tuple_reuse"])

        engine.observe(tcp(3, SERVER, CLIENT, survey.TCP_SYN | survey.TCP_ACK, 20))
        engine.observe(tcp(4, flags=survey.TCP_SYN, sequence=30))
        self.assertEqual(1, engine.reference_completion_reasons["tuple_reuse"])
        self.assertEqual(1, len(engine.active))


class ParserTests(unittest.TestCase):
    def test_tcp_and_vlan_udp_are_parsed_without_payload_storage(self):
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ipv4_tcp = bytes.fromhex("4500002c0000400040060000c0a80101c0a80102")
        tcp_header = bytes.fromhex("04d2005000000001000000005018200000000000")
        packet, error = survey.parse_flow_packet(
            ethernet + ipv4_tcp + tcp_header + b"test",
            123,
        )

        self.assertIsNone(error)
        self.assertEqual(1234, packet.source_port)
        self.assertEqual(80, packet.destination_port)
        self.assertFalse(hasattr(packet, "payload"))

        vlan = bytes.fromhex("00112233445566778899aabb810000640800")
        ipv4_udp = bytes.fromhex("4500001f0000000040110000c0a80101c0a80102")
        udp_header = bytes.fromhex("04d2162e000b0000")
        packet, error = survey.parse_flow_packet(vlan + ipv4_udp + udp_header + b"udp", 456)
        self.assertIsNone(error)
        self.assertEqual(17, packet.protocol)
        self.assertEqual(5678, packet.destination_port)

    def test_malformed_and_fragmented_packets_are_rejected(self):
        packet, error = survey.parse_flow_packet(b"short", 1)
        self.assertIsNone(packet)
        self.assertEqual("truncated_ethernet_header", error)

        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ipv4_tcp = bytearray.fromhex("450000280000200040060000c0a80101c0a80102")
        tcp_header = bytes.fromhex("04d2005000000001000000005018200000000000")
        packet, error = survey.parse_flow_packet(ethernet + ipv4_tcp + tcp_header, 1)
        self.assertIsNone(packet)
        self.assertEqual("ipv4_fragmented", error)


class AggregateTests(unittest.TestCase):
    def test_capacity_assessment_uses_reference_peak_as_upper_bound(self):
        receipts = []
        for name in sorted(survey.EXPECTED_FILES):
            engine = survey.FlowSurvey()
            engine.observe(udp(1))
            engine.observe(udp(1, (0x0A000003, 1), (0x0A000004, 2)))
            engine.finish_file()
            receipts.append(
                {
                    "status": "passed",
                    "source": {"name": name},
                    "statistics": {
                        "packet_count": 2,
                        "timestamp_duplicate_count": 1,
                        "timestamp_regression_count": 0,
                        "timestamp_rounding_count": 0,
                        "ignored_packets": {},
                        "flow": engine.as_document(),
                    },
                }
            )

        aggregate = survey.aggregate_receipts(receipts, "2.7.0")

        self.assertEqual("passed", aggregate["status"])
        self.assertEqual(2, aggregate["totals"]["active_flow_peak"])
        first_candidate = aggregate["totals"]["capacity_assessment"][0]
        self.assertEqual("no_capacity_eviction_required", first_candidate["assessment"])
        self.assertEqual(65_534, first_candidate["headroom_flows"])


if __name__ == "__main__":
    unittest.main()
