#include "nids/flow.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failure_count_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    [[nodiscard]] int failure_count() const noexcept {
        return failure_count_;
    }

private:
    int failure_count_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)

constexpr nids::Ipv4Address client_address{{10U, 0U, 0U, 2U}};
constexpr nids::Ipv4Address server_address{{10U, 0U, 0U, 1U}};
constexpr nids::Ipv4Address other_address{{10U, 0U, 0U, 3U}};

[[nodiscard]] nids::PacketView make_tcp_packet(
    nids::Ipv4Address source,
    std::uint16_t source_port,
    nids::Ipv4Address destination,
    std::uint16_t destination_port,
    std::int64_t timestamp_ns = 0) {
    auto packet = nids::PacketView{};
    packet.timestamp_ns = timestamp_ns;
    packet.clock_domain = nids::ClockDomain::unix_epoch;
    packet.ipv4.source = source;
    packet.ipv4.destination = destination;
    packet.ipv4.protocol = static_cast<std::uint8_t>(nids::TransportProtocol::tcp);
    packet.transport = nids::TcpView{
        {},
        source_port,
        destination_port,
        0U,
        0U,
        0U,
        {},
    };
    return packet;
}

[[nodiscard]] nids::PacketView make_udp_packet(
    nids::Ipv4Address source,
    std::uint16_t source_port,
    nids::Ipv4Address destination,
    std::uint16_t destination_port) {
    auto packet = nids::PacketView{};
    packet.ipv4.source = source;
    packet.ipv4.destination = destination;
    packet.ipv4.protocol = static_cast<std::uint8_t>(nids::TransportProtocol::udp);
    packet.transport = nids::UdpView{{}, source_port, destination_port, 8U};
    return packet;
}

void test_canonical_key(TestContext& test) {
    const auto request = make_tcp_packet(client_address, 50'000U, server_address, 443U);
    const auto response = make_tcp_packet(server_address, 443U, client_address, 50'000U);
    const auto request_key = nids::make_flow_key(request);
    const auto response_key = nids::make_flow_key(response);

    EXPECT(test, request_key == response_key);
    EXPECT(test, request_key.protocol == nids::TransportProtocol::tcp);
    EXPECT(test, (request_key.low == nids::FlowEndpoint{server_address, 443U}));
    EXPECT(test, (request_key.high == nids::FlowEndpoint{client_address, 50'000U}));

    const auto udp = make_udp_packet(client_address, 50'000U, server_address, 443U);
    EXPECT(test, nids::make_flow_key(udp) != request_key);

    const auto same_address = make_tcp_packet(client_address, 50'000U, client_address, 443U);
    const auto same_address_key = nids::make_flow_key(same_address);
    EXPECT(test, same_address_key.low.port == 443U);
    EXPECT(test, same_address_key.high.port == 50'000U);
}

void test_first_packet_direction(TestContext& test) {
    const auto first = make_tcp_packet(server_address, 443U, client_address, 50'000U);
    const auto reply = make_tcp_packet(client_address, 50'000U, server_address, 443U);
    const auto unrelated = make_tcp_packet(other_address, 123U, server_address, 443U);
    const auto identity = nids::make_flow_identity(first);

    EXPECT(test, (identity.forward_source == nids::FlowEndpoint{server_address, 443U}));
    EXPECT(test, nids::flow_direction(identity, first) == nids::FlowDirection::forward);
    EXPECT(test, nids::flow_direction(identity, reply) == nids::FlowDirection::reverse);
    EXPECT(test, !nids::flow_direction(identity, unrelated).has_value());
}

void test_timestamp_contract(TestContext& test) {
    EXPECT(test, nids::signed_iat_ns(110, 100) == 10);
    EXPECT(test, nids::signed_iat_ns(100, 100) == 0);
    EXPECT(test, nids::signed_iat_ns(90, 100) == -10);
    EXPECT(test, !nids::signed_iat_ns(
        std::numeric_limits<std::int64_t>::min(),
        std::numeric_limits<std::int64_t>::max()).has_value());
    EXPECT(test, !nids::signed_iat_ns(
        std::numeric_limits<std::int64_t>::max(),
        std::numeric_limits<std::int64_t>::min()).has_value());

    EXPECT(test, nids::advance_timestamp_watermark(std::nullopt, 100) == 100);
    EXPECT(test, nids::advance_timestamp_watermark(100, 90) == 100);
    EXPECT(test, nids::advance_timestamp_watermark(100, 110) == 110);

    constexpr auto idle = nids::flow_timing_v1.idle_timeout_ns;
    constexpr auto maximum_age = nids::flow_timing_v1.maximum_age_ns;
    EXPECT(test, !nids::idle_timeout_expired(idle - 1, 0));
    EXPECT(test, nids::idle_timeout_expired(idle, 0));
    EXPECT(test, !nids::maximum_age_expired(maximum_age - 1, 0));
    EXPECT(test, nids::maximum_age_expired(maximum_age, 0));
    EXPECT(test, nids::elapsed_at_least(-5, -65, 60));
    EXPECT(test, !nids::elapsed_at_least(
        std::numeric_limits<std::int64_t>::max(),
        std::numeric_limits<std::int64_t>::max() - 10,
        60));

    EXPECT(test, nids::flow_timing_v1.preserve_capture_order);
    EXPECT(test, nids::flow_timing_v1.preserve_signed_iat);
    EXPECT(test, !nids::flow_timing_v1.clamp_negative_iat);
    EXPECT(test, nids::flow_timing_v1.timeout_uses_nondecreasing_watermark);
    EXPECT(test, nids::flow_timing_v1.require_single_clock_domain);
}

void test_termination_and_capacity_contract(TestContext& test) {
    EXPECT(test, nids::tcp_termination_v1.include_reset_packet_before_close);
    EXPECT(test, nids::tcp_termination_v1.require_fin_in_both_directions);
    EXPECT(test, nids::tcp_termination_v1.require_ack_after_second_fin);
    EXPECT(test, nids::tcp_termination_v1.require_ack_from_peer_of_second_fin);

    EXPECT(test, nids::tuple_reuse_v1.non_ack_syn_starts_new_generation);
    EXPECT(test, nids::tuple_reuse_v1.identical_initial_syn_is_retransmission);
    EXPECT(test, nids::tuple_reuse_v1.initial_syn_identity_includes_source_endpoint);
    EXPECT(test, nids::tuple_reuse_v1.initial_syn_identity_includes_sequence_number);

    EXPECT(test, nids::flow_capacity_v1.hard_active_flow_limit == 65'536U);
    EXPECT(test, nids::flow_capacity_v1.memory_budget_bytes == 256ULL * 1024ULL * 1024ULL);
    EXPECT(test, nids::flow_capacity_v1.eviction_order
        == nids::CapacityEvictionOrder::least_recently_active_then_creation_order);
    EXPECT(test, nids::flow_capacity_v1.emit_reason_counter);
    EXPECT(test, !nids::flow_capacity_v1.retain_packet_bytes_in_flow_state);
}

}

int main() {
    static_assert(nids::flow_timing_v1.idle_timeout_ns == 60'000'000'000LL);
    static_assert(nids::flow_timing_v1.maximum_age_ns == 1'800'000'000'000LL);
    static_assert(nids::flow_capacity_v1.hard_active_flow_limit == 65'536U);

    TestContext test;
    test_canonical_key(test);
    test_first_packet_direction(test);
    test_timestamp_contract(test);
    test_termination_and_capacity_contract(test);
    return test.failure_count() == 0 ? 0 : 1;
}
