#pragma once

#include "nids/packet.hpp"

#include <compare>
#include <cstdint>
#include <limits>
#include <optional>
#include <variant>

namespace nids {

enum class TransportProtocol : std::uint8_t {
    tcp = 6,
    udp = 17,
};

struct FlowEndpoint {
    Ipv4Address address{};
    std::uint16_t port{};

    friend constexpr bool operator==(const FlowEndpoint&, const FlowEndpoint&) noexcept = default;

    friend constexpr std::strong_ordering operator<=> (
        const FlowEndpoint& left,
        const FlowEndpoint& right) noexcept {
        if (const auto address_order = left.address.wire_bytes <=> right.address.wire_bytes;
            address_order != 0) {
            return address_order;
        }
        return left.port <=> right.port;
    }
};

struct FlowKey {
    TransportProtocol protocol{};
    FlowEndpoint low{};
    FlowEndpoint high{};

    friend constexpr bool operator==(const FlowKey&, const FlowKey&) noexcept = default;
};

enum class FlowDirection : std::uint8_t {
    forward,
    reverse,
};

struct FlowIdentity {
    FlowKey key{};
    FlowEndpoint forward_source{};

    friend constexpr bool operator==(const FlowIdentity&, const FlowIdentity&) noexcept = default;
};

[[nodiscard]] constexpr TransportProtocol transport_protocol(const PacketView& packet) noexcept {
    return std::holds_alternative<TcpView>(packet.transport)
        ? TransportProtocol::tcp
        : TransportProtocol::udp;
}

[[nodiscard]] constexpr FlowEndpoint source_endpoint(const PacketView& packet) noexcept {
    return std::visit(
        [&packet](const auto& transport) {
            return FlowEndpoint{packet.ipv4.source, transport.source_port};
        },
        packet.transport);
}

[[nodiscard]] constexpr FlowEndpoint destination_endpoint(const PacketView& packet) noexcept {
    return std::visit(
        [&packet](const auto& transport) {
            return FlowEndpoint{packet.ipv4.destination, transport.destination_port};
        },
        packet.transport);
}

[[nodiscard]] constexpr FlowKey make_flow_key(const PacketView& packet) noexcept {
    const auto source = source_endpoint(packet);
    const auto destination = destination_endpoint(packet);
    if (destination < source) {
        return FlowKey{transport_protocol(packet), destination, source};
    }
    return FlowKey{transport_protocol(packet), source, destination};
}

[[nodiscard]] constexpr FlowIdentity make_flow_identity(const PacketView& first_packet) noexcept {
    return FlowIdentity{make_flow_key(first_packet), source_endpoint(first_packet)};
}

[[nodiscard]] constexpr std::optional<FlowDirection> flow_direction(
    const FlowIdentity& identity,
    const PacketView& packet) noexcept {
    if (make_flow_key(packet) != identity.key) {
        return std::nullopt;
    }
    return source_endpoint(packet) == identity.forward_source
        ? FlowDirection::forward
        : FlowDirection::reverse;
}

struct FlowTimingContract {
    std::int64_t idle_timeout_ns{};
    std::int64_t maximum_age_ns{};
    bool preserve_capture_order{};
    bool preserve_signed_iat{};
    bool clamp_negative_iat{};
    bool timeout_uses_nondecreasing_watermark{};
    bool require_single_clock_domain{};
};

inline constexpr FlowTimingContract flow_timing_v1{
    60LL * 1'000'000'000LL,
    30LL * 60LL * 1'000'000'000LL,
    true,
    true,
    false,
    true,
    true,
};

[[nodiscard]] constexpr std::optional<std::int64_t> signed_iat_ns(
    std::int64_t current_timestamp_ns,
    std::int64_t previous_timestamp_ns) noexcept {
    constexpr auto minimum = std::numeric_limits<std::int64_t>::min();
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    if (previous_timestamp_ns > 0
        && current_timestamp_ns < minimum + previous_timestamp_ns) {
        return std::nullopt;
    }
    if (previous_timestamp_ns < 0
        && current_timestamp_ns > maximum + previous_timestamp_ns) {
        return std::nullopt;
    }
    return current_timestamp_ns - previous_timestamp_ns;
}

[[nodiscard]] constexpr std::int64_t advance_timestamp_watermark(
    std::optional<std::int64_t> watermark_ns,
    std::int64_t observed_timestamp_ns) noexcept {
    if (watermark_ns.has_value() && *watermark_ns > observed_timestamp_ns) {
        return *watermark_ns;
    }
    return observed_timestamp_ns;
}

[[nodiscard]] constexpr bool elapsed_at_least(
    std::int64_t watermark_ns,
    std::int64_t since_ns,
    std::int64_t duration_ns) noexcept {
    if (duration_ns < 0 || watermark_ns < since_ns) {
        return false;
    }
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    if (since_ns > maximum - duration_ns) {
        return false;
    }
    return watermark_ns >= since_ns + duration_ns;
}

[[nodiscard]] constexpr bool idle_timeout_expired(
    std::int64_t watermark_ns,
    std::int64_t last_event_ns) noexcept {
    return elapsed_at_least(watermark_ns, last_event_ns, flow_timing_v1.idle_timeout_ns);
}

[[nodiscard]] constexpr bool maximum_age_expired(
    std::int64_t watermark_ns,
    std::int64_t creation_ns) noexcept {
    return elapsed_at_least(watermark_ns, creation_ns, flow_timing_v1.maximum_age_ns);
}

enum class FlowCloseReason : std::uint8_t {
    idle_timeout,
    maximum_age,
    tcp_reset,
    tcp_fin_handshake,
    tuple_reuse,
    capacity_eviction,
    end_of_input,
};

struct TcpTerminationContract {
    bool include_reset_packet_before_close{};
    bool require_fin_in_both_directions{};
    bool require_ack_after_second_fin{};
    bool require_ack_from_peer_of_second_fin{};
};

inline constexpr TcpTerminationContract tcp_termination_v1{
    true,
    true,
    true,
    true,
};

struct TupleReuseContract {
    bool non_ack_syn_starts_new_generation{};
    bool identical_initial_syn_is_retransmission{};
    bool initial_syn_identity_includes_source_endpoint{};
    bool initial_syn_identity_includes_sequence_number{};
};

inline constexpr TupleReuseContract tuple_reuse_v1{
    true,
    true,
    true,
    true,
};

enum class CapacityEvictionOrder : std::uint8_t {
    least_recently_active_then_creation_order,
};

struct FlowCapacityContract {
    std::uint32_t hard_active_flow_limit{};
    std::uint64_t memory_budget_bytes{};
    CapacityEvictionOrder eviction_order{};
    bool emit_reason_counter{};
    bool retain_packet_bytes_in_flow_state{};
};

inline constexpr FlowCapacityContract flow_capacity_v1{
    65'536U,
    256ULL * 1024ULL * 1024ULL,
    CapacityEvictionOrder::least_recently_active_then_creation_order,
    true,
    false,
};

}
