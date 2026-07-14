#pragma once

#include "nids/checkpoint.hpp"
#include "nids/flow.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <variant>

namespace nids {

struct PopulationStatistics {
    std::uint64_t count{};
    double minimum{};
    double maximum{};
    double mean{};
    double m2{};
};

struct FlowFeatureState {
    std::uint64_t wire_byte_count{};
    std::array<std::uint64_t, 2> directional_wire_byte_count{};
    PopulationStatistics packet_length{};
    std::array<PopulationStatistics, 2> directional_packet_length{};
    PopulationStatistics flow_iat_ns{};
    std::array<PopulationStatistics, 2> directional_iat_ns{};
    std::optional<FlowDirection> previous_direction{};
    std::uint64_t direction_change_count{};
    std::uint64_t tcp_syn_count{};
    std::uint64_t tcp_ack_count{};
    std::uint64_t tcp_fin_count{};
    std::uint64_t tcp_rst_count{};
    std::uint64_t tcp_psh_count{};
    std::array<std::optional<std::uint16_t>, 2> initial_tcp_window{};
    PopulationStatistics tcp_window{};
    PopulationStatistics ttl{};
    std::uint64_t payload_packet_count{};
    std::array<std::uint64_t, 2> directional_payload_packet_count{};
    std::uint64_t payload_byte_count{};
    std::array<std::uint64_t, 2> directional_payload_byte_count{};
    PopulationStatistics payload_length{};
    PopulationStatistics header_length{};
};

enum class FeatureErrorCode : std::uint8_t {
    numeric_overflow,
    non_finite_value,
    timestamp_overflow,
};

struct FeatureError {
    FeatureErrorCode code{};
    std::uint64_t packet_count{};
};

using FeatureUpdateResult = std::optional<FeatureError>;
using FeatureVectorResult = std::variant<FixedFeatureVector, FeatureError>;

struct FlowState;

class FeatureEngine {
public:
    [[nodiscard]] static FeatureUpdateResult update(
        FlowFeatureState& state,
        const PacketView& packet,
        FlowDirection direction,
        std::optional<std::int64_t> flow_iat_ns,
        std::optional<std::int64_t> direction_iat_ns,
        std::uint64_t packet_count) noexcept;

    [[nodiscard]] static FeatureVectorResult encode(
        const FlowState& state) noexcept;
};

}
