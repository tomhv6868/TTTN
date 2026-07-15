#include "nids/feature.hpp"

#include "nids/flow_table.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace nids {
namespace {

struct StatisticsSummary {
    double minimum{};
    double maximum{};
    double mean{};
    double standard_deviation{};
};

[[nodiscard]] constexpr std::size_t direction_index(
    FlowDirection direction) noexcept {
    return direction == FlowDirection::forward ? 0U : 1U;
}

[[nodiscard]] bool checked_add(
    std::uint64_t& target,
    std::uint64_t value) noexcept {
    if (value > std::numeric_limits<std::uint64_t>::max() - target) {
        return false;
    }
    target += value;
    return true;
}

[[nodiscard]] bool add_sample(
    PopulationStatistics& statistics,
    double value) noexcept {
    if (!std::isfinite(value)
        || statistics.count == std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
    if (statistics.count == 0U) {
        statistics.count = 1U;
        statistics.minimum = value;
        statistics.maximum = value;
        statistics.mean = value;
        statistics.m2 = 0.0;
        return true;
    }

    const auto next_count = statistics.count + 1U;
    const auto delta = value - statistics.mean;
    const auto next_mean = statistics.mean
        + delta / static_cast<double>(next_count);
    const auto next_m2 = statistics.m2 + delta * (value - next_mean);
    if (!std::isfinite(next_mean)
        || !std::isfinite(next_m2)
        || next_m2 < 0.0) {
        return false;
    }

    statistics.count = next_count;
    statistics.minimum = std::min(statistics.minimum, value);
    statistics.maximum = std::max(statistics.maximum, value);
    statistics.mean = next_mean;
    statistics.m2 = next_m2;
    return true;
}

[[nodiscard]] std::optional<StatisticsSummary> summarize(
    const PopulationStatistics& statistics) noexcept {
    if (statistics.count == 0U) {
        return StatisticsSummary{};
    }
    if (!std::isfinite(statistics.minimum)
        || !std::isfinite(statistics.maximum)
        || !std::isfinite(statistics.mean)
        || !std::isfinite(statistics.m2)
        || statistics.m2 < 0.0) {
        return std::nullopt;
    }
    const auto variance = statistics.m2
        / static_cast<double>(statistics.count);
    if (!std::isfinite(variance) || variance < 0.0) {
        return std::nullopt;
    }
    const auto standard_deviation = std::sqrt(variance);
    if (!std::isfinite(standard_deviation)) {
        return std::nullopt;
    }
    return StatisticsSummary{
        statistics.minimum,
        statistics.maximum,
        statistics.mean,
        standard_deviation,
    };
}

[[nodiscard]] double safe_divide(
    std::uint64_t numerator,
    std::uint64_t denominator) noexcept {
    if (denominator == 0U) {
        return 0.0;
    }
    return static_cast<double>(numerator)
        / static_cast<double>(denominator);
}

[[nodiscard]] FeatureError error(
    FeatureErrorCode code,
    std::uint64_t packet_count) noexcept {
    return FeatureError{code, packet_count};
}

}

FeatureUpdateResult FeatureEngine::update(
    FlowFeatureState& state,
    const PacketView& packet,
    FlowDirection direction,
    std::optional<std::int64_t> flow_iat_ns,
    std::optional<std::int64_t> direction_iat_ns,
    std::uint64_t packet_count) noexcept {
    if (packet.payload.offset > std::numeric_limits<std::uint32_t>::max()
        || packet.payload.length > std::numeric_limits<std::uint32_t>::max()) {
        return error(FeatureErrorCode::numeric_overflow, packet_count);
    }

    auto updated = state;
    const auto index = direction_index(direction);
    const auto wire_length = static_cast<std::uint64_t>(packet.wire_length);
    const auto payload_length = static_cast<std::uint64_t>(packet.payload.length);
    const auto header_length = static_cast<double>(packet.payload.offset);

    if (!checked_add(updated.wire_byte_count, wire_length)
        || !checked_add(updated.directional_wire_byte_count[index], wire_length)
        || !add_sample(updated.packet_length, static_cast<double>(wire_length))
        || !add_sample(
            updated.directional_packet_length[index],
            static_cast<double>(wire_length))) {
        return error(FeatureErrorCode::numeric_overflow, packet_count);
    }
    if (flow_iat_ns.has_value()
        && !add_sample(updated.flow_iat_ns, static_cast<double>(*flow_iat_ns))) {
        return error(FeatureErrorCode::non_finite_value, packet_count);
    }
    if (direction_iat_ns.has_value()
        && !add_sample(
            updated.directional_iat_ns[index],
            static_cast<double>(*direction_iat_ns))) {
        return error(FeatureErrorCode::non_finite_value, packet_count);
    }

    if (updated.previous_direction.has_value()
        && *updated.previous_direction != direction
        && !checked_add(updated.direction_change_count, 1U)) {
        return error(FeatureErrorCode::numeric_overflow, packet_count);
    }
    updated.previous_direction = direction;

    if (const auto* tcp = std::get_if<TcpView>(&packet.transport); tcp != nullptr) {
        const auto add_flag = [packet_count](
                                  std::uint64_t& count,
                                  bool present) -> FeatureUpdateResult {
            if (present && !checked_add(count, 1U)) {
                return error(FeatureErrorCode::numeric_overflow, packet_count);
            }
            return std::nullopt;
        };
        if (const auto result = add_flag(
                updated.tcp_syn_count,
                tcp->flags.contains(TcpFlag::syn));
            result.has_value()) {
            return result;
        }
        if (const auto result = add_flag(
                updated.tcp_ack_count,
                tcp->flags.contains(TcpFlag::ack));
            result.has_value()) {
            return result;
        }
        if (const auto result = add_flag(
                updated.tcp_fin_count,
                tcp->flags.contains(TcpFlag::fin));
            result.has_value()) {
            return result;
        }
        if (const auto result = add_flag(
                updated.tcp_rst_count,
                tcp->flags.contains(TcpFlag::rst));
            result.has_value()) {
            return result;
        }
        if (const auto result = add_flag(
                updated.tcp_psh_count,
                tcp->flags.contains(TcpFlag::psh));
            result.has_value()) {
            return result;
        }
        if (!updated.initial_tcp_window[index].has_value()) {
            updated.initial_tcp_window[index] = tcp->window_size;
        }
        if (!add_sample(updated.tcp_window, static_cast<double>(tcp->window_size))) {
            return error(FeatureErrorCode::non_finite_value, packet_count);
        }
    }

    if (!add_sample(updated.ttl, static_cast<double>(packet.ipv4.ttl))
        || !add_sample(updated.payload_length, static_cast<double>(payload_length))
        || !add_sample(updated.header_length, header_length)) {
        return error(FeatureErrorCode::non_finite_value, packet_count);
    }
    if (!checked_add(updated.payload_byte_count, payload_length)
        || !checked_add(
            updated.directional_payload_byte_count[index],
            payload_length)) {
        return error(FeatureErrorCode::numeric_overflow, packet_count);
    }
    if (payload_length > 0U
        && (!checked_add(updated.payload_packet_count, 1U)
            || !checked_add(
                updated.directional_payload_packet_count[index],
                1U))) {
        return error(FeatureErrorCode::numeric_overflow, packet_count);
    }

    state = updated;
    return std::nullopt;
}

FeatureVectorResult FeatureEngine::encode(const FlowState& state) noexcept {
    const auto age_ns = signed_iat_ns(
        state.last_event_timestamp_ns,
        state.creation_timestamp_ns);
    if (!age_ns.has_value() || *age_ns < 0) {
        return error(FeatureErrorCode::timestamp_overflow, state.packet_count);
    }

    const auto packet_length = summarize(state.feature_state.packet_length);
    const auto forward_packet_length = summarize(
        state.feature_state.directional_packet_length[0]);
    const auto reverse_packet_length = summarize(
        state.feature_state.directional_packet_length[1]);
    const auto flow_iat = summarize(state.feature_state.flow_iat_ns);
    const auto forward_iat = summarize(
        state.feature_state.directional_iat_ns[0]);
    const auto reverse_iat = summarize(
        state.feature_state.directional_iat_ns[1]);
    const auto tcp_window = summarize(state.feature_state.tcp_window);
    const auto ttl = summarize(state.feature_state.ttl);
    const auto payload_length = summarize(state.feature_state.payload_length);
    const auto header_length = summarize(state.feature_state.header_length);
    if (!packet_length.has_value()
        || !forward_packet_length.has_value()
        || !reverse_packet_length.has_value()
        || !flow_iat.has_value()
        || !forward_iat.has_value()
        || !reverse_iat.has_value()
        || !tcp_window.has_value()
        || !ttl.has_value()
        || !payload_length.has_value()
        || !header_length.has_value()) {
        return error(FeatureErrorCode::non_finite_value, state.packet_count);
    }

    const auto age_us = static_cast<double>(*age_ns) / 1'000.0;
    const auto packet_rate = age_us <= 0.0
        ? 0.0
        : static_cast<double>(state.packet_count) * 1'000'000.0 / age_us;
    const auto wire_byte_rate = age_us <= 0.0
        ? 0.0
        : static_cast<double>(state.feature_state.wire_byte_count)
            * 1'000'000.0 / age_us;

    FixedFeatureVector vector{};
    std::size_t index{};
    const auto append = [&vector, &index](double value) {
        vector[index] = value;
        ++index;
    };

    append(age_us);
    append(static_cast<double>(state.packet_count));
    append(static_cast<double>(state.directional_packet_count[0]));
    append(static_cast<double>(state.directional_packet_count[1]));
    append(static_cast<double>(state.feature_state.wire_byte_count));
    append(static_cast<double>(state.feature_state.directional_wire_byte_count[0]));
    append(static_cast<double>(state.feature_state.directional_wire_byte_count[1]));
    append(packet_length->minimum);
    append(packet_length->maximum);
    append(packet_length->mean);
    append(packet_length->standard_deviation);
    append(forward_packet_length->mean);
    append(forward_packet_length->standard_deviation);
    append(reverse_packet_length->mean);
    append(reverse_packet_length->standard_deviation);
    append(flow_iat->minimum / 1'000.0);
    append(flow_iat->maximum / 1'000.0);
    append(flow_iat->mean / 1'000.0);
    append(flow_iat->standard_deviation / 1'000.0);
    append(forward_iat->mean / 1'000.0);
    append(forward_iat->standard_deviation / 1'000.0);
    append(reverse_iat->mean / 1'000.0);
    append(reverse_iat->standard_deviation / 1'000.0);
    append(packet_rate);
    append(wire_byte_rate);
    append(safe_divide(
        state.directional_packet_count[0],
        state.directional_packet_count[1]));
    append(safe_divide(
        state.feature_state.directional_wire_byte_count[0],
        state.feature_state.directional_wire_byte_count[1]));
    append(static_cast<double>(state.feature_state.direction_change_count));
    append(static_cast<double>(state.feature_state.tcp_syn_count));
    append(static_cast<double>(state.feature_state.tcp_ack_count));
    append(static_cast<double>(state.feature_state.tcp_fin_count));
    append(static_cast<double>(state.feature_state.tcp_rst_count));
    append(static_cast<double>(state.feature_state.tcp_psh_count));
    append(safe_divide(
        state.feature_state.tcp_syn_count,
        state.feature_state.tcp_ack_count));
    append(static_cast<double>(
        state.feature_state.initial_tcp_window[0].value_or(0U)));
    append(static_cast<double>(
        state.feature_state.initial_tcp_window[1].value_or(0U)));
    append(tcp_window->mean);
    append(tcp_window->standard_deviation);
    append(ttl->minimum);
    append(ttl->maximum);
    append(ttl->mean);
    append(ttl->standard_deviation);
    append(static_cast<double>(state.feature_state.payload_packet_count));
    append(static_cast<double>(
        state.feature_state.directional_payload_packet_count[0]));
    append(static_cast<double>(
        state.feature_state.directional_payload_packet_count[1]));
    append(static_cast<double>(state.feature_state.payload_byte_count));
    append(static_cast<double>(
        state.feature_state.directional_payload_byte_count[0]));
    append(static_cast<double>(
        state.feature_state.directional_payload_byte_count[1]));
    append(payload_length->minimum);
    append(payload_length->maximum);
    append(payload_length->mean);
    append(payload_length->standard_deviation);
    append(header_length->mean);
    append(header_length->standard_deviation);

    if (index != flow_feature_count_v1 || !finite_feature_vector(vector)) {
        return error(FeatureErrorCode::non_finite_value, state.packet_count);
    }
    return vector;
}

}
