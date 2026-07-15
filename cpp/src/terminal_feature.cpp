#include "nids/terminal_feature.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <new>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace nids {
namespace {

constexpr std::int64_t idle_threshold_ns = 5'000'000'000LL;
constexpr std::int64_t context_block_ns = 60'000'000'000LL;
constexpr std::size_t context_entry_limit = 1'048'576U;

struct RunningMean {
    std::uint64_t count{};
    double mean{};
};

struct ExtraFlowState {
    TransportProtocol protocol{};
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    std::array<RunningMean, 2> directional_ttl{};
    RunningMean active_us{};
    RunningMean idle_us{};
    std::int64_t active_start_ns{};
    std::int64_t last_watermark_ns{};
    std::uint64_t same_destination_endpoint_count{};
    std::uint64_t same_source_destination_count{};
    std::uint64_t distinct_destination_port_count{};
};

[[nodiscard]] constexpr std::size_t direction_index(
    FlowDirection direction) noexcept {
    return static_cast<std::size_t>(direction);
}

[[nodiscard]] constexpr std::uint32_t ipv4_value(
    const Ipv4Address& address) noexcept {
    return (static_cast<std::uint32_t>(address.wire_bytes[0]) << 24U)
        | (static_cast<std::uint32_t>(address.wire_bytes[1]) << 16U)
        | (static_cast<std::uint32_t>(address.wire_bytes[2]) << 8U)
        | static_cast<std::uint32_t>(address.wire_bytes[3]);
}

[[nodiscard]] constexpr std::uint64_t destination_endpoint_key(
    const FlowEndpoint& endpoint) noexcept {
    return (static_cast<std::uint64_t>(ipv4_value(endpoint.address)) << 16U)
        | endpoint.port;
}

[[nodiscard]] constexpr std::uint64_t source_destination_key(
    const FlowEndpoint& source,
    const FlowEndpoint& destination) noexcept {
    return (static_cast<std::uint64_t>(ipv4_value(source.address)) << 32U)
        | ipv4_value(destination.address);
}

[[nodiscard]] constexpr std::int64_t floor_block(
    std::int64_t timestamp_ns) noexcept {
    auto quotient = timestamp_ns / context_block_ns;
    if (timestamp_ns % context_block_ns < 0) {
        --quotient;
    }
    return quotient;
}

[[nodiscard]] bool increment(std::uint64_t& value) noexcept {
    if (value == std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
    ++value;
    return true;
}

[[nodiscard]] bool add_mean(RunningMean& state, double value) noexcept {
    if (!std::isfinite(value) || !increment(state.count)) {
        return false;
    }
    state.mean += (value - state.mean) / static_cast<double>(state.count);
    return std::isfinite(state.mean);
}

[[nodiscard]] TerminalFeatureError failure(
    TerminalFeatureErrorCode code,
    std::uint64_t generation) noexcept {
    return TerminalFeatureError{code, generation};
}

[[nodiscard]] double rate(
    double byte_count,
    double flow_age_us) noexcept {
    if (flow_age_us <= 0.0) {
        return 0.0;
    }
    return byte_count * 8.0 * 1'000'000.0 / flow_age_us;
}

}

class TerminalFeatureEngine::Impl {
public:
    [[nodiscard]] TerminalFeatureUpdateResult update(
        const FlowState& state,
        const PacketView& packet,
        const FlowPacketContext& context) noexcept {
        try {
            global_watermark_ns_ = global_watermark_ns_.has_value()
                ? std::max(*global_watermark_ns_, packet.timestamp_ns)
                : packet.timestamp_ns;

            auto flow = flows_.find(state.generation);
            if (context.created) {
                if (flow != flows_.end()) {
                    return failure(
                        TerminalFeatureErrorCode::duplicate_generation,
                        state.generation);
                }
                const auto created = create_state(state, packet);
                if (std::holds_alternative<TerminalFeatureError>(created)) {
                    return std::get<TerminalFeatureError>(created);
                }
                flow = flows_.emplace(
                    state.generation,
                    std::get<ExtraFlowState>(created)).first;
            } else if (flow == flows_.end()) {
                return failure(
                    TerminalFeatureErrorCode::missing_generation,
                    state.generation);
            }

            auto& extra = flow->second;
            const auto watermark_ns = state.last_event_timestamp_ns;
            if (!context.created) {
                const auto gap_ns = watermark_ns - extra.last_watermark_ns;
                if (gap_ns > idle_threshold_ns) {
                    const auto active_ns =
                        extra.last_watermark_ns - extra.active_start_ns;
                    if (!add_mean(
                            extra.active_us,
                            static_cast<double>(active_ns) / 1000.0)
                        || !add_mean(
                            extra.idle_us,
                            static_cast<double>(gap_ns) / 1000.0)) {
                        return failure(
                            TerminalFeatureErrorCode::numeric_overflow,
                            state.generation);
                    }
                    extra.active_start_ns = watermark_ns;
                }
                extra.last_watermark_ns = watermark_ns;
            }

            if (!add_mean(
                    extra.directional_ttl[direction_index(context.direction)],
                    static_cast<double>(packet.ipv4.ttl))) {
                return failure(
                    TerminalFeatureErrorCode::numeric_overflow,
                    state.generation);
            }
            return std::nullopt;
        } catch (const std::bad_alloc&) {
            return failure(
                TerminalFeatureErrorCode::resource_exhausted,
                state.generation);
        } catch (...) {
            return failure(
                TerminalFeatureErrorCode::non_finite_value,
                state.generation);
        }
    }

    [[nodiscard]] TerminalFeatureVectorResult close(
        const FlowState& state) noexcept {
        try {
            const auto found = flows_.find(state.generation);
            if (found == flows_.end()) {
                return failure(
                    TerminalFeatureErrorCode::missing_generation,
                    state.generation);
            }
            auto extra = found->second;
            flows_.erase(found);

            const auto encoded = FeatureEngine::encode(state);
            if (!std::holds_alternative<FixedFeatureVector>(encoded)) {
                return failure(
                    TerminalFeatureErrorCode::base_feature_error,
                    state.generation);
            }
            if (!add_mean(
                    extra.active_us,
                    static_cast<double>(
                        extra.last_watermark_ns - extra.active_start_ns)
                        / 1000.0)) {
                return failure(
                    TerminalFeatureErrorCode::numeric_overflow,
                    state.generation);
            }

            TerminalFeatureVector vector{};
            const auto& base = std::get<FixedFeatureVector>(encoded);
            std::copy(base.begin(), base.end(), vector.begin());
            vector[54] = static_cast<double>(
                static_cast<std::uint8_t>(extra.protocol));
            vector[55] = extra.directional_ttl[
                direction_index(FlowDirection::forward)].mean;
            vector[56] = extra.directional_ttl[
                direction_index(FlowDirection::reverse)].mean;
            vector[57] = rate(vector[5], vector[0]);
            vector[58] = rate(vector[6], vector[0]);
            vector[59] = extra.active_us.mean;
            vector[60] = extra.idle_us.mean;
            vector[61] =
                static_cast<double>(extra.same_destination_endpoint_count);
            vector[62] =
                static_cast<double>(extra.same_source_destination_count);
            vector[63] =
                static_cast<double>(extra.distinct_destination_port_count);
            vector[64] = static_cast<double>(extra.source_port);
            vector[65] = static_cast<double>(extra.destination_port);

            const auto is_tcp = extra.protocol == TransportProtocol::tcp;
            const auto reset =
                is_tcp && state.feature_state.tcp_rst_count != 0U;
            const auto fin_handshake =
                is_tcp && !reset && state.fin_seen[0] && state.fin_seen[1];
            vector[66] = reset ? 1.0 : 0.0;
            vector[67] = fin_handshake ? 1.0 : 0.0;
            vector[68] = is_tcp && !reset && !fin_handshake ? 1.0 : 0.0;
            vector[69] = is_tcp ? 0.0 : 1.0;

            if (!std::all_of(
                    vector.begin(),
                    vector.end(),
                    [](double value) { return std::isfinite(value); })) {
                return failure(
                    TerminalFeatureErrorCode::non_finite_value,
                    state.generation);
            }
            return vector;
        } catch (const std::bad_alloc&) {
            return failure(
                TerminalFeatureErrorCode::resource_exhausted,
                state.generation);
        } catch (...) {
            return failure(
                TerminalFeatureErrorCode::non_finite_value,
                state.generation);
        }
    }

    [[nodiscard]] std::size_t active_generation_count() const noexcept {
        return flows_.size();
    }

private:
    using CreateResult = std::variant<ExtraFlowState, TerminalFeatureError>;

    [[nodiscard]] CreateResult create_state(
        const FlowState& state,
        const PacketView& packet) {
        const auto block = floor_block(*global_watermark_ns_);
        if (!context_block_.has_value() || *context_block_ != block) {
            context_block_ = block;
            destination_counts_.clear();
            source_destination_counts_.clear();
            source_destination_ports_.clear();
        }

        const auto source = source_endpoint(packet);
        const auto destination = destination_endpoint(packet);
        const auto destination_key = destination_endpoint_key(destination);
        const auto pair_key = source_destination_key(source, destination);
        if ((!destination_counts_.contains(destination_key)
                && destination_counts_.size() == context_entry_limit)
            || (!source_destination_counts_.contains(pair_key)
                && source_destination_counts_.size() == context_entry_limit)
            || (!source_destination_ports_.contains(pair_key)
                && source_destination_ports_.size() == context_entry_limit)) {
            return failure(
                TerminalFeatureErrorCode::resource_exhausted,
                state.generation);
        }
        auto& destination_count = destination_counts_[destination_key];
        auto& source_destination_count =
            source_destination_counts_[pair_key];
        if (!increment(destination_count)
            || !increment(source_destination_count)) {
            return failure(
                TerminalFeatureErrorCode::numeric_overflow,
                state.generation);
        }

        auto& ports = source_destination_ports_[pair_key];
        ports.insert(destination.port);

        return ExtraFlowState{
            transport_protocol(packet),
            source.port,
            destination.port,
            {},
            {},
            {},
            state.last_event_timestamp_ns,
            state.last_event_timestamp_ns,
            destination_count,
            source_destination_count,
            static_cast<std::uint64_t>(ports.size()),
        };
    }

    std::unordered_map<std::uint64_t, ExtraFlowState> flows_{};
    std::optional<std::int64_t> global_watermark_ns_{};
    std::optional<std::int64_t> context_block_{};
    std::unordered_map<std::uint64_t, std::uint64_t> destination_counts_{};
    std::unordered_map<std::uint64_t, std::uint64_t>
        source_destination_counts_{};
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint16_t>>
        source_destination_ports_{};
};

TerminalFeatureEngine::TerminalFeatureEngine()
    : impl_{std::make_unique<Impl>()} {}

TerminalFeatureEngine::~TerminalFeatureEngine() = default;
TerminalFeatureEngine::TerminalFeatureEngine(TerminalFeatureEngine&&) noexcept =
    default;
TerminalFeatureEngine& TerminalFeatureEngine::operator=(
    TerminalFeatureEngine&&) noexcept = default;

TerminalFeatureUpdateResult TerminalFeatureEngine::update(
    const FlowState& state,
    const PacketView& packet,
    const FlowPacketContext& context) noexcept {
    return impl_->update(state, packet, context);
}

TerminalFeatureVectorResult TerminalFeatureEngine::close(
    const FlowState& state) noexcept {
    return impl_->close(state);
}

std::size_t TerminalFeatureEngine::active_generation_count() const noexcept {
    return impl_->active_generation_count();
}

}
