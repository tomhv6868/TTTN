#pragma once

#include "nids/feature.hpp"
#include "nids/flow.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace nids {

inline constexpr std::size_t flow_close_reason_count = 7U;

struct FlowState {
    FlowIdentity identity{};
    std::uint64_t generation{};
    ClockDomain clock_domain{ClockDomain::unix_epoch};
    std::int64_t creation_timestamp_ns{};
    std::int64_t last_capture_timestamp_ns{};
    std::int64_t last_event_timestamp_ns{};
    std::array<std::optional<std::int64_t>, 2> last_direction_timestamp_ns{};
    std::uint64_t packet_count{};
    std::array<std::uint64_t, 2> directional_packet_count{};
    FlowFeatureState feature_state{};
    CheckpointTracker checkpoint_tracker{};
    bool initial_syn_retransmission_open{};
    FlowEndpoint initial_syn_source{};
    std::uint32_t initial_syn_sequence_number{};
    std::array<bool, 2> fin_seen{};
    std::optional<FlowDirection> final_ack_direction{};
};

struct FlowPacketContext {
    FlowDirection direction{};
    std::optional<std::int64_t> flow_iat_ns{};
    std::optional<std::int64_t> direction_iat_ns{};
    std::optional<Checkpoint> checkpoint{};
    bool created{};
};

class FlowObserver {
public:
    virtual ~FlowObserver() = default;

    // State is an immutable event snapshot; callback references are valid only for the call.
    virtual void on_packet(
        const FlowState& state,
        const PacketView& packet,
        const FlowPacketContext& context) noexcept = 0;

    virtual void on_close(
        const FlowState& state,
        FlowCloseReason reason) noexcept = 0;
};

struct FlowTableConfig {
    std::uint32_t hard_active_flow_limit{flow_capacity_v1.hard_active_flow_limit};
    std::uint64_t memory_budget_bytes{flow_capacity_v1.memory_budget_bytes};
};

enum class FlowIngestStatus : std::uint8_t {
    accepted,
    clock_domain_mismatch,
    timestamp_overflow,
    feature_update_error,
    resource_exhausted,
};

struct FlowIngestResult {
    FlowIngestStatus status{FlowIngestStatus::accepted};
    std::optional<std::uint64_t> generation{};
    std::optional<FlowDirection> direction{};
    std::optional<std::int64_t> flow_iat_ns{};
    std::optional<std::int64_t> direction_iat_ns{};
    std::optional<FeatureErrorCode> feature_error{};
    bool created{};
    std::optional<FlowCloseReason> close_reason{};
};

struct FlowCounters {
    std::uint64_t packets_accepted{};
    std::uint64_t packets_rejected_clock_domain{};
    std::uint64_t packets_rejected_timestamp_overflow{};
    std::uint64_t packets_rejected_feature_update{};
    std::uint64_t packets_rejected_resource_exhausted{};
    std::uint64_t flow_generations_created{};
    std::uint64_t flows_closed{};
    std::array<std::uint64_t, flow_close_reason_count> close_reason_count{};
    std::uint32_t active_flow_count{};
    std::uint32_t peak_active_flow_count{};
    std::uint64_t fixed_memory_bytes{};
    std::uint64_t current_allocator_bytes{};
    std::uint64_t peak_allocator_bytes{};
    std::uint64_t current_memory_bytes{};
    std::uint64_t peak_memory_bytes{};
    std::uint64_t memory_budget_bytes{};
};

[[nodiscard]] constexpr std::size_t flow_close_reason_index(
    FlowCloseReason reason) noexcept {
    return static_cast<std::size_t>(reason);
}

class FlowTable {
public:
    explicit FlowTable(FlowTableConfig config = {});
    // Observer must outlive the table. Callbacks may re-enter, but must not destroy or move it.
    FlowTable(FlowObserver& observer, FlowTableConfig config = {});
    ~FlowTable();

    FlowTable(const FlowTable&) = delete;
    FlowTable& operator=(const FlowTable&) = delete;
    FlowTable(FlowTable&&) noexcept;
    FlowTable& operator=(FlowTable&&) noexcept;

    [[nodiscard]] FlowIngestResult ingest(const PacketView& packet);
    void flush();

    // The returned pointer is invalidated by the next ingest or flush operation.
    [[nodiscard]] const FlowState* find(const FlowKey& key) const noexcept;
    [[nodiscard]] std::optional<std::int64_t> watermark_ns() const noexcept;
    [[nodiscard]] std::optional<ClockDomain> clock_domain() const noexcept;
    [[nodiscard]] FlowCounters counters() const noexcept;

private:
    FlowTable(FlowObserver* observer, FlowTableConfig config);

    class Impl;
    std::unique_ptr<Impl> impl_;
};

}
