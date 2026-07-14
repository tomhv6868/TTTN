#pragma once

#include "nids/packet.hpp"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>

namespace nids {

inline constexpr std::size_t flow_feature_count_v1 = 54U;
using FixedFeatureVector = std::array<double, flow_feature_count_v1>;

enum class Checkpoint : std::uint8_t {
    f3 = 3,
    f5 = 5,
    f7 = 7,
    f9 = 9,
};

inline constexpr std::array<Checkpoint, 4> checkpoint_schedule_v1{
    Checkpoint::f3,
    Checkpoint::f5,
    Checkpoint::f7,
    Checkpoint::f9,
};

[[nodiscard]] constexpr std::uint32_t checkpoint_packet_count(
    Checkpoint checkpoint) noexcept {
    return static_cast<std::uint32_t>(checkpoint);
}

[[nodiscard]] constexpr std::optional<Checkpoint> checkpoint_for_packet_count(
    std::uint64_t packet_count) noexcept {
    switch (packet_count) {
    case 3U:
        return Checkpoint::f3;
    case 5U:
        return Checkpoint::f5;
    case 7U:
        return Checkpoint::f7;
    case 9U:
        return Checkpoint::f9;
    default:
        return std::nullopt;
    }
}

[[nodiscard]] constexpr std::uint8_t checkpoint_bit(Checkpoint checkpoint) noexcept {
    switch (checkpoint) {
    case Checkpoint::f3:
        return 1U << 0U;
    case Checkpoint::f5:
        return 1U << 1U;
    case Checkpoint::f7:
        return 1U << 2U;
    case Checkpoint::f9:
        return 1U << 3U;
    }
    return 0U;
}

class CheckpointTracker {
public:
    [[nodiscard]] constexpr std::optional<Checkpoint> claim(
        std::uint64_t packet_count) noexcept {
        const auto checkpoint = checkpoint_for_packet_count(packet_count);
        if (!checkpoint.has_value()) {
            return std::nullopt;
        }
        const auto bit = checkpoint_bit(*checkpoint);
        if ((emitted_mask_ & bit) != 0U) {
            return std::nullopt;
        }
        emitted_mask_ = static_cast<std::uint8_t>(emitted_mask_ | bit);
        return checkpoint;
    }

    [[nodiscard]] constexpr bool emitted(Checkpoint checkpoint) const noexcept {
        return (emitted_mask_ & checkpoint_bit(checkpoint)) != 0U;
    }

    [[nodiscard]] constexpr std::uint8_t emitted_mask() const noexcept {
        return emitted_mask_;
    }

private:
    std::uint8_t emitted_mask_{};
};

struct FlowInstanceId {
    std::uint64_t namespace_id{};
    std::uint64_t sequence{};

    friend constexpr bool operator==(const FlowInstanceId&, const FlowInstanceId&) noexcept = default;

    [[nodiscard]] constexpr bool is_valid() const noexcept {
        return namespace_id != 0U || sequence != 0U;
    }
};

struct DatasetSplitGroupId {
    std::uint64_t namespace_id{};
    std::uint64_t sequence{};

    friend constexpr bool operator==(
        const DatasetSplitGroupId&,
        const DatasetSplitGroupId&) noexcept = default;
};

struct PacketSequencePrefixRef {
    FlowInstanceId flow_id{};
    std::uint32_t packet_count{};

    friend constexpr bool operator==(
        const PacketSequencePrefixRef&,
        const PacketSequencePrefixRef&) noexcept = default;
};

struct FeatureSchemaVersion {
    std::uint16_t major{};
    std::uint16_t minor{};
    std::uint16_t patch{};

    friend constexpr bool operator==(
        const FeatureSchemaVersion&,
        const FeatureSchemaVersion&) noexcept = default;
};

inline constexpr FeatureSchemaVersion flow_feature_schema_version_v1{1U, 0U, 0U};

struct SnapshotMetadata {
    FlowInstanceId flow_id{};
    Checkpoint checkpoint{Checkpoint::f3};
    std::uint64_t packet_count{};
    std::int64_t checkpoint_timestamp_ns{};
    ClockDomain clock_domain{ClockDomain::unix_epoch};
    PacketSequencePrefixRef packet_sequence_prefix{};
    std::optional<DatasetSplitGroupId> split_group_id{};
    FeatureSchemaVersion feature_schema_version{flow_feature_schema_version_v1};
};

struct CheckpointSnapshot {
    SnapshotMetadata metadata{};
    FixedFeatureVector model_features{};
};

struct NoCheckpoint {
    friend constexpr bool operator==(NoCheckpoint, NoCheckpoint) noexcept = default;
};

enum class CheckpointErrorCode : std::uint8_t {
    invalid_metadata,
    packet_sequence_prefix_unavailable,
    non_finite_feature,
    timestamp_overflow,
};

struct CheckpointError {
    CheckpointErrorCode code{};
    FlowInstanceId flow_id{};
    std::uint64_t packet_count{};
};

using CheckpointResult = std::variant<NoCheckpoint, CheckpointSnapshot, CheckpointError>;

enum class OfflineCheckpointErrorPolicy : std::uint8_t {
    abort_run,
};

enum class LiveCheckpointErrorPolicy : std::uint8_t {
    discard_flow_generation_increment_counter_and_continue,
};

struct CheckpointContract {
    bool update_flow_and_features_before_checkpoint{};
    bool include_triggering_packet{};
    bool packet_sequence_record_precedes_snapshot{};
    bool emit_before_terminal_close{};
    bool emit_each_checkpoint_once_per_generation{};
    bool emit_only_reached_checkpoints{};
    bool synthesize_final_checkpoint{};
    bool reset_schedule_for_new_generation{};
    bool snapshot_owns_feature_vector{};
    bool snapshot_owns_packet_bytes{};
    bool metadata_is_model_input{};
    bool flow_id_is_opaque{};
    bool flow_id_is_derived_from_endpoints{};
    OfflineCheckpointErrorPolicy offline_error_policy{};
    LiveCheckpointErrorPolicy live_error_policy{};
};

inline constexpr CheckpointContract checkpoint_contract_v1{
    true,
    true,
    true,
    true,
    true,
    true,
    false,
    true,
    true,
    false,
    false,
    true,
    false,
    OfflineCheckpointErrorPolicy::abort_run,
    LiveCheckpointErrorPolicy::discard_flow_generation_increment_counter_and_continue,
};

[[nodiscard]] constexpr bool valid_snapshot_metadata(
    const SnapshotMetadata& metadata) noexcept {
    const auto expected_packet_count = checkpoint_packet_count(metadata.checkpoint);
    return metadata.flow_id.is_valid()
        && metadata.packet_count == expected_packet_count
        && metadata.packet_sequence_prefix.flow_id == metadata.flow_id
        && metadata.packet_sequence_prefix.packet_count == expected_packet_count
        && metadata.feature_schema_version == flow_feature_schema_version_v1;
}

[[nodiscard]] inline bool finite_feature_vector(
    const FixedFeatureVector& features) noexcept {
    for (const auto value : features) {
        if (!std::isfinite(value)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline CheckpointResult make_checkpoint_snapshot(
    SnapshotMetadata metadata,
    FixedFeatureVector features,
    bool packet_sequence_prefix_ready) noexcept {
    if (!valid_snapshot_metadata(metadata)) {
        return CheckpointError{
            CheckpointErrorCode::invalid_metadata,
            metadata.flow_id,
            metadata.packet_count,
        };
    }
    if (!packet_sequence_prefix_ready) {
        return CheckpointError{
            CheckpointErrorCode::packet_sequence_prefix_unavailable,
            metadata.flow_id,
            metadata.packet_count,
        };
    }
    if (!finite_feature_vector(features)) {
        return CheckpointError{
            CheckpointErrorCode::non_finite_feature,
            metadata.flow_id,
            metadata.packet_count,
        };
    }
    return CheckpointSnapshot{std::move(metadata), std::move(features)};
}

[[nodiscard]] inline std::span<const double, flow_feature_count_v1> model_input(
    const CheckpointSnapshot& snapshot) noexcept {
    return snapshot.model_features;
}

}
