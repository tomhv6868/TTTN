#pragma once

#include "nids/alert.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace nids {

inline constexpr std::string_view accepted_model_artifact_id_v1{
    "nids.native_inference_bundle.v1",
};
inline constexpr std::string_view accepted_model_artifact_version_v1{"1.0.0"};

enum class IncidentTrackerErrorCode : std::uint8_t {
    duplicate_or_out_of_order_checkpoint,
    capacity_exceeded,
};

struct IncidentTrackerError {
    IncidentTrackerErrorCode code{};
    std::string detail{};
};

using IncidentTrackerResult =
    std::variant<IncidentMetadata, IncidentTrackerError>;

class IncidentTracker final {
public:
    static constexpr std::size_t maximum_incidents{65'536U};

    [[nodiscard]] IncidentTrackerResult observe(
        FlowInstanceId flow_id,
        Checkpoint checkpoint);
    void erase(FlowInstanceId flow_id) noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    struct FlowIdHash {
        [[nodiscard]] std::size_t operator()(
            const FlowInstanceId& value) const noexcept;
    };

    struct State {
        Checkpoint first_checkpoint{Checkpoint::f3};
        Checkpoint latest_checkpoint{Checkpoint::f3};
        std::uint32_t update_index{};
    };

    std::unordered_map<FlowInstanceId, State, FlowIdHash> incidents_{};
};

struct DetectionPipelineConfig {
    std::string model_artifact_id{accepted_model_artifact_id_v1};
    std::string model_artifact_version{accepted_model_artifact_version_v1};
    std::optional<DecisionThresholds> decision_thresholds{};
    IncidentTracker* incident_tracker{};
};

struct NoDetectionAlert {
    Decision decision{};
};

struct DetectionAlert {
    Decision decision{};
    ModelScores scores{};
    std::string json_line{};
};

enum class DetectionPipelineErrorCode : std::uint8_t {
    invalid_snapshot,
    checkpoint_bundle_mismatch,
    model_inference_failure,
    incident_tracking_failure,
    alert_serialization_failure,
    internal_failure,
};

struct DetectionPipelineError {
    DetectionPipelineErrorCode code{};
    std::string detail{};
};

using DetectionPipelineResult = std::variant<
    NoDetectionAlert,
    DetectionAlert,
    DetectionPipelineError>;

class DetectionPipeline final {
public:
    explicit DetectionPipeline(
        const ModelBundle& bundle,
        DetectionPipelineConfig config = {});

    [[nodiscard]] DetectionPipelineResult process(
        const FlowIdentity& flow,
        const CheckpointSnapshot& snapshot,
        std::uint64_t detection_delay_ns) const noexcept;

private:
    const ModelBundle* bundle_{};
    DetectionPipelineConfig config_{};
    DecisionEngine decision_engine_{};
    IncidentTracker owned_incident_tracker_{};
    IncidentTracker* incident_tracker_{};
};

}
