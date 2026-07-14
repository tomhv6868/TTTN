#pragma once

#include "nids/flow.hpp"
#include "nids/model_runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace nids {

inline constexpr std::string_view alert_schema_version_v1{"1.0.0"};

enum class DetectionDecision : std::uint8_t {
    benign,
    known_attack,
    unknown_candidate,
    uncertain,
};

struct DecisionThresholds {
    double flow_rf{};
    double hbos_normalized{};
    double isolation_forest_normalized{};

    friend bool operator==(
        const DecisionThresholds&,
        const DecisionThresholds&) noexcept = default;
};

[[nodiscard]] bool valid_decision_thresholds(
    const DecisionThresholds& thresholds) noexcept;

struct Decision {
    DetectionDecision classification{DetectionDecision::benign};
    bool supervised_attack{};
    std::uint8_t anomaly_votes{};
    std::size_t known_family_index{};
    float known_family_confidence{};
    bool hbos_anomaly{};
    bool isolation_forest_anomaly{};
    std::optional<DecisionThresholds> calibrated_thresholds{};

    friend bool operator==(const Decision&, const Decision&) noexcept = default;
};

class DecisionEngine final {
public:
    explicit DecisionEngine(
        std::optional<DecisionThresholds> thresholds = std::nullopt) noexcept;

    [[nodiscard]] Decision classify(const ModelScores& scores) const noexcept;

private:
    std::optional<DecisionThresholds> thresholds_{};
};

[[nodiscard]] std::string_view decision_name(
    DetectionDecision decision) noexcept;

struct ThresholdConfigError {
    std::string detail{};
};

using ThresholdConfigResult =
    std::variant<DecisionThresholds, ThresholdConfigError>;

[[nodiscard]] ThresholdConfigResult load_decision_thresholds(
    const std::filesystem::path& path,
    Checkpoint checkpoint) noexcept;

enum class IncidentLifecycle : std::uint8_t {
    created,
    updated,
};

struct IncidentMetadata {
    FlowInstanceId flow_id{};
    IncidentLifecycle lifecycle{IncidentLifecycle::created};
    Checkpoint first_checkpoint{Checkpoint::f3};
    Checkpoint latest_checkpoint{Checkpoint::f3};
    std::uint32_t update_index{};

    friend bool operator==(
        const IncidentMetadata&,
        const IncidentMetadata&) noexcept = default;
};

[[nodiscard]] std::string_view incident_lifecycle_name(
    IncidentLifecycle lifecycle) noexcept;

struct AlertEvent {
    FlowIdentity flow{};
    SnapshotMetadata snapshot{};
    ModelScores scores{};
    Decision decision{};
    std::string known_family_candidate{};
    std::string model_artifact_id{};
    std::string model_artifact_version{};
    std::uint64_t detection_delay_ns{};
    std::optional<IncidentMetadata> incident{};
};

enum class AlertErrorCode : std::uint8_t {
    invalid_event,
    serialization_failure,
};

struct AlertError {
    AlertErrorCode code{};
    std::string detail{};
};

using AlertJsonResult = std::variant<std::string, AlertError>;

[[nodiscard]] AlertJsonResult serialize_alert_json_line(
    const AlertEvent& event) noexcept;

}
