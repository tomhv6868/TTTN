#include "nids/alert.hpp"

#include <jansson.h>

#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace nids {
namespace {

struct JsonDeleter {
    void operator()(json_t* value) const noexcept {
        if (value != nullptr) {
            json_decref(value);
        }
    }
};

using JsonDocument = std::unique_ptr<json_t, JsonDeleter>;

class SerializationFailure final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] JsonDocument checked(json_t* value) {
    if (value == nullptr) {
        throw SerializationFailure{"JSON allocation failed"};
    }
    return JsonDocument{value};
}

[[nodiscard]] json_t* required_object(json_t* object, const char* name) {
    auto* const value = json_object_get(object, name);
    if (!json_is_object(value)) {
        throw SerializationFailure{
            "threshold artifact member is not an object: "
            + std::string{name},
        };
    }
    return value;
}

[[nodiscard]] std::string_view required_string(
    json_t* object,
    const char* name) {
    auto* const value = json_object_get(object, name);
    if (!json_is_string(value)) {
        throw SerializationFailure{
            "threshold artifact member is not a string: "
            + std::string{name},
        };
    }
    return json_string_value(value);
}

[[nodiscard]] double required_number(json_t* object, const char* name) {
    auto* const value = json_object_get(object, name);
    if (!json_is_number(value)) {
        throw SerializationFailure{
            "threshold artifact member is not numeric: "
            + std::string{name},
        };
    }
    return json_number_value(value);
}

void set(json_t* object, const char* name, JsonDocument value) {
    if (json_object_set(object, name, value.get()) != 0) {
        throw SerializationFailure{
            "failed to set JSON member: " + std::string{name},
        };
    }
}

void append(json_t* array, JsonDocument value) {
    if (json_array_append(array, value.get()) != 0) {
        throw SerializationFailure{"failed to append JSON array value"};
    }
}

[[nodiscard]] std::string unsigned_decimal(std::uint64_t value) {
    return std::to_string(value);
}

[[nodiscard]] std::string ipv4_text(const Ipv4Address& address) {
    return std::to_string(address.wire_bytes[0]) + "."
        + std::to_string(address.wire_bytes[1]) + "."
        + std::to_string(address.wire_bytes[2]) + "."
        + std::to_string(address.wire_bytes[3]);
}

[[nodiscard]] std::string feature_schema_version_text(
    FeatureSchemaVersion version) {
    return std::to_string(version.major) + "."
        + std::to_string(version.minor) + "."
        + std::to_string(version.patch);
}

[[nodiscard]] std::string checkpoint_text(Checkpoint checkpoint) {
    return "F" + std::to_string(checkpoint_packet_count(checkpoint));
}

[[nodiscard]] std::string_view protocol_name(
    TransportProtocol protocol) noexcept {
    switch (protocol) {
    case TransportProtocol::tcp:
        return "tcp";
    case TransportProtocol::udp:
        return "udp";
    }
    return "invalid";
}

[[nodiscard]] std::string_view clock_domain_name(
    ClockDomain domain) noexcept {
    switch (domain) {
    case ClockDomain::unix_epoch:
        return "unix_epoch";
    case ClockDomain::monotonic:
        return "monotonic";
    }
    return "invalid";
}

[[nodiscard]] bool probability(float value) noexcept {
    return std::isfinite(value) && value >= 0.0F && value <= 1.0F;
}

[[nodiscard]] bool finite_anomaly(const AnomalyScore& value) noexcept {
    return std::isfinite(value.raw) && std::isfinite(value.normalized);
}

[[nodiscard]] bool valid_scores(const ModelScores& scores) noexcept {
    if (!probability(scores.flow_attack_probability)
        || scores.known_family_index >= known_family_count_v1
        || !probability(scores.known_family_confidence)
        || !finite_anomaly(scores.hbos)
        || !finite_anomaly(scores.isolation_forest)) {
        return false;
    }
    double total{};
    for (const auto value : scores.known_family_probabilities) {
        if (!probability(value)) {
            return false;
        }
        total += value;
    }
    return std::abs(total - 1.0) <= 1e-3
        && std::abs(
               scores.known_family_probabilities[scores.known_family_index]
               - scores.known_family_confidence)
            <= 1e-6F;
}

[[nodiscard]] bool valid_flow_identity(const FlowIdentity& flow) noexcept {
    return !(flow.key.high < flow.key.low)
        && (flow.forward_source == flow.key.low
            || flow.forward_source == flow.key.high)
        && protocol_name(flow.key.protocol) != "invalid";
}

[[nodiscard]] JsonDocument endpoint_json(const FlowEndpoint& endpoint) {
    auto result = checked(json_object());
    set(
        result.get(),
        "ip",
        checked(json_string(ipv4_text(endpoint.address).c_str())));
    set(
        result.get(),
        "port",
        checked(json_integer(static_cast<json_int_t>(endpoint.port))));
    return result;
}

[[nodiscard]] JsonDocument anomaly_json(
    const AnomalyScore& score,
    bool threshold_exceeded) {
    auto result = checked(json_object());
    set(result.get(), "raw", checked(json_real(score.raw)));
    set(result.get(), "normalized", checked(json_real(score.normalized)));
    set(
        result.get(),
        "threshold_exceeded",
        checked(json_boolean(threshold_exceeded)));
    return result;
}

[[nodiscard]] JsonDocument evidence_json(const AlertEvent& event) {
    auto evidence = checked(json_object());

    auto flow_rf = checked(json_object());
    set(
        flow_rf.get(),
        "attack_probability",
        checked(json_real(event.scores.flow_attack_probability)));
    set(
        flow_rf.get(),
        "threshold_exceeded",
        checked(json_boolean(event.decision.supervised_attack)));
    set(evidence.get(), "flow_rf", std::move(flow_rf));

    auto known = checked(json_object());
    set(
        known.get(),
        "top_candidate",
        checked(json_string(event.known_family_candidate.c_str())));
    set(
        known.get(),
        "class_index",
        checked(json_integer(static_cast<json_int_t>(
            event.scores.known_family_index))));
    set(
        known.get(),
        "confidence",
        checked(json_real(event.scores.known_family_confidence)));
    auto probabilities = checked(json_array());
    for (const auto value : event.scores.known_family_probabilities) {
        append(probabilities.get(), checked(json_real(value)));
    }
    set(known.get(), "probabilities", std::move(probabilities));
    set(evidence.get(), "known_family", std::move(known));

    set(
        evidence.get(),
        "hbos",
        anomaly_json(event.scores.hbos, event.decision.hbos_anomaly));
    set(
        evidence.get(),
        "isolation_forest",
        anomaly_json(
            event.scores.isolation_forest,
            event.decision.isolation_forest_anomaly));
    set(
        evidence.get(),
        "anomaly_votes",
        checked(json_integer(event.decision.anomaly_votes)));
    if (event.decision.calibrated_thresholds.has_value()) {
        const auto& thresholds = *event.decision.calibrated_thresholds;
        auto values = checked(json_object());
        set(
            values.get(),
            "flow_rf",
            checked(json_real(thresholds.flow_rf)));
        set(
            values.get(),
            "hbos_normalized",
            checked(json_real(thresholds.hbos_normalized)));
        set(
            values.get(),
            "isolation_forest_normalized",
            checked(json_real(thresholds.isolation_forest_normalized)));
        set(evidence.get(), "decision_thresholds", std::move(values));
    }
    return evidence;
}

[[nodiscard]] JsonDocument flow_json(const AlertEvent& event) {
    const auto& source = event.flow.forward_source;
    const auto& destination = source == event.flow.key.low
        ? event.flow.key.high
        : event.flow.key.low;
    auto flow = checked(json_object());
    auto id = checked(json_object());
    set(
        id.get(),
        "namespace",
        checked(json_string(
            unsigned_decimal(event.snapshot.flow_id.namespace_id).c_str())));
    set(
        id.get(),
        "sequence",
        checked(json_string(
            unsigned_decimal(event.snapshot.flow_id.sequence).c_str())));
    set(flow.get(), "id", std::move(id));
    set(flow.get(), "source", endpoint_json(source));
    set(flow.get(), "destination", endpoint_json(destination));
    const auto protocol = protocol_name(event.flow.key.protocol);
    set(flow.get(), "protocol", checked(json_string(protocol.data())));
    return flow;
}

[[nodiscard]] JsonDocument incident_json(const IncidentMetadata& incident) {
    auto result = checked(json_object());
    auto id = checked(json_object());
    set(
        id.get(),
        "namespace",
        checked(json_string(
            unsigned_decimal(incident.flow_id.namespace_id).c_str())));
    set(
        id.get(),
        "sequence",
        checked(json_string(
            unsigned_decimal(incident.flow_id.sequence).c_str())));
    set(result.get(), "id", std::move(id));
    const auto lifecycle = incident_lifecycle_name(incident.lifecycle);
    set(
        result.get(),
        "lifecycle",
        checked(json_string(lifecycle.data())));
    set(
        result.get(),
        "first_checkpoint",
        checked(json_string(
            checkpoint_text(incident.first_checkpoint).c_str())));
    set(
        result.get(),
        "latest_checkpoint",
        checked(json_string(
            checkpoint_text(incident.latest_checkpoint).c_str())));
    set(
        result.get(),
        "update_index",
        checked(json_integer(incident.update_index)));
    return result;
}

[[nodiscard]] bool valid_incident(const AlertEvent& event) noexcept {
    if (!event.incident.has_value()) {
        return true;
    }
    const auto& incident = *event.incident;
    const auto first = checkpoint_packet_count(incident.first_checkpoint);
    const auto latest = checkpoint_packet_count(incident.latest_checkpoint);
    const auto created = incident.lifecycle == IncidentLifecycle::created;
    const auto updated = incident.lifecycle == IncidentLifecycle::updated;
    return incident.flow_id == event.snapshot.flow_id
        && incident.latest_checkpoint == event.snapshot.checkpoint
        && first <= latest
        && (
            (created
             && incident.update_index == 0U
             && incident.first_checkpoint == incident.latest_checkpoint)
            || (updated && incident.update_index > 0U));
}

[[nodiscard]] bool valid_event(const AlertEvent& event) noexcept {
    const DecisionEngine engine{event.decision.calibrated_thresholds};
    const auto checkpoint =
        checkpoint_for_packet_count(event.snapshot.packet_count);
    return event.decision.classification != DetectionDecision::benign
        && event.decision == engine.classify(event.scores)
        && valid_snapshot_metadata(event.snapshot)
        && checkpoint.has_value()
        && *checkpoint == event.snapshot.checkpoint
        && clock_domain_name(event.snapshot.clock_domain) != "invalid"
        && valid_flow_identity(event.flow)
        && valid_scores(event.scores)
        && valid_incident(event)
        && !event.known_family_candidate.empty()
        && !event.model_artifact_id.empty()
        && !event.model_artifact_version.empty()
        && event.detection_delay_ns
            <= static_cast<std::uint64_t>(
                std::numeric_limits<json_int_t>::max());
}

}

bool valid_decision_thresholds(
    const DecisionThresholds& thresholds) noexcept {
    return std::isfinite(thresholds.flow_rf)
        && thresholds.flow_rf >= 0.0
        && thresholds.flow_rf <= 1.0
        && std::isfinite(thresholds.hbos_normalized)
        && std::isfinite(thresholds.isolation_forest_normalized);
}

DecisionEngine::DecisionEngine(
    std::optional<DecisionThresholds> thresholds) noexcept
    : thresholds_{std::move(thresholds)} {
}

Decision DecisionEngine::classify(const ModelScores& scores) const noexcept {
    const auto supervised_attack = thresholds_.has_value()
        ? static_cast<double>(scores.flow_attack_probability)
            >= thresholds_->flow_rf
        : scores.flow_attack;
    const auto hbos_anomaly = thresholds_.has_value()
        ? scores.hbos.normalized >= thresholds_->hbos_normalized
        : scores.hbos.threshold_exceeded;
    const auto isolation_forest_anomaly = thresholds_.has_value()
        ? scores.isolation_forest.normalized
            >= thresholds_->isolation_forest_normalized
        : scores.isolation_forest.threshold_exceeded;
    const auto anomaly_votes = static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(hbos_anomaly)
        + static_cast<std::uint8_t>(isolation_forest_anomaly));
    auto classification = DetectionDecision::benign;
    if (supervised_attack) {
        classification = DetectionDecision::known_attack;
    } else if (anomaly_votes == 2U) {
        classification = DetectionDecision::unknown_candidate;
    } else if (anomaly_votes == 1U) {
        classification = DetectionDecision::uncertain;
    }
    return Decision{
        classification,
        supervised_attack,
        anomaly_votes,
        scores.known_family_index,
        scores.known_family_confidence,
        hbos_anomaly,
        isolation_forest_anomaly,
        thresholds_,
    };
}

std::string_view decision_name(DetectionDecision decision) noexcept {
    switch (decision) {
    case DetectionDecision::benign:
        return "benign";
    case DetectionDecision::known_attack:
        return "known_attack";
    case DetectionDecision::unknown_candidate:
        return "unknown_candidate";
    case DetectionDecision::uncertain:
        return "uncertain";
    }
    return "invalid";
}

ThresholdConfigResult load_decision_thresholds(
    const std::filesystem::path& path,
    Checkpoint checkpoint) noexcept {
    try {
        json_error_t error{};
        JsonDocument root{
            json_load_file(
                path.string().c_str(),
                JSON_REJECT_DUPLICATES,
                &error),
        };
        if (!root || !json_is_object(root.get())) {
            return ThresholdConfigError{
                "cannot parse threshold artifact: "
                + std::string{error.text},
            };
        }
        if (
            required_string(root.get(), "schema_version") != "1.0.0"
            || required_string(root.get(), "task") != "T6.1"
            || required_string(root.get(), "status") != "accepted"
            || required_string(root.get(), "kind") != "fusion_thresholds") {
            return ThresholdConfigError{"threshold artifact identity mismatch"};
        }
        auto* const policy = required_object(root.get(), "policy");
        auto* const flow_locked =
            json_object_get(policy, "flow_rf_threshold_locked");
        const auto policy_flow =
            required_number(policy, "flow_rf_threshold");
        if (
            required_number(policy, "benign_validation_fpr_cap") != 0.01
            || policy_flow != 0.5
            || !json_is_true(flow_locked)
            || required_string(policy, "comparison")
                != "score >= threshold") {
            return ThresholdConfigError{"threshold policy mismatch"};
        }
        auto* const checkpoints = required_object(root.get(), "checkpoints");
        const auto checkpoint_name = checkpoint_text(checkpoint);
        auto* const record = required_object(
            checkpoints,
            checkpoint_name.c_str());
        DecisionThresholds thresholds{
            required_number(record, "flow_rf_threshold"),
            required_number(record, "hbos_normalized_threshold"),
            required_number(record, "isolation_forest_normalized_threshold"),
        };
        if (
            !valid_decision_thresholds(thresholds)
            || thresholds.flow_rf != policy_flow) {
            return ThresholdConfigError{
                "threshold artifact contains invalid values",
            };
        }
        return thresholds;
    } catch (const std::exception& error) {
        return ThresholdConfigError{error.what()};
    }
}

std::string_view incident_lifecycle_name(
    IncidentLifecycle lifecycle) noexcept {
    switch (lifecycle) {
    case IncidentLifecycle::created:
        return "created";
    case IncidentLifecycle::updated:
        return "updated";
    }
    return "invalid";
}

AlertJsonResult serialize_alert_json_line(const AlertEvent& event) noexcept {
    if (!valid_event(event)) {
        return AlertError{
            AlertErrorCode::invalid_event,
            "alert event violates the decision or schema invariant",
        };
    }
    try {
        auto root = checked(json_object());
        set(
            root.get(),
            "schema_version",
            checked(json_string(alert_schema_version_v1.data())));
        set(root.get(), "event_type", checked(json_string("nids_alert")));
        set(root.get(), "flow", flow_json(event));
        set(
            root.get(),
            "checkpoint",
            checked(json_string(
                checkpoint_text(event.snapshot.checkpoint).c_str())));
        set(
            root.get(),
            "packet_count",
            checked(json_integer(static_cast<json_int_t>(
                event.snapshot.packet_count))));
        set(
            root.get(),
            "checkpoint_timestamp_ns",
            checked(json_integer(static_cast<json_int_t>(
                event.snapshot.checkpoint_timestamp_ns))));
        const auto clock = clock_domain_name(event.snapshot.clock_domain);
        set(
            root.get(),
            "clock_domain",
            checked(json_string(clock.data())));
        const auto classification =
            decision_name(event.decision.classification);
        set(
            root.get(),
            "decision",
            checked(json_string(classification.data())));
        if (event.incident.has_value()) {
            set(root.get(), "incident", incident_json(*event.incident));
        }
        set(root.get(), "evidence", evidence_json(event));
        set(
            root.get(),
            "detection_delay_ns",
            checked(json_integer(static_cast<json_int_t>(
                event.detection_delay_ns))));

        auto model = checked(json_object());
        set(
            model.get(),
            "artifact_id",
            checked(json_string(event.model_artifact_id.c_str())));
        set(
            model.get(),
            "version",
            checked(json_string(event.model_artifact_version.c_str())));
        set(root.get(), "model", std::move(model));
        set(
            root.get(),
            "feature_schema_version",
            checked(json_string(
                feature_schema_version_text(
                    event.snapshot.feature_schema_version)
                    .c_str())));

        std::unique_ptr<char, decltype(&std::free)> encoded{
            json_dumps(
                root.get(),
                JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII),
            &std::free,
        };
        if (!encoded) {
            throw SerializationFailure{"JSON encoding failed"};
        }
        std::string line{encoded.get()};
        line.push_back('\n');
        return line;
    } catch (const std::exception& error) {
        return AlertError{
            AlertErrorCode::serialization_failure,
            error.what(),
        };
    }
}

}
