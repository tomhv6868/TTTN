#include "nids/detection_pipeline.hpp"

#include <exception>
#include <functional>
#include <stdexcept>
#include <utility>

namespace nids {

DetectionPipeline::DetectionPipeline(
    const ModelBundle& bundle,
    DetectionPipelineConfig config)
    : bundle_{&bundle},
      config_{std::move(config)},
      decision_engine_{config_.decision_thresholds},
      incident_tracker_{
          config_.incident_tracker != nullptr
              ? config_.incident_tracker
              : &owned_incident_tracker_} {
    if (
        config_.decision_thresholds.has_value()
        && !valid_decision_thresholds(*config_.decision_thresholds)) {
        throw std::invalid_argument{"invalid decision thresholds"};
    }
}

std::size_t IncidentTracker::FlowIdHash::operator()(
    const FlowInstanceId& value) const noexcept {
    const auto first = std::hash<std::uint64_t>{}(value.namespace_id);
    const auto second = std::hash<std::uint64_t>{}(value.sequence);
    return first ^ (second + 0x9e3779b9U + (first << 6U) + (first >> 2U));
}

IncidentTrackerResult IncidentTracker::observe(
    FlowInstanceId flow_id,
    Checkpoint checkpoint) {
    const auto found = incidents_.find(flow_id);
    if (found == incidents_.end()) {
        if (incidents_.size() >= maximum_incidents) {
            return IncidentTrackerError{
                IncidentTrackerErrorCode::capacity_exceeded,
                "incident tracker capacity exceeded",
            };
        }
        incidents_.emplace(flow_id, State{checkpoint, checkpoint, 0U});
        return IncidentMetadata{
            flow_id,
            IncidentLifecycle::created,
            checkpoint,
            checkpoint,
            0U,
        };
    }
    auto& state = found->second;
    if (
        checkpoint_packet_count(checkpoint)
        <= checkpoint_packet_count(state.latest_checkpoint)) {
        return IncidentTrackerError{
            IncidentTrackerErrorCode::duplicate_or_out_of_order_checkpoint,
            "incident checkpoint is duplicate or out of order",
        };
    }
    state.latest_checkpoint = checkpoint;
    ++state.update_index;
    return IncidentMetadata{
        flow_id,
        IncidentLifecycle::updated,
        state.first_checkpoint,
        state.latest_checkpoint,
        state.update_index,
    };
}

void IncidentTracker::erase(FlowInstanceId flow_id) noexcept {
    incidents_.erase(flow_id);
}

std::size_t IncidentTracker::size() const noexcept {
    return incidents_.size();
}

DetectionPipelineResult DetectionPipeline::process(
    const FlowIdentity& flow,
    const CheckpointSnapshot& snapshot,
    std::uint64_t detection_delay_ns) const noexcept {
    try {
        if (!valid_snapshot_metadata(snapshot.metadata)
            || !finite_feature_vector(snapshot.model_features)) {
            return DetectionPipelineError{
                DetectionPipelineErrorCode::invalid_snapshot,
                "checkpoint snapshot violates metadata or feature invariants",
            };
        }
        if (snapshot.metadata.checkpoint != bundle_->checkpoint()) {
            return DetectionPipelineError{
                DetectionPipelineErrorCode::checkpoint_bundle_mismatch,
                "checkpoint snapshot does not match the loaded model bundle",
            };
        }

        auto inference = bundle_->infer(model_input(snapshot));
        if (std::holds_alternative<ModelRuntimeError>(inference)) {
            return DetectionPipelineError{
                DetectionPipelineErrorCode::model_inference_failure,
                std::get<ModelRuntimeError>(std::move(inference)).detail,
            };
        }
        auto scores = std::get<ModelScores>(std::move(inference));
        const auto decision = decision_engine_.classify(scores);
        if (decision.classification == DetectionDecision::benign) {
            return NoDetectionAlert{decision};
        }
        auto incident = incident_tracker_->observe(
            snapshot.metadata.flow_id,
            snapshot.metadata.checkpoint);
        if (std::holds_alternative<IncidentTrackerError>(incident)) {
            return DetectionPipelineError{
                DetectionPipelineErrorCode::incident_tracking_failure,
                std::get<IncidentTrackerError>(std::move(incident)).detail,
            };
        }

        const auto family_names = bundle_->known_family_names();
        if (scores.known_family_index >= family_names.size()) {
            return DetectionPipelineError{
                DetectionPipelineErrorCode::model_inference_failure,
                "known-family index is outside the loaded class order",
            };
        }
        AlertEvent event{
            flow,
            snapshot.metadata,
            scores,
            decision,
            family_names[scores.known_family_index],
            config_.model_artifact_id,
            config_.model_artifact_version,
            detection_delay_ns,
            std::get<IncidentMetadata>(std::move(incident)),
        };
        auto serialized = serialize_alert_json_line(event);
        if (std::holds_alternative<AlertError>(serialized)) {
            return DetectionPipelineError{
                DetectionPipelineErrorCode::alert_serialization_failure,
                std::get<AlertError>(std::move(serialized)).detail,
            };
        }
        return DetectionAlert{
            decision,
            std::move(scores),
            std::get<std::string>(std::move(serialized)),
        };
    } catch (const std::exception& error) {
        return DetectionPipelineError{
            DetectionPipelineErrorCode::internal_failure,
            error.what(),
        };
    }
}

}
