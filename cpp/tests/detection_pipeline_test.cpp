#include "nids/detection_pipeline.hpp"

#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace {

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failures_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    [[nodiscard]] int failures() const noexcept {
        return failures_;
    }

private:
    int failures_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)

[[nodiscard]] nids::FlowIdentity test_flow() {
    const nids::FlowEndpoint source{
        nids::Ipv4Address{{192U, 168U, 252U, 10U}},
        42424U,
    };
    const nids::FlowEndpoint destination{
        nids::Ipv4Address{{192U, 168U, 252U, 20U}},
        80U,
    };
    return nids::FlowIdentity{
        nids::FlowKey{nids::TransportProtocol::tcp, source, destination},
        source,
    };
}

[[nodiscard]] nids::CheckpointSnapshot test_snapshot() {
    const nids::FlowInstanceId flow_id{700U, 9U};
    nids::SnapshotMetadata metadata;
    metadata.flow_id = flow_id;
    metadata.checkpoint = nids::Checkpoint::f9;
    metadata.packet_count = 9U;
    metadata.checkpoint_timestamp_ns = 1'721'234'567'890'000'000LL;
    metadata.clock_domain = nids::ClockDomain::unix_epoch;
    metadata.packet_sequence_prefix = {flow_id, 9U};

    nids::FixedFeatureVector features;
    for (std::size_t index = 0; index < features.size(); ++index) {
        features[index] = static_cast<double>(index + 1U);
    }
    return nids::CheckpointSnapshot{metadata, features};
}

[[nodiscard]] nids::DecisionThresholds calibrated_f9_thresholds() {
    return nids::DecisionThresholds{
        0.5,
        4.600573106634243,
        4.898310657202311,
    };
}

void test_calibrated_decision_engine(TestContext& test) {
    const nids::DecisionEngine engine{calibrated_f9_thresholds()};
    nids::ModelScores scores;
    scores.flow_attack_probability = 0.49F;
    scores.flow_attack = true;
    scores.hbos.normalized = 4.0;
    scores.hbos.threshold_exceeded = true;
    scores.isolation_forest.normalized = 4.0;
    scores.isolation_forest.threshold_exceeded = true;
    auto decision = engine.classify(scores);
    EXPECT(test, decision.classification == nids::DetectionDecision::benign);
    EXPECT(test, !decision.supervised_attack);
    EXPECT(test, decision.anomaly_votes == 0U);

    scores.hbos.normalized = 5.0;
    scores.isolation_forest.normalized = 5.0;
    decision = engine.classify(scores);
    EXPECT(
        test,
        decision.classification
            == nids::DetectionDecision::unknown_candidate);
    EXPECT(test, decision.anomaly_votes == 2U);
    EXPECT(test, decision.calibrated_thresholds.has_value());
}

void test_incident_lifecycle(TestContext& test) {
    nids::IncidentTracker tracker;
    const nids::FlowInstanceId flow_id{91U, 7U};
    const auto created = tracker.observe(flow_id, nids::Checkpoint::f3);
    EXPECT(test, std::holds_alternative<nids::IncidentMetadata>(created));
    if (std::holds_alternative<nids::IncidentMetadata>(created)) {
        const auto& value = std::get<nids::IncidentMetadata>(created);
        EXPECT(test, value.lifecycle == nids::IncidentLifecycle::created);
        EXPECT(test, value.first_checkpoint == nids::Checkpoint::f3);
        EXPECT(test, value.latest_checkpoint == nids::Checkpoint::f3);
        EXPECT(test, value.update_index == 0U);
    }
    const auto updated = tracker.observe(flow_id, nids::Checkpoint::f5);
    EXPECT(test, std::holds_alternative<nids::IncidentMetadata>(updated));
    if (std::holds_alternative<nids::IncidentMetadata>(updated)) {
        const auto& value = std::get<nids::IncidentMetadata>(updated);
        EXPECT(test, value.lifecycle == nids::IncidentLifecycle::updated);
        EXPECT(test, value.first_checkpoint == nids::Checkpoint::f3);
        EXPECT(test, value.latest_checkpoint == nids::Checkpoint::f5);
        EXPECT(test, value.update_index == 1U);
    }
    const auto duplicate = tracker.observe(flow_id, nids::Checkpoint::f5);
    EXPECT(
        test,
        std::holds_alternative<nids::IncidentTrackerError>(duplicate));
    EXPECT(test, tracker.size() == 1U);
    tracker.erase(flow_id);
    EXPECT(test, tracker.size() == 0U);
}

void test_real_pipeline(
    TestContext& test,
    const nids::ModelBundle& bundle,
    nids::DecisionThresholds thresholds) {
    nids::DetectionPipelineConfig config;
    config.decision_thresholds = thresholds;
    const nids::DetectionPipeline pipeline{bundle, std::move(config)};
    const auto flow = test_flow();
    const auto snapshot = test_snapshot();
    const auto first = pipeline.process(flow, snapshot, 400'000U);
    const auto second = pipeline.process(flow, snapshot, 400'000U);
    EXPECT(test, std::holds_alternative<nids::DetectionAlert>(first));
    EXPECT(
        test,
        std::holds_alternative<nids::DetectionPipelineError>(second));
    if (!std::holds_alternative<nids::DetectionAlert>(first)) {
        if (std::holds_alternative<nids::DetectionPipelineError>(first)) {
            std::cerr
                << std::get<nids::DetectionPipelineError>(first).detail
                << '\n';
        }
        return;
    }
    const auto& alert = std::get<nids::DetectionAlert>(first);
    EXPECT(
        test,
        alert.decision.classification
            == nids::DetectionDecision::unknown_candidate);
    EXPECT(test, alert.decision.anomaly_votes == 2U);
    EXPECT(test, !alert.decision.supervised_attack);
    EXPECT(test, alert.decision.calibrated_thresholds.has_value());
    EXPECT(
        test,
        alert.json_line.find("\"checkpoint\":\"F9\"")
            != std::string::npos);
    EXPECT(
        test,
        alert.json_line.find("\"decision\":\"unknown_candidate\"")
            != std::string::npos);
    EXPECT(
        test,
        alert.json_line.find(
            "\"artifact_id\":\"nids.native_inference_bundle.v1\"")
            != std::string::npos);
    EXPECT(
        test,
        alert.json_line.find("\"feature_schema_version\":\"1.0.0\"")
            != std::string::npos);
    EXPECT(
        test,
        alert.json_line.find("\"lifecycle\":\"created\"")
            != std::string::npos);
    EXPECT(
        test,
        alert.json_line.find("\"decision_thresholds\"")
            != std::string::npos);
    if (std::holds_alternative<nids::DetectionPipelineError>(second)) {
        EXPECT(
            test,
            std::get<nids::DetectionPipelineError>(second).code
                == nids::DetectionPipelineErrorCode::
                    incident_tracking_failure);
    }
}

void test_pipeline_guards(
    TestContext& test,
    const nids::ModelBundle& bundle) {
    const nids::DetectionPipeline pipeline{bundle};
    const auto flow = test_flow();

    auto mismatch = test_snapshot();
    mismatch.metadata.checkpoint = nids::Checkpoint::f7;
    mismatch.metadata.packet_count = 7U;
    mismatch.metadata.packet_sequence_prefix.packet_count = 7U;
    const auto mismatch_result = pipeline.process(flow, mismatch, 1U);
    EXPECT(
        test,
        std::holds_alternative<nids::DetectionPipelineError>(
            mismatch_result));
    if (std::holds_alternative<nids::DetectionPipelineError>(
            mismatch_result)) {
        EXPECT(
            test,
            std::get<nids::DetectionPipelineError>(mismatch_result).code
                == nids::DetectionPipelineErrorCode::
                    checkpoint_bundle_mismatch);
    }

    auto invalid = test_snapshot();
    invalid.model_features[0] = std::numeric_limits<double>::infinity();
    const auto invalid_result = pipeline.process(flow, invalid, 1U);
    EXPECT(
        test,
        std::holds_alternative<nids::DetectionPipelineError>(invalid_result));
    if (std::holds_alternative<nids::DetectionPipelineError>(
            invalid_result)) {
        EXPECT(
            test,
            std::get<nids::DetectionPipelineError>(invalid_result).code
                == nids::DetectionPipelineErrorCode::invalid_snapshot);
    }
}

}

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) {
        std::cerr
            << "usage: nids_detection_pipeline_test "
               "<staged-bundle-directory> [threshold-artifact]\n";
        return 2;
    }
    auto loaded = nids::load_model_bundle(std::filesystem::path{argv[1]});
    if (!loaded) {
        if (loaded.error.has_value()) {
            std::cerr << loaded.error->detail << '\n';
        }
        return 2;
    }
    auto thresholds = calibrated_f9_thresholds();
    if (argc == 3) {
        auto loaded_thresholds = nids::load_decision_thresholds(
            std::filesystem::path{argv[2]},
            nids::Checkpoint::f9);
        if (std::holds_alternative<nids::ThresholdConfigError>(
                loaded_thresholds)) {
            std::cerr
                << std::get<nids::ThresholdConfigError>(loaded_thresholds)
                       .detail
                << '\n';
            return 2;
        }
        thresholds = std::get<nids::DecisionThresholds>(loaded_thresholds);
    }
    TestContext test;
    test_calibrated_decision_engine(test);
    test_incident_lifecycle(test);
    test_real_pipeline(test, *loaded.bundle, thresholds);
    test_pipeline_guards(test, *loaded.bundle);
    if (test.failures() == 0) {
        std::cout
            << "[detection pipeline] status=passed checkpoint=F9 "
               "calibrated_decision=unknown_candidate "
               "incident_lifecycle=passed jsonl=passed\n";
    }
    return test.failures() == 0 ? 0 : 1;
}
