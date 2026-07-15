#include "nids/alert.hpp"

#include <jansson.h>

#include <iostream>
#include <string>
#include <string_view>
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

[[nodiscard]] nids::ModelScores base_scores() {
    nids::ModelScores scores;
    scores.flow_attack_probability = 0.1F;
    scores.known_family_probabilities[7] = 1.0F;
    scores.known_family_index = 7U;
    scores.known_family_confidence = 1.0F;
    scores.hbos.raw = 2.0;
    scores.hbos.normalized = 0.5;
    scores.isolation_forest.raw = 0.4;
    scores.isolation_forest.normalized = 0.25;
    return scores;
}

void test_decision_engine(TestContext& test) {
    const nids::DecisionEngine engine;
    auto scores = base_scores();
    auto decision = engine.classify(scores);
    EXPECT(test, decision.classification == nids::DetectionDecision::benign);
    EXPECT(test, decision.anomaly_votes == 0U);

    scores.hbos.threshold_exceeded = true;
    decision = engine.classify(scores);
    EXPECT(test, decision.classification == nids::DetectionDecision::uncertain);
    EXPECT(test, decision.anomaly_votes == 1U);

    scores.isolation_forest.threshold_exceeded = true;
    decision = engine.classify(scores);
    EXPECT(
        test,
        decision.classification
            == nids::DetectionDecision::unknown_candidate);
    EXPECT(test, decision.anomaly_votes == 2U);

    scores.flow_attack = true;
    scores.flow_attack_probability = 0.9F;
    decision = engine.classify(scores);
    EXPECT(
        test,
        decision.classification == nids::DetectionDecision::known_attack);
    EXPECT(test, decision.supervised_attack);
    EXPECT(test, decision.anomaly_votes == 2U);
    EXPECT(test, nids::decision_name(decision.classification) == "known_attack");
}

[[nodiscard]] nids::AlertEvent known_alert() {
    auto scores = base_scores();
    scores.flow_attack_probability = 0.9F;
    scores.flow_attack = true;
    scores.hbos.normalized = 4.0;
    scores.hbos.threshold_exceeded = true;
    scores.isolation_forest.normalized = 3.0;
    scores.isolation_forest.threshold_exceeded = true;

    const nids::FlowEndpoint source{
        nids::Ipv4Address{{192U, 168U, 1U, 10U}},
        12345U,
    };
    const nids::FlowEndpoint destination{
        nids::Ipv4Address{{192U, 168U, 1U, 20U}},
        80U,
    };
    const nids::FlowInstanceId flow_id{41U, 99U};
    nids::SnapshotMetadata snapshot;
    snapshot.flow_id = flow_id;
    snapshot.checkpoint = nids::Checkpoint::f9;
    snapshot.packet_count = 9U;
    snapshot.checkpoint_timestamp_ns = 1'721'234'567'890'000'000LL;
    snapshot.clock_domain = nids::ClockDomain::unix_epoch;
    snapshot.packet_sequence_prefix = {flow_id, 9U};

    const nids::DecisionEngine engine;
    return nids::AlertEvent{
        nids::FlowIdentity{
            nids::FlowKey{nids::TransportProtocol::tcp, source, destination},
            source,
        },
        snapshot,
        scores,
        engine.classify(scores),
        "DDoS",
        "nids.native_inference_bundle.v1",
        "1.0.0",
        250'000U,
    };
}

[[nodiscard]] bool string_member(
    json_t* object,
    const char* name,
    std::string_view expected) {
    auto* const value = json_object_get(object, name);
    return json_is_string(value)
        && std::string_view{json_string_value(value)} == expected;
}

void test_json_alert(TestContext& test) {
    const auto event = known_alert();
    const auto result = nids::serialize_alert_json_line(event);
    EXPECT(test, std::holds_alternative<std::string>(result));
    if (!std::holds_alternative<std::string>(result)) {
        return;
    }
    const auto& line = std::get<std::string>(result);
    EXPECT(test, !line.empty());
    EXPECT(test, line.back() == '\n');
    EXPECT(test, line.find('\n') == line.size() - 1U);

    json_error_t error{};
    auto* const root = json_loadb(
        line.data(),
        line.size(),
        JSON_REJECT_DUPLICATES,
        &error);
    EXPECT(test, json_is_object(root));
    if (!json_is_object(root)) {
        json_decref(root);
        return;
    }
    EXPECT(test, string_member(root, "schema_version", "1.0.0"));
    EXPECT(test, string_member(root, "event_type", "nids_alert"));
    EXPECT(test, string_member(root, "checkpoint", "F9"));
    EXPECT(test, string_member(root, "clock_domain", "unix_epoch"));
    EXPECT(test, string_member(root, "decision", "known_attack"));
    EXPECT(test, json_integer_value(json_object_get(root, "packet_count")) == 9);
    EXPECT(
        test,
        json_integer_value(json_object_get(root, "detection_delay_ns"))
            == 250'000);
    EXPECT(
        test,
        string_member(root, "feature_schema_version", "1.0.0"));

    auto* const flow = json_object_get(root, "flow");
    EXPECT(test, json_is_object(flow));
    EXPECT(test, string_member(flow, "protocol", "tcp"));
    auto* const source = json_object_get(flow, "source");
    auto* const destination = json_object_get(flow, "destination");
    EXPECT(test, string_member(source, "ip", "192.168.1.10"));
    EXPECT(test, json_integer_value(json_object_get(source, "port")) == 12345);
    EXPECT(test, string_member(destination, "ip", "192.168.1.20"));
    EXPECT(
        test,
        json_integer_value(json_object_get(destination, "port")) == 80);

    auto* const evidence = json_object_get(root, "evidence");
    auto* const known = json_object_get(evidence, "known_family");
    EXPECT(test, string_member(known, "top_candidate", "DDoS"));
    EXPECT(
        test,
        json_array_size(json_object_get(known, "probabilities"))
            == nids::known_family_count_v1);
    EXPECT(
        test,
        json_integer_value(json_object_get(evidence, "anomaly_votes")) == 2);

    auto* const model = json_object_get(root, "model");
    EXPECT(
        test,
        string_member(
            model,
            "artifact_id",
            "nids.native_inference_bundle.v1"));
    EXPECT(test, string_member(model, "version", "1.0.0"));
    json_decref(root);
}

void test_alert_guards(TestContext& test) {
    const nids::DecisionEngine engine;
    auto benign = known_alert();
    benign.scores = base_scores();
    benign.decision = engine.classify(benign.scores);
    const auto benign_result = nids::serialize_alert_json_line(benign);
    EXPECT(test, std::holds_alternative<nids::AlertError>(benign_result));
    if (std::holds_alternative<nids::AlertError>(benign_result)) {
        EXPECT(
            test,
            std::get<nids::AlertError>(benign_result).code
                == nids::AlertErrorCode::invalid_event);
    }

    auto inconsistent = known_alert();
    inconsistent.decision.classification =
        nids::DetectionDecision::unknown_candidate;
    EXPECT(
        test,
        std::holds_alternative<nids::AlertError>(
            nids::serialize_alert_json_line(inconsistent)));

    auto unknown = known_alert();
    unknown.scores.flow_attack = false;
    unknown.scores.flow_attack_probability = 0.1F;
    unknown.decision = engine.classify(unknown.scores);
    const auto unknown_result = nids::serialize_alert_json_line(unknown);
    EXPECT(test, std::holds_alternative<std::string>(unknown_result));
    if (std::holds_alternative<std::string>(unknown_result)) {
        EXPECT(
            test,
            std::get<std::string>(unknown_result).find(
                "\"decision\":\"unknown_candidate\"")
                != std::string::npos);
    }
}

}

int main() {
    TestContext test;
    test_decision_engine(test);
    test_json_alert(test);
    test_alert_guards(test);
    return test.failures() == 0 ? 0 : 1;
}
