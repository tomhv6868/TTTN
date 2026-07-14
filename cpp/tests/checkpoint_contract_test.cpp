#include "nids/checkpoint.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <type_traits>
#include <variant>

namespace {

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failure_count_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    [[nodiscard]] int failure_count() const noexcept {
        return failure_count_;
    }

private:
    int failure_count_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)

[[nodiscard]] nids::SnapshotMetadata make_metadata(nids::Checkpoint checkpoint) {
    constexpr nids::FlowInstanceId flow_id{7U, 42U};
    const auto packet_count = nids::checkpoint_packet_count(checkpoint);
    return nids::SnapshotMetadata{
        flow_id,
        checkpoint,
        packet_count,
        1'500'000'000LL,
        nids::ClockDomain::unix_epoch,
        nids::PacketSequencePrefixRef{flow_id, packet_count},
        nids::DatasetSplitGroupId{11U, 9U},
        nids::flow_feature_schema_version_v1,
    };
}

void test_exact_schedule(TestContext& test) {
    EXPECT(test, !nids::checkpoint_for_packet_count(1U).has_value());
    EXPECT(test, !nids::checkpoint_for_packet_count(2U).has_value());
    EXPECT(test, nids::checkpoint_for_packet_count(3U) == nids::Checkpoint::f3);
    EXPECT(test, !nids::checkpoint_for_packet_count(4U).has_value());
    EXPECT(test, nids::checkpoint_for_packet_count(5U) == nids::Checkpoint::f5);
    EXPECT(test, !nids::checkpoint_for_packet_count(6U).has_value());
    EXPECT(test, nids::checkpoint_for_packet_count(7U) == nids::Checkpoint::f7);
    EXPECT(test, !nids::checkpoint_for_packet_count(8U).has_value());
    EXPECT(test, nids::checkpoint_for_packet_count(9U) == nids::Checkpoint::f9);
    EXPECT(test, !nids::checkpoint_for_packet_count(10U).has_value());

    EXPECT(test, nids::checkpoint_packet_count(nids::checkpoint_schedule_v1[0]) == 3U);
    EXPECT(test, nids::checkpoint_packet_count(nids::checkpoint_schedule_v1[1]) == 5U);
    EXPECT(test, nids::checkpoint_packet_count(nids::checkpoint_schedule_v1[2]) == 7U);
    EXPECT(test, nids::checkpoint_packet_count(nids::checkpoint_schedule_v1[3]) == 9U);
}

void test_once_per_generation(TestContext& test) {
    nids::CheckpointTracker tracker;
    for (std::uint64_t packet_count = 1U; packet_count <= 10U; ++packet_count) {
        const auto checkpoint = tracker.claim(packet_count);
        const auto expected = nids::checkpoint_for_packet_count(packet_count);
        EXPECT(test, checkpoint == expected);
        if (checkpoint.has_value()) {
            EXPECT(test, !tracker.claim(packet_count).has_value());
        }
    }
    EXPECT(test, tracker.emitted(nids::Checkpoint::f3));
    EXPECT(test, tracker.emitted(nids::Checkpoint::f5));
    EXPECT(test, tracker.emitted(nids::Checkpoint::f7));
    EXPECT(test, tracker.emitted(nids::Checkpoint::f9));
    EXPECT(test, tracker.emitted_mask() == 0x0FU);

    nids::CheckpointTracker new_generation;
    EXPECT(test, new_generation.claim(3U) == nids::Checkpoint::f3);
    EXPECT(test, new_generation.emitted_mask() == 0x01U);
}

void test_short_flow_has_no_synthetic_checkpoint(TestContext& test) {
    nids::CheckpointTracker two_packet_flow;
    EXPECT(test, !two_packet_flow.claim(1U).has_value());
    EXPECT(test, !two_packet_flow.claim(2U).has_value());
    EXPECT(test, two_packet_flow.emitted_mask() == 0U);

    nids::CheckpointTracker four_packet_flow;
    EXPECT(test, !four_packet_flow.claim(1U).has_value());
    EXPECT(test, !four_packet_flow.claim(2U).has_value());
    EXPECT(test, four_packet_flow.claim(3U) == nids::Checkpoint::f3);
    EXPECT(test, !four_packet_flow.claim(4U).has_value());
    EXPECT(test, four_packet_flow.emitted_mask() == nids::checkpoint_bit(nids::Checkpoint::f3));
}

void test_snapshot_and_model_boundary(TestContext& test) {
    auto features = nids::FixedFeatureVector{};
    for (std::size_t index = 0; index < features.size(); ++index) {
        features[index] = static_cast<double>(index + 1U);
    }

    auto result = nids::make_checkpoint_snapshot(
        make_metadata(nids::Checkpoint::f3),
        features,
        true);
    EXPECT(test, std::holds_alternative<nids::CheckpointSnapshot>(result));
    if (!std::holds_alternative<nids::CheckpointSnapshot>(result)) {
        return;
    }

    features[0] = 999.0;
    const auto& snapshot = std::get<nids::CheckpointSnapshot>(result);
    const auto input = nids::model_input(snapshot);
    EXPECT(test, input.size() == nids::flow_feature_count_v1);
    EXPECT(test, input[0] == 1.0);
    EXPECT(test, input[53] == 54.0);
    EXPECT(test, snapshot.metadata.flow_id == (nids::FlowInstanceId{7U, 42U}));
    EXPECT(test, snapshot.metadata.split_group_id.has_value());
    EXPECT(test, snapshot.metadata.packet_sequence_prefix.packet_count == 3U);
    EXPECT(test, snapshot.metadata.feature_schema_version == nids::flow_feature_schema_version_v1);
}

void test_typed_errors(TestContext& test) {
    auto features = nids::FixedFeatureVector{};
    features.fill(1.0);

    auto invalid_metadata = make_metadata(nids::Checkpoint::f5);
    invalid_metadata.packet_count = 4U;
    auto invalid_result = nids::make_checkpoint_snapshot(invalid_metadata, features, true);
    EXPECT(test, std::holds_alternative<nids::CheckpointError>(invalid_result));
    if (std::holds_alternative<nids::CheckpointError>(invalid_result)) {
        EXPECT(test, std::get<nids::CheckpointError>(invalid_result).code
            == nids::CheckpointErrorCode::invalid_metadata);
    }

    auto prefix_result = nids::make_checkpoint_snapshot(
        make_metadata(nids::Checkpoint::f5),
        features,
        false);
    EXPECT(test, std::holds_alternative<nids::CheckpointError>(prefix_result));
    if (std::holds_alternative<nids::CheckpointError>(prefix_result)) {
        EXPECT(test, std::get<nids::CheckpointError>(prefix_result).code
            == nids::CheckpointErrorCode::packet_sequence_prefix_unavailable);
    }

    features[17] = std::numeric_limits<double>::quiet_NaN();
    auto non_finite_result = nids::make_checkpoint_snapshot(
        make_metadata(nids::Checkpoint::f7),
        features,
        true);
    EXPECT(test, std::holds_alternative<nids::CheckpointError>(non_finite_result));
    if (std::holds_alternative<nids::CheckpointError>(non_finite_result)) {
        EXPECT(test, std::get<nids::CheckpointError>(non_finite_result).code
            == nids::CheckpointErrorCode::non_finite_feature);
    }

    const nids::CheckpointResult overflow = nids::CheckpointError{
        nids::CheckpointErrorCode::timestamp_overflow,
        nids::FlowInstanceId{7U, 42U},
        3U,
    };
    EXPECT(test, std::holds_alternative<nids::CheckpointError>(overflow));
}

void test_contract_flags(TestContext& test) {
    const auto& contract = nids::checkpoint_contract_v1;
    EXPECT(test, contract.update_flow_and_features_before_checkpoint);
    EXPECT(test, contract.include_triggering_packet);
    EXPECT(test, contract.packet_sequence_record_precedes_snapshot);
    EXPECT(test, contract.emit_before_terminal_close);
    EXPECT(test, contract.emit_each_checkpoint_once_per_generation);
    EXPECT(test, contract.emit_only_reached_checkpoints);
    EXPECT(test, !contract.synthesize_final_checkpoint);
    EXPECT(test, contract.reset_schedule_for_new_generation);
    EXPECT(test, contract.snapshot_owns_feature_vector);
    EXPECT(test, !contract.snapshot_owns_packet_bytes);
    EXPECT(test, !contract.metadata_is_model_input);
    EXPECT(test, contract.flow_id_is_opaque);
    EXPECT(test, !contract.flow_id_is_derived_from_endpoints);
    EXPECT(test, contract.offline_error_policy
        == nids::OfflineCheckpointErrorPolicy::abort_run);
    EXPECT(test, contract.live_error_policy
        == nids::LiveCheckpointErrorPolicy::discard_flow_generation_increment_counter_and_continue);
}

}

int main() {
    static_assert(nids::flow_feature_count_v1 == 54U);
    static_assert(nids::checkpoint_schedule_v1.size() == 4U);
    static_assert(sizeof(nids::FlowInstanceId) == 16U);
    static_assert(std::is_trivially_copyable_v<nids::FixedFeatureVector>);
    static_assert(std::variant_size_v<nids::CheckpointResult> == 3U);

    TestContext test;
    test_exact_schedule(test);
    test_once_per_generation(test);
    test_short_flow_has_no_synthetic_checkpoint(test);
    test_snapshot_and_model_boundary(test);
    test_typed_errors(test);
    test_contract_flags(test);
    return test.failure_count() == 0 ? 0 : 1;
}
