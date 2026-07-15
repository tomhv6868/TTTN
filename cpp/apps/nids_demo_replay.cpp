#include "nids/detection_pipeline.hpp"
#include "nids/feature.hpp"
#include "nids/flow_table.hpp"
#include "nids/pcap_adapter.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>

namespace {

struct Arguments {
    std::filesystem::path input{};
    std::filesystem::path bundle{};
    std::uint64_t max_records{};
    std::uint64_t expected_records{};
    std::uint64_t expected_f9_snapshots{};
    std::optional<std::filesystem::path> thresholds{};
    std::optional<std::string> thresholds_sha256{};
};

[[nodiscard]] std::optional<std::uint64_t> parse_unsigned(
    std::string_view value) noexcept {
    std::uint64_t result{};
    const auto parsed = std::from_chars(
        value.data(),
        value.data() + value.size(),
        result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return result;
}

[[nodiscard]] bool valid_sha256(std::string_view value) noexcept {
    if (value.size() != 64U) {
        return false;
    }
    for (const auto character : value) {
        if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<Arguments> parse_arguments(
    int argc,
    char** argv) {
    const bool calibrated = argc == 15;
    if ((argc != 11 && !calibrated)
        || std::string_view{argv[1]} != "--input"
        || std::string_view{argv[3]} != "--bundle"
        || std::string_view{argv[5]} != "--max-records"
        || std::string_view{argv[7]} != "--expect-records"
        || std::string_view{argv[9]} != "--expect-f9"
        || (calibrated
            && (std::string_view{argv[11]} != "--thresholds"
                || std::string_view{argv[13]} != "--thresholds-sha256"
                || std::string_view{argv[12]}.empty()
                || !valid_sha256(argv[14])))) {
        return std::nullopt;
    }
    const auto max_records = parse_unsigned(argv[6]);
    const auto expected_records = parse_unsigned(argv[8]);
    const auto expected_f9 = parse_unsigned(argv[10]);
    if (!max_records.has_value() || *max_records == 0U
        || !expected_records.has_value()
        || *expected_records > *max_records
        || !expected_f9.has_value()) {
        return std::nullopt;
    }
    return Arguments{
        std::filesystem::path{argv[2]},
        std::filesystem::path{argv[4]},
        *max_records,
        *expected_records,
        *expected_f9,
        calibrated
            ? std::optional<std::filesystem::path>{
                std::filesystem::path{argv[12]}}
            : std::nullopt,
        calibrated
            ? std::optional<std::string>{argv[14]}
            : std::nullopt,
    };
}

using DetectionConfigResult =
    std::variant<nids::DetectionPipelineConfig, std::string>;

[[nodiscard]] std::optional<std::string> verify_threshold_artifact(
    const Arguments& arguments) {
    if (!arguments.thresholds.has_value()) {
        return std::nullopt;
    }
    auto digest = nids::compute_file_sha256(*arguments.thresholds);
    if (std::holds_alternative<nids::ModelRuntimeError>(digest)) {
        return std::get<nids::ModelRuntimeError>(std::move(digest)).detail;
    }
    if (std::get<std::string>(digest) != *arguments.thresholds_sha256) {
        return std::string{"threshold artifact SHA-256 mismatch"};
    }
    return std::nullopt;
}

[[nodiscard]] DetectionConfigResult load_detection_config(
    const Arguments& arguments,
    nids::Checkpoint checkpoint) {
    nids::DetectionPipelineConfig config;
    if (!arguments.thresholds.has_value()) {
        return config;
    }

    auto loaded = nids::load_decision_thresholds(
        *arguments.thresholds,
        checkpoint);
    if (std::holds_alternative<nids::ThresholdConfigError>(loaded)) {
        return std::get<nids::ThresholdConfigError>(
            std::move(loaded)).detail;
    }
    config.decision_thresholds =
        std::get<nids::DecisionThresholds>(std::move(loaded));
    return config;
}

class ReplayPipeline final
    : public nids::PcapPacketObserver,
      public nids::FlowObserver {
public:
    explicit ReplayPipeline(const nids::DetectionPipeline& detection)
        : detection_{detection},
          table_{*this} {
    }

    void on_packet(const nids::PcapPacketEvent& event) noexcept override {
        if (failure_.has_value()) {
            return;
        }
        if (std::holds_alternative<nids::ParseError>(event.parsed)) {
            ++parser_errors_;
            return;
        }
        try {
            const auto result =
                table_.ingest(std::get<nids::PacketView>(event.parsed));
            if (result.status != nids::FlowIngestStatus::accepted) {
                fail(
                    "flow ingest failed at PCAP record "
                    + std::to_string(event.record_number));
            }
        } catch (const std::exception& error) {
            fail(
                "flow ingest threw at PCAP record "
                + std::to_string(event.record_number)
                + ": " + error.what());
        }
    }

    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView& packet,
        const nids::FlowPacketContext& context) noexcept override {
        if (failure_.has_value() || !context.checkpoint.has_value()
            || *context.checkpoint != nids::Checkpoint::f9) {
            return;
        }
        try {
            const auto encoded = nids::FeatureEngine::encode(state);
            if (!std::holds_alternative<nids::FixedFeatureVector>(encoded)) {
                fail("feature encoding failed at F9");
                return;
            }
            const nids::FlowInstanceId flow_id{1U, state.generation};
            nids::SnapshotMetadata metadata;
            metadata.flow_id = flow_id;
            metadata.checkpoint = nids::Checkpoint::f9;
            metadata.packet_count = state.packet_count;
            metadata.checkpoint_timestamp_ns = packet.timestamp_ns;
            metadata.clock_domain = state.clock_domain;
            metadata.packet_sequence_prefix = {flow_id, 9U};
            auto snapshot = nids::make_checkpoint_snapshot(
                metadata,
                std::get<nids::FixedFeatureVector>(encoded),
                true);
            if (!std::holds_alternative<nids::CheckpointSnapshot>(snapshot)) {
                fail("checkpoint construction failed at F9");
                return;
            }
            ++f9_snapshots_;
            auto result = detection_.process(
                state.identity,
                std::get<nids::CheckpointSnapshot>(snapshot),
                0U);
            if (std::holds_alternative<nids::DetectionPipelineError>(result)) {
                fail(
                    std::get<nids::DetectionPipelineError>(
                        std::move(result))
                        .detail);
                return;
            }
            if (std::holds_alternative<nids::NoDetectionAlert>(result)) {
                ++benign_decisions_;
                return;
            }
            auto alert =
                std::get<nids::DetectionAlert>(std::move(result));
            count(alert.decision.classification);
            std::cout << alert.json_line;
            if (!std::cout.good()) {
                fail("stdout failed while writing an alert");
                return;
            }
            ++alerts_;
        } catch (const std::exception& error) {
            fail(std::string{"F9 replay callback failed: "} + error.what());
        }
    }

    void on_close(
        const nids::FlowState&,
        nids::FlowCloseReason) noexcept override {
    }

    void flush() noexcept {
        try {
            table_.flush();
        } catch (const std::exception& error) {
            fail(std::string{"flow flush failed: "} + error.what());
        }
    }

    [[nodiscard]] const std::optional<std::string>& failure() const noexcept {
        return failure_;
    }

    [[nodiscard]] std::uint64_t parser_errors() const noexcept {
        return parser_errors_;
    }

    [[nodiscard]] std::uint64_t f9_snapshots() const noexcept {
        return f9_snapshots_;
    }

    [[nodiscard]] std::uint64_t alerts() const noexcept {
        return alerts_;
    }

    [[nodiscard]] std::uint64_t benign_decisions() const noexcept {
        return benign_decisions_;
    }

    [[nodiscard]] std::uint64_t known_attacks() const noexcept {
        return known_attacks_;
    }

    [[nodiscard]] std::uint64_t unknown_candidates() const noexcept {
        return unknown_candidates_;
    }

    [[nodiscard]] std::uint64_t uncertain_decisions() const noexcept {
        return uncertain_decisions_;
    }

private:
    void fail(std::string detail) {
        if (!failure_.has_value()) {
            failure_ = std::move(detail);
        }
    }

    void count(nids::DetectionDecision decision) noexcept {
        switch (decision) {
        case nids::DetectionDecision::benign:
            ++benign_decisions_;
            break;
        case nids::DetectionDecision::known_attack:
            ++known_attacks_;
            break;
        case nids::DetectionDecision::unknown_candidate:
            ++unknown_candidates_;
            break;
        case nids::DetectionDecision::uncertain:
            ++uncertain_decisions_;
            break;
        }
    }

    const nids::DetectionPipeline& detection_;
    nids::FlowTable table_;
    std::optional<std::string> failure_{};
    std::uint64_t parser_errors_{};
    std::uint64_t f9_snapshots_{};
    std::uint64_t alerts_{};
    std::uint64_t benign_decisions_{};
    std::uint64_t known_attacks_{};
    std::uint64_t unknown_candidates_{};
    std::uint64_t uncertain_decisions_{};
};

void print_summary(
    bool passed,
    const nids::PcapReadSummary& pcap,
    const ReplayPipeline& replay,
    bool calibrated_thresholds) {
    std::cout
        << "{\"event_type\":\"nids_replay_summary\""
        << ",\"status\":\"" << (passed ? "passed" : "failed") << '"'
        << ",\"calibrated_thresholds\":"
        << (calibrated_thresholds ? "true" : "false")
        << ",\"bounded\":" << (pcap.record_limit_reached ? "true" : "false")
        << ",\"records_read\":" << pcap.records_read
        << ",\"packets_parsed\":" << pcap.packets_parsed
        << ",\"parser_errors\":" << pcap.parser_errors
        << ",\"f9_snapshots\":" << replay.f9_snapshots()
        << ",\"alerts\":" << replay.alerts()
        << ",\"benign\":" << replay.benign_decisions()
        << ",\"known_attack\":" << replay.known_attacks()
        << ",\"unknown_candidate\":" << replay.unknown_candidates()
        << ",\"uncertain\":" << replay.uncertain_decisions()
        << "}\n";
}

}

int main(int argc, char** argv) {
    const auto arguments = parse_arguments(argc, argv);
    if (!arguments.has_value()) {
        std::cerr
            << "usage: nids_demo_replay --input PATH --bundle DIR "
               "--max-records N --expect-records N --expect-f9 N "
               "[--thresholds PATH --thresholds-sha256 HEX]\n";
        return 2;
    }
    if (const auto error = verify_threshold_artifact(*arguments);
        error.has_value()) {
        std::cerr << *error << '\n';
        return 2;
    }
    auto loaded = nids::load_model_bundle(arguments->bundle);
    if (!loaded) {
        if (loaded.error.has_value()) {
            std::cerr << loaded.error->detail << '\n';
        }
        return 2;
    }

    auto detection_config = load_detection_config(
        *arguments,
        loaded.bundle->checkpoint());
    if (std::holds_alternative<std::string>(detection_config)) {
        std::cerr << std::get<std::string>(detection_config) << '\n';
        return 2;
    }
    const nids::DetectionPipeline detection{
        *loaded.bundle,
        std::get<nids::DetectionPipelineConfig>(
            std::move(detection_config)),
    };
    ReplayPipeline replay{detection};
    const auto read_result = nids::read_pcap_file(
        arguments->input,
        replay,
        nids::PcapReadOptions{arguments->max_records});
    if (std::holds_alternative<nids::PcapAdapterError>(read_result)) {
        const auto& error = std::get<nids::PcapAdapterError>(read_result);
        std::cerr
            << "PCAP replay failed at record " << error.record_number
            << ": " << error.detail << '\n';
        return 1;
    }
    replay.flush();
    const auto& summary = std::get<nids::PcapReadSummary>(read_result);
    const bool passed = !replay.failure().has_value()
        && summary.record_limit_reached
        && summary.records_read == arguments->expected_records
        && summary.packets_parsed == arguments->expected_records
        && summary.parser_errors == 0U
        && replay.parser_errors() == 0U
        && replay.f9_snapshots() == arguments->expected_f9_snapshots;
    print_summary(
        passed,
        summary,
        replay,
        arguments->thresholds.has_value());
    if (!passed) {
        if (replay.failure().has_value()) {
            std::cerr << *replay.failure() << '\n';
        }
        return 1;
    }
    return std::cout.good() ? 0 : 1;
}
