#include "nids/terminal_flow_export.hpp"

#include <cstddef>
#include <limits>
#include <utility>
#include <variant>

namespace nids {
namespace {

[[nodiscard]] constexpr std::size_t direction_index(
    FlowDirection direction) noexcept {
    return static_cast<std::size_t>(direction);
}

class TerminalExportPipeline final
    : public PcapPacketObserver,
      public FlowObserver {
public:
    TerminalExportPipeline(
        TerminalFlowExportSink& sink,
        FlowTableConfig config)
        : sink_{sink}, table_{*this, config} {}

    void on_packet(const PcapPacketEvent& event) noexcept override {
        current_record_number_ = event.record_number;
        observed_pcap_.records_read = event.record_number;
        observed_pcap_.captured_bytes += event.input.captured_length();
        observed_pcap_.wire_bytes += event.input.wire_length;

        if (std::holds_alternative<ParseError>(event.parsed)) {
            ++observed_pcap_.parser_errors;
            ++parser_errors_;
            return;
        }
        ++observed_pcap_.packets_parsed;

        if (failure_.has_value()) {
            return;
        }

        try {
            const auto result = table_.ingest(std::get<PacketView>(event.parsed));
            if (result.status != FlowIngestStatus::accepted) {
                ++ingest_errors_;
                failure_ = TerminalFlowExportFailure{
                    TerminalFlowExportFailureCode::flow_ingest,
                    event.record_number,
                    result.status,
                    std::nullopt,
                    std::nullopt,
                };
            }
        } catch (...) {
            ++ingest_errors_;
            failure_ = TerminalFlowExportFailure{
                TerminalFlowExportFailureCode::flow_ingest,
                event.record_number,
                std::nullopt,
                std::nullopt,
                std::nullopt,
            };
        }
    }

    void on_packet(
        const FlowState& state,
        const PacketView& packet,
        const FlowPacketContext& context) noexcept override {
        if (failure_.has_value()) {
            return;
        }
        const auto update = terminal_features_.update(state, packet, context);
        if (!update.has_value()) {
            return;
        }
        ++terminal_feature_errors_;
        failure_ = TerminalFlowExportFailure{
            TerminalFlowExportFailureCode::terminal_feature,
            current_record_number_,
            std::nullopt,
            update->code,
            std::nullopt,
        };
    }

    void on_close(
        const FlowState& state,
        FlowCloseReason reason) noexcept override {
        if (failure_.has_value()) {
            return;
        }

        const auto encoded = terminal_features_.close(state);
        if (!std::holds_alternative<TerminalFeatureVector>(encoded)) {
            ++terminal_feature_errors_;
            failure_ = TerminalFlowExportFailure{
                TerminalFlowExportFailureCode::terminal_feature,
                current_record_number_,
                std::nullopt,
                std::get<TerminalFeatureError>(encoded).code,
                std::nullopt,
            };
            return;
        }
        if (exported_flows_ == std::numeric_limits<std::uint64_t>::max()) {
            failure_ = TerminalFlowExportFailure{
                TerminalFlowExportFailureCode::sink,
                current_record_number_,
                std::nullopt,
                std::nullopt,
                std::nullopt,
            };
            return;
        }

        const auto record = TerminalFlowExportRecord{
            state.identity,
            state.generation,
            state.clock_domain,
            state.creation_timestamp_ns,
            state.last_capture_timestamp_ns,
            state.last_event_timestamp_ns,
            state.packet_count,
            state.directional_packet_count[
                direction_index(FlowDirection::forward)],
            state.directional_packet_count[
                direction_index(FlowDirection::reverse)],
            reason,
            std::get<TerminalFeatureVector>(encoded),
        };
        if (!sink_.write(record)) {
            failure_ = TerminalFlowExportFailure{
                TerminalFlowExportFailureCode::sink,
                current_record_number_,
                std::nullopt,
                std::nullopt,
                std::nullopt,
            };
            return;
        }
        ++exported_flows_;
    }

    void flush_end_of_input() noexcept {
        try {
            table_.flush();
        } catch (...) {
            if (!failure_.has_value()) {
                ++ingest_errors_;
                failure_ = TerminalFlowExportFailure{
                    TerminalFlowExportFailureCode::flow_ingest,
                    current_record_number_,
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                };
            }
        }
    }

    [[nodiscard]] TerminalFlowExportSummary summary() const noexcept {
        return TerminalFlowExportSummary{
            observed_pcap_,
            table_.counters(),
            exported_flows_,
            parser_errors_,
            ingest_errors_,
            terminal_feature_errors_,
        };
    }

    [[nodiscard]] const std::optional<TerminalFlowExportFailure>&
    failure() const noexcept {
        return failure_;
    }

private:
    TerminalFlowExportSink& sink_;
    TerminalFeatureEngine terminal_features_{};
    FlowTable table_;
    PcapReadSummary observed_pcap_{};
    std::uint64_t current_record_number_{};
    std::uint64_t exported_flows_{};
    std::uint64_t parser_errors_{};
    std::uint64_t ingest_errors_{};
    std::uint64_t terminal_feature_errors_{};
    std::optional<TerminalFlowExportFailure> failure_{};
};

}

TerminalFlowExportResult export_pcap_terminal_flows(
    const std::filesystem::path& path,
    TerminalFlowExportSink& sink,
    FlowTableConfig config) {
    TerminalExportPipeline pipeline{sink, config};
    auto pcap_result = read_pcap_file(path, pipeline);

    if (std::holds_alternative<PcapReadSummary>(pcap_result)) {
        pipeline.flush_end_of_input();
        auto summary = pipeline.summary();
        summary.pcap = std::get<PcapReadSummary>(pcap_result);
        return TerminalFlowExportResult{summary, pipeline.failure()};
    }

    auto summary = pipeline.summary();
    if (pipeline.failure().has_value()) {
        return TerminalFlowExportResult{summary, pipeline.failure()};
    }
    auto error = std::get<PcapAdapterError>(std::move(pcap_result));
    return TerminalFlowExportResult{
        summary,
        TerminalFlowExportFailure{
            TerminalFlowExportFailureCode::pcap_adapter,
            error.record_number,
            std::nullopt,
            std::nullopt,
            std::move(error),
        },
    };
}

}
