#include "nids/flow_export.hpp"

#include <cstddef>
#include <limits>
#include <utility>
#include <variant>

namespace nids {
namespace {

[[nodiscard]] constexpr std::size_t direction_index(FlowDirection direction) noexcept {
    return static_cast<std::size_t>(direction);
}

class ExportPipeline final : public PcapPacketObserver, public FlowObserver {
public:
    ExportPipeline(FlowExportSink& sink, FlowTableConfig config)
        : sink_{sink}, table_{*this, config} {}

    ExportPipeline(
        FlowExportSink& sink,
        CheckpointExportSink& checkpoint_sink,
        FlowTableConfig config)
        : sink_{sink}, checkpoint_sink_{&checkpoint_sink}, table_{*this, config} {}

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
                failure_ = FlowExportFailure{
                    FlowExportFailureCode::flow_ingest,
                    event.record_number,
                    result.status,
                    std::nullopt,
                };
            }
        } catch (...) {
            ++ingest_errors_;
            failure_ = FlowExportFailure{
                FlowExportFailureCode::flow_ingest,
                event.record_number,
                std::nullopt,
                std::nullopt,
            };
        }
    }

    void on_packet(
        const FlowState& state,
        const PacketView& packet,
        const FlowPacketContext& context) noexcept override {
        if (failure_.has_value() || checkpoint_sink_ == nullptr
            || !context.checkpoint.has_value()) {
            return;
        }

        const auto encoded = FeatureEngine::encode(state);
        if (!std::holds_alternative<FixedFeatureVector>(encoded)) {
            ++ingest_errors_;
            failure_ = FlowExportFailure{
                FlowExportFailureCode::flow_ingest,
                current_record_number_,
                std::nullopt,
                std::nullopt,
            };
            return;
        }

        const auto record = CheckpointExportRecord{
            state.identity,
            state.generation,
            state.clock_domain,
            *context.checkpoint,
            packet.timestamp_ns,
            std::get<FixedFeatureVector>(encoded),
        };
        if (!checkpoint_sink_->write(record)
            || exported_checkpoints_ == std::numeric_limits<std::uint64_t>::max()) {
            failure_ = FlowExportFailure{
                FlowExportFailureCode::sink,
                current_record_number_,
                std::nullopt,
                std::nullopt,
            };
            return;
        }
        ++exported_checkpoints_;
    }

    void on_close(
        const FlowState& state,
        FlowCloseReason reason) noexcept override {
        if (failure_.has_value()) {
            return;
        }

        const FlowExportRecord record{
            state.identity,
            state.generation,
            state.clock_domain,
            state.creation_timestamp_ns,
            state.last_capture_timestamp_ns,
            state.last_event_timestamp_ns,
            state.packet_count,
            state.directional_packet_count[direction_index(FlowDirection::forward)],
            state.directional_packet_count[direction_index(FlowDirection::reverse)],
            reason,
        };
        if (!sink_.write(record)) {
            failure_ = FlowExportFailure{
                FlowExportFailureCode::sink,
                current_record_number_,
                std::nullopt,
                std::nullopt,
            };
            return;
        }
        if (exported_flows_ == std::numeric_limits<std::uint64_t>::max()) {
            failure_ = FlowExportFailure{
                FlowExportFailureCode::sink,
                current_record_number_,
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
                failure_ = FlowExportFailure{
                    FlowExportFailureCode::flow_ingest,
                    current_record_number_,
                    std::nullopt,
                    std::nullopt,
                };
            }
        }
    }

    [[nodiscard]] FlowExportSummary summary() const noexcept {
        return FlowExportSummary{
            observed_pcap_,
            table_.counters(),
            exported_flows_,
            parser_errors_,
            ingest_errors_,
        };
    }

    [[nodiscard]] const std::optional<FlowExportFailure>& failure() const noexcept {
        return failure_;
    }

    [[nodiscard]] std::uint64_t exported_checkpoints() const noexcept {
        return exported_checkpoints_;
    }

private:
    FlowExportSink& sink_;
    CheckpointExportSink* checkpoint_sink_{};
    FlowTable table_;
    PcapReadSummary observed_pcap_{};
    std::uint64_t current_record_number_{};
    std::uint64_t exported_flows_{};
    std::uint64_t exported_checkpoints_{};
    std::uint64_t parser_errors_{};
    std::uint64_t ingest_errors_{};
    std::optional<FlowExportFailure> failure_{};
};

}

FlowExportResult export_pcap_flows(
    const std::filesystem::path& path,
    FlowExportSink& sink,
    FlowTableConfig config) {
    ExportPipeline pipeline{sink, config};
    auto pcap_result = read_pcap_file(path, pipeline);

    if (std::holds_alternative<PcapReadSummary>(pcap_result)) {
        pipeline.flush_end_of_input();
        auto summary = pipeline.summary();
        summary.pcap = std::get<PcapReadSummary>(pcap_result);
        return FlowExportResult{summary, pipeline.failure()};
    }

    auto summary = pipeline.summary();
    auto error = std::get<PcapAdapterError>(std::move(pcap_result));
    return FlowExportResult{
        summary,
        FlowExportFailure{
            FlowExportFailureCode::pcap_adapter,
            error.record_number,
            std::nullopt,
            std::move(error),
        },
    };
}

CheckpointExportResult export_pcap_checkpoints(
    const std::filesystem::path& path,
    FlowExportSink& flow_sink,
    CheckpointExportSink& checkpoint_sink,
    FlowTableConfig config) {
    ExportPipeline pipeline{flow_sink, checkpoint_sink, config};
    auto pcap_result = read_pcap_file(path, pipeline);

    if (std::holds_alternative<PcapReadSummary>(pcap_result)) {
        pipeline.flush_end_of_input();
        auto summary = pipeline.summary();
        summary.pcap = std::get<PcapReadSummary>(pcap_result);
        return CheckpointExportResult{
            summary,
            pipeline.exported_checkpoints(),
            pipeline.failure(),
        };
    }

    auto summary = pipeline.summary();
    auto error = std::get<PcapAdapterError>(std::move(pcap_result));
    return CheckpointExportResult{
        summary,
        pipeline.exported_checkpoints(),
        FlowExportFailure{
            FlowExportFailureCode::pcap_adapter,
            error.record_number,
            std::nullopt,
            std::move(error),
        },
    };
}

}
