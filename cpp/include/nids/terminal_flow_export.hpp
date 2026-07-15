#pragma once

#include "nids/pcap_adapter.hpp"
#include "nids/terminal_feature.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>

namespace nids {

struct TerminalFlowExportRecord {
    FlowIdentity identity{};
    std::uint64_t generation{};
    ClockDomain clock_domain{ClockDomain::unix_epoch};
    std::int64_t creation_timestamp_ns{};
    std::int64_t last_capture_timestamp_ns{};
    std::int64_t last_event_timestamp_ns{};
    std::uint64_t packet_count{};
    std::uint64_t forward_packet_count{};
    std::uint64_t reverse_packet_count{};
    FlowCloseReason close_reason{FlowCloseReason::end_of_input};
    TerminalFeatureVector features{};
};

class TerminalFlowExportSink {
public:
    virtual ~TerminalFlowExportSink() = default;

    [[nodiscard]] virtual bool write(
        const TerminalFlowExportRecord& record) noexcept = 0;
};

enum class TerminalFlowExportFailureCode : std::uint8_t {
    pcap_adapter,
    flow_ingest,
    terminal_feature,
    sink,
};

struct TerminalFlowExportFailure {
    TerminalFlowExportFailureCode code{};
    std::uint64_t record_number{};
    std::optional<FlowIngestStatus> ingest_status{};
    std::optional<TerminalFeatureErrorCode> terminal_feature_error{};
    std::optional<PcapAdapterError> pcap_error{};
};

struct TerminalFlowExportSummary {
    PcapReadSummary pcap{};
    FlowCounters flows{};
    std::uint64_t exported_flows{};
    std::uint64_t parser_errors{};
    std::uint64_t ingest_errors{};
    std::uint64_t terminal_feature_errors{};
};

struct TerminalFlowExportResult {
    TerminalFlowExportSummary summary{};
    std::optional<TerminalFlowExportFailure> failure{};

    [[nodiscard]] bool succeeded() const noexcept {
        return !failure.has_value();
    }
};

[[nodiscard]] TerminalFlowExportResult export_pcap_terminal_flows(
    const std::filesystem::path& path,
    TerminalFlowExportSink& sink,
    FlowTableConfig config = {});

}
