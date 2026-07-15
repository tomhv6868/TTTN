#pragma once

#include "nids/flow_table.hpp"
#include "nids/pcap_adapter.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>

namespace nids {

struct FlowExportRecord {
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
};

struct CheckpointExportRecord {
    FlowIdentity identity{};
    std::uint64_t generation{};
    ClockDomain clock_domain{ClockDomain::unix_epoch};
    Checkpoint checkpoint{Checkpoint::f3};
    std::int64_t checkpoint_timestamp_ns{};
    FixedFeatureVector features{};
};

class FlowExportSink {
public:
    virtual ~FlowExportSink() = default;

    [[nodiscard]] virtual bool write(const FlowExportRecord& record) noexcept = 0;
};

class CheckpointExportSink {
public:
    virtual ~CheckpointExportSink() = default;

    [[nodiscard]] virtual bool write(
        const CheckpointExportRecord& record) noexcept = 0;
};

enum class FlowExportFailureCode : std::uint8_t {
    pcap_adapter,
    flow_ingest,
    sink,
};

struct FlowExportFailure {
    FlowExportFailureCode code{};
    std::uint64_t record_number{};
    std::optional<FlowIngestStatus> ingest_status{};
    std::optional<PcapAdapterError> pcap_error{};
};

struct FlowExportSummary {
    PcapReadSummary pcap{};
    FlowCounters flows{};
    std::uint64_t exported_flows{};
    std::uint64_t parser_errors{};
    std::uint64_t ingest_errors{};
};

struct FlowExportResult {
    FlowExportSummary summary{};
    std::optional<FlowExportFailure> failure{};

    [[nodiscard]] bool succeeded() const noexcept {
        return !failure.has_value();
    }
};

struct CheckpointExportResult {
    FlowExportSummary summary{};
    std::uint64_t exported_checkpoints{};
    std::optional<FlowExportFailure> failure{};

    [[nodiscard]] bool succeeded() const noexcept {
        return !failure.has_value();
    }
};

[[nodiscard]] FlowExportResult export_pcap_flows(
    const std::filesystem::path& path,
    FlowExportSink& sink,
    FlowTableConfig config = {});

[[nodiscard]] CheckpointExportResult export_pcap_checkpoints(
    const std::filesystem::path& path,
    FlowExportSink& flow_sink,
    CheckpointExportSink& checkpoint_sink,
    FlowTableConfig config = {});

}
