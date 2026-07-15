#include "nids/terminal_flow_export.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr std::string_view feature_schema_id{
    "nids.terminal_flow_features.v1"};

[[nodiscard]] bool valid_capture_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    for (const unsigned char character : value) {
        const bool allowed = (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character == '.' || character == '_' || character == '-';
        if (!allowed) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string json_string(std::string_view value) {
    std::ostringstream output;
    output << '"';
    for (const unsigned char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20U) {
                output << "\\u00" << std::hex << std::setw(2)
                       << std::setfill('0')
                       << static_cast<unsigned int>(character) << std::dec;
            } else {
                output << static_cast<char>(character);
            }
        }
    }
    output << '"';
    return output.str();
}

[[nodiscard]] std::string ipv4_string(const nids::Ipv4Address& address) {
    std::ostringstream output;
    for (std::size_t index = 0; index < address.wire_bytes.size(); ++index) {
        if (index != 0U) {
            output << '.';
        }
        output << static_cast<unsigned int>(address.wire_bytes[index]);
    }
    return output.str();
}

[[nodiscard]] constexpr std::string_view protocol_name(
    nids::TransportProtocol protocol) noexcept {
    return protocol == nids::TransportProtocol::tcp ? "tcp" : "udp";
}

[[nodiscard]] constexpr std::string_view clock_domain_name(
    nids::ClockDomain domain) noexcept {
    return domain == nids::ClockDomain::unix_epoch
        ? "unix_epoch"
        : "monotonic";
}

[[nodiscard]] constexpr std::string_view close_reason_name(
    nids::FlowCloseReason reason) noexcept {
    constexpr std::array names{
        std::string_view{"idle_timeout"},
        std::string_view{"maximum_age"},
        std::string_view{"tcp_reset"},
        std::string_view{"tcp_fin_handshake"},
        std::string_view{"tuple_reuse"},
        std::string_view{"capacity_eviction"},
        std::string_view{"end_of_input"},
    };
    return names[nids::flow_close_reason_index(reason)];
}

[[nodiscard]] constexpr std::string_view failure_name(
    nids::TerminalFlowExportFailureCode code) noexcept {
    switch (code) {
    case nids::TerminalFlowExportFailureCode::pcap_adapter:
        return "pcap_adapter";
    case nids::TerminalFlowExportFailureCode::flow_ingest:
        return "flow_ingest";
    case nids::TerminalFlowExportFailureCode::terminal_feature:
        return "terminal_feature";
    case nids::TerminalFlowExportFailureCode::sink:
        return "sink";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view ingest_status_name(
    nids::FlowIngestStatus status) noexcept {
    switch (status) {
    case nids::FlowIngestStatus::accepted:
        return "accepted";
    case nids::FlowIngestStatus::clock_domain_mismatch:
        return "clock_domain_mismatch";
    case nids::FlowIngestStatus::timestamp_overflow:
        return "timestamp_overflow";
    case nids::FlowIngestStatus::feature_update_error:
        return "feature_update_error";
    case nids::FlowIngestStatus::resource_exhausted:
        return "resource_exhausted";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view pcap_error_name(
    nids::PcapAdapterErrorCode code) noexcept {
    switch (code) {
    case nids::PcapAdapterErrorCode::open_failed:
        return "open_failed";
    case nids::PcapAdapterErrorCode::unsupported_link_layer:
        return "unsupported_link_layer";
    case nids::PcapAdapterErrorCode::timestamp_overflow:
        return "timestamp_overflow";
    case nids::PcapAdapterErrorCode::read_failed:
        return "read_failed";
    case nids::PcapAdapterErrorCode::summary_overflow:
        return "summary_overflow";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view terminal_feature_error_name(
    nids::TerminalFeatureErrorCode code) noexcept {
    switch (code) {
    case nids::TerminalFeatureErrorCode::duplicate_generation:
        return "duplicate_generation";
    case nids::TerminalFeatureErrorCode::missing_generation:
        return "missing_generation";
    case nids::TerminalFeatureErrorCode::numeric_overflow:
        return "numeric_overflow";
    case nids::TerminalFeatureErrorCode::non_finite_value:
        return "non_finite_value";
    case nids::TerminalFeatureErrorCode::base_feature_error:
        return "base_feature_error";
    case nids::TerminalFeatureErrorCode::resource_exhausted:
        return "resource_exhausted";
    }
    return "unknown";
}

void write_identity(
    std::ostringstream& output,
    const nids::FlowIdentity& identity) {
    const auto& key = identity.key;
    output << ",\"protocol\":" << json_string(protocol_name(key.protocol))
           << ",\"low_ip\":" << json_string(ipv4_string(key.low.address))
           << ",\"low_port\":" << key.low.port
           << ",\"high_ip\":" << json_string(ipv4_string(key.high.address))
           << ",\"high_port\":" << key.high.port
           << ",\"forward_source_ip\":"
           << json_string(ipv4_string(identity.forward_source.address))
           << ",\"forward_source_port\":" << identity.forward_source.port;
}

class JsonlSink final : public nids::TerminalFlowExportSink {
public:
    explicit JsonlSink(std::string capture_id)
        : capture_id_{std::move(capture_id)} {}

    [[nodiscard]] bool write(
        const nids::TerminalFlowExportRecord& record) noexcept override {
        try {
            std::ostringstream output;
            output
                << "{\"schema_version\":1,\"task\":\"T9.1\""
                << ",\"kind\":\"terminal_flow\""
                << ",\"feature_schema_id\":"
                << json_string(feature_schema_id)
                << ",\"feature_count\":" << nids::terminal_feature_count
                << ",\"capture_id\":" << json_string(capture_id_)
                << ",\"export_ordinal\":" << export_ordinal_ + 1U;
            write_identity(output, record.identity);
            output
                << ",\"generation\":" << record.generation
                << ",\"clock_domain\":"
                << json_string(clock_domain_name(record.clock_domain))
                << ",\"creation_timestamp_ns\":"
                << record.creation_timestamp_ns
                << ",\"last_capture_timestamp_ns\":"
                << record.last_capture_timestamp_ns
                << ",\"last_event_timestamp_ns\":"
                << record.last_event_timestamp_ns
                << ",\"packet_count\":" << record.packet_count
                << ",\"forward_packet_count\":"
                << record.forward_packet_count
                << ",\"reverse_packet_count\":"
                << record.reverse_packet_count
                << ",\"close_reason\":"
                << json_string(close_reason_name(record.close_reason))
                << ",\"features\":["
                << std::setprecision(
                       std::numeric_limits<double>::max_digits10);
            for (std::size_t index = 0; index < record.features.size(); ++index) {
                if (index != 0U) {
                    output << ',';
                }
                output << record.features[index];
            }
            output << "]}\n";
            std::cout << output.str();
            if (!std::cout.good()) {
                return false;
            }
            ++export_ordinal_;
            return true;
        } catch (...) {
            return false;
        }
    }

private:
    std::string capture_id_;
    std::uint64_t export_ordinal_{};
};

void write_summary(
    const std::filesystem::path& input,
    std::string_view capture_id,
    const nids::TerminalFlowExportResult& result) {
    const auto& pcap = result.summary.pcap;
    const auto& flows = result.summary.flows;
    std::cout
        << "{\"schema_version\":1,\"task\":\"T9.1\",\"kind\":\"summary\""
        << ",\"status\":"
        << json_string(result.succeeded() ? "passed" : "failed")
        << ",\"feature_schema_id\":" << json_string(feature_schema_id)
        << ",\"feature_count\":" << nids::terminal_feature_count
        << ",\"input\":" << json_string(input.string())
        << ",\"capture_id\":" << json_string(capture_id)
        << ",\"pcap\":{\"records_read\":" << pcap.records_read
        << ",\"packets_parsed\":" << pcap.packets_parsed
        << ",\"parser_errors\":" << pcap.parser_errors
        << ",\"captured_bytes\":" << pcap.captured_bytes
        << ",\"wire_bytes\":" << pcap.wire_bytes << '}'
        << ",\"flows\":{\"packets_accepted\":" << flows.packets_accepted
        << ",\"packets_rejected_clock_domain\":"
        << flows.packets_rejected_clock_domain
        << ",\"packets_rejected_timestamp_overflow\":"
        << flows.packets_rejected_timestamp_overflow
        << ",\"packets_rejected_feature_update\":"
        << flows.packets_rejected_feature_update
        << ",\"packets_rejected_resource_exhausted\":"
        << flows.packets_rejected_resource_exhausted
        << ",\"flow_generations_created\":" << flows.flow_generations_created
        << ",\"flows_closed\":" << flows.flows_closed
        << ",\"active_flow_count\":" << flows.active_flow_count
        << ",\"peak_active_flow_count\":" << flows.peak_active_flow_count
        << ",\"fixed_memory_bytes\":" << flows.fixed_memory_bytes
        << ",\"current_allocator_bytes\":" << flows.current_allocator_bytes
        << ",\"peak_allocator_bytes\":" << flows.peak_allocator_bytes
        << ",\"current_memory_bytes\":" << flows.current_memory_bytes
        << ",\"peak_memory_bytes\":" << flows.peak_memory_bytes
        << ",\"memory_budget_bytes\":" << flows.memory_budget_bytes
        << ",\"close_reason_count\":{\"idle_timeout\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::idle_timeout)]
        << ",\"maximum_age\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::maximum_age)]
        << ",\"tcp_reset\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::tcp_reset)]
        << ",\"tcp_fin_handshake\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::tcp_fin_handshake)]
        << ",\"tuple_reuse\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::tuple_reuse)]
        << ",\"capacity_eviction\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::capacity_eviction)]
        << ",\"end_of_input\":"
        << flows.close_reason_count[nids::flow_close_reason_index(
               nids::FlowCloseReason::end_of_input)]
        << "}}"
        << ",\"exported_flows\":" << result.summary.exported_flows
        << ",\"parser_errors\":" << result.summary.parser_errors
        << ",\"ingest_errors\":" << result.summary.ingest_errors
        << ",\"terminal_feature_errors\":"
        << result.summary.terminal_feature_errors;
    if (result.failure.has_value()) {
        std::cout
            << ",\"failure\":"
            << json_string(failure_name(result.failure->code))
            << ",\"failure_record_number\":"
            << result.failure->record_number;
        if (result.failure->ingest_status.has_value()) {
            std::cout
                << ",\"ingest_status\":"
                << json_string(ingest_status_name(
                       *result.failure->ingest_status));
        }
        if (result.failure->terminal_feature_error.has_value()) {
            std::cout
                << ",\"terminal_feature_error\":"
                << json_string(terminal_feature_error_name(
                       *result.failure->terminal_feature_error));
        }
        if (result.failure->pcap_error.has_value()) {
            std::cout
                << ",\"pcap_error\":"
                << json_string(pcap_error_name(
                       result.failure->pcap_error->code))
                << ",\"pcap_error_detail\":"
                << json_string(result.failure->pcap_error->detail);
        }
    }
    std::cout << "}\n";
}

}

int main(int argc, char** argv) {
    if (argc != 5 || std::string_view{argv[1]} != "--input"
        || std::string_view{argv[3]} != "--capture-id") {
        std::cerr
            << "usage: nids_t91_terminal_flow_export "
               "--input PATH --capture-id TOKEN\n";
        return 2;
    }

    const std::filesystem::path input{argv[2]};
    const std::string capture_id{argv[4]};
    if (input.empty() || !valid_capture_id(capture_id)) {
        std::cerr << "invalid input path or capture-id\n";
        return 2;
    }

    try {
        JsonlSink sink{capture_id};
        const auto result =
            nids::export_pcap_terminal_flows(input, sink);
        write_summary(input, capture_id, result);
        std::cout.flush();
        if (!result.succeeded()) {
            std::cerr
                << "terminal flow export failed: "
                << failure_name(result.failure->code)
                << " at record " << result.failure->record_number << '\n';
            return 1;
        }
        if (!std::cout.good()) {
            std::cerr << "terminal flow export failed: stdout\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "terminal flow export failed: " << error.what() << '\n';
        return 1;
    }
}
