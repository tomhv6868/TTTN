#include "nids/flow_export.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace {

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
                output << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
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
    return domain == nids::ClockDomain::unix_epoch ? "unix_epoch" : "monotonic";
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
    nids::FlowExportFailureCode code) noexcept {
    switch (code) {
    case nids::FlowExportFailureCode::pcap_adapter: return "pcap_adapter";
    case nids::FlowExportFailureCode::flow_ingest: return "flow_ingest";
    case nids::FlowExportFailureCode::sink: return "sink";
    }
    return "unknown";
}

class JsonlSink final : public nids::FlowExportSink {
public:
    explicit JsonlSink(std::string capture_id) : capture_id_{std::move(capture_id)} {}

    [[nodiscard]] bool write(const nids::FlowExportRecord& record) noexcept override {
        try {
            const auto& key = record.identity.key;
            std::ostringstream output;
            output << "{\"schema_version\":1,\"task\":\"T3.3\",\"kind\":\"flow\""
                   << ",\"capture_id\":" << json_string(capture_id_)
                   << ",\"protocol\":" << json_string(protocol_name(key.protocol))
                   << ",\"low_ip\":" << json_string(ipv4_string(key.low.address))
                   << ",\"low_port\":" << key.low.port
                   << ",\"high_ip\":" << json_string(ipv4_string(key.high.address))
                   << ",\"high_port\":" << key.high.port
                   << ",\"forward_source_ip\":"
                   << json_string(ipv4_string(record.identity.forward_source.address))
                   << ",\"forward_source_port\":" << record.identity.forward_source.port
                   << ",\"generation\":" << record.generation
                   << ",\"clock_domain\":" << json_string(clock_domain_name(record.clock_domain))
                   << ",\"creation_timestamp_ns\":" << record.creation_timestamp_ns
                   << ",\"last_capture_timestamp_ns\":"
                   << record.last_capture_timestamp_ns
                   << ",\"last_event_timestamp_ns\":" << record.last_event_timestamp_ns
                   << ",\"packet_count\":" << record.packet_count
                   << ",\"forward_packet_count\":" << record.forward_packet_count
                   << ",\"reverse_packet_count\":" << record.reverse_packet_count
                   << ",\"close_reason\":" << json_string(close_reason_name(record.close_reason))
                   << "}\n";
            std::cout << output.str();
            return std::cout.good();
        } catch (...) {
            return false;
        }
    }

private:
    std::string capture_id_;
};

void write_summary(
    const std::filesystem::path& input,
    std::string_view capture_id,
    const nids::FlowExportResult& result) {
    const auto& pcap = result.summary.pcap;
    const auto& flows = result.summary.flows;
    std::cout << "{\"schema_version\":1,\"task\":\"T3.3\",\"kind\":\"summary\""
              << ",\"status\":" << json_string(result.succeeded() ? "passed" : "failed")
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
                     nids::FlowCloseReason::end_of_input)] << "}}"
              << ",\"exported_flows\":" << result.summary.exported_flows
              << ",\"parser_errors\":" << result.summary.parser_errors
              << ",\"ingest_errors\":" << result.summary.ingest_errors;
    if (result.failure.has_value()) {
        std::cout << ",\"failure\":" << json_string(failure_name(result.failure->code))
                  << ",\"failure_record_number\":" << result.failure->record_number;
    }
    std::cout << "}\n";
}

}

int main(int argc, char** argv) {
    if (argc != 5 || std::string_view{argv[1]} != "--input"
        || std::string_view{argv[3]} != "--capture-id") {
        std::cerr << "usage: nids_t33_flow_export --input PATH --capture-id TOKEN\n";
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
        const auto result = nids::export_pcap_flows(input, sink);
        write_summary(input, capture_id, result);
        if (!result.succeeded()) {
            std::cerr << "flow export failed: "
                      << failure_name(result.failure->code)
                      << " at record " << result.failure->record_number << '\n';
            return 1;
        }
        if (!std::cout.good()) {
            std::cerr << "flow export failed: stdout\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "flow export failed: " << error.what() << '\n';
        return 1;
    }
}
