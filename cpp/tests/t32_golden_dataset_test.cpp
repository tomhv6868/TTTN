#include "nids/pcap_adapter.hpp"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {

constexpr std::uint64_t expected_record_count = 9U;

class ParserObserver final : public nids::PcapPacketObserver {
public:
    void on_packet(const nids::PcapPacketEvent& event) noexcept override {
        ++record_count;
        records_are_sequential = records_are_sequential
            && event.record_number == record_count;

        const auto reparsed = nids::parse_packet(event.input);
        const auto adapter_accepted = std::holds_alternative<nids::PacketView>(event.parsed);
        const auto direct_accepted = std::holds_alternative<nids::PacketView>(reparsed);
        parser_results_agree = parser_results_agree && adapter_accepted == direct_accepted;
        if (adapter_accepted) {
            ++accepted_count;
        } else {
            ++rejected_count;
        }
    }

    std::uint64_t record_count{};
    std::uint64_t accepted_count{};
    std::uint64_t rejected_count{};
    bool records_are_sequential{true};
    bool parser_results_agree{true};
};

struct FileResult {
    std::string path{};
    std::uint64_t record_count{};
    std::uint64_t accepted_count{};
    std::uint64_t rejected_count{};
};

[[nodiscard]] std::string json_string(std::string_view value) {
    constexpr char hexadecimal[] = "0123456789abcdef";
    std::string output;
    output.reserve(value.size() + 2U);
    output.push_back('"');
    for (const auto character : value) {
        const auto byte = static_cast<unsigned char>(character);
        switch (character) {
        case '"':
            output += "\\\"";
            break;
        case '\\':
            output += "\\\\";
            break;
        case '\b':
            output += "\\b";
            break;
        case '\f':
            output += "\\f";
            break;
        case '\n':
            output += "\\n";
            break;
        case '\r':
            output += "\\r";
            break;
        case '\t':
            output += "\\t";
            break;
        default:
            if (byte < 0x20U) {
                output += "\\u00";
                output.push_back(hexadecimal[byte >> 4U]);
                output.push_back(hexadecimal[byte & 0x0FU]);
            } else {
                output.push_back(character);
            }
            break;
        }
    }
    output.push_back('"');
    return output;
}

[[nodiscard]] bool inspect_file(const char* argument, FileResult& output) {
    ParserObserver observer;
    const auto result = nids::read_pcap_file(std::filesystem::path{argument}, observer);
    if (!std::holds_alternative<nids::PcapReadSummary>(result)) {
        const auto& error = std::get<nids::PcapAdapterError>(result);
        std::cerr << "failed to read " << argument << ": " << error.detail << '\n';
        return false;
    }

    const auto& summary = std::get<nids::PcapReadSummary>(result);
    const auto valid = summary.records_read == expected_record_count
        && summary.packets_parsed == expected_record_count
        && summary.parser_errors == 0U
        && observer.record_count == expected_record_count
        && observer.accepted_count == expected_record_count
        && observer.rejected_count == 0U
        && observer.records_are_sequential
        && observer.parser_results_agree;
    if (!valid) {
        std::cerr << "golden parser contract failed for " << argument << '\n';
        return false;
    }

    output = FileResult{
        argument,
        summary.records_read,
        summary.packets_parsed,
        summary.parser_errors,
    };
    return true;
}

void write_result(const std::vector<FileResult>& files) {
    std::cout
        << "{\"schema_version\":\"1.0.0\",\"task\":\"T3.2\","
        << "\"status\":\"passed\",\"reader\":\"nids::read_pcap_file\","
        << "\"parser\":\"nids::parse_packet\",\"files\":[";
    for (std::size_t index = 0; index < files.size(); ++index) {
        if (index != 0U) {
            std::cout << ',';
        }
        const auto& file = files[index];
        std::cout
            << "{\"path\":" << json_string(file.path)
            << ",\"record_count\":" << file.record_count
            << ",\"accepted_count\":" << file.accepted_count
            << ",\"rejected_count\":" << file.rejected_count
            << '}';
    }
    std::cout << "]}\n";
}

}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: nids_t32_golden_dataset_test <pcap> <pcap> <pcap>\n";
        return 2;
    }

    std::vector<FileResult> files;
    files.reserve(3U);
    for (int index = 1; index < argc; ++index) {
        FileResult result;
        if (!inspect_file(argv[index], result)) {
            return 1;
        }
        files.push_back(std::move(result));
    }
    write_result(files);
    return 0;
}
