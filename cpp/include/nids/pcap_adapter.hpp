#pragma once

#include "nids/packet.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>

namespace nids {

enum class PcapAdapterErrorCode : std::uint8_t {
    open_failed,
    unsupported_link_layer,
    timestamp_overflow,
    read_failed,
    summary_overflow,
};

struct PcapAdapterError {
    PcapAdapterErrorCode code{};
    std::uint64_t record_number{};
    std::string detail{};
};

struct PcapReadSummary {
    std::uint64_t records_read{};
    std::uint64_t packets_parsed{};
    std::uint64_t parser_errors{};
    std::uint64_t captured_bytes{};
    std::uint64_t wire_bytes{};
    bool record_limit_reached{};
};

struct PcapReadOptions {
    std::optional<std::uint64_t> max_records{};
};

struct PcapPacketEvent {
    std::uint64_t record_number{};
    PacketInput input{};
    ParseResult<PacketView> parsed{};
};

class PcapPacketObserver {
public:
    virtual ~PcapPacketObserver() = default;

    // All packet-backed spans are valid only until this callback returns.
    virtual void on_packet(const PcapPacketEvent& event) noexcept = 0;
};

using PcapReadResult = std::variant<PcapReadSummary, PcapAdapterError>;

[[nodiscard]] PcapReadResult read_pcap_file(
    const std::filesystem::path& path,
    PcapPacketObserver& observer,
    PcapReadOptions options = {});

[[nodiscard]] std::string pcap_runtime_version();

}
