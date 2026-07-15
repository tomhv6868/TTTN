#include "nids/pcap_adapter.hpp"

#include <pcap/pcap.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>

namespace nids {
namespace {

using PcapHandle = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

[[nodiscard]] PcapAdapterError make_error(
    PcapAdapterErrorCode code,
    std::uint64_t record_number,
    std::string detail) {
    return PcapAdapterError{code, record_number, std::move(detail)};
}

[[nodiscard]] bool add_would_overflow(std::uint64_t total, std::uint64_t value) noexcept {
    return value > std::numeric_limits<std::uint64_t>::max() - total;
}

[[nodiscard]] bool timestamp_to_nanoseconds(
    const timeval& timestamp,
    std::int64_t& output) noexcept {
    constexpr std::int64_t nanoseconds_per_second = 1'000'000'000LL;
    constexpr auto minimum = std::numeric_limits<std::int64_t>::min();
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    constexpr auto minimum_seconds = minimum / nanoseconds_per_second;
    constexpr auto maximum_seconds = maximum / nanoseconds_per_second;

    if (!std::in_range<std::int64_t>(timestamp.tv_sec)
        || !std::in_range<std::int64_t>(timestamp.tv_usec)) {
        return false;
    }

    const auto seconds = static_cast<std::int64_t>(timestamp.tv_sec);
    const auto fraction = static_cast<std::int64_t>(timestamp.tv_usec);
    if (fraction < 0 || fraction >= nanoseconds_per_second) {
        return false;
    }

    if (seconds < minimum_seconds - 1 || seconds > maximum_seconds) {
        return false;
    }

    if (seconds == minimum_seconds - 1) {
        constexpr auto minimum_fraction = nanoseconds_per_second
            + minimum % nanoseconds_per_second;
        if (fraction < minimum_fraction) {
            return false;
        }
        output = minimum_seconds * nanoseconds_per_second
            + (fraction - nanoseconds_per_second);
        return true;
    }

    const auto whole_seconds = seconds * nanoseconds_per_second;
    if (seconds == maximum_seconds && fraction > maximum - whole_seconds) {
        return false;
    }
    output = whole_seconds + fraction;
    return true;
}

}

PcapReadResult read_pcap_file(
    const std::filesystem::path& path,
    PcapPacketObserver& observer,
    PcapReadOptions options) {
    std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
    const auto native_path = path.string();
    PcapHandle capture{
        pcap_open_offline_with_tstamp_precision(
            native_path.c_str(),
            PCAP_TSTAMP_PRECISION_NANO,
            error_buffer.data()),
        &pcap_close,
    };
    if (!capture) {
        return make_error(PcapAdapterErrorCode::open_failed, 0U, error_buffer.data());
    }

    const auto link_layer = pcap_datalink(capture.get());
    if (link_layer != DLT_EN10MB) {
        return make_error(
            PcapAdapterErrorCode::unsupported_link_layer,
            0U,
            "libpcap link-layer type " + std::to_string(link_layer)
                + " is not DLT_EN10MB");
    }

    PcapReadSummary summary{};
    while (true) {
        if (options.max_records.has_value()
            && summary.records_read >= *options.max_records) {
            summary.record_limit_reached = true;
            return summary;
        }
        pcap_pkthdr* header{};
        const u_char* packet_data{};
        const auto status = pcap_next_ex(capture.get(), &header, &packet_data);
        if (status == PCAP_ERROR_BREAK) {
            return summary;
        }
        if (status != 1) {
            const auto detail = status == 0
                ? std::string{"unexpected timeout while reading an offline capture"}
                : std::string{pcap_geterr(capture.get())};
            return make_error(
                PcapAdapterErrorCode::read_failed,
                summary.records_read + 1U,
                detail);
        }
        if (header == nullptr || (header->caplen != 0U && packet_data == nullptr)) {
            return make_error(
                PcapAdapterErrorCode::read_failed,
                summary.records_read + 1U,
                "libpcap returned an incomplete packet record");
        }
        if (summary.records_read == std::numeric_limits<std::uint64_t>::max()
            || add_would_overflow(summary.captured_bytes, header->caplen)
            || add_would_overflow(summary.wire_bytes, header->len)) {
            return make_error(
                PcapAdapterErrorCode::summary_overflow,
                summary.records_read + 1U,
                "capture summary exceeds uint64 range");
        }

        const auto record_number = summary.records_read + 1U;
        std::int64_t timestamp_ns{};
        if (!timestamp_to_nanoseconds(header->ts, timestamp_ns)) {
            return make_error(
                PcapAdapterErrorCode::timestamp_overflow,
                record_number,
                "packet timestamp cannot be represented as signed nanoseconds");
        }

        const PacketInput input{
            PacketBytes{packet_data, header->caplen},
            timestamp_ns,
            ClockDomain::unix_epoch,
            header->len,
            LinkLayerType::ethernet,
        };
        auto parsed = parse_packet(input);

        summary.records_read = record_number;
        summary.captured_bytes += header->caplen;
        summary.wire_bytes += header->len;
        if (std::holds_alternative<PacketView>(parsed)) {
            ++summary.packets_parsed;
        } else {
            ++summary.parser_errors;
        }

        observer.on_packet(PcapPacketEvent{record_number, input, std::move(parsed)});
    }
}

std::string pcap_runtime_version() {
    return pcap_lib_version();
}

}
