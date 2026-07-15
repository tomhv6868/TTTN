#include "nids/pcap_adapter.hpp"

#include <pcap/pcap.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace {

constexpr std::array<std::uint8_t, 64> tcp_packet{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    0x08, 0x00,
    0x46, 0x00, 0x00, 0x32, 0x12, 0x34, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x0A,
    0xC0, 0xA8, 0x01, 0x14,
    0x01, 0x01, 0x00, 0x00,
    0x30, 0x39, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04,
    0xA0, 0xB0, 0xC0, 0xD0, 0x61, 0x1A, 0x12, 0x34,
    0x00, 0x00, 0x00, 0x00,
    0x02, 0x04, 0x05, 0xB4,
    0xDE, 0xAD,
};

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failure_count_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    [[nodiscard]] int failure_count() const noexcept {
        return failure_count_;
    }

private:
    int failure_count_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)

class TemporaryCapture {
public:
    explicit TemporaryCapture(std::string_view extension) {
        static std::atomic_uint64_t sequence{};
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path()
            / ("nids-t24-" + std::to_string(nonce) + "-"
                + std::to_string(sequence.fetch_add(1U)) + std::string{extension});
    }

    ~TemporaryCapture() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    TemporaryCapture(const TemporaryCapture&) = delete;
    TemporaryCapture& operator=(const TemporaryCapture&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_{};
};

struct ClassicRecord {
    std::int64_t seconds{};
    std::int64_t fraction{};
    std::span<const std::uint8_t> bytes{};
    std::uint32_t wire_length{};
};

using DeadCapture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using CaptureDumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;

[[nodiscard]] bool write_classic_capture(
    const std::filesystem::path& path,
    int precision,
    int link_layer,
    std::span<const ClassicRecord> records) {
    DeadCapture dead{
        pcap_open_dead_with_tstamp_precision(link_layer, 65'535, precision),
        &pcap_close,
    };
    if (!dead) {
        return false;
    }
    CaptureDumper dumper{pcap_dump_open(dead.get(), path.string().c_str()), &pcap_dump_close};
    if (!dumper) {
        return false;
    }

    for (const auto& record : records) {
        pcap_pkthdr header{};
        header.ts.tv_sec = static_cast<decltype(header.ts.tv_sec)>(record.seconds);
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>(record.fraction);
        header.caplen = static_cast<bpf_u_int32>(record.bytes.size());
        header.len = record.wire_length;
        pcap_dump(
            reinterpret_cast<u_char*>(dumper.get()),
            &header,
            record.bytes.data());
    }
    return pcap_dump_flush(dumper.get()) == 0;
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (std::size_t index = 0; index < 4U; ++index) {
        output.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
    }
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (std::size_t index = 0; index < 8U; ++index) {
        output.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
    }
}

[[nodiscard]] bool write_bytes(
    const std::filesystem::path& path,
    std::span<const std::uint8_t> bytes) {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    return output.good();
}

[[nodiscard]] bool write_pcapng_capture(
    const std::filesystem::path& path,
    bool nanosecond_resolution,
    std::uint64_t timestamp,
    std::span<const std::uint8_t> packet) {
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, 0x0A0D0D0AU);
    append_u32(bytes, 28U);
    append_u32(bytes, 0x1A2B3C4DU);
    append_u16(bytes, 1U);
    append_u16(bytes, 0U);
    append_u64(bytes, std::numeric_limits<std::uint64_t>::max());
    append_u32(bytes, 28U);

    const std::uint32_t interface_block_length = nanosecond_resolution ? 32U : 20U;
    append_u32(bytes, 1U);
    append_u32(bytes, interface_block_length);
    append_u16(bytes, 1U);
    append_u16(bytes, 0U);
    append_u32(bytes, 65'535U);
    if (nanosecond_resolution) {
        append_u16(bytes, 9U);
        append_u16(bytes, 1U);
        bytes.push_back(9U);
        bytes.insert(bytes.end(), 3U, 0U);
        append_u16(bytes, 0U);
        append_u16(bytes, 0U);
    }
    append_u32(bytes, interface_block_length);

    const auto padded_length = (packet.size() + 3U) & ~std::size_t{3U};
    const auto packet_block_length = static_cast<std::uint32_t>(32U + padded_length);
    append_u32(bytes, 6U);
    append_u32(bytes, packet_block_length);
    append_u32(bytes, 0U);
    append_u32(bytes, static_cast<std::uint32_t>(timestamp >> 32U));
    append_u32(bytes, static_cast<std::uint32_t>(timestamp));
    append_u32(bytes, static_cast<std::uint32_t>(packet.size()));
    append_u32(bytes, static_cast<std::uint32_t>(packet.size()));
    bytes.insert(bytes.end(), packet.begin(), packet.end());
    bytes.insert(bytes.end(), padded_length - packet.size(), 0U);
    append_u32(bytes, packet_block_length);
    return write_bytes(path, bytes);
}

[[nodiscard]] bool write_truncated_classic_capture(const std::filesystem::path& path) {
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, 0xA1B2C3D4U);
    append_u16(bytes, 2U);
    append_u16(bytes, 4U);
    append_u32(bytes, 0U);
    append_u32(bytes, 0U);
    append_u32(bytes, 65'535U);
    append_u32(bytes, 1U);
    append_u32(bytes, 1U);
    append_u32(bytes, 0U);
    append_u32(bytes, static_cast<std::uint32_t>(tcp_packet.size()));
    append_u32(bytes, static_cast<std::uint32_t>(tcp_packet.size()));
    bytes.insert(bytes.end(), tcp_packet.begin(), tcp_packet.begin() + 3);
    return write_bytes(path, bytes);
}

[[nodiscard]] bool same_parse_result(
    const nids::ParseResult<nids::PacketView>& left,
    const nids::ParseResult<nids::PacketView>& right) {
    if (left.index() != right.index()) {
        return false;
    }
    if (std::holds_alternative<nids::ParseError>(left)) {
        const auto& a = std::get<nids::ParseError>(left);
        const auto& b = std::get<nids::ParseError>(right);
        return a.kind == b.kind && a.layer == b.layer && a.code == b.code
            && a.offset == b.offset && a.available == b.available
            && a.required == b.required;
    }

    const auto& a = std::get<nids::PacketView>(left);
    const auto& b = std::get<nids::PacketView>(right);
    if (!std::equal(a.raw_bytes.begin(), a.raw_bytes.end(), b.raw_bytes.begin(), b.raw_bytes.end())
        || a.timestamp_ns != b.timestamp_ns || a.clock_domain != b.clock_domain
        || a.wire_length != b.wire_length || a.link_layer != b.link_layer
        || a.ethernet.header != b.ethernet.header
        || a.ethernet.destination != b.ethernet.destination
        || a.ethernet.source != b.ethernet.source
        || a.ethernet.ether_type != b.ethernet.ether_type
        || a.vlan.has_value() != b.vlan.has_value()
        || a.ipv4.header != b.ipv4.header || a.ipv4.source != b.ipv4.source
        || a.ipv4.destination != b.ipv4.destination || a.ipv4.ttl != b.ipv4.ttl
        || a.ipv4.protocol != b.ipv4.protocol || a.transport.index() != b.transport.index()
        || a.payload != b.payload) {
        return false;
    }
    if (a.vlan.has_value()
        && (a.vlan->header != b.vlan->header
            || a.vlan->tag_control_information != b.vlan->tag_control_information
            || a.vlan->inner_ether_type != b.vlan->inner_ether_type)) {
        return false;
    }
    if (std::holds_alternative<nids::TcpView>(a.transport)) {
        const auto& x = std::get<nids::TcpView>(a.transport);
        const auto& y = std::get<nids::TcpView>(b.transport);
        return x.header == y.header && x.source_port == y.source_port
            && x.destination_port == y.destination_port
            && x.sequence_number == y.sequence_number
            && x.acknowledgement_number == y.acknowledgement_number
            && x.window_size == y.window_size && x.flags == y.flags;
    }
    const auto& x = std::get<nids::UdpView>(a.transport);
    const auto& y = std::get<nids::UdpView>(b.transport);
    return x.header == y.header && x.source_port == y.source_port
        && x.destination_port == y.destination_port
        && x.datagram_length == y.datagram_length;
}

class ComparingObserver final : public nids::PcapPacketObserver {
public:
    void on_packet(const nids::PcapPacketEvent& event) noexcept override {
        ++calls;
        records_are_sequential = records_are_sequential && event.record_number == calls;
        timestamps.push_back(event.input.timestamp_ns);
        domains_are_unix_epoch = domains_are_unix_epoch
            && event.input.clock_domain == nids::ClockDomain::unix_epoch;
        parity = parity && same_parse_result(event.parsed, nids::parse_packet(event.input));
    }

    std::uint64_t calls{};
    bool records_are_sequential{true};
    bool domains_are_unix_epoch{true};
    bool parity{true};
    std::vector<std::int64_t> timestamps{};
};

struct CoverageStats {
    std::uint64_t packets_seen{};
    std::uint64_t packets_parsed{};
    std::uint64_t parser_errors{};
};

void accumulate(CoverageStats& stats, const nids::PcapReadSummary& summary) {
    stats.packets_seen += summary.records_read;
    stats.packets_parsed += summary.packets_parsed;
    stats.parser_errors += summary.parser_errors;
}

void test_classic_micro_and_parser_continue(TestContext& test, CoverageStats& stats) {
    TemporaryCapture capture{"-micro.pcap"};
    auto arp_packet = tcp_packet;
    arp_packet[12U] = 0x08U;
    arp_packet[13U] = 0x06U;
    const std::array records{
        ClassicRecord{1, 234'567, tcp_packet, static_cast<std::uint32_t>(tcp_packet.size())},
        ClassicRecord{2, 345'678, arp_packet, static_cast<std::uint32_t>(arp_packet.size())},
    };
    EXPECT(test, write_classic_capture(
        capture.path(), PCAP_TSTAMP_PRECISION_MICRO, DLT_EN10MB, records));

    ComparingObserver observer;
    const auto result = nids::read_pcap_file(capture.path(), observer);
    EXPECT(test, std::holds_alternative<nids::PcapReadSummary>(result));
    if (!std::holds_alternative<nids::PcapReadSummary>(result)) {
        return;
    }
    const auto& summary = std::get<nids::PcapReadSummary>(result);
    EXPECT(test, summary.records_read == 2U);
    EXPECT(test, summary.packets_parsed == 1U);
    EXPECT(test, summary.parser_errors == 1U);
    EXPECT(test, observer.calls == 2U);
    EXPECT(test, observer.timestamps == (std::vector<std::int64_t>{1'234'567'000LL, 2'345'678'000LL}));
    EXPECT(test, observer.records_are_sequential);
    EXPECT(test, observer.domains_are_unix_epoch);
    EXPECT(test, observer.parity);
    accumulate(stats, summary);
}

void test_classic_nano(TestContext& test, CoverageStats& stats) {
    TemporaryCapture capture{"-nano.pcap"};
    const std::array records{
        ClassicRecord{2, 987'654'321, tcp_packet, static_cast<std::uint32_t>(tcp_packet.size())},
    };
    EXPECT(test, write_classic_capture(
        capture.path(), PCAP_TSTAMP_PRECISION_NANO, DLT_EN10MB, records));
    ComparingObserver observer;
    const auto result = nids::read_pcap_file(capture.path(), observer);
    EXPECT(test, std::holds_alternative<nids::PcapReadSummary>(result));
    if (std::holds_alternative<nids::PcapReadSummary>(result)) {
        const auto& summary = std::get<nids::PcapReadSummary>(result);
        EXPECT(test, summary.records_read == 1U);
        EXPECT(test, summary.packets_parsed == 1U);
        EXPECT(test, observer.timestamps == (std::vector<std::int64_t>{2'987'654'321LL}));
        EXPECT(test, observer.parity);
        accumulate(stats, summary);
    }
}

void test_pcapng(TestContext& test, CoverageStats& stats) {
    TemporaryCapture capture{".pcapng"};
    EXPECT(test, write_pcapng_capture(capture.path(), false, 3'456'789U, tcp_packet));
    ComparingObserver observer;
    const auto result = nids::read_pcap_file(capture.path(), observer);
    EXPECT(test, std::holds_alternative<nids::PcapReadSummary>(result));
    if (std::holds_alternative<nids::PcapReadSummary>(result)) {
        const auto& summary = std::get<nids::PcapReadSummary>(result);
        EXPECT(test, summary.records_read == 1U);
        EXPECT(test, summary.packets_parsed == 1U);
        EXPECT(test, observer.timestamps == (std::vector<std::int64_t>{3'456'789'000LL}));
        EXPECT(test, observer.parity);
        accumulate(stats, summary);
    }
}

void expect_adapter_error(
    TestContext& test,
    const nids::PcapReadResult& result,
    nids::PcapAdapterErrorCode code,
    std::uint64_t record_number) {
    EXPECT(test, std::holds_alternative<nids::PcapAdapterError>(result));
    if (!std::holds_alternative<nids::PcapAdapterError>(result)) {
        return;
    }
    const auto& error = std::get<nids::PcapAdapterError>(result);
    EXPECT(test, error.code == code);
    EXPECT(test, error.record_number == record_number);
    EXPECT(test, !error.detail.empty());
}

void test_fatal_errors(TestContext& test) {
    ComparingObserver observer;
    TemporaryCapture missing{"-missing.pcap"};
    expect_adapter_error(
        test,
        nids::read_pcap_file(missing.path(), observer),
        nids::PcapAdapterErrorCode::open_failed,
        0U);

    TemporaryCapture raw{"-raw.pcap"};
    const std::array raw_records{
        ClassicRecord{1, 0, tcp_packet, static_cast<std::uint32_t>(tcp_packet.size())},
    };
    EXPECT(test, write_classic_capture(
        raw.path(), PCAP_TSTAMP_PRECISION_MICRO, DLT_RAW, raw_records));
    expect_adapter_error(
        test,
        nids::read_pcap_file(raw.path(), observer),
        nids::PcapAdapterErrorCode::unsupported_link_layer,
        0U);

    TemporaryCapture truncated{"-truncated.pcap"};
    EXPECT(test, write_truncated_classic_capture(truncated.path()));
    expect_adapter_error(
        test,
        nids::read_pcap_file(truncated.path(), observer),
        nids::PcapAdapterErrorCode::read_failed,
        1U);

    TemporaryCapture overflow{"-overflow.pcapng"};
    EXPECT(test, write_pcapng_capture(
        overflow.path(),
        true,
        std::numeric_limits<std::uint64_t>::max(),
        tcp_packet));
    expect_adapter_error(
        test,
        nids::read_pcap_file(overflow.path(), observer),
        nids::PcapAdapterErrorCode::timestamp_overflow,
        1U);
}

}

int main() {
    TestContext test;
    CoverageStats stats;
    test_classic_micro_and_parser_continue(test, stats);
    test_classic_nano(test, stats);
    test_pcapng(test, stats);
    test_fatal_errors(test);
    EXPECT(test, !nids::pcap_runtime_version().empty());
    EXPECT(test, stats.packets_seen == stats.packets_parsed + stats.parser_errors);

    if (test.failure_count() != 0) {
        return 1;
    }
    std::cout
        << "T2.4 coverage: pcap_micro=1 pcap_nano=1 pcapng=1 open_error=1"
        << " read_error=1 linktype_error=1 timestamp_overflow=1"
        << " parser_error_continue=1 packets_seen=" << stats.packets_seen
        << " packets_parsed=" << stats.packets_parsed
        << " parser_errors=" << stats.parser_errors << '\n';
    return 0;
}
