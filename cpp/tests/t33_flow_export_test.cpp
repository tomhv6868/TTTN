#include "nids/flow_export.hpp"

#include <pcap/pcap.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::array<std::uint8_t, 64> forward_packet{
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
    TemporaryCapture() {
        static std::atomic_uint64_t sequence{};
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path()
            / ("nids-t33-" + std::to_string(nonce) + "-"
                + std::to_string(sequence.fetch_add(1U)) + ".pcap");
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

struct CaptureRecord {
    std::int64_t seconds{};
    std::int64_t nanoseconds{};
    std::span<const std::uint8_t> bytes{};
};

using DeadCapture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using CaptureDumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;

[[nodiscard]] bool write_capture(
    const std::filesystem::path& path,
    std::span<const CaptureRecord> records) {
    DeadCapture dead{
        pcap_open_dead_with_tstamp_precision(
            DLT_EN10MB,
            65'535,
            PCAP_TSTAMP_PRECISION_NANO),
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
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>(record.nanoseconds);
        header.caplen = static_cast<bpf_u_int32>(record.bytes.size());
        header.len = header.caplen;
        pcap_dump(
            reinterpret_cast<u_char*>(dumper.get()),
            &header,
            record.bytes.data());
    }
    return pcap_dump_flush(dumper.get()) == 0;
}

[[nodiscard]] std::array<std::uint8_t, forward_packet.size()> reverse_packet() {
    auto packet = forward_packet;
    for (std::size_t offset = 0; offset < 4U; ++offset) {
        std::swap(packet[26U + offset], packet[30U + offset]);
    }
    std::swap(packet[38U], packet[40U]);
    std::swap(packet[39U], packet[41U]);
    return packet;
}

class RecordingSink final : public nids::FlowExportSink {
public:
    [[nodiscard]] bool write(const nids::FlowExportRecord& record) noexcept override {
        if (reject) {
            return false;
        }
        try {
            records.push_back(record);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool reject{};
    std::vector<nids::FlowExportRecord> records{};
};

void test_pipeline_and_summary(TestContext& test) {
    const auto reverse = reverse_packet();
    constexpr std::array<std::uint8_t, 3> malformed{0x00, 0x11, 0x22};
    const std::array records{
        CaptureRecord{10, 100, forward_packet},
        CaptureRecord{10, 150, malformed},
        CaptureRecord{10, 200, reverse},
    };
    TemporaryCapture capture;
    EXPECT(test, write_capture(capture.path(), records));

    RecordingSink sink;
    const auto result = nids::export_pcap_flows(capture.path(), sink);

    EXPECT(test, result.succeeded());
    EXPECT(test, result.summary.pcap.records_read == 3U);
    EXPECT(test, result.summary.pcap.packets_parsed == 2U);
    EXPECT(test, result.summary.pcap.parser_errors == 1U);
    EXPECT(test, result.summary.parser_errors == 1U);
    EXPECT(test, result.summary.ingest_errors == 0U);
    EXPECT(test, result.summary.exported_flows == 1U);
    EXPECT(test, result.summary.flows.packets_accepted == 2U);
    EXPECT(test, result.summary.flows.flow_generations_created == 1U);
    EXPECT(test, result.summary.flows.flows_closed == 1U);
    EXPECT(test, result.summary.flows.active_flow_count == 0U);
    EXPECT(test, result.summary.flows.close_reason_count[nids::flow_close_reason_index(
        nids::FlowCloseReason::end_of_input)] == 1U);
    EXPECT(test, sink.records.size() == 1U);
    if (sink.records.size() != 1U) {
        return;
    }

    const auto& flow = sink.records.front();
    EXPECT(test, flow.identity.key.protocol == nids::TransportProtocol::tcp);
    EXPECT(test, flow.identity.key.low.address == (nids::Ipv4Address{{192U, 168U, 1U, 10U}}));
    EXPECT(test, flow.identity.key.low.port == 12'345U);
    EXPECT(test, flow.identity.key.high.address == (nids::Ipv4Address{{192U, 168U, 1U, 20U}}));
    EXPECT(test, flow.identity.key.high.port == 80U);
    EXPECT(test, flow.identity.forward_source == flow.identity.key.low);
    EXPECT(test, flow.generation == 1U);
    EXPECT(test, flow.clock_domain == nids::ClockDomain::unix_epoch);
    EXPECT(test, flow.creation_timestamp_ns == 10'000'000'100LL);
    EXPECT(test, flow.last_capture_timestamp_ns == 10'000'000'200LL);
    EXPECT(test, flow.last_event_timestamp_ns == 10'000'000'200LL);
    EXPECT(test, flow.packet_count == 2U);
    EXPECT(test, flow.forward_packet_count == 1U);
    EXPECT(test, flow.reverse_packet_count == 1U);
    EXPECT(test, flow.close_reason == nids::FlowCloseReason::end_of_input);
}

void test_sink_failure_is_fatal(TestContext& test) {
    const std::array records{CaptureRecord{20, 0, forward_packet}};
    TemporaryCapture capture;
    EXPECT(test, write_capture(capture.path(), records));

    RecordingSink sink;
    sink.reject = true;
    const auto result = nids::export_pcap_flows(capture.path(), sink);

    EXPECT(test, !result.succeeded());
    EXPECT(test, result.failure.has_value());
    if (result.failure.has_value()) {
        EXPECT(test, result.failure->code == nids::FlowExportFailureCode::sink);
        EXPECT(test, result.failure->record_number == 1U);
    }
    EXPECT(test, result.summary.exported_flows == 0U);
    EXPECT(test, result.summary.flows.flows_closed == 1U);
    EXPECT(test, result.summary.flows.active_flow_count == 0U);
}

}

int main() {
    TestContext test;
    test_pipeline_and_summary(test);
    test_sink_failure_is_fatal(test);
    return test.failure_count() == 0 ? 0 : 1;
}
