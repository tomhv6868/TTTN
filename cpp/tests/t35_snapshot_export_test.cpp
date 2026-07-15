#include "nids/flow_export.hpp"

#include <pcap/pcap.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::array<std::uint8_t, 64> packet{
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
        if (!condition) {
            ++failure_count_;
            std::cerr << "line " << line << ": expected " << expression << '\n';
        }
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
            / ("nids-t35-" + std::to_string(nonce) + "-"
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

using DeadCapture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using CaptureDumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;

[[nodiscard]] bool write_capture(
    const std::filesystem::path& path,
    std::size_t packet_count) {
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

    for (std::size_t index = 0; index < packet_count; ++index) {
        pcap_pkthdr header{};
        header.ts.tv_sec = 10;
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>((index + 1U) * 100U);
        header.caplen = static_cast<bpf_u_int32>(packet.size());
        header.len = header.caplen;
        pcap_dump(
            reinterpret_cast<u_char*>(dumper.get()),
            &header,
            packet.data());
    }
    return pcap_dump_flush(dumper.get()) == 0;
}

class RecordingFlowSink final : public nids::FlowExportSink {
public:
    [[nodiscard]] bool write(const nids::FlowExportRecord& record) noexcept override {
        try {
            records.push_back(record);
            return true;
        } catch (...) {
            return false;
        }
    }

    std::vector<nids::FlowExportRecord> records{};
};

class RecordingCheckpointSink final : public nids::CheckpointExportSink {
public:
    [[nodiscard]] bool write(const nids::CheckpointExportRecord& record) noexcept override {
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
    std::vector<nids::CheckpointExportRecord> records{};
};

void test_exact_schedule_and_prefix_semantics(TestContext& test) {
    TemporaryCapture capture;
    EXPECT(test, write_capture(capture.path(), 9U));

    RecordingFlowSink flow_sink;
    RecordingCheckpointSink checkpoint_sink;
    const auto result = nids::export_pcap_checkpoints(
        capture.path(), flow_sink, checkpoint_sink);

    EXPECT(test, result.succeeded());
    EXPECT(test, result.exported_checkpoints == 4U);
    EXPECT(test, checkpoint_sink.records.size() == 4U);
    EXPECT(test, flow_sink.records.size() == 1U);
    if (checkpoint_sink.records.size() != 4U) {
        return;
    }

    constexpr std::array expected{
        nids::Checkpoint::f3,
        nids::Checkpoint::f5,
        nids::Checkpoint::f7,
        nids::Checkpoint::f9,
    };
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto& snapshot = checkpoint_sink.records[index];
        const auto count = nids::checkpoint_packet_count(expected[index]);
        EXPECT(test, snapshot.checkpoint == expected[index]);
        EXPECT(test, snapshot.features.size() == nids::flow_feature_count_v1);
        EXPECT(test, snapshot.features[1] == static_cast<double>(count));
        EXPECT(test, snapshot.features[4] == static_cast<double>(count * packet.size()));
        EXPECT(test, snapshot.checkpoint_timestamp_ns == 10'000'000'000LL
            + static_cast<std::int64_t>(count * 100U));
        EXPECT(test, snapshot.generation == 1U);
    }
}

void test_short_flow_and_old_api(TestContext& test) {
    TemporaryCapture short_capture;
    EXPECT(test, write_capture(short_capture.path(), 2U));

    RecordingFlowSink short_flows;
    RecordingCheckpointSink short_checkpoints;
    const auto short_result = nids::export_pcap_checkpoints(
        short_capture.path(), short_flows, short_checkpoints);
    EXPECT(test, short_result.succeeded());
    EXPECT(test, short_result.exported_checkpoints == 0U);
    EXPECT(test, short_checkpoints.records.empty());
    EXPECT(test, short_flows.records.size() == 1U);

    TemporaryCapture old_capture;
    EXPECT(test, write_capture(old_capture.path(), 9U));
    RecordingFlowSink old_sink;
    const auto old_result = nids::export_pcap_flows(old_capture.path(), old_sink);
    EXPECT(test, old_result.succeeded());
    EXPECT(test, old_result.summary.exported_flows == 1U);
    EXPECT(test, old_sink.records.size() == 1U);
}

void test_future_suffix_does_not_change_f3(TestContext& test) {
    TemporaryCapture prefix_capture;
    TemporaryCapture full_capture;
    EXPECT(test, write_capture(prefix_capture.path(), 3U));
    EXPECT(test, write_capture(full_capture.path(), 9U));

    RecordingFlowSink prefix_flows;
    RecordingCheckpointSink prefix_checkpoints;
    const auto prefix_result = nids::export_pcap_checkpoints(
        prefix_capture.path(), prefix_flows, prefix_checkpoints);
    RecordingFlowSink full_flows;
    RecordingCheckpointSink full_checkpoints;
    const auto full_result = nids::export_pcap_checkpoints(
        full_capture.path(), full_flows, full_checkpoints);

    EXPECT(test, prefix_result.succeeded());
    EXPECT(test, full_result.succeeded());
    EXPECT(test, prefix_checkpoints.records.size() == 1U);
    EXPECT(test, full_checkpoints.records.size() == 4U);
    if (!prefix_checkpoints.records.empty() && !full_checkpoints.records.empty()) {
        EXPECT(test, prefix_checkpoints.records[0].features
            == full_checkpoints.records[0].features);
        EXPECT(test, prefix_checkpoints.records[0].checkpoint_timestamp_ns
            == full_checkpoints.records[0].checkpoint_timestamp_ns);
    }
}

void test_checkpoint_sink_failure_is_fatal(TestContext& test) {
    TemporaryCapture capture;
    EXPECT(test, write_capture(capture.path(), 5U));

    RecordingFlowSink flow_sink;
    RecordingCheckpointSink checkpoint_sink;
    checkpoint_sink.reject = true;
    const auto result = nids::export_pcap_checkpoints(
        capture.path(), flow_sink, checkpoint_sink);

    EXPECT(test, !result.succeeded());
    EXPECT(test, result.failure.has_value());
    if (result.failure.has_value()) {
        EXPECT(test, result.failure->code == nids::FlowExportFailureCode::sink);
        EXPECT(test, result.failure->record_number == 3U);
    }
    EXPECT(test, result.exported_checkpoints == 0U);
    EXPECT(test, checkpoint_sink.records.empty());
    EXPECT(test, flow_sink.records.empty());
}

}

int main() {
    TestContext test;
    test_exact_schedule_and_prefix_semantics(test);
    test_short_flow_and_old_api(test);
    test_future_suffix_does_not_change_f3(test);
    test_checkpoint_sink_failure_is_fatal(test);
    return test.failure_count() == 0 ? 0 : 1;
}
