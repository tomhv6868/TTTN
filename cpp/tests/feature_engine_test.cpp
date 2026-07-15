#include "nids/feature.hpp"
#include "nids/flow_table.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <optional>
#include <string_view>
#include <type_traits>
#include <variant>

namespace {

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

struct PacketSpec {
    std::int64_t timestamp_ns{};
    nids::FlowDirection direction{};
    std::uint32_t wire_length{};
    std::uint32_t payload_length{};
    std::uint32_t header_length{};
    std::uint8_t ttl{};
    std::uint16_t tcp_window{};
    std::uint16_t tcp_flags{};
};

constexpr auto forward = nids::FlowDirection::forward;
constexpr auto reverse = nids::FlowDirection::reverse;

[[nodiscard]] constexpr std::uint16_t flags(
    std::initializer_list<nids::TcpFlag> values) noexcept {
    auto result = std::uint16_t{};
    for (const auto value : values) {
        result = static_cast<std::uint16_t>(
            result | static_cast<std::uint16_t>(value));
    }
    return result;
}

constexpr std::array<PacketSpec, 9> tcp_trace{{
    {1'000'000'000LL, forward, 60U, 0U, 54U, 64U, 1'000U, flags({nids::TcpFlag::syn})},
    {1'001'000'000LL, reverse, 74U, 0U, 54U, 63U, 2'000U, flags({nids::TcpFlag::syn, nids::TcpFlag::ack})},
    {1'000'500'000LL, forward, 100U, 40U, 60U, 62U, 1'500U, flags({nids::TcpFlag::ack})},
    {1'002'000'000LL, forward, 120U, 60U, 60U, 61U, 2'500U, flags({nids::TcpFlag::ack, nids::TcpFlag::psh})},
    {1'003'500'000LL, reverse, 80U, 20U, 54U, 60U, 3'000U, flags({nids::TcpFlag::ack})},
    {1'001'500'000LL, forward, 140U, 80U, 60U, 59U, 3'500U, flags({nids::TcpFlag::ack, nids::TcpFlag::psh})},
    {1'005'000'000LL, reverse, 90U, 30U, 60U, 58U, 4'000U, flags({nids::TcpFlag::ack})},
    {1'004'500'000LL, reverse, 110U, 50U, 60U, 57U, 4'500U, flags({nids::TcpFlag::ack})},
    {1'008'000'000LL, forward, 130U, 70U, 60U, 56U, 5'000U, flags({nids::TcpFlag::fin, nids::TcpFlag::ack})},
}};

constexpr std::array<PacketSpec, 3> udp_trace{{
    {2'000'000'000LL, forward, 70U, 28U, 42U, 128U, 0U, 0U},
    {2'000'000'000LL, forward, 90U, 48U, 42U, 128U, 0U, 0U},
    {1'999'500'000LL, reverse, 80U, 38U, 42U, 64U, 0U, 0U},
}};

constexpr std::array<std::uint8_t, 2'048> packet_storage{};
constexpr nids::Ipv4Address client_address{{10U, 0U, 0U, 1U}};
constexpr nids::Ipv4Address server_address{{10U, 0U, 0U, 2U}};

[[nodiscard]] nids::PacketView make_packet(
    const PacketSpec& spec,
    bool tcp) {
    const auto from_client = spec.direction == forward;
    const auto source_address = from_client ? client_address : server_address;
    const auto destination_address = from_client ? server_address : client_address;
    const auto source_port = static_cast<std::uint16_t>(from_client ? 40'000U : 443U);
    const auto destination_port = static_cast<std::uint16_t>(from_client ? 443U : 40'000U);

    nids::PacketView packet{};
    packet.raw_bytes = nids::PacketBytes{packet_storage.data(), spec.wire_length};
    packet.timestamp_ns = spec.timestamp_ns;
    packet.clock_domain = nids::ClockDomain::unix_epoch;
    packet.wire_length = spec.wire_length;
    packet.ethernet.header = nids::ByteRange{0U, 14U};
    packet.ipv4 = nids::Ipv4View{
        nids::ByteRange{14U, 20U},
        source_address,
        destination_address,
        spec.ttl,
        static_cast<std::uint8_t>(tcp ? 6U : 17U),
    };
    if (tcp) {
        packet.transport = nids::TcpView{
            nids::ByteRange{34U, spec.header_length - 34U},
            source_port,
            destination_port,
            1U,
            0U,
            spec.tcp_window,
            *nids::TcpFlags::from_bits(spec.tcp_flags),
        };
    } else {
        packet.transport = nids::UdpView{
            nids::ByteRange{34U, 8U},
            source_port,
            destination_port,
            static_cast<std::uint16_t>(8U + spec.payload_length),
        };
    }
    packet.payload = nids::ByteRange{spec.header_length, spec.payload_length};
    return packet;
}

struct FeatureRecord {
    nids::Checkpoint checkpoint{};
    nids::FixedFeatureVector values{};
};

class FeatureObserver final : public nids::FlowObserver {
public:
    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView&,
        const nids::FlowPacketContext& context) noexcept override {
        if (!context.checkpoint.has_value()) {
            return;
        }
        const auto encoded = nids::FeatureEngine::encode(state);
        if (!std::holds_alternative<nids::FixedFeatureVector>(encoded)
            || record_count == records.size()) {
            failed = true;
            return;
        }
        records[record_count] = FeatureRecord{
            *context.checkpoint,
            std::get<nids::FixedFeatureVector>(encoded),
        };
        ++record_count;
    }

    void on_close(
        const nids::FlowState&,
        nids::FlowCloseReason) noexcept override {}

    std::array<FeatureRecord, 4> records{};
    std::size_t record_count{};
    bool failed{};
};

template <std::size_t Size>
void ingest_trace(
    nids::FlowTable& table,
    const std::array<PacketSpec, Size>& trace,
    bool tcp,
    TestContext& test) {
    for (const auto& spec : trace) {
        const auto result = table.ingest(make_packet(spec, tcp));
        EXPECT(test, result.status == nids::FlowIngestStatus::accepted);
    }
}

[[nodiscard]] bool near(double left, double right) noexcept {
    const auto difference = std::abs(left - right);
    return difference <= 1e-12
        || difference <= 1e-12 * std::max(std::abs(left), std::abs(right));
}

void test_golden_checkpoint_shape(TestContext& test) {
    FeatureObserver tcp_observer;
    nids::FlowTable tcp_table{tcp_observer};
    ingest_trace(tcp_table, tcp_trace, true, test);
    EXPECT(test, !tcp_observer.failed);
    EXPECT(test, tcp_observer.record_count == 4U);
    EXPECT(test, tcp_observer.records[0].checkpoint == nids::Checkpoint::f3);
    EXPECT(test, tcp_observer.records[1].checkpoint == nids::Checkpoint::f5);
    EXPECT(test, tcp_observer.records[2].checkpoint == nids::Checkpoint::f7);
    EXPECT(test, tcp_observer.records[3].checkpoint == nids::Checkpoint::f9);
    EXPECT(test, near(tcp_observer.records[0].values[0], 1'000.0));
    EXPECT(test, near(tcp_observer.records[0].values[17], 250.0));
    EXPECT(test, near(tcp_observer.records[3].values[30], 1.0));
    EXPECT(test, near(tcp_observer.records[3].values[53], 2.8284271247461903));

    FeatureObserver udp_observer;
    nids::FlowTable udp_table{udp_observer};
    ingest_trace(udp_table, udp_trace, false, test);
    EXPECT(test, !udp_observer.failed);
    EXPECT(test, udp_observer.record_count == 1U);
    EXPECT(test, udp_observer.records[0].checkpoint == nids::Checkpoint::f3);
    EXPECT(test, near(udp_observer.records[0].values[0], 0.0));
    EXPECT(test, near(udp_observer.records[0].values[23], 0.0));
    EXPECT(test, near(udp_observer.records[0].values[36], 0.0));
}

class TerminalObserver final : public nids::FlowObserver {
public:
    enum class Event : std::uint8_t {
        checkpoint,
        close,
    };

    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView&,
        const nids::FlowPacketContext& context) noexcept override {
        if (context.checkpoint == nids::Checkpoint::f3) {
            const auto encoded = nids::FeatureEngine::encode(state);
            encoded_checkpoint = std::holds_alternative<nids::FixedFeatureVector>(encoded);
            events[event_count++] = Event::checkpoint;
        }
    }

    void on_close(
        const nids::FlowState& state,
        nids::FlowCloseReason reason) noexcept override {
        close_packet_count = state.packet_count;
        close_reason = reason;
        events[event_count++] = Event::close;
    }

    std::array<Event, 2> events{};
    std::size_t event_count{};
    std::uint64_t close_packet_count{};
    std::optional<nids::FlowCloseReason> close_reason{};
    bool encoded_checkpoint{};
};

void test_checkpoint_precedes_terminal_close(TestContext& test) {
    auto terminal_trace = std::array<PacketSpec, 3>{
        tcp_trace[0],
        tcp_trace[1],
        tcp_trace[2],
    };
    terminal_trace[2].tcp_flags = flags({nids::TcpFlag::ack, nids::TcpFlag::rst});

    TerminalObserver observer;
    nids::FlowTable table{observer};
    ingest_trace(table, terminal_trace, true, test);
    EXPECT(test, observer.event_count == 2U);
    EXPECT(test, observer.events[0] == TerminalObserver::Event::checkpoint);
    EXPECT(test, observer.events[1] == TerminalObserver::Event::close);
    EXPECT(test, observer.encoded_checkpoint);
    EXPECT(test, observer.close_packet_count == 3U);
    EXPECT(test, observer.close_reason == nids::FlowCloseReason::tcp_reset);
}

void test_typed_numeric_errors(TestContext& test) {
    auto feature_state = nids::FlowFeatureState{};
    feature_state.wire_byte_count = std::numeric_limits<std::uint64_t>::max();
    const auto overflow = nids::FeatureEngine::update(
        feature_state,
        make_packet(tcp_trace[0], true),
        forward,
        std::nullopt,
        std::nullopt,
        1U);
    EXPECT(test, overflow.has_value());
    if (overflow.has_value()) {
        EXPECT(test, overflow->code == nids::FeatureErrorCode::numeric_overflow);
    }
    EXPECT(test, feature_state.packet_length.count == 0U);

    auto invalid_time = nids::FlowState{};
    invalid_time.creation_timestamp_ns = std::numeric_limits<std::int64_t>::min();
    invalid_time.last_event_timestamp_ns = std::numeric_limits<std::int64_t>::max();
    const auto time_result = nids::FeatureEngine::encode(invalid_time);
    EXPECT(test, std::holds_alternative<nids::FeatureError>(time_result));
    if (std::holds_alternative<nids::FeatureError>(time_result)) {
        EXPECT(test, std::get<nids::FeatureError>(time_result).code
            == nids::FeatureErrorCode::timestamp_overflow);
    }

    auto non_finite = nids::FlowState{};
    non_finite.feature_state.ttl.count = 1U;
    non_finite.feature_state.ttl.minimum = 1.0;
    non_finite.feature_state.ttl.maximum = 1.0;
    non_finite.feature_state.ttl.mean = std::numeric_limits<double>::quiet_NaN();
    const auto finite_result = nids::FeatureEngine::encode(non_finite);
    EXPECT(test, std::holds_alternative<nids::FeatureError>(finite_result));
    if (std::holds_alternative<nids::FeatureError>(finite_result)) {
        EXPECT(test, std::get<nids::FeatureError>(finite_result).code
            == nids::FeatureErrorCode::non_finite_value);
    }
}

[[nodiscard]] constexpr bool integer_logical_feature(std::size_t index) noexcept {
    return (index >= 1U && index <= 8U)
        || (index >= 27U && index <= 32U)
        || index == 34U
        || index == 35U
        || index == 38U
        || index == 39U
        || (index >= 42U && index <= 49U);
}

[[nodiscard]] bool valid_emission(const FeatureRecord& record) noexcept {
    constexpr auto uint64_upper_bound = 18'446'744'073'709'551'616.0;
    for (std::size_t index = 0; index < record.values.size(); ++index) {
        const auto value = record.values[index];
        if (!std::isfinite(value)) {
            return false;
        }
        if (integer_logical_feature(index)
            && (value < 0.0
                || value >= uint64_upper_bound
                || value != std::trunc(value))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string_view checkpoint_name(nids::Checkpoint checkpoint) noexcept {
    switch (checkpoint) {
    case nids::Checkpoint::f3:
        return "F3";
    case nids::Checkpoint::f5:
        return "F5";
    case nids::Checkpoint::f7:
        return "F7";
    case nids::Checkpoint::f9:
        return "F9";
    }
    return "";
}

void emit_record(std::string_view trace_id, const FeatureRecord& record) {
    std::cout << "{\"trace_id\":\"" << trace_id
              << "\",\"checkpoint\":\"" << checkpoint_name(record.checkpoint)
              << "\",\"packet_count\":"
              << nids::checkpoint_packet_count(record.checkpoint)
              << ",\"values\":[";
    for (std::size_t index = 0; index < record.values.size(); ++index) {
        if (index != 0U) {
            std::cout << ',';
        }
        if (integer_logical_feature(index)) {
            std::cout << static_cast<std::uint64_t>(record.values[index]);
        } else {
            std::cout << std::setprecision(17) << record.values[index];
        }
    }
    std::cout << "]}\n";
}

[[nodiscard]] int emit_fixture_vectors() {
    TestContext test;
    FeatureObserver tcp_observer;
    nids::FlowTable tcp_table{tcp_observer};
    ingest_trace(tcp_table, tcp_trace, true, test);
    FeatureObserver udp_observer;
    nids::FlowTable udp_table{udp_observer};
    ingest_trace(udp_table, udp_trace, false, test);
    if (test.failure_count() != 0
        || tcp_observer.failed
        || tcp_observer.record_count != 4U
        || udp_observer.failed
        || udp_observer.record_count != 1U
        || !valid_emission(udp_observer.records[0])) {
        return 1;
    }
    for (std::size_t index = 0; index < tcp_observer.record_count; ++index) {
        if (!valid_emission(tcp_observer.records[index])) {
            return 1;
        }
    }
    for (std::size_t index = 0; index < tcp_observer.record_count; ++index) {
        emit_record("tcp_bidirectional_9", tcp_observer.records[index]);
    }
    emit_record("udp_bidirectional_3", udp_observer.records[0]);
    return 0;
}

}

int main(int argc, char** argv) {
    static_assert(nids::flow_feature_count_v1 == 54U);
    static_assert(std::is_trivially_copyable_v<nids::FlowFeatureState>);

    if (argc == 2 && std::string_view{argv[1]} == "--emit-fixture-vectors") {
        return emit_fixture_vectors();
    }
    if (argc != 1) {
        return 2;
    }

    TestContext test;
    test_golden_checkpoint_shape(test);
    test_checkpoint_precedes_terminal_close(test);
    test_typed_numeric_errors(test);
    return test.failure_count() == 0 ? 0 : 1;
}
