#include "nids/terminal_feature.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>
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

constexpr std::array<std::uint8_t, 256> packet_storage{};
constexpr nids::Ipv4Address client{{10U, 0U, 0U, 1U}};
constexpr nids::Ipv4Address server{{10U, 0U, 0U, 2U}};

[[nodiscard]] nids::PacketView make_packet(
    std::int64_t timestamp_ns,
    bool tcp,
    nids::Ipv4Address source,
    std::uint16_t source_port,
    nids::Ipv4Address destination,
    std::uint16_t destination_port,
    std::uint8_t ttl,
    std::uint16_t tcp_flags = 0U) {
    nids::PacketView packet{};
    packet.raw_bytes = nids::PacketBytes{packet_storage.data(), 60U};
    packet.timestamp_ns = timestamp_ns;
    packet.clock_domain = nids::ClockDomain::unix_epoch;
    packet.wire_length = 60U;
    packet.ethernet.header = nids::ByteRange{0U, 14U};
    packet.ipv4 = nids::Ipv4View{
        nids::ByteRange{14U, 20U},
        source,
        destination,
        ttl,
        static_cast<std::uint8_t>(tcp ? 6U : 17U),
    };
    if (tcp) {
        packet.transport = nids::TcpView{
            nids::ByteRange{34U, 20U},
            source_port,
            destination_port,
            1U,
            0U,
            4096U,
            *nids::TcpFlags::from_bits(tcp_flags),
        };
    } else {
        packet.transport = nids::UdpView{
            nids::ByteRange{34U, 8U},
            source_port,
            destination_port,
            8U,
        };
    }
    packet.payload = nids::ByteRange{tcp ? 54U : 42U, 0U};
    return packet;
}

[[nodiscard]] constexpr std::uint16_t flags(
    nids::TcpFlag first,
    std::optional<nids::TcpFlag> second = std::nullopt) noexcept {
    auto value = static_cast<std::uint16_t>(first);
    if (second.has_value()) {
        value = static_cast<std::uint16_t>(
            value | static_cast<std::uint16_t>(*second));
    }
    return value;
}

struct Record {
    std::uint64_t generation{};
    nids::FlowCloseReason reason{};
    nids::TerminalFeatureVector features{};
    bool legacy_prefix_equal{};
};

class Observer final : public nids::FlowObserver {
public:
    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView& packet,
        const nids::FlowPacketContext& context) noexcept override {
        if (engine.update(state, packet, context).has_value()) {
            failed = true;
        }
    }

    void on_close(
        const nids::FlowState& state,
        nids::FlowCloseReason reason) noexcept override {
        const auto base = nids::FeatureEngine::encode(state);
        const auto terminal = engine.close(state);
        if (!std::holds_alternative<nids::FixedFeatureVector>(base)
            || !std::holds_alternative<nids::TerminalFeatureVector>(terminal)
            || record_count == records.size()) {
            failed = true;
            return;
        }
        const auto& base_values = std::get<nids::FixedFeatureVector>(base);
        const auto& terminal_values =
            std::get<nids::TerminalFeatureVector>(terminal);
        records[record_count++] = Record{
            state.generation,
            reason,
            terminal_values,
            std::equal(
                base_values.begin(),
                base_values.end(),
                terminal_values.begin()),
        };
    }

    [[nodiscard]] const Record* find(std::uint64_t generation) const noexcept {
        const auto found = std::find_if(
            records.begin(),
            records.begin() + static_cast<std::ptrdiff_t>(record_count),
            [generation](const Record& record) {
                return record.generation == generation;
            });
        return found == records.begin()
                + static_cast<std::ptrdiff_t>(record_count)
            ? nullptr
            : &*found;
    }

    nids::TerminalFeatureEngine engine{};
    std::array<Record, 16> records{};
    std::size_t record_count{};
    bool failed{};
};

[[nodiscard]] bool near(double left, double right) noexcept {
    const auto difference = std::abs(left - right);
    return difference <= 1e-9
        || difference <= 1e-9 * std::max(std::abs(left), std::abs(right));
}

void expect_one_hot(
    TestContext& test,
    const nids::TerminalFeatureVector& features) {
    EXPECT(test, near(
        features[66] + features[67] + features[68] + features[69],
        1.0));
}

void test_terminal_reset_and_timing(TestContext& test) {
    Observer observer;
    nids::FlowTable table{observer};
    EXPECT(test, table.ingest(make_packet(
        1'000'000'000LL,
        true,
        client,
        40'000U,
        server,
        21U,
        64U,
        flags(nids::TcpFlag::syn))).status == nids::FlowIngestStatus::accepted);
    EXPECT(test, table.ingest(make_packet(
        2'000'000'000LL,
        true,
        server,
        21U,
        client,
        40'000U,
        60U,
        flags(nids::TcpFlag::ack))).status == nids::FlowIngestStatus::accepted);
    EXPECT(test, table.ingest(make_packet(
        8'000'000'000LL,
        true,
        client,
        40'000U,
        server,
        21U,
        62U,
        flags(nids::TcpFlag::rst, nids::TcpFlag::ack))).status
        == nids::FlowIngestStatus::accepted);

    EXPECT(test, !observer.failed);
    EXPECT(test, observer.record_count == 1U);
    EXPECT(test, observer.engine.active_generation_count() == 0U);
    const auto* record = observer.find(1U);
    EXPECT(test, record != nullptr);
    if (record == nullptr) {
        return;
    }
    const auto& value = record->features;
    EXPECT(test, record->reason == nids::FlowCloseReason::tcp_reset);
    EXPECT(test, record->legacy_prefix_equal);
    EXPECT(test, near(value[0], 7'000'000.0));
    EXPECT(test, near(value[1], 3.0));
    EXPECT(test, near(value[54], 6.0));
    EXPECT(test, near(value[55], 63.0));
    EXPECT(test, near(value[56], 60.0));
    EXPECT(test, near(value[59], 500'000.0));
    EXPECT(test, near(value[60], 6'000'000.0));
    EXPECT(test, near(value[61], 1.0));
    EXPECT(test, near(value[62], 1.0));
    EXPECT(test, near(value[63], 1.0));
    EXPECT(test, near(value[64], 40'000.0));
    EXPECT(test, near(value[65], 21.0));
    EXPECT(test, near(value[66], 1.0));
    expect_one_hot(test, value);
}

void test_causal_context_and_block_reset(TestContext& test) {
    Observer observer;
    nids::FlowTable table{observer};
    const auto ingest = [&table, &test](
                            std::int64_t timestamp_ns,
                            std::uint16_t source_port,
                            std::uint16_t destination_port) {
        EXPECT(test, table.ingest(make_packet(
            timestamp_ns,
            false,
            client,
            source_port,
            server,
            destination_port,
            64U)).status == nids::FlowIngestStatus::accepted);
    };
    ingest(10'000'000'000LL, 50'000U, 80U);
    ingest(11'000'000'000LL, 50'001U, 80U);
    ingest(12'000'000'000LL, 50'002U, 81U);
    ingest(70'000'000'000LL, 50'003U, 80U);
    table.flush();

    EXPECT(test, !observer.failed);
    EXPECT(test, observer.record_count == 4U);
    EXPECT(test, observer.engine.active_generation_count() == 0U);
    const auto* first = observer.find(1U);
    const auto* second = observer.find(2U);
    const auto* third = observer.find(3U);
    const auto* next_block = observer.find(4U);
    EXPECT(test, first != nullptr);
    EXPECT(test, second != nullptr);
    EXPECT(test, third != nullptr);
    EXPECT(test, next_block != nullptr);
    if (first == nullptr || second == nullptr || third == nullptr
        || next_block == nullptr) {
        return;
    }
    EXPECT(test, near(first->features[61], 1.0));
    EXPECT(test, near(first->features[62], 1.0));
    EXPECT(test, near(first->features[63], 1.0));
    EXPECT(test, near(second->features[61], 2.0));
    EXPECT(test, near(second->features[62], 2.0));
    EXPECT(test, near(second->features[63], 1.0));
    EXPECT(test, near(third->features[61], 1.0));
    EXPECT(test, near(third->features[62], 3.0));
    EXPECT(test, near(third->features[63], 2.0));
    EXPECT(test, near(next_block->features[61], 1.0));
    EXPECT(test, near(next_block->features[62], 1.0));
    EXPECT(test, near(next_block->features[63], 1.0));
    for (const auto* record : {first, second, third, next_block}) {
        EXPECT(test, record->legacy_prefix_equal);
        EXPECT(test, near(record->features[54], 17.0));
        EXPECT(test, near(record->features[69], 1.0));
        expect_one_hot(test, record->features);
    }
}

void test_strict_idle_boundary_and_tcp_other(TestContext& test) {
    Observer observer;
    nids::FlowTable table{observer};
    EXPECT(test, table.ingest(make_packet(
        1'000'000'000LL,
        true,
        client,
        40'000U,
        server,
        22U,
        64U,
        flags(nids::TcpFlag::syn))).status == nids::FlowIngestStatus::accepted);
    EXPECT(test, table.ingest(make_packet(
        6'000'000'000LL,
        true,
        server,
        22U,
        client,
        40'000U,
        64U,
        flags(nids::TcpFlag::ack))).status == nids::FlowIngestStatus::accepted);
    table.flush();

    const auto* record = observer.find(1U);
    EXPECT(test, !observer.failed);
    EXPECT(test, record != nullptr);
    if (record == nullptr) {
        return;
    }
    EXPECT(test, near(record->features[59], 5'000'000.0));
    EXPECT(test, near(record->features[60], 0.0));
    EXPECT(test, near(record->features[68], 1.0));
    expect_one_hot(test, record->features);
}

void test_fin_lifecycle(TestContext& test) {
    Observer observer;
    nids::FlowTable table{observer};
    const auto send = [&table, &test](
                          std::int64_t timestamp_ns,
                          bool forward,
                          std::uint16_t tcp_flags) {
        EXPECT(test, table.ingest(make_packet(
            timestamp_ns,
            true,
            forward ? client : server,
            forward ? 40'000U : 443U,
            forward ? server : client,
            forward ? 443U : 40'000U,
            64U,
            tcp_flags)).status == nids::FlowIngestStatus::accepted);
    };
    send(1'000'000'000LL, true, flags(nids::TcpFlag::syn));
    send(
        2'000'000'000LL,
        false,
        flags(nids::TcpFlag::syn, nids::TcpFlag::ack));
    send(3'000'000'000LL, true, flags(nids::TcpFlag::ack));
    send(
        4'000'000'000LL,
        true,
        flags(nids::TcpFlag::fin, nids::TcpFlag::ack));
    send(
        5'000'000'000LL,
        false,
        flags(nids::TcpFlag::fin, nids::TcpFlag::ack));
    send(6'000'000'000LL, true, flags(nids::TcpFlag::ack));

    const auto* record = observer.find(1U);
    EXPECT(test, !observer.failed);
    EXPECT(test, observer.record_count == 1U);
    EXPECT(test, record != nullptr);
    if (record == nullptr) {
        return;
    }
    EXPECT(test, record->reason == nids::FlowCloseReason::tcp_fin_handshake);
    EXPECT(test, near(record->features[67], 1.0));
    expect_one_hot(test, record->features);
}

}

int main() {
    TestContext test;
    test_terminal_reset_and_timing(test);
    test_causal_context_and_block_reset(test);
    test_strict_idle_boundary_and_tcp_other(test);
    test_fin_lifecycle(test);
    return test.failure_count() == 0 ? 0 : 1;
}
