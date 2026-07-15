#include "nids/flow_table.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string_view>
#include <type_traits>
#include <vector>

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

constexpr nids::Ipv4Address client_address{{10U, 0U, 0U, 2U}};
constexpr nids::Ipv4Address server_address{{10U, 0U, 0U, 1U}};
constexpr nids::Ipv4Address third_address{{10U, 0U, 0U, 3U}};
constexpr nids::Ipv4Address fourth_address{{10U, 0U, 0U, 4U}};

[[nodiscard]] nids::TcpFlags tcp_flags(std::uint16_t bits) {
    return nids::TcpFlags::from_bits(bits).value();
}

[[nodiscard]] constexpr std::uint16_t flag(nids::TcpFlag value) noexcept {
    return static_cast<std::uint16_t>(value);
}

[[nodiscard]] nids::PacketView make_tcp_packet(
    nids::Ipv4Address source,
    std::uint16_t source_port,
    nids::Ipv4Address destination,
    std::uint16_t destination_port,
    std::int64_t timestamp_ns,
    std::uint16_t flags = 0U,
    std::uint32_t sequence_number = 0U,
    nids::ClockDomain clock_domain = nids::ClockDomain::unix_epoch) {
    auto packet = nids::PacketView{};
    packet.timestamp_ns = timestamp_ns;
    packet.clock_domain = clock_domain;
    packet.ipv4.source = source;
    packet.ipv4.destination = destination;
    packet.ipv4.protocol = static_cast<std::uint8_t>(nids::TransportProtocol::tcp);
    packet.transport = nids::TcpView{
        {},
        source_port,
        destination_port,
        sequence_number,
        0U,
        1024U,
        tcp_flags(flags),
    };
    return packet;
}

[[nodiscard]] nids::PacketView make_udp_packet(
    nids::Ipv4Address source,
    std::uint16_t source_port,
    nids::Ipv4Address destination,
    std::uint16_t destination_port,
    std::int64_t timestamp_ns) {
    auto packet = nids::PacketView{};
    packet.timestamp_ns = timestamp_ns;
    packet.clock_domain = nids::ClockDomain::unix_epoch;
    packet.ipv4.source = source;
    packet.ipv4.destination = destination;
    packet.ipv4.protocol = static_cast<std::uint8_t>(nids::TransportProtocol::udp);
    packet.transport = nids::UdpView{{}, source_port, destination_port, 8U};
    return packet;
}

struct PacketEvent {
    std::uint64_t generation{};
    std::uint64_t packet_count{};
    nids::FlowDirection direction{};
    std::optional<std::int64_t> flow_iat_ns{};
    std::optional<std::int64_t> direction_iat_ns{};
    bool created{};
};

struct CloseEvent {
    std::uint64_t generation{};
    std::uint64_t packet_count{};
    nids::FlowKey key{};
    nids::FlowCloseReason reason{};
};

class RecordingObserver final : public nids::FlowObserver {
public:
    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView&,
        const nids::FlowPacketContext& context) noexcept override {
        order.push_back('p');
        packets.push_back(PacketEvent{
            state.generation,
            state.packet_count,
            context.direction,
            context.flow_iat_ns,
            context.direction_iat_ns,
            context.created,
        });
    }

    void on_close(
        const nids::FlowState& state,
        nids::FlowCloseReason reason) noexcept override {
        order.push_back('c');
        closes.push_back(CloseEvent{
            state.generation,
            state.packet_count,
            state.identity.key,
            reason,
        });
        if (observed_table != nullptr) {
            close_watermarks.push_back(observed_table->watermark_ns());
        }
    }

    nids::FlowTable* observed_table{};
    std::vector<char> order;
    std::vector<PacketEvent> packets;
    std::vector<CloseEvent> closes;
    std::vector<std::optional<std::int64_t>> close_watermarks;
};

class ReentrantCloseObserver final : public nids::FlowObserver {
public:
    void on_packet(
        const nids::FlowState&,
        const nids::PacketView&,
        const nids::FlowPacketContext&) noexcept override {}

    void on_close(
        const nids::FlowState&,
        nids::FlowCloseReason) noexcept override {
        ++close_count;
        if (table != nullptr && close_count == 1U) {
            table->flush();
        }
    }

    nids::FlowTable* table{};
    std::uint64_t close_count{};
};

[[nodiscard]] std::uint64_t reason_count(
    const nids::FlowCounters& counters,
    nids::FlowCloseReason reason) {
    return counters.close_reason_count[nids::flow_close_reason_index(reason)];
}

void test_bidirectional_and_out_of_order_trace(TestContext& test) {
    RecordingObserver observer;
    nids::FlowTable table{observer};
    const auto forward = make_tcp_packet(
        client_address, 50'000U, server_address, 443U, 100);
    const auto reverse = make_tcp_packet(
        server_address, 443U, client_address, 50'000U, 130);
    const auto late_forward = make_tcp_packet(
        client_address, 50'000U, server_address, 443U, 120);
    const auto same_time_reverse = make_tcp_packet(
        server_address, 443U, client_address, 50'000U, 130);

    const auto first = table.ingest(forward);
    const auto second = table.ingest(reverse);
    const auto third = table.ingest(late_forward);
    const auto fourth = table.ingest(same_time_reverse);

    EXPECT(test, first.status == nids::FlowIngestStatus::accepted);
    EXPECT(test, first.created);
    EXPECT(test, first.direction == nids::FlowDirection::forward);
    EXPECT(test, !first.flow_iat_ns.has_value());
    EXPECT(test, second.direction == nids::FlowDirection::reverse);
    EXPECT(test, second.flow_iat_ns == 30);
    EXPECT(test, !second.direction_iat_ns.has_value());
    EXPECT(test, third.direction == nids::FlowDirection::forward);
    EXPECT(test, third.flow_iat_ns == -10);
    EXPECT(test, third.direction_iat_ns == 20);
    EXPECT(test, fourth.flow_iat_ns == 10);
    EXPECT(test, fourth.direction_iat_ns == 0);
    EXPECT(test, table.watermark_ns() == 130);

    const auto* state = table.find(nids::make_flow_key(forward));
    EXPECT(test, state != nullptr);
    EXPECT(test, state != nullptr && state->packet_count == 4U);
    EXPECT(test, state != nullptr && state->directional_packet_count[0] == 2U);
    EXPECT(test, state != nullptr && state->directional_packet_count[1] == 2U);
    EXPECT(test, state != nullptr && state->last_capture_timestamp_ns == 130);
    EXPECT(test, state != nullptr && state->last_event_timestamp_ns == 130);
    EXPECT(test, observer.packets.size() == 4U);

    const auto wrong_clock = make_tcp_packet(
        client_address,
        50'000U,
        server_address,
        443U,
        140,
        0U,
        0U,
        nids::ClockDomain::monotonic);
    EXPECT(test, table.ingest(wrong_clock).status
        == nids::FlowIngestStatus::clock_domain_mismatch);
    EXPECT(test, table.counters().packets_rejected_clock_domain == 1U);
    const auto* unchanged = table.find(nids::make_flow_key(forward));
    EXPECT(test, unchanged != nullptr && unchanged->packet_count == 4U);
}

void test_timestamp_overflow_rejection(TestContext& test) {
    nids::FlowTable table;
    const auto first = make_udp_packet(
        client_address,
        40'000U,
        server_address,
        53U,
        std::numeric_limits<std::int64_t>::max());
    const auto overflow = make_udp_packet(
        server_address,
        53U,
        client_address,
        40'000U,
        std::numeric_limits<std::int64_t>::min());

    EXPECT(test, table.ingest(first).status == nids::FlowIngestStatus::accepted);
    EXPECT(test, table.ingest(overflow).status
        == nids::FlowIngestStatus::timestamp_overflow);
    const auto* state = table.find(nids::make_flow_key(first));
    EXPECT(test, state != nullptr && state->packet_count == 1U);
    EXPECT(test, table.counters().packets_rejected_timestamp_overflow == 1U);
}

void test_idle_timeout_and_multiple_close_events(TestContext& test) {
    RecordingObserver observer;
    nids::FlowTable table{observer};
    const auto first = make_udp_packet(client_address, 10'001U, server_address, 53U, 0);
    const auto second = make_udp_packet(client_address, 10'002U, server_address, 53U, 0);
    const auto trigger = make_udp_packet(
        third_address,
        10'003U,
        server_address,
        53U,
        nids::flow_timing_v1.idle_timeout_ns);

    static_cast<void>(table.ingest(first));
    static_cast<void>(table.ingest(second));
    const auto trigger_result = table.ingest(trigger);

    EXPECT(test, trigger_result.created);
    EXPECT(test, observer.closes.size() == 2U);
    if (observer.closes.size() == 2U) {
        EXPECT(test, observer.closes[0].reason == nids::FlowCloseReason::idle_timeout);
        EXPECT(test, observer.closes[1].reason == nids::FlowCloseReason::idle_timeout);
    }
    EXPECT(test, reason_count(table.counters(), nids::FlowCloseReason::idle_timeout) == 2U);
    EXPECT(test, table.find(nids::make_flow_key(first)) == nullptr);
    EXPECT(test, table.find(nids::make_flow_key(trigger)) != nullptr);

    RecordingObserver boundary_observer;
    nids::FlowTable boundary_table{boundary_observer};
    boundary_observer.observed_table = &boundary_table;
    const auto boundary_first = boundary_table.ingest(first);
    auto boundary_packet = first;
    boundary_packet.timestamp_ns = nids::flow_timing_v1.idle_timeout_ns;
    const auto boundary_result = boundary_table.ingest(boundary_packet);
    EXPECT(test, boundary_result.created);
    EXPECT(test, boundary_result.generation != boundary_first.generation);
    EXPECT(test, boundary_observer.closes.size() == 1U);
    if (boundary_observer.closes.size() == 1U) {
        EXPECT(test, boundary_observer.closes[0].reason
            == nids::FlowCloseReason::idle_timeout);
    }
    EXPECT(test, boundary_observer.close_watermarks.size() == 1U);
    if (boundary_observer.close_watermarks.size() == 1U) {
        EXPECT(test, boundary_observer.close_watermarks[0]
            == nids::flow_timing_v1.idle_timeout_ns);
    }
}

void test_maximum_age(TestContext& test) {
    RecordingObserver observer;
    nids::FlowTable table{observer};
    constexpr auto step = 59LL * 1'000'000'000LL;
    auto packet = make_udp_packet(client_address, 20'000U, server_address, 53U, 0);
    static_cast<void>(table.ingest(packet));
    for (auto timestamp = step;
         timestamp < nids::flow_timing_v1.maximum_age_ns;
         timestamp += step) {
        packet.timestamp_ns = timestamp;
        static_cast<void>(table.ingest(packet));
    }
    const auto trigger = make_udp_packet(
        third_address,
        20'001U,
        server_address,
        53U,
        nids::flow_timing_v1.maximum_age_ns);
    static_cast<void>(table.ingest(trigger));

    EXPECT(test, observer.closes.size() == 1U);
    if (observer.closes.size() == 1U) {
        EXPECT(test, observer.closes[0].reason == nids::FlowCloseReason::maximum_age);
    }
    EXPECT(test, reason_count(table.counters(), nids::FlowCloseReason::maximum_age) == 1U);

    RecordingObserver tie_observer;
    nids::FlowTable tie_table{tie_observer};
    const auto tie_flow = make_udp_packet(client_address, 20'002U, server_address, 53U, 0);
    const auto tie_trigger = make_udp_packet(
        third_address,
        20'003U,
        server_address,
        53U,
        nids::flow_timing_v1.maximum_age_ns);
    static_cast<void>(tie_table.ingest(tie_flow));
    static_cast<void>(tie_table.ingest(tie_trigger));
    EXPECT(test, tie_observer.closes.size() == 1U);
    if (tie_observer.closes.size() == 1U) {
        EXPECT(test, tie_observer.closes[0].reason == nids::FlowCloseReason::idle_timeout);
    }
}

void test_reset_and_fin_handshake(TestContext& test) {
    RecordingObserver reset_observer;
    nids::FlowTable reset_table{reset_observer};
    const auto reset = make_tcp_packet(
        client_address,
        30'000U,
        server_address,
        443U,
        1,
        flag(nids::TcpFlag::rst) | flag(nids::TcpFlag::fin));
    const auto reset_result = reset_table.ingest(reset);

    EXPECT(test, reset_result.close_reason == nids::FlowCloseReason::tcp_reset);
    EXPECT(test, reset_observer.order.size() == 2U);
    if (reset_observer.order.size() == 2U) {
        EXPECT(test, reset_observer.order[0] == 'p');
        EXPECT(test, reset_observer.order[1] == 'c');
    }
    EXPECT(test, reset_observer.closes.size() == 1U);
    if (reset_observer.closes.size() == 1U) {
        EXPECT(test, reset_observer.closes[0].packet_count == 1U);
    }
    EXPECT(test, reset_table.find(nids::make_flow_key(reset)) == nullptr);

    RecordingObserver fin_observer;
    nids::FlowTable fin_table{fin_observer};
    const auto forward_fin = make_tcp_packet(
        client_address,
        30'001U,
        server_address,
        443U,
        10,
        flag(nids::TcpFlag::fin) | flag(nids::TcpFlag::ack));
    const auto reverse_fin = make_tcp_packet(
        server_address,
        443U,
        client_address,
        30'001U,
        11,
        flag(nids::TcpFlag::fin) | flag(nids::TcpFlag::ack));
    auto reverse_ack = reverse_fin;
    std::get<nids::TcpView>(reverse_ack.transport).flags = tcp_flags(flag(nids::TcpFlag::ack));
    reverse_ack.timestamp_ns = 12;
    auto final_ack = forward_fin;
    std::get<nids::TcpView>(final_ack.transport).flags = tcp_flags(flag(nids::TcpFlag::ack));
    final_ack.timestamp_ns = 13;

    EXPECT(test, !fin_table.ingest(forward_fin).close_reason.has_value());
    EXPECT(test, !fin_table.ingest(reverse_fin).close_reason.has_value());
    EXPECT(test, !fin_table.ingest(reverse_ack).close_reason.has_value());
    const auto final_result = fin_table.ingest(final_ack);
    EXPECT(test, final_result.close_reason == nids::FlowCloseReason::tcp_fin_handshake);
    EXPECT(test, fin_observer.closes.size() == 1U);
    if (fin_observer.closes.size() == 1U) {
        EXPECT(test, fin_observer.closes[0].packet_count == 4U);
    }
    EXPECT(test, fin_table.find(nids::make_flow_key(forward_fin)) == nullptr);
}

void test_tuple_reuse(TestContext& test) {
    RecordingObserver observer;
    nids::FlowTable table{observer};
    const auto syn = make_tcp_packet(
        client_address,
        40'000U,
        server_address,
        443U,
        1,
        flag(nids::TcpFlag::syn),
        700U);
    auto retransmission = syn;
    retransmission.timestamp_ns = 2;
    auto handshake_packet = syn;
    handshake_packet.timestamp_ns = 3;
    std::get<nids::TcpView>(handshake_packet.transport).flags = tcp_flags(flag(nids::TcpFlag::ack));
    auto reused_syn = syn;
    reused_syn.timestamp_ns = 4;

    const auto first = table.ingest(syn);
    const auto retransmitted = table.ingest(retransmission);
    static_cast<void>(table.ingest(handshake_packet));
    const auto reused = table.ingest(reused_syn);

    EXPECT(test, first.generation == retransmitted.generation);
    EXPECT(test, !retransmitted.created);
    EXPECT(test, reused.created);
    EXPECT(test, reused.generation != first.generation);
    EXPECT(test, observer.closes.size() == 1U);
    if (observer.closes.size() == 1U) {
        EXPECT(test, observer.closes[0].reason == nids::FlowCloseReason::tuple_reuse);
        EXPECT(test, observer.closes[0].packet_count == 3U);
    }
    EXPECT(test, observer.order.size() >= 2U);
    if (observer.order.size() >= 2U) {
        EXPECT(test, observer.order[observer.order.size() - 2U] == 'c');
        EXPECT(test, observer.order.back() == 'p');
    }
}

void test_close_callback_can_reenter_safely(TestContext& test) {
    ReentrantCloseObserver observer;
    nids::FlowTable table{observer};
    observer.table = &table;
    const auto first = make_udp_packet(client_address, 45'001U, server_address, 53U, 1);
    const auto second = make_udp_packet(third_address, 45'002U, server_address, 53U, 2);
    static_cast<void>(table.ingest(first));
    static_cast<void>(table.ingest(second));

    table.flush();

    EXPECT(test, observer.close_count == 2U);
    EXPECT(test, table.counters().active_flow_count == 0U);
    EXPECT(test, reason_count(table.counters(), nids::FlowCloseReason::end_of_input) == 2U);
}

void test_capacity_and_memory_budget(TestContext& test) {
    RecordingObserver count_observer;
    nids::FlowTable count_table{
        count_observer,
        nids::FlowTableConfig{2U, nids::flow_capacity_v1.memory_budget_bytes},
    };
    const auto first = make_udp_packet(client_address, 50'001U, server_address, 53U, 100);
    const auto second = make_udp_packet(third_address, 50'002U, server_address, 53U, 100);
    const auto third = make_udp_packet(fourth_address, 50'003U, server_address, 53U, 101);
    static_cast<void>(count_table.ingest(first));
    static_cast<void>(count_table.ingest(second));
    static_cast<void>(count_table.ingest(third));

    EXPECT(test, count_table.find(nids::make_flow_key(first)) == nullptr);
    EXPECT(test, count_table.find(nids::make_flow_key(second)) != nullptr);
    EXPECT(test, count_table.find(nids::make_flow_key(third)) != nullptr);
    EXPECT(test, reason_count(
        count_table.counters(),
        nids::FlowCloseReason::capacity_eviction) == 1U);

    const auto probe_config = nids::FlowTableConfig{
        8U,
        nids::flow_capacity_v1.memory_budget_bytes,
    };
    nids::FlowTable probe{probe_config};
    const auto empty_bytes = probe.counters().current_memory_bytes;
    static_cast<void>(probe.ingest(first));
    const auto one_flow_bytes = probe.counters().current_memory_bytes;
    const auto per_flow_bytes = one_flow_bytes - empty_bytes;
    EXPECT(test, per_flow_bytes > 0U);

    RecordingObserver memory_observer;
    const auto two_flow_budget = empty_bytes + 2U * per_flow_bytes;
    nids::FlowTable memory_table{
        memory_observer,
        nids::FlowTableConfig{8U, two_flow_budget},
    };
    static_cast<void>(memory_table.ingest(first));
    static_cast<void>(memory_table.ingest(second));
    static_cast<void>(memory_table.ingest(third));
    const auto memory_counters = memory_table.counters();
    EXPECT(test, memory_counters.active_flow_count == 2U);
    EXPECT(test, memory_counters.current_memory_bytes <= two_flow_budget);
    EXPECT(test, memory_counters.peak_memory_bytes <= two_flow_budget);
    EXPECT(test, reason_count(
        memory_counters,
        nids::FlowCloseReason::capacity_eviction) == 1U);

    nids::FlowTable exhausted{
        nids::FlowTableConfig{8U, empty_bytes + per_flow_bytes - 1U},
    };
    EXPECT(test, exhausted.ingest(first).status
        == nids::FlowIngestStatus::resource_exhausted);
    EXPECT(test, exhausted.counters().packets_rejected_resource_exhausted == 1U);
}

void test_flush_and_default_memory_receipt(TestContext& test) {
    RecordingObserver observer;
    nids::FlowTable table{observer};
    const auto packet = make_udp_packet(client_address, 60'000U, server_address, 53U, 1);
    static_cast<void>(table.ingest(packet));
    const auto before_flush = table.counters();
    table.flush();
    const auto after_flush = table.counters();

    EXPECT(test, after_flush.active_flow_count == 0U);
    EXPECT(test, reason_count(after_flush, nids::FlowCloseReason::end_of_input) == 1U);
    EXPECT(test, after_flush.current_memory_bytes < before_flush.current_memory_bytes);
    EXPECT(test, after_flush.current_memory_bytes
        == after_flush.fixed_memory_bytes + after_flush.current_allocator_bytes);
    EXPECT(test, after_flush.peak_memory_bytes
        == after_flush.fixed_memory_bytes + after_flush.peak_allocator_bytes);
    EXPECT(test, after_flush.current_allocator_bytes <= after_flush.peak_allocator_bytes);
    EXPECT(test, after_flush.peak_memory_bytes <= after_flush.memory_budget_bytes);
    std::cout << "T2.2 memory accounting: flow_state_bytes=" << sizeof(nids::FlowState)
              << " fixed_bytes=" << after_flush.fixed_memory_bytes
              << " allocator_current_bytes=" << after_flush.current_allocator_bytes
              << " allocator_peak_bytes=" << after_flush.peak_allocator_bytes
              << " current_bytes=" << after_flush.current_memory_bytes
              << " peak_bytes=" << after_flush.peak_memory_bytes
              << " budget_bytes=" << after_flush.memory_budget_bytes << '\n';
}

}

int main() {
    static_assert(std::is_move_constructible_v<nids::FlowTable>);
    static_assert(!std::is_copy_constructible_v<nids::FlowTable>);
    static_assert(nids::flow_close_reason_count == 7U);

    TestContext test;
    test_bidirectional_and_out_of_order_trace(test);
    test_timestamp_overflow_rejection(test);
    test_idle_timeout_and_multiple_close_events(test);
    test_maximum_age(test);
    test_reset_and_fin_handshake(test);
    test_tuple_reuse(test);
    test_close_callback_can_reenter_safely(test);
    test_capacity_and_memory_budget(test);
    test_flush_and_default_memory_receipt(test);
    return test.failure_count() == 0 ? 0 : 1;
}
