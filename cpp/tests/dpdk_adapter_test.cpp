#include "nids/dpdk_adapter.hpp"
#include "nids/pcap_adapter.hpp"

#include <pcap/pcap.h>
#include <rte_bus_vdev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
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
    TemporaryCapture() {
        static std::atomic_uint64_t sequence{};
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path()
            / ("nids-t25-" + std::to_string(nonce) + "-"
                + std::to_string(sequence.fetch_add(1U)) + ".pcap");
    }

    ~TemporaryCapture() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_{};
};

using DeadCapture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using CaptureDumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;

[[nodiscard]] bool write_capture(const std::filesystem::path& path) {
    DeadCapture dead{
        pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 65'535, PCAP_TSTAMP_PRECISION_NANO),
        &pcap_close,
    };
    if (!dead) {
        return false;
    }
    CaptureDumper dumper{pcap_dump_open(dead.get(), path.string().c_str()), &pcap_dump_close};
    if (!dumper) {
        return false;
    }

    auto second_packet = tcp_packet;
    second_packet.back() = 0xBE;
    const std::array packets{tcp_packet, second_packet};
    for (std::size_t index = 0; index < packets.size(); ++index) {
        pcap_pkthdr header{};
        header.ts.tv_sec = static_cast<decltype(header.ts.tv_sec)>(10 + index);
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>(123'456'789 + index);
        header.caplen = static_cast<bpf_u_int32>(packets[index].size());
        header.len = header.caplen;
        pcap_dump(
            reinterpret_cast<u_char*>(dumper.get()),
            &header,
            packets[index].data());
    }
    return pcap_dump_flush(dumper.get()) == 0;
}

struct OwnedPacket {
    std::vector<std::uint8_t> bytes{};
    std::int64_t timestamp_ns{};
    nids::ClockDomain clock_domain{};
    std::uint32_t wire_length{};

    [[nodiscard]] nids::PacketInput input() const noexcept {
        return nids::PacketInput{
            .raw_bytes = bytes,
            .timestamp_ns = timestamp_ns,
            .clock_domain = clock_domain,
            .wire_length = wire_length,
            .link_layer = nids::LinkLayerType::ethernet,
        };
    }
};

class CollectingObserver final : public nids::PcapPacketObserver {
public:
    void on_packet(const nids::PcapPacketEvent& event) noexcept override {
        packets.push_back(OwnedPacket{
            .bytes = {event.input.raw_bytes.begin(), event.input.raw_bytes.end()},
            .timestamp_ns = event.input.timestamp_ns,
            .clock_domain = event.input.clock_domain,
            .wire_length = event.input.wire_length,
        });
    }

    std::vector<OwnedPacket> packets{};
};

[[nodiscard]] int validate_pcapng(
    const std::filesystem::path& path,
    std::string_view expected_text) {
    std::uint64_t expected{};
    const auto [end, error] = std::from_chars(
        expected_text.data(),
        expected_text.data() + expected_text.size(),
        expected);
    if (error != std::errc{} || end != expected_text.data() + expected_text.size()
        || expected == 0U) {
        std::cerr << "invalid expected packet count\n";
        return 2;
    }

    CollectingObserver observer;
    const auto result = nids::read_pcap_file(path, observer);
    if (!std::holds_alternative<nids::PcapReadSummary>(result)) {
        std::cerr << "captured PCAPNG could not be reopened\n";
        return 1;
    }
    const auto& summary = std::get<nids::PcapReadSummary>(result);
    if (summary.records_read != expected || summary.packets_parsed != expected
        || summary.parser_errors != 0U || observer.packets.size() != expected) {
        std::cerr << "captured PCAPNG record count or parser result is inconsistent\n";
        return 1;
    }
    std::cout
        << "T2.5 pcapng reopen: records=" << summary.records_read
        << " parsed=" << summary.packets_parsed
        << " parser_errors=" << summary.parser_errors << '\n';
    return 0;
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

struct ParityStats {
    bool bytes_equal{true};
    bool timestamp_equal{true};
    bool parse_equal{true};
    std::uint64_t packets_compared{};
    std::uint64_t packets_parsed{};
    std::uint64_t parser_errors{};
};

class EalEnvironment {
public:
    EalEnvironment() {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        arguments_ = {
            "nids_dpdk_adapter_test",
            "-l", "0",
            "--no-pci",
            "--no-huge",
            "--in-memory",
            "--no-telemetry",
            "--log-level=*:warning",
            "--file-prefix=nids_t25_" + std::to_string(nonce),
        };
        argv_.reserve(arguments_.size());
        for (auto& argument : arguments_) {
            argv_.push_back(argument.data());
        }
        initialized_ = rte_eal_init(static_cast<int>(argv_.size()), argv_.data()) >= 0;
    }

    ~EalEnvironment() {
        if (initialized_) {
            rte_eal_cleanup();
        }
    }

    [[nodiscard]] bool initialized() const noexcept {
        return initialized_;
    }

private:
    std::vector<std::string> arguments_{};
    std::vector<char*> argv_{};
    bool initialized_{};
};

[[nodiscard]] bool start_rx_port(std::uint16_t port_id, rte_mempool* pool) {
    rte_eth_conf configuration{};
    if (rte_eth_dev_configure(port_id, 1U, 0U, &configuration) != 0) {
        return false;
    }
    if (rte_eth_rx_queue_setup(
            port_id,
            0U,
            128U,
            rte_eth_dev_socket_id(port_id),
            nullptr,
            pool) != 0) {
        return false;
    }
    return rte_eth_dev_start(port_id) == 0;
}

[[nodiscard]] bool compare_received_packets(
    TestContext& test,
    std::uint16_t port_id,
    std::span<const OwnedPacket> expected,
    ParityStats& stats) {
    std::size_t next_packet{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (next_packet < expected.size() && std::chrono::steady_clock::now() < deadline) {
        std::array<rte_mbuf*, 16> received{};
        const auto count = rte_eth_rx_burst(
            port_id,
            0U,
            received.data(),
            static_cast<std::uint16_t>(received.size()));
        if (count == 0U) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        for (std::uint16_t index = 0; index < count; ++index) {
            if (next_packet >= expected.size()) {
                rte_pktmbuf_free(received[index]);
                continue;
            }
            std::array<std::uint8_t, 65'535> scratch{};
            const auto adapted = nids::adapt_mbuf(
                *received[index],
                expected[next_packet].timestamp_ns,
                expected[next_packet].clock_domain,
                scratch);
            EXPECT(test, std::holds_alternative<nids::DpdkPacketEvent>(adapted));
            if (std::holds_alternative<nids::DpdkPacketEvent>(adapted)) {
                const auto& event = std::get<nids::DpdkPacketEvent>(adapted);
                const auto expected_input = expected[next_packet].input();
                const bool bytes_equal = event.input.raw_bytes.size() == expected_input.raw_bytes.size()
                    && std::equal(
                        event.input.raw_bytes.begin(),
                        event.input.raw_bytes.end(),
                        expected_input.raw_bytes.begin());
                const bool timestamp_equal = event.input.timestamp_ns == expected_input.timestamp_ns
                    && event.input.clock_domain == expected_input.clock_domain;
                const bool parse_equal = same_parse_result(
                    event.parsed,
                    nids::parse_packet(expected_input));
                EXPECT(test, bytes_equal);
                EXPECT(test, timestamp_equal);
                EXPECT(test, parse_equal);
                stats.bytes_equal = stats.bytes_equal && bytes_equal;
                stats.timestamp_equal = stats.timestamp_equal && timestamp_equal;
                stats.parse_equal = stats.parse_equal && parse_equal;
                ++stats.packets_compared;
                if (std::holds_alternative<nids::PacketView>(event.parsed)) {
                    ++stats.packets_parsed;
                } else {
                    ++stats.parser_errors;
                }
            }
            ++next_packet;
            rte_pktmbuf_free(received[index]);
        }
    }
    EXPECT(test, next_packet == expected.size());
    return next_packet == expected.size();
}

[[nodiscard]] bool test_pcap_pmd(
    TestContext& test,
    const std::filesystem::path& capture_path,
    std::span<const OwnedPacket> expected,
    rte_mempool* pool,
    ParityStats& stats) {
    constexpr std::string_view device_name{"net_pcap_t25"};
    const auto device_arguments = "rx_pcap=" + capture_path.string();
    EXPECT(test, rte_vdev_init(device_name.data(), device_arguments.c_str()) == 0);
    std::uint16_t port_id{};
    if (rte_eth_dev_get_port_by_name(device_name.data(), &port_id) != 0) {
        EXPECT(test, false);
        rte_vdev_uninit(device_name.data());
        return false;
    }
    const bool started = start_rx_port(port_id, pool);
    EXPECT(test, started);
    const bool compared = started && compare_received_packets(test, port_id, expected, stats);
    if (started) {
        rte_eth_dev_stop(port_id);
    }
    rte_eth_dev_close(port_id);
    EXPECT(test, rte_vdev_uninit(device_name.data()) == 0);
    return compared;
}

[[nodiscard]] bool enqueue_packet(
    rte_ring* ring,
    rte_mempool* pool,
    std::span<const std::uint8_t> bytes) {
    auto* mbuf = rte_pktmbuf_alloc(pool);
    if (mbuf == nullptr) {
        return false;
    }
    auto* destination = rte_pktmbuf_append(mbuf, static_cast<std::uint16_t>(bytes.size()));
    if (destination == nullptr) {
        rte_pktmbuf_free(mbuf);
        return false;
    }
    std::memcpy(destination, bytes.data(), bytes.size());
    if (rte_ring_enqueue(ring, mbuf) != 0) {
        rte_pktmbuf_free(mbuf);
        return false;
    }
    return true;
}

[[nodiscard]] bool test_ring_pmd(
    TestContext& test,
    std::span<const OwnedPacket> expected,
    rte_mempool* pool,
    ParityStats& stats) {
    constexpr std::string_view device_name{"net_ring_t25"};
    auto* ring = rte_ring_create("nids_t25_rx", 256U, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    EXPECT(test, ring != nullptr);
    if (ring == nullptr) {
        return false;
    }
    std::array<rte_ring*, 1> rings{ring};
    const auto port_result = rte_eth_from_rings(
        device_name.data(),
        rings.data(),
        static_cast<unsigned>(rings.size()),
        rings.data(),
        static_cast<unsigned>(rings.size()),
        rte_socket_id());
    EXPECT(test, port_result >= 0);
    if (port_result < 0) {
        std::cerr
            << "rte_eth_from_rings failed: return=" << port_result
            << " rte_errno=" << rte_errno
            << " message=" << rte_strerror(rte_errno) << '\n';
        rte_ring_free(ring);
        return false;
    }
    const auto port_id = static_cast<std::uint16_t>(port_result);
    const bool started = start_rx_port(port_id, pool);
    EXPECT(test, started);
    bool enqueued = started;
    if (started) {
        for (const auto& packet : expected) {
            enqueued = enqueue_packet(ring, pool, packet.bytes) && enqueued;
        }
    }
    EXPECT(test, enqueued);
    const bool compared = enqueued && compare_received_packets(test, port_id, expected, stats);
    if (started) {
        rte_eth_dev_stop(port_id);
    }
    rte_eth_dev_close(port_id);
    rte_ring_free(ring);
    return compared;
}

void test_segment_contracts(
    TestContext& test,
    rte_mempool* pool,
    bool& contiguous_ok,
    bool& multisegment_ok) {
    auto* contiguous = rte_pktmbuf_alloc(pool);
    EXPECT(test, contiguous != nullptr);
    if (contiguous != nullptr) {
        auto* destination = rte_pktmbuf_append(
            contiguous,
            static_cast<std::uint16_t>(tcp_packet.size()));
        EXPECT(test, destination != nullptr);
        if (destination != nullptr) {
            std::memcpy(destination, tcp_packet.data(), tcp_packet.size());
            const auto adapted = nids::adapt_mbuf(
                *contiguous,
                101,
                nids::ClockDomain::monotonic,
                {});
            EXPECT(test, std::holds_alternative<nids::DpdkPacketEvent>(adapted));
            if (std::holds_alternative<nids::DpdkPacketEvent>(adapted)) {
                const auto& event = std::get<nids::DpdkPacketEvent>(adapted);
                contiguous_ok = !event.copied_from_segments
                    && event.input.raw_bytes.data()
                        == rte_pktmbuf_mtod(contiguous, const std::uint8_t*);
                EXPECT(test, contiguous_ok);
            }

            const auto data_length = rte_pktmbuf_data_len(contiguous);
            contiguous->pkt_len = static_cast<std::uint32_t>(data_length) + 1U;
            std::array<std::uint8_t, tcp_packet.size() + 1U> invalid_scratch{};
            const auto invalid = nids::adapt_mbuf(
                *contiguous,
                101,
                nids::ClockDomain::monotonic,
                invalid_scratch);
            EXPECT(test, std::holds_alternative<nids::DpdkAdapterError>(invalid));
            if (std::holds_alternative<nids::DpdkAdapterError>(invalid)) {
                EXPECT(
                    test,
                    std::get<nids::DpdkAdapterError>(invalid).code
                        == nids::DpdkAdapterErrorCode::invalid_mbuf_chain);
            }
            contiguous->pkt_len = data_length;
        }
        rte_pktmbuf_free(contiguous);
    }

    auto* head = rte_pktmbuf_alloc(pool);
    auto* tail = rte_pktmbuf_alloc(pool);
    EXPECT(test, head != nullptr && tail != nullptr);
    if (head == nullptr || tail == nullptr) {
        if (head != nullptr) {
            rte_pktmbuf_free(head);
        }
        if (tail != nullptr) {
            rte_pktmbuf_free(tail);
        }
        return;
    }
    constexpr std::size_t split = 31U;
    auto* head_bytes = rte_pktmbuf_append(head, static_cast<std::uint16_t>(split));
    auto* tail_bytes = rte_pktmbuf_append(
        tail,
        static_cast<std::uint16_t>(tcp_packet.size() - split));
    EXPECT(test, head_bytes != nullptr && tail_bytes != nullptr);
    bool tail_chained{};
    if (head_bytes != nullptr && tail_bytes != nullptr) {
        std::memcpy(head_bytes, tcp_packet.data(), split);
        std::memcpy(tail_bytes, tcp_packet.data() + split, tcp_packet.size() - split);
        tail_chained = rte_pktmbuf_chain(head, tail) == 0;
        EXPECT(test, tail_chained);
        if (tail_chained && head->nb_segs == 2U) {
            std::array<std::uint8_t, tcp_packet.size() - 1U> too_small{};
            const auto rejected = nids::adapt_mbuf(
                *head,
                202,
                nids::ClockDomain::monotonic,
                too_small);
            EXPECT(test, std::holds_alternative<nids::DpdkAdapterError>(rejected));
            bool scratch_error_ok{};
            if (std::holds_alternative<nids::DpdkAdapterError>(rejected)) {
                const auto& error = std::get<nids::DpdkAdapterError>(rejected);
                scratch_error_ok = error.code
                        == nids::DpdkAdapterErrorCode::scratch_buffer_too_small
                    && error.scratch_available == too_small.size()
                    && error.scratch_required == tcp_packet.size();
                EXPECT(test, scratch_error_ok);
            }
            std::array<std::uint8_t, tcp_packet.size()> scratch{};
            const auto adapted = nids::adapt_mbuf(
                *head,
                202,
                nids::ClockDomain::monotonic,
                scratch);
            EXPECT(test, std::holds_alternative<nids::DpdkPacketEvent>(adapted));
            if (std::holds_alternative<nids::DpdkPacketEvent>(adapted)) {
                const auto& event = std::get<nids::DpdkPacketEvent>(adapted);
                multisegment_ok = scratch_error_ok && event.copied_from_segments
                    && event.input.raw_bytes.data() == scratch.data()
                    && std::equal(
                        event.input.raw_bytes.begin(),
                        event.input.raw_bytes.end(),
                        tcp_packet.begin());
                EXPECT(test, multisegment_ok);
            }
        }
    }
    rte_pktmbuf_free(head);
    if (!tail_chained) {
        rte_pktmbuf_free(tail);
    }
}

}

int main(int argc, char** argv) {
    if (argc != 1) {
        if (argc == 5 && std::string_view{argv[1]} == "--validate-pcapng"
            && std::string_view{argv[3]} == "--expected-packets") {
            return validate_pcapng(argv[2], argv[4]);
        }
        std::cerr
            << "usage: nids_dpdk_adapter_test"
            << " [--validate-pcapng PATH --expected-packets COUNT]\n";
        return 2;
    }
    TestContext test;
    TemporaryCapture capture;
    EXPECT(test, write_capture(capture.path()));

    CollectingObserver observer;
    const auto pcap_result = nids::read_pcap_file(capture.path(), observer);
    EXPECT(test, std::holds_alternative<nids::PcapReadSummary>(pcap_result));
    if (std::holds_alternative<nids::PcapReadSummary>(pcap_result)) {
        const auto& summary = std::get<nids::PcapReadSummary>(pcap_result);
        EXPECT(test, summary.records_read == 2U);
        EXPECT(test, summary.packets_parsed == 2U);
        EXPECT(test, summary.parser_errors == 0U);
    }
    EXPECT(test, observer.packets.size() == 2U);

    EalEnvironment eal;
    EXPECT(test, eal.initialized());
    if (!eal.initialized() || observer.packets.size() != 2U) {
        return 1;
    }
    auto* pool = rte_pktmbuf_pool_create(
        "nids_t25_pool",
        1'024U,
        32U,
        0U,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    EXPECT(test, pool != nullptr);
    if (pool == nullptr) {
        return 1;
    }

    ParityStats stats;
    const bool pcap_ok = test_pcap_pmd(test, capture.path(), observer.packets, pool, stats);
    const bool ring_ok = test_ring_pmd(test, observer.packets, pool, stats);
    bool contiguous_ok{};
    bool multisegment_ok{};
    test_segment_contracts(test, pool, contiguous_ok, multisegment_ok);
    rte_mempool_free(pool);

    EXPECT(test, stats.packets_compared == 4U);
    EXPECT(test, stats.packets_parsed == stats.packets_compared);
    EXPECT(test, stats.parser_errors == 0U);
    if (test.failure_count() != 0) {
        return 1;
    }
    std::cout
        << "T2.5 parity: pcap=" << static_cast<int>(pcap_ok)
        << " ring=" << static_cast<int>(ring_ok)
        << " contiguous=" << static_cast<int>(contiguous_ok)
        << " multisegment=" << static_cast<int>(multisegment_ok)
        << " bytes_equal=" << static_cast<int>(stats.bytes_equal)
        << " timestamp_equal=" << static_cast<int>(stats.timestamp_equal)
        << " parse_equal=" << static_cast<int>(stats.parse_equal)
        << " packets_compared=" << stats.packets_compared
        << " packets_parsed=" << stats.packets_parsed
        << " parser_errors=" << stats.parser_errors << '\n';
    return 0;
}
