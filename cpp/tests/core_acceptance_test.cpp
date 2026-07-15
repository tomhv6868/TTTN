#include "nids/dpdk_adapter.hpp"
#include "nids/feature.hpp"
#include "nids/flow_table.hpp"
#include "nids/pcap_adapter.hpp"

#include <pcap/pcap.h>
#include <rte_eal.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace {

constexpr std::uint16_t tcp_fin = 1U << 0U;
constexpr std::uint16_t tcp_syn = 1U << 1U;
constexpr std::uint16_t tcp_psh = 1U << 3U;
constexpr std::uint16_t tcp_ack = 1U << 4U;
constexpr std::size_t parser_valid_header_adjustments = 6U;
constexpr std::size_t future_sentinel_packets = 2U;

enum class Transport : std::uint8_t {
    tcp,
    udp,
};

struct PacketSpec {
    Transport transport{};
    nids::FlowDirection direction{};
    std::int64_t timestamp_ns{};
    std::uint32_t wire_length{};
    std::uint32_t payload_length{};
    std::uint32_t header_length{};
    std::uint8_t ttl{};
    std::uint16_t tcp_window{};
    std::uint16_t tcp_flags{};
};

constexpr auto forward = nids::FlowDirection::forward;
constexpr auto reverse = nids::FlowDirection::reverse;

constexpr std::array<PacketSpec, 14> golden_specs{{
    {Transport::tcp, forward, 1'000'000'000LL, 60U, 0U, 54U, 64U, 1'000U, tcp_syn},
    {Transport::tcp, reverse, 1'001'000'000LL, 74U, 0U, 54U, 63U, 2'000U, tcp_syn | tcp_ack},
    {Transport::tcp, forward, 1'000'500'000LL, 100U, 40U, 58U, 62U, 1'500U, tcp_ack},
    {Transport::tcp, forward, 1'002'000'000LL, 120U, 60U, 58U, 61U, 2'500U, tcp_ack | tcp_psh},
    {Transport::tcp, reverse, 1'003'500'000LL, 80U, 20U, 54U, 60U, 3'000U, tcp_ack},
    {Transport::tcp, forward, 1'001'500'000LL, 140U, 80U, 58U, 59U, 3'500U, tcp_ack | tcp_psh},
    {Transport::tcp, reverse, 1'005'000'000LL, 90U, 30U, 58U, 58U, 4'000U, tcp_ack},
    {Transport::tcp, reverse, 1'004'500'000LL, 110U, 50U, 58U, 57U, 4'500U, tcp_ack},
    {Transport::tcp, forward, 1'008'000'000LL, 130U, 70U, 58U, 56U, 5'000U, tcp_fin | tcp_ack},
    {Transport::tcp, reverse, 1'009'000'000LL, 82U, 24U, 58U, 55U, 5'500U, tcp_ack},
    {Transport::udp, forward, 2'000'000'000LL, 70U, 28U, 42U, 128U, 0U, 0U},
    {Transport::udp, forward, 2'000'000'000LL, 90U, 48U, 42U, 128U, 0U, 0U},
    {Transport::udp, reverse, 1'999'500'000LL, 80U, 38U, 42U, 64U, 0U, 0U},
    {Transport::udp, reverse, 2'001'000'000LL, 72U, 30U, 42U, 63U, 0U, 0U},
}};

struct PrefixCase {
    std::size_t record_count{};
    nids::TransportProtocol protocol{};
    nids::Checkpoint checkpoint{};
};

constexpr std::array<PrefixCase, 5> prefix_cases{{
    {3U, nids::TransportProtocol::tcp, nids::Checkpoint::f3},
    {5U, nids::TransportProtocol::tcp, nids::Checkpoint::f5},
    {7U, nids::TransportProtocol::tcp, nids::Checkpoint::f7},
    {9U, nids::TransportProtocol::tcp, nids::Checkpoint::f9},
    {13U, nids::TransportProtocol::udp, nids::Checkpoint::f3},
}};

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failures_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    [[nodiscard]] int failures() const noexcept {
        return failures_;
    }

private:
    int failures_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)

void write_be16(std::span<std::uint8_t> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write_be32(std::span<std::uint8_t> bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] std::vector<std::uint8_t> build_frame(
    const PacketSpec& spec,
    std::size_t record_index) {
    constexpr std::size_t ethernet_length = 14U;
    constexpr std::size_t ipv4_length = 20U;
    constexpr std::size_t transport_offset = ethernet_length + ipv4_length;
    const auto tcp_length = spec.transport == Transport::tcp
        ? static_cast<std::size_t>(spec.header_length) - transport_offset
        : 8U;
    const auto transport_length = spec.transport == Transport::tcp ? tcp_length : 8U;
    const auto parsed_length = transport_offset + transport_length + spec.payload_length;
    if (spec.wire_length < parsed_length
        || (spec.transport == Transport::tcp && tcp_length != 20U && tcp_length != 24U)
        || (spec.transport == Transport::udp && spec.header_length != 42U)) {
        return {};
    }

    std::vector<std::uint8_t> frame(spec.wire_length, 0U);
    const std::array<std::uint8_t, 6> client_mac{0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
    const std::array<std::uint8_t, 6> server_mac{0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U};
    const auto& source_mac = spec.direction == forward ? client_mac : server_mac;
    const auto& destination_mac = spec.direction == forward ? server_mac : client_mac;
    std::copy(destination_mac.begin(), destination_mac.end(), frame.begin());
    std::copy(source_mac.begin(), source_mac.end(), frame.begin() + 6);
    write_be16(frame, 12U, 0x0800U);

    const std::array<std::uint8_t, 4> tcp_client{10U, 0U, 0U, 1U};
    const std::array<std::uint8_t, 4> tcp_server{10U, 0U, 0U, 2U};
    const std::array<std::uint8_t, 4> udp_client{10U, 0U, 1U, 1U};
    const std::array<std::uint8_t, 4> udp_server{10U, 0U, 1U, 2U};
    const auto& client_ip = spec.transport == Transport::tcp ? tcp_client : udp_client;
    const auto& server_ip = spec.transport == Transport::tcp ? tcp_server : udp_server;
    const auto& source_ip = spec.direction == forward ? client_ip : server_ip;
    const auto& destination_ip = spec.direction == forward ? server_ip : client_ip;
    frame[14U] = 0x45U;
    write_be16(
        frame,
        16U,
        static_cast<std::uint16_t>(ipv4_length + transport_length + spec.payload_length));
    write_be16(frame, 18U, static_cast<std::uint16_t>(record_index + 1U));
    write_be16(frame, 20U, 0x4000U);
    frame[22U] = spec.ttl;
    frame[23U] = spec.transport == Transport::tcp ? 6U : 17U;
    std::copy(source_ip.begin(), source_ip.end(), frame.begin() + 26);
    std::copy(destination_ip.begin(), destination_ip.end(), frame.begin() + 30);

    const auto source_port = spec.transport == Transport::tcp
        ? static_cast<std::uint16_t>(spec.direction == forward ? 40'000U : 443U)
        : static_cast<std::uint16_t>(spec.direction == forward ? 53'000U : 53U);
    const auto destination_port = spec.transport == Transport::tcp
        ? static_cast<std::uint16_t>(spec.direction == forward ? 443U : 40'000U)
        : static_cast<std::uint16_t>(spec.direction == forward ? 53U : 53'000U);
    write_be16(frame, transport_offset, source_port);
    write_be16(frame, transport_offset + 2U, destination_port);

    if (spec.transport == Transport::tcp) {
        write_be32(frame, transport_offset + 4U, static_cast<std::uint32_t>(1'000U + record_index * 100U));
        write_be32(frame, transport_offset + 8U, static_cast<std::uint32_t>(2'000U + record_index * 100U));
        frame[transport_offset + 12U] = static_cast<std::uint8_t>((tcp_length / 4U) << 4U);
        frame[transport_offset + 13U] = static_cast<std::uint8_t>(spec.tcp_flags);
        write_be16(frame, transport_offset + 14U, spec.tcp_window);
        if (tcp_length == 24U) {
            std::fill(
                frame.begin() + static_cast<std::ptrdiff_t>(transport_offset + 20U),
                frame.begin() + static_cast<std::ptrdiff_t>(transport_offset + 24U),
                1U);
        }
    } else {
        write_be16(
            frame,
            transport_offset + 4U,
            static_cast<std::uint16_t>(8U + spec.payload_length));
    }

    const auto payload_offset = transport_offset + transport_length;
    for (std::size_t index = 0; index < spec.payload_length; ++index) {
        frame[payload_offset + index] = static_cast<std::uint8_t>(
            0x80U + ((record_index * 17U + index) % 0x70U));
    }
    return frame;
}

struct OwnedPacket {
    std::vector<std::uint8_t> bytes{};
    std::int64_t timestamp_ns{};
    nids::ClockDomain clock_domain{nids::ClockDomain::unix_epoch};
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

using DeadCapture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
using CaptureDumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;

[[nodiscard]] bool write_capture(
    const std::filesystem::path& path,
    std::span<const PacketSpec> specs) {
    if (std::filesystem::exists(path) || (!path.parent_path().empty()
        && !std::filesystem::is_directory(path.parent_path()))) {
        return false;
    }
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

    for (std::size_t index = 0; index < specs.size(); ++index) {
        const auto frame = build_frame(specs[index], index);
        if (frame.size() != specs[index].wire_length) {
            return false;
        }
        pcap_pkthdr header{};
        header.ts.tv_sec = static_cast<decltype(header.ts.tv_sec)>(
            specs[index].timestamp_ns / 1'000'000'000LL);
        header.ts.tv_usec = static_cast<decltype(header.ts.tv_usec)>(
            specs[index].timestamp_ns % 1'000'000'000LL);
        header.caplen = static_cast<bpf_u_int32>(frame.size());
        header.len = header.caplen;
        pcap_dump(
            reinterpret_cast<u_char*>(dumper.get()),
            &header,
            frame.data());
    }
    return pcap_dump_flush(dumper.get()) == 0;
}

class TemporaryCapture {
public:
    TemporaryCapture() {
        static std::atomic_uint64_t sequence{};
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path()
            / ("nids-t26-" + std::to_string(nonce) + "-"
                + std::to_string(sequence.fetch_add(1U)) + ".pcap");
    }

    explicit TemporaryCapture(std::filesystem::path retained_path)
        : path_{std::move(retained_path)}, retained_{true} {}

    ~TemporaryCapture() {
        if (!retained_) {
            std::error_code ignored;
            std::filesystem::remove(path_, ignored);
        }
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_{};
    bool retained_{};
};

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

using FeatureBits = std::array<std::uint64_t, nids::flow_feature_count_v1>;

[[nodiscard]] FeatureBits feature_bits(const nids::FixedFeatureVector& values) noexcept {
    FeatureBits bits{};
    for (std::size_t index = 0; index < values.size(); ++index) {
        bits[index] = std::bit_cast<std::uint64_t>(values[index]);
    }
    return bits;
}

struct FlowSnapshot {
    nids::FlowIdentity identity{};
    std::uint64_t generation{};
    nids::FlowDirection direction{};
    nids::Checkpoint checkpoint{};
    std::uint64_t packet_count{};
    std::array<std::uint64_t, 2> directional_packet_count{};
    std::int64_t creation_timestamp_ns{};
    std::int64_t last_capture_timestamp_ns{};
    std::int64_t last_event_timestamp_ns{};
    std::optional<std::int64_t> flow_iat_ns{};
    std::optional<std::int64_t> direction_iat_ns{};
    std::uint8_t emitted_checkpoint_mask{};
    FeatureBits features{};
};

[[nodiscard]] bool same_snapshot(const FlowSnapshot& left, const FlowSnapshot& right) noexcept {
    return left.identity == right.identity
        && left.generation == right.generation
        && left.direction == right.direction
        && left.checkpoint == right.checkpoint
        && left.packet_count == right.packet_count
        && left.directional_packet_count == right.directional_packet_count
        && left.creation_timestamp_ns == right.creation_timestamp_ns
        && left.last_capture_timestamp_ns == right.last_capture_timestamp_ns
        && left.last_event_timestamp_ns == right.last_event_timestamp_ns
        && left.flow_iat_ns == right.flow_iat_ns
        && left.direction_iat_ns == right.direction_iat_ns
        && left.emitted_checkpoint_mask == right.emitted_checkpoint_mask
        && left.features == right.features;
}

class SnapshotObserver final : public nids::FlowObserver {
public:
    SnapshotObserver() {
        snapshots.reserve(5U);
    }

    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView&,
        const nids::FlowPacketContext& context) noexcept override {
        if (!context.checkpoint.has_value()) {
            return;
        }
        const auto encoded = nids::FeatureEngine::encode(state);
        if (!std::holds_alternative<nids::FixedFeatureVector>(encoded)) {
            failed = true;
            return;
        }
        snapshots.push_back(FlowSnapshot{
            .identity = state.identity,
            .generation = state.generation,
            .direction = context.direction,
            .checkpoint = *context.checkpoint,
            .packet_count = state.packet_count,
            .directional_packet_count = state.directional_packet_count,
            .creation_timestamp_ns = state.creation_timestamp_ns,
            .last_capture_timestamp_ns = state.last_capture_timestamp_ns,
            .last_event_timestamp_ns = state.last_event_timestamp_ns,
            .flow_iat_ns = context.flow_iat_ns,
            .direction_iat_ns = context.direction_iat_ns,
            .emitted_checkpoint_mask = state.checkpoint_tracker.emitted_mask(),
            .features = feature_bits(std::get<nids::FixedFeatureVector>(encoded)),
        });
    }

    void on_close(const nids::FlowState&, nids::FlowCloseReason) noexcept override {}

    std::vector<FlowSnapshot> snapshots{};
    bool failed{};
};

class PcapPipeline final : public nids::PcapPacketObserver {
public:
    PcapPipeline() : table_{snapshot_observer_} {
        packets.reserve(golden_specs.size());
    }

    void on_packet(const nids::PcapPacketEvent& event) noexcept override {
        packets.push_back(OwnedPacket{
            .bytes = {event.input.raw_bytes.begin(), event.input.raw_bytes.end()},
            .timestamp_ns = event.input.timestamp_ns,
            .clock_domain = event.input.clock_domain,
            .wire_length = event.input.wire_length,
        });
        adapter_parse_equal = adapter_parse_equal
            && same_parse_result(event.parsed, nids::parse_packet(event.input));
        if (!std::holds_alternative<nids::PacketView>(event.parsed)) {
            ++parser_errors;
            return;
        }
        const auto result = table_.ingest(std::get<nids::PacketView>(event.parsed));
        if (result.status != nids::FlowIngestStatus::accepted) {
            ++ingest_errors;
        }
    }

    [[nodiscard]] const std::vector<FlowSnapshot>& snapshots() const noexcept {
        return snapshot_observer_.snapshots;
    }

    [[nodiscard]] bool observer_failed() const noexcept {
        return snapshot_observer_.failed;
    }

    std::vector<OwnedPacket> packets{};
    std::uint64_t parser_errors{};
    std::uint64_t ingest_errors{};
    bool adapter_parse_equal{true};

private:
    SnapshotObserver snapshot_observer_{};
    nids::FlowTable table_;
};

[[nodiscard]] bool read_pipeline(
    const std::filesystem::path& path,
    PcapPipeline& pipeline) {
    const auto result = nids::read_pcap_file(path, pipeline);
    if (!std::holds_alternative<nids::PcapReadSummary>(result)) {
        return false;
    }
    const auto& summary = std::get<nids::PcapReadSummary>(result);
    return summary.records_read == pipeline.packets.size()
        && summary.packets_parsed + summary.parser_errors == summary.records_read
        && summary.parser_errors == pipeline.parser_errors;
}

class EalEnvironment {
public:
    EalEnvironment() {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        arguments_ = {
            "nids_core_acceptance_test",
            "-l", "0",
            "--no-pci",
            "--no-huge",
            "--in-memory",
            "--no-telemetry",
            "--log-level=*:warning",
            "--file-prefix=nids_t26_" + std::to_string(nonce),
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

struct DpdkPipelineResult {
    std::vector<FlowSnapshot> snapshots{};
    std::uint64_t packets_compared{};
    std::uint64_t parser_errors{};
    std::uint64_t ingest_errors{};
    bool bytes_equal{true};
    bool timestamps_equal{true};
    bool clock_domains_equal{true};
    bool wire_lengths_equal{true};
    bool packet_views_equal{true};
    bool observer_failed{};
};

[[nodiscard]] bool enqueue_packets(
    rte_ring* ring,
    rte_mempool* pool,
    std::span<const OwnedPacket> packets) {
    for (const auto& packet : packets) {
        auto* mbuf = rte_pktmbuf_alloc(pool);
        if (mbuf == nullptr) {
            return false;
        }
        auto* destination = rte_pktmbuf_append(
            mbuf,
            static_cast<std::uint16_t>(packet.bytes.size()));
        if (destination == nullptr) {
            rte_pktmbuf_free(mbuf);
            return false;
        }
        std::memcpy(destination, packet.bytes.data(), packet.bytes.size());
        if (rte_ring_enqueue(ring, mbuf) != 0) {
            rte_pktmbuf_free(mbuf);
            return false;
        }
    }
    return true;
}

void drain_ring(rte_ring* ring) noexcept {
    void* object{};
    while (rte_ring_dequeue(ring, &object) == 0) {
        rte_pktmbuf_free(static_cast<rte_mbuf*>(object));
    }
}

[[nodiscard]] bool run_dpdk_pipeline(
    std::span<const OwnedPacket> expected,
    rte_mempool* pool,
    DpdkPipelineResult& output) {
    static std::atomic_uint64_t sequence{};
    const auto id = sequence.fetch_add(1U);
    const auto ring_name = "t26_q_" + std::to_string(id);
    const auto device_name = "t26r" + std::to_string(id);
    auto* ring = rte_ring_create(
        ring_name.c_str(),
        256U,
        rte_socket_id(),
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (ring == nullptr) {
        return false;
    }
    std::array<rte_ring*, 1> rings{ring};
    const auto port_result = rte_eth_from_rings(
        device_name.c_str(),
        rings.data(),
        static_cast<unsigned>(rings.size()),
        rings.data(),
        static_cast<unsigned>(rings.size()),
        rte_socket_id());
    if (port_result < 0) {
        rte_ring_free(ring);
        return false;
    }
    const auto port_id = static_cast<std::uint16_t>(port_result);
    rte_eth_conf configuration{};
    const bool started = rte_eth_dev_configure(port_id, 1U, 0U, &configuration) == 0
        && rte_eth_rx_queue_setup(
            port_id,
            0U,
            128U,
            rte_eth_dev_socket_id(port_id),
            nullptr,
            pool) == 0
        && rte_eth_dev_start(port_id) == 0;
    bool success = started && enqueue_packets(ring, pool, expected);

    SnapshotObserver observer;
    nids::FlowTable table{observer};
    std::size_t next_packet{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (success && next_packet < expected.size()
        && std::chrono::steady_clock::now() < deadline) {
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
            auto* mbuf = received[index];
            if (next_packet >= expected.size()) {
                success = false;
                rte_pktmbuf_free(mbuf);
                continue;
            }
            std::array<std::uint8_t, 65'535> scratch{};
            const auto adapted = nids::adapt_mbuf(
                *mbuf,
                expected[next_packet].timestamp_ns,
                expected[next_packet].clock_domain,
                scratch);
            if (!std::holds_alternative<nids::DpdkPacketEvent>(adapted)) {
                success = false;
                ++output.parser_errors;
            } else {
                const auto& event = std::get<nids::DpdkPacketEvent>(adapted);
                const auto expected_input = expected[next_packet].input();
                output.bytes_equal = output.bytes_equal
                    && event.input.raw_bytes.size() == expected_input.raw_bytes.size()
                    && std::equal(
                        event.input.raw_bytes.begin(),
                        event.input.raw_bytes.end(),
                        expected_input.raw_bytes.begin());
                output.timestamps_equal = output.timestamps_equal
                    && event.input.timestamp_ns == expected_input.timestamp_ns;
                output.clock_domains_equal = output.clock_domains_equal
                    && event.input.clock_domain == expected_input.clock_domain;
                output.wire_lengths_equal = output.wire_lengths_equal
                    && event.input.wire_length == expected_input.wire_length;
                const auto expected_parsed = nids::parse_packet(expected_input);
                output.packet_views_equal = output.packet_views_equal
                    && same_parse_result(event.parsed, expected_parsed);
                if (!std::holds_alternative<nids::PacketView>(event.parsed)) {
                    ++output.parser_errors;
                } else {
                    const auto ingested = table.ingest(std::get<nids::PacketView>(event.parsed));
                    if (ingested.status != nids::FlowIngestStatus::accepted) {
                        ++output.ingest_errors;
                    }
                }
                ++output.packets_compared;
            }
            ++next_packet;
            rte_pktmbuf_free(mbuf);
        }
    }
    success = success && next_packet == expected.size();
    output.snapshots = std::move(observer.snapshots);
    output.observer_failed = observer.failed;

    if (started) {
        rte_eth_dev_stop(port_id);
    }
    rte_eth_dev_close(port_id);
    drain_ring(ring);
    rte_ring_free(ring);
    return success;
}

[[nodiscard]] const FlowSnapshot* find_snapshot(
    const std::vector<FlowSnapshot>& snapshots,
    nids::TransportProtocol protocol,
    nids::Checkpoint checkpoint) noexcept {
    const auto found = std::find_if(
        snapshots.begin(),
        snapshots.end(),
        [protocol, checkpoint](const FlowSnapshot& snapshot) {
            return snapshot.identity.key.protocol == protocol
                && snapshot.checkpoint == checkpoint;
        });
    return found == snapshots.end() ? nullptr : &*found;
}

[[nodiscard]] bool exact_checkpoint_coverage(
    const std::vector<FlowSnapshot>& snapshots) noexcept {
    if (snapshots.size() != prefix_cases.size()) {
        return false;
    }
    return std::all_of(
        prefix_cases.begin(),
        prefix_cases.end(),
        [&snapshots](const PrefixCase& item) {
            return find_snapshot(snapshots, item.protocol, item.checkpoint) != nullptr;
        });
}

}

int main(int argc, char**) {
    if (argc != 1) {
        std::cerr << "usage: nids_core_acceptance_test\n";
        return 2;
    }
    TestContext test;
    const auto observed_header_adjustments = static_cast<std::size_t>(std::count_if(
        golden_specs.begin(),
        golden_specs.begin() + 9,
        [](const PacketSpec& spec) {
            return spec.transport == Transport::tcp && spec.header_length == 58U;
        }));
    const auto observed_future_sentinels = static_cast<std::size_t>(
        golden_specs[9].transport == Transport::tcp)
        + static_cast<std::size_t>(golden_specs[13].transport == Transport::udp);
    EXPECT(test, observed_header_adjustments == parser_valid_header_adjustments);
    EXPECT(test, observed_future_sentinels == future_sentinel_packets);

    const auto* retained_output = std::getenv("NIDS_T26_GOLDEN_PCAP_OUTPUT");
    auto golden = retained_output == nullptr || *retained_output == '\0'
        ? TemporaryCapture{}
        : TemporaryCapture{std::filesystem::path{retained_output}};
    EXPECT(test, write_capture(golden.path(), golden_specs));

    PcapPipeline full_pcap;
    EXPECT(test, read_pipeline(golden.path(), full_pcap));
    EXPECT(test, full_pcap.packets.size() == golden_specs.size());
    EXPECT(test, full_pcap.parser_errors == 0U);
    EXPECT(test, full_pcap.ingest_errors == 0U);
    EXPECT(test, full_pcap.adapter_parse_equal);
    EXPECT(test, !full_pcap.observer_failed());
    EXPECT(test, exact_checkpoint_coverage(full_pcap.snapshots()));

    EalEnvironment eal;
    EXPECT(test, eal.initialized());
    if (!eal.initialized() || full_pcap.packets.size() != golden_specs.size()) {
        return 1;
    }
    auto* pool = rte_pktmbuf_pool_create(
        "nids_t26_pool",
        2'048U,
        32U,
        0U,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    EXPECT(test, pool != nullptr);
    if (pool == nullptr) {
        return 1;
    }

    DpdkPipelineResult full_dpdk;
    EXPECT(test, run_dpdk_pipeline(full_pcap.packets, pool, full_dpdk));
    EXPECT(test, full_dpdk.packets_compared == golden_specs.size());
    EXPECT(test, full_dpdk.parser_errors == 0U);
    EXPECT(test, full_dpdk.ingest_errors == 0U);
    EXPECT(test, !full_dpdk.observer_failed);
    EXPECT(test, full_dpdk.bytes_equal);
    EXPECT(test, full_dpdk.timestamps_equal);
    EXPECT(test, full_dpdk.clock_domains_equal);
    EXPECT(test, full_dpdk.wire_lengths_equal);
    EXPECT(test, full_dpdk.packet_views_equal);
    EXPECT(test, exact_checkpoint_coverage(full_dpdk.snapshots));

    const auto* tcp_flow = find_snapshot(
        full_pcap.snapshots(), nids::TransportProtocol::tcp, nids::Checkpoint::f3);
    const auto* udp_flow = find_snapshot(
        full_pcap.snapshots(), nids::TransportProtocol::udp, nids::Checkpoint::f3);
    const auto flows = tcp_flow != nullptr && udp_flow != nullptr
        && tcp_flow->identity != udp_flow->identity
        ? 2U
        : 0U;
    EXPECT(test, flows == 2U);

    bool flow_snapshots_equal = true;
    bool feature_bits_equal = true;
    std::uint64_t snapshots_compared{};
    for (const auto& item : prefix_cases) {
        const auto* pcap = find_snapshot(full_pcap.snapshots(), item.protocol, item.checkpoint);
        const auto* dpdk = find_snapshot(full_dpdk.snapshots, item.protocol, item.checkpoint);
        const auto comparable = pcap != nullptr && dpdk != nullptr;
        flow_snapshots_equal = flow_snapshots_equal
            && comparable && same_snapshot(*pcap, *dpdk);
        feature_bits_equal = feature_bits_equal
            && comparable && pcap->features == dpdk->features;
        if (comparable) {
            ++snapshots_compared;
        }
    }

    bool prefix_equal = true;
    bool prefix_inputs_equal = true;
    std::uint64_t prefix_runs{};
    std::uint64_t prefix_vectors_compared{};
    std::uint64_t nonvacuous_prefixes{};
    std::uint64_t prefix_parser_errors{};
    std::uint64_t prefix_ingest_errors{};
    for (const auto& item : prefix_cases) {
        TemporaryCapture prefix_capture;
        EXPECT(test, write_capture(
            prefix_capture.path(),
            std::span<const PacketSpec>{golden_specs}.first(item.record_count)));
        PcapPipeline prefix_pcap;
        EXPECT(test, read_pipeline(prefix_capture.path(), prefix_pcap));
        DpdkPipelineResult prefix_dpdk;
        EXPECT(test, run_dpdk_pipeline(prefix_pcap.packets, pool, prefix_dpdk));
        const auto inputs_equal = prefix_pcap.adapter_parse_equal
            && !prefix_pcap.observer_failed()
            && prefix_dpdk.bytes_equal
            && prefix_dpdk.timestamps_equal
            && prefix_dpdk.clock_domains_equal
            && prefix_dpdk.wire_lengths_equal
            && prefix_dpdk.packet_views_equal
            && !prefix_dpdk.observer_failed;
        prefix_inputs_equal = prefix_inputs_equal && inputs_equal;
        prefix_runs += 2U;
        prefix_parser_errors += prefix_pcap.parser_errors + prefix_dpdk.parser_errors;
        prefix_ingest_errors += prefix_pcap.ingest_errors + prefix_dpdk.ingest_errors;

        const auto* full_pcap_snapshot = find_snapshot(
            full_pcap.snapshots(), item.protocol, item.checkpoint);
        const auto* full_dpdk_snapshot = find_snapshot(
            full_dpdk.snapshots, item.protocol, item.checkpoint);
        const auto* prefix_pcap_snapshot = find_snapshot(
            prefix_pcap.snapshots(), item.protocol, item.checkpoint);
        const auto* prefix_dpdk_snapshot = find_snapshot(
            prefix_dpdk.snapshots, item.protocol, item.checkpoint);
        const auto complete = full_pcap_snapshot != nullptr
            && full_dpdk_snapshot != nullptr
            && prefix_pcap_snapshot != nullptr
            && prefix_dpdk_snapshot != nullptr;
        prefix_equal = prefix_equal && inputs_equal && complete
            && same_snapshot(*full_pcap_snapshot, *prefix_pcap_snapshot)
            && same_snapshot(*full_dpdk_snapshot, *prefix_dpdk_snapshot)
            && same_snapshot(*prefix_pcap_snapshot, *prefix_dpdk_snapshot);
        if (complete) {
            prefix_vectors_compared += 2U;
            const auto full_flow_packets = item.protocol == nids::TransportProtocol::tcp
                ? 10U
                : 4U;
            if (full_flow_packets > nids::checkpoint_packet_count(item.checkpoint)) {
                ++nonvacuous_prefixes;
            }
        }
    }
    rte_mempool_free(pool);

    const auto parser_errors = full_pcap.parser_errors + full_dpdk.parser_errors
        + prefix_parser_errors;
    const auto ingest_errors = full_pcap.ingest_errors + full_dpdk.ingest_errors
        + prefix_ingest_errors;
    EXPECT(test, flow_snapshots_equal);
    EXPECT(test, feature_bits_equal);
    EXPECT(test, prefix_equal);
    EXPECT(test, prefix_inputs_equal);
    EXPECT(test, snapshots_compared == 5U);
    EXPECT(test, prefix_runs == 10U);
    EXPECT(test, prefix_vectors_compared == 10U);
    EXPECT(test, nonvacuous_prefixes == 5U);
    EXPECT(test, parser_errors == 0U);
    EXPECT(test, ingest_errors == 0U);
    if (test.failures() != 0) {
        return 1;
    }

    std::cout
        << "T2.6 core acceptance:"
        << " golden_pcap=1"
        << " parser_valid_header_adjustments=" << parser_valid_header_adjustments
        << " pcap_adapter=1"
        << " dpdk_ring=1"
        << " input_bytes_equal=" << static_cast<int>(full_dpdk.bytes_equal)
        << " input_timestamps_equal=" << static_cast<int>(full_dpdk.timestamps_equal)
        << " input_clock_domains_equal=" << static_cast<int>(full_dpdk.clock_domains_equal)
        << " input_wire_lengths_equal=" << static_cast<int>(full_dpdk.wire_lengths_equal)
        << " packet_views_equal=" << static_cast<int>(full_dpdk.packet_views_equal)
        << " flow_snapshots_equal=" << static_cast<int>(flow_snapshots_equal)
        << " feature_bits_equal=" << static_cast<int>(feature_bits_equal)
        << " prefix_equal=" << static_cast<int>(prefix_equal)
        << " tcp_f3=1 tcp_f5=1 tcp_f7=1 tcp_f9=1 udp_f3=1"
        << " packets_compared=" << full_dpdk.packets_compared
        << " flows=" << flows
        << " flow_snapshots_compared=" << snapshots_compared
        << " vectors_compared=5"
        << " features_per_vector=" << nids::flow_feature_count_v1
        << " feature_values_compared=" << snapshots_compared * nids::flow_feature_count_v1
        << " prefix_runs=" << prefix_runs
        << " prefix_vectors_compared=" << prefix_vectors_compared
        << " prefix_feature_values_compared="
        << prefix_vectors_compared * nids::flow_feature_count_v1
        << " nonvacuous_prefixes=" << nonvacuous_prefixes
        << " future_sentinel_packets=" << future_sentinel_packets
        << " parser_errors=" << parser_errors
        << " ingest_errors=" << ingest_errors << '\n';
    return 0;
}
