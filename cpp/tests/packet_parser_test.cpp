#include "nids/packet.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <span>
#include <string_view>
#include <variant>

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

constexpr std::array<std::uint8_t, 49> vlan_udp_packet{
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x81, 0x00,
    0x00, 0x64, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x1F, 0x00, 0x01, 0x00, 0x00,
    0x3F, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
    0x0A, 0x00, 0x00, 0x02,
    0x00, 0x35, 0x14, 0xE9, 0x00, 0x0B, 0x00, 0x00,
    0x01, 0x02, 0x03,
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

struct ExpectedError {
    nids::ParseErrorKind kind{};
    nids::ParseLayer layer{};
    nids::ParseErrorCode code{};
    std::size_t offset{};
    std::size_t available{};
    std::size_t required{};
};

template <std::size_t Size>
[[nodiscard]] nids::ParseResult<nids::PacketView> parse(
    const std::array<std::uint8_t, Size>& bytes,
    std::size_t captured_length = Size,
    std::uint32_t wire_length = static_cast<std::uint32_t>(Size),
    nids::LinkLayerType link_layer = nids::LinkLayerType::ethernet) {
    return nids::parse_packet(nids::PacketInput{
        std::span<const std::uint8_t>{bytes.data(), captured_length},
        1'499'428'779'599'128'000LL,
        nids::ClockDomain::unix_epoch,
        wire_length,
        link_layer,
    });
}

void expect_error(
    TestContext& test,
    const nids::ParseResult<nids::PacketView>& result,
    ExpectedError expected) {
    EXPECT(test, std::holds_alternative<nids::ParseError>(result));
    if (!std::holds_alternative<nids::ParseError>(result)) {
        return;
    }
    const auto& actual = std::get<nids::ParseError>(result);
    EXPECT(test, actual.kind == expected.kind);
    EXPECT(test, actual.layer == expected.layer);
    EXPECT(test, actual.code == expected.code);
    EXPECT(test, actual.offset == expected.offset);
    EXPECT(test, actual.available == expected.available);
    EXPECT(test, actual.required == expected.required);
}

template <std::size_t Size>
[[nodiscard]] bool bytes_equal(
    nids::PacketBytes actual,
    const std::array<std::uint8_t, Size>& expected) {
    return actual.size() == expected.size()
        && std::equal(actual.begin(), actual.end(), expected.begin());
}

void test_tcp(TestContext& test) {
    const auto result = parse(tcp_packet, tcp_packet.size(), tcp_packet.size() + 12U);
    EXPECT(test, std::holds_alternative<nids::PacketView>(result));
    if (!std::holds_alternative<nids::PacketView>(result)) {
        return;
    }

    const auto& packet = std::get<nids::PacketView>(result);
    EXPECT(test, packet.raw_bytes.data() == tcp_packet.data());
    EXPECT(test, packet.is_capture_truncated());
    EXPECT(test, packet.has_valid_ranges());
    EXPECT(test, packet.timestamp_ns == 1'499'428'779'599'128'000LL);
    EXPECT(test, packet.clock_domain == nids::ClockDomain::unix_epoch);
    EXPECT(test, !packet.vlan.has_value());
    EXPECT(test, packet.ethernet.header == (nids::ByteRange{0U, 14U}));
    EXPECT(test, packet.ethernet.destination == (nids::MacAddress{{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}}));
    EXPECT(test, packet.ethernet.source == (nids::MacAddress{{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}}));
    EXPECT(test, packet.ethernet.ether_type == 0x0800U);
    EXPECT(test, packet.ipv4.header == (nids::ByteRange{14U, 24U}));
    EXPECT(test, packet.ipv4.source == (nids::Ipv4Address{{0xC0, 0xA8, 0x01, 0x0A}}));
    EXPECT(test, packet.ipv4.destination == (nids::Ipv4Address{{0xC0, 0xA8, 0x01, 0x14}}));
    EXPECT(test, packet.ipv4.ttl == 64U);
    EXPECT(test, packet.ipv4.protocol == 6U);
    EXPECT(test, std::holds_alternative<nids::TcpView>(packet.transport));

    const auto& tcp = std::get<nids::TcpView>(packet.transport);
    EXPECT(test, tcp.header == (nids::ByteRange{38U, 24U}));
    EXPECT(test, tcp.source_port == 12'345U);
    EXPECT(test, tcp.destination_port == 80U);
    EXPECT(test, tcp.sequence_number == 0x01020304U);
    EXPECT(test, tcp.acknowledgement_number == 0xA0B0C0D0U);
    EXPECT(test, tcp.window_size == 0x1234U);
    EXPECT(test, tcp.flags.bits() == 0x011AU);
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::ns));
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::syn));
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::psh));
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::ack));
    EXPECT(test, !tcp.flags.contains(nids::TcpFlag::fin));
    EXPECT(test, !tcp.flags.contains(nids::TcpFlag::rst));
    EXPECT(test, !tcp.flags.contains(nids::TcpFlag::urg));
    EXPECT(test, !tcp.flags.contains(nids::TcpFlag::ece));
    EXPECT(test, !tcp.flags.contains(nids::TcpFlag::cwr));
    EXPECT(test, bytes_equal(packet.payload_bytes(), std::array<std::uint8_t, 2>{0xDE, 0xAD}));

    auto all_flags_bytes = tcp_packet;
    all_flags_bytes[51U] = 0xFFU;
    const auto all_flags_result = parse(all_flags_bytes);
    EXPECT(test, std::holds_alternative<nids::PacketView>(all_flags_result));
    if (std::holds_alternative<nids::PacketView>(all_flags_result)) {
        const auto& all_flags_tcp = std::get<nids::TcpView>(
            std::get<nids::PacketView>(all_flags_result).transport);
        EXPECT(test, all_flags_tcp.flags.bits() == nids::TcpFlags::valid_mask);
    }

    auto empty_payload_bytes = tcp_packet;
    empty_payload_bytes[16U] = 0x00U;
    empty_payload_bytes[17U] = 0x30U;
    const auto empty_payload_result = parse(empty_payload_bytes);
    EXPECT(test, std::holds_alternative<nids::PacketView>(empty_payload_result));
    if (std::holds_alternative<nids::PacketView>(empty_payload_result)) {
        const auto& empty_payload = std::get<nids::PacketView>(empty_payload_result);
        EXPECT(test, empty_payload.payload == (nids::ByteRange{62U, 0U}));
        EXPECT(test, empty_payload.payload_bytes().empty());
    }
}

void test_vlan_udp(TestContext& test) {
    for (const std::uint16_t tag_type : {
             std::uint16_t{0x8100U},
             std::uint16_t{0x88A8U},
             std::uint16_t{0x9100U},
         }) {
        auto bytes = vlan_udp_packet;
        bytes[12U] = static_cast<std::uint8_t>(tag_type >> 8U);
        bytes[13U] = static_cast<std::uint8_t>(tag_type);
        const auto result = parse(bytes);
        EXPECT(test, std::holds_alternative<nids::PacketView>(result));
        if (!std::holds_alternative<nids::PacketView>(result)) {
            continue;
        }

        const auto& packet = std::get<nids::PacketView>(result);
        EXPECT(test, packet.has_valid_ranges());
        EXPECT(test, packet.ethernet.ether_type == tag_type);
        EXPECT(test, packet.vlan.has_value());
        EXPECT(test, packet.vlan->header == (nids::ByteRange{14U, 4U}));
        EXPECT(test, packet.vlan->tag_control_information == 100U);
        EXPECT(test, packet.vlan->inner_ether_type == 0x0800U);
        EXPECT(test, packet.ipv4.header == (nids::ByteRange{18U, 20U}));
        EXPECT(test, packet.ipv4.ttl == 63U);
        EXPECT(test, packet.ipv4.protocol == 17U);
        EXPECT(test, std::holds_alternative<nids::UdpView>(packet.transport));

        const auto& udp = std::get<nids::UdpView>(packet.transport);
        EXPECT(test, udp.header == (nids::ByteRange{38U, 8U}));
        EXPECT(test, udp.source_port == 53U);
        EXPECT(test, udp.destination_port == 5'353U);
        EXPECT(test, udp.datagram_length == 11U);
        EXPECT(test, bytes_equal(packet.payload_bytes(), std::array<std::uint8_t, 3>{0x01, 0x02, 0x03}));
    }
}

void test_input_and_link_errors(TestContext& test) {
    expect_error(test, parse(tcp_packet, tcp_packet.size(), 63U), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::packet_input,
        nids::ParseErrorCode::inconsistent_lengths,
        0U,
        63U,
        64U,
    });
    expect_error(test, parse(
        tcp_packet,
        tcp_packet.size(),
        tcp_packet.size(),
        static_cast<nids::LinkLayerType>(999U)), {
        nids::ParseErrorKind::unsupported,
        nids::ParseLayer::packet_input,
        nids::ParseErrorCode::unsupported_link_layer,
        0U,
        0U,
        0U,
    });
    expect_error(test, parse(tcp_packet, 13U, 13U), {
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::ethernet,
        nids::ParseErrorCode::truncated_ethernet_header,
        0U,
        13U,
        14U,
    });

    auto arp = tcp_packet;
    arp[12U] = 0x08U;
    arp[13U] = 0x06U;
    expect_error(test, parse(arp), {
        nids::ParseErrorKind::unsupported,
        nids::ParseLayer::ethernet,
        nids::ParseErrorCode::unsupported_ether_type,
        12U,
        2U,
        0U,
    });
}

void test_vlan_errors(TestContext& test) {
    expect_error(test, parse(vlan_udp_packet, 16U, 16U), {
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::vlan,
        nids::ParseErrorCode::truncated_vlan_header,
        14U,
        2U,
        4U,
    });

    auto nested = vlan_udp_packet;
    nested[16U] = 0x88U;
    nested[17U] = 0xA8U;
    expect_error(test, parse(nested), {
        nids::ParseErrorKind::unsupported,
        nids::ParseLayer::vlan,
        nids::ParseErrorCode::nested_vlan,
        16U,
        2U,
        0U,
    });
}

void test_ipv4_errors(TestContext& test) {
    expect_error(test, parse(tcp_packet, 30U, 30U), {
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::truncated_ipv4_header,
        14U,
        16U,
        20U,
    });

    auto invalid_version = tcp_packet;
    invalid_version[14U] = 0x66U;
    expect_error(test, parse(invalid_version), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::invalid_ipv4_version,
        14U,
        1U,
        1U,
    });

    auto invalid_header_length = tcp_packet;
    invalid_header_length[14U] = 0x44U;
    expect_error(test, parse(invalid_header_length), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::invalid_ipv4_header_length,
        14U,
        16U,
        20U,
    });

    expect_error(test, parse(tcp_packet, 63U, 64U), {
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::truncated_ipv4_packet,
        14U,
        49U,
        50U,
    });

    auto invalid_total_length = tcp_packet;
    invalid_total_length[16U] = 0x00U;
    invalid_total_length[17U] = 0x14U;
    expect_error(test, parse(invalid_total_length), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::invalid_ipv4_total_length,
        16U,
        20U,
        24U,
    });

    auto fragment = tcp_packet;
    fragment[20U] = 0x20U;
    fragment[21U] = 0x00U;
    expect_error(test, parse(fragment), {
        nids::ParseErrorKind::unsupported,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::fragmented_ipv4,
        20U,
        2U,
        0U,
    });

    auto icmp = tcp_packet;
    icmp[23U] = 1U;
    expect_error(test, parse(icmp), {
        nids::ParseErrorKind::unsupported,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::unsupported_transport_protocol,
        23U,
        1U,
        0U,
    });
}

void test_tcp_errors(TestContext& test) {
    auto short_tcp = tcp_packet;
    short_tcp[16U] = 0x00U;
    short_tcp[17U] = 0x22U;
    expect_error(test, parse(short_tcp), {
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::tcp,
        nids::ParseErrorCode::truncated_tcp_header,
        38U,
        10U,
        20U,
    });

    auto small_header = tcp_packet;
    small_header[50U] = 0x41U;
    expect_error(test, parse(small_header), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::tcp,
        nids::ParseErrorCode::invalid_tcp_header_length,
        50U,
        16U,
        20U,
    });

    auto oversized_header = tcp_packet;
    oversized_header[50U] = 0x71U;
    expect_error(test, parse(oversized_header), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::tcp,
        nids::ParseErrorCode::invalid_tcp_header_length,
        50U,
        26U,
        28U,
    });
}

void test_udp_errors(TestContext& test) {
    auto short_udp = vlan_udp_packet;
    short_udp[20U] = 0x00U;
    short_udp[21U] = 0x18U;
    expect_error(test, parse(short_udp), {
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::udp,
        nids::ParseErrorCode::truncated_udp_header,
        38U,
        4U,
        8U,
    });

    auto invalid_minimum = vlan_udp_packet;
    invalid_minimum[42U] = 0x00U;
    invalid_minimum[43U] = 0x07U;
    expect_error(test, parse(invalid_minimum), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::udp,
        nids::ParseErrorCode::invalid_udp_length,
        42U,
        7U,
        8U,
    });

    auto exceeds_ipv4 = vlan_udp_packet;
    exceeds_ipv4[42U] = 0x00U;
    exceeds_ipv4[43U] = 0x0CU;
    expect_error(test, parse(exceeds_ipv4), {
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::udp,
        nids::ParseErrorCode::invalid_udp_length,
        42U,
        11U,
        12U,
    });

    std::array<std::uint8_t, 50> trailing_ipv4_byte{};
    std::copy(vlan_udp_packet.begin(), vlan_udp_packet.end(), trailing_ipv4_byte.begin());
    trailing_ipv4_byte[20U] = 0x00U;
    trailing_ipv4_byte[21U] = 0x20U;
    trailing_ipv4_byte[49U] = 0xFFU;
    const auto result = parse(trailing_ipv4_byte);
    EXPECT(test, std::holds_alternative<nids::PacketView>(result));
    if (std::holds_alternative<nids::PacketView>(result)) {
        const auto& packet = std::get<nids::PacketView>(result);
        EXPECT(test, packet.payload == (nids::ByteRange{46U, 3U}));
        EXPECT(test, bytes_equal(packet.payload_bytes(), std::array<std::uint8_t, 3>{0x01, 0x02, 0x03}));
    }
}

}

int main() {
    TestContext test;
    test_tcp(test);
    test_vlan_udp(test);
    test_input_and_link_errors(test);
    test_vlan_errors(test);
    test_ipv4_errors(test);
    test_tcp_errors(test);
    test_udp_errors(test);
    return test.failure_count() == 0 ? 0 : 1;
}
