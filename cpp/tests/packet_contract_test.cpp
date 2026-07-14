#include "nids/packet.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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

[[nodiscard]] constexpr std::uint16_t read_be16(nids::PacketBytes bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U)
        | static_cast<std::uint16_t>(bytes[offset + 1U]));
}

[[nodiscard]] constexpr std::uint32_t read_be32(nids::PacketBytes bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U)
        | (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U)
        | (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U)
        | static_cast<std::uint32_t>(bytes[offset + 3U]);
}

template <std::size_t Size>
[[nodiscard]] bool bytes_equal(nids::PacketBytes actual, const std::array<std::uint8_t, Size>& expected) {
    return actual.size() == expected.size()
        && std::equal(actual.begin(), actual.end(), expected.begin());
}

[[nodiscard]] nids::PacketView make_tcp_view() {
    const auto flags = nids::TcpFlags::from_bits(0x011AU).value_or(nids::TcpFlags{});
    return {
        std::span{tcp_packet},
        1'499'428'779'599'128'000LL,
        nids::ClockDomain::unix_epoch,
        static_cast<std::uint32_t>(tcp_packet.size() + 12U),
        nids::LinkLayerType::ethernet,
        nids::EthernetView{
            nids::ByteRange{0U, 14U},
            nids::MacAddress{{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
            nids::MacAddress{{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}},
            0x0800U,
        },
        std::nullopt,
        nids::Ipv4View{
            nids::ByteRange{14U, 24U},
            nids::Ipv4Address{{0xC0, 0xA8, 0x01, 0x0A}},
            nids::Ipv4Address{{0xC0, 0xA8, 0x01, 0x14}},
            64U,
            6U,
        },
        nids::TcpView{
            nids::ByteRange{38U, 24U},
            12'345U,
            80U,
            0x01020304U,
            0xA0B0C0D0U,
            0x1234U,
            flags,
        },
        nids::ByteRange{62U, 2U},
    };
}

[[nodiscard]] nids::PacketView make_vlan_udp_view() {
    return {
        std::span{vlan_udp_packet},
        42'000LL,
        nids::ClockDomain::monotonic,
        static_cast<std::uint32_t>(vlan_udp_packet.size()),
        nids::LinkLayerType::ethernet,
        nids::EthernetView{
            nids::ByteRange{0U, 14U},
            nids::MacAddress{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
            nids::MacAddress{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}},
            0x8100U,
        },
        nids::VlanView{nids::ByteRange{14U, 4U}, 100U, 0x0800U},
        nids::Ipv4View{
            nids::ByteRange{18U, 20U},
            nids::Ipv4Address{{0x0A, 0x00, 0x00, 0x01}},
            nids::Ipv4Address{{0x0A, 0x00, 0x00, 0x02}},
            63U,
            17U,
        },
        nids::UdpView{nids::ByteRange{38U, 8U}, 53U, 5'353U, 11U},
        nids::ByteRange{46U, 3U},
    };
}

void test_packet_input(TestContext& test) {
    const nids::PacketInput input{
        std::span{tcp_packet},
        1'499'428'779'599'128'000LL,
        nids::ClockDomain::unix_epoch,
        static_cast<std::uint32_t>(tcp_packet.size() + 12U),
        nids::LinkLayerType::ethernet,
    };

    EXPECT(test, input.captured_length() == tcp_packet.size());
    EXPECT(test, input.has_consistent_lengths());
    EXPECT(test, input.is_capture_truncated());
    EXPECT(test, input.timestamp_ns == 1'499'428'779'599'128'000LL);
    EXPECT(test, input.clock_domain == nids::ClockDomain::unix_epoch);
    EXPECT(test, input.link_layer == nids::LinkLayerType::ethernet);

    auto inconsistent = input;
    inconsistent.wire_length = static_cast<std::uint32_t>(tcp_packet.size() - 1U);
    EXPECT(test, !inconsistent.has_consistent_lengths());
}

void test_tcp_contract(TestContext& test) {
    const auto view = make_tcp_view();

    EXPECT(test, view.has_consistent_lengths());
    EXPECT(test, view.is_capture_truncated());
    EXPECT(test, view.has_valid_ranges());
    EXPECT(test, !view.vlan.has_value());
    EXPECT(test, view.ethernet.ether_type == read_be16(view.raw_bytes, 12U));
    EXPECT(test, (view.ethernet.destination == nids::MacAddress{{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}}));
    EXPECT(test, (view.ipv4.source == nids::Ipv4Address{{0xC0, 0xA8, 0x01, 0x0A}}));
    EXPECT(test, view.ipv4.header.length == 24U);
    const nids::ByteRange ipv4_options{34U, 4U};
    EXPECT(test, bytes_equal(
        ipv4_options.view(view.raw_bytes),
        std::array<std::uint8_t, 4>{0x01, 0x01, 0x00, 0x00}));
    EXPECT(test, std::holds_alternative<nids::TcpView>(view.transport));

    const auto& tcp = std::get<nids::TcpView>(view.transport);
    EXPECT(test, tcp.header.length == 24U);
    EXPECT(test, tcp.source_port == read_be16(view.raw_bytes, tcp.header.offset));
    EXPECT(test, tcp.destination_port == read_be16(view.raw_bytes, tcp.header.offset + 2U));
    EXPECT(test, tcp.sequence_number == read_be32(view.raw_bytes, tcp.header.offset + 4U));
    EXPECT(test, tcp.acknowledgement_number == read_be32(view.raw_bytes, tcp.header.offset + 8U));
    EXPECT(test, tcp.window_size == read_be16(view.raw_bytes, tcp.header.offset + 14U));
    EXPECT(test, tcp.flags.bits() == 0x011AU);
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::ns));
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::ack));
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::psh));
    EXPECT(test, tcp.flags.contains(nids::TcpFlag::syn));
    EXPECT(test, !tcp.flags.contains(nids::TcpFlag::rst));
    EXPECT(test, !nids::TcpFlags::from_bits(0x0200U).has_value());
    const nids::ByteRange tcp_options{58U, 4U};
    EXPECT(test, bytes_equal(
        tcp_options.view(view.raw_bytes),
        std::array<std::uint8_t, 4>{0x02, 0x04, 0x05, 0xB4}));
    EXPECT(test, bytes_equal(view.payload_bytes(), std::array<std::uint8_t, 2>{0xDE, 0xAD}));

    const nids::ByteRange invalid_range{view.raw_bytes.size(), 1U};
    EXPECT(test, !invalid_range.is_valid_for(view.raw_bytes));
    EXPECT(test, invalid_range.view(view.raw_bytes).empty());
}

void test_vlan_udp_contract(TestContext& test) {
    const auto view = make_vlan_udp_view();

    EXPECT(test, view.has_consistent_lengths());
    EXPECT(test, !view.is_capture_truncated());
    EXPECT(test, view.has_valid_ranges());
    EXPECT(test, view.clock_domain == nids::ClockDomain::monotonic);
    EXPECT(test, view.vlan.has_value());
    EXPECT(test, (view.vlan->header == nids::ByteRange{14U, 4U}));
    EXPECT(test, view.vlan->tag_control_information == 100U);
    EXPECT(test, view.vlan->inner_ether_type == 0x0800U);
    EXPECT(test, bytes_equal(view.vlan->header.view(view.raw_bytes), std::array<std::uint8_t, 4>{0x00, 0x64, 0x08, 0x00}));
    EXPECT(test, std::holds_alternative<nids::UdpView>(view.transport));

    const auto& udp = std::get<nids::UdpView>(view.transport);
    EXPECT(test, udp.source_port == read_be16(view.raw_bytes, udp.header.offset));
    EXPECT(test, udp.destination_port == read_be16(view.raw_bytes, udp.header.offset + 2U));
    EXPECT(test, udp.datagram_length == read_be16(view.raw_bytes, udp.header.offset + 4U));
    EXPECT(test, bytes_equal(view.payload_bytes(), std::array<std::uint8_t, 3>{0x01, 0x02, 0x03}));
}

void test_error_contract(TestContext& test) {
    const nids::ParseResult<nids::PacketView> truncated = nids::ParseError{
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::tcp,
        nids::ParseErrorCode::truncated_tcp_header,
        34U,
        12U,
        20U,
    };
    const nids::ParseResult<nids::PacketView> malformed = nids::ParseError{
        nids::ParseErrorKind::malformed,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::invalid_ipv4_header_length,
        14U,
        20U,
        20U,
    };
    const nids::ParseResult<nids::PacketView> unsupported = nids::ParseError{
        nids::ParseErrorKind::unsupported,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::fragmented_ipv4,
        20U,
        2U,
        0U,
    };
    const nids::ParseResult<nids::PacketView> truncated_packet = nids::ParseError{
        nids::ParseErrorKind::truncated,
        nids::ParseLayer::ipv4,
        nids::ParseErrorCode::truncated_ipv4_packet,
        14U,
        44U,
        50U,
    };

    EXPECT(test, std::holds_alternative<nids::ParseError>(truncated));
    const auto& error = std::get<nids::ParseError>(truncated);
    EXPECT(test, error.kind == nids::ParseErrorKind::truncated);
    EXPECT(test, error.layer == nids::ParseLayer::tcp);
    EXPECT(test, error.code == nids::ParseErrorCode::truncated_tcp_header);
    EXPECT(test, error.offset == 34U);
    EXPECT(test, error.available == 12U);
    EXPECT(test, error.required == 20U);
    EXPECT(test, std::get<nids::ParseError>(malformed).kind == nids::ParseErrorKind::malformed);
    EXPECT(test, std::get<nids::ParseError>(unsupported).kind == nids::ParseErrorKind::unsupported);
    const auto& truncated_ipv4 = std::get<nids::ParseError>(truncated_packet);
    EXPECT(test, truncated_ipv4.code == nids::ParseErrorCode::truncated_ipv4_packet);
}

}

int main() {
    static_assert(nids::TcpFlags::from_bits(nids::TcpFlags::valid_mask).has_value());
    static_assert(!nids::TcpFlags::from_bits(0x0200U).has_value());

    TestContext test;
    test_packet_input(test);
    test_tcp_contract(test);
    test_vlan_udp_contract(test);
    test_error_contract(test);
    return test.failure_count() == 0 ? 0 : 1;
}
