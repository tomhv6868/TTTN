#include "nids/packet.hpp"

#include <cstddef>
#include <cstdint>

namespace nids {
namespace {

constexpr std::size_t ethernet_header_length = 14U;
constexpr std::size_t vlan_header_length = 4U;
constexpr std::size_t ipv4_minimum_header_length = 20U;
constexpr std::size_t tcp_minimum_header_length = 20U;
constexpr std::size_t udp_header_length = 8U;

constexpr std::uint16_t ether_type_ipv4 = 0x0800U;
constexpr std::uint16_t ether_type_vlan = 0x8100U;
constexpr std::uint16_t ether_type_service_vlan = 0x88A8U;
constexpr std::uint16_t ether_type_alternate_vlan = 0x9100U;
constexpr std::uint8_t protocol_tcp = 6U;
constexpr std::uint8_t protocol_udp = 17U;

[[nodiscard]] constexpr std::size_t available_from(PacketBytes bytes, std::size_t offset) noexcept {
    return offset <= bytes.size() ? bytes.size() - offset : 0U;
}

[[nodiscard]] constexpr std::uint16_t read_be16(PacketBytes bytes, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U)
        | static_cast<std::uint16_t>(bytes[offset + 1U]));
}

[[nodiscard]] constexpr std::uint32_t read_be32(PacketBytes bytes, std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U)
        | (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U)
        | (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U)
        | static_cast<std::uint32_t>(bytes[offset + 3U]);
}

[[nodiscard]] constexpr bool is_vlan(std::uint16_t ether_type) noexcept {
    return ether_type == ether_type_vlan
        || ether_type == ether_type_service_vlan
        || ether_type == ether_type_alternate_vlan;
}

[[nodiscard]] constexpr ParseError error(
    ParseErrorKind kind,
    ParseLayer layer,
    ParseErrorCode code,
    std::size_t offset,
    std::size_t available,
    std::size_t required) noexcept {
    return ParseError{kind, layer, code, offset, available, required};
}

[[nodiscard]] constexpr MacAddress read_mac(PacketBytes bytes, std::size_t offset) noexcept {
    return MacAddress{{
        bytes[offset],
        bytes[offset + 1U],
        bytes[offset + 2U],
        bytes[offset + 3U],
        bytes[offset + 4U],
        bytes[offset + 5U],
    }};
}

[[nodiscard]] constexpr Ipv4Address read_ipv4(PacketBytes bytes, std::size_t offset) noexcept {
    return Ipv4Address{{
        bytes[offset],
        bytes[offset + 1U],
        bytes[offset + 2U],
        bytes[offset + 3U],
    }};
}

}

ParseResult<PacketView> parse_packet(PacketInput input) noexcept {
    const PacketBytes bytes = input.raw_bytes;
    if (!input.has_consistent_lengths()) {
        return error(
            ParseErrorKind::malformed,
            ParseLayer::packet_input,
            ParseErrorCode::inconsistent_lengths,
            0U,
            input.wire_length,
            input.captured_length());
    }
    if (input.link_layer != LinkLayerType::ethernet) {
        return error(
            ParseErrorKind::unsupported,
            ParseLayer::packet_input,
            ParseErrorCode::unsupported_link_layer,
            0U,
            0U,
            0U);
    }
    if (bytes.size() < ethernet_header_length) {
        return error(
            ParseErrorKind::truncated,
            ParseLayer::ethernet,
            ParseErrorCode::truncated_ethernet_header,
            0U,
            bytes.size(),
            ethernet_header_length);
    }

    const std::uint16_t outer_ether_type = read_be16(bytes, 12U);
    const EthernetView ethernet{
        ByteRange{0U, ethernet_header_length},
        read_mac(bytes, 0U),
        read_mac(bytes, 6U),
        outer_ether_type,
    };

    std::size_t network_offset = ethernet_header_length;
    std::size_t ether_type_offset = 12U;
    std::uint16_t inner_ether_type = outer_ether_type;
    std::optional<VlanView> vlan;
    if (is_vlan(outer_ether_type)) {
        const std::size_t available = available_from(bytes, network_offset);
        if (available < vlan_header_length) {
            return error(
                ParseErrorKind::truncated,
                ParseLayer::vlan,
                ParseErrorCode::truncated_vlan_header,
                network_offset,
                available,
                vlan_header_length);
        }
        inner_ether_type = read_be16(bytes, network_offset + 2U);
        vlan = VlanView{
            ByteRange{network_offset, vlan_header_length},
            read_be16(bytes, network_offset),
            inner_ether_type,
        };
        ether_type_offset = network_offset + 2U;
        network_offset += vlan_header_length;
        if (is_vlan(inner_ether_type)) {
            return error(
                ParseErrorKind::unsupported,
                ParseLayer::vlan,
                ParseErrorCode::nested_vlan,
                ether_type_offset,
                2U,
                0U);
        }
    }

    if (inner_ether_type != ether_type_ipv4) {
        return error(
            ParseErrorKind::unsupported,
            vlan.has_value() ? ParseLayer::vlan : ParseLayer::ethernet,
            ParseErrorCode::unsupported_ether_type,
            ether_type_offset,
            2U,
            0U);
    }

    const std::size_t captured_ipv4_length = available_from(bytes, network_offset);
    if (captured_ipv4_length < ipv4_minimum_header_length) {
        return error(
            ParseErrorKind::truncated,
            ParseLayer::ipv4,
            ParseErrorCode::truncated_ipv4_header,
            network_offset,
            captured_ipv4_length,
            ipv4_minimum_header_length);
    }

    const std::uint8_t version_and_ihl = bytes[network_offset];
    if ((version_and_ihl >> 4U) != 4U) {
        return error(
            ParseErrorKind::malformed,
            ParseLayer::ipv4,
            ParseErrorCode::invalid_ipv4_version,
            network_offset,
            1U,
            1U);
    }

    const std::size_t ipv4_header_length = static_cast<std::size_t>(version_and_ihl & 0x0FU) * 4U;
    if (ipv4_header_length < ipv4_minimum_header_length) {
        return error(
            ParseErrorKind::malformed,
            ParseLayer::ipv4,
            ParseErrorCode::invalid_ipv4_header_length,
            network_offset,
            ipv4_header_length,
            ipv4_minimum_header_length);
    }
    if (captured_ipv4_length < ipv4_header_length) {
        return error(
            ParseErrorKind::truncated,
            ParseLayer::ipv4,
            ParseErrorCode::truncated_ipv4_header,
            network_offset,
            captured_ipv4_length,
            ipv4_header_length);
    }

    const std::size_t ipv4_total_length = read_be16(bytes, network_offset + 2U);
    if (ipv4_total_length < ipv4_header_length) {
        return error(
            ParseErrorKind::malformed,
            ParseLayer::ipv4,
            ParseErrorCode::invalid_ipv4_total_length,
            network_offset + 2U,
            ipv4_total_length,
            ipv4_header_length);
    }
    if (captured_ipv4_length < ipv4_total_length) {
        return error(
            ParseErrorKind::truncated,
            ParseLayer::ipv4,
            ParseErrorCode::truncated_ipv4_packet,
            network_offset,
            captured_ipv4_length,
            ipv4_total_length);
    }

    const std::uint16_t fragment_field = read_be16(bytes, network_offset + 6U);
    if ((fragment_field & 0x3FFFU) != 0U) {
        return error(
            ParseErrorKind::unsupported,
            ParseLayer::ipv4,
            ParseErrorCode::fragmented_ipv4,
            network_offset + 6U,
            2U,
            0U);
    }

    const std::uint8_t protocol = bytes[network_offset + 9U];
    const Ipv4View ipv4{
        ByteRange{network_offset, ipv4_header_length},
        read_ipv4(bytes, network_offset + 12U),
        read_ipv4(bytes, network_offset + 16U),
        bytes[network_offset + 8U],
        protocol,
    };

    const std::size_t transport_offset = network_offset + ipv4_header_length;
    const std::size_t transport_length = ipv4_total_length - ipv4_header_length;
    TransportView transport;
    ByteRange payload;

    if (protocol == protocol_tcp) {
        if (transport_length < tcp_minimum_header_length) {
            return error(
                ParseErrorKind::truncated,
                ParseLayer::tcp,
                ParseErrorCode::truncated_tcp_header,
                transport_offset,
                transport_length,
                tcp_minimum_header_length);
        }

        const std::size_t tcp_header_length = static_cast<std::size_t>(bytes[transport_offset + 12U] >> 4U) * 4U;
        if (tcp_header_length < tcp_minimum_header_length) {
            return error(
                ParseErrorKind::malformed,
                ParseLayer::tcp,
                ParseErrorCode::invalid_tcp_header_length,
                transport_offset + 12U,
                tcp_header_length,
                tcp_minimum_header_length);
        }
        if (transport_length < tcp_header_length) {
            return error(
                ParseErrorKind::malformed,
                ParseLayer::tcp,
                ParseErrorCode::invalid_tcp_header_length,
                transport_offset + 12U,
                transport_length,
                tcp_header_length);
        }

        const std::uint16_t flag_bits = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[transport_offset + 12U] & 0x01U) << 8U)
            | bytes[transport_offset + 13U]);
        const TcpFlags flags = *TcpFlags::from_bits(flag_bits);

        transport = TcpView{
            ByteRange{transport_offset, tcp_header_length},
            read_be16(bytes, transport_offset),
            read_be16(bytes, transport_offset + 2U),
            read_be32(bytes, transport_offset + 4U),
            read_be32(bytes, transport_offset + 8U),
            read_be16(bytes, transport_offset + 14U),
            flags,
        };
        payload = ByteRange{
            transport_offset + tcp_header_length,
            transport_length - tcp_header_length,
        };
    } else if (protocol == protocol_udp) {
        if (transport_length < udp_header_length) {
            return error(
                ParseErrorKind::truncated,
                ParseLayer::udp,
                ParseErrorCode::truncated_udp_header,
                transport_offset,
                transport_length,
                udp_header_length);
        }

        const std::size_t udp_length = read_be16(bytes, transport_offset + 4U);
        if (udp_length < udp_header_length) {
            return error(
                ParseErrorKind::malformed,
                ParseLayer::udp,
                ParseErrorCode::invalid_udp_length,
                transport_offset + 4U,
                udp_length,
                udp_header_length);
        }
        if (udp_length > transport_length) {
            return error(
                ParseErrorKind::malformed,
                ParseLayer::udp,
                ParseErrorCode::invalid_udp_length,
                transport_offset + 4U,
                transport_length,
                udp_length);
        }

        transport = UdpView{
            ByteRange{transport_offset, udp_header_length},
            read_be16(bytes, transport_offset),
            read_be16(bytes, transport_offset + 2U),
            static_cast<std::uint16_t>(udp_length),
        };
        payload = ByteRange{
            transport_offset + udp_header_length,
            udp_length - udp_header_length,
        };
    } else {
        return error(
            ParseErrorKind::unsupported,
            ParseLayer::ipv4,
            ParseErrorCode::unsupported_transport_protocol,
            network_offset + 9U,
            1U,
            0U);
    }

    return PacketView{
        bytes,
        input.timestamp_ns,
        input.clock_domain,
        input.wire_length,
        input.link_layer,
        ethernet,
        vlan,
        ipv4,
        transport,
        payload,
    };
}

}
