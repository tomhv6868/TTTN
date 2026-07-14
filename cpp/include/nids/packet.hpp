#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>

namespace nids {

using PacketBytes = std::span<const std::uint8_t>;

enum class ClockDomain : std::uint8_t {
    unix_epoch,
    monotonic,
};

enum class LinkLayerType : std::uint16_t {
    ethernet = 1,
};

struct ByteRange {
    std::size_t offset{};
    std::size_t length{};

    friend constexpr bool operator==(const ByteRange&, const ByteRange&) noexcept = default;

    [[nodiscard]] constexpr bool is_valid_for(std::size_t extent) const noexcept {
        return offset <= extent && length <= extent - offset;
    }

    [[nodiscard]] constexpr bool is_valid_for(PacketBytes bytes) const noexcept {
        return is_valid_for(bytes.size());
    }

    [[nodiscard]] constexpr PacketBytes view(PacketBytes bytes) const noexcept {
        if (!is_valid_for(bytes)) {
            return {};
        }
        return bytes.subspan(offset, length);
    }
};

struct PacketInput {
    PacketBytes raw_bytes{};
    std::int64_t timestamp_ns{};
    ClockDomain clock_domain{ClockDomain::unix_epoch};
    std::uint32_t wire_length{};
    LinkLayerType link_layer{LinkLayerType::ethernet};

    [[nodiscard]] constexpr std::size_t captured_length() const noexcept {
        return raw_bytes.size();
    }

    [[nodiscard]] constexpr bool has_consistent_lengths() const noexcept {
        return captured_length() <= static_cast<std::size_t>(wire_length);
    }

    [[nodiscard]] constexpr bool is_capture_truncated() const noexcept {
        return captured_length() < static_cast<std::size_t>(wire_length);
    }
};

struct MacAddress {
    std::array<std::uint8_t, 6> wire_bytes{};

    friend constexpr bool operator==(const MacAddress&, const MacAddress&) noexcept = default;
};

struct Ipv4Address {
    std::array<std::uint8_t, 4> wire_bytes{};

    friend constexpr bool operator==(const Ipv4Address&, const Ipv4Address&) noexcept = default;
};

struct EthernetView {
    ByteRange header{};
    MacAddress destination{};
    MacAddress source{};
    std::uint16_t ether_type{};
};

struct VlanView {
    ByteRange header{};
    std::uint16_t tag_control_information{};
    std::uint16_t inner_ether_type{};
};

struct Ipv4View {
    ByteRange header{};
    Ipv4Address source{};
    Ipv4Address destination{};
    std::uint8_t ttl{};
    std::uint8_t protocol{};
};

enum class TcpFlag : std::uint16_t {
    fin = 1U << 0U,
    syn = 1U << 1U,
    rst = 1U << 2U,
    psh = 1U << 3U,
    ack = 1U << 4U,
    urg = 1U << 5U,
    ece = 1U << 6U,
    cwr = 1U << 7U,
    ns = 1U << 8U,
};

class TcpFlags {
public:
    static constexpr std::uint16_t valid_mask = 0x01FFU;

    constexpr TcpFlags() noexcept = default;

    [[nodiscard]] static constexpr std::optional<TcpFlags> from_bits(std::uint16_t bits) noexcept {
        if ((bits & static_cast<std::uint16_t>(~valid_mask)) != 0U) {
            return std::nullopt;
        }
        return TcpFlags{bits};
    }

    [[nodiscard]] constexpr std::uint16_t bits() const noexcept {
        return bits_;
    }

    [[nodiscard]] constexpr bool contains(TcpFlag flag) const noexcept {
        return (bits_ & static_cast<std::uint16_t>(flag)) != 0U;
    }

    friend constexpr bool operator==(TcpFlags, TcpFlags) noexcept = default;

private:
    explicit constexpr TcpFlags(std::uint16_t bits) noexcept : bits_{bits} {}

    std::uint16_t bits_{};
};

struct TcpView {
    ByteRange header{};
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    std::uint32_t sequence_number{};
    std::uint32_t acknowledgement_number{};
    std::uint16_t window_size{};
    TcpFlags flags{};
};

struct UdpView {
    ByteRange header{};
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    std::uint16_t datagram_length{};
};

using TransportView = std::variant<TcpView, UdpView>;

struct PacketView {
    PacketBytes raw_bytes{};
    std::int64_t timestamp_ns{};
    ClockDomain clock_domain{ClockDomain::unix_epoch};
    std::uint32_t wire_length{};
    LinkLayerType link_layer{LinkLayerType::ethernet};
    EthernetView ethernet{};
    std::optional<VlanView> vlan{};
    Ipv4View ipv4{};
    TransportView transport{};
    ByteRange payload{};

    [[nodiscard]] constexpr std::size_t captured_length() const noexcept {
        return raw_bytes.size();
    }

    [[nodiscard]] constexpr bool has_consistent_lengths() const noexcept {
        return captured_length() <= static_cast<std::size_t>(wire_length);
    }

    [[nodiscard]] constexpr bool is_capture_truncated() const noexcept {
        return captured_length() < static_cast<std::size_t>(wire_length);
    }

    [[nodiscard]] constexpr bool has_valid_ranges() const noexcept {
        const auto transport_range_is_valid = [this](const auto& value) {
            return value.header.is_valid_for(raw_bytes);
        };

        return ethernet.header.is_valid_for(raw_bytes)
            && (!vlan.has_value() || vlan->header.is_valid_for(raw_bytes))
            && ipv4.header.is_valid_for(raw_bytes)
            && std::visit(transport_range_is_valid, transport)
            && payload.is_valid_for(raw_bytes);
    }

    [[nodiscard]] constexpr PacketBytes payload_bytes() const noexcept {
        return payload.view(raw_bytes);
    }
};

enum class ParseErrorKind : std::uint8_t {
    truncated,
    malformed,
    unsupported,
};

enum class ParseLayer : std::uint8_t {
    packet_input,
    ethernet,
    vlan,
    ipv4,
    tcp,
    udp,
};

enum class ParseErrorCode : std::uint8_t {
    inconsistent_lengths,
    unsupported_link_layer,
    truncated_ethernet_header,
    unsupported_ether_type,
    truncated_vlan_header,
    nested_vlan,
    truncated_ipv4_header,
    invalid_ipv4_version,
    invalid_ipv4_header_length,
    truncated_ipv4_packet,
    invalid_ipv4_total_length,
    fragmented_ipv4,
    unsupported_transport_protocol,
    truncated_tcp_header,
    invalid_tcp_header_length,
    truncated_udp_header,
    invalid_udp_length,
};

struct ParseError {
    ParseErrorKind kind{};
    ParseLayer layer{};
    ParseErrorCode code{};
    std::size_t offset{};
    std::size_t available{};
    std::size_t required{};
};

template <typename T>
using ParseResult = std::variant<T, ParseError>;

[[nodiscard]] ParseResult<PacketView> parse_packet(PacketInput input) noexcept;

}
