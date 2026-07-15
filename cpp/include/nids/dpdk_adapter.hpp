#pragma once

#include "nids/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

struct rte_mbuf;

namespace nids {

enum class DpdkAdapterErrorCode : std::uint8_t {
    scratch_buffer_too_small,
    invalid_mbuf_chain,
};

struct DpdkAdapterError {
    DpdkAdapterErrorCode code{};
    std::uint32_t packet_length{};
    std::size_t scratch_available{};
    std::size_t scratch_required{};
};

struct DpdkPacketEvent {
    PacketInput input{};
    ParseResult<PacketView> parsed{};
    bool copied_from_segments{};
};

using DpdkAdapterResult = std::variant<DpdkPacketEvent, DpdkAdapterError>;

// Packet-backed spans remain valid only while the mbuf or supplied scratch storage is unchanged.
[[nodiscard]] DpdkAdapterResult adapt_mbuf(
    const rte_mbuf& mbuf,
    std::int64_t timestamp_ns,
    ClockDomain clock_domain,
    std::span<std::uint8_t> scratch) noexcept;

}
