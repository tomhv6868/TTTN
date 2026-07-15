#include "nids/dpdk_adapter.hpp"

#include <rte_mbuf.h>

#include <cstddef>
#include <cstdint>

namespace nids {

DpdkAdapterResult adapt_mbuf(
    const rte_mbuf& mbuf,
    std::int64_t timestamp_ns,
    ClockDomain clock_domain,
    std::span<std::uint8_t> scratch) noexcept {
    const auto packet_length = rte_pktmbuf_pkt_len(&mbuf);
    const std::uint8_t* packet_data{};
    bool copied_from_segments{};

    if (rte_pktmbuf_is_contiguous(&mbuf)) {
        if (packet_length > rte_pktmbuf_data_len(&mbuf)) {
            return DpdkAdapterError{
                .code = DpdkAdapterErrorCode::invalid_mbuf_chain,
                .packet_length = packet_length,
                .scratch_available = scratch.size(),
                .scratch_required = packet_length,
            };
        }
        packet_data = rte_pktmbuf_mtod(&mbuf, const std::uint8_t*);
    } else {
        if (scratch.size() < packet_length) {
            return DpdkAdapterError{
                .code = DpdkAdapterErrorCode::scratch_buffer_too_small,
                .packet_length = packet_length,
                .scratch_available = scratch.size(),
                .scratch_required = packet_length,
            };
        }
        packet_data = static_cast<const std::uint8_t*>(
            rte_pktmbuf_read(&mbuf, 0U, packet_length, scratch.data()));
        if (packet_data == nullptr) {
            return DpdkAdapterError{
                .code = DpdkAdapterErrorCode::invalid_mbuf_chain,
                .packet_length = packet_length,
                .scratch_available = scratch.size(),
                .scratch_required = packet_length,
            };
        }
        copied_from_segments = true;
    }

    const PacketInput input{
        .raw_bytes = {packet_data, packet_length},
        .timestamp_ns = timestamp_ns,
        .clock_domain = clock_domain,
        .wire_length = packet_length,
        .link_layer = LinkLayerType::ethernet,
    };
    return DpdkPacketEvent{
        .input = input,
        .parsed = parse_packet(input),
        .copied_from_segments = copied_from_segments,
    };
}

}
