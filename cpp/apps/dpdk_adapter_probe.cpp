#include "nids/dpdk_adapter.hpp"

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_pdump.h>
#include <rte_ring.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

namespace {

void report_dpdk_failure(std::string_view stage, int result) {
    const auto error = rte_errno;
    std::cerr
        << "T2.5 probe failure: stage=" << stage
        << " return=" << result
        << " rte_errno=" << error
        << " message=" << rte_strerror(error) << '\n';
}

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

constexpr char ring_port_name[] = "t25_capture";
// rte_eth_from_rings prepends "net_ring_" into an RTE_RING_NAMESIZE buffer.
static_assert(sizeof("net_ring_") - 1U + sizeof(ring_port_name) <= RTE_RING_NAMESIZE);

struct Options {
    std::string file_prefix{};
    std::filesystem::path huge_dir{};
    std::filesystem::path ready_file{};
    std::filesystem::path arm_file{};
    std::filesystem::path result_file{};
    std::uint32_t max_packets{4U};
    bool verification_capture_enabled{false};
};

[[nodiscard]] bool parse_count(std::string_view text, std::uint32_t& value) {
    const auto* begin = text.data();
    const auto* end = begin + text.size();
    const auto [parsed_end, error] = std::from_chars(begin, end, value);
    return error == std::errc{} && parsed_end == end && value > 0U && value <= 128U;
}

[[nodiscard]] std::optional<Options> parse_options(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--enable-verification-capture") {
            options.verification_capture_enabled = true;
            continue;
        }
        if (index + 1 >= argc) {
            return std::nullopt;
        }
        const std::string_view value{argv[++index]};
        if (argument == "--file-prefix") {
            options.file_prefix = value;
        } else if (argument == "--huge-dir") {
            options.huge_dir = value;
        } else if (argument == "--ready-file") {
            options.ready_file = value;
        } else if (argument == "--arm-file") {
            options.arm_file = value;
        } else if (argument == "--result-file") {
            options.result_file = value;
        } else if (argument == "--max-packets") {
            if (!parse_count(value, options.max_packets)) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
    if (options.file_prefix.empty() || options.huge_dir.empty() || options.ready_file.empty()
        || options.arm_file.empty() || options.result_file.empty()) {
        return std::nullopt;
    }
    return options;
}

[[nodiscard]] bool write_ready(
    const std::filesystem::path& path,
    std::string_view interface_name,
    std::uint32_t max_packets,
    std::uint16_t rx_queues,
    std::uint16_t tx_queues) {
    std::ofstream output{path, std::ios::trunc};
    output << "{\"interface\":\"" << interface_name
           << "\",\"max_packets\":" << max_packets
           << ",\"rx_queues\":" << rx_queues
           << ",\"tx_queues\":" << tx_queues << "}\n";
    return output.good();
}

[[nodiscard]] bool write_result(
    const std::filesystem::path& path,
    std::uint32_t packets_sent,
    std::uint32_t packets_parsed,
    std::uint32_t parser_errors,
    std::uint32_t adapter_errors) {
    std::ofstream output{path, std::ios::trunc};
    output << "{\"packets_sent\":" << packets_sent
           << ",\"packets_parsed\":" << packets_parsed
           << ",\"parser_errors\":" << parser_errors
           << ",\"adapter_errors\":" << adapter_errors << "}\n";
    return output.good();
}

[[nodiscard]] bool wait_for_file(
    const std::filesystem::path& path,
    std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code error;
        if (std::filesystem::exists(path, error) && !error) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
}

class ProbeRuntime {
public:
    ~ProbeRuntime() {
        if (pdump_initialized) {
            rte_pdump_uninit();
        }
        if (port_started) {
            rte_eth_dev_stop(port_id);
        }
        if (port_created) {
            rte_eth_dev_close(port_id);
        }
        if (ring != nullptr) {
            void* object{};
            while (rte_ring_dequeue(ring, &object) == 0) {
                rte_pktmbuf_free(static_cast<rte_mbuf*>(object));
            }
            rte_ring_free(ring);
        }
        if (pool != nullptr) {
            rte_mempool_free(pool);
        }
        if (eal_initialized) {
            rte_eal_cleanup();
        }
    }

    bool eal_initialized{};
    bool port_created{};
    bool port_started{};
    bool pdump_initialized{};
    std::uint16_t port_id{};
    rte_mempool* pool{};
    rte_ring* ring{};
};

[[nodiscard]] bool initialize_eal(const Options& options) {
    std::vector<std::string> arguments{
        "nids_dpdk_adapter_probe",
        "-l", "0",
        "--proc-type=primary",
        "--no-pci",
        "--no-telemetry",
        "--log-level=*:warning",
        "-m", "64",
        "--huge-dir=" + options.huge_dir.string(),
        "--file-prefix=" + options.file_prefix,
    };
    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (auto& argument : arguments) {
        argv.push_back(argument.data());
    }
    const auto result = rte_eal_init(static_cast<int>(argv.size()), argv.data());
    if (result < 0) {
        report_dpdk_failure("eal_init", result);
        return false;
    }
    return true;
}

[[nodiscard]] bool start_ring_port(ProbeRuntime& runtime) {
    runtime.pool = rte_pktmbuf_pool_create(
        "nids_t25_capture_pool",
        1'024U,
        32U,
        0U,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (runtime.pool == nullptr) {
        report_dpdk_failure("mbuf_pool_create", -1);
        return false;
    }
    runtime.ring = rte_ring_create(
        "nids_t25_capture_rx",
        256U,
        rte_socket_id(),
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (runtime.ring == nullptr) {
        report_dpdk_failure("ring_create", -1);
        return false;
    }
    std::array<rte_ring*, 1> rings{runtime.ring};
    const auto port = rte_eth_from_rings(
        ring_port_name,
        rings.data(),
        static_cast<unsigned>(rings.size()),
        rings.data(),
        static_cast<unsigned>(rings.size()),
        rte_socket_id());
    if (port < 0) {
        report_dpdk_failure("eth_from_rings", port);
        return false;
    }
    runtime.port_id = static_cast<std::uint16_t>(port);
    runtime.port_created = true;

    rte_eth_conf configuration{};
    const auto configure_result = rte_eth_dev_configure(runtime.port_id, 1U, 1U, &configuration);
    if (configure_result != 0) {
        report_dpdk_failure("eth_dev_configure", configure_result);
        return false;
    }
    const auto rx_queue_result = rte_eth_rx_queue_setup(
        runtime.port_id,
        0U,
        128U,
        rte_eth_dev_socket_id(runtime.port_id),
        nullptr,
        runtime.pool);
    if (rx_queue_result != 0) {
        report_dpdk_failure("eth_rx_queue_setup", rx_queue_result);
        return false;
    }
    const auto tx_queue_result = rte_eth_tx_queue_setup(
        runtime.port_id,
        0U,
        128U,
        rte_eth_dev_socket_id(runtime.port_id),
        nullptr);
    if (tx_queue_result != 0) {
        report_dpdk_failure("eth_tx_queue_setup", tx_queue_result);
        return false;
    }
    const auto start_result = rte_eth_dev_start(runtime.port_id);
    if (start_result != 0) {
        report_dpdk_failure("eth_dev_start", start_result);
        return false;
    }
    runtime.port_started = true;
    return true;
}

[[nodiscard]] bool enqueue_packets(ProbeRuntime& runtime, std::uint32_t count) {
    for (std::uint32_t index = 0; index < count; ++index) {
        auto* mbuf = rte_pktmbuf_alloc(runtime.pool);
        if (mbuf == nullptr) {
            report_dpdk_failure("pktmbuf_alloc", -1);
            return false;
        }
        auto* destination = rte_pktmbuf_append(
            mbuf,
            static_cast<std::uint16_t>(tcp_packet.size()));
        if (destination == nullptr) {
            report_dpdk_failure("pktmbuf_append", -1);
            rte_pktmbuf_free(mbuf);
            return false;
        }
        std::memcpy(destination, tcp_packet.data(), tcp_packet.size());
        reinterpret_cast<std::uint8_t*>(destination)[tcp_packet.size() - 1U]
            = static_cast<std::uint8_t>(tcp_packet.back() + index);
        const auto enqueue_result = rte_ring_enqueue(runtime.ring, mbuf);
        if (enqueue_result != 0) {
            report_dpdk_failure("ring_enqueue", enqueue_result);
            rte_pktmbuf_free(mbuf);
            return false;
        }
    }
    return true;
}

struct ProcessingSummary {
    std::uint32_t packets_seen{};
    std::uint32_t packets_parsed{};
    std::uint32_t parser_errors{};
    std::uint32_t adapter_errors{};
};

[[nodiscard]] ProcessingSummary process_packets(
    ProbeRuntime& runtime,
    std::uint32_t expected_count) {
    ProcessingSummary summary;
    std::array<std::uint8_t, 65'535> scratch{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (summary.packets_seen < expected_count
        && std::chrono::steady_clock::now() < deadline) {
        std::array<rte_mbuf*, 16> received{};
        const auto count = rte_eth_rx_burst(
            runtime.port_id,
            0U,
            received.data(),
            static_cast<std::uint16_t>(received.size()));
        if (count == 0U) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        for (std::uint16_t index = 0; index < count; ++index) {
            const auto timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            const auto adapted = nids::adapt_mbuf(
                *received[index],
                timestamp_ns,
                nids::ClockDomain::monotonic,
                scratch);
            if (std::holds_alternative<nids::DpdkAdapterError>(adapted)) {
                ++summary.adapter_errors;
            } else if (std::holds_alternative<nids::PacketView>(
                           std::get<nids::DpdkPacketEvent>(adapted).parsed)) {
                ++summary.packets_parsed;
            } else {
                ++summary.parser_errors;
            }
            ++summary.packets_seen;
            rte_pktmbuf_free(received[index]);
        }
    }
    return summary;
}

}

int main(int argc, char** argv) {
    const auto parsed_options = parse_options(argc, argv);
    if (!parsed_options.has_value()) {
        std::cerr
            << "usage: nids_dpdk_adapter_probe --file-prefix PREFIX"
            << " --huge-dir PATH"
            << " --ready-file PATH --arm-file PATH --result-file PATH"
            << " [--max-packets 1..128] --enable-verification-capture\n";
        return 2;
    }
    const auto& options = *parsed_options;
    if (!options.verification_capture_enabled) {
        std::cerr << "verification capture is disabled by default\n";
        return 2;
    }

    ProbeRuntime runtime;
    runtime.eal_initialized = initialize_eal(options);
    if (!runtime.eal_initialized || !start_ring_port(runtime)) {
        std::cerr << "failed to initialize the bounded DPDK ring probe\n";
        return 1;
    }
    const auto pdump_result = rte_pdump_init();
    if (pdump_result != 0) {
        report_dpdk_failure("pdump_init", pdump_result);
        return 1;
    }
    runtime.pdump_initialized = true;

    std::array<char, RTE_ETH_NAME_MAX_LEN> interface_name{};
    const auto name_result = rte_eth_dev_get_name_by_port(runtime.port_id, interface_name.data());
    if (name_result != 0) {
        report_dpdk_failure("eth_dev_get_name_by_port", name_result);
        return 1;
    }
    rte_eth_dev_info device_info{};
    const auto info_result = rte_eth_dev_info_get(runtime.port_id, &device_info);
    if (info_result != 0) {
        report_dpdk_failure("eth_dev_info_get", info_result);
        return 1;
    }
    if (!write_ready(
            options.ready_file,
            interface_name.data(),
            options.max_packets,
            device_info.nb_rx_queues,
            device_info.nb_tx_queues)) {
        std::cerr << "failed to publish probe readiness\n";
        return 1;
    }
    if (!wait_for_file(options.arm_file, std::chrono::seconds{10})) {
        std::cerr << "timed out waiting for capture arm file\n";
        return 1;
    }
    if (!enqueue_packets(runtime, options.max_packets)) {
        std::cerr << "failed to enqueue synthetic packets\n";
        return 1;
    }

    const auto summary = process_packets(runtime, options.max_packets);
    const bool complete = summary.packets_seen == options.max_packets
        && summary.packets_parsed == options.max_packets
        && summary.parser_errors == 0U && summary.adapter_errors == 0U;
    if (!write_result(
            options.result_file,
            summary.packets_seen,
            summary.packets_parsed,
            summary.parser_errors,
            summary.adapter_errors)) {
        std::cerr << "failed to write probe result\n";
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds{2});
    if (!complete) {
        std::cerr << "bounded packet processing did not complete\n";
        return 1;
    }
    std::cout
        << "T2.5 probe: verification_capture=1 pdump_initialized=1 bounded=1"
        << " packets_seen=" << summary.packets_seen
        << " packets_parsed=" << summary.packets_parsed
        << " parser_errors=" << summary.parser_errors
        << " adapter_errors=" << summary.adapter_errors << '\n';
    return 0;
}
