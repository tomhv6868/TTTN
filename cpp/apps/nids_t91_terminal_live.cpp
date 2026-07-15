#include "nids/dpdk_adapter.hpp"
#include "nids/flow_table.hpp"
#include "nids/latency_samples.hpp"
#include "nids/terminal_feature.hpp"
#include "nids/terminal_model_runtime.hpp"

#include <jansson.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>

namespace {

constexpr std::uint32_t live_mbuf_pool_capacity{2'047U};
constexpr std::uint32_t live_flow_limit{2'048U};
constexpr std::uint64_t live_decision_event_hard_limit{4'096U};
constexpr std::chrono::milliseconds bounded_shutdown_grace{250};
constexpr std::string_view feature_schema_id{
    "nids.terminal_flow_features.v1"};
constexpr std::string_view task_id{"T9.1"};
constexpr std::string_view schema_version{"1.0.0"};

enum class OutputMode {
    diagnostic,
    alerts_only,
};

enum class LifecycleMode {
    bounded,
    signal_only,
};

[[nodiscard]] constexpr std::string_view lifecycle_mode_name(
    LifecycleMode mode) noexcept {
    return mode == LifecycleMode::bounded
        ? "bounded"
        : "signal_only";
}

[[nodiscard]] constexpr std::string_view output_mode_name(
    OutputMode mode) noexcept {
    return mode == OutputMode::diagnostic
        ? "diagnostic"
        : "alerts_only";
}

[[nodiscard]] constexpr std::string_view decision_event_policy(
    OutputMode mode) noexcept {
    return mode == OutputMode::diagnostic
        ? "fail_closed_no_sampling"
        : "disabled_alerts_only";
}

volatile std::sig_atomic_t stop_requested{};

extern "C" void request_stop(int) {
    stop_requested = 1;
}

using JsonDocument = std::unique_ptr<json_t, decltype(&json_decref)>;

[[nodiscard]] JsonDocument json_object_document() {
    auto* const value = json_object();
    if (value == nullptr) {
        throw std::bad_alloc{};
    }
    return JsonDocument{value, &json_decref};
}

[[nodiscard]] JsonDocument json_array_document() {
    auto* const value = json_array();
    if (value == nullptr) {
        throw std::bad_alloc{};
    }
    return JsonDocument{value, &json_decref};
}

[[nodiscard]] json_t* checked_json(json_t* value) {
    if (value == nullptr) {
        throw std::bad_alloc{};
    }
    return value;
}

void set_json(json_t* object, const char* name, json_t* value) {
    if (value == nullptr || json_object_set_new(object, name, value) != 0) {
        throw std::bad_alloc{};
    }
}

void append_json(json_t* array, json_t* value) {
    if (value == nullptr || json_array_append_new(array, value) != 0) {
        throw std::bad_alloc{};
    }
}

void set_string(json_t* object, const char* name, std::string_view value) {
    const auto copy = std::string{value};
    set_json(object, name, checked_json(json_string(copy.c_str())));
}

void set_bool(json_t* object, const char* name, bool value) {
    set_json(object, name, json_boolean(value));
}

void set_i64(json_t* object, const char* name, std::int64_t value) {
    set_json(
        object,
        name,
        checked_json(json_integer(static_cast<json_int_t>(value))));
}

void set_u64(json_t* object, const char* name, std::uint64_t value) {
    if (value > static_cast<std::uint64_t>(
            std::numeric_limits<json_int_t>::max())) {
        throw std::overflow_error{"JSON integer overflow"};
    }
    set_i64(object, name, static_cast<std::int64_t>(value));
}

void set_real(json_t* object, const char* name, double value) {
    set_json(object, name, checked_json(json_real(value)));
}

[[nodiscard]] bool write_json_line(
    std::ostream& output,
    const JsonDocument& document) {
    constexpr std::size_t flags =
        JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII;
    std::unique_ptr<char, decltype(&std::free)> encoded{
        json_dumps(document.get(), flags),
        &std::free,
    };
    if (!encoded) {
        return false;
    }
    output << encoded.get() << '\n' << std::flush;
    return output.good();
}

[[nodiscard]] std::optional<std::uint64_t> parse_unsigned(
    std::string_view value) noexcept {
    std::uint64_t result{};
    const auto parsed = std::from_chars(
        value.data(),
        value.data() + value.size(),
        result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return result;
}

[[nodiscard]] bool valid_sha256(std::string_view value) noexcept {
    if (value.size() != 64U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f');
    });
}

[[nodiscard]] bool valid_token(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character == '.' || character == '_' || character == '-';
    });
}

[[nodiscard]] std::optional<nids::Ipv4Address> parse_ipv4(
    std::string_view value) noexcept {
    nids::Ipv4Address result{};
    std::size_t cursor{};
    for (std::size_t index = 0; index < result.wire_bytes.size(); ++index) {
        const auto separator = value.find('.', cursor);
        const auto end = index + 1U == result.wire_bytes.size()
            ? value.size()
            : separator;
        if (end == std::string_view::npos || end == cursor
            || (index + 1U != result.wire_bytes.size()
                && separator == std::string_view::npos)) {
            return std::nullopt;
        }
        std::uint16_t octet{};
        const auto parsed = std::from_chars(
            value.data() + cursor,
            value.data() + end,
            octet);
        if (parsed.ec != std::errc{}
            || parsed.ptr != value.data() + end
            || octet > std::numeric_limits<std::uint8_t>::max()) {
            return std::nullopt;
        }
        result.wire_bytes[index] = static_cast<std::uint8_t>(octet);
        cursor = end + 1U;
    }
    if (cursor != value.size() + 1U) {
        return std::nullopt;
    }
    return result;
}

[[nodiscard]] std::string ipv4_string(const nids::Ipv4Address& address) {
    std::string result;
    for (std::size_t index = 0; index < address.wire_bytes.size(); ++index) {
        if (index != 0U) {
            result.push_back('.');
        }
        result += std::to_string(address.wire_bytes[index]);
    }
    return result;
}

enum class RawPacketScope : std::uint8_t {
    scoped,
    ambient,
    unknown,
};

[[nodiscard]] constexpr std::uint16_t read_be16(
    nids::PacketBytes bytes,
    std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U)
        | static_cast<std::uint16_t>(bytes[offset + 1U]));
}

[[nodiscard]] constexpr bool is_vlan(std::uint16_t ether_type) noexcept {
    return ether_type == 0x8100U
        || ether_type == 0x88A8U
        || ether_type == 0x9100U;
}

[[nodiscard]] RawPacketScope classify_raw_scope(
    nids::PacketBytes bytes,
    const nids::Ipv4Address& first,
    const nids::Ipv4Address& second,
    bool any_source) noexcept {
    constexpr std::size_t ethernet_header_length{14U};
    constexpr std::size_t vlan_header_length{4U};
    constexpr std::size_t ipv4_minimum_header_length{20U};
    constexpr std::uint16_t ether_type_ipv4{0x0800U};

    if (bytes.size() < ethernet_header_length) {
        return RawPacketScope::unknown;
    }
    auto ether_type = read_be16(bytes, 12U);
    std::size_t network_offset{ethernet_header_length};
    while (is_vlan(ether_type)) {
        if (bytes.size() - network_offset < vlan_header_length) {
            return RawPacketScope::unknown;
        }
        ether_type = read_be16(bytes, network_offset + 2U);
        network_offset += vlan_header_length;
    }
    if (ether_type != ether_type_ipv4) {
        return RawPacketScope::ambient;
    }
    if (bytes.size() - network_offset < ipv4_minimum_header_length
        || (bytes[network_offset] >> 4U) != 4U) {
        return RawPacketScope::unknown;
    }

    nids::Ipv4Address source{};
    nids::Ipv4Address destination{};
    std::copy_n(
        bytes.begin() + static_cast<std::ptrdiff_t>(network_offset + 12U),
        source.wire_bytes.size(),
        source.wire_bytes.begin());
    std::copy_n(
        bytes.begin() + static_cast<std::ptrdiff_t>(network_offset + 16U),
        destination.wire_bytes.size(),
        destination.wire_bytes.begin());
    const auto scoped = any_source
        ? source == second || destination == second
        : (source == first && destination == second)
            || (source == second && destination == first);
    return scoped ? RawPacketScope::scoped : RawPacketScope::ambient;
}

struct Arguments {
    std::filesystem::path bundle{};
    std::string manifest_sha256{};
    nids::Ipv4Address source_ip{};
    nids::Ipv4Address target_ip{};
    std::string source_ip_text{};
    std::string target_ip_text{};
    bool any_source{};
    OutputMode output_mode{OutputMode::diagnostic};
    LifecycleMode lifecycle_mode{LifecycleMode::bounded};
    std::optional<std::filesystem::path> alerts_file{};
    std::string attempt_id{};
    std::string run_token{};
    std::string run_contract_sha256{};
    std::uint16_t port_id{};
    std::uint64_t max_packets{};
    std::chrono::milliseconds max_runtime{};
    std::chrono::milliseconds arm_timeout{};
    std::chrono::milliseconds idle_timeout{};
    std::chrono::milliseconds shutdown_grace{bounded_shutdown_grace};
    std::uint16_t mtu{1'500U};
    bool require_promiscuous{};
    bool benchmark_metrics{};
    int eal_argc{};
};

[[nodiscard]] std::optional<Arguments> parse_arguments(
    int argc,
    char** argv) {
    int separator{-1};
    for (int index = 1; index < argc; ++index) {
        if (std::string_view{argv[index]} == "--") {
            separator = index;
            break;
        }
    }
    if (separator < 1 || separator + 1 >= argc) {
        return std::nullopt;
    }

    std::optional<std::filesystem::path> bundle;
    std::optional<std::string> manifest_sha256;
    std::optional<std::string> source_ip_text;
    std::optional<std::string> target_ip_text;
    std::optional<std::string> attempt_id;
    std::optional<std::string> run_token;
    std::optional<std::string> run_contract_sha256;
    std::optional<std::uint64_t> port_id;
    std::optional<std::uint64_t> max_packets;
    std::optional<std::uint64_t> max_runtime_ms;
    std::optional<std::uint64_t> arm_timeout_ms;
    std::optional<std::uint64_t> idle_timeout_ms;
    std::optional<std::uint64_t> shutdown_grace_ms;
    std::optional<std::uint64_t> mtu;
    std::optional<OutputMode> output_mode;
    std::optional<LifecycleMode> lifecycle_mode;
    std::optional<std::filesystem::path> alerts_file;
    bool any_source{};
    bool require_promiscuous{};
    bool benchmark_metrics{};

    for (int index = separator + 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--any-source") {
            if (any_source) {
                return std::nullopt;
            }
            any_source = true;
            continue;
        }
        if (argument == "--require-promiscuous") {
            if (require_promiscuous) {
                return std::nullopt;
            }
            require_promiscuous = true;
            continue;
        }
        if (argument == "--benchmark-metrics") {
            if (benchmark_metrics) {
                return std::nullopt;
            }
            benchmark_metrics = true;
            continue;
        }
        if (index + 1 >= argc) {
            return std::nullopt;
        }
        const std::string value{argv[++index]};
        if (argument == "--bundle") {
            if (bundle.has_value() || value.empty()) {
                return std::nullopt;
            }
            bundle = std::filesystem::path{value};
        } else if (argument == "--manifest-sha256") {
            if (manifest_sha256.has_value() || !valid_sha256(value)) {
                return std::nullopt;
            }
            manifest_sha256 = value;
        } else if (argument == "--source-ip") {
            if (source_ip_text.has_value() || !parse_ipv4(value).has_value()) {
                return std::nullopt;
            }
            source_ip_text = value;
        } else if (argument == "--target-ip") {
            if (target_ip_text.has_value() || !parse_ipv4(value).has_value()) {
                return std::nullopt;
            }
            target_ip_text = value;
        } else if (argument == "--output-mode") {
            if (output_mode.has_value()) {
                return std::nullopt;
            }
            if (value == "diagnostic") {
                output_mode = OutputMode::diagnostic;
            } else if (value == "alerts-only") {
                output_mode = OutputMode::alerts_only;
            } else {
                return std::nullopt;
            }
        } else if (argument == "--lifecycle-mode") {
            if (lifecycle_mode.has_value()) {
                return std::nullopt;
            }
            if (value == "bounded") {
                lifecycle_mode = LifecycleMode::bounded;
            } else if (value == "signal-only") {
                lifecycle_mode = LifecycleMode::signal_only;
            } else {
                return std::nullopt;
            }
        } else if (argument == "--alerts-file") {
            const std::filesystem::path requested{value};
            if (alerts_file.has_value() || value.empty()
                || !requested.is_absolute()) {
                return std::nullopt;
            }
            alerts_file = requested;
        } else if (argument == "--attempt-id") {
            if (attempt_id.has_value() || !valid_token(value)) {
                return std::nullopt;
            }
            attempt_id = value;
        } else if (argument == "--run-token") {
            if (run_token.has_value() || !valid_token(value)) {
                return std::nullopt;
            }
            run_token = value;
        } else if (argument == "--run-contract-sha256") {
            if (run_contract_sha256.has_value() || !valid_sha256(value)) {
                return std::nullopt;
            }
            run_contract_sha256 = value;
        } else if (argument == "--port-id") {
            if (port_id.has_value()) {
                return std::nullopt;
            }
            port_id = parse_unsigned(value);
        } else if (argument == "--max-packets") {
            if (max_packets.has_value()) {
                return std::nullopt;
            }
            max_packets = parse_unsigned(value);
        } else if (argument == "--max-runtime-ms") {
            if (max_runtime_ms.has_value()) {
                return std::nullopt;
            }
            max_runtime_ms = parse_unsigned(value);
        } else if (argument == "--arm-timeout-ms") {
            if (arm_timeout_ms.has_value()) {
                return std::nullopt;
            }
            arm_timeout_ms = parse_unsigned(value);
        } else if (argument == "--idle-timeout-ms") {
            if (idle_timeout_ms.has_value()) {
                return std::nullopt;
            }
            idle_timeout_ms = parse_unsigned(value);
        } else if (argument == "--shutdown-grace-ms") {
            if (shutdown_grace_ms.has_value()) {
                return std::nullopt;
            }
            shutdown_grace_ms = parse_unsigned(value);
        } else if (argument == "--mtu") {
            if (mtu.has_value()) {
                return std::nullopt;
            }
            mtu = parse_unsigned(value);
        } else {
            return std::nullopt;
        }
    }

    constexpr std::uint64_t maximum_packets{100'000'000U};
    constexpr std::uint64_t maximum_timeout_ms{300'000U};
    constexpr std::uint64_t maximum_shutdown_grace_ms{30'000U};
    constexpr std::uint64_t minimum_ipv4_mtu{576U};
    constexpr std::uint64_t maximum_live_mtu{9'000U};
    const auto requested_mtu = mtu.value_or(1'500U);
    const auto requested_output_mode =
        output_mode.value_or(OutputMode::diagnostic);
    const auto requested_lifecycle_mode =
        lifecycle_mode.value_or(LifecycleMode::bounded);
    const auto bounded_limits_valid =
        max_packets.has_value() && *max_packets > 0U
        && *max_packets <= maximum_packets
        && max_runtime_ms.has_value() && *max_runtime_ms > 0U
        && *max_runtime_ms <= maximum_timeout_ms
        && arm_timeout_ms.has_value() && *arm_timeout_ms > 0U
        && *arm_timeout_ms <= *max_runtime_ms
        && idle_timeout_ms.has_value() && *idle_timeout_ms > 0U
        && *idle_timeout_ms <= *max_runtime_ms
        && !shutdown_grace_ms.has_value()
        && !alerts_file.has_value();
    const auto signal_only_valid =
        requested_lifecycle_mode == LifecycleMode::signal_only
        && requested_output_mode == OutputMode::alerts_only
        && !max_packets.has_value()
        && !max_runtime_ms.has_value()
        && !arm_timeout_ms.has_value()
        && !idle_timeout_ms.has_value()
        && shutdown_grace_ms.has_value()
        && *shutdown_grace_ms > 0U
        && *shutdown_grace_ms <= maximum_shutdown_grace_ms
        && alerts_file.has_value();
    if (!bundle.has_value() || !manifest_sha256.has_value()
        || source_ip_text.has_value() == any_source
        || !target_ip_text.has_value()
        || !attempt_id.has_value() || !run_token.has_value()
        || !run_contract_sha256.has_value() || !port_id.has_value()
        || *port_id > std::numeric_limits<std::uint16_t>::max()
        || (requested_lifecycle_mode == LifecycleMode::bounded
            ? !bounded_limits_valid
            : !signal_only_valid)
        || requested_mtu < minimum_ipv4_mtu
        || requested_mtu > maximum_live_mtu) {
        return std::nullopt;
    }

    const auto source_ip = source_ip_text.has_value()
        ? parse_ipv4(*source_ip_text)
        : std::optional<nids::Ipv4Address>{};
    const auto target_ip = parse_ipv4(*target_ip_text);
    if (!target_ip.has_value()
        || (source_ip_text.has_value() && !source_ip.has_value())
        || (source_ip.has_value() && *source_ip == *target_ip)) {
        return std::nullopt;
    }

    return Arguments{
        *bundle,
        *manifest_sha256,
        source_ip.value_or(nids::Ipv4Address{}),
        *target_ip,
        source_ip.has_value() ? ipv4_string(*source_ip) : std::string{},
        ipv4_string(*target_ip),
        any_source,
        requested_output_mode,
        requested_lifecycle_mode,
        alerts_file,
        *attempt_id,
        *run_token,
        *run_contract_sha256,
        static_cast<std::uint16_t>(*port_id),
        max_packets.value_or(0U),
        std::chrono::milliseconds{
            static_cast<std::chrono::milliseconds::rep>(
                max_runtime_ms.value_or(0U))},
        std::chrono::milliseconds{
            static_cast<std::chrono::milliseconds::rep>(
                arm_timeout_ms.value_or(0U))},
        std::chrono::milliseconds{
            static_cast<std::chrono::milliseconds::rep>(
                idle_timeout_ms.value_or(0U))},
        std::chrono::milliseconds{
            static_cast<std::chrono::milliseconds::rep>(
                shutdown_grace_ms.value_or(
                    static_cast<std::uint64_t>(
                        bounded_shutdown_grace.count())))},
        static_cast<std::uint16_t>(requested_mtu),
        require_promiscuous,
        benchmark_metrics,
        separator,
    };
}

void report_dpdk_failure(std::string_view stage, int result) {
    const auto error = result < 0 ? -result : rte_errno;
    std::cerr
        << "T9.1 DPDK failure: stage=" << stage
        << " return=" << result
        << " rte_errno=" << rte_errno
        << " message=" << rte_strerror(error) << '\n';
}

class DpdkRuntime final {
public:
    ~DpdkRuntime() {
        if (port_started_) {
            rte_eth_dev_stop(port_id_);
        }
        if (port_configured_) {
            rte_eth_dev_close(port_id_);
        }
        if (pool_ != nullptr) {
            rte_mempool_free(pool_);
        }
        if (eal_initialized_) {
            rte_eal_cleanup();
        }
    }

    [[nodiscard]] bool initialize_eal(int argc, char** argv) {
        const auto result = rte_eal_init(argc, argv);
        if (result < 0) {
            report_dpdk_failure("eal_init", result);
            return false;
        }
        eal_initialized_ = true;
        return true;
    }

    [[nodiscard]] bool start_port(
        std::uint16_t port_id,
        std::uint16_t mtu,
        bool require_promiscuous) {
        if (rte_eth_dev_is_valid_port(port_id) == 0) {
            std::cerr << "T9.1 DPDK failure: invalid port id " << port_id << '\n';
            return false;
        }
        port_id_ = port_id;

        rte_eth_dev_info device_info{};
        const auto info_result = rte_eth_dev_info_get(port_id_, &device_info);
        if (info_result != 0) {
            report_dpdk_failure("eth_dev_info_get", info_result);
            return false;
        }
        if ((device_info.min_mtu != 0U && mtu < device_info.min_mtu)
            || (device_info.max_mtu != 0U && mtu > device_info.max_mtu)) {
            std::cerr
                << "T9.1 DPDK failure: requested MTU " << mtu
                << " is outside device range [" << device_info.min_mtu
                << ',' << device_info.max_mtu << "]\n";
            return false;
        }

        auto socket_id = rte_eth_dev_socket_id(port_id_);
        if (socket_id < 0) {
            socket_id = rte_socket_id();
        }
        constexpr std::uint32_t frame_headroom{32U};
        const auto data_room_size = std::max<std::uint32_t>(
            RTE_MBUF_DEFAULT_BUF_SIZE,
            static_cast<std::uint32_t>(mtu)
                + RTE_PKTMBUF_HEADROOM
                + frame_headroom);
        pool_ = rte_pktmbuf_pool_create(
            "nids_t91_live_pool",
            live_mbuf_pool_capacity,
            256U,
            0U,
            static_cast<std::uint16_t>(data_room_size),
            socket_id);
        if (pool_ == nullptr) {
            report_dpdk_failure("pktmbuf_pool_create", -rte_errno);
            return false;
        }

        rte_eth_conf configuration{};
        const auto configure_result =
            rte_eth_dev_configure(port_id_, 1U, 0U, &configuration);
        if (configure_result != 0) {
            report_dpdk_failure("eth_dev_configure", configure_result);
            return false;
        }
        port_configured_ = true;

        if (mtu != 1'500U) {
            const auto mtu_result = rte_eth_dev_set_mtu(port_id_, mtu);
            if (mtu_result != 0) {
                report_dpdk_failure("eth_dev_set_mtu", mtu_result);
                return false;
            }
        }

        constexpr std::uint16_t rx_descriptors{1'024U};
        const auto queue_result = rte_eth_rx_queue_setup(
            port_id_,
            0U,
            rx_descriptors,
            socket_id,
            &device_info.default_rxconf,
            pool_);
        if (queue_result != 0) {
            report_dpdk_failure("eth_rx_queue_setup", queue_result);
            return false;
        }
        const auto start_result = rte_eth_dev_start(port_id_);
        if (start_result != 0) {
            report_dpdk_failure("eth_dev_start", start_result);
            return false;
        }
        port_started_ = true;

        if (require_promiscuous) {
            const auto result = rte_eth_promiscuous_enable(port_id_);
            if (result != 0) {
                report_dpdk_failure("eth_promiscuous_enable", result);
                return false;
            }
            if (rte_eth_promiscuous_get(port_id_) != 1) {
                std::cerr
                    << "T9.1 DPDK failure: promiscuous mode did not remain enabled\n";
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] std::optional<rte_eth_stats> stats() const noexcept {
        rte_eth_stats result{};
        if (!port_started_ || rte_eth_stats_get(port_id_, &result) != 0) {
            return std::nullopt;
        }
        return result;
    }

private:
    bool eal_initialized_{};
    bool port_configured_{};
    bool port_started_{};
    std::uint16_t port_id_{};
    rte_mempool* pool_{};
};

struct TerminalFlowRecord {
    nids::FlowIdentity identity{};
    std::uint64_t generation{};
    nids::ClockDomain clock_domain{nids::ClockDomain::monotonic};
    std::int64_t creation_timestamp_ns{};
    std::int64_t last_capture_timestamp_ns{};
    std::int64_t last_event_timestamp_ns{};
    std::uint64_t packet_count{};
    std::uint64_t forward_packet_count{};
    std::uint64_t reverse_packet_count{};
    nids::FlowCloseReason close_reason{nids::FlowCloseReason::end_of_input};
    nids::TerminalFeatureVector features{};
};

class TerminalFlowSink {
public:
    virtual ~TerminalFlowSink() = default;
    [[nodiscard]] virtual bool write(
        const TerminalFlowRecord& record) noexcept = 0;
};

[[nodiscard]] constexpr std::size_t direction_index(
    nids::FlowDirection direction) noexcept {
    return static_cast<std::size_t>(direction);
}

class TerminalLivePipeline final : public nids::FlowObserver {
public:
    TerminalLivePipeline(
        nids::Ipv4Address first,
        nids::Ipv4Address second,
        bool any_source,
        TerminalFlowSink& sink)
        : first_{first},
          second_{second},
          any_source_{any_source},
          sink_{sink},
          table_{
              *this,
              nids::FlowTableConfig{
                  live_flow_limit,
                  nids::flow_capacity_v1.memory_budget_bytes}} {}

    [[nodiscard]] bool process(
        const nids::DpdkAdapterResult& adapted) noexcept {
        ++packets_seen_;
        if (std::holds_alternative<nids::DpdkAdapterError>(adapted)) {
            ++adapter_errors_;
            fail("DPDK adapter rejected a packet");
            return false;
        }
        const auto& event = std::get<nids::DpdkPacketEvent>(adapted);
        if (std::holds_alternative<nids::ParseError>(event.parsed)) {
            const auto& error = std::get<nids::ParseError>(event.parsed);
            const auto raw_scope =
                classify_raw_scope(
                    event.input.raw_bytes,
                    first_,
                    second_,
                    any_source_);
            if (error.kind == nids::ParseErrorKind::unsupported
                || raw_scope == RawPacketScope::ambient) {
                ++ambient_packets_;
                ++ambient_parse_rejections_;
                return false;
            }
            ++parser_errors_;
            fail(raw_scope == RawPacketScope::scoped
                ? "parser rejected a scoped packet"
                : "parser rejected an unclassifiable packet");
            return raw_scope == RawPacketScope::scoped;
        }
        ++packets_parsed_;
        const auto& packet = std::get<nids::PacketView>(event.parsed);
        if (!in_scope(packet)) {
            ++ambient_packets_;
            return false;
        }
        ++scoped_packets_;
        if (failure_.has_value()) {
            return true;
        }
        try {
            const auto result = table_.ingest(packet);
            if (result.status != nids::FlowIngestStatus::accepted) {
                ++ingest_errors_;
                fail("flow ingest rejected a scoped packet");
            }
        } catch (const std::exception& error) {
            ++ingest_errors_;
            fail(error.what());
        } catch (...) {
            ++ingest_errors_;
            fail("flow ingest threw an unknown exception");
        }
        return true;
    }

    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView& packet,
        const nids::FlowPacketContext& context) noexcept override {
        const auto result = terminal_features_.update(state, packet, context);
        if (result.has_value()) {
            ++terminal_feature_errors_;
            fail("terminal feature update failed");
        }
    }

    void on_close(
        const nids::FlowState& state,
        nids::FlowCloseReason reason) noexcept override {
        const auto encoded = terminal_features_.close(state);
        if (!std::holds_alternative<nids::TerminalFeatureVector>(encoded)) {
            ++terminal_feature_errors_;
            fail("terminal feature close failed");
            return;
        }
        if (failure_.has_value()) {
            return;
        }
        const auto record = TerminalFlowRecord{
            state.identity,
            state.generation,
            state.clock_domain,
            state.creation_timestamp_ns,
            state.last_capture_timestamp_ns,
            state.last_event_timestamp_ns,
            state.packet_count,
            state.directional_packet_count[
                direction_index(nids::FlowDirection::forward)],
            state.directional_packet_count[
                direction_index(nids::FlowDirection::reverse)],
            reason,
            std::get<nids::TerminalFeatureVector>(encoded),
        };
        if (!sink_.write(record)) {
            ++sink_errors_;
            fail("terminal flow sink failed");
            return;
        }
        ++terminal_flows_;
    }

    void flush() noexcept {
        try {
            table_.flush();
        } catch (const std::exception& error) {
            ++ingest_errors_;
            fail(error.what());
        } catch (...) {
            ++ingest_errors_;
            fail("flow flush threw an unknown exception");
        }
    }

    [[nodiscard]] const std::optional<std::string>& failure() const noexcept {
        return failure_;
    }

    [[nodiscard]] std::uint64_t packets_seen() const noexcept {
        return packets_seen_;
    }

    [[nodiscard]] std::uint64_t packets_parsed() const noexcept {
        return packets_parsed_;
    }

    [[nodiscard]] std::uint64_t adapter_errors() const noexcept {
        return adapter_errors_;
    }

    [[nodiscard]] std::uint64_t parser_errors() const noexcept {
        return parser_errors_;
    }

    [[nodiscard]] std::uint64_t ambient_packets() const noexcept {
        return ambient_packets_;
    }

    [[nodiscard]] std::uint64_t ambient_parse_rejections() const noexcept {
        return ambient_parse_rejections_;
    }

    [[nodiscard]] std::uint64_t scoped_packets() const noexcept {
        return scoped_packets_;
    }

    [[nodiscard]] std::uint64_t ingest_errors() const noexcept {
        return ingest_errors_;
    }

    [[nodiscard]] std::uint64_t terminal_feature_errors() const noexcept {
        return terminal_feature_errors_;
    }

    [[nodiscard]] std::uint64_t sink_errors() const noexcept {
        return sink_errors_;
    }

    [[nodiscard]] std::uint64_t terminal_flows() const noexcept {
        return terminal_flows_;
    }

    [[nodiscard]] std::size_t active_terminal_generations() const noexcept {
        return terminal_features_.active_generation_count();
    }

    [[nodiscard]] nids::FlowCounters flow_counters() const noexcept {
        return table_.counters();
    }

private:
    [[nodiscard]] bool in_scope(const nids::PacketView& packet) const noexcept {
        return any_source_
            ? (packet.ipv4.source == second_
                || packet.ipv4.destination == second_)
            : ((packet.ipv4.source == first_
                    && packet.ipv4.destination == second_)
                || (packet.ipv4.source == second_
                    && packet.ipv4.destination == first_));
    }

    void fail(std::string_view detail) noexcept {
        if (failure_.has_value()) {
            return;
        }
        try {
            failure_ = detail;
        } catch (...) {
            failure_ = std::string{};
        }
    }

    nids::Ipv4Address first_{};
    nids::Ipv4Address second_{};
    bool any_source_{};
    TerminalFlowSink& sink_;
    nids::TerminalFeatureEngine terminal_features_{};
    nids::FlowTable table_;
    std::optional<std::string> failure_{};
    std::uint64_t packets_seen_{};
    std::uint64_t packets_parsed_{};
    std::uint64_t adapter_errors_{};
    std::uint64_t parser_errors_{};
    std::uint64_t ambient_packets_{};
    std::uint64_t ambient_parse_rejections_{};
    std::uint64_t scoped_packets_{};
    std::uint64_t ingest_errors_{};
    std::uint64_t terminal_feature_errors_{};
    std::uint64_t sink_errors_{};
    std::uint64_t terminal_flows_{};
};

[[nodiscard]] constexpr std::string_view protocol_name(
    nids::TransportProtocol protocol) noexcept {
    return protocol == nids::TransportProtocol::tcp ? "tcp" : "udp";
}

[[nodiscard]] constexpr std::string_view clock_domain_name(
    nids::ClockDomain domain) noexcept {
    return domain == nids::ClockDomain::unix_epoch
        ? "unix_epoch"
        : "monotonic";
}

[[nodiscard]] constexpr std::string_view close_reason_name(
    nids::FlowCloseReason reason) noexcept {
    constexpr std::array names{
        std::string_view{"idle_timeout"},
        std::string_view{"maximum_age"},
        std::string_view{"tcp_reset"},
        std::string_view{"tcp_fin_handshake"},
        std::string_view{"tuple_reuse"},
        std::string_view{"capacity_eviction"},
        std::string_view{"end_of_input"},
    };
    return names[nids::flow_close_reason_index(reason)];
}

[[nodiscard]] constexpr bool acceptance_eligible(
    nids::FlowCloseReason reason) noexcept {
    return reason == nids::FlowCloseReason::tcp_reset
        || reason == nids::FlowCloseReason::tcp_fin_handshake;
}

[[nodiscard]] std::int64_t duration_ns(
    const TerminalFlowRecord& record) noexcept {
    const auto value = nids::signed_iat_ns(
        record.last_event_timestamp_ns,
        record.creation_timestamp_ns);
    return value.has_value() && *value > 0 ? *value : 0;
}

void add_class_order(
    json_t* parent,
    const nids::TerminalModelBundle& bundle) {
    auto array = json_array_document();
    for (const auto& name : bundle.class_names()) {
        append_json(
            array.get(),
            checked_json(json_string(name.c_str())));
    }
    set_json(parent, "class_order", array.release());
}

void add_artifact(
    json_t* parent,
    const nids::TerminalModelBundle& bundle) {
    auto artifact = json_object_document();
    set_string(artifact.get(), "artifact_id", bundle.artifact_id());
    set_string(artifact.get(), "artifact_version", bundle.artifact_version());
    set_string(artifact.get(), "bundle_manifest_sha256", bundle.manifest_sha256());
    set_string(artifact.get(), "feature_schema_id", feature_schema_id);
    set_string(
        artifact.get(),
        "feature_schema_sha256",
        bundle.feature_schema_sha256());
    set_string(artifact.get(), "model_sha256", bundle.model_sha256());
    set_string(artifact.get(), "profile_id", bundle.profile_id());
    set_json(parent, "artifact", artifact.release());
}

void add_run_identity(json_t* parent, const Arguments& arguments) {
    set_string(parent, "attempt_id", arguments.attempt_id);
    set_string(parent, "run_contract_sha256", arguments.run_contract_sha256);
    set_string(parent, "run_token", arguments.run_token);
    set_string(
        parent,
        "scope_mode",
        arguments.any_source ? "target_ip" : "endpoint_pair");
    if (arguments.any_source) {
        set_json(parent, "source_ip", json_null());
    } else {
        set_string(parent, "source_ip", arguments.source_ip_text);
    }
    set_string(parent, "target_ip", arguments.target_ip_text);
}

void add_flow_record(json_t* parent, const TerminalFlowRecord& record) {
    set_bool(
        parent,
        "acceptance_eligible",
        acceptance_eligible(record.close_reason));
    set_string(
        parent,
        "clock_domain",
        clock_domain_name(record.clock_domain));
    set_i64(
        parent,
        "creation_timestamp_ns",
        record.creation_timestamp_ns);
    set_i64(
        parent,
        "last_capture_timestamp_ns",
        record.last_capture_timestamp_ns);
    set_i64(
        parent,
        "last_event_timestamp_ns",
        record.last_event_timestamp_ns);
    set_i64(parent, "duration_ns", duration_ns(record));
    set_u64(parent, "packet_count", record.packet_count);
    set_u64(
        parent,
        "forward_packet_count",
        record.forward_packet_count);
    set_u64(
        parent,
        "reverse_packet_count",
        record.reverse_packet_count);
    set_string(
        parent,
        "close_reason",
        close_reason_name(record.close_reason));

    const auto source = record.identity.forward_source;
    const auto destination = source == record.identity.key.low
        ? record.identity.key.high
        : record.identity.key.low;
    auto flow = json_object_document();
    set_u64(flow.get(), "generation", record.generation);
    set_string(
        flow.get(),
        "protocol",
        protocol_name(record.identity.key.protocol));
    auto source_json = json_object_document();
    set_string(source_json.get(), "ip", ipv4_string(source.address));
    set_u64(source_json.get(), "port", source.port);
    set_json(flow.get(), "source", source_json.release());
    auto destination_json = json_object_document();
    set_string(
        destination_json.get(),
        "ip",
        ipv4_string(destination.address));
    set_u64(destination_json.get(), "port", destination.port);
    set_json(flow.get(), "destination", destination_json.release());
    set_json(parent, "flow", flow.release());
}

void add_probability_vector(
    json_t* parent,
    const nids::TerminalModelBundle& bundle,
    const nids::TerminalModelScores& scores) {
    add_class_order(parent, bundle);
    auto probabilities = json_array_document();
    for (const auto probability : scores.class_probabilities) {
        append_json(
            probabilities.get(),
            checked_json(json_real(probability)));
    }
    set_json(
        parent,
        "class_probabilities",
        probabilities.release());
}

class TerminalInferenceSink final : public TerminalFlowSink {
public:
    TerminalInferenceSink(
        const nids::TerminalModelBundle& bundle,
        const Arguments& arguments,
        std::ostream& output,
        std::ostream* alerts_output)
        : bundle_{bundle},
          arguments_{arguments},
          output_{output},
          alerts_output_{alerts_output},
          collect_benchmark_metrics_{arguments.benchmark_metrics} {}

    /// Nanoseconds elapsed since `start`, clamped at zero.
    [[nodiscard]] static std::uint64_t elapsed_since(
        std::chrono::steady_clock::time_point start) noexcept {
        const auto delta = std::chrono::steady_clock::now() - start;
        const auto nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(delta).count();
        return nanoseconds > 0 ? static_cast<std::uint64_t>(nanoseconds) : 0U;
    }

    void begin_shutdown(
        std::chrono::steady_clock::time_point deadline) noexcept {
        shutdown_deadline_ = deadline;
    }

    [[nodiscard]] bool write(
        const TerminalFlowRecord& record) noexcept override {
        if (record.close_reason == nids::FlowCloseReason::end_of_input) {
            ++eof_flows_;
        } else {
            ++non_eof_flows_;
        }
        if (acceptance_eligible(record.close_reason)) {
            ++eligible_flows_;
        }
        if (record.close_reason == nids::FlowCloseReason::end_of_input
            && shutdown_deadline_.has_value()
            && std::chrono::steady_clock::now() >= *shutdown_deadline_) {
            ++skipped_eof_inferences_;
            return true;
        }
        if (arguments_.output_mode == OutputMode::diagnostic
            && decision_events_ >= decision_event_limit()) {
            ++decision_event_limit_rejections_;
            set_failure("terminal decision diagnostic limit exceeded");
            return false;
        }

        ++inference_attempts_;
        // Features are already built by the exporter before write() is called,
        // so timing only this call gives the model call on its own. The F9
        // sensor starts its clock before feature encoding, so the two
        // `inference` buckets are NOT the same quantity; see the summary note.
        const auto inference_started = std::chrono::steady_clock::now();
        const auto result = bundle_.infer(record.features);
        if (collect_benchmark_metrics_) {
            inference_latency_.record(elapsed_since(inference_started));
        }
        if (!std::holds_alternative<nids::TerminalModelScores>(result)) {
            ++inference_errors_;
            const auto& error =
                std::get<nids::TerminalModelRuntimeError>(result);
            set_failure(error.detail);
            return false;
        }
        ++inferences_;
        const auto& scores = std::get<nids::TerminalModelScores>(result);
        if (scores.class_index >= bundle_.class_names().size()
            || (scores.attack && scores.class_index == 0U)
            || (!scores.attack && scores.class_index != 0U)) {
            ++inference_errors_;
            set_failure("terminal decision gate returned an invalid class");
            return false;
        }

        if (arguments_.output_mode == OutputMode::diagnostic) {
            try {
                auto decision = build_decision(record, scores);
                if (!write_json_line(output_, decision)) {
                    ++output_errors_;
                    set_failure(
                        "stdout failed while writing a terminal decision");
                    return false;
                }
            } catch (const std::exception& error) {
                ++serialization_errors_;
                set_failure(error.what());
                return false;
            } catch (...) {
                ++serialization_errors_;
                set_failure("terminal decision serialization failed");
                return false;
            }
            ++decision_events_;
        } else {
            ++decision_diagnostics_suppressed_;
        }

        if (!scores.attack) {
            ++benign_decisions_;
            return !record_shutdown_deadline_overrun(record);
        }
        ++attack_decisions_;

        try {
            auto alert = build_alert(record, scores);
            if (!write_json_line(output_, alert)) {
                ++output_errors_;
                set_failure("stdout failed while writing a terminal alert");
                return false;
            }
            if (alerts_output_ != nullptr
                && !write_json_line(*alerts_output_, alert)) {
                ++output_errors_;
                set_failure(
                    "alerts file failed while writing a terminal alert");
                return false;
            }
        } catch (const std::exception& error) {
            ++serialization_errors_;
            set_failure(error.what());
            return false;
        } catch (...) {
            ++serialization_errors_;
            set_failure("terminal alert serialization failed");
            return false;
        }

        if (collect_benchmark_metrics_
            && record.clock_domain == nids::ClockDomain::monotonic) {
            const auto emitted_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
            // last_capture_timestamp_ns is on the same monotonic clock, so the
            // subtraction is valid. Guard against a negative value anyway: a
            // clock domain mismatch must not be reported as a zero latency.
            if (emitted_ns > record.last_capture_timestamp_ns) {
                alert_latency_.record(
                    static_cast<std::uint64_t>(
                        emitted_ns - record.last_capture_timestamp_ns));
            }
        }
        ++alerts_;
        ++alerts_by_class_[scores.class_index];
        if (acceptance_eligible(record.close_reason)) {
            ++eligible_alerts_;
        }
        return !record_shutdown_deadline_overrun(record);
    }

    [[nodiscard]] const std::optional<std::string>& failure() const noexcept {
        return failure_;
    }

    [[nodiscard]] nids::LatencySummary inference_latency() const {
        return inference_latency_.summary();
    }

    [[nodiscard]] nids::LatencySummary alert_latency() const {
        return alert_latency_.summary();
    }

    [[nodiscard]] std::uint64_t inference_attempts() const noexcept {
        return inference_attempts_;
    }

    [[nodiscard]] std::uint64_t inferences() const noexcept {
        return inferences_;
    }

    [[nodiscard]] std::uint64_t inference_errors() const noexcept {
        return inference_errors_;
    }

    [[nodiscard]] std::uint64_t serialization_errors() const noexcept {
        return serialization_errors_;
    }

    [[nodiscard]] std::uint64_t output_errors() const noexcept {
        return output_errors_;
    }

    [[nodiscard]] std::uint64_t benign_decisions() const noexcept {
        return benign_decisions_;
    }

    [[nodiscard]] std::uint64_t attack_decisions() const noexcept {
        return attack_decisions_;
    }

    [[nodiscard]] std::uint64_t alerts() const noexcept {
        return alerts_;
    }

    [[nodiscard]] std::uint64_t decision_events() const noexcept {
        return decision_events_;
    }

    [[nodiscard]] std::uint64_t decision_event_limit() const noexcept {
        return arguments_.output_mode == OutputMode::diagnostic
            ? std::min(
                arguments_.max_packets,
                live_decision_event_hard_limit)
            : 0U;
    }

    [[nodiscard]] std::uint64_t
    decision_event_limit_rejections() const noexcept {
        return decision_event_limit_rejections_;
    }

    [[nodiscard]] std::uint64_t
    decision_diagnostics_suppressed() const noexcept {
        return decision_diagnostics_suppressed_;
    }

    [[nodiscard]] bool decision_output_accounting_clean() const noexcept {
        return arguments_.output_mode == OutputMode::diagnostic
            ? decision_events_ == inferences_
                && decision_diagnostics_suppressed_ == 0U
            : decision_events_ == 0U
                && decision_diagnostics_suppressed_ == inferences_;
    }

    [[nodiscard]] std::uint64_t eligible_alerts() const noexcept {
        return eligible_alerts_;
    }

    [[nodiscard]] std::uint64_t eligible_flows() const noexcept {
        return eligible_flows_;
    }

    [[nodiscard]] std::uint64_t non_eof_flows() const noexcept {
        return non_eof_flows_;
    }

    [[nodiscard]] std::uint64_t eof_flows() const noexcept {
        return eof_flows_;
    }

    [[nodiscard]] std::uint64_t skipped_eof_inferences() const noexcept {
        return skipped_eof_inferences_;
    }

    [[nodiscard]] std::uint64_t shutdown_deadline_overruns() const noexcept {
        return shutdown_deadline_overruns_;
    }

    [[nodiscard]] const std::array<
        std::uint64_t,
        nids::terminal_model_class_count_v1>&
    alerts_by_class() const noexcept {
        return alerts_by_class_;
    }

private:
    nids::LatencySamples inference_latency_{};
    nids::LatencySamples alert_latency_{};
    bool collect_benchmark_metrics_{};


    [[nodiscard]] bool record_shutdown_deadline_overrun(
        const TerminalFlowRecord& record) noexcept {
        if (record.close_reason != nids::FlowCloseReason::end_of_input
            || !shutdown_deadline_.has_value()
            || std::chrono::steady_clock::now() < *shutdown_deadline_) {
            return false;
        }
        ++shutdown_deadline_overruns_;
        set_failure("EOF inference exceeded the shutdown deadline");
        return true;
    }

    [[nodiscard]] JsonDocument build_decision(
        const TerminalFlowRecord& record,
        const nids::TerminalModelScores& scores) {
        const auto raw = std::max_element(
            scores.class_probabilities.begin(),
            scores.class_probabilities.end());
        const auto raw_index = static_cast<std::size_t>(
            std::distance(scores.class_probabilities.begin(), raw));
        const auto attack_candidate = std::max_element(
            scores.class_probabilities.begin() + 1,
            scores.class_probabilities.end());
        const auto attack_candidate_index = static_cast<std::size_t>(
            std::distance(
                scores.class_probabilities.begin(),
                attack_candidate));

        auto root = json_object_document();
        set_string(root.get(), "schema_version", schema_version);
        set_string(root.get(), "task", task_id);
        set_string(
            root.get(),
            "event_type",
            "nids_terminal_flow_decision");
        add_run_identity(root.get(), arguments_);
        add_artifact(root.get(), bundle_);
        set_u64(
            root.get(),
            "decision_ordinal",
            decision_events_ + 1U);
        set_string(
            root.get(),
            "decision",
            bundle_.class_names()[scores.class_index]);
        add_flow_record(root.get(), record);

        auto features = json_object_document();
        set_u64(features.get(), "count", record.features.size());
        set_string(
            features.get(),
            "encoding",
            "ascending_feature_index_float64");
        auto feature_values = json_array_document();
        for (const auto feature : record.features) {
            append_json(
                feature_values.get(),
                checked_json(json_real(feature)));
        }
        set_json(features.get(), "values", feature_values.release());
        set_json(root.get(), "features", features.release());

        auto score_json = json_object_document();
        set_string(score_json.get(), "probability_dtype", "float32");
        add_probability_vector(score_json.get(), bundle_, scores);

        auto raw_json = json_object_document();
        set_u64(raw_json.get(), "class_index", raw_index);
        set_string(
            raw_json.get(),
            "class_name",
            bundle_.class_names()[raw_index]);
        set_real(raw_json.get(), "class_confidence", *raw);
        set_json(score_json.get(), "raw_argmax", raw_json.release());

        auto candidate_json = json_object_document();
        set_u64(
            candidate_json.get(),
            "class_index",
            attack_candidate_index);
        set_string(
            candidate_json.get(),
            "class_name",
            bundle_.class_names()[attack_candidate_index]);
        set_real(
            candidate_json.get(),
            "class_confidence",
            *attack_candidate);
        set_json(
            score_json.get(),
            "top_attack_candidate",
            candidate_json.release());

        auto gate_json = json_object_document();
        set_real(gate_json.get(), "attack_score", scores.attack_score);
        set_string(gate_json.get(), "comparison", ">=");
        set_bool(gate_json.get(), "passed", scores.attack);
        set_string(
            gate_json.get(),
            "score_name",
            "one_minus_benign_probability");
        set_real(
            gate_json.get(),
            "threshold",
            bundle_.attack_threshold());
        set_json(score_json.get(), "attack_gate", gate_json.release());

        auto gated_json = json_object_document();
        set_u64(
            gated_json.get(),
            "class_index",
            scores.class_index);
        set_string(
            gated_json.get(),
            "class_name",
            bundle_.class_names()[scores.class_index]);
        set_real(
            gated_json.get(),
            "class_confidence",
            scores.class_confidence);
        set_json(
            score_json.get(),
            "gated_decision",
            gated_json.release());
        set_json(root.get(), "scores", score_json.release());
        return root;
    }

    [[nodiscard]] JsonDocument build_alert(
        const TerminalFlowRecord& record,
        const nids::TerminalModelScores& scores) {
        auto root = json_object_document();
        set_string(root.get(), "schema_version", schema_version);
        set_string(root.get(), "task", task_id);
        set_string(root.get(), "event_type", "nids_terminal_flow_alert");
        add_run_identity(root.get(), arguments_);
        add_artifact(root.get(), bundle_);
        set_u64(root.get(), "alert_ordinal", alerts_ + 1U);
        set_string(
            root.get(),
            "decision",
            bundle_.class_names()[scores.class_index]);
        add_flow_record(root.get(), record);

        auto score_json = json_object_document();
        set_bool(score_json.get(), "attack", true);
        set_real(score_json.get(), "attack_score", scores.attack_score);
        set_real(
            score_json.get(),
            "attack_threshold",
            bundle_.attack_threshold());
        set_string(score_json.get(), "comparison", ">=");
        set_u64(score_json.get(), "class_index", scores.class_index);
        set_real(
            score_json.get(),
            "class_confidence",
            scores.class_confidence);
        add_probability_vector(score_json.get(), bundle_, scores);
        set_json(root.get(), "scores", score_json.release());
        return root;
    }

    void set_failure(std::string_view detail) noexcept {
        if (failure_.has_value()) {
            return;
        }
        try {
            failure_ = detail;
        } catch (...) {
            failure_ = std::string{};
        }
    }

    const nids::TerminalModelBundle& bundle_;
    const Arguments& arguments_;
    std::ostream& output_;
    std::ostream* alerts_output_;
    std::optional<std::string> failure_{};
    std::optional<std::chrono::steady_clock::time_point> shutdown_deadline_{};
    std::array<std::uint64_t, nids::terminal_model_class_count_v1>
        alerts_by_class_{};
    std::uint64_t inference_attempts_{};
    std::uint64_t inferences_{};
    std::uint64_t inference_errors_{};
    std::uint64_t serialization_errors_{};
    std::uint64_t output_errors_{};
    std::uint64_t benign_decisions_{};
    std::uint64_t attack_decisions_{};
    std::uint64_t decision_events_{};
    std::uint64_t decision_event_limit_rejections_{};
    std::uint64_t decision_diagnostics_suppressed_{};
    std::uint64_t alerts_{};
    std::uint64_t eligible_alerts_{};
    std::uint64_t eligible_flows_{};
    std::uint64_t non_eof_flows_{};
    std::uint64_t eof_flows_{};
    std::uint64_t skipped_eof_inferences_{};
    std::uint64_t shutdown_deadline_overruns_{};
};

[[nodiscard]] JsonDocument latency_object(
    const nids::LatencySummary& summary) {
    auto object = json_object_document();
    set_u64(object.get(), "observations", summary.observations);
    set_u64(object.get(), "samples", summary.samples);
    set_string(object.get(), "sampling", "first_1000000");
    set_u64(object.get(), "p50", summary.p50_ns);
    set_u64(object.get(), "p95", summary.p95_ns);
    set_u64(object.get(), "p99", summary.p99_ns);
    set_u64(object.get(), "max", summary.maximum_ns);
    return object;
}

[[nodiscard]] JsonDocument ready_event(
    const Arguments& arguments,
    const nids::TerminalModelBundle& bundle) {
    auto root = json_object_document();
    set_string(root.get(), "schema_version", schema_version);
    set_string(root.get(), "task", task_id);
    set_string(root.get(), "event_type", "nids_terminal_live_ready");
    set_string(root.get(), "status", "ready");
    add_run_identity(root.get(), arguments);
    add_artifact(root.get(), bundle);
    add_class_order(root.get(), bundle);
    set_real(root.get(), "attack_threshold", bundle.attack_threshold());
    set_bool(
        root.get(),
        "bounded",
        arguments.lifecycle_mode == LifecycleMode::bounded);
    set_string(
        root.get(),
        "lifecycle_mode",
        lifecycle_mode_name(arguments.lifecycle_mode));
    set_u64(root.get(), "port_id", arguments.port_id);
    set_u64(root.get(), "rx_queues", 1U);
    set_u64(root.get(), "tx_queues", 0U);
    set_u64(root.get(), "mtu", arguments.mtu);
    set_u64(root.get(), "mbuf_pool_capacity", live_mbuf_pool_capacity);
    set_u64(root.get(), "active_flow_limit", live_flow_limit);
    set_string(
        root.get(),
        "output_mode",
        output_mode_name(arguments.output_mode));
    set_u64(
        root.get(),
        "decision_event_limit",
        arguments.output_mode == OutputMode::diagnostic
            ? std::min(
                arguments.max_packets,
                live_decision_event_hard_limit)
            : 0U);
    set_string(
        root.get(),
        "decision_event_policy",
        decision_event_policy(arguments.output_mode));
    set_u64(root.get(), "max_packets", arguments.max_packets);
    set_u64(
        root.get(),
        "max_runtime_ms",
        static_cast<std::uint64_t>(arguments.max_runtime.count()));
    set_u64(
        root.get(),
        "arm_timeout_ms",
        static_cast<std::uint64_t>(arguments.arm_timeout.count()));
    set_u64(
        root.get(),
        "idle_timeout_ms",
        static_cast<std::uint64_t>(arguments.idle_timeout.count()));
    set_u64(
        root.get(),
        "shutdown_grace_ms",
        static_cast<std::uint64_t>(arguments.shutdown_grace.count()));
    return root;
}

[[nodiscard]] JsonDocument summary_event(
    bool passed,
    std::string_view stop_reason,
    std::chrono::milliseconds duration,
    const Arguments& arguments,
    const nids::TerminalModelBundle& bundle,
    const TerminalLivePipeline& pipeline,
    const TerminalInferenceSink& sink,
    const std::optional<rte_eth_stats>& stats) {
    const auto flows = pipeline.flow_counters();
    auto root = json_object_document();
    set_string(root.get(), "schema_version", schema_version);
    set_string(root.get(), "task", task_id);
    set_string(root.get(), "event_type", "nids_terminal_live_summary");
    set_string(root.get(), "status", passed ? "passed" : "failed");
    set_string(root.get(), "stop_reason", stop_reason);
    add_run_identity(root.get(), arguments);
    add_artifact(root.get(), bundle);
    add_class_order(root.get(), bundle);
    set_real(root.get(), "attack_threshold", bundle.attack_threshold());
    set_bool(
        root.get(),
        "bounded",
        arguments.lifecycle_mode == LifecycleMode::bounded);
    set_string(
        root.get(),
        "lifecycle_mode",
        lifecycle_mode_name(arguments.lifecycle_mode));
    set_bool(
        root.get(),
        "shutdown_complete",
        sink.skipped_eof_inferences() == 0U
            && sink.shutdown_deadline_overruns() == 0U);
    set_u64(
        root.get(),
        "duration_ms",
        static_cast<std::uint64_t>(duration.count()));
    set_u64(
        root.get(),
        "shutdown_grace_ms",
        static_cast<std::uint64_t>(arguments.shutdown_grace.count()));
    set_u64(root.get(), "rx_queues", 1U);
    set_u64(root.get(), "tx_queues", 0U);
    set_u64(root.get(), "packets_seen", pipeline.packets_seen());
    set_u64(root.get(), "packets_parsed", pipeline.packets_parsed());
    set_u64(root.get(), "scoped_packets", pipeline.scoped_packets());
    set_u64(root.get(), "ambient_packets", pipeline.ambient_packets());
    set_u64(
        root.get(),
        "ambient_parse_rejections",
        pipeline.ambient_parse_rejections());
    set_u64(root.get(), "terminal_flows", pipeline.terminal_flows());
    set_u64(root.get(), "inference_attempts", sink.inference_attempts());
    set_u64(root.get(), "inferences", sink.inferences());
    set_u64(root.get(), "benign_decisions", sink.benign_decisions());
    set_u64(root.get(), "attack_decisions", sink.attack_decisions());
    set_string(
        root.get(),
        "output_mode",
        output_mode_name(arguments.output_mode));
    set_u64(root.get(), "decision_events", sink.decision_events());
    set_u64(
        root.get(),
        "decision_event_limit",
        sink.decision_event_limit());
    set_u64(
        root.get(),
        "decision_event_limit_rejections",
        sink.decision_event_limit_rejections());
    set_u64(
        root.get(),
        "decision_diagnostics_suppressed",
        sink.decision_diagnostics_suppressed());
    set_bool(
        root.get(),
        "decision_diagnostics_complete",
        arguments.output_mode == OutputMode::diagnostic
            && sink.decision_events() == sink.inferences()
            && sink.decision_event_limit_rejections() == 0U);
    set_string(
        root.get(),
        "decision_event_policy",
        decision_event_policy(arguments.output_mode));
    set_u64(root.get(), "alerts", sink.alerts());
    set_bool(
        root.get(),
        "alerts_complete",
        sink.alerts() == sink.attack_decisions());
    set_u64(root.get(), "eligible_flows", sink.eligible_flows());
    set_u64(root.get(), "eligible_alerts", sink.eligible_alerts());
    set_u64(root.get(), "non_eof_flows", sink.non_eof_flows());
    set_u64(root.get(), "eof_flows", sink.eof_flows());
    set_u64(
        root.get(),
        "skipped_eof_inferences",
        sink.skipped_eof_inferences());
    set_u64(
        root.get(),
        "shutdown_deadline_overruns",
        sink.shutdown_deadline_overruns());
    set_u64(root.get(), "active_flow_limit", live_flow_limit);

    if (arguments.benchmark_metrics) {
        auto latency = json_object_document();
        auto inference = latency_object(sink.inference_latency());
        set_json(latency.get(), "inference", inference.release());
        auto alert = latency_object(sink.alert_latency());
        set_json(latency.get(), "alert", alert.release());
        // Stated in the payload so a reader cannot mistake this bucket for the
        // F9 one, which also covers feature encoding.
        set_string(
            latency.get(),
            "inference_scope",
            "model_call_only_features_already_built");
        set_string(
            latency.get(),
            "alert_scope",
            "last_capture_timestamp_ns_until_alert_written");
        set_json(root.get(), "latency_ns", latency.release());
    }

    auto errors = json_object_document();
    set_u64(errors.get(), "adapter", pipeline.adapter_errors());
    set_u64(errors.get(), "parser", pipeline.parser_errors());
    set_u64(errors.get(), "ingest", pipeline.ingest_errors());
    set_u64(
        errors.get(),
        "terminal_feature",
        pipeline.terminal_feature_errors());
    set_u64(errors.get(), "sink", pipeline.sink_errors());
    set_u64(errors.get(), "inference", sink.inference_errors());
    set_u64(errors.get(), "serialization", sink.serialization_errors());
    set_u64(errors.get(), "output", sink.output_errors());
    set_json(root.get(), "errors", errors.release());

    auto flow_json = json_object_document();
    set_u64(
        flow_json.get(),
        "flow_generations_created",
        flows.flow_generations_created);
    set_u64(flow_json.get(), "flows_closed", flows.flows_closed);
    set_u64(flow_json.get(), "active_flows", flows.active_flow_count);
    set_u64(
        flow_json.get(),
        "peak_active_flows",
        flows.peak_active_flow_count);
    set_u64(
        flow_json.get(),
        "active_terminal_generations",
        pipeline.active_terminal_generations());
    auto close_reasons = json_object_document();
    for (std::size_t index = 0; index < nids::flow_close_reason_count; ++index) {
        set_u64(
            close_reasons.get(),
            close_reason_name(static_cast<nids::FlowCloseReason>(index)).data(),
            flows.close_reason_count[index]);
    }
    set_json(flow_json.get(), "close_reason_count", close_reasons.release());
    set_json(root.get(), "flows", flow_json.release());

    auto alerts_by_class = json_object_document();
    for (std::size_t index = 0; index < bundle.class_names().size(); ++index) {
        set_u64(
            alerts_by_class.get(),
            bundle.class_names()[index].c_str(),
            sink.alerts_by_class()[index]);
    }
    set_json(root.get(), "alerts_by_class", alerts_by_class.release());

    auto port = json_object_document();
    set_bool(port.get(), "available", stats.has_value());
    set_u64(port.get(), "ipackets", stats.has_value() ? stats->ipackets : 0U);
    set_u64(port.get(), "imissed", stats.has_value() ? stats->imissed : 0U);
    set_u64(port.get(), "ierrors", stats.has_value() ? stats->ierrors : 0U);
    set_u64(port.get(), "rx_nombuf", stats.has_value() ? stats->rx_nombuf : 0U);
    set_u64(port.get(), "opackets", stats.has_value() ? stats->opackets : 0U);
    set_u64(port.get(), "oerrors", stats.has_value() ? stats->oerrors : 0U);
    set_json(root.get(), "port_stats", port.release());

    if (pipeline.failure().has_value()) {
        set_string(root.get(), "pipeline_failure", *pipeline.failure());
    }
    if (sink.failure().has_value()) {
        set_string(root.get(), "inference_failure", *sink.failure());
    }
    return root;
}

[[nodiscard]] bool clean_port_stats(
    const std::optional<rte_eth_stats>& stats) noexcept {
    return stats.has_value()
        && stats->imissed == 0U
        && stats->ierrors == 0U
        && stats->rx_nombuf == 0U
        && stats->opackets == 0U
        && stats->oerrors == 0U;
}

[[nodiscard]] bool clean_pipeline(
    const TerminalLivePipeline& pipeline,
    const TerminalInferenceSink& sink) noexcept {
    const auto flows = pipeline.flow_counters();
    return !pipeline.failure().has_value()
        && !sink.failure().has_value()
        && pipeline.adapter_errors() == 0U
        && pipeline.parser_errors() == 0U
        && pipeline.ingest_errors() == 0U
        && pipeline.terminal_feature_errors() == 0U
        && pipeline.sink_errors() == 0U
        && sink.inference_errors() == 0U
        && sink.serialization_errors() == 0U
        && sink.output_errors() == 0U
        && sink.decision_output_accounting_clean()
        && sink.decision_event_limit_rejections() == 0U
        && sink.benign_decisions() + sink.attack_decisions()
                == sink.inferences()
        && sink.alerts() == sink.attack_decisions()
        && sink.skipped_eof_inferences() == 0U
        && sink.shutdown_deadline_overruns() == 0U
        && pipeline.packets_seen()
                == pipeline.packets_parsed()
                    + pipeline.adapter_errors()
                    + pipeline.parser_errors()
                    + pipeline.ambient_parse_rejections()
        && pipeline.ambient_parse_rejections()
                <= pipeline.ambient_packets()
        && pipeline.packets_parsed()
                == pipeline.scoped_packets()
                    + pipeline.ambient_packets()
                    - pipeline.ambient_parse_rejections()
        && flows.packets_accepted == pipeline.scoped_packets()
        && flows.active_flow_count == 0U
        && pipeline.active_terminal_generations() == 0U
        && sink.inferences() + sink.skipped_eof_inferences()
                == pipeline.terminal_flows();
}

}

int main(int argc, char** argv) {
    const auto arguments = parse_arguments(argc, argv);
    if (!arguments.has_value()) {
        std::cerr
            << "usage: nids_t91_terminal_live [EAL options] --"
               " --bundle DIR --manifest-sha256 HEX"
               " (--source-ip IPV4 | --any-source) --target-ip IPV4"
               " [--output-mode diagnostic|alerts-only]"
               " [--lifecycle-mode bounded|signal-only]"
               " --attempt-id TOKEN --run-token TOKEN"
               " --run-contract-sha256 HEX --port-id N"
               " [--max-packets N --max-runtime-ms N"
               " --arm-timeout-ms N --idle-timeout-ms N]"
               " [--shutdown-grace-ms N --alerts-file PATH]"
               " [--mtu N] [--require-promiscuous]\n";
        return 2;
    }

    try {
        auto loaded = nids::load_terminal_model_bundle(
            arguments->bundle,
            arguments->manifest_sha256);
        if (!loaded) {
            if (loaded.error.has_value()) {
                std::cerr << loaded.error->detail << '\n';
            }
            return 2;
        }

        std::ofstream alerts_output;
        if (arguments->alerts_file.has_value()) {
            const auto status =
                std::filesystem::symlink_status(*arguments->alerts_file);
            if (!std::filesystem::is_regular_file(status)
                || std::filesystem::file_size(*arguments->alerts_file) != 0U) {
                std::cerr << "alerts file must be an empty regular file\n";
                return 2;
            }
            alerts_output.open(
                *arguments->alerts_file,
                std::ios::out | std::ios::app);
            if (!alerts_output.is_open() || !alerts_output.good()) {
                std::cerr << "failed to open alerts file\n";
                return 2;
            }
        }

        DpdkRuntime runtime;
        if (!runtime.initialize_eal(arguments->eal_argc, argv)
            || !runtime.start_port(
                arguments->port_id,
                arguments->mtu,
                arguments->require_promiscuous)) {
            return 1;
        }

        TerminalInferenceSink sink{
            *loaded.bundle,
            *arguments,
            std::cout,
            arguments->alerts_file.has_value() ? &alerts_output : nullptr,
        };
        TerminalLivePipeline pipeline{
            arguments->source_ip,
            arguments->target_ip,
            arguments->any_source,
            sink,
        };

        stop_requested = 0;
        if (std::signal(SIGINT, request_stop) == SIG_ERR
            || std::signal(SIGTERM, request_stop) == SIG_ERR) {
            std::cerr << "failed to install signal handlers\n";
            return 1;
        }
        const auto ready = ready_event(*arguments, *loaded.bundle);
        if (!write_json_line(std::cout, ready)) {
            std::cerr << "stdout failed while writing READY\n";
            return 1;
        }
        std::cerr << "[NIDS T9.1] sensor ready\n";

        const auto started = std::chrono::steady_clock::now();
        auto last_scoped_packet = started;
        bool scope_armed{};
        const auto bounded =
            arguments->lifecycle_mode == LifecycleMode::bounded;
        std::string_view stop_reason{
            bounded ? "max_runtime" : "signal"};
        std::array<std::uint8_t, 65'535> scratch{};

        while (true) {
            if (pipeline.failure().has_value() || sink.failure().has_value()) {
                stop_reason = "pipeline_failure";
                break;
            }
            if (stop_requested != 0) {
                stop_reason = "signal";
                break;
            }
            if (bounded
                && pipeline.packets_seen() >= arguments->max_packets) {
                stop_reason = "packet_limit";
                break;
            }

            const auto now = std::chrono::steady_clock::now();
            if (bounded && now - started >= arguments->max_runtime) {
                stop_reason = "max_runtime";
                break;
            }
            if (bounded && !scope_armed
                && now - started >= arguments->arm_timeout) {
                stop_reason = "arm_timeout";
                break;
            }
            if (bounded && scope_armed
                && now - last_scoped_packet >= arguments->idle_timeout) {
                stop_reason = "scoped_idle_timeout";
                break;
            }

            std::array<rte_mbuf*, 32> received{};
            const auto count = rte_eth_rx_burst(
                arguments->port_id,
                0U,
                received.data(),
                static_cast<std::uint16_t>(received.size()));
            if (count == 0U) {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
                continue;
            }

            for (std::uint16_t index = 0; index < count; ++index) {
                auto* const mbuf = received[index];
                if ((!bounded
                        || pipeline.packets_seen() < arguments->max_packets)
                    && !pipeline.failure().has_value()
                    && !sink.failure().has_value()) {
                    const auto packet_time = std::chrono::steady_clock::now();
                    const auto timestamp_ns =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            packet_time.time_since_epoch())
                            .count();
                    const auto adapted = nids::adapt_mbuf(
                        *mbuf,
                        timestamp_ns,
                        nids::ClockDomain::monotonic,
                        scratch);
                    if (pipeline.process(adapted)) {
                        scope_armed = true;
                        last_scoped_packet = packet_time;
                    }
                }
                rte_pktmbuf_free(mbuf);
            }
        }

        const auto shutdown_started = std::chrono::steady_clock::now();
        auto shutdown_deadline =
            shutdown_started + arguments->shutdown_grace;
        if (bounded) {
            shutdown_deadline = std::min(
                started + arguments->max_runtime,
                shutdown_deadline);
        }
        sink.begin_shutdown(shutdown_deadline);
        pipeline.flush();
        if (pipeline.failure().has_value() || sink.failure().has_value()) {
            stop_reason = "pipeline_failure";
        }
        const auto duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started);
        const auto stats = runtime.stats();
        const auto passed =
            clean_pipeline(pipeline, sink) && clean_port_stats(stats);
        const auto summary = summary_event(
            passed,
            stop_reason,
            duration,
            *arguments,
            *loaded.bundle,
            pipeline,
            sink,
            stats);
        if (!write_json_line(std::cout, summary)) {
            std::cerr << "stdout failed while writing SUMMARY\n";
            return 1;
        }
        if (!passed) {
            if (pipeline.failure().has_value()) {
                std::cerr << *pipeline.failure() << '\n';
            }
            if (sink.failure().has_value()) {
                std::cerr << *sink.failure() << '\n';
            }
        }
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "T9.1 terminal live failure: " << error.what() << '\n';
        return 1;
    }
}
