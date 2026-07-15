#include "nids/detection_pipeline.hpp"
#include "nids/dpdk_adapter.hpp"
#include "nids/feature.hpp"
#include "nids/flow_table.hpp"

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
#include <exception>
#include <filesystem>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <sys/resource.h>

namespace {

inline constexpr std::uint32_t live_mbuf_pool_capacity{2'047U};

volatile std::sig_atomic_t stop_requested{};

extern "C" void request_stop(int) {
    stop_requested = 1;
}

struct Arguments {
    std::filesystem::path bundle{};
    std::optional<std::filesystem::path> thresholds{};
    std::optional<std::string> thresholds_sha256{};
    std::uint16_t port_id{};
    std::uint64_t max_packets{};
    std::uint64_t min_packets{};
    std::uint64_t min_f9_snapshots{};
    std::uint64_t min_alerts{};
    std::uint64_t max_parser_errors{};
    std::chrono::milliseconds arm_timeout{};
    std::chrono::milliseconds idle_timeout{};
    std::uint16_t mtu{1500U};
    bool require_promiscuous{};
    bool stop_after_alert{};
    bool benchmark_metrics{};
    bool disable_inference{};
    int eal_argc{};
};

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
    for (const auto character : value) {
        if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

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
    if (separator < 2 || separator + 1 >= argc) {
        return std::nullopt;
    }

    std::optional<std::filesystem::path> bundle;
    std::optional<std::filesystem::path> thresholds;
    std::optional<std::string> thresholds_sha256;
    std::optional<std::uint64_t> port_id;
    std::optional<std::uint64_t> max_packets;
    std::optional<std::uint64_t> min_packets;
    std::optional<std::uint64_t> min_f9;
    std::optional<std::uint64_t> min_alerts;
    std::optional<std::uint64_t> max_parser_errors;
    std::optional<std::uint64_t> arm_timeout_ms;
    std::optional<std::uint64_t> idle_timeout_ms;
    std::optional<std::uint64_t> mtu;
    bool require_promiscuous{};
    bool stop_after_alert{};
    bool benchmark_metrics{};
    bool disable_inference{};

    for (int index = separator + 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--require-promiscuous") {
            if (require_promiscuous) {
                return std::nullopt;
            }
            require_promiscuous = true;
            continue;
        }
        if (argument == "--stop-after-alert") {
            if (stop_after_alert) {
                return std::nullopt;
            }
            stop_after_alert = true;
            continue;
        }
        if (argument == "--benchmark-metrics") {
            if (benchmark_metrics) {
                return std::nullopt;
            }
            benchmark_metrics = true;
            continue;
        }
        if (argument == "--disable-inference") {
            if (disable_inference) {
                return std::nullopt;
            }
            disable_inference = true;
            continue;
        }
        if (index + 1 >= argc) {
            return std::nullopt;
        }
        const std::string_view value{argv[++index]};
        if (argument == "--bundle") {
            if (bundle.has_value() || value.empty()) {
                return std::nullopt;
            }
            bundle = std::filesystem::path{value};
        } else if (argument == "--thresholds") {
            if (thresholds.has_value() || value.empty()) {
                return std::nullopt;
            }
            thresholds = std::filesystem::path{value};
        } else if (argument == "--thresholds-sha256") {
            if (thresholds_sha256.has_value() || !valid_sha256(value)) {
                return std::nullopt;
            }
            thresholds_sha256 = value;
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
        } else if (argument == "--min-packets") {
            if (min_packets.has_value()) {
                return std::nullopt;
            }
            min_packets = parse_unsigned(value);
        } else if (argument == "--min-f9") {
            if (min_f9.has_value()) {
                return std::nullopt;
            }
            min_f9 = parse_unsigned(value);
        } else if (argument == "--min-alerts") {
            if (min_alerts.has_value()) {
                return std::nullopt;
            }
            min_alerts = parse_unsigned(value);
        } else if (argument == "--max-parser-errors") {
            if (max_parser_errors.has_value()) {
                return std::nullopt;
            }
            max_parser_errors = parse_unsigned(value);
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
        } else if (argument == "--mtu") {
            if (mtu.has_value()) {
                return std::nullopt;
            }
            mtu = parse_unsigned(value);
        } else {
            return std::nullopt;
        }
    }

    constexpr std::uint64_t maximum_bounded_packets{100'000'000U};
    constexpr std::uint64_t maximum_idle_timeout_ms{300'000U};
    constexpr std::uint64_t minimum_ipv4_mtu{576U};
    constexpr std::uint64_t maximum_live_mtu{9'000U};
    const auto requested_mtu = mtu.value_or(1'500U);
    const auto unlimited_packets =
        max_packets.has_value() && *max_packets == 0U;
    const auto allowed_parser_errors = max_parser_errors.value_or(
        unlimited_packets
            ? std::numeric_limits<std::uint64_t>::max()
            : 0U);
    const auto requested_arm_timeout_ms =
        arm_timeout_ms.value_or(idle_timeout_ms.value_or(0U));
    if (!bundle.has_value()
        || thresholds.has_value() != thresholds_sha256.has_value()
        || !port_id.has_value()
        || *port_id > std::numeric_limits<std::uint16_t>::max()
        || !max_packets.has_value()
        || (!unlimited_packets && *max_packets > maximum_bounded_packets)
        || !min_packets.has_value()
        || (!unlimited_packets && *min_packets > *max_packets)
        || !min_f9.has_value()
        || (!unlimited_packets && *min_f9 > *max_packets)
        || !min_alerts.has_value()
        || (!unlimited_packets && *min_alerts > *max_packets)
        || (!unlimited_packets && allowed_parser_errors > *max_packets)
        || !idle_timeout_ms.has_value()
        || (requested_arm_timeout_ms != 0U
            && requested_arm_timeout_ms > maximum_idle_timeout_ms)
        || (*idle_timeout_ms != 0U
            && *idle_timeout_ms > maximum_idle_timeout_ms)
        || requested_mtu < minimum_ipv4_mtu
        || requested_mtu > maximum_live_mtu
        || (disable_inference && !benchmark_metrics)
        || (disable_inference
            && (stop_after_alert || *min_alerts != 0U))) {
        return std::nullopt;
    }
    return Arguments{
        *bundle,
        thresholds,
        thresholds_sha256,
        static_cast<std::uint16_t>(*port_id),
        *max_packets,
        *min_packets,
        *min_f9,
        *min_alerts,
        allowed_parser_errors,
        std::chrono::milliseconds{
            static_cast<std::chrono::milliseconds::rep>(
                requested_arm_timeout_ms)},
        std::chrono::milliseconds{
            static_cast<std::chrono::milliseconds::rep>(*idle_timeout_ms)},
        static_cast<std::uint16_t>(requested_mtu),
        require_promiscuous,
        stop_after_alert,
        benchmark_metrics,
        disable_inference,
        separator,
    };
}

using DetectionConfigResult =
    std::variant<nids::DetectionPipelineConfig, std::string>;

[[nodiscard]] std::optional<std::string> verify_threshold_artifact(
    const Arguments& arguments) {
    if (!arguments.thresholds.has_value()) {
        return std::nullopt;
    }
    auto digest = nids::compute_file_sha256(*arguments.thresholds);
    if (std::holds_alternative<nids::ModelRuntimeError>(digest)) {
        return std::get<nids::ModelRuntimeError>(std::move(digest)).detail;
    }
    if (std::get<std::string>(digest) != *arguments.thresholds_sha256) {
        return std::string{"threshold artifact SHA-256 mismatch"};
    }
    return std::nullopt;
}

[[nodiscard]] DetectionConfigResult load_detection_config(
    const Arguments& arguments,
    nids::Checkpoint checkpoint) {
    nids::DetectionPipelineConfig config;
    if (!arguments.thresholds.has_value()) {
        return config;
    }

    auto loaded = nids::load_decision_thresholds(
        *arguments.thresholds,
        checkpoint);
    if (std::holds_alternative<nids::ThresholdConfigError>(loaded)) {
        return std::get<nids::ThresholdConfigError>(
            std::move(loaded)).detail;
    }
    config.decision_thresholds =
        std::get<nids::DecisionThresholds>(std::move(loaded));
    return config;
}

void report_dpdk_failure(std::string_view stage, int result) {
    const auto error = result < 0 ? -result : rte_errno;
    std::cerr
        << "DPDK live failure: stage=" << stage
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
            std::cerr << "DPDK live failure: invalid port id " << port_id << '\n';
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
                << "DPDK live failure: requested MTU " << mtu
                << " is outside device range [" << device_info.min_mtu
                << "," << device_info.max_mtu << "]\n";
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
            "nids_live_pool",
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
            const auto promiscuous_result =
                rte_eth_promiscuous_enable(port_id_);
            if (promiscuous_result != 0) {
                report_dpdk_failure(
                    "eth_promiscuous_enable",
                    promiscuous_result);
                return false;
            }
            if (rte_eth_promiscuous_get(port_id_) != 1) {
                std::cerr
                    << "DPDK live failure: promiscuous mode did not remain enabled\n";
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

struct LatencySummary {
    std::uint64_t observations{};
    std::uint64_t samples{};
    std::uint64_t p50_ns{};
    std::uint64_t p95_ns{};
    std::uint64_t p99_ns{};
    std::uint64_t maximum_ns{};
};

class LatencySamples final {
public:
    void record(std::uint64_t value) {
        ++observations_;
        if (values_.size() < sample_limit) {
            values_.push_back(value);
        }
    }

    [[nodiscard]] LatencySummary summary() const {
        if (values_.empty()) {
            return LatencySummary{observations_};
        }
        auto ordered = values_;
        std::sort(ordered.begin(), ordered.end());
        return LatencySummary{
            observations_,
            static_cast<std::uint64_t>(ordered.size()),
            percentile(ordered, 50U),
            percentile(ordered, 95U),
            percentile(ordered, 99U),
            ordered.back(),
        };
    }

private:
    [[nodiscard]] static std::uint64_t percentile(
        const std::vector<std::uint64_t>& ordered,
        std::size_t percentage) {
        const auto rank =
            (ordered.size() * percentage + 99U) / 100U;
        return ordered[std::max<std::size_t>(rank, 1U) - 1U];
    }

    static constexpr std::size_t sample_limit{1'000'000U};
    std::vector<std::uint64_t> values_{};
    std::uint64_t observations_{};
};

class LivePipeline final : public nids::FlowObserver {
public:
    LivePipeline(
        const nids::DetectionPipeline& detection,
        bool collect_benchmark_metrics,
        bool inference_enabled)
        : detection_{detection},
          table_{*this},
          collect_benchmark_metrics_{collect_benchmark_metrics},
          inference_enabled_{inference_enabled} {
    }

    void record_parse_latency(std::uint64_t value) {
        if (collect_benchmark_metrics_) {
            parse_latency_.record(value);
        }
    }

    void record_pipeline_latency(std::uint64_t value) {
        if (collect_benchmark_metrics_) {
            pipeline_latency_.record(value);
        }
    }

    void process(const nids::DpdkAdapterResult& adapted) noexcept {
        if (failure_.has_value()) {
            return;
        }
        if (std::holds_alternative<nids::DpdkAdapterError>(adapted)) {
            ++adapter_errors_;
            return;
        }
        const auto& event = std::get<nids::DpdkPacketEvent>(adapted);
        if (std::holds_alternative<nids::ParseError>(event.parsed)) {
            ++parser_errors_;
            return;
        }
        ++packets_parsed_;
        try {
            const auto result =
                table_.ingest(std::get<nids::PacketView>(event.parsed));
            if (result.status != nids::FlowIngestStatus::accepted) {
                ++ingest_errors_;
            }
        } catch (const std::exception& error) {
            fail(std::string{"flow ingest threw: "} + error.what());
        }
    }

    void on_packet(
        const nids::FlowState& state,
        const nids::PacketView& packet,
        const nids::FlowPacketContext& context) noexcept override {
        if (failure_.has_value() || !context.checkpoint.has_value()
            || *context.checkpoint != nids::Checkpoint::f9) {
            return;
        }
        ++f9_snapshots_;
        if (!inference_enabled_) {
            return;
        }
        const auto inference_started = std::chrono::steady_clock::now();
        try {
            const auto encoded = nids::FeatureEngine::encode(state);
            if (!std::holds_alternative<nids::FixedFeatureVector>(encoded)) {
                fail("feature encoding failed at F9");
                return;
            }
            const nids::FlowInstanceId flow_id{2U, state.generation};
            nids::SnapshotMetadata metadata;
            metadata.flow_id = flow_id;
            metadata.checkpoint = nids::Checkpoint::f9;
            metadata.packet_count = state.packet_count;
            metadata.checkpoint_timestamp_ns = packet.timestamp_ns;
            metadata.clock_domain = state.clock_domain;
            metadata.packet_sequence_prefix = {flow_id, 9U};
            auto snapshot = nids::make_checkpoint_snapshot(
                metadata,
                std::get<nids::FixedFeatureVector>(encoded),
                true);
            if (!std::holds_alternative<nids::CheckpointSnapshot>(snapshot)) {
                fail("checkpoint construction failed at F9");
                return;
            }
            const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            const auto detection_delay_ns = now_ns > packet.timestamp_ns
                ? static_cast<std::uint64_t>(now_ns - packet.timestamp_ns)
                : 0U;
            auto result = detection_.process(
                state.identity,
                std::get<nids::CheckpointSnapshot>(snapshot),
                detection_delay_ns);
            if (collect_benchmark_metrics_) {
                inference_latency_.record(elapsed_ns(inference_started));
            }
            if (std::holds_alternative<nids::DetectionPipelineError>(result)) {
                fail(
                    std::get<nids::DetectionPipelineError>(
                        std::move(result))
                        .detail);
                return;
            }
            if (std::holds_alternative<nids::NoDetectionAlert>(result)) {
                ++benign_decisions_;
                return;
            }
            auto alert =
                std::get<nids::DetectionAlert>(std::move(result));
            count(alert.decision.classification);
            std::cout << alert.json_line << std::flush;
            if (!std::cout.good()) {
                fail("stdout failed while writing an alert");
                return;
            }
            if (collect_benchmark_metrics_) {
                const auto alert_emitted_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count();
                alert_latency_.record(
                    alert_emitted_ns > packet.timestamp_ns
                        ? static_cast<std::uint64_t>(
                            alert_emitted_ns - packet.timestamp_ns)
                        : 0U);
            }
            ++alerts_;
        } catch (const std::exception& error) {
            fail(std::string{"F9 live callback failed: "} + error.what());
        }
    }

    void on_close(
        const nids::FlowState&,
        nids::FlowCloseReason) noexcept override {
    }

    void flush() noexcept {
        try {
            table_.flush();
        } catch (const std::exception& error) {
            fail(std::string{"flow flush failed: "} + error.what());
        }
    }

    [[nodiscard]] const std::optional<std::string>& failure() const noexcept {
        return failure_;
    }

    [[nodiscard]] std::uint64_t packets_parsed() const noexcept {
        return packets_parsed_;
    }

    [[nodiscard]] std::uint64_t parser_errors() const noexcept {
        return parser_errors_;
    }

    [[nodiscard]] std::uint64_t adapter_errors() const noexcept {
        return adapter_errors_;
    }

    [[nodiscard]] std::uint64_t ingest_errors() const noexcept {
        return ingest_errors_;
    }

    [[nodiscard]] std::uint64_t f9_snapshots() const noexcept {
        return f9_snapshots_;
    }

    [[nodiscard]] std::uint64_t alerts() const noexcept {
        return alerts_;
    }

    [[nodiscard]] std::uint64_t benign_decisions() const noexcept {
        return benign_decisions_;
    }

    [[nodiscard]] std::uint64_t known_attacks() const noexcept {
        return known_attacks_;
    }

    [[nodiscard]] std::uint64_t unknown_candidates() const noexcept {
        return unknown_candidates_;
    }

    [[nodiscard]] std::uint64_t uncertain_decisions() const noexcept {
        return uncertain_decisions_;
    }

    [[nodiscard]] nids::FlowCounters flow_counters() const noexcept {
        return table_.counters();
    }

    [[nodiscard]] LatencySummary parse_latency() const {
        return parse_latency_.summary();
    }

    [[nodiscard]] LatencySummary pipeline_latency() const {
        return pipeline_latency_.summary();
    }

    [[nodiscard]] LatencySummary inference_latency() const {
        return inference_latency_.summary();
    }

    [[nodiscard]] LatencySummary alert_latency() const {
        return alert_latency_.summary();
    }

private:
    [[nodiscard]] static std::uint64_t elapsed_ns(
        std::chrono::steady_clock::time_point started) {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started)
                .count());
    }

    void fail(std::string detail) {
        if (!failure_.has_value()) {
            failure_ = std::move(detail);
        }
    }

    void count(nids::DetectionDecision decision) noexcept {
        switch (decision) {
        case nids::DetectionDecision::benign:
            ++benign_decisions_;
            break;
        case nids::DetectionDecision::known_attack:
            ++known_attacks_;
            break;
        case nids::DetectionDecision::unknown_candidate:
            ++unknown_candidates_;
            break;
        case nids::DetectionDecision::uncertain:
            ++uncertain_decisions_;
            break;
        }
    }

    const nids::DetectionPipeline& detection_;
    nids::FlowTable table_;
    bool collect_benchmark_metrics_{};
    bool inference_enabled_{true};
    LatencySamples parse_latency_{};
    LatencySamples pipeline_latency_{};
    LatencySamples inference_latency_{};
    LatencySamples alert_latency_{};
    std::optional<std::string> failure_{};
    std::uint64_t packets_parsed_{};
    std::uint64_t parser_errors_{};
    std::uint64_t adapter_errors_{};
    std::uint64_t ingest_errors_{};
    std::uint64_t f9_snapshots_{};
    std::uint64_t alerts_{};
    std::uint64_t benign_decisions_{};
    std::uint64_t known_attacks_{};
    std::uint64_t unknown_candidates_{};
    std::uint64_t uncertain_decisions_{};
};

[[nodiscard]] std::string_view stop_reason_name(
    std::uint64_t packets_seen,
    std::uint64_t max_packets,
    bool stop_after_alert,
    const LivePipeline& pipeline) noexcept {
    if (pipeline.failure().has_value()) {
        return "pipeline_failure";
    }
    if (stop_requested != 0) {
        return "signal";
    }
    if (stop_after_alert && pipeline.alerts() != 0U) {
        return "alert";
    }
    if (max_packets != 0U && packets_seen >= max_packets) {
        return "packet_limit";
    }
    return "idle_timeout";
}

[[nodiscard]] bool is_continuous(const Arguments& arguments) noexcept {
    return arguments.max_packets == 0U
        && arguments.idle_timeout.count() == 0
        && !arguments.stop_after_alert;
}

void print_ready(const Arguments& arguments) {
    std::cerr
        << "[NIDS] sensor ready\n"
        << "[NIDS] listening...\n";
    std::cout
        << "{\"event_type\":\"nids_dpdk_live_ready\""
        << ",\"status\":\"ready\""
        << ",\"calibrated_thresholds\":"
        << (arguments.thresholds.has_value() ? "true" : "false")
        << ",\"bounded\":"
        << (is_continuous(arguments) ? "false" : "true")
        << ",\"continuous\":"
        << (is_continuous(arguments) ? "true" : "false")
        << ",\"port_id\":" << arguments.port_id
        << ",\"checkpoint\":\"F9\""
        << ",\"mtu\":" << arguments.mtu
        << ",\"mbuf_pool_capacity\":" << live_mbuf_pool_capacity
        << ",\"max_packets\":" << arguments.max_packets
        << ",\"max_parser_errors\":" << arguments.max_parser_errors
        << ",\"stop_after_alert\":"
        << (arguments.stop_after_alert ? "true" : "false")
        << ",\"benchmark_metrics\":"
        << (arguments.benchmark_metrics ? "true" : "false")
        << ",\"inference_enabled\":"
        << (arguments.disable_inference ? "false" : "true")
        << ",\"arm_timeout_ms\":" << arguments.arm_timeout.count()
        << ",\"idle_timeout_ms\":" << arguments.idle_timeout.count()
        << "}\n"
        << std::flush;
}

void print_latency(
    std::string_view name,
    const LatencySummary& summary) {
    std::cout
        << '"' << name << "\":{"
        << "\"observations\":" << summary.observations
        << ",\"samples\":" << summary.samples
        << ",\"sampling\":\"first_1000000\""
        << ",\"p50\":" << summary.p50_ns
        << ",\"p95\":" << summary.p95_ns
        << ",\"p99\":" << summary.p99_ns
        << ",\"max\":" << summary.maximum_ns
        << '}';
}

[[nodiscard]] std::uint64_t timeval_microseconds(const timeval& value) noexcept {
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000U
        + static_cast<std::uint64_t>(value.tv_usec);
}

void print_summary(
    bool passed,
    const Arguments& arguments,
    std::string_view stop_reason,
    std::uint64_t packets_seen,
    std::chrono::milliseconds duration,
    std::chrono::nanoseconds active_duration,
    const LivePipeline& pipeline,
    const std::optional<rte_eth_stats>& stats,
    const std::optional<rusage>& usage_started) {
    const auto flow_counters = pipeline.flow_counters();
    const auto active_seconds =
        static_cast<double>(active_duration.count()) / 1'000'000'000.0;
    rusage usage{};
    const auto usage_available =
        usage_started.has_value() && getrusage(RUSAGE_SELF, &usage) == 0;
    const auto user_cpu_us = usage_available
        ? timeval_microseconds(usage.ru_utime)
            - timeval_microseconds(usage_started->ru_utime)
        : 0U;
    const auto system_cpu_us = usage_available
        ? timeval_microseconds(usage.ru_stime)
            - timeval_microseconds(usage_started->ru_stime)
        : 0U;
    std::cout
        << "{\"event_type\":\"nids_dpdk_live_summary\""
        << ",\"status\":\"" << (passed ? "passed" : "failed") << '"'
        << ",\"calibrated_thresholds\":"
        << (arguments.thresholds.has_value() ? "true" : "false")
        << ",\"bounded\":"
        << (is_continuous(arguments) ? "false" : "true")
        << ",\"continuous\":"
        << (is_continuous(arguments) ? "true" : "false")
        << ",\"stop_reason\":\"" << stop_reason << '"'
        << ",\"port_id\":" << arguments.port_id
        << ",\"mtu\":" << arguments.mtu
        << ",\"mbuf_pool_capacity\":" << live_mbuf_pool_capacity
        << ",\"duration_ms\":" << duration.count()
        << ",\"active_duration_ns\":" << active_duration.count()
        << ",\"packets_seen\":" << packets_seen
        << ",\"packets_parsed\":" << pipeline.packets_parsed()
        << ",\"parser_errors\":" << pipeline.parser_errors()
        << ",\"adapter_errors\":" << pipeline.adapter_errors()
        << ",\"ingest_errors\":" << pipeline.ingest_errors()
        << ",\"max_parser_errors\":" << arguments.max_parser_errors
        << ",\"f9_snapshots\":" << pipeline.f9_snapshots()
        << ",\"alerts\":" << pipeline.alerts()
        << ",\"benign\":" << pipeline.benign_decisions()
        << ",\"known_attack\":" << pipeline.known_attacks()
        << ",\"unknown_candidate\":" << pipeline.unknown_candidates()
        << ",\"uncertain\":" << pipeline.uncertain_decisions()
        << ",\"port_stats_available\":"
        << (stats.has_value() ? "true" : "false")
        << ",\"port_ipackets\":"
        << (stats.has_value() ? stats->ipackets : 0U)
        << ",\"port_imissed\":"
        << (stats.has_value() ? stats->imissed : 0U)
        << ",\"port_rx_nombuf\":"
        << (stats.has_value() ? stats->rx_nombuf : 0U)
        << ",\"benchmark_metrics\":"
        << (arguments.benchmark_metrics ? "true" : "false")
        << ",\"inference_enabled\":"
        << (arguments.disable_inference ? "false" : "true")
        << ",\"packets_per_second\":"
        << (active_seconds > 0.0
                ? static_cast<double>(packets_seen) / active_seconds
                : 0.0)
        << ",\"flows_per_second\":"
        << (active_seconds > 0.0
                ? static_cast<double>(flow_counters.flow_generations_created)
                    / active_seconds
                : 0.0)
        << ",\"flow_generations_created\":"
        << flow_counters.flow_generations_created
        << ",\"flows_closed\":" << flow_counters.flows_closed
        << ",\"active_flows\":" << flow_counters.active_flow_count
        << ",\"peak_active_flows\":" << flow_counters.peak_active_flow_count
        << ",\"peak_flow_memory_bytes\":"
        << flow_counters.peak_memory_bytes
        << ",\"process_resource\":{\"available\":"
        << (usage_available ? "true" : "false")
        << ",\"user_cpu_us\":" << user_cpu_us
        << ",\"system_cpu_us\":" << system_cpu_us
        << ",\"max_rss_kb\":"
        << (usage_available ? usage.ru_maxrss : 0)
        << "},\"alert_queue\":{\"implemented\":false"
        << ",\"pressure_available\":false}";
    if (arguments.benchmark_metrics) {
        std::cout << ",\"latency_ns\":{";
        print_latency("parse", pipeline.parse_latency());
        std::cout << ',';
        print_latency("pipeline", pipeline.pipeline_latency());
        std::cout << ',';
        print_latency("inference", pipeline.inference_latency());
        std::cout << ',';
        print_latency("alert", pipeline.alert_latency());
        std::cout << '}';
    }
    std::cout << "}\n";
}

}

int main(int argc, char** argv) {
    const auto arguments = parse_arguments(argc, argv);
    if (!arguments.has_value()) {
        std::cerr
            << "usage: nids_dpdk_live [EAL options] --"
               " --bundle DIR --port-id N --max-packets N"
               " --min-packets N --min-f9 N --min-alerts N"
               " [--thresholds PATH --thresholds-sha256 HEX]"
               " [--max-parser-errors N]"
               " [--arm-timeout-ms N] --idle-timeout-ms N [--mtu N]"
               " [--require-promiscuous] [--stop-after-alert]"
               " [--benchmark-metrics] [--disable-inference]\n"
               "  --max-packets 0 means unlimited packets\n"
               "  --arm-timeout-ms defaults to --idle-timeout-ms\n"
               "  --idle-timeout-ms 0 disables idle shutdown\n";
        return 2;
    }

    if (const auto error = verify_threshold_artifact(*arguments);
        error.has_value()) {
        std::cerr << *error << '\n';
        return 2;
    }
    auto loaded = nids::load_model_bundle(arguments->bundle);
    if (!loaded) {
        if (loaded.error.has_value()) {
            std::cerr << loaded.error->detail << '\n';
        }
        return 2;
    }
    auto detection_config = load_detection_config(
        *arguments,
        loaded.bundle->checkpoint());
    if (std::holds_alternative<std::string>(detection_config)) {
        std::cerr << std::get<std::string>(detection_config) << '\n';
        return 2;
    }
    const nids::DetectionPipeline detection{
        *loaded.bundle,
        std::get<nids::DetectionPipelineConfig>(
            std::move(detection_config)),
    };
    LivePipeline pipeline{
        detection,
        arguments->benchmark_metrics,
        !arguments->disable_inference,
    };

    DpdkRuntime runtime;
    if (!runtime.initialize_eal(arguments->eal_argc, argv)
        || !runtime.start_port(
            arguments->port_id,
            arguments->mtu,
            arguments->require_promiscuous)) {
        return 1;
    }

    std::signal(SIGINT, request_stop);
    std::signal(SIGTERM, request_stop);
    print_ready(*arguments);

    std::uint64_t packets_seen{};
    std::array<std::uint8_t, 65'535> scratch{};
    rusage usage_started{};
    bool usage_start_available{};
    const auto started = std::chrono::steady_clock::now();
    auto last_packet = started;
    std::optional<std::chrono::steady_clock::time_point> first_packet;
    while ((arguments->max_packets == 0U
            || packets_seen < arguments->max_packets)
        && stop_requested == 0
        && (!arguments->stop_after_alert || pipeline.alerts() == 0U)
        && !pipeline.failure().has_value()) {
        std::array<rte_mbuf*, 32> received{};
        const auto count = rte_eth_rx_burst(
            arguments->port_id,
            0U,
            received.data(),
            static_cast<std::uint16_t>(received.size()));
        if (count == 0U) {
            const auto timeout = first_packet.has_value()
                ? arguments->idle_timeout
                : arguments->arm_timeout;
            if (timeout.count() != 0
                && std::chrono::steady_clock::now() - last_packet
                    >= timeout) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        last_packet = std::chrono::steady_clock::now();
        if (!first_packet.has_value()) {
            first_packet = last_packet;
            usage_start_available =
                getrusage(RUSAGE_SELF, &usage_started) == 0;
        }
        for (std::uint16_t index = 0; index < count; ++index) {
            auto* mbuf = received[index];
            if ((arguments->max_packets == 0U
                    || packets_seen < arguments->max_packets)
                && (!arguments->stop_after_alert || pipeline.alerts() == 0U)
                && !pipeline.failure().has_value()) {
                const auto parse_started = std::chrono::steady_clock::now();
                const auto timestamp_ns =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        parse_started.time_since_epoch())
                        .count();
                auto adapted = nids::adapt_mbuf(
                    *mbuf,
                    timestamp_ns,
                    nids::ClockDomain::monotonic,
                    scratch);
                const auto parse_finished = std::chrono::steady_clock::now();
                pipeline.record_parse_latency(
                    static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            parse_finished - parse_started)
                            .count()));
                pipeline.process(adapted);
                pipeline.record_pipeline_latency(
                    static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - parse_finished)
                            .count()));
                ++packets_seen;
            }
            rte_pktmbuf_free(mbuf);
        }
    }
    pipeline.flush();

    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    const auto active_duration = first_packet.has_value()
        ? std::chrono::duration_cast<std::chrono::nanoseconds>(
            last_packet - *first_packet)
        : std::chrono::nanoseconds{};
    const auto stats = runtime.stats();
    const auto stop_reason = stop_reason_name(
        packets_seen,
        arguments->max_packets,
        arguments->stop_after_alert,
        pipeline);
    const bool passed = !pipeline.failure().has_value()
        && packets_seen >= arguments->min_packets
        && pipeline.packets_parsed()
                + pipeline.parser_errors()
                + pipeline.adapter_errors()
            == packets_seen
        && pipeline.parser_errors() <= arguments->max_parser_errors
        && pipeline.adapter_errors() == 0U
        && pipeline.ingest_errors() == 0U
        && pipeline.f9_snapshots() >= arguments->min_f9_snapshots
        && pipeline.alerts() >= arguments->min_alerts
        && stats.has_value();
    print_summary(
        passed,
        *arguments,
        stop_reason,
        packets_seen,
        duration,
        active_duration,
        pipeline,
        stats,
        usage_start_available
            ? std::optional<rusage>{usage_started}
            : std::nullopt);
    if (!passed && pipeline.failure().has_value()) {
        std::cerr << *pipeline.failure() << '\n';
    }
    return passed && std::cout.good() ? 0 : 1;
}
