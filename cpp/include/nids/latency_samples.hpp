#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nids {

/// Percentiles of a latency distribution, in nanoseconds.
///
/// `observations` counts every recorded value. `samples` counts the values
/// actually retained: recording stops storing after `LatencySamples::sample_limit`
/// so a long run cannot exhaust memory. When the two differ, the percentiles
/// describe the retained prefix, not the whole run.
struct LatencySummary {
    std::uint64_t observations{};
    std::uint64_t samples{};
    std::uint64_t p50_ns{};
    std::uint64_t p95_ns{};
    std::uint64_t p99_ns{};
    std::uint64_t maximum_ns{};
};

/// Reservoir-free latency collector: keeps the first `sample_limit` values.
///
/// Deliberately identical in behaviour to the collector inside
/// `nids_dpdk_live.cpp` so numbers from the two sensors can sit in one table.
class LatencySamples final {
public:
    static constexpr std::size_t sample_limit{1'000'000U};

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

    [[nodiscard]] std::uint64_t observations() const noexcept {
        return observations_;
    }

private:
    /// Nearest-rank percentile, matching the F9 sensor exactly.
    [[nodiscard]] static std::uint64_t percentile(
        const std::vector<std::uint64_t>& ordered,
        std::size_t percentage) {
        const auto rank = (ordered.size() * percentage + 99U) / 100U;
        return ordered[std::max<std::size_t>(rank, 1U) - 1U];
    }

    std::vector<std::uint64_t> values_{};
    std::uint64_t observations_{};
};

}  // namespace nids
