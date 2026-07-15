#include "nids/latency_samples.hpp"

#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failures_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    [[nodiscard]] int failures() const noexcept {
        return failures_;
    }

private:
    int failures_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)

/// An empty collector must report nothing, not a zero latency.
void empty_collector_reports_no_samples(TestContext& context) {
    const nids::LatencySamples samples;
    const auto summary = samples.summary();
    EXPECT(context, summary.observations == 0U);
    EXPECT(context, summary.samples == 0U);
    EXPECT(context, summary.p50_ns == 0U);
    EXPECT(context, summary.maximum_ns == 0U);
}

void single_value_collapses_every_percentile(TestContext& context) {
    nids::LatencySamples samples;
    samples.record(4'242U);
    const auto summary = samples.summary();
    EXPECT(context, summary.observations == 1U);
    EXPECT(context, summary.samples == 1U);
    EXPECT(context, summary.p50_ns == 4'242U);
    EXPECT(context, summary.p95_ns == 4'242U);
    EXPECT(context, summary.p99_ns == 4'242U);
    EXPECT(context, summary.maximum_ns == 4'242U);
}

/// Nearest-rank on 1..100 puts p50 at 50, p95 at 95, p99 at 99.
/// This must match the F9 sensor exactly or the two tables cannot be compared.
void nearest_rank_matches_the_f9_sensor(TestContext& context) {
    nids::LatencySamples samples;
    for (std::uint64_t value = 1U; value <= 100U; ++value) {
        samples.record(value);
    }
    const auto summary = samples.summary();
    EXPECT(context, summary.observations == 100U);
    EXPECT(context, summary.samples == 100U);
    EXPECT(context, summary.p50_ns == 50U);
    EXPECT(context, summary.p95_ns == 95U);
    EXPECT(context, summary.p99_ns == 99U);
    EXPECT(context, summary.maximum_ns == 100U);
}

/// Percentiles are order independent: recording shuffled input gives the same
/// answer, because summary() sorts a copy.
void insertion_order_does_not_change_the_result(TestContext& context) {
    nids::LatencySamples ascending;
    nids::LatencySamples descending;
    for (std::uint64_t value = 1U; value <= 100U; ++value) {
        ascending.record(value);
        descending.record(101U - value);
    }
    const auto first = ascending.summary();
    const auto second = descending.summary();
    EXPECT(context, first.p50_ns == second.p50_ns);
    EXPECT(context, first.p95_ns == second.p95_ns);
    EXPECT(context, first.p99_ns == second.p99_ns);
    EXPECT(context, first.maximum_ns == second.maximum_ns);
}

void percentiles_are_monotonic(TestContext& context) {
    nids::LatencySamples samples;
    for (std::uint64_t value = 0U; value < 1'000U; ++value) {
        samples.record((value * 7U) % 991U);
    }
    const auto summary = samples.summary();
    EXPECT(context, summary.p50_ns <= summary.p95_ns);
    EXPECT(context, summary.p95_ns <= summary.p99_ns);
    EXPECT(context, summary.p99_ns <= summary.maximum_ns);
}

/// Zero is a legitimate observation and must not be dropped.
void zero_is_recorded_like_any_other_value(TestContext& context) {
    nids::LatencySamples samples;
    samples.record(0U);
    samples.record(0U);
    samples.record(10U);
    const auto summary = samples.summary();
    EXPECT(context, summary.observations == 3U);
    EXPECT(context, summary.samples == 3U);
    EXPECT(context, summary.p50_ns == 0U);
    EXPECT(context, summary.maximum_ns == 10U);
}

void observations_accessor_tracks_every_record(TestContext& context) {
    nids::LatencySamples samples;
    EXPECT(context, samples.observations() == 0U);
    samples.record(1U);
    samples.record(2U);
    EXPECT(context, samples.observations() == 2U);
}

}  // namespace

int main() {
    TestContext context;
    empty_collector_reports_no_samples(context);
    single_value_collapses_every_percentile(context);
    nearest_rank_matches_the_f9_sensor(context);
    insertion_order_does_not_change_the_result(context);
    percentiles_are_monotonic(context);
    zero_is_recorded_like_any_other_value(context);
    observations_accessor_tracks_every_record(context);

    if (context.failures() != 0) {
        std::cerr << context.failures() << " check(s) failed\n";
        return 1;
    }
    std::cout << "{\"status\":\"passed\",\"test\":\"nids_latency_samples\"}\n";
    return 0;
}
