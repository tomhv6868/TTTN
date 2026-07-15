#include "nids/model_runtime.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <string>
#include <string_view>
#include <variant>

namespace {

class TestContext {
public:
    void expect(bool condition, std::string_view expression, int line) {
        if (condition) {
            return;
        }
        ++failure_count_;
        std::cerr << "line " << line << ": expected " << expression << '\n';
    }

    void expect_close(
        double observed,
        double expected,
        double tolerance,
        std::string_view expression,
        int line) {
        const auto difference = std::abs(observed - expected);
        if (std::isfinite(observed) && difference <= tolerance) {
            return;
        }
        ++failure_count_;
        std::cerr << "line " << line << ": " << expression
                  << " observed=" << observed
                  << " expected=" << expected
                  << " difference=" << difference
                  << " tolerance=" << tolerance << '\n';
    }

    [[nodiscard]] int failure_count() const noexcept {
        return failure_count_;
    }

private:
    int failure_count_{};
};

#define EXPECT(context, expression) (context).expect((expression), #expression, __LINE__)
#define EXPECT_CLOSE(context, observed, expected, tolerance) \
    (context).expect_close( \
        (observed), \
        (expected), \
        (tolerance), \
        #observed, \
        __LINE__)

inline constexpr double parity_absolute_tolerance = 1e-5;
inline constexpr std::string_view parity_record_prefix = "T53_PARITY_JSON ";
inline constexpr std::array<double, nids::known_family_count_v1>
    expected_known_probabilities{
        0.22,
        0.17333333333333334,
        0.023333333333333334,
        0.03,
        0.03333333333333333,
        0.02666666666666667,
        0.13,
        0.29333333333333333,
        0.013333333333333334,
        0.056666666666666664,
        0.0,
        0.0,
        0.0,
    };

struct ParityCase {
    std::string_view id;
    nids::FixedFeatureVector features{};
};

[[nodiscard]] std::array<ParityCase, 6> parity_cases() {
    std::array<ParityCase, 6> cases{{
        {"ascending", {}},
        {"zeros", {}},
        {"negative", {}},
        {"alternating", {}},
        {"wide", {}},
        {"missing", {}},
    }};
    for (std::size_t index = 0; index < nids::flow_feature_count_v1; ++index) {
        const auto ordinal = static_cast<double>(index + 1U);
        cases[0].features[index] = ordinal;
        cases[1].features[index] = 0.0;
        cases[2].features[index] = -ordinal;
        cases[3].features[index] =
            index % 2U == 0U ? -0.5 * ordinal : 1.5 * ordinal;
        cases[4].features[index] =
            (static_cast<double>(index) - 27.0) * 1000.0;
        cases[5].features[index] =
            index % 7U == 0U
            ? std::numeric_limits<double>::quiet_NaN()
            : ordinal;
    }
    return cases;
}

void emit_parity_record(
    nids::Checkpoint checkpoint,
    std::string_view case_id,
    const nids::ModelScores& scores) {
    std::cout << parity_record_prefix
              << "{\"case_id\":\"" << case_id
              << "\",\"checkpoint\":\"F"
              << nids::checkpoint_packet_count(checkpoint)
              << "\",\"scores\":{"
              << "\"flow_attack_probability\":"
              << static_cast<double>(scores.flow_attack_probability)
              << ",\"flow_attack\":"
              << (scores.flow_attack ? "true" : "false")
              << ",\"known_family_probabilities\":[";
    for (std::size_t index = 0; index < nids::known_family_count_v1; ++index) {
        if (index != 0U) {
            std::cout << ',';
        }
        std::cout << static_cast<double>(
            scores.known_family_probabilities[index]);
    }
    std::cout << "],\"known_family_index\":" << scores.known_family_index
              << ",\"hbos_raw\":" << scores.hbos.raw
              << ",\"hbos_normalized\":" << scores.hbos.normalized
              << ",\"hbos_threshold_exceeded\":"
              << (scores.hbos.threshold_exceeded ? "true" : "false")
              << ",\"isolation_forest_raw\":"
              << scores.isolation_forest.raw
              << ",\"isolation_forest_normalized\":"
              << scores.isolation_forest.normalized
              << ",\"isolation_forest_threshold_exceeded\":"
              << (
                     scores.isolation_forest.threshold_exceeded
                     ? "true"
                     : "false")
              << "}}\n";
}

[[nodiscard]] int emit_parity_matrix(
    const std::filesystem::path& staged_directory) {
    auto loaded = nids::load_model_bundle(staged_directory);
    if (!loaded) {
        if (loaded.error.has_value()) {
            std::cerr << loaded.error->detail << '\n';
        }
        return 1;
    }
    std::cout << std::setprecision(std::numeric_limits<double>::max_digits10);
    for (const auto& item : parity_cases()) {
        const auto result = loaded.bundle->infer(item.features);
        if (std::holds_alternative<nids::ModelRuntimeError>(result)) {
            std::cerr
                << "native parity inference failed for case " << item.id
                << ": "
                << std::get<nids::ModelRuntimeError>(result).detail
                << '\n';
            return 1;
        }
        emit_parity_record(
            loaded.bundle->checkpoint(),
            item.id,
            std::get<nids::ModelScores>(result));
    }
    return 0;
}

[[nodiscard]] bool equal_scores(
    const nids::ModelScores& left,
    const nids::ModelScores& right) {
    return left.flow_attack_probability == right.flow_attack_probability
        && left.flow_attack == right.flow_attack
        && left.known_family_probabilities == right.known_family_probabilities
        && left.known_family_index == right.known_family_index
        && left.known_family_confidence == right.known_family_confidence
        && left.hbos.raw == right.hbos.raw
        && left.hbos.normalized == right.hbos.normalized
        && left.hbos.threshold_exceeded == right.hbos.threshold_exceeded
        && left.isolation_forest.raw == right.isolation_forest.raw
        && left.isolation_forest.normalized
            == right.isolation_forest.normalized
        && left.isolation_forest.threshold_exceeded
            == right.isolation_forest.threshold_exceeded;
}

void test_missing_bundle(TestContext& test) {
    const auto missing = nids::load_model_bundle(
        std::filesystem::path{"/definitely/missing/nids-bundle"});
    EXPECT(test, !missing);
    EXPECT(test, missing.error.has_value());
    if (missing.error.has_value()) {
        EXPECT(
            test,
            missing.error->code
                == nids::ModelRuntimeErrorCode::invalid_bundle_path);
    }
}

void test_manifest_drift(
    TestContext& test,
    const std::filesystem::path& staged_directory) {
    const auto suffix = std::chrono::steady_clock::now()
        .time_since_epoch()
        .count();
    const auto temporary = std::filesystem::temp_directory_path()
        / ("nids-t52-manifest-drift-" + std::to_string(suffix));
    std::filesystem::create_directories(temporary);
    try {
        const auto manifest = temporary / "manifest.json";
        std::filesystem::copy_file(
            staged_directory / "manifest.json",
            manifest);
        std::ofstream output(manifest, std::ios::app);
        output << '\n';
        output.close();
        const auto drift = nids::load_model_bundle(temporary);
        EXPECT(test, !drift);
        EXPECT(test, drift.error.has_value());
        if (drift.error.has_value()) {
            EXPECT(
                test,
                drift.error->code
                    == nids::ModelRuntimeErrorCode::integrity_mismatch);
        }
    } catch (...) {
        std::filesystem::remove_all(temporary);
        throw;
    }
    std::filesystem::remove_all(temporary);
}

void test_real_bundle(
    TestContext& test,
    const std::filesystem::path& staged_directory) {
    auto loaded = nids::load_model_bundle(staged_directory);
    EXPECT(test, static_cast<bool>(loaded));
    if (!loaded) {
        if (loaded.error.has_value()) {
            std::cerr << loaded.error->detail << '\n';
        }
        return;
    }
    auto& bundle = *loaded.bundle;
    EXPECT(test, nids::checkpoint_packet_count(bundle.checkpoint()) == 9U);
    EXPECT(test, bundle.known_family_names().size() == nids::known_family_count_v1);
    EXPECT(
        test,
        std::ranges::all_of(
            bundle.known_family_names(),
            [](const std::string& value) { return !value.empty(); }));

    nids::FixedFeatureVector features{};
    for (std::size_t index = 0; index < features.size(); ++index) {
        features[index] = static_cast<double>(index + 1U);
    }
    const auto first = bundle.infer(features);
    const auto second = bundle.infer(features);
    EXPECT(test, std::holds_alternative<nids::ModelScores>(first));
    EXPECT(test, std::holds_alternative<nids::ModelScores>(second));
    if (!std::holds_alternative<nids::ModelScores>(first)
        || !std::holds_alternative<nids::ModelScores>(second)) {
        return;
    }
    const auto& scores = std::get<nids::ModelScores>(first);
    EXPECT(test, equal_scores(scores, std::get<nids::ModelScores>(second)));
    EXPECT(test, std::isfinite(scores.flow_attack_probability));
    EXPECT(test, scores.flow_attack_probability >= 0.0F);
    EXPECT(test, scores.flow_attack_probability <= 1.0F);
    EXPECT(test, scores.known_family_index < nids::known_family_count_v1);
    EXPECT(
        test,
        scores.known_family_confidence
            == scores.known_family_probabilities[scores.known_family_index]);
    const auto known_probability_sum = std::accumulate(
        scores.known_family_probabilities.begin(),
        scores.known_family_probabilities.end(),
        0.0);
    EXPECT(test, std::abs(known_probability_sum - 1.0) <= 1e-4);
    EXPECT(test, std::isfinite(scores.hbos.raw));
    EXPECT(test, std::isfinite(scores.hbos.normalized));
    EXPECT(test, std::isfinite(scores.isolation_forest.raw));
    EXPECT(test, std::isfinite(scores.isolation_forest.normalized));
    EXPECT_CLOSE(
        test,
        scores.flow_attack_probability,
        0.15333333333333332,
        parity_absolute_tolerance);
    EXPECT(test, !scores.flow_attack);
    for (std::size_t index = 0; index < expected_known_probabilities.size();
         ++index) {
        EXPECT_CLOSE(
            test,
            scores.known_family_probabilities[index],
            expected_known_probabilities[index],
            parity_absolute_tolerance);
    }
    EXPECT(test, scores.known_family_index == 7U);
    EXPECT_CLOSE(
        test,
        scores.hbos.raw,
        6.134572512395559,
        parity_absolute_tolerance);
    EXPECT_CLOSE(
        test,
        scores.hbos.normalized,
        14.407523268767934,
        parity_absolute_tolerance);
    EXPECT(test, scores.hbos.threshold_exceeded);
    EXPECT_CLOSE(
        test,
        scores.isolation_forest.raw,
        0.6761065713939267,
        parity_absolute_tolerance);
    EXPECT_CLOSE(
        test,
        scores.isolation_forest.normalized,
        6.191863938446235,
        parity_absolute_tolerance);
    EXPECT(test, scores.isolation_forest.threshold_exceeded);

    features[0] = std::numeric_limits<double>::infinity();
    const auto invalid = bundle.infer(features);
    EXPECT(test, std::holds_alternative<nids::ModelRuntimeError>(invalid));
    if (std::holds_alternative<nids::ModelRuntimeError>(invalid)) {
        EXPECT(
            test,
            std::get<nids::ModelRuntimeError>(invalid).code
                == nids::ModelRuntimeErrorCode::invalid_input);
    }

    std::cout
        << "[native runtime parity] status=passed checkpoint=F"
        << nids::checkpoint_packet_count(bundle.checkpoint())
        << " absolute_tolerance=" << parity_absolute_tolerance
        << " flow_attack_probability=" << scores.flow_attack_probability
        << " known_family="
        << bundle.known_family_names()[scores.known_family_index]
        << " known_confidence=" << scores.known_family_confidence
        << " hbos_normalized=" << scores.hbos.normalized
        << " iforest_normalized=" << scores.isolation_forest.normalized
        << '\n';
}

}

int main(int argc, char** argv) {
    if (argc == 3 && std::string_view{argv[2]} == "--emit-matrix") {
        return emit_parity_matrix(argv[1]);
    }
    if (argc != 2) {
        std::cerr
            << "usage: nids_model_runtime_test <staged-bundle-directory> "
               "[--emit-matrix]\n";
        return 2;
    }
    TestContext test;
    test_missing_bundle(test);
    test_manifest_drift(test, argv[1]);
    test_real_bundle(test, argv[1]);
    return test.failure_count() == 0 ? 0 : 1;
}
