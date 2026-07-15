#include "nids/model_runtime.hpp"
#include "nids/terminal_model_runtime.hpp"

#include <jansson.h>

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace {

using JsonDocument = std::unique_ptr<json_t, decltype(&json_decref)>;

class TestContext {
public:
    void expect(
        bool condition,
        std::string_view expression,
        int line,
        std::string_view context = {}) {
        if (condition) {
            return;
        }
        ++failure_count_;
        std::cerr << "line " << line << ": expected " << expression;
        if (!context.empty()) {
            std::cerr << " [" << context << ']';
        }
        std::cerr << '\n';
    }

    [[nodiscard]] int failure_count() const noexcept {
        return failure_count_;
    }

private:
    int failure_count_{};
};

#define EXPECT(test, expression) \
    (test).expect((expression), #expression, __LINE__)
#define EXPECT_CASE(test, expression, context) \
    (test).expect((expression), #expression, __LINE__, (context))

[[nodiscard]] JsonDocument load_json(const std::filesystem::path& path) {
    json_error_t error{};
    const auto native = path.string();
    JsonDocument document{
        json_load_file(native.c_str(), JSON_REJECT_DUPLICATES, &error),
        &json_decref,
    };
    if (!document) {
        std::ostringstream message;
        message << "cannot load " << path.string() << " at line "
                << error.line << ", column " << error.column << ": "
                << error.text;
        throw std::runtime_error(message.str());
    }
    return document;
}

[[nodiscard]] json_t* member(json_t* object, std::string_view name) {
    if (!json_is_object(object)) {
        throw std::runtime_error("JSON parent is not an object");
    }
    auto* const value = json_object_get(
        object,
        std::string{name}.c_str());
    if (value == nullptr) {
        throw std::runtime_error("missing JSON member: " + std::string{name});
    }
    return value;
}

[[nodiscard]] json_t* array_member(
    json_t* object,
    std::string_view name,
    std::size_t size) {
    auto* const value = member(object, name);
    if (!json_is_array(value) || json_array_size(value) != size) {
        throw std::runtime_error(
            "invalid JSON array: " + std::string{name});
    }
    return value;
}

[[nodiscard]] std::string_view string_member(
    json_t* object,
    std::string_view name) {
    auto* const value = member(object, name);
    if (!json_is_string(value)) {
        throw std::runtime_error(
            "invalid JSON string: " + std::string{name});
    }
    return json_string_value(value);
}

[[nodiscard]] std::int64_t integer_member(
    json_t* object,
    std::string_view name) {
    auto* const value = member(object, name);
    if (!json_is_integer(value)) {
        throw std::runtime_error(
            "invalid JSON integer: " + std::string{name});
    }
    return json_integer_value(value);
}

[[nodiscard]] double number_member(
    json_t* object,
    std::string_view name) {
    auto* const value = member(object, name);
    if (!json_is_number(value)) {
        throw std::runtime_error(
            "invalid JSON number: " + std::string{name});
    }
    const auto result = json_number_value(value);
    if (!std::isfinite(result)) {
        throw std::runtime_error(
            "non-finite JSON number: " + std::string{name});
    }
    return result;
}

[[nodiscard]] std::string file_sha256(
    const std::filesystem::path& path) {
    auto digest = nids::compute_file_sha256(path);
    if (std::holds_alternative<nids::ModelRuntimeError>(digest)) {
        throw std::runtime_error(
            std::get<nids::ModelRuntimeError>(digest).detail);
    }
    return std::get<std::string>(std::move(digest));
}

class TemporaryBundle {
public:
    explicit TemporaryBundle(const std::filesystem::path& source) {
        const auto nonce = std::chrono::steady_clock::now()
            .time_since_epoch()
            .count();
        path_ = std::filesystem::temp_directory_path()
            / ("nids-t91-terminal-runtime-" + std::to_string(nonce));
        std::filesystem::create_directory(path_);
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(source)) {
            const auto relative = std::filesystem::relative(
                entry.path(),
                source);
            const auto destination = path_ / relative;
            if (entry.is_directory()) {
                std::filesystem::create_directory(destination);
            } else if (entry.is_regular_file()) {
                std::filesystem::copy_file(entry.path(), destination);
            } else {
                throw std::runtime_error(
                    "unsupported source bundle entry: "
                    + entry.path().string());
            }
        }
    }

    ~TemporaryBundle() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    TemporaryBundle(const TemporaryBundle&) = delete;
    TemporaryBundle& operator=(const TemporaryBundle&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_{};
};

void dump_json(json_t* document, const std::filesystem::path& path) {
    const auto native = path.string();
    if (json_dump_file(
            document,
            native.c_str(),
            JSON_COMPACT | JSON_SORT_KEYS)
        != 0) {
        throw std::runtime_error("cannot write JSON: " + path.string());
    }
}

void refresh_manifest_member(
    const std::filesystem::path& root,
    std::string_view relative_path) {
    const auto manifest_path = root / "manifest.json";
    auto manifest = load_json(manifest_path);
    auto* const members = array_member(manifest.get(), "members", 4U);
    json_t* record = nullptr;
    for (std::size_t index = 0; index < json_array_size(members); ++index) {
        auto* const candidate = json_array_get(members, index);
        if (string_member(candidate, "path") == relative_path) {
            record = candidate;
            break;
        }
    }
    if (record == nullptr) {
        throw std::runtime_error("manifest member not found");
    }
    const auto path = root / std::filesystem::path{relative_path};
    if (json_object_set_new(
            record,
            "sha256",
            json_string(file_sha256(path).c_str()))
            != 0
        || json_object_set_new(
               record,
               "size_bytes",
               json_integer(static_cast<json_int_t>(
                   std::filesystem::file_size(path))))
            != 0) {
        throw std::runtime_error("cannot update manifest member");
    }
    dump_json(manifest.get(), manifest_path);
}

[[nodiscard]] bool expect_load_error(
    TestContext& test,
    const std::filesystem::path& path,
    std::string_view hash,
    nids::TerminalModelRuntimeErrorCode expected) {
    const auto before = test.failure_count();
    const auto result = nids::load_terminal_model_bundle(path, hash);
    EXPECT(test, !result);
    EXPECT(test, result.error.has_value());
    if (result.error.has_value()) {
        EXPECT(test, result.error->code == expected);
    }
    return test.failure_count() == before;
}

[[nodiscard]] std::size_t test_load_guards(
    TestContext& test,
    const std::filesystem::path& staged,
    std::string_view accepted_hash) {
    std::size_t passed{};
    passed += expect_load_error(
        test,
        staged / "missing",
        accepted_hash,
        nids::TerminalModelRuntimeErrorCode::invalid_bundle_path);
    passed += expect_load_error(
        test,
        staged,
        "invalid",
        nids::TerminalModelRuntimeErrorCode::integrity_mismatch);
    passed += expect_load_error(
        test,
        staged,
        std::string(64U, '0'),
        nids::TerminalModelRuntimeErrorCode::integrity_mismatch);

    {
        TemporaryBundle temporary{staged};
        std::ofstream{temporary.path() / "unexpected.txt"} << "unexpected";
        passed += expect_load_error(
            test,
            temporary.path(),
            accepted_hash,
            nids::TerminalModelRuntimeErrorCode::invalid_bundle_path);
    }
    {
        TemporaryBundle temporary{staged};
        std::ofstream{
            temporary.path() / "models" / "unexpected.onnx"} << "unexpected";
        passed += expect_load_error(
            test,
            temporary.path(),
            accepted_hash,
            nids::TerminalModelRuntimeErrorCode::invalid_bundle_path);
    }
    {
        TemporaryBundle temporary{staged};
        std::ofstream output{
            temporary.path() / "thresholds.json",
            std::ios::app,
        };
        output << '\n';
        output.close();
        passed += expect_load_error(
            test,
            temporary.path(),
            accepted_hash,
            nids::TerminalModelRuntimeErrorCode::integrity_mismatch);
    }
    {
        TemporaryBundle temporary{staged};
        const auto manifest_path = temporary.path() / "manifest.json";
        std::ifstream input{manifest_path};
        const std::string text{
            std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{},
        };
        input.close();
        std::ofstream output{manifest_path, std::ios::trunc};
        output << "{\"artifact_id\":\"duplicate\"," << text.substr(1U);
        output.close();
        passed += expect_load_error(
            test,
            temporary.path(),
            file_sha256(manifest_path),
            nids::TerminalModelRuntimeErrorCode::invalid_json);
    }
    {
        TemporaryBundle temporary{staged};
        const auto threshold_path = temporary.path() / "thresholds.json";
        auto thresholds = load_json(threshold_path);
        if (json_object_set_new(
                thresholds.get(),
                "selected_threshold",
                json_real(0.5))
            != 0) {
            throw std::runtime_error("cannot alter threshold fixture");
        }
        dump_json(thresholds.get(), threshold_path);
        refresh_manifest_member(temporary.path(), "thresholds.json");
        const auto manifest_hash = file_sha256(
            temporary.path() / "manifest.json");
        passed += expect_load_error(
            test,
            temporary.path(),
            manifest_hash,
            nids::TerminalModelRuntimeErrorCode::schema_mismatch);
    }
    return passed;
}

struct ParitySummary {
    std::size_t cases_total{};
    std::size_t cases_passed{};
    double tolerance{};
    double maximum_probability_error{};
    std::string reference_sha256{};
};

[[nodiscard]] ParitySummary test_native_parity(
    TestContext& test,
    const nids::TerminalModelBundle& bundle,
    const std::filesystem::path& reference_path,
    std::string_view accepted_hash,
    std::string_view accepted_reference_hash) {
    const auto reference_hash = file_sha256(reference_path);
    if (reference_hash != accepted_reference_hash) {
        throw std::runtime_error(
            "native parity reference hash mismatch: observed="
            + reference_hash + ", expected="
            + std::string{accepted_reference_hash});
    }
    auto reference = load_json(reference_path);
    EXPECT(test, string_member(reference.get(), "schema_version") == "1.0.0");
    EXPECT(test, string_member(reference.get(), "task") == "T9.1");
    EXPECT(
        test,
        string_member(reference.get(), "status")
            == "python_ort_passed_native_pending");
    auto* const reference_bundle = member(reference.get(), "bundle");
    EXPECT(
        test,
        string_member(reference_bundle, "manifest_sha256") == accepted_hash);
    auto* const sealed = member(reference.get(), "test_partition");
    EXPECT(test, string_member(sealed, "status") == "sealed");
    EXPECT(test, integer_member(sealed, "feature_reads") == 0);
    EXPECT(test, integer_member(sealed, "metric_reads") == 0);
    EXPECT(
        test,
        integer_member(sealed, "path_resolution_or_hash_reads") == 0);

    ParitySummary summary;
    summary.tolerance = number_member(reference.get(), "absolute_tolerance");
    summary.reference_sha256 = reference_hash;
    EXPECT(test, summary.tolerance <= 1e-5);
    auto* const cases = array_member(reference.get(), "cases", 14U);
    summary.cases_total = json_array_size(cases);
    for (std::size_t case_index = 0; case_index < summary.cases_total;
         ++case_index) {
        auto* const item = json_array_get(cases, case_index);
        const auto case_id = string_member(item, "case_id");
        auto* const input = array_member(
            item,
            "input",
            nids::terminal_model_feature_count_v1);
        auto* const bits = array_member(
            item,
            "input_float32_uint32_bits",
            nids::terminal_model_feature_count_v1);
        std::array<double, nids::terminal_feature_count> features{};
        bool bits_exact = true;
        for (std::size_t index = 0;
             index < nids::terminal_model_feature_count_v1;
             ++index) {
            auto* const value = json_array_get(input, index);
            auto* const bit_value = json_array_get(bits, index);
            if (!json_is_number(value) || !json_is_integer(bit_value)) {
                throw std::runtime_error("invalid parity input encoding");
            }
            features[index] = json_number_value(value);
            const auto expected_bits = static_cast<std::uint32_t>(
                json_integer_value(bit_value));
            bits_exact = bits_exact
                && std::bit_cast<std::uint32_t>(
                       static_cast<float>(features[index]))
                    == expected_bits;
        }

        const auto inference = bundle.infer(features);
        const bool inferred =
            std::holds_alternative<nids::TerminalModelScores>(inference);
        EXPECT_CASE(test, inferred, case_id);
        if (!inferred) {
            if (std::holds_alternative<nids::TerminalModelRuntimeError>(
                    inference)) {
                std::cerr
                    << "native inference failed [" << case_id << "]: "
                    << std::get<nids::TerminalModelRuntimeError>(inference)
                           .detail
                    << '\n';
            }
            continue;
        }

        const auto& scores = std::get<nids::TerminalModelScores>(inference);
        auto* const expected = member(item, "expected");
        auto* const probabilities = array_member(
            expected,
            "probabilities",
            nids::terminal_model_class_count_v1);
        double case_maximum_error{};
        for (std::size_t index = 0;
             index < nids::terminal_model_class_count_v1;
             ++index) {
            auto* const probability = json_array_get(probabilities, index);
            if (!json_is_number(probability)) {
                throw std::runtime_error("invalid expected probability");
            }
            case_maximum_error = std::max(
                case_maximum_error,
                std::abs(
                    static_cast<double>(scores.class_probabilities[index])
                    - json_number_value(probability)));
        }
        summary.maximum_probability_error = std::max(
            summary.maximum_probability_error,
            case_maximum_error);
        const auto expected_decision = static_cast<std::size_t>(
            integer_member(expected, "decision_index"));
        const auto expected_model_label = static_cast<std::size_t>(
            integer_member(expected, "model_label_index"));
        const auto model_top = static_cast<std::size_t>(std::distance(
            scores.class_probabilities.begin(),
            std::max_element(
                scores.class_probabilities.begin(),
                scores.class_probabilities.end())));
        const auto attack_score_error = std::abs(
            scores.attack_score
            - number_member(expected, "attack_score"));
        const bool case_passed = bits_exact
            && case_maximum_error <= summary.tolerance
            && attack_score_error <= summary.tolerance
            && scores.class_index == expected_decision
            && model_top == expected_model_label
            && scores.attack == (expected_decision != 0U)
            && bundle.class_names()[expected_decision]
                == string_member(expected, "decision")
            && bundle.class_names()[expected_model_label]
                == string_member(expected, "model_label")
            && number_member(expected, "selected_threshold")
                == bundle.attack_threshold();
        EXPECT_CASE(test, bits_exact, case_id);
        EXPECT_CASE(
            test,
            case_maximum_error <= summary.tolerance,
            case_id);
        EXPECT_CASE(
            test,
            attack_score_error <= summary.tolerance,
            case_id);
        EXPECT_CASE(test, scores.class_index == expected_decision, case_id);
        EXPECT_CASE(test, model_top == expected_model_label, case_id);
        EXPECT_CASE(
            test,
            scores.attack == (expected_decision != 0U),
            case_id);
        if (case_passed) {
            ++summary.cases_passed;
        }
    }
    return summary;
}

void test_input_guards(
    TestContext& test,
    const nids::TerminalModelBundle& bundle) {
    std::array<double, nids::terminal_feature_count> features{};
    features.back() = std::numeric_limits<double>::quiet_NaN();
    auto result = bundle.infer(features);
    EXPECT(
        test,
        std::holds_alternative<nids::TerminalModelRuntimeError>(result));
    if (std::holds_alternative<nids::TerminalModelRuntimeError>(result)) {
        EXPECT(
            test,
            std::get<nids::TerminalModelRuntimeError>(result).code
                == nids::TerminalModelRuntimeErrorCode::invalid_input);
    }

    features = {};
    features.front() = std::numeric_limits<double>::max();
    result = bundle.infer(features);
    EXPECT(
        test,
        std::holds_alternative<nids::TerminalModelRuntimeError>(result));
    if (std::holds_alternative<nids::TerminalModelRuntimeError>(result)) {
        EXPECT(
            test,
            std::get<nids::TerminalModelRuntimeError>(result).code
                == nids::TerminalModelRuntimeErrorCode::invalid_input);
    }
}

void write_receipt(
    const std::filesystem::path& path,
    bool passed,
    std::string_view manifest_hash,
    const ParitySummary& parity,
    std::size_t guards_passed) {
    std::ostringstream output;
    output << std::setprecision(std::numeric_limits<double>::max_digits10)
           << "{\"schema_version\":\"1.0.0\",\"task\":\"T9.1\""
           << ",\"kind\":\"terminal_flow_native_parity\""
           << ",\"status\":\"" << (passed ? "passed" : "failed") << '"'
           << ",\"bundle_manifest_sha256\":\"" << manifest_hash << '"'
           << ",\"reference_sha256\":\"" << parity.reference_sha256 << '"'
           << ",\"cases_total\":" << parity.cases_total
           << ",\"cases_passed\":" << parity.cases_passed
           << ",\"absolute_tolerance\":" << parity.tolerance
           << ",\"maximum_absolute_probability_error\":"
           << parity.maximum_probability_error
           << ",\"decisions_exact\":"
           << (parity.cases_passed == parity.cases_total ? "true" : "false")
           << ",\"corruption_guards_passed\":" << guards_passed
           << ",\"test_partition\":{\"status\":\"sealed\""
           << ",\"feature_reads\":0,\"metric_reads\":0"
           << ",\"path_resolution_or_hash_reads\":0}}\n";
    if (!path.empty()) {
        if (!path.parent_path().empty()) {
            std::filesystem::create_directories(path.parent_path());
        }
        std::ofstream receipt{path, std::ios::trunc};
        receipt << output.str();
        if (!receipt) {
            throw std::runtime_error("cannot write native parity receipt");
        }
    }
    std::cout << output.str();
}

}

int main(int argc, char** argv) {
    if (argc != 5 && argc != 6) {
        std::cerr
            << "usage: nids_terminal_model_runtime_test "
               "<staged-bundle-directory> <manifest-sha256> "
               "<native-parity-reference> <reference-sha256> "
               "[receipt-path]\n";
        return 2;
    }
    try {
        TestContext test;
        const std::filesystem::path staged{argv[1]};
        const std::string_view manifest_hash{argv[2]};
        const auto guards_passed = test_load_guards(
            test,
            staged,
            manifest_hash);
        auto loaded = nids::load_terminal_model_bundle(
            staged,
            manifest_hash);
        EXPECT(test, static_cast<bool>(loaded));
        if (!loaded) {
            if (loaded.error.has_value()) {
                std::cerr << loaded.error->detail << '\n';
            }
            return 1;
        }
        EXPECT(
            test,
            loaded.bundle->artifact_id()
                == "nids.terminal_flow_bundle.v1");
        EXPECT(test, loaded.bundle->artifact_version() == "1.0.0");
        EXPECT(test, loaded.bundle->profile_id() == "A");
        EXPECT(
            test,
            loaded.bundle->attack_threshold() == 0.9984837643022101);
        EXPECT(test, loaded.bundle->manifest_sha256() == manifest_hash);
        EXPECT(
            test,
            loaded.bundle->feature_schema_sha256()
                == "41bcc2fbb43f88aa3be10dad34fe65b3b50218718493810251d538616a01d596");
        EXPECT(
            test,
            loaded.bundle->model_sha256()
                == "21f3a5c4eff068d6901c88a64bb6f0aa144c0a898f565d7dfb7b9ed36362b062");

        const auto parity = test_native_parity(
            test,
            *loaded.bundle,
            argv[3],
            manifest_hash,
            argv[4]);
        test_input_guards(test, *loaded.bundle);
        const bool passed = test.failure_count() == 0
            && guards_passed == 8U
            && parity.cases_passed == parity.cases_total;
        write_receipt(
            argc == 6 ? std::filesystem::path{argv[5]}
                      : std::filesystem::path{},
            passed,
            manifest_hash,
            parity,
            guards_passed);
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "terminal native parity test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
