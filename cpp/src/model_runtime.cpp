#include "nids/model_runtime.hpp"

#include <jansson.h>
#include <onnxruntime_cxx_api.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace nids {
namespace {

inline constexpr std::array<std::string_view, flow_feature_count_v1>
    feature_names_v1{
        "flow_age_us",
        "packet_count",
        "forward_packet_count",
        "reverse_packet_count",
        "wire_byte_count",
        "forward_wire_byte_count",
        "reverse_wire_byte_count",
        "packet_length_min",
        "packet_length_max",
        "packet_length_mean",
        "packet_length_std",
        "forward_packet_length_mean",
        "forward_packet_length_std",
        "reverse_packet_length_mean",
        "reverse_packet_length_std",
        "flow_iat_min_us",
        "flow_iat_max_us",
        "flow_iat_mean_us",
        "flow_iat_std_us",
        "forward_iat_mean_us",
        "forward_iat_std_us",
        "reverse_iat_mean_us",
        "reverse_iat_std_us",
        "packet_rate_per_second",
        "wire_byte_rate_per_second",
        "forward_reverse_packet_ratio",
        "forward_reverse_wire_byte_ratio",
        "direction_change_count",
        "tcp_syn_count",
        "tcp_ack_count",
        "tcp_fin_count",
        "tcp_rst_count",
        "tcp_psh_count",
        "tcp_syn_ack_ratio",
        "tcp_initial_forward_window",
        "tcp_initial_reverse_window",
        "tcp_window_mean",
        "tcp_window_std",
        "ttl_min",
        "ttl_max",
        "ttl_mean",
        "ttl_std",
        "payload_packet_count",
        "forward_payload_packet_count",
        "reverse_payload_packet_count",
        "payload_byte_count",
        "forward_payload_byte_count",
        "reverse_payload_byte_count",
        "payload_length_min",
        "payload_length_max",
        "payload_length_mean",
        "payload_length_std",
        "header_length_mean",
        "header_length_std",
    };

inline constexpr std::array<std::string_view, 7> bundle_members{
    "feature_schema.json",
    "preprocessing.json",
    "hbos.json",
    "thresholds.json",
    "models/flow_rf.onnx",
    "models/isolation_forest.onnx",
    "models/known_family_rf.onnx",
};

inline constexpr std::array<std::uint32_t, 64> sha256_constants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

class LoadFailure final : public std::runtime_error {
public:
    LoadFailure(ModelRuntimeErrorCode error_code, std::string message)
        : std::runtime_error(std::move(message)), code(error_code) {
    }

    ModelRuntimeErrorCode code;
};

class Sha256 {
public:
    void update(std::span<const std::uint8_t> bytes) {
        total_bytes_ += bytes.size();
        std::size_t offset{};
        while (offset < bytes.size()) {
            const auto count = std::min(
                block_.size() - block_size_,
                bytes.size() - offset);
            std::copy_n(
                bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                count,
                block_.begin() + static_cast<std::ptrdiff_t>(block_size_));
            block_size_ += count;
            offset += count;
            if (block_size_ == block_.size()) {
                process(block_);
                block_size_ = 0U;
            }
        }
    }

    [[nodiscard]] std::string finish() {
        const auto bit_length = total_bytes_ * 8U;
        block_[block_size_++] = 0x80U;
        if (block_size_ > 56U) {
            std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0U);
            process(block_);
            block_size_ = 0U;
        }
        std::fill(
            block_.begin() + static_cast<std::ptrdiff_t>(block_size_),
            block_.begin() + 56,
            0U);
        for (std::size_t index = 0; index < 8U; ++index) {
            block_[63U - index] = static_cast<std::uint8_t>(
                bit_length >> (index * 8U));
        }
        process(block_);

        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (const auto value : state_) {
            output << std::setw(8) << value;
        }
        return output.str();
    }

private:
    static constexpr std::uint32_t choose(
        std::uint32_t x,
        std::uint32_t y,
        std::uint32_t z) noexcept {
        return (x & y) ^ (~x & z);
    }

    static constexpr std::uint32_t majority(
        std::uint32_t x,
        std::uint32_t y,
        std::uint32_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    void process(const std::array<std::uint8_t, 64>& block) {
        std::array<std::uint32_t, 64> schedule{};
        for (std::size_t index = 0; index < 16U; ++index) {
            const auto offset = index * 4U;
            schedule[index] =
                (static_cast<std::uint32_t>(block[offset]) << 24U)
                | (static_cast<std::uint32_t>(block[offset + 1U]) << 16U)
                | (static_cast<std::uint32_t>(block[offset + 2U]) << 8U)
                | static_cast<std::uint32_t>(block[offset + 3U]);
        }
        for (std::size_t index = 16U; index < schedule.size(); ++index) {
            const auto s0 = std::rotr(schedule[index - 15U], 7)
                ^ std::rotr(schedule[index - 15U], 18)
                ^ (schedule[index - 15U] >> 3U);
            const auto s1 = std::rotr(schedule[index - 2U], 17)
                ^ std::rotr(schedule[index - 2U], 19)
                ^ (schedule[index - 2U] >> 10U);
            schedule[index] = schedule[index - 16U]
                + s0
                + schedule[index - 7U]
                + s1;
        }

        auto a = state_[0];
        auto b = state_[1];
        auto c = state_[2];
        auto d = state_[3];
        auto e = state_[4];
        auto f = state_[5];
        auto g = state_[6];
        auto h = state_[7];
        for (std::size_t index = 0; index < schedule.size(); ++index) {
            const auto sigma1 = std::rotr(e, 6)
                ^ std::rotr(e, 11)
                ^ std::rotr(e, 25);
            const auto temporary1 = h
                + sigma1
                + choose(e, f, g)
                + sha256_constants[index]
                + schedule[index];
            const auto sigma0 = std::rotr(a, 2)
                ^ std::rotr(a, 13)
                ^ std::rotr(a, 22);
            const auto temporary2 = sigma0 + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{
        0x6a09e667U,
        0xbb67ae85U,
        0x3c6ef372U,
        0xa54ff53aU,
        0x510e527fU,
        0x9b05688cU,
        0x1f83d9abU,
        0x5be0cd19U,
    };
    std::array<std::uint8_t, 64> block_{};
    std::size_t block_size_{};
    std::uint64_t total_bytes_{};
};

struct JsonDeleter {
    void operator()(json_t* value) const noexcept {
        if (value != nullptr) {
            json_decref(value);
        }
    }
};

using JsonDocument = std::unique_ptr<json_t, JsonDeleter>;

struct Transform {
    std::array<double, flow_feature_count_v1> imputation{};
    std::vector<std::size_t> indices{};
    std::vector<double> mean{};
    std::vector<double> scale{};
};

struct HbosState {
    std::vector<std::size_t> feature_indices{};
    std::vector<std::vector<double>> edges{};
    std::vector<std::vector<double>> probabilities{};
};

struct DecisionState {
    double mean{};
    double standard_deviation{};
    double threshold{};
};

[[nodiscard]] std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw LoadFailure(
            ModelRuntimeErrorCode::invalid_bundle_path,
            "cannot open bundle member: " + path.string());
    }
    Sha256 digest;
    std::array<char, 64U * 1024U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            digest.update(std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                static_cast<std::size_t>(count),
            });
        }
    }
    if (!input.eof()) {
        throw LoadFailure(
            ModelRuntimeErrorCode::invalid_bundle_path,
            "failed reading bundle member: " + path.string());
    }
    return digest.finish();
}

[[nodiscard]] JsonDocument load_json(const std::filesystem::path& path) {
    json_error_t error{};
    JsonDocument document{
        json_load_file(path.c_str(), JSON_REJECT_DUPLICATES, &error),
    };
    if (!document || !json_is_object(document.get())) {
        throw LoadFailure(
            ModelRuntimeErrorCode::invalid_json,
            path.string() + ":" + std::to_string(error.line) + ": "
                + error.text);
    }
    return document;
}

[[nodiscard]] json_t* required_member(
    json_t* object,
    std::string_view name) {
    auto* const value = json_object_get(object, name.data());
    if (value == nullptr) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "missing JSON member: " + std::string{name});
    }
    return value;
}

[[nodiscard]] std::string_view required_string(
    json_t* object,
    std::string_view name) {
    auto* const value = required_member(object, name);
    if (!json_is_string(value)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not a string: " + std::string{name});
    }
    return json_string_value(value);
}

[[nodiscard]] double required_number(
    json_t* object,
    std::string_view name) {
    auto* const value = required_member(object, name);
    if (!json_is_number(value)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not numeric: " + std::string{name});
    }
    const auto result = json_number_value(value);
    if (!std::isfinite(result)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not finite: " + std::string{name});
    }
    return result;
}

[[nodiscard]] std::size_t required_size(
    json_t* object,
    std::string_view name) {
    auto* const value = required_member(object, name);
    if (!json_is_integer(value) || json_integer_value(value) < 0) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not a non-negative integer: " + std::string{name});
    }
    return static_cast<std::size_t>(json_integer_value(value));
}

[[nodiscard]] json_t* required_array(
    json_t* object,
    std::string_view name,
    std::optional<std::size_t> size = std::nullopt) {
    auto* const value = required_member(object, name);
    if (!json_is_array(value)
        || (size.has_value() && json_array_size(value) != *size)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "JSON member has an invalid array shape: " + std::string{name});
    }
    return value;
}

void require_string_array(
    json_t* value,
    std::span<const std::string_view> expected,
    std::string_view context) {
    if (!json_is_array(value) || json_array_size(value) != expected.size()) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "invalid string array: " + std::string{context});
    }
    for (std::size_t index = 0; index < expected.size(); ++index) {
        auto* const item = json_array_get(value, index);
        if (!json_is_string(item)
            || std::string_view{json_string_value(item)} != expected[index]) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "string array mismatch: " + std::string{context});
        }
    }
}

[[nodiscard]] std::vector<double> number_array(
    json_t* value,
    std::size_t expected_size,
    std::string_view context) {
    if (!json_is_array(value) || json_array_size(value) != expected_size) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "invalid numeric array: " + std::string{context});
    }
    std::vector<double> result;
    result.reserve(expected_size);
    for (std::size_t index = 0; index < expected_size; ++index) {
        auto* const item = json_array_get(value, index);
        if (!json_is_number(item)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "non-numeric array item: " + std::string{context});
        }
        const auto number = json_number_value(item);
        if (!std::isfinite(number)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "non-finite array item: " + std::string{context});
        }
        result.push_back(number);
    }
    return result;
}

[[nodiscard]] Checkpoint parse_checkpoint(std::string_view value) {
    if (value == "F3") {
        return Checkpoint::f3;
    }
    if (value == "F5") {
        return Checkpoint::f5;
    }
    if (value == "F7") {
        return Checkpoint::f7;
    }
    if (value == "F9") {
        return Checkpoint::f9;
    }
    throw LoadFailure(
        ModelRuntimeErrorCode::schema_mismatch,
        "unsupported checkpoint: " + std::string{value});
}

[[nodiscard]] std::string_view accepted_manifest_hash(
    Checkpoint checkpoint) noexcept {
    switch (checkpoint) {
    case Checkpoint::f3:
        return "3f3afe923475ae76076d3436fd3a479a1e6881160c4c534c1a5dbf1e32c198eb";
    case Checkpoint::f5:
        return "478ab8f130f9ec5afeae2425b223aabeb8f71473c071dcc4db389b57ea526749";
    case Checkpoint::f7:
        return "df92eb21c25edb816742e3b8e906ab393e5302e8d962a98ece75d479cc0d2923";
    case Checkpoint::f9:
        return "ca60467ae2e721bcb59d15afdf0e9e2cb031958e40b98548b50b58e998af1a3d";
    }
    return {};
}

void verify_manifest_and_members(
    const std::filesystem::path& root,
    json_t* manifest,
    Checkpoint checkpoint) {
    if (required_string(manifest, "artifact_id")
            != "nids.native_inference_bundle.v1"
        || required_string(manifest, "artifact_version") != "1.0.0"
        || required_string(manifest, "feature_schema_id")
            != "nids.flow_features.v1"
        || parse_checkpoint(required_string(manifest, "checkpoint"))
            != checkpoint) {
        throw LoadFailure(
            ModelRuntimeErrorCode::integrity_mismatch,
            "manifest identity mismatch");
    }

    const auto manifest_path = root / "manifest.json";
    if (sha256_file(manifest_path) != accepted_manifest_hash(checkpoint)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::integrity_mismatch,
            "manifest is not the accepted T5.1 artifact");
    }

    auto* const members = required_array(
        manifest,
        "members",
        bundle_members.size());
    for (std::size_t index = 0; index < bundle_members.size(); ++index) {
        auto* const record = json_array_get(members, index);
        if (!json_is_object(record)
            || required_string(record, "path") != bundle_members[index]) {
            throw LoadFailure(
                ModelRuntimeErrorCode::integrity_mismatch,
                "manifest member order mismatch");
        }
        const auto path = root / std::filesystem::path{bundle_members[index]};
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (error || !std::filesystem::is_regular_file(status)
            || std::filesystem::is_symlink(status)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::invalid_bundle_path,
                "bundle member is missing or not a regular file: "
                    + path.string());
        }
        const auto expected_size = required_size(record, "size_bytes");
        if (std::filesystem::file_size(path, error) != expected_size || error) {
            throw LoadFailure(
                ModelRuntimeErrorCode::integrity_mismatch,
                "bundle member size mismatch: " + path.string());
        }
        if (sha256_file(path) != required_string(record, "sha256")) {
            throw LoadFailure(
                ModelRuntimeErrorCode::integrity_mismatch,
                "bundle member hash mismatch: " + path.string());
        }
    }
}

void verify_feature_schema(json_t* schema) {
    if (required_string(schema, "schema_id") != "nids.flow_features.v1") {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "feature schema id mismatch");
    }
    auto* const features = required_array(
        schema,
        "features",
        flow_feature_count_v1);
    for (std::size_t index = 0; index < feature_names_v1.size(); ++index) {
        auto* const feature = json_array_get(features, index);
        if (!json_is_object(feature)
            || required_string(feature, "name") != feature_names_v1[index]) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "feature order mismatch at index " + std::to_string(index));
        }
    }
}

[[nodiscard]] Transform parse_transform(
    json_t* profile,
    std::size_t expected_output_size,
    std::string_view context) {
    if (required_string(profile, "input_dtype") != "float64"
        || required_string(profile, "output_dtype") != "float32"
        || required_string(profile, "imputer") != "median") {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "preprocessing type mismatch: " + std::string{context});
    }
    require_string_array(
        required_member(profile, "input_features"),
        feature_names_v1,
        context);

    Transform result;
    const auto imputation = number_array(
        required_member(profile, "imputation_values"),
        flow_feature_count_v1,
        context);
    std::copy(imputation.begin(), imputation.end(), result.imputation.begin());

    auto* const selected = required_array(
        profile,
        "selected_indices",
        expected_output_size);
    std::array<bool, flow_feature_count_v1> seen{};
    result.indices.reserve(expected_output_size);
    for (std::size_t index = 0; index < expected_output_size; ++index) {
        auto* const item = json_array_get(selected, index);
        if (!json_is_integer(item)
            || json_integer_value(item) < 0
            || json_integer_value(item)
                >= static_cast<json_int_t>(flow_feature_count_v1)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "invalid selected feature index: " + std::string{context});
        }
        const auto feature_index = static_cast<std::size_t>(
            json_integer_value(item));
        if (seen[feature_index]) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "duplicate selected feature index: " + std::string{context});
        }
        seen[feature_index] = true;
        result.indices.push_back(feature_index);
    }
    result.mean = number_array(
        required_member(profile, "scaler_mean"),
        expected_output_size,
        context);
    result.scale = number_array(
        required_member(profile, "scaler_scale"),
        expected_output_size,
        context);
    if (std::ranges::any_of(result.scale, [](double value) {
            return value <= 0.0;
        })) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "non-positive preprocessing scale: " + std::string{context});
    }
    return result;
}

[[nodiscard]] HbosState parse_hbos(
    json_t* document,
    Checkpoint checkpoint,
    std::size_t anomaly_feature_count) {
    if (parse_checkpoint(required_string(document, "checkpoint"))
        != checkpoint) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "HBOS checkpoint mismatch");
    }
    auto* const state = required_member(document, "state");
    if (!json_is_object(state)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "HBOS state is not an object");
    }
    const auto expected_features =
        checkpoint == Checkpoint::f3 || checkpoint == Checkpoint::f5
        ? 39U
        : 41U;
    auto* const indices = required_array(
        state,
        "feature_indices",
        expected_features);
    auto* const edges = required_array(state, "edges", expected_features);
    auto* const probabilities = required_array(
        state,
        "probabilities",
        expected_features);

    HbosState result;
    result.feature_indices.reserve(expected_features);
    result.edges.reserve(expected_features);
    result.probabilities.reserve(expected_features);
    for (std::size_t index = 0; index < expected_features; ++index) {
        auto* const feature_index = json_array_get(indices, index);
        if (!json_is_integer(feature_index)
            || json_integer_value(feature_index) < 0
            || json_integer_value(feature_index)
                >= static_cast<json_int_t>(anomaly_feature_count)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "HBOS feature index out of range");
        }
        result.feature_indices.push_back(static_cast<std::size_t>(
            json_integer_value(feature_index)));
        auto edge_values = number_array(
            json_array_get(edges, index),
            17U,
            "HBOS edges");
        if (!std::is_sorted(edge_values.begin(), edge_values.end())
            || std::adjacent_find(
                   edge_values.begin(),
                   edge_values.end(),
                   std::greater_equal<double>{})
                != edge_values.end()) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "HBOS edges are not strictly increasing");
        }
        auto probability_values = number_array(
            json_array_get(probabilities, index),
            18U,
            "HBOS probabilities");
        if (std::ranges::any_of(probability_values, [](double value) {
                return value <= 0.0;
            })) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "HBOS probability is not positive");
        }
        result.edges.push_back(std::move(edge_values));
        result.probabilities.push_back(std::move(probability_values));
    }
    return result;
}

[[nodiscard]] DecisionState parse_decision(
    json_t* thresholds,
    std::string_view model) {
    auto* const state = required_member(thresholds, model);
    if (!json_is_object(state)) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "threshold state is not an object: " + std::string{model});
    }
    DecisionState result{
        required_number(state, "mean"),
        required_number(state, "standard_deviation"),
        required_number(state, "threshold"),
    };
    if (result.standard_deviation <= 0.0) {
        throw LoadFailure(
            ModelRuntimeErrorCode::schema_mismatch,
            "anomaly standard deviation is not positive");
    }
    return result;
}

[[nodiscard]] std::vector<float> transform(
    const Transform& profile,
    std::span<const double, flow_feature_count_v1> features) {
    std::vector<float> output;
    output.reserve(profile.indices.size());
    for (std::size_t index = 0; index < profile.indices.size(); ++index) {
        const auto feature_index = profile.indices[index];
        auto raw = features[feature_index];
        if (std::isnan(raw)) {
            raw = profile.imputation[feature_index];
        }
        if (!std::isfinite(raw)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::invalid_input,
                "model input contains a non-finite feature");
        }
        const auto scaled = (raw - profile.mean[index]) / profile.scale[index];
        const auto value = static_cast<float>(scaled);
        if (!std::isfinite(value)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::invalid_input,
                "preprocessing produced a non-finite feature");
        }
        output.push_back(value);
    }
    return output;
}

void validate_session(
    const Ort::Session& session,
    std::string_view model_name,
    std::size_t feature_count,
    std::span<const std::string_view> expected_outputs) {
    Ort::AllocatorWithDefaultOptions allocator;
    const auto input_count = session.GetInputCount();
    const auto output_count = session.GetOutputCount();
    if (input_count != 1U || output_count != expected_outputs.size()) {
        std::ostringstream message;
        message << model_name
                << ": ONNX input/output count mismatch: observed inputs="
                << input_count << ", outputs=" << output_count
                << "; expected inputs=1, outputs="
                << expected_outputs.size();
        throw LoadFailure(
            ModelRuntimeErrorCode::model_load_failure,
            message.str());
    }
    const auto input_name = session.GetInputNameAllocated(0U, allocator);
    const auto input_type_info = session.GetInputTypeInfo(0U);
    const auto input_info = input_type_info.GetTensorTypeAndShapeInfo();
    const auto input_shape = input_info.GetShape();
    const auto observed_input_name = input_name.get() == nullptr
        ? std::string_view{"<null>"}
        : std::string_view{input_name.get()};
    if (observed_input_name != "input"
        || input_info.GetElementType()
            != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT
        || input_shape.size() != 2U
        || input_shape[1] != static_cast<std::int64_t>(feature_count)) {
        std::ostringstream message;
        message << model_name
                << ": ONNX input tensor metadata mismatch: observed name='"
                << observed_input_name << "', type="
                << static_cast<int>(input_info.GetElementType())
                << ", shape=[";
        for (std::size_t index = 0; index < input_shape.size(); ++index) {
            if (index != 0U) {
                message << ',';
            }
            message << input_shape[index];
        }
        message << "]; expected name='input', type="
                << static_cast<int>(ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT)
                << ", shape=[N," << feature_count << ']';
        throw LoadFailure(
            ModelRuntimeErrorCode::model_load_failure,
            message.str());
    }
    for (std::size_t index = 0; index < expected_outputs.size(); ++index) {
        const auto output_name = session.GetOutputNameAllocated(index, allocator);
        const auto observed_output_name = output_name.get() == nullptr
            ? std::string_view{"<null>"}
            : std::string_view{output_name.get()};
        if (observed_output_name != expected_outputs[index]) {
            std::ostringstream message;
            message << model_name << ": ONNX output name mismatch at index "
                    << index << ": observed='" << observed_output_name
                    << "'; expected='" << expected_outputs[index] << '\'';
            throw LoadFailure(
                ModelRuntimeErrorCode::model_load_failure,
                message.str());
        }
    }
}

[[nodiscard]] double hbos_score(
    const HbosState& state,
    std::span<const float> features) {
    double score{};
    for (std::size_t index = 0; index < state.feature_indices.size(); ++index) {
        const auto value = static_cast<double>(
            features[state.feature_indices[index]]);
        const auto& edges = state.edges[index];
        std::size_t bin{};
        if (value < edges.front()) {
            bin = 0U;
        } else if (value > edges.back()) {
            bin = edges.size();
        } else {
            const auto upper = std::upper_bound(
                edges.begin(),
                edges.end(),
                value);
            const auto interior = std::clamp<std::ptrdiff_t>(
                std::distance(edges.begin(), upper) - 1,
                0,
                static_cast<std::ptrdiff_t>(edges.size() - 2U));
            bin = 1U + static_cast<std::size_t>(interior);
        }
        score -= std::log(state.probabilities[index][bin]);
    }
    return score / static_cast<double>(state.feature_indices.size());
}

void require_probability(float value, std::string_view context) {
    if (!std::isfinite(value) || value < 0.0F || value > 1.0F) {
        throw LoadFailure(
            ModelRuntimeErrorCode::inference_failure,
            "invalid probability from " + std::string{context});
    }
}

}

struct ModelBundle::Impl {
    explicit Impl(Checkpoint value)
        : checkpoint(value),
          environment(ORT_LOGGING_LEVEL_WARNING, "nids-model-runtime"),
          flow_rf(nullptr),
          isolation_forest(nullptr),
          known_family_rf(nullptr) {
        session_options.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
        session_options.SetIntraOpNumThreads(1);
        session_options.SetInterOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(
            GraphOptimizationLevel::ORT_ENABLE_ALL);
    }

    Checkpoint checkpoint;
    Transform supervised{};
    Transform anomaly{};
    HbosState hbos{};
    DecisionState hbos_decision{};
    DecisionState isolation_forest_decision{};
    double flow_threshold{0.5};
    std::array<std::string, known_family_count_v1> known_family_names{};
    Ort::Env environment;
    Ort::SessionOptions session_options;
    Ort::Session flow_rf;
    Ort::Session isolation_forest;
    Ort::Session known_family_rf;
};

FileSha256Result compute_file_sha256(
    const std::filesystem::path& path) noexcept {
    try {
        return sha256_file(path);
    } catch (const LoadFailure& error) {
        return ModelRuntimeError{error.code, error.what()};
    } catch (const std::exception& error) {
        return ModelRuntimeError{
            ModelRuntimeErrorCode::invalid_bundle_path,
            error.what(),
        };
    }
}

ModelBundle::ModelBundle(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {
}

ModelBundle::~ModelBundle() = default;
ModelBundle::ModelBundle(ModelBundle&&) noexcept = default;
ModelBundle& ModelBundle::operator=(ModelBundle&&) noexcept = default;

Checkpoint ModelBundle::checkpoint() const noexcept {
    return implementation_->checkpoint;
}

std::span<const std::string, known_family_count_v1>
ModelBundle::known_family_names() const noexcept {
    return implementation_->known_family_names;
}

ModelInferenceResult ModelBundle::infer(
    std::span<const double, flow_feature_count_v1> features) const noexcept {
    try {
        const auto supervised = transform(implementation_->supervised, features);
        const auto anomaly = transform(implementation_->anomaly, features);
        const std::array<std::int64_t, 2> supervised_shape{
            1,
            static_cast<std::int64_t>(supervised.size()),
        };
        const std::array<std::int64_t, 2> anomaly_shape{
            1,
            static_cast<std::int64_t>(anomaly.size()),
        };
        const auto memory = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator,
            OrtMemTypeDefault);
        auto supervised_tensor = Ort::Value::CreateTensor<float>(
            memory,
            const_cast<float*>(supervised.data()),
            supervised.size(),
            supervised_shape.data(),
            supervised_shape.size());
        auto anomaly_tensor = Ort::Value::CreateTensor<float>(
            memory,
            const_cast<float*>(anomaly.data()),
            anomaly.size(),
            anomaly_shape.data(),
            anomaly_shape.size());
        const std::array<const char*, 1> input_names{"input"};
        const std::array<const char*, 1> probability_output{"probabilities"};
        const std::array<const char*, 1> score_sample_output{"score_samples"};
        const Ort::RunOptions run_options{nullptr};

        const auto flow_outputs = implementation_->flow_rf.Run(
            run_options,
            input_names.data(),
            &supervised_tensor,
            1U,
            probability_output.data(),
            probability_output.size());
        const auto known_outputs = implementation_->known_family_rf.Run(
            run_options,
            input_names.data(),
            &supervised_tensor,
            1U,
            probability_output.data(),
            probability_output.size());
        const auto isolation_outputs = implementation_->isolation_forest.Run(
            run_options,
            input_names.data(),
            &anomaly_tensor,
            1U,
            score_sample_output.data(),
            score_sample_output.size());
        if (flow_outputs[0].GetTensorTypeAndShapeInfo().GetElementCount() != 2U
            || known_outputs[0].GetTensorTypeAndShapeInfo().GetElementCount()
                != known_family_count_v1
            || isolation_outputs[0]
                    .GetTensorTypeAndShapeInfo()
                    .GetElementCount()
                != 1U) {
            throw LoadFailure(
                ModelRuntimeErrorCode::inference_failure,
                "ONNX runtime output shape mismatch");
        }

        ModelScores result;
        const auto* const flow = flow_outputs[0].GetTensorData<float>();
        result.flow_attack_probability = flow[1];
        require_probability(result.flow_attack_probability, "Flow RF");
        result.flow_attack =
            static_cast<double>(result.flow_attack_probability)
            >= implementation_->flow_threshold;

        const auto* const known = known_outputs[0].GetTensorData<float>();
        for (std::size_t index = 0; index < known_family_count_v1; ++index) {
            require_probability(known[index], "known-family RF");
            result.known_family_probabilities[index] = known[index];
        }
        const auto top = std::max_element(
            result.known_family_probabilities.begin(),
            result.known_family_probabilities.end());
        result.known_family_index = static_cast<std::size_t>(
            std::distance(result.known_family_probabilities.begin(), top));
        result.known_family_confidence = *top;

        result.hbos.raw = hbos_score(implementation_->hbos, anomaly);
        result.hbos.normalized =
            (result.hbos.raw - implementation_->hbos_decision.mean)
            / implementation_->hbos_decision.standard_deviation;
        result.hbos.threshold_exceeded =
            result.hbos.normalized >= implementation_->hbos_decision.threshold;

        const auto score_sample =
            static_cast<double>(isolation_outputs[0].GetTensorData<float>()[0]);
        result.isolation_forest.raw = -score_sample;
        result.isolation_forest.normalized =
            (result.isolation_forest.raw
                - implementation_->isolation_forest_decision.mean)
            / implementation_->isolation_forest_decision.standard_deviation;
        result.isolation_forest.threshold_exceeded =
            result.isolation_forest.normalized
            >= implementation_->isolation_forest_decision.threshold;
        if (!std::isfinite(result.hbos.raw)
            || !std::isfinite(result.hbos.normalized)
            || !std::isfinite(result.isolation_forest.raw)
            || !std::isfinite(result.isolation_forest.normalized)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::inference_failure,
                "native anomaly scoring produced a non-finite value");
        }
        return result;
    } catch (const LoadFailure& error) {
        return ModelRuntimeError{error.code, error.what()};
    } catch (const Ort::Exception& error) {
        return ModelRuntimeError{
            ModelRuntimeErrorCode::inference_failure,
            error.what(),
        };
    } catch (const std::exception& error) {
        return ModelRuntimeError{
            ModelRuntimeErrorCode::inference_failure,
            error.what(),
        };
    }
}

ModelBundleLoadResult load_model_bundle(
    const std::filesystem::path& staged_directory) {
    try {
        std::error_code error;
        const auto root = std::filesystem::weakly_canonical(
            staged_directory,
            error);
        if (error || !std::filesystem::is_directory(root)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::invalid_bundle_path,
                "staged bundle directory does not exist: "
                    + staged_directory.string());
        }
        const auto manifest = load_json(root / "manifest.json");
        const auto checkpoint = parse_checkpoint(
            required_string(manifest.get(), "checkpoint"));
        verify_manifest_and_members(root, manifest.get(), checkpoint);

        const auto feature_schema = load_json(root / "feature_schema.json");
        verify_feature_schema(feature_schema.get());

        const auto preprocessing = load_json(root / "preprocessing.json");
        if (parse_checkpoint(
                required_string(preprocessing.get(), "checkpoint"))
            != checkpoint) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "preprocessing checkpoint mismatch");
        }
        require_string_array(
            required_member(preprocessing.get(), "input_features"),
            feature_names_v1,
            "preprocessing input features");
        auto* const profiles = required_member(
            preprocessing.get(),
            "profiles");
        if (!json_is_object(profiles)) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "preprocessing profiles are not an object");
        }
        const auto feature_count =
            checkpoint == Checkpoint::f3 ? 52U : 53U;
        auto implementation = std::make_unique<ModelBundle::Impl>(checkpoint);
        implementation->supervised = parse_transform(
            required_member(profiles, "supervised_known"),
            feature_count,
            "supervised_known");
        implementation->anomaly = parse_transform(
            required_member(profiles, "anomaly_benign"),
            feature_count,
            "anomaly_benign");

        const auto hbos = load_json(root / "hbos.json");
        implementation->hbos = parse_hbos(
            hbos.get(),
            checkpoint,
            implementation->anomaly.indices.size());

        const auto thresholds = load_json(root / "thresholds.json");
        if (parse_checkpoint(required_string(thresholds.get(), "checkpoint"))
                != checkpoint
            || !json_is_false(required_member(
                thresholds.get(),
                "recalibration_performed"))) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "threshold identity or recalibration state mismatch");
        }
        auto* const flow_threshold = required_member(
            thresholds.get(),
            "flow_rf");
        implementation->flow_threshold = required_number(
            flow_threshold,
            "threshold");
        if (implementation->flow_threshold != 0.5) {
            throw LoadFailure(
                ModelRuntimeErrorCode::schema_mismatch,
                "Flow RF threshold mismatch");
        }
        implementation->hbos_decision = parse_decision(
            thresholds.get(),
            "hbos");
        implementation->isolation_forest_decision = parse_decision(
            thresholds.get(),
            "isolation_forest");

        auto* const models = required_member(manifest.get(), "models");
        auto* const known_model = required_member(models, "known_family_rf");
        auto* const class_order = required_array(
            known_model,
            "class_order",
            known_family_count_v1);
        for (std::size_t index = 0; index < known_family_count_v1; ++index) {
            auto* const name = json_array_get(class_order, index);
            if (!json_is_string(name)) {
                throw LoadFailure(
                    ModelRuntimeErrorCode::schema_mismatch,
                    "known-family class order is invalid");
            }
            implementation->known_family_names[index] =
                json_string_value(name);
        }

        implementation->flow_rf = Ort::Session{
            implementation->environment,
            (root / "models/flow_rf.onnx").c_str(),
            implementation->session_options,
        };
        implementation->isolation_forest = Ort::Session{
            implementation->environment,
            (root / "models/isolation_forest.onnx").c_str(),
            implementation->session_options,
        };
        implementation->known_family_rf = Ort::Session{
            implementation->environment,
            (root / "models/known_family_rf.onnx").c_str(),
            implementation->session_options,
        };
        constexpr std::array<std::string_view, 2> rf_outputs{
            "label",
            "probabilities",
        };
        constexpr std::array<std::string_view, 3> isolation_outputs{
            "label",
            "scores",
            "score_samples",
        };
        validate_session(
            implementation->flow_rf,
            "flow_rf",
            implementation->supervised.indices.size(),
            rf_outputs);
        validate_session(
            implementation->known_family_rf,
            "known_family_rf",
            implementation->supervised.indices.size(),
            rf_outputs);
        validate_session(
            implementation->isolation_forest,
            "isolation_forest",
            implementation->anomaly.indices.size(),
            isolation_outputs);
        return ModelBundleLoadResult{
            std::unique_ptr<ModelBundle>{
                new ModelBundle{std::move(implementation)},
            },
            std::nullopt,
        };
    } catch (const LoadFailure& error) {
        return ModelBundleLoadResult{
            nullptr,
            ModelRuntimeError{error.code, error.what()},
        };
    } catch (const Ort::Exception& error) {
        return ModelBundleLoadResult{
            nullptr,
            ModelRuntimeError{
                ModelRuntimeErrorCode::model_load_failure,
                error.what(),
            },
        };
    } catch (const std::exception& error) {
        return ModelBundleLoadResult{
            nullptr,
            ModelRuntimeError{
                ModelRuntimeErrorCode::model_load_failure,
                error.what(),
            },
        };
    }
}

}
