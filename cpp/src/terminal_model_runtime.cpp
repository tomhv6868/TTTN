#include "nids/terminal_model_runtime.hpp"

#include "nids/model_runtime.hpp"

#include <jansson.h>
#include <onnxruntime_cxx_api.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace nids {
namespace {

inline constexpr std::string_view artifact_id{
    "nids.terminal_flow_bundle.v1"};
inline constexpr std::string_view artifact_version{"1.0.0"};
inline constexpr std::string_view profile_id{"A"};
inline constexpr std::string_view feature_schema_id{
    "nids.terminal_flow_features.v1"};
inline constexpr std::string_view feature_schema_source_sha256{
    "ebe260327df74e265c2dc89178e3d038c3183de55603187c4b1e503e06173dfc"};
inline constexpr double selected_threshold{0.9984837643022101};

inline constexpr std::array<std::string_view, 4> bundle_members{
    "feature_schema.json",
    "preprocessing.json",
    "thresholds.json",
    "models/terminal_multiclass.onnx",
};

inline constexpr std::array<std::string_view, terminal_model_class_count_v1>
    class_names_v1{
        "Benign",
        "FTP-Bruteforce",
        "SSH-Bruteforce",
        "PortScan",
        "DoS",
        "Other",
    };

inline constexpr std::array<std::string_view, terminal_feature_count>
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
        "protocol_number",
        "forward_ttl_mean",
        "reverse_ttl_mean",
        "forward_wire_bit_rate_per_second",
        "reverse_wire_bit_rate_per_second",
        "active_mean_us",
        "idle_mean_us",
        "context_same_destination_endpoint_flow_count_60s",
        "context_same_source_destination_flow_count_60s",
        "context_source_destination_distinct_destination_port_count_60s",
        "first_observed_source_port",
        "first_observed_destination_port",
        "lifecycle_tcp_reset",
        "lifecycle_tcp_fin_handshake",
        "lifecycle_tcp_other",
        "lifecycle_udp",
    };

class LoadFailure final : public std::runtime_error {
public:
    LoadFailure(TerminalModelRuntimeErrorCode error_code, std::string message)
        : std::runtime_error(std::move(message)), code(error_code) {
    }

    TerminalModelRuntimeErrorCode code;
};

using JsonDocument = std::unique_ptr<json_t, decltype(&json_decref)>;

[[nodiscard]] bool valid_sha256(std::string_view value) noexcept {
    if (value.size() != 64U) {
        return false;
    }
    return std::ranges::all_of(value, [](char character) {
        return (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f');
    });
}

[[nodiscard]] std::string sha256_file(const std::filesystem::path& path) {
    auto result = compute_file_sha256(path);
    if (std::holds_alternative<ModelRuntimeError>(result)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::invalid_bundle_path,
            std::get<ModelRuntimeError>(std::move(result)).detail);
    }
    return std::get<std::string>(std::move(result));
}

[[nodiscard]] JsonDocument load_json(const std::filesystem::path& path) {
    json_error_t error{};
    JsonDocument document{
        json_load_file(path.c_str(), JSON_REJECT_DUPLICATES, &error),
        &json_decref,
    };
    if (!document) {
        std::ostringstream message;
        message << "invalid JSON " << path.string() << " at line "
                << error.line << ", column " << error.column << ": "
                << error.text;
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::invalid_json,
            message.str());
    }
    if (!json_is_object(document.get())) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON document is not an object: " + path.string());
    }
    return document;
}

[[nodiscard]] json_t* required_member(
    json_t* object,
    std::string_view name) {
    if (!json_is_object(object)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON parent is not an object while reading: "
                + std::string{name});
    }
    auto* const value = json_object_get(object, std::string{name}.c_str());
    if (value == nullptr) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
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
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not a string: " + std::string{name});
    }
    return json_string_value(value);
}

[[nodiscard]] json_int_t required_integer(
    json_t* object,
    std::string_view name) {
    auto* const value = required_member(object, name);
    if (!json_is_integer(value)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not an integer: " + std::string{name});
    }
    return json_integer_value(value);
}

[[nodiscard]] std::size_t required_size(
    json_t* object,
    std::string_view name) {
    const auto value = required_integer(object, name);
    if (value < 0
        || static_cast<std::uintmax_t>(value)
            > std::numeric_limits<std::size_t>::max()) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not a valid size: " + std::string{name});
    }
    return static_cast<std::size_t>(value);
}

[[nodiscard]] double required_number(
    json_t* object,
    std::string_view name) {
    auto* const value = required_member(object, name);
    if (!json_is_number(value)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not numeric: " + std::string{name});
    }
    const auto result = json_number_value(value);
    if (!std::isfinite(result)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not finite: " + std::string{name});
    }
    return result;
}

[[nodiscard]] bool required_bool(
    json_t* object,
    std::string_view name) {
    auto* const value = required_member(object, name);
    if (!json_is_boolean(value)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member is not boolean: " + std::string{name});
    }
    return json_is_true(value);
}

[[nodiscard]] json_t* required_array(
    json_t* object,
    std::string_view name,
    std::size_t expected_size) {
    auto* const value = required_member(object, name);
    if (!json_is_array(value) || json_array_size(value) != expected_size) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member has an invalid array shape: " + std::string{name});
    }
    return value;
}

void require_null(json_t* object, std::string_view name) {
    if (!json_is_null(required_member(object, name))) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON member must be null: " + std::string{name});
    }
}

void require_string_value(
    json_t* object,
    std::string_view name,
    std::string_view expected) {
    const auto observed = required_string(object, name);
    if (observed != expected) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON string mismatch for " + std::string{name}
                + ": observed='" + std::string{observed}
                + "', expected='" + std::string{expected} + "'");
    }
}

void require_integer_value(
    json_t* object,
    std::string_view name,
    json_int_t expected) {
    const auto observed = required_integer(object, name);
    if (observed != expected) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON integer mismatch for " + std::string{name});
    }
}

void require_bool_value(
    json_t* object,
    std::string_view name,
    bool expected) {
    if (required_bool(object, name) != expected) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "JSON boolean mismatch for " + std::string{name});
    }
}

void require_string_array(
    json_t* value,
    std::span<const std::string_view> expected,
    std::string_view context) {
    if (!json_is_array(value) || json_array_size(value) != expected.size()) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "invalid string array: " + std::string{context});
    }
    for (std::size_t index = 0; index < expected.size(); ++index) {
        auto* const item = json_array_get(value, index);
        if (!json_is_string(item)
            || std::string_view{json_string_value(item)} != expected[index]) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::schema_mismatch,
                "string array mismatch at index " + std::to_string(index)
                    + ": " + std::string{context});
        }
    }
}

void require_index_array(
    json_t* value,
    std::size_t first,
    std::size_t count,
    std::string_view context) {
    if (!json_is_array(value) || json_array_size(value) != count) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "invalid index array: " + std::string{context});
    }
    for (std::size_t index = 0; index < count; ++index) {
        auto* const item = json_array_get(value, index);
        if (!json_is_integer(item)
            || json_integer_value(item)
                != static_cast<json_int_t>(first + index)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::schema_mismatch,
                "index array mismatch at index " + std::to_string(index)
                    + ": " + std::string{context});
        }
    }
}

void require_shape(
    json_t* value,
    std::span<const std::int64_t> expected,
    std::string_view context) {
    if (!json_is_array(value) || json_array_size(value) != expected.size()) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "invalid tensor shape: " + std::string{context});
    }
    for (std::size_t index = 0; index < expected.size(); ++index) {
        auto* const item = json_array_get(value, index);
        if (!json_is_integer(item)
            || json_integer_value(item) != expected[index]) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::schema_mismatch,
                "tensor shape mismatch at dimension "
                    + std::to_string(index) + ": " + std::string{context});
        }
    }
}

void require_regular_file(
    const std::filesystem::path& path,
    std::string_view context) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)
        || std::filesystem::is_symlink(status)) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::invalid_bundle_path,
            std::string{context} + " is missing or not a regular file: "
                + path.string());
    }
}

void verify_staged_inventory(const std::filesystem::path& root) {
    constexpr std::array<std::string_view, 4> root_files{
        "feature_schema.json",
        "manifest.json",
        "preprocessing.json",
        "thresholds.json",
    };
    std::array<bool, root_files.size()> root_file_seen{};
    bool models_seen = false;
    std::error_code error;
    std::filesystem::directory_iterator iterator{root, error};
    const std::filesystem::directory_iterator end;
    while (!error && iterator != end) {
        const auto& entry = *iterator;
        const auto name = entry.path().filename().string();
        const auto status = entry.symlink_status(error);
        if (error) {
            break;
        }
        if (std::filesystem::is_symlink(status)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::invalid_bundle_path,
                "terminal bundle root contains a symlink: " + name);
        }
        if (name == "models") {
            if (models_seen || !std::filesystem::is_directory(status)) {
                throw LoadFailure(
                    TerminalModelRuntimeErrorCode::invalid_bundle_path,
                    "invalid terminal bundle models entry");
            }
            models_seen = true;
        } else {
            const auto match = std::ranges::find(
                root_files,
                std::string_view{name});
            if (match == root_files.end()
                || !std::filesystem::is_regular_file(status)) {
                throw LoadFailure(
                    TerminalModelRuntimeErrorCode::invalid_bundle_path,
                    "unexpected terminal bundle root entry: " + name);
            }
            root_file_seen[
                static_cast<std::size_t>(match - root_files.begin())] = true;
        }
        iterator.increment(error);
    }
    if (error || !models_seen
        || !std::ranges::all_of(
            root_file_seen,
            [](bool seen) { return seen; })) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::invalid_bundle_path,
            "terminal bundle root inventory is incomplete or unreadable");
    }

    const auto models = root / "models";
    bool model_seen = false;
    std::filesystem::directory_iterator model_iterator{models, error};
    while (!error && model_iterator != end) {
        const auto& entry = *model_iterator;
        const auto status = entry.symlink_status(error);
        const auto name = entry.path().filename().string();
        if (error) {
            break;
        }
        if (std::filesystem::is_symlink(status)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::invalid_bundle_path,
                "terminal bundle models contains a symlink: " + name);
        }
        if (model_seen || name != "terminal_multiclass.onnx"
            || !std::filesystem::is_regular_file(status)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::invalid_bundle_path,
                "unexpected terminal bundle models entry: " + name);
        }
        model_seen = true;
        model_iterator.increment(error);
    }
    if (error || !model_seen) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::invalid_bundle_path,
            "terminal bundle model inventory is incomplete or unreadable");
    }
}

struct MemberHashes {
    std::string feature_schema;
    std::string preprocessing;
    std::string thresholds;
    std::string model;
};

[[nodiscard]] MemberHashes verify_manifest_and_members(
    const std::filesystem::path& root,
    json_t* manifest) {
    require_string_value(manifest, "schema_version", "1.0.0");
    require_string_value(manifest, "task", "T9.1");
    require_string_value(
        manifest,
        "kind",
        "terminal_flow_native_bundle_manifest");
    require_string_value(manifest, "status", "locked");
    require_string_value(manifest, "artifact_id", artifact_id);
    require_string_value(manifest, "artifact_version", artifact_version);
    require_string_value(manifest, "bundle_schema_id", artifact_id);
    require_string_value(manifest, "feature_schema_id", feature_schema_id);
    require_string_value(
        manifest,
        "feature_schema_source_sha256",
        feature_schema_source_sha256);
    require_integer_value(manifest, "benign_index", 0);
    require_integer_value(
        manifest,
        "selected_feature_count",
        terminal_model_feature_count_v1);
    require_string_value(manifest, "selected_profile", profile_id);
    if (required_number(manifest, "selected_threshold")
        != selected_threshold) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "selected threshold mismatch in manifest");
    }
    require_index_array(
        required_member(manifest, "selected_feature_indices"),
        0U,
        terminal_model_feature_count_v1,
        "manifest selected features");
    require_string_array(
        required_member(manifest, "selected_feature_names"),
        std::span{feature_names_v1}.first<terminal_model_feature_count_v1>(),
        "manifest selected feature names");
    require_string_array(
        required_member(manifest, "class_order"),
        class_names_v1,
        "manifest class order");

    auto* const converter = required_member(manifest, "converter");
    require_string_value(converter, "lightgbm", "4.6.0");
    require_string_value(converter, "onnx", "1.20.1");
    require_string_value(converter, "onnxmltools", "1.16.0");
    require_integer_value(converter, "requested_target_opset", 15);
    require_string_value(
        converter,
        "serialization",
        "protobuf_deterministic");
    require_bool_value(converter, "zipmap", false);

    auto* const selection = required_member(manifest, "model_selection");
    require_string_value(
        selection,
        "manifest_path",
        "run_log/full-flow-v1/model/manifest.json");
    for (const auto name : {
             "manifest_sha256",
             "selected_model_sha256",
             "validation_predictions_sha256"}) {
        if (!valid_sha256(required_string(selection, name))) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::schema_mismatch,
                "invalid model-selection SHA-256: " + std::string{name});
        }
    }

    auto* const parity = required_member(manifest, "parity");
    auto* const cpp = required_member(parity, "python_cpp_numeric_parity");
    require_bool_value(cpp, "claimed", false);
    require_string_value(cpp, "deferred_to", "phase7");
    require_bool_value(cpp, "required_before_live", true);
    auto* const python = required_member(parity, "python_ort");
    require_bool_value(python, "claimed", false);
    require_string_value(python, "external_evidence", "onnx-parity.json");
    require_bool_value(python, "required_before_native", true);

    auto* const model = required_member(manifest, "model");
    require_string_value(
        model,
        "graph_name",
        "nids_t91_terminal_multiclass");
    auto* const input = required_member(model, "input");
    require_string_value(input, "name", "input");
    require_string_value(input, "dtype", "float");
    constexpr std::array<std::int64_t, 2> input_shape{
        -1,
        terminal_model_feature_count_v1,
    };
    require_shape(required_member(input, "shape"), input_shape, "model input");
    auto* const outputs = required_array(model, "outputs", 2U);
    auto* const label = json_array_get(outputs, 0U);
    require_string_value(label, "name", "label");
    require_string_value(label, "dtype", "int64");
    constexpr std::array<std::int64_t, 1> label_shape{-1};
    require_shape(required_member(label, "shape"), label_shape, "model label");
    auto* const probabilities = json_array_get(outputs, 1U);
    require_string_value(probabilities, "name", "probabilities");
    require_string_value(probabilities, "dtype", "float");
    constexpr std::array<std::int64_t, 2> probability_shape{
        -1,
        terminal_model_class_count_v1,
    };
    require_shape(
        required_member(probabilities, "shape"),
        probability_shape,
        "model probabilities");
    auto* const opsets = required_member(model, "opset_imports");
    require_integer_value(opsets, "ai.onnx", 9);
    require_integer_value(opsets, "ai.onnx.ml", 1);

    MemberHashes hashes;
    auto* const members = required_array(
        manifest,
        "members",
        bundle_members.size());
    for (std::size_t index = 0; index < bundle_members.size(); ++index) {
        auto* const record = json_array_get(members, index);
        if (!json_is_object(record)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "manifest member record is not an object");
        }
        if (required_string(record, "path") != bundle_members[index]) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "manifest member order mismatch");
        }
        const auto expected_hash = required_string(record, "sha256");
        if (!valid_sha256(expected_hash)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "manifest member SHA-256 is invalid");
        }
        const auto path = root / std::filesystem::path{bundle_members[index]};
        require_regular_file(path, "bundle member");
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if (error || size != required_size(record, "size_bytes")) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "bundle member size mismatch: " + path.string());
        }
        const auto observed_hash = sha256_file(path);
        if (observed_hash != expected_hash) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "bundle member hash mismatch: " + path.string());
        }
        auto* destination = index == 0U ? &hashes.feature_schema
            : index == 1U ? &hashes.preprocessing
            : index == 2U ? &hashes.thresholds
                          : &hashes.model;
        *destination = std::string{expected_hash};
    }
    return hashes;
}

void verify_feature_schema(json_t* schema) {
    require_string_value(schema, "schema_id", feature_schema_id);
    require_string_value(schema, "schema_version", "1.0.0");
    require_string_value(schema, "task", "T9.1");
    require_string_value(schema, "kind", "terminal_flow_feature_schema");
    auto* const vector = required_member(schema, "feature_vector");
    require_integer_value(vector, "length", terminal_feature_count);
    require_string_value(vector, "ordering", "ascending feature index");
    require_string_value(vector, "encoded_type", "float64");
    require_bool_value(vector, "finite_only", true);
    auto* const features = required_array(
        schema,
        "features",
        terminal_feature_count);
    for (std::size_t index = 0; index < feature_names_v1.size(); ++index) {
        auto* const feature = json_array_get(features, index);
        require_integer_value(feature, "index", static_cast<json_int_t>(index));
        require_string_value(feature, "name", feature_names_v1[index]);
    }

    constexpr std::array<std::string_view, 5> ids{"A", "B", "C", "D", "E"};
    constexpr std::array<std::string_view, 5> names{
        "legacy_terminal",
        "terminal_traffic",
        "terminal_context",
        "terminal_ports",
        "terminal_full",
    };
    constexpr std::array<json_int_t, 5> ends{53, 60, 63, 65, 69};
    constexpr std::array<json_int_t, 5> lengths{54, 61, 64, 66, 70};
    auto* const profiles = required_array(schema, "feature_profiles", 5U);
    for (std::size_t index = 0; index < ids.size(); ++index) {
        auto* const profile = json_array_get(profiles, index);
        require_string_value(profile, "id", ids[index]);
        require_string_value(profile, "name", names[index]);
        require_integer_value(profile, "start_index", 0);
        require_integer_value(profile, "end_index", ends[index]);
        require_integer_value(profile, "length", lengths[index]);
    }
}

void verify_preprocessing(json_t* document) {
    require_string_value(document, "schema_version", "1.0.0");
    require_string_value(document, "feature_schema_id", feature_schema_id);
    require_string_value(
        document,
        "feature_schema_source_sha256",
        feature_schema_source_sha256);
    require_null(document, "categorical_encoding");
    require_null(document, "imputation");
    require_null(document, "scaler");

    auto* const input = required_member(document, "input");
    require_string_value(input, "dtype", "float64");
    require_integer_value(input, "feature_count", terminal_feature_count);
    require_string_array(
        required_member(input, "feature_names"),
        feature_names_v1,
        "preprocessing input feature names");
    require_bool_value(input, "finite_required", true);
    require_string_value(input, "ordering", "ascending_feature_index");

    const auto selected_names =
        std::span{feature_names_v1}.first<terminal_model_feature_count_v1>();
    auto* const output = required_member(document, "output");
    require_string_value(output, "dtype", "float32");
    require_integer_value(
        output,
        "feature_count",
        terminal_model_feature_count_v1);
    require_string_array(
        required_member(output, "feature_names"),
        selected_names,
        "preprocessing output feature names");
    require_bool_value(output, "finite_required", true);
    require_string_value(output, "float32_overflow", "fail_fast");

    auto* const selection = required_member(document, "selection");
    require_integer_value(
        selection,
        "feature_count",
        terminal_model_feature_count_v1);
    require_index_array(
        required_member(selection, "feature_indices"),
        0U,
        terminal_model_feature_count_v1,
        "preprocessing selection");
    require_string_array(
        required_member(selection, "feature_names"),
        selected_names,
        "preprocessing selection names");
    require_string_value(selection, "operation", "select_indices");
    require_string_value(selection, "profile_id", profile_id);
    require_string_value(selection, "profile_kind", "prefix");

    auto* const steps = required_array(document, "steps", 4U);
    auto* const finite_input = json_array_get(steps, 0U);
    require_string_value(finite_input, "operation", "require_finite");
    require_string_value(finite_input, "dtype", "float64");
    require_integer_value(
        finite_input,
        "feature_count",
        terminal_feature_count);
    auto* const select = json_array_get(steps, 1U);
    require_string_value(select, "operation", "select_indices");
    require_index_array(
        required_member(select, "indices"),
        0U,
        terminal_model_feature_count_v1,
        "preprocessing select step");
    auto* const cast = json_array_get(steps, 2U);
    require_string_value(cast, "operation", "cast");
    require_string_value(cast, "from_dtype", "float64");
    require_string_value(cast, "to_dtype", "float32");
    require_string_value(cast, "overflow", "fail_fast");
    auto* const finite_output = json_array_get(steps, 3U);
    require_string_value(finite_output, "operation", "require_finite");
    require_string_value(finite_output, "dtype", "float32");
    require_integer_value(
        finite_output,
        "feature_count",
        terminal_model_feature_count_v1);
}

[[nodiscard]] double verify_thresholds(json_t* document) {
    require_string_value(document, "schema_version", "1.0.0");
    require_string_array(
        required_member(document, "class_order"),
        class_names_v1,
        "threshold class order");
    const auto threshold = required_number(document, "selected_threshold");
    if (threshold != selected_threshold) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "selected threshold mismatch");
    }
    auto* const decision = required_member(document, "decision");
    require_string_value(decision, "probability_tensor", "probabilities");
    require_integer_value(decision, "benign_class_index", 0);
    require_integer_value(decision, "benign_result_index", 0);
    auto* const attack_score = required_member(decision, "attack_score");
    require_string_value(
        attack_score,
        "operation",
        "one_minus_probability");
    require_integer_value(attack_score, "probability_index", 0);
    require_string_value(
        attack_score,
        "formula",
        "1.0 - probabilities[0]");
    auto* const gate = required_member(decision, "gate");
    require_string_value(gate, "comparator", ">=");
    if (required_number(gate, "threshold") != threshold) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::schema_mismatch,
            "decision gate threshold mismatch");
    }
    auto* const attack_class = required_member(decision, "attack_class");
    require_index_array(
        required_member(attack_class, "indices"),
        1U,
        terminal_model_class_count_v1 - 1U,
        "attack class indices");
    require_string_value(attack_class, "operation", "argmax");
    require_string_value(
        attack_class,
        "tie_break",
        "lowest_class_index");
    return threshold;
}

[[nodiscard]] std::string shape_string(
    std::span<const std::int64_t> shape) {
    std::ostringstream output;
    output << '[';
    for (std::size_t index = 0; index < shape.size(); ++index) {
        if (index != 0U) {
            output << ',';
        }
        output << shape[index];
    }
    output << ']';
    return output.str();
}

void validate_tensor_metadata(
    const Ort::Session& session,
    bool input,
    std::size_t index,
    std::string_view expected_name,
    ONNXTensorElementDataType expected_type,
    std::span<const std::int64_t> expected_shape) {
    Ort::AllocatorWithDefaultOptions allocator;
    const auto name = input
        ? session.GetInputNameAllocated(index, allocator)
        : session.GetOutputNameAllocated(index, allocator);
    const auto type_info = input
        ? session.GetInputTypeInfo(index)
        : session.GetOutputTypeInfo(index);
    const auto tensor_info = type_info.GetTensorTypeAndShapeInfo();
    const auto shape = tensor_info.GetShape();
    const auto observed_name = name.get() == nullptr
        ? std::string_view{"<null>"}
        : std::string_view{name.get()};
    const auto observed_type = tensor_info.GetElementType();
    if (observed_name != expected_name || observed_type != expected_type
        || !std::ranges::equal(shape, expected_shape)) {
        std::ostringstream message;
        message << "terminal_multiclass: ONNX "
                << (input ? "input" : "output") << '[' << index
                << "] tensor metadata mismatch: observed name='"
                << observed_name << "', type="
                << static_cast<int>(observed_type) << ", shape="
                << shape_string(shape) << "; expected name='"
                << expected_name << "', type="
                << static_cast<int>(expected_type) << ", shape="
                << shape_string(expected_shape);
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::model_load_failure,
            message.str());
    }
}

void validate_session(const Ort::Session& session) {
    const auto input_count = session.GetInputCount();
    const auto output_count = session.GetOutputCount();
    if (input_count != 1U || output_count != 2U) {
        std::ostringstream message;
        message << "terminal_multiclass: ONNX input/output count mismatch: "
                << "observed inputs=" << input_count << ", outputs="
                << output_count << "; expected inputs=1, outputs=2";
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::model_load_failure,
            message.str());
    }
    constexpr std::array<std::int64_t, 2> input_shape{
        -1,
        terminal_model_feature_count_v1,
    };
    constexpr std::array<std::int64_t, 1> label_shape{-1};
    constexpr std::array<std::int64_t, 2> probability_shape{
        -1,
        terminal_model_class_count_v1,
    };
    validate_tensor_metadata(
        session,
        true,
        0U,
        "input",
        ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
        input_shape);
    validate_tensor_metadata(
        session,
        false,
        0U,
        "label",
        ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
        label_shape);
    validate_tensor_metadata(
        session,
        false,
        1U,
        "probabilities",
        ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
        probability_shape);
}

void require_probability(float value, std::size_t index) {
    if (!std::isfinite(value) || value < 0.0F || value > 1.0F) {
        throw LoadFailure(
            TerminalModelRuntimeErrorCode::inference_failure,
            "terminal_multiclass returned an invalid probability at index "
                + std::to_string(index));
    }
}

}

struct TerminalModelBundle::Impl {
    Impl()
        : environment(
              ORT_LOGGING_LEVEL_WARNING,
              "nids-terminal-model-runtime"),
          session(nullptr) {
        session_options.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
        session_options.SetIntraOpNumThreads(1);
        session_options.SetInterOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(
            GraphOptimizationLevel::ORT_ENABLE_ALL);
        for (std::size_t index = 0; index < class_names_v1.size(); ++index) {
            class_names[index] = class_names_v1[index];
        }
    }

    std::array<std::string, terminal_model_class_count_v1> class_names{};
    double threshold{};
    std::string manifest_hash{};
    std::string schema_hash{};
    std::string model_hash{};
    Ort::Env environment;
    Ort::SessionOptions session_options;
    Ort::Session session;
};

TerminalModelBundle::TerminalModelBundle(
    std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {
}

TerminalModelBundle::~TerminalModelBundle() = default;
TerminalModelBundle::TerminalModelBundle(TerminalModelBundle&&) noexcept =
    default;
TerminalModelBundle& TerminalModelBundle::operator=(
    TerminalModelBundle&&) noexcept = default;

std::string_view TerminalModelBundle::artifact_id() const noexcept {
    return nids::artifact_id;
}

std::string_view TerminalModelBundle::artifact_version() const noexcept {
    return nids::artifact_version;
}

std::string_view TerminalModelBundle::profile_id() const noexcept {
    return nids::profile_id;
}

double TerminalModelBundle::attack_threshold() const noexcept {
    return implementation_->threshold;
}

std::string_view TerminalModelBundle::manifest_sha256() const noexcept {
    return implementation_->manifest_hash;
}

std::string_view TerminalModelBundle::feature_schema_sha256() const noexcept {
    return implementation_->schema_hash;
}

std::string_view TerminalModelBundle::model_sha256() const noexcept {
    return implementation_->model_hash;
}

std::span<const std::string, terminal_model_class_count_v1>
TerminalModelBundle::class_names() const noexcept {
    return implementation_->class_names;
}

TerminalModelInferenceResult TerminalModelBundle::infer(
    std::span<const double, terminal_feature_count> features) const noexcept {
    try {
        for (std::size_t index = 0; index < features.size(); ++index) {
            if (!std::isfinite(features[index])) {
                throw LoadFailure(
                    TerminalModelRuntimeErrorCode::invalid_input,
                    "terminal model input contains a non-finite feature at index "
                        + std::to_string(index));
            }
        }

        std::array<float, terminal_model_feature_count_v1> selected{};
        for (std::size_t index = 0; index < selected.size(); ++index) {
            selected[index] = static_cast<float>(features[index]);
            if (!std::isfinite(selected[index])) {
                throw LoadFailure(
                    TerminalModelRuntimeErrorCode::invalid_input,
                    "terminal model float32 conversion overflow at index "
                        + std::to_string(index));
            }
        }

        constexpr std::array<std::int64_t, 2> input_shape{
            1,
            terminal_model_feature_count_v1,
        };
        const auto memory = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator,
            OrtMemTypeDefault);
        auto input = Ort::Value::CreateTensor<float>(
            memory,
            selected.data(),
            selected.size(),
            input_shape.data(),
            input_shape.size());
        constexpr std::array<const char*, 1> input_names{"input"};
        constexpr std::array<const char*, 2> output_names{
            "label",
            "probabilities",
        };
        const Ort::RunOptions run_options{nullptr};
        auto outputs = implementation_->session.Run(
            run_options,
            input_names.data(),
            &input,
            input_names.size(),
            output_names.data(),
            output_names.size());
        if (outputs.size() != output_names.size()
            || !outputs[0].IsTensor() || !outputs[1].IsTensor()) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::inference_failure,
                "terminal model returned an invalid output collection");
        }
        const auto label_info = outputs[0].GetTensorTypeAndShapeInfo();
        const auto probability_info = outputs[1].GetTensorTypeAndShapeInfo();
        const auto label_shape = label_info.GetShape();
        const auto probability_shape = probability_info.GetShape();
        constexpr std::array<std::int64_t, 1> expected_label_shape{1};
        constexpr std::array<std::int64_t, 2> expected_probability_shape{
            1,
            terminal_model_class_count_v1,
        };
        if (label_info.GetElementType()
                != ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64
            || !std::ranges::equal(label_shape, expected_label_shape)
            || label_info.GetElementCount() != 1U
            || probability_info.GetElementType()
                != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT
            || !std::ranges::equal(
                probability_shape,
                expected_probability_shape)
            || probability_info.GetElementCount()
                != terminal_model_class_count_v1) {
            std::ostringstream message;
            message << "terminal_multiclass: runtime output metadata mismatch: "
                    << "observed label type="
                    << static_cast<int>(label_info.GetElementType())
                    << ", shape=" << shape_string(label_shape)
                    << "; probabilities type="
                    << static_cast<int>(probability_info.GetElementType())
                    << ", shape=" << shape_string(probability_shape)
                    << "; expected label type="
                    << static_cast<int>(ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64)
                    << ", shape=[1]; probabilities type="
                    << static_cast<int>(ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT)
                    << ", shape=[1,6]";
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::inference_failure,
                message.str());
        }

        TerminalModelScores result;
        const auto* const probabilities = outputs[1].GetTensorData<float>();
        for (std::size_t index = 0; index < result.class_probabilities.size();
             ++index) {
            require_probability(probabilities[index], index);
            result.class_probabilities[index] = probabilities[index];
        }
        const auto probability_sum = std::accumulate(
            result.class_probabilities.begin(),
            result.class_probabilities.end(),
            0.0);
        if (!std::isfinite(probability_sum)
            || std::abs(probability_sum - 1.0) > 1e-4) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::inference_failure,
                "terminal model probabilities do not sum to one");
        }

        const auto raw_label = outputs[0].GetTensorData<std::int64_t>()[0];
        if (raw_label < 0
            || raw_label
                >= static_cast<std::int64_t>(terminal_model_class_count_v1)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::inference_failure,
                "terminal model returned an out-of-range label");
        }
        const auto model_top = std::max_element(
            result.class_probabilities.begin(),
            result.class_probabilities.end());
        if (raw_label != std::distance(
                result.class_probabilities.begin(),
                model_top)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::inference_failure,
                "terminal model label disagrees with probability argmax");
        }

        result.attack_score =
            1.0 - static_cast<double>(result.class_probabilities[0]);
        result.attack = result.attack_score >= implementation_->threshold;
        if (result.attack) {
            const auto first = result.class_probabilities.begin() + 1;
            const auto top = std::max_element(
                first,
                result.class_probabilities.end());
            result.class_index = static_cast<std::size_t>(
                std::distance(result.class_probabilities.begin(), top));
        } else {
            result.class_index = 0U;
        }
        result.class_confidence =
            result.class_probabilities[result.class_index];
        return result;
    } catch (const LoadFailure& error) {
        return TerminalModelRuntimeError{error.code, error.what()};
    } catch (const Ort::Exception& error) {
        return TerminalModelRuntimeError{
            TerminalModelRuntimeErrorCode::inference_failure,
            error.what(),
        };
    } catch (const std::exception& error) {
        return TerminalModelRuntimeError{
            TerminalModelRuntimeErrorCode::inference_failure,
            error.what(),
        };
    } catch (...) {
        return TerminalModelRuntimeError{
            TerminalModelRuntimeErrorCode::inference_failure,
            "terminal model inference failed with an unknown exception",
        };
    }
}

TerminalModelBundleLoadResult load_terminal_model_bundle(
    const std::filesystem::path& staged_directory,
    std::string_view expected_manifest_sha256) {
    try {
        if (!valid_sha256(expected_manifest_sha256)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "expected terminal manifest SHA-256 must be 64 lowercase hex characters");
        }
        std::error_code error;
        const auto root_status = std::filesystem::symlink_status(
            staged_directory,
            error);
        if (error || !std::filesystem::is_directory(root_status)
            || std::filesystem::is_symlink(root_status)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::invalid_bundle_path,
                "staged terminal bundle directory does not exist or is a symlink: "
                    + staged_directory.string());
        }
        const auto root = std::filesystem::canonical(staged_directory, error);
        if (error) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::invalid_bundle_path,
                "cannot canonicalize staged terminal bundle: "
                    + staged_directory.string());
        }
        verify_staged_inventory(root);
        const auto models = root / "models";
        const auto models_status = std::filesystem::symlink_status(models, error);
        if (error || !std::filesystem::is_directory(models_status)
            || std::filesystem::is_symlink(models_status)) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::invalid_bundle_path,
                "terminal bundle models path is missing or is a symlink: "
                    + models.string());
        }

        const auto manifest_path = root / "manifest.json";
        require_regular_file(manifest_path, "terminal bundle manifest");
        const auto manifest_hash = sha256_file(manifest_path);
        if (manifest_hash != expected_manifest_sha256) {
            throw LoadFailure(
                TerminalModelRuntimeErrorCode::integrity_mismatch,
                "terminal bundle manifest hash mismatch: observed="
                    + manifest_hash + ", expected="
                    + std::string{expected_manifest_sha256});
        }
        const auto manifest = load_json(manifest_path);
        const auto member_hashes = verify_manifest_and_members(
            root,
            manifest.get());

        const auto schema = load_json(root / "feature_schema.json");
        verify_feature_schema(schema.get());
        const auto preprocessing = load_json(root / "preprocessing.json");
        verify_preprocessing(preprocessing.get());
        const auto thresholds = load_json(root / "thresholds.json");
        const auto threshold = verify_thresholds(thresholds.get());

        auto implementation = std::make_unique<TerminalModelBundle::Impl>();
        implementation->threshold = threshold;
        implementation->manifest_hash = manifest_hash;
        implementation->schema_hash = member_hashes.feature_schema;
        implementation->model_hash = member_hashes.model;
        implementation->session = Ort::Session{
            implementation->environment,
            (root / "models/terminal_multiclass.onnx").c_str(),
            implementation->session_options,
        };
        validate_session(implementation->session);
        return TerminalModelBundleLoadResult{
            std::unique_ptr<TerminalModelBundle>{
                new TerminalModelBundle{std::move(implementation)},
            },
            std::nullopt,
        };
    } catch (const LoadFailure& error) {
        return TerminalModelBundleLoadResult{
            nullptr,
            TerminalModelRuntimeError{error.code, error.what()},
        };
    } catch (const Ort::Exception& error) {
        return TerminalModelBundleLoadResult{
            nullptr,
            TerminalModelRuntimeError{
                TerminalModelRuntimeErrorCode::model_load_failure,
                error.what(),
            },
        };
    } catch (const std::exception& error) {
        return TerminalModelBundleLoadResult{
            nullptr,
            TerminalModelRuntimeError{
                TerminalModelRuntimeErrorCode::model_load_failure,
                error.what(),
            },
        };
    }
}

}
