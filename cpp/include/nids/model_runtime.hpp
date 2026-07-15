#pragma once

#include "nids/checkpoint.hpp"

#include <array>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>

namespace nids {

inline constexpr std::size_t known_family_count_v1 = 13U;

struct AnomalyScore {
    double raw{};
    double normalized{};
    bool threshold_exceeded{};
};

struct ModelScores {
    float flow_attack_probability{};
    bool flow_attack{};
    std::array<float, known_family_count_v1> known_family_probabilities{};
    std::size_t known_family_index{};
    float known_family_confidence{};
    AnomalyScore hbos{};
    AnomalyScore isolation_forest{};
};

enum class ModelRuntimeErrorCode {
    invalid_bundle_path,
    integrity_mismatch,
    invalid_json,
    schema_mismatch,
    model_load_failure,
    invalid_input,
    inference_failure,
};

struct ModelRuntimeError {
    ModelRuntimeErrorCode code{};
    std::string detail{};
};

using ModelInferenceResult = std::variant<ModelScores, ModelRuntimeError>;
using FileSha256Result = std::variant<std::string, ModelRuntimeError>;

struct ModelBundleLoadResult;

class ModelBundle final {
public:
    ~ModelBundle();
    ModelBundle(ModelBundle&&) noexcept;
    ModelBundle& operator=(ModelBundle&&) noexcept;

    ModelBundle(const ModelBundle&) = delete;
    ModelBundle& operator=(const ModelBundle&) = delete;

    [[nodiscard]] Checkpoint checkpoint() const noexcept;
    [[nodiscard]] std::span<const std::string, known_family_count_v1>
    known_family_names() const noexcept;
    [[nodiscard]] ModelInferenceResult infer(
        std::span<const double, flow_feature_count_v1> features) const noexcept;

private:
    struct Impl;

    explicit ModelBundle(std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> implementation_;

    friend ModelBundleLoadResult load_model_bundle(
        const std::filesystem::path& staged_directory);
};

struct ModelBundleLoadResult {
    std::unique_ptr<ModelBundle> bundle{};
    std::optional<ModelRuntimeError> error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return bundle != nullptr;
    }
};

[[nodiscard]] ModelBundleLoadResult load_model_bundle(
    const std::filesystem::path& staged_directory);

[[nodiscard]] FileSha256Result compute_file_sha256(
    const std::filesystem::path& path) noexcept;

}
