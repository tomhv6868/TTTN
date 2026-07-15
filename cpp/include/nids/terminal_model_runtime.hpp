#pragma once

#include "nids/terminal_feature.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace nids {

inline constexpr std::size_t terminal_model_feature_count_v1 = 54U;
inline constexpr std::size_t terminal_model_class_count_v1 = 6U;

enum class TerminalModelRuntimeErrorCode : std::uint8_t {
    invalid_bundle_path,
    integrity_mismatch,
    invalid_json,
    schema_mismatch,
    model_load_failure,
    invalid_input,
    inference_failure,
};

struct TerminalModelRuntimeError {
    TerminalModelRuntimeErrorCode code{};
    std::string detail{};
};

struct TerminalModelScores {
    std::array<float, terminal_model_class_count_v1> class_probabilities{};
    std::size_t class_index{};
    float class_confidence{};
    double attack_score{};
    bool attack{};
};

using TerminalModelInferenceResult =
    std::variant<TerminalModelScores, TerminalModelRuntimeError>;

struct TerminalModelBundleLoadResult;

class TerminalModelBundle final {
public:
    ~TerminalModelBundle();
    TerminalModelBundle(TerminalModelBundle&&) noexcept;
    TerminalModelBundle& operator=(TerminalModelBundle&&) noexcept;

    TerminalModelBundle(const TerminalModelBundle&) = delete;
    TerminalModelBundle& operator=(const TerminalModelBundle&) = delete;

    [[nodiscard]] std::string_view artifact_id() const noexcept;
    [[nodiscard]] std::string_view artifact_version() const noexcept;
    [[nodiscard]] std::string_view profile_id() const noexcept;
    [[nodiscard]] double attack_threshold() const noexcept;
    [[nodiscard]] std::string_view manifest_sha256() const noexcept;
    [[nodiscard]] std::string_view feature_schema_sha256() const noexcept;
    [[nodiscard]] std::string_view model_sha256() const noexcept;
    [[nodiscard]] std::span<
        const std::string,
        terminal_model_class_count_v1>
    class_names() const noexcept;

    [[nodiscard]] TerminalModelInferenceResult infer(
        std::span<const double, terminal_feature_count> features) const noexcept;

private:
    struct Impl;

    explicit TerminalModelBundle(
        std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> implementation_;

    friend TerminalModelBundleLoadResult load_terminal_model_bundle(
        const std::filesystem::path& staged_directory,
        std::string_view expected_manifest_sha256);
};

struct TerminalModelBundleLoadResult {
    std::unique_ptr<TerminalModelBundle> bundle{};
    std::optional<TerminalModelRuntimeError> error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return bundle != nullptr;
    }
};

[[nodiscard]] TerminalModelBundleLoadResult load_terminal_model_bundle(
    const std::filesystem::path& staged_directory,
    std::string_view expected_manifest_sha256);

}
