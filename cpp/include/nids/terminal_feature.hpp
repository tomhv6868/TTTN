#pragma once

#include "nids/flow_table.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <variant>

namespace nids {

inline constexpr std::size_t terminal_feature_count = 70U;
using TerminalFeatureVector = std::array<double, terminal_feature_count>;

enum class TerminalFeatureErrorCode : std::uint8_t {
    duplicate_generation,
    missing_generation,
    numeric_overflow,
    non_finite_value,
    base_feature_error,
    resource_exhausted,
};

struct TerminalFeatureError {
    TerminalFeatureErrorCode code{};
    std::uint64_t generation{};
};

using TerminalFeatureUpdateResult = std::optional<TerminalFeatureError>;
using TerminalFeatureVectorResult =
    std::variant<TerminalFeatureVector, TerminalFeatureError>;

class TerminalFeatureEngine {
public:
    TerminalFeatureEngine();
    ~TerminalFeatureEngine();

    TerminalFeatureEngine(const TerminalFeatureEngine&) = delete;
    TerminalFeatureEngine& operator=(const TerminalFeatureEngine&) = delete;
    TerminalFeatureEngine(TerminalFeatureEngine&&) noexcept;
    TerminalFeatureEngine& operator=(TerminalFeatureEngine&&) noexcept;

    [[nodiscard]] TerminalFeatureUpdateResult update(
        const FlowState& state,
        const PacketView& packet,
        const FlowPacketContext& context) noexcept;

    [[nodiscard]] TerminalFeatureVectorResult close(
        const FlowState& state) noexcept;

    [[nodiscard]] std::size_t active_generation_count() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}
