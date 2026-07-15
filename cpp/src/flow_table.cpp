#include "nids/flow_table.hpp"

#include <algorithm>
#include <limits>
#include <memory_resource>
#include <new>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace nids {
namespace {

[[nodiscard]] constexpr std::size_t direction_index(FlowDirection direction) noexcept {
    return direction == FlowDirection::forward ? 0U : 1U;
}

[[nodiscard]] constexpr FlowDirection opposite_direction(FlowDirection direction) noexcept {
    return direction == FlowDirection::forward
        ? FlowDirection::reverse
        : FlowDirection::forward;
}

[[nodiscard]] constexpr bool flow_key_less(
    const FlowKey& left,
    const FlowKey& right) noexcept {
    if (left.protocol != right.protocol) {
        return left.protocol < right.protocol;
    }
    if (left.low != right.low) {
        return left.low < right.low;
    }
    return left.high < right.high;
}

struct FlowKeyHash {
    [[nodiscard]] std::size_t operator()(const FlowKey& key) const noexcept {
        auto hash = std::size_t{1'469'598'103'934'665'603ULL};
        const auto append = [&hash](std::uint8_t value) {
            hash ^= value;
            hash *= std::size_t{1'099'511'628'211ULL};
        };

        append(static_cast<std::uint8_t>(key.protocol));
        for (const auto value : key.low.address.wire_bytes) {
            append(value);
        }
        append(static_cast<std::uint8_t>(key.low.port >> 8U));
        append(static_cast<std::uint8_t>(key.low.port));
        for (const auto value : key.high.address.wire_bytes) {
            append(value);
        }
        append(static_cast<std::uint8_t>(key.high.port >> 8U));
        append(static_cast<std::uint8_t>(key.high.port));
        return hash;
    }
};

class BudgetMemoryResource final : public std::pmr::memory_resource {
public:
    explicit BudgetMemoryResource(std::size_t limit_bytes) noexcept
        : limit_bytes_{limit_bytes} {}

    [[nodiscard]] std::size_t current_bytes() const noexcept {
        return current_bytes_;
    }

    [[nodiscard]] std::size_t peak_bytes() const noexcept {
        return peak_bytes_;
    }

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        if (bytes > limit_bytes_ - current_bytes_) {
            throw std::bad_alloc{};
        }
        auto* allocation = std::pmr::new_delete_resource()->allocate(bytes, alignment);
        current_bytes_ += bytes;
        peak_bytes_ = std::max(peak_bytes_, current_bytes_);
        return allocation;
    }

    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
        std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
        current_bytes_ -= bytes;
    }

    [[nodiscard]] bool do_is_equal(
        const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }

    std::size_t limit_bytes_{};
    std::size_t current_bytes_{};
    std::size_t peak_bytes_{};
};

struct ActivityRecord {
    std::int64_t last_event_timestamp_ns{};
    std::uint64_t generation{};
    FlowKey key{};
};

struct ActivityRecordLess {
    [[nodiscard]] bool operator()(
        const ActivityRecord& left,
        const ActivityRecord& right) const noexcept {
        if (left.last_event_timestamp_ns != right.last_event_timestamp_ns) {
            return left.last_event_timestamp_ns < right.last_event_timestamp_ns;
        }
        if (left.generation != right.generation) {
            return left.generation < right.generation;
        }
        return flow_key_less(left.key, right.key);
    }
};

struct AgeRecord {
    std::int64_t creation_timestamp_ns{};
    std::uint64_t generation{};
    FlowKey key{};
};

struct AgeRecordLess {
    [[nodiscard]] bool operator()(
        const AgeRecord& left,
        const AgeRecord& right) const noexcept {
        if (left.creation_timestamp_ns != right.creation_timestamp_ns) {
            return left.creation_timestamp_ns < right.creation_timestamp_ns;
        }
        if (left.generation != right.generation) {
            return left.generation < right.generation;
        }
        return flow_key_less(left.key, right.key);
    }
};

[[nodiscard]] bool is_non_ack_syn(const PacketView& packet) noexcept {
    const auto* tcp = std::get_if<TcpView>(&packet.transport);
    return tcp != nullptr
        && tcp->flags.contains(TcpFlag::syn)
        && !tcp->flags.contains(TcpFlag::ack);
}

[[nodiscard]] bool starts_new_generation(
    const FlowState& state,
    const PacketView& packet) noexcept {
    if (!is_non_ack_syn(packet)) {
        return false;
    }
    const auto& tcp = std::get<TcpView>(packet.transport);
    return !state.initial_syn_retransmission_open
        || source_endpoint(packet) != state.initial_syn_source
        || tcp.sequence_number != state.initial_syn_sequence_number;
}

}

class FlowTable::Impl {
public:
    using FlowMap = std::pmr::unordered_map<FlowKey, FlowState, FlowKeyHash>;
    using ActivityIndex = std::pmr::set<ActivityRecord, ActivityRecordLess>;
    using AgeIndex = std::pmr::set<AgeRecord, AgeRecordLess>;

    Impl(
        FlowObserver* observer,
        FlowTableConfig config,
        std::uint64_t fixed_memory_bytes,
        std::size_t dynamic_memory_limit)
        : observer_{observer},
          config_{config},
          fixed_memory_bytes_{fixed_memory_bytes},
          memory_{dynamic_memory_limit},
          flows_{&memory_},
          activity_index_{&memory_},
          age_index_{&memory_} {
        flows_.max_load_factor(1.0F);
        try {
            flows_.reserve(config_.hard_active_flow_limit);
        } catch (const std::bad_alloc&) {
            throw std::invalid_argument{
                "FlowTable memory budget cannot hold the configured hash index"};
        }
    }

    [[nodiscard]] FlowIngestResult ingest(const PacketView& packet) {
        if (clock_domain_.has_value() && packet.clock_domain != *clock_domain_) {
            ++counters_.packets_rejected_clock_domain;
            return FlowIngestResult{FlowIngestStatus::clock_domain_mismatch};
        }

        const auto next_watermark = advance_timestamp_watermark(
            watermark_ns_,
            packet.timestamp_ns);
        if (clock_domain_.has_value()) {
            watermark_ns_ = next_watermark;
            expire(next_watermark);
        }

        const auto key = make_flow_key(packet);
        auto existing = flows_.find(key);
        if (existing != flows_.end() && starts_new_generation(existing->second, packet)) {
            close_flow(key, FlowCloseReason::tuple_reuse);
            existing = flows_.find(key);
        }

        if (existing == flows_.end()) {
            auto* state = create_flow(packet);
            if (state == nullptr) {
                ++counters_.packets_rejected_resource_exhausted;
                return FlowIngestResult{FlowIngestStatus::resource_exhausted};
            }
            const auto initialize_clock_domain = !clock_domain_.has_value();
            const auto result = update_flow(
                *state,
                packet,
                FlowDirection::forward,
                true);
            if (initialize_clock_domain
                && result.status == FlowIngestStatus::accepted) {
                clock_domain_ = packet.clock_domain;
                watermark_ns_ = next_watermark;
            }
            return result;
        }

        auto& state = existing->second;
        const auto direction = flow_direction(state.identity, packet);
        if (!direction.has_value()) {
            throw std::logic_error{"FlowTable key matched but direction was not resolvable"};
        }
        return update_flow(state, packet, *direction, false);
    }

    void flush() {
        while (!age_index_.empty()) {
            close_flow(age_index_.begin()->key, FlowCloseReason::end_of_input);
        }
    }

    [[nodiscard]] const FlowState* find(const FlowKey& key) const noexcept {
        const auto found = flows_.find(key);
        return found == flows_.end() ? nullptr : &found->second;
    }

    [[nodiscard]] FlowCounters counters() const noexcept {
        auto result = counters_;
        result.active_flow_count = static_cast<std::uint32_t>(flows_.size());
        result.fixed_memory_bytes = fixed_memory_bytes_;
        result.current_allocator_bytes = memory_.current_bytes();
        result.peak_allocator_bytes = memory_.peak_bytes();
        result.current_memory_bytes = result.fixed_memory_bytes
            + result.current_allocator_bytes;
        result.peak_memory_bytes = result.fixed_memory_bytes
            + result.peak_allocator_bytes;
        result.memory_budget_bytes = config_.memory_budget_bytes;
        return result;
    }

    [[nodiscard]] std::optional<std::int64_t> watermark_ns() const noexcept {
        return watermark_ns_;
    }

    [[nodiscard]] std::optional<ClockDomain> clock_domain() const noexcept {
        return clock_domain_;
    }

private:
    [[nodiscard]] FlowState* create_flow(const PacketView& packet) {
        while (flows_.size() >= config_.hard_active_flow_limit) {
            evict_one();
        }

        const auto generation = next_generation_;
        const auto state = FlowState{
            make_flow_identity(packet),
            generation,
            packet.clock_domain,
            packet.timestamp_ns,
            packet.timestamp_ns,
            packet.timestamp_ns,
        };

        while (!insert_state(state)) {
            if (flows_.empty()) {
                return nullptr;
            }
            evict_one();
        }

        ++next_generation_;
        ++counters_.flow_generations_created;
        counters_.peak_active_flow_count = std::max(
            counters_.peak_active_flow_count,
            static_cast<std::uint32_t>(flows_.size()));
        return &flows_.find(state.identity.key)->second;
    }

    [[nodiscard]] bool insert_state(const FlowState& state) {
        try {
            const auto [flow, flow_inserted] = flows_.emplace(state.identity.key, state);
            if (!flow_inserted) {
                return false;
            }

            const auto activity = ActivityRecord{
                state.last_event_timestamp_ns,
                state.generation,
                state.identity.key,
            };
            const auto [activity_position, activity_inserted] = activity_index_.insert(activity);
            if (!activity_inserted) {
                flows_.erase(flow);
                return false;
            }

            const auto age = AgeRecord{
                state.creation_timestamp_ns,
                state.generation,
                state.identity.key,
            };
            const auto [age_position, age_inserted] = age_index_.insert(age);
            if (!age_inserted) {
                activity_index_.erase(activity_position);
                flows_.erase(flow);
                return false;
            }
            return true;
        } catch (const std::bad_alloc&) {
            const auto flow = flows_.find(state.identity.key);
            if (flow != flows_.end() && flow->second.generation == state.generation) {
                activity_index_.erase(ActivityRecord{
                    state.last_event_timestamp_ns,
                    state.generation,
                    state.identity.key,
                });
                age_index_.erase(AgeRecord{
                    state.creation_timestamp_ns,
                    state.generation,
                    state.identity.key,
                });
                flows_.erase(flow);
            }
            return false;
        }
    }

    [[nodiscard]] FlowIngestResult update_flow(
        FlowState& state,
        const PacketView& packet,
        FlowDirection direction,
        bool created) {
        auto flow_iat = std::optional<std::int64_t>{};
        auto direction_iat = std::optional<std::int64_t>{};
        const auto index = direction_index(direction);

        if (state.packet_count == std::numeric_limits<std::uint64_t>::max()) {
            ++counters_.packets_rejected_feature_update;
            return FlowIngestResult{
                .status = FlowIngestStatus::feature_update_error,
                .generation = state.generation,
                .direction = direction,
                .feature_error = FeatureErrorCode::numeric_overflow,
                .created = created,
            };
        }

        if (state.packet_count != 0U) {
            flow_iat = signed_iat_ns(packet.timestamp_ns, state.last_capture_timestamp_ns);
            if (!flow_iat.has_value()) {
                ++counters_.packets_rejected_timestamp_overflow;
                return FlowIngestResult{FlowIngestStatus::timestamp_overflow};
            }
        }
        if (state.last_direction_timestamp_ns[index].has_value()) {
            direction_iat = signed_iat_ns(
                packet.timestamp_ns,
                *state.last_direction_timestamp_ns[index]);
            if (!direction_iat.has_value()) {
                ++counters_.packets_rejected_timestamp_overflow;
                return FlowIngestResult{FlowIngestStatus::timestamp_overflow};
            }
        }

        const auto next_packet_count = state.packet_count + 1U;
        const auto feature_update = FeatureEngine::update(
            state.feature_state,
            packet,
            direction,
            flow_iat,
            direction_iat,
            next_packet_count);
        if (feature_update.has_value()) {
            ++counters_.packets_rejected_feature_update;
            const auto result = FlowIngestResult{
                .status = FlowIngestStatus::feature_update_error,
                .generation = state.generation,
                .direction = direction,
                .flow_iat_ns = flow_iat,
                .direction_iat_ns = direction_iat,
                .feature_error = feature_update->code,
                .created = created,
            };
            if (created) {
                discard_flow(state);
            }
            return result;
        }

        const auto previous_event_timestamp = state.last_event_timestamp_ns;
        state.last_capture_timestamp_ns = packet.timestamp_ns;
        state.last_event_timestamp_ns = std::max(
            state.last_event_timestamp_ns,
            packet.timestamp_ns);
        state.last_direction_timestamp_ns[index] = packet.timestamp_ns;
        ++state.packet_count;
        ++state.directional_packet_count[index];

        update_initial_syn_tracking(state, packet);
        const auto close_reason = update_tcp_close_state(state, packet, direction);
        update_activity_index(state, previous_event_timestamp);
        const auto checkpoint = state.checkpoint_tracker.claim(state.packet_count);

        const auto context = FlowPacketContext{
            .direction = direction,
            .flow_iat_ns = flow_iat,
            .direction_iat_ns = direction_iat,
            .checkpoint = checkpoint,
            .created = created,
        };
        ++counters_.packets_accepted;
        const auto state_snapshot = state;
        const auto result = FlowIngestResult{
            .status = FlowIngestStatus::accepted,
            .generation = state_snapshot.generation,
            .direction = direction,
            .flow_iat_ns = flow_iat,
            .direction_iat_ns = direction_iat,
            .created = created,
            .close_reason = close_reason,
        };
        auto close_snapshot = std::optional<FlowState>{};
        if (close_reason.has_value()) {
            close_snapshot = detach_flow(state_snapshot.identity.key, *close_reason);
        }
        if (observer_ != nullptr) {
            observer_->on_packet(state_snapshot, packet, context);
            if (close_snapshot.has_value()) {
                observer_->on_close(*close_snapshot, *close_reason);
            }
        }
        return result;
    }

    static void update_initial_syn_tracking(
        FlowState& state,
        const PacketView& packet) noexcept {
        const auto* tcp = std::get_if<TcpView>(&packet.transport);
        const auto non_ack_syn = tcp != nullptr
            && tcp->flags.contains(TcpFlag::syn)
            && !tcp->flags.contains(TcpFlag::ack);

        if (state.packet_count == 1U && non_ack_syn) {
            state.initial_syn_retransmission_open = true;
            state.initial_syn_source = source_endpoint(packet);
            state.initial_syn_sequence_number = tcp->sequence_number;
            return;
        }

        const auto repeats_initial_syn = non_ack_syn
            && state.initial_syn_retransmission_open
            && source_endpoint(packet) == state.initial_syn_source
            && tcp->sequence_number == state.initial_syn_sequence_number;
        if (!repeats_initial_syn) {
            state.initial_syn_retransmission_open = false;
        }
    }

    [[nodiscard]] static std::optional<FlowCloseReason> update_tcp_close_state(
        FlowState& state,
        const PacketView& packet,
        FlowDirection direction) noexcept {
        const auto* tcp = std::get_if<TcpView>(&packet.transport);
        if (tcp == nullptr) {
            return std::nullopt;
        }

        const auto final_ack_seen = state.final_ack_direction == direction
            && tcp->flags.contains(TcpFlag::ack);
        if (tcp->flags.contains(TcpFlag::fin)) {
            const auto had_both_fin = state.fin_seen[0] && state.fin_seen[1];
            state.fin_seen[direction_index(direction)] = true;
            if (!had_both_fin && state.fin_seen[0] && state.fin_seen[1]) {
                state.final_ack_direction = opposite_direction(direction);
            }
        }

        if (tcp->flags.contains(TcpFlag::rst)) {
            return FlowCloseReason::tcp_reset;
        }
        if (final_ack_seen) {
            return FlowCloseReason::tcp_fin_handshake;
        }
        return std::nullopt;
    }

    void update_activity_index(
        const FlowState& state,
        std::int64_t previous_event_timestamp) {
        if (state.last_event_timestamp_ns == previous_event_timestamp) {
            return;
        }
        auto node = activity_index_.extract(ActivityRecord{
            previous_event_timestamp,
            state.generation,
            state.identity.key,
        });
        if (node.empty()) {
            throw std::logic_error{"FlowTable activity index is inconsistent"};
        }
        node.value().last_event_timestamp_ns = state.last_event_timestamp_ns;
        activity_index_.insert(std::move(node));
    }

    void expire(std::int64_t watermark) {
        while (!activity_index_.empty()
            && idle_timeout_expired(
                watermark,
                activity_index_.begin()->last_event_timestamp_ns)) {
            close_flow(activity_index_.begin()->key, FlowCloseReason::idle_timeout);
        }
        while (!age_index_.empty()
            && maximum_age_expired(
                watermark,
                age_index_.begin()->creation_timestamp_ns)) {
            close_flow(age_index_.begin()->key, FlowCloseReason::maximum_age);
        }
    }

    void evict_one() {
        if (activity_index_.empty()) {
            return;
        }
        close_flow(activity_index_.begin()->key, FlowCloseReason::capacity_eviction);
    }

    void close_flow(const FlowKey& key, FlowCloseReason reason) {
        const auto snapshot = detach_flow(key, reason);
        if (snapshot.has_value() && observer_ != nullptr) {
            observer_->on_close(*snapshot, reason);
        }
    }

    void discard_flow(const FlowState& state) noexcept {
        activity_index_.erase(ActivityRecord{
            state.last_event_timestamp_ns,
            state.generation,
            state.identity.key,
        });
        age_index_.erase(AgeRecord{
            state.creation_timestamp_ns,
            state.generation,
            state.identity.key,
        });
        flows_.erase(state.identity.key);
    }

    [[nodiscard]] std::optional<FlowState> detach_flow(
        const FlowKey& key,
        FlowCloseReason reason) {
        const auto found = flows_.find(key);
        if (found == flows_.end()) {
            return std::nullopt;
        }
        const auto state = found->second;
        ++counters_.flows_closed;
        ++counters_.close_reason_count[flow_close_reason_index(reason)];

        activity_index_.erase(ActivityRecord{
            state.last_event_timestamp_ns,
            state.generation,
            state.identity.key,
        });
        age_index_.erase(AgeRecord{
            state.creation_timestamp_ns,
            state.generation,
            state.identity.key,
        });
        flows_.erase(found);
        return state;
    }

    FlowObserver* observer_{};
    FlowTableConfig config_{};
    std::uint64_t fixed_memory_bytes_{};
    BudgetMemoryResource memory_;
    FlowMap flows_;
    ActivityIndex activity_index_;
    AgeIndex age_index_;
    FlowCounters counters_{};
    std::optional<std::int64_t> watermark_ns_{};
    std::optional<ClockDomain> clock_domain_{};
    std::uint64_t next_generation_{1U};
};

FlowTable::FlowTable(FlowTableConfig config) : FlowTable{nullptr, config} {}

FlowTable::FlowTable(FlowObserver& observer, FlowTableConfig config)
    : FlowTable{&observer, config} {}

FlowTable::FlowTable(FlowObserver* observer, FlowTableConfig config) {
    if (config.hard_active_flow_limit == 0U) {
        throw std::invalid_argument{"FlowTable hard active-flow limit must be positive"};
    }

    const auto fixed_memory_bytes = std::uint64_t{sizeof(FlowTable) + sizeof(Impl)};
    if (config.memory_budget_bytes <= fixed_memory_bytes) {
        throw std::invalid_argument{"FlowTable memory budget is smaller than its fixed state"};
    }
    const auto available = config.memory_budget_bytes - fixed_memory_bytes;
    const auto dynamic_limit = static_cast<std::size_t>(std::min<std::uint64_t>(
        available,
        std::numeric_limits<std::size_t>::max()));
    impl_ = std::make_unique<Impl>(
        observer,
        config,
        fixed_memory_bytes,
        dynamic_limit);
}

FlowTable::~FlowTable() = default;
FlowTable::FlowTable(FlowTable&&) noexcept = default;
FlowTable& FlowTable::operator=(FlowTable&&) noexcept = default;

FlowIngestResult FlowTable::ingest(const PacketView& packet) {
    return impl_->ingest(packet);
}

void FlowTable::flush() {
    impl_->flush();
}

const FlowState* FlowTable::find(const FlowKey& key) const noexcept {
    return impl_->find(key);
}

std::optional<std::int64_t> FlowTable::watermark_ns() const noexcept {
    return impl_->watermark_ns();
}

std::optional<ClockDomain> FlowTable::clock_domain() const noexcept {
    return impl_->clock_domain();
}

FlowCounters FlowTable::counters() const noexcept {
    return impl_->counters();
}

}
