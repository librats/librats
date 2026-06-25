#pragma once

/**
 * @file node_entry.h
 * @brief A single contact in the routing table: who it is, where to reach it, and
 *        the liveness/quality bookkeeping that decides who to keep or evict.
 *
 * Quality model (mirrors libtorrent's node_entry):
 *   - rtt        — smoothed round-trip time; kRttUnknown until the first reply.
 *   - fail_count — consecutive failed queries; kNeverPinged means we've only ever
 *                  *heard about* this node (from someone else's reply) and never had
 *                  a reply from it ourselves.
 *   - verified   — its id is derived from its IP per BEP 42, so it's harder to spoof
 *                  and is preferred when we have to choose who to drop.
 */

#include "core/address.h"
#include "dht/id.h"

#include <chrono>
#include <cstdint>
#include <utility>

namespace librats {
namespace dht {

struct NodeEntry {
    static constexpr uint16_t kRttUnknown  = 0xffff;  // no RTT sample yet
    static constexpr uint8_t  kNeverPinged = 0xff;    // only heard about, never replied

    NodeId   id{};
    Address  endpoint;
    // Last time we "touched" this contact: a reply received OR a probe issued to it.
    // Defaults to the clock minimum so a never-contacted contact sorts as most stale
    // (refreshed first). Read only by RoutingTable::next_to_refresh for its ordering.
    std::chrono::steady_clock::time_point last_seen{std::chrono::steady_clock::time_point::min()};
    uint16_t rtt        = kRttUnknown;
    uint8_t  fail_count = kNeverPinged;
    bool     verified   = false;

    NodeEntry() = default;
    NodeEntry(const NodeId& id, Address endpoint)
        : id(id), endpoint(std::move(endpoint)) {}

    // Have we ever had a reply from this node (vs only heard it mentioned)?
    bool pinged() const noexcept { return fail_count != kNeverPinged; }
    // Replied with no outstanding failures — safe to hand out and keep.
    bool confirmed() const noexcept { return fail_count == 0; }

    // A reply arrived: clear failures, refresh last_seen, fold in the RTT sample.
    void record_success(uint16_t rtt_sample = kRttUnknown) noexcept {
        fail_count = 0;
        last_seen  = std::chrono::steady_clock::now();
        update_rtt(rtt_sample);
    }

    // A query to this node timed out. Only meaningful once pinged; saturates just
    // below kNeverPinged so a long-dead node never wraps back to "never pinged".
    void record_failure() noexcept {
        if (pinged() && fail_count < kNeverPinged - 1) ++fail_count;
    }

    // Exponential moving average (2/3 old + 1/3 new), seeded by the first sample.
    void update_rtt(uint16_t sample) noexcept {
        if (sample == kRttUnknown) return;
        rtt = (rtt == kRttUnknown)
                  ? sample
                  : static_cast<uint16_t>(rtt * 2 / 3 + sample / 3);
    }

    // Eviction ordering: true if *this is the worse contact and should go first.
    // Worse = more failures, then unverified before verified, then higher RTT.
    bool is_worse_than(const NodeEntry& other) const noexcept {
        if (fail_count != other.fail_count) return fail_count > other.fail_count;
        if (verified   != other.verified)   return !verified;  // unverified is worse
        return rtt > other.rtt;
    }
};

} // namespace dht
} // namespace librats
