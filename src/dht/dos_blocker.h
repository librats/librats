#pragma once

/**
 * @file dos_blocker.h
 * @brief Per-IP flood protection for the DHT's incoming path.
 *
 * A peer is allowed a burst of packets per short window; cross the threshold and it's
 * banned for a while. Cheap and bounded — a single counter + two timestamps per IP,
 * with the tracking table capped. Consulted before any incoming packet is processed.
 */

#include "dht/observer.h"  // for TimePoint

#include <chrono>
#include <cstddef>
#include <string>
#include <unordered_map>

namespace librats {
namespace dht {

class DosBlocker {
public:
    static constexpr int kMaxPerWindow = 50;                 // packets per window before a ban
    static constexpr std::chrono::seconds kWindow{10};
    static constexpr std::chrono::minutes kBanDuration{5};
    static constexpr std::size_t kMaxTracked = 2000;         // cap the per-IP table

    // True if a packet from `ip` should be processed; false if it's being rate-limited.
    bool allow(const std::string& ip, TimePoint now);

    std::size_t tracked() const noexcept { return table_.size(); }

private:
    struct Entry {
        int       count = 0;
        TimePoint window_start{};
        TimePoint banned_until{};
    };

    void prune(TimePoint now);

    std::unordered_map<std::string, Entry> table_;
};

} // namespace dht
} // namespace librats
