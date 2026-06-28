#include "dht/dos_blocker.h"
#include "dht/log.h"

namespace librats {
namespace dht {

bool DosBlocker::allow(const std::string& ip, TimePoint now) {
    Entry& e = table_[ip];

    if (e.banned_until > now) return false;  // still serving a ban

    if (now - e.window_start >= kWindow) {   // start of a fresh window
        e.window_start = now;
        e.count = 0;
    }

    if (++e.count > kMaxPerWindow) {
        e.banned_until = now + kBanDuration;
        // Logged once at the ban transition only — the top-of-function early return keeps
        // every subsequent packet from this IP from re-logging. DEBUG (not WARN) on purpose:
        // a spoofed-source flood could otherwise turn one ban per IP into log amplification.
        LOG_DEBUG("dht", "rate-limit ban: " << ip << " (" << e.count << " queries in window)");
        return false;
    }

    if (table_.size() > kMaxTracked) prune(now);
    return true;
}

void DosBlocker::prune(TimePoint now) {
    // Drop idle, unbanned entries; they carry no state worth keeping.
    for (auto it = table_.begin(); it != table_.end();) {
        const Entry& e = it->second;
        if (e.banned_until <= now && now - e.window_start >= kWindow)
            it = table_.erase(it);
        else
            ++it;
    }
}

} // namespace dht
} // namespace librats
