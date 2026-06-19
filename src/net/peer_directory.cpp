#include "net/peer_directory.h"

#include <mutex>  // std::unique_lock (shared_lock comes from <shared_mutex>)

namespace librats {

void PeerDirectory::add(const PeerInfo& info, PeerRoute route) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto [it, inserted] = peers_.try_emplace(info.id, Entry{info, route});
    if (inserted) {
        count_.fetch_add(1, std::memory_order_relaxed);
    } else {
        it->second = Entry{info, route};  // replace (e.g. reconnect)
    }
}

void PeerDirectory::remove(const PeerId& id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (peers_.erase(id) > 0) {
        count_.fetch_sub(1, std::memory_order_relaxed);
    }
}

std::optional<PeerRoute> PeerDirectory::route(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) return std::nullopt;
    return it->second.route;
}

std::optional<PeerInfo> PeerDirectory::info(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) return std::nullopt;
    return it->second.info;
}

bool PeerDirectory::contains(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return peers_.find(id) != peers_.end();
}

std::vector<PeerInfo> PeerDirectory::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<PeerInfo> out;
    out.reserve(peers_.size());
    for (const auto& [id, entry] : peers_) out.push_back(entry.info);
    return out;
}

} // namespace librats
