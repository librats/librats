#include "subsystems/reconnection.h"
#include "node/node_context.h"
#include "util/logger.h"

#include <algorithm>
#include <vector>

namespace librats {

ReconnectionService::ReconnectionService() : ReconnectionService(Config()) {}

ReconnectionService::ReconnectionService(Config config) : config_(std::move(config)) {
    // Construct the store up front so the pointer is fixed for the object's life
    // (no race with reactor-thread reads in on_connected) and so add() called
    // before start() persists into an already-loaded set rather than clobbering it.
    if (!config_.store_path.empty()) {
        store_ = std::make_unique<PeerStore>(config_.store_path);
        store_->load();
    }
}

ReconnectionService::~ReconnectionService() { stop(); }

void ReconnectionService::add(const Address& address) {
    const std::string key = address.to_string();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (targets_.find(key) != targets_.end()) return;
        if (targets_.size() >= config_.max_targets) {
            LOG_WARN("reconnect", "Target cap (" << config_.max_targets << ") reached; dropping " << key);
            return;
        }
        Target& t = targets_[key];
        t.address = address;
        t.next_attempt = std::chrono::steady_clock::now();
    }
    if (store_ && store_->add(address)) store_->save();
    wake_.notify_all();
}

void ReconnectionService::remove(const Address& address) {
    bool erased;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        erased = targets_.erase(address.to_string()) > 0;
    }
    if (store_ && store_->remove(address)) store_->save();
    if (erased) LOG_DEBUG("reconnect", "Stopped reconnecting to " << address.to_string());
}

size_t ReconnectionService::target_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return targets_.size();
}

void ReconnectionService::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    network_->on_peer_connected([this](const Peer& peer) { on_connected(peer); });
    network_->on_peer_disconnected([this](const PeerId& id) { on_disconnected(id); });
}

void ReconnectionService::start() {
    if (running_.exchange(true)) return;

    if (store_) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Address& addr : store_->all()) {
            if (targets_.size() >= config_.max_targets) break;
            auto [it, inserted] = targets_.try_emplace(addr.to_string());
            if (inserted) { it->second.address = addr; it->second.next_attempt = std::chrono::steady_clock::now(); }
        }
    }
    thread_ = std::thread(&ReconnectionService::loop, this);
}

void ReconnectionService::stop() {
    if (!running_.exchange(false)) return;
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    if (store_) store_->save();
}

void ReconnectionService::on_connected(const Peer& peer) {
    auto info = peer.info();
    if (!info) return;

    std::vector<Address> learned;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Address& addr : info->addresses) {
            const std::string key = addr.to_string();
            auto it = targets_.find(key);
            if (it == targets_.end()) {
                if (!config_.persist_discovered) continue;
                if (targets_.size() >= config_.max_targets) continue;  // bound discovered growth
                it = targets_.emplace(key, Target{}).first;
                it->second.address = addr;
                learned.push_back(addr);
            }
            it->second.connected = true;
            it->second.peer_id = peer.id();
            it->second.attempts = 0;
        }
    }
    if (store_ && !learned.empty()) {
        bool changed = false;
        for (const Address& addr : learned) changed |= store_->add(addr);
        if (changed) store_->save();
    }
}

void ReconnectionService::on_disconnected(const PeerId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, target] : targets_) {
        if (target.connected && target.peer_id == id) {
            target.connected = false;
            target.attempts = 0;
            target.next_attempt = std::chrono::steady_clock::now();  // re-dial promptly
            wake_.notify_all();
        }
    }
}

std::chrono::milliseconds ReconnectionService::backoff_for(int attempts) const {
    // base * 2^(attempts-1), capped at max.
    auto delay = config_.base_backoff;
    for (int i = 1; i < attempts && delay < config_.max_backoff; ++i) delay *= 2;
    return std::min(delay, config_.max_backoff);
}

void ReconnectionService::loop() {
    while (running_.load()) {
        const auto now = std::chrono::steady_clock::now();

        std::vector<Address> to_dial, gave_up;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = targets_.begin(); it != targets_.end();) {
                Target& target = it->second;
                if (target.connected || target.next_attempt > now) { ++it; continue; }

                // Give up on a persistently-dead target: drop it (and from the store
                // below) instead of re-dialing forever. A reconnect resets attempts,
                // so this only reaps addresses that never came back.
                if (config_.max_attempts > 0 && target.attempts >= config_.max_attempts) {
                    gave_up.push_back(target.address);
                    it = targets_.erase(it);
                    continue;
                }

                to_dial.push_back(target.address);
                target.attempts++;
                target.next_attempt = now + backoff_for(target.attempts);
                ++it;
            }
        }
        if (store_ && !gave_up.empty()) {
            bool changed = false;
            for (const Address& addr : gave_up) changed |= store_->remove(addr);
            if (changed) store_->save();
        }
        for (const Address& addr : gave_up)
            LOG_DEBUG("reconnect", "Giving up on " << addr.to_string() << " after "
                      << config_.max_attempts << " attempts");
        for (const Address& addr : to_dial) {
            LOG_DEBUG("reconnect", "Dialing " << addr.to_string());
            network_->connect(addr);
        }

        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_for(lock, config_.tick, [this] { return !running_.load(); });
    }
}

} // namespace librats
