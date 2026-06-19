#include "subsystems/reconnection.h"
#include "logger.h"

#include <algorithm>
#include <vector>

namespace librats {

ReconnectionService::ReconnectionService() : ReconnectionService(Config()) {}

ReconnectionService::ReconnectionService(Config config) : config_(std::move(config)) {}

ReconnectionService::~ReconnectionService() { stop(); }

void ReconnectionService::add(const Address& address) {
    const std::string key = address.to_string();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto [it, inserted] = targets_.try_emplace(key);
        if (!inserted) return;
        it->second.address = address;
        it->second.next_attempt = std::chrono::steady_clock::now();
    }
    if (store_ && store_->add(address)) store_->save();
    wake_.notify_all();
}

size_t ReconnectionService::target_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return targets_.size();
}

void ReconnectionService::attach(PeerNetwork& network) {
    network_ = &network;
    network_->on_peer_connected([this](const PeerHandle& peer) { on_connected(peer); });
    network_->on_peer_disconnected([this](const PeerId& id) { on_disconnected(id); });
}

void ReconnectionService::start() {
    if (running_.exchange(true)) return;

    if (!config_.store_path.empty()) {
        store_ = std::make_unique<PeerStore>(config_.store_path);
        store_->load();
        for (const Address& addr : store_->all()) {
            std::lock_guard<std::mutex> lock(mutex_);
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

void ReconnectionService::on_connected(const PeerHandle& peer) {
    auto info = peer.info();
    if (!info) return;

    bool learned = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Address& addr : info->addresses) {
            const std::string key = addr.to_string();
            auto it = targets_.find(key);
            if (it == targets_.end()) {
                if (!config_.persist_discovered) continue;
                it = targets_.emplace(key, Target{}).first;
                it->second.address = addr;
                learned = true;
            }
            it->second.connected = true;
            it->second.peer_id = peer.id();
            it->second.attempts = 0;
        }
    }
    if (learned && store_) {
        for (const Address& addr : info->addresses) if (store_->add(addr)) store_->save();
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

        std::vector<Address> to_dial;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [key, target] : targets_) {
                if (!target.connected && target.next_attempt <= now) {
                    to_dial.push_back(target.address);
                    target.attempts++;
                    target.next_attempt = now + backoff_for(target.attempts);
                }
            }
        }
        for (const Address& addr : to_dial) {
            LOG_DEBUG("reconnect", "Dialing " << addr.to_string());
            network_->connect(addr);
        }

        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_for(lock, config_.tick, [this] { return !running_.load(); });
    }
}

} // namespace librats
