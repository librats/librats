#include "subsystems/ping_service.h"

#include <cstring>

namespace librats {

namespace {
constexpr uint8_t kPing = 0;
constexpr uint8_t kPong = 1;
constexpr size_t  kProbeSize = 1 + 8;  // tag + 8-byte token

uint64_t now_ticks() {
    return static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
}
} // namespace

PingService::PingService(std::chrono::milliseconds interval) : interval_(interval) {}

PingService::~PingService() { stop(); }

void PingService::attach(PeerNetwork& network) {
    network_ = &network;
    network_->on_message(MessageType::Ping,
                         [this](const Peer& peer, ByteView payload) { handle(peer, payload); });
}

void PingService::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&PingService::run, this);
}

void PingService::stop() {
    if (!running_.exchange(false)) return;
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void PingService::run() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_for(lock, interval_, [this] { return !running_.load(); });
        if (!running_.load()) break;
        lock.unlock();
        ping_all();
    }
}

void PingService::ping_all() {
    if (!network_) return;

    uint8_t probe[kProbeSize];
    probe[0] = kPing;
    const uint64_t token = now_ticks();
    std::memcpy(probe + 1, &token, 8);

    for (const PeerId& id : network_->connected_peers())
        network_->send(id, MessageType::Ping, ByteView(probe, kProbeSize));
}

void PingService::handle(const Peer& peer, ByteView payload) {
    if (payload.size() != kProbeSize) return;
    const uint8_t tag = payload.data()[0];

    if (tag == kPing) {
        // Echo the probe straight back as a pong.
        uint8_t pong[kProbeSize];
        pong[0] = kPong;
        std::memcpy(pong + 1, payload.data() + 1, 8);
        network_->send(peer.id(), MessageType::Ping, ByteView(pong, kProbeSize));
        return;
    }

    if (tag == kPong) {
        uint64_t token = 0;
        std::memcpy(&token, payload.data() + 1, 8);
        const uint64_t elapsed_ticks = now_ticks() - token;
        const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::duration(static_cast<std::chrono::steady_clock::rep>(elapsed_ticks)));
        std::lock_guard<std::mutex> lock(mutex_);
        rtt_[peer.id()] = rtt;
    }
}

std::optional<std::chrono::milliseconds> PingService::last_rtt(const PeerId& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rtt_.find(id);
    if (it == rtt_.end()) return std::nullopt;
    return it->second;
}

size_t PingService::alive_peer_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rtt_.size();
}

} // namespace librats
