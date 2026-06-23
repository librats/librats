#include "subsystems/reconnection.h"
#include "node/node_context.h"
#include "util/logger.h"

#include <algorithm>
#include <chrono>
#include <unordered_set>
#include <vector>

namespace librats {

namespace {
// Wall clock at the edge, kept out of PeerBook so the book stays pure/testable.
uint64_t now_secs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
} // namespace

ReconnectionService::ReconnectionService() : ReconnectionService(Config()) {}

ReconnectionService::ReconnectionService(Config config) : config_(std::move(config)) {
    // Build the book up front so the pointer is fixed for the object's life (no race
    // with reactor-thread reads in on_connected) and so add() before start() records
    // into an already-loaded book rather than clobbering it.
    if (!config_.store_path.empty()) {
        book_ = std::make_unique<PeerBook>(config_.store_path);
        book_->load();
        // Age out the long tail and cap the archive immediately on load.
        book_->prune(now_secs(), static_cast<uint64_t>(config_.archive_max_age.count()), config_.archive_max);
        book_->save();
    }
}

ReconnectionService::~ReconnectionService() { stop(); }

void ReconnectionService::add(const Address& address) {
    const std::string key = address.to_string();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (targets_.find(key) != targets_.end()) return;
        if (targets_.size() >= config_.max_targets) {
            LOG_WARN("reconnect", "Active-target cap (" << config_.max_targets << ") reached; dropping " << key);
            return;
        }
        Target& t = targets_[key];
        t.address = address;
        t.next_attempt = std::chrono::steady_clock::now();
    }
    if (book_) { book_->note_seen(address, now_secs()); book_->save(); }
    wake_.notify_all();
}

void ReconnectionService::remove(const Address& address) {
    bool erased;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        erased = targets_.erase(address.to_string()) > 0;
    }
    if (book_ && book_->remove(address)) book_->save();
    if (erased) LOG_DEBUG("reconnect", "Stopped reconnecting to " << address.to_string());
}

size_t ReconnectionService::target_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return targets_.size();
}

std::vector<Address> ReconnectionService::known_peers(size_t n) const {
    if (!book_) return {};
    return book_->best(n, now_secs(), static_cast<uint64_t>(config_.archive_max_age.count()));
}

void ReconnectionService::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    network_->on_peer_connected([this](const Peer& peer) { on_connected(peer); });
    network_->on_peer_disconnected([this](const PeerId& id) { on_disconnected(id); });
    network_->on_dial_failed([this](const Address& addr) { on_dial_failed(addr); });
}

void ReconnectionService::start() {
    if (running_.exchange(true)) return;

    // Seed the active set with the most promising peers from the book — the
    // working set is "best N recent", the rest of the book stays a passive
    // reserve pool reachable via known_peers().
    if (book_) {
        const auto recent = book_->best(config_.startup_targets, now_secs(),
                                        static_cast<uint64_t>(config_.archive_max_age.count()));
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Address& addr : recent) {
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
    if (book_) book_->save();
}

// A successful connection. Two jobs: record the address in the book, and — the
// success-side mirror of on_dial_failed — clear this target's in-flight dial state
// right now. We must NOT wait for the loop to reconcile from the live-peer snapshot:
// a peer that connects and then drops again BETWEEN ticks would otherwise leave its
// dial flagged in-flight until dial_timeout, needlessly stalling the redial for
// seconds even though the address is plainly reachable. (For an inbound peer
// info->addresses is still empty at this point — its dialable address arrives later
// via identify — so an inbound link matches no target here and is reconciled by the
// loop's live snapshot instead; inbound links are thus not auto-persisted either.)
void ReconnectionService::on_connected(const Peer& peer) {
    auto info = peer.info();
    if (!info) return;

    const uint64_t now       = now_secs();
    const auto     steady_now = std::chrono::steady_clock::now();
    bool book_changed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Address& addr : info->addresses) {
            const std::string key = addr.to_string();
            auto it = targets_.find(key);
            if (it == targets_.end()) {
                if (!config_.persist_discovered) continue;
                if (targets_.size() >= config_.max_targets) continue;  // bound active growth
                it = targets_.emplace(key, Target{}).first;
                it->second.address = addr;
            }
            it->second.mark_connected(steady_now);  // resolve the in-flight dial now
            if (book_) { book_->note_connected(addr, peer.id(), now); book_changed = true; }
        }
    }
    if (book_ && book_changed) book_->save();
}

// A peer dropped. The loop reconciles which targets are live from the directory
// snapshot, so there is no per-target state to clear here — just wake it so the
// re-dial happens at once rather than waiting out a tick.
void ReconnectionService::on_disconnected(const PeerId& /*id*/) {
    wake_.notify_all();
}

// An outbound dial we asked for closed before establishing. Clear the in-flight
// flag so the target becomes eligible again — it then re-dials on its own backoff
// schedule (next_attempt, set when we dispatched the dial). Without this signal
// the target would stay "dialing" until the dial_deadline backstop, needlessly
// stretching every retry to that timeout.
void ReconnectionService::on_dial_failed(const Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = targets_.find(address.to_string());
    if (it != targets_.end()) it->second.dialing = false;
}

std::chrono::milliseconds ReconnectionService::backoff_for(int attempts) const {
    // base * 2^(attempts-1), capped at max.
    auto delay = config_.base_backoff;
    for (int i = 1; i < attempts && delay < config_.max_backoff; ++i) delay *= 2;
    return (std::min)(delay, config_.max_backoff);  // parenthesized: dodge windows.h min macro
}

void ReconnectionService::loop() {
    std::unordered_set<std::string> live;  // reused across ticks to avoid re-allocating
    while (running_.load()) {
        const auto now = std::chrono::steady_clock::now();

        // Ground truth for "this target is already connected": the union of every
        // live peer's dialable addresses, identify-learned ones included. Matching
        // on this — instead of a flag set only on the on_peer_connected event — is
        // what lets us recognise a peer reached over a route we did not dial (an
        // inbound link, or a cross-connect the directory resolved to the other
        // connection). Without it such a peer is never seen as connected and we
        // re-dial it forever, each dial torn down by the node as a duplicate.
        live.clear();
        for (const PeerInfo& p : network_->peers())
            for (const Address& a : p.addresses)
                live.insert(a.to_string());

        std::vector<Address> to_dial, gave_up;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = targets_.begin(); it != targets_.end();) {
                Target& target = it->second;

                // Connected right now (over any route): keep the retry state armed
                // so a later drop re-dials promptly, and never dial a live peer.
                if (live.count(it->first)) {
                    target.mark_connected(now);
                    ++it;
                    continue;
                }

                // A dial is already in flight: don't pile on a duplicate while the
                // handshake completes. We clear `dialing` on dial failure; the next
                // tick clears it once the peer shows up live; dial_deadline is only a
                // backstop for the case where neither signal ever arrives.
                if (target.dialing && now < target.dial_deadline) { ++it; continue; }
                if (target.next_attempt > now) { ++it; continue; }

                // Give up actively dialing a persistently-dead target: drop it from
                // the active set (it stays in the book as history, ranked down by its
                // failure streak, until it ages out). A reconnect resets attempts, so
                // only addresses that never came back are reaped.
                if (config_.max_attempts > 0 && target.attempts >= static_cast<int>(config_.max_attempts)) {
                    gave_up.push_back(target.address);
                    it = targets_.erase(it);
                    continue;
                }

                to_dial.push_back(target.address);
                target.attempts++;
                target.dialing = true;
                target.dial_deadline = now + config_.dial_timeout;
                target.next_attempt = now + backoff_for(target.attempts);
                ++it;
            }
        }
        if (book_ && !gave_up.empty()) {
            const uint64_t ts = now_secs();
            for (const Address& addr : gave_up) book_->note_failure(addr, ts);
            book_->save();
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
