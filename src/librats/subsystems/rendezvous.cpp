#include "librats/subsystems/rendezvous.h"

#include "librats/crypto/sha256.h"
#include "librats/node/dial_service.h"
#include "librats/node/node_context.h"
#include "librats/peer/peer.h"
#include "librats/subsystems/hole_punch_service.h"
#include "librats/subsystems/relay_service.h"
#include "librats/util/logger.h"
#include "librats/util/network_utils.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace librats {

namespace {

using Clock = std::chrono::steady_clock;

constexpr uint8_t kVersion    = 1;
constexpr uint8_t kOpHello    = 0;
constexpr uint8_t kOpRegister = 1;
constexpr uint8_t kOpPeers    = 2;
constexpr uint8_t kOpMoved    = 3;
constexpr uint8_t kOpServers  = 4;
constexpr uint8_t kOpWatch    = 5;
constexpr uint8_t kOpWatched  = 6;
constexpr uint8_t kOpUnregister = 7;

/// Peers one Peers message names, and endpoints each: a cap on what one
/// server's word makes this node dial.
constexpr size_t kMaxPeersPerMessage = 64;
constexpr size_t kMaxEndpoints       = 4;
/// Servers one Servers message names.
constexpr size_t kMaxServersPerMessage = 64;

/// The longest honest message: a full Peers, or a full Watched.
constexpr size_t kMaxMessageSize =
    (std::max)(3 + kMaxPeersPerMessage * (PeerId::kSize + 1 + kMaxEndpoints * (1 + 16 + 2)),
               4 + Rendezvous::kWatchesAtMost * (std::tuple_size_v<Rendezvous::Key> + 2));

/// How often the worker looks at what is due, at most this far apart.
constexpr auto kTick = std::chrono::milliseconds(250);

/// A peer's link gone dead has the servers spoken to at most this often: again
/// if what was said first went out before the way did (a VPN still connecting).
constexpr auto kSpeakAgain = std::chrono::seconds(2);

void put_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

/// [u8 ip_len][ip][u16 port]
void put_endpoint(Bytes& out, const Address& a) {
    const ByteView ip = a.ip.bytes();
    out.push_back(static_cast<uint8_t>(ip.size()));
    out.insert(out.end(), ip.begin(), ip.end());
    put_u16(out, a.port);
}

/// A message's body, read front to back.
struct Reader {
    const uint8_t* p;
    size_t         n;

    explicit Reader(ByteView body) : p(body.data()), n(body.size()) {}
    /// The next `k` bytes; null past the end.
    const uint8_t* take(size_t k) {
        if (n < k) return nullptr;
        const uint8_t* at = p;
        p += k;
        n -= k;
        return at;
    }
    /// An endpoint (put_endpoint()): false if the message is malformed; `out`
    /// none for one that names nowhere to dial.
    bool endpoint(std::optional<Address>& out) {
        out.reset();
        const uint8_t* len = take(1);
        if (!len || (*len != 4 && *len != 16)) return false;
        const uint8_t* ip_p = take(*len);
        const uint8_t* port_p = take(2);
        if (!ip_p || !port_p) return false;
        const auto ip = IpAddress::from_bytes(ByteView(ip_p, *len));
        const uint16_t port = static_cast<uint16_t>((port_p[0] << 8) | port_p[1]);
        if (ip && !ip->is_any() && port != 0) out = Address{*ip, port};
        return true;
    }
};

/// Where a peer may be dialed, best first: the endpoint its UDP packets come
/// from, then what it identified itself with.
std::vector<Address> endpoints_of(const PeerInfo& info) {
    std::vector<Address> out;
    auto add = [&](const Address& a) {
        if (out.size() < kMaxEndpoints && a.port != 0 && !a.ip.is_any() &&
            std::find(out.begin(), out.end(), a) == out.end())
            out.push_back(a);
    };
    if (info.transport == TransportKind::Udp && info.endpoint) add(*info.endpoint);
    for (const Address& a : info.addresses) add(a);
    return out;
}

std::optional<Address> resolve(const HostEndpoint& at) {
    if (auto ip = IpAddress::parse(at.host)) return Address{*ip, at.port};
    std::string ip = network_utils::resolve_hostname(at.host);
    if (ip.empty()) ip = network_utils::resolve_hostname_v6(at.host);
    if (auto parsed = IpAddress::parse(ip)) return Address{*parsed, at.port};
    return std::nullopt;
}

} // namespace

Rendezvous::Key Rendezvous::key_of(const std::string& key) {
    Key out{};
    rats_sha256_hash(out.data(), key.data(), key.size());
    return out;
}

std::vector<Address> Rendezvous::choose(const Key& key, const std::vector<Address>& candidates,
                                        size_t count) {
    struct Ranked {
        uint64_t rank;
        Address  at;
    };
    std::vector<Ranked> ranked;
    for (const Address& at : candidates) {
        if (std::any_of(ranked.begin(), ranked.end(),
                        [&](const Ranked& r) { return r.at.ip == at.ip; }))
            continue;
        // SHA-256(key ‖ ip): its first eight bytes, big-endian.
        Bytes input(key.begin(), key.end());
        const ByteView ip = at.ip.bytes();
        input.insert(input.end(), ip.begin(), ip.end());
        uint8_t hash[32];
        rats_sha256_hash(hash, input.data(), input.size());
        uint64_t rank = 0;
        for (int i = 0; i < 8; ++i) rank = (rank << 8) | hash[i];
        ranked.push_back({rank, at});
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const Ranked& a, const Ranked& b) { return a.rank > b.rank; });
    std::vector<Address> out;
    for (size_t i = 0; i < ranked.size() && i < count; ++i) out.push_back(ranked[i].at);
    return out;
}

Rendezvous::Rendezvous() : Rendezvous(Config()) {}

Rendezvous::Rendezvous(Config config) : config_(std::move(config)) {
    for (const std::string& key : config_.keys) keys_.push_back(key_of(key));
    for (const std::string& key : config_.watched) {
        const Key hashed = key_of(key);
        if (watched_.size() < kWatchesAtMost &&
            std::none_of(watched_.begin(), watched_.end(),
                         [&](const Watch& w) { return w.key == hashed; }))
            watched_.push_back({hashed, key});
    }
    for (const HostEndpoint& at : config_.servers)
        server_dials_.push_back(ServerDial{at, std::nullopt, {}, config_.redial});
}

Rendezvous::~Rendezvous() { stop(); }

void Rendezvous::attach(NodeContext& ctx) {
    network_  = &ctx.network;
    services_ = &ctx.services;
    dial_     = ctx.services.get<DialService>();
    network_->on(MessageType::Rendezvous,
                 [this](const Peer& peer, ByteView payload) { handle(peer, payload); });
    network_->on_peer_connected([this](const Peer& peer) { on_connected(peer.id()); });
    // Hello, or a registration, may have gone on the link that lost.
    network_->on_peer_rerouted([this](const Peer& peer) { on_connected(peer.id()); });
    network_->on_peer_disconnected(
        [this](const PeerId& peer, CloseReason) { on_disconnected(peer); });
    network_->on_peer_moved([this](const Peer& peer) { on_moved(peer.id()); });
    // Whether a link to a peer answers is in its path samples. A node with no
    // keys yet may be given some (set_keys()), and one with no servers met none.
    if (!keys_.empty() || !server_dials_.empty())
        network_->on_peer_path([this](const Peer& peer, const PathStats& path) { on_path(peer.id(), path); });
}

void Rendezvous::start() {
    if (running_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        refresh_at_ = Clock::now() + config_.refresh;
    }
    bool keys = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        keys = !keys_.empty();
    }
    if (!server_dials_.empty() || keys) worker_ = std::thread([this] { loop(); });
}

void Rendezvous::stop() {
    if (!running_.exchange(false)) return;
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    servers_.clear();
    unreached_.clear();
    registered_.clear();
    keys_of_.clear();
    budgets_.clear();
    watch_budgets_.clear();
    servers_told_.clear();
    watchers_.clear();
    watches_of_.clear();
    watch_count_ = 0;
    counts_.clear();
    seen_.clear();
}

std::vector<PeerId> Rendezvous::servers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerId> out(servers_.begin(), servers_.end());
    for (const PeerId& peer : at_servers_)
        if (servers_.count(peer) == 0) out.push_back(peer);
    return out;
}

std::vector<Address> Rendezvous::chosen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chosen_;
}

bool Rendezvous::is_server(const PeerId& peer) const {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (servers_.count(peer) != 0 || at_servers_.count(peer) != 0) return true;
    }
    // Asked from a connected handler that ran before ours.
    return running_.load() && at_server_address(peer);
}

size_t Rendezvous::registrations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t n = 0;
    for (const auto& [key, registered] : registered_) n += registered.peers.size();
    return n;
}

size_t Rendezvous::watches() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return watch_count_;
}

size_t Rendezvous::registered(const std::string& key) const {
    const Key hashed = key_of(key);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = seen_.find(hashed);
    return it == seen_.end() ? 0 : it->second;
}

void Rendezvous::on_watched(std::function<void(const std::string&, size_t)> handler) {
    watched_handlers_.push_back(std::move(handler));
}

// ── Inbound ─────────────────────────────────────────────────────────────────

void Rendezvous::handle(const Peer& from, ByteView payload) {
    if (!running_.load() || payload.size() < 2 || payload.size() > kMaxMessageSize) return;
    if (payload.data()[0] != kVersion) return;
    const ByteView body(payload.data() + 2, payload.size() - 2);
    switch (payload.data()[1]) {
        case kOpHello:
            on_hello(from.id());
            break;
        case kOpRegister: {
            if (!config_.serve || body.size() != std::tuple_size_v<Key>) return;
            Key key;
            std::memcpy(key.data(), body.data(), key.size());
            on_register(from.id(), key);
            break;
        }
        case kOpUnregister: {
            if (!config_.serve || body.size() != std::tuple_size_v<Key>) return;
            Key key;
            std::memcpy(key.data(), body.data(), key.size());
            on_unregister(from.id(), key);
            break;
        }
        case kOpWatch:
            if (config_.serve) on_watch(from.id(), body);
            break;
        case kOpWatched:
            on_watched_told(from.id(), body);
            break;
        case kOpPeers:
            on_peers(from.id(), body, /*moved=*/false);
            break;
        case kOpMoved:
            on_peers(from.id(), body, /*moved=*/true);
            break;
        case kOpServers:
            on_servers_told(from.id(), body);
            break;
        default:
            break;  // an op from a newer version: ignored
    }
}

void Rendezvous::on_connected(const PeerId& peer) {
    if (!running_.load()) return;
    if (at_server_address(peer)) {
        std::lock_guard<std::mutex> lock(mutex_);
        at_servers_.insert(peer);
    }
    if (!config_.serve) return;
    const uint8_t hello[] = {kVersion, kOpHello};
    network_->send(peer, MessageType::Rendezvous, ByteView(hello, sizeof hello));
    tell_servers(peer);
}

bool Rendezvous::at_server_address(const PeerId& peer) const {
    std::vector<Address> servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const ServerDial& server : server_dials_)
            if (server.resolved) servers.push_back(*server.resolved);
    }
    if (servers.empty()) return false;
    for (const PeerInfo& info : network_->peers()) {
        if (info.id != peer) continue;
        for (const Address& a : info.addresses)
            if (std::find(servers.begin(), servers.end(), a) != servers.end()) return true;
    }
    return false;
}

void Rendezvous::on_server_found(std::function<void(const PeerId&)> handler) {
    found_handlers_.push_back(std::move(handler));
}

void Rendezvous::on_servers(
    std::function<void(const PeerId&, const std::vector<Address>&)> handler) {
    servers_handlers_.push_back(std::move(handler));
}

void Rendezvous::on_disconnected(const PeerId& peer) {
    Tell tell;
    Changes changes;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        servers_.erase(peer);
        at_servers_.erase(peer);
        budgets_.erase(peer);
        watch_budgets_.erase(peer);
        servers_told_.erase(peer);
        // A server lost: what it told counts no longer.
        if (const auto counts = counts_.find(peer); counts != counts_.end()) {
            const std::map<Key, size_t> told = std::move(counts->second);
            counts_.erase(counts);
            for (const auto& [key, n] : told) recount(key, changes);
        }
        if (const auto watches = watches_of_.find(peer); watches != watches_of_.end()) {
            for (const Key& key : watches->second) {
                const auto it = watchers_.find(key);
                if (it == watchers_.end()) continue;
                it->second.erase(peer);
                if (it->second.empty()) watchers_.erase(it);
            }
            watch_count_ -= watches->second.size();
            watches_of_.erase(watches);
        }
        if (const auto keys = keys_of_.find(peer); keys != keys_of_.end()) {
            for (const Key& key : keys->second) {
                const auto it = registered_.find(key);
                if (it == registered_.end()) continue;
                it->second.peers.erase(peer);
                if (it->second.peers.empty()) registered_.erase(it);
                tell_watchers(key, tell);
            }
            keys_of_.erase(keys);
        }
    }
    send_told(tell);
    run_watched(changes);
}

void Rendezvous::on_hello(const PeerId& server) {
    bool found = false;
    bool again = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (servers_.insert(server).second) {
            ++servers_came_;
            found = at_servers_.count(server) == 0;
        } else {
            again = true;
        }
    }
    if (found)
        for (const auto& handler : found_handlers_) handler(server);
    size_t keys = 0;
    size_t watched = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        keys = keys_.size();
        watched = watched_.size();
    }
    // Said again when a link to the server lost a race to another (rerouted):
    // what went on the one lost may be lost with it.
    if (again) {
        LOG_DEBUG("rendezvous", "Server " << server.short_hex() << " said Hello again");
    } else {
        LOG_INFO("rendezvous", "Server " << server.short_hex() << " is up; registering "
                 << keys << " key(s), watching " << watched);
    }
    register_keys(server);
    send_watch(server);
}

void Rendezvous::register_keys(const PeerId& server) {
    std::vector<Key> keys;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        keys = keys_;
    }
    register_keys(server, keys);
}

void Rendezvous::register_keys(const PeerId& server, const std::vector<Key>& keys) {
    for (const Key& key : keys) {
        Bytes message{kVersion, kOpRegister};
        message.insert(message.end(), key.begin(), key.end());
        network_->send(server, MessageType::Rendezvous, ByteView(message));
    }
}

void Rendezvous::unregister_keys(const PeerId& server, const std::vector<Key>& keys) {
    for (const Key& key : keys) {
        Bytes message{kVersion, kOpUnregister};
        message.insert(message.end(), key.begin(), key.end());
        network_->send(server, MessageType::Rendezvous, ByteView(message));
    }
}

void Rendezvous::set_keys(const std::vector<std::string>& keys) {
    std::vector<Key> hashed;
    for (const std::string& key : keys) hashed.push_back(key_of(key));
    std::vector<Key> added, removed;
    std::vector<PeerId> servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Key& key : hashed)
            if (std::find(keys_.begin(), keys_.end(), key) == keys_.end()) added.push_back(key);
        for (const Key& key : keys_)
            if (std::find(hashed.begin(), hashed.end(), key) == hashed.end()) removed.push_back(key);
        keys_ = std::move(hashed);
        if (running_.load()) servers.assign(servers_.begin(), servers_.end());
    }
    if (added.empty() && removed.empty()) return;
    LOG_DEBUG("rendezvous", "Registering " << added.size() << " new key(s), taking back "
              << removed.size() << ", with " << servers.size() << " server(s)");
    for (const PeerId& server : servers) {
        unregister_keys(server, removed);
        register_keys(server, added);
    }
}

void Rendezvous::set_watched(const std::vector<std::string>& keys) {
    std::vector<Watch> watched;
    for (const std::string& key : keys) {
        const Key hashed = key_of(key);
        if (watched.size() < kWatchesAtMost &&
            std::none_of(watched.begin(), watched.end(),
                         [&](const Watch& w) { return w.key == hashed; }))
            watched.push_back({hashed, key});
    }
    if (watched.size() < keys.size())
        LOG_DEBUG("rendezvous", "Watching " << watched.size() << " of " << keys.size() << " key(s)");
    std::vector<PeerId> servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool same = watched.size() == watched_.size() &&
                          std::equal(watched.begin(), watched.end(), watched_.begin(),
                                     [](const Watch& a, const Watch& b) { return a.key == b.key; });
        if (same) return;
        // One no longer watched is no longer told of.
        for (auto it = seen_.begin(); it != seen_.end();) {
            const Key& key = it->first;
            if (std::none_of(watched.begin(), watched.end(), [&](const Watch& w) { return w.key == key; }))
                it = seen_.erase(it);
            else
                ++it;
        }
        for (auto& [server, counts] : counts_)
            for (auto it = counts.begin(); it != counts.end();) {
                const Key& key = it->first;
                if (std::none_of(watched.begin(), watched.end(), [&](const Watch& w) { return w.key == key; }))
                    it = counts.erase(it);
                else
                    ++it;
            }
        watched_ = std::move(watched);
        watched_changed_ = true;
        if (running_.load()) servers.assign(servers_.begin(), servers_.end());
    }
    for (const PeerId& server : servers) send_watch(server, /*even_none=*/true);
}

void Rendezvous::send_watch(const PeerId& server, bool even_none) {
    Bytes message{kVersion, kOpWatch, 0, 0};
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Watch& w : watched_) {
            message.insert(message.end(), w.key.begin(), w.key.end());
            ++count;
        }
    }
    if (count == 0 && !even_none) return;
    message[2] = static_cast<uint8_t>(count >> 8);
    message[3] = static_cast<uint8_t>(count);
    network_->send(server, MessageType::Rendezvous, ByteView(message));
}

namespace {

/// Whether one more fits in `budget`'s window (a Rendezvous::Budget).
template <typename Budget>
bool spend_of(Budget& budget, size_t most, std::chrono::milliseconds window) {
    const auto now = Clock::now();
    if (now - budget.window_started > window) {
        budget.window_started = now;
        budget.spent = 0;
    }
    return ++budget.spent <= most;
}

} // namespace

bool Rendezvous::spend(const PeerId& peer) {
    return spend_of(budgets_[peer], config_.request_budget, config_.request_window);
}

bool Rendezvous::spend_watch(const PeerId& peer) {
    return spend_of(watch_budgets_[peer], config_.watch_budget, config_.request_window);
}

void Rendezvous::on_register(const PeerId& peer, const Key& key) {
    std::vector<PeerId> others;
    bool kept = false;
    Tell tell;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!spend(peer)) return;

        auto it = registered_.find(key);
        if (it != registered_.end()) {
            for (const PeerId& other : it->second.peers)
                if (other != peer && others.size() < kMaxPeersPerMessage) others.push_back(other);
        }
        std::vector<Key>& keys = keys_of_[peer];
        const bool has_key = std::find(keys.begin(), keys.end(), key) != keys.end();
        if (!has_key && keys.size() < config_.max_keys_per_peer &&
            (it != registered_.end() || registered_.size() < config_.max_keys)) {
            if (it == registered_.end()) it = registered_.emplace(key, Registered{}).first;
            if (it->second.peers.size() < config_.max_peers_per_key) {
                it->second.peers.insert(peer);
                keys.push_back(key);
                kept = true;
            } else if (it->second.peers.empty()) {
                registered_.erase(it);
            }
        }
        if (keys.empty()) keys_of_.erase(peer);
        if (kept) tell_watchers(key, tell);
    }
    send_told(tell);
    tell_servers(peer);
    if (others.empty() && !kept) return;

    std::unordered_map<PeerId, PeerInfo, PeerId::Hash> known;
    for (PeerInfo& info : network_->peers()) known.emplace(info.id, std::move(info));
    // The newcomer and the others hear of each other at once: their dials cross.
    if (!others.empty()) {
        const Bytes answer = peers_message(kOpPeers, others, known);
        network_->send(peer, MessageType::Rendezvous, ByteView(answer));
    }
    if (kept) {
        const Bytes told = peers_message(kOpPeers, {peer}, known);
        for (const PeerId& other : others) network_->send(other, MessageType::Rendezvous, ByteView(told));
    }
    LOG_DEBUG("rendezvous", "Peer " << peer.short_hex() << " registered, meeting "
              << others.size() << " other(s)");
}

void Rendezvous::on_unregister(const PeerId& peer, const Key& key) {
    Tell tell;
    {
        // Free: it only lessens what is kept, and what it tells watchers a
        // registration (spent) told before.
        std::lock_guard<std::mutex> lock(mutex_);
        const auto keys = keys_of_.find(peer);
        if (keys == keys_of_.end()) return;
        const auto at = std::find(keys->second.begin(), keys->second.end(), key);
        if (at == keys->second.end()) return;
        keys->second.erase(at);
        if (keys->second.empty()) keys_of_.erase(keys);
        if (const auto it = registered_.find(key); it != registered_.end()) {
            it->second.peers.erase(peer);
            if (it->second.peers.empty()) registered_.erase(it);
        }
        tell_watchers(key, tell);
    }
    send_told(tell);
    LOG_DEBUG("rendezvous", "Peer " << peer.short_hex() << " took a key back");
}

void Rendezvous::on_watch(const PeerId& peer, ByteView body) {
    Reader read(body);
    const uint8_t* count_p = read.take(2);
    if (!count_p) return;
    const size_t count = (size_t(count_p[0]) << 8) | count_p[1];
    if (count > kWatchesAtMost || read.n != count * std::tuple_size_v<Key>) return;
    std::vector<std::pair<Key, size_t>> answer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!spend_watch(peer)) return;
        // In place of what it watched.
        if (const auto old = watches_of_.find(peer); old != watches_of_.end()) {
            for (const Key& key : old->second) {
                const auto it = watchers_.find(key);
                if (it == watchers_.end()) continue;
                it->second.erase(peer);
                if (it->second.empty()) watchers_.erase(it);
            }
            watch_count_ -= old->second.size();
            watches_of_.erase(old);
        }
        std::vector<Key> kept;
        for (size_t i = 0; i < count; ++i) {
            Key key;
            std::memcpy(key.data(), read.take(key.size()), key.size());
            if (kept.size() >= config_.max_watches_per_peer || watch_count_ >= config_.max_watches)
                break;
            if (std::find(kept.begin(), kept.end(), key) != kept.end()) continue;
            auto& watchers = watchers_[key];
            if (watchers.size() >= config_.max_watchers_per_key) {
                if (watchers.empty()) watchers_.erase(key);
                continue;
            }
            watchers.insert(peer);
            kept.push_back(key);
            ++watch_count_;
            const auto it = registered_.find(key);
            const size_t n = it == registered_.end()
                                 ? 0
                                 : it->second.peers.size() - it->second.peers.count(peer);
            answer.emplace_back(key, n);
        }
        if (!kept.empty()) watches_of_[peer] = std::move(kept);
    }
    // Every key kept answered, those none is under too: the watcher's counts
    // are this server's from now on.
    Tell tell;
    tell[peer] = std::move(answer);
    send_told(tell);
    LOG_DEBUG("rendezvous", "Peer " << peer.short_hex() << " watches " << tell[peer].size()
              << " key(s)");
}

void Rendezvous::tell_watchers(const Key& key, Tell& tell) const {
    const auto watchers = watchers_.find(key);
    if (watchers == watchers_.end()) return;
    const auto it = registered_.find(key);
    for (const PeerId& watcher : watchers->second) {
        const size_t n =
            it == registered_.end() ? 0 : it->second.peers.size() - it->second.peers.count(watcher);
        auto& told = tell[watcher];
        // Once per key: a later count in place of an earlier one.
        const auto same = std::find_if(told.begin(), told.end(),
                                       [&](const auto& t) { return t.first == key; });
        if (same != told.end()) {
            same->second = n;
        } else {
            told.emplace_back(key, n);
        }
    }
}

void Rendezvous::send_told(const Tell& tell) {
    for (const auto& [watcher, told] : tell) {
        Bytes message{kVersion, kOpWatched, 0, 0};
        size_t count = 0;
        for (const auto& [key, n] : told) {
            if (count == kWatchesAtMost) break;  // never more: one per key watched
            message.insert(message.end(), key.begin(), key.end());
            put_u16(message, static_cast<uint16_t>((std::min)(n, size_t(0xFFFF))));
            ++count;
        }
        message[2] = static_cast<uint8_t>(count >> 8);
        message[3] = static_cast<uint8_t>(count);
        network_->send(watcher, MessageType::Rendezvous, ByteView(message));
    }
}

void Rendezvous::on_watched_told(const PeerId& server, ByteView body) {
    if (!is_server(server)) return;
    Reader read(body);
    const uint8_t* count_p = read.take(2);
    if (!count_p) return;
    const size_t count = (size_t(count_p[0]) << 8) | count_p[1];
    if (count > kWatchesAtMost || read.n != count * (std::tuple_size_v<Key> + 2)) return;
    Changes changes;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_.load()) return;
        for (size_t i = 0; i < count; ++i) {
            Key key;
            std::memcpy(key.data(), read.take(key.size()), key.size());
            const uint8_t* n_p = read.take(2);
            const size_t n = (size_t(n_p[0]) << 8) | n_p[1];
            if (std::none_of(watched_.begin(), watched_.end(),
                             [&](const Watch& w) { return w.key == key; }))
                continue;  // no longer watched
            counts_[server][key] = n;
            recount(key, changes);
        }
    }
    run_watched(changes);
}

void Rendezvous::recount(const Key& key, Changes& changes) {
    size_t most = 0;
    for (const auto& [server, counts] : counts_)
        if (const auto it = counts.find(key); it != counts.end()) most = (std::max)(most, it->second);
    const auto seen = seen_.find(key);
    const size_t was = seen == seen_.end() ? 0 : seen->second;
    if (most == was) return;
    if (most == 0) {
        seen_.erase(seen);
    } else {
        seen_[key] = most;
    }
    for (const Watch& w : watched_)
        if (w.key == key) changes.emplace_back(w.name, most);
}

void Rendezvous::run_watched(const Changes& changes) {
    for (const auto& [key, n] : changes)
        for (const auto& handler : watched_handlers_) handler(key, n);
}

void Rendezvous::on_moved(const PeerId& peer) {
    if (!config_.serve || !running_.load()) return;
    std::vector<PeerId> others;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto keys = keys_of_.find(peer);
        if (keys == keys_of_.end() || !spend(peer)) return;
        for (const Key& key : keys->second) {
            const auto it = registered_.find(key);
            if (it == registered_.end()) continue;
            for (const PeerId& other : it->second.peers)
                if (other != peer && others.size() < kMaxPeersPerMessage &&
                    std::find(others.begin(), others.end(), other) == others.end())
                    others.push_back(other);
        }
    }
    if (others.empty()) return;

    std::unordered_map<PeerId, PeerInfo, PeerId::Hash> known;
    for (PeerInfo& info : network_->peers()) known.emplace(info.id, std::move(info));
    // As a newcomer's meeting: each side told of the other at once, their dials
    // crossing — the old links between them gone dead or not.
    const Bytes told = peers_message(kOpMoved, {peer}, known);
    for (const PeerId& other : others) network_->send(other, MessageType::Rendezvous, ByteView(told));
    const Bytes answer = peers_message(kOpMoved, others, known);
    network_->send(peer, MessageType::Rendezvous, ByteView(answer));
    LOG_INFO("rendezvous", "Peer " << peer.short_hex() << " moved; telling "
              << others.size() << " other(s)");
}

void Rendezvous::on_path(const PeerId& peer, const PathStats& path) {
    // Any link: one to a server gone dead is the server not yet hearing where
    // this node is, which speaking to it is what shows.
    const auto now = Clock::now();
    if (!running_.load() || path.answers(now)) return;
    std::vector<PeerId> servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (now - spoken_at_ < kSpeakAgain) return;
        spoken_at_ = now;
        servers.assign(servers_.begin(), servers_.end());
    }
    LOG_DEBUG("rendezvous", "The link to " << peer.short_hex()
              << " went unanswered; registering again");
    for (const PeerId& server : servers) register_keys(server);
}

void Rendezvous::tell_servers(const PeerId& peer) {
    std::vector<PeerId> servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t& told = servers_told_[peer];
        if (told == servers_came_) return;
        told = servers_came_;
        for (const PeerId& server : servers_)
            if (server != peer) servers.push_back(server);
    }
    Bytes out{kVersion, kOpServers, 0};
    uint8_t count = 0;
    for (const PeerInfo& info : network_->peers()) {
        if (count == kMaxServersPerMessage ||
            std::find(servers.begin(), servers.end(), info.id) == servers.end())
            continue;
        const std::vector<Address> endpoints = endpoints_of(info);
        if (endpoints.empty()) continue;
        put_endpoint(out, endpoints.front());
        ++count;
    }
    if (count == 0) return;
    out[2] = count;
    network_->send(peer, MessageType::Rendezvous, ByteView(out));
}

Bytes Rendezvous::peers_message(
    uint8_t op, const std::vector<PeerId>& peers,
    const std::unordered_map<PeerId, PeerInfo, PeerId::Hash>& known) const {
    Bytes out{kVersion, op, 0};
    uint8_t count = 0;
    for (const PeerId& id : peers) {
        const auto info = known.find(id);
        if (info == known.end()) continue;
        const std::vector<Address> endpoints = endpoints_of(info->second);
        if (endpoints.empty()) continue;
        const auto& raw = id.bytes();
        out.insert(out.end(), raw.begin(), raw.end());
        out.push_back(static_cast<uint8_t>(endpoints.size()));
        for (const Address& a : endpoints) put_endpoint(out, a);
        ++count;
    }
    out[2] = count;
    return out;
}

void Rendezvous::on_peers(const PeerId& server, ByteView body, bool moved) {
    if (!is_server(server) || body.empty()) return;
    Reader read(body);
    struct Told {
        PeerId               id;
        std::vector<Address> endpoints;
    };
    std::vector<Told> told;
    const uint8_t count = *read.take(1);
    for (uint8_t i = 0; i < count && i < kMaxPeersPerMessage; ++i) {
        const uint8_t* id_p = read.take(PeerId::kSize);
        const uint8_t* n_p = read.take(1);
        if (!id_p || !n_p || *n_p > kMaxEndpoints) return;
        const auto id = PeerId::from_bytes(ByteView(id_p, PeerId::kSize));
        if (!id) return;
        Told peer{*id, {}};
        for (uint8_t e = 0; e < *n_p; ++e) {
            std::optional<Address> at;
            if (!read.endpoint(at)) return;
            if (at) peer.endpoints.push_back(*at);
        }
        told.push_back(std::move(peer));
    }

    const std::vector<PeerId> connected = network_->connected_peers();
    const auto due = Clock::now() + (moved ? config_.punch_after_move : config_.punch_after);
    for (const Told& peer : told) {
        // A peer that moved is dialed whether connected or not: the dial opens
        // this side's NAT to where it is now, which the link to it needs.
        if (peer.id == network_->local_id() || peer.endpoints.empty() ||
            (!moved && std::find(connected.begin(), connected.end(), peer.id) != connected.end()))
            continue;
        LOG_INFO("rendezvous", "Told of " << peer.id.short_hex() << (moved ? ", moved," : "")
                  << " at " << peer.endpoints.front().to_string() << "; dialing");
        bool dialed = false;
        if (dial_)
            for (const Address& at : peer.endpoints)
                dialed |= dial_->dial_direct(at, TransportKind::Udp, DialProfile::punch());
        if (!dialed) network_->connect(peer.endpoints.front());
        std::lock_guard<std::mutex> lock(mutex_);
        if (moved) {
            unreached_.insert_or_assign(peer.id, Unreached{due, true});
        } else {
            unreached_.try_emplace(peer.id, Unreached{due, false});
        }
    }
}

void Rendezvous::on_servers_told(const PeerId& server, ByteView body) {
    if (servers_handlers_.empty() || !is_server(server) || body.empty()) return;
    Reader read(body);
    const uint8_t count = *read.take(1);
    if (count > kMaxServersPerMessage) return;
    std::vector<Address> servers;
    for (uint8_t i = 0; i < count; ++i) {
        std::optional<Address> at;
        if (!read.endpoint(at)) return;
        if (at && std::find(servers.begin(), servers.end(), *at) == servers.end())
            servers.push_back(*at);
    }
    if (servers.empty()) return;
    LOG_DEBUG("rendezvous", "Server " << server.short_hex() << " told of " << servers.size()
              << " other server(s)");
    for (const auto& handler : servers_handlers_) handler(server, servers);
}

// ── Worker ──────────────────────────────────────────────────────────────────

void Rendezvous::loop() {
    choose_servers();
    std::unique_lock<std::mutex> lock(mutex_);
    while (running_.load()) {
        lock.unlock();
        const auto now = Clock::now();
        dial_servers(now);
        hand_on_unreached(now);
        refresh(now);
        lock.lock();
        wake_.wait_for(lock, kTick, [this] { return !running_.load(); });
    }
}

void Rendezvous::choose_servers() {
    std::vector<Key> keys;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        keys = keys_;
    }
    if (config_.candidates.empty() || config_.choose == 0 || keys.empty()) return;
    // Config::servers resolved first, so that one chosen too is dialed once.
    for (size_t i = 0; i < server_dials_.size(); ++i) {
        const std::optional<Address> resolved = resolve(server_dials_[i].at);
        std::lock_guard<std::mutex> lock(mutex_);
        server_dials_[i].resolved = resolved;
    }
    std::vector<Address> candidates;
    for (const HostEndpoint& at : config_.candidates) {
        if (!running_.load()) return;
        // Resolving blocks: not under the lock a reactor thread takes.
        if (const std::optional<Address> resolved = resolve(at)) candidates.push_back(*resolved);
    }
    std::vector<Address> chosen;
    for (const Key& key : keys)
        for (const Address& at : choose(key, candidates, config_.choose))
            if (std::find(chosen.begin(), chosen.end(), at) == chosen.end()) chosen.push_back(at);

    std::lock_guard<std::mutex> lock(mutex_);
    chosen_ = chosen;
    for (const Address& at : chosen) {
        // One of Config::servers already, as it was last resolved.
        if (std::any_of(server_dials_.begin(), server_dials_.end(),
                        [&](const ServerDial& s) { return s.resolved == at; }))
            continue;
        server_dials_.push_back(
            ServerDial{HostEndpoint(at.ip.to_string(), at.port), at, {}, config_.redial});
    }
    LOG_INFO("rendezvous", "Chose " << chosen.size() << " of " << candidates.size()
             << " server(s) known");
}

void Rendezvous::dial_servers(Clock::time_point now) {
    // Grown only by choose_servers(), on this thread.
    if (server_dials_.empty()) return;
    std::vector<Address> connected;
    for (const PeerInfo& info : network_->peers())
        connected.insert(connected.end(), info.addresses.begin(), info.addresses.end());
    for (size_t i = 0; i < server_dials_.size(); ++i) {
        HostEndpoint at;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ServerDial& server = server_dials_[i];
            if (server.resolved && std::find(connected.begin(), connected.end(),
                                             *server.resolved) != connected.end()) {
                server.backoff = config_.redial;
                server.next = now + server.backoff;
                continue;
            }
            if (now < server.next) continue;
            server.next = now + server.backoff;
            server.backoff = (std::min)(server.backoff * 2, config_.redial_max);
            at = server.at;
        }
        // Resolving blocks: not under the lock a reactor thread takes.
        const std::optional<Address> resolved = resolve(at);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            server_dials_[i].resolved = resolved;
        }
        if (!resolved) {
            LOG_WARN("rendezvous", "Cannot resolve server " << at.to_string());
            continue;
        }
        LOG_DEBUG("rendezvous", "Dialing server " << at.to_string() << " at " << resolved->to_string());
        network_->connect(*resolved);
    }
}

void Rendezvous::hand_on_unreached(Clock::time_point now) {
    std::vector<std::pair<PeerId, bool>> due;  // and whether it moved
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = unreached_.begin(); it != unreached_.end();) {
            if (it->second.due > now) {
                ++it;
                continue;
            }
            due.emplace_back(it->first, it->second.moved);
            it = unreached_.erase(it);
        }
    }
    if (due.empty()) return;
    const std::vector<PeerId> connected = network_->connected_peers();
    auto* relay = services_->get<RelayService>();
    auto* punch = services_->get<HolePunchService>();
    for (const auto& [peer, moved] : due) {
        // Reached: connected — over a link that answers, for one that moved,
        // whose old link may be connected and dead.
        if (moved ? network_->answers(peer)
                  : std::find(connected.begin(), connected.end(), peer) != connected.end())
            continue;
        LOG_INFO("rendezvous", "Peer " << peer.short_hex() << " not reached by dialing; "
                  << (relay ? "relaying" : "punching"));
        // The dials were a punch, timed by the server: a NAT they did not get
        // through most likely maps anew for each destination, where no punch
        // will. A relay is up in a round trip, and punches on over its circuit
        // for a direct link to take its place unseen; a punch first took three
        // rounds of six seconds to give up.
        if (relay ? relay->connect_via_relay(peer) : punch && punch->punch(peer)) ++handed_on_;
    }
}

void Rendezvous::refresh(Clock::time_point now) {
    std::vector<PeerId> servers;
    bool watch = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (now < refresh_at_) return;
        refresh_at_ = now + config_.refresh;
        servers.assign(servers_.begin(), servers_.end());
        // A list changed since is told again: changed more often than a
        // server's budget allows, the last may have been dropped.
        watch = std::exchange(watched_changed_, false);
    }
    for (const PeerId& server : servers) {
        register_keys(server);
        if (watch) send_watch(server, /*even_none=*/true);
    }
}

} // namespace librats
