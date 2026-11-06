#include "librats/subsystems/dht_discovery.h"
#include "librats/node/node_context.h"
#include "librats/node/host_events.h"
#include "librats/node/dial_service.h"
#include "librats/node/reflexive_probe.h"
#include "librats/nat/stun.h"
#include "librats/crypto/sha1.h"
#include "librats/util/fs.h"
#include "librats/util/network_utils.h"
#include "librats/util/logger.h"

#include <algorithm>

namespace librats {

namespace {
int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// A couple of well-known public STUN servers, tried in order. Kept short so a
// total-outage startup costs at most a few timeouts before we fall back to voting.
std::vector<HostEndpoint> default_stun_servers() {
    return { HostEndpoint("stun.l.google.com", 19302), HostEndpoint("stun1.l.google.com", 19302) };
}

// What has not been found for this long is forgotten (the DHT keeps an
// announce for half an hour).
constexpr std::chrono::minutes kForgetFound{10};

// The configured bind literal only applies to its own family; the other family
// binds the wildcard. An empty config means wildcard for both.
std::string bind_for(const std::string& cfg, bool want_v6) {
    if (cfg.empty()) return "";
    const bool cfg_is_v6 = cfg.find(':') != std::string::npos;
    return (cfg_is_v6 == want_v6) ? cfg : "";
}
} // namespace

InfoHash DhtDiscovery::hash_for_key(const std::string& key) {
    const std::string hex = SHA1::hash(key);  // 40 hex chars
    InfoHash hash{};
    for (size_t i = 0; i < hash.size() && (2 * i + 1) < hex.size(); ++i)
        hash[i] = static_cast<uint8_t>((hex_val(hex[2 * i]) << 4) | hex_val(hex[2 * i + 1]));
    return hash;
}

// ── Redials ─────────────────────────────────────────────────────────────────

DhtDiscovery::Redials::Dial DhtDiscovery::Redials::found(const Address& address,
                                                         Clock::time_point now) {
    const auto [it, first] = found_.try_emplace(address, Dialed{now, now, now});
    Dialed& dialed = it->second;
    dialed.seen = now;
    if (first) return Dial::First;
    // In its first stretch every `every` (due() keeps that time too); after it,
    // once in a while, for as long as it is found.
    const auto gap = now - dialed.first <= for_ ? every_ : slow_;
    if (now - dialed.last < gap) return Dial::None;
    dialed.last = now;
    return Dial::Again;
}

std::vector<Address> DhtDiscovery::Redials::due(Clock::time_point now) {
    std::vector<Address> out;
    for (auto& [address, dialed] : found_) {
        if (now - dialed.first > for_ || now - dialed.last < every_) continue;
        dialed.last = now;
        out.push_back(address);
    }
    return out;
}

std::optional<DhtDiscovery::Redials::Clock::time_point> DhtDiscovery::Redials::next_due() const {
    std::optional<Clock::time_point> next;
    for (const auto& [address, dialed] : found_) {
        const Clock::time_point at = dialed.last + every_;
        if (at - dialed.first > for_) continue;  // past its first stretch
        if (!next || at < *next) next = at;
    }
    return next;
}

void DhtDiscovery::Redials::forget_older_than(Clock::time_point before) {
    for (auto it = found_.begin(); it != found_.end();)
        it = it->second.seen < before ? found_.erase(it) : std::next(it);
}

// ── DhtDiscovery ────────────────────────────────────────────────────────────

DhtDiscovery::DhtDiscovery(Config config)
    : config_(std::move(config)),
      dialed_(config_.redial_every, config_.redial_for, config_.redial_slow) {
    // Keys given are the namespaces; else the discovery key — or, with neither,
    // the node's protocol, resolved in attach().
    if (!config_.keys.empty()) {
        for (const std::string& key : config_.keys) hashes_.push_back({hash_for_key(key), Use::Both});
        keys_set_ = true;
    } else if (!config_.discovery_key.empty()) {
        hashes_.push_back({hash_for_key(config_.discovery_key), Use::Both});
        keys_set_ = true;
    }
}

DhtDiscovery::~DhtDiscovery() { stop(); }

void DhtDiscovery::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    // Namespace discovery by the node's protocol unless an explicit key overrides
    // it: peers of the same app/version announce/search the same hash, and ones with
    // a different protocol (which couldn't complete a handshake anyway) never meet in
    // the DHT. A non-empty discovery_key opts into a custom, protocol-independent net.
    // Keys given — in the config, or set before attach — are the namespaces instead.
    {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        if (!keys_set_) hashes_ = {{hash_for_key(network_->protocol()), Use::Both}};
    }
    // Publish the DHT as a borrowable capability so a sibling subsystem (e.g.
    // Bittorrent) can share this Kademlia node instead of running a second one.
    ctx.services.provide<DhtService>(this);
    // A host network change means our public endpoint may have moved. Re-probe it
    // via STUN and re-announce so the DHT advertises our current reachable address
    // rather than the previous network's. We only flag + wake here (cheap, on the
    // node's maintenance thread); the actual STUN runs on our own loop thread.
    ctx.events.on<NetworkChanged>([this](const NetworkChanged&) {
        mapped_port_.store(0);  // renewed, and told again, if it still can be
        reflexive_port_.store(0);  // asked again
        recover_pending_.store(true);
        wake();
    });
    // The router forwards a port of its own to ours: announce that one — its
    // mapping for the transport a dial tries first.
    ctx.events.on<PortMapped>([this](const PortMapped& mapped) {
        const bool udp = (network_->transports() & PeerTransportUdp) != 0;
        if ((mapped.protocol == PortMapProtocol::UDP) != udp) return;
        const uint16_t before = announced_port();
        mapped_port_.store(mapped.external_port);
        if (const std::optional<IpAddress> ip = IpAddress::parse(mapped.external_ip)) {
            std::lock_guard<std::mutex> lock(own_mutex_);
            own_mapped_ = *ip;
        }
        if (announced_port() == before) return;
        announce_pending_.store(true);
        wake();
    });
    dial_ = ctx.services.get<DialService>();
    reflexive_ = ctx.services.get<ReflexiveAddressService>();
}

uint16_t DhtDiscovery::announced_port(bool v6) const {
    const uint16_t listen = network_->listen_port();
    if (v6) return listen;
    if (const uint16_t mapped = mapped_port_.load()) return mapped;
    if (const uint16_t seen = reflexive_port_.load()) return seen;
    return listen;
}

std::unique_ptr<DhtClient> DhtDiscovery::make_client(AddressFamily family) {
    const bool v6 = (family == AddressFamily::IPv6);
    const char* label = v6 ? "IPv6" : "IPv4";

    auto client = std::make_unique<DhtClient>(config_.dht_port, bind_for(config_.bind_address, v6),
                                              config_.data_dir, family);
    client->set_seed_directory(config_.seed_dir);
    if (!client->start()) {
        LOG_WARN("dht-discovery", label << " DHT client failed to start (skipping this family)");
        return nullptr;
    }

    const std::vector<HostEndpoint> nodes =
        config_.bootstrap_nodes.empty() ? DhtClient::get_default_bootstrap_nodes() : config_.bootstrap_nodes;
    if (!nodes.empty()) client->bootstrap(nodes);

    LOG_INFO("dht-discovery", label << " DHT on UDP port " << client->get_port());
    return client;
}

void DhtDiscovery::start() {
    if (running_.exchange(true)) return;

    // Make sure the routing-table directory exists before the clients try to use it.
    if (!config_.data_dir.empty()) create_directories(config_.data_dir.c_str());

    if (config_.enable_ipv4) dht_  = make_client(AddressFamily::IPv4);
    if (config_.enable_ipv6) dht6_ = make_client(AddressFamily::IPv6);

    if (!dht_ && !dht6_) {
        LOG_ERROR("dht-discovery", "Failed to start DHT client on any address family");
        running_.store(false);
        return;
    }

    refresh_own_ips();
    thread_ = std::thread(&DhtDiscovery::loop, this);
    LOG_INFO("dht-discovery", "Started (" << (dht_ ? "IPv4" : "") << (dht_ && dht6_ ? "+" : "")
             << (dht6_ ? "IPv6" : "") << "), " << discovery_hashes().size() << " key(s)");
}

void DhtDiscovery::stop() {
    if (!running_.exchange(false)) return;
    wake();
    if (thread_.joinable()) thread_.join();
    if (dht_)  { dht_->stop();  dht_.reset(); }
    if (dht6_) { dht6_->stop(); dht6_.reset(); }
}

bool DhtDiscovery::is_running() const {
    return running_.load() && ((dht_ && dht_->is_running()) || (dht6_ && dht6_->is_running()));
}

InfoHash DhtDiscovery::discovery_hash() const {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    return hashes_.empty() ? InfoHash{} : hashes_.front().hash;
}

std::vector<InfoHash> DhtDiscovery::discovery_hashes() const {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    std::vector<InfoHash> hashes;
    for (const Announced& a : hashes_) hashes.push_back(a.hash);
    return hashes;
}

void DhtDiscovery::set_keys(const std::vector<std::string>& keys) {
    std::vector<Key> both;
    for (const std::string& key : keys) both.push_back({key, Use::Both});
    set_keys(both);
}

void DhtDiscovery::set_keys(const std::vector<Key>& keys) {
    std::vector<Announced> hashes;
    for (const Key& key : keys) {
        const InfoHash hash = hash_for_key(key.key);
        const auto it = std::find_if(hashes.begin(), hashes.end(),
                                     [&](const Announced& a) { return a.hash == hash; });
        if (it == hashes.end()) {
            hashes.push_back({hash, key.use, {}, false});
        } else {
            it->use = Use(uint8_t(it->use) | uint8_t(key.use));
        }
    }
    bool added = false;
    {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        // A key kept as it was keeps when it was announced; one new, or put to
        // another use, is announced or searched at once.
        for (Announced& a : hashes) {
            const auto kept = std::find_if(hashes_.begin(), hashes_.end(), [&](const Announced& k) {
                return k.hash == a.hash && k.use == a.use;
            });
            if (kept != hashes_.end()) {
                a = *kept;
            } else {
                added = true;
            }
        }
        hashes_ = std::move(hashes);
        keys_set_ = true;
    }
    if (added) {
        keys_pending_.store(true);
        wake();
    }
}

void DhtDiscovery::wake() {
    // The loop checks its flags and goes to sleep under wait_mutex_: taken here,
    // a flag set just before is either seen by its check or followed by this
    // notify once it sleeps — never set between the two, and the wake lost.
    { std::lock_guard<std::mutex> lock(wait_mutex_); }
    wake_.notify_all();
}

void DhtDiscovery::refresh_own_ips() {
    std::vector<IpAddress> ips;
    for (const char* loopback : {"127.0.0.1", "::1"})
        if (const std::optional<IpAddress> ip = IpAddress::parse(loopback)) ips.push_back(*ip);
    for (const std::string& text : network_utils::get_local_interface_addresses())
        if (const std::optional<IpAddress> ip = IpAddress::parse(text)) ips.push_back(*ip);
    std::lock_guard<std::mutex> lock(own_mutex_);
    own_local_ = std::move(ips);
}

bool DhtDiscovery::is_own(const Address& address) const {
    if (!network_ || address.port == 0) return false;
    const uint16_t port = address.port;
    // At this host's IPs it listens; outside, it is at the ports the outside
    // sees — the one announced, the router's, STUN's. Not the listen port
    // there: another device behind the same NAT may hold that one.
    const uint16_t mapped = mapped_port_.load();
    const uint16_t seen = reflexive_port_.load();
    const bool outside_port = port == announced_port(address.ip.is_v6()) ||
                              (mapped != 0 && port == mapped) || (seen != 0 && port == seen);
    const bool listen_port = port == network_->listen_port();
    if (!outside_port && !listen_port) return false;
    std::lock_guard<std::mutex> lock(own_mutex_);
    if (listen_port &&
        std::find(own_local_.begin(), own_local_.end(), address.ip) != own_local_.end())
        return true;
    if (!outside_port) return false;
    return (own_seen_ && address.ip == *own_seen_) || (own_mapped_ && address.ip == *own_mapped_);
}

uint16_t DhtDiscovery::dht_port() const { return dht_ ? static_cast<uint16_t>(dht_->get_port()) : 0; }

uint16_t DhtDiscovery::dht_port_v6() const { return dht6_ ? static_cast<uint16_t>(dht6_->get_port()) : 0; }

std::string DhtDiscovery::external_address() const {
    // The IPv4 reflexive address is the public-facing one most callers expect;
    // fall back to the IPv6 client's view if only that family is up.
    if (dht_) {
        std::string a = dht_->get_external_address();
        if (!a.empty()) return a;
    }
    return dht6_ ? dht6_->get_external_address() : "";
}

// Discover our reflexive (public) address via STUN and feed it to the DHT so the
// node id is BEP-42-correct from the start instead of waiting for "ip" voting —
// from the shared datagram socket, whose mapping is then the port announced, or,
// on a node without one, from a socket of our own, for the IP alone.
// Runs on the loop thread; stop() joins that thread before resetting dht_, so the
// dht_ access here can never touch a freed client.
bool DhtDiscovery::probe_external_ip() {
    std::vector<HostEndpoint> servers = config_.stun_servers.empty() ? default_stun_servers()
                                                                      : config_.stun_servers;
    const bool shared = reflexive_ && (network_->transports() & PeerTransportUdp) != 0;
    StunClient stun;
    std::optional<Address> first;
    for (const HostEndpoint& s : servers) {
        if (!running_.load()) return false;  // stopping; don't keep probing
        std::optional<Address> seen;
        if (shared) {
            const std::optional<IpAddress> ip = IpAddress::parse(network_utils::resolve_hostname(s.host));
            if (ip && ip->is_v4()) seen = reflexive_->udp_endpoint(Address{*ip, s.port}, config_.stun_timeout);
        } else {
            const StunResult r = stun.binding_request(s.host, s.port, static_cast<int>(config_.stun_timeout.count()));
            if (r.success && r.mapped_address)
                if (const std::optional<IpAddress> ip = IpAddress::parse(r.mapped_address->address))
                    seen = Address{*ip, 0};
        }
        if (!seen) continue;

        if (first) {
            // A second server, asked once: a NAT that maps the socket anew for it
            // does so for every peer (symmetric), and no peer's dial gets through.
            if (seen->port != first->port)
                LOG_WARN("dht-discovery", "The NAT maps our socket to another port for each destination ("
                         << first->port << ", " << seen->port << "): peers cannot dial it");
            return true;
        }
        first = seen;
        const std::string ip = seen->ip.to_string();
        if (seen != last_seen_) {
            LOG_INFO("dht-discovery", "STUN reflexive address " << (shared ? seen->to_string() : ip)
                     << " (via " << s.host << ":" << s.port << ")");
        }
        last_seen_ = seen;
        {
            std::lock_guard<std::mutex> lock(own_mutex_);
            own_seen_ = seen->ip;
        }
        // Feed it to whichever clients are up; each ignores it if it's not a
        // public address of its own family (e.g. a v4 reflexive on the v6 client).
        if (running_.load()) for_each_client([&](DhtClient& c) { c.set_external_ip(ip); });
        if (shared) reflexive_port_.store(seen->port);
        if (!shared || mapping_checked_) return true;
        mapping_checked_ = true;  // and on to the next server, once
    }
    if (!first) LOG_DEBUG("dht-discovery", "STUN external-IP discovery failed; relying on DHT ip voting");
    return first.has_value();
}

void DhtDiscovery::loop() {
    using Clock = std::chrono::steady_clock;
    // STUN again when due, on the round of searching it falls in: it keeps the
    // shared socket's mapping alive, and finds it anew if it moved — then
    // announced at once.
    Clock::time_point stun_due = Clock::now();
    auto ask_stun = [&] {
        const uint16_t before = announced_port();
        const bool answered = probe_external_ip();
        stun_due = Clock::now() + (answered ? config_.stun_every : config_.stun_every * 10);
        return announced_port() != before;
    };
    if (config_.discover_external_ip) ask_stun();

    // Every key announced anew: its last announce forgotten.
    auto announce_all = [this] {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        for (Announced& a : hashes_) a.announced[0].reset(), a.announced[1].reset();
    };
    std::optional<Clock::time_point> last_search;
    // What is held back for a DHT that knows no node is tried again half a
    // second on, then twice as long each time up to a round: a family that
    // never comes to know one (IPv6 with no route out) is not asked of twice a
    // second for ever. Keys new, or a network changed, start it over.
    constexpr std::chrono::milliseconds kHoldFirst{500};
    std::chrono::milliseconds hold_retry = kHoldFirst;
    while (running_.load()) {
        // Network changed: re-learn our public IP and force an immediate re-announce.
        if (recover_pending_.exchange(false)) {
            LOG_INFO("dht-discovery", "Network changed — re-probing STUN and re-announcing");
            refresh_own_ips();
            if (config_.discover_external_ip) ask_stun();
            announce_all();
            hold_retry = kHoldFirst;
        }
        const bool moved = config_.discover_external_ip && Clock::now() >= stun_due && ask_stun();
        if (announce_pending_.exchange(false) || moved) {
            LOG_INFO("dht-discovery", "Announcing port " << announced_port());
            announce_all();
        }
        if (keys_pending_.exchange(false)) hold_retry = kHoldFirst;

        const auto now = Clock::now();
        auto deliver = [this](const std::vector<Address>& peers, const InfoHash& h) { on_peers(peers, h); };
        // Each key due is announced. announce_peer runs a get_peers traversal and
        // announces on completion, so it discovers peers itself — fed to on_peers,
        // with no find_peers for that key this round, otherwise we'd run two
        // identical traversals per hash (every node queried twice). The keys
        // searched are searched on the faster cadence in between announces —
        // unless the round is early, woken for a key new: then only that one.
        // What a key announced alone hands back is dialed by nobody (on_peers).
        const bool search_due = !last_search || now - *last_search >= config_.search_interval;
        if (search_due) last_search = now;
        // A DHT that knows no node yet (bootstrapping) is asked nothing: its
        // lookup would end at once with none, and an announce so lost would
        // leave the node unfound until the next — what is held back goes at
        // the next round, soon.
        DhtClient* const clients[2] = {dht_.get(), dht6_.get()};
        bool knows[2] = {};
        for (int f = 0; f < 2; ++f) knows[f] = clients[f] && clients[f]->get_routing_table_size() > 0;
        struct Ask {
            DhtClient* client;
            InfoHash hash;
            bool announce;
            bool v6;
        };
        std::vector<Ask> asks;
        bool held = false;
        {
            std::lock_guard<std::mutex> lock(keys_mutex_);
            for (Announced& a : hashes_) {
                const bool announced = (uint8_t(a.use) & uint8_t(Use::Announce)) != 0;
                const bool searched = (uint8_t(a.use) & uint8_t(Use::Search)) != 0;
                const bool search_now = searched && (search_due || !a.searched);
                if (search_now && !(knows[0] || knows[1])) held = true;
                if (search_now && (knows[0] || knows[1])) a.searched = true;
                for (int f = 0; f < 2; ++f) {
                    if (!clients[f]) continue;
                    if (announced && (!a.announced[f] ||
                                      now - *a.announced[f] >= config_.announce_interval)) {
                        if (!knows[f]) {
                            held = true;
                            continue;
                        }
                        asks.push_back({clients[f], a.hash, true, f == 1});
                        a.announced[f] = now;
                    } else if (search_now && knows[f]) {
                        asks.push_back({clients[f], a.hash, false, f == 1});
                    }
                }
            }
        }
        for (const Ask& ask : asks) {
            if (ask.announce) {
                ask.client->announce_peer(ask.hash, announced_port(ask.v6), deliver);
            } else {
                ask.client->find_peers(ask.hash, deliver);
            }
        }
        // What was found lately and is in its first stretch is punched on its
        // own time, not only as the DHT hands it out again (once a round): two
        // behind NATs that keep punching each other every few seconds overlap.
        punch_pending_.store(false);
        punch_due(now);
        std::optional<Clock::time_point> punch_at;
        {
            std::lock_guard<std::mutex> lock(dialed_mutex_);
            dialed_.forget_older_than(now - kForgetFound);
            punch_at = dialed_.next_due();
        }

        auto next = *last_search + config_.search_interval;
        if (held) {
            next = (std::min)(next, now + hold_retry);
            hold_retry = (std::min)(hold_retry * 2, config_.search_interval);
        } else {
            hold_retry = kHoldFirst;
        }
        if (punch_at) next = (std::min)(next, *punch_at);
        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_until(lock, next, [this] {
            return !running_.load() || recover_pending_.load() || announce_pending_.load() ||
                   keys_pending_.load() || punch_pending_.load();
        });
    }
}

std::vector<Address> DhtDiscovery::connected_addresses() const {
    // The addresses dialable — the one dialed, or the one seen with the listen
    // port told — and where the packets come from: what a peer behind a NAT
    // announces is its NAT's mapping of the shared socket, which is the latter.
    std::vector<Address> connected;
    for (PeerInfo& info : network_->peers()) {
        connected.insert(connected.end(), info.addresses.begin(), info.addresses.end());
        if (info.endpoint) connected.push_back(*info.endpoint);
    }
    return connected;
}

void DhtDiscovery::punch_due(std::chrono::steady_clock::time_point now) {
    std::vector<Address> due;
    {
        std::lock_guard<std::mutex> lock(dialed_mutex_);
        due = dialed_.due(now);
    }
    if (due.empty()) return;
    const std::vector<Address> connected = connected_addresses();
    for (const Address& peer : due) {
        if (std::find(connected.begin(), connected.end(), peer) != connected.end()) {
            std::lock_guard<std::mutex> lock(dialed_mutex_);
            dialed_.connected(peer);
            continue;
        }
        LOG_DEBUG("dht-discovery", "Punching discovered peer " << peer.to_string());
        if (!dial_ || !dial_->dial_direct(peer, TransportKind::Udp, DialProfile::punch()))
            network_->connect(peer);
    }
}

bool DhtDiscovery::searches(const InfoHash& hash) const {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    const auto it = std::find_if(hashes_.begin(), hashes_.end(),
                                 [&](const Announced& a) { return a.hash == hash; });
    return it != hashes_.end() && (uint8_t(it->use) & uint8_t(Use::Search)) != 0;
}

void DhtDiscovery::on_peers(const std::vector<Address>& peers, const InfoHash& info_hash) {
    // An announce is a lookup first and hands back who is there: a key
    // announced alone seeks nobody, and one gone since the lookup began no
    // longer seeks anybody.
    if (!searches(info_hash)) return;
    const std::vector<Address> connected = connected_addresses();

    const auto now = Redials::Clock::now();
    for (const Address& peer : peers) {
        if (peer.ip.is_any() || peer.port == 0 || is_own(peer)) continue;
        const bool is_connected =
            std::find(connected.begin(), connected.end(), peer) != connected.end();
        Redials::Dial dial = Redials::Dial::None;
        {
            std::lock_guard<std::mutex> lock(dialed_mutex_);
            if (is_connected) {
                dialed_.connected(peer);
            } else {
                dial = dialed_.found(peer, now);
            }
        }
        if (dial == Redials::Dial::None) continue;
        if (dial == Redials::Dial::First) {
            LOG_INFO("dht-discovery", "Dialing discovered peer " << peer.to_string());
            // Its punches from now on are the loop's to time.
            punch_pending_.store(true);
            wake();
        } else {
            LOG_DEBUG("dht-discovery", "Punching discovered peer " << peer.to_string());
        }
        // The first dial races TCP in, for a network that blocks UDP; a punch is
        // the shared datagram socket's alone.
        if (dial == Redials::Dial::First || !dial_ ||
            !dial_->dial_direct(peer, TransportKind::Udp, DialProfile::punch())) {
            network_->connect(peer);
        }
    }
}

} // namespace librats
