#include "librats/subsystems/hole_punch.h"
#include "librats/node/dial_service.h"
#include "librats/node/node_context.h"
#include "librats/peer/peer_info.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <optional>

namespace librats {

namespace {

constexpr uint8_t kVersion = 1;

// Envelope ops — what a message is *for the relay*.
constexpr uint8_t kOpRelay   = 0;  ///< sender → relay: pass this on to dst
constexpr uint8_t kOpRelayed = 1;  ///< relay → destination: this came from src

// Inner kinds — what the two punching peers say to each other.
constexpr uint8_t kKindConnect = 0;
constexpr uint8_t kKindSync    = 1;

/// Ceiling on addresses a Connect may carry, independent of the local config: a
/// peer must not be able to make us walk a longer list than we would ever send.
constexpr size_t kMaxAddressesOnWire = 8;

/// Largest envelope worth parsing. Version + op + id + kind + count + the address
/// list at its widest (IPv6). Anything past this is malformed by construction.
constexpr size_t kMaxMessageSize = 2 + PeerId::kSize + 3 + kMaxAddressesOnWire * 19;

/// The `role` byte of a Connect: is this opening a rendezvous, or answering one?
constexpr uint8_t kRoleOpening = 0;
constexpr uint8_t kRoleAnswer  = 1;

void put_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

void put_address(Bytes& out, const Address& a) {
    const ByteView ip = a.ip.bytes();  // 4 (v4) or 16 (v6) raw bytes
    out.push_back(static_cast<uint8_t>(ip.size()));
    out.insert(out.end(), ip.begin(), ip.end());
    put_u16(out, a.port);
}

/// Bounds-checked forward reader: any short read aborts the whole message, which
/// is the only way a hostile payload is allowed to affect us.
struct Reader {
    const uint8_t* p;
    size_t         n;

    const uint8_t* take(size_t k) {
        if (n < k) return nullptr;
        const uint8_t* at = p;
        p += k; n -= k;
        return at;
    }
};

Bytes encode_connect(bool opening, const std::vector<Address>& addresses) {
    Bytes out;
    out.push_back(kKindConnect);
    out.push_back(opening ? kRoleOpening : kRoleAnswer);
    const size_t count = (std::min)(addresses.size(), kMaxAddressesOnWire);
    out.push_back(static_cast<uint8_t>(count));
    for (size_t i = 0; i < count; ++i) put_address(out, addresses[i]);
    return out;
}

struct ConnectBody {
    bool                 opening = false;
    std::vector<Address> addresses;
};

/// Parse a Connect body (everything after the kind byte). nullopt on anything
/// malformed — a partially-read list is never acted on.
std::optional<ConnectBody> decode_connect(ByteView body) {
    Reader r{body.data(), body.size()};
    const uint8_t* role_p = r.take(1);
    if (!role_p) return std::nullopt;
    if (*role_p != kRoleOpening && *role_p != kRoleAnswer) return std::nullopt;

    const uint8_t* count_p = r.take(1);
    if (!count_p) return std::nullopt;
    const uint8_t count = *count_p;
    if (count > kMaxAddressesOnWire) return std::nullopt;

    std::vector<Address> out;
    out.reserve(count);
    for (uint8_t i = 0; i < count; ++i) {
        const uint8_t* len_p = r.take(1);
        if (!len_p) return std::nullopt;
        const uint8_t ip_len = *len_p;
        if (ip_len != 4 && ip_len != 16) return std::nullopt;
        const uint8_t* ip_p = r.take(ip_len);
        if (!ip_p) return std::nullopt;
        const uint8_t* port_p = r.take(2);
        if (!port_p) return std::nullopt;

        const auto ip = IpAddress::from_bytes(ByteView(ip_p, ip_len));
        if (!ip) return std::nullopt;
        Address addr{*ip, get_u16(port_p)};
        if (!addr.is_valid() || addr.ip.is_any()) continue;  // not dialable; skip, don't fail
        out.push_back(addr);
    }
    return ConnectBody{*role_p == kRoleOpening, std::move(out)};
}

Bytes envelope(uint8_t op, const PeerId& id, const Bytes& inner) {
    Bytes out;
    out.reserve(2 + PeerId::kSize + inner.size());
    out.push_back(kVersion);
    out.push_back(op);
    const auto& bytes = id.bytes();
    out.insert(out.end(), bytes.begin(), bytes.end());
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

} // namespace

HolePunch::HolePunch() : HolePunch(Config()) {}
HolePunch::HolePunch(Config config) : config_(std::move(config)) {}
HolePunch::~HolePunch() { stop(); }

void HolePunch::attach(NodeContext& ctx) {
    network_  = &ctx.network;
    // Both are optional by construction: resolve() answers nullptr when nothing
    // provides the interface, and a node that cannot dial a specific endpoint or
    // does not know its own external one simply cannot punch — it can still relay.
    dialer_   = ctx.services.get<DialService>();
    external_ = ctx.services.get<ExternalAddressService>();
    services_ = &ctx.services;

    // Offer punching to sibling modules. Registered even without a dialer: punch()
    // answers false on its own then, which is exactly what a caller expects from a
    // node that can only relay.
    ctx.services.provide<HolePunchService>(this);

    network_->on(MessageType::Punch,
                 [this](const Peer& peer, ByteView payload) { handle(peer, payload); });

    // A peer arriving retires its session at once, rather than at the next tick.
    // Watching for the peer — not for our dial reporting success — is the reliable
    // signal: a punch lands in both directions and the one that survives is often
    // the INBOUND link, which no dial of ours would ever report. The worker still
    // reconciles sessions against the peer set, so this is the fast path, not the
    // only one.
    network_->on_peer_connected([this](const Peer& peer) {
        // A relayed link is not what a punch was for — it is the fallback the punch
        // is trying to make unnecessary, and a punch may well have been started
        // BECAUSE it came up (see subsystems/relay.h). Retiring the session here
        // would call the upgrade off the moment it began.
        const auto info = peer.info();
        if (info && info->transport == TransportKind::Relay) return;
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.erase(peer.id());
    });
}

void HolePunch::start() {
    // Resolved here rather than in attach(): Relay may be attached after us, and
    // every attach() runs before any start(). Stored before running_ goes true, so
    // an escalation on a reactor thread never sees a half-initialised state.
    if (config_.relay_on_failure && services_)
        relay_.store(services_->get<RelayService>());

    if (running_.exchange(true)) return;
    worker_ = std::thread([this] { loop(); });
}

void HolePunch::stop() {
    relay_.store(nullptr);
    if (!running_.exchange(false)) return;
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();

    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
    cooldown_.clear();
}

// ── Starting a punch ────────────────────────────────────────────────────────

bool HolePunch::punch(const PeerId& target) {
    if (!running_.load() || !network_ || !dialer_) return false;
    if (target == network_->local_id()) return false;

    // Already reachable the ordinary way. Checked before any state is created so a
    // caller can punch() freely on discovery without having to check first. A
    // RELAYED peer is deliberately not "already reachable": punching it is how the
    // circuit gets replaced by a direct link (see subsystems/relay.h).
    for (const PeerId& id : directly_connected())
        if (id == target) return false;

    if (config_.skip_when_endpoint_dependent && external_ &&
        external_->udp_mapping() == NatMapping::EndpointDependent) {
        LOG_DEBUG("punch", "Not punching to " << target.short_hex()
                  << ": our own mapping is per-destination (symmetric NAT)");
        // Nothing about this will improve with time or retries: no endpoint we can
        // advertise is the one the target's packets would arrive on. This is
        // exactly the case a relayed path exists for.
        escalate_to_relay(target);
        return false;
    }

    const auto addresses = own_punch_addresses();
    if (addresses.empty()) {
        LOG_DEBUG("punch", "Not punching to " << target.short_hex()
                  << ": no external datagram endpoint to advertise yet");
        escalate_to_relay(target);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sessions_.count(target)) return false;          // already running
        if (in_cooldown(target)) return false;              // recently gave up
        if (sessions_.size() >= config_.max_sessions) return false;

        Session session;
        session.initiator = true;
        session.phase     = Phase::AwaitingPeerConnect;
        session.deadline  = std::chrono::steady_clock::now() + config_.round_timeout;
        sessions_.emplace(target, std::move(session));
    }

    if (!send_connect(target, /*opening=*/true, nullptr)) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sessions_.erase(target);   // nobody could carry it; nothing is in flight
        }
        escalate_to_relay(target);
        return false;
    }
    LOG_DEBUG("punch", "Punch rendezvous started with " << target.short_hex());
    return true;
}

bool HolePunch::send_connect(const PeerId& target, bool opening, const PeerId* via) {
    const auto addresses = own_punch_addresses();
    if (addresses.empty()) return false;
    return relay_to(target, encode_connect(opening, addresses), via) > 0;
}

void HolePunch::send_sync(const PeerId& target, const PeerId* via) {
    Bytes inner;
    inner.push_back(kKindSync);
    relay_to(target, inner, via);
}

size_t HolePunch::relay_to(const PeerId& dst, const Bytes& inner, const PeerId* via) {
    const Bytes message = envelope(kOpRelay, dst, inner);

    // A hop that has already carried something from the target is known to reach it,
    // so the rest of the exchange goes back that way rather than out to everybody
    // again. Only the very first message pays the fan-out.
    if (via) {
        network_->send(*via, MessageType::Punch, ByteView(message));
        return 1;
    }

    // Nothing known yet: we do not know which of our peers also has the target, so
    // ask a few and let the ones that cannot help drop it. Bounded on purpose —
    // every extra relay is a duplicate rendezvous the far end has to recognise.
    size_t sent = 0;
    for (const PeerId& relay : network_->connected_peers()) {
        if (sent >= config_.max_relays) break;
        if (relay == dst) continue;  // if it were connected we would not be punching
        // send() answers backpressure, not delivery, and every id here is a peer we
        // hold — so the message is on its way either way.
        network_->send(relay, MessageType::Punch, ByteView(message));
        ++sent;
    }
    return sent;
}

std::vector<Address> HolePunch::own_punch_addresses() const {
    if (!external_) return {};
    auto addresses = external_->external_udp_endpoints();
    if (addresses.size() > config_.max_addresses) addresses.resize(config_.max_addresses);
    return addresses;
}

// ── Inbound ─────────────────────────────────────────────────────────────────

void HolePunch::handle(const Peer& from, ByteView payload) {
    if (!running_.load()) return;
    if (payload.size() < 2 + PeerId::kSize || payload.size() > kMaxMessageSize) return;
    if (payload.data()[0] != kVersion) return;

    const uint8_t  op    = payload.data()[1];
    const auto     id    = PeerId::from_bytes(ByteView(payload.data() + 2, PeerId::kSize));
    if (!id) return;
    const ByteView inner(payload.data() + 2 + PeerId::kSize,
                         payload.size() - 2 - PeerId::kSize);
    if (inner.empty()) return;

    if (op == kOpRelay) {
        handle_relay_request(from, *id, inner);
    } else if (op == kOpRelayed) {
        // The envelope names who this came from, but only the peer that actually
        // delivered it vouches for anything — and it vouches only for having
        // forwarded it. That is the whole trust model here; see the note in the
        // header about what acting on a forged Connect can cost.
        handle_relayed(from, *id, inner);
    }
}

void HolePunch::handle_relay_request(const Peer& from, const PeerId& dst, ByteView inner) {
    if (!config_.enable_relay) return;
    if (dst == network_->local_id() || dst == from.id()) return;

    // Forward ONLY to a peer we already hold. This is what keeps a relay from being
    // an open reflector: it never resolves an address, never dials, and can only
    // ever deliver to somebody that chose to connect to it. Checked before the
    // budget is spent, so the common case — a fan-out request for a peer we simply
    // do not have — costs the sender nothing.
    const std::vector<PeerId> peers = network_->connected_peers();
    if (std::find(peers.begin(), peers.end(), dst) == peers.end()) return;

    if (!relay_budget_ok(from.id())) {
        LOG_DEBUG("punch", "Dropping relay from " << from.id().short_hex() << ": over budget");
        return;
    }

    const Bytes message = envelope(kOpRelayed, from.id(), Bytes(inner.begin(), inner.end()));
    network_->send(dst, MessageType::Punch, ByteView(message));
    relayed_.fetch_add(1, std::memory_order_relaxed);
}

void HolePunch::handle_relayed(const Peer& via, const PeerId& src, ByteView inner) {
    if (src == network_->local_id()) return;   // a relay looping our own message back

    const uint8_t  kind = inner.data()[0];
    const ByteView body(inner.data() + 1, inner.size() - 1);

    if (kind == kKindConnect) {
        auto connect = decode_connect(body);
        if (!connect) return;               // malformed → ignore, never fatal
        handle_connect(via, src, connect->opening, std::move(connect->addresses));
    } else if (kind == kKindSync) {
        handle_sync(src);
    }
}

void HolePunch::handle_connect(const Peer& via, const PeerId& src, bool opening,
                               std::vector<Address> addresses) {
    if (addresses.empty()) return;
    if (addresses.size() > config_.max_addresses) addresses.resize(config_.max_addresses);

    bool                 reply_with_connect = false;
    bool                 punch_now = false;
    std::vector<Address> targets;
    const PeerId         hop = via.id();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(src);

        if (!opening) {
            // The answer to a rendezvous WE opened. Anything else — an answer with
            // no question, or one arriving after we stood down — is stale and is
            // dropped rather than acted on.
            if (it == sessions_.end() || !it->second.initiator) return;
            if (it->second.phase != Phase::AwaitingPeerConnect) return;
        } else if (it != sessions_.end() && it->second.initiator) {
            // Both ends opened a rendezvous at once. Left alone each would wait for
            // the other's Sync and neither would send one, so the same symmetric
            // rule the peer table uses for a cross-connect settles it: the smaller
            // id keeps the round, the larger stands down and answers. Both ends
            // compute it identically, so exactly one of them stands down.
            if (network_->local_id() < src) return;   // ours wins; ignore theirs
            it->second.initiator = false;
        }

        if (it == sessions_.end()) {
            if (sessions_.size() >= config_.max_sessions) return;
            if (in_cooldown(src)) return;
            Session session;
            session.initiator = false;
            it = sessions_.emplace(src, std::move(session)).first;
        }

        Session& session = it->second;
        session.peer_addresses = std::move(addresses);
        session.deadline = std::chrono::steady_clock::now() + config_.round_timeout;
        session.via      = hop;    // this hop just proved it reaches the target
        session.have_via = true;

        if (session.initiator) {
            // Step 3: the round trip through the relay is now known, so send Sync
            // and start dialing immediately — the peer starts when Sync lands, and
            // the two bursts meet in the middle.
            session.phase = Phase::Punching;
            punch_now = true;
            targets   = session.peer_addresses;
        } else {
            session.phase      = Phase::AwaitingSync;
            reply_with_connect = true;
        }
    }

    // Outside the lock: both reach the network, and dialing may run callbacks inline.
    if (reply_with_connect) {
        if (!send_connect(src, /*opening=*/false, &hop)) {
            std::lock_guard<std::mutex> lock(mutex_);
            sessions_.erase(src);
        }
        return;
    }
    if (punch_now) {
        // Order matters: Sync goes first, then we dial. The peer starts dialing when
        // Sync lands, so leaving here first is what buys the half round trip that
        // makes the two bursts overlap.
        send_sync(src, &hop);
        fire_punch(src, targets);
    }
}

void HolePunch::handle_sync(const PeerId& src) {
    std::vector<Address> targets;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(src);
        if (it == sessions_.end() || it->second.phase != Phase::AwaitingSync) return;
        if (it->second.peer_addresses.empty()) return;
        it->second.phase    = Phase::Punching;
        it->second.deadline = std::chrono::steady_clock::now() + config_.round_timeout;
        targets             = it->second.peer_addresses;
    }
    fire_punch(src, targets);
}

void HolePunch::fire_punch(const PeerId& target, const std::vector<Address>& addresses) {
    if (!dialer_) return;
    LOG_DEBUG("punch", "Punching to " << target.short_hex() << " at " << addresses.size()
              << " endpoint(s)");
    for (const Address& addr : addresses)
        dialer_->dial_direct(addr, TransportKind::Udp, config_.profile);
    punches_started_.fetch_add(1, std::memory_order_relaxed);
}

// ── Relay budget ────────────────────────────────────────────────────────────

bool HolePunch::relay_budget_ok(const PeerId& from) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(relay_mutex_);

    // Bounded by dropping the whole table when it grows past what a real mesh would
    // hold. Cheaper than per-entry expiry on a path that runs per forwarded message,
    // and the only cost of the reset is one over-generous window for everybody.
    if (relay_budget_.size() > 4096) relay_budget_.clear();

    RelayBudget& budget = relay_budget_[from];
    if (now - budget.window_started >= config_.relay_window) {
        budget.window_started = now;
        budget.spent = 0;
    }
    if (budget.spent >= config_.relay_budget) return false;
    ++budget.spent;
    return true;
}

// ── Worker ──────────────────────────────────────────────────────────────────

void HolePunch::loop() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (running_.load()) {
        cv_.wait_for(lock, config_.tick, [this] { return !running_.load(); });
        if (!running_.load()) return;
        lock.unlock();
        service_sessions();
        lock.lock();
    }
}

void HolePunch::service_sessions() {
    const auto now = std::chrono::steady_clock::now();

    // Connected peers first, without the lock: a session whose target is now a peer
    // succeeded, however it got there (our burst, or theirs arriving as inbound).
    // Direct links only — a relayed one is what a punch is trying to replace.
    std::vector<PeerId> connected = directly_connected();

    struct Retry { PeerId target; PeerId via; bool have_via; };
    std::vector<Retry> retry;
    std::vector<PeerId> exhausted;   ///< targets to hand on to the relay, once unlocked
    {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto it = cooldown_.begin(); it != cooldown_.end();) {
            if (now >= it->second) it = cooldown_.erase(it);
            else                   ++it;
        }

        for (auto it = sessions_.begin(); it != sessions_.end();) {
            const PeerId& target = it->first;
            if (std::find(connected.begin(), connected.end(), target) != connected.end()) {
                LOG_DEBUG("punch", "Punch to " << target.short_hex() << " succeeded");
                it = sessions_.erase(it);
                continue;
            }
            if (now < it->second.deadline) { ++it; continue; }

            // The round is over and the peer is still not here. Only the initiator
            // retries: a responder has no idea whether the other side is still
            // trying, and two ends retrying independently would drift apart from the
            // one thing that makes a punch work — starting together.
            const bool initiator = it->second.initiator;
            if (!initiator || ++it->second.attempt >= config_.attempts) {
                LOG_DEBUG("punch", "Giving up on " << target.short_hex() << " for now");
                // Cooldown is the INITIATOR's verdict on a target and nobody else's.
                // A responder round ending means only that the Sync never came — the
                // initiator is very likely mid-retry at that exact moment (its round
                // started a relay hop earlier than ours, so its deadline expires
                // first). Calling the target off here would drop the retries it is
                // about to send, and block this node's own later punch to it, for
                // the whole cooldown. So a responder just forgets the round.
                if (initiator) {
                    begin_cooldown(target);
                    exhausted.push_back(target);
                }
                it = sessions_.erase(it);
                continue;
            }
            it->second.phase    = Phase::AwaitingPeerConnect;
            it->second.peer_addresses.clear();
            it->second.deadline = now + config_.round_timeout;
            retry.push_back(Retry{target, it->second.via, it->second.have_via});
            ++it;
        }
    }

    for (const Retry& r : retry) {
        if (send_connect(r.target, /*opening=*/true, r.have_via ? &r.via : nullptr)) continue;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sessions_.erase(r.target);
        }
        exhausted.push_back(r.target);
    }

    // The rungs above this one are spent: no address we can advertise got through.
    // Handing the target on is the difference between a peer that is unreachable
    // and one that is merely expensive to reach.
    for (const PeerId& target : exhausted) escalate_to_relay(target);
}

void HolePunch::escalate_to_relay(const PeerId& target) {
    RelayService* relay = relay_.load();
    if (!relay) return;   // no Relay attached, or the fallback is off
    if (!relay->connect_via_relay(target)) return;

    LOG_DEBUG("punch", "Punching to " << target.short_hex()
              << " is not going to work; looking for a relay instead");

    // The target has just changed hands, and the cooldown a give-up started must not
    // outlive that. It exists to stop us hammering a peer we cannot reach — a job
    // the relay now owns, with an attempt timeout and a cooldown of its own.
    //
    // And if that attempt lands, the circuit is precisely the new information that
    // makes another punch worth trying: the two ends are peers at last, so the
    // rendezvous can travel over the very circuit carrying them, which is what
    // Relay asks for the moment the circuit comes up (see subsystems/relay.h).
    // Leaving the cooldown standing would refuse that upgrade before it started —
    // and nothing would ever ask again, so the circuit would outlive its purpose and
    // keep costing a third node bandwidth for the life of the peer.
    //
    // Bounded, not a loop: an upgrade punch that fails lands here again, and
    // connect_via_relay then answers false — the target is already a peer — so the
    // fresh cooldown stands. Taken after the call, never around it: Relay resolves
    // the reverse direction through us, and this mutex must not be held into it.
    std::lock_guard<std::mutex> lock(mutex_);
    cooldown_.erase(target);
}

std::vector<PeerId> HolePunch::directly_connected() const {
    std::vector<PeerId> ids;
    for (const PeerInfo& info : network_->peers())
        if (info.transport != TransportKind::Relay) ids.push_back(info.id);
    return ids;
}

bool HolePunch::in_cooldown(const PeerId& target) const {
    auto it = cooldown_.find(target);
    return it != cooldown_.end() && std::chrono::steady_clock::now() < it->second;
}

void HolePunch::begin_cooldown(const PeerId& target) {
    cooldown_[target] = std::chrono::steady_clock::now() + config_.cooldown;
}

size_t HolePunch::active_sessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

} // namespace librats
