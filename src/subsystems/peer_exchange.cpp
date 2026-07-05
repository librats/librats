#include "subsystems/peer_exchange.h"
#include "node/node_context.h"
#include "util/logger.h"
#include "util/network_utils.h"

#include <algorithm>
#include <unordered_set>

namespace librats {

namespace {

constexpr uint8_t kVersion  = 1;  // peer IPs are raw address bytes (4/16), not text
constexpr uint8_t kRequest  = 0;
constexpr uint8_t kResponse = 1;

constexpr size_t kRequestSize = 4;  // ver + op + u16 max

void put_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

} // namespace

PeerExchange::PeerExchange() : PeerExchange(Config()) {}
PeerExchange::PeerExchange(Config config) : config_(std::move(config)) {}
PeerExchange::~PeerExchange() { stop(); }

void PeerExchange::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    network_->on(MessageType::Pex,
                         [this](const Peer& peer, ByteView payload) { handle(peer, payload); });
    network_->on_peer_connected([this](const Peer& peer) { on_connected(peer); });
}

void PeerExchange::start() { running_.store(true); }
void PeerExchange::stop()  { running_.store(false); }

// ── Outgoing request (on connect) ────────────────────────────────────────────

void PeerExchange::on_connected(const Peer& peer) {
    if (!running_.load() || !config_.request_on_connect) return;
    const uint16_t max = static_cast<uint16_t>(std::min<size_t>(config_.request_max, 0xFFFF));

    uint8_t req[kRequestSize] = {kVersion, kRequest,
                                 static_cast<uint8_t>(max >> 8), static_cast<uint8_t>(max & 0xFF)};
    network_->send(peer.id(), MessageType::Pex, ByteView(req, kRequestSize));
}

// ── Inbound dispatch ─────────────────────────────────────────────────────────

void PeerExchange::handle(const Peer& peer, ByteView payload) {
    if (!running_.load() || payload.size() < 2) return;
    if (payload.data()[0] != kVersion) return;                // unknown version → ignore

    const uint8_t op = payload.data()[1];
    const ByteView body(payload.data() + 2, payload.size() - 2);
    if (op == kRequest) {
        if (body.size() < 2) return;
        handle_request(peer, get_u16(body.data()));
    } else if (op == kResponse) {
        handle_response(body);
    }
}

void PeerExchange::handle_request(const Peer& requester, uint16_t max) {
    const size_t limit = std::min<size_t>(max, config_.max_addresses_per_response);
    if (limit == 0) return;
    const PeerId& self = network_->local_id();

    Bytes out;
    out.push_back(kVersion);
    out.push_back(kResponse);
    const size_t count_pos = out.size();
    put_u16(out, 0);  // count placeholder, back-patched below

    uint16_t count = 0;
    for (const PeerInfo& p : network_->peers()) {
        if (count >= limit) break;
        if (p.id == requester.id() || p.id == self) continue;  // not the asker, not us
        const Address* addr = pick_shareable(p.addresses);
        if (!addr) continue;

        const ByteView ip = addr->ip.bytes();  // 4 (v4) or 16 (v6) raw bytes
        out.push_back(static_cast<uint8_t>(ip.size()));
        out.insert(out.end(), ip.begin(), ip.end());
        put_u16(out, addr->port);
        const auto& id_bytes = p.id.bytes();
        out.insert(out.end(), id_bytes.begin(), id_bytes.end());
        ++count;
    }
    if (count == 0) return;  // nothing worth sending

    out[count_pos]     = static_cast<uint8_t>(count >> 8);
    out[count_pos + 1] = static_cast<uint8_t>(count & 0xFF);
    network_->send(requester.id(), MessageType::Pex, ByteView(out));
}

void PeerExchange::handle_response(ByteView body) {
    const uint8_t* p = body.data();
    size_t         n = body.size();
    // Bounds-checked forward reader: any short read aborts the whole response.
    auto take = [&](size_t k) -> const uint8_t* {
        if (n < k) return nullptr;
        const uint8_t* at = p;
        p += k; n -= k;
        return at;
    };

    const uint8_t* hdr = take(2);
    if (!hdr) return;
    const uint16_t count = get_u16(hdr);

    const PeerId self = network_->local_id();
    std::unordered_set<PeerId, PeerId::Hash> connected;
    for (const PeerId& id : network_->connected_peers()) connected.insert(id);

    size_t dialed = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (dialed >= config_.max_addresses_per_response) break;  // bound receiver work

        const uint8_t* len_p = take(1);
        if (!len_p) return;
        const uint8_t ip_len = *len_p;
        if (ip_len != 4 && ip_len != 16) return;  // malformed
        const uint8_t* ip_p = take(ip_len);
        if (!ip_p) return;
        const auto ip = IpAddress::from_bytes(ByteView(ip_p, ip_len));
        const uint8_t* port_p = take(2);
        if (!port_p) return;
        const uint16_t port = get_u16(port_p);
        const uint8_t* id_p = take(PeerId::kSize);
        if (!id_p) return;
        const auto id = PeerId::from_bytes(ByteView(id_p, PeerId::kSize));

        if (!id || *id == self || connected.count(*id)) continue;     // us / already linked
        if (!ip || port == 0 || ip->is_any()) continue;               // not dialable
        Address addr{*ip, port};
        if (!should_dial(addr)) continue;                             // cooldown / dedup

        LOG_DEBUG("pex", "Discovered peer " << id->short_hex() << " at " << addr.to_string() << "; dialing");
        network_->connect(addr);
        ++dialed;
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const Address* PeerExchange::pick_shareable(const std::vector<Address>& addrs) const {
    for (const Address& a : addrs) {
        if (a.port == 0 || a.ip.is_any()) continue;
        if (config_.public_only && !network_utils::is_public_ip(a.ip)) continue;
        return &a;
    }
    return nullptr;
}

bool PeerExchange::should_dial(const Address& addr) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    // Drop expired entries so the set stays bounded and old failures can be retried.
    for (auto it = recent_dials_.begin(); it != recent_dials_.end();) {
        if (now - it->second > config_.dial_cooldown) it = recent_dials_.erase(it);
        else ++it;
    }
    if (recent_dials_.size() >= config_.max_recent_dials) return false;  // overloaded → back off

    auto [it, inserted] = recent_dials_.emplace(addr, now);
    return inserted;  // false ⇒ dialed within the cooldown window
}

} // namespace librats
