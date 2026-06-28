#include "dht/node.h"
#include "dht/announce.h"
#include "dht/bep42.h"
#include "dht/krpc.h"
#include "dht/log.h"
#include "util/network_utils.h"

#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
#include <utility>

namespace librats {
namespace dht {

namespace {

// Convert routing-table contacts to the wire form used in find_node/get_peers replies.
std::vector<KrpcNode> to_krpc(const std::vector<NodeEntry>& nodes) {
    std::vector<KrpcNode> out;
    out.reserve(nodes.size());
    for (const auto& n : nodes) out.emplace_back(n.id, n.endpoint.ip, n.endpoint.port);
    return out;
}

// A capped, comma-joined rendering of peer endpoints for a log line: show the first few
// and summarise the rest, so even a large result set stays one readable line. Only ever
// called inside a LOG_* argument, so it costs nothing when the level is filtered out.
std::string format_peers(const std::vector<Address>& peers, std::size_t max = 6) {
    std::ostringstream s;
    const std::size_t shown = std::min(peers.size(), max);
    for (std::size_t i = 0; i < shown; ++i) {
        if (i) s << ", ";
        s << peers[i].to_string();
    }
    if (peers.size() > shown) s << " (+" << (peers.size() - shown) << " more)";
    return s.str();
}

// A bare liveness ping. Owned solely by the RpcManager while in flight; on the
// outcome it just records the contact's liveness in the routing table. This is the
// "ping" half of ping-before-replace — a timeout here lets the table promote a standby.
class PingObserver : public Observer {
public:
    PingObserver(RoutingTable& table, const NodeId& id, const Address& ep)
        : Observer(id, ep), table_(table) {}

    void on_response(const KrpcMessage& msg, uint16_t rtt, TimePoint) override {
        // BEP 42: a contact whose id is derived from its IP is harder to spoof and is
        // preferred when the table has to choose who to drop.
        const bool verified = verify_node_id_for_ip(msg.response_id, endpoint_.ip);
        table_.node_seen(msg.response_id, endpoint_, rtt, verified);
    }
    void on_timeout(TimePoint) override { table_.node_failed(id_, endpoint_); }
    void on_short_timeout(TimePoint) override {}

private:
    RoutingTable& table_;
};

} // namespace

Node::Node(Transport& transport, const NodeId& self, bool ipv6)
    : transport_(transport), self_(self), ipv6_(ipv6), table_(self), rpc_(transport) {}

void Node::on_datagram(const std::vector<uint8_t>& data, const Address& from, TimePoint now) {
    now_ = now;
    if (!dos_.allow(from.ip, now)) return;  // flooding source — ignore

    auto msg = KrpcProtocol::decode_message(data);
    if (!msg) return;

    switch (msg->type) {
        case KrpcMessageType::Query:    handle_query(*msg, from, now); break;
        case KrpcMessageType::Response: handle_response(*msg, from, now); break;
        case KrpcMessageType::Error:    rpc_.handle_response(*msg, from, now); break;  // → observer timeout
    }
}

void Node::handle_query(const KrpcMessage& msg, const Address& from, TimePoint now) {
#ifdef RATS_SEARCH_FEATURES
    const bool spider = spider_mode_.load();
    // While ignoring, still take announce_peer (the whole point of a crawl) but drop the rest.
    if (spider && spider_ignore_.load() && msg.query_type != KrpcQueryType::AnnouncePeer) return;
    // Answer with a neighbour id only to IPs we've crawled, so we don't pollute organic peers.
    const bool use_neighbor = spider && spider_contacted(from.ip);
    if (spider) add_spider_node(NodeEntry(msg.sender_id, from));
#else
    const bool use_neighbor = false;
#endif

    LOG_DEBUG("dht.rpc", "<- " << KrpcProtocol::query_type_to_string(msg.query_type)
                         << " from " << from.to_string() << " (" << short_hex(msg.sender_id) << ")");

    // Organic senders join the routing table; crawled IPs are kept out of it.
    auto learn = [&](const NodeId& sender) {
        // A node that merely *queries* us hasn't proven a round-trip: the UDP source
        // address can be spoofed, so we must not trust it as a confirmed contact (which
        // we'd hand out in find_node replies and let split buckets). Record it as
        // heard_about — an unconfirmed candidate that a refresh ping must verify before
        // we route with it. We still carry the BEP 42 verdict on the (id, ip) pair as a
        // tie-breaker among candidates.
        if (!use_neighbor)
            table_.heard_about(sender, from, verify_node_id_for_ip(sender, from.ip));
    };
    auto reply_id = [&](const NodeId& anchor) -> NodeId {
#ifdef RATS_SEARCH_FEATURES
        if (use_neighbor) return neighbor_id(anchor);
#endif
        (void)anchor;
        return self_;
    };

    switch (msg.query_type) {
        case KrpcQueryType::Ping: {
            learn(msg.sender_id);
            send_message(KrpcProtocol::create_ping_response(msg.transaction_id, reply_id(msg.sender_id)), from);
            break;
        }
        case KrpcQueryType::FindNode: {
            learn(msg.sender_id);
            auto nodes = to_krpc(table_.find_closest(msg.target_id, kBucketSize));
            send_message(KrpcProtocol::create_find_node_response(msg.transaction_id, reply_id(msg.target_id), nodes), from);
            break;
        }
        case KrpcQueryType::GetPeers: {
            learn(msg.sender_id);
            const std::string token = tokens_.generate(from, msg.info_hash, now);
            const auto peers = peers_.get(msg.info_hash);
            const NodeId rid = reply_id(msg.info_hash);
            KrpcMessage reply = peers.empty()
                ? KrpcProtocol::create_get_peers_response_with_nodes(
                      msg.transaction_id, rid, to_krpc(table_.find_closest(msg.info_hash, kBucketSize)), token)
                : KrpcProtocol::create_get_peers_response(msg.transaction_id, rid, peers, token);
            send_message(reply, from);
            break;
        }
        case KrpcQueryType::AnnouncePeer: {
#ifdef RATS_SEARCH_FEATURES
            const bool skip_token = spider;  // crawl collects every announce it can
#else
            const bool skip_token = false;
#endif
            if (!skip_token && !tokens_.verify(from, msg.info_hash, msg.token, now)) {
                LOG_DEBUG("dht.rpc", "announce_peer from " << from.to_string() << " rejected: invalid token");
                send_message(KrpcProtocol::create_error(msg.transaction_id,
                                 KrpcErrorCode::ProtocolError, "Invalid token"), from);
                return;
            }
            learn(msg.sender_id);
            const uint16_t port = msg.implied_port ? from.port : msg.port;
            const Address peer(from.ip, port);
            peers_.store(msg.info_hash, peer, now);
#ifdef RATS_SEARCH_FEATURES
            if (spider && spider_announce_) spider_announce_(msg.info_hash, peer);
#endif
            send_message(KrpcProtocol::create_announce_peer_response(msg.transaction_id, reply_id(msg.info_hash)), from);
            break;
        }
    }
}

void Node::handle_response(const KrpcMessage& msg, const Address& from, TimePoint now) {
    if (!msg.external_ip.empty()) maybe_update_external_ip(msg.external_ip, from);
    // The matching observer (a lookup or a ping) feeds the routing table and drives
    // its lookup; anti-spoofing and timeouts live in the RpcManager.
    rpc_.handle_response(msg, from, now);
}

void Node::send_message(const KrpcMessage& msg, const Address& to) {
    KrpcMessage out = msg;
    // BEP 42: tell the requester the address we see them at, so they can derive a
    // compliant node id (and so we learn our own address from their replies).
    if (out.type == KrpcMessageType::Response && out.external_ip.empty()) {
        out.external_ip = to.ip;
        out.external_port = to.port;
    }
    const auto data = KrpcProtocol::encode_message(out);
    if (!data.empty()) transport_.send(to, data);
}

void Node::ping(const NodeId& id, const Address& ep, TimePoint now) {
    auto obs = std::make_shared<PingObserver>(table_, id, ep);
    KrpcMessage q = KrpcProtocol::create_ping_query("", self_);
    rpc_.invoke(q, ep, obs, now);  // the RpcManager owns obs until it resolves
}

FindPeers& Node::start_lookup(std::unique_ptr<FindPeers> lookup, TimePoint now) {
    now_ = now;  // so a synchronous completion inside start() measures a sane duration
    lookup->set_want(want());
    FindPeers& ref = *lookup;
    lookups_.push_back(std::move(lookup));
    ref.start(now);  // may complete synchronously (e.g. empty table) — reaped next tick
    return ref;
}

void Node::bootstrap(const std::vector<Address>& nodes, TimePoint now) {
    now_ = now;  // bootstrap seeds and starts its lookup without going through start_lookup
    LOG_DEBUG("dht.find", "bootstrap lookup: " << nodes.size() << " seed(s), table=" << table_.size());
    // A self-targeted get_peers lookup populates the table with our neighbourhood; on
    // completion we report how warm the table got.
    auto boot = std::make_unique<FindPeers>(table_, rpc_, self_, self_,
        FindPeers::PeersCallback{},
        [this](const std::vector<Address>&) {
            LOG_INFO("dht.find", "bootstrap complete — routing table: " << table_.size()
                                 << " node(s), " << table_.bucket_count() << " bucket(s)");
        });
    boot->set_want(want());
    for (const auto& ep : nodes) boot->add_seed(ep);
    FindPeers& ref = *boot;
    lookups_.push_back(std::move(boot));
    ref.start(now);
}

void Node::find_peers(const InfoHash& info_hash, FindPeers::PeersCallback on_peers,
                      FindPeers::DoneCallback on_done, TimePoint now) {
    LOG_DEBUG("dht.find", "find_peers " << short_hex(info_hash) << " started (table=" << table_.size() << ")");
    // Peers as they arrive — the actual endpoints, so progress is visible mid-lookup.
    auto peers = [this, info_hash, cb = std::move(on_peers)](const std::vector<Address>& fresh) {
        LOG_DEBUG("dht.find", "find_peers " << short_hex(info_hash) << ": +" << fresh.size()
                              << " peer(s): " << format_peers(fresh));
        if (cb) cb(fresh);
    };
    // The result line: total peers, how long it took, and (capped) which ones.
    auto done = [this, info_hash, start = now, cb = std::move(on_done)](const std::vector<Address>& all) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now_ - start).count();
        LOG_INFO("dht.find", "find_peers " << short_hex(info_hash) << " → " << all.size()
                             << " peer(s) in " << (ms < 0 ? 0 : ms) << "ms"
                             << (all.empty() ? "" : ": " + format_peers(all)));
        if (cb) cb(all);
    };
    start_lookup(std::make_unique<FindPeers>(table_, rpc_, self_, info_hash,
                                             std::move(peers), std::move(done)), now);
}

void Node::announce_peer(const InfoHash& info_hash, uint16_t port, bool implied_port,
                         FindPeers::DoneCallback on_done, TimePoint now) {
    LOG_DEBUG("dht.find", "announce " << short_hex(info_hash) << " on port " << port
                          << (implied_port ? " (implied)" : "") << " started (table=" << table_.size() << ")");
    auto done = [this, info_hash, start = now, cb = std::move(on_done)](const std::vector<Address>& all) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now_ - start).count();
        LOG_INFO("dht.find", "announce " << short_hex(info_hash) << " complete in "
                             << (ms < 0 ? 0 : ms) << "ms (" << all.size() << " peer(s) seen)");
        if (cb) cb(all);
    };
    start_lookup(std::make_unique<Announce>(table_, rpc_, self_, info_hash, port, implied_port,
                                            FindPeers::PeersCallback{}, std::move(done)), now);
}

void Node::cancel_lookup(const InfoHash& info_hash) {
    // Erasing a Traversal cancels its in-flight RPCs in its destructor.
    lookups_.erase(std::remove_if(lookups_.begin(), lookups_.end(),
                       [&](const std::unique_ptr<Traversal>& t) { return t->target() == info_hash; }),
                   lookups_.end());
}

bool Node::lookup_active(const InfoHash& info_hash, bool announce) const {
    for (const auto& t : lookups_)
        if (!t->finished() && t->is_announce() == announce && t->target() == info_hash) return true;
    return false;
}

std::size_t Node::lookup_count(bool announce) const {
    std::size_t n = 0;
    for (const auto& t : lookups_)
        if (!t->finished() && t->is_announce() == announce) ++n;
    return n;
}

void Node::tick(TimePoint now) {
    now_ = now;
    rpc_.tick(now);          // fire query timeouts (drives lookups + ping-before-replace)
    reap_finished();
    peers_.expire(now);      // drop announced peers older than the TTL

    // Refresh one stale contact per interval (confirms hearsay, prunes dead nodes).
    if (now - last_refresh_ >= kRefreshInterval) {
        if (auto stale = table_.next_to_refresh(now)) ping(stale->id, stale->endpoint, now);
        last_refresh_ = now;
    }

    // Periodically re-explore our own neighbourhood to keep the table fresh.
    if (now - last_self_refresh_ >= kSelfRefreshInterval && lookups_.empty() && !table_.empty()) {
        start_lookup(std::make_unique<FindPeers>(table_, rpc_, self_, self_,
                         FindPeers::PeersCallback{}, FindPeers::DoneCallback{}), now);
        last_self_refresh_ = now;
    }

    // DEBUG heartbeat: periodic activity counters plus a pretty routing-table dump, so
    // the live state is visible over time without tracing every event. describe() is only
    // built when DEBUG is actually enabled (the macro guards on the level).
    if (now - last_state_log_ >= kStateLogInterval) {
        LOG_DEBUG("dht", "activity: " << lookups_.size() << " lookup(s), "
                         << rpc_.outstanding() << " rpc in-flight, "
                         << peers_.hash_count() << " stored hash(es)");
        LOG_DEBUG("dht.route", table_.describe());
        last_state_log_ = now;
    }
}

void Node::reap_finished() {
    lookups_.erase(std::remove_if(lookups_.begin(), lookups_.end(),
                       [](const std::unique_ptr<Traversal>& t) { return t->finished(); }),
                   lookups_.end());
}

void Node::maybe_update_external_ip(const std::string& reported_ip, const Address& from) {
    if (!is_public_address(reported_ip)) return;
    if (network_utils::is_valid_ipv6(reported_ip) != ipv6_) return;  // wrong family
    if (reported_ip == external_address_) return;

    if (!ip_voters_.insert(from.ip).second) return;  // one vote per distinct responder
    const int votes = ++ip_votes_[reported_ip];
    LOG_DEBUG("dht", "external IP vote: " << reported_ip << " (" << votes << "/"
                     << kExternalIpVoteThreshold << ", from " << from.ip << ")");
    if (votes >= kExternalIpVoteThreshold) {
        ip_votes_.clear();
        ip_voters_.clear();
        set_external_ip(reported_ip);
    }
}

void Node::set_external_ip(const std::string& ip) {
    if (!is_public_address(ip)) return;
    if (network_utils::is_valid_ipv6(ip) != ipv6_) return;  // separate networks per family
    const bool changed = (ip != external_address_);
    external_address_ = ip;

    if (verify_node_id_for_ip(self_, ip)) {  // our id already matches this address
        if (changed) LOG_INFO("dht", "external address is " << ip << " (node id already BEP 42-compliant)");
        return;
    }

    std::mt19937 gen(std::random_device{}());
    NodeId new_id;
    if (!generate_node_id_from_ip(ip, new_id, gen)) return;
    self_ = new_id;
    table_.set_self(new_id);  // re-bucket everything against the new id
    LOG_INFO("dht", "external address is " << ip << ", regenerated node id "
                    << short_hex(self_) << " (BEP 42)");
}

std::vector<Address> Node::default_bootstrap_nodes() {
    // Hostnames resolve per-family at send time; dht.libtorrent.org also has an AAAA
    // record, giving IPv6 a reliable entry point.
    return {
        {"router.bittorrent.com", 6881},
        {"dht.transmissionbt.com", 6881},
        {"router.utorrent.com", 6881},
        {"dht.libtorrent.org", 25401},
        {"dht.aelitis.com", 6881},
    };
}

#ifdef RATS_SEARCH_FEATURES

namespace {
// Forwards a successful reply to a callback and ignores timeouts. Owned solely by the
// RpcManager while in flight — used by the spider crawl to feed discovered nodes back.
class CallbackObserver : public Observer {
public:
    using Fn = std::function<void(const KrpcMessage&, const Address&)>;
    CallbackObserver(const NodeId& id, const Address& ep, Fn on_reply)
        : Observer(id, ep), on_reply_(std::move(on_reply)) {}
    void on_response(const KrpcMessage& msg, uint16_t, TimePoint) override {
        if (on_reply_) on_reply_(msg, endpoint_);
    }
    void on_timeout(TimePoint) override {}
    void on_short_timeout(TimePoint) override {}

private:
    Fn on_reply_;
};
}  // namespace

NodeId Node::neighbor_id(const NodeId& target) const {
    NodeId out;
    std::copy(target.begin(), target.begin() + 10, out.begin());        // look close to the target
    std::copy(self_.begin() + 10, self_.end(), out.begin() + 10);       // but still uniquely us
    return out;
}

void Node::add_spider_node(const NodeEntry& node) {
    for (auto& n : spider_pool_)
        if (n.id == node.id) { n.endpoint = node.endpoint; return; }
    if (spider_pool_.size() < kMaxSpiderNodes) {
        spider_pool_.push_back(node);
        return;
    }
    static thread_local std::mt19937 gen(std::random_device{}());  // pool full → evict a random slot
    spider_pool_[std::uniform_int_distribution<std::size_t>(0, spider_pool_.size() - 1)(gen)] = node;
}

bool Node::spider_contacted(const std::string& ip) const {
    return spider_contacted_ips_.count(ip) > 0;
}

void Node::spider_absorb(const KrpcMessage& msg, const Address& from) {
    add_spider_node(NodeEntry(msg.response_id, from));
    for (const auto& n : msg.nodes) add_spider_node(NodeEntry(n.id, Address(n.ip, n.port)));
}

void Node::clear_spider_state() {
    spider_pool_.clear();
    spider_visited_.clear();
    spider_contacted_ips_.clear();
}

void Node::spider_walk(TimePoint now) {
    static thread_local std::mt19937 gen(std::random_device{}());

    if (spider_visited_.size() >= kMaxSpiderVisited) spider_visited_.clear();
    if (spider_contacted_ips_.size() >= kMaxSpiderContactedIps) spider_contacted_ips_.clear();

    if (spider_pool_.empty()) {
        for (const auto& n : table_.find_closest(self_, kMaxSpiderNodes, true)) {
            if (spider_pool_.size() >= kMaxSpiderNodes) break;
            spider_pool_.push_back(n);
        }
        if (spider_pool_.empty()) {
            if (now - last_spider_bootstrap_ >= std::chrono::seconds(30)) {
                last_spider_bootstrap_ = now;
                // Reuse the resolved seed set the facade gave us; only fall back to the
                // (hostname) defaults if we were never seeded.
                bootstrap(bootstrap_nodes_.empty() ? default_bootstrap_nodes() : bootstrap_nodes_, now);
            }
            return;
        }
    }

    auto pick = [&] { return std::uniform_int_distribution<std::size_t>(0, spider_pool_.size() - 1)(gen); };
    NodeEntry target = spider_pool_[pick()];
    for (int i = 0; i < 10; ++i) {
        const NodeEntry& cand = spider_pool_[pick()];
        if (spider_visited_.find(cand.id) == spider_visited_.end()) { target = cand; break; }
    }
    spider_visited_.insert(target.id);
    spider_contacted_ips_.insert(target.endpoint.ip);

    NodeId random_target;
    { std::uniform_int_distribution<int> b(0, 255); for (auto& x : random_target) x = static_cast<uint8_t>(b(gen)); }

    // find_node toward a random target, posing as a neighbour of the node we ask.
    KrpcMessage q = KrpcProtocol::create_find_node_query("", neighbor_id(target.id), random_target);
    auto obs = std::make_shared<CallbackObserver>(target.id, target.endpoint,
                   [this](const KrpcMessage& m, const Address& ep) { spider_absorb(m, ep); });
    rpc_.invoke(q, target.endpoint, obs, now);
}

#endif  // RATS_SEARCH_FEATURES

} // namespace dht
} // namespace librats
