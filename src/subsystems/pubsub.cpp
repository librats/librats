#include "subsystems/pubsub.h"
#include "node/node_context.h"
#include "util/logger.h"

#include <algorithm>
#include <random>
#include <tuple>

namespace librats {

namespace {

// Wire ops (see the format table in pubsub.h).
enum : uint8_t {
    OP_PUBLISH     = 0,
    OP_SUBSCRIBE   = 1,
    OP_UNSUBSCRIBE = 2,
    OP_GRAFT       = 3,
    OP_PRUNE       = 4,
    OP_IHAVE       = 5,
    OP_IWANT       = 6,
};

constexpr size_t kIdSize = PeerId::kSize + 8;  // origin(32) || seqno(u64) = 40 bytes

void put_u16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
void put_u64(Bytes& b, uint64_t v) { for (int i = 7; i >= 0; --i) b.push_back((v >> (i * 8)) & 0xFF); }
void put_topic(Bytes& b, const std::string& t) {
    put_u16(b, static_cast<uint16_t>(t.size()));
    b.insert(b.end(), t.begin(), t.end());
}

/// The dedup / cache key for a message: its origin id followed by the origin's
/// per-message sequence number. Globally unique without a clock or hash.
std::string make_id(const PeerId& origin, uint64_t seqno) {
    std::string id(reinterpret_cast<const char*>(origin.bytes().data()), PeerId::kSize);
    for (int i = 7; i >= 0; --i) id.push_back(static_cast<char>((seqno >> (i * 8)) & 0xFF));
    return id;
}

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;

    uint8_t  u8()  { if (p >= end) { ok = false; return 0; } return *p++; }
    uint16_t u16() { if (end - p < 2) { ok = false; return 0; } uint16_t v = (uint16_t(p[0]) << 8) | p[1]; p += 2; return v; }
    uint64_t u64() { if (end - p < 8) { ok = false; return 0; } uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | *p++; return v; }
    ByteView bytes(size_t n) { if (size_t(end - p) < n) { ok = false; return {}; } ByteView v(p, n); p += n; return v; }
    ByteView rest() { ByteView v(p, size_t(end - p)); p = end; return v; }
    std::string str(size_t n) { ByteView v = bytes(n); return ok ? std::string(reinterpret_cast<const char*>(v.data()), v.size()) : std::string(); }
};

// Frame builders.
Bytes build_publish(const PeerId& origin, uint64_t seqno, const std::string& topic, ByteView data) {
    Bytes f;
    f.push_back(OP_PUBLISH);
    f.insert(f.end(), origin.bytes().begin(), origin.bytes().end());
    put_u64(f, seqno);
    put_topic(f, topic);
    f.insert(f.end(), data.begin(), data.end());
    return f;
}
Bytes build_ctrl(uint8_t op, const std::string& topic) {
    Bytes f;
    f.push_back(op);
    put_topic(f, topic);
    return f;
}
Bytes build_ihave(const std::string& topic, const std::vector<std::string>& ids) {
    Bytes f;
    f.push_back(OP_IHAVE);
    put_topic(f, topic);
    put_u16(f, static_cast<uint16_t>(std::min<size_t>(ids.size(), 0xFFFF)));
    for (const std::string& id : ids) { if (id.size() == kIdSize) f.insert(f.end(), id.begin(), id.end()); }
    return f;
}
Bytes build_iwant(const std::vector<std::string>& ids) {
    Bytes f;
    f.push_back(OP_IWANT);
    put_u16(f, static_cast<uint16_t>(std::min<size_t>(ids.size(), 0xFFFF)));
    for (const std::string& id : ids) { if (id.size() == kIdSize) f.insert(f.end(), id.begin(), id.end()); }
    return f;
}

} // namespace

// ── Construction ──────────────────────────────────────────────────────────────

PubSub::PubSub() : PubSub(Config{}) {}

PubSub::PubSub(Config config) : config_(config) {
    std::random_device rd;
    rng_.seed(rd());
    // Seed the sequence counter randomly so a restarted node does not reuse the
    // (origin, seqno) ids a previous instance with the same PeerId already burned.
    seqno_ = (static_cast<uint64_t>(rd()) << 32) ^ rd();
}

PubSub::~PubSub() { stop(); }

// ── Subsystem lifecycle ───────────────────────────────────────────────────────

void PubSub::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    network_->on_message(MessageType::Gossip,
                         [this](const Peer& peer, ByteView payload) { on_gossip(peer, payload); });
    network_->on_peer_connected([this](const Peer& peer) { on_new_peer(peer); });
    network_->on_peer_disconnected([this](const PeerId& id) { on_peer_gone(id); });
}

void PubSub::start() {
    if (running_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lock(mcache_mutex_);
        if (history_.empty()) history_.push_front({});  // current gossip window
    }
    heartbeat_thread_ = std::thread(&PubSub::heartbeat_loop, this);
}

void PubSub::stop() {
    if (!running_.exchange(false)) return;
    hb_cv_.notify_all();
    if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
}

// ── Local subscription API ────────────────────────────────────────────────────

void PubSub::subscribe(const std::string& topic, Handler handler) {
    bool is_new;
    CtrlList grafts, prunes;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        is_new = subscriptions_.find(topic) == subscriptions_.end();
        subscriptions_[topic] = std::move(handler);
        topics_[topic];  // ensure peering state exists
        if (is_new) maintain_mesh_locked(topic, grafts, prunes);  // graft from peers already known
    }
    if (is_new && network_) {
        broadcast_ctrl(OP_SUBSCRIBE, topic);
        for (const auto& g : grafts) send_ctrl(g.first, OP_GRAFT, g.second);
        for (const auto& p : prunes) send_ctrl(p.first, OP_PRUNE, p.second);
    }
}

void PubSub::unsubscribe(const std::string& topic) {
    std::vector<PeerId> mesh_to_prune;
    bool removed;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        removed = subscriptions_.erase(topic) > 0;
        auto it = topics_.find(topic);
        if (removed && it != topics_.end()) {
            mesh_to_prune.assign(it->second.mesh.begin(), it->second.mesh.end());
            it->second.mesh.clear();
        }
    }
    if (removed && network_) {
        broadcast_ctrl(OP_UNSUBSCRIBE, topic);
        for (const PeerId& p : mesh_to_prune) send_ctrl(p, OP_PRUNE, topic);
    }
}

void PubSub::publish(const std::string& topic, ByteView data) {
    if (!network_) return;

    const PeerId origin = network_->local_id();
    uint64_t seqno;
    std::vector<PeerId> targets;
    bool subscribed;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        seqno = seqno_++;
        subscribed = subscriptions_.count(topic) > 0;
        Topic& t = topics_[topic];
        if (subscribed) {
            targets.assign(t.mesh.begin(), t.mesh.end());  // eager push along the mesh
        } else {
            // Fanout: top up to fanout_size from known subscribers, then publish to them.
            if (static_cast<int>(t.fanout.size()) < config_.fanout_size) {
                std::vector<PeerId> cands;
                for (const PeerId& p : t.subscribers)
                    if (!t.fanout.count(p)) cands.push_back(p);
                for (const PeerId& p : random_sample(std::move(cands),
                                                     config_.fanout_size - static_cast<int>(t.fanout.size())))
                    t.fanout.insert(p);
            }
            t.last_fanout = std::chrono::steady_clock::now();
            targets.assign(t.fanout.begin(), t.fanout.end());
        }
    }

    const std::string id = make_id(origin, seqno);
    const Bytes frame = build_publish(origin, seqno, topic, data);
    mark_seen(id);                       // so an echo of our own message is dropped
    cache_message(id, topic, frame);     // keep content so we can answer IWANT
    deliver_local(origin, topic, data);  // a subscribed publisher hears itself

    for (const PeerId& t : targets) network_->send(t, MessageType::Gossip, ByteView(frame));
}

// ── Inbound dispatch ──────────────────────────────────────────────────────────

void PubSub::on_gossip(const Peer& peer, ByteView payload) {
    Reader r{payload.data(), payload.data() + payload.size()};
    const uint8_t op = r.u8();
    const PeerId& from = peer.id();

    switch (op) {
        case OP_SUBSCRIBE:
        case OP_UNSUBSCRIBE: {
            std::string topic = r.str(r.u16());
            if (r.ok && !topic.empty()) recv_subscription(from, topic, op == OP_SUBSCRIBE);
            return;
        }
        case OP_GRAFT: {
            std::string topic = r.str(r.u16());
            if (r.ok && !topic.empty()) recv_graft(from, topic);
            return;
        }
        case OP_PRUNE: {
            std::string topic = r.str(r.u16());
            if (r.ok && !topic.empty()) recv_prune(from, topic);
            return;
        }
        case OP_IHAVE: {
            std::string topic = r.str(r.u16());
            const uint16_t count = r.u16();
            std::vector<std::string> ids;
            for (uint16_t i = 0; i < count && r.ok; ++i) ids.push_back(r.str(kIdSize));
            if (r.ok && !topic.empty()) recv_ihave(from, topic, ids);
            return;
        }
        case OP_IWANT: {
            const uint16_t count = r.u16();
            std::vector<std::string> ids;
            for (uint16_t i = 0; i < count && r.ok; ++i) ids.push_back(r.str(kIdSize));
            if (r.ok) recv_iwant(from, ids);
            return;
        }
        case OP_PUBLISH: {
            ByteView origin_bytes = r.bytes(PeerId::kSize);
            const uint64_t seqno = r.u64();
            const uint16_t topic_len = r.u16();
            ByteView topic_bytes = r.bytes(topic_len);
            if (!r.ok) return;
            ByteView data = r.rest();
            auto origin = PeerId::from_bytes(origin_bytes);
            if (!origin) return;
            std::string topic(reinterpret_cast<const char*>(topic_bytes.data()), topic_bytes.size());
            recv_publish(from, payload, *origin, seqno, topic, data);
            return;
        }
        default:
            return;
    }
}

void PubSub::recv_subscription(const PeerId& from, const std::string& topic, bool subscribe) {
    CtrlList grafts, prunes;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Topic& t = topics_[topic];
        if (subscribe) {
            t.subscribers.insert(from);
            if (subscriptions_.count(topic)) maintain_mesh_locked(topic, grafts, prunes);
        } else {
            t.subscribers.erase(from);
            t.mesh.erase(from);
            t.fanout.erase(from);
        }
    }
    for (const auto& g : grafts) send_ctrl(g.first, OP_GRAFT, g.second);
    for (const auto& p : prunes) send_ctrl(p.first, OP_PRUNE, p.second);
}

void PubSub::recv_graft(const PeerId& from, const std::string& topic) {
    bool reject = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Topic& t = topics_[topic];
        if (subscriptions_.count(topic)) {
            t.subscribers.insert(from);  // a peer that grafts us is interested
            t.mesh.insert(from);
        } else {
            reject = true;  // we don't carry this topic — bounce them back out of the mesh
        }
    }
    if (reject) send_ctrl(from, OP_PRUNE, topic);
}

void PubSub::recv_prune(const PeerId& from, const std::string& topic) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = topics_.find(topic);
    if (it != topics_.end()) it->second.mesh.erase(from);
}

void PubSub::recv_publish(const PeerId& from, ByteView frame, const PeerId& origin, uint64_t seqno,
                          const std::string& topic, ByteView data) {
    const std::string id = make_id(origin, seqno);
    if (!mark_seen(id)) return;  // already processed → stop the loop

    switch (validate(origin, topic, data)) {
        case ValidationResult::Accept: break;
        case ValidationResult::Reject:
        case ValidationResult::Ignore: return;
    }

    cache_message(id, topic, frame.to_bytes());
    deliver_local(origin, topic, data);

    // Forward along our mesh for the topic (only meaningful if we subscribe), never
    // back to the peer we got it from.
    std::vector<PeerId> forward;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (subscriptions_.count(topic)) {
            auto it = topics_.find(topic);
            if (it != topics_.end())
                for (const PeerId& p : it->second.mesh)
                    if (p != from) forward.push_back(p);
        }
    }
    for (const PeerId& p : forward) network_->send(p, MessageType::Gossip, frame);
}

void PubSub::recv_ihave(const PeerId& from, const std::string& /*topic*/, const std::vector<std::string>& ids) {
    std::vector<std::string> wanted;
    {
        std::lock_guard<std::mutex> lock(mcache_mutex_);
        for (const std::string& id : ids)
            if (id.size() == kIdSize && !seen_.count(id)) wanted.push_back(id);
    }
    if (!wanted.empty()) {
        Bytes frame = build_iwant(wanted);
        network_->send(from, MessageType::Gossip, ByteView(frame));
    }
}

void PubSub::recv_iwant(const PeerId& from, const std::vector<std::string>& ids) {
    std::vector<Bytes> frames;
    {
        std::lock_guard<std::mutex> lock(mcache_mutex_);
        for (const std::string& id : ids) {
            auto it = mcache_.find(id);
            if (it != mcache_.end()) frames.push_back(it->second.frame);  // resend real content
        }
    }
    for (const Bytes& f : frames) network_->send(from, MessageType::Gossip, ByteView(f));
}

// ── Peer lifecycle ────────────────────────────────────────────────────────────

void PubSub::on_new_peer(const Peer& peer) {
    std::vector<std::string> topics;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        topics.reserve(subscriptions_.size());
        for (const auto& kv : subscriptions_) topics.push_back(kv.first);
    }
    // Announce our interests so the new peer can route to (and mesh with) us.
    for (const std::string& topic : topics) send_ctrl(peer.id(), OP_SUBSCRIBE, topic);
}

void PubSub::on_peer_gone(const PeerId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& kv : topics_) {
        kv.second.subscribers.erase(id);
        kv.second.mesh.erase(id);
        kv.second.fanout.erase(id);
    }
}

// ── Heartbeat: mesh maintenance + gossip emission ─────────────────────────────

void PubSub::heartbeat_loop() {
    while (running_.load()) {
        do_heartbeat();
        std::unique_lock<std::mutex> lock(hb_mutex_);
        hb_cv_.wait_for(lock, config_.heartbeat_interval, [this] { return !running_.load(); });
    }
}

void PubSub::do_heartbeat() {
    if (!network_) return;

    // 1. Collect the ids worth gossiping, grouped by topic, from the recent windows.
    std::unordered_map<std::string, std::vector<std::string>> gossip_by_topic;
    {
        std::lock_guard<std::mutex> lock(mcache_mutex_);
        const int windows = std::min<int>(config_.history_gossip, static_cast<int>(history_.size()));
        for (int i = 0; i < windows; ++i)
            for (const std::string& id : history_[i]) {
                auto it = mcache_.find(id);
                if (it != mcache_.end()) gossip_by_topic[it->second.topic].push_back(id);
            }
    }

    // 2. Under the topic lock: maintain each subscribed mesh and pick IHAVE targets.
    CtrlList grafts, prunes;
    std::vector<std::pair<std::string, std::vector<PeerId>>> ihave_plan;
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& kv : subscriptions_) {
            const std::string& topic = kv.first;
            maintain_mesh_locked(topic, grafts, prunes);
            Topic& t = topics_[topic];
            std::vector<PeerId> cands;
            for (const PeerId& p : t.subscribers)
                if (!t.mesh.count(p)) cands.push_back(p);
            ihave_plan.emplace_back(topic, random_sample(std::move(cands), config_.gossip_factor));
        }
        // Expire idle fanout sets for topics we no longer publish to.
        for (auto& kv : topics_) {
            Topic& t = kv.second;
            if (!subscriptions_.count(kv.first) && !t.fanout.empty() &&
                now - t.last_fanout >= config_.fanout_ttl)
                t.fanout.clear();
        }
    }

    // 3. Dispatch mesh control + per-topic IHAVE outside the lock.
    for (const auto& g : grafts) send_ctrl(g.first, OP_GRAFT, g.second);
    for (const auto& p : prunes) send_ctrl(p.first, OP_PRUNE, p.second);
    for (const auto& plan : ihave_plan) {
        auto git = gossip_by_topic.find(plan.first);
        if (git == gossip_by_topic.end() || plan.second.empty()) continue;
        Bytes frame = build_ihave(plan.first, git->second);
        for (const PeerId& p : plan.second) network_->send(p, MessageType::Gossip, ByteView(frame));
    }

    // 4. Shift the gossip history forward and evict messages that aged out.
    {
        std::lock_guard<std::mutex> lock(mcache_mutex_);
        history_.push_front({});
        while (static_cast<int>(history_.size()) > config_.history_length) {
            for (const std::string& id : history_.back()) mcache_.erase(id);
            history_.pop_back();
        }
    }
}

void PubSub::maintain_mesh_locked(const std::string& topic, CtrlList& grafts, CtrlList& prunes) {
    if (!subscriptions_.count(topic)) return;  // mesh only exists for topics we subscribe to
    Topic& t = topics_[topic];

    if (static_cast<int>(t.mesh.size()) < config_.mesh_low) {
        // Below the low watermark: graft random non-mesh subscribers up to the target.
        std::vector<PeerId> cands;
        for (const PeerId& p : t.subscribers)
            if (!t.mesh.count(p)) cands.push_back(p);
        const int need = config_.mesh_target - static_cast<int>(t.mesh.size());
        for (const PeerId& p : random_sample(std::move(cands), need)) {
            t.mesh.insert(p);
            grafts.emplace_back(p, topic);
        }
    } else if (static_cast<int>(t.mesh.size()) > config_.mesh_high) {
        // Above the high watermark: prune random mesh peers back down to the target.
        std::vector<PeerId> mesh_vec(t.mesh.begin(), t.mesh.end());
        const int excess = static_cast<int>(t.mesh.size()) - config_.mesh_target;
        for (const PeerId& p : random_sample(std::move(mesh_vec), excess)) {
            t.mesh.erase(p);
            prunes.emplace_back(p, topic);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

void PubSub::send_ctrl(const PeerId& to, uint8_t op, const std::string& topic) {
    if (!network_) return;
    Bytes frame = build_ctrl(op, topic);
    network_->send(to, MessageType::Gossip, ByteView(frame));
}

void PubSub::broadcast_ctrl(uint8_t op, const std::string& topic) {
    if (!network_) return;
    Bytes frame = build_ctrl(op, topic);
    network_->broadcast(MessageType::Gossip, ByteView(frame));
}

void PubSub::deliver_local(const PeerId& from, const std::string& topic, ByteView data) {
    Handler handler = handler_for(topic);
    if (handler) handler(from, topic, data);
}

PubSub::Handler PubSub::handler_for(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(topic);
    return it == subscriptions_.end() ? Handler{} : it->second;
}

ValidationResult PubSub::validate(const PeerId& from, const std::string& topic, ByteView data) {
    Validator v;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = validators_.find(topic);
        if (it != validators_.end()) v = it->second;
        else                         v = global_validator_;
    }
    return v ? v(from, topic, data) : ValidationResult::Accept;
}

void PubSub::set_validator(const std::string& topic, Validator validator) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (topic.empty()) global_validator_ = std::move(validator);
    else               validators_[topic] = std::move(validator);
}

bool PubSub::mark_seen(const std::string& id) {
    std::lock_guard<std::mutex> lock(mcache_mutex_);
    if (!seen_.insert(id).second) return false;
    seen_order_.push_back(id);
    if (seen_order_.size() > config_.seen_limit) {
        seen_.erase(seen_order_.front());
        seen_order_.pop_front();
    }
    return true;
}

void PubSub::cache_message(const std::string& id, const std::string& topic, const Bytes& frame) {
    std::lock_guard<std::mutex> lock(mcache_mutex_);
    if (history_.empty()) history_.push_front({});
    auto inserted = mcache_.emplace(id, CachedMessage{topic, frame});
    if (inserted.second) history_.front().push_back(id);  // remember it in the current window
}

std::vector<PeerId> PubSub::random_sample(std::vector<PeerId> in, int n) {
    if (n <= 0 || in.empty()) return {};
    if (static_cast<int>(in.size()) <= n) return in;
    std::lock_guard<std::mutex> lock(rng_mutex_);
    std::shuffle(in.begin(), in.end(), rng_);
    in.resize(n);
    return in;
}

// ── Read-only queries ─────────────────────────────────────────────────────────

bool PubSub::is_subscribed(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriptions_.count(topic) > 0;
}

std::vector<std::string> PubSub::subscribed_topics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.reserve(subscriptions_.size());
    for (const auto& kv : subscriptions_) out.push_back(kv.first);
    return out;
}

std::vector<PeerId> PubSub::peers_for_topic(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = topics_.find(topic);
    if (it == topics_.end()) return {};
    return std::vector<PeerId>(it->second.subscribers.begin(), it->second.subscribers.end());
}

std::vector<PeerId> PubSub::mesh_peers(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = topics_.find(topic);
    if (it == topics_.end()) return {};
    return std::vector<PeerId>(it->second.mesh.begin(), it->second.mesh.end());
}

} // namespace librats
