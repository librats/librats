#include "subsystems/pubsub.h"

#include <cstring>

namespace librats {

namespace {

enum : uint8_t { OP_PUBLISH = 0, OP_SUBSCRIBE = 1, OP_UNSUBSCRIBE = 2 };

void put_u16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
void put_u64(Bytes& b, uint64_t v) { for (int i = 7; i >= 0; --i) b.push_back((v >> (i * 8)) & 0xFF); }

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;

    uint8_t u8() {
        if (p >= end) { ok = false; return 0; }
        return *p++;
    }
    uint16_t u16() {
        if (end - p < 2) { ok = false; return 0; }
        uint16_t v = (uint16_t(p[0]) << 8) | p[1]; p += 2; return v;
    }
    uint64_t u64() {
        if (end - p < 8) { ok = false; return 0; }
        uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | *p++; return v;
    }
    ByteView bytes(size_t n) {
        if (size_t(end - p) < n) { ok = false; return {}; }
        ByteView v(p, n); p += n; return v;
    }
    ByteView rest() { ByteView v(p, size_t(end - p)); p = end; return v; }
};

std::string dedup_key(const PeerId& origin, uint64_t seqno) {
    std::string key(reinterpret_cast<const char*>(origin.bytes().data()), PeerId::kSize);
    for (int i = 7; i >= 0; --i) key.push_back(static_cast<char>((seqno >> (i * 8)) & 0xFF));
    return key;
}

} // namespace

void PubSub::attach(PeerNetwork& network) {
    network_ = &network;
    network_->on_message(MessageType::Gossip,
                         [this](const PeerHandle& peer, ByteView payload) { on_gossip(peer, payload); });
    network_->on_peer_connected([this](const PeerHandle& peer) { on_new_peer(peer); });
    network_->on_peer_disconnected([this](const PeerId& id) { on_peer_gone(id); });
}

// ── Local subscription API ──────────────────────────────────────────────────

void PubSub::subscribe(const std::string& topic, Handler handler) {
    bool is_new;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        is_new = subscriptions_.find(topic) == subscriptions_.end();
        subscriptions_[topic] = std::move(handler);
    }
    if (is_new && network_) {
        Bytes msg;
        msg.push_back(OP_SUBSCRIBE);
        put_u16(msg, static_cast<uint16_t>(topic.size()));
        msg.insert(msg.end(), topic.begin(), topic.end());
        network_->broadcast(MessageType::Gossip, ByteView(msg));
    }
}

void PubSub::unsubscribe(const std::string& topic) {
    bool removed;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        removed = subscriptions_.erase(topic) > 0;
    }
    if (removed && network_) {
        Bytes msg;
        msg.push_back(OP_UNSUBSCRIBE);
        put_u16(msg, static_cast<uint16_t>(topic.size()));
        msg.insert(msg.end(), topic.begin(), topic.end());
        network_->broadcast(MessageType::Gossip, ByteView(msg));
    }
}

void PubSub::publish(const std::string& topic, ByteView data) {
    if (!network_) return;

    const PeerId origin = network_->local_id();
    uint64_t seqno;
    std::vector<PeerId> targets;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        seqno = seqno_++;
        for (const auto& [peer, topics] : remote_subs_)
            if (topics.count(topic)) targets.push_back(peer);
    }

    mark_seen(dedup_key(origin, seqno));  // so an echo of our own message is dropped

    // Build the PUBLISH frame.
    Bytes msg;
    msg.push_back(OP_PUBLISH);
    msg.insert(msg.end(), origin.bytes().begin(), origin.bytes().end());
    put_u64(msg, seqno);
    put_u16(msg, static_cast<uint16_t>(topic.size()));
    msg.insert(msg.end(), topic.begin(), topic.end());
    msg.insert(msg.end(), data.begin(), data.end());

    deliver_local(origin, topic, data);
    for (const PeerId& t : targets) network_->send(t, MessageType::Gossip, ByteView(msg));
}

// ── Inbound ─────────────────────────────────────────────────────────────────

void PubSub::on_gossip(const PeerHandle& peer, ByteView payload) {
    Reader r{payload.data(), payload.data() + payload.size()};
    const uint8_t op = r.u8();

    if (op == OP_SUBSCRIBE || op == OP_UNSUBSCRIBE) {
        const uint16_t len = r.u16();
        ByteView t = r.bytes(len);
        if (!r.ok) return;
        std::string topic(reinterpret_cast<const char*>(t.data()), t.size());
        std::lock_guard<std::mutex> lock(mutex_);
        if (op == OP_SUBSCRIBE) remote_subs_[peer.id()].insert(topic);
        else                    remote_subs_[peer.id()].erase(topic);
        return;
    }

    if (op != OP_PUBLISH) return;

    ByteView origin_bytes = r.bytes(PeerId::kSize);
    const uint64_t seqno = r.u64();
    const uint16_t topic_len = r.u16();
    ByteView topic_bytes = r.bytes(topic_len);
    if (!r.ok) return;
    ByteView data = r.rest();

    auto origin = PeerId::from_bytes(origin_bytes);
    if (!origin) return;
    const std::string topic(reinterpret_cast<const char*>(topic_bytes.data()), topic_bytes.size());

    if (!mark_seen(dedup_key(*origin, seqno))) return;  // already seen → stop the loop

    deliver_local(*origin, topic, data);

    // Forward to other interested peers (not back to the sender).
    std::vector<PeerId> targets;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [p, topics] : remote_subs_)
            if (p != peer.id() && topics.count(topic)) targets.push_back(p);
    }
    for (const PeerId& t : targets) network_->send(t, MessageType::Gossip, payload);
}

// ── Peer lifecycle ──────────────────────────────────────────────────────────

void PubSub::on_new_peer(const PeerHandle& peer) {
    std::vector<std::string> topics;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        topics.reserve(subscriptions_.size());
        for (const auto& [topic, _] : subscriptions_) topics.push_back(topic);
    }
    for (const std::string& topic : topics) send_subscription(peer.id(), topic, /*subscribe=*/true);
}

void PubSub::on_peer_gone(const PeerId& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    remote_subs_.erase(id);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

void PubSub::send_subscription(const PeerId& to, const std::string& topic, bool subscribe) {
    Bytes msg;
    msg.push_back(subscribe ? OP_SUBSCRIBE : OP_UNSUBSCRIBE);
    put_u16(msg, static_cast<uint16_t>(topic.size()));
    msg.insert(msg.end(), topic.begin(), topic.end());
    network_->send(to, MessageType::Gossip, ByteView(msg));
}

void PubSub::deliver_local(const PeerId& from, const std::string& topic, ByteView data) {
    Handler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = subscriptions_.find(topic);
        if (it == subscriptions_.end()) return;
        handler = it->second;
    }
    handler(from, topic, data);
}

bool PubSub::mark_seen(const std::string& key) {
    std::lock_guard<std::mutex> lock(seen_mutex_);
    if (!seen_set_.insert(key).second) return false;
    seen_order_.push_back(key);
    if (seen_order_.size() > kSeenLimit) {
        seen_set_.erase(seen_order_.front());
        seen_order_.pop_front();
    }
    return true;
}

std::vector<std::string> PubSub::subscribed_topics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.reserve(subscriptions_.size());
    for (const auto& [topic, _] : subscriptions_) out.push_back(topic);
    return out;
}

std::vector<PeerId> PubSub::peers_for_topic(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerId> out;
    for (const auto& [peer, topics] : remote_subs_)
        if (topics.count(topic)) out.push_back(peer);
    return out;
}

} // namespace librats
