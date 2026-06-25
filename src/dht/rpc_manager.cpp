#include "dht/rpc_manager.h"
#include "dht/krpc.h"

#include <vector>

namespace librats {
namespace dht {

namespace {

// Transaction ids are 2-byte strings on the wire.
std::string txn_to_string(uint16_t t) {
    std::string s(2, '\0');
    s[0] = static_cast<char>((t >> 8) & 0xff);
    s[1] = static_cast<char>(t & 0xff);
    return s;
}

bool string_to_txn(const std::string& s, uint16_t& out) {
    if (s.size() != 2) return false;
    out = static_cast<uint16_t>((static_cast<uint8_t>(s[0]) << 8) | static_cast<uint8_t>(s[1]));
    return true;
}

} // namespace

uint16_t RpcManager::next_txn() {
    // 65536 ids is far more than we ever have outstanding; skip any still in use.
    for (int i = 0; i < 65536; ++i) {
        const uint16_t t = counter_++;
        if (pending_.find(t) == pending_.end()) return t;
    }
    return counter_++;  // unreachable in practice
}

bool RpcManager::invoke(KrpcMessage& msg, const Address& to, const ObserverPtr& obs, TimePoint now) {
    const uint16_t t = next_txn();
    msg.transaction_id = txn_to_string(t);

    const std::vector<uint8_t> data = KrpcProtocol::encode_message(msg);
    if (data.empty()) return false;

    transport_.send(to, data);
    obs->txn_ = t;
    pending_[t] = Pending{obs, to, now};
    return true;
}

void RpcManager::send_oneshot(KrpcMessage& msg, const Address& to) {
    msg.transaction_id = txn_to_string(next_txn());  // the peer may echo it; we don't track the reply
    const std::vector<uint8_t> data = KrpcProtocol::encode_message(msg);
    if (!data.empty()) transport_.send(to, data);
}

bool RpcManager::handle_response(const KrpcMessage& msg, const Address& from, TimePoint now) {
    uint16_t t;
    if (!string_to_txn(msg.transaction_id, t)) return false;

    auto it = pending_.find(t);
    if (it == pending_.end()) return false;          // unknown / already resolved
    if (it->second.endpoint != from) return false;   // anti-spoof: not from whom we queried

    const ObserverPtr obs = it->second.obs;          // keep alive across the callback
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.sent).count();
    const uint16_t rtt = elapsed < 0 ? 0 : (elapsed > 0xfffe ? uint16_t(0xfffe) : uint16_t(elapsed));
    pending_.erase(it);

    if (msg.type == KrpcMessageType::Error) obs->on_timeout(now);  // an error is a failed query
    else obs->on_response(msg, rtt, now);
    return true;
}

void RpcManager::tick(TimePoint now) {
    // Collect first (callbacks mutate pending_), and keep the observers alive while we call them.
    std::vector<ObserverPtr> shorts, fulls;
    for (auto& [t, p] : pending_) {
        const auto elapsed = now - p.sent;
        if (elapsed >= kFullTimeout)
            fulls.push_back(p.obs);
        else if (elapsed >= kShortTimeout && !p.obs->has(Observer::kShortTimeout))
            shorts.push_back(p.obs);
    }

    for (auto& o : shorts) o->on_short_timeout(now);          // keeps the pending entry
    for (auto& o : fulls) { cancel(o.get()); o->on_timeout(now); }
}

void RpcManager::cancel(Observer* obs) {
    if (!obs) return;
    auto it = pending_.find(obs->txn_);
    if (it != pending_.end() && it->second.obs.get() == obs) pending_.erase(it);
}

} // namespace dht
} // namespace librats
