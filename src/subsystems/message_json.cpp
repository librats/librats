#include "subsystems/message_json.h"
#include "node/node_context.h"
#include "util/logger.h"

#include <algorithm>

namespace librats {

void MessageJson::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    network_->on(MessageType::Typed,
        [this](const Peer& peer, ByteView payload) { on_typed(peer.id(), payload); });
}

// ── Registration ────────────────────────────────────────────────────────────

void MessageJson::on(const std::string& type, Handler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_[type].push_back({std::move(handler), /*once=*/false});
}

void MessageJson::once(const std::string& type, Handler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_[type].push_back({std::move(handler), /*once=*/true});
}

void MessageJson::off(const std::string& type) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_.erase(type);
}

// ── Sending ─────────────────────────────────────────────────────────────────

Bytes MessageJson::encode(const std::string& type, const nlohmann::json& data) {
    const std::string body = data.dump();
    Bytes out;
    out.reserve(2 + type.size() + body.size());
    out.push_back(static_cast<uint8_t>((type.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(type.size() & 0xFF));
    out.insert(out.end(), type.begin(), type.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

void MessageJson::send(const std::string& type, const nlohmann::json& data, SendCallback cb) {
    if (!network_) { if (cb) cb(false, "not attached to a network"); return; }

    const Bytes payload = encode(type, data);
    const size_t n = network_->connected_peers().size();
    network_->broadcast(MessageType::Typed, ByteView(payload));
    if (cb) cb(n > 0, n > 0 ? "" : "no connected peers");
}

void MessageJson::send(const PeerId& to, const std::string& type, const nlohmann::json& data,
                       SendCallback cb) {
    if (!network_) { if (cb) cb(false, "not attached to a network"); return; }

    // A send() to an unknown peer is a safe no-op, so only pay for the directory
    // lookup when the caller actually wants a delivery verdict.
    if (cb) {
        const auto peers = network_->connected_peers();
        if (std::find(peers.begin(), peers.end(), to) == peers.end()) {
            cb(false, "peer not connected");
            return;
        }
    }
    network_->send(to, MessageType::Typed, ByteView(encode(type, data)));
    if (cb) cb(true, "");
}

// ── Receiving (reactor thread) ──────────────────────────────────────────────

void MessageJson::on_typed(const PeerId& from, ByteView payload) {
    const uint8_t* p = payload.data();
    const size_t   n = payload.size();
    if (n < 2) return;

    const size_t type_len = (static_cast<size_t>(p[0]) << 8) | p[1];
    if (2 + type_len > n) return;

    std::string type(reinterpret_cast<const char*>(p + 2), type_len);
    nlohmann::json data = nlohmann::json::parse(p + 2 + type_len, p + n, nullptr, /*allow_exceptions=*/false);
    if (data.is_discarded()) {
        LOG_WARN("msgex", "Malformed JSON for type '" << type << "' from " << from.short_hex());
        return;
    }

    // Snapshot the handlers under the lock and drop the one-shot ones, then invoke
    // outside the lock so a handler may freely (un)register without deadlocking.
    std::vector<Entry> to_call;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = handlers_.find(type);
        if (it == handlers_.end()) return;
        to_call = it->second;
        auto& vec = it->second;
        vec.erase(std::remove_if(vec.begin(), vec.end(), [](const Entry& e) { return e.once; }), vec.end());
        if (vec.empty()) handlers_.erase(it);
    }

    for (const Entry& e : to_call) {
        try {
            e.handler(from, data);
        } catch (const std::exception& ex) {
            LOG_ERROR("msgex", "Handler for '" << type << "' threw: " << ex.what());
        } catch (...) {
            LOG_ERROR("msgex", "Handler for '" << type << "' threw an unknown exception");
        }
    }
}

} // namespace librats
