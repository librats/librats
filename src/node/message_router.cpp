#include "node/message_router.h"
#include "logger.h"

namespace librats {

uint16_t MessageRouter::channel_id(std::string_view name) {
    // FNV-1a (32-bit) folded to 16 bits — deterministic across nodes/runs.
    uint32_t hash = 2166136261u;
    for (char c : name) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    const uint16_t id = static_cast<uint16_t>((hash >> 16) ^ (hash & 0xFFFF));
    return id == 0 ? 1 : id;  // reserve 0 for "no channel"
}

void MessageRouter::on_channel(std::string_view name, Handler handler) {
    const uint16_t id = channel_id(name);
    auto existing = channel_names_.find(id);
    if (existing != channel_names_.end() && existing->second != name) {
        LOG_WARN("router", "Channel id collision: '" << name << "' and '"
                 << existing->second << "' both hash to " << id);
    }
    channel_names_[id] = std::string(name);
    by_channel_[id] = std::move(handler);
}

void MessageRouter::on_type(MessageType type, Handler handler) {
    by_type_[static_cast<uint8_t>(type)] = std::move(handler);
}

bool MessageRouter::dispatch(const PeerHandle& peer, const Frame& frame) const {
    if (frame.header.type == MessageType::App) {
        auto it = by_channel_.find(frame.header.channel);
        if (it == by_channel_.end()) return false;
        it->second(peer, frame.payload);
        return true;
    }
    const auto& handler = by_type_[static_cast<uint8_t>(frame.header.type)];
    if (!handler) return false;
    handler(peer, frame.payload);
    return true;
}

} // namespace librats
