#pragma once

/**
 * @file message_router.h
 * @brief Routes decoded inner frames to handlers.
 *
 * App frames are dispatched by their `channel`; everything else by MessageType.
 * Application channels are named; the name is hashed to a stable 16-bit id with
 * a deterministic function so the SAME name maps to the SAME id on every node
 * (no shared registry needed). Distinct names can in principle collide in the
 * 16-bit space — on_channel() logs if a new name collides with a registered one.
 */

#include "core/bytes.h"
#include "wire/frame.h"
#include "peer/peer.h"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace librats {

class MessageRouter {
public:
    using Handler = std::function<void(const Peer&, ByteView)>;

    /// Deterministic 16-bit channel id (FNV-1a) for a channel name.
    static uint16_t channel_id(std::string_view name);

    void on_channel(std::string_view name, Handler handler);
    void on_type(MessageType type, Handler handler);

    /// Dispatch one decoded frame to its handler, if any. Returns true if handled.
    bool dispatch(const Peer& peer, const Frame& frame) const;

private:
    std::unordered_map<uint16_t, Handler>     by_channel_;
    std::unordered_map<uint16_t, std::string> channel_names_;  // for collision checks
    std::array<Handler, 256>                  by_type_{};
};

} // namespace librats
