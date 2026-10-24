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

#include "librats/util/rats_export.h"
#include "librats/core/bytes.h"
#include "librats/wire/frame.h"
#include "librats/peer/peer.h"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace librats {

class RATS_API MessageRouter {
public:
    using Handler = std::function<void(const Peer&, ByteView)>;
    /// One that is also told the message's deadline (Frame::deadline).
    using DeadlineHandler = std::function<void(const Peer&, ByteView, Deadline)>;

    /// Deterministic 16-bit channel id (FNV-1a) for a channel name.
    static uint16_t channel_id(std::string_view name);

    void on_channel(std::string_view name, Handler handler);
    /// Each type has one handler: registering one replaces the one before, of
    /// either kind.
    void on_type(MessageType type, Handler handler);
    void on_type(MessageType type, DeadlineHandler handler);

    /// Dispatch one decoded frame to its handler, if any. Returns true if handled.
    bool dispatch(const Peer& peer, const Frame& frame) const;

private:
    std::unordered_map<uint16_t, Handler>     by_channel_;
    std::unordered_map<uint16_t, std::string> channel_names_;  // for collision checks
    std::array<Handler, 256>                  by_type_{};
    std::array<DeadlineHandler, 256>          by_type_with_deadline_{};
};

} // namespace librats
