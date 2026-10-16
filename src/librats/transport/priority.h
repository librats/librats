#pragma once

/**
 * @file priority.h
 * @brief Which of a connection's queued messages leave first.
 *
 * Every transport schedules by the same classes: a StreamTransport when it picks
 * the next lane to seal (send_queue.h), a datagram connection as it fills each
 * packet (udp_connection.h). A more urgent class always goes first; lanes of one
 * class take turns.
 */

#include "librats/wire/frame.h"

#include <cstddef>
#include <cstdint>

namespace librats {

/// How urgently a lane's messages should leave, ahead of others on the same
/// connection. Lower values go first.
enum class Priority : uint8_t {
    Control     = 0,  ///< the connection's own plane (identify)
    Interactive = 1,  ///< small and latency-bound: ping, hole-punch rendezvous
    /// Live messages (SendOptions::lifetime), whatever their type: they are worth
    /// something only while they are fresh, and are dropped when they are not, so
    /// they never pile up in front of what comes after them for long.
    Live        = 2,
    Normal      = 3,  ///< everything else
    Bulk        = 4,  ///< file transfer, which would otherwise crowd the rest out
};
constexpr size_t kPriorityCount = 5;

/// The priority a reliable lane of `type` is scheduled at. A live message is
/// always Priority::Live.
constexpr Priority priority_of(MessageType type) noexcept {
    switch (type) {
        case MessageType::Control:   return Priority::Control;
        // Both measure or exploit timing — a ping queued behind a file measures the
        // file, and a punch Sync that waits misses the window it was timed for —
        // and both are a handful of bytes.
        case MessageType::Ping:
        case MessageType::Punch:     return Priority::Interactive;
        // Media frames are live messages and scheduled as such; what is left on
        // this lane is their control plane — subscriptions and, above all,
        // keyframe requests, each of which stands between a receiver and a
        // picture it can decode again. Small, rare and latency-bound.
        case MessageType::Media:     return Priority::Interactive;
        // A file is the one thing here that is all bulk. Storage stays Normal: its
        // lane carries a store's small requests as well as its snapshots, and the
        // requests must not wait out everything else that is queued.
        case MessageType::FileChunk: return Priority::Bulk;
        default:                     return Priority::Normal;
    }
}

} // namespace librats
