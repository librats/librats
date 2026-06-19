#pragma once

/**
 * @file peer_directory.h
 * @brief Control-plane registry: PeerId → route + metadata.
 *
 * This is the only shared peer structure in the redesign, and it is deliberately
 * **off the per-byte data path**: it is touched on connect/disconnect and on
 * explicit by-id lookups (send-by-id, peers()), never per inbound/outbound frame
 * (those use the route carried in the Connection/Peer handle). It is therefore
 * read-mostly and guarded by a shared_mutex with short critical sections — a
 * world away from the old global peers_mutex_ held across recv/send.
 */

#include "core/types.h"   // ConnId
#include "net/peer_id.h"
#include "net/peer_info.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace librats {

/// Where a peer's live connection lives: which reactor owns it, and its ConnId.
struct PeerRoute {
    uint8_t reactor = 0;
    ConnId  conn    = kInvalidConnId;
};

class PeerDirectory {
public:
    /// Register (or replace) a peer and its route. Write lock.
    void add(const PeerInfo& info, PeerRoute route);

    /// Drop a peer. Write lock. No-op if absent.
    void remove(const PeerId& id);

    /// Route to a peer's live connection, if connected. Read lock.
    std::optional<PeerRoute> route(const PeerId& id) const;

    /// Metadata snapshot for a peer. Read lock.
    std::optional<PeerInfo> info(const PeerId& id) const;

    bool contains(const PeerId& id) const;

    /// Snapshot of all known peers (for the public API / persistence). Read lock.
    std::vector<PeerInfo> snapshot() const;

    size_t size() const noexcept { return count_.load(std::memory_order_relaxed); }

private:
    struct Entry {
        PeerInfo  info;
        PeerRoute route;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<PeerId, Entry, PeerId::Hash> peers_;
    std::atomic<size_t> count_{0};
};

} // namespace librats
