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
#include "peer/peer_id.h"
#include "peer/peer_info.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace librats {

/// Where a peer's live connection lives: which reactor owns it, and its ConnId.
/// (reactor, conn) identifies a connection globally and is never reused while it
/// is alive, so it is the stable key for matching a teardown to a directory entry.
struct PeerRoute {
    uint8_t reactor = 0;
    ConnId  conn    = kInvalidConnId;

    bool operator==(const PeerRoute& o) const noexcept { return reactor == o.reactor && conn == o.conn; }
    bool operator!=(const PeerRoute& o) const noexcept { return !(*this == o); }
};

class PeerTable {
public:
    enum class AddResult {
        NewPeer,   ///< First connection to this peer — caller should fire "connected".
        Updated,   ///< Same connection re-registered; metadata refreshed only.
        Replaced,  ///< A previous connection was superseded (`close` holds its route).
        Rejected,  ///< An existing connection was kept; the new one (`close`) must close.
    };
    struct AddOutcome {
        AddResult                result = AddResult::NewPeer;
        std::optional<PeerRoute> close;  ///< Loser of a duplicate race; tear it down.
    };

    /// Register a connection for a peer, resolving duplicates deterministically.
    /// On a duplicate, connections with opposite roles are a simultaneous
    /// cross-connect: `prefer_outbound` (which BOTH peers compute identically from
    /// a symmetric rule over their ids) picks the surviving link so both converge
    /// on the same one. Same-role duplicates are reconnects, so the newcomer wins.
    /// The loser's route is returned in `close`. Write lock.
    AddOutcome add(const PeerInfo& info, PeerRoute route, bool prefer_outbound);

    /// Drop a peer, but only if its current route matches `route` — so a stale
    /// connection's teardown cannot evict a newer one that replaced it. Write lock.
    /// Returns true iff an entry was actually removed.
    bool remove(const PeerId& id, PeerRoute route);

    /// Route to a peer's live connection, if connected. Read lock.
    std::optional<PeerRoute> route(const PeerId& id) const;

    /// Merge dialable addresses into a peer's metadata, de-duplicated and bounded
    /// to kMaxAddressesPerPeer. Applies only if `route` is still the peer's live
    /// route (a stale connection's late identify cannot mutate a newer link).
    /// Returns the addresses actually added (i.e. not already known). Write lock.
    std::vector<Address> add_addresses(const PeerId& id, PeerRoute route,
                                       const std::vector<Address>& addresses);

    /// Upper bound on stored addresses per peer — caps memory and stops a peer
    /// from flooding us with bogus addresses via the identify/PEX path.
    static constexpr size_t kMaxAddressesPerPeer = 32;

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
