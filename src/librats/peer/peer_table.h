#pragma once

/**
 * @file peer_table.h
 * @brief Control-plane registry: PeerId → route + metadata.
 *
 * This is the only shared peer structure in the redesign, and it is deliberately
 * **off the per-byte data path**: it is touched on connect/disconnect and on
 * explicit by-id lookups (send-by-id, peers()), never per inbound/outbound frame
 * (those use the route carried in the Connection/Peer handle). It is therefore
 * read-mostly and guarded by a shared_mutex with short critical sections — a
 * world away from the old global peers_mutex_ held across recv/send.
 */

#include "librats/util/rats_export.h"
#include "librats/core/types.h"   // ConnId
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_info.h"

#include <atomic>
#include <cstdint>
#include <memory>
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

class RATS_API PeerTable {
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

    /// Record which transports a peer advertised in its identify message. Applies
    /// only while `route` is still the peer's live route. Write lock.
    void set_supported_transports(const PeerId& id, PeerRoute route, uint8_t mask);

    /// A peer's live route together with whether its send queue has room, in one
    /// lookup — the send path needs both and should not pay for two.
    struct Destination {
        PeerRoute route;
        bool      writable = true;
        /// The peer's in-transit counter (see Entry::owed). Shared, not copied,
        /// so the caller charges the same counter the reactor task discharges.
        std::shared_ptr<std::atomic<size_t>> owed;
    };
    std::optional<Destination> destination(const PeerId& id) const;

    /// Whether every connected peer's send queue has room — what broadcast()
    /// answers, since "may I send more?" to a fan-out is only usefully answered
    /// by its slowest recipient.
    bool all_writable() const;

    /// Record that a peer's send queue filled up or drained. Applies only while
    /// `route` is still the peer's live route. Write lock, but only ever taken
    /// when the mark is actually crossed, which is rare.
    void set_writable(const PeerId& id, PeerRoute route, bool writable);

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
        /// Whether this peer's send queue has room. Maintained by the reactor as
        /// the queue crosses its low-water mark, read by send() so a caller on
        /// any thread gets an answer without having to reach into a connection it
        /// does not own. Advisory by nature — it is a snapshot of a queue that is
        /// draining as it is read, which is exactly what a backpressure hint is.
        bool      writable = true;
        /// Bytes handed to the owning reactor by send() that it has not taken up
        /// yet. The queue itself lives on the reactor thread and `writable` above
        /// only ever reports what the reactor has already seen — so a caller in a
        /// tight loop could hand over megabytes before a single one of them was
        /// counted. This is that backlog, incremented by the caller and decremented
        /// by the reactor task, so the answer covers both halves.
        std::shared_ptr<std::atomic<size_t>> owed =
            std::make_shared<std::atomic<size_t>>(0);
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<PeerId, Entry, PeerId::Hash> peers_;
    std::atomic<size_t> count_{0};
};

} // namespace librats
