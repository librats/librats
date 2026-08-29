#pragma once

/**
 * @file peer.h
 * @brief A lightweight handle to a connected peer.
 *
 * Peer is a value passed to callbacks. It carries the peer's id and its route
 * (which reactor + connection). disconnect() uses the route, reaching that exact
 * connection with no directory lookup. send() goes by id instead: it has to
 * consult the directory anyway for the backpressure answer it returns, and by
 * then the peer's *current* route is the better destination — a handle can
 * outlive the link it names. info() consults the directory on demand too.
 */

#include "librats/util/rats_export.h"
#include "librats/core/bytes.h"
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_info.h"
#include "librats/peer/peer_table.h"  // PeerRoute

#include <optional>
#include <string_view>

namespace librats {

class Node;

class RATS_API Peer {
public:
    const PeerId& id() const noexcept { return id_; }

    /// Send bytes on a named application channel, to this peer over whichever
    /// connection currently serves it.
    ///
    /// @return whether that peer's queue still has room — the same answer, and the
    ///         same contract, as Node::send(): false means stop and wait for
    ///         on_peer_writable rather than keep going. A handler that replies
    ///         through this handle is the most ordinary way to write to a peer, so
    ///         it has to be able to feel backpressure like any other sender; while
    ///         this returned void it could not, and the bytes it queued were
    ///         invisible to peer_writable() into the bargain.
    bool send(std::string_view channel, ByteView payload) const;

    /// Request this peer be disconnected.
    void disconnect() const;

    /// Look up the peer's metadata in the directory (nullopt if gone).
    std::optional<PeerInfo> info() const;

private:
    friend class Node;
    Peer(PeerId id, PeerRoute route, Node& node)
        : id_(std::move(id)), route_(route), node_(&node) {}

    PeerId    id_;
    PeerRoute route_;
    Node*     node_;
};

} // namespace librats
