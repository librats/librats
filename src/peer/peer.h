#pragma once

/**
 * @file peer.h
 * @brief A lightweight handle to a connected peer.
 *
 * Peer is a value passed to callbacks. It carries the peer's id and its
 * route (which reactor + connection), so send()/disconnect() reach the right
 * reactor directly — no PeerTable lookup on the reply path. info() does
 * consult the directory, on demand, for metadata.
 */

#include "core/bytes.h"
#include "peer/peer_id.h"
#include "peer/peer_info.h"
#include "peer/peer_table.h"  // PeerRoute

#include <optional>
#include <string_view>

namespace librats {

class Node;

class Peer {
public:
    const PeerId& id() const noexcept { return id_; }

    /// Send bytes on a named application channel.
    void send(std::string_view channel, ByteView payload) const;

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
