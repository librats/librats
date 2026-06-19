#pragma once

/**
 * @file peer.h
 * @brief A lightweight handle to a connected peer.
 *
 * PeerHandle is a value passed to callbacks. It carries the peer's id and its
 * route (which reactor + connection), so send()/disconnect() reach the right
 * reactor directly — no PeerDirectory lookup on the reply path. info() does
 * consult the directory, on demand, for metadata.
 *
 * (Named PeerHandle rather than Peer for historical reasons; the legacy `Peer`
 * UDP-endpoint struct has been removed in favour of the unified Address type.)
 */

#include "core/bytes.h"
#include "net/peer_id.h"
#include "net/peer_info.h"
#include "net/peer_directory.h"  // PeerRoute

#include <optional>
#include <string_view>

namespace librats {

class Node;

class PeerHandle {
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
    PeerHandle(PeerId id, PeerRoute route, Node& node)
        : id_(std::move(id)), route_(route), node_(&node) {}

    PeerId    id_;
    PeerRoute route_;
    Node*     node_;
};

} // namespace librats
