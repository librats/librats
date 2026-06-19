#pragma once

/**
 * @file peer_network.h
 * @brief The narrow contract a subsystem needs from the node — and nothing more.
 *
 * Subsystems (DHT, GossipSub, file transfer, …) talk to the network only through
 * PeerNetwork. They never see Node's internals, never hold a Node& or are
 * `friend`s of it — which is exactly what made the old RatsClient a god-class.
 * A subsystem is mocked in tests by implementing this one interface.
 */

#include "core/bytes.h"
#include "net/frame.h"   // MessageType
#include "net/peer_id.h"

#include <functional>
#include <vector>

namespace librats {

class PeerHandle;

class PeerNetwork {
public:
    virtual ~PeerNetwork() = default;
    using MessageHandler = std::function<void(const PeerHandle&, ByteView)>;

    virtual const PeerId&       local_id() const = 0;
    virtual void                send(const PeerId& to, MessageType type, ByteView payload) = 0;
    virtual void                broadcast(MessageType type, ByteView payload) = 0;
    virtual std::vector<PeerId>  connected_peers() const = 0;
    virtual void                on_message(MessageType type, MessageHandler handler) = 0;
};

/// A pluggable network subsystem. Owns its own threads/sockets if it needs them;
/// reaches the peer mesh only through the PeerNetwork it is attached to.
class Subsystem {
public:
    virtual ~Subsystem() = default;
    virtual void attach(PeerNetwork& network) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
};

} // namespace librats
