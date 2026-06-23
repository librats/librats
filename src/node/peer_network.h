#pragma once

/**
 * @file peer_network.h
 * @brief The narrow contract a subsystem needs from the node — and nothing more.
 *
 * Subsystems (DHT, GossipSub, file transfer, …) talk to the network only through
 * PeerNetwork. They never see Node's internals, never hold a Node& or are
 * `friend`s of it — this narrow contract is what keeps the node a small core
 * instead of a god-class that every feature reaches into.
 * A subsystem is mocked in tests by implementing this one interface.
 */

#include "core/bytes.h"
#include "wire/frame.h"   // MessageType
#include "peer/peer_id.h"
#include "peer/peer_info.h"
#include "core/address.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace librats {

class Peer;

class PeerNetwork {
public:
    virtual ~PeerNetwork() = default;
    using MessageHandler = std::function<void(const Peer&, ByteView)>;

    using PeerEventHandler       = std::function<void(const Peer&)>;
    using PeerDisconnectHandler  = std::function<void(const PeerId&)>;
    using DialFailedHandler      = std::function<void(const Address&)>;

    virtual const PeerId&       local_id() const = 0;
    virtual uint16_t            listen_port() const = 0;     ///< our advertised TCP port
    virtual const std::string&  protocol() const = 0;        ///< app protocol id (e.g. "librats/1.0"); namespaces discovery
    virtual void                connect(const Address& address) = 0;  ///< dial a discovered peer
    virtual void                send(const PeerId& to, MessageType type, ByteView payload) = 0;
    virtual void                broadcast(MessageType type, ByteView payload) = 0;
    virtual std::vector<PeerId>  connected_peers() const = 0;
    virtual std::vector<PeerInfo> peers() const = 0;  ///< snapshot incl. dialable addresses
    virtual void                on(MessageType type, MessageHandler handler) = 0;

    // Lifecycle hooks. Multiple subsystems (and the application) may subscribe;
    // all run on a reactor thread. Register before start().
    virtual void                on_peer_connected(PeerEventHandler handler) = 0;
    virtual void                on_peer_disconnected(PeerDisconnectHandler handler) = 0;
    // An outbound dial WE initiated closed before it ever established (TCP connect
    // refused/timed out, or the handshake failed). Carries the address we dialed.
    // There is no on_peer_disconnected for a connection that never came up, so this
    // is the only signal a redial policy gets that an in-flight dial has resolved.
    virtual void                on_dial_failed(DialFailedHandler handler) = 0;
};

struct NodeContext;  // node/node_context.h — bundles network + events + services

/// A pluggable network subsystem. Owns its own threads/sockets if it needs them;
/// reaches the rest of the node only through the NodeContext it is attached to
/// (the peer mesh via ctx.network, host events via ctx.events, sibling modules via
/// ctx.services). A subsystem is mocked in tests by faking those interfaces.
class Subsystem {
public:
    virtual ~Subsystem() = default;
    virtual void attach(NodeContext& ctx) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
};

} // namespace librats
