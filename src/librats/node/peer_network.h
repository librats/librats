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

#include "librats/util/rats_export.h"
#include "librats/core/bytes.h"
#include "librats/wire/frame.h"   // MessageType
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_info.h"
#include "librats/core/address.h"
#include "librats/core/types.h"  // CloseReason

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace librats {

class Peer;

class RATS_API PeerNetwork {
public:
    virtual ~PeerNetwork() = default;
    using MessageHandler = std::function<void(const Peer&, ByteView)>;

    using PeerEventHandler       = std::function<void(const Peer&)>;
    /// A peer went away, and why. The reason matters as much as the event: an
    /// application dropped as a slow consumer (CloseReason::SlowConsumer) has to
    /// slow down, while one whose peer simply left should reconnect — and without
    /// the reason those look identical, so the usual answer to both is to redial
    /// and repeat whatever caused it.
    using PeerDisconnectHandler  = std::function<void(const PeerId&, CloseReason)>;
    using DialFailedHandler      = std::function<void(const Address&)>;

    virtual const PeerId&       local_id() const = 0;
    virtual uint16_t            listen_port() const = 0;     ///< our advertised listen port (shared by both transports)
    /// Which transports that port actually accepts, as a PeerTransports bitmask —
    /// the same value identify reports to peers. A subsystem that has to make the
    /// port reachable from outside (PortMappingService) needs to know which
    /// protocols to ask the router for. Default: TCP only, which is all a mock that
    /// merely moves messages has to claim.
    virtual uint8_t             transports() const { return PeerTransportTcp; }
    virtual const std::string&  protocol() const = 0;        ///< app protocol id (e.g. "librats/1.0"); namespaces discovery
    virtual void                connect(const Address& address) = 0;  ///< dial a discovered peer
    /// Send to one peer. @return whether that peer's send queue still has room;
    /// false means "stop and wait for on_peer_writable" — the message is queued
    /// either way, but continuing past this is what gets a peer dropped as a slow
    /// consumer. Also false if the peer is not connected. Wait on the event and
    /// not on a poll of the queue's state: the answer is re-derived on the reactor
    /// thread, so a caller that spins instead of yielding never lets it change.
    virtual bool                send(const PeerId& to, MessageType type, ByteView payload) = 0;
    /// Send to every connected peer. @return whether *every* one of them still
    /// has room, so a subsystem that fans out can pause on the slowest.
    virtual bool                broadcast(MessageType type, ByteView payload) = 0;
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
    /// A peer whose send queue had filled up has drained back under its mark, so
    /// sending to it may resume. The counterpart of send() returning false; a
    /// subsystem that never checks that return never needs this either. Runs on a
    /// reactor thread. Default: not offered (nothing subscribes).
    virtual void                on_peer_writable(PeerEventHandler /*handler*/) {}
    /// The same question send() answers — "has this peer room for more?" — asked
    /// without sending anything. For a subsystem that paces a long fan-out from a
    /// thread of its own (StorageManager streaming a snapshot): the event alone
    /// cannot serve it, because a queue filled *only* with bytes handed to send()
    /// that the reactor has not taken up yet never crossed anything on the
    /// connection, so nothing raises on_peer_writable when they drain. Safe to
    /// poll — it weighs those in-flight bytes too. False for an unknown peer.
    /// Default: always writable, all a mock that merely moves messages can claim.
    virtual bool                peer_writable(const PeerId& /*id*/) const { return true; }
};

struct NodeContext;  // node/node_context.h — bundles network + events + services

/// A pluggable network subsystem. Owns its own threads/sockets if it needs them;
/// reaches the rest of the node only through the NodeContext it is attached to
/// (the peer mesh via ctx.network, host events via ctx.events, sibling modules via
/// ctx.services). A subsystem is mocked in tests by faking those interfaces.
class RATS_API Subsystem {
public:
    virtual ~Subsystem() = default;
    virtual void attach(NodeContext& ctx) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
};

} // namespace librats
