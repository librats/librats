#pragma once

/**
 * @file circuit_service.h
 * @brief Turning a relayed byte stream into a peer connection — the capability a
 *        relay module needs and PeerNetwork deliberately does not offer.
 *
 * A relay module speaks a protocol (who forwards what to whom) and owns the byte
 * stream that comes out of it (transport/relay_link.h). What it cannot do on its
 * own is the one remaining step: making that stream a Connection, so the ordinary
 * Noise handshake, framing, identify and peer table all run over it and the peer
 * at the far end becomes an ordinary peer. That step needs the reactor pool, which
 * a Subsystem has no business holding.
 *
 * So this is the narrow escape hatch, published by the Node in its ServiceRegistry
 * next to DialService, and resolved by whoever needs it:
 *
 *     if (auto* circuits = ctx.services.get<CircuitService>())
 *         auto route = circuits->adopt_circuit(relay_id, std::move(link),
 *                                              ConnRole::Outbound, false);
 *
 * ── One thread, chosen for you ──────────────────────────────────────────────
 * The node places the circuit on the reactor that owns the CARRIER's connection,
 * and that is the whole reason this call exists rather than a bare "adopt this
 * link somewhere". Every byte of a circuit arrives on the carrier's connection and
 * leaves through it, so putting the two on one thread means the entire relayed
 * path is handled without a lock, a queue or a hand-off — the same shared-nothing
 * property every other connection has. Any other placement would move bytes
 * between reactor threads twice per message.
 *
 * The route comes back synchronously (the ConnId is reserved before the adoption
 * is posted, exactly as Reactor::connect does), so the caller can wake and close
 * the circuit from the moment it asks for one.
 *
 * ── Or a datagram connection the relay forwards ─────────────────────────────
 * When both legs are datagram connections, a circuit needs no byte stream: the
 * two ends run a datagram connection of their own whose packets the relay passes
 * on by connection id (transport/udp_mux.h, "Relayed connections"). The last four
 * calls are that: the relay files the id with forward_datagrams, the target
 * expects the dial, the opener makes it. All of them stay on the mux's reactor,
 * which owns every datagram connection — the carriers included.
 *
 * ── What is deliberately NOT here ───────────────────────────────────────────
 * Nothing about relaying: no relay selection, no protocol, no policy about when a
 * circuit is worth opening. Those belong to the module. This interface would serve
 * any transport that arrives from outside the reactor pool.
 */

#include "librats/core/types.h"
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_table.h"   // PeerRoute
#include "librats/transport/link.h"
#include "librats/transport/relay_link.h"   // ForwardedCircuit

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>

namespace librats {

class CircuitService {
public:
    virtual ~CircuitService() = default;

    /// Adopt `link` as a connection carried by the peer `carrier`, on the reactor
    /// that owns the carrier's own connection.
    ///
    /// @param role      Outbound for a circuit we opened, Inbound for one opened to
    ///                  us. It is what the secure handshake and the peer table's
    ///                  duplicate resolution read, so it must say who asked.
    /// @param connected whether the far end is already there. An inbound circuit is
    ///                  (the opener would not have sent it otherwise); an outbound
    ///                  one is not until its acceptance arrives, and until then the
    ///                  connection waits in Connecting for a PollOut.
    /// @return the new connection's route, or nullopt when the carrier is no longer
    ///         a peer, or when an inbound circuit would push this node past its peer
    ///         limit. Nothing is started in that case and `link` is released.
    virtual std::optional<PeerRoute> adopt_circuit(const PeerId& carrier,
                                                   std::unique_ptr<Link> link,
                                                   ConnRole role, bool connected) = 0;

    /// Deliver poll-equivalent events (PollIn / PollOut / PollErr, see
    /// core/io_poller.h) to a circuit connection — the events a socket-backed link
    /// would have got from the poller. Thread-safe, and a no-op for a route that is
    /// already gone.
    virtual void wake_circuit(PeerRoute route, uint32_t events) = 0;

    /// Tear a circuit connection down. Thread-safe; a no-op for a route that is
    /// already gone.
    virtual void close_circuit(PeerRoute route, CloseReason reason) = 0;

    // — circuits whose relay forwards datagrams —
    //
    // `cid` is the dialer's (even) half of the connection id pair the relay chose.
    // Each returns nullopt / false when the carrier is not a peer reached over UDP
    // — the circuit is then ended — and otherwise reports failures that only the
    // reactor can see by ending the circuit too.

    /// Dial the far end through `carrier`, the relay. The connection is Outbound.
    virtual std::optional<PeerRoute> dial_relayed(const PeerId& carrier, uint64_t cid,
                                                  ForwardedCircuit circuit) = 0;

    /// Accept the dial that will come through `carrier`, the relay, as an Inbound
    /// connection — under the same admission gate as adopt_circuit.
    virtual std::optional<PeerRoute> expect_relayed(const PeerId& carrier, uint64_t cid,
                                                    ForwardedCircuit circuit) = 0;

    /// As the relay: forward the packets of `cid` between `dialer` and
    /// `responder`, counting their bytes into `bytes`, at most `rate` bytes a
    /// second each way with bursts of `burst` (0: no rate; how it is held is
    /// UdpMux's, "Relayed connections"). False when the two are not both
    /// datagram peers on one socket — the circuit must then be a byte stream.
    virtual bool forward_datagrams(const PeerId& dialer, const PeerId& responder, uint64_t cid,
                                   std::shared_ptr<std::atomic<uint64_t>> bytes, uint64_t rate,
                                   uint64_t burst) = 0;
    virtual void stop_forwarding(uint64_t cid) = 0;
};

} // namespace librats
