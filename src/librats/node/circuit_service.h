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
 * ── What is deliberately NOT here ───────────────────────────────────────────
 * Nothing about relaying: no relay selection, no protocol, no policy about when a
 * circuit is worth opening. Those belong to the module. This interface would serve
 * any transport that arrives from outside the reactor pool.
 */

#include "librats/core/types.h"
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_table.h"   // PeerRoute
#include "librats/transport/link.h"

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
};

} // namespace librats
