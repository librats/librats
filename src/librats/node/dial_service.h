#pragma once

/**
 * @file dial_service.h
 * @brief Dialing a specific endpoint over a specific wire — the capability a
 *        NAT-traversal module needs and the ordinary connect() cannot express.
 *
 * PeerNetwork::connect(Address) is deliberately opinionated: it hands the target to
 * the Dialer, which picks a transport, races the other one in after the fallback
 * delay, and remembers what it learned for next time (see node/dialer.h). That is
 * exactly right for "connect me to this peer" and exactly wrong for a hole punch,
 * which needs three things the race cannot give:
 *
 *   - the datagram wire and nothing else. A punch is only possible on the shared
 *     UDP socket; racing TCP alongside it spends a connect attempt on a path that
 *     a NAT will refuse by construction.
 *   - a dial that starts NOW, at a moment agreed with the peer. A punch works
 *     because two Syns cross mid-path; a fallback delay measured from our own clock
 *     has nothing to do with that instant.
 *   - a different retry shape (see DialProfile) — dense probes rather than a long
 *     patient tail, because the early Syns are *expected* to die on the peer's NAT.
 *
 * So this is the narrow escape hatch, published by the Node in its ServiceRegistry
 * and resolved by whoever needs it:
 *
 *     if (auto* dial = ctx.services.get<DialService>())
 *         dial->dial_direct(addr, TransportKind::Udp, DialProfile::punch());
 *
 * It is deliberately *not* on PeerNetwork: every subsystem sees that interface, and
 * "dial exactly this, exactly this way" is a capability one module needs rather than
 * a contract all of them should have. Everything else about the resulting connection
 * is ordinary — the same handshake, the same identify, the same duplicate resolution
 * in PeerTable if the peer dialed us back at the same moment.
 */

#include "librats/core/address.h"
#include "librats/core/types.h"

namespace librats {

class DialService {
public:
    virtual ~DialService() = default;

    /// Start exactly one dial to `addr` over `kind`, bypassing the transport race.
    /// Non-blocking; the outcome surfaces through the node's ordinary peer-connected
    /// event. Returns false when the node cannot carry that transport at all (no
    /// datagram socket, or an address family the one socket cannot reach), in which
    /// case nothing was started and no failure event will follow.
    virtual bool dial_direct(const Address& addr, TransportKind kind,
                             const DialProfile& profile) = 0;
};

} // namespace librats
