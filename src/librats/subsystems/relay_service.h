#pragma once

/**
 * @file relay_service.h
 * @brief Capability that lets a sibling module ask for a peer to be reached
 *        through a third node, by PeerId.
 *
 * Published by Relay via ServiceRegistry (see service_registry.h). It is the last
 * rung of the connectivity ladder — a direct dial, then a hole punch, then this —
 * and the module that gives up on the rung above should not have to know anything
 * about how the rung below works. HolePunch, for instance, learns that a target is
 * unreachable (a symmetric NAT it declined to punch, or a rendezvous that ran out
 * of attempts) and this is the whole contract it needs to hand the id on: no relay
 * selection, no circuits, no policy, all of which are Relay's own business.
 *
 * Resolving it returns nullptr when relaying is not enabled, which is exactly what
 * makes the fallback optional at the consumer's side:
 *
 *     if (auto* relay = ctx.services.get<RelayService>()) relay->connect_via_relay(id);
 *
 * The provider registers during attach(), so resolve it in start() (every attach()
 * runs before any start()) rather than in your own attach(), where the provider may
 * not have been attached yet. The pointer is NON-owning and valid while the node is.
 */

#include "librats/util/rats_export.h"
#include "librats/peer/peer_id.h"

namespace librats {

struct RATS_API RelayService {
    virtual ~RelayService() = default;

    /// Try to reach `target` through a node both ends are connected to.
    /// Non-blocking; success surfaces as an ordinary peer-connected event, and the
    /// resulting peer is ordinary in every way except that its bytes take a detour
    /// (PeerInfo::transport is TransportKind::Relay).
    ///
    /// @return whether an attempt actually started — false is routine (already
    ///         connected, an attempt is already running, the target is in cooldown,
    ///         or this node has no peer that could carry the circuit) and needs no
    ///         handling by the caller.
    virtual bool connect_via_relay(const PeerId& target) = 0;
};

} // namespace librats
