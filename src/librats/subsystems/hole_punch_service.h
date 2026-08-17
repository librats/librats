#pragma once

/**
 * @file hole_punch_service.h
 * @brief Capability that lets a sibling module ask for a NAT hole punch by PeerId.
 *
 * Published by HolePunch via ServiceRegistry (see service_registry.h). A discovery
 * module knows *who* it failed to reach long before it knows why — PeerExchange, for
 * instance, learns a peer's id together with an address that then refuses to dial —
 * and this is the whole contract it needs to hand that id over: no addresses, no
 * relay selection, no NAT reasoning, all of which are HolePunch's own business.
 *
 * Resolving it returns nullptr when hole punching is not enabled, which is exactly
 * what makes the fallback optional at the consumer's side:
 *
 *     if (auto* punch = ctx.services.get<HolePunchService>()) punch->punch(id);
 *
 * The provider registers during attach(), so resolve it in start() (every attach()
 * runs before any start()) rather than in your own attach(), where the provider may
 * not have been attached yet. The pointer is NON-owning and valid while the node is.
 */

#include "librats/util/rats_export.h"
#include "librats/peer/peer_id.h"

namespace librats {

struct RATS_API HolePunchService {
    virtual ~HolePunchService() = default;

    /// Try to reach `target` by punching. Non-blocking; a successful punch surfaces
    /// as an ordinary peer-connected event. @return whether a rendezvous actually
    /// started — false is routine (already connected, already punching, in cooldown,
    /// or nothing punchable to advertise) and needs no handling by the caller.
    virtual bool punch(const PeerId& target) = 0;
};

} // namespace librats
