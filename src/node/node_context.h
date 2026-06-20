#pragma once

/**
 * @file node_context.h
 * @brief What a subsystem receives at attach() — the node's gift to its plugins.
 *
 * Bundles the three ways a subsystem reaches the rest of the node, each a separate
 * concern so none becomes a god-object:
 *
 *   - `network`  — the peer mesh (send/broadcast/connect/on_message…). See PeerNetwork.
 *   - `events`   — fire-and-forget notifications, one→many, no return. See EventBus.
 *   - `services` — targeted synchronous calls by capability interface, one→one,
 *                  with a return value. See ServiceRegistry.
 *
 * Rule of thumb: "something happened" → events; "do X / give me Y from module Z"
 * → services; talking to peers → network. A subsystem stores only what it needs
 * (most keep just `&ctx.network`). The references stay valid for the node's life;
 * subscribe / provide during attach(), before start().
 */

#include "node/peer_network.h"
#include "core/event_bus.h"
#include "core/service_registry.h"

namespace librats {

struct NodeContext {
    PeerNetwork&     network;
    EventBus&        events;
    ServiceRegistry& services;
};

} // namespace librats
