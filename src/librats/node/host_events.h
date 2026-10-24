#pragma once

/**
 * @file host_events.h
 * @brief Node-level event types published on the EventBus.
 *
 * These describe things that happen to the *host* the node runs on (as opposed to
 * the peer mesh), which several subsystems may want to react to independently.
 * They are plain value types; a subsystem subscribes via `ctx.events.on<...>()`.
 */

#include "librats/nat/port_mapping.h"

#include <cstdint>
#include <string>
#include <vector>

namespace librats {

/// The set of local interface addresses changed — an interface came up/down, an
/// IP was added/removed, the default route flipped (Wi-Fi↔cellular, VPN, dock,
/// wake-from-sleep). Long-lived nodes react by renewing port mappings and
/// re-discovering/re-announcing their public endpoint, which would otherwise go
/// stale. Emitted (debounced) by the Node's NetworkMonitor.
struct NetworkChanged {
    std::vector<std::string> local_addresses;  ///< new, full list of local IPs
};

/// The router forwards a public port to the node's listen port (UPnP / NAT-PMP):
/// what a peer outside is to dial over `protocol`. Emitted by PortMappingService
/// each time a mapping with a genuinely public address comes up or is renewed,
/// from a backend's worker thread; one discovery announces it (DhtDiscovery).
/// After NetworkChanged a mapping is told again only once it is renewed.
struct PortMapped {
    PortMapProtocol protocol = PortMapProtocol::UDP;
    std::string     external_ip;
    uint16_t        external_port = 0;
};

} // namespace librats
