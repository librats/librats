#pragma once

/**
 * @file host_events.h
 * @brief Node-level event types published on the EventBus.
 *
 * These describe things that happen to the *host* the node runs on (as opposed to
 * the peer mesh), which several subsystems may want to react to independently.
 * They are plain value types; a subsystem subscribes via `ctx.events.on<...>()`.
 */

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

} // namespace librats
