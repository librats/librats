#pragma once

/**
 * @file port_mapping.h
 * @brief Shared types for automatic NAT port forwarding (UPnP IGD + NAT-PMP)
 *
 * Both the UPnP (@ref UpnpClient) and NAT-PMP (@ref NatPmpClient) backends ask a
 * home router to forward an external (WAN) port to a local (LAN) port so that
 * inbound peer connections can reach a host behind NAT. They share the small set
 * of vocabulary types defined here: the transport protocol of the mapping, which
 * backend produced a result, and the result/callback shape RatsClient consumes.
 */

#include <cstdint>
#include <string>
#include <functional>

namespace librats {

/// Transport protocol of a port mapping.
enum class PortMapProtocol : uint8_t {
    TCP,
    UDP
};

/// Which NAT traversal backend produced a result.
enum class PortMapTransport : uint8_t {
    UPnP,
    NatPMP
};

/// Human readable protocol name ("TCP"/"UDP").
inline const char* to_string(PortMapProtocol p) {
    return p == PortMapProtocol::TCP ? "TCP" : "UDP";
}

/// Human readable transport name ("UPnP"/"NAT-PMP").
inline const char* to_string(PortMapTransport t) {
    return t == PortMapTransport::UPnP ? "UPnP" : "NAT-PMP";
}

/**
 * Result of a port mapping attempt.
 *
 * On success @ref external_port holds the public port the router assigned (which
 * may differ from the requested one) and, when the backend can report it,
 * @ref external_ip holds the discovered public IP address.
 */
struct PortMapResult {
    PortMapTransport transport;          ///< Backend that produced this result
    PortMapProtocol  protocol;           ///< Protocol of the mapping
    bool             success = false;    ///< Whether the mapping is currently active
    uint16_t         internal_port = 0;  ///< Local (LAN) port that was mapped
    uint16_t         external_port = 0;  ///< Public (WAN) port assigned by the router
    std::string      external_ip;        ///< Discovered public IP (may be empty)
    std::string      error;              ///< Human readable error when !success
};

/**
 * Callback invoked whenever a mapping is established, refreshed, removed or fails.
 * Always called from the backend's own worker thread.
 */
using PortMapCallback = std::function<void(const PortMapResult&)>;

/**
 * Configuration for RatsClient's automatic port forwarding.
 *
 * Both backends run in parallel by default; whichever the router supports
 * succeeds. Disabling one (or all) of them is a matter of flipping a flag.
 */
struct PortMappingConfig {
    bool enabled = true;                  ///< Master switch for automatic port forwarding
    bool enable_upnp = true;              ///< Use the UPnP IGD backend
    bool enable_natpmp = true;            ///< Use the NAT-PMP backend
    uint32_t lease_duration_seconds = 3600; ///< Requested lease duration
};

} // namespace librats
