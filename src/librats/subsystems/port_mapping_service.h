#pragma once

/**
 * @file port_mapping_service.h
 * @brief Automatic NAT port forwarding (UPnP IGD + NAT-PMP) as a Subsystem.
 *
 * Wraps the standalone UpnpClient (src/upnp.h) and NatPmpClient (src/natpmp.h)
 * backends into the Node lifecycle. On start() it asks the home router to forward
 * the node's listen port so peers behind NAT can accept inbound connections; on
 * stop() it removes the mappings. Both backends run in parallel on their own worker
 * threads — whichever the router supports wins.
 *
 * The port is forwarded under EVERY protocol the node is actually listening on
 * (PeerNetwork::transports()), not just TCP. Both transports share one listen port
 * by design, and UDP is the dialer's first choice — a TCP-only mapping leaves an
 * inbound peer able to reach us solely over the TCP fallback. It is also the UDP
 * mapping that a hole punch benefits from: a static, port-preserving mapping is
 * what turns the NAT in front of the shared datagram socket into the
 * endpoint-independent kind HolePunch is willing to fire at (see nat_status.h).
 *
 * Threading: the backends invoke our result callback from their own worker
 * threads, so all shared state is guarded by mutex_. stop() moves the clients out
 * under the lock and stops them OUTSIDE it — stop() joins those workers, which
 * take the lock from handle_result(), so holding it across stop() would deadlock.
 */

#include "librats/util/rats_export.h"
#include "librats/node/peer_network.h"
#include "librats/nat/port_mapping.h"   // PortMappingConfig, PortMapResult, PortMapCallback

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace librats {

class UpnpClient;
class NatPmpClient;

/// Maps the node's TCP listen port through the home router via UPnP and/or
/// NAT-PMP. Owns its backends' worker threads; reaches the node only for its
/// listen port (it neither sends nor receives peer traffic).
class RATS_API PortMappingService final : public Subsystem {
public:
    explicit PortMappingService(PortMappingConfig config = {});
    ~PortMappingService() override;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    /// Observe mapping results (established / refreshed / failed). Optional;
    /// invoked from a backend worker thread. Register before start().
    void on_result(PortMapCallback cb) { user_callback_ = std::move(cb); }

    /// The public endpoint peers should reach us on over @p protocol, once a
    /// backend reports a usable (genuinely public) external IP + port for it.
    /// nullopt until then. The two protocols are mapped independently and a router
    /// may accept one and refuse the other, so ask for the one you intend to dial.
    std::optional<std::pair<std::string, uint16_t>> mapped_public_address(
        PortMapProtocol protocol = PortMapProtocol::TCP) const;

private:
    void handle_result(const PortMapResult& result);
    /// The recorded external port for @p protocol. Call under mutex_.
    uint16_t& external_port_slot(PortMapProtocol protocol);

    PortMappingConfig config_;
    PeerNetwork*      network_ = nullptr;
    PortMapCallback   user_callback_;

    mutable std::mutex            mutex_;  ///< guards the clients and mapped_* below
    std::unique_ptr<UpnpClient>   upnp_;
    std::unique_ptr<NatPmpClient> natpmp_;
    std::string                   mapped_external_ip_;
    uint16_t                      mapped_external_tcp_port_ = 0;
    uint16_t                      mapped_external_udp_port_ = 0;
    bool                          double_nat_warned_ = false;
};

} // namespace librats
