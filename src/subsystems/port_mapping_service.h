#pragma once

/**
 * @file port_mapping_service.h
 * @brief Automatic NAT port forwarding (UPnP IGD + NAT-PMP) as a Subsystem.
 *
 * Wraps the standalone UpnpClient (src/upnp.h) and NatPmpClient (src/natpmp.h)
 * backends into the Node lifecycle. On start() it asks the home router to forward
 * the node's TCP listen port so peers behind NAT can accept inbound connections;
 * on stop() it removes the mapping. Both backends run in parallel on their own
 * worker threads — whichever the router supports wins. This is the Node-era
 * replacement for the old RatsClient::start_port_mapping() wiring that was lost
 * in the rewrite.
 *
 * Threading: the backends invoke our result callback from their own worker
 * threads, so all shared state is guarded by mutex_. stop() moves the clients out
 * under the lock and stops them OUTSIDE it — stop() joins those workers, which
 * take the lock from handle_result(), so holding it across stop() would deadlock.
 */

#include "node/peer_network.h"
#include "nat/port_mapping.h"   // PortMappingConfig, PortMapResult, PortMapCallback

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
class PortMappingService final : public Subsystem {
public:
    explicit PortMappingService(PortMappingConfig config = {});
    ~PortMappingService() override;

    void attach(PeerNetwork& network) override;
    void start() override;
    void stop() override;

    /// Observe mapping results (established / refreshed / failed). Optional;
    /// invoked from a backend worker thread. Register before start().
    void on_result(PortMapCallback cb) { user_callback_ = std::move(cb); }

    /// The public endpoint peers should reach us on, once a backend reports a
    /// usable (genuinely public) external IP + TCP port. nullopt until then.
    std::optional<std::pair<std::string, uint16_t>> mapped_public_address() const;

private:
    void handle_result(const PortMapResult& result);

    PortMappingConfig config_;
    PeerNetwork*      network_ = nullptr;
    PortMapCallback   user_callback_;

    mutable std::mutex            mutex_;  ///< guards the clients and mapped_* below
    std::unique_ptr<UpnpClient>   upnp_;
    std::unique_ptr<NatPmpClient> natpmp_;
    std::string                   mapped_external_ip_;
    uint16_t                      mapped_external_tcp_port_ = 0;
    bool                          double_nat_warned_ = false;
};

} // namespace librats
