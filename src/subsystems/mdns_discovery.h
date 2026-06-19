#pragma once

/**
 * @file mdns_discovery.h
 * @brief Local-network peer discovery via mDNS — a thin adapter, not a rewrite.
 *
 * Wraps the existing MdnsClient (src/mdns.h) as a Subsystem WITHOUT modifying it.
 * On start it announces our TCP listen port as an mDNS service and browses for
 * the same service type, dialing discovered instances through the node. Each
 * node uses a unique instance name (derived from its PeerId) so two nodes on the
 * same host don't collide and can filter out their own announcement.
 */

#include "node/peer_network.h"
#include "mdns.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

namespace librats {

class MdnsDiscovery final : public Subsystem {
public:
    struct Config {
        std::string instance_name = "";  ///< empty → derived from our PeerId
    };

    MdnsDiscovery();
    explicit MdnsDiscovery(Config config);
    ~MdnsDiscovery() override;

    void attach(PeerNetwork& network) override;
    void start() override;
    void stop() override;

    bool is_running() const;

private:
    void on_service(const MdnsService& service, bool is_new);

    Config                     config_;
    std::string                instance_;
    PeerNetwork*               network_ = nullptr;
    std::unique_ptr<MdnsClient> mdns_;
    std::atomic<bool>          running_{false};

    std::mutex                      dialed_mutex_;
    std::unordered_set<std::string> dialed_;  ///< ip:port we've already dialed
};

} // namespace librats
