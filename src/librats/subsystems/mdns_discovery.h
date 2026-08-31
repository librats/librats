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
 *
 * The backend differs by platform (see MdnsBackend below) but the wire protocol
 * does not, so nodes on any mix of platforms discover each other.
 */

#include "librats/util/rats_export.h"
#include "librats/node/peer_network.h"
#include "librats/mdns/mdns.h"
#include "librats/mdns/mdns_dnssd.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

namespace librats {

/// Which mDNS implementation this build talks to the network through.
///
/// Apple platforms go through Bonjour (mDNSResponder) instead of a multicast socket
/// of our own, because since iOS 14 sending or receiving multicast directly requires
/// `com.apple.developer.networking.multicast` — an entitlement Apple grants only on
/// request, without which the raw-socket backend discovers nothing. Everywhere else
/// the raw socket is the fewest moving parts and has no such gate.
///
/// Both speak standard mDNS, so the choice is invisible on the wire: an iPhone and an
/// Android phone on the same LAN find each other regardless.
#if defined(__APPLE__)
using MdnsBackend = DnssdMdnsClient;
#else
using MdnsBackend = MdnsClient;
#endif

class RATS_API MdnsDiscovery final : public Subsystem {
public:
    struct Config {
        std::string instance_name = "";  ///< empty → derived from our PeerId
    };

    MdnsDiscovery();
    explicit MdnsDiscovery(Config config);
    ~MdnsDiscovery() override;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    bool is_running() const;

private:
    void on_service(const MdnsService& service, bool is_new);

    Config                     config_;
    std::string                instance_;
    PeerNetwork*               network_ = nullptr;
    std::unique_ptr<MdnsBackend> mdns_;
    std::atomic<bool>          running_{false};

    std::mutex                      dialed_mutex_;
    std::unordered_set<Address> dialed_;  ///< peers we've already dialed
};

} // namespace librats
