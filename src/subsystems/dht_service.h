#pragma once

/**
 * @file dht_service.h
 * @brief Capability that hands out the node-owned DhtClient to sibling modules.
 *
 * Published by DhtDiscovery via ServiceRegistry (see service_registry.h). It lets
 * another subsystem — notably Bittorrent — borrow the very same Kademlia node the
 * node already runs for peer discovery, instead of standing up a second DHT. That
 * means one UDP socket, one routing table, one shared swarm.
 *
 * The pointer is NON-owning and only valid while the provider is running. Resolve
 * it during a consumer's start() (after the provider's start() has created the
 * client) and stop using it in the consumer's stop(); the node stops subsystems in
 * reverse attach order, so a consumer attached after DhtDiscovery is guaranteed to
 * stop before the borrowed client is torn down:
 *
 *     if (auto* dht = ctx.services.get<DhtService>())
 *         if (auto* c = dht->dht_client()) bt_client_->set_external_dht(c);
 */

namespace librats {

class DhtClient;

struct DhtService {
    virtual ~DhtService() = default;

    /// The primary live DHT client (IPv4 preferred, IPv6 as fallback), or nullptr
    /// if neither family is currently up.
    virtual DhtClient* dht_client() = 0;
};

} // namespace librats
