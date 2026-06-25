#pragma once

/**
 * @file announce.h
 * @brief announce_peer lookup: tell the k closest nodes we're a peer (BEP 5).
 *
 * Runs exactly like a FindPeers lookup (it must, to collect write tokens), then on
 * completion sends announce_peer — with each node's token — to the closest nodes
 * that answered. Any peers it discovered along the way are still delivered through
 * the FindPeers callbacks.
 */

#include "dht/find_peers.h"
#include "dht/id.h"

#include <cstdint>

namespace librats {
namespace dht {

class Announce : public FindPeers {
public:
    // `port` is the TCP port we're announcing; with implied_port the receiver uses
    // our UDP source port instead (better behind NAT).
    Announce(RoutingTable& table, RpcManager& rpc, const NodeId& self, const InfoHash& info_hash,
             uint16_t port, bool implied_port,
             PeersCallback on_peers = {}, DoneCallback on_done = {});

    bool is_announce() const noexcept override { return true; }

protected:
    void on_complete() override;
    const char* name() const override { return "announce"; }

private:
    uint16_t port_;
    bool     implied_port_;
};

} // namespace dht
} // namespace librats
