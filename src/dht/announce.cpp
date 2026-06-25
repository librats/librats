#include "dht/announce.h"
#include "dht/krpc.h"

#include <utility>

namespace librats {
namespace dht {

Announce::Announce(RoutingTable& table, RpcManager& rpc, const NodeId& self,
                   const InfoHash& info_hash, uint16_t port, bool implied_port,
                   PeersCallback on_peers, DoneCallback on_done)
    : FindPeers(table, rpc, self, info_hash, std::move(on_peers), std::move(on_done)),
      port_(port),
      implied_port_(implied_port) {}

void Announce::on_complete() {
    // Announce to the closest nodes that replied AND gave us a token. results_ is
    // sorted by distance, so walking it front-to-back yields the closest first.
    int announced = 0;
    for (const auto& obs : results_) {
        if (announced >= static_cast<int>(kBucketSize)) break;
        if (!obs->has(Observer::kAlive)) continue;

        const auto token = tokens_.find(obs->id());
        if (token == tokens_.end()) continue;  // no token → we may not announce here

        KrpcMessage msg = KrpcProtocol::create_announce_peer_query(
            /*txn set by rpc*/ "", self_, target(), port_, token->second, implied_port_);
        rpc_.send_oneshot(msg, obs->endpoint());  // the ack carries nothing we need
        ++announced;
    }

    FindPeers::on_complete();  // still deliver whatever peers we discovered
}

} // namespace dht
} // namespace librats
