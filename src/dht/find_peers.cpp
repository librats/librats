#include "dht/find_peers.h"
#include "dht/krpc.h"

#include <algorithm>
#include <utility>

namespace librats {
namespace dht {

FindPeers::FindPeers(RoutingTable& table, RpcManager& rpc, const NodeId& self,
                     const InfoHash& info_hash, PeersCallback on_peers, DoneCallback on_done)
    : Traversal(table, rpc, self, info_hash),
      on_peers_(std::move(on_peers)),
      on_done_(std::move(on_done)) {}

void FindPeers::got_peers(const std::vector<Address>& peers) {
    std::vector<Address> fresh;
    for (const auto& p : peers) {
        if (std::find(peers_.begin(), peers_.end(), p) == peers_.end()) {
            peers_.push_back(p);
            fresh.push_back(p);
        }
    }
    if (!fresh.empty() && on_peers_) on_peers_(fresh);
}

void FindPeers::got_token(const NodeId& id, const std::string& token) {
    if (token.empty()) return;
    tokens_.emplace(id, token);  // first token from a node wins
}

bool FindPeers::invoke(const ObserverPtr& o, TimePoint now) {
    KrpcMessage msg = KrpcProtocol::create_get_peers_query(/*txn set by rpc*/ "", self_, target());
    msg.want = want_;  // BEP 32: ask for our own family's nodes
    return rpc_.invoke(msg, o->endpoint(), o, now);
}

ObserverPtr FindPeers::make_observer(const NodeId& id, const Address& ep) {
    return std::make_shared<FindPeersObserver>(*this, id, ep);
}

void FindPeers::on_complete() {
    if (on_done_) on_done_(peers_);
}

void FindPeersObserver::parse_reply(const KrpcMessage& msg) {
    if (!msg.token.empty()) owner_.got_token(msg.response_id, msg.token);
    if (!msg.peers.empty()) owner_.got_peers(msg.peers);
}

} // namespace dht
} // namespace librats
