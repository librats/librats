#pragma once

/**
 * @file find_peers.h
 * @brief get_peers lookup: find the peers announced under an info-hash (BEP 5).
 *
 * An iterative lookup toward the info-hash. Along the way it collects peer
 * endpoints from "values" replies (delivered incrementally, then once more in full
 * on completion) and the write tokens nodes hand out — the tokens are what an
 * announce needs, so Announce builds directly on this.
 */

#include "dht/id.h"
#include "dht/observer.h"
#include "dht/traversal.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace librats {
struct KrpcMessage;

namespace dht {

class FindPeers : public Traversal {
public:
    // Called with each batch of newly-discovered peers as the lookup runs.
    using PeersCallback = std::function<void(const std::vector<Address>&)>;
    // Called once when the lookup converges, with every peer found.
    using DoneCallback  = std::function<void(const std::vector<Address>&)>;

    FindPeers(RoutingTable& table, RpcManager& rpc, const NodeId& self, const InfoHash& info_hash,
              PeersCallback on_peers, DoneCallback on_done);

    void got_peers(const std::vector<Address>& peers);          // from a values reply
    void got_token(const NodeId& id, const std::string& token); // from a node's reply

    // BEP 32: which node families to ask for ("n4" / "n6"). Empty = unspecified.
    void set_want(std::vector<std::string> want) { want_ = std::move(want); }

protected:
    bool invoke(const ObserverPtr& o, TimePoint now) override;
    ObserverPtr make_observer(const NodeId& id, const Address& ep) override;
    void on_complete() override;
    const char* name() const override { return "find_peers"; }

    // The write token each responding node gave us, keyed by node id (Announce reads
    // this). std::map avoids needing a NodeId hash; the map only ever holds ~k entries.
    std::map<NodeId, std::string> tokens_;

private:
    PeersCallback on_peers_;
    DoneCallback  on_done_;
    std::vector<Address> peers_;        // all unique peers found
    std::vector<std::string> want_;     // BEP 32 family hint for our queries
};

class FindPeersObserver : public TraversalObserver {
public:
    FindPeersObserver(FindPeers& owner, const NodeId& id, const Address& ep)
        : TraversalObserver(owner, id, ep), owner_(owner) {}

protected:
    void parse_reply(const KrpcMessage& msg) override;

private:
    FindPeers& owner_;
};

} // namespace dht
} // namespace librats
