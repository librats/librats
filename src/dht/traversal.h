#pragma once

/**
 * @file traversal.h
 * @brief Base of an iterative Kademlia lookup (libtorrent's traversal_algorithm).
 *
 * Holds the candidate set as a list of Observers kept sorted by XOR distance to the
 * target, keeps up to branch_factor queries in flight, and converges on the k nodes
 * closest to the target. Each reply feeds discovered nodes back in (and into the
 * routing table); a two-level timeout keeps a slow node from stalling the search.
 *
 * Subclasses supply the three lookup-specific pieces: which query to send (invoke),
 * how to read a reply (the observer subtype via make_observer), and what to do once
 * it converges (on_complete).
 */

#include "dht/id.h"
#include "dht/observer.h"
#include "dht/routing_table.h"
#include "dht/rpc_manager.h"

#include <cstddef>
#include <vector>

namespace librats {
struct KrpcMessage;

namespace dht {

class Traversal {
public:
    Traversal(RoutingTable& table, RpcManager& rpc, const NodeId& self, const NodeId& target);
    virtual ~Traversal();

    // Seed from the routing table and fire the first round of queries.
    void start(TimePoint now);

    const NodeId& target() const noexcept { return target_; }
    bool finished() const noexcept { return done_; }
    virtual bool is_announce() const noexcept { return false; }  // overridden by Announce

    // Add a bootstrap/router contact whose node id we don't know yet (learned from
    // its reply). Used to seed a lookup when the routing table is empty.
    void add_seed(const Address& ep);

    // -- driven by observers ----------------------------------------------------
    void on_responded(Observer& o, uint16_t rtt, TimePoint now);
    void on_failed(Observer& o, bool short_timeout, TimePoint now);
    void traverse(const NodeId& id, const Address& ep);  // a node a peer told us about

protected:
    // Build and send this node's query (returns false if it couldn't be sent).
    virtual bool invoke(const ObserverPtr& o, TimePoint now) = 0;
    virtual ObserverPtr make_observer(const NodeId& id, const Address& ep) = 0;
    virtual void on_complete() {}
    virtual const char* name() const { return "traversal"; }

    void add_entry(const NodeId& id, const Address& ep, uint8_t flags = 0);

    RoutingTable& table_;
    RpcManager&   rpc_;
    NodeId        self_;
    // Candidate observers; the first `sorted_` are ordered by distance to target_.
    std::vector<ObserverPtr> results_;

private:
    bool add_requests(TimePoint now);  // returns true when the search is complete
    void finish();

    NodeId target_;
    int  sorted_ = 0;
    int  branch_factor_ = static_cast<int>(kAlpha);
    int  invoke_count_ = 0;
    bool done_ = false;

    static constexpr std::size_t kMaxResults = 100;
};

// Common observer for nodes inside a traversal: forwards timeouts to the algorithm,
// and on a reply learns the responder's id, lets the subclass read lookup-specific
// fields (parse_reply), folds in the nodes it returned, then reports back.
class TraversalObserver : public Observer {
public:
    TraversalObserver(Traversal& algorithm, const NodeId& id, const Address& ep)
        : Observer(id, ep), algorithm_(algorithm) {}

    void on_response(const KrpcMessage& msg, uint16_t rtt_ms, TimePoint now) override;
    void on_timeout(TimePoint now) override { algorithm_.on_failed(*this, /*short=*/false, now); }
    void on_short_timeout(TimePoint now) override { algorithm_.on_failed(*this, /*short=*/true, now); }

protected:
    virtual void parse_reply(const KrpcMessage& msg) {}  // subclass collects peers/token/etc.

    Traversal& algorithm_;
};

} // namespace dht
} // namespace librats
