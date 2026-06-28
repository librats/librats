#include "dht/traversal.h"
#include "dht/bep42.h"
#include "dht/krpc.h"
#include "dht/log.h"

#include <algorithm>
#include <atomic>

// Per-wave "dht.traversal" round logging is verbose; gate it behind a compile-time flag
// so it can be dropped entirely from a build. Default on (true).
#ifndef DHT_TRAVERSAL_DEBUG
#define DHT_TRAVERSAL_DEBUG true
#endif

namespace librats {
namespace dht {

namespace {
// Monotonic lookup-id source. Atomic because v4 and v6 nodes run on separate threads,
// so ids stay unique across both instances — a single "L<id>" disambiguates everything.
// Unsigned so wrap-around past 2^32 is defined (benign) rather than signed-overflow UB.
std::atomic<unsigned> g_lookup_seq{0};
}  // namespace

Traversal::Traversal(RoutingTable& table, RpcManager& rpc, const NodeId& self, const NodeId& target)
    : table_(table), rpc_(rpc), self_(self), target_(target),
      id_(g_lookup_seq.fetch_add(1, std::memory_order_relaxed)) {}

Traversal::~Traversal() {
    // Detach any still-in-flight queries so the RpcManager won't call into a
    // half-destroyed traversal once we're gone.
    for (auto& obs : results_) {
        if (obs->has(Observer::kQueried) && !obs->has(Observer::kAlive) && !obs->has(Observer::kFailed))
            rpc_.cancel(obs.get());
    }
}

void Traversal::start(TimePoint now) {
    // Seed from the closest contacts we know, including unconfirmed ones so a fresh
    // table can still bootstrap a lookup.
    for (const auto& n : table_.find_closest(target_, kBucketSize, /*include_unconfirmed=*/true))
        add_entry(n.id, n.endpoint);
    if (add_requests(now)) finish();
}

void Traversal::add_seed(const Address& ep) {
    add_entry(NodeId{}, ep, Observer::kInitial);
}

void Traversal::add_entry(const NodeId& id, const Address& ep, uint8_t flags) {
    if (done_) return;

    // Seeds with an unknown id (routers) go to the unsorted tail: we can't place them
    // by distance and there may be several, so we skip the id-based dedup for them.
    if (flags & Observer::kInitial) {
        ObserverPtr seed = make_observer(id, ep);
        seed->set(Observer::kInitial);
        results_.push_back(std::move(seed));
        return;
    }

    // Binary-search the sorted prefix results_[0..sorted_) for the insertion point.
    // A duplicate id has identical XOR distance to the target, so lower_bound lands
    // exactly on it — one search does both the dedup and the placement.
    const auto sorted_end = results_.begin() + sorted_;
    auto pos = std::lower_bound(results_.begin(), sorted_end, id,
        [&](const ObserverPtr& o, const NodeId& nid) { return closer_to(o->id(), nid, target_); });
    if (pos != sorted_end && (*pos)->id() == id) return;  // already a candidate

    results_.insert(pos, make_observer(id, ep));
    ++sorted_;

    // Cap the candidate list; abandon anything past the cutoff, releasing in-flight
    // queries so they neither leak nor report back later.
    if (results_.size() > kMaxResults) {
        for (std::size_t i = kMaxResults; i < results_.size(); ++i) {
            Observer* o = results_[i].get();
            const bool in_flight = o->has(Observer::kQueried) && !o->has(Observer::kAlive) &&
                                   !o->has(Observer::kFailed) && !o->has(Observer::kDone);
            if (in_flight) {
                o->set(Observer::kDone);
                if (invoke_count_ > 0) --invoke_count_;
                if (o->has(Observer::kShortTimeout) && branch_factor_ > static_cast<int>(kAlpha))
                    --branch_factor_;
                rpc_.cancel(o);
            }
        }
        results_.resize(kMaxResults);
        if (sorted_ > static_cast<int>(kMaxResults)) sorted_ = static_cast<int>(kMaxResults);
    }
}

bool Traversal::add_requests(TimePoint now) {
    if (done_) return true;

    int results_target = static_cast<int>(kBucketSize);  // want k alive nodes at the top
    int outstanding = 0;                                  // queries in flight among the top
    int alive = 0;                                        // confirmed-alive among the top
    int sent  = 0;                                        // queries fired in this wave

    for (auto& obs_ptr : results_) {
        if (results_target <= 0) break;
        Observer* o = obs_ptr.get();

        if (o->has(Observer::kAlive)) { --results_target; ++alive; continue; }
        if (o->has(Observer::kFailed) || o->has(Observer::kDone)) continue;
        if (o->has(Observer::kQueried)) { ++outstanding; continue; }  // in flight, awaiting reply

        if (invoke_count_ >= branch_factor_) continue;  // no free slot; keep scanning to count

        o->set(Observer::kQueried);
        if (invoke(obs_ptr, now)) {
            ++invoke_count_;
            ++outstanding;
            ++sent;
        } else {
            o->set(Observer::kFailed);
        }
    }

    // One line per wave that actually fired queries — this is the search "round". A stall
    // (slots full, nothing sent) prints nothing, so the cadence of these lines reveals
    // timeout-bound progress; `closest` (shared-prefix bits with the target) climbing shows
    // real convergence, while a flat `closest` with a rising `branch` means we're spinning
    // on dead/sybil nodes. Built only when DEBUG is on (the macro guards the level).
    if (sent > 0) {
        ++round_;
#if DHT_TRAVERSAL_DEBUG
        const int closest = sorted_ > 0 ? shared_prefix_bits(results_.front()->id(), target_) : 0;
        LOG_DEBUG("dht.traversal", name() << " L" << id_ << ' ' << short_hex(target_) << " round "
                              << round_ << ": +" << sent << " sent, " << invoke_count_
                              << " in-flight, " << alive << '/' << kBucketSize << " alive, branch="
                              << branch_factor_ << ", closest +" << closest << "b");
#endif
    }

    // Done when the k closest have all answered with nothing left in flight, or when
    // there is simply nothing more we can do.
    return (results_target == 0 && outstanding == 0) || invoke_count_ == 0;
}

void Traversal::on_responded(Observer& o, uint16_t rtt, TimePoint now) {
    if (done_) return;
    // The reply already set kAlive (see TraversalObserver::on_response); the rtt and
    // alive flag let the routing table record a confirmed contact.
    if (o.has(Observer::kShortTimeout) && branch_factor_ > static_cast<int>(kAlpha))
        --branch_factor_;
    if (invoke_count_ > 0) --invoke_count_;

    // A reply makes this a confirmed contact (its real id was resolved in on_response).
    // BEP 42: prefer contacts whose id is derived from their IP.
    table_.node_seen(o.id(), o.endpoint(), rtt, verify_node_id_for_ip(o.id(), o.endpoint().ip));

    if (add_requests(now)) finish();
}

void Traversal::on_failed(Observer& o, bool short_timeout, TimePoint now) {
    if (done_) return;
    if (o.has(Observer::kDone) || o.has(Observer::kAlive) || o.has(Observer::kFailed)) return;

    if (short_timeout) {
        if (!o.has(Observer::kShortTimeout)) {
            o.set(Observer::kShortTimeout);
            ++branch_factor_;  // free a slot but keep waiting for a possible late reply
        }
        if (add_requests(now)) finish();
        return;
    }

    o.set(Observer::kFailed);
    if (o.has(Observer::kShortTimeout) && branch_factor_ > static_cast<int>(kAlpha))
        --branch_factor_;
    if (invoke_count_ > 0) --invoke_count_;
    if (!o.has(Observer::kInitial)) table_.node_failed(o.id(), o.endpoint());

    if (add_requests(now)) finish();
}

void Traversal::traverse(const NodeId& id, const Address& ep) {
    if (done_) return;
    table_.heard_about(id, ep, verify_node_id_for_ip(id, ep.ip));
    add_entry(id, ep);
}

void Traversal::finish() {
    if (done_) return;
    done_ = true;

    // Convergence mechanics, common to every lookup type — *how* it converged, which
    // explains a slow or empty result (e.g. many queried but few alive = a sparse or
    // unresponsive neighbourhood). The peer set and the elapsed time belong to the
    // dht.find layer in node.cpp, so they are deliberately not repeated here.
    int alive = 0, queried = 0;
    for (const auto& o : results_) {
        if (o->has(Observer::kAlive)) ++alive;
        if (o->has(Observer::kQueried)) ++queried;
    }
    LOG_DEBUG("dht.find", name() << " L" << id_ << ' ' << short_hex(target_) << " converged in "
                          << round_ << " round(s): " << alive << " alive / " << queried
                          << " queried, " << results_.size() << " candidate(s)");

    on_complete();
}

void TraversalObserver::on_response(const KrpcMessage& msg, uint16_t rtt_ms, TimePoint now) {
    if (has(kDone) || has(kAlive)) return;  // late/duplicate
    set(kAlive);                            // protect against truncation during traverse()

    if (has(kInitial)) id_ = msg.response_id;  // learn a seed node's real id from its reply

    parse_reply(msg);

    // Adopt the nodes it pointed us at, then report the success (which may finish us).
    for (const auto& kn : msg.nodes)
        algorithm_.traverse(kn.id, Address(kn.ip, kn.port));

    algorithm_.on_responded(*this, rtt_ms, now);
}

} // namespace dht
} // namespace librats
