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

    // Anti-Sybil (libtorrent's dht_restrict_search_ips): a genuinely new candidate — the
    // dedup above already let same-id repeats out — sharing a /24 (v4) or /64 (v6) with one
    // we've already admitted is ignored, so no single operator can pack the candidate set
    // and steer the search. The first node in a block wins. This mirrors libtorrent, which
    // runs the check *after* the id dedup and skips it for kInitial seeds (handled above).
    // The packed prefixes live in a per-lookup set, so it is an O(1) test rather than an
    // O(n) scan of results_, and a prefix persists for the lookup's lifetime (a candidate
    // dropped by truncation can't re-open its block). Only public IPs are restricted, so a
    // LAN/loopback/CGNAT test topology is unaffected.
    if (register_subnet(ep)) return;

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

bool Traversal::register_subnet(const Address& ep) {
    // Only public addresses are constrained; a LAN/loopback/CGNAT topology is exempt (the
    // same rule the routing table applies) and never collides. is_public_address implies a
    // specified v4/v6 address, so bytes() below has the octets we index.
    if (!is_public_address(ep.ip)) return false;

    const uint8_t* b = ep.ip.bytes().data();  // network-order octets
    if (ep.ip.is_v6()) {
        // /64: the leading 8 bytes packed big-endian (matches ip_too_close's compare and
        // libtorrent's read_uint64 over the first 8 v6 octets).
        uint64_t prefix = 0;
        for (int i = 0; i < 8; ++i) prefix = (prefix << 8) | b[i];
        return !subnet6_.insert(prefix).second;  // insert() fails ⇒ block already admitted
    }
    // /24: the leading 3 bytes, low octet dropped — libtorrent's to_uint() & 0xffffff00.
    const uint32_t prefix = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8);
    return !subnet4_.insert(prefix).second;
}

bool Traversal::add_requests(TimePoint now) {
    if (done_) return true;

    // How many of the k closest still need a live answer before the search has converged.
    // Starts at k and counts down as we meet alive nodes walking the list closest-first;
    // reaching 0 means the k nodes nearest the target have all replied.
    int alive_needed = static_cast<int>(kBucketSize);
    // Queries among the k closest that we still genuinely wait on: sent, not yet answered,
    // and not yet past their short timeout. A query that has already passed its short
    // timeout is deliberately NOT counted here — a stale straggler must not block completion
    // (see the return below). A just-sent query counts too.
    int in_flight = 0;
    int alive = 0;   // alive nodes seen among the closest (for the round log line)
    int sent  = 0;   // queries fired in this pass (a stall sends nothing)

    for (auto& obs_ptr : results_) {
        if (alive_needed <= 0) break;  // the k closest have all replied — stop scanning
        Observer* o = obs_ptr.get();

        if (o->has(Observer::kAlive)) { --alive_needed; ++alive; continue; }
        if (o->has(Observer::kFailed) || o->has(Observer::kDone)) continue;
        if (o->has(Observer::kQueried)) {
            // Only a *fresh* query — one that hasn't yet passed its short timeout — blocks
            // completion. Once a query is past its short timeout it has almost certainly
            // gone dead; holding the whole lookup for it until the 15 s full timeout is
            // pure dead time. Such a node gave us no peers, and (being silent) no write
            // token, so it was never a candidate to announce to either — waiting for it
            // cannot improve the result. We keep the observer registered so a late reply
            // is still welcome, but a stale query no longer gates convergence.
            if (!o->has(Observer::kShortTimeout)) ++in_flight;
            continue;
        }

        if (invoke_count_ >= branch_factor_) continue;  // no free slot; keep scanning to count

        o->set(Observer::kQueried);
        if (invoke(obs_ptr, now)) {
            ++invoke_count_;
            ++in_flight;
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

    // Done exactly when nothing we still wait on is in flight. This one check already covers
    // both ways a lookup can end:
    //   - success:   the k closest have all replied, so none of them is still in flight;
    //   - exhausted: a sparse/dead neighbourhood we can't fill to k live nodes — but if any
    //                reachable candidate were left, the loop above would have just queried it
    //                (which bumps in_flight), so in_flight == 0 also means "nothing left to
    //                try". (A stale query frees its slot, so it never hides a sendable one.)
    // A fresh query always keeps in_flight > 0, so we never stop while a node might still
    // answer inside its short timeout. Conversely a *stale* query — one past its short
    // timeout, so almost certainly dead — is excluded from in_flight on purpose: that is what
    // decouples termination from the 15 s full timeout. The full timeout now only ages out
    // routing-table liveness (node_failed), never lookup completion, so one silent-but-close
    // node can no longer stall the search (nor delay an announce_peer) by sitting out its
    // full timeout.
    return in_flight == 0;
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

void Traversal::resort_result(Observer& o) {
    if (done_) return;

    // Locate the observer by identity. It may have been dropped by a truncation while a
    // reply was in flight, in which case there is nothing to re-place.
    auto it = std::find_if(results_.begin(), results_.end(),
        [&](const ObserverPtr& p) { return p.get() == &o; });
    if (it == results_.end()) return;

    // If it already sat inside the sorted prefix, account for pulling it out of there.
    // (For a seed it lives in the unsorted tail, so this branch won't fire — but a
    // duplicate id resolved into the prefix could, exactly as in libtorrent.)
    if (it - results_.begin() < sorted_) --sorted_;

    ObserverPtr ptr = std::move(*it);
    results_.erase(it);

    // Re-insert by XOR distance now that the id is known — same lower_bound the sorted
    // prefix is built with in add_entry, so the invariant is preserved.
    const NodeId id = ptr->id();
    const auto sorted_end = results_.begin() + sorted_;
    auto pos = std::lower_bound(results_.begin(), sorted_end, id,
        [&](const ObserverPtr& a, const NodeId& nid) { return closer_to(a->id(), nid, target_); });
    results_.insert(pos, std::move(ptr));
    ++sorted_;
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

    // We complete as soon as the top-k have answered, but queries to farther nodes may
    // still be in flight (counted in invoke_count_, not in the top-k in_flight).
    for (const auto& obs : results_) {
        Observer* o = obs.get();
        const bool in_flight = o->has(Observer::kQueried) && !o->has(Observer::kAlive) &&
                               !o->has(Observer::kFailed) && !o->has(Observer::kDone);
        if (in_flight) {
            o->set(Observer::kDone);
            rpc_.cancel(o);
        }
    }

    on_complete();
}

void TraversalObserver::on_response(const KrpcMessage& msg, uint16_t rtt_ms, TimePoint now) {
    if (has(kDone) || has(kAlive)) return;  // late/duplicate
    if (algorithm_.finished()) return;      // lookup already converged; don't re-enter parse_reply
    set(kAlive);                            // protect against truncation during traverse()

    if (has(kInitial) && msg.response_id != NodeId{}) {
        // A seed/router we only knew by address just revealed its real id. Adopt it and
        // re-place this observer among the distance-sorted candidates (a zero id is the
        // "unknown" sentinel, so guard against a malformed reply re-sorting us to the top).
        id_ = msg.response_id;
        algorithm_.resort_result(*this);
    }

    parse_reply(msg);

    // Adopt the nodes it pointed us at, then report the success (which may finish us).
    for (const auto& kn : msg.nodes)
        algorithm_.traverse(kn.id, Address(kn.ip, kn.port));

    algorithm_.on_responded(*this, rtt_ms, now);
}

} // namespace dht
} // namespace librats
