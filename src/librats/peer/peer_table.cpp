#include "librats/peer/peer_table.h"

#include <algorithm>  // std::find
#include <mutex>      // std::unique_lock (shared_lock comes from <shared_mutex>)

namespace librats {

namespace {

/// How much a transport is worth when two connections to the same peer have to be
/// ranked. Both ends see the same pair of transports and apply the same order, so
/// they converge on the same survivor without exchanging a word.
///
///   Udp   — one socket, one NAT mapping, a source port that can be dialed back
///           (see dialer.h). The best link there is.
///   Tcp   — a direct link all the same, just a less useful one to a NAT.
///   Relay — not a direct link at all: every byte costs a third node bandwidth and
///           a round trip. Ranked last here for completeness; in practice a relayed
///           link is settled before this by the rule in add(), which lets ANY direct
///           link beat it regardless of role.
int transport_rank(TransportKind t) noexcept {
    switch (t) {
        case TransportKind::Udp:   return 2;
        case TransportKind::Tcp:   return 1;
        case TransportKind::Relay: return 0;
    }
    return 0;
}

} // namespace

PeerTable::AddOutcome PeerTable::add(const PeerInfo& info, PeerRoute route,
                                             bool prefer_outbound) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto [it, inserted] = peers_.try_emplace(info.id, Entry{info, route});
    if (inserted) {
        count_.fetch_add(1, std::memory_order_relaxed);
        return {AddResult::NewPeer, std::nullopt};
    }

    Entry& cur = it->second;
    if (cur.route == route) {            // same connection re-registering: refresh only
        cur.info = info;
        return {AddResult::Updated, std::nullopt};
    }

    // A different connection already serves this peer, and exactly one may survive.
    // Both ends resolve the same pair, so every rule here must read something that
    // looks identical from either side. Timing does not qualify — "whichever arrived
    // first" gets a different answer at each end, and two ends that each keep the
    // link the other just dropped are left with no link at all.
    //
    //   one relayed, one not ⇒ not a race at all but an upgrade (or a late relay
    //                        arriving under a direct link): the direct one wins,
    //                        whatever the roles. Ranked FIRST, ahead of the role
    //                        rule, because a relayed link that won on role would
    //                        keep costing a third node bandwidth for the life of a
    //                        peer we can reach ourselves. Both ends see the same
    //                        pair of transports, so both reach this same verdict.
    //   opposite roles     ⇒ cross-connect: keep the link started by the smaller id
    //                        (prefer_outbound, opposite at each end by construction).
    //   different wires    ⇒ a dial race whose attempts both got through. Both ends
    //                        see the transports and rank them by the same explicit
    //                        order (transport_rank above), so neither can rank the
    //                        same pair differently.
    //   same role and wire ⇒ a reconnect, not a simultaneous pair: the old link is
    //                        stale or already dead, so the newcomer is the live one.
    const bool cur_relayed = cur.info.transport == TransportKind::Relay;
    const bool new_relayed = info.transport == TransportKind::Relay;

    bool keep_new = true;
    if (cur_relayed != new_relayed) {
        keep_new = !new_relayed;
    } else if (cur.info.direction != info.direction) {
        const ConnRole survivor = prefer_outbound ? ConnRole::Outbound : ConnRole::Inbound;
        keep_new = (info.direction == survivor);
    } else if (cur.info.transport != info.transport) {
        keep_new = transport_rank(info.transport) > transport_rank(cur.info.transport);
    }

    if (keep_new) {
        const PeerRoute loser = cur.route;
        cur = Entry{info, route};
        return {AddResult::Replaced, loser};
    }
    return {AddResult::Rejected, route};  // existing wins; caller closes the new connection
}

std::vector<Address> PeerTable::add_addresses(const PeerId& id, PeerRoute route,
                                              const std::vector<Address>& addresses) {
    std::vector<Address> added;
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end() || it->second.route != route) return added;

    std::vector<Address>& known = it->second.info.addresses;
    for (const Address& addr : addresses) {
        if (known.size() >= kMaxAddressesPerPeer) break;
        if (std::find(known.begin(), known.end(), addr) != known.end()) continue;  // dedup
        known.push_back(addr);
        added.push_back(addr);
    }
    return added;
}

std::optional<PeerTable::Destination> PeerTable::destination(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) return std::nullopt;
    return Destination{it->second.route, it->second.writable, it->second.owed};
}

bool PeerTable::all_writable() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& [id, entry] : peers_)
        if (!entry.writable) return false;
    return true;
}

void PeerTable::set_writable(const PeerId& id, PeerRoute route, bool writable) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end() || it->second.route != route) return;
    it->second.writable = writable;
}

void PeerTable::set_supported_transports(const PeerId& id, PeerRoute route, uint8_t mask) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end() || it->second.route != route) return;
    it->second.info.supported_transports = mask;
}

bool PeerTable::remove(const PeerId& id, PeerRoute route) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end() || it->second.route != route) return false;
    peers_.erase(it);
    count_.fetch_sub(1, std::memory_order_relaxed);
    return true;
}

std::optional<PeerRoute> PeerTable::route(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) return std::nullopt;
    return it->second.route;
}

std::optional<PeerInfo> PeerTable::info(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = peers_.find(id);
    if (it == peers_.end()) return std::nullopt;
    return it->second.info;
}

bool PeerTable::contains(const PeerId& id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return peers_.find(id) != peers_.end();
}

std::vector<PeerInfo> PeerTable::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<PeerInfo> out;
    out.reserve(peers_.size());
    for (const auto& [id, entry] : peers_) out.push_back(entry.info);
    return out;
}

} // namespace librats
