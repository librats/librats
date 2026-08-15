#include "librats/peer/peer_table.h"

#include <algorithm>  // std::find
#include <mutex>      // std::unique_lock (shared_lock comes from <shared_mutex>)

namespace librats {

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
    //   opposite roles     ⇒ cross-connect: keep the link started by the smaller id
    //                        (prefer_outbound, opposite at each end by construction).
    //   different wires    ⇒ a dial race whose attempts both got through. Both ends
    //                        see the transports, and there is a right answer: the
    //                        datagram link (one socket, one NAT mapping, a source
    //                        port that can be dialed back — see dialer.h). "Is it
    //                        UDP" ranks the pair only because there are exactly two
    //                        wires; a third would need an explicit order, or the two
    //                        ends could rank the same pair differently.
    //   same role and wire ⇒ a reconnect, not a simultaneous pair: the old link is
    //                        stale or already dead, so the newcomer is the live one.
    bool keep_new = true;
    if (cur.info.direction != info.direction) {
        const ConnRole survivor = prefer_outbound ? ConnRole::Outbound : ConnRole::Inbound;
        keep_new = (info.direction == survivor);
    } else if (cur.info.transport != info.transport) {
        keep_new = (info.transport == TransportKind::Udp);
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
